#!/usr/bin/env python3
"""Build the privacy-preserving static account-fleet dashboard payload."""

import argparse
import contextlib
import copy
import datetime as dt
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import zipfile


SCHEMA = "account-fleet-dashboard/v1"
WINDOWS = (("5h", "5 hour"), ("7d", "7 day"), ("fable_7d_oi", "Fable 7 day"))
ACCOUNT_REF_RE = re.compile(r"ACCT[A-Z0-9]+_TOKEN")
SAFE_PROVIDER_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")
SAFE_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}")
# The `owner/name` shape, defined ONCE. The holder grammar below embeds it, and the serviced-target
# reader (issue #78) validates policy/repos.toml's table keys against the same pattern — so the
# repositories the census SEEDS and the repositories it COUNTS can never be two different grammars.
SAFE_REPOSITORY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")
HOLDER_RE = re.compile(
    r"^(?:review:|fix:)?(?P<repository>" + SAFE_REPOSITORY_RE.pattern + r")#\d+@\S+$")
# The per-repository agent census reads its ROW SET from this repo's own worker policy (issue #78).
# Not a CLI flag on purpose: the set of repositories this orchestrator services is a property of the
# checkout the generator runs from, so there is no seam an invocation could point somewhere else.
POLICY_PATH_PARTS = ("policy", "repos.toml")
DISPATCH_COMPLETE_RE = re.compile(
    r"^\S+\s+dispatcher complete:\s+(\d+) worker/review/fix run\(s\) launched", re.MULTILINE)
DISPATCHED_RE = re.compile(r"^\S+\s+dispatched\s", re.MULTILINE)
DEFERRED_RE = re.compile(r"^\S+\s+defer(?:red)?\s", re.MULTILINE)
# Per-lane tick counts (issues #108/#323). dispatch-claim.py prints one
# `lane <name>: planned=N launched=N deferred=N error=N` line per lane immediately after
# `dispatcher complete:`, from the same counters it writes into the dispatch-summary.json the
# tick-health recorder reads — that summary is a runner-temp file the dashboard build never sees,
# so the RUN LOG is the only place these counts are reachable from here. The lane NAME is read from
# the log rather than pinned to a list, exactly as _obs_lane_rows does for the collector's lanes: a
# lane added to dispatch-claim's DISPATCH_LANES appears on the page with no change here. Counts are
# digit-bounded and the name must be a safe token.
DISPATCH_LANE_RE = re.compile(
    r"^\S+\s+lane (?P<lane>[A-Za-z0-9][A-Za-z0-9_.-]{0,31}): "
    r"planned=(?P<planned>\d{1,6}) launched=(?P<launched>\d{1,6}) "
    r"deferred=(?P<deferred>\d{1,6}) error=(?P<error>\d{1,6})\s*$", re.MULTILINE)
DISPATCH_LANE_CAP = 12
# The block dispatch-claim prints is BOUNDED on both sides — `dispatcher complete:`, the
# `fix-dispatch:` fan-out line, one lane line per DISPATCH_LANES, then `defer attribution:` — and
# `_dispatch_lane_rows` validates it as a WHOLE against these two anchors plus the lanes below.
# A tick truncated mid-block has no terminator; a lane row omitted from a rendered tick reads as a
# healthy lane that simply is not there. Both must be "unknown", never a selectively complete tick.
DISPATCH_FIX_LINE_RE = re.compile(r"^\S+\s+fix-dispatch: ")
DISPATCH_LANE_END_RE = re.compile(r"^\S+\s+defer attribution:")
# The lanes dispatch-claim's DISPATCH_LANES prints on EVERY tick, in THIS order (it iterates that
# tuple), and so the minimum a rendered block must carry. This is a floor on the SET and a pin on
# the ORDER of these four: an ADDED lane still reaches the page unread-ahead (the name comes from
# the log) wherever it sits in the block, while a MISSING one — the stalled review or failed disarm
# this feature exists to expose — refuses the whole block instead of publishing the survivors, and
# so does a block whose four required rows arrive in an order the dispatcher cannot emit. Should
# dispatch-claim ever reorder its own DISPATCH_LANES, ticks read `—` until this tuple is matched to
# it: unknown, which is the safe direction, rather than a block of unclear provenance published as
# the dispatcher's own.
DISPATCH_REQUIRED_LANES = ("worker", "review", "fix", "disarm")

# Agent-run observability (issue #246). The collector persists a snapshot of cache-effectiveness /
# per-lane run-health / flow metrics + auto-fixer trigger fires on the ledger data-plane branch
# (data/observability.json); dashboard.yml hands it in via --observability and
# _normalize_observability() validates it FAIL-CLOSED here before it may reach the public
# data.json (rendered by the dashboard's Observability panels; absent file => hidden panel).
# Decision 22: no raw account handles anywhere on the public surface — observability lease rows
# must already carry the collector's salted label (OBS_SALTED_LABEL_RE below); anything else
# dies loudly, and _assert_private additionally backstops every known raw handle over the finished
# document. Issue #374 additionally stops the SALTED per-account rows being published at all — see
# the fleet-composition block below — but the label validation stays, because a raw handle reaching
# the collector output is a privacy incident whether or not this build would have published it.
# Issue #841: the snapshot itself is readable on the PUBLIC `ledger` branch, so this contract no
# longer REQUIRES the per-account rows either — `flow.lease_utilization_1h` may be sent already
# aggregated, and a collector that does so writes no per-account row array to a public branch.
OBS_SCHEMA = "registry-observability/v1"
# Issue #375: the salted label is the CANONICAL account fingerprint — sha256(handle:salt)[:16],
# locked decision 22a, the one shape model-health.account_hash / worker-pr.account_hash produce and
# lease_schema.ACCOUNT / groom.SAFE_ACCOUNT_HASH / select-and-claim.ACCOUNT_FINGERPRINT_RE already
# validate. This read `[0-9a-f]{8}` — a second, shorter fingerprint format that no producer in this
# repo can emit, so a collector handing over the fingerprint every other surface uses would have
# failed the build. Tightening it here is safe in exactly this order because the collector has not
# landed yet (dashboard.yml: the snapshot is OPTIONAL until it does, and the panel stays hidden) —
# there is no producer to break, and the shape it must be built against is now the canonical one.
# The self-test pins this against model-health.account_hash's real output, not against a literal,
# so the two cannot drift apart again.
OBS_SALTED_LABEL_RE = re.compile(r"[0-9a-f]{16}")
OBS_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:+-]{0,63}")
OBS_QUEUE_CLASS_RE = re.compile(r"[1-4][a-z]?")   # the #243 queue classes (1, 2, 2a..2d, 3, 4)
OBS_EVIDENCE_RE = re.compile(r"https://github\.com/[A-Za-z0-9_.~!$&'()*+,;=:@/?#%-]{1,220}")
OBS_THRESHOLD_KEYS = {"workflow_failure_rate", "defer_reason_hourly",
                      "queue_age_clamp_minutes", "merge_stall_minutes"}
# [#1557] THE CACHE GROUP HAS NO PRODUCER, and the file the docs named as its source never had one
# either: `data/cache-affinity.json` is documented as "a rolling {account -> [{package,role,model,
# at}]} affinity", but nothing in this repo has ever written it (README.md / data/README.md now say
# so). Cache affinity is DERIVED at claim time from the lease ledger by
# select-and-claim.choose_account, which keeps no history.
# [#1839] SO THE GROUP IS NOW USAGE-DERIVED ONLY, and its three affinity-CHAIN fields —
# `warm_drain_rate_1h`, `drained_1h`, `chain_length_histogram` — are RETIRED. #1557 left the consumer
# contract deliberately open because the group's fate was an undecided question; this is the decision,
# and it is the only one this seam can take alone. The two surviving fields are sourceable TODAY from
# the provider usage responses `account-usage.py` already reads (a cache-read input-token count per
# request). The three retired ones need affinity-chain HISTORY that nothing keeps: affinity is
# re-derived per claim and a released lease leaves only its receipt comment, so there is no source at
# all — not a late producer, an absent one. A contract field no producer can ever fill is not an open
# seam, it is a promise, and it renders as a confident number the moment anything half-fills it.
# Re-opening it is a PRODUCER-FIRST change (durably record the chain transitions through the same CAS
# discipline as the other ledger writers, never a `run_gh`-wrapped write), then re-add the field it
# feeds — not the reverse.
# A collector built against the pre-#1839 shape is not punished for it: the retired keys are ignored
# (never republished, and never measurement enough to publish the group) and NAMED on stdout, so the
# mismatch lands in the build log instead of nowhere. The tuple's order IS the order they are named
# in, so the announcement is stable across builds.
OBS_CACHE_RETIRED_FIELDS = ("chain_length_histogram", "drained_1h", "warm_drain_rate_1h")
OBS_CACHE_RETIRED = ("dashboard-gen: ignored retired observability cache field(s) {} — "
                     "affinity-chain history has no producer (issue #1839)")
OBS_CACHE_DROP = ("dashboard-gen: dropped the observability cache group (type {}) — "
                  "no field it publishes was measured")

# [#1570] How many per-row drop warnings ONE seam may print before it stops naming rows and prints
# a single counting tail instead. The drop diagnostics (#982 on `flow.queue`, and the evidence-link
# warning that set the precedent) emit ONE LINE PER DROPPED ROW, and NEITHER input list is bounded
# on the way IN — `_obs_capped` truncates both on the way OUT, after the loop. So a collector
# snapshot on the public `ledger` branch carrying 100k malformed rows writes 100k lines into
# dashboard.yml's step log, which is the failure the diagnostic exists to FIX: a log nobody can read
# is a log nobody reads. The cap is on the DIAGNOSTIC only — the drop-the-row tolerance, the
# published rows and the build's exit status are all unchanged.
OBS_DROP_WARN_MAX = 12

# Usage-probe outcome sidecar (issue #219). dashboard.yml's secret-materialization and probe steps
# are `continue-on-error`, and a failed probe used to be replaced by `{}` — indistinguishable from
# "every account is idle". The probe job now PERSISTS its outcome next to the snapshot and the
# build hands it in via --usage-status; anything that is not an explicit, FRESH `ok` means the
# measurement did not happen, so no account may be published as usable capacity on its basis.
PROBE_SCHEMA = "account-usage-probe/v1"
# The probe runs on dashboard.yml's */15 cron; one hour is four missed slots. Beyond it the
# snapshot describes a fleet state nobody has observed recently, so it stops counting as measured.
PROBE_MAX_AGE_SECONDS = 3600
# Runner/generator clock skew is seconds, not minutes; a stamp further in the future than this is
# not a clock artifact but a bogus stamp, and bogus == unmeasured.
PROBE_MAX_SKEW_SECONDS = 300

# FLEET-COMPOSITION MINIMIZATION (issue #374, closing the sol-audit finding #184 deferred).
#
# The line this repo had already accepted is model-health.render_body's PUBLIC-registry route
# (sol-audit #204): when an alert lands on the public registry it carries the provider and the
# condition and SUPPRESSES the failure/fleet counts, reset hints and diagnostics, because those
# "would compositionally disclose the worker-account fleet". The dashboard was the loud version of
# the very same disclosure and had never been held to that line: it published one row per account
# (salted label, provider, availability, live windows, active-agent count) plus
# accounts_total/available/capped/unavailable/unknown, single_account, per-window
# accounts_reporting/remaining_account_windows/limit_remaining/limits_known, and
# fleet.capacity {eligible, total}. Every one of those is a direct read of the fleet's CARDINALITY,
# and the salted labels were stable across builds, so the page also tracked individual accounts
# over time.
#
# The counts are NOT deleted — they remain the internal single source of truth for "is there usable
# headroom" (_provider_quota / the capacity tally in build_dashboard), still unit-tested here, still
# the one predicate shared with the allocator. They are PROJECTED AWAY at publication time by
# _public_provider_quota + _public_capacity, which keep the operational answer (has this provider
# headroom, how full are its windows on average, when does it refill) while being invariant under
# cloning the fleet. _assert_no_fleet_composition then backstops the FINISHED document fail-closed,
# so a future field cannot silently re-open the surface this closes.
#
# KNOWN RESIDUAL, stated rather than hidden: `fleet.active_agents` (and the per-repository model
# counts it summarizes) is a count of LIVE LEASES, not of accounts. It used to be documented here as
# a lower BOUND on the fleet size — "the catalog's `max_concurrent_workers` is 1, so N concurrent
# agents implies at least N accounts" — and that premise is false (#882): accounts carry their own
# cap, acct01 was hand-set to 12 long ago, and since #278 set-up-account MINTS at the per-provider
# default (openai 12, anthropic 4). One account can therefore hold many of these leases at once, so
# N live leases implies only ceil(N / the largest cap in the catalog) accounts — a far weaker
# inference, and one whose divisor is not even published. The residual is thus WEAKER than it was
# stated to be, never stronger; nothing that was safe becomes unsafe. Do not restore the cap-1
# reasoning: a future minimization pass that trusts it would be reading a false invariant, and the
# suite pins the counter-example (one account, three concurrent leases, `active_agents` 3).
#
# KEPT — and #840 settles WHY, rather than leaving the disposition open. It is the dashboard's core
# operational number, and the two alternatives it weighed (bucket it `1-3 / 4-9 / 10+`, or drop it)
# would withhold NOTHING: `data/leases.json` on the public `ledger` branch already carries ONE ROW
# PER LIVE LEASE, and each row is strictly more informative than anything published here — holder
# (`owner/repo#issue@run`), model, role, package, the salted account fingerprint and the exact
# expiry. What this page publishes is a LOSSY PROJECTION of a document any reader can already fetch
# and count exactly, so bucketing or dropping costs the operational number and buys no privacy at
# all. The residual's disposition is therefore not an independent product call: it is ENTAILED by
# the `ledger`-branch question, and only a decision to stop publishing per-lease rows THERE could
# make bucketing or dropping here mean anything. That is a data-plane decision, out of scope for the
# dashboard.
#
# The one thing that would quietly falsify the paragraph above is a future live-agent field folding
# in something the ledger does NOT carry (a capacity term, a per-account breakdown, anything only
# the catalog/usage/probe knows) — the prose would still claim "already public" while the page had
# started disclosing something new. So the ground is PINNED, not asserted: the suite holds the
# ledger and the serviced set fixed at non-zero load, varies every other build input, and requires
# the live-agent surface to come out identical — while proving that same variation really did move
# the rest of the payload. If that row goes red, this justification has stopped holding and the
# residual has to be re-decided, not re-worded.
#
# So the property this change actually establishes is "the public payload carries no ACCOUNT CENSUS
# and no per-account row", NOT "no fleet count" — and both halves are load-bearing statements that
# the suite pins: the clone-invariance test below runs each fleet size WITH one live lease per
# account, so it asserts the invariance where the residual is live, and asserts the residual itself
# (the agent counts DO scale) rather than avoiding load and implying it does not. The page footer is
# worded to the same scope; do not restore an absolute "no fleet counts are published" claim while
# `active_agents` ships.
FLEET_COMPOSITION_KEYS = frozenset({
    "accounts", "accounts_total", "accounts_available", "accounts_capped", "accounts_unavailable",
    "accounts_unknown", "accounts_reporting", "single_account", "remaining_account_windows",
    "limit_remaining", "limits_known", "eligible", "total", "label",
})


# [#1353 BLOCKED] Thresholds that CANNOT yet be re-sized to satisfy the #680 bound. The historical
# groom keepalive leg at 1200 and retriage.yml at 2400 made dashboard.yml refuse ingestion
# (action_required, jobs total_count=0 — measured on master 2026-07-31T03:04Z, PR #1363, reverted
# by #1364). #2076 retargets that same conservative groom threshold to groom-core.yml; it does not
# pretend the unexplained dashboard-ingestion failure has become safe. Remove this exemption once
# #1353 is resolved and the tighter threshold is proved on default-branch runs.
_THRESHOLD_BOUND_EXEMPT = frozenset({"groom-core.yml", "retriage.yml"})


# [#1084] The nominal cadence of every workflow the CROSS-REPO keepalive leg watches, keyed by
# (repository, workflow-file). A registry leg's bound is READ out of the watched workflow's own
# `on: schedule:` block (`_workflow_cadence_seconds`), so a re-timed cron and the threshold sized
# against it cannot drift apart. The cross-repo leg watches a repository that is not checked out
# beside this one, so there is nothing to read — and with nothing to read, the only reference point
# its threshold had was ITSELF: every fixture age in the #559 rows is derived from the threshold
# (`limit ± 600`), so widening `rearm-sweeper.yml:1200` to `:99999` in
# .github/workflows/dashboard.yml turned that leg into a no-op with the whole suite green. This
# table is the missing independent statement — two files that must agree, which is the one shape a
# tautological assertion cannot take.
#
# DECLARED, NOT READ — so it can go stale, and nothing offline can detect that. Re-verify against
# the target repository's `.github/workflows/<workflow>` `on: schedule:` block and update this
# table whenever that cron is re-timed; a value here that is too LARGE is the dangerous direction,
# because it is what lets a threshold widen without a row going red. `rearm-sweeper.yml` is the
# 10-minute cron .github/workflows/dashboard.yml's own cross-repo step comment records (the merge-
# queue closure backstop in sparq-org/sparq).
_CROSS_REPO_KEEPALIVE_CADENCE_SECONDS = {
    ("sparq-org/sparq", "rearm-sweeper.yml"): 600,
}


class DashboardError(RuntimeError):
    pass


_LEASE_SCHEMA_MODULE = None


def _lease_schema_module():
    global _LEASE_SCHEMA_MODULE
    if _LEASE_SCHEMA_MODULE is None:
        path = Path(__file__).resolve().with_name("lease_schema.py")
        spec = importlib.util.spec_from_file_location("registry_lease_schema", path)
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load shared lease schema")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _LEASE_SCHEMA_MODULE = module
    return _LEASE_SCHEMA_MODULE


def _utc_iso(value):
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, (int, float)) or re.fullmatch(r"\d+(?:\.\d+)?", str(value).strip()):
            stamp = float(value)
            if stamp > 10_000_000_000:
                stamp /= 1000
            parsed = dt.datetime.fromtimestamp(stamp, tz=dt.timezone.utc)
        else:
            text = str(value).strip().replace("Z", "+00:00")
            parsed = dt.datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            parsed = parsed.astimezone(dt.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def _json_documents(text):
    decoder = json.JSONDecoder()
    documents = []
    index = 0
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index == len(text):
            break
        try:
            document, index = decoder.raw_decode(text, index)
        except json.JSONDecodeError as exc:
            raise DashboardError("JSON input is malformed") from exc
        documents.append(document)
    return documents


def _issue_list_from_text(text):
    documents = _json_documents(text)
    issues = []
    for document in documents:
        if isinstance(document, dict) and isinstance(document.get("items"), list):
            document = document["items"]
        if not isinstance(document, list):
            raise DashboardError("account issue input must contain JSON arrays")
        for item in document:
            if isinstance(item, list):
                issues.extend(row for row in item if isinstance(row, dict))
            elif isinstance(item, dict):
                issues.append(item)
    return issues


def _read_json(path, default=None, required=False):
    if path is None or not Path(path).is_file():
        if required:
            raise DashboardError(f"required JSON file is missing: {path}")
        return default
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise DashboardError(f"cannot read JSON file: {path}") from exc


def _load_gh_403():
    """Load scripts/gh_403.py (same checkout) — THE 403 taxonomy (registry #1208). By PATH, not
    `import gh_403`: `scripts/` is not a package. The `build` job takes a FULL checkout, so a
    missing file means someone made it sparse and must be told, not silently degraded to the
    unclassified message this replaces."""
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gh_403.py")
    spec = importlib.util.spec_from_file_location("registry_gh_403_for_dashboard", path)
    if spec is None or spec.loader is None:
        raise DashboardError(
            "cannot load scripts/gh_403.py — if the build job was made sparse, add "
            "scripts/gh_403.py to its sparse-checkout list in dashboard.yml")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gh_403 = _load_gh_403()

_GH_DETAIL_LIMIT = 300
_GH_TOKEN_SHAPE = re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,})\b")


def _gh_failure_suffix(result):
    """`: <class> — <masked stderr>` for a failed `gh` call, or "" when it said nothing.

    WHY. Until now this raised a bare `public account issue query failed` — no exit code, no
    status, no stderr. Measured 2026-07-28/29, dashboard.yml failed 10 times in the window and
    NOT ONE of them is classifiable after the fact.

    THE DEGRADED PATH, KNOWINGLY. `gh` stderr carries no response headers, so this uses
    `classify_403_text` and — per that function's contract — must NOT claim to have read
    `x-ratelimit-remaining`, because it has not. It also establishes the STATUS first, which the
    classifier requires of its caller: without a `(HTTP 403)` marker an unrelated failure whose
    message happens to say "retry later" would be labelled a rate limit."""
    text = " ".join((result.stderr or "").split())
    parts = [f"rc={result.returncode}"]
    if "(HTTP 403)" in text or "HTTP 403" in text:
        parts.append(gh_403.classify_403_text(text) + " (classified from gh stderr; no response "
                     "headers on this path, so no rate-limit count was read)")
    detail = _GH_TOKEN_SHAPE.sub("***", text)
    if len(detail) > _GH_DETAIL_LIMIT:
        detail = detail[:_GH_DETAIL_LIMIT] + "…"
    if detail:
        parts.append(detail)
    return ": " + " — ".join(parts)


def _fetch_issues(repo):
    if not repo or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repo):
        raise DashboardError("REGISTRY_REPO must be an owner/repository name")
    result = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{repo}/issues?state=open&per_page=100"],
        capture_output=True, text=True, timeout=90, check=False)
    if result.returncode != 0:
        raise DashboardError("public account issue query failed" + _gh_failure_suffix(result))
    return _issue_list_from_text(result.stdout)


def _front_matter(body):
    fields = {}
    limits = {}
    for line in (body or "").splitlines():
        if ":" not in line:
            continue
        key, _, raw = line.partition(":")
        key, value = key.strip(), raw.strip()
        if key in {"provider", "models", "secret_ref", "email"}:
            fields[key] = value.strip('"\'')
        elif key == "limits":
            try:
                parts = shlex.split(value)
            except ValueError:
                parts = []
            for part in parts:
                limit_key, separator, limit_value = part.partition("=")
                if (separator and limit_key in {f"{prefix}_limit" for prefix, _ in WINDOWS}
                        and 0 < len(limit_value) <= 80 and limit_value.isprintable()):
                    limits[limit_key] = limit_value
    fields["limits"] = limits
    return fields


def _labels(issue):
    names = set()
    for label in issue.get("labels") or []:
        name = label.get("name") if isinstance(label, dict) else label
        if isinstance(name, str):
            names.add(name.strip().lower())
    return names


def _catalog(issues):
    accounts = []
    private_values = set()
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        handle = str(issue.get("title") or "").strip()
        fields = _front_matter(issue.get("body"))
        provider = str(fields.get("provider") or "").lower()
        models = fields.get("models") or ""
        secret_ref = fields.get("secret_ref") or ""
        if (not handle or SAFE_PROVIDER_RE.fullmatch(provider) is None or not models.startswith("[")
                or ACCOUNT_REF_RE.fullmatch(secret_ref) is None):
            continue
        labels = _labels(issue)
        accounts.append({
            "handle": handle,
            "provider": provider,
            "catalog_available": "status:available" in labels,
            "limits": fields["limits"],
        })
        private_values.add(handle)
        if fields.get("email"):
            private_values.add(fields["email"])
    accounts.sort(key=lambda account: (account["provider"], account["handle"]))
    return accounts, private_values


def _require_salt(salt):
    """Issue #184's fail-closed salt precondition, RETAINED after #374 removed the last
    handle-derived label from the payload. It no longer guards a value this build publishes; it
    guards the ENVIRONMENT. A dashboard that builds happily with PROVENANCE_SALT unset is exactly
    the environment in which a re-added account label would be published unsalted (the pre-#184 bug
    deployed literal `salt-missing` rows, pinning a public row to a single account with no salt at
    all). One string check, and the whole build dies rather than proceeding unsalted."""
    if not isinstance(salt, str) or not salt.strip() or not salt.isprintable():
        raise DashboardError(
            "the dashboard build requires a non-empty printable PROVENANCE_SALT (issue #184)")


def _percent(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not (number >= 0) or number == float("inf"):
        return None
    return round(number * 100, 1)


def _availability(account, usage_entry):
    if not account["catalog_available"]:
        return "unavailable"
    if not isinstance(usage_entry, dict) or not usage_entry:
        # NO measurement exists for this account (issue #219). account-usage.py fail-closed OMITS an
        # account whose token is missing or whose probe failed, and a wholly failed probe publishes
        # an EMPTY map — so this branch is exactly the "measurement did not happen" case. It used to
        # return "available", which is why a failed probe rendered the entire catalog as fresh
        # usable capacity. Dispatch (select-and-claim.usage_eligible) treats the omission as
        # INELIGIBLE, so the honest public label is "unknown", never "available".
        return "unknown"
    status = str(usage_entry.get("status") or "").strip().lower()
    if status not in {"", "allowed"}:
        return "unavailable"
    known = [_percent(usage_entry.get(f"{prefix}_util")) for prefix, _ in WINDOWS]
    if any(value is not None and value >= 100 for value in known):
        return "capped"
    return "available"


_SELECT_AND_CLAIM_MODULE = None


def _select_and_claim_module():
    """Load scripts/select-and-claim.py (hyphenated name — importlib, the _model_health_module
    pattern) so the ALLOCATOR'S backoff-stamp parsing semantics are SHARED, not re-implemented
    here where they would drift (sol finding 3, PR #281 fix round)."""
    global _SELECT_AND_CLAIM_MODULE
    if _SELECT_AND_CLAIM_MODULE is None:
        path = Path(__file__).resolve().with_name("select-and-claim.py")
        spec = importlib.util.spec_from_file_location("registry_select_and_claim", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _SELECT_AND_CLAIM_MODULE = module
    return _SELECT_AND_CLAIM_MODULE


def _backoff_epoch(value):
    """A backoff_until stamp parsed with the ALLOCATOR'S semantics, or None (fail open):
    select-and-claim.usage_eligible admits the stamp iff `_usage_num` parses it AND it is
    finite. This dashboard used to diverge both ways — it accepted Infinity/absurd integers
    (rendering "capped indefinitely" while the allocator failed open and kept using the
    account) and ignored parseable string epochs (rendering "available" while the allocator
    backed off). The self-test's parity vector locks the two scripts to one predicate."""
    number = _select_and_claim_module()._usage_num(value)
    if number is None or not math.isfinite(number):
        return None
    return number


def _quota_state(account, entry, now):
    """Availability for the CUMULATIVE provider view AND (since issue #219) for the per-account
    cards + `fleet.capacity.eligible`, so one predicate decides every "is this capacity usable"
    claim on the public page: the per-account state from _availability — where (a) a
    catalog-available account with NO usage entry is already "unknown", because the probe
    fail-closed OMITS an account whose token is missing or whose probe failed and dispatch
    (select-and-claim.usage_eligible) plus usage-alert treat that omission as UNAVAILABLE, so
    counting it free would advertise quota the allocator will never use (sol finding 2, PR #281
    fix round) — refined so that (b) a probe-exempt account under an ACTIVE reactive
    backoff (its only quota signal — issue #29) counts as capped until the backoff expires,
    with the stamp parsed by the allocator's shared `_backoff_epoch` semantics; and (c) a
    non-exempt account counts "available" only with BOTH mandatory windows (5h AND 7d) validly
    reported — account-usage.py can emit a PARTIAL entry (status-only, or one window without
    the other), and dispatch (usage_eligible: `util is None` → ineligible) plus usage-alert
    (classify: `u5 is None or u7 is None` → UNAVAILABLE) both fail closed on that shape, so
    rendering it free would again advertise quota the allocator will never use (sol finding 1,
    PR #281 fix round 3); partial ⇒ "unknown". Returns (state, backoff_epoch_or_None).
    Pure — unit-tested by --self-test."""
    if not isinstance(entry, dict) or not entry:
        # No measurement at all. _availability already answers "unknown"/"unavailable" here; the
        # restatement keeps this function TOTAL (every dict access below is unreachable on a
        # non-dict) rather than resting on a caller-invisible coupling to that branch.
        return _availability(account, entry), None
    availability = _availability(account, entry)
    if availability != "available":
        return availability, None
    if entry.get("exempt") is True:
        # [registry #639] Exemption skips the QUOTA probe; it never asserts reachability. The page
        # must not publish as capacity what dispatch refuses to use, in EITHER direction (sol finding
        # 2, PR #281), so the same allowlist the allocator applies decides here: a credential the
        # health record proves dead is `unavailable` (a rejected credential, exactly like a non-allowed
        # probe status), and an entry that states no reachability at all is `unknown` (the producer did
        # not evaluate it — no measurement to publish), never `available`.
        reachability = entry.get("reachability")
        if reachability == _select_and_claim_module().USAGE_REACHABILITY_DEAD:
            return "unavailable", None
        if not isinstance(reachability, str) or \
                reachability not in _select_and_claim_module().USAGE_REACHABILITY_ADMITTED:
            return "unknown", None
        until = _backoff_epoch(entry.get("backoff_until"))
        if until is not None and until > now:
            return "capped", until
        return "available", None
    if any(_percent(entry.get(f"{prefix}_util")) is None for prefix in ("5h", "7d")):
        return "unknown", None
    return "available", None


def _quota_probe_signal(probe):
    """The provider-row `signal` for a snapshot the probe verdict DISTRUSTED (issue #628).

    When `_probe_outcome` says the snapshot was not measured, build_dashboard discards the usage
    map, so every provider row used to fall through to the "no live usage signal (catalog
    availability only)" wording — the SAME string a provider that genuinely exposes no usage
    headers emits, and one that still implies catalog availability is the signal (it is
    deliberately not counted as free any more). The reason word tracks the normalized outcome so
    "the probe reported a failure", "the last success is too old" and "no usable sidecar exists"
    stay distinguishable on the row itself. Pure — unit-tested by --self-test."""
    outcome = probe.get("outcome") if isinstance(probe, dict) else None
    if outcome == "failed":
        reason = "usage probe failed"
    elif outcome == "ok":
        # `ok` but not measured can only mean the freshness check rejected the stamp.
        reason = "usage probe is stale"
    else:
        reason = "usage probe outcome is unknown"
    return (f"{reason} — no measurement for this snapshot "
            "(catalog availability is not counted as free)")


def _provider_quota(accounts, usage, now, probe=None):
    """Per-provider CUMULATIVE quota rows (maintainer request 2026-07-18): where a provider has
    several accounts, the AGGREGATE headroom across them; single-account providers still emit a
    row, marked `single_account`. HONEST aggregation of the signals that actually exist — no
    invented precision:

    * Probed (anthropic) accounts expose per-window utilization FRACTIONS (plus a raw unit-less
      `*-limit` header value when the provider sends one), so the aggregate unit is
      "account-windows free": Σ over reporting accounts of that account's remaining window
      fraction (a provider with 2.4 of 3 account-windows free has, e.g., one fresh account, one
      at 60% and one capped). `limit_remaining` additionally sums limit×remaining, but ONLY over
      the accounts whose limit header is known — `limits_known`/`accounts_reporting` says how
      partial that sum is, and its unit is whatever the provider's opaque limit header means.
    * Probe-exempt providers (openai) have NO usage observability at all (issue #29): the row
      aggregates only the availability trichotomy + active reactive backoffs, and `signal` says
      so — `windows` stays empty rather than fabricating a remaining-quota number.

    Accounts fail-closed omitted from the usage snapshot count in `accounts_total` and in
    `accounts_unknown` ("unreported" — dispatch treats the omission as unavailable, so they are
    NEVER counted free), and never in `accounts_reporting`. The same holds for PARTIAL probe
    entries (quota state "unknown"): the whole account is excluded from the aggregation — its
    parseable window contributes NOTHING to the window sums, `limit_remaining`/`limits_known`,
    or the reset stamps (sol finding, PR #281 fix round 4: a 5h-only entry used to render
    "accounts_unknown: 1" NEXT TO headroom summed from that very account). The exclusion is
    keyed off the SAME `_quota_state` result as the counts — one source of truth, no
    re-derivation. `soonest_reset`/`oldest_reset` span
    every known window-reset/backoff stamp for the provider: soonest = the first moment ANY
    quota refills, oldest = when the last known window has refilled. Pure — unit-tested by
    --self-test; rows carry provider names + counts only (decision 22: no account identifiers,
    salted or otherwise, on this surface).

    `probe` is the normalized probe verdict (`_probe_outcome`) for the snapshot, when the caller
    has one. It changes NO count — the counts already fail closed on the empty map build_dashboard
    hands over — only the `signal` label, which must name the broken probe instead of borrowing the
    "this provider exposes no usage headers" wording (issue #628). A distrusted verdict takes
    precedence over the probed/exempt derivation below, because both of those are read out of the
    very snapshot the verdict rejected: the row must never claim a live measurement it cannot back.

    These rows are INTERNAL as of issue #374. The counts below are the source of truth for the
    capacity decision and are asserted in both directions by the suite, but they are never
    published: build_dashboard emits `_public_provider_quota(_provider_quota(...))`, which keeps the
    operational answer and drops every field that reads out the fleet's size."""
    # #628: `probe=None` means "the caller stated nothing about the probe" and leaves the labels
    # exactly as they were; any verdict that is not an explicit measurement distrusts the snapshot.
    distrusted = probe is not None and not (isinstance(probe, dict) and probe.get("measured") is True)
    groups = {}
    for account in accounts:
        groups.setdefault(account["provider"], []).append(account)
    rows = []
    for provider in sorted(groups):
        members = groups[provider]
        counts = {"available": 0, "capped": 0, "unavailable": 0, "unknown": 0}
        probed = exempt = False
        stats = {prefix: {"reporting": 0, "remaining": 0.0, "limits_known": 0,
                          "limit_remaining": 0.0, "resets": []}
                 for prefix, _ in WINDOWS}
        provider_resets = []
        for account in members:
            entry = usage.get(account["handle"])
            state, backoff_until = _quota_state(account, entry, now)
            counts[state] += 1
            backoff_iso = _utc_iso(backoff_until)
            if backoff_iso:
                provider_resets.append(backoff_iso)
            if not isinstance(entry, dict):
                continue
            if entry.get("exempt") is True:
                exempt = True
            elif entry:
                probed = True
            if state == "unknown":
                # An "unknown" account (PARTIAL probe entry — e.g. 5h-only) contributes NOTHING
                # to the aggregate (sol finding, PR #281 fix round 4): its parseable window used
                # to leak into the sums, rendering "accounts_unknown: 1" next to account-window
                # headroom from that same account. Keyed off the _quota_state result above —
                # the single source of truth the counts already use, not a re-derivation.
                continue
            for prefix, _name in WINDOWS:
                used = _percent(entry.get(f"{prefix}_util"))
                if used is None:
                    continue
                window = stats[prefix]
                window["reporting"] += 1
                remaining = max(0.0, 100.0 - used) / 100.0
                window["remaining"] += remaining
                limit = entry.get(f"{prefix}_limit")
                if limit is None:
                    limit = account["limits"].get(f"{prefix}_limit")
                try:
                    limit_number = float(limit)
                except (TypeError, ValueError, OverflowError):
                    # OverflowError (sol finding 2, PR #281 fix round 3): a huge-int limit
                    # (10**400) is valid JSON but float() of it RAISES rather than returning
                    # inf — same trap select-and-claim._usage_num already guards.
                    limit_number = None
                if limit_number is not None and math.isfinite(limit_number) and limit_number >= 0:
                    # Individually-finite limits can still overflow the WEIGHTED SUM (two
                    # "1e308" limits are each finite but their sum is inf), and round(inf) at
                    # render would crash the whole dashboard build on one malformed account
                    # record (sol finding 2, PR #281 fix round 3). Validate the product AND
                    # the running sum; on overflow, reject THIS account's limit contribution
                    # (its limit stays unknown — not in limits_known) and keep the build alive.
                    product = limit_number * remaining
                    if math.isfinite(product) and math.isfinite(window["limit_remaining"] + product):
                        window["limits_known"] += 1
                        window["limit_remaining"] += product
                # _utc_iso emits a fixed-width "...Z" format, so lexicographic min/max below is
                # chronological.
                reset_iso = _utc_iso(entry.get(f"{prefix}_reset"))
                if reset_iso:
                    window["resets"].append(reset_iso)
                    provider_resets.append(reset_iso)
        windows = []
        for prefix, name in WINDOWS:
            window = stats[prefix]
            if not window["reporting"]:
                continue  # nothing measured for this window (e.g. fable on a non-fable provider)
            windows.append({
                "name": name,
                "accounts_reporting": window["reporting"],
                "remaining_account_windows": round(window["remaining"], 2),
                "limit_remaining": round(window["limit_remaining"])
                if window["limits_known"] else None,
                "limits_known": window["limits_known"],
                "soonest_reset": min(window["resets"], default=None),
                "oldest_reset": max(window["resets"], default=None),
            })
        if distrusted:
            signal = _quota_probe_signal(probe)
        elif probed and exempt:
            signal = "mixed: live rate-limit-header probe + probe-exempt accounts"
        elif probed:
            signal = "live rate-limit-header probe (per-window utilization)"
        elif exempt:
            signal = ("not observable (probe-exempt provider): catalog availability "
                      "+ reactive rate-limit backoff only")
        else:
            signal = "no live usage signal (catalog availability only)"
        rows.append({
            "provider": provider,
            "accounts_total": len(members),
            "accounts_available": counts["available"],
            "accounts_capped": counts["capped"],
            "accounts_unavailable": counts["unavailable"],
            "accounts_unknown": counts["unknown"],
            "single_account": len(members) == 1,
            "signal": signal,
            "windows": windows,
            "soonest_reset": min(provider_resets, default=None),
            "oldest_reset": max(provider_resets, default=None),
        })
    return rows


def _provider_headroom(row):
    """The cardinality-free replacement for a provider row's five-number account census (#374):
    WHETHER this provider has usable headroom right now and, when it does not, why. A strict
    function of the same counts `fleet.capacity` and the allocator key off — so the page still
    cannot advertise capacity dispatch would refuse — but four words instead of a fleet census.
    Precedence is "can we dispatch?" first, then the most actionable reason: capped refills at
    `soonest_reset`, unknown means the probe told us nothing, unavailable means the catalog or a
    dead credential took the provider out."""
    if row["accounts_available"]:
        return "available"
    if row["accounts_capped"]:
        return "capped"
    if row["accounts_unknown"]:
        return "unknown"
    return "unavailable"


def _public_provider_quota(rows):
    """Project the internal provider rows onto the published payload (#374).

    Dropped outright: accounts_total/available/capped/unavailable/unknown, single_account,
    accounts_reporting, limit_remaining, limits_known. Every one is either a count of accounts or
    a sum whose magnitude scales with the number of accounts (`limit_remaining` is Σ limit×remaining
    over reporting accounts, so a publicly-known plan limit divides straight back out to a fleet
    size). `remaining_account_windows` was itself Σ of per-account fractions and therefore bounded
    ABOVE by the fleet size — 2.4 said "at least 3 accounts" out loud — so it is published as the
    MEAN remaining fraction instead: same headroom reading, invariant under cloning the fleet."""
    public = []
    for row in rows:
        windows = []
        for window in row["windows"]:
            reporting = window["accounts_reporting"]
            if reporting <= 0:
                continue    # _provider_quota never emits one; never divide by it if it ever does
            windows.append({
                "name": window["name"],
                "remaining_fraction": round(
                    window["remaining_account_windows"] / reporting, 2),
                "soonest_reset": window["soonest_reset"],
                "oldest_reset": window["oldest_reset"],
            })
        public.append({
            "provider": row["provider"],
            "headroom": _provider_headroom(row),
            "signal": row["signal"],
            "windows": windows,
            "soonest_reset": row["soonest_reset"],
            "oldest_reset": row["oldest_reset"],
        })
    return public


def _public_capacity(capacity):
    """fleet.capacity, cardinality-free (#374): per provider, WHETHER the allocator would find an
    eligible account right now — not how many eligible out of how many held."""
    return {provider: values["eligible"] > 0 for provider, values in capacity.items()}


def _assert_no_fleet_composition(document):
    """Fail-closed backstop over the FINISHED public document (#374) — the composition twin of
    _assert_private. Every name in FLEET_COMPOSITION_KEYS was, until this change, a published read
    of the fleet's size or of one identified account; `accounts` and `label` additionally catch a
    re-introduced per-account row array (the shape both the account cards and the observability
    lease rows used). Refusing the build is the point: the projection above is easy to bypass by
    adding one key to the document literal, and a public-surface regression that only prose forbids
    is a regression waiting to happen."""
    found = set()

    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in FLEET_COMPOSITION_KEYS:
                    found.add(key)
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(document)
    if found:
        raise DashboardError(
            "fleet-composition assertion failed: the public dashboard payload may not disclose "
            f"{sorted(found)} (issue #374)")


# --- WIRING ASSERTIONS: reading the workflow / the page script without letting a comment or a
# neighbouring occurrence stand in for the call site under test. ------------------------------------
#
# #612 cross-provider review round 2 (class E). A mutation harness found that 18/18 mutations
# against this repo's PYTHON guards were caught while EVERY surviving mutation was a workflow `if:`,
# a workflow step body, or a production call site. Concretely, on this PR: dropping the `!` from the
# probe step's snapshot condition, replacing the materialization step's body with `true`, deleting
# `probe_status=probe_status` from `main()`, and deleting `summary.append(probe)` /
# `updateFreshness(..., data.usage_probe)` from the page script all left the suite green. These
# helpers exist so the assertions below are scoped to ONE step or ONE function — a whole-file
# substring search is satisfiable by prose or by any of several other occurrences — and so the
# probe step's shell body can be EXECUTED rather than pattern-matched (`bash -n` and actionlint
# cannot see polarity). Every helper raises DashboardError when it cannot resolve its target: a
# wiring assertion that cannot find what it is asserting about must fail, never pass vacuously.
def _repo_file(*parts):
    """Text of a repository file addressed relative to the repo root, independent of cwd.

    Used both by the wiring assertions below and, since issue #78, by the BUILD itself to read the
    worker policy the per-repository census seeds its rows from — hence the neutral message: either
    caller must fail loudly when the file is not there, never continue on a default."""
    path = Path(__file__).resolve().parent.parent.joinpath(*parts)
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DashboardError(f"cannot read the repository file {path}") from exc


def _strip_yaml_comments(text):
    """`text` with every whole-line `#` comment removed (YAML comments and, inside `run:` blocks,
    shell/python comments alike). A claim in prose must never satisfy an assertion about code."""
    return "\n".join(line for line in text.split("\n") if not line.lstrip().startswith("#"))


def _cron_minutes(expression):
    """The set of minutes-past-the-hour one `on: schedule:` cron fires at.

    Only pure minute-field schedules are expressible; any other field carrying a value is a
    REFUSAL. A cadence this reader silently mis-derives would make the #680 threshold bound it
    feeds satisfiable by any threshold at all, so it must fail rather than guess."""
    fields = expression.split()
    if len(fields) != 5 or any(field != "*" for field in fields[1:]):
        raise DashboardError(
            f"cron {expression!r} is not a pure minute-field schedule — refusing to derive a "
            "nominal cadence from it (fail closed)")
    minutes = set()
    for term in fields[0].split(","):
        base, _, raw_step = term.partition("/")
        if raw_step:
            if not raw_step.isdigit() or int(raw_step) < 1:
                raise DashboardError(f"cron {expression!r}: unreadable step in {term!r} — refusing")
            step = int(raw_step)
        else:
            step = 1
        if base == "*":
            low, high = 0, 59
        else:
            low_text, dash, high_text = base.partition("-")
            high_text = high_text if dash else low_text
            if not (low_text.isdigit() and high_text.isdigit()):
                raise DashboardError(
                    f"cron {expression!r}: unreadable minute term {term!r} — refusing")
            low, high = int(low_text), int(high_text)
        if not 0 <= low <= high <= 59:
            raise DashboardError(
                f"cron {expression!r}: minute term {term!r} out of range — refusing")
        minutes.update(range(low, high + 1, step))
    if not minutes:
        # Unreachable under the grammar above (an accepted term always has low <= high, so it
        # contributes at least one minute) and kept as the structural backstop for a future term
        # form that does not: an empty firing set would otherwise reach the wrap-around gap in
        # _cron_cadence_seconds as an IndexError rather than as a named refusal.
        raise DashboardError(f"cron {expression!r} fires at no minute at all — refusing")
    return minutes


def _cron_cadence_seconds(*expressions):
    """The NOMINAL gap, in seconds, between consecutive fires of a set of hourly crons.

    The WIDEST gap in the union of their firing minutes (the wrap-around gap from the last minute
    of one hour to the first of the next included) — that is the interval a keepalive threshold has
    to clear, so the widest is the only safe reading."""
    if not expressions:
        raise DashboardError("no cron expression supplied — refusing to invent a cadence")
    minutes = set()
    for expression in expressions:
        minutes.update(_cron_minutes(expression))
    fires = sorted(minutes)
    gaps = [later - earlier for earlier, later in zip(fires, fires[1:])]
    gaps.append(fires[0] + 60 - fires[-1])
    return max(gaps) * 60


def _schedule_cadence_seconds(text, label):
    """The nominal cadence of one workflow YAML's `on: schedule:` block.

    Split from the file read below purely so its two refusal branches are reachable from the
    self-test: a refusal nothing ever executes is a refusal nothing has checked. The scan is
    bounded to the top-level `on:` block, so a `cron:` in prose or in some other mapping cannot
    supply the cadence a keepalive threshold is then sized against."""
    lines = _strip_yaml_comments(text).split("\n")
    heads = [index for index, line in enumerate(lines) if line.rstrip() == "on:"]
    if len(heads) != 1:
        raise DashboardError(
            f"{label} has {len(heads)} top-level `on:` blocks, expected exactly 1 — refusing")
    end = len(lines)
    for index in range(heads[0] + 1, len(lines)):
        if lines[index].strip() and not lines[index][:1].isspace():
            end = index
            break
    crons = re.findall(r"^\s*-\s*cron:\s*['\"]?([^'\"\n]+?)['\"]?\s*$",
                       "\n".join(lines[heads[0]:end]), re.MULTILINE)
    if not crons:
        raise DashboardError(
            f"{label} declares no `on: schedule:` cron — refusing to size a keepalive threshold "
            "against a workflow that has no schedule for the keepalive to be a fallback to")
    return _cron_cadence_seconds(*crons)


def _workflow_cadence_seconds(workflow):
    """The nominal cadence of `.github/workflows/<workflow>`, read out of THAT file's own
    `on: schedule:` block.

    Never restated here: the whole point of the #680 bound is that a re-timed cron and the
    keepalive threshold sized against it cannot drift apart silently."""
    return _schedule_cadence_seconds(_repo_file(".github", "workflows", workflow), workflow)


def _workflow_step(text, step_id):
    """The full YAML text of the ONE step whose `id:` is `step_id`, comments stripped.

    Bounded by the enclosing `- ` sequence entry's indentation, so a call in a NEIGHBOURING step
    cannot satisfy an assertion about this one."""
    lines = text.split("\n")
    marks = [index for index, line in enumerate(lines) if line.strip() == f"id: {step_id}"]
    if len(marks) != 1:
        raise DashboardError(
            f"expected exactly one workflow step with `id: {step_id}`, found {len(marks)} — "
            "refusing to assert against a step that cannot be located (fail closed)")
    starts = [index for index in range(marks[0], -1, -1) if lines[index].lstrip().startswith("- ")]
    if not starts:
        raise DashboardError(f"step `id: {step_id}` has no enclosing `- ` sequence entry — refusing")
    start = starts[0]
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if not line.strip():
            continue
        here = len(line) - len(line.lstrip())
        if here < indent or (here == indent and line.lstrip().startswith("- ")):
            end = index
            break
    body = _strip_yaml_comments("\n".join(lines[start:end]))
    if not body.strip():
        raise DashboardError(f"step `id: {step_id}` extracted to an empty body — refusing")
    return body


def _workflow_step_block(text, step_id, key):
    """The dedented block-scalar value of `<key>: |` inside the step whose `id:` is `step_id`.

    Raises when the step has no such block or the block is empty — a step body that cannot be
    recovered must not silently become a no-op the harness then 'passes'."""
    lines = _workflow_step(text, step_id).split("\n")
    wanted = {f"{key}: |", f"{key}: |-"}
    starts = [index for index, line in enumerate(lines) if line.strip() in wanted]
    if len(starts) != 1:
        raise DashboardError(
            f"step `id: {step_id}` has {len(starts)} block `{key}:` values, expected exactly 1")
    head = starts[0]
    indent = len(lines[head]) - len(lines[head].lstrip())
    body = []
    for line in lines[head + 1:]:
        if line.strip() and (len(line) - len(line.lstrip())) <= indent:
            break
        body.append(line[indent + 2:] if line.strip() else "")
    value = "\n".join(body)
    if not value.strip():
        raise DashboardError(
            f"step `id: {step_id}` extracted to an empty `{key}:` block — refusing")
    return value


def _workflow_step_script(text, step_id):
    """The EXECUTABLE `run:` script of the step whose `id:` is `step_id`, dedented.

    Comments are NOT kept — this text comes through _workflow_step, which strips them (the round-4
    correction of an earlier docstring that claimed otherwise). That is harmless for execution and
    is the point for pattern-matching, so the two uses share one extractor."""
    return _workflow_step_block(text, step_id, "run")


def _workflow_step_mapping(text, step_id, key):
    """The `<key>:` mapping of the step whose `id:` is `step_id`, as {name: raw value text}.

    #612 review round 4: deleting `SECRETS_STEP_OUTCOME: ${{ steps.acct-secrets.outcome }}` from the
    probe step survived the suite, because the executed body reads the variable from the process
    environment the HARNESS supplies — execution can never see a missing workflow-level wiring. A
    mapping (rather than a substring search) is what makes "this step defines this variable, from
    that step's outcome" falsifiable, and resolving the step id it names is what stops the wiring
    from pointing at a step that no longer exists.

    #935 review round 1 shares the reader with `with:`: an action's INPUTS are wiring by exactly
    the same argument — nothing a harness can execute observes which owner/repository/permission a
    mint step asked for, so the only place that is falsifiable is the YAML."""
    lines = _workflow_step(text, step_id).split("\n")
    heads = [index for index, line in enumerate(lines) if line.strip() == f"{key}:"]
    if len(heads) != 1:
        raise DashboardError(
            f"step `id: {step_id}` has {len(heads)} `{key}:` mappings, expected exactly 1")
    head = heads[0]
    indent = len(lines[head]) - len(lines[head].lstrip())
    mapping = {}
    for line in lines[head + 1:]:
        if not line.strip():
            continue
        if (len(line) - len(line.lstrip())) <= indent:
            break
        name, separator, value = line.strip().partition(":")
        if separator:
            mapping[name.strip()] = value.strip()
    if not mapping:
        raise DashboardError(f"step `id: {step_id}` has an empty `{key}:` mapping — refusing")
    return mapping


def _workflow_step_env(text, step_id):
    """The `env:` mapping of the step whose `id:` is `step_id`, as {NAME: raw expression text}."""
    return _workflow_step_mapping(text, step_id, "env")


def _workflow_step_key(text, step_id, key):
    """The raw scalar value of the step's OWN top-level `<key>:`, or None when it has none.

    #935: executing a step body — which is all a hermetic shell harness can do — can never see the
    `if:` that decides whether production runs that body at all. Bounded to the step's own key
    column, so a `key:` nested under `with:`/`env:` cannot satisfy an assertion about the step
    itself, and two of them at that column is a refusal rather than a first-wins guess."""
    lines = _workflow_step(text, step_id).split("\n")
    indent = len(lines[0]) - len(lines[0].lstrip()) + 2
    values = []
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        # The `- ` of the sequence entry carries the step's first key two columns right of the
        # dash — the same column every later key sits at.
        here = (" " * indent + line.lstrip()[2:]
                if index == 0 and line.lstrip().startswith("- ") else line)
        if len(here) - len(here.lstrip()) != indent:
            continue
        name, separator, value = here.strip().partition(":")
        if separator and name.strip() == key:
            values.append(value.strip())
    if len(values) > 1:
        raise DashboardError(
            f"step `id: {step_id}` has {len(values)} top-level `{key}:` keys, expected at most 1")
    return values[0] if values else None


def _js_function_body(text, name):
    """The brace-matched body of `function <name>(...)` in a JS source, or raise.

    Scoping a call-site assertion to ONE function is the difference between "this file mentions
    updateFreshness" and "render() passes the probe to it": `grant-account.py` appears 7× in its
    own workflow, and whole-file greps on repeated tokens are exactly the vacuity #612 round 2
    flagged."""
    marks = [match.start() for match in re.finditer(rf"\bfunction\s+{re.escape(name)}\s*\(", text)]
    if len(marks) != 1:
        raise DashboardError(
            f"expected exactly one `function {name}(` definition, found {len(marks)} — refusing")
    open_brace = text.find("{", marks[0])
    if open_brace < 0:
        raise DashboardError(f"`function {name}(` has no body — refusing")
    depth, index = 0, open_brace
    while index < len(text):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace:index + 1]
        index += 1
    raise DashboardError(f"`function {name}(` body is unbalanced — refusing")


def _js_code_count(text, needle):
    """Occurrences of `needle` at CODE positions of `text`: comments are blanked out first, and a
    match that BEGINS inside a string/template literal does not count.

    #612 review round 4 (MINOR, class E): the round-3 UI assertions were satisfiable by a COMMENT —
    commenting out `summary.append(probe)` kept the suite green while the operator warning was gone —
    and by any string literal that happened to contain the needle. Counting only code positions
    closes both, and asserting an exact COUNT (rather than presence) is what stops a neighbouring
    branch's occurrence from standing in for the one under test."""
    chars = list(text)
    in_string = [False] * len(text)
    index, quote, comment = 0, None, None
    while index < len(text):
        char, pair = text[index], text[index:index + 2]
        if comment == "line":
            if char == "\n":
                comment = None
            else:
                chars[index] = " "
            index += 1
        elif comment == "block":
            if pair == "*/":
                chars[index] = chars[index + 1] = " "
                comment = None
                index += 2
                continue
            if char != "\n":
                chars[index] = " "
            index += 1
        elif quote:
            in_string[index] = True
            if char == "\\":
                if index + 1 < len(text):
                    in_string[index + 1] = True
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
        elif pair == "//":
            comment = "line"
        elif pair == "/*":
            comment = "block"
        elif char in "\"'`":
            quote, in_string[index] = char, True
            index += 1
        else:
            index += 1
    code = "".join(chars)
    hits, at = 0, code.find(needle)
    while at >= 0:
        if not in_string[at]:
            hits += 1
        at = code.find(needle, at + 1)
    return hits


def _node_json(script, payload):
    """Run `script` under `node` with `payload` on stdin and parse its stdout as JSON, or raise.

    #612 review round 4: the page's consumption of the probe marker was asserted LEXICALLY, so
    flipping `if (!measured)` to `if (measured)` survived. `node` is present on every runner this
    suite runs on (ubuntu-latest, and the worker image copies it in), so the two call sites are
    EXECUTED instead — and a missing interpreter fails the suite loudly rather than skipping a
    check, which would be the same false pass in a different costume."""
    try:
        completed = subprocess.run(["node", "-e", script], input=json.dumps(payload),
                                   capture_output=True, text=True, timeout=120, check=False)
    except OSError as exc:
        raise DashboardError(
            "`node` is required to EXECUTE the dashboard page's probe call sites — refusing to "
            f"skip that assertion ({exc})") from exc
    if completed.returncode != 0:
        raise DashboardError(
            f"the page-script harness exited {completed.returncode}: {completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise DashboardError(
            f"the page-script harness printed no parseable result: {completed.stdout!r}") from exc


class _RaisedPage(str):
    """Stand-in for a page script that threw: EVERY lookup below yields the diagnostic itself.

    Issue #1341. The sibling harnesses compare the whole page object, or read it through a
    `.get`-based helper, so a plain-dict fallback is enough there. The executed-page block that
    consumes `_executed_page` subscripts the page directly (`page["cards"]["measured"]["deg…"]`),
    where a dict fallback would raise `KeyError` and abort the suite exactly as the unguarded call
    did. Returning self from every `[...]`/`.get` instead keeps every row below reachable: each one
    compares this diagnostic against its expected tuple and goes red BY NAME, and the suite still
    reaches its full check count."""

    def __getitem__(self, key):
        return self

    def get(self, key, default=None):
        return self


def _executed_page(harness, payload):
    """`_node_json(harness, payload)`, with a page that THROWS reported as a VALUE, never an abort.

    Issue #1341. A renderer that reaches a DOM API the shim does not implement — or a mutant that
    drops an exported symbol from the harness's `new Function(... return {...})` list — otherwise
    raises out of `_self_test` and terminates the run: every check below it never executes, while a
    mutation run scores the abort as a KILL (AGENTS.md AUTHOR pre-flight item 4,
    *crash-after-partial-run*). It also loses the diagnostic — an abort names the exception, a red
    row names WHICH assertion the broken page failed. So the raise becomes the rows' value."""
    try:
        return _node_json(harness, payload)
    except DashboardError as exc:
        return _RaisedPage(f"page script raised: {str(exc)[:160]}")


def _probe_epoch(value):
    """`value` as a UTC epoch second, reusing _utc_iso's tolerant epoch/ISO parsing, or None."""
    iso = _utc_iso(value)
    if iso is None:
        return None
    return dt.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def _probe_outcome(document, now):
    """Normalize the probe job's persisted outcome sidecar, FAIL-CLOSED (issue #219).

    `measured` is True ONLY for an explicit, correctly-schema'd `ok` outcome with a fresh
    attempt stamp. Every other shape — a `failed` outcome, an absent/empty/alien document, an
    unparseable or missing stamp, a stamp older than PROBE_MAX_AGE_SECONDS or implausibly far in
    the future — is "we did not measure", and build_dashboard then refuses to publish ANY account
    as usable capacity on the strength of a snapshot nobody produced. Pure — unit-tested by
    --self-test.

    `None` (no sidecar supplied at all) is the WEAKEST evidence of the lot and normalizes to the
    same unmeasured verdict as `{}` — #612 review finding 1: treating it as measured was a
    fail-open branch inside the capacity decision itself."""
    outcome, detail, attempted = "unknown", "probe outcome was not persisted", None
    if isinstance(document, dict) and document.get("schema") == PROBE_SCHEMA:
        raw = str(document.get("outcome") or "").strip().lower()
        outcome = raw if raw in {"ok", "failed"} else "unknown"
        # `detail` reaches the PUBLIC page and arrives from another job's artifact, so it is held
        # to the same bounded safe-token shape this generator uses for every externally-sourced
        # label — never published as free text.
        text = str(document.get("detail") or "").strip()
        detail = text if OBS_TOKEN_RE.fullmatch(text) else ""
        attempted = _probe_epoch(document.get("attempted_at"))
    # #612 review round 4 (MINOR): the freshness comparison runs on the EXACT age, not on a
    # truncated one — `int()` rounds toward zero, so an attempt 3600.9s old (or 300.9s in the
    # future) used to compare as 3600/-300 and stay `measured` at the nominal limit. Production
    # writes integer epochs (`date -u +%s`) so nothing was mismeasured in practice, but the
    # predicate now implements the boundary it documents. The PUBLISHED age stays an integer.
    exact_age = (now - attempted) if attempted is not None else None
    age = int(exact_age) if exact_age is not None else None
    stale = (exact_age is None or exact_age > PROBE_MAX_AGE_SECONDS
             or exact_age < -PROBE_MAX_SKEW_SECONDS)
    return {
        "outcome": outcome,
        "detail": detail,
        "attempted_at": _utc_iso(attempted),
        "age_seconds": age,
        "stale": stale,
        "measured": outcome == "ok" and not stale,
    }


def _dispatch_lane_state(planned, launched, error):
    """The DISPLAY tone for one lane's tick: ok | idle | stalled (the vocabulary the page's
    existing `.lane-dot` states already use).

    Deliberately WIDER than the ALERTING predicate, which lives in the tick-health step of
    `.github/workflows/dispatch.yml` and is the authority — it pages on a `disarm` error, or on a
    review/fix lane that planned work, launched nothing AND hit hard errors. Both of those are
    strict subsets of `error > 0 or (planned > 0 and launched == 0)`, so every lane the alert fires
    on is shown red here, and a lane merely held by capacity contention (planned, launched some,
    deferred the rest) still reads `ok`. The containment direction is the safety property: widening
    this can only over-report, narrowing it could hide a lane the alert is paging on, so it must
    never be tightened toward the workflow's predicate (the self-test pins the containment)."""
    if error > 0 or (planned > 0 and launched == 0):
        return "stalled"
    return "idle" if planned == 0 else "ok"


def _dispatch_lane_rows(log_text):
    """Per-lane tick counts (issues #108/#323) for ONE dispatch run, or None when the run printed
    none (a claim that aborted before the dispatcher finished, or a pre-#108 run).

    Read ONLY from the block after the LAST `dispatcher complete:` line. dispatch-claim prints the
    lane block immediately after that line, so the block is the dispatcher's own trusted output —
    while everything before it is a whole run's log, into which target-controlled text (an issue
    title, a rejected plan row) is echoed. Every line of a raw Actions log carries a timestamp
    prefix, so `^\\S+\\s+` alone does not make a line the dispatcher's; anchoring to the block is
    what stops an echoed string from FABRICATING a lane row (AGENTS.md pre-flight item 5: who can
    write the thing this reads?). No complete line => no lanes, rather than a scan of the log.

    The block is validated as a WHOLE, and a partial one is refused rather than trimmed (review
    round 1): the rows must be CONTIGUOUS between the `fix-dispatch:` header and the
    `defer attribution:` terminator, each must parse, none may repeat, DISPATCH_REQUIRED_LANES must
    all be present IN THAT ORDER (review round 2 — the dispatcher iterates one fixed tuple, so a
    complete-but-permuted block is one it could not have printed; unknown lanes are exempt and may
    sit anywhere), and the block may not exceed DISPATCH_LANE_CAP rows. Publishing the survivors of
    a truncated or malformed block renders the vanished lane as absent rather than unknown — which
    is exactly how a stalled review/fix lane or a failed disarm would disappear from the one cell
    built to show it — so every one of those shapes returns None and the page shows `—`. Trailing
    output cannot reach the rows either: the scan STOPS at the terminator, so a lane line echoed
    after the block cannot overwrite the dispatcher's own count for that lane."""
    complete = list(DISPATCH_COMPLETE_RE.finditer(log_text))
    if not complete:
        return None
    # `[1:]` drops the remainder of the completion line itself; last block wins, matching the
    # `complete[-1]` rule above for a log that carries more than one dispatcher run.
    lines = log_text[complete[-1].end():].splitlines()[1:]
    if not lines or not DISPATCH_FIX_LINE_RE.match(lines[0]):
        return None
    rows = {}
    for line in lines[1:]:
        if DISPATCH_LANE_END_RE.match(line):
            # Presence AND order in one comparison: `rows` keeps the block's own order, so the
            # required lanes read out of it — extra lanes dropped, they are exempt — must be the
            # authoritative tuple exactly. A short list is a missing lane, a permuted one is a
            # block the dispatcher's single loop cannot have printed; both are unknown.
            if [lane for lane in rows if lane in DISPATCH_REQUIRED_LANES] != list(
                    DISPATCH_REQUIRED_LANES):
                return None
            return list(rows.values())
        match = DISPATCH_LANE_RE.match(line)
        if match is None or match.group("lane") in rows or len(rows) >= DISPATCH_LANE_CAP:
            return None
        planned, launched, error = (int(match.group(key))
                                    for key in ("planned", "launched", "error"))
        # `deferred` is READ from the line, not re-derived: dispatch-claim derives it there
        # (planned-launched-error, clamped) and re-deriving it here would republish this build's
        # arithmetic as if it were the dispatcher's count.
        rows[match.group("lane")] = {
            "lane": match.group("lane"), "planned": planned, "launched": launched,
            "deferred": int(match.group("deferred")), "error": error,
            "state": _dispatch_lane_state(planned, launched, error)}
    return None   # ran off the end of the log: the block was truncated, so nothing is known


def _parse_dispatch_log(log_text):
    complete = DISPATCH_COMPLETE_RE.findall(log_text)
    dispatched = int(complete[-1]) if complete else len(DISPATCHED_RE.findall(log_text))
    deferred = len(DEFERRED_RE.findall(log_text))
    return dispatched, deferred, _dispatch_lane_rows(log_text)


def _run_log_counts(repo, run_id):
    result = subprocess.run(
        ["gh", "api", f"repos/{repo}/actions/runs/{run_id}/logs"],
        capture_output=True, timeout=60, check=False)
    if result.returncode != 0:
        return None, None, None
    try:
        with zipfile.ZipFile(io.BytesIO(result.stdout)) as archive:
            names = [name for name in archive.namelist()
                     if "/" in name and "Strictly validate" in name and name.endswith(".txt")]
            if not names:
                return None, None, None
            log_text = "\n".join(
                archive.read(name).decode("utf-8", errors="replace") for name in names)
    except (OSError, zipfile.BadZipFile):
        return None, None, None
    return _parse_dispatch_log(log_text)


def _fetch_dispatch_history(repo, count):
    """`(history, status)` — the newest `count` dispatch runs AND the fetch's own outcome.

    Issue #1106: both failure branches used to return a bare `[]`, which the page renders as
    "No dispatch history is available." — byte-identical to a fleet that has genuinely never
    dispatched — and which silently zeroes `fleet.last_sweep_at` as well. That is the #28 shape (an
    infra failure wearing a quiet tick's clothes) one layer out, on the PUBLIC surface. The outcome
    now travels with the rows exactly as the usage probe's does (#219/#612), so the consumer can
    tell "we read the history and it was empty" from "we could not read the history".

    `status` is the RAW claim; `_history_outcome` normalizes it fail-closed."""
    result = subprocess.run(
        ["gh", "api", f"repos/{repo}/actions/workflows/dispatch.yml/runs?per_page={count}"],
        capture_output=True, text=True, timeout=60, check=False)
    if result.returncode != 0:
        return [], {"outcome": "failed", "detail": "gh-exited-nonzero"}
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError:
        return [], {"outcome": "failed", "detail": "run-listing-unparseable"}
    # The SCHEMA is part of the read (#1748 review round 2). `gh` answers a throttled or errored
    # call with a syntactically valid document that carries no runs at all — `{}`, `{"message":
    # ...}`, `{"workflow_runs": null}` — and the old `.get(...) or []` collapsed every one of those
    # into an empty list and an `ok` outcome, i.e. the exact "infra failure wearing a quiet tick's
    # clothes" shape this issue exists to kill. A truthy non-list was worse still: a str was sliced
    # into characters that were then dropped, and a dict raised TypeError out of the whole build.
    # So: only an OBJECT whose `workflow_runs` is genuinely a list counts as read. The explicitly
    # empty list stays the successful quiet-fleet case; everything else fails closed.
    if not isinstance(document, dict) or not isinstance(document.get("workflow_runs"), list):
        return [], {"outcome": "failed", "detail": "run-listing-schema-alien"}
    runs = document["workflow_runs"]
    history = []
    for run in runs[:count]:
        if not isinstance(run, dict):
            continue
        dispatched, deferred, lanes = (None, None, None)
        if run.get("status") == "completed" and isinstance(run.get("id"), int):
            dispatched, deferred, lanes = _run_log_counts(repo, run["id"])
        history.append({
            "at": _utc_iso(run.get("run_started_at") or run.get("created_at")),
            "conclusion": str(run.get("conclusion") or run.get("status") or "unknown")[:24],
            "dispatched": dispatched,
            "deferred": deferred,
            # Issue #323: the per-lane breakdown (or None for a run that printed none), so a
            # persistently stalled review/fix lane — or a failed safety disarm, which consumes no
            # lease and is therefore invisible in `dispatched` — is legible on the ops page and not
            # only inside the model-health alert.
            "lanes": lanes,
        })
    return history, {"outcome": "ok", "detail": ""}


def _history_outcome(status):
    """Normalize the dispatch-history fetch outcome, FAIL-CLOSED (issue #1106).

    `fetched` is True ONLY for an explicit `ok` claim from the fetcher. Every other shape — a
    `failed` claim, an alien document, and `None` (no claim at all, which is the WEAKEST evidence
    of the lot — #612 review finding 1, where a `None` default selecting the trusting branch was
    the bug) — normalizes to "we did not read the history", so an empty `dispatch_outcomes` is
    never published as though it had been observed. Pure — unit-tested by --self-test.

    `detail` reaches the PUBLIC page, so it is held to the same bounded safe-token shape every
    other externally-sourced label on this document uses; it is never published as free text."""
    outcome, detail = "unknown", ""
    if isinstance(status, dict):
        raw = str(status.get("outcome") or "").strip().lower()
        outcome = raw if raw in {"ok", "failed"} else "unknown"
        text = str(status.get("detail") or "").strip()
        detail = text if OBS_TOKEN_RE.fullmatch(text) else ""
    return {"outcome": outcome, "detail": detail, "fetched": outcome == "ok"}


def _health_status(value):
    if isinstance(value, bool):
        return "healthy" if value else "unhealthy"
    text = str(value or "").strip().lower()
    if text in {"ok", "pass", "passed", "passing", "healthy", "available", "up", "success"}:
        return "healthy"
    if text in {"warn", "warning", "degraded", "partial"}:
        return "degraded"
    if text in {"fail", "failed", "failing", "unhealthy", "unavailable", "down", "error"}:
        return "unhealthy"
    return "unknown"


_MODEL_HEALTH_MODULE = None


def _model_health_module():
    """Load scripts/model-health.py (hyphenated name — importlib, same pattern as
    account-usage._load_model_health) so the ledger validator + exit-class taxonomy are SHARED,
    not re-implemented here where they would drift."""
    global _MODEL_HEALTH_MODULE
    if _MODEL_HEALTH_MODULE is None:
        path = Path(__file__).resolve().with_name("model-health.py")
        spec = importlib.util.spec_from_file_location("registry_model_health", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _MODEL_HEALTH_MODULE = module
    return _MODEL_HEALTH_MODULE


def _no_change_reason_census(records, health):
    """Issue #1827 — the DECLARED-reason distribution of the ledger's `no_change` runs.

    #738 §7 M4 asks which reasons workers actually declare when they produce no diff. The
    aggregation existed only as a line printed once per `model-health.py decide` tick, i.e. in a
    workflow log that GitHub drops after ~90 days and that nothing reads across ticks. The same
    records are already normalized here, so the distribution is published into the payload instead
    and becomes a standing board observable.

    The row set is #701's CLOSED vocabulary, read from the one module that declares it, and EVERY
    reason emits — zeroes included (AGENTS.md pre-flight item 8). A census that lists only what
    fired cannot show an operator that a reason has gone to nothing, and it disappears entirely on
    the quiet tick that is exactly when someone interrogates it.

    `runs` is the population the distribution is OF (never `total`: _assert_no_fleet_composition
    refuses that key anywhere in the public document), and `since` is the OLDEST no-change run
    counted — the honest span label, because this reader censuses whatever the ledger still
    retains rather than a window it chose. It is read off the counted rows themselves, so it never
    reports the ledger's overall span when the no-change rows cover less of it.

    An absent `why_no_diff` folds to `unspecified`, which is what index 0 of the wire vocabulary
    MEANS and what `no_change_routing.declared_reasons` already does: a run that declared nothing
    and a run that declared `unspecified` route identically, so splitting them here would publish a
    distinction the router does not make.

    [#1950] AND THE FOLD IS TOTAL — READ THIS ROW AS "DECLARED NOTHING", NEVER AS "DECLARED
    `unspecified`". A *stored* `why_no_diff == "unspecified"` is PRODUCER-UNREACHABLE: worker-live's
    `_no_change_health_envelope` builds the fields as `[("why", why)] if why else []` over the
    vocabulary INDEX, so index 0 is omitted whether the declaration was absent, unparseable, or an
    explicit `{"why": "unspecified"}` — a word the task prompt does not even offer, since it builds
    that clause from the vocabulary MINUS index 0. And that envelope is the ONLY ingress, since
    `why_no_diff` has no CLI flag on purpose (`model-health.py` `_cmd_record`). All three producer
    directions are pinned by worker-live's own self-test; `model-health`'s index-0 decode is
    FIXTURE-side coverage of a wire arm production never writes, and says so where it sits.

    So this row counts absences and nothing else, and it must not be split into stored-vs-absent:
    the stored half would be a structural zero published beside a real number, which reads as a
    measurement and is not one. The honest cost of the fold, stated because the census is a
    denominator argument: a seam that DROPPED a declared reason would land here too, so this row
    bounds "no signal" from above rather than measuring it exactly — the producer self-test above
    is what makes that a tested-against failure and not an assumption.

    Nothing model-authored crosses onto the public page (AGENTS.md pre-flight item 5 — the value
    ORIGINATES in a file the model writes). `validate_ledger` has already refused any `why_no_diff`
    outside the vocabulary, and any such field on another exit class; and the labels emitted here
    are the VOCABULARY's own strings, not the record's — a value this reader did not recognise is
    counted under `unspecified` and can never be echoed onto the page."""
    counts = {reason: 0 for reason in health.NO_CHANGE_REASONS}
    unspecified = health.no_change_routing.UNSPECIFIED
    oldest = None
    for record in records:
        if record.get("exit_class") != health.CLASS_NO_CHANGE:
            continue
        reason = record.get("why_no_diff")
        counts[reason if reason in counts else unspecified] += 1
        ts = record.get("ts")
        oldest = ts if oldest is None else min(oldest, ts)
    return {
        "runs": sum(counts.values()),
        "since": _utc_iso(oldest),
        "reasons": [{"reason": reason, "count": counts[reason]}
                    for reason in health.NO_CHANGE_REASONS],
    }


def _normalize_ledger_health(document):
    """Canonical model-health ledger, {"records": [...]} (issue #218): validate with the shared
    model-health validator — a malformed ledger fails LOUD, never renders a fabricated check —
    then derive one status per (provider, model): the NEWEST record's exit-class, folded to
    healthy/degraded/unhealthy/unknown. Records without a model alias (zero-dispatch fleet
    signals) carry no per-model information and are skipped; account hashes never reach the
    output. Output is bounded: one check per distinct (provider, model), newest 20 pairs.

    Issue #1827: the same validated records also carry the declared no-diff reason, censused by
    `_no_change_reason_census` into `no_change_reasons` — a bounded 6-row distribution, always
    present on this (ledger) path."""
    health = _model_health_module()
    try:
        records = health.validate_ledger(document)
    except ValueError as exc:
        raise DashboardError(f"model-health ledger is malformed: {exc}") from exc
    class_status = {
        health.SUCCESS: "healthy",
        health.CLASS_LIMIT: "degraded",
        health.CLASS_TRANSIENT: "degraded",
        health.CLASS_AUTH: "unhealthy",
        health.CLASS_BILLING: "unhealthy",
    }
    latest = {}
    for record in records:
        provider = str(record["provider"]).lower()
        model = str(record.get("model_alias") or "")
        if (SAFE_PROVIDER_RE.fullmatch(provider) is None
                or SAFE_MODEL_RE.fullmatch(model) is None):
            continue
        key = (provider, model)
        if key not in latest or record["ts"] >= latest[key]["ts"]:
            latest[key] = record
    newest_pairs = sorted(latest.items(), key=lambda item: item[1]["ts"], reverse=True)[:20]
    checks = sorted(({
        "model": model,
        "provider": provider,
        "status": class_status.get(record["exit_class"], "unknown"),
        "checked_at": _utc_iso(record["ts"]),
    } for (provider, model), record in newest_pairs),
        key=lambda check: (check["provider"], check["model"]))
    generated_at = _utc_iso(max((record["ts"] for record in records), default=None))
    return {"generated_at": generated_at, "checks": checks,
            "no_change_reasons": _no_change_reason_census(records, health)}


def _normalize_model_health(document):
    if document is None:
        return None
    if isinstance(document, dict) and "records" in document:
        return _normalize_ledger_health(document)
    generated_at = None
    candidates = document
    if isinstance(document, dict):
        generated_at = _utc_iso(
            document.get("generated_at") or document.get("checked_at") or document.get("timestamp"))
        candidates = next((document[key] for key in ("models", "checks", "results", "statuses")
                           if isinstance(document.get(key), (list, dict))), None)
        if candidates is None:
            candidates = {key: value for key, value in document.items()
                          if key not in {"generated_at", "checked_at", "timestamp", "schema"}}
    if isinstance(candidates, dict):
        candidates = [({"model": key, **value} if isinstance(value, dict)
                       else {"model": key, "status": value}) for key, value in candidates.items()]
    if not isinstance(candidates, list):
        candidates = []
    checks = []
    for item in candidates[:50]:
        if not isinstance(item, dict):
            continue
        model = next((item.get(key) for key in ("model", "model_id", "name", "alias")
                      if item.get(key)), None)
        if not isinstance(model, str) or SAFE_MODEL_RE.fullmatch(model) is None:
            continue
        raw_status = next((item.get(key) for key in ("status", "health", "conclusion", "outcome")
                           if key in item), item.get("healthy"))
        provider = str(item.get("provider") or "").lower()
        checks.append({
            "model": model,
            "provider": provider if SAFE_PROVIDER_RE.fullmatch(provider) else None,
            "status": _health_status(raw_status),
            "checked_at": _utc_iso(
                item.get("checked_at") or item.get("generated_at") or item.get("timestamp")),
        })
        if len(checks) == 20:
            break
    # [#1827] NULL IS NOT ZERO. These legacy/ad-hoc shapes carry no health RECORDS, so there is no
    # population to census — publishing an all-zero distribution here would read as "no worker has
    # produced a no-change run", which is a measurement this input cannot support.
    return {"generated_at": generated_at, "checks": checks, "no_change_reasons": None}


def _live_leases(leases, now):
    live = []
    for lease in leases:
        if not isinstance(lease, dict):
            raise DashboardError("lease ledger entries must be objects")
        expires_at = lease.get("expires_at")
        if (not isinstance(expires_at, (int, float)) or isinstance(expires_at, bool)):
            raise DashboardError("lease ledger entry has an invalid expiry")
        if expires_at > now:
            live.append(lease)
    return live


def _serviced_repositories(policy_text):
    """The ENABLED `[repos."owner/name"]` targets of this repo's worker policy.

    Issue #78: these are the repositories the orchestrator SERVICES, and so the rows the
    per-repository agent census must emit on EVERY tick. Before this, the census listed only the
    repositories that happened to hold a live lease, which is the #938 shape — a serviced target
    running zero agents was indistinguishable from a target that is not serviced at all, and on a
    fully quiet tick the whole table vanished. That is exactly the state an operator interrogates
    after a stall, so a zero row has to be published rather than omitted.

    Every refusal below is fail-closed on the SET: a policy this reader cannot fully understand
    would silently narrow the census (a hidden serviced repo reads as "not serviced"), so it
    refuses the build instead of publishing the rows it did manage to parse."""
    try:
        document = tomllib.loads(policy_text)
    except tomllib.TOMLDecodeError as exc:
        raise DashboardError(f"worker policy is not parseable TOML: {exc}") from exc
    rows = document.get("repos")
    if not isinstance(rows, dict) or not rows:
        raise DashboardError("worker policy carries no [repos.*] targets")
    serviced = []
    for repository, row in rows.items():
        if not isinstance(row, dict):
            raise DashboardError(f"worker policy target {repository!r} is not a table")
        enabled = row.get("enabled")
        # A non-boolean `enabled` is NOT read as "disabled": guessing here drops a serviced
        # repository off the census, which is the disclosure failure this function exists to close.
        if not isinstance(enabled, bool):
            raise DashboardError(
                f"worker policy target {repository!r} has a non-boolean enabled flag")
        if not enabled:
            continue
        if SAFE_REPOSITORY_RE.fullmatch(repository) is None:
            raise DashboardError(
                f"worker policy target {repository!r} is not an owner/name repository")
        serviced.append(repository)
    if not serviced:
        raise DashboardError(
            "worker policy has no ENABLED targets — refusing to publish an agent census with no "
            "rows (an empty row set is what issue #78 closes)")
    return sorted(serviced)


def _repository_activity(live, serviced):
    # Seeded from the SERVICED set, so an idle target publishes an explicit zero row rather than
    # disappearing. A repository that holds a live lease without being serviced still gets its row
    # below — live evidence is never dropped just because the policy did not predict it.
    counts = {repository: {} for repository in serviced}
    models = set()
    for lease in live:
        holder = lease.get("holder")
        match = HOLDER_RE.fullmatch(holder) if isinstance(holder, str) else None
        if match is None:
            raise DashboardError("live lease has an invalid holder")
        model = lease.get("model")
        if not isinstance(model, str) or SAFE_MODEL_RE.fullmatch(model) is None:
            raise DashboardError("live lease has an invalid model")
        repository = match.group("repository")
        models.add(model)
        repository_counts = counts.setdefault(repository, {})
        repository_counts[model] = repository_counts.get(model, 0) + 1
    return {
        "models": sorted(models),
        "repositories": [
            {"repository": repository, "counts": counts[repository]}
            for repository in sorted(counts)
        ],
    }


def _assert_private(document, private_values):
    strings = []

    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                strings.append(str(key))
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
        elif isinstance(value, str):
            strings.append(value)

    visit(document)
    public_text = "\n".join(strings).casefold()
    leaked = [value for value in private_values
              if isinstance(value, str) and value and value.casefold() in public_text]
    if leaked:
        raise DashboardError("privacy assertion failed: raw account identity reached public JSON")


def _obs_fraction(value):
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not 0.0 <= number <= 1.0:
        return None
    return round(number, 4)


def _obs_count(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _obs_minutes(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return round(float(value), 1) if 0 <= value < 10_000_000 else None


def _obs_mean(value):
    """A non-negative finite arithmetic mean, rounded — `review_rounds.mean` is a FLOAT reading,
    not a count, so it cannot go through `_obs_count`. Same fail-closed None as its siblings.

    The conversion is TOTAL over every type accepted above it, which is why it happens FIRST and
    inside a `try`: Python's JSON decoder preserves an arbitrary-precision integer, and both
    `float(10**400)` and `math.isfinite(10**400)` raise `OverflowError` converting it. Reading the
    range off the raw value therefore turns an unreadable collector mean into a DEAD BUILD instead
    of the dropped stat this seam promises — `_obs_minutes` is safe only by accident, because its
    `0 <= value < 10_000_000` compares the integer without ever converting it.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return round(number, 2) if math.isfinite(number) and number >= 0 else None


def _obs_text(value, cap):
    text = str(value or "").strip()
    return text[:cap] if text and text.isprintable() else ""


def _obs_capped(rows, cap):
    """[#1868] A DISPLAY cap, with what it hid: `(rows[:cap], the PRE-cap total)`.

    Every observability array on this panel is a top-N slice — the queue's 12, the fires' 20, the
    defer/exit `[:16]`s, the 12 lanes — and each of them drops WELL-FORMED rows. #982/#1570/#1571
    deliberately left that silent in the BUILD LOG and said why: a truncation of rows the seam
    successfully READ is a display contract, not a producer/consumer mismatch, and a warning would
    fire on every healthy 13-lane fleet. But the operator-facing half was still missing — a fleet
    with 50 congested target repositories and one with 12 rendered IDENTICALLY, which is #1571's
    'indistinguishable from nothing happened' one layer up. So the total travels WITH the slice and
    `dashboard/app.js` renders `showing 12 of 50`.

    The total counts the rows that SURVIVED validation, never the raw input: a malformed row is a
    different fact, it is already announced on stdout by its own seam, and folding it in here would
    put a count on the public page that no rendered row can account for. It is also COUNTED here
    rather than read from a collector-supplied field, which matters because that snapshot lives on
    a branch this build does not own (AGENTS.md pre-flight item 5, *who can write what this
    reads*): a collector cannot assert `of 50000` on the public page, only send rows to be counted.

    Published UNCONDITIONALLY, including when the cap hid nothing (AGENTS.md pre-flight item 8: a
    census that emits only when it has something to say is one a mutant can silence on exactly the
    quiet tick an operator interrogates). The page owns the `total > shown` decision.
    """
    return rows[:cap], len(rows)


def _obs_lane_rows(lanes):
    """Per-workflow (worker/review-fix/drain/groom/...) run outcomes over the 1h/24h windows.
    Lane names are declared by the collector, validated as safe tokens here — a new lane appears
    on the dashboard without a UI change. Malformed rows are dropped, not fatal.

    [#1868] The 12-lane cap is applied on the way OUT, like every sibling seam's. It used to sit
    INSIDE the loop (`len(rows) == 12 or ...`), which stopped validating at the cap and so could
    not have counted the lanes past it."""
    rows = []
    if not isinstance(lanes, dict):
        return _obs_capped(rows, 12)
    for name in sorted(str(key) for key in lanes):
        row = lanes.get(name)
        if OBS_TOKEN_RE.fullmatch(name) is None or not isinstance(row, dict):
            continue
        out = {"lane": name}
        for window in ("1h", "24h"):
            source = row.get(window)
            if not isinstance(source, dict):
                out[window] = None
                continue
            out[window] = {key: _obs_count(source.get(key)) or 0
                           for key in ("success", "failure", "defer")}
        rows.append(out)
    return _obs_capped(rows, 12)


def _obs_counted_rows(items, key_field, cap):
    """[{<key_field>, count}] sorted by count descending (the TOP-N contract for defer reasons)."""
    rows = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        key = item.get(key_field)
        count = _obs_count(item.get("count"))
        if not isinstance(key, str) or OBS_TOKEN_RE.fullmatch(key) is None or count is None:
            continue
        rows.append({key_field: key, "count": count})
    rows.sort(key=lambda row: (-row["count"], row[key_field]))
    return _obs_capped(rows, cap)


def _obs_exit_rows(items):
    rows = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        model, exit_class = item.get("model"), item.get("exit_class")
        count = _obs_count(item.get("count"))
        if (not isinstance(model, str) or SAFE_MODEL_RE.fullmatch(model) is None
                or not isinstance(exit_class, str)
                or OBS_TOKEN_RE.fullmatch(exit_class) is None or count is None):
            continue
        rows.append({"model": model, "exit_class": exit_class, "count": count})
    rows.sort(key=lambda row: (-row["count"], row["model"], row["exit_class"]))
    return _obs_capped(rows, 16)


def _obs_lease_aggregate(value):
    """A lease-utilization aggregate the COLLECTOR computed, i.e. the row-free form of the input
    (issue #841). Same published shape as the rows-derived one: ``{"mean", "max"}``.

    Fail-closed to None — the panel stat hides — rather than to a plausible-looking number: both
    fields must be real fractions and ``max >= mean``, which no aggregate over real samples can
    violate. DROPPING rather than raising is the tolerance this document already declares: inside
    a well-formed snapshot a malformed row is dropped and only a privacy violation is fatal, and
    this value carries no identity to violate."""
    if not isinstance(value, dict):
        return None
    mean = _obs_fraction(value.get("mean"))
    maximum = _obs_fraction(value.get("max"))
    if mean is None or maximum is None or maximum < mean:
        return None
    return {"mean": round(mean, 2), "max": round(maximum, 2)}


class _ObsDropLog:
    """[#1570] A BOUNDED drop-diagnostic printer for one observability seam.

    One instance per seam per build: `drop()` names the first `OBS_DROP_WARN_MAX` dropped rows and
    counts the rest, `close()` prints the one tail line carrying the counts an operator actually
    needs — how many warnings were withheld, and how many rows were dropped in TOTAL. Below the cap
    nothing changes: the same per-row lines print and no tail is emitted, so a two-row shape
    mismatch still reads exactly as it did before this cap existed.

    The seams count SEPARATELY. A queue snapshot that floods its own budget must not silence the
    evidence-link warning on the same document — that would trade one invisible loss for another.

    Callers pass a fully-composed message: every value a message quotes is sanitized at its own call
    site (`_obs_text`), so no collector value reaches the build log raw. The tail line quotes only
    integers this build counted itself."""

    def __init__(self, seam):
        self.seam = seam            # plural noun for the tail line, e.g. "observability queue rows"
        self.dropped = 0            # every drop, including the ones never printed
        self.printed = 0

    def drop(self, message):
        self.dropped += 1
        if self.printed < OBS_DROP_WARN_MAX:
            self.printed += 1
            print(f"dashboard-gen: dropped {message}")

    def close(self):
        suppressed = self.dropped - self.printed
        if suppressed:
            print(f"dashboard-gen: ... {suppressed} further dropped {self.seam} suppressed "
                  f"({self.dropped} dropped in total)")


def _obs_drop_queue(drops, detail):
    """[#982] Announce a dropped observability queue input instead of swallowing it.

    `_obs_trigger_rows` already sets this precedent on the same collector document. It matters
    more here: a dropped queue row leaves `flow.queue` EMPTY, and an empty queue panel is exactly
    what an IDLE queue renders as. So a producer/consumer shape mismatch — a collector handing
    over the natural `queue_stats()` shape, whose classes are Python INTEGERS — published a green
    build, a green self-test and a panel reading `no backlog`, with the loss visible nowhere.

    Only the SHAPE is named: a type name, a field name, and for a class string the `_obs_text`
    sanitized form. No collector value reaches the build log raw, so a malformed snapshot cannot
    inject lines into the log it is being diagnosed in.

    [#1570] `drops` is this build's queue-seam `_ObsDropLog`: the wording is unchanged, the emission
    is capped, and the rows past the cap are counted into its tail line rather than printed."""
    drops.drop(f"observability queue input ({detail})")


def _obs_stat(drops, name, source, fields):
    """[#1880] One flow-panel statistic (`review_rounds` / `parks_1h` / `arm_to_merge_minutes_24h`)
    read FAIL-CLOSED out of the collector's dict, as ``{field: value}`` or None.

    `fields` is one ``(field, reader, default, accepts)`` row per published field, where `accepts`
    describes the reader's contract for the drop line. Three cases, and the difference between the
    first two is the whole point:

    * The collector did NOT send a field (absent, or an explicit null — #1557 settled that an
      explicit null is "no value", not a shape mismatch): the field takes its `default`. If at
      least one sibling parses, nothing is announced; if NO field parses, the whole statistic is
      dropped and announced. A present-but-empty statistic measured nothing, so publishing all of
      its defaults would fabricate a confident zero.
    * The collector SENT it and this build cannot read it: a producer/consumer mismatch. EVERY such
      field is announced through this seam's `_ObsDropLog`, and the WHOLE statistic publishes None
      so the panel stat HIDES. Dropping only the field would not be enough — the page reads each
      count as `obsNum(value, 0)`, so a null park count still renders `0 user · 0 orch`, the
      false-healthy panel this guard exists to prevent (AGENTS.md pre-flight item 11; #1879 is the
      same read one seam over). This replaces `_obs_count(...) or 0`, which published a confident
      ZERO for a park/sample count nobody could read, and bare `_obs_count(...)`, which hid a stat
      with no diagnostic at all — so a collector that RENAMED a field looked exactly like a
      collector that has not shipped it yet.
    * The stat itself is present but is not an object: same announcement, same None (the container
      check `_obs_drop_queue` already makes on `flow.queue`, for the same reason).

    Only the SHAPE reaches the build log — this build's own field name and a Python type name — so
    a malformed snapshot cannot inject lines into the log it is being diagnosed in.

    Tolerance is unchanged: a malformed stat is dropped, never fatal.
    """
    if source is None:
        return None
    if not isinstance(source, dict):
        drops.drop(f"observability flow stat `{name}` "
                   f"(the stat (type {type(source).__name__}) is not an object)")
        return None
    published, readable, parsed = {}, True, False
    for field, reader, default, accepts in fields:
        raw = source.get(field)
        if raw is None:
            published[field] = default
            continue
        value = reader(raw)
        if value is None:
            drops.drop(f"observability flow stat `{name}` (field `{field}` "
                       f"(type {type(raw).__name__}) is not {accepts})")
            readable = False
        else:
            parsed = True
        published[field] = value
    if readable and not parsed:
        drops.drop(f"observability flow stat `{name}` (the stat has no parsed fields)")
    return published if readable and parsed else None


def _obs_flow(flow):
    """Queue depth/age per class, fleet-wide lease utilization, review rounds, park rates,
    arm→merge latency, target-CI congestion. A lease row whose label is not the canonical 16-hex
    salted account fingerprint (issue #375) is a raw account identity reaching the collector
    output — or a second identity format nothing else here speaks — a decision-22 privacy
    incident, fatal — and since issue #374 the rows themselves are aggregated away rather than
    republished (issue #841: and since the rows sit on a PUBLIC branch, they need not be sent at
    all)."""
    if not isinstance(flow, dict):
        return None
    queue = []
    # [#982] Drop-the-row tolerance is unchanged — a malformed queue row never fails the build —
    # but every drop is now ANNOUNCED, one reason at a time, so a shape mismatch is legible
    # instead of arriving as an empty panel. The container check is part of it: `queue_stats()`
    # keyed by the integer classes is a dict, which loses every row before the loop even starts.
    # [#1570] `raw_queue` is UNBOUNDED (`_obs_capped` truncates it on the way out, below), so the
    # announcement is capped: the first OBS_DROP_WARN_MAX rows are named and the rest are counted.
    drops = _ObsDropLog("observability queue rows")
    raw_queue = flow.get("queue")
    if "queue" in flow and not isinstance(raw_queue, list):
        _obs_drop_queue(
            drops, f"`flow.queue` (type {type(raw_queue).__name__}) is not a list of rows")
    for item in raw_queue if isinstance(raw_queue, list) else []:
        if not isinstance(item, dict):
            _obs_drop_queue(drops, f"the row (type {type(item).__name__}) is not an object")
            continue
        queue_class = item.get("class")
        if not isinstance(queue_class, str):
            _obs_drop_queue(drops, f"row `class` (type {type(queue_class).__name__}) is not a "
                            "class STRING such as '1'/'2a'/'4'")
            continue
        if OBS_QUEUE_CLASS_RE.fullmatch(queue_class) is None:
            _obs_drop_queue(
                drops, f"row `class` {_obs_text(queue_class, 16)!r} is not one of the queue classes")
            continue
        depth = _obs_count(item.get("depth"))
        if depth is None:
            _obs_drop_queue(drops, f"row `depth` (type {type(item.get('depth')).__name__}) is not "
                            "a non-negative integer")
            continue
        raw_age = item.get("oldest_age_minutes")
        age = _obs_minutes(raw_age)
        if raw_age is not None and age is None:
            _obs_drop_queue(
                drops, f"row `oldest_age_minutes` (type {type(raw_age).__name__}) is not "
                "a non-negative number of minutes")
            continue
        queue.append({"class": queue_class, "depth": depth,
                      "oldest_age_minutes": age})
    drops.close()
    queue.sort(key=lambda row: row["class"])

    # Issue #374: the per-account lease rows are validated but NOT published. A list of up to 40
    # {label, provider, utilization} rows is a per-account row array by another name — it reads out
    # the fleet's size directly and its labels are stable across builds, which is exactly what the
    # `accounts` array was removed for. The load-balance question the panel answers ("is one account
    # carrying the fleet?") survives as summary statistics that are invariant under cloning the
    # fleet. The decision-22 label check still runs on every INPUT row: a raw handle in the
    # collector's output is a privacy incident regardless of what this build would have published.
    #
    # Issue #841: #374 fixed what this build PUBLISHES; it did not stop the rows EXISTING. The
    # collector's snapshot lives at data/observability.json on the `ledger` branch of this PUBLIC
    # repo, so a consumer contract that says "keep sending one row per account and we will drop
    # them" still parks a per-account row array — fleet size, stable salted labels — one branch
    # over from the page #374 cleaned. So the aggregate is now accepted DIRECTLY as
    # `flow.lease_utilization_1h`, and a collector can satisfy this panel while writing no rows to
    # the public branch at all. Two properties this must NOT trade away, both self-tested:
    #   * rows-first precedence, keyed on the PRESENCE of the legacy `leases` key rather than on
    #     whether a row happened to parse. A collector mid-migration that sends both keeps exactly
    #     today's published value — including the null it publishes when the rows it sent carry no
    #     usable `utilization_1h` — so the new key can never override a legacy result. Only the
    #     genuinely row-free form (no `leases` key at all) consults the collector's aggregate.
    #   * the decision-22 label check is unconditional over the rows that ARE present. Supplying
    #     the aggregate is not a way to smuggle an unvalidated row past it, and a collector that
    #     regresses to writing rows is still caught the moment a raw handle appears in one.
    #
    # [#1869] Drop-the-row tolerance is unchanged — a malformed lease row never fails the build —
    # but the drop is now ANNOUNCED, in the shape #982/#1867 set on the queue and trigger-fire
    # seams. It reads WORSE here than at either of those: a dropped queue row empties a panel,
    # whereas a dropped lease row leaves the SURVIVORS and `lease_utilization_1h` publishes a
    # confident mean/max over them. A collector sending half its rows in the wrong shape therefore
    # published a load-balance figure derived from the other half, and a wrong number reads as a
    # measurement where an empty panel at least reads as nothing.
    #
    # A row is subtracted from that sample TWO ways, and both are announced: the row is not an
    # object at all, or it is a well-formed row whose `utilization_1h` this build cannot read. The
    # second is the likelier producer/consumer mismatch — a collector reporting a percentage, a
    # string, or a null-shaped sentinel keeps a row that PARSES and passes the decision-22 label
    # check, and pre-#1869 it lowered the sample with no diagnostic anywhere. The absent/null case
    # is NOT a mismatch and stays silent: a row that reports no utilization is an unmeasured row,
    # which is #1557's reading of an explicit null, held here for the reason `_obs_stat` holds it.
    #
    # Decision 22 bounds what may be said, which is why this seam took its own review rather than
    # riding along with #1571's six: the message names the row's SHAPE — a type name this build
    # computed — and NOTHING out of the row. A lease row's `label` is a salted account fingerprint
    # and #374/#841 removed exactly those from the published page; echoing one into the build log
    # would republish it one artifact over. A non-object row can itself BE a raw handle string, so
    # there is no safe `_obs_text` form of it and none is taken; an unreadable `utilization_1h` is
    # named by TYPE for the same reason, since a collector controls that value too.
    lease_drops = _ObsDropLog("observability lease rows")
    lease_utilizations = []
    for item in flow.get("leases") if isinstance(flow.get("leases"), list) else []:
        if not isinstance(item, dict):
            lease_drops.drop("observability lease input "
                             f"(the row (type {type(item).__name__}) is not an object)")
            continue
        label = item.get("label")
        if not isinstance(label, str) or OBS_SALTED_LABEL_RE.fullmatch(label) is None:
            raise DashboardError(
                "observability lease row does not carry a salted account label (decision 22)")
        raw_utilization = item.get("utilization_1h")
        utilization = _obs_fraction(raw_utilization)
        if utilization is not None:
            lease_utilizations.append(utilization)
        elif raw_utilization is not None:
            lease_drops.drop("observability lease input (row `utilization_1h` "
                             f"(type {type(raw_utilization).__name__}) is not a fraction "
                             "between 0 and 1)")
    # Load-bearing, unlike the stat seam's `close()` below: `flow.leases` is unbounded on the way
    # IN and #374 publishes none of it on the way out, so nothing else limits how many rows can
    # announce themselves. A snapshot of 100k unreadable rows must write 12 lines and one total.
    lease_drops.close()
    if "leases" in flow:
        lease_utilization = {
            "mean": round(sum(lease_utilizations) / len(lease_utilizations), 2),
            "max": round(max(lease_utilizations), 2),
        } if lease_utilizations else None
    else:
        lease_utilization = _obs_lease_aggregate(flow.get("lease_utilization_1h"))

    # [#1880] The three flow STATS share one seam and one drop log — separate from the queue rows
    # above, which count and cap on their own (`_ObsDropLog`: a queue snapshot that floods its
    # budget must not silence the stat warnings on the same document). Each field a collector SENT
    # must be readable or the whole stat hides and says so; only a field it did not send takes the
    # default. See `_obs_stat` for why the drop is the STAT rather than the field.
    stat_drops = _ObsDropLog("observability flow stats")
    counted, minutes = "a non-negative integer", "a non-negative number of minutes"
    review_rounds = _obs_stat(stat_drops, "review_rounds", flow.get("review_rounds"), (
        ("mean", _obs_mean, None, "a non-negative finite number"),
        ("max", _obs_count, None, counted),
        ("budget_exhausted_1h", _obs_count, None, counted)))
    parks_1h = _obs_stat(stat_drops, "parks_1h", flow.get("parks_1h"), (
        ("needs_user", _obs_count, 0, counted),
        ("needs_orchestrator", _obs_count, 0, counted)))
    arm_to_merge = _obs_stat(
        stat_drops, "arm_to_merge_minutes_24h", flow.get("arm_to_merge_minutes_24h"), (
            ("p50", _obs_minutes, None, minutes),
            ("p90", _obs_minutes, None, minutes),
            ("samples", _obs_count, 0, counted)))
    # Closed for symmetry with the other seams, and it is deliberately UNKILLABLE today: this seam
    # is BOUNDED at three stats of at most three fields, so it can announce at most 8 drops and can
    # never reach OBS_DROP_WARN_MAX. The tail line therefore cannot fire, and no self-test row can
    # distinguish this call from `pass` (an equivalent survivor, AGENTS.md pre-flight item 4). It
    # stays because a fourth stat, or an unbounded one, would make it load-bearing again.
    stat_drops.close()

    ci_queue = []
    for item in (flow.get("target_ci_queue")
                 if isinstance(flow.get("target_ci_queue"), list) else []):
        if not isinstance(item, dict):
            continue
        repository = item.get("repository")
        depth = _obs_count(item.get("depth"))
        if (not isinstance(repository, str) or depth is None or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repository)):
            continue
        ci_queue.append({"repository": repository, "depth": depth})

    # [#1868] Both row arrays publish the pre-cap total of well-formed rows beside themselves, so a
    # 26-class backlog and a 12-class one stop rendering identically. See `_obs_capped`.
    queue, queue_total = _obs_capped(queue, 12)
    ci_queue, ci_queue_total = _obs_capped(ci_queue, 12)
    return {"queue": queue, "queue_total": queue_total,
            "lease_utilization_1h": lease_utilization,
            "review_rounds": review_rounds,
            "parks_1h": parks_1h, "arm_to_merge_minutes_24h": arm_to_merge,
            "target_ci_queue": ci_queue, "target_ci_queue_total": ci_queue_total}


def _obs_trigger_rows(items):
    """Auto-fixer trigger fires (fire-only alarm semantics — the collector records each fire; the
    dashboard only displays). Evidence links are pinned to github.com — anything else is dropped
    loudly rather than published on the public page.

    [#1570] `items` is UNBOUNDED here — `_obs_capped` truncates at 20 on the way OUT, after
    every row has been walked — and each row contributes up to 8 evidence drops, so the
    announcement is capped per BUILD rather than per row: a hoisted-into-the-loop counter would
    still let N rows write 8N lines.

    [#1867] The ROW drops are announced too, which REVERSES the decision #1570 asserted (that a
    non-object fire row stays silent). The evidence drops were loud while the row CARRYING them was
    not, so a collector that spells a rule with a space (`worker failure rate`) lost the whole alarm
    — panel row, summary and every link — with the loss visible nowhere: the exact `flow.queue`
    shape #982 fixed, one seam over, and it reads worse here because a fire row that never arrives
    renders identically to an alarm that never fired.

    Two seams, counted SEPARATELY, for the reason `_ObsDropLog` keeps the queue and evidence seams
    apart: a malformed ROW never reaches the evidence loop, so one shared budget would let a flood
    of unreadable rows silence every link warning on the same document — trading one invisible loss
    for another."""
    rows = []
    row_drops = _ObsDropLog("observability trigger fire rows")
    drops = _ObsDropLog("observability evidence links")
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            row_drops.drop("observability trigger fire input "
                           f"(the row (type {type(item).__name__}) is not an object)")
            continue
        rule = item.get("rule")
        # [#1867] One warning per drop REASON, as on `flow.queue`: a collector that omitted `rule`
        # and one that spelled it with a space are different mistakes and must not read alike. Only
        # the SHAPE reaches the build log — a type name, or the `_obs_text` sanitized and BOUNDED
        # form of the rule — so a malformed snapshot cannot inject lines into the log diagnosing it.
        if not isinstance(rule, str):
            row_drops.drop("observability trigger fire input "
                           f"(row `rule` (type {type(rule).__name__}) is not a rule-name STRING)")
            continue
        if OBS_TOKEN_RE.fullmatch(rule) is None:
            row_drops.drop("observability trigger fire input "
                           f"(row `rule` {_obs_text(rule, 64)!r} is not a safe token)")
            continue
        evidence = []
        for link in (item.get("evidence") if isinstance(item.get("evidence"), list) else [])[:8]:
            if isinstance(link, str) and OBS_EVIDENCE_RE.fullmatch(link):
                evidence.append(link)
            else:
                drops.drop("a non-GitHub observability evidence link")
        task = item.get("enqueued_task")
        rows.append({
            "rule": rule,
            "fired_at": _utc_iso(item.get("fired_at")),
            "summary": _obs_text(item.get("summary"), 240),
            "evidence": evidence[:5],
            "enqueued_task": task if isinstance(task, str)
            and OBS_TOKEN_RE.fullmatch(task) else None,
        })
    row_drops.close()
    drops.close()
    rows.sort(key=lambda row: row["fired_at"] or "", reverse=True)
    return _obs_capped(rows, 20)


def _normalize_observability(document):
    """Validate + sanitize the collector's ledger observability snapshot before publication.

    An ABSENT file is the not-yet-deployed collector => None (the panel hides; never blocks the
    rest of the dashboard). A PRESENT document that is not the declared schema dies loudly — this
    is collector-written data-plane input and must never be published on a guess. Inside a
    well-formed document, malformed rows are dropped (the _normalize_model_health tolerance),
    EXCEPT privacy-shaped violations (a non-salted lease label), which are always fatal."""
    if document is None:
        return None
    if not isinstance(document, dict) or document.get("schema") != OBS_SCHEMA:
        raise DashboardError(f"observability snapshot must declare schema {OBS_SCHEMA!r}")

    cache_source = document.get("cache")
    cache = None
    if isinstance(cache_source, dict):
        # [#1839] Keyed on the KEY's PRESENCE, never on whether its value would have parsed: a
        # collector still sending a retired field has a stale contract whether or not that send was
        # well-formed, and the retirement is exactly the thing it needs told.
        retired = [key for key in OBS_CACHE_RETIRED_FIELDS if key in cache_source]
        if retired:
            print(OBS_CACHE_RETIRED.format(", ".join(retired)))
        read_fraction = _obs_fraction(cache_source.get("prompt_cache_read_fraction_1h"))
        usage_samples = _obs_count(cache_source.get("usage_samples_1h"))
        # [#1557] An UNMEASURED group must not publish as a MEASURED ZERO. `usage_samples_1h` is
        # coerced to 0 below, so a `cache` key carrying nothing this seam can read used to render a
        # confident "Warm drains — of 0 drained / 1h" card built entirely out of that coercion (and
        # out of the retired `drained_1h`, whose own coercion is what made that card readable).
        # Publication therefore requires at least ONE of the two SURVIVING fields to have parsed;
        # parsed is not truthy, so a genuine all-zero hour (0.0 fraction, 0 samples) still
        # publishes (a census must always emit its zero row — AGENTS.md pre-flight item 8). A group
        # carrying only retired fields measures nothing this panel publishes, so it drops like any
        # other unreadable group. The drop is ANNOUNCED for the same reason #982 announced a
        # dropped queue row: `cache: {}` and "no collector at all" render identically as a hidden
        # panel, so a producer/consumer shape mismatch would otherwise be visible nowhere.
        if read_fraction is not None or usage_samples is not None:
            cache = {
                "prompt_cache_read_fraction_1h": read_fraction,
                "usage_samples_1h": usage_samples or 0,
            }
    if cache is None and cache_source is not None:
        print(OBS_CACHE_DROP.format(type(cache_source).__name__))

    thresholds_source = document.get("thresholds")
    thresholds = None
    if isinstance(thresholds_source, dict):
        thresholds = {}
        for key in OBS_THRESHOLD_KEYS:
            value = thresholds_source.get(key)
            if (isinstance(value, (int, float)) and not isinstance(value, bool)
                    and math.isfinite(value) and value >= 0):
                thresholds[key] = value

    # [#1868] Each capped array travels with the pre-cap total of the well-formed rows it came
    # from, published unconditionally; `dashboard/app.js` turns `total > len(rows)` into
    # `showing 12 of 50`. See `_obs_capped` for why the count is not a build-log warning.
    # The call ORDER is the one the dict literal below used to impose (lanes, defers, exits, flow,
    # fires): each of these seams announces its dropped rows on stdout as it runs, and the #1570
    # rows assert those lines as an ordered list.
    lanes, lanes_total = _obs_lane_rows(document.get("lanes"))
    defer_reasons, defer_reasons_total = _obs_counted_rows(
        document.get("defer_reasons_1h"), "reason", 16)
    exit_classes, exit_classes_total = _obs_exit_rows(document.get("model_exit_classes_1h"))
    flow = _obs_flow(document.get("flow"))
    trigger_fires, trigger_fires_total = _obs_trigger_rows(document.get("trigger_fires"))
    return {
        "generated_at": _utc_iso(document.get("generated_at")),
        "cache": cache,
        "lanes": lanes,
        "lanes_total": lanes_total,
        "defer_reasons_1h": defer_reasons,
        "defer_reasons_1h_total": defer_reasons_total,
        "model_exit_classes_1h": exit_classes,
        "model_exit_classes_1h_total": exit_classes_total,
        "flow": flow,
        "trigger_fires": trigger_fires,
        "trigger_fires_total": trigger_fires_total,
        "thresholds": thresholds,
    }


def build_dashboard(issues, leases_document, usage, dispatch_history, model_health, now, salt,
                    observability=None, probe_status=None, serviced=None, history_status=None):
    accounts, private_values = _catalog(issues)
    # Issue #78. `serviced=None` means "READ THE LIVE POLICY", never "no serviced repositories": an
    # empty seed would silently restore the vanishing census this closes, which is the #612 review
    # finding 1 shape (a `None` default that selects the fail-OPEN branch inside the very function
    # that makes the decision). `_repo_file` raises when the policy is unreadable, so a checkout
    # without one refuses the build rather than publishing a lease-only row set.
    if serviced is None:
        serviced = _serviced_repositories(_repo_file(*POLICY_PATH_PARTS))
    _require_salt(salt)
    usage = usage if isinstance(usage, dict) else {}
    try:
        leases = _lease_schema_module().validate_ledger(leases_document)
    except ValueError as exc:
        raise DashboardError(f"lease ledger is malformed: {exc}") from exc
    live = _live_leases(leases, now)
    # Only the AGGREGATE lease count reaches the payload (#374); lease identities never do. Raw
    # handles come only from the catalog/usage inputs and remain in the privacy deny-set.
    private_values.update(str(handle) for handle in usage)

    # Issue #219: a snapshot the probe did not actually produce is not evidence of anything. When
    # the persisted outcome is not a fresh `ok`, the usage map is DISCARDED for every rendering
    # decision — accounts, per-provider aggregates and eligible capacity all fall back to
    # "unknown" — rather than being published as fresh available capacity.
    #
    # #612 review finding 1: NO SIDECAR AT ALL IS THE WEAKEST EVIDENCE OF THE LOT, so it degrades
    # exactly like an unusable one. The first form made `probe_status=None` mean MEASURED, which put
    # a fail-OPEN branch inside the very function that decides capacity: a caller could hand
    # build_dashboard a (possibly stale) non-empty usage map with no sidecar and get every account
    # rendered "available", `fleet.capacity.eligible` positive, and — because the degradation key was
    # omitted in that same branch — NO warning anywhere on the page. That is the #219 failure mode
    # reachable through a different door. `main()`'s `--usage-status`-is-required check guards only
    # the CLI; the invariant belongs here, where the decision is made. The sidecar is now the ONLY
    # thing that can license publishing usage as capacity, and the marker is ALWAYS emitted so no
    # code path can drop the page's degradation notice.
    probe = _probe_outcome(probe_status, now)
    usage_rendered = usage if probe["measured"] else {}

    # The internal capacity tally. ONE predicate for the provider row and eligible capacity: an
    # account is counted eligible only where the allocator would also admit it. Issue #374: this
    # stays a count internally — it is what decides "is there headroom" — but only the boolean
    # projection of it is published.
    capacity = {}
    for account in accounts:
        entry = usage_rendered.get(account["handle"])
        availability, _backoff_until = _quota_state(account, entry, now)
        provider_capacity = capacity.setdefault(
            account["provider"], {"eligible": 0, "total": 0})
        provider_capacity["total"] += 1
        if availability == "available":
            provider_capacity["eligible"] += 1
    history = dispatch_history if isinstance(dispatch_history, list) else []
    document = {
        "schema": SCHEMA,
        "generated_at": _utc_iso(now),
        # Per-provider headroom (maintainer request 2026-07-18), MINIMIZED for the public payload
        # (issue #374). The per-account `accounts` array that used to sit under this key is gone;
        # this section is now the whole quota surface.
        "provider_quota": _public_provider_quota(
            # The verdict travels WITH the snapshot it licensed (#628): when it distrusted the
            # snapshot, the row says so instead of reading like a provider with no usage headers.
            _provider_quota(accounts, usage_rendered, now, probe)),
        "fleet": {
            "active_agents": len(live),
            "capacity": _public_capacity(capacity),
            "last_sweep_at": history[0].get("at") if history else None,
            "dispatch_outcomes": history,
        },
        # Issue #78: one row per SERVICED repository on every tick (zeroes included), plus a column
        # per model that is live somewhere — "how many instances of each model are running on each
        # repo we service", readable at a glance instead of inferred from which rows are absent.
        "active_by_repository": _repository_activity(live, serviced),
        "model_health": _normalize_model_health(model_health),
    }
    # Degradation marker (issue #219): the page renders probe age + failure so a stale or failed
    # measurement is visible instead of silently looking like a fresh, idle fleet. ALWAYS present
    # (#612 review finding 1) — it used to be omitted on exactly the branch that also trusted the
    # usage map unconditionally, so the one state that most needed a warning carried none.
    document["usage_probe"] = probe
    # Degradation marker (issue #1106), the same shape and for the same reason as `usage_probe`:
    # `fleet.dispatch_outcomes == []` and `fleet.last_sweep_at == None` are what a failed `gh` read
    # produces AND what a fleet that has never dispatched produces, so the page cannot tell them
    # apart without this. ALWAYS present — an omitted-on-one-branch marker is exactly the #612
    # finding-1 shape, where the one state that most needed the warning carried none.
    document["dispatch_history"] = _history_outcome(history_status)
    observability = _normalize_observability(observability)
    if observability is not None:
        # Optional key (absent => the dashboard hides the Observability panels), placed INSIDE the
        # document so the raw-identity assertion below covers every observability string too.
        document["observability"] = observability
    _assert_private(document, private_values)
    _assert_no_fleet_composition(document)
    return document


def _write_site(document, assets, site):
    assets, site = Path(assets).resolve(), Path(site).resolve()
    if not assets.is_dir() or assets == site:
        raise DashboardError("dashboard asset directory is missing or unsafe")
    site.mkdir(parents=True, exist_ok=True)
    copied = 0
    for source in assets.rglob("*"):
        if source.is_symlink():
            raise DashboardError("dashboard assets may not contain symlinks")
        if source.is_file():
            target = site / source.relative_to(assets)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            copied += 1
    if copied == 0:
        raise DashboardError("dashboard asset directory is empty")
    with open(site / "data.json", "w", encoding="utf-8") as handle:
        # allow_nan=False: NaN/Infinity would serialize as non-standard JSON tokens that browser
        # response.json() rejects, taking down the whole public page — die here instead.
        json.dump(document, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")


def _optional_usage_path(cli_path):
    candidates = [cli_path, os.environ.get("WORKER_USAGE_FILE"),
                  "data/usage.json", "data/account-usage.json"]
    return next((path for path in candidates if path and Path(path).is_file()), None)


# Issue #1107. ONE DOM shim, not one per harness. The three page-script harnesses below each
# carried a hand-written copy of `element()`/`document`, and they had already drifted: two of them
# stubbed `classList` to a no-op whose `contains()` answered `false` unconditionally, so a renderer
# that degrades a cell BY CLASS was EXECUTED against a DOM physically unable to record the
# degradation. That reads like a page-level assertion while being blind to the thing it names —
# which is the same false pass #612 round 4 found in the lexical form, in a costume. The shim kept
# here is the highest-fidelity of the three (real `classList`, `setAttribute`, `style`); a harness
# supplies only its export list and its body. `_self_test_page_shim` holds it to both properties:
# the shim behaves like the DOM, and it is defined exactly once.
_PAGE_HARNESS = r"""
const fs = require("fs");
const source = fs.readFileSync(__APP_JS__, "utf8");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
function element(tag) {
  const self = {
    tagName: tag, children: [], attributes: {}, style: {}, hidden: false, textContent: "",
    className: "", classes: new Set(),
    // [#1880] A real element counts its children, and the page BRANCHES on that count:
    // `obsFlowCard` attaches its metric grid only `if (grid.childElementCount)`, and
    // `renderObservability` falls back to an empty-state line the same way. Without this the
    // property read `undefined` on every element, so both branches took their empty side and a
    // harness that renders the flow panel found no metrics to assert on — an EXECUTED assertion
    // quietly weaker than it reads, which is the fidelity property #1107 exists to hold.
    // [#1838] ELEMENT children only, which is what the DOM property means: `createTextNode`
    // returns a node with no `tagName`, and the page DOES mix the two inside one parent (the
    // lane-light chip, `laneLight`). A shim counting text nodes reports an element the browser
    // calls empty as non-empty — the same fidelity gap in the opposite direction.
    get childElementCount() {
      return self.children.filter((kid) => kid.tagName !== undefined).length;
    },
    append: (...kids) => { for (const kid of kids) self.children.push(kid); },
    // [#1585] ORDER-SENSITIVE, and not a synonym for append: the throughput card's sparkline is
    // built and then has its caption `prepend`ed, so a shim missing this method threw out of any
    // harness that rendered that panel (which is how this one was found), and a shim that aliased
    // it to append would silently render the caption below the chart it labels.
    prepend: (...kids) => { self.children = [...kids, ...self.children]; },
    replaceChildren: (...kids) => { self.children = [...kids]; },
    setAttribute: (name, value) => { self.attributes[name] = value; },
    classList: { add: (name) => self.classes.add(name), remove: (name) => self.classes.delete(name),
                 contains: (name) => self.classes.has(name) },
  };
  return self;
}
const ids = {};
globalThis.document = {
  getElementById: (id) => (ids[id] = ids[id] || element("div#" + id)),
  createElement: element,
  createElementNS: (_ns, tag) => element(tag),
  createTextNode: (text) => ({ textContent: text, children: [] }),
};
globalThis.fetch = () => Promise.reject(new Error("network is not under test"));
globalThis.setInterval = () => 0;
const flat = (node) => [node.textContent || "", ...(node.children || []).flatMap(flat)];
const text = (node) => flat(node).join(" ");
const degraded = (node) =>
  (node.classes && node.classes.has("degraded")) ||
  (node.children || []).some(degraded);
(async () => {
  // Loading the page runs its own `refresh()`, whose stubbed fetch rejects into the page's catch
  // and writes to #warning; the tick below lets that settle so it cannot be mistaken for a notice
  // under test, and every render below starts from a fresh element.
  const scope = new Function(source + "; return { __EXPORTS__ };")();
  await new Promise((resolve) => setImmediate(resolve));
__BODY__
})().catch((error) => { console.error(error && error.stack || error); process.exit(1); });
"""


def _page_harness(exports, body):
    """A page-script harness for `_node_json`: the shared DOM shim, then `body`.

    `exports` is the comma-separated list of `dashboard/app.js` names the body reaches through
    `scope` — the ONLY thing that varies besides the body itself. `body` is JavaScript indented two
    spaces (it runs inside the harness's async IIFE) and must write its result to stdout as JSON."""
    app_js = Path(__file__).resolve().parent.parent / "dashboard" / "app.js"
    return (_PAGE_HARNESS
            .replace("__EXPORTS__", exports)
            .replace("__BODY__", body.strip("\n"))
            .replace("__APP_JS__", json.dumps(str(app_js))))


# Issue #78. The per-repository census is only observability if the PAGE renders it, and the #612
# round-4 lesson is that a lexical assertion about `renderRepositoryAgents` is satisfiable by a
# comment or a neighbouring occurrence. So the real function is EXECUTED against a stub DOM and the
# rendered header/rows are compared cell by cell — including the quiet tick, where every count is
# zero and the pre-#78 page named no repository at all.
_REPO_AGENTS_PAGE_BODY = r"""
  const out = {};
  for (const [name, spec] of Object.entries(input.cases)) {
    for (const id of ["repo-agents-empty", "repo-agents-table", "repo-agents-head",
                      "repo-agents-body"]) {
      ids[id] = element(id);
    }
    let error = null;
    try {
      scope.renderRepositoryAgents(spec.activity, spec.active);
    } catch (raised) {
      error = String((raised && raised.message) || raised);
    }
    const head = ids["repo-agents-head"].children[0];
    out[name] = {
      error,
      tableHidden: ids["repo-agents-table"].hidden === true,
      emptyText: ids["repo-agents-empty"].hidden === true
        ? null : ids["repo-agents-empty"].textContent,
      header: head ? head.children.map((cell) => cell.textContent) : [],
      rows: ids["repo-agents-body"].children.map((row) =>
        row.children.map((cell) => cell.textContent)),
    };
  }
  process.stdout.write(JSON.stringify(out));
"""


_LANE_PAGE_BODY = r"""
  const out = {};
  for (const [name, outcomes] of Object.entries(input.outcomes)) {
    ids.outcomes = element("tbody#outcomes");
    scope.renderOutcomes(outcomes);
    out[name] = ids.outcomes.children.map((row) => {
      const cell = row.children[4];
      return {
        cells: row.children.length,
        colSpan: row.children[0] ? (row.children[0].colSpan ?? null) : null,
        cellText: cell ? flat(cell).join("").trim() : null,
        chips: cell ? (cell.children || []).map((chip) => ({
          dot: chip.children && chip.children[0] ? chip.children[0].className : "",
          text: flat(chip).join("").trim(),
        })) : [],
      };
    });
  }
  process.stdout.write(JSON.stringify(out));
"""


def _self_test_page_shim(check):
    """Issue #1107 — the ONE DOM shim every page-script harness is built on.

    Scaffolding rather than a guard, so no trust surface rides on it; but a shim that silently
    swallows what the page does to it makes an EXECUTED assertion quietly weaker than it reads,
    which is the #612-round-4 false pass wearing a different costume. Two properties, and the
    pre-#1107 `classList: {add: () => {}, contains: () => false}` copies failed the first: the shim
    RECORDS what the page does to an element, and there is exactly one of it."""
    # Composed through `_page_harness` exactly as the real harnesses are, so `loaded` below also
    # witnesses that the export list substituted and that the app.js path resolved to a real file.
    probe_body = r"""
  const el = document.getElementById("cell");
  el.classList.add("degraded");
  el.setAttribute("data-lane", "worker");
  el.append(document.createTextNode("dropped"), document.createElement("span"));
  const kept = document.createElement("b");
  kept.textContent = "kept";
  el.replaceChildren(kept);
  const parent = document.createElement("td");
  const child = document.createElement("span");
  child.classList.add("degraded");
  parent.append(child);
  const before = { degraded: degraded(el), contains: el.classList.contains("degraded") };
  el.classList.remove("degraded");
  // [#1880] The count the page BRANCHES on, read at three sizes: a stub answering any constant
  // (0 was the pre-#1880 `undefined`) sends `obsFlowCard`/`renderObservability` down their
  // empty-state branch on a panel that has content, or the reverse.
  // [#1585] `prepend` puts its children FIRST — aliasing it to append reverses every caption the
  // page places above the element it already built.
  const ordered = document.createElement("ol");
  ordered.append(document.createTextNode("second"));
  ordered.prepend(document.createTextNode("first"));
  const counter = document.createElement("ul");
  const counted = [counter.childElementCount];
  counter.append(document.createElement("li"), document.createElement("li"));
  counted.push(counter.childElementCount);
  counter.replaceChildren(document.createElement("li"));
  counted.push(counter.childElementCount);
  // [#1838] ...and a TEXT node is not an element child, so the count does not move.
  counter.append(document.createTextNode("not an element"));
  counted.push(counter.childElementCount);
  process.stdout.write(JSON.stringify({
    before, counted,
    prepended: ordered.children.map((kid) => kid.textContent),
    after: { degraded: degraded(el), contains: el.classList.contains("degraded") },
    attribute: el.attributes["data-lane"] === undefined ? null : el.attributes["data-lane"],
    replaced: el.children.map((kid) => kid.textContent),
    inherited: degraded(parent),
    memoized: document.getElementById("cell") === el,
    namespaced: document.createElementNS("http://www.w3.org/2000/svg", "svg").tagName,
    text: text(el).trim(),
    loaded: typeof scope.render,
  }));
"""
    try:
        shim = _node_json(_page_harness("render", probe_body), {})
    except DashboardError as exc:
        # Same convention as the harnesses below: report the raise as the row's value, so the row
        # goes red by name instead of aborting the suite with every later check unrun.
        shim = {"page script raised": str(exc)[:200]}
    check("[#1107] EXECUTED: the shared DOM shim RECORDS what the page does to an element — a "
          "class added and removed, an attribute, a child REPLACED rather than appended, a child "
          "PREPENDED ahead of one already there, the ELEMENT-child COUNT the page branches on "
          "(text nodes excluded, as the DOM excludes them), and id identity all read back, and a "
          "class added to a child reaches an ancestor's walk",
          shim,
          {"before": {"degraded": True, "contains": True}, "counted": [0, 2, 1, 1],
           "prepended": ["first", "second"],
           "after": {"degraded": False, "contains": False},
           "attribute": "worker", "replaced": ["kept"], "inherited": True, "memoized": True,
           "namespaced": "svg", "text": "kept", "loaded": "function"})
    # AGENTS.md pre-flight item 4, *mutually-masking duplicates*: two copies of one thing make each
    # copy individually unkillable, so the invariant has to be on the COUNT. The needles are
    # regexes on purpose — a plain-substring needle for a shim line would occur in this assertion
    # too and could never read 1 — and the `\(`/`\{` escapes mean none of them matches its own
    # source text here.
    module_source = _repo_file("scripts", "dashboard-gen.py")
    check("[#1107] ...and it is defined exactly ONCE. Three harnesses each hand-rolled a copy and "
          "two had already drifted from the third; a fresh copy is that defect returning",
          (len(re.findall(r"^function element\(tag\) \{$", module_source, re.M)),
           len(re.findall(r"^globalThis\.document = \{$", module_source, re.M)),
           len(re.findall(r"^const ids = \{\};$", module_source, re.M)),
           # The app.js read, so a second PRELUDE is caught even if its `element()` were reformatted
           # past the first needle — every harness reaches the page through the one builder.
           len(re.findall(r'^const source = fs\.readFileSync\(__APP_JS__, "utf8"\);$',
                          module_source, re.M))),
          (1, 1, 1, 1))


# Issue #1585 — the worker-health row of the throughput card. `metrics.py` has published
# `worker_attempts_1h` + `worker_success_rate_1h` since the collector shipped and the card drew
# neither, so this is the first coverage the throughput panel has had at all; a lexical assertion
# about `workerRow` would be satisfiable by the comment above it (the #612 round-4 lesson), so the
# page is EXECUTED through `renderThroughput` — its ONE production call site — and the rows below
# read the cells an operator sees. Rendering through the call site is deliberate (AUTHOR pre-flight
# item 2a): dropping the alert argument there, not in `workerRow`, is how the tone would really be
# lost, and it reds the toned rows below.
_THROUGHPUT_WORKER_PAGE_BODY = r"""
  const out = {};
  for (const [name, snapshot] of Object.entries(input.snapshots)) {
    for (const id of ["throughput-section", "throughput-time", "throughput-alerts",
                      "throughput-targets"]) {
      ids[id] = element("div#" + id);
    }
    scope.renderThroughput(snapshot);
    out[name] = ids["throughput-targets"].children.map((card) => {
      const grids = (card.children || []).filter(
        (kid) => String(kid.className || "").split(" ").includes("worker-grid"));
      const top = card.children[0];
      return {
        repo: top && top.children[0] ? top.children[0].textContent : null,
        rows: grids.length,
        cells: grids.flatMap((grid) => grid.children.map((cell) => [
          cell.children[0] ? cell.children[0].textContent : null,
          cell.children[1] ? cell.children[1].textContent : null,
          cell.children[1] && cell.children[1].children[0]
            ? cell.children[1].children[0].textContent : null,
          cell.children[1] ? cell.children[1].className : null,
        ])),
      };
    });
  }
  process.stdout.write(JSON.stringify(out));
"""

_THROUGHPUT_BACKLOG_FIXTURE = {
    "issues_open": 1, "issues_ready": 1, "issues_closed_1h": 0,
    "prs_open": 1, "prs_draft": 0, "prs_merged_1h": 0, "prs_merged_24h": 0,
    "review_changes_backlog": 0, "needs_user_parked": 0, "review_lane_health": "ok",
    "pr_open_rate": 0, "pr_close_rate": 0, "net_pr_flow": 0,
}


def _self_test_throughput_worker(check):
    """Issue #1585 — the worker-health metrics the public page is SERVED but never drew."""
    def target(**worker):
        return {**_THROUGHPUT_BACKLOG_FIXTURE, **worker}

    def snapshot(targets, alerts=()):
        return {"generated_at": "2025-06-15T15:06:40Z", "schema_version": 1,
                "targets": targets, "alerts": list(alerts)}

    def alert(target_repo, classification, fire=True):
        return {"target": target_repo, "classification": classification, "fire": fire,
                "summary": "fixture", "metrics": {}}

    page = _executed_page(
        _page_harness("renderThroughput", _THROUGHPUT_WORKER_PAGE_BODY),
        {"snapshots": {
            # What metrics.py publishes TODAY: the two worker fields, no no-change family.
            "served-today": snapshot({
                "owner/alpha": target(worker_attempts_1h=4, worker_success_rate_1h=0.75)}),
            # A target the collector has said nothing about — no worker key at all.
            "collector-quiet": snapshot({"owner/beta": target()}),
            # The #987 family served on BOTH targets, with the two alerts naming one target each:
            # worker-failing names delta, worker-no-change names gamma. Each card must take the
            # tone of ITS OWN alert and neither of the other's — asserted in both directions.
            # delta ALSO carries a FIRING near-match classification on its OWN target
            # (`worker-no-change-sustained` — a name no rule publishes). A tone that tested
            # containment rather than the exact classification would turn delta's no-change cell
            # bad on it, so this row is the control that keeps the exact match load-bearing.
            "no-change-served": snapshot(
                {"owner/delta": target(
                    worker_attempts_1h=5, worker_success_rate_1h=0.2,
                    worker_no_change_1h=2, worker_no_change_rate_1h=0.4,
                    # An unreadable bucket count is skipped, not ranked: `other` is the top reason
                    # here only because `already-done`'s count cannot be read.
                    worker_no_change_by_reason_1h={"already-done": None, "other": 2},
                    worker_no_change_repeat_issues_1h=[42, 99]),
                 "owner/gamma": target(
                     worker_attempts_1h=6, worker_success_rate_1h=0.5,
                     worker_no_change_1h=3, worker_no_change_rate_1h=0.5,
                     worker_no_change_by_reason_1h={"already-done": 2, "blocked_on_decision": 1},
                     worker_no_change_repeat_issues_1h=[1174, 1509, 396, 987, 1585])},
                [alert("owner/delta", "worker-failing"),
                 alert("owner/delta", "worker-no-change-sustained"),
                 alert("owner/gamma", "worker-no-change")]),
            # The family served with NO signal in it: every value null.
            "nulls-served": snapshot({"owner/zeta": target(
                worker_attempts_1h=1, worker_success_rate_1h=None,
                worker_no_change_1h=None, worker_no_change_rate_1h=None,
                worker_no_change_by_reason_1h=None, worker_no_change_repeat_issues_1h=None)}),
            # RECOVERED alerts (fire=false) on this very target, and an empty repeat list.
            "recovered-alert": snapshot(
                {"owner/eta": target(
                    worker_attempts_1h=4, worker_success_rate_1h=0.25,
                    worker_no_change_1h=1, worker_no_change_rate_1h=0.125,
                    worker_no_change_by_reason_1h={"other": 1},
                    worker_no_change_repeat_issues_1h=[])},
                [alert("owner/eta", "worker-failing", fire=False),
                 alert("owner/eta", "worker-no-change", fire=False)]),
            # A REAL ZERO, an unreadable repeat list, and an alert row whose classification is not
            # a string (the page must not tone off it, and must not raise on it either).
            "zero-and-unreadable": snapshot(
                {"owner/theta": target(
                    worker_attempts_1h=2, worker_success_rate_1h=0,
                    worker_no_change_1h=0, worker_no_change_rate_1h=0,
                    # EVERY bucket unreadable, so skipping them has to leave NO top reason. A map
                    # that merely mixes one unreadable bucket in cannot kill the skip: the
                    # readable bucket outranks it either way (measured — that mutant survived).
                    worker_no_change_by_reason_1h={"unreadable": None},
                    worker_no_change_repeat_issues_1h=["#12", None])},
                [alert("owner/theta", None)]),
        }})

    check("[#1585] EXECUTED: the card draws the two worker fields metrics.py serves TODAY — a "
          "success PERCENTAGE with the attempt count that qualifies it. Neither reached the page "
          "before this row",
          page["served-today"],
          [{"repo": "owner/alpha", "rows": 1,
            "cells": [["Worker success / 1h", "75%", "4 attempts", "metric-value"]]}])
    check("[#1585] a snapshot carrying NO worker_no_change_* key renders NO no-change cell — three "
          "permanent em-dashes would claim a signal the collector is not emitting",
          page["collector-quiet"],
          [{"repo": "owner/beta", "rows": 1,
            "cells": [["Worker success / 1h", "—", "attempts unknown", "metric-value"]]}])
    check("[#1585] the #987 family drawn: rate, run count + top reason, and the repeat-offender "
          "issue numbers — CAPPED with the overflow stated on gamma (no silent cap), listed whole "
          "on delta. Each card takes the tone of ITS OWN alert in BOTH directions: worker-failing "
          "names delta, so delta's success cell is bad and gamma's is plain; worker-no-change "
          "names gamma, so gamma's no-change cell is bad and delta's is plain — and delta's stays "
          "plain under a FIRING near-match classification on delta itself, so only the EXACT "
          "classification tones",
          page["no-change-served"],
          [{"repo": "owner/delta", "rows": 1,
            "cells": [["Worker success / 1h", "20%", "5 attempts", "metric-value bad"],
                      ["No-change / 1h", "40%", "2 runs · top other 2", "metric-value"],
                      ["Repeat no-change", "#42 #99", None, "metric-value"]]},
           {"repo": "owner/gamma", "rows": 1,
            "cells": [["Worker success / 1h", "50%", "6 attempts", "metric-value"],
                      ["No-change / 1h", "50%", "3 runs · top already-done 2", "metric-value bad"],
                      ["Repeat no-change", "#1174 #1509 #396 #987 +1 more", None,
                       "metric-value"]]}])
    check("[#1585] NULL IS NOT ZERO: a served-but-null rate reads '—', never '0%' — a quiet hour "
          "and a total-failure hour must not render identically",
          page["nulls-served"],
          [{"repo": "owner/zeta", "rows": 1,
            "cells": [["Worker success / 1h", "—", "1 attempt", "metric-value"],
                      ["No-change / 1h", "—", "no signal", "metric-value"],
                      ["Repeat no-change", "—", None, "metric-value"]]}])
    check("[#1585] a RECOVERED alert (fire=false) on this target tones nothing, and an EMPTY "
          "repeat list is a published finding ('none'), not an absent one ('—')",
          page["recovered-alert"],
          [{"repo": "owner/eta", "rows": 1,
            "cells": [["Worker success / 1h", "25%", "4 attempts", "metric-value"],
                      ["No-change / 1h", "12.5%", "1 run · top other 1", "metric-value"],
                      ["Repeat no-change", "none", None, "metric-value"]]}])
    check("[#1585] ...and the converse of that row: a MEASURED zero reads '0%', not '—'. A reason "
          "map with nothing readable in it contributes no top reason, a repeat list whose entries "
          "cannot be read as issue numbers claims nothing, and an alert row with no string "
          "classification tones nothing rather than raising",
          page["zero-and-unreadable"],
          [{"repo": "owner/theta", "rows": 1,
            "cells": [["Worker success / 1h", "0%", "2 attempts", "metric-value"],
                      ["No-change / 1h", "0%", "0 runs", "metric-value"],
                      ["Repeat no-change", "—", None, "metric-value"]]}])


# Issue #1827 — the no-change reason census, from the payload build_dashboard really publishes to
# the cells an operator reads. `renderHealth` is EXECUTED (the #612 round-4 lesson: a lexical
# assertion about `renderNoChangeCensus` is satisfied by the comment above it), and the census is
# reached through `renderHealth` rather than called directly, because the defect this closes is one
# of PLACEMENT — a census drawn after the per-model strip's empty-state return renders on every
# board except the one whose ledger is all no-change rows. The `models` field beside it records
# which branch that surrounding renderer took, so the placement row cannot pass by accident.
_HEALTH_CENSUS_PAGE_BODY = r"""
  const out = {};
  for (const [name, health] of Object.entries(input.cases)) {
    for (const id of ["health-section", "health-time", "model-health", "health-no-change"]) {
      ids[id] = element("div#" + id);
    }
    scope.renderHealth(health);
    const panel = ids["health-no-change"];
    const caption = panel.children[0];
    const strip = panel.children[1];
    // Every field below is a SCALAR or a whole array: the rows that read them must never index
    // into a value a mutant can turn null, or the mutant aborts the suite and scores as a kill
    // with every later check unrun (AGENTS.md pre-flight item 4, *crash-after-partial-run* —
    // measured here: the first form of this harness did exactly that on two mutants).
    const line = caption === undefined || caption === null ? null : String(caption.textContent);
    // Cut at the span joiner so the half this page composes is compared EXACTLY while the
    // absolute stamp — rendered by the one `utc()` helper #1343 already pins, under whatever
    // locale the runner's ICU defaults to — is only required to be present and readable.
    const cut = line === null ? -1 : line.indexOf(" since ");
    out[name] = {
      sectionHidden: ids["health-section"].hidden === true,
      panelHidden: panel.hidden === true,
      caption: cut < 0 ? line : line.slice(0, cut),
      stamp: cut < 0 ? null : line.slice(cut + " since ".length),
      chips: strip ? strip.children.map((item) => [
        item.children[0] ? item.children[0].textContent : null,
        item.children[1] && item.children[1].children[1]
          ? item.children[1].children[1].textContent : null,
      ]) : null,
      models: ids["model-health"].children.map((kid) => flat(kid).filter(Boolean).join("|")),
    };
  }
  process.stdout.write(JSON.stringify(out));
"""


def _self_test_health_census(check, published, zero_census):
    """Issue #1827 — the declared-reason census on the PAGE, including the tick that has no
    per-model check at all."""
    # The vocabulary as this suite expects to SEE it — written out, never imported from
    # `NO_CHANGE_REASONS` (pre-flight item 2(b)). The "published" row below still spells its six
    # chips out in full, so this tuple cannot mask a wrong vocabulary: that row and these two would
    # have to be wrong in the same way, and only one of them is derived from this.
    vocabulary = ("unspecified", "underspecified", "blocked_on_decision",
                  "too_large", "already_done", "other")

    def reasons(**counts):
        return [{"reason": name, "count": counts.get(name, 0)} for name in vocabulary]

    zero_chips = [[name, "0"] for name in vocabulary]
    page = _executed_page(
        _page_harness("renderHealth", _HEALTH_CENSUS_PAGE_BODY),
        {"cases": {
            # The payload build_dashboard REALLY publishes — the key name is the seam where this
            # would otherwise be vacuous on both sides at once (pre-flight item 6).
            "published": published,
            # The tick this defect was invisible on: a ledger whose only rows are no-change/fleet
            # signals publishes an EMPTY `checks`, so the per-model strip takes its empty-state
            # return. Census rows all zero as well, so this is also the "would it emit at 100 %
            # of one branch" row (pre-flight item 8).
            "no-model-checks": {"generated_at": None, "checks": [],
                                "no_change_reasons": zero_census},
            # A snapshot with checks but NO census (the non-ledger normalizer's null): the panel
            # is absent, never an all-zero distribution the input cannot support.
            "no-census": {"generated_at": None, "no_change_reasons": None,
                          "checks": [{"model": "fable", "provider": "anthropic",
                                      "status": "healthy", "checked_at": None}]},
            # One run — the singular, and a span that renders.
            "one-run": {"generated_at": None, "checks": [],
                        "no_change_reasons": {"runs": 1, "since": "2025-06-15T14:41:40Z",
                                              "reasons": reasons(other=1)}},
            # Unreadable values inside an otherwise well-formed census: the page states what it
            # cannot read rather than printing `NaN`/`undefined` as a measurement.
            "unreadable": {"generated_at": None, "checks": [],
                           "no_change_reasons": {
                               "runs": "many", "since": None,
                               "reasons": [{"reason": "other", "count": None},
                                           {"reason": 5, "count": 2}]}},
            # No `reasons` array at all: hidden, not raised.
            "no-rows": {"generated_at": None, "checks": [],
                        "no_change_reasons": {"runs": 3, "since": None}},
        }})
    check("[#1827] EXECUTED: the census dashboard-gen really publishes reaches the page — one chip "
          "per vocabulary reason IN ORDER, zero rows drawn rather than dropped, the counted runs "
          "in the caption and a readable span stamp beside them",
          (page["published"]["panelHidden"], page["published"]["caption"],
           page["published"]["stamp"] in (None, "", "unknown"), page["published"]["chips"]),
          (False, "No-change runs by declared reason — 4 runs", False,
           [["unspecified", "1"], ["underspecified", "0"], ["blocked_on_decision", "0"],
            ["too_large", "2"], ["already_done", "1"], ["other", "0"]]))
    check("[#1827] THE PLACEMENT ROW: a ledger with no per-model check still draws the census. The "
          "strip beside it is on its empty-state line, which is the branch a census drawn after "
          "that return would have been skipped by — and an all-zero census is still published, "
          "with its span named as the ledger rather than as a stamp",
          (page["no-model-checks"]["panelHidden"], page["no-model-checks"]["models"],
           page["no-model-checks"]["caption"], page["no-model-checks"]["stamp"],
           page["no-model-checks"]["chips"]),
          (False, ["No recognized model checks in the snapshot."],
           "No-change runs by declared reason — 0 runs in the retained health ledger", None,
           zero_chips))
    check("[#1827] NULL IS NOT ZERO on the page either: a snapshot whose census is null hides the "
          "panel, while the per-model strip it sits under still renders",
          (page["no-census"]["panelHidden"], page["no-census"]["caption"],
           page["no-census"]["chips"], page["no-census"]["models"],
           page["no-census"]["sectionHidden"]),
          (True, None, None, ["fable|anthropic|healthy"], False))
    check("[#1827] one run reads '1 run', not '1 runs', and carries a span stamp",
          (page["one-run"]["caption"], page["one-run"]["stamp"] in (None, "", "unknown"),
           page["one-run"]["chips"]),
          ("No-change runs by declared reason — 1 run", False,
           [[name, "1" if name == "other" else "0"] for name in vocabulary]))
    check("[#1827] an unreadable run count, bucket count or reason LABEL is SAID to be unknown — "
          "never rendered as a number or a name the payload does not contain, and never dropped, "
          "which would shorten the distribution — and a census with no reason rows at all hides "
          "the panel instead of raising out of the render",
          (page["unreadable"]["caption"], page["unreadable"]["chips"],
           page["no-rows"]["panelHidden"], page["no-rows"]["chips"]),
          ("No-change runs by declared reason — count unknown in the retained health ledger",
           [["other", "—"], ["—", "2"]], True, None))


def _self_test_dispatch_lanes(check, history, issues, leases, usage, now, measured_sidecar):
    """Issue #323 — the per-lane dispatch tick counts, from the RUN LOG they are parsed out of, all
    the way to the cell the page renders.

    Split out of `_self_test` only because that function is already thousands of lines; every row
    below is part of the same suite and `check` is the same accumulator."""
    # --- the parser. `deferred` is the LINE's value (5-1-1 would derive 3, the line says 2), so a
    # re-derivation here goes red; the second dispatcher block wins, matching `complete[-1]`.
    log = (
        "2025-01-01Z lane review: planned=9 launched=0 deferred=0 error=9\n"   # pre-complete: not
        "2025-01-01Z dispatched worker owner/repo#1\n"                         # the dispatcher's
        "2025-01-01Z dispatcher complete: 1 worker/review/fix run(s) launched\n"
        "2025-01-01Z fix-dispatch: 0 eligible, 0 launched, 0 deferred (reasons: none)\n"
        "2025-01-01Z lane worker: planned=4 launched=4 deferred=0 error=0\n"
        "2025-01-01Z lane review: planned=4 launched=4 deferred=0 error=0\n"
        "2025-01-01Z lane fix: planned=4 launched=4 deferred=0 error=0\n"
        "2025-01-01Z lane disarm: planned=4 launched=4 deferred=0 error=0\n"
        "2025-01-01Z defer attribution: none\n"
        "2025-01-01Z dispatcher complete: 2 worker/review/fix run(s) launched\n"
        "2025-01-01Z fix-dispatch: 3 eligible, 1 launched, 2 deferred (reasons: capacity=2)\n"
        "2025-01-01Z lane worker: planned=5 launched=1 deferred=2 error=1\n"
        "2025-01-01Z lane review: planned=2 launched=0 deferred=2 error=0\n"
        "2025-01-01Z lane fix: planned=0 launched=0 deferred=0 error=0\n"
        "2025-01-01Z lane disarm: planned=1 launched=1 deferred=0 error=1\n"
        "2025-01-01Z defer attribution: none\n"
        # Echoed AFTER the block's terminator — a clean `review` row that would have overwritten
        # the dispatcher's stalled one under a last-wins scan of the whole tail.
        "2025-01-01Z lane review: planned=0 launched=0 deferred=0 error=0\n")
    check("[#323] the lane block parses into per-lane rows with the LINE's deferred count and a "
          "display state per lane",
          _dispatch_lane_rows(log),
          [{"lane": "worker", "planned": 5, "launched": 1, "deferred": 2, "error": 1,
            "state": "stalled"},
           {"lane": "review", "planned": 2, "launched": 0, "deferred": 2, "error": 0,
            "state": "stalled"},
           {"lane": "fix", "planned": 0, "launched": 0, "deferred": 0, "error": 0,
            "state": "idle"},
           {"lane": "disarm", "planned": 1, "launched": 1, "deferred": 0, "error": 1,
            "state": "stalled"}])
    # AGENTS.md pre-flight item 5 — who can write the thing this reads? A whole run's log carries
    # target-controlled text, and every line of a raw Actions log is timestamp-prefixed, so the
    # `^\S+\s+` shape is NOT evidence the dispatcher printed it. The forged `review` row above sits
    # before the last `dispatcher complete:` and must not appear at all; here it is the only lane
    # line in the log, and the answer is still no rows rather than a fabricated stall.
    check("[#323] a lane line the dispatcher did not print (before the last `dispatcher "
          "complete:`) cannot fabricate a lane row",
          (_dispatch_lane_rows(
              "2025-01-01Z lane review: planned=9 launched=0 deferred=0 error=9\n"
              "2025-01-01Z dispatcher complete: 1 worker/review/fix run(s) launched\n"),
           _dispatch_lane_rows(
               "2025-01-01Z lane review: planned=9 launched=0 deferred=0 error=9\n")),
          (None, None))
    check("[#323] a lane row echoed AFTER the block's terminator cannot overwrite the "
          "dispatcher's own row for that lane (the scan stops at the terminator)",
          [row for row in (_dispatch_lane_rows(log) or []) if row["lane"] == "review"],
          [{"lane": "review", "planned": 2, "launched": 0, "deferred": 2, "error": 0,
            "state": "stalled"}])

    def lane_names(rows):
        """The parsed lane names, or the refusal itself — so a mutant that turns a published block
        into `None` reds ONE named row instead of raising out of the comprehension and aborting the
        suite, which records as a kill while every check below it never runs (pre-flight item 4)."""
        return None if rows is None else [row["lane"] for row in rows]

    # --- the block is validated as a WHOLE (review round 1). Publishing the survivors of a
    # damaged block renders a vanished lane as absent rather than unknown, which is precisely how
    # the stalled review/fix lane or the failed disarm this cell exists to expose would go missing.
    # Every shape below is a block the dispatcher could not have printed, and each must be None —
    # asserting "no partial lane set is published" rather than "the bad row was dropped".
    def block(*body):
        """One dispatcher block: the completion marker, the fix-dispatch header, then `body`."""
        return ("2025-01-01Z dispatcher complete: 1 worker/review/fix run(s) launched\n"
                "2025-01-01Z fix-dispatch: 0 eligible, 0 launched, 0 deferred (reasons: none)\n"
                + "".join(line + "\n" for line in body))

    worker_row = "2025-01-01Z lane worker: planned=5 launched=0 deferred=5 error=0"
    review_row = "2025-01-01Z lane review: planned=2 launched=0 deferred=2 error=0"
    fix_row = "2025-01-01Z lane fix: planned=1 launched=1 deferred=0 error=0"
    disarm_row = "2025-01-01Z lane disarm: planned=1 launched=0 deferred=0 error=1"
    terminator = "2025-01-01Z defer attribution: none"
    check("[#323] a block missing a required lane publishes NOTHING — neither the stalled review "
          "lane nor the failed disarm may be silently absent from an otherwise healthy tick",
          (_dispatch_lane_rows(block(worker_row, fix_row, disarm_row, terminator)),
           _dispatch_lane_rows(block(worker_row, review_row, fix_row, terminator))),
          (None, None))
    check("[#323] a malformed row inside the block refuses the WHOLE block (an unsafe lane name, a "
          "count that is not a bounded integer, and a duplicated lane)",
          (_dispatch_lane_rows(block(
              worker_row, review_row, fix_row,
              "2025-01-01Z lane bad name: planned=1 launched=0 deferred=0 error=1", terminator)),
           _dispatch_lane_rows(block(
               worker_row, review_row, fix_row,
               "2025-01-01Z lane disarm: planned=1234567 launched=0 deferred=0 error=1",
               terminator)),
           _dispatch_lane_rows(block(
               worker_row, review_row, fix_row, disarm_row, disarm_row, terminator))),
          (None, None, None))
    check("[#323] a block that is truncated or non-contiguous is unknown rather than partially "
          "published",
          (_dispatch_lane_rows(block(worker_row, review_row, fix_row, disarm_row)),
           _dispatch_lane_rows(block(worker_row, review_row,
                                     "2025-01-01Z dispatched worker owner/repo#7",
                                     fix_row, disarm_row, terminator))),
          (None, None))
    # The header anchor needs its OWN input, carrying a COMPLETE lane set — the two guards are
    # otherwise mutually masking (pre-flight item 4): with the header line simply absent, the first
    # lane row is eaten in its place, the block then looks like it is missing that lane, and the
    # required-lane floor refuses it for the wrong reason. Deleting the anchor outright survived the
    # suite until this row existed. Here the header's slot holds a foreign line and all four lanes
    # follow, so ONLY the anchor can refuse it.
    check("[#323] a block whose fix-dispatch header is not there — an unrelated line in its slot, "
          "or no header line at all — publishes nothing even with every lane row present",
          (_dispatch_lane_rows(block(worker_row, review_row, fix_row, disarm_row, terminator)
                               .replace("2025-01-01Z fix-dispatch: 0 eligible, 0 launched, "
                                        "0 deferred (reasons: none)",
                                        "2025-01-01Z dispatched worker owner/repo#7")),
           _dispatch_lane_rows(
               "2025-01-01Z dispatcher complete: 1 worker/review/fix run(s) launched\n"
               + "".join(line + "\n" for line in
                         (worker_row, review_row, fix_row, disarm_row, terminator)))),
          (None, None))
    # ...and the required set is a FLOOR, not a pin: a lane added to dispatch-claim's
    # DISPATCH_LANES still reaches the page with no change here (a check that only ever expected
    # None would be satisfied by hard-coding `return None`).
    check("[#323] a block carrying an UNKNOWN extra lane still publishes, extra row included",
          lane_names(_dispatch_lane_rows(block(
              worker_row, review_row, fix_row, disarm_row,
              "2025-01-01Z lane audit: planned=3 launched=3 deferred=0 error=0", terminator))),
          ["worker", "review", "fix", "disarm", "audit"])
    # --- ...and the required four are ORDERED (review round 2). dispatch-claim iterates ONE fixed
    # tuple, so a complete, contiguous, terminated block whose four required rows are permuted is a
    # block it cannot have printed — provenance the membership/duplicate/cap checks all wave
    # through. Both permutations are written LITERALLY, in an order no rotation of the shipped
    # tuple produces, so neither this input nor its expectation moves if DISPATCH_REQUIRED_LANES is
    # edited (pre-flight item 2(b)/(c)).
    check("[#323] a COMPLETE block whose required lanes arrive out of the dispatcher's emission "
          "order publishes nothing — every lane present is not evidence the dispatcher printed it",
          (_dispatch_lane_rows(block(worker_row, fix_row, review_row, disarm_row, terminator)),
           _dispatch_lane_rows(block(disarm_row, review_row, fix_row, worker_row, terminator))),
          (None, None))
    # The exemption is what keeps that order rule from being a pin on the whole block: an unknown
    # lane may sit ANYWHERE, including between two required rows, and publishes in its own place.
    # Without this row, refusing every block whose lane list is not exactly the required tuple —
    # which would silently drop a future lane off the page — stays green.
    check("[#323] an unknown extra lane INTERLEAVED among the required rows still publishes, in "
          "the position the dispatcher printed it",
          lane_names(_dispatch_lane_rows(block(
              worker_row, review_row,
              "2025-01-01Z lane audit: planned=3 launched=3 deferred=0 error=0",
              fix_row, disarm_row, terminator))),
          ["worker", "review", "audit", "fix", "disarm"])
    # 12 and 13 are LITERAL here. Deriving either from DISPATCH_LANE_CAP would make the row
    # vacuous — raising the constant would raise the input and the expectation together and stay
    # green, which is the #941 shape AGENTS.md pre-flight item 2(c) names.
    def padded(count):
        return block(worker_row, review_row, fix_row, disarm_row, *[
            f"2025-01-01Z lane l{index}: planned=1 launched=1 deferred=0 error=0"
            for index in range(count)], terminator)

    twelve = _dispatch_lane_rows(padded(8))
    check("[#323] the lane row count is bounded at twelve, and a block that EXCEEDS the bound is "
          "refused whole rather than truncated to the first twelve lanes",
          (len(twelve or []), (lane_names(twelve) or ["<refused>"])[-1],
           _dispatch_lane_rows(padded(9))),
          (12, "l7", None))

    # --- the display tone. The ALERTING predicate is the tick-health step of dispatch.yml; this
    # oracle restates it (there is no importable copy — it is inline python inside the workflow),
    # and the property is CONTAINMENT: everything that pages must render red. A tone rule that ever
    # narrows toward the alert would hide a lane the operator is being paged about.
    def workflow_alerts(lane, planned, launched, error):
        if lane == "disarm":
            return error > 0
        if lane in ("review", "fix"):
            return planned > 0 and launched == 0 and error > 0
        return False

    grid = [(lane, planned, launched, error)
            for lane in ("worker", "review", "fix", "disarm")
            for planned in range(3) for launched in range(planned + 1) for error in range(3)]
    alerting = [case for case in grid if workflow_alerts(*case)]
    check("[#323] EVERY lane state the dispatch.yml tick-health step pages on renders `stalled` "
          "(containment), over a non-empty grid of cases",
          (bool(alerting),
           sorted({_dispatch_lane_state(*case[1:]) for case in alerting})),
          (True, ["stalled"]))
    check("[#323] ...and the tone is STRICTLY wider than the alert — a lane that planned work and "
          "launched none of it is red here even with no hard error",
          (_dispatch_lane_state(2, 0, 0), workflow_alerts("worker", 2, 0, 0)),
          ("stalled", False))
    check("[#323] the tone actually discriminates (a constant would satisfy containment alone)",
          (_dispatch_lane_state(0, 0, 0), _dispatch_lane_state(3, 3, 0),
           _dispatch_lane_state(3, 3, 1)),
          ("idle", "ok", "stalled"))

    # --- ...and the same rows reaching a published document through the REAL fetch path. Both
    # `_fetch_dispatch_history` and `_run_log_counts` shell out to `gh`, so neither had ever
    # executed in this suite (AGENTS.md pre-flight item 1: the entry points are where a fabricating
    # bug survives) — dropping `"lanes": lanes` from the history entry was unkillable. `gh` is
    # stubbed here, so the seam between the log parser and the published payload is real.
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("dispatch/9_Strictly validate, CAS claim, and dispatch.txt", log)
    logs_zip = archive.getvalue()
    stepless = io.BytesIO()
    with zipfile.ZipFile(stepless, "w") as bundle:
        bundle.writestr("dispatch/1_Set up job.txt", log)
    stepless_zip = stepless.getvalue()
    runs_payload = json.dumps({"workflow_runs": [
        {"id": 11, "status": "completed", "conclusion": "success",
         "run_started_at": "2025-06-15T15:05:00Z"},
        {"id": 12, "status": "completed", "conclusion": "failure",
         "run_started_at": "2025-06-15T14:05:00Z"},
        {"id": 13, "status": "in_progress", "run_started_at": "2025-06-15T13:05:00Z"},
        # The two log-shaped failures the counts share with the lanes: an archive with no claim
        # step in it, and a body that is not an archive at all. Both must reach the caller as a
        # THREE-value answer — the arity is the seam this change moved, and an unexercised return
        # there raises out of _fetch_dispatch_history and takes the whole build down.
        {"id": 14, "status": "completed", "conclusion": "success",
         "run_started_at": "2025-06-15T12:05:00Z"},
        {"id": 15, "status": "completed", "conclusion": "success",
         "run_started_at": "2025-06-15T11:05:00Z"},
    ]})

    class _Completed:
        def __init__(self, returncode, stdout):
            self.returncode, self.stdout = returncode, stdout

    def fake_gh(command, **kwargs):
        url = command[-1]
        if "/workflows/dispatch.yml/runs" in url:
            return _Completed(0, runs_payload)
        if url.endswith("/runs/11/logs"):
            return _Completed(0, logs_zip)
        if url.endswith("/runs/14/logs"):
            return _Completed(0, stepless_zip)   # an archive with no claim-step member
        if url.endswith("/runs/15/logs"):
            return _Completed(0, b"not a zip")   # an unreadable archive
        return _Completed(1, b"")                # run 12: the log fetch fails

    # Every read below reports rather than raises. A mutant that changes `_run_log_counts`'s arity
    # aborts this call, and an abort records as a kill while every check after it never runs
    # (AGENTS.md pre-flight item 4, crash-after-partial-run) — so the failure is turned into a NAMED
    # red row and the suite continues to its full check count.
    saved_run = subprocess.run
    try:
        subprocess.run = fake_gh
        (fetched, fetch_status), fetch_error = _fetch_dispatch_history("owner/registry", 5), None
    except Exception as exc:                    # noqa: BLE001 - reported as a row, never swallowed
        fetched, fetch_status, fetch_error = [], None, f"{type(exc).__name__}: {exc}"
    finally:
        subprocess.run = saved_run
    check("[#323] the fetched history carries the per-lane rows for the run whose log was read, "
          "and an explicit None — never a fabricated empty lane set — for a run whose log it "
          "could not read or which has not finished",
          fetch_error or [(entry.get("dispatched"), entry.get("deferred"),
                           None if entry.get("lanes") is None
                           else [row["lane"] for row in entry["lanes"]])
                          for entry in fetched],
          # `deferred` is 2 because the fixture log carries the TWO dispatcher blocks the
          # last-block-wins rule above is stated over, and DEFERRED_RE matches each block's
          # `defer attribution:` header (pre-existing counting behaviour, untouched here).
          [(2, 2, ["worker", "review", "fix", "disarm"]), (None, None, None), (None, None, None),
           (None, None, None), (None, None, None)])
    published = build_dashboard(issues, leases, usage, fetched, None, now, "fixture-salt",
                                probe_status=measured_sidecar, history_status=fetch_status)
    published_sweeps = published["fleet"]["dispatch_outcomes"]
    published_lanes = next((sweep.get("lanes") or [] for sweep in published_sweeps), [])
    # Stated as LITERALS, not as `fetched[0]["lanes"]`: comparing the payload against the object
    # that was handed in is a tautology over a pass-through (pre-flight item 2(b)).
    check("[#323] ...and they survive into the public payload the page fetches",
          published_lanes[:2],
          [{"lane": "worker", "planned": 5, "launched": 1, "deferred": 2, "error": 1,
            "state": "stalled"},
           {"lane": "review", "planned": 2, "launched": 0, "deferred": 2, "error": 0,
            "state": "stalled"}])

    # --- the page. The header and the row must agree on the column count: a cell appended without
    # a `<th>` renders under the wrong heading, which is the failure this seam check exists for.
    index_html = _repo_file("dashboard", "index.html")
    thead = re.search(r"<thead>(.*?)</thead>\s*<tbody id=\"outcomes\">", index_html, re.S)
    if thead is None:
        raise DashboardError("wiring assertion cannot locate the dispatch-outcomes table header")
    app_js = _repo_file("dashboard", "app.js")
    outcomes_body = _js_function_body(app_js, "renderOutcomes")
    check("[#323] renderOutcomes() appends the lane cell from the outcome's OWN lanes, and the "
          "empty-history row spans the widened table",
          (_js_code_count(outcomes_body, "laneCell(outcome.lanes)"),
           _js_code_count(outcomes_body, "cell.colSpan = 5;")),
          (1, 1))
    lane_body = _js_function_body(app_js, "laneCell")
    check("[#323] the lane tone comes from the GENERATOR's verdict, with an unknown state falling "
          "back rather than reaching the stylesheet unvalidated",
          _js_code_count(
              lane_body,
              'const state = LANE_STATES.has(lane.state) ? lane.state : "unknown";'), 1)
    harness = _page_harness("renderOutcomes", _LANE_PAGE_BODY)
    fixtures = {
        "lanes": published_sweeps[:1],
        "absent": [dict(history[0], lanes=None)],
        "empty": [],
        # A state token no stylesheet rule matches, and one that is not a string at all: both
        # must land on `unknown` rather than being concatenated into the class attribute.
        "hostile": [dict(history[0], lanes=[
            {"lane": "worker", "planned": 1, "launched": 1, "deferred": 0, "error": 0,
             "state": "ok stalled"},
            {"lane": "review", "planned": 1, "launched": 1, "deferred": 0, "error": 0,
             "state": None}])],
    }
    try:
        page = _node_json(harness, {"outcomes": fixtures})
    except DashboardError as exc:
        # A page that throws while rendering IS the finding; reporting it as the value of every
        # row below keeps those rows named and red instead of aborting the suite mid-run.
        page = {"page script raised": str(exc)[:160]}

    def rendered(name, field):
        rows = page.get(name)
        return rows[0].get(field) if isinstance(rows, list) and rows else page

    def chips(name, *fields):
        found = rendered(name, "chips")
        if not isinstance(found, list):
            return found
        return [tuple(chip.get(field) for field in fields) if len(fields) > 1
                else chip.get(fields[0]) for chip in found]

    check("[#323] EXECUTED page script: the header and the rendered row agree on the column count",
          (len(re.findall(r"<th\b", thead.group(1))), rendered("lanes", "cells"),
           rendered("empty", "colSpan")),
          (5, 5, 5))
    check("[#323] EXECUTED page script: every lane renders all four counts unconditionally "
          "(including the zeroes of a quiet lane) with the generator's tone on the dot",
          chips("lanes", "dot", "text"),
          [("lane-dot stalled", "worker 5p 1l 2d 1e"),
           ("lane-dot stalled", "review 2p 0l 2d 0e"),
           ("lane-dot idle", "fix 0p 0l 0d 0e"),
           ("lane-dot stalled", "disarm 1p 1l 0d 1e")])
    check("[#323] EXECUTED page script: a sweep with no lane data renders an explicit blank, not "
          "an all-zero lane set that would read as a healthy tick",
          (rendered("absent", "cellText"), rendered("absent", "chips")), ("—", []))
    check("[#323] EXECUTED page script: a state token that is not one of the four known ones "
          "renders `unknown` — it never reaches the class attribute as written",
          chips("hostile", "dot"), ["lane-dot unknown", "lane-dot unknown"])


def _self_test_history_fetch(check, issues, leases, usage, now, measured_sidecar):
    """Issue #1106 — the dispatch-history FETCH OUTCOME, from the `gh` subprocess that decides it
    to the document the page reads it out of.

    Measured while implementing #323 with `python3 -m trace --count --missing`: the non-zero-exit
    `return`, the `except (AttributeError, json.JSONDecodeError)` arm and the non-dict-run
    `continue` were at ZERO executions across the whole suite, so a mutant in any of them was
    unkillable — and the bug they were hiding is that all three published a bare `[]`, which the
    page renders exactly like a fleet that has genuinely never dispatched. `gh` is stubbed per case
    below, so all three execute."""
    # --- the pure normalizer, BOTH directions. Only an explicit `ok` may license "we read it".
    check("[#1106] the fetch-outcome normalizer trusts ONLY an explicit `ok` — a failed claim, an "
          "alien one, a non-dict one and NO claim at all all refuse",
          [_history_outcome(status)["fetched"] for status in (
              {"outcome": "ok"}, {"outcome": "  OK "}, {"outcome": "failed"},
              {"outcome": "probably-fine"}, {}, None, [], "ok")],
          [True, True, False, False, False, False, False, False])
    check("[#1106] ...and it carries the failure DETAIL to the page, bounded to the same safe-token "
          "shape as every other externally-sourced label on this document",
          (_history_outcome({"outcome": "failed", "detail": "gh-exited-nonzero"}),
           _history_outcome({"outcome": "failed",
                             "detail": "<img src=x onerror=alert(1)>"})["detail"]),
          ({"outcome": "failed", "detail": "gh-exited-nonzero", "fetched": False}, ""))

    # --- the three branches, EXECUTED against a stubbed `gh`.
    class _Completed:
        def __init__(self, returncode, stdout):
            self.returncode, self.stdout = returncode, stdout

    def fetch_with(listing):
        """The real fetcher against a stubbed `gh`: `listing` answers the run-listing call and every
        per-run log call fails, so only the LISTING branches are under test here. An exception is
        turned into a named red row rather than aborting the suite (pre-flight item 4)."""
        def fake_gh(command, **kwargs):
            if "/workflows/dispatch.yml/runs" in command[-1]:
                return listing
            return _Completed(1, b"")

        saved_run = subprocess.run
        try:
            subprocess.run = fake_gh
            return _fetch_dispatch_history("owner/registry", 5)
        except Exception as exc:                # noqa: BLE001 - reported as a row, never swallowed
            return [], f"raised {type(exc).__name__}: {exc}"
        finally:
            subprocess.run = saved_run

    nonzero = fetch_with(_Completed(1, ""))
    check("[#1106] a run listing whose `gh` exits NON-ZERO reports the failure instead of an empty "
          "history that reads as a quiet fleet",
          nonzero, ([], {"outcome": "failed", "detail": "gh-exited-nonzero"}))
    check("[#1106] ...so does a body that is not JSON at all (the JSONDecodeError arm)",
          fetch_with(_Completed(0, "{not json")),
          ([], {"outcome": "failed", "detail": "run-listing-unparseable"}))
    check("[#1106] ...and one that parses to something that is not an object at all (a bare scalar "
          "and a bare array both fail the SCHEMA check, not the JSON parse)",
          (fetch_with(_Completed(0, "3")), fetch_with(_Completed(0, "[]"))),
          (([], {"outcome": "failed", "detail": "run-listing-schema-alien"}),
           ([], {"outcome": "failed", "detail": "run-listing-schema-alien"})))
    # THE ROUND-2 SEAM: `gh` answers a throttled/errored call with a syntactically VALID document
    # that carries no run list. `.get("workflow_runs") or []` turned every one of these into an
    # empty history with an `ok` outcome — a quiet fleet on the public page — and the truthy
    # non-lists were worse: a str was sliced into characters and dropped, a dict raised TypeError
    # out of the build. Each row states the document as a LITERAL so a mutant that re-widens the
    # check (e.g. back to `or []`, or to a truthiness test) goes red on a NAMED row rather than
    # aborting the suite (pre-flight item 4).
    alien = ([], {"outcome": "failed", "detail": "run-listing-schema-alien"})
    for label, body in (("no `workflow_runs` field at all", {}),
                        ("an ERROR document from a throttled call", {"message": "API rate limit"}),
                        ("a null field", {"workflow_runs": None}),
                        ("a truthy STRING (was sliced into characters)",
                         {"workflow_runs": "not-a-list"}),
                        ("a truthy OBJECT (slicing it raised TypeError)",
                         {"workflow_runs": {"11": {"id": 11}}}),
                        ("a truthy NUMBER", {"workflow_runs": 3})):
        check(f"[#1106] a valid JSON run listing with {label} FAILS CLOSED — not a quiet fleet",
              fetch_with(_Completed(0, json.dumps(body))), alien)
    quiet = fetch_with(_Completed(0, json.dumps({"workflow_runs": []})))
    check("[#1106] THE DISCRIMINATION: a fleet that has genuinely never dispatched returns the same "
          "empty row set with an `ok` outcome — the rows alone cannot tell the two apart",
          (quiet, quiet[0] == nonzero[0], quiet[1] == nonzero[1]),
          (([], {"outcome": "ok", "detail": ""}), True, False))
    mixed = fetch_with(_Completed(0, json.dumps({"workflow_runs": [
        {"id": 21, "status": "queued"}, "not-a-run", None, {"id": 22, "status": "waiting"}]})))
    check("[#1106] a run entry that is not an object is DROPPED, and the real entries either side "
          "of it still land (the `continue` had never executed)",
          (mixed[1], [entry["conclusion"] for entry in mixed[0]]),
          ({"outcome": "ok", "detail": ""}, ["queued", "waiting"]))

    # --- ...and the published document, where the ambiguity was actually visible. The `fleet`
    # blocks are stated as LITERALS on both sides, so this row goes red if the marker starts
    # tracking something other than the fetch (pre-flight item 2(b)).
    empty_fleet = {"active_agents": 1, "capacity": {"anthropic": True},
                   "last_sweep_at": None, "dispatch_outcomes": []}
    quiet_document = build_dashboard(issues, leases, usage, [], None, now, "fixture-salt",
                                     probe_status=measured_sidecar, serviced=("owner/repo",),
                                     history_status={"outcome": "ok", "detail": ""})
    lost_document = build_dashboard(issues, leases, usage, [], None, now, "fixture-salt",
                                    probe_status=measured_sidecar, serviced=("owner/repo",),
                                    history_status={"outcome": "failed",
                                                    "detail": "gh-exited-nonzero"})
    # `.get`, never `[...]`: a mutant that DROPS the marker must land as a named red row here, not
    # as a KeyError that aborts the suite and records as a kill while every check below it never
    # ran (AGENTS.md pre-flight item 4, crash-after-partial-run — measured on this very block).
    check("[#1106] the two published documents are no longer BYTE-IDENTICAL: both zero the sweep "
          "and the outcome list, and only the marker says which of the two it is",
          (quiet_document["fleet"], lost_document["fleet"],
           quiet_document.get("dispatch_history"), lost_document.get("dispatch_history"),
           json.dumps(quiet_document, sort_keys=True)
           == json.dumps(lost_document, sort_keys=True)),
          (empty_fleet, empty_fleet,
           {"outcome": "ok", "detail": "", "fetched": True},
           {"outcome": "failed", "detail": "gh-exited-nonzero", "fetched": False},
           False))
    check("[#1106] the marker is on EVERY document, including a build that stated no fetch outcome "
          "at all — which normalizes to NOT fetched rather than being omitted",
          build_dashboard([], {"leases": []}, {}, [], None, now, "fixture-salt",
                          serviced=("solo/target",)).get("dispatch_history"),
          {"outcome": "unknown", "detail": "", "fetched": False})


def _self_test():
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    # ---- [#1303] THE FAILURE MESSAGE MUST NAME THE CAUSE. ----------------------------
    # 10 dashboard failures on 2026-07-28/29, every one of them `public account issue query
    # failed` with no exit code, no status and no stderr — unclassifiable after the fact.
    class _Result:
        def __init__(self, rc, stderr):
            self.returncode, self.stderr, self.stdout = rc, stderr, ""

    _budget = _gh_failure_suffix(_Result(
        1, "gh: API rate limit exceeded for installation. (HTTP 403)"))
    check("gh failure: an installation-budget 403 is named 'budget' and keeps the exit code",
          ("budget" in _budget, "rc=1" in _budget,
           "API rate limit exceeded for installation." in _budget), (True, True, True))
    # THE CONTRACT of the headerless path: it must NOT claim a count it cannot have read.
    check("gh failure: the degraded path does not claim to have read a rate-limit count",
          "x-ratelimit-remaining=" in _budget, False)
    _secondary = _gh_failure_suffix(_Result(
        1, "gh: You have exceeded a secondary rate limit ... retry your request again later. "
           "(HTTP 403)"))
    check("gh failure: a secondary 403 is NOT called budget (the responses are opposite)",
          ("secondary" in _secondary, "budget" in _secondary), (True, False))
    _perm = _gh_failure_suffix(_Result(1, "gh: Resource not accessible by integration (HTTP 403)"))
    check("gh failure: a permission 403 is the residual class", "permission" in _perm, True)
    check("gh failure: the three classes are distinguishable (non-vacuity)",
          len({_budget.split("—")[1], _secondary.split("—")[1], _perm.split("—")[1]}), 3)
    # STATUS FIRST. classify_403_text answers "IF this is a 403, which one" — so a non-403 whose
    # text happens to carry a marker must not be labelled a rate limit.
    _not403 = _gh_failure_suffix(_Result(1, "gh: connection reset, please retry later"))
    check("gh failure: a non-403 carrying a 403 marker word is NOT classified",
          any(c in _not403 for c in ("budget", "secondary", "permission")), False)
    check("gh failure: ...but its stderr still reaches the log",
          "connection reset" in _not403, True)
    _leak = _gh_failure_suffix(_Result(1, "bad token ghp_" + "B" * 40 + " (HTTP 403)"))
    check("gh failure: a token-shaped string in stderr is masked",
          ("ghp_" + "B" * 40 not in _leak, "***" in _leak), (True, True))
    check("gh failure: the detail is bounded",
          len(_gh_failure_suffix(_Result(1, "x" * 5000))) < _GH_DETAIL_LIMIT + 200, True)

    def _raises_dashboard(thunk):
        try:
            thunk()
        except DashboardError:
            return True
        return False

    now = 1_750_000_000
    # #612 review finding 1: since a build with NO sidecar publishes nothing as capacity (correct —
    # an unsupplied measurement is the weakest evidence of all), every fixture below that means to
    # exercise the real CAPACITY/rendering path must SAY the probe measured. That this whole golden
    # block previously ran through the sidecar-less branch is itself the evidence that the fail-open
    # branch was load-bearing for the suite: the tests were mostly exercising the unguarded path.
    measured_sidecar = {"schema": PROBE_SCHEMA, "outcome": "ok", "detail": "probe-succeeded",
                        "attempted_at": now - 30}
    measured_marker = {"outcome": "ok", "detail": "probe-succeeded",
                       "attempted_at": _utc_iso(now - 30), "age_seconds": 30, "stale": False,
                       "measured": True}
    handle = "acct-fixture"
    email = "private@example.invalid"
    issues = [{
        "title": handle,
        "labels": [{"name": "status:available"}],
        "body": ("provider: anthropic\nmodels: [opus]\nsecret_ref: ACCTFIXTURE_TOKEN\n"
                 f"email: {email}\nlimits: 5h_limit=1000 7d_limit=7000\n"),
    }]
    lease_account = hashlib.sha256(f"{handle}:fixture-salt".encode()).hexdigest()[:16]
    leases = {"leases": [
        {"account": lease_account, "claim_id": "a" * 32,
         "holder": "owner/repo#7@run.1", "package": "pkg", "role": "impl", "model": "opus",
         "issued_at": now - 60, "expires_at": now + 60},
        {"account": lease_account, "claim_id": "b" * 32,
         "holder": "owner/repo#8@run.1", "package": "pkg", "role": "impl", "model": "opus",
         "issued_at": now - 60, "expires_at": now - 1},
    ]}
    usage = {handle: {"status": "allowed", "5h_util": "0.42", "5h_reset": now + 3600,
                      "7d_util": "0.8", "7d_reset": now + 86400}}
    # Issue #323: the fixture sweep carries all four lanes in all three display states — `worker`
    # productive, `review` stalled the way the alert defines it, `disarm` errored while still
    # launching (the safety case the fleet `dispatched` count cannot see), `fix` idle — so the page
    # assertions below can state a TONE per lane rather than merely that a cell was populated.
    fixture_lanes = [
        {"lane": "worker", "planned": 3, "launched": 2, "deferred": 1, "error": 0, "state": "ok"},
        {"lane": "review", "planned": 2, "launched": 0, "deferred": 0, "error": 2,
         "state": "stalled"},
        {"lane": "fix", "planned": 0, "launched": 0, "deferred": 0, "error": 0, "state": "idle"},
        {"lane": "disarm", "planned": 1, "launched": 1, "deferred": 0, "error": 1,
         "state": "stalled"},
    ]
    history = [{"at": "2025-06-15T15:05:00Z", "conclusion": "success",
                "dispatched": 2, "deferred": 3, "lanes": fixture_lanes}]
    # `serviced` is pinned to the fixture's own repository (#78) so this golden document stays
    # hermetic: the default reads the live policy, which is exercised on its own rows further down.
    got = build_dashboard(issues, leases, usage, history, None, now, "fixture-salt",
                          probe_status=measured_sidecar, serviced=("owner/repo",),
                          history_status={"outcome": "ok", "detail": ""})
    expected = {
        "schema": SCHEMA,
        "generated_at": "2025-06-15T15:06:40Z",
        # Issue #374: NO `accounts` array, and the provider row carries a headroom WORD plus mean
        # window fractions instead of the five-number account census + Σ-over-accounts sums.
        "provider_quota": [{
            "provider": "anthropic",
            "headroom": "available",
            "signal": "live rate-limit-header probe (per-window utilization)",
            "windows": [
                {"name": "5 hour", "remaining_fraction": 0.58,
                 "soonest_reset": "2025-06-15T16:06:40Z", "oldest_reset": "2025-06-15T16:06:40Z"},
                {"name": "7 day", "remaining_fraction": 0.2,
                 "soonest_reset": "2025-06-16T15:06:40Z", "oldest_reset": "2025-06-16T15:06:40Z"},
            ],
            "soonest_reset": "2025-06-15T16:06:40Z", "oldest_reset": "2025-06-16T15:06:40Z",
        }],
        "fleet": {
            "active_agents": 1,
            "capacity": {"anthropic": True},
            "last_sweep_at": "2025-06-15T15:05:00Z",
            "dispatch_outcomes": history,
        },
        "active_by_repository": {
            "models": ["opus"],
            "repositories": [{"repository": "owner/repo", "counts": {"opus": 1}}],
        },
        "model_health": None,
        # The degradation marker is now on EVERY document (#612 review finding 1), so the golden
        # fixture carries it too — and a measured build must say `measured: True` rather than omit
        # the key, which is what let a sidecar-less build look indistinguishable from a healthy one.
        "usage_probe": measured_marker,
        # Issue #1106: likewise ALWAYS present, so a build whose `gh` history read failed cannot
        # publish the same empty `dispatch_outcomes` a quiet fleet publishes with nothing to say
        # about which of the two it is.
        "dispatch_history": {"outcome": "ok", "detail": "", "fetched": True},
    }
    check("fixture leases + limits -> expected JSON", got, expected)
    check("dispatch log counts", _parse_dispatch_log(
        "2025-01-01Z dispatched worker owner/repo#1\n"
        "2025-01-01Z defer owner/repo#2: busy\n"
        "2025-01-01Z dispatcher complete: 1 worker/review/fix run(s) launched\n"), (1, 1, None))
    _self_test_page_shim(check)
    _self_test_throughput_worker(check)
    _self_test_dispatch_lanes(check, history, issues, leases, usage, now, measured_sidecar)
    _self_test_history_fetch(check, issues, leases, usage, now, measured_sidecar)
    check("raw identity absent", handle not in json.dumps(got) and email not in json.dumps(got), True)
    leaky = copy.deepcopy(got)
    leaky["provider_quota"][0]["debug"] = handle
    try:
        _assert_private(leaky, {handle})
    except DashboardError:
        rejected = True
    else:
        rejected = False
    check("privacy assertion rejects injected raw handle", rejected, True)
    try:
        build_dashboard(issues, {"leases": []}, {}, [], None, now, "")
    except DashboardError:
        salt_missing_failed = True
    else:
        salt_missing_failed = False
    check("missing salt fails closed (no dashboard is built without PROVENANCE_SALT)",
          salt_missing_failed, True)
    invalid_salts_rejected = []
    for invalid_salt in (None, "", "   ", "salt\nvalue"):
        try:
            _require_salt(invalid_salt)
        except DashboardError:
            invalid_salts_rejected.append(True)
        else:
            invalid_salts_rejected.append(False)
    check("invalid salts fail closed", invalid_salts_rejected, [True, True, True, True])
    check("a real salt is accepted (the precondition is not vacuously fatal)",
          _require_salt("fixture-salt"), None)

    # --- Issue #374: NO FLEET COMPOSITION ON THE PUBLIC PAYLOAD. -------------------------------
    # The sharpest statement of the property, and the one that goes red on any partial revert: two
    # fleets that differ ONLY in how many accounts they contain must publish the same document apart
    # from the live-agent counts named as the KNOWN RESIDUAL above. The three-account fixture below
    # is three clones of the one-account fixture — same provider, same limits, same probe numbers,
    # same resets — so every surviving field is one an observer cannot count accounts with, and it
    # is run both idle and at full occupancy. Pre-#374 this was red on accounts (1 row vs 3),
    # accounts_total (1 vs 3),
    # single_account (True vs False), accounts_available (1 vs 3), remaining_account_windows
    # (0.58 vs 1.74), limit_remaining (580 vs 1740), limits_known/accounts_reporting (1 vs 3) and
    # fleet.capacity (eligible/total 1/1 vs 3/3) — i.e. on every field this change touched.
    def clone_fleet(size, busy=0, leases_per_account=1):
        """`size` identical accounts, the first `busy` of them holding `leases_per_account` live
        leases each (accounts really do run several at once — see the #882 note in the
        FLEET-COMPOSITION block: mint-time `max_concurrent_workers` is 12/4, not 1)."""
        clone_issues, clone_usage, clone_leases = [], {}, []
        for index in range(size):
            clone_handle = f"acct-clone-{index}"
            clone_issues.append({
                "title": clone_handle,
                "labels": [{"name": "status:available"}],
                "body": ("provider: anthropic\nmodels: [opus]\n"
                         f"secret_ref: ACCTCLONE{index}_TOKEN\n"
                         "limits: 5h_limit=1000 7d_limit=7000\n"),
            })
            clone_usage[clone_handle] = {"status": "allowed", "5h_util": "0.42",
                                         "5h_reset": now + 3600, "7d_util": "0.8",
                                         "7d_reset": now + 86400}
            if index < busy:
                for slot in range(leases_per_account):
                    clone_leases.append({
                        "account": hashlib.sha256(
                            f"{clone_handle}:fixture-salt".encode()).hexdigest()[:16],
                        "claim_id": f"{len(clone_leases):032x}",
                        "holder": f"owner/repo#{index + 1}@run.{slot + 1}",
                        "package": "pkg", "role": "impl", "model": "opus",
                        "issued_at": now - 60, "expires_at": now + 60})
        # Hermetic serviced set (#78): the clone-invariance property is about the ACCOUNT fleet, so
        # the census row set is pinned to the fixture's own repository rather than reading the live
        # policy — which would make onboarding a target move this row's index.
        built = build_dashboard(clone_issues, {"leases": clone_leases}, clone_usage, history, None,
                                now, "fixture-salt", probe_status=measured_sidecar,
                                serviced=("owner/repo",))
        return {"provider_quota": built["provider_quota"], "fleet": built["fleet"],
                "active_by_repository": built["active_by_repository"]}

    def without_agent_counts(published):
        """The payload minus the KNOWN RESIDUAL (see the FLEET-COMPOSITION block at the top): the
        live-lease counts, which are not claimed to be invariant and are not published as if they
        were."""
        trimmed = copy.deepcopy(published)
        trimmed["fleet"].pop("active_agents")
        trimmed.pop("active_by_repository")
        return trimmed

    check("[#374] a 1-account and a 3-account IDLE fleet publish a byte-identical payload",
          clone_fleet(1), clone_fleet(3))
    # #839 review round 1, finding 1: idle fleets exercise the property at ZERO load, where nothing
    # about the fleet is in play — which is precisely the state the residual cannot be seen from.
    # Re-run it with one live agent per account, so each fixture is a fleet at full occupancy and
    # the per-account census fields (accounts_total 1 vs 3, remaining_account_windows 0.58 vs 1.74,
    # limit_remaining 580 vs 1740, capacity 1/1 vs 3/3) are all live and would diverge on a partial
    # revert.
    check("[#374] ...and so do a BUSY 1-account and 3-account fleet, one live agent per account",
          without_agent_counts(clone_fleet(1, busy=1)),
          without_agent_counts(clone_fleet(3, busy=3)))
    # The residual, ASSERTED rather than implied by omission: the counts trimmed above really do
    # scale with the fleet under load, so the property is "no account census", not "no fleet count".
    # This row is what keeps the page footer and the block comment honest — a change that removes
    # `active_agents` (or one that quietly restores an absolute no-fleet-count claim) has to come
    # through here.
    check("[#374] KNOWN RESIDUAL: the live-agent counts DO scale with the fleet under load",
          [(clone_fleet(size, busy=size)["fleet"]["active_agents"],
            clone_fleet(size, busy=size)["active_by_repository"]["repositories"][0]["counts"])
           for size in (1, 3)],
          [(1, {"opus": 1}), (3, {"opus": 3})])
    # #882: and the residual is exactly that — a LEASE count, which bounds the account count only
    # by ceil(N / the largest `max_concurrent_workers` in the catalog). ONE account holding three
    # concurrent leases publishes the same `active_agents` as three accounts holding one each, so
    # the retired "cap is 1, therefore ≥N accounts" reading is refuted here rather than in prose
    # alone. This goes red if `active_agents` is ever redefined as a count of BUSY ACCOUNTS (the
    # shape a pass that believed the old invariant would think equivalent): the first tuple would
    # read 1, not 3.
    check("[#882] active_agents counts LEASES: 1 account x3 leases == 3 accounts x1 lease",
          [(clone_fleet(1, busy=1, leases_per_account=3)["fleet"]["active_agents"],
            clone_fleet(1, busy=1,
                        leases_per_account=3)["active_by_repository"]["repositories"][0]["counts"]),
           (clone_fleet(3, busy=3)["fleet"]["active_agents"],
            clone_fleet(3, busy=3)["active_by_repository"]["repositories"][0]["counts"])],
          [(3, {"opus": 3}), (3, {"opus": 3})])

    # --- Issue #840: the residual is KEPT, and the ground for keeping it is pinned here. --------
    # That ground (see the FLEET-COMPOSITION block) is that the live-agent surface is a strictly
    # lossier projection of `data/leases.json` on the public `ledger` branch — so bucketing or
    # dropping it withholds nothing. It holds only while the surface is a pure function of the
    # LEDGER (plus `now` and the serviced set, itself public in policy/repos.toml). Below: one
    # ledger at non-zero load, built twice with every OTHER input disagreeing, required to publish
    # the same live-agent surface. Goes red on `len(live) + eligible`, on a per-account breakdown,
    # on gating the count behind the probe verdict, and on a "publish 0 when unmeasured" degradation
    # — each of which would put something on the page that the ledger branch does not already carry.
    residual_leases = {"leases": [
        {"account": lease_account, "claim_id": "c" * 32, "holder": "owner/repo#11@run.1",
         "package": "pkg", "role": "impl", "model": "opus",
         "issued_at": now - 60, "expires_at": now + 60},
        {"account": lease_account, "claim_id": "d" * 32, "holder": "owner/repo#12@run.1",
         "package": "pkg", "role": "review", "model": "haiku",
         "issued_at": now - 60, "expires_at": now + 60},
        {"account": lease_account, "claim_id": "e" * 32, "holder": "owner/other#13@run.1",
         "package": "pkg", "role": "impl", "model": "opus",
         "issued_at": now - 60, "expires_at": now + 60},
        # On the ledger but EXPIRED: the projection is of the LIVE rows, so a reader counting rows
        # blind would get 4 where the page says 3. Keeps the expected value below hand-counted
        # rather than "however many rows the fixture happens to have".
        {"account": lease_account, "claim_id": "f" * 32, "holder": "owner/repo#14@run.1",
         "package": "pkg", "role": "impl", "model": "opus",
         "issued_at": now - 600, "expires_at": now - 1},
    ]}

    def residual_build(catalog, account_usage, sweeps, health, sidecar):
        return build_dashboard(catalog, residual_leases, account_usage, sweeps, health, now,
                               "fixture-salt", probe_status=sidecar, serviced=("owner/repo",))

    def agent_surface(built):
        return {"active_agents": built["fleet"]["active_agents"],
                "active_by_repository": built["active_by_repository"]}

    residual_baseline = residual_build(issues, usage, history, None, measured_sidecar)
    residual_varied = residual_build(
        [{"title": f"acct-840-{index}", "labels": [{"name": "status:available"}],
          "body": (f"provider: openai\nmodels: [haiku]\nsecret_ref: ACCT840{index}_TOKEN\n")}
         for index in range(3)],
        {}, [], {"models": [{"model": "haiku", "status": "degraded"}]},
        {"schema": PROBE_SCHEMA, "outcome": "failed", "detail": "probe-failed",
         "attempted_at": now - 30})
    residual_surface = {
        "active_agents": 3,
        "active_by_repository": {
            "models": ["haiku", "opus"],
            "repositories": [{"repository": "owner/other", "counts": {"opus": 1}},
                             {"repository": "owner/repo", "counts": {"opus": 1, "haiku": 1}}],
        },
    }
    check("[#840] the live-agent surface is exactly the ledger's LIVE rows (3 of 4 fixture rows)",
          agent_surface(residual_baseline), residual_surface)
    check("[#840] ...and is unchanged by every input the `ledger` branch does not carry: a "
          "3-account openai catalog, no usable usage, a DISTRUSTED probe, model health, no sweeps",
          agent_surface(residual_varied), residual_surface)
    # Non-vacuity: an invariance row proves nothing if the variation was inert. Each axis varied
    # above is shown to have MOVED the rest of the document, so the equality above is a real
    # separation and not two identical builds compared with extra steps.
    check("[#840] ...and that variation really did move the rest of the payload (non-vacuity)",
          (residual_baseline["fleet"]["capacity"] == residual_varied["fleet"]["capacity"],
           residual_baseline["provider_quota"] == residual_varied["provider_quota"],
           residual_baseline["usage_probe"]["measured"],
           residual_varied["usage_probe"]["measured"],
           residual_baseline["model_health"] == residual_varied["model_health"],
           residual_baseline["fleet"]["dispatch_outcomes"]
           == residual_varied["fleet"]["dispatch_outcomes"]),
          (False, False, True, False, False, False))

    check("[#374] ...and that payload still reports the headroom honestly (not blanked out)",
          (clone_fleet(3)["provider_quota"][0]["headroom"],
           clone_fleet(3)["provider_quota"][0]["windows"][0]["remaining_fraction"],
           clone_fleet(3)["fleet"]["capacity"]),
          ("available", 0.58, {"anthropic": True}))
    check("[#374] the golden document carries none of the composition keys",
          sorted(FLEET_COMPOSITION_KEYS
                 & set(re.findall(r'"([^"]+)":', json.dumps(got)))), [])
    for banned_key, banned_value in (("accounts", []), ("accounts_total", 3),
                                     ("single_account", True), ("label", "26208fef35e33b14"),
                                     ("eligible", 1), ("limit_remaining", 580)):
        poisoned = copy.deepcopy(got)
        poisoned["fleet"][banned_key] = banned_value
        try:
            _assert_no_fleet_composition(poisoned)
        except DashboardError:
            composition_rejected = True
        else:
            composition_rejected = False
        check(f"[#374] a re-introduced `{banned_key}` key fails the build closed",
              composition_rejected, True)
    check("[#374] ...and the real document passes the same assertion (not vacuously fatal)",
          _assert_no_fleet_composition(got), None)
    check("[#374] the assertion reaches keys nested inside lists, not just the top level",
          _raises_dashboard(lambda: _assert_no_fleet_composition(
              {"provider_quota": [{"windows": [{"accounts_reporting": 2}]}]})), True)

    def issue(account_handle, provider, secret):
        return {
            "title": account_handle,
            "labels": [{"name": "status:available"}],
            "body": (f"provider: {provider}\nmodels: [haiku]\n"
                     f"secret_ref: {secret}\n"),
        }

    ordered_handles = ["anth-late", "anth-unknown", "anth-soon", "openai-one", "future-one"]
    ordered_issues = [
        issue("anth-late", "anthropic", "ACCTLATE_TOKEN"),
        issue("anth-unknown", "anthropic", "ACCTUNKNOWN_TOKEN"),
        issue("anth-soon", "anthropic", "ACCTSOON_TOKEN"),
        issue("openai-one", "openai", "ACCTOPENAI_TOKEN"),
        issue("future-one", "future-provider", "ACCTFUTURE_TOKEN"),
    ]
    ordered_usage = {
        "anth-late": {"status": "allowed", "7d_reset": now + 900},
        "anth-unknown": {"status": "allowed"},
        "anth-soon": {"status": "allowed", "7d_reset": now + 100},
        # [#639] the probe stamps reachability on every exempt entry (absent => unknown, so a
        # fixture without it would exercise the refusal path rather than the healthy one).
        "openai-one": {"exempt": True, "reachability": "live"},
        "future-one": {"status": "allowed", "7d_reset": now + 500},
    }
    activity_leases = {"leases": [
        {"account": "1" * 16, "claim_id": "1" * 32,
         "holder": "org/alpha#1@run.1", "package": "pkg", "role": "impl", "model": "sol",
         "issued_at": now - 30, "expires_at": now + 30},
        {"account": "2" * 16, "claim_id": "2" * 32,
         "holder": "review:org/alpha#2@run.1", "package": "pkg", "role": "review",
         "model": "fable", "issued_at": now - 30, "expires_at": now + 20},
        {"account": "3" * 16, "claim_id": "3" * 32,
         "holder": "fix:org/beta#3@run.1", "package": "pkg", "role": "fix", "model": "opus",
         "issued_at": now - 30, "expires_at": now + 10},
        {"account": "4" * 16, "claim_id": "4" * 32,
         "holder": "org/expired#4@old", "package": "pkg", "role": "impl", "model": "terra",
         "issued_at": now - 30, "expires_at": now - 1},
    ]}
    # Live ledger fixture — the exact {"records": [...]} shape model-health.py writes (#218).
    health_ledger = {"records": [
        {"ts": now - 900, "provider": "anthropic", "account": "a" * 16,
         "model_alias": "fable", "exit_class": "transient", "run_id": "r1"},
        {"ts": now - 600, "provider": "anthropic", "account": "b" * 16,
         "model_alias": "fable", "exit_class": "success", "run_id": "r2"},
        {"ts": now - 300, "provider": "openai", "account": "c" * 16,
         "model_alias": "codex", "exit_class": "limit", "run_id": "r3",
         "reset_hint": "2025-06-15T18:00:00Z"},
        {"ts": now - 120, "provider": "anthropic", "account": "d" * 16,
         "model_alias": "", "exit_class": "zero-dispatch", "run_id": "r4"},
        # [#1827] The no-change rows the reason census counts. They are deliberately the OLDEST
        # rows in the fixture (older than the `transient` at -900) so `since` cannot pass by
        # reporting the ledger's own span, and none of them is the newest row, so `generated_at`
        # stays where the pre-#1827 rows put it. Two carry the SAME reason (so the census counts
        # rather than sets), one carries NO `why_no_diff` at all (the fold to `unspecified`), and
        # one has an EMPTY model_alias — the per-model strip skips that row, and the census must
        # not, because a run nobody could attribute to a tier is still a no-change run.
        {"ts": now - 1500, "provider": "anthropic", "account": "e" * 16,
         "model_alias": "fable", "exit_class": "no_change", "run_id": "r5",
         "issue": 1827, "why_no_diff": "too_large"},
        {"ts": now - 1400, "provider": "anthropic", "account": "f" * 16,
         "model_alias": "", "exit_class": "no_change", "run_id": "r6",
         "issue": 1595, "why_no_diff": "too_large"},
        {"ts": now - 1300, "provider": "openai", "account": "1" * 16,
         "model_alias": "codex", "exit_class": "no_change", "run_id": "r7", "issue": 738},
        {"ts": now - 1200, "provider": "anthropic", "account": "2" * 16,
         "model_alias": "fable", "exit_class": "no_change", "run_id": "r8",
         "issue": 701, "why_no_diff": "already_done"},
    ]}
    # Issue #78: the serviced set handed in here is deliberately NOT the set of repositories the
    # fixture's leases name. `org/alpha` is serviced AND busy, `org/idle` is serviced and quiet (so
    # it must publish an explicit zero row), and `org/beta` holds a live lease WITHOUT being
    # serviced (so live evidence must survive a policy that did not predict it). None of these three
    # names appears anywhere else in this suite, so nothing here can pass by colliding with another
    # fixture's value.
    ordered = build_dashboard(
        ordered_issues, activity_leases, ordered_usage, [], health_ledger, now, "fixture-salt",
        probe_status=measured_sidecar, serviced=("org/alpha", "org/idle"))
    # [#1827] The census travels with the checks, through the PRODUCTION call site
    # (build_dashboard -> _normalize_model_health -> _normalize_ledger_health), and the whole
    # `model_health` block is compared by equality — a census dropped, renamed, or reshaped reds
    # this row. Every reason NAME and count is written out here rather than derived from
    # `NO_CHANGE_REASONS` (pre-flight item 2(b): an expected value read out of the code under test
    # cannot fail), which also pins the vocabulary's ORDER — it is the #701 wire format, and a
    # reorder there silently re-labels every previously stored index.
    check("canonical records ledger -> per-provider/model checks, and [#1827] the declared "
          "no-change reason census beside them: counted (not set-ified), zero rows kept, an "
          "absent declaration folded to `unspecified`, an unattributable run still counted, and "
          "`since` reading the OLDEST no-change run rather than the ledger's own span",
          ordered["model_health"], {
        "generated_at": _utc_iso(now - 120),
        "checks": [
            {"model": "fable", "provider": "anthropic", "status": "healthy",
             "checked_at": _utc_iso(now - 600)},
            {"model": "codex", "provider": "openai", "status": "degraded",
             "checked_at": _utc_iso(now - 300)},
        ],
        "no_change_reasons": {
            "runs": 4,
            "since": _utc_iso(now - 1500),
            "reasons": [
                {"reason": "unspecified", "count": 1},
                {"reason": "underspecified", "count": 0},
                {"reason": "blocked_on_decision", "count": 0},
                {"reason": "too_large", "count": 2},
                {"reason": "already_done", "count": 1},
                {"reason": "other", "count": 0},
            ],
        },
    })
    # ...and the ZERO row, which is the mutant item 3 exists for: a census emitted only
    # `if runs` reads identically to a healthy board on the quiet tick that is exactly when an
    # operator interrogates it. Same ledger shape, no no-change rows in it at all.
    quiet_census = _normalize_model_health({"records": [
        {"ts": now - 300, "provider": "openai", "account": "9" * 16,
         "model_alias": "codex", "exit_class": "success", "run_id": "z1"}]}).get(
             # `.get`, not `[...]`: a mutant that DROPS the key must red the row below by name,
             # never abort the suite here and score as a kill with 291 checks unrun (pre-flight
             # item 4, *crash-after-partial-run* — measured on exactly that mutant).
             "no_change_reasons")
    check("[#1827] a ledger with NO no-change runs still publishes the census — every reason at "
          "zero and a null span, never an omitted or empty block",
          quiet_census,
          {"runs": 0, "since": None,
           "reasons": [{"reason": "unspecified", "count": 0},
                       {"reason": "underspecified", "count": 0},
                       {"reason": "blocked_on_decision", "count": 0},
                       {"reason": "too_large", "count": 0},
                       {"reason": "already_done", "count": 0},
                       {"reason": "other", "count": 0}]})
    # [#1950] WHAT THE `unspecified` ROW MEANS, pinned so a later reader cannot re-split it. The
    # producer omits index 0 from the envelope for EVERY ingress (worker-live's own self-test pins
    # the absent, the unparseable and the explicit `{"why": "unspecified"}` directions), so a
    # STORED `unspecified` never arrives from the live fleet — but the ledger schema admits one, so
    # the reader has to put it somewhere. Both facts land in ONE bucket: a change that gave the
    # stored form its own row would publish a structural zero beside a real number, and reds here
    # rather than shipping. The two rows are otherwise IDENTICAL apart from the field, so nothing
    # but the fold can produce the count below.
    fold_census = _normalize_model_health({"records": [
        {"ts": now - 1700, "provider": "openai", "account": "8" * 16, "model_alias": "codex",
         "exit_class": "no_change", "run_id": "u1", "issue": 1950},
        {"ts": now - 1600, "provider": "openai", "account": "8" * 16, "model_alias": "codex",
         "exit_class": "no_change", "run_id": "u2", "issue": 1950,
         "why_no_diff": "unspecified"}]}).get("no_change_reasons")
    check("[#1950] an ABSENT declaration and a (producer-unreachable) STORED `unspecified` are ONE "
          "bucket — the census never splits 'declared nothing' into a real number beside the "
          "structural zero the live producer can never fill",
          fold_census,
          {"runs": 2, "since": _utc_iso(now - 1700),
           "reasons": [{"reason": "unspecified", "count": 2},
                       {"reason": "underspecified", "count": 0},
                       {"reason": "blocked_on_decision", "count": 0},
                       {"reason": "too_large", "count": 0},
                       {"reason": "already_done", "count": 0},
                       {"reason": "other", "count": 0}]})
    # The PAGE half, driven by the two payloads pinned immediately above rather than by fixtures
    # written to match it (pre-flight item 11: a census that normalizes perfectly and is never
    # drawn has delivered nothing).
    _self_test_health_census(check, ordered["model_health"], quiet_census)
    try:
        _normalize_model_health({"records": [
            {"ts": now, "provider": "anthropic", "account": "acct01",
             "model_alias": "fable", "exit_class": "success", "run_id": "r5"},
        ]})
    except DashboardError:
        ledger_rejected = True
    else:
        ledger_rejected = False
    check("malformed records ledger fails loudly, never a fabricated check",
          ledger_rejected, True)
    # Issue #374 replaced the per-account rows this used to order with one row per provider; the
    # surviving public ordering promise is "one alphabetical row per provider, no account rows".
    check("one alphabetical provider row, and no per-account rows at all",
          ([row["provider"] for row in ordered["provider_quota"]], "accounts" in ordered),
          (["anthropic", "future-provider", "openai"], False))
    check("repo/model table parses impl + review + fix and excludes expired, and [#78] emits a "
          "ZERO row for a serviced-but-quiet repository while keeping a busy unserviced one", [
        ordered["fleet"]["active_agents"], ordered["active_by_repository"]
    ], [3, {
        "models": ["fable", "opus", "sol"],
        "repositories": [
            {"repository": "org/alpha", "counts": {"sol": 1, "fable": 1}},
            {"repository": "org/beta", "counts": {"opus": 1}},
            {"repository": "org/idle", "counts": {}},
        ],
    }])
    check("expanded fixture preserves private account identities",
          all(account_handle not in json.dumps(ordered) for account_handle in ordered_handles), True)

    # --- Issue #78: WHERE THE CENSUS ROW SET COMES FROM, and that it cannot narrow silently. -----
    # The row set is the ENABLED targets of policy/repos.toml. Every leg below is either a hermetic
    # policy literal or a claim about the LIVE file that is written here rather than read out of the
    # reader (pre-flight item 2(b): an expected value taken from the code under test cannot fail).
    # The path is written out LITERALLY here rather than taken from POLICY_PATH_PARTS (pre-flight
    # item 2(c)): an input derived from the constant the code reads moves with it, so a repoint at
    # some other readable TOML would keep this row green. The constant is pinned by equality instead.
    check("[#78] the census reads THIS repo's worker policy, and nothing else can be substituted "
          "for it", POLICY_PATH_PARTS, ("policy", "repos.toml"))
    live_serviced = _serviced_repositories(_repo_file("policy", "repos.toml"))
    check("[#78] the live worker policy resolves to owner/name targets, and the registry itself is "
          "one of them — so the real board can never render a census with no rows",
          ("jeswr/agent-account-registry" in live_serviced,
           bool(live_serviced) and all(SAFE_REPOSITORY_RE.fullmatch(repo) is not None
                                       for repo in live_serviced),
           live_serviced == sorted(set(live_serviced))),
          (True, True, True))
    # The `enabled` filter, killed by its own row: a reader that ignored the flag would publish
    # `off/two` as a serviced repository the pipeline never dispatches to.
    check("[#78] only ENABLED targets become census rows, de-duplicated and sorted",
          _serviced_repositories('[repos."on/one"]\nenabled = true\n'
                                 '[repos."off/two"]\nenabled = false\n'
                                 '[repos."on/three"]\nenabled = true\n'),
          ["on/one", "on/three"])

    def serviced_refused(text):
        try:
            _serviced_repositories(text)
        except DashboardError:
            return True
        return False

    # Each refusal narrows or fabricates the ROW SET if it is waved through, so each must die. The
    # last leg is the non-vacuity control: the minimal well-formed policy is ACCEPTED, which is what
    # stops a reader that simply refuses everything from passing the five rows above it.
    #
    # ⚠️ The malformed-row and non-boolean-`enabled` legs each pair their bad target with a VALID
    # enabled one on purpose. Measured: with a lone bad target, a mutant that reads an unparseable
    # `enabled` as "disabled" still refuses — via the no-enabled-targets guard below — and SURVIVED.
    # Two guards masking each other is pre-flight item 4's fourth outcome; the valid neighbour is
    # what makes each leg fail on its own guard rather than on the other one.
    check("[#78] a policy this reader cannot fully understand refuses the build instead of "
          "publishing the rows it did manage to parse — and a well-formed one is still accepted",
          (serviced_refused("this is not = [ toml"),
           serviced_refused("# a policy with no [repos.*] table at all\n"),
           serviced_refused('[repos]\n"bad/one" = 1\n[repos."ok/one"]\nenabled = true\n'),
           serviced_refused('[repos."ok/one"]\nenabled = true\n[repos."o/r"]\nenabled = 1\n'),
           serviced_refused('[repos."o/r"]\nenabled = false\n'),
           serviced_refused('[repos."ok/one"]\nenabled = true\n'
                            '[repos."not-a-repository"]\nenabled = true\n'),
           serviced_refused('[repos."o/r"]\nenabled = true\n')),
          (True, True, True, True, True, True, False))
    # THE DEFAULT IS NOT AN EMPTY SEED (#612 review finding 1 applied to this argument): omitting
    # `serviced` must read the live policy, not skip the seeding. A build with no catalog, no leases
    # and no history still names every repository we service, each at an explicit zero.
    default_rows = build_dashboard([], {"leases": []}, None, [], None, now,
                                   "fixture-salt")["active_by_repository"]
    check("[#78] with NO serviced argument the build reads the LIVE policy — the default can never "
          "be the lease-only row set this issue closes",
          (default_rows["models"],
           "jeswr/agent-account-registry" in [row["repository"]
                                              for row in default_rows["repositories"]],
           all(row["counts"] == {} for row in default_rows["repositories"])),
          ([], True, True))

    def activity_refused(lease):
        try:
            _repository_activity([lease], ())
        except DashboardError:
            return True
        return False

    # Measured with `python3 -m trace --count` before this change: BOTH refusal lines of
    # `_repository_activity` were never executed by this suite. The one row that looked like it
    # covered them ("malformed live lease fails loudly") is rejected earlier, by
    # lease_schema.validate_ledger, so the census's own guards were untested.
    activity_lease = {"holder": "org/gamma#9@run.1", "model": "sol"}
    check("[#78] the census refuses a live lease whose holder or model it cannot read, and accepts "
          "the well-formed one (so the five refusals are not a reader that refuses everything)",
          (activity_refused(dict(activity_lease, holder="org/gamma#9")),
           activity_refused(dict(activity_lease, holder="org/gamma#9@run.1 extra")),
           activity_refused(dict(activity_lease, holder=None)),
           activity_refused(dict(activity_lease, model="sol sol")),
           activity_refused(dict(activity_lease, model=None)),
           activity_refused(activity_lease)),
          (True, True, True, True, True, False))

    # --- the page. EXECUTED, not pattern-matched: what an operator can read off the table. -------
    # First the LAST HOP (pre-flight item 11): a census that renders perfectly but is never called
    # from `render()` delivers into a panel still reading "Loading agent activity…".
    check("[#78] render() actually hands the payload's census and the published live-lease count to "
          "the table renderer",
          _js_code_count(_js_function_body(_repo_file("dashboard", "app.js"), "render"),
                         "renderRepositoryAgents(data.active_by_repository, "
                         "data.fleet.active_agents);"), 1)
    repo_agents_page = _page_harness("renderRepositoryAgents", _REPO_AGENTS_PAGE_BODY)
    try:
        rendered_agents = _node_json(repo_agents_page, {"cases": {
            # A fully quiet fleet: no model is live anywhere, so there are no per-model columns and
            # the row total is the ONLY number on the page. Pre-#78 this rendered no rows at all.
            "quiet": {"active": 0, "activity": {"models": [], "repositories": [
                {"repository": "quiet/one", "counts": {}},
                {"repository": "quiet/two", "counts": {}}]}},
            # The mixed tick the issue actually asks for: per-model counts per repository, with a
            # serviced-but-idle repository reading zero rather than being absent.
            "mixed": {"active": 3, "activity": {"models": ["opus5", "sol"], "repositories": [
                {"repository": "busy/one", "counts": {"sol": 2, "opus5": 1}},
                {"repository": "idle/two", "counts": {}}]}},
            # A payload that names NO serviced repository is not evidence of an idle fleet.
            "norows": {"active": 0, "activity": {"models": [], "repositories": []}},
            # The row set and the fleet count must still be cross-checked.
            "mismatch": {"active": 9, "activity": {"models": ["sol"], "repositories": [
                {"repository": "busy/one", "counts": {"sol": 2}}]}},
        }})
    except DashboardError as exc:
        rendered_agents = {"page script raised": str(exc)[:160]}

    def agents_case(name, field):
        case = rendered_agents.get(name)
        return case.get(field) if isinstance(case, dict) else rendered_agents

    check("[#78] EXECUTED page script: a quiet tick still publishes one row per serviced "
          "repository, each carrying an explicit 0 — the table does not vanish",
          (agents_case("quiet", "header"), agents_case("quiet", "rows"),
           agents_case("quiet", "tableHidden"), agents_case("quiet", "emptyText")),
          (["Repository", "Agents"], [["quiet/one", "0"], ["quiet/two", "0"]], False, None))
    check("[#78] EXECUTED page script: one column per live model plus the row total, and the "
          "header and every row agree on the column count",
          (agents_case("mixed", "header"), agents_case("mixed", "rows"),
           [len(row) for row in agents_case("mixed", "rows")]
           if isinstance(agents_case("mixed", "rows"), list) else None),
          (["Repository", "Agents", "opus5", "sol"],
           [["busy/one", "3", "1", "2"], ["idle/two", "0", "0", "0"]], [4, 4]))
    check("[#78] EXECUTED page script: a payload naming no serviced repository says so, rather "
          "than reporting an idle fleet it never observed",
          (agents_case("norows", "emptyText"), agents_case("norows", "tableHidden"),
           agents_case("norows", "rows")),
          ("No serviced repositories in this snapshot.", True, []))
    check("[#78] EXECUTED page script: the zero rows do not weaken the cross-check against the "
          "published live-lease count",
          agents_case("mismatch", "error"), "repository activity does not match live lease count")

    # --- provider-cumulative quota (maintainer request 2026-07-18): 2 providers — one
    # multi-account anthropic with mixed capped/free (+ one fail-closed-omitted account), one
    # single-account probe-exempt openai under an active backoff. Asserts the aggregation math,
    # the honest signal labels, and that no raw handle reaches the rows (decision 22). ----------
    quota_handles = ["multi-a", "multi-b", "multi-c", "solo-openai"]
    quota_accounts = [
        {"handle": "multi-a", "provider": "anthropic", "catalog_available": True, "limits": {}},
        {"handle": "multi-b", "provider": "anthropic", "catalog_available": True,
         "limits": {"5h_limit": "1000"}},  # overridden by the probe's live 5h_limit below
        {"handle": "multi-c", "provider": "anthropic", "catalog_available": True, "limits": {}},
        {"handle": "solo-openai", "provider": "openai", "catalog_available": True, "limits": {}},
    ]
    quota_usage = {
        "multi-a": {"status": "allowed", "5h_util": "0.25", "5h_reset": now + 600,
                    "7d_util": "0.5", "7d_reset": now + 4000},
        # multi-b: capped on the 7d window, but with NONZERO 5h headroom (0.1) so the
        # limit-weighted sum distinguishes limit PRECEDENCE non-vacuously (sol finding 4,
        # PR #281 fix round): the LIVE 5h_limit header (2000) must beat the persisted catalog
        # limit (1000) — 2000×0.1=200, not 100. Swapping the precedence turns this red.
        "multi-b": {"status": "allowed", "5h_util": "0.9", "5h_reset": now + 1200,
                    "5h_limit": "2000", "7d_util": "1.0", "7d_reset": now + 90000},
        # multi-c: probe fail-closed omitted — counts in the total and as UNKNOWN/unreported
        # (dispatch treats the omission as unavailable), never in accounts_reporting and
        # never as free (sol finding 2, PR #281 fix round)
        "solo-openai": {"exempt": True, "reachability": "live", "backoff_until": now + 300},
    }
    quota_rows = _provider_quota(quota_accounts, quota_usage, now)
    check("cumulative quota: multi-account provider aggregates mixed capped/free", quota_rows[0], {
        "provider": "anthropic", "accounts_total": 3, "accounts_available": 1,
        "accounts_capped": 1, "accounts_unavailable": 0, "accounts_unknown": 1,
        "single_account": False,
        "signal": "live rate-limit-header probe (per-window utilization)",
        "windows": [
            # 0.75 free (multi-a) + 0.1 free (7d-capped multi-b); only multi-b's LIVE limit is
            # known, so the limit-weighted sum is PARTIAL (limits_known 1 of 2) and equals
            # live 2000 × 0.1 = 200 (the persisted-limit precedence would fabricate 100).
            {"name": "5 hour", "accounts_reporting": 2, "remaining_account_windows": 0.85,
             "limit_remaining": 200, "limits_known": 1,
             "soonest_reset": _utc_iso(now + 600), "oldest_reset": _utc_iso(now + 1200)},
            # no account exposes a 7d limit -> no limit-weighted sum is fabricated
            {"name": "7 day", "accounts_reporting": 2, "remaining_account_windows": 0.5,
             "limit_remaining": None, "limits_known": 0,
             "soonest_reset": _utc_iso(now + 4000), "oldest_reset": _utc_iso(now + 90000)},
        ],
        "soonest_reset": _utc_iso(now + 600), "oldest_reset": _utc_iso(now + 90000),
    })
    check("cumulative quota: single-account probe-exempt provider stays honest", quota_rows[1], {
        "provider": "openai", "accounts_total": 1, "accounts_available": 0,
        "accounts_capped": 1, "accounts_unavailable": 0, "accounts_unknown": 0,
        "single_account": True,
        "signal": ("not observable (probe-exempt provider): catalog availability "
                   "+ reactive rate-limit backoff only"),
        "windows": [],  # no usage signal exists -> no remaining-quota number is fabricated
        "soonest_reset": _utc_iso(now + 300), "oldest_reset": _utc_iso(now + 300),
    })
    # [#628] A DISTRUSTED snapshot must not borrow the future-provider wording. Once the probe
    # verdict fails closed, build_dashboard hands over an empty usage map, so every row fell into
    # the "no live usage signal (catalog availability only)" branch — which says the provider
    # exposes no usage headers (it may well expose them; the probe broke) and still credits catalog
    # availability as the signal (it is deliberately not counted as free). Each reason word is
    # pinned separately, so collapsing the outcomes into one label turns a row red.
    def _distrust_signal(reason):
        return (f"{reason} — no measurement for this snapshot "
                "(catalog availability is not counted as free)")

    unmeasured_probes = {
        "failed": _probe_outcome({"schema": PROBE_SCHEMA, "outcome": "failed",
                                  "attempted_at": now - 30}, now),
        "stale ok": _probe_outcome({"schema": PROBE_SCHEMA, "outcome": "ok",
                                    "attempted_at": now - PROBE_MAX_AGE_SECONDS - 1}, now),
        "no sidecar": _probe_outcome(None, now),
    }
    check("[#628] a distrusted snapshot names the probe, and the reason tracks the outcome",
          {name: _provider_quota(quota_accounts[3:], {}, now, probe)[0]["signal"]
           for name, probe in unmeasured_probes.items()},
          {"failed": _distrust_signal("usage probe failed"),
           "stale ok": _distrust_signal("usage probe is stale"),
           "no sidecar": _distrust_signal("usage probe outcome is unknown")})
    check("[#628] ...and none of them is the no-usage-headers label that provider would emit",
          [_provider_quota(quota_accounts[3:], {}, now)[0]["signal"],
           any(_provider_quota(quota_accounts[3:], {}, now, probe)[0]["signal"]
               == _provider_quota(quota_accounts[3:], {}, now)[0]["signal"]
               for probe in unmeasured_probes.values())],
          ["no live usage signal (catalog availability only)", False])
    # Both directions of the precedence. A distrusted verdict wins over the probed/exempt
    # derivation (those are read out of the rejected snapshot, so "live rate-limit-header probe"
    # would be a claim the verdict cannot back) — and a MEASURED verdict changes nothing at all,
    # so the new branch cannot swallow the honest labels.
    check("[#628] a distrusted verdict never claims a live measurement, however live the map looks",
          [row["signal"] for row in _provider_quota(quota_accounts, quota_usage, now,
                                                    unmeasured_probes["failed"])],
          [_distrust_signal("usage probe failed")] * 2)
    check("[#628] a measured verdict leaves the probed/exempt signals exactly as they were",
          [row["signal"] for row in _provider_quota(
              quota_accounts, quota_usage, now,
              _probe_outcome({"schema": PROBE_SCHEMA, "outcome": "ok",
                              "attempted_at": now - 30}, now))],
          [quota_rows[0]["signal"], quota_rows[1]["signal"]])
    check("cumulative quota: fail-closed-omitted account is unknown, never free",
          [(row["accounts_available"], row["accounts_unknown"]) for row in _provider_quota(
              [{"handle": "ghost", "provider": "anthropic", "catalog_available": True,
                "limits": {}}], {}, now)],
          [(0, 1)])
    # Backoff-stamp parsing PARITY (sol finding 3, PR #281 fix round): the dashboard's "capped"
    # rendering and the allocator's admission decision must be the same predicate on the same
    # input — dashboard-gen used to accept Infinity/absurd integers (rendering "capped
    # indefinitely" while select-and-claim failed open and kept USING the account) and ignored
    # parseable string epochs (rendering "available" while the allocator backed off). One shared
    # vector locks both scripts to the allocator's _usage_num + isfinite semantics.
    allocator = _select_and_claim_module()
    exempt_account = {"handle": "solo-openai", "provider": "openai",
                      "catalog_available": True, "limits": {}}
    for stamp, want_capped in ((now + 300, True), (float(now + 300), True),
                               (str(now + 300), True),          # parseable string epoch: capped
                               (f"{now + 300}.5", True),
                               (now - 1, False),                # expired: free again
                               (float("inf"), False),           # non-finite: fail OPEN
                               ("inf", False), ("nan", False),
                               (10 ** 400, False),              # absurd int: float() overflows
                               ("garbage", False), (None, False), ([], False), ({}, False),
                               (True, False)):
        entry = {"exempt": True, "reachability": "live", "backoff_until": stamp}
        state, _until = _quota_state(exempt_account, entry, now)
        check(f"backoff stamp {str(stamp)[:24]!r}: dashboard capped == allocator excluded",
              (state == "capped", not allocator.usage_eligible(entry, now=now)),
              (want_capped, want_capped))
    # [registry #639] EXEMPTION IS NOT REACHABILITY, on the page too. #612 made the page honest about
    # a failed PROBE; this makes it honest about a dead CREDENTIAL. The pairing is the point: every row
    # asserts the page state and the allocator verdict TOGETHER, so neither surface can drift into
    # advertising capacity the other refuses (or vice versa).
    for reachability, want_state in (("live", "available"), ("unproven", "available"),
                                     ("dead", "unavailable"),
                                     (None, "unknown"),          # producer never stated it
                                     ("LIVE", "unknown"), ("available", "unknown"),
                                     (True, "unknown"), ({}, "unknown")):
        reach_entry = {"exempt": True}
        if reachability is not None:
            reach_entry["reachability"] = reachability
        state, _until = _quota_state(exempt_account, reach_entry, now)
        check(f"[#639] exempt reachability {reachability!r}: page state == allocator verdict",
              (state, state == "available", allocator.usage_eligible(dict(reach_entry), now=now)),
              (want_state, want_state == "available", want_state == "available"))
    check("[#639] a DEAD exempt account contributes no cumulative capacity either",
          [(row["accounts_available"], row["accounts_capped"], row["accounts_unavailable"])
           for row in _provider_quota(
               quota_accounts[3:], {"solo-openai": {"exempt": True, "reachability": "dead"}}, now)],
          [(0, 0, 1)])
    check("cumulative quota: expired backoff no longer counts as capped",
          [(row["accounts_available"], row["accounts_capped"]) for row in _provider_quota(
              quota_accounts[3:],
              {"solo-openai": {"exempt": True, "reachability": "live", "backoff_until": now - 1}},
              now)],
          [(1, 0)])
    # PARTIAL probe entries are never free (sol finding 1, PR #281 fix round 3):
    # account-usage.py can emit an entry whose mandatory utilization windows are missing
    # (status-only, or 5h without 7d) — dispatch (usage_eligible) and usage-alert (classify)
    # both fail closed on that shape, so the dashboard must file it under accounts_unknown
    # ("unreported — treated unavailable by dispatch"), not "1 free". Each shape is also
    # parity-checked against the allocator's own admission predicate.
    partial_account = {"handle": "partial", "provider": "anthropic",
                       "catalog_available": True, "limits": {}}
    for shape_name, partial_entry in (
            ("status-only", {"status": "allowed"}),
            ("5h-only", {"status": "allowed", "5h_util": "0.2", "5h_reset": now + 600,
                         "5h_limit": "1000"})):
        state, _until = _quota_state(partial_account, partial_entry, now)
        check(f"partial probe entry ({shape_name}) is unknown, never free",
              (state, allocator.usage_eligible(dict(partial_entry), now=now)),
              ("unknown", False))
        # The COMPLETE row (sol finding, PR #281 fix round 4): an unknown account contributes
        # NOTHING — even though the 5h-only shape carries a fully parseable window (util 0.2 +
        # reset + limit), the row's windows stay EMPTY and no reset/limit is aggregated. Before
        # this round it rendered "accounts_unknown: 1" NEXT TO "0.8 of 1 account-window free"
        # summed from that very account.
        check(f"partial probe entry ({shape_name}) contributes nothing to the provider row",
              _provider_quota([partial_account], {"partial": dict(partial_entry)}, now),
              [{"provider": "anthropic", "accounts_total": 1, "accounts_available": 0,
                "accounts_capped": 0, "accounts_unavailable": 0, "accounts_unknown": 1,
                "single_account": True,
                "signal": "live rate-limit-header probe (per-window utilization)",
                "windows": [], "soonest_reset": None, "oldest_reset": None}])
    check("both-windows entry still counts available (not over-rejected)",
          _quota_state(partial_account,
                       {"status": "allowed", "5h_util": "0.2", "7d_util": "0.3"}, now),
          ("available", None))
    # Mixed complete+partial provider (sol finding, PR #281 fix round 4): the sums must reflect
    # ONLY the complete account. The partial account's parseable 5h window is a trap on every
    # aggregate axis — earlier reset (would flip soonest_reset), big known limit (would inflate
    # limit_remaining + limits_known), 0.9 headroom (would inflate remaining + reporting) — so
    # reverting the aggregation exclusion turns this red on the first leaked field.
    mixed_accounts = [
        {"handle": "mixed-full", "provider": "anthropic", "catalog_available": True,
         "limits": {}},
        {"handle": "mixed-partial", "provider": "anthropic", "catalog_available": True,
         "limits": {}},
    ]
    mixed_usage = {
        "mixed-full": {"status": "allowed", "5h_util": "0.25", "5h_reset": now + 600,
                       "5h_limit": "1000", "7d_util": "0.5", "7d_reset": now + 4000},
        "mixed-partial": {"status": "allowed", "5h_util": "0.1", "5h_reset": now + 60,
                          "5h_limit": "9000"},
    }
    check("mixed complete+partial: sums reflect only the complete account",
          _provider_quota(mixed_accounts, mixed_usage, now),
          [{"provider": "anthropic", "accounts_total": 2, "accounts_available": 1,
            "accounts_capped": 0, "accounts_unavailable": 0, "accounts_unknown": 1,
            "single_account": False,
            "signal": "live rate-limit-header probe (per-window utilization)",
            "windows": [
                {"name": "5 hour", "accounts_reporting": 1, "remaining_account_windows": 0.75,
                 "limit_remaining": 750, "limits_known": 1,
                 "soonest_reset": _utc_iso(now + 600), "oldest_reset": _utc_iso(now + 600)},
                {"name": "7 day", "accounts_reporting": 1, "remaining_account_windows": 0.5,
                 "limit_remaining": None, "limits_known": 0,
                 "soonest_reset": _utc_iso(now + 4000), "oldest_reset": _utc_iso(now + 4000)},
            ],
            "soonest_reset": _utc_iso(now + 600), "oldest_reset": _utc_iso(now + 4000)}])
    # Malformed/extreme limit headers must never crash the build (sol finding 2, PR #281 fix
    # round 3): float() of a huge JSON int RAISES OverflowError, and two individually-FINITE
    # "1e308" limits overflow the weighted SUM to inf — round(inf) at render then raised and
    # one malformed account record killed the whole dashboard. The offending contribution is
    # rejected (limit stays unknown — outside limits_known) and the build stays alive.
    def _limit_window(limits_map):
        rows_ = _provider_quota(
            [{"handle": f"lim-{i}", "provider": "anthropic", "catalog_available": True,
              "limits": {}} for i in range(len(limits_map))],
            {f"lim-{i}": {"status": "allowed", "5h_util": "0.0", "5h_limit": limit_value,
                          "7d_util": "0.0"}
             for i, limit_value in enumerate(limits_map)}, now)
        window = rows_[0]["windows"][0]
        return (window["limits_known"], window["limit_remaining"],
                window["limit_remaining"] is None
                or isinstance(window["limit_remaining"], int))
    check("single 1e308 limit: finite, counted, round() survives",
          _limit_window(["1e308"]), (1, round(1e308), True))
    check("two 1e308 limits: finite each, infinite sum -> second rejected, build alive",
          _limit_window(["1e308", "1e308"]), (1, round(1e308), True))
    check("huge-int limit (10**400): float() OverflowError caught, limit unknown",
          _limit_window([10 ** 400]), (0, None, True))
    check("'inf'/'nan'/negative limit strings rejected, never summed",
          _limit_window(["inf", "nan", "-5"]), (0, None, True))
    check("cumulative quota rows carry no raw account identifier (decision 22)",
          all(h not in json.dumps(quota_rows) for h in quota_handles), True)
    # The INTERNAL rows still carry the census (they are what decides capacity); the PUBLISHED rows
    # carry the headroom word derived from it. Both halves are asserted so neither can drift.
    check("ordered fixture: internal census -> published headroom, per provider",
          [(row["provider"], row["accounts_total"], row["single_account"],
            _provider_headroom(row))
           for row in _provider_quota(_catalog(ordered_issues)[0], ordered_usage, now)],
          # every anthropic/future entry in ordered_usage is a PARTIAL probe row (a reset stamp with
          # no utilization), which _quota_state files as unknown — so the census is 3/1 accounts,
          # none of them free, and the headroom word says exactly that without saying how many.
          [("anthropic", 3, False, "unknown"), ("future-provider", 1, True, "unknown"),
           ("openai", 1, True, "available")])
    check("ordered fixture publishes headroom words, never the census behind them",
          [(row["provider"], row["headroom"]) for row in ordered["provider_quota"]],
          [("anthropic", "unknown"), ("future-provider", "unknown"),
           ("openai", "available")])
    # The headroom precedence, all four branches, both directions: "can we dispatch" wins, then the
    # most actionable reason. Collapsing any branch into another (or always answering "available")
    # turns a row red.
    for census, want_headroom in (
            ({"accounts_available": 1, "accounts_capped": 9, "accounts_unknown": 9,
              "accounts_unavailable": 9}, "available"),
            ({"accounts_available": 0, "accounts_capped": 1, "accounts_unknown": 9,
              "accounts_unavailable": 9}, "capped"),
            ({"accounts_available": 0, "accounts_capped": 0, "accounts_unknown": 1,
              "accounts_unavailable": 9}, "unknown"),
            ({"accounts_available": 0, "accounts_capped": 0, "accounts_unknown": 0,
              "accounts_unavailable": 1}, "unavailable")):
        check(f"headroom precedence resolves to {want_headroom}",
              _provider_headroom(census), want_headroom)

    # --- usage-probe outcome (issue #219): dashboard.yml's secret-materialization + probe steps
    # are continue-on-error and a failed probe was replaced by `{}`, so precisely WHEN measurement
    # failed the public page showed every catalog-available account as fresh usable capacity. Every
    # case below feeds the IDENTICAL complete usage entry and varies only the persisted outcome.
    #
    # WHICH MUTATION EACH ROW KILLS (#612 review finding 3 asked for this to be stated precisely
    # rather than claimed in aggregate):
    #   * the REJECT rows (failed / stale / alien schema / unstamped / unknown word / NO sidecar)
    #     go red on ANY weakening of the gate — including the narrow one that keeps the marker and
    #     only stops discarding the usage map.
    #   * the ACCEPT row (fresh `ok`) kills the WHOLE-GATE deletion, because its expected tuple
    #     includes `usage_probe.measured is True` and a build with no gate emits no marker at all
    #     (`.get("measured")` -> None). It does NOT — and cannot — kill the narrow "always trust
    #     usage" mutation: by construction a passing gate and an absent gate agree on a fresh probe.
    #     Its job there is over-rejection regression cover, which is a real but different job.
    # -----------------------------------------------------------------------------------------
    fresh_probe = {"schema": PROBE_SCHEMA, "outcome": "ok", "detail": "probe-succeeded",
                   "attempted_at": now - 30}
    failed_probe = {"schema": PROBE_SCHEMA, "outcome": "failed",
                    "detail": "secret-materialization-failed", "attempted_at": now - 30}
    stale_probe = {"schema": PROBE_SCHEMA, "outcome": "ok", "detail": "probe-succeeded",
                   "attempted_at": now - PROBE_MAX_AGE_SECONDS - 1}

    def probe_view(status):
        built = build_dashboard(issues, leases, usage, history, None, now, "fixture-salt",
                                probe_status=status)
        # #374 moved the observable from the per-account row + the census to the headroom word and
        # the capacity boolean. It is the SAME predicate underneath, so this block still fails on
        # any weakening of the #219/#612 gate — an unmeasured probe must read `unknown`/no capacity.
        return (built["provider_quota"][0]["headroom"], built["fleet"]["capacity"],
                built["provider_quota"][0]["windows"],
                (built.get("usage_probe") or {}).get("measured"))

    check("fresh ok probe: a real measurement still publishes real capacity",
          probe_view(fresh_probe),
          ("available", {"anthropic": True},
           [{"name": "5 hour", "remaining_fraction": 0.58,
             "soonest_reset": _utc_iso(now + 3600), "oldest_reset": _utc_iso(now + 3600)},
            {"name": "7 day", "remaining_fraction": 0.2,
             "soonest_reset": _utc_iso(now + 86400), "oldest_reset": _utc_iso(now + 86400)}],
           True))
    for probe_name, probe_status in (
            ("failed", failed_probe),
            ("stale ok", stale_probe),
            ("empty/absent sidecar", {}),
            # #612 review finding 1: NO sidecar at all used to mean MEASURED — the usage map was
            # taken at face value, capacity went positive AND the degradation key was omitted, so
            # the page carried no warning. Non-vacuous: pre-fix this row read
            # ("available", eligible 1, 1, 0, None).
            ("no sidecar supplied at all", None),
            ("alien schema", {"schema": "wrong/v0", "outcome": "ok", "attempted_at": now}),
            ("unstamped ok", {"schema": PROBE_SCHEMA, "outcome": "ok"}),
            ("unknown outcome word", {"schema": PROBE_SCHEMA, "outcome": "maybe",
                                      "attempted_at": now})):
        check(f"{probe_name} probe: the SAME usage input is never published as capacity",
              probe_view(probe_status),
              ("unknown", {"anthropic": False}, [], False))
    degraded = build_dashboard(issues, leases, usage, history, None, now, "fixture-salt",
                               probe_status=failed_probe)
    check("failed probe publishes no window numbers or reset stamps from the dead snapshot",
          [(row["windows"], row["soonest_reset"], row["oldest_reset"])
           for row in degraded["provider_quota"]],
          [([], None, None)])
    check("failed probe surfaces its outcome, detail and age on the public document",
          degraded["usage_probe"],
          {"outcome": "failed", "detail": "secret-materialization-failed",
           "attempted_at": _utc_iso(now - 30), "age_seconds": 30, "stale": False,
           "measured": False})
    # [#628] The WIRING: the verdict must actually reach the row build_dashboard publishes. Dropping
    # the `probe` argument at the call site leaves every other assertion in this file green while the
    # page goes back to blaming the provider for a broken probe, so it is asserted end-to-end here —
    # once for a failed sidecar and once for none at all, which carry different reason words.
    check("[#628] the published row blames the probe, not the provider, on a distrusted snapshot",
          [degraded["provider_quota"][0]["signal"],
           build_dashboard(issues, leases, usage, history, None, now,
                           "fixture-salt")["provider_quota"][0]["signal"]],
          [_distrust_signal("usage probe failed"),
           _distrust_signal("usage probe outcome is unknown")])
    check("[#628] ...while a fresh measurement publishes the live-probe signal unchanged",
          build_dashboard(issues, leases, usage, history, None, now, "fixture-salt",
                          probe_status=fresh_probe)["provider_quota"][0]["signal"],
          "live rate-limit-header probe (per-window utilization)")
    check("stale ok probe surfaces its age and stops counting as measured",
          _probe_outcome(stale_probe, now),
          {"outcome": "ok", "detail": "probe-succeeded",
           "attempted_at": _utc_iso(now - PROBE_MAX_AGE_SECONDS - 1),
           "age_seconds": PROBE_MAX_AGE_SECONDS + 1, "stale": True, "measured": False})
    check("free-text probe detail is dropped, never published as-is on the public page",
          _probe_outcome({"schema": PROBE_SCHEMA, "outcome": "failed",
                          "attempted_at": now, "detail": "token acct-fixture rejected"},
                         now)["detail"], "")
    check("probe age boundary: exactly at the limit is measured, one second past is not",
          [_probe_outcome({"schema": PROBE_SCHEMA, "outcome": "ok",
                           "attempted_at": now - probe_age}, now)["measured"]
           for probe_age in (PROBE_MAX_AGE_SECONDS, PROBE_MAX_AGE_SECONDS + 1)],
          [True, False])
    check("future probe stamp: clock skew tolerated, an implausible stamp is not measured",
          [_probe_outcome({"schema": PROBE_SCHEMA, "outcome": "ok",
                           "attempted_at": now + skew}, now)["measured"]
           for skew in (PROBE_MAX_SKEW_SECONDS, PROBE_MAX_SKEW_SECONDS + 1)],
          [True, False])
    # #612 review round 4 (MINOR): the comparison used to run on `int(now - attempted)`, which
    # rounds toward zero — an age of 3600.9s (or a 300.9s future stamp) compared as 3600/-300 and
    # stayed `measured` past the documented boundary. Production stamps are integers so nothing was
    # mismeasured, but a caller with a float `now` was outside the predicate's own contract.
    check("fractional ages obey the documented boundary (not a truncated one)",
          [_probe_outcome({"schema": PROBE_SCHEMA, "outcome": "ok",
                           "attempted_at": now - PROBE_MAX_AGE_SECONDS}, now + fraction)["measured"]
           for fraction in (0.0, 0.9)]
          + [_probe_outcome({"schema": PROBE_SCHEMA, "outcome": "ok",
                             "attempted_at": now + PROBE_MAX_SKEW_SECONDS},
                            now - fraction)["measured"]
             for fraction in (0.0, 0.9)],
          [True, False, True, False])
    check("...while the PUBLISHED age stays an integer",
          _probe_outcome({"schema": PROBE_SCHEMA, "outcome": "ok",
                          "attempted_at": now - 30}, now + 0.4)["age_seconds"],
          30)
    # #612 review finding 2: this check used to assert "no degradation key" against `got` — a
    # DIFFERENT document built ~350 lines earlier — so that half would have stayed green even if the
    # sidecar-less build had started emitting a bogus marker; and its availability half deliberately
    # pinned the pre-fix PERMISSIVE behaviour, locking in the fail-open of finding 1. It now asserts
    # against the document the adjacent call actually builds, and pins the fail-CLOSED behaviour:
    # a build with no sidecar publishes nothing as capacity AND carries the degradation marker.
    sidecarless = build_dashboard(issues, leases, usage, history, None, now, "fixture-salt")
    # `.get` on purpose: under the pre-fix code the key is ABSENT, and this check must then go red
    # with a legible value rather than take the suite down with a KeyError.
    sidecarless_marker = sidecarless.get("usage_probe") or {}
    check("[#612] NO sidecar: nothing published as capacity, and the marker IS on the document",
          (sidecarless["provider_quota"][0]["headroom"],
           sidecarless["fleet"]["capacity"],
           "usage_probe" in sidecarless,
           (sidecarless_marker.get("outcome"), sidecarless_marker.get("measured"),
            sidecarless_marker.get("stale"), sidecarless_marker.get("attempted_at"))),
          ("unknown", {"anthropic": False}, True,
           ("unknown", False, True, None)))
    check("[#612] and no window numbers or reset stamps leak from the untrusted snapshot",
          [(row["windows"], row["soonest_reset"]) for row in sidecarless["provider_quota"]],
          [([], None)])
    # The core misreport (issue #219): a catalog-available account the probe never reported on used
    # to render "available" and count toward eligible capacity. It is the allocator's INELIGIBLE
    # shape, so it is "unknown" and eligible 0 — even with a perfectly healthy probe.
    unreported = build_dashboard(issues, leases, {}, history, None, now, "fixture-salt",
                                 probe_status=fresh_probe)
    check("catalog-available account with NO probe entry is unknown and not eligible capacity",
          (unreported["provider_quota"][0]["headroom"], unreported["fleet"]["capacity"]),
          ("unknown", {"anthropic": False}))
    # The one-shared-predicate parity, restated on the minimized surface (#374): published capacity
    # is true for exactly the providers whose published headroom is "available". Both projections
    # read the SAME internal count, so the page cannot advertise capacity dispatch would refuse.
    check("published capacity agrees with the published headroom word (one shared predicate)",
          [(row["provider"], row["headroom"] == "available")
           for row in ordered["provider_quota"]],
          sorted(ordered["fleet"]["capacity"].items()))
    with tempfile.TemporaryDirectory() as directory:
        usage_file = Path(directory, "usage.json")
        usage_file.write_text(json.dumps(usage), encoding="utf-8")
        leases_file = Path(directory, "leases.json")
        leases_file.write_text(json.dumps(leases), encoding="utf-8")
        health_file = Path(directory, "model-health.json")
        health_file.write_text(json.dumps({"records": []}), encoding="utf-8")
        try:
            main(["--leases", str(leases_file), "--model-health", str(health_file),
                  "--usage", str(usage_file)])
        except DashboardError as exc:
            # Assert on the MESSAGE, not merely that something raised: main() has several later
            # fail-closed exits (no REGISTRY_REPO, gh unavailable) that would make a bare
            # "did it raise" assertion pass with the coupling deleted — i.e. vacuous.
            status_required = "--usage-status" in str(exc)
        else:
            status_required = False
        check("a usage snapshot without --usage-status is refused (the #219 caller coupling)",
              status_required, True)

    # --- #612 review round 2, finding 4 (MAJOR): the probe step's shell body is EXECUTED, not
    # pattern-matched. `bash -n` and actionlint cannot see polarity, so dropping the `!` from
    # `if [ "$outcome" = ok ] && ! python3 scripts/account-usage.py > "$RUNNER_TEMP/usage.json"`
    # inverted the whole classification with the full suite green: a NONZERO probe stayed `ok` and
    # published a fresh `measured` sidecar. The step body is extracted from the real workflow and
    # run under bash against a stubbed probe, so each row below dies on a one-token change to the
    # shell — including replacing the body with `true` (no sidecar is written at all).
    # ------------------------------------------------------------------------------------------
    dashboard_workflow = _repo_file(".github", "workflows", "dashboard.yml")
    probe_script = _workflow_step_script(dashboard_workflow, "usage-probe")
    # The stub prints a snapshot on stdout even when it EXITS NONZERO: real probes are incremental,
    # so the `!`-dropped mutation must be caught by the recorded OUTCOME rather than by an
    # accidentally-empty file.
    probe_stub = ("import json, os, sys\n"
                  "if '--self-test' in sys.argv:\n"
                  "    sys.exit(int(os.environ['STUB_SELFTEST_EXIT']))\n"
                  "json.dump({'acct-fixture': {'status': 'allowed'}}, sys.stdout)\n"
                  "sys.exit(int(os.environ['STUB_PROBE_EXIT']))\n")
    # Every document round 3's `grep -q '"ACCT'` accepted, next to the one it should. The last four
    # are the round-4 measurement: they pass a substring search and still leave the probe with no
    # usable token, so the exempt accounts were published as free capacity off an unusable subset.
    SUBSET_FIXTURES = {
        "tokens": '{"ACCT01_TOKEN": "redacted"}',
        "empty-subset": "{}",
        "empty-value": '{"ACCT01_TOKEN": ""}',
        "blank-value": '{"ACCT01_TOKEN": "   "}',
        "non-string-value": '{"ACCT01_TOKEN": 1234}',
        "wrong-key": '{"NOT_AN_ACCT_TOKEN": "redacted", "ACCTLOOKALIKE": "redacted"}',
        "truncated": '{"ACCT01_TOKEN":',
        "not-an-object": '["ACCT01_TOKEN"]',
    }

    def run_probe_step(secrets_outcome="success", secrets_file="tokens",
                       selftest_exit=0, probe_exit=0):
        """Execute the REAL probe step body.

        Returns (exit code, sidecar dict|"MALFORMED"|None, snapshot text|None, combined step log,
        the names of the files the step left in RUNNER_TEMP)."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "scripts" / "account-usage.py").write_text(probe_stub, encoding="utf-8")
            temp = root / "runner-temp"
            temp.mkdir()
            secrets_path = root / "acct-secrets.json"
            # "missing": the materialization step's body was replaced by `true` — it reports
            # `success` and leaves no file behind. Every other shape below is a document that the
            # round-3 `grep -q '"ACCT'` guard ACCEPTED while `_load_secrets` yielded no usable
            # token (#612 review round 4, MAJOR).
            if secrets_file != "missing":
                secrets_path.write_text(SUBSET_FIXTURES[secrets_file], encoding="utf-8")
            environment = dict(os.environ,
                               RUNNER_TEMP=str(temp),
                               SECRETS_STEP_OUTCOME=secrets_outcome,
                               SECRETS_FILE=str(secrets_path),
                               STUB_SELFTEST_EXIT=str(selftest_exit),
                               STUB_PROBE_EXIT=str(probe_exit),
                               GH_TOKEN="", PROVENANCE_SALT="", REGISTRY_REPO="owner/repo",
                               MODEL_HEALTH_FILE=str(root / "absent-model-health.json"))
            completed = subprocess.run(["bash", "-c", probe_script], cwd=str(root),
                                       env=environment, capture_output=True, text=True,
                                       timeout=120, check=False)
            sidecar_path, snapshot_path = temp / "usage-probe.json", temp / "usage.json"
            sidecar = None
            if sidecar_path.is_file():
                try:
                    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    sidecar = "MALFORMED"
            return (completed.returncode, sidecar,
                    snapshot_path.read_text(encoding="utf-8") if snapshot_path.is_file() else None,
                    completed.stdout + completed.stderr,
                    sorted(item.name for item in temp.iterdir()))

    def probe_step_view(**kwargs):
        code, sidecar, snapshot, _log, _produced = run_probe_step(**kwargs)
        marker = sidecar if isinstance(sidecar, dict) else {}
        return (code, marker.get("schema"), marker.get("outcome"), marker.get("detail"), snapshot)

    check("[#612] probe step: a succeeding probe records ok and keeps its real snapshot",
          probe_step_view(),
          (0, PROBE_SCHEMA, "ok", "probe-succeeded",
           '{"acct-fixture": {"status": "allowed"}}'))
    # THE polarity mutation: without the `!` this row reads ("ok", "probe-succeeded", <stub json>).
    check("[#612] probe step: a NONZERO probe is recorded failed and its output discarded",
          probe_step_view(probe_exit=1),
          (0, PROBE_SCHEMA, "failed", "probe-exited-nonzero", "{}"))
    check("[#612] probe step: a failing probe self-test is recorded failed",
          probe_step_view(selftest_exit=1),
          (0, PROBE_SCHEMA, "failed", "probe-self-test-failed", "{}"))
    check("[#612] probe step: a failed secret materialization is recorded failed",
          probe_step_view(secrets_outcome="failure"),
          (0, PROBE_SCHEMA, "failed", "secret-materialization-failed", "{}"))
    # The `true`-body mutation on the materialization step: outcome `success`, no file. Pre-fix this
    # row read ("ok", "probe-succeeded") — a false-healthy probe status with nothing measured, and
    # the probe-EXEMPT providers published as free capacity off a materialization that never ran.
    check("[#612] probe step: `success` with NO subset file is recorded failed, not measured",
          probe_step_view(secrets_file="missing"),
          (0, PROBE_SCHEMA, "failed", "secret-file-missing", "{}"))
    check("[#612] probe step: an EMPTY token subset is recorded failed, not measured",
          probe_step_view(secrets_file="empty-subset"),
          (0, PROBE_SCHEMA, "failed", "secret-subset-empty", "{}"))
    # --- #612 review round 4 (MAJOR): `grep -q '"ACCT'` proves NEITHER valid JSON NOR a non-empty
    # token. Measured: `{"ACCT01_TOKEN":""}` and the truncated `{"ACCT01_TOKEN":` both passed it, so
    # `outcome` stayed `ok`, the sidecar published `measured=True`, and the probe-EXEMPT accounts
    # were published as fresh free capacity off a subset carrying no usable token — the SAME
    # overgrant this PR exists to close, surviving the fix. Each row below reads
    # ("ok", "probe-succeeded", <stub json>) under the grep guard and dies under the parsing one.
    # ------------------------------------------------------------------------------------------
    for subset_name, subset_detail in (("empty-value", "secret-subset-empty"),
                                       ("blank-value", "secret-subset-empty"),
                                       ("non-string-value", "secret-subset-empty"),
                                       ("wrong-key", "secret-subset-empty"),
                                       ("truncated", "secret-subset-malformed"),
                                       ("not-an-object", "secret-subset-malformed")):
        check(f"[#612] probe step: a `{subset_name}` subset is refused, not measured",
              probe_step_view(secrets_file=subset_name),
              (0, PROBE_SCHEMA, "failed", subset_detail, "{}"))
    # ...and the refusal must stay SILENT about the document: the validator's only stdout is one of
    # three fixed words (captured, never echoed) and it has no traceback path, so no fragment of a
    # token can reach the step log. Asserted over the union of every stream, for every shape.
    for subset_name in SUBSET_FIXTURES:
        code, _sidecar, _snapshot, logged, _produced = run_probe_step(secrets_file=subset_name)
        check(f"[#612] probe step: the `{subset_name}` refusal leaks no subset bytes to the log",
              (code, "ACCT01_TOKEN" in logged, "redacted" in logged, "Traceback" in logged),
              (0, False, False, False))
    # The shell -> python contract itself: whatever the step actually wrote must parse HERE. This is
    # what a scoped substring assertion could never do — it ties the printf's schema string, outcome
    # vocabulary and stamp format to _probe_outcome's fail-closed parser.
    step_now = int(time.time())
    check("[#612] the sidecar the step really wrote is what _probe_outcome accepts/refuses",
          [_probe_outcome(run_probe_step(**kwargs)[1], step_now)["measured"]
           for kwargs in ({}, {"probe_exit": 1}, {"secrets_file": "missing"},
                          {"secrets_file": "empty-value"}, {"secrets_file": "truncated"})],
          [True, False, False, False, False])
    build_step = _workflow_step(dashboard_workflow, "dashboard-build")
    check("[#612] the build step passes the sidecar WITH the snapshot (scoped to that one step)",
          ('--usage "$RUNNER_TEMP/usage.json"' in build_step,
           '--usage-status "$RUNNER_TEMP/usage-probe.json"' in build_step),
          (True, True))

    # --- #612 review round 4: the four survivors in the WIRING seam around the probe step. Round 3
    # executed the probe body; the PRODUCER of the file that body checks, the env wiring that hands
    # it the producer's outcome, and the transport that carries the sidecar to the build job were all
    # still assertion-free, so `run: true` on the materialization step, deleting `id: acct-secrets`,
    # deleting the `SECRETS_STEP_OUTCOME` env line and dropping `usage-probe.json` from the upload
    # each left the whole suite green.
    #
    # (i) The materialization step body is EXECUTED, against a fake complete secret map. This is the
    # producer, and it is also the filter that keeps every NON-worker secret away from the probe — so
    # the row asserts the exact subset, not merely that a file appeared. `run: true` writes no file.
    # ------------------------------------------------------------------------------------------
    materialize_script = _workflow_step_script(dashboard_workflow, "acct-secrets")

    def run_materialize_step(all_secrets):
        """Execute the REAL materialization step body; return (exit code, subset|None, mode|None)."""
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory, "runner-temp")
            temp.mkdir()
            completed = subprocess.run(
                ["bash", "-c", materialize_script], cwd=directory, capture_output=True, text=True,
                timeout=120, check=False,
                env=dict(os.environ, RUNNER_TEMP=str(temp), ALL_SECRETS=json.dumps(all_secrets)))
            written = temp / "acct-secrets.json"
            if not written.is_file():
                return completed.returncode, None, None, completed.stdout + completed.stderr
            return (completed.returncode,
                    json.loads(written.read_text(encoding="utf-8")),
                    oct(written.stat().st_mode & 0o777),
                    completed.stdout + completed.stderr)
    all_secrets = {"ACCT01_TOKEN": "worker-one", "ACCT7X_TOKEN": "worker-two",
                   "PROVENANCE_SALT": "not-a-worker-token", "GITHUB_TOKEN": "not-a-worker-token",
                   "ACCT01_TOKEN_BACKUP": "not-exactly-the-shape", "ACCTLOOKALIKE": "no-suffix",
                   "ACCT02_TOKEN": ["not", "a", "string"]}
    code, subset, mode, materialize_log = run_materialize_step(all_secrets)
    check("[#612] materialization step: EXECUTED, it writes exactly the ACCT*_TOKEN string subset",
          (code, subset, mode),
          (0, {"ACCT01_TOKEN": "worker-one", "ACCT7X_TOKEN": "worker-two"}, "0o600"))
    check("[#612] materialization step: no secret VALUE of any kind reaches its own step log",
          [value for value in ("worker-one", "worker-two", "not-a-worker-token")
           if value in materialize_log],
          [])
    # A `{}` secret map is a real production shape (a repo with no worker tokens yet): the filter
    # must still succeed, and the PROBE step must then refuse — the two halves of the seam meeting.
    empty_code, empty_subset, _mode, _log = run_materialize_step({"PROVENANCE_SALT": "salt"})
    with tempfile.TemporaryDirectory() as directory:
        handoff = Path(directory, "acct-secrets.json")
        handoff.write_text(json.dumps(empty_subset), encoding="utf-8")
        handoff_state = subprocess.run(
            ["bash", "-c", probe_script], cwd=str(directory), capture_output=True, text=True,
            timeout=120, check=False,
            env=dict(os.environ, RUNNER_TEMP=directory, SECRETS_STEP_OUTCOME="success",
                     SECRETS_FILE=str(handoff), GH_TOKEN="", PROVENANCE_SALT="",
                     REGISTRY_REPO="owner/repo",
                     MODEL_HEALTH_FILE=str(Path(directory, "absent.json"))))
        handoff_sidecar = json.loads(Path(directory, "usage-probe.json").read_text(encoding="utf-8"))
    check("[#612] the two step bodies MEET: a token-less filter output is refused by the probe",
          (empty_code, empty_subset, handoff_state.returncode,
           handoff_sidecar["outcome"], handoff_sidecar["detail"]),
          (0, {}, 0, "failed", "secret-subset-empty"))
    # (ii) The env wiring. Execution can never catch its deletion — the harness supplies
    # SECRETS_STEP_OUTCOME from the process environment — so the wiring is read as a MAPPING, and
    # the step id it names must resolve in the same workflow. Deleting the env line makes the first
    # element None; deleting `id: acct-secrets` makes _workflow_step raise its "found 0" refusal.
    probe_env = _workflow_step_env(dashboard_workflow, "usage-probe")
    wired = re.fullmatch(r"\$\{\{\s*steps\.([A-Za-z0-9_-]+)\.outcome\s*\}\}",
                         probe_env.get("SECRETS_STEP_OUTCOME") or "")
    check("[#612] the probe step's gate is WIRED to the materialization step's outcome, by id",
          (probe_env.get("SECRETS_STEP_OUTCOME"),
           wired.group(1) if wired else None,
           '"${SECRETS_STEP_OUTCOME}" != "success"' in probe_script,
           bool(wired) and _workflow_step_script(dashboard_workflow, wired.group(1)) != ""),
          ("${{ steps.acct-secrets.outcome }}", "acct-secrets", True, True))
    # (iii) The transport. Deleting `usage-probe.json` from the upload path is invisible to every
    # generator test — an absent sidecar fails CLOSED, so the loss looks like a healthy refusal
    # instead of a broken pipeline. Asserted as a PROPERTY rather than a substring: every file the
    # probe step actually produced (measured by running it) must be listed by the upload step, whose
    # artifact is what the build step above was just shown to read both flags from.
    produced = run_probe_step()[4]
    uploaded = [line.strip().replace("${{ runner.temp }}/", "")
                for line in _workflow_step_block(
                    dashboard_workflow, "upload-usage", "path").split("\n") if line.strip()]
    check("[#612] every file the probe step PRODUCES is carried by the artifact upload",
          (produced, sorted(uploaded), sorted(set(produced) - set(uploaded))),
          (["usage-probe.json", "usage.json"], ["usage-probe.json", "usage.json"], []))

    # --- #922: cron-keepalive, the liveness mesh that revives every other scheduled workflow. The
    # only thing that makes a leg of it real is WHICH EVENT it keys on, and nothing static can see
    # that: `bash -n` and actionlint parse the shell, and a YAML assertion can only read the spec
    # list back to itself. The pre-#922 body anchored every leg on `.workflow_runs[0].created_at`,
    # which since the #819 tick floor is satisfied by a within-floor ring that concludes `success`
    # in ~30s having executed NOTHING — and #79's registry-internal ring sources make those no-op
    # runs the normal case (dispatch is rung roughly every <=7 min). So the dispatch leg reported a
    # dispatcher that had not executed a tick in hours as permanently fresh: it looked like
    # coverage and was not. The body is therefore EXTRACTED and EXECUTED against hermetic gh/jq
    # stubs, and every row below is an OUTCOME (which workflows got kicked) rather than a substring.
    # ------------------------------------------------------------------------------------------
    def _keepalive_specs(script, leg):
        """{workflow-file: (threshold-seconds, executed-marker or "")} read out of a leg's own
        `for spec in ...` list. A watch list that cannot be read is a REFUSAL, never an empty
        dict: the rows below would all pass trivially against a leg watching nothing."""
        spec_line = re.search(r"for spec in ([^\n]+); do", script)
        if spec_line is None:
            raise DashboardError(
                f"{leg}'s spec list could not be located in the extracted step body — refusing "
                "to assert against a keepalive whose watch list cannot be read (fail closed)")
        specs = {}
        for raw in spec_line.group(1).split():
            fields = raw.split(":")
            if len(fields) not in (2, 3) or not fields[1].isdigit():
                raise DashboardError(f"unparseable spec {raw!r} in {leg} — refusing")
            specs[fields[0]] = (int(fields[1]), fields[2] if len(fields) > 2 else "")
        if not specs:
            raise DashboardError(f"{leg} watches no workflow at all — refusing")
        return specs

    keepalive_script = _workflow_step_script(dashboard_workflow, "registry-keepalive")
    keepalive_specs = _keepalive_specs(keepalive_script, "cron-keepalive")
    sparq_script = _workflow_step_script(dashboard_workflow, "sparq-keepalive-dispatch")
    sparq_specs = _keepalive_specs(sparq_script, "the cross-repo cron-keepalive leg")

    # The floor module is the OTHER side of this wire contract. Loaded rather than restated, so the
    # marker name and the tick interval cannot drift out from under the threshold below.
    floor_path = Path(__file__).resolve().parent / "dispatch-tick-floor.py"
    floor_spec = importlib.util.spec_from_file_location("registry_dispatch_tick_floor", floor_path)
    if floor_spec is None or floor_spec.loader is None:
        raise DashboardError(f"cannot load {floor_path} for the #922 keepalive anchor contract")
    tick_floor = importlib.util.module_from_spec(floor_spec)
    floor_spec.loader.exec_module(tick_floor)
    dispatch_workflow = _repo_file(".github", "workflows", "dispatch.yml")

    check("[#922] EXACTLY the dispatch leg is anchored on an executed-work marker — reverting it "
          "to run-anchoring (or anchoring a leg whose runs really do imply work) goes red here",
          {name: marker for name, (_limit, marker) in keepalive_specs.items() if marker},
          {"dispatch.yml": tick_floor.TICK_MARKER_ARTIFACT})
    check("[#922] the anchor names an artifact dispatch.yml actually UPLOADS — a keepalive keyed "
          "on an artifact nobody writes reads as permanently stale and kicks every 15 minutes",
          bool(re.search(r"uses: actions/upload-artifact@\S+[^\n]*\n\s*with:\n\s*name: "
                         + re.escape(tick_floor.TICK_MARKER_ARTIFACT) + r"\s*\n",
                         dispatch_workflow)),
          True)
    check("[#922] the dispatch threshold clears the tick floor with a whole missed tick of slack "
          "(exactly two floor intervals: less kicks a healthy hold; more delays recovery)",
          keepalive_specs["dispatch.yml"][0], 2 * tick_floor.MIN_TICK_INTERVAL_SECONDS)

    # --- #680: a keepalive threshold is a CADENCE CONTROL, not a courtesy. Measured over the 7
    # days to 2026-07-25 GitHub delivered only ~60% of this fleet's scheduled fires, and this leg
    # supplied the rest, so each threshold is what actually decides how often its target runs.
    # Every run-anchored one is bounded strictly between one and two nominal cadences of the
    # WATCHED workflow — above one so a punctual cron is never kicked behind its own fire (#559),
    # below two so a single dropped fire is recovered inside the cycle it was dropped from. Both
    # sides come from the watched workflow's OWN `on: schedule:` block rather than from anything
    # restated here, so the rows fail when a cron is re-timed as well as when a threshold is
    # re-sized: two files that must agree, which is the one shape a tautological assertion cannot
    # take. dispatch.yml is exempt — it is marker-anchored and bounded by the tick floor above.
    # ------------------------------------------------------------------------------------------
    # Three of these shapes are what separate a real reader from a plausible one, and each answer
    # appears nowhere else in this block. `0,5,10` is BUNCHED: its widest gap is the wrap-around
    # from :10 to the next hour's :00 (3000s), so a reader that drops the wrap reads 300 and one
    # that takes the narrowest gap reads 300 too — a tenth of the truth in both cases, which would
    # call every threshold in the fleet compliant. `5` fires once an hour, where the wrap gap is the
    # ONLY gap. The last row is a UNION over a workflow's crons, not a per-cron maximum.
    check("[#680] the cron reader derives a nominal cadence from the minute field, wrap-around gap "
          "included, taking the WIDEST gap over the union of a workflow's crons — a reader that "
          "cannot tell 5 minutes from 50 makes the bound below satisfiable by any threshold",
          [_cron_cadence_seconds("*/15 * * * *"), _cron_cadence_seconds("11-59/15 * * * *"),
           _cron_cadence_seconds("1,21,41 * * * *"), _cron_cadence_seconds("17,47 * * * *"),
           _cron_cadence_seconds("0,5,10 * * * *"), _cron_cadence_seconds("5 * * * *"),
           _cron_cadence_seconds("*/20 * * * *", "10-59/20 * * * *")],
          [900, 900, 1200, 1800, 3000, 3600, 600])
    check("[#680] ...and a schedule it cannot read is a REFUSAL, never a default cadence that the "
          "bound would then be measured against",
          [_raises_dashboard(lambda text=text: _cron_cadence_seconds(text))
           for text in ("*/15 * * * 1", "*/0 * * * *", "60 * * * *", "15-5 * * * *",
                        "a,5 * * * *", "not-a-cron")]
          + [_raises_dashboard(lambda: _cron_cadence_seconds())],
          [True] * 7)
    # The refusals on the FILE side, driven as text so both branches actually execute: a workflow
    # with no `on:` block at all, and one whose `on:` block carries no cron. Both must refuse rather
    # than yield a cadence, because a cadence invented here is one the bound below would then find
    # any threshold compliant with.
    #
    # The positive control does the other half of the work, and its schedule is chosen so that
    # every leak CHANGES THE ANSWER — a union can only ever NARROW the widest gap, so a fixture
    # whose real cron is dense (`*/15`) reads the same whether or not a stray `- cron:` leaks in.
    # The real schedule here is therefore the SPARSE one (hourly, 3600s) and each decoy is chosen
    # against it. A scan that runs past the top-level `on:` block picks up the job-level `- cron:`
    # and reads 2700; a scan that stops stripping comments takes the column-0 comment between the
    # triggers for the end of the block, never reaches `schedule:`, and refuses a workflow that
    # plainly has one. That comment is the shape every workflow in this repo is written in.
    hourly_with_decoys = ("# - cron: '20 * * * *'   <- this file's schedule, discussed in prose\n"
                          "on:\n"
                          "  workflow_dispatch:\n"
                          "# Column-0 commentary between the triggers, as every workflow here has.\n"
                          "  schedule:\n"
                          "    - cron: '0 * * * *'\n"
                          "\n"
                          "jobs:\n"
                          "  a:\n"
                          "    steps:\n"
                          "      - uses: some/scheduling-action\n"
                          "        with:\n"
                          "          entries:\n"
                          "            - cron: '45 * * * *'\n")

    def _cadence_or_refusal(text, label):
        """`_schedule_cadence_seconds` with a refusal reported as a VALUE rather than raised. A
        leak that makes the reader refuse would otherwise abort the suite from inside a row and
        register as a kill while every check below it never ran."""
        try:
            return _schedule_cadence_seconds(text, label)
        except DashboardError:
            return "REFUSED"

    check("[#680] a workflow YAML the cadence reader cannot resolve a schedule from REFUSES, and on "
          "one it can it reads the top-level `on: schedule:` block ONLY — neither a `- cron:` in a "
          "job nor a column-0 comment mid-block may change the number a threshold is sized against",
          [_cadence_or_refusal("jobs:\n  a:\n", "no-on.yml"),
           _cadence_or_refusal("on:\n  workflow_dispatch:\n\njobs:\n  a:\n", "no-cron.yml"),
           _cadence_or_refusal(hourly_with_decoys, "hourly-with-decoys.yml")],
          ["REFUSED", "REFUSED", 3600])
    keepalive_cadences = {name: _workflow_cadence_seconds(name)
                          for name, (_limit, marker) in keepalive_specs.items() if not marker}
    check("[#680] the run-anchored watch list these rows drive, pinned by equality — a leg that "
          "quietly stops watching a workflow must go red here rather than silently narrow the "
          "bound below to whatever is left",
          sorted(keepalive_cadences),
          ["conflict-resolver.yml", "curate.yml", "groom-core.yml", "metrics.yml", "retriage.yml"])
    # [#1353 BLOCKED] The groom keepalive and retriage.yml SHOULD be re-sized to 1200 and 2400 to
    # satisfy the bound below. They are not, and this is a deliberate, documented exemption rather
    # than an oversight: setting those historical values in `.github/workflows/dashboard.yml` made
    # GitHub REFUSE TO INGEST THE WORKFLOW — every run concluded `action_required` with
    # `jobs total_count=0`, measured on master (2026-07-31T03:04Z, PR #1363, reverted by #1364).
    # #2076 retargets the groom leg to groom-core.yml without claiming that unrelated
    # dashboard-ingestion defect is fixed. Until it is, both sit at exactly 2x cadence.
    # ⚠️ REMOVE THIS EXEMPTION the moment #1353 is resolved — it is the weaker of the two states.
    check("[#680] every run-anchored threshold sits strictly between ONE and TWO nominal cadences "
          "of the workflow it watches (offenders listed as workflow -> (threshold, cadence)): at "
          "or under one cadence it kicks a punctual cron behind its own fire; at or over two, one "
          "dropped fire costs a whole extra cycle on a fleet losing ~40% of its fires "
          "[groom-core.yml/retriage.yml exempt while #1353 blocks their re-sizing]",
          {name: (keepalive_specs[name][0], cadence)
           for name, cadence in keepalive_cadences.items()
           if name not in _THRESHOLD_BOUND_EXEMPT
           and not cadence < keepalive_specs[name][0] < 2 * cadence},
          {})
    check("[#1353] the exemption above is NOT silent — every exempt workflow is still watched, and "
          "the set is pinned so a future re-size that drops one cannot quietly widen it",
          sorted(_THRESHOLD_BOUND_EXEMPT & set(keepalive_cadences)),
          ["groom-core.yml", "retriage.yml"])

    # --- #1084: the WIDENING direction, on the three thresholds the row above cannot see. The
    # strict bound covers three registry legs; the #1353 pair is excused from it ENTIRELY (so
    # `groom-core.yml:1800` -> `:99999` is invisible), and the CROSS-REPO leg is not in that row's
    # population at all because sparq-org/sparq is not checked out here for
    # `_workflow_cadence_seconds` to read. With every fixture age below derived from the threshold
    # itself, `rearm-sweeper.yml:1200` -> `:99999` left the whole suite green (#1084 measured 187
    # rows) while that leg of the liveness mesh became a no-op. The two
    # rows here bound EVERY run-anchored threshold in the mesh against a cadence that is not a
    # restatement of it — read from the watched workflow for the registry legs, declared in
    # `_CROSS_REPO_KEEPALIVE_CADENCE_SECONDS` for the cross-repo one. Ceiling and floor are stated
    # SEPARATELY because a threshold that grows and one that shrinks are different failures with
    # different consequences, and a single combined row cannot say which one it caught.
    # ------------------------------------------------------------------------------------------
    def _cross_repo_targets(script, specs, leg):
        """{(repository, workflow-file): threshold-seconds} for a cross-repo keepalive leg.

        The repository is read out of the leg's OWN `repos/<owner>/<name>/actions/…` endpoints
        rather than restated here, so a leg re-pointed at another repository stops matching the
        cadence declared for the old one instead of silently inheriting its bound. Anything other
        than exactly one addressed repository is a REFUSAL: a leg whose target cannot be identified
        must not be sized against a guess. Marker-anchored specs are excluded for the same reason
        the registry side excludes dispatch.yml — their freshness is not a function of the watched
        workflow's cron — and the membership row below reds if one ever appears here."""
        repositories = sorted(set(re.findall(
            r"repos/([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)/actions/", script)))
        # Resolved BEFORE the refusal, and never by indexing the list under the guard: a guard that
        # is the only thing standing between an empty list and `repositories[0]` cannot be measured
        # — deleting it raises IndexError from the mutated line itself, which aborts the suite and
        # records as a kill while every row below it never ran.
        repository = repositories[0] if len(repositories) == 1 else None
        if repository is None:
            raise DashboardError(
                f"{leg} addresses {len(repositories)} repositories, expected exactly 1 — refusing "
                "to bound its thresholds against a cadence declared for some other repository")
        return {(repository, name): limit
                for name, (limit, marker) in specs.items() if not marker}

    # The reader's own refusals, EXECUTED — a refusal nothing ever runs is a refusal nothing has
    # checked, and both of these decide whether a threshold is measured against its own
    # repository's cadence or another one's. `a-org/a` and `b-org/b` appear nowhere else in this
    # suite, so the positive control cannot pass on a value the harness already had.
    _cross_repo_probe_specs = {"probe.yml": (900, ""), "marked.yml": (300, "some-marker")}
    check("[#1084] the repository a declared cadence is matched to is READ out of the leg's own "
          "`repos/<owner>/<name>/actions/…` endpoints: a leg addressing none of them, or two "
          "different ones, REFUSES rather than bounding its thresholds against a cadence declared "
          "for some other repository — and a marker-anchored spec is not sized against a cron",
          [_raises_dashboard(lambda: _cross_repo_targets(
              "gh api -X POST dispatches", _cross_repo_probe_specs, "x")),
           _raises_dashboard(
               lambda: _cross_repo_targets(
                   "repos/a-org/a/actions/workflows/probe.yml/runs?per_page=1\n"
                   "repos/b-org/b/actions/workflows/probe.yml/dispatches",
                   _cross_repo_probe_specs, "x")),
           _cross_repo_targets("repos/a-org/a/actions/workflows/probe.yml/runs?per_page=1",
                               _cross_repo_probe_specs, "x")],
          [True, True, {("a-org/a", "probe.yml"): 900}])

    cross_repo_thresholds = _cross_repo_targets(
        sparq_script, sparq_specs, "the cross-repo cron-keepalive leg")
    check("[#1084] every workflow the cross-repo leg watches has a DECLARED cadence, and the "
          "declaration names nothing the leg has stopped watching — both sides pinned by equality, "
          "so a target added to that leg without a declared cadence (a threshold with no reference "
          "point at all) goes red here rather than joining the bounds below unmeasured",
          (sorted(cross_repo_thresholds), sorted(_CROSS_REPO_KEEPALIVE_CADENCE_SECONDS)),
          ([("sparq-org/sparq", "rearm-sweeper.yml")],
           [("sparq-org/sparq", "rearm-sweeper.yml")]))
    # `label -> (threshold, cadence)` for every run-anchored threshold in the mesh. An undeclared
    # cross-repo target is DROPPED rather than raised on: the row above already names that failure,
    # and aborting the suite here would stop every row below it from running at all (a mutant that
    # crashes the harness records as a kill while nothing under it was measured).
    anchored_thresholds = {name: (keepalive_specs[name][0], cadence)
                           for name, cadence in keepalive_cadences.items()}
    anchored_thresholds.update({
        f"{repository} {name}": (limit, _CROSS_REPO_KEEPALIVE_CADENCE_SECONDS[(repository, name)])
        for (repository, name), limit in cross_repo_thresholds.items()
        if (repository, name) in _CROSS_REPO_KEEPALIVE_CADENCE_SECONDS})
    check("[#1084] NO run-anchored threshold in the mesh exceeds TWO nominal cadences of what it "
          "watches — the #1353 exempts and the cross-repo leg included (offenders listed as "
          "label -> (threshold, cadence)): a threshold widened past two cadences costs a whole "
          "extra cycle per dropped fire, and one widened to hours retires that leg of the mesh "
          "while every fixture-driven row below it still passes",
          {label: pair for label, pair in anchored_thresholds.items() if pair[0] > 2 * pair[1]},
          {})
    check("[#1084] ...and none sits at or under ONE cadence, where the keepalive kicks a punctual "
          "cron behind its own fire — the #559 dup-dispatch storm, which on the cross-repo leg "
          "shows up only in ANOTHER repository's telemetry",
          {label: pair for label, pair in anchored_thresholds.items() if pair[0] <= pair[1]},
          {})

    # --- #1085: PER-TARGET JITTER, the optional half of #559 — ANSWERED here, not implemented.
    #
    # #559 asked optionally for per-target jitter so independent mesh sources "do not converge on
    # the same second": two sources watching one target read the same COMPLETED anchor in the same
    # tick, both conclude stale, and both dispatch. The #559 live-run guard BOUNDS that duplicate
    # (it can no longer become self-sustaining) but cannot remove it, because neither kick is live
    # yet at the moment the other reads.
    #
    # Jitter costs something on EVERY fire — #559's own sketch was a `sleep` in the keepalive step,
    # i.e. runner minutes on ~96 fires a day per leg — so #559 required the residual duplicate rate
    # to be MEASURED before paying it. That measurement cannot run from inside the worker container
    # (no token, no network), and it does not have to: convergence is a STRUCTURAL property of the
    # mesh's source -> target map, and that map is readable offline out of the three real step
    # bodies. A target watched by exactly ONE source has no second source to converge with, whatever
    # a dispatch-fire histogram would say. Two findings came out of reading it, and the rows below
    # are what hold each of them in place:
    #
    # (1) NO target in this mesh is watched by more than one source. The six registry legs, the
    #     cross-repo sweeper and metrics.yml's mutual kick of the dashboard partition cleanly, so
    #     the convergence jitter would dephase does not exist to be dephased. The duplicate this
    #     mesh really does produce is a keepalive kick racing the target's OWN cron delivery — and
    #     jitter in the SOURCE cannot dephase that, because the cron is not ours to move. That one
    #     is already addressed from the other side by the #680 bound above: a threshold strictly
    #     above one cadence never kicks a punctual cron behind its own fire.
    #
    # (2) When a second source does appear, `hash(target) % window` — the derivation #559 itself
    #     suggested — is the WRONG KEY and would buy nothing: both sources hash the SAME target
    #     name to the SAME offset and stay exactly as converged as they were. A jitter that
    #     actually dephases has to be keyed on the (source, target) PAIR.
    #
    # So the deliverable is the premise, enforced: the map pinned by equality, plus a collision
    # detector that reds the moment any target acquires a second watcher — which is precisely the
    # condition under which jitter stops being speculative and becomes required.
    # ------------------------------------------------------------------------------------------
    # Spelled out as a literal in every expected value below rather than interpolated from here:
    # an expectation that reads its sentinel from the code under test agrees with any value that
    # code happens to produce, which is the one shape an assertion cannot fail in.
    _MESH_SELF = "<self>"

    def _keepalive_leg_repository(script, leg):
        """The ONE repository a keepalive leg addresses, read out of that leg's OWN
        `repos/<x>/actions/…` endpoints rather than restated here.

        `${GITHUB_REPOSITORY}` normalises to `<self>`, because the two registry legs name their
        repository only through that variable: without the normalisation every registry target
        would carry a different key from every other and the collision row below could never fire
        at all. Anything other than exactly one addressed repository is a REFUSAL — a leg whose
        target repository cannot be identified must not enter a map that decides whether two legs
        watch the same thing."""
        addressed = sorted(set(re.findall(
            r"repos/(\$\{GITHUB_REPOSITORY\}|[A-Za-z0-9._-]+/[A-Za-z0-9._-]+)/actions/", script)))
        # Resolved BEFORE the refusal, never by indexing the list under the guard: a guard that is
        # the only thing between an empty list and `addressed[0]` cannot be measured — deleting it
        # raises IndexError from the mutated line itself, aborting the suite and recording as a
        # kill while every row below it never ran.
        repository = addressed[0] if len(addressed) == 1 else None
        if repository is None:
            raise DashboardError(
                f"{leg} addresses {len(addressed)} repositories, expected exactly 1 — refusing to "
                "place its targets in the mesh map under a guessed repository")
        return _MESH_SELF if repository == "${GITHUB_REPOSITORY}" else repository

    def _mesh_watchers(legs):
        """{(repository, workflow-file): [source-leg, …]} over the whole keepalive mesh."""
        watchers = {}
        for leg, (script, specs) in sorted(legs.items()):
            repository = _keepalive_leg_repository(script, leg)
            for name in sorted(specs):
                watchers.setdefault((repository, name), []).append(leg)
        return watchers

    def _mesh_labelled(watchers, only_shared=False):
        return {f"{repository} {name}": legs
                for (repository, name), legs in sorted(watchers.items())
                if not only_shared or len(legs) > 1}

    # The reader's refusals and its normalisation, EXECUTED. `jit-org/*` appears nowhere else in
    # this suite, so the positive controls cannot pass on a value the harness already had.
    check("[#1085] the repository a mesh target is keyed by is READ out of the leg's own "
          "`repos/<owner>/<name>/actions/…` endpoints, and `${GITHUB_REPOSITORY}` normalises to a "
          "single key so the two registry legs are seen to watch ONE repository — a leg addressing "
          "no repository, or two different ones, REFUSES rather than entering the map under a guess",
          [_raises_dashboard(lambda: _keepalive_leg_repository("gh api -X POST dispatches", "x")),
           _raises_dashboard(lambda: _keepalive_leg_repository(
               "repos/jit-org/one/actions/workflows/probe.yml/runs?per_page=1\n"
               "repos/jit-org/two/actions/workflows/probe.yml/dispatches", "x")),
           _keepalive_leg_repository("repos/jit-org/three/actions/workflows/probe.yml/runs", "x"),
           _keepalive_leg_repository(
               "repos/${GITHUB_REPOSITORY}/actions/workflows/probe.yml/runs", "x")],
          [True, True, "jit-org/three", "<self>"])
    # The detector driven over a mesh that DOES collide — without this the production row below is
    # satisfied by a detector that can never report anything, which is the whole failure mode a
    # zero-row assertion has. `probe-c` watches the same workflow FILE in a different repository
    # and must NOT be folded in: a detector keyed on the file name alone reports a collision that
    # is not there, and would have declared this mesh in need of jitter it does not need.
    _mesh_probe = {
        "probe-a": ("repos/jit-org/one/actions/workflows/shared.yml/runs?per_page=1",
                    {"shared.yml": (900, ""), "solo.yml": (900, "")}),
        "probe-b": ("repos/jit-org/one/actions/workflows/shared.yml/runs?per_page=1",
                    {"shared.yml": (900, "")}),
        "probe-c": ("repos/jit-org/two/actions/workflows/shared.yml/runs?per_page=1",
                    {"shared.yml": (900, "")}),
    }
    check("[#1085] the collision detector DETECTS one: over a fixture mesh where two legs watch a "
          "target it names both watchers, a singly-watched target is not reported, and the same "
          "workflow file in another repository is a different target",
          (_mesh_labelled(_mesh_watchers(_mesh_probe), only_shared=True),
           sorted(_mesh_labelled(_mesh_watchers(_mesh_probe)))),
          ({"jit-org/one shared.yml": ["probe-a", "probe-b"]},
           ["jit-org/one shared.yml", "jit-org/one solo.yml", "jit-org/two shared.yml"]))

    # metrics.yml's mutual kick is the mesh's THIRD source and lives in another file entirely, so
    # nothing above has ever read it. Extracted the same way as the two dashboard legs; its
    # staleness `for spec in …` list is its watch list. The publish kick beside it in the same step
    # is deliberately NOT a member: it is causal rather than staleness-driven and is deduped by the
    # dashboard's own publish decision, so it cannot converge with a stale-anchor reader.
    metrics_workflow = _repo_file(".github", "workflows", "metrics.yml")
    metrics_keepalive_script = _workflow_step_script(metrics_workflow, "dashboard-publish")
    metrics_specs = _keepalive_specs(metrics_keepalive_script,
                                     "metrics.yml's mutual keepalive leg")
    mesh_watchers = _mesh_watchers({
        "dashboard.yml/registry-keepalive": (keepalive_script, keepalive_specs),
        "dashboard.yml/sparq-keepalive-dispatch": (sparq_script, sparq_specs),
        "metrics.yml/dashboard-publish": (metrics_keepalive_script, metrics_specs),
    })
    check("[#1085] the whole mesh's source -> target map, read out of the three REAL step bodies "
          "and pinned by equality — a leg that quietly stops watching a workflow, or one that "
          "stops being extractable at all, goes red HERE rather than letting the single-watcher "
          "row below pass because there is nothing left to collide",
          _mesh_labelled(mesh_watchers),
          {"<self> conflict-resolver.yml": ["dashboard.yml/registry-keepalive"],
           "<self> curate.yml": ["dashboard.yml/registry-keepalive"],
           "<self> dashboard.yml": ["metrics.yml/dashboard-publish"],
           "<self> dispatch.yml": ["dashboard.yml/registry-keepalive"],
           "<self> groom-core.yml": ["dashboard.yml/registry-keepalive"],
           "<self> metrics.yml": ["dashboard.yml/registry-keepalive"],
           "<self> retriage.yml": ["dashboard.yml/registry-keepalive"],
           "sparq-org/sparq rearm-sweeper.yml": ["dashboard.yml/sparq-keepalive-dispatch"]})
    check("[#1085] ...and NO target in it is watched by more than one source (offenders listed as "
          "target -> watching legs). This is the premise that makes per-target jitter unnecessary "
          "and the exact condition under which it becomes REQUIRED: two sources on one target read "
          "the same COMPLETED anchor in the same tick, both conclude stale and both dispatch, and "
          "the #559 live-run guard cannot see it because neither kick is live yet when the other "
          "reads. Adding a second watcher reds this row — dephase on the (SOURCE, target) pair, "
          "never on `hash(target)`, which both sources compute identically",
          _mesh_labelled(mesh_watchers, only_shared=True),
          {})

    keepalive_gh_stub = r'''#!/usr/bin/env bash
# Hermetic `gh` for dashboard.yml's cron-keepalive body. Every argv is recorded; the three reads
# the body makes are served from fixture files; an argv this stub does not model exits 64, so a
# reshaped request fails LOUDLY instead of quietly satisfying the rows above.
set -u
printf '%s\n' "$*" >> "${STUB_CALLS}"
filter=""; want=0; endpoint=""
for a in "$@"; do
  if [ "$want" = 1 ]; then filter="$a"; want=0; continue; fi
  case "$a" in
    --jq) want=1 ;;
    repos/*) endpoint="$a" ;;
  esac
done
case "${endpoint}" in
  */dispatches)
    exit 0
    ;;
  *"/actions/artifacts?"*)
    if [ "${STUB_ARTIFACTS_FAIL}" = 1 ]; then
      printf 'gh-stub: artifacts read failed\n' >&2
      exit 1
    fi
    jq -r "${filter}" < "${STUB_DIR}/artifacts.json"
    ;;
  *"/runs?per_page=30")
    if [ "${STUB_LIVE_FAIL}" = 1 ]; then
      printf 'gh-stub: live-run read failed\n' >&2
      exit 1
    fi
    wf="${endpoint#*/workflows/}"; wf="${wf%%/*}"
    jq -r "${filter}" < "${STUB_DIR}/live-${wf}.json"
    ;;
  *"/runs?per_page=1")
    wf="${endpoint#*/workflows/}"; wf="${wf%%/*}"
    jq -r "${filter}" < "${STUB_DIR}/runs-${wf}.json"
    ;;
  *)
    printf 'gh-stub: unexpected argv: %s\n' "$*" >&2
    exit 64
    ;;
esac
'''
    keepalive_now = int(time.time())

    def _ka_stamp(age):
        return _utc_iso(keepalive_now - age)

    def _ka_run(age, status="completed"):
        return {"id": 1, "status": status, "conclusion": "success", "created_at": _ka_stamp(age)}

    def run_keepalive_leg(script, specs, *, artifacts=(), runs=None, live=None,
                          artifacts_fail=False, live_fail=False):
        """Execute a REAL cron-keepalive leg body. -> (exit code, [dispatch argv], log).

        Every listed workflow defaults to one settled run a minute old and no live run, so a row
        that says nothing about a workflow is asserting that leg stayed quiet. The dispatch argv is
        returned WHOLE rather than reduced to workflow names, so a leg's target repository and ref
        can be pinned by equality — the seam where a substring assertion goes vacuous."""
        runs, live = dict(runs or {}), dict(live or {})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binaries, stubs = root / "bin", root / "stub"
            binaries.mkdir()
            stubs.mkdir()
            (binaries / "gh").write_text(keepalive_gh_stub, encoding="utf-8")
            (binaries / "gh").chmod(0o755)
            (stubs / "artifacts.json").write_text(json.dumps({"artifacts": list(artifacts)}),
                                                  encoding="utf-8")
            for workflow in specs:
                (stubs / f"runs-{workflow}.json").write_text(
                    json.dumps({"workflow_runs": list(runs.get(workflow, [_ka_run(60)]))}),
                    encoding="utf-8")
                (stubs / f"live-{workflow}.json").write_text(
                    json.dumps({"workflow_runs": list(live.get(workflow, []))}), encoding="utf-8")
            calls = root / "calls"
            calls.write_text("", encoding="utf-8")
            completed = subprocess.run(
                ["bash", "-c", script], cwd=directory, capture_output=True, text=True,
                timeout=120, check=False,
                env=dict(os.environ,
                         PATH=f"{binaries}{os.pathsep}{os.environ.get('PATH', '')}",
                         GITHUB_REPOSITORY="o/r", GH_TOKEN="stub",
                         STUB_DIR=str(stubs), STUB_CALLS=str(calls),
                         STUB_ARTIFACTS_FAIL="1" if artifacts_fail else "0",
                         STUB_LIVE_FAIL="1" if live_fail else "0"))
            dispatched = sorted(line for line in calls.read_text(encoding="utf-8").split("\n")
                                if "/dispatches" in line)
        return completed.returncode, dispatched, completed.stdout + completed.stderr

    def run_keepalive_step(**fixtures):
        """The REGISTRY leg, subject of the #922 rows. -> (exit code, [workflows kicked], log)."""
        code, dispatched, log = run_keepalive_leg(keepalive_script, keepalive_specs, **fixtures)
        return code, sorted(re.findall(r"workflows/(\S+?)/dispatches", "\n".join(dispatched))), log

    marker_name = tick_floor.TICK_MARKER_ARTIFACT
    dispatch_limit = keepalive_specs["dispatch.yml"][0]

    def _ka_marker(age, **overrides):
        return dict({"name": marker_name, "created_at": _ka_stamp(age), "expired": False},
                    **overrides)

    def keepalive_check(name, got, want, log):
        """`check` with the step log attached ONLY on failure — a hermetic shell harness that fails
        silently is unusable, and attaching the log unconditionally would bury every row."""
        check(name, got if got == want else (got, log), want)

    def _tool_probe(*argv):
        """Exit status of `argv`, or a NAMED diagnostic string when the binary cannot be executed.

        A bare `subprocess.run` raises `FileNotFoundError` on a host without the tool, and it
        raises it while building the `check(...)` argument — so the row it was meant to produce
        never prints and the suite ABORTS mid-run. #1496 measured 178 rows on a worker container
        without `jq`; re-measured on this checkout, 203 of the suite's 305 rows printed and every
        check below never executed, with no named FAIL to say why — the count differs because the
        suite grew, the truncation does not. That is the crash-after-partial-run hazard of pre-flight
        item 4, baked into the suite itself: any author comparing a mutant's kill count against a
        pristine run would be comparing a truncated run against a full one. Returning the
        diagnostic as the row's VALUE keeps the dependency NAMED and red — the #922 contract —
        while the rest of the suite still runs. `node` is guarded the same way (`_node_json`)."""
        try:
            return subprocess.run(argv, capture_output=True, check=False).returncode
        except OSError as exc:
            return f"`{argv[0]}` could not be executed: {type(exc).__name__}: {exc}"

    # [#1496] The guard's OWN two directions, before the row that depends on it. A probe that
    # still raises reds `_probe_raised` here instead of aborting, so the mutant is a KILL with the
    # suite's full check count intact rather than another truncated run.
    _probe_raised = False
    try:
        _absent_probe = _tool_probe("dashboard-gen-1496-no-such-binary", "--version")
    except OSError:
        _absent_probe = None
        _probe_raised = True
    check("[#1496] a MISSING binary is reported as the probe's value, never raised: the row below "
          "goes red by name and every check after it still executes",
          (_probe_raised, isinstance(_absent_probe, str),
           "dashboard-gen-1496-no-such-binary" in str(_absent_probe), _absent_probe == 0),
          (False, True, True, False))
    check("[#1496] ...and the guard is not blanket exception-swallowing: a binary that EXISTS and "
          "exits non-zero still reports THAT exit status, so a broken tool cannot be mistaken for "
          "a working one (nor a working one for a missing one)",
          (_tool_probe(sys.executable, "-c", "raise SystemExit(37)"),
           _tool_probe(sys.executable, "-c", "")), (37, 0))
    # The rows above test the GUARD; this one tests its USE. A call site rewired back to an
    # unguarded `subprocess.run` on the binary keeps them both green while restoring the abort,
    # which is the AGENTS.md pre-flight item 6 seam — so pin the shape by exact count, both
    # directions. (The rejected spelling is deliberately never written out below: its own regex is
    # backslash-escaped and the prose around it says `jq` and the call separately, so this row
    # counts real call sites rather than matching the text that describes them.)
    _probe_source = Path(__file__).resolve().read_text(encoding="utf-8")
    check("[#1496] the jq probe reaches the binary THROUGH the guard: exactly one guarded call "
          "site and no bare `subprocess.run` one",
          (len(re.findall(r'_tool_probe\("jq", "--version"\)', _probe_source)),
           len(re.findall(r'subprocess\.run\(\["jq"', _probe_source))),
          (1, 0))
    check("[#922] jq is available for the hermetic harness below (a missing dependency must be "
          "NAMED, never silently skipped into a green run)",
          _tool_probe("jq", "--version"), 0)
    # THE REGRESSION. Fresh runs everywhere — exactly the steady state #79's ring sources produce —
    # and no executed tick for well past the threshold. The pre-#922 body kicked nothing here.
    code, kicked, log = run_keepalive_step(artifacts=[_ka_marker(dispatch_limit + 600)])
    keepalive_check(
        "[#922] a dispatcher that RUNS constantly but has executed no tick is kicked",
        (code, kicked), (0, ["dispatch.yml"]), log)
    code, kicked, log = run_keepalive_step(artifacts=[_ka_marker(dispatch_limit - 600)])
    keepalive_check(
        "[#922] ...and one that executed a tick inside the threshold is left alone (the leg is "
        "not simply kicking dispatch on every fire)", (code, kicked), (0, []), log)
    # The mirror: run-anchoring and marker-anchoring disagree in BOTH directions, so pin both.
    code, kicked, log = run_keepalive_step(
        artifacts=[_ka_marker(60)], runs={"dispatch.yml": [_ka_run(dispatch_limit + 600)]})
    keepalive_check(
        "[#922] a fresh executed tick keeps dispatch fresh even when its RUN listing is ancient — "
        "the leg reads the marker, not the run", (code, kicked), (0, []), log)
    code, kicked, log = run_keepalive_step(artifacts=[_ka_marker(60, expired=True)])
    keepalive_check(
        "[#922] an EXPIRED marker is not evidence of a recent tick",
        (code, kicked), (0, ["dispatch.yml"]), log)
    # The stub serves the artifact page UNFILTERED, so what is under test here is the body's own
    # `select(.name == env.ANCHOR)` rather than the `?name=` query parameter beside it. Two
    # neighbours, one per mutation: `dispatch-plan-9-1` is the real artifact dispatch.yml uploads
    # next to the marker and catches dropping the name test altogether; `dispatch-tick-9-1` catches
    # relaxing equality into a prefix, which is exactly the confusion dispatch-tick-floor.py's
    # newest_marker_epoch warns about.
    code, kicked, log = run_keepalive_step(
        artifacts=[{"name": "dispatch-plan-9-1", "created_at": _ka_stamp(60), "expired": False},
                   {"name": f"{marker_name}-9-1", "created_at": _ka_stamp(60), "expired": False}])
    keepalive_check(
        "[#922] the marker is matched by EQUALITY — neither a sibling dispatch artifact nor a "
        "name that merely starts with it is evidence that a tick executed",
        (code, kicked), (0, ["dispatch.yml"]), log)
    code, kicked, log = run_keepalive_step(
        artifacts=[_ka_marker(dispatch_limit + 600)],
        live={"dispatch.yml": [_ka_run(30, status="in_progress")]})
    keepalive_check(
        "[#922] the #559 live-run guard still wins: a queued/in-progress dispatch run is never "
        "kicked behind", (code, kicked), (0, []), log)
    code, kicked, log = run_keepalive_step(artifacts=[_ka_marker(60)], artifacts_fail=True)
    keepalive_check(
        "[#922] FAIL-OPEN: an unreadable artifact listing still kicks — the keepalive's whole job "
        "is liveness, and a mesh that goes quiet when a read fails IS the outage",
        (code, kicked), (0, ["dispatch.yml"]), log)
    # ...and the run-anchored legs are untouched by all of the above.
    code, kicked, log = run_keepalive_step(artifacts=[_ka_marker(60)],
                                           runs={"groom-core.yml": [_ka_run(99_999)]})
    keepalive_check(
        "[#922] the run-anchored legs still key on run age, and only the stale one is kicked",
        (code, kicked), (0, ["groom-core.yml"]), log)
    code, kicked, log = run_keepalive_step(artifacts=[_ka_marker(60)])
    keepalive_check(
        "[#922] control: a fleet that is fresh on BOTH anchors is kicked not at all",
        (code, kicked), (0, []), log)
    # #559's guard has TWO live statuses and the row above exercises one. A guard narrowed to
    # `.status == "in_progress"` leaves a QUEUED run — the run a kick most directly duplicates,
    # because the singleton group then runs the pair back to back — kicked behind, which is the
    # storm itself.
    code, kicked, log = run_keepalive_step(
        artifacts=[_ka_marker(dispatch_limit + 600)],
        live={"dispatch.yml": [_ka_run(30, status="queued")]})
    keepalive_check(
        "[#559] a QUEUED run is live too — the guard reads 'not completed', not 'in_progress'",
        (code, kicked), (0, []), log)
    # ...and the guard's OWN fail-open, which nothing executed before: a live check that cannot be
    # read must fall through to the age check. A guard that treats an unreadable read as "live"
    # silences the whole keepalive on exactly the API blip it was added to survive.
    code, kicked, log = run_keepalive_step(
        artifacts=[_ka_marker(dispatch_limit + 600)], live_fail=True)
    keepalive_check(
        "[#559] FAIL-OPEN: an unreadable live-run check still consults age, and still kicks a "
        "stale target", (code, kicked), (0, ["dispatch.yml"]), log)

    # #680: the bound above is arithmetic across two files; these two rows are the BEHAVIOUR it
    # buys, driven through the real leg. Every age is derived from the watched workflow's OWN
    # cadence and never from the spec list the leg reads, so moving a threshold to either side of
    # the bound flips one of them: at 2x cadence (where groom-core.yml and retriage.yml sat) the
    # missed-a-fire row goes quiet for exactly those two, and at 1x cadence the punctual row starts
    # kicking. The pair is deliberately one row per direction — a single-direction row is satisfied
    # by a leg that kicks everything, or by one that kicks nothing.
    punctual = {name: [_ka_run(cadence + 60)] for name, cadence in keepalive_cadences.items()}
    code, kicked, log = run_keepalive_step(artifacts=[_ka_marker(60)], runs=punctual)
    keepalive_check(
        "[#680] a workflow whose last fire was DELIVERED one cadence ago is not kicked behind it — "
        "a threshold tightened to or under the cadence is the #559 storm on every healthy tick",
        (code, kicked), (0, []), log)
    missed = {name: [_ka_run(2 * cadence - 60)] for name, cadence in keepalive_cadences.items()}
    code, kicked, log = run_keepalive_step(artifacts=[_ka_marker(60)], runs=missed)
    keepalive_check(
        "[#680] ...and EVERY non-exempt run-anchored workflow that has missed exactly one fire is "
        "kicked inside that same cycle. groom-core.yml/retriage.yml are EXEMPT while #1353 blocks their "
        "re-sizing: at exactly 2x cadence a single dropped fire still reads FRESH, so they are not "
        "kicked — that is the cost of the exemption, asserted here so it stays visible",
        (code, kicked),
        (0, sorted(set(keepalive_cadences) - _THRESHOLD_BOUND_EXEMPT)), log)

    # --- #559: the CROSS-REPO leg. It kicks sparq-org/sparq, where a dup-dispatch storm shows up in
    # ANOTHER repo's telemetry entirely, and until now nothing executed it: the live-run guard, the
    # target repository and the ref were all covered by `bash -n` and actionlint, neither of which
    # can see any of the three. Same hermetic harness, same stubs — a leg of the mesh with no
    # executable coverage is a leg that silently reverts.
    # ------------------------------------------------------------------------------------------
    sparq_target = "rearm-sweeper.yml"
    check("[#559] the cross-repo leg watches exactly the one RUN-anchored spec these rows drive — "
          "a second target, or a marker-anchored one (which this leg's 2-field `${spec##*:}` parse "
          "cannot express), must go red here rather than ship untested",
          {name: marker for name, (_limit, marker) in sparq_specs.items()},
          {sparq_target: ""})
    if sparq_target not in sparq_specs:
        raise DashboardError(
            f"the cross-repo keepalive leg no longer watches {sparq_target} — refusing: the #559 "
            "rows below cannot be driven against a target that is not there, and a NAMED refusal "
            "beats aborting the suite half-way through on a KeyError")
    sparq_limit = sparq_specs[sparq_target][0]
    # Pinned by EQUALITY, and deliberately not assembled from anything the body supplies: owner,
    # repo and ref are the three values a mis-edit here would silently redirect (a kick at `master`
    # on a `main`-default repo 404s and the sweeper simply stops being revived).
    sparq_dispatch = ("api -X POST "
                      f"repos/sparq-org/sparq/actions/workflows/{sparq_target}/dispatches "
                      "-f ref=main")
    code, dispatched, log = run_keepalive_leg(
        sparq_script, sparq_specs, runs={sparq_target: [_ka_run(sparq_limit + 600)]})
    keepalive_check(
        "[#559] the cross-repo leg kicks a stale sparq sweeper — at sparq-org/sparq, on `main`",
        (code, dispatched), (0, [sparq_dispatch]), log)
    for status in ("queued", "in_progress"):
        code, dispatched, log = run_keepalive_leg(
            sparq_script, sparq_specs,
            runs={sparq_target: [_ka_run(sparq_limit + 600)]},
            live={sparq_target: [_ka_run(30, status=status)]})
        keepalive_check(
            f"[#559] ...but never behind a run whose status is {status}: an ancient run listing is "
            "NOT stale while that run is still live, which is the cancel-storm this guard ends",
            (code, dispatched), (0, []), log)
    code, dispatched, log = run_keepalive_leg(
        sparq_script, sparq_specs, runs={sparq_target: [_ka_run(sparq_limit + 600)]},
        live_fail=True)
    keepalive_check(
        "[#559] FAIL-OPEN cross-repo too: an unreadable live check falls through to the age check "
        "rather than wedging the sweeper's only fallback shut",
        (code, dispatched), (0, [sparq_dispatch]), log)
    code, dispatched, log = run_keepalive_leg(sparq_script, sparq_specs)
    keepalive_check(
        "[#559] control: a sweeper that ran inside its threshold is not kicked at all — the leg is "
        "not simply dispatching on every fire", (code, dispatched), (0, []), log)

    # --- #935: the SEAM around that leg, which no amount of executing the body can reach. The rows
    # above drive the script directly; production reaches it only through a step-level `if:`, and
    # only on the token the mint step before it produces. Both of those wirings are deletable with
    # every row above still green: `if: false` on the step retires the sweeper's only fallback in
    # complete silence (a skipped step concludes the job green), and re-pointing GH_TOKEN at the
    # default `github.token` breaks it exactly when it is needed and at no other time, because that
    # token has no actions:write in sparq-org and so 403s at the moment of the kick. #935 names this
    # leg the hardest silent break to notice from the registry side; both survivors are that break.
    # Pinned by EQUALITY on the raw expression text — a containment check is satisfied by appending
    # `&& false`. (The JOB carrying both legs is asserted ungated by metrics.py's own suite, which
    # parses dashboard.yml at job level; not restated here.)
    # ------------------------------------------------------------------------------------------
    sparq_env = _workflow_step_env(dashboard_workflow, "sparq-keepalive-dispatch")
    minted = re.fullmatch(r"\$\{\{\s*steps\.([A-Za-z0-9_-]+)\.outputs\.token\s*\}\}",
                          sparq_env.get("GH_TOKEN") or "")
    # ...and WHAT THE PRODUCER IS, not merely that something answers to its id. Round 1's review:
    # resolving the step id proved only that SOME step carries it, so a same-id `run: echo` no-op —
    # or the same mint re-pointed at another owner/repository, or asked for `permission-actions:
    # read` — left the tuple identical while the dispatch can no longer obtain the cross-repo
    # actions:write credential this leg exists to spend. Every input the credential's SCOPE depends
    # on is pinned by equality, including the App the secrets name: a mint fed a different App's
    # id/key is a different (possibly uninstalled) identity on sparq-org.
    #
    # A wiring naming a step that no longer exists, or one that is no longer a mint at all, must go
    # RED on this row and never abort the suite part-way: every row below an unhandled refusal
    # stops running and the mutant reads as a kill.
    def _minted_by(text, step_id):
        try:
            uses = _workflow_step_key(text, step_id, "uses")
            inputs = _workflow_step_mapping(text, step_id, "with")
        except DashboardError:
            return None
        # The pin's trailing ` # v3.2.0` annotates the SHA; it is not part of the reference.
        return ((uses or "").partition(" #")[0].strip(), inputs.get("app-id"),
                inputs.get("private-key"), inputs.get("owner"), inputs.get("repositories"),
                inputs.get("permission-actions"))

    mint_pin = ("actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
                "${{ secrets.REGISTRY_ADMIN_APP_ID }}", "${{ secrets.REGISTRY_ADMIN_APP_KEY }}",
                "sparq-org", "sparq", "write")
    check("[#935] the cross-repo leg is GATED on a minted App token and RUNS on that same minted "
          "token, and the step it names IS the SHA-pinned App mint scoped to sparq-org/sparq with "
          "actions:write — dropping or weakening any of those wirings leaves every executed row "
          "above green while the sweeper's only fallback is dead",
          (_workflow_step_key(dashboard_workflow, "sparq-keepalive-dispatch", "if"),
           sparq_env.get("GH_TOKEN"),
           minted.group(1) if minted else None,
           _minted_by(dashboard_workflow, minted.group(1)) if minted else None),
          ("steps.sparq-keepalive-token.outputs.token != ''",
           "${{ steps.sparq-keepalive-token.outputs.token }}",
           "sparq-keepalive-token",
           mint_pin))
    # ...and that the row above is the thing killing those mutants, driven as mutations of the LIVE
    # file so neither reads its own stub: a same-id non-mint step is a NAMED miss rather than a
    # raise (the suite keeps running, so the row count is the same red-or-green), and a redirected
    # scope is read back changed rather than defaulted away.
    noop_mint = ("      - name: synthetic\n"
                 "        id: sparq-keepalive-token\n"
                 "        run: |\n"
                 "          true\n")

    def _mint_input(text, slot):
        """One slot of the producer's identity under a mutation, or None when the mutant left no
        readable mint — indexing a miss here would abort the suite on the very mutant this row
        exists to prove is survivable, which is how the count stops being comparable."""
        found = _minted_by(text, "sparq-keepalive-token")
        return found[slot] if found else None

    check("[#935] the producer pin is falsifiable: a same-id non-mint step reads as None without "
          "aborting the suite, and a redirected owner or downgraded permission is read back as "
          "the changed value",
          (_minted_by(noop_mint, "sparq-keepalive-token"),
           _mint_input(dashboard_workflow.replace("          owner: sparq-org\n",
                                                  "          owner: jeswr\n"), 3),
           _mint_input(dashboard_workflow.replace("          permission-actions: write\n",
                                                  "          permission-actions: read\n"), 5)),
          (None, "jeswr", "read"))
    # The extractor's OWN guards, driven directly: the live step has exactly one `if:` at its own
    # column, so neither the nesting bound nor the absent/duplicate paths execute above — and an
    # extractor that answered `nested-must-not-count` (or first-wins on a duplicate) would make the
    # row above pass against a step carrying no gate at all.
    nested_key = ("      - name: synthetic\n"
                  "        id: synthetic-step\n"
                  "        with:\n"
                  "          if: nested-must-not-count\n"
                  "        run: |\n"
                  "          true\n")
    own_key = nested_key.replace("          if: nested-must-not-count\n",
                                 "          ref: main\n"
                                 "        if: own-gate\n")
    check("[#935] the step-key extractor reads the step's OWN keys: a nested `if:` is not one, an "
          "absent gate is None rather than a default, the first key rides the `- `, and two gates "
          "at that column is a refusal",
          (_workflow_step_key(nested_key, "synthetic-step", "if"),
           _workflow_step_key(own_key, "synthetic-step", "if"),
           _workflow_step_key(own_key, "synthetic-step", "name"),
           _raises_dashboard(lambda: _workflow_step_key(
               own_key.replace("        run: |\n", "        if: second-gate\n        run: |\n"),
               "synthetic-step", "if"))),
          (None, "own-gate", "synthetic", True))

    # --- #612 review round 2, finding 5 (MINOR): the successful CLI -> builder handoff. Deleting
    # `probe_status=probe_status` from main()'s build_dashboard call left every direct-builder test
    # AND the missing-flag negative test above green, while production parsed a valid sidecar and
    # then threw it away — publishing zero eligible capacity with an unmeasured warning on every
    # healthy run. So main() is driven end to end here, and the assertion is a PAIR: the same
    # entrypoint must publish capacity for a fresh sidecar and refuse it for a failed one, which no
    # constant return value satisfies. `_fetch_dispatch_history` (a `gh` subprocess) is the only
    # stub; the probe_status plumbing under test is the real code path.
    # ------------------------------------------------------------------------------------------
    live_now = int(time.time())
    live_usage = {handle: {"status": "allowed", "5h_used": "10", "5h_util": "0.1",
                           "5h_reset": live_now + 3600, "7d_used": "80", "7d_util": "0.8",
                           "7d_reset": live_now + 86400}}

    # [#1106] The history stub is now a PAIR (rows, fetch outcome), and the published marker joins
    # the tuple below: dropping `history_status=history_status` from main()'s build_dashboard call
    # would publish `unknown` where the fetcher said `failed`, with every other row here green.
    failed_history_marker = {"outcome": "failed", "detail": "gh-exited-nonzero", "fetched": False}

    def main_document(sidecar, history_stub=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, payload in (("issues.json", issues), ("usage.json", live_usage),
                                  ("leases.json", leases),
                                  ("model-health.json", {"records": []}),
                                  ("usage-probe.json", sidecar)):
                Path(root, name).write_text(json.dumps(payload), encoding="utf-8")
            saved_history = globals()["_fetch_dispatch_history"]
            saved_salt = os.environ.get("PROVENANCE_SALT")
            globals()["_fetch_dispatch_history"] = history_stub or (
                lambda repo, count: ([], {"outcome": "failed", "detail": "gh-exited-nonzero"}))
            os.environ["PROVENANCE_SALT"] = "fixture-salt"
            try:
                main(["--issues-file", str(root / "issues.json"),
                      "--usage", str(root / "usage.json"),
                      "--usage-status", str(root / "usage-probe.json"),
                      "--leases", str(root / "leases.json"),
                      "--model-health", str(root / "model-health.json"),
                      "--assets", str(Path(__file__).resolve().parent.parent / "dashboard"),
                      "--site", str(root / "site")])
            finally:
                globals()["_fetch_dispatch_history"] = saved_history
                if saved_salt is None:
                    os.environ.pop("PROVENANCE_SALT", None)
                else:
                    os.environ["PROVENANCE_SALT"] = saved_salt
            published = json.loads(Path(root, "site", "data.json").read_text(encoding="utf-8"))
            return ((published.get("usage_probe") or {}).get("measured"),
                    published["provider_quota"][0]["headroom"],
                    published["fleet"]["capacity"],
                    # [#374] the END-TO-END statement: whatever else main() writes, the file that
                    # actually reaches Pages carries no composition key.
                    sorted(FLEET_COMPOSITION_KEYS
                           & set(re.findall(r'"([^"]+)":', json.dumps(published)))),
                    # [#1106] ...and the fetch outcome the stubbed fetcher handed main().
                    published.get("dispatch_history"))

    check("[#612] main() forwards a FRESH sidecar, so a healthy run still publishes capacity",
          main_document({"schema": PROBE_SCHEMA, "outcome": "ok", "detail": "probe-succeeded",
                         "attempted_at": live_now}),
          (True, "available", {"anthropic": True}, [], failed_history_marker))
    check("[#612] main() forwards a FAILED sidecar, so the same run publishes none",
          main_document({"schema": PROBE_SCHEMA, "outcome": "failed",
                         "detail": "probe-exited-nonzero", "attempted_at": live_now}),
          (False, "unknown", {"anthropic": False}, [], failed_history_marker))
    # ...and the OTHER polarity through the same entrypoint, so the marker is shown to track the
    # fetcher's answer rather than being pinned to one constant (pre-flight item 2(d)).
    check("[#1106] main() publishes `fetched: True` when the history read SUCCEEDED — the marker "
          "tracks the fetch outcome, it is not pinned to one value",
          main_document({"schema": PROBE_SCHEMA, "outcome": "ok", "detail": "probe-succeeded",
                         "attempted_at": live_now},
                        history_stub=lambda repo, count: (
                            [{"at": "2025-06-15T15:05:00Z", "conclusion": "success",
                              "dispatched": 1, "deferred": 0, "lanes": None}],
                            {"outcome": "ok", "detail": ""}))[-1],
          {"outcome": "ok", "detail": "", "fetched": True})

    # --- #612 review round 2, finding 5 (MINOR), UI half: the page's call sites. Deleting
    # `summary.append(probe)` or the SECOND argument of `updateFreshness(...)` removes the promised
    # operator warning with no Python test affected. Each assertion below is scoped to the ONE
    # function that must make the call — a whole-file search for `usage_probe` in app.js is
    # satisfied by any of its several other occurrences, which is precisely the vacuity class here.
    # ------------------------------------------------------------------------------------------
    # #612 review round 4 (MINOR, class E): the round-3 form of this block was COMMENT-satisfiable
    # (`_js_function_body` strips nothing, so commenting the call out kept it green) and could not
    # see polarity (flipping `if (!measured)` to `if (measured)` survived). Two changes: every
    # lexical row now counts CODE positions only, with an exact count so a neighbouring branch's
    # occurrence cannot stand in; and the page script is EXECUTED under node against the document
    # this generator really builds, which is what actually pins polarity.
    # ------------------------------------------------------------------------------------------
    app_js = _repo_file("dashboard", "app.js")
    summary_body = _js_function_body(app_js, "renderSummary")
    check("[#612] renderSummary() builds the probe card from data.usage_probe AND appends it",
          (_js_code_count(summary_body, "usageProbeCard(data.usage_probe)"),
           _js_code_count(summary_body, "if (probe) summary.append(probe);")),
          (1, 1))
    check("[#612] render() hands the probe marker to updateFreshness (both arguments)",
          _js_code_count(_js_function_body(app_js, "render"),
                         "updateFreshness(data.generated_at, data.usage_probe)"),
          1)
    freshness = _js_function_body(app_js, "updateFreshness")
    check("[#612] updateFreshness() consumes the marker, on the unmeasured polarity",
          (_js_code_count(freshness, 'probe.measured !== true'),
           # NOT a bare `notices.push` count: the stale-generation branch supplies another
           # occurrence, so deleting the probe branch's push used to pass (round-4 MINOR).
           _js_code_count(freshness, "notices.push(`Usage probe did not measure the fleet"),
           _js_code_count(freshness, "warning.hidden = notices.length === 0;")),
          (1, 1, 1))
    probe_card = _js_function_body(app_js, "usageProbeCard")
    check("[#612] the probe card degrades on anything but an explicit measured:true",
          (_js_code_count(probe_card, "const measured = probe.measured === true;"),
           _js_code_count(probe_card, 'if (!measured) card.classList.add("degraded");')),
          (1, 1))
    # A control on the matcher itself: a commented-out call and a call inside a string literal must
    # BOTH read as zero, or the rows above are back to being satisfiable by prose.
    check("[#612] the code-position matcher ignores comments and string literals",
          (_js_code_count("// if (probe) summary.append(probe);\n", "summary.append(probe)"),
           _js_code_count('const help = "summary.append(probe)";\n', "summary.append(probe)"),
           _js_code_count("/* summary.append(probe) */\nsummary.append(probe);\n",
                          "summary.append(probe)")),
          (0, 0, 1))
    # --- ...and the two call sites EXECUTED. The page is loaded into the shared DOM shim under node
    # (`_PAGE_HARNESS`, which also stubs `fetch` to reject — the page's own load path is not under
    # test — and `setInterval` to a no-op so node exits) and handed the real generated document, so
    # `if (!measured)` -> `if (measured)`, dropping `summary.append(probe)`, or dropping
    # updateFreshness's second argument each change an OUTCOME rather than a substring.
    # ------------------------------------------------------------------------------------------
    page_body = r"""
  const cards = {};
  for (const [name, probe] of Object.entries(input.probes)) {
    const card = scope.usageProbeCard(probe);
    cards[name] = card === null ? null : { text: text(card), degraded: degraded(card) };
  }
  const warnings = {};
  for (const [name, document_] of Object.entries(input.documents)) {
    ids.warning = element("div#warning");
    ids.summary = element("div#summary");
    ids["provider-quota"] = element("div#provider-quota");
    ids.outcomes = element("tbody#outcomes");
    scope.render(document_);
    warnings[name] = {
      hidden: ids.warning.hidden,
      // [#1106] the dispatch-outcomes body as the page SHOWS it. render() is the one call site
      // that wires `data.dispatch_history` into renderOutcomes, so dropping that second argument
      // changes this text — it is not satisfiable by an occurrence elsewhere in app.js.
      outcomes: text(ids.outcomes),
      outcomesDegraded: (ids.outcomes.children || []).some(degraded),
      // [#374] the rendered quota + summary text, so the assertions below can state what the page
      // SHOWS rather than what app.js contains: a headroom word and a percentage, never a count of
      // accounts. `text()` walks children, which is where every one of those strings lives.
      quota: text(ids["provider-quota"]),
      capacityLines: text(ids.summary),
      // `text()`, not `.textContent`: updateFreshness renders each independent degradation as its
      // own `.warning-line` child (issue #580), so the banner's own textContent is empty and a
      // direct read would make this row vacuously false for BOTH documents.
      probeNotice: /Usage probe did not measure the fleet/.test(text(ids.warning)),
      summaryDegraded: ids.summary.children.some(degraded),
      // Issue #580: staleness and the probe verdict are independent, so a page carrying both must
      // render both — as SEPARATE `.warning-line` paragraphs, not one run-together blob.
      lines: (ids.warning.children || []).filter((kid) => kid.className === "warning-line").length,
      staleNotice: /Stale data/.test(text(ids.warning)),
      capacityNote: /Eligible capacity unmeasured/.test(text(ids.summary)),
    };
  }
  // [#71] the quota card on its own, so a reset stamp can be placed either side of the wall clock
  // the renderer compares against. `Date.now()` inside the page is the real clock here — the whole
  // point of the assertions below is that the comparison happens at RENDER time — so the fixtures
  // offset their stamps from that clock rather than pinning it.
  const resets = {};
  for (const [name, row] of Object.entries(input.quotaRows || {})) {
    resets[name] = text(scope.providerQuotaCard(row));
  }
  // [#1343] the one absolute-stamp helper every timestamp on the page goes through, called
  // directly on pinned instants — the hour glyph it prints is the whole finding, so the rows
  // read the RENDERED string rather than anything app.js was grepped for.
  const stamps = {};
  for (const [name, value] of Object.entries(input.stamps || {})) {
    stamps[name] = scope.utc(value);
  }
  process.stdout.write(JSON.stringify({ cards, warnings, resets, stamps }));
"""
    # A LIVE `now`: the page's own staleness notice fires on a year-old fixture stamp, and that
    # notice would then mask the probe notice this block is about.
    measured_document = build_dashboard(
        issues, leases, live_usage, history, None, live_now, "fixture-salt",
        probe_status={"schema": PROBE_SCHEMA, "outcome": "ok", "detail": "probe-succeeded",
                      "attempted_at": live_now})
    failed_document = build_dashboard(
        issues, leases, live_usage, history, None, live_now, "fixture-salt",
        probe_status={"schema": PROBE_SCHEMA, "outcome": "failed",
                      "detail": "secret-materialization-failed", "attempted_at": live_now})
    # ...and the same failed probe on a STALE generation (the year-old fixture `now`), which is the
    # one document where both independent degradations fire at once (issue #580).
    stale_failed_document = build_dashboard(
        issues, leases, live_usage, history, None, now, "fixture-salt",
        probe_status={"schema": PROBE_SCHEMA, "outcome": "failed",
                      "detail": "secret-materialization-failed", "attempted_at": now})
    # --- [#1106] the pair the issue is about: NO dispatch history, once because the fleet has
    # genuinely never dispatched and once because the `gh` run listing failed. Everything the page
    # had to go on — `dispatch_outcomes: []` and `last_sweep_at: null` — is identical between them.
    quiet_history_document = build_dashboard(
        issues, leases, live_usage, [], None, live_now, "fixture-salt",
        probe_status={"schema": PROBE_SCHEMA, "outcome": "ok", "detail": "probe-succeeded",
                      "attempted_at": live_now},
        history_status={"outcome": "ok", "detail": ""})
    lost_history_document = build_dashboard(
        issues, leases, live_usage, [], None, live_now, "fixture-salt",
        probe_status={"schema": PROBE_SCHEMA, "outcome": "ok", "detail": "probe-succeeded",
                      "attempted_at": live_now},
        history_status={"outcome": "failed", "detail": "gh-exited-nonzero"})
    # --- [#71] reset stamps, on BOTH sides of the wall clock the page renders against. A reset is
    # the only FORWARD-looking instant the page shows, and `relative()` renders any instant, so a
    # stamp that elapsed after the build printed "next reset 6 minutes ago" — a pending refill that
    # had in fact already happened, next to a utilization figure the refill had invalidated. The
    # stamps are offset from the WALL CLOCK (never from `now`/`live_now` as a rendering-time
    # constant: the page compares against `Date.now()`, and a fixture that elapses only because the
    # generator's clock says so would not exercise that comparison at all).
    def reset_row(soonest_offset, oldest_offset):
        wall = time.time()
        soonest, oldest = _utc_iso(wall + soonest_offset), _utc_iso(wall + oldest_offset)
        return {"provider": "anthropic", "headroom": "capped",
                "signal": "live rate-limit-header probe (per-window utilization)",
                "windows": [{"name": "5h", "remaining_fraction": 0.0,
                             "soonest_reset": soonest, "oldest_reset": oldest}],
                "soonest_reset": soonest, "oldest_reset": oldest}

    # --- [#1341] the guard the executed-page call below depends on, held to BOTH directions on a
    # real `node` run: a page that throws becomes the rows' VALUE (every nested lookup they make
    # resolves to the diagnostic, so each row goes red BY NAME and the suite still reaches its full
    # check count), and a page that renders reaches them unaltered.
    def _guard_probe(exports, body, probe):
        """`probe` applied to what `_executed_page` hands the rows below — or the raise, as a value.

        Own-abort insurance: the regressions this row exists to catch (an unguarded call, or a
        fallback whose nested lookups cannot be traversed) RAISE, and a raise here would terminate
        the suite in exactly the way #1341 is about — recording as a kill with every later check
        unrun. Reporting it as the row's value keeps this row red by name instead.

        `exports` and the non-empty payload come from the caller so that they MATCH the real call
        site below: a guard made conditionally inert on either (pre-flight item 3 — the mutant that
        is not a deletion) then goes inert here too, and is caught, instead of surviving because the
        probe happened to call through a differently-shaped harness."""
        harness = _page_harness(exports, body)
        try:
            return probe(_executed_page(harness, {"probe": "1341"}))
        except Exception as exc:  # noqa: BLE001 — any raise out of the guard IS the finding
            return f"probe raised: {type(exc).__name__}: {exc}"[:120]

    _thrown_probe = _guard_probe(
        "usageProbeCard, updateFreshness, render, providerQuotaCard, utc",
        "  throw new Error('deliberate-1341-page-failure');",
        lambda page: ("deliberate-1341-page-failure" in page,
                      page.startswith("page script raised:"),
                      page["cards"]["measured"]["degraded"] is page,
                      page["warnings"].get("quietHistory") is page,
                      page["cards"]["absent"] is None,
                      "NOT MEASURED" in page["cards"]["failed"]["text"]))
    _rendered_probe = _guard_probe(
        "usageProbeCard, updateFreshness, render, providerQuotaCard, utc",
        "  console.log(JSON.stringify({ loaded: typeof scope.render }));",
        lambda page: (page, isinstance(page, _RaisedPage)))
    check("[#1341] a page script that THROWS is reported as the rows' value rather than raised: "
          "the diagnostic names the underlying failure, and the nested lookups the rows below make "
          "resolve to it instead of aborting the suite on a KeyError",
          _thrown_probe, (True, True, True, True, False, False))
    check("[#1341] ...and a page that RENDERS reaches those rows untouched — the guard reports a "
          "failed render, it never stands in for a successful one",
          _rendered_probe, ({"loaded": "function"}, False))
    # The two rows above test the GUARD; this one tests its USE. A call site rewired back to a bare
    # `_node_json` keeps them both green while losing the whole protection, which is the AGENTS.md
    # pre-flight item 6 seam — so the executed-page call below is pinned by exact shape here.
    _own_source = Path(__file__).resolve().read_text(encoding="utf-8")
    check("[#1341] the executed-page block reaches `node` THROUGH the guard: exactly one guarded "
          "call site and no bare `_node_json` one",
          (len(re.findall(r'_executed_page\(\s*_page_harness\("usageProbeCard', _own_source)),
           len(re.findall(r'_node_json\(\s*_page_harness\("usageProbeCard', _own_source))),
          (1, 0))

    # `_executed_page`, never a bare `_node_json`: a page that throws while rendering IS the
    # finding, and reporting it as the value of every row below keeps those rows named and red
    # instead of aborting the suite mid-run with its later checks unexecuted (issue #1341).
    page = _executed_page(
        _page_harness("usageProbeCard, updateFreshness, render, providerQuotaCard, utc", page_body),
        {"probes": {"measured": measured_document["usage_probe"],
                    "failed": failed_document["usage_probe"],
                    "absent": None},
         "documents": {"measured": measured_document, "failed": failed_document,
                       "staleFailed": stale_failed_document,
                       "quietHistory": quiet_history_document,
                       "lostHistory": lost_history_document},
         # -360 is the issue's own reading ("Resets 6 minutes ago"). `split` is the case a single
         # per-CARD staleness flag gets wrong: the first window has refilled while the last known
         # refill is still ahead, so the two stamps must be judged INDEPENDENTLY.
         "quotaRows": {"future": reset_row(5400, 86400), "elapsed": reset_row(-360, -60),
                       "split": reset_row(-360, 5400)},
         # [#1343] FIXED instants, never a clock reading: the hour cycle is what is under test, so
         # the input has to name the hour. `midnight`/`midnightExact` are the bug's own hour;
         # `noon`/`afternoon` are the controls that keep the fix from over-shooting into h11/h12.
         "stamps": {"midnight": "2026-07-18T00:30:00Z",
                    "midnightExact": "2026-07-18T00:00:00Z",
                    "noon": "2026-07-18T12:00:00Z",
                    "afternoon": "2026-07-18T13:05:00Z",
                    "unparseable": "not-a-timestamp"}})
    # --- [#1343] `utc()` EXECUTED on pinned instants. `hour12: false` resolves to the **h24** hour
    # cycle for many locales (en-US on the pinned node 20 among them), so the hour after midnight
    # printed as hour 24 of the PREVIOUS day's clock: `00:30Z` rendered "Jul 18, 2026, 24:30". Every
    # absolute stamp on the page — freshness, last sweep, probe attempt, health/metrics/observability
    # collection, the outcome rows, the reset notes — goes through this one helper.
    #
    # The rows read the CLOCK TOKEN out of the rendered string rather than the whole string, because
    # `dateStyle: "medium"` is locale-shaped; the hour and minute glyphs are the entire finding. Both
    # directions are pinned, and each rejected spelling moves a DIFFERENT row: h24 (the bug) prints
    # `24` at midnight, h12 prints `12`/`1`, h11 prints `0` at midnight and `0` at noon, and dropping
    # the option altogether lands on the locale default (h12 here). A non-latin-digit default locale
    # finds no token at all and goes red by name — this row never passes by failing to look.
    def _clock(rendered):
        """`(hour, minute, ends-in-UTC)` as the page SHOWS them — or a diagnostic, never a pass."""
        if not isinstance(rendered, str):
            return f"not a rendered stamp: {rendered!r}"[:120]
        token = re.search(r"(\d{1,2}):(\d{2})", rendered)
        if not token:
            return f"no clock token in {rendered!r}"[:120]
        return (token.group(1), token.group(2), rendered.endswith(" UTC"))

    # `.get` off a truthy fallback, never `page["stamps"]["…"]`: an emptied or deleted stamps block
    # would otherwise `KeyError` out of the suite and score as a kill with every later row unrun
    # (#1341 / pre-flight item 4). A raised page keeps `_RaisedPage`'s self-returning lookups.
    stamps = page.get("stamps") or _RaisedPage("the executed page emitted no `stamps` block")
    check("[#1343] EXECUTED page script: utc() prints the midnight hour as 00, not h24's 24 — the "
          "one hour a day every absolute stamp on the page read across a day boundary",
          (_clock(stamps.get("midnight")), _clock(stamps.get("midnightExact"))),
          (("00", "30", True), ("00", "00", True)))
    check("[#1343] ...and the rest of the day still reads as a 24-hour clock: noon is 12 (not h11's "
          "0) and the afternoon is 13 (not h12's 1), so the fix cannot overshoot the other way",
          (_clock(stamps.get("noon")), _clock(stamps.get("afternoon"))),
          (("12", "00", True), ("13", "05", True)))
    check("[#1343] ...and an unparseable stamp is still refused rather than formatted",
          stamps.get("unparseable"), "unknown")
    # A control on the extractor itself: it must be able to SEE the h24 rendering and the two
    # 12-hour ones, or the three rows above are satisfiable by an instrument that reads nothing.
    check("[#1343] the clock-token extractor distinguishes the spellings the rows above reject",
          (_clock("Jul 18, 2026, 24:30 UTC"), _clock("Jul 18, 2026, 12:30 AM UTC"),
           _clock("Jul 18, 2026, 0:30 AM UTC"), _clock("unknown"), _clock(None)),
          (("24", "30", True), ("12", "30", True), ("0", "30", True),
           "no clock token in 'unknown'", "not a rendered stamp: None"))

    check("[#612] EXECUTED page script: the probe card degrades exactly when nothing was measured",
          (page["cards"]["measured"]["degraded"],
           "NOT MEASURED" in page["cards"]["measured"]["text"],
           page["cards"]["failed"]["degraded"],
           "NOT MEASURED" in page["cards"]["failed"]["text"],
           "secret-materialization-failed" in page["cards"]["failed"]["text"],
           page["cards"]["absent"]),
          (False, False, True, True, True, None))
    check("[#612] EXECUTED page script: render() raises the operator warning on a failed probe",
          (page["warnings"]["measured"]["hidden"],
           page["warnings"]["measured"]["probeNotice"],
           page["warnings"]["measured"]["summaryDegraded"],
           page["warnings"]["failed"]["hidden"],
           page["warnings"]["failed"]["probeNotice"],
           page["warnings"]["failed"]["summaryDegraded"]),
          (True, False, False, False, True, True))
    # --- issue #580: the banner carries INDEPENDENT degradations as separate lines, and the
    # unmeasured `eligible` figure is annotated where it is rendered. Both directions are pinned:
    # a healthy page has zero lines and no capacity note, a failed-but-fresh page has exactly one
    # line, and a stale+failed page has TWO — so collapsing them back into one joined blob, or
    # letting either notice mask the other, is red rather than green.
    check("[#580] EXECUTED page script: independent degradations render as separate lines",
          (page["warnings"]["measured"]["lines"],
           page["warnings"]["measured"]["capacityNote"],
           page["warnings"]["failed"]["lines"],
           page["warnings"]["failed"]["staleNotice"],
           page["warnings"]["failed"]["capacityNote"],
           page["warnings"]["staleFailed"]["hidden"],
           page["warnings"]["staleFailed"]["lines"],
           page["warnings"]["staleFailed"]["staleNotice"],
           page["warnings"]["staleFailed"]["probeNotice"],
           page["warnings"]["staleFailed"]["capacityNote"]),
          (0, False, 1, False, True, False, 2, True, True, True))
    # --- [#1106] ...and the same executed page on the two histories-that-are-not-there. Both rows
    # below are red on the pre-#1106 page, where the two documents rendered the SAME string.
    quiet_page = page["warnings"].get("quietHistory") or {}
    lost_page = page["warnings"].get("lostHistory") or {}
    check("[#1106] EXECUTED page script: a fleet that has genuinely never dispatched and one whose "
          "history could not be READ no longer render the same empty-history row",
          (quiet_page.get("outcomes", "").strip(), quiet_page.get("outcomesDegraded"),
           "could not be read" in lost_page.get("outcomes", ""),
           "gh-exited-nonzero" in lost_page.get("outcomes", ""),
           lost_page.get("outcomesDegraded"),
           quiet_page.get("outcomes") == lost_page.get("outcomes")),
          ("No dispatch history is available.", False, True, True, True, False))
    check("[#1106] EXECUTED page script: the zeroed Last-dispatch-sweep card says the history "
          "could not be read, instead of the quiet fleet's `No completed sweep data`",
          ("No completed sweep data" in quiet_page.get("capacityLines", ""),
           quiet_page.get("summaryDegraded"),
           "could not be read" in lost_page.get("capacityLines", ""),
           "No completed sweep data" in lost_page.get("capacityLines", ""),
           lost_page.get("summaryDegraded")),
          (True, False, True, False, True))
    # The marker is consulted ONLY where the absence of rows is the ambiguous signal: `measured`
    # carries a real sweep and no fetch outcome at all, and must still read as a normal page rather
    # than being relabelled unavailable by the fail-closed default.
    check("[#1106] a document that HAS sweeps is untouched by the marker (the notice is scoped to "
          "the empty case, not applied to every build that stated no fetch outcome)",
          (measured_document.get("dispatch_history"),
           "could not be read" in page["warnings"]["measured"]["capacityLines"],
           "could not be read" in page["warnings"]["measured"]["outcomes"],
           page["warnings"]["measured"]["outcomesDegraded"]),
          ({"outcome": "unknown", "detail": "", "fetched": False}, False, False, False))

    # --- [#374] the SAME executed page, on what the fleet section now shows. The measured document
    # is the one-anthropic-account fixture: pre-#374 this section rendered "1 account · 1 free ·
    # 0 capped", a "single account" badge, "0.9 of 1 account-windows free" and a
    # "1 / 1" capacity line — four independent counts of the fleet. Every row below is red on the
    # pre-#374 page and on any partial revert of the renderer.
    quota_text = page["warnings"]["measured"]["quota"]
    failed_quota_text = page["warnings"]["failed"]["quota"]
    check("[#374] the page renders a headroom word and a percentage, not an account census",
          ("capacity available" in quota_text,
           "anthropic" in quota_text,
           "% of this window's quota left" in quota_text,
           re.search(r"\d+\s+accounts?\b", quota_text) is not None,
           re.search(r"account-windows?\b", quota_text) is not None,
           "single account" in quota_text,
           "limit-units left" in quota_text),
          (True, True, True, False, False, False, False))
    check("[#374] an unmeasured probe still degrades the rendered headroom (fail-closed on the UI)",
          ("no usable measurement" in failed_quota_text,
           "capacity available" in failed_quota_text),
          (True, False))
    check("[#374] the summary capacity card states availability, never eligible/total",
          ("anthropic available" in " ".join(
              page["warnings"]["measured"]["capacityLines"].split()),
           "anthropic none free" in " ".join(
               page["warnings"]["failed"]["capacityLines"].split()),
           re.search(r"\d+\s*/\s*\d+",
                     page["warnings"]["measured"]["capacityLines"]) is not None),
          (True, True, False))

    # --- [#71] ...and the reset sentences those cards carry. Each direction asserts the OTHER
    # direction's wording is ABSENT, so the three ways this regresses are all red: deleting the
    # elapsed branch (the `elapsed` row loses "already refilled"), inverting the comparison (the
    # `future` row gains it), and making `hasElapsed` constant either way (one row or the other).
    # The wordings below are written out independently here — the page is never asked what it says.
    future_reset = page["resets"]["future"]
    elapsed_reset = page["resets"]["elapsed"]
    split_reset = page["resets"]["split"]
    check("[#71] EXECUTED page script: a reset still ahead of the render clock reads as a PENDING "
          "refill, in both the window row and the provider note",
          ("next reset" in future_reset, "last reset" in future_reset,
           "all known windows reset by" in future_reset,
           "was due" in future_reset, "already refilled" in future_reset,
           "have refilled" in future_reset),
          (True, True, True, False, False, False))
    check("[#71] EXECUTED page script: a reset the render clock has passed says the window ALREADY "
          "refilled and that the quota beside it predates the refill — never `next reset ... ago`",
          ("reset was due" in elapsed_reset,
           "already refilled, the quota above predates it" in elapsed_reset,
           "all refilled by" in elapsed_reset,
           "Soonest known reset was due" in elapsed_reset,
           "all known windows have refilled" in elapsed_reset,
           "next reset" in elapsed_reset, "last reset" in elapsed_reset,
           "all known windows reset by" in elapsed_reset),
          (True, True, True, True, True, False, False, False))
    check("[#71] EXECUTED page script: every stamp is judged on its own — one elapsed and one "
          "still-pending refill on the SAME card render as one of each, not as a card-wide verdict",
          ("reset was due" in split_reset, "already refilled" in split_reset,
           "last reset" in split_reset, "all known windows reset by" in split_reset,
           "next reset" in split_reset, "all refilled by" in split_reset,
           "have refilled" in split_reset),
          (True, True, True, True, False, False, False))
    # The fixtures above name the payload's reset keys by hand; this row is the same wording on the
    # document build_dashboard really publishes, so a renamed/dropped key cannot leave them green.
    check("[#71] the published document's own reset stamps reach the same sentence",
          ("next reset" in quota_text, "already refilled" in quota_text),
          (True, False))

    health = _normalize_model_health({
        "generated_at": now,
        "models": [{"model": "fable", "provider": "anthropic", "status": "ok"}],
    })
    check("optional model-health normalization, and [#1827] NULL IS NOT ZERO: a non-ledger shape "
          "carries no records to census, so the census is null — an all-zero distribution here "
          "would publish 'no worker has produced a no-change run' off an input that cannot say it",
          health,
          {"generated_at": "2025-06-15T15:06:40Z",
           "checks": [{"model": "fable", "provider": "anthropic",
                       "status": "healthy", "checked_at": None}],
           "no_change_reasons": None})

    # --- observability normalization (issue #246): accept path is a GOLDEN fixture (every field
    # class exercised, every malformed row visibly dropped), reject paths are explicit. ---------
    obs_fixture = {
        "schema": "registry-observability/v1",
        "generated_at": now,
        # [#1839] The three chain/drain keys stay in the FIXTURE on purpose, well-formed and in the
        # shape a collector built against the pre-#1839 contract emits: the golden row below is what
        # proves a retired field is ignored rather than republished.
        "cache": {"prompt_cache_read_fraction_1h": 0.62, "usage_samples_1h": 7,
                  "warm_drain_rate_1h": "0.5", "drained_1h": 12,
                  "chain_length_histogram": {"1": 4, "2": 3, "5+": 1, "bogus": 2, "3": -1}},
        "lanes": {"worker": {"1h": {"success": 3, "failure": 1, "defer": 2},
                             "24h": {"success": 30, "failure": 4, "defer": 9}},
                  "review-fix": {"1h": {"success": 1, "failure": 0, "defer": 0}},
                  "bad lane!": {"1h": {"success": 1}}},
        "defer_reasons_1h": [{"reason": "partial-disarm", "count": 7},
                             {"reason": "trust-gate-missing", "count": 9},
                             {"reason": "bad reason!", "count": 3},
                             {"reason": "plan-ordering", "count": "x"}],
        "model_exit_classes_1h": [{"model": "fable", "exit_class": "success", "count": 3},
                                  {"model": "terra", "exit_class": "no-changes", "count": 8},
                                  {"model": "bad model!", "exit_class": "x", "count": 1}],
        "flow": {"queue": [{"class": "2a", "depth": 1, "oldest_age_minutes": 12.34},
                           {"class": "4", "depth": 9, "oldest_age_minutes": 3},
                           {"class": "9z", "depth": 1}],
                 "leases": [{"label": "ab12cd340a5f9e71", "provider": "anthropic",
                             "utilization_1h": 0.8},
                            {"label": "ef56ab78b3c2d104", "provider": "anthropic",
                             "utilization_1h": 0.4},
                            {"label": "cd90ef1276a8b535", "provider": "openai"}],
                 "review_rounds": {"mean": 1.44444, "max": 3, "budget_exhausted_1h": 0},
                 "parks_1h": {"needs_user": 2, "needs_orchestrator": 1},
                 "arm_to_merge_minutes_24h": {"p50": 18, "p90": 55.5, "samples": 9},
                 "target_ci_queue": [{"repository": "sparq-org/sparq", "depth": 5},
                                     {"repository": "not-a-repo", "depth": 2}]},
        "trigger_fires": [
            {"rule": "worker-failure-rate", "fired_at": now - 300,
             "summary": "worker failure rate 67% over 3 consecutive runs",
             "evidence": ["https://github.com/jeswr/agent-account-registry/actions/runs/1",
                          "https://evil.example/exfil"],
             "enqueued_task": "heal-2a-0001"},
            {"rule": "bad rule!", "fired_at": now, "summary": "must be skipped"}],
        "thresholds": {"workflow_failure_rate": 0.5, "defer_reason_hourly": 4,
                       "queue_age_clamp_minutes": 10, "merge_stall_minutes": 90, "bogus": 1},
    }
    obs_expected = {
        "generated_at": "2025-06-15T15:06:40Z",
        # [#1839] TWO fields, not five: the retired chain/drain keys the fixture still sends do not
        # survive normalization at all, so nothing downstream of here can render them.
        "cache": {"prompt_cache_read_fraction_1h": 0.62, "usage_samples_1h": 7},
        "lanes": [
            {"lane": "review-fix", "1h": {"success": 1, "failure": 0, "defer": 0}, "24h": None},
            {"lane": "worker", "1h": {"success": 3, "failure": 1, "defer": 2},
             "24h": {"success": 30, "failure": 4, "defer": 9}}],
        # [#1868] Every `_total` below is the count of the rows that SURVIVED validation, never of
        # the rows the collector sent: each of these six seams is handed one malformed row in the
        # fixture above, so a total taken over the raw input reads one higher on every one of them.
        # Nothing here is truncated (each array is far under its cap), which is the other half —
        # the total is published on the quiet tick too, so the page can tell "12 of 12" from "12 of
        # 50" and a mutant cannot silence it by only emitting when it has something to say.
        "lanes_total": 2,
        "defer_reasons_1h": [{"reason": "trust-gate-missing", "count": 9},
                             {"reason": "partial-disarm", "count": 7}],
        "defer_reasons_1h_total": 2,
        "model_exit_classes_1h": [{"model": "terra", "exit_class": "no-changes", "count": 8},
                                  {"model": "fable", "exit_class": "success", "count": 3}],
        "model_exit_classes_1h_total": 2,
        "flow": {"queue": [{"class": "2a", "depth": 1, "oldest_age_minutes": 12.3},
                           {"class": "4", "depth": 9, "oldest_age_minutes": 3.0}],
                 "queue_total": 2,
                 # [#374] three validated lease rows in, ZERO published: only the mean/max of the
                 # utilizations that parsed (0.8, 0.4 -> 0.6/0.8). The unparseable third row proves
                 # the aggregate is taken over reporting rows, and the count itself never appears.
                 "lease_utilization_1h": {"mean": 0.6, "max": 0.8},
                 "review_rounds": {"mean": 1.44, "max": 3, "budget_exhausted_1h": 0},
                 "parks_1h": {"needs_user": 2, "needs_orchestrator": 1},
                 "arm_to_merge_minutes_24h": {"p50": 18.0, "p90": 55.5, "samples": 9},
                 "target_ci_queue": [{"repository": "sparq-org/sparq", "depth": 5}],
                 "target_ci_queue_total": 1},
        "trigger_fires": [
            {"rule": "worker-failure-rate", "fired_at": "2025-06-15T15:01:40Z",
             "summary": "worker failure rate 67% over 3 consecutive runs",
             "evidence": ["https://github.com/jeswr/agent-account-registry/actions/runs/1"],
             "enqueued_task": "heal-2a-0001"}],
        "trigger_fires_total": 1,
        "thresholds": {"workflow_failure_rate": 0.5, "defer_reason_hourly": 4,
                       "queue_age_clamp_minutes": 10, "merge_stall_minutes": 90},
    }

    class ObsRefusal(dict):
        """A FATAL `_normalize_observability` refusal rendered as a value instead of an exception.

        The rows below hand this seam whole documents and then subscript the result, so a refusal
        raised out of any one of them aborts every check after it — the crash-after-partial-run
        shape (AGENTS.md, AUTHOR pre-flight item 4), which records as a kill while the rest of the
        suite never ran. It measured as exactly that here: narrowing OBS_SALTED_LABEL_RE back to
        the pre-#375 8-hex width took the run from 214 checks to 181 with no named row. A dict, so
        subscript chains keep working (any missing key yields the refusal itself), carrying the
        message and equal to nothing any row expects — one named red row, suite intact.
        Rows that assert a refusal IS raised keep their own try/except and do not use this.
        """

        def __missing__(self, _key):
            return self

    def obs_normalized(document):
        try:
            return _normalize_observability(document)
        except DashboardError as error:
            return ObsRefusal(refused=str(error))
        except Exception as error:  # noqa: BLE001 — see below; never re-raised, always one red row
            # [#1880] ANY other exception out of this seam is itself the defect (a reader that
            # RAISES on a collector value is not a fail-closed reader), so it must red the row that
            # provoked it rather than abort every row below — the same crash-after-partial-run
            # shape ObsRefusal exists for. Rendered, not swallowed: no expectation equals this.
            return ObsRefusal(raised=f"{type(error).__name__}: {error}"[:200])

    check("observability golden normalization (bad rows dropped, top-N sorted, links pinned)",
          obs_normalized(obs_fixture), obs_expected)
    check("absent observability snapshot stays hidden (None)",
          _normalize_observability(None), None)
    # ---- [#1557] THE CACHE GROUP IS THE ONE OBSERVABILITY GROUP WITH NO PRODUCER ANYWHERE: the
    # file the docs named as its source (`data/cache-affinity.json`) has never been written by
    # anything in this repo, and affinity itself is derived from the lease ledger at claim time and
    # kept nowhere. Two of the group's five fields were coerced to 0 on the way out, so a collector
    # that shipped the KEY without the measurements rendered `Prompt-cache read —` beside a
    # confident `of 0 drained / 1h`: an unmeasured group wearing a measured zero. Publication now
    # requires at least one field to have PARSED — parsed, NOT truthy, so a genuinely quiet hour
    # still emits its zero row — and the drop is ANNOUNCED, because `cache: {}` and "no collector
    # at all" are the same hidden panel otherwise (#982's lesson, same seam).
    # ---- [#1839] AND THE GROUP IS NOW TWO FIELDS, NOT FIVE. `warm_drain_rate_1h`, `drained_1h` and
    # `chain_length_histogram` are RETIRED: they measure affinity-CHAIN history, and there is no
    # source for one anywhere in the repo — not a producer that has not landed, an impossible one,
    # because affinity is re-derived per claim and a released lease keeps nothing. #1557 left the
    # contract open pending this decision; the rows below are the decision, and they are written so
    # that BOTH directions red. A retired field is no longer measurement (it cannot publish a card
    # on its own any more, which it could before), it is never republished, and it is NAMED rather
    # than silently swallowed, so a collector on the stale contract learns of the mismatch.
    # Every input below is a JSON literal and both messages are literals too: reading either back
    # off the module under test is the tautology AGENTS.md pre-flight 2(b) names.
    _CACHE_DROP = ("dashboard-gen: dropped the observability cache group (type {}) — "
                   "no field it publishes was measured")
    _CACHE_RETIRED = ("dashboard-gen: ignored retired observability cache field(s) {} — "
                      "affinity-chain history has no producer (issue #1839)")
    _ALL_RETIRED = {"warm_drain_rate_1h": 0.5, "drained_1h": 12,
                    "chain_length_histogram": {"2": 6}}
    _ALL_RETIRED_NAMED = _CACHE_RETIRED.format(
        "chain_length_histogram, drained_1h, warm_drain_rate_1h")

    def obs_cache(source, present=True):
        """(published `cache` group, the cache-drop warnings, the retired-field warnings)."""
        fixture = copy.deepcopy(obs_fixture)
        if present:
            fixture["cache"] = source
        else:
            del fixture["cache"]
        stream = io.StringIO()
        try:                       # same crash-after-partial-run guard as ObsRefusal above
            with contextlib.redirect_stdout(stream):
                document = _normalize_observability(fixture)
        except DashboardError as error:
            document = ObsRefusal(refused=str(error))
        printed = stream.getvalue().splitlines()
        return (document["cache"],
                [line for line in printed
                 if line.startswith("dashboard-gen: dropped the observability cache group")],
                [line for line in printed
                 if line.startswith("dashboard-gen: ignored retired observability cache field")])

    check("[#1557] a MEASURED all-zero hour still PUBLISHES: 0.0 and 0 are readings, not absences. "
          "Guarding on truthiness instead of on `is not None` hides exactly the quiet hour an "
          "operator interrogates (AGENTS.md pre-flight item 8)",
          obs_cache({"prompt_cache_read_fraction_1h": 0.0, "usage_samples_1h": 0}),
          ({"prompt_cache_read_fraction_1h": 0.0, "usage_samples_1h": 0}, [], []))
    # Each row below is the ONLY row that reds if its own disjunct is dropped from the publication
    # guard, so neither SURVIVING field can quietly stop counting as a measurement.
    for case, source, published in (
        ("a lone usage-sample count", {"usage_samples_1h": 3},
         {"prompt_cache_read_fraction_1h": None, "usage_samples_1h": 3}),
        ("a lone prompt-cache read fraction", {"prompt_cache_read_fraction_1h": 0.25},
         {"prompt_cache_read_fraction_1h": 0.25, "usage_samples_1h": 0}),
    ):
        check(f"[#1557] {case} is measurement enough to publish the group, SILENTLY (both warnings "
              "mark a real defect, so neither can fire on the accept path)",
              obs_cache(source), (published, [], []))
    # The RETIRED side of the same guard, one row per field: before #1839 each of these three
    # published a whole card on its own. Re-adding any one of them as a disjunct reds exactly its
    # own row, so the retirement cannot be half-reverted unnoticed.
    for field, value in (("warm_drain_rate_1h", 0.5), ("drained_1h", 4),
                         ("chain_length_histogram", {"2": 6})):
        check(f"[#1839] a lone `{field}` — a RETIRED field, WELL-FORMED — is not a measurement any "
              "more: nothing publishes, the retirement is named, and the drop is named",
              obs_cache({field: value}),
              (None, [_CACHE_DROP.format("dict")], [_CACHE_RETIRED.format(field)]))
    check("[#1839] all three retired fields together — the exact shape a collector built against "
          "the pre-#1839 contract emits — still publish NOTHING, and are named in one line",
          obs_cache(copy.deepcopy(_ALL_RETIRED)),
          (None, [_CACHE_DROP.format("dict")], [_ALL_RETIRED_NAMED]))
    check("[#1839] retired fields alongside a REAL measurement neither reach the published group "
          "nor vanish quietly: the two usage-derived fields publish alone, the retirement is named, "
          "and no drop is claimed. A normalizer that keeps copying them through reds here",
          obs_cache({"prompt_cache_read_fraction_1h": 0.4, "usage_samples_1h": 2,
                     **copy.deepcopy(_ALL_RETIRED)}),
          ({"prompt_cache_read_fraction_1h": 0.4, "usage_samples_1h": 2}, [],
           [_ALL_RETIRED_NAMED]))
    check("[#1839] the notice keys on the retired KEY's PRESENCE, not on whether its value would "
          "have parsed: a stale contract is a stale contract, and reading the value to decide would "
          "leave the noisiest producers unnamed",
          obs_cache({"prompt_cache_read_fraction_1h": 0.4, "drained_1h": "not a count"}),
          ({"prompt_cache_read_fraction_1h": 0.4, "usage_samples_1h": 0}, [],
           [_CACHE_RETIRED.format("drained_1h")]))
    # None of these four carries a retired key, so the third slot is the empty list in every one:
    # the retirement notice marks a producer on the OLD contract, and neither an unreadable group
    # nor a group of the wrong TYPE is that.
    for case, source, container in (
        ("an EMPTY cache group", {}, "dict"),
        ("a group in which every surviving field is unreadable",
         {"prompt_cache_read_fraction_1h": "abc", "usage_samples_1h": -2}, "dict"),
        ("a cache group sent as a list", ["prompt_cache_read_fraction_1h", 0.62], "list"),
        ("a cache group sent as a JSON string", "0.62", "str"),
    ):
        check(f"[#1557] {case} publishes NOTHING and names itself once — never a fabricated "
              "measured zero on a panel no producer has ever filled",
              obs_cache(source), (None, [_CACHE_DROP.format(container)], []))
    # ...and the whole snapshot still normalizes around the hole: this is a drop diagnostic, not a
    # new fatality. Turning the drop into a raise turns this row red.
    with contextlib.redirect_stdout(io.StringIO()):
        cache_dropped = obs_normalized({**copy.deepcopy(obs_fixture), "cache": {}})
    check("[#1557] a snapshot whose cache group is dropped is still TOLERATED — every other panel "
          "is published unchanged and the build stays green",
          (cache_dropped["cache"], cache_dropped["thresholds"]["merge_stall_minutes"],
           [row["lane"] for row in cache_dropped["lanes"]]),
          (None, 90, ["review-fix", "worker"]))
    # ...and the PAGE is what the drop has to DELIVER INTO (AGENTS.md pre-flight item 11): a group
    # normalized to None must leave the panel with no cache CARD at all — not a card whose numbers
    # merely read `—` beside the `of 0 drained / 1h` sub-label #1557 is about. Executed against
    # dashboard/app.js under the shared DOM shim, never asserted lexically (the #612 round-4 lesson).
    # [#1839] The page is also the LAST hop, and the retirement has a second, independent half here:
    # dropping the retired READS from `obsCacheCard` is invisible to any document this generator
    # produces (it no longer emits those keys), which is exactly the equivalent-survivor shape
    # AGENTS.md pre-flight item 4 names. So a third document is rendered: `legacy`, hand-written in
    # the pre-#1839 published shape — the `site/data.json` a browser holds from before this build, or
    # any stale copy of it. It must render the read fraction and NOTHING chain/drain-shaped.
    # The card's own metric cells and sparkline captions are enumerated (not substring-searched), so
    # a retired metric or trend reappearing anywhere inside the card reds the row.
    _OBS_CACHE_PAGE_BODY = r"""
  const out = {};
  for (const [name, document] of Object.entries(input.documents)) {
    for (const id of ["obs-section", "obs-grid", "obs-time", "obs-triggers"]) {
      ids[id] = element(id);
    }
    let error = null;
    try {
      scope.renderObservability(document);
    } catch (raised) {
      error = String((raised && raised.message) || raised);
    }
    const cards = ids["obs-grid"].children.filter((card) => card.tagName === "article");
    const cache = cards.find((card) => card.children[0]
      && card.children[0].textContent === "Cache effectiveness");
    const owned = (className) => (cache ? cache.children : [])
      .filter((kid) => kid.className === className);
    out[name] = {
      error,
      cards: cards.map((card) => card.children[0].textContent),
      metrics: owned("obs-metric-grid").flatMap((grid) =>
        grid.children.map((cell) => text(cell).trim().replace(/\s+/g, " "))),
      sparks: owned("obs-spark-wrap").map((wrap) => wrap.children[0].textContent),
      drained: text(ids["obs-grid"]).includes("drained / 1h"),
      chains: text(ids["obs-grid"]).includes("cache-chain lengths"),
    };
  }
  process.stdout.write(JSON.stringify(out));
"""
    with contextlib.redirect_stdout(io.StringIO()):
        obs_measured = obs_normalized(copy.deepcopy(obs_fixture))
        obs_unmeasured = obs_normalized({**copy.deepcopy(obs_fixture), "cache": {}})
    # The same `generated_at` as the normalized pair on purpose: `obsRecordTrend` keys on it, so all
    # three renders share ONE accumulated trend point and every sparkline reports the same
    # "collecting trend…" state — the document under test cannot perturb the others' captions.
    obs_legacy = {"generated_at": obs_measured["generated_at"],
                  "cache": {"prompt_cache_read_fraction_1h": 0.62, "usage_samples_1h": 7,
                            "warm_drain_rate_1h": 0.5, "drained_1h": 12,
                            "chain_length_histogram": {"1": 4, "2": 3, "5+": 1}}}
    try:
        obs_page = _node_json(_page_harness("renderObservability", _OBS_CACHE_PAGE_BODY),
                              {"documents": {"measured": obs_measured,
                                             "unmeasured": obs_unmeasured,
                                             "legacy": obs_legacy}})
    except DashboardError as exc:
        # A page that throws while rendering IS the finding; reporting it as the row's value keeps
        # the row named and red instead of aborting the suite mid-run.
        obs_page = {"page script raised": str(exc)[:160]}

    def obs_rendered(name):
        rendered = obs_page.get(name)
        return ((rendered.get("cards"), rendered.get("drained"), rendered.get("error"))
                if isinstance(rendered, dict) else obs_page)

    def obs_cache_card(name):
        rendered = obs_page.get(name)
        return ((rendered.get("metrics"), rendered.get("sparks"), rendered.get("chains"),
                 rendered.get("drained"), rendered.get("error"))
                if isinstance(rendered, dict) else obs_page)

    check("[#1557] the measured group still renders its card, and the DROPPED one leaves the panel "
          "with no Cache-effectiveness card at all — not a card whose numbers merely read `—`. The "
          "`drained / 1h` flag is now False on BOTH sides, because #1839 removed that sub-label from "
          "the page outright; the CARD LIST is what separates the two",
          (obs_rendered("measured"), obs_rendered("unmeasured")),
          ((["Cache effectiveness", "Agent-run health", "Queue & flow"], False, None),
           (["Agent-run health", "Queue & flow"], False, None)))
    check("[#1839] the surviving card is USAGE-DERIVED ONLY: exactly one metric (the read fraction "
          "over its sample count) and one trend. The `Warm drains` metric and the `warm-drain trend` "
          "sparkline are gone from the page, and the expected strings are literals written here "
          "rather than read back off the card (pre-flight 2(b))",
          obs_cache_card("measured"),
          (["Prompt-cache read 62% 7 usage samples / 1h"], ["read fraction trend"],
           False, False, None))
    check("[#1839] and a LEGACY data.json — one published before the retirement, still carrying all "
          "three chain/drain fields with credible values — renders the SAME one metric and one "
          "trend: the page itself stops reading them, so a stale snapshot cannot resurrect the card "
          "this retires. Compared against the literals, not against the row above, so this cannot "
          "pass by agreeing with an equally-wrong render",
          obs_cache_card("legacy"),
          (["Prompt-cache read 62% 7 usage samples / 1h"], ["read fraction trend"],
           False, False, None))
    # The two ABSENCES are silent: a collector that has no cache group yet is the expected state
    # (there is no producer), and only a SUPPLIED-but-unreadable group is the mismatch worth naming.
    for case, args in (("no cache key at all", (None, False)),
                       ("an explicit null cache key", (None,))):
        check(f"[#1557] {case} hides the panel SILENTLY — the warnings name a producer/consumer "
              "mismatch, and 'the collector has not landed' is not one",
              obs_cache(*args), (None, [], []))
    # ---- [#1838] THE EMPTY STATE IS A BRANCH, AND BOTH OF ITS SIDES HAVE TO BE ASSERTABLE.
    # `renderObservability` decides it with `if (!grid.childElementCount)`, so before the shim
    # carried that property (#1880) the read was `undefined` on every element and the
    # "no renderable groups yet" line was appended to EVERY render — including the three-card one
    # asserted above, which is why THAT row has to filter `obs-grid` to `article`. A filter is a
    # workaround, not a check: with it in place an assertion that the panel DOES show its empty
    # state, or that it does NOT, passes whatever the page does. That is the #1107 finding ("a shim
    # that silently swallows what the page does to it makes an EXECUTED assertion quietly weaker
    # than it reads") in a shape #1107 did not cover. The two rows below therefore read `obs-grid`
    # UNFILTERED and exhaustively, so neither side of the branch can hide behind a card filter, and
    # the expected text is a literal written here rather than read back off the page (pre-flight
    # 2(b)). Both documents are real `_normalize_observability` output: the hollow one is what a
    # deployed collector publishes before any group it feeds has a producer.
    _OBS_EMPTY_STATE_PAGE_BODY = r"""
  const out = {};
  for (const [name, document] of Object.entries(input.documents)) {
    for (const id of ["obs-section", "obs-grid", "obs-time", "obs-triggers"]) {
      ids[id] = element(id);
    }
    let error = null;
    try {
      scope.renderObservability(document);
    } catch (raised) {
      error = String((raised && raised.message) || raised);
    }
    out[name] = {
      error,
      hidden: ids["obs-section"].hidden === true,
      // EVERY child of the grid, in render order, as [tag.class, its heading or its own text] —
      // no `article` filter, so a stray empty-state `<p>` beside real cards is visible here.
      children: ids["obs-grid"].children.map((kid) => [
        `${kid.tagName}.${kid.className}`,
        kid.children[0] ? kid.children[0].textContent : kid.textContent,
      ]),
    };
  }
  process.stdout.write(JSON.stringify(out));
"""
    with contextlib.redirect_stdout(io.StringIO()):
        obs_hollow = obs_normalized({"schema": OBS_SCHEMA, "generated_at": now})
    empty_state_page = _executed_page(
        _page_harness("renderObservability", _OBS_EMPTY_STATE_PAGE_BODY),
        {"documents": {"groups": copy.deepcopy(obs_measured), "hollow": obs_hollow}})

    def obs_grid_children(name):
        rendered = empty_state_page[name]
        return (rendered.get("children"), rendered.get("hidden"), rendered.get("error"))

    check("[#1838] EXECUTED page script: a snapshot WITH renderable groups renders its three cards "
          "and NOTHING else — the `Observability snapshot has no renderable groups yet.` line is "
          "absent from a grid that is not empty, which is what a shim without `childElementCount` "
          "could not say (the property read `undefined`, so the empty branch fired on EVERY "
          "render)",
          obs_grid_children("groups"),
          ([["article.obs-card", "Cache effectiveness"],
            ["article.obs-card", "Agent-run health"],
            ["article.obs-card", "Queue & flow"]], False, None))
    check("[#1838] ...and the other side of the same branch still fires: a snapshot the collector "
          "published with no renderable group at all leaves the panel VISIBLE and carrying the "
          "empty-state line alone — never a silently blank grid",
          obs_grid_children("hollow"),
          ([["p.empty subtle",
             "Observability snapshot has no renderable groups yet."]], False, None))
    # ---- [#1879] AN UNMEASURED LANE WINDOW MUST NOT RENDER AS A HEALTHY ZERO. `_obs_lane_rows`
    # publishes `None` for a 1h/24h window it could not read — the same shape a window the collector
    # never sent publishes — but `obsHealthCard()` read it as `obsNum(hour.success, 0)`, so BOTH
    # collapsed to `0 / 0 / 0` with a `—` fail rate: pixel-identical to a genuinely idle lane. The
    # generator-side drop announcement is real evidence and nobody reads a green build's log, so the
    # fix has to land on the layer an operator actually looks at (AGENTS.md pre-flight item 11).
    # `obsRecordTrend()` had the same shape one function over, folding an unreadable window into the
    # defer sparkline as a zero. Both are EXECUTED below against dashboard/app.js under the shared
    # DOM shim — a lexical assertion here is satisfiable by a comment (the #612 round-4 lesson).
    _OBS_LANE_WINDOW_PAGE_BODY = r"""
  const out = {};
  for (const [name, documents] of Object.entries(input.scenarios)) {
    // A FRESH page per scenario: obsTrend is module state that accumulates across renders, so one
    // shared scope would carry one scenario's sparkline points into the next.
    const page = new Function(source + "; return { renderObservability };")();
    await new Promise((resolve) => setImmediate(resolve));
    for (const id of ["obs-section", "obs-grid", "obs-time", "obs-triggers", "warning"]) {
      ids[id] = element(id);
    }
    let error = null;
    try {
      for (const document of documents) page.renderObservability(document);
    } catch (raised) {
      error = String((raised && raised.message) || raised);
    }
    const card = ids["obs-grid"].children.find((kid) =>
      kid.tagName === "article" && kid.children[0]
      && kid.children[0].textContent === "Agent-run health");
    const table = card ? card.children.find((kid) => kid.tagName === "table") : null;
    const spark = card ? card.children.find((kid) =>
      kid.className === "obs-spark-wrap" && flat(kid).join(" ").includes("defers / 1h trend")) : null;
    out[name] = {
      error,
      // The header row is children[0]; every row below it is one lane, cell text beside cell class.
      rows: table ? table.children.slice(1).map((row) =>
        row.children.map((cell) => [flat(cell).join("").trim(), cell.className])) : null,
      defersPlotted: spark ? spark.children.some((kid) => kid.tagName === "svg") : null,
    };
  }
  process.stdout.write(JSON.stringify(out));
"""

    def obs_lane_scenario(lanes, inject=None):
        """Two published snapshots one minute apart carrying `lanes` — two ticks, because the defer
        sparkline needs two recorded points before it plots anything at all. `inject` post-edits the
        PUBLISHED document, for window shapes this generator cannot emit but the page must survive;
        it is skipped on a refusal so a broken fixture reds a named row instead of aborting."""
        documents = []
        for offset in (0, 60):
            fixture = copy.deepcopy(obs_fixture)
            fixture["generated_at"] = now + offset
            fixture["lanes"] = copy.deepcopy(lanes)
            with contextlib.redirect_stdout(io.StringIO()):
                document = obs_normalized(fixture)
            if inject is not None and isinstance(document.get("lanes"), list):
                inject(document)
            documents.append(document)
        return documents

    _ZERO_WINDOW = {"success": 0, "failure": 0, "defer": 0}
    # `unread` carries the SAME zeroed 24h window as `idle`, and `idle`'s own 1h window is a real
    # measurement of zero runs: the ONLY thing differing between those two rendered rows is whether
    # the 1h window was readable. Asserting them together is what makes this non-vacuous — a page
    # that dashes everything, or one that zeroes everything, fails on the other row.
    _QUIET_LANES = {"idle": {"1h": dict(_ZERO_WINDOW), "24h": dict(_ZERO_WINDOW)}}
    obs_window_page = _executed_page(
        _page_harness("renderObservability", _OBS_LANE_WINDOW_PAGE_BODY),
        {"scenarios": {
            "measured": obs_lane_scenario(obs_fixture["lanes"]),
            "quiet": obs_lane_scenario(_QUIET_LANES),
            "unread": obs_lane_scenario({
                **copy.deepcopy(_QUIET_LANES),
                "hot": {"1h": {"success": 0, "failure": 3, "defer": 1},
                        "24h": dict(_ZERO_WINDOW)},
                # A string where the collector should have sent an object: `_obs_lane_rows` drops
                # it to None, which is exactly what an unsent window publishes.
                "unread": {"1h": "3 ok / 1 failed", "24h": dict(_ZERO_WINDOW)}}),
            # data.json is a public document and its windows are only ever an object or null from
            # THIS generator; a hand-edited or future producer's array/number window must still not
            # read as a measured zero, so the page's own window guard is exercised directly.
            "hostile": obs_lane_scenario(_QUIET_LANES, inject=lambda document: document["lanes"]
                                         .append({"lane": "alien", "1h": [], "24h": 0}))}})

    def obs_window(name, field):
        rendered = obs_window_page.get(name)
        return rendered.get(field) if isinstance(rendered, dict) else obs_window_page

    check("[#1879] EXECUTED page script: a lane whose 1h window the generator could NOT read renders "
          "an explicitly unmeasured cell, while a lane that genuinely ran nothing still renders its "
          "zeroes — the two rows are no longer identical",
          obs_window("unread", "rows"),
          [[["hot", "obs-lane"], ["0 / 3 / 1", ""], ["100%", "bad"], ["0 / 0 / 0", ""]],
           [["idle", "obs-lane"], ["0 / 0 / 0", ""], ["—", ""], ["0 / 0 / 0", ""]],
           [["unread", "obs-lane"], ["—", "obs-unmeasured"], ["—", ""], ["0 / 0 / 0", ""]]])
    # ...and the measured lanes are untouched by the fix, including the 24h column that already
    # dashed an absent window (`review-fix` sends no 24h at all) — a regression there would swap the
    # bug from "unmeasured reads as zero" to "measured reads as unmeasured".
    check("[#1879] EXECUTED page script: the golden lanes still render every count, both fail-rate "
          "tones and the 24h column, with only the window the collector never sent dashed",
          obs_window("measured", "rows"),
          [[["review-fix", "obs-lane"], ["1 / 0 / 0", ""], ["0%", "good"], ["—", "obs-unmeasured"]],
           [["worker", "obs-lane"], ["3 / 1 / 2", ""], ["25%", "good"], ["30 / 4 / 9", ""]]])
    # The defer sparkline, both directions. `quiet` is the control the non-vacuity rests on: its
    # fleet-wide defer total is a MEASURED zero and it must still plot, so "plots nothing" cannot be
    # satisfied by a helper that simply treats every zero as unknown. Pre-fix, `unread` summed its
    # missing window as 0 and plotted a reassuring line.
    check("[#1879] EXECUTED page script: an unreadable 1h window makes the fleet defer total "
          "UNKNOWN and the sparkline plots nothing, while a fleet that genuinely deferred ZERO "
          "times still plots its flat line",
          (obs_window("quiet", "defersPlotted"), obs_window("measured", "defersPlotted"),
           obs_window("unread", "defersPlotted"), obs_window("hostile", "defersPlotted")),
          (True, True, False, False))
    check("[#1879] EXECUTED page script: a window of the wrong TYPE altogether is unmeasured too — "
          "an array is `typeof 'object'`, so a bare truthiness test would read `[]` as a lane that "
          "successfully ran nothing",
          obs_window("hostile", "rows"),
          [[["idle", "obs-lane"], ["0 / 0 / 0", ""], ["—", ""], ["0 / 0 / 0", ""]],
           [["alien", "obs-lane"], ["—", "obs-unmeasured"], ["—", ""], ["—", "obs-unmeasured"]]])
    check("[#1879] ...and no scenario raised while rendering — a page that throws is the finding, "
          "never a silently absent health table",
          {name: rendered.get("error") if isinstance(rendered, dict) else rendered
           for name, rendered in (obs_window_page.items()
                                  if isinstance(obs_window_page, dict) else ())},
          {"measured": None, "quiet": None, "unread": None, "hostile": None})
    # ---- [#1868] A DISPLAY CAP MUST SAY WHAT IT HID. Every array this panel publishes is a top-N
    # slice, and the rows past the cap are WELL-FORMED ones — nothing announces them, by design
    # (#982/#1570/#1571 all decided a truncation of rows the seam READ is not a producer/consumer
    # mismatch and must not warn on every healthy 13-lane fleet). So a fleet with 50 congested
    # target repositories and one with 12 rendered IDENTICALLY: #1571's "indistinguishable from
    # nothing happened", one layer up. The fix is a PAGE affordance fed by a published count, and
    # the rows below pin it at both layers and in both directions.
    #
    # Every size here is a LITERAL — 20 lanes, 19 reasons, 18 exit classes, 26 queue classes, 15
    # target repositories, 23 fires — and so is every expected pair. Deriving an over-cap input, or
    # an expectation, from the cap the code reads is the #941 tautology (pre-flight 2(b)/2(c)):
    # re-tuning any cap would then move the input and the expectation together and stay green.
    # Each seam is also handed exactly ONE malformed row, so a total taken over the RAW input reads
    # one higher on all six.
    over_cap_fixture = copy.deepcopy(obs_fixture)
    over_cap_fixture["lanes"] = {
        **{f"lane-{index:02d}": {"1h": {"success": 1, "failure": 0, "defer": 0}}
           for index in range(20)},
        "bad lane!": {"1h": {"success": 1}}}
    over_cap_fixture["defer_reasons_1h"] = (
        [{"reason": f"reason-{index:02d}", "count": 40 - index} for index in range(19)]
        + [{"reason": "bad reason!", "count": 3}])
    over_cap_fixture["model_exit_classes_1h"] = (
        [{"model": f"model-{index:02d}", "exit_class": "success", "count": 30 - index}
         for index in range(18)]
        + [{"model": "bad model!", "exit_class": "x", "count": 1}])
    over_cap_fixture["flow"]["queue"] = (
        [{"class": f"2{chr(ord('a') + index)}", "depth": index + 1} for index in range(26)]
        + [{"class": "9z", "depth": 1}])
    over_cap_fixture["flow"]["target_ci_queue"] = (
        [{"repository": f"owner/repo-{index:02d}", "depth": index} for index in range(15)]
        + [{"repository": "not-a-repo", "depth": 2}])
    over_cap_fixture["trigger_fires"] = (
        [{"rule": f"rule-{index:02d}", "fired_at": now - index, "summary": "over the cap"}
         for index in range(23)]
        + [{"rule": "bad rule!", "fired_at": now, "summary": "must be skipped"}])
    with contextlib.redirect_stdout(io.StringIO()):
        over_cap = obs_normalized(copy.deepcopy(over_cap_fixture))

    def obs_capped_pairs(document):
        """{seam: (rows PUBLISHED, the total published beside them)} for all six capped seams."""
        flow = document["flow"]
        return {"lanes": (len(document["lanes"]), document["lanes_total"]),
                "defer reasons": (len(document["defer_reasons_1h"]),
                                  document["defer_reasons_1h_total"]),
                "model exit classes": (len(document["model_exit_classes_1h"]),
                                       document["model_exit_classes_1h_total"]),
                "queue classes": (len(flow["queue"]), flow["queue_total"]),
                "target repositories": (len(flow["target_ci_queue"]),
                                        flow["target_ci_queue_total"]),
                "trigger fires": (len(document["trigger_fires"]), document["trigger_fires_total"])}

    check("[#1868] every capped seam publishes the PRE-CAP total of its WELL-FORMED rows beside "
          "the slice it published. Dropping a cap reds the left number; deriving a total from the "
          "published slice reds the right one; counting the raw input instead of the rows that "
          "survived validation reds it by exactly the one malformed row each seam was handed",
          obs_capped_pairs(over_cap),
          {"lanes": (12, 20), "defer reasons": (16, 19), "model exit classes": (16, 18),
           "queue classes": (12, 26), "target repositories": (12, 15), "trigger fires": (20, 23)})
    # The other direction, and the one a conditional emission would pass: an UNTRUNCATED fleet
    # publishes its totals too, equal to what it published. Emitting a total only when the cap bit
    # is the "census that never zero-seals" shape (pre-flight item 8) — the page could then no
    # longer tell "12 of 12" from a producer that stopped sending the count at all.
    with contextlib.redirect_stdout(io.StringIO()):
        under_cap = obs_normalized(copy.deepcopy(obs_fixture))
    check("[#1868] ...and a fleet comfortably UNDER every cap publishes each total anyway, equal "
          "to the rows it published — the golden fixture's one malformed row per seam is already "
          "excluded from all six",
          obs_capped_pairs(under_cap),
          {"lanes": (2, 2), "defer reasons": (2, 2), "model exit classes": (2, 2),
           "queue classes": (2, 2), "target repositories": (1, 1), "trigger fires": (1, 1)})
    # ...and THE PAGE IS WHAT THIS HAS TO DELIVER INTO (pre-flight item 11): a count published into
    # site/data.json that no panel renders leaves the operator exactly where #1868 found them. So
    # the affordance is EXECUTED against dashboard/app.js under the shared DOM shim — a lexical
    # assertion here is satisfiable by a comment (the #612 round-4 lesson) — and the notes are
    # collected by EXACT className, never by searching the card's text for "showing".
    _OBS_TRUNCATION_PAGE_BODY = r"""
  const byClass = (root, wanted) => {
    const found = [];
    const walk = (el) => {
      if (!el) return;
      if (el.className === wanted) found.push(flat(el).join(" ").trim());
      for (const kid of el.children || []) walk(kid);
    };
    walk(root);
    return found;
  };
  const truncations = (root) => byClass(root, "obs-truncated");
  const out = {};
  for (const [name, document] of Object.entries(input.documents)) {
    for (const id of ["obs-section", "obs-grid", "obs-time", "obs-triggers"]) {
      ids[id] = element(id);
    }
    let error = null;
    try {
      scope.renderObservability(document);
    } catch (raised) {
      error = String((raised && raised.message) || raised);
    }
    const card = (title) => ids["obs-grid"].children.find((kid) =>
      kid.tagName === "article" && kid.children[0]
      && kid.children[0].textContent === title);
    out[name] = {
      error,
      health: truncations(card("Agent-run health")),
      flow: truncations(card("Queue & flow")),
      triggers: truncations(ids["obs-triggers"]),
      // The health card's OWN rows, so a card that renders a note while dropping the content it
      // sits beside cannot read as a pass — the notes above are identical either way.
      reasons: byClass(card("Agent-run health"), "obs-reason-row"),
      chips: byClass(card("Agent-run health"), "obs-chip"),
    };
  }
  process.stdout.write(JSON.stringify(out));
"""
    # `legacy` is the pre-#1868 published shape of the SAME truncated fleet — a data.json a browser
    # still holds, or one hand-edited — and `hostile` carries every unusable total a future or
    # tampered producer can put in a JSON document: a string, a negative, a null, a boolean, one
    # EQUAL to the slice beside it and one SMALLER than it. None of them may draw a note: an
    # unknown total is not a truncation, and `showing 12 of undefined` would be a worse lie than
    # the silence #1868 replaces. (NaN/Infinity are absent on purpose — `_write_site` dumps with
    # `allow_nan=False`, so neither can reach a browser through this page's own data.json.)
    legacy_page_doc = {key: value for key, value in copy.deepcopy(over_cap).items()
                       if not key.endswith("_total")}
    legacy_page_doc["flow"] = {key: value for key, value in legacy_page_doc["flow"].items()
                               if not key.endswith("_total")}
    hostile_page_doc = copy.deepcopy(over_cap)
    hostile_page_doc["lanes_total"] = "20"
    hostile_page_doc["defer_reasons_1h_total"] = -19
    hostile_page_doc["model_exit_classes_1h_total"] = None
    hostile_page_doc["trigger_fires_total"] = True
    hostile_page_doc["flow"]["queue_total"] = 12
    hostile_page_doc["flow"]["target_ci_queue_total"] = 11
    # `fractional` is the hostile case the six seams above have no room left to carry, and it is a
    # DIFFERENT shape from all of them: a finite number, larger than the slice, that is not a count.
    # Every one of these fields counts ROWS, so `12.5` is malformed whichever way it arrived —
    # rendering `showing 12 of 12.5 lanes` with a `0.5 more` title would be the fabricated total
    # the row above exists to forbid, dressed as a readable one. All six seams carry it, so the
    # check reds for a call site that reaches the note through anything looser than an integer test.
    fractional_page_doc = copy.deepcopy(over_cap)
    fractional_page_doc["lanes_total"] = 12.5
    fractional_page_doc["defer_reasons_1h_total"] = 19.5
    fractional_page_doc["model_exit_classes_1h_total"] = 18.5
    fractional_page_doc["trigger_fires_total"] = 23.5
    fractional_page_doc["flow"]["queue_total"] = 26.5
    fractional_page_doc["flow"]["target_ci_queue_total"] = 15.5
    # ...and the zero-row case obsHealthCard documents: `shown === 0 && total > 0` cannot come out
    # of this generator, but it is exactly what a hand-edited data.json looks like, and gating the
    # whole card on `lanes.length` made the promised `showing 0 of 50 lanes` unreachable — the same
    # slice-is-empty silence #1868 was filed about. The defer/exit rows stay populated so the row
    # below can also witness that widening the gate did not cost the card its sibling content.
    zero_lane_page_doc = copy.deepcopy(over_cap)
    zero_lane_page_doc["lanes"] = []
    zero_lane_page_doc["lanes_total"] = 50
    truncation_page = _executed_page(
        _page_harness("renderObservability", _OBS_TRUNCATION_PAGE_BODY),
        {"documents": {"truncated": copy.deepcopy(over_cap),
                       "healthy": copy.deepcopy(under_cap),
                       "legacy": legacy_page_doc,
                       "hostile": hostile_page_doc,
                       "fractional": fractional_page_doc,
                       "zero-lane": zero_lane_page_doc}})

    def obs_truncation_notes(name):
        rendered = truncation_page.get(name)
        return ((rendered.get("health"), rendered.get("flow"), rendered.get("triggers"),
                 rendered.get("error")) if isinstance(rendered, dict) else truncation_page)

    check("[#1868] EXECUTED page script: the truncated fleet states every cap it hit, beside the "
          "rows it accounts for — six notes, each naming the REAL total. Expected strings are "
          "literals written here rather than read back off the page (pre-flight 2(b))",
          obs_truncation_notes("truncated"),
          (["showing 12 of 20 lanes", "showing 16 of 19 defer reasons",
            "showing 16 of 18 model exit classes"],
           ["showing 12 of 26 queue classes", "showing 12 of 15 target repositories"],
           ["showing 20 of 23 trigger fires"], None))
    check("[#1868] EXECUTED page script: ...and a fleet under every cap draws NO note anywhere — "
          "the affordance is `total > shown`, not a badge on every panel. This is the control the "
          "row above rests on: a page that always renders the note would pass it and fail here",
          obs_truncation_notes("healthy"), ([], [], [], None))
    check("[#1868] EXECUTED page script: a LEGACY data.json — the same truncated fleet published "
          "before the totals existed — renders no note rather than `showing 12 of undefined`, and "
          "the page does not throw reaching for a key that is not there",
          obs_truncation_notes("legacy"), ([], [], [], None))
    check("[#1868] EXECUTED page script: an unusable total draws nothing either — a string, a "
          "negative, a null, a boolean, a total EQUAL to the slice and one SMALLER than it are "
          "each 'no truncation known', never a fabricated one",
          obs_truncation_notes("hostile"), ([], [], [], None))
    check("[#1868] EXECUTED page script: ...and a FRACTIONAL total is unusable too — `12.5` beside "
          "12 rows is not a row count, and the page states nothing rather than `showing 12 of "
          "12.5 lanes`. All six seams carry one, so no call site can reach the note through a "
          "finite-number test",
          obs_truncation_notes("fractional"), ([], [], [], None))
    check("[#1868] EXECUTED page script: a hand-edited document whose lane slice is EMPTY beside a "
          "positive total still states it — `showing 0 of 50 lanes` is the honest render of it, "
          "and gating the health card on `lanes.length` made that documented case unreachable. "
          "Its flow and trigger notes are unchanged, so the widened gate is the only thing moving",
          obs_truncation_notes("zero-lane"),
          (["showing 0 of 50 lanes", "showing 16 of 19 defer reasons",
            "showing 16 of 18 model exit classes"],
           ["showing 12 of 26 queue classes", "showing 12 of 15 target repositories"],
           ["showing 20 of 23 trigger fires"], None))

    def obs_health_rows(name):
        rendered = truncation_page.get(name)
        if not isinstance(rendered, dict):
            return truncation_page
        reasons, chips = rendered.get("reasons") or [], rendered.get("chips") or []
        return (reasons[:1], reasons[-1:], len(reasons), chips[:1], chips[-1:], len(chips))

    check("[#1868] ...and that card still carries the ROWS the notes account for: a gate widened "
          "far enough to render a lone note over an empty card would pass the row above and fail "
          "this one. Sixteen defer rows and sixteen exit chips, first and last named literally",
          obs_health_rows("zero-lane"),
          (["reason-00 ×40"], ["reason-15 ×25"], 16,
           ["model-00 · success ×30"], ["model-15 · success ×15"], 16))
    # ---- [#982] A DROPPED QUEUE ROW MUST BE ANNOUNCED. `flow.queue: []` renders identically to
    # an idle queue, so the pre-#982 silent `continue` turned a producer/consumer shape mismatch
    # into a green build, a green self-test and a panel reading `no backlog` — the loss visible
    # nowhere. The tolerance is deliberately unchanged (drop the row, never fail the build); only
    # the silence is fixed, and the rows below pin BOTH halves of that.
    # The expected strings are literals on purpose: reading them back off the module under test
    # would be the tautology AGENTS.md pre-flight 2(b) names — it cannot fail.
    _QUEUE_DROP = "dashboard-gen: dropped observability queue input ({})"

    def obs_queue(rows):
        """(published `flow.queue`, the queue-drop warnings this build printed)."""
        fixture = copy.deepcopy(obs_fixture)
        fixture["flow"]["queue"] = rows
        stream = io.StringIO()
        try:                       # same crash-after-partial-run guard as ObsRefusal above
            with contextlib.redirect_stdout(stream):
                document = _normalize_observability(fixture)
        except DashboardError as error:
            document = ObsRefusal(refused=str(error))
        return (document["flow"]["queue"],
                [line for line in stream.getvalue().splitlines()
                 if line.startswith("dashboard-gen: dropped observability queue")])

    # THE REGRESSION, in the exact shape #636 found: `queue_stats()`'s classes are Python ints.
    # Every row is dropped and the panel reads `no backlog`; pre-#982 nothing said so.
    check("[#982] INTEGER queue classes publish an empty queue — and now name themselves once per "
          "dropped row instead of rendering as `no backlog` on a green build",
          obs_queue([{"class": 1, "depth": 4}, {"class": 2, "depth": 0}]),
          ([], [_QUEUE_DROP.format(
              "row `class` (type int) is not a class STRING such as '1'/'2a'/'4'")] * 2))
    # ...and the whole snapshot still normalizes: this is a drop diagnostic, NOT a new fatality.
    # Turning the drop into a raise (or into a `flow: None`) turns this row red.
    dropped_all = copy.deepcopy(obs_fixture)
    dropped_all["flow"]["queue"] = [{"class": 1, "depth": 4}]
    with contextlib.redirect_stdout(io.StringIO()):
        tolerated = obs_normalized(dropped_all)["flow"]
    check("[#982] a queue nothing in it parses is still TOLERATED — the rest of the flow panel is "
          "published unchanged and the build stays green",
          (tolerated["queue"], tolerated["parks_1h"], tolerated["lease_utilization_1h"]),
          ([], {"needs_user": 2, "needs_orchestrator": 1}, {"mean": 0.6, "max": 0.8}))
    # The accept path must stay SILENT, or the warning marks nothing: an unconditional print, or
    # one hoisted above the guards, publishes the same rows and turns this row red.
    check("[#982] a queue whose rows all parse prints NOTHING (the warning marks a real drop, so "
          "it can never fire on the accept path)",
          obs_queue([{"class": "2a", "depth": 1}, {"class": "4", "depth": 9}]),
          ([{"class": "2a", "depth": 1, "oldest_age_minutes": None},
            {"class": "4", "depth": 9, "oldest_age_minutes": None}], []))
    # [#1919] Age follows the same sent-vs-unreadable rule as its queue-row siblings. A collector
    # that has not shipped the optional field stays silent; one that SENT an unreadable value
    # loses the row loudly instead of publishing a depth-only row indistinguishable from absence.
    check("[#1919] a SENT unreadable queue age drops the row LOUDLY instead of silently erasing "
          "only the age",
          obs_queue([{"class": "2a", "depth": 9, "oldest_age_minutes": "12m"}]),
          ([], [_QUEUE_DROP.format(
              "row `oldest_age_minutes` (type str) is not a non-negative number of minutes")]))
    check("[#1919] an UNSENT queue age keeps the row and stays SILENT — absence is not a producer/"
          "consumer mismatch",
          obs_queue([{"class": "2a", "depth": 9}]),
          ([{"class": "2a", "depth": 9, "oldest_age_minutes": None}], []))
    # One warning per drop REASON, each naming the field that failed — a single shared message
    # would leave a `depth` mismatch reading as a `class` mismatch. The non-object row is the
    # branch a `--self-test` line-coverage run showed had never executed at all (pre-flight 1).
    for case, rows, detail in (
        ("a whole non-list queue container (`queue_stats()` handed over verbatim)",
         {1: {"depth": 4}, 2: {"depth": 0}},
         "`flow.queue` (type dict) is not a list of rows"),
        ("an explicit null queue", None, "`flow.queue` (type NoneType) is not a list of rows"),
        ("a non-object row", [["2a", 4]], "the row (type list) is not an object"),
        # The three ABSENT-field cases are here because their siblings above do not cover them:
        # a guard made inert for exactly the null/missing input (`item is None or …`) survived a
        # suite that only ever sent a WRONGLY-TYPED value. That is pre-flight item 3's #938 shape,
        # and null is the likeliest thing a JSON producer actually emits.
        ("a null row", [None], "the row (type NoneType) is not an object"),
        ("a missing class", [{"depth": 4}],
         "row `class` (type NoneType) is not a class STRING such as '1'/'2a'/'4'"),
        ("an unknown class string", [{"class": "9z", "depth": 1}],
         "row `class` '9z' is not one of the queue classes"),
        ("a non-integer depth", [{"class": "2a", "depth": "4"}],
         "row `depth` (type str) is not a non-negative integer"),
        ("a negative depth", [{"class": "2a", "depth": -1}],
         "row `depth` (type int) is not a non-negative integer"),
        ("a missing depth", [{"class": "2a"}],
         "row `depth` (type NoneType) is not a non-negative integer"),
    ):
        check(f"[#982] {case} is dropped LOUDLY, by the field that failed",
              obs_queue(rows), ([], [_QUEUE_DROP.format(detail)]))
    # ...and the ONE collector value any of these messages quotes is sanitized and BOUNDED on the
    # way out. Echo `queue_class` raw instead of `_obs_text(queue_class, 16)` and a hostile or
    # merely enormous class writes itself into the build log that is diagnosing it.
    for case, queue_class, quoted in (
        ("non-printable", "2a\ndashboard-gen: dropped observability queue input (forged)", "''"),
        ("4000 characters long", "9" * 4000, "'9999999999999999'"),
    ):
        check(f"[#982] a {case} class is not echoed into the build log that diagnoses it",
              obs_queue([{"class": queue_class, "depth": 1}]),
              ([], [_QUEUE_DROP.format(
                  f"row `class` {quoted} is not one of the queue classes")]))
    # ---- [#1570] THE DIAGNOSTIC ITSELF MUST BE BOUNDED. Both drop warnings above emit ONE LINE
    # PER DROPPED ROW over a list nothing bounds on the way IN (`_obs_capped` cuts both of them on
    # the way OUT, after the loop), so a snapshot on the public `ledger` branch carrying 100k
    # malformed rows writes 100k lines into dashboard.yml's step log — the very failure the drop
    # diagnostic exists to fix. The rows below pin BOTH directions: the cap FIRES, and the tail
    # line names the REAL total rather than anything derived from the cap.
    # Every expected string and every input SIZE below is a literal: deriving either from
    # OBS_DROP_WARN_MAX is pre-flight 2(b)/2(c)'s tautology (#941 set every over-cap input from the
    # constant it tested, so raising the constant left 76/76 green). Here, moving the constant reds
    # the over-cap rows, and a cap read off a different seam's counter reds the independence row.
    _EVIDENCE_DROP = "dashboard-gen: dropped a non-GitHub observability evidence link"
    _SUPPRESSED = "dashboard-gen: ... {} further dropped {} suppressed ({} dropped in total)"
    _INT_CLASS = _QUEUE_DROP.format(
        "row `class` (type int) is not a class STRING such as '1'/'2a'/'4'")

    def obs_drops(queue_rows, trigger_rows):
        """(published `flow.queue`, published `trigger_fires`, EVERY `dashboard-gen:` line printed).

        Unlike `obs_queue`/`obs_cache` this keeps every diagnostic line, in order and unfiltered —
        a cap that merely relabelled its warnings, or a tail line printed to the wrong seam, would
        be invisible to a prefix-filtered capture.
        """
        fixture = copy.deepcopy(obs_fixture)
        fixture["flow"]["queue"] = queue_rows
        fixture["trigger_fires"] = trigger_rows
        # [#1839] The golden fixture's cache group deliberately still sends the RETIRED chain/drain
        # keys, which makes it announce itself — a line about a different seam entirely. This capture
        # is unfiltered on purpose, so it is the FIXTURE that is quietened here rather than the
        # capture: a silent, publishing cache group, so any line these rows do see belongs to the
        # queue or evidence seam under test.
        fixture["cache"] = {"prompt_cache_read_fraction_1h": 0.62, "usage_samples_1h": 7}
        stream = io.StringIO()
        try:                       # same crash-after-partial-run guard as ObsRefusal above
            with contextlib.redirect_stdout(stream):
                document = _normalize_observability(fixture)
        except DashboardError as error:
            document = ObsRefusal(refused=str(error))
        return (document["flow"]["queue"], document["trigger_fires"],
                [line for line in stream.getvalue().splitlines()
                 if line.startswith("dashboard-gen:")])

    # 21 rows in, 20 of them malformed: 12 warnings, then ONE tail carrying the two numbers that
    # survive the cap. Remove the cap and this row reds with 20 warnings and no tail; count the
    # suppressed rows as the total (or the total as the cap) and the tail text reds.
    check("[#1570] 20 malformed queue rows print 12 warnings and ONE tail naming the REAL total — "
          "an unbounded diagnostic floods the log it exists to make legible",
          obs_drops([{"class": index, "depth": 1} for index in range(20)]
                    + [{"class": "2a", "depth": 3}], []),
          ([{"class": "2a", "depth": 3, "oldest_age_minutes": None}], [],
           [_INT_CLASS] * 12 + [_SUPPRESSED.format(8, "observability queue rows", 20)]))
    # The cap is on the DIAGNOSTIC, never on the data: suppressing a warning must not suppress a
    # row. The good row above publishes, and the build stays green (a refusal would red both).
    # AT the cap nothing is withheld, so NO tail may print: an unconditional `close()` emission —
    # or a `<=` comparison — turns this row red, and a "0 further ... suppressed" line on a
    # 12-row snapshot is exactly the noise this issue is about.
    check("[#1570] a snapshot exactly AT the cap prints its 12 warnings and NO tail — the tail "
          "line marks real suppression, so it can never fire when nothing was withheld",
          obs_drops([{"class": index, "depth": 1} for index in range(12)], []),
          ([], [], [_INT_CLASS] * 12))
    check("[#1570] one row PAST the cap: the 13th is withheld and counted, not printed",
          obs_drops([{"class": index, "depth": 1} for index in range(13)], []),
          ([], [], [_INT_CLASS] * 12 + [_SUPPRESSED.format(1, "observability queue rows", 13)]))
    # The evidence seam is the one with the multiplier: each row contributes up to 8 drops, so a
    # counter scoped to the ROW (the obvious wrong fix) still lets N rows write 8N lines. Three
    # rows x 8 non-GitHub links = 24 drops; a per-row cap prints all 24 and no tail.
    _flood_triggers = [{"rule": f"flood-rule-{index}", "fired_at": now - 300,
                        "summary": "flood", "evidence": ["https://evil.example/exfil"] * 8}
                       for index in range(3)]
    _flood_queue, _flood_rows, _flood_lines = obs_drops([], _flood_triggers)
    check("[#1570] the evidence cap counts per BUILD, not per row: 3 fire rows x 8 non-GitHub "
          "links each is 24 drops, capped at 12 with the real total in the tail",
          (_flood_lines, [row["rule"] for row in _flood_rows],
           [row["evidence"] for row in _flood_rows], _flood_queue),
          ([_EVIDENCE_DROP] * 12
           + [_SUPPRESSED.format(12, "observability evidence links", 24)],
           ["flood-rule-0", "flood-rule-1", "flood-rule-2"], [[], [], []], []))
    # The two seams count SEPARATELY. One shared counter would let a flooded queue silence the
    # evidence warning on the same document — trading one invisible loss for another — and would
    # print a single tail naming the wrong seam. Ordering is fixed: `flow` normalizes before
    # `trigger_fires`, so the queue seam closes before the evidence line prints.
    check("[#1570] a flooded queue seam does not consume the evidence seam's budget: the lone "
          "bad link still names itself, and each seam closes with its own tail",
          obs_drops([{"class": index, "depth": 1} for index in range(20)],
                    [{"rule": "lone-rule", "fired_at": now - 300, "summary": "s",
                      "evidence": ["https://evil.example/exfil"]}])[2],
          [_INT_CLASS] * 12 + [_SUPPRESSED.format(8, "observability queue rows", 20)]
          + [_EVIDENCE_DROP])
    # The accept path of BOTH trigger seams stays SILENT — a build that dropped nothing may print
    # neither a per-row line nor a tail, or the warning marks nothing. ([#1867] rewrote this row:
    # it used to ride a `None` fire row along and assert the row drop was silent, which is the
    # decision that issue reverses. The accept-path half is unchanged and is what keeps the loud
    # rows below non-vacuous — an unconditional print, or an unconditional `close()`, reds here.)
    check("[#1570] a fire row whose links all parse prints NOTHING — a tail line on a build that "
          "withheld nothing is noise",
          obs_drops([{"class": "2a", "depth": 1}],
                    [{"rule": "quiet-rule", "fired_at": now - 300, "summary": "s",
                      "evidence": ["https://github.com/jeswr/agent-account-registry/"
                                   "actions/runs/7"]}]),
          ([{"class": "2a", "depth": 1, "oldest_age_minutes": None}],
           [{"rule": "quiet-rule", "fired_at": "2025-06-15T15:01:40Z", "summary": "s",
             "evidence": ["https://github.com/jeswr/agent-account-registry/actions/runs/7"],
             "enqueued_task": None}], []))
    # ---- [#1867] A DROPPED FIRE ROW MUST NAME ITSELF. The evidence-LINK drops above are loud while
    # the row CARRYING them was not, so a collector that spells a rule with a space lost the whole
    # alarm — panel row, summary, every link — on a green build with the loss visible nowhere. That
    # reads worse than the `flow.queue` case #982 fixed: an alarm that was dropped and an alarm that
    # never fired both render as an absent trigger row. Every expected string below is a test-side
    # literal (reading the message back off the module is pre-flight 2(b)'s tautology) and every
    # input is a literal (2(c)); the capture is `obs_drops`, which keeps EVERY `dashboard-gen:` line
    # in order and unfiltered, so a line printed to the wrong seam or with the wrong text reds.
    _FIRE_DROP = "dashboard-gen: dropped observability trigger fire input ({})"
    _FIRE_ROWS = "observability trigger fire rows"
    _KEPT_FIRE = {"rule": "kept-rule", "fired_at": now - 300, "summary": "s", "evidence": []}
    _KEPT_PUBLISHED = {"rule": "kept-rule", "fired_at": "2025-06-15T15:01:40Z", "summary": "s",
                       "evidence": [], "enqueued_task": None}
    # THE REGRESSION, in the shape the issue names. Both directions in one row: the unreadable rule
    # is announced, AND the row beside it still publishes — this is a drop diagnostic, not a new
    # fatality and not a reason to fail the panel.
    check("[#1867] a rule spelled with a SPACE loses its whole alarm — row, summary and links — "
          "and now names itself instead of vanishing from the trigger panel on a green build",
          obs_drops([], [{"rule": "worker failure rate", "fired_at": now - 300,
                          "summary": "worker failure rate 67% over 3 consecutive runs",
                          "evidence": ["https://github.com/jeswr/agent-account-registry/"
                                       "actions/runs/9"]},
                         copy.deepcopy(_KEPT_FIRE)]),
          ([], [_KEPT_PUBLISHED],
           [_FIRE_DROP.format("row `rule` 'worker failure rate' is not a safe token")]))
    # One warning per drop REASON, each naming what failed: a single shared message would leave a
    # missing `rule` reading as a misspelled one. The null/missing cases are here because their
    # wrongly-typed siblings do not cover them — pre-flight item 3's #938 shape, and null is the
    # likeliest thing a JSON producer actually emits.
    for case, fires, detail in (
        ("a non-object row", [["worker-failure-rate", 3]], "the row (type list) is not an object"),
        ("a null row", [None], "the row (type NoneType) is not an object"),
        ("a missing rule", [{"summary": "s"}],
         "row `rule` (type NoneType) is not a rule-name STRING"),
        ("an explicitly null rule", [{"rule": None, "summary": "s"}],
         "row `rule` (type NoneType) is not a rule-name STRING"),
        ("a non-string rule", [{"rule": 7, "summary": "s"}],
         "row `rule` (type int) is not a rule-name STRING"),
        ("an empty rule", [{"rule": "", "summary": "s"}], "row `rule` '' is not a safe token"),
        ("a punctuated rule", [{"rule": "bad rule!", "summary": "s"}],
         "row `rule` 'bad rule!' is not a safe token"),
    ):
        check(f"[#1867] {case} is dropped LOUDLY, by the reason that failed",
              obs_drops([], fires), ([], [], [_FIRE_DROP.format(detail)]))
    # ...and the ONE collector value these messages quote is sanitized and BOUNDED on the way out.
    # Echo `rule` raw instead of `_obs_text(rule, 64)` and a hostile or merely enormous rule writes
    # itself into the build log that is diagnosing it — the capture is unfiltered, so a forged line
    # would arrive as a second entry here.
    for case, rule, quoted in (
        ("non-printable", "ok\ndashboard-gen: dropped observability trigger fire input (forged)",
         "''"),
        ("4000 characters long", "9" * 4000, "'" + "9" * 64 + "'"),
    ):
        check(f"[#1867] a {case} rule is not echoed into the build log that diagnoses it",
              obs_drops([], [{"rule": rule, "summary": "s"}]),
              ([], [], [_FIRE_DROP.format(f"row `rule` {quoted} is not a safe token")]))
    # `items` is unbounded on the way IN (`_obs_capped` cuts at 20 on the way OUT), so this seam
    # needs the #1570 cap as much as the queue seam does: 20 unreadable rows print 12 warnings
    # and ONE tail naming the REAL total. Sizes and expected strings are literals — deriving either from
    # OBS_DROP_WARN_MAX is the #941 tautology. The 21st row still publishes: capping a WARNING must
    # never cap the DATA.
    check("[#1867] 20 unreadable fire rows print 12 warnings and ONE tail naming the real total — "
          "an unbounded diagnostic floods the log it exists to make legible",
          obs_drops([], [{"rule": "bad rule!", "summary": "s"} for _ in range(20)]
                    + [copy.deepcopy(_KEPT_FIRE)]),
          ([], [_KEPT_PUBLISHED],
           [_FIRE_DROP.format("row `rule` 'bad rule!' is not a safe token")] * 12
           + [_SUPPRESSED.format(8, _FIRE_ROWS, 20)]))
    # The row seam and the evidence seam count SEPARATELY, for the reason the queue and evidence
    # seams do. A malformed ROW never reaches the evidence loop, so a single shared counter would
    # let a flood of unreadable rows silence every link warning on the same document — trading one
    # invisible loss for another — and would print one tail naming the wrong seam. Order is fixed:
    # the good row is last, so its link warning prints inside the loop, before either tail.
    check("[#1867] a flooded row seam does not consume the evidence seam's budget: the lone bad "
          "link still names itself, and each seam closes with its own tail",
          obs_drops([], [{"rule": "bad rule!", "summary": "s"} for _ in range(20)]
                    + [{"rule": "kept-rule", "fired_at": now - 300, "summary": "s",
                        "evidence": ["https://evil.example/exfil"]}])[2],
          [_FIRE_DROP.format("row `rule` 'bad rule!' is not a safe token")] * 12
          + [_EVIDENCE_DROP] + [_SUPPRESSED.format(8, _FIRE_ROWS, 20)])
    # Both seams over their budget on ONE document, which is the only shape that pins the whole
    # interleaving: 12 row lines, then the link lines from the two rows that survived, then TWO
    # tails, each naming its own seam with its own two numbers. A shared counter, a tail attributed
    # to the wrong seam, or a total that counted the other seam's drops reds this row.
    check("[#1867] both seams over budget on one document: each caps at 12, and each closes with "
          "its OWN tail carrying its OWN real total",
          obs_drops([], [{"rule": "bad rule!", "summary": "s"} for _ in range(20)]
                    + [{"rule": f"kept-rule-{index}", "fired_at": now - 300, "summary": "s",
                        "evidence": ["https://evil.example/exfil"] * 8} for index in range(2)])[2],
          [_FIRE_DROP.format("row `rule` 'bad rule!' is not a safe token")] * 12
          + [_EVIDENCE_DROP] * 12
          + [_SUPPRESSED.format(8, _FIRE_ROWS, 20),
             _SUPPRESSED.format(4, "observability evidence links", 16)])
    # ---- [#1880] A FLOW STAT THE COLLECTOR SENT AND THIS BUILD CANNOT READ MUST NOT PUBLISH AS A
    # HEALTHY NUMBER. `_obs_count(...) or 0` mapped every unreadable park/sample count to 0, so
    # `parks_1h: {"needs_user": "lots", "needs_orchestrator": -3}` published `0 user · 0 orch` on
    # the panel an operator reads to decide whether the fleet is stuck on humans — and printed
    # nothing. The milder form is the same failure: an unreadable `mean`/`max`/`p50` became None
    # with no diagnostic, so a collector that RENAMED a field is indistinguishable from one that
    # has not shipped it yet. Every input below is a JSON literal and every expected string is a
    # literal: reading either back off the module under test is the tautology AGENTS.md pre-flight
    # 2(b) names, and deriving an input from the code's own field tuple is 2(c).
    _STAT_DROP = "dashboard-gen: dropped observability flow stat `{}` ({})"
    _NOT_COUNT = "field `{}` (type {}) is not a non-negative integer"

    def obs_stat(key, value, present=True):
        """(published `flow.<key>`, the flow-stat warnings this build printed)."""
        fixture = copy.deepcopy(obs_fixture)
        if present:
            fixture["flow"][key] = value
        else:
            del fixture["flow"][key]
        stream = io.StringIO()
        try:                       # same crash-after-partial-run guard as ObsRefusal above
            with contextlib.redirect_stdout(stream):
                document = _normalize_observability(fixture)
        except DashboardError as error:
            document = ObsRefusal(refused=str(error))
        except Exception as error:  # noqa: BLE001 — [#1880], as in obs_normalized above
            document = ObsRefusal(raised=f"{type(error).__name__}: {error}"[:200])
        return (document["flow"][key],
                [line for line in stream.getvalue().splitlines()
                 if line.startswith("dashboard-gen: dropped observability flow stat")])

    check("[#1880] the park counts from this issue — a STRING and a NEGATIVE where the collector "
          "should have sent counts — hide the park stat and name BOTH fields, instead of "
          "publishing the `0 user · 0 orch` of a fleet parked on nobody",
          obs_stat("parks_1h", {"needs_user": "lots", "needs_orchestrator": -3}),
          (None, [_STAT_DROP.format("parks_1h", _NOT_COUNT.format("needs_user", "str")),
                  _STAT_DROP.format("parks_1h",
                                    _NOT_COUNT.format("needs_orchestrator", "int"))]))
    # The accept path is what makes the row above non-vacuous: a guard that hid every zero, or one
    # that announced on every read, satisfies the reject rows while erasing the quiet hour an
    # operator interrogates (AGENTS.md pre-flight item 8 — a census must emit its zero row).
    check("[#1880] a REAL zero-park hour still publishes its zeroes, SILENTLY — 0 is a reading, "
          "not an absence, and the warning marks a producer/consumer mismatch",
          obs_stat("parks_1h", {"needs_user": 0, "needs_orchestrator": 0}),
          ({"needs_user": 0, "needs_orchestrator": 0}, []))
    check("[#1880] a field the collector did NOT send takes its default and says nothing — a "
          "collector that has not shipped a field yet is not a mismatch",
          obs_stat("parks_1h", {"needs_user": 4}),
          ({"needs_user": 4, "needs_orchestrator": 0}, []))
    for key in ("parks_1h", "review_rounds", "arm_to_merge_minutes_24h"):
        check(f"[#1918] an EMPTY `{key}` stat measured nothing: hide it and announce the drop "
              "instead of publishing a complete row made only from defaults",
              obs_stat(key, {}),
              (None, [_STAT_DROP.format(key, "the stat has no parsed fields")]))
    check("[#1918] explicit nulls are still absent values, but a stat made ONLY of nulls has no "
          "parsed field and cannot publish its sample-count default as a measurement",
          obs_stat("arm_to_merge_minutes_24h", {"p50": None, "p90": None, "samples": None}),
          (None, [_STAT_DROP.format("arm_to_merge_minutes_24h",
                                   "the stat has no parsed fields")]))
    check("[#1918] null/unsent siblings keep their defaults once ONE field genuinely parses — a "
          "quiet 24h sample count is a reading and still publishes silently",
          obs_stat("arm_to_merge_minutes_24h", {"p50": None, "samples": 0}),
          ({"p50": None, "p90": None, "samples": 0}, []))
    # ...and the defaults are per FIELD, not one shared value: a park count nobody sent is 0 (the
    # panel reads counts through `obsNum(value, 0)` either way), while an unsent mean/max is None
    # so the stat renders `—` instead of a fabricated `0 avg`.
    check("[#1880] the review-round fields the collector did not send default to None — a shared "
          "0 default would publish `0 avg · max 0` for a collector that sends only the exhaustion "
          "count",
          obs_stat("review_rounds", {"budget_exhausted_1h": 2}),
          ({"mean": None, "max": None, "budget_exhausted_1h": 2}, []))
    check("[#1880] a review-round stat whose every field parses publishes all three, SILENTLY",
          obs_stat("review_rounds", {"mean": 0, "max": 0, "budget_exhausted_1h": 0}),
          ({"mean": 0.0, "max": 0, "budget_exhausted_1h": 0}, []))
    # One row per (stat, reader), each the ONLY row that reds if its own field stops being checked
    # — and each carries a SIBLING field that parses, so "the stat hides" cannot be satisfied by a
    # guard that only ever looks at the first field, and the published value can never be the
    # half-real `{"mean": None, "max": 3}` this issue is about.
    for case, key, value, detail in (
        ("a stringified p90 (the arm→merge sub-label)", "arm_to_merge_minutes_24h",
         {"p50": 18, "p90": "55.5", "samples": 9},
         "field `p90` (type str) is not a non-negative number of minutes"),
        ("a negative sample count", "arm_to_merge_minutes_24h",
         {"p50": 18, "p90": 55.5, "samples": -3}, _NOT_COUNT.format("samples", "int")),
        ("a stringified review-round mean", "review_rounds",
         {"mean": "1.4", "max": 3, "budget_exhausted_1h": 0},
         "field `mean` (type str) is not a non-negative finite number"),
        ("a negative review-round max", "review_rounds",
         {"mean": 1.4, "max": -1, "budget_exhausted_1h": 0}, _NOT_COUNT.format("max", "int")),
        # A mean is the one FLOAT field of the three, so its reader is `_obs_mean` rather than
        # `_obs_count` — and it has to reject the same directions: a negative average number of
        # review rounds is not a measurement any collector can have taken.
        ("a NEGATIVE review-round mean", "review_rounds",
         {"mean": -1.4, "max": 3, "budget_exhausted_1h": 0},
         "field `mean` (type float) is not a non-negative finite number"),
        # ...and it has to reject that direction WITHOUT RAISING. `json.loads` hands back an
        # arbitrary-precision int, and this one is unconvertible: `float(10**400)` and
        # `math.isfinite(10**400)` both raise `OverflowError`. A reader that range-checks the raw
        # value never returns None here at all — it takes the build down (see the row below).
        # The literal is written out as `10 ** 400`, tied to nothing the module defines.
        ("an OVERSIZED review-round mean — an integer too large to convert to float",
         "review_rounds", {"mean": 10 ** 400, "max": 3, "budget_exhausted_1h": 0},
         "field `mean` (type int) is not a non-negative finite number"),
        # `isinstance(True, int)` is what `_obs_count` exists to reject: a boolean exhaustion flag
        # would otherwise publish as the count 1, or as the reassuring `0 budget-exhausted / 1h`.
        ("a BOOLEAN budget-exhausted flag", "review_rounds",
         {"mean": 1.4, "max": 3, "budget_exhausted_1h": True},
         _NOT_COUNT.format("budget_exhausted_1h", "bool")),
    ):
        check(f"[#1880] {case} hides its whole stat and names the field — publishing the readable "
              "siblings beside a silently blanked one is what made a RENAMED collector field look "
              "like an unshipped one",
              obs_stat(key, value), (None, [_STAT_DROP.format(key, detail)]))
    # Each count field is bound to `_obs_count` SPECIFICALLY. A fractional value is the input that
    # separates it from the seam's other readers — `_obs_minutes`/`_obs_mean` both accept a float —
    # so a reader swapped at one of these five call sites would otherwise publish `9.5 samples /
    # 24h` or `1.5 orch` with every other row still green (AGENTS.md pre-flight 2(a): the call site
    # is where the wiring lives).
    for key, value, field in (("parks_1h", {"needs_user": 2.5}, "needs_user"),
                              ("parks_1h", {"needs_orchestrator": 1.5}, "needs_orchestrator"),
                              ("review_rounds", {"max": 3.5}, "max"),
                              ("review_rounds", {"budget_exhausted_1h": 0.5},
                               "budget_exhausted_1h"),
                              ("arm_to_merge_minutes_24h", {"samples": 9.5}, "samples")):
        check(f"[#1880] a FRACTIONAL `{field}` is not a count: this field is read by `_obs_count`, "
              "and a call site wired to the minutes/mean reader would publish the fraction",
              obs_stat(key, value),
              (None, [_STAT_DROP.format(key, _NOT_COUNT.format(field, "float"))]))
    for key, value, container in (("parks_1h", "lots", "str"),
                                  ("review_rounds", [1.44, 3, 0], "list"),
                                  ("arm_to_merge_minutes_24h", 18, "int")):
        check(f"[#1880] a `{key}` the collector sent as a {container} names itself once and "
              "publishes nothing — the container check `_obs_drop_queue` already makes on "
              "`flow.queue`, for the same reason",
              obs_stat(key, value),
              (None, [_STAT_DROP.format(key, f"the stat (type {container}) is not an object")]))
    for case, args in (("no `parks_1h` key at all", ("parks_1h", None, False)),
                       ("an explicit null `parks_1h`", ("parks_1h", None))):
        check(f"[#1880] {case} hides the stat SILENTLY — 'the collector has not landed' is not a "
              "producer/consumer mismatch, and the panel has always hidden an unsent stat",
              obs_stat(*args), (None, []))
    # ...and a dropped stat is a drop diagnostic, not a new fatality and NOT contagious: the build
    # stays green and every sibling of the hole publishes unchanged. Turning the drop into a raise,
    # or into a `flow: None`, turns this row red.
    stat_dropped = copy.deepcopy(obs_fixture)
    stat_dropped["flow"]["parks_1h"] = {"needs_user": "lots", "needs_orchestrator": 1}
    with contextlib.redirect_stdout(io.StringIO()):
        stat_tolerated = obs_normalized(stat_dropped)["flow"]
    check("[#1880] a snapshot whose park stat is dropped is still TOLERATED — the queue, the lease "
          "aggregate and both sibling stats are published unchanged around the hole",
          (stat_tolerated["parks_1h"], stat_tolerated["review_rounds"],
           stat_tolerated["arm_to_merge_minutes_24h"], stat_tolerated["lease_utilization_1h"],
           [row["class"] for row in stat_tolerated["queue"]]),
          (None, {"mean": 1.44, "max": 3, "budget_exhausted_1h": 0},
           {"p50": 18.0, "p90": 55.5, "samples": 9}, {"mean": 0.6, "max": 0.8}, ["2a", "4"]))
    # ...and the oversized mean has to be tolerated the SAME way, which is a strictly stronger
    # claim than "the reader returns None": an `OverflowError` out of `_obs_mean` is not a
    # DashboardError, so it escapes `_normalize_observability` uncaught and kills the whole
    # dashboard build — every sibling group on this document goes with it, and the panel an
    # operator reads goes dark rather than dropping one stat. Asserted on the WHOLE flow group,
    # because the row above proves only that `review_rounds` itself hid.
    oversized_mean = copy.deepcopy(obs_fixture)
    oversized_mean["flow"]["review_rounds"]["mean"] = 10 ** 400
    with contextlib.redirect_stdout(io.StringIO()):
        oversized_flow = obs_normalized(oversized_mean)["flow"]
    # The queue is projected only if it IS one: on a refusal every subscript above yields the
    # ObsRefusal itself, and iterating THAT raises out of this row — which would abort the suite
    # from the very row proving the seam does not abort. Measured: reverting `_obs_mean` to the
    # raw-value range check took the run from 358 checks to 324 — a kill that hid 34 unrun rows —
    # until this projection was guarded (AUTHOR pre-flight item 4).
    oversized_queue = oversized_flow["queue"]
    check("[#1880] an UNCONVERTIBLE integer mean drops its stat and leaves the BUILD standing — "
          "range-checking the raw value raises `OverflowError` past this seam's DashboardError "
          "contract, so the park counts, the arm→merge percentiles and the queue below all "
          "vanish with it instead of publishing around the hole",
          (oversized_flow["review_rounds"], oversized_flow["parks_1h"],
           oversized_flow["arm_to_merge_minutes_24h"],
           [row["class"] for row in oversized_queue]
           if isinstance(oversized_queue, list) else oversized_queue),
          (None, {"needs_user": 2, "needs_orchestrator": 1},
           {"p50": 18.0, "p90": 55.5, "samples": 9}, ["2a", "4"]))
    # ...and the PAGE is what the drop has to DELIVER INTO (AGENTS.md pre-flight item 11). The
    # generator's build-log announcement is evidence nobody reads on a green build, so the fix only
    # counts if the false-healthy METRIC is gone from the panel: `obsFlowCard` renders every count
    # through `obsNum(value, 0)`, so dropping the unreadable FIELD alone would still have printed
    # `0 user · 0 orch`. Executed against dashboard/app.js under the shared DOM shim, never
    # asserted lexically (the #612 round-4 lesson).
    _OBS_FLOW_STAT_PAGE_BODY = r"""
  const out = {};
  for (const [name, document] of Object.entries(input.documents)) {
    for (const id of ["obs-section", "obs-grid", "obs-time", "obs-triggers", "warning"]) {
      ids[id] = element(id);
    }
    let error = null;
    try {
      scope.renderObservability(document);
    } catch (raised) {
      error = String((raised && raised.message) || raised);
    }
    const card = ids["obs-grid"].children.find((kid) =>
      kid.tagName === "article" && kid.children[0]
      && kid.children[0].textContent === "Queue & flow");
    const grid = card ? card.children.find((kid) => kid.className === "obs-metric-grid") : null;
    out[name] = {
      error,
      // [label, the value cell INCLUDING its sub-label] per metric, in render order.
      metrics: grid ? grid.children.map((cell) => [cell.children[0].textContent,
                                                   flat(cell.children[1]).join(" ").trim()]) : null,
    };
  }
  process.stdout.write(JSON.stringify(out));
"""
    with contextlib.redirect_stdout(io.StringIO()):
        flow_measured = obs_normalized(copy.deepcopy(obs_fixture))
        flow_unreadable = obs_normalized(stat_dropped)
    flow_stat_page = _executed_page(
        _page_harness("renderObservability", _OBS_FLOW_STAT_PAGE_BODY),
        {"documents": {"measured": flow_measured, "unreadable": flow_unreadable}})

    def flow_metrics(name):
        rendered = flow_stat_page[name]
        return (rendered.get("metrics"), rendered.get("error"))

    check("[#1880] EXECUTED page script: the golden flow stats all render — the control the row "
          "below rests on, since a panel that dropped every metric would satisfy it",
          flow_metrics("measured"),
          ([["Review rounds", "1.44 avg max 3 · 0 budget-exhausted / 1h"],
            ["Parked / 1h", "2 user · 1 orch"],
            ["Arm → merge", "18m p50 55.5m p90 · 9 samples / 24h"],
            ["CI queue · sparq-org/sparq", "5 pending target CI runs"]], None))
    check("[#1880] EXECUTED page script: a park stat this build could not read leaves NO "
          "`Parked / 1h` metric on the panel at all — never the `0 user · 0 orch` an operator "
          "would read as a fleet that is not waiting on any human — and every other metric, "
          "including the ORCHESTRATOR park count that WAS readable, is unaffected",
          flow_metrics("unreadable"),
          ([["Review rounds", "1.44 avg max 3 · 0 budget-exhausted / 1h"],
            ["Arm → merge", "18m p50 55.5m p90 · 9 samples / 24h"],
            ["CI queue · sparq-org/sparq", "5 pending target CI runs"]], None))
    overflow = copy.deepcopy(obs_fixture)
    overflow["flow"]["review_rounds"]["mean"] = 1e309       # JSON 1e309 decodes to +Infinity
    overflow["thresholds"]["workflow_failure_rate"] = 1e309
    with contextlib.redirect_stdout(io.StringIO()) as overflow_log:
        overflow_normalized = obs_normalized(overflow)
    # [#1880] The rejection is unchanged; what the rejection PUBLISHES is not. `+Infinity` used to
    # blank the mean and publish it beside the real `max 3`, which reads as a collector that does
    # not send a mean. The stat now hides and the seam names the field.
    check("non-finite review-round mean is rejected, never published — and since #1880 the whole "
          "review-round stat hides and says so, instead of a dashed mean beside a confident max",
          (overflow_normalized["flow"]["review_rounds"],
           [line for line in overflow_log.getvalue().splitlines()
            if line.startswith("dashboard-gen: dropped observability flow stat")]),
          (None, [_STAT_DROP.format(
              "review_rounds",
              "field `mean` (type float) is not a non-negative finite number")]))
    check("non-finite threshold is dropped, never published",
          "workflow_failure_rate" in overflow_normalized["thresholds"], False)
    for bad_document in ({"schema": "wrong/v0"}, ["not", "a", "dict"], {}):
        try:
            _normalize_observability(bad_document)
        except DashboardError:
            schema_rejected = True
        else:
            schema_rejected = False
        check(f"alien observability document rejected loudly ({type(bad_document).__name__})",
              schema_rejected, True)
    raw_label = copy.deepcopy(obs_fixture)
    raw_label["flow"]["leases"][0]["label"] = handle   # a raw account handle, not the salted form
    try:
        _normalize_observability(raw_label)
    except DashboardError:
        label_rejected = True
    else:
        label_rejected = False
    check("raw (non-salted) lease label is a fatal privacy violation (decision 22)",
          label_rejected, True)
    # [#374] ...and the salted labels are not published either. Two fleets whose lease rows differ
    # only in COUNT must normalize identically; pre-#374 the row array itself was the disclosure.
    def obs_leases(rows):
        fixture = copy.deepcopy(obs_fixture)
        fixture["flow"]["leases"] = rows
        return obs_normalized(fixture)["flow"]

    one_lease = obs_leases([{"label": "ab12cd340a5f9e71", "provider": "anthropic",
                             "utilization_1h": 0.5}])
    four_leases = obs_leases([{"label": f"ab12cd340a5f9e7{index}", "provider": "anthropic",
                               "utilization_1h": 0.5} for index in range(4)])
    check("[#374] lease rows of different fleet sizes normalize to the same published flow",
          (one_lease, one_lease == four_leases,
           "ab12cd340a5f9e71" in json.dumps(one_lease)),
          (four_leases, True, False))
    check("[#374] no reported lease utilization publishes nothing rather than a zero",
          obs_leases([])["lease_utilization_1h"], None)
    # ---- [#375] the salted label IS the canonical account fingerprint, sha256(handle:salt)[:16]
    # (locked decision 22a). Pre-#375 this seam validated an 8-hex shape that NOTHING in this repo
    # produces, so a collector handing over the same fingerprint model-health / worker-pr / the
    # lease ledger all carry would have failed the build, while a truncated half of one was waved
    # through as "salted". The accept row derives its label from the canonical implementation
    # rather than from a literal, so a shortening on EITHER side of the wire turns it red.
    canonical_label = _model_health_module().account_hash("acct-obs-375", "fixture-salt")
    canonical_flow = obs_leases([{"label": canonical_label, "provider": "anthropic",
                                  "utilization_1h": 0.5}])
    check("[#375] the CANONICAL salted fingerprint (model-health.account_hash) is the accepted "
          "lease label, and its row is really consumed rather than merely tolerated",
          (len(canonical_label), canonical_flow["lease_utilization_1h"]),
          (16, {"mean": 0.5, "max": 0.5}))
    # ...and the pre-#375 8-hex format is now fatal rather than a second accepted identity shape.
    # Widening the pattern back to `{8}` kills the row above; widening it to `{8,16}`/`{8,}` — the
    # tempting "accept both" — is what these rows exist to kill, so they assert REJECTION.
    for case, bad_label in (("the pre-#375 8-hex format", "ab12cd34"),
                            ("the canonical fingerprint truncated to 8 hex", canonical_label[:8]),
                            ("a 15-hex near-miss", canonical_label[:15]),
                            ("a 17-hex overrun", canonical_label + "0")):
        mis_shaped = copy.deepcopy(obs_fixture)
        mis_shaped["flow"]["leases"][0]["label"] = bad_label
        check(f"[#375] {case} is a fatal decision-22 violation, never a second accepted format",
              _raises_dashboard(lambda: _normalize_observability(mis_shaped)), True)
    # ---- [#841] the ROW-FREE collector contract. #374 stopped this build PUBLISHING the rows; it
    # did not stop them EXISTING at data/observability.json on the public `ledger` branch. So the
    # aggregate is accepted directly and a collector need write no per-account rows anywhere.
    def obs_flow_without_rows(aggregate):
        fixture = copy.deepcopy(obs_fixture)
        fixture["flow"].pop("leases", None)          # the collector sends NO per-account rows
        fixture["flow"]["lease_utilization_1h"] = aggregate
        return obs_normalized(fixture)["flow"]["lease_utilization_1h"]

    check("[#841] a collector that sends NO lease rows still publishes the aggregate it computed",
          obs_flow_without_rows({"mean": 0.31, "max": 0.77}), {"mean": 0.31, "max": 0.77})
    # Precedence is ROWS-FIRST and total, so a collector mid-migration that sends both publishes
    # exactly its pre-#841 value — the new key can never silently override real measurements.
    # Flipping the precedence turns this into {0.99, 0.99}.
    both = copy.deepcopy(obs_fixture)
    both["flow"]["lease_utilization_1h"] = {"mean": 0.99, "max": 0.99}
    check("[#841] lease ROWS outrank a collector-supplied aggregate (no silent override)",
          obs_normalized(both)["flow"]["lease_utilization_1h"],
          {"mean": 0.6, "max": 0.8})
    # ...and precedence keys on the legacy KEY, not on a row happening to parse. Rows that are
    # present but report no usable utilization published null pre-#841 and must still publish null:
    # make the fallback conditional on `lease_utilizations` instead and these become {0.99, 0.99},
    # i.e. the new key overriding a legacy source that was sent.
    for case, rows in (
        ("no utilization field", [{"label": "ab12cd340a5f9e71", "provider": "anthropic"}]),
        ("malformed utilization", [{"label": "ab12cd340a5f9e71", "provider": "anthropic",
                                    "utilization_1h": "busy"}]),
        ("zero rows", []),
    ):
        unparseable = copy.deepcopy(both)
        unparseable["flow"]["leases"] = rows
        check(f"[#841] legacy rows with {case} keep their pre-#841 null, aggregate or not",
              obs_normalized(unparseable)["flow"]["lease_utilization_1h"], None)
    # ...and sending the aggregate is NOT a way around the decision-22 check on the rows that ARE
    # present. Make the label check conditional on the rows being used and this normalizes happily.
    both_raw = copy.deepcopy(both)
    both_raw["flow"]["leases"][0]["label"] = handle    # a raw account handle alongside a valid mean
    try:
        _normalize_observability(both_raw)
    except DashboardError:
        aggregate_is_no_bypass = True
    else:
        aggregate_is_no_bypass = False
    check("[#841] a raw lease label stays fatal even when an aggregate is also supplied",
          aggregate_is_no_bypass, True)
    for case, aggregate in (
        ("incoherent (max < mean)", {"mean": 0.8, "max": 0.4}),
        ("out-of-range fraction", {"mean": 0.2, "max": 1.4}),
        ("half-supplied (no max)", {"mean": 0.2}),
        ("non-numeric", {"mean": "busy", "max": "busy"}),
        ("non-object", [0.2, 0.4]),
    ):
        check(f"[#841] {case} collector aggregate is dropped, never published",
              obs_flow_without_rows(aggregate), None)
    # ---- [#1869] A DROPPED LEASE ROW MUST NAME ITSELF. The seams #982/#1570/#1571/#1867 made loud
    # all EMPTY a panel when they drop. This one does not: it shrinks the sample
    # `lease_utilization_1h` is computed over and publishes a confident mean/max across whatever
    # survived, so a collector sending half its rows in the wrong shape reported a load-balance
    # figure derived from the other half. A wrong number reads as a measurement; an empty panel at
    # least reads as nothing. Every expected string below is a test-side literal (reading the
    # message back off the module under test is pre-flight 2(b)'s tautology) and every input is a
    # literal (2(c)); the capture keeps EVERY `dashboard-gen:` line, in order and unfiltered, so a
    # line printed to the wrong seam, or with the wrong text, reds.
    _LEASE_DROP = "dashboard-gen: dropped observability lease input ({})"
    _LEASE_ROWS = "observability lease rows"
    _KEPT_LEASE = {"label": "ab12cd340a5f9e71", "provider": "anthropic", "utilization_1h": 0.8}

    def obs_lease_drops(rows, queue_rows=None):
        """(published `flow.lease_utilization_1h`, EVERY `dashboard-gen:` line printed).

        The FIXTURE is quietened rather than the capture (as `obs_drops` does above): the golden
        snapshot's unknown queue class, retired cache keys and unsafe trigger rule each announce
        themselves from a different seam, and filtering them out of the capture would also hide a
        lease line mislabelled as one of them.
        """
        fixture = copy.deepcopy(obs_fixture)
        fixture["flow"]["leases"] = rows
        fixture["flow"]["queue"] = ([{"class": "2a", "depth": 1}]
                                    if queue_rows is None else queue_rows)
        fixture["cache"] = {"prompt_cache_read_fraction_1h": 0.62, "usage_samples_1h": 7}
        fixture["trigger_fires"] = []
        stream = io.StringIO()
        try:                       # same crash-after-partial-run guard as ObsRefusal above
            with contextlib.redirect_stdout(stream):
                document = _normalize_observability(fixture)
        except DashboardError as error:
            document = ObsRefusal(refused=str(error))
        except Exception as error:  # noqa: BLE001 — #1880's arm, for #1880's reason: this seam
            # walks rows it has just declared unreadable, so a guard that ANNOUNCES the row without
            # skipping it raises out of `item.get(...)` and would abort every check below rather
            # than red the row that provoked it. Rendered, not swallowed: nothing here equals it.
            document = ObsRefusal(raised=f"{type(error).__name__}: {error}"[:200])
        return (document["flow"]["lease_utilization_1h"],
                [line for line in stream.getvalue().splitlines()
                 if line.startswith("dashboard-gen:")])

    # THE REGRESSION, in the shape the issue names, and both directions in one row: the survivors
    # still publish (this is a drop diagnostic, not a new fatality), and the two rows that were
    # silently subtracted from the sample now name themselves. Pre-#1869 the value below was
    # published with an empty line list — a confident 0.5 mean over half a fleet, announced nowhere.
    check("[#1869] a lease list half of whose rows are unreadable publishes a mean/max over the "
          "SURVIVORS — the aggregate is unchanged, and every subtracted row now names itself "
          "instead of quietly lowering the sample the load-balance figure is computed from",
          obs_lease_drops([copy.deepcopy(_KEPT_LEASE),
                           ["ef56ab78b3c2d104", 0.4],
                           None,
                           {"label": "cd90ef1276a8b535", "provider": "openai",
                            "utilization_1h": 0.2}]),
          ({"mean": 0.5, "max": 0.8},
           [_LEASE_DROP.format("the row (type list) is not an object"),
            _LEASE_DROP.format("the row (type NoneType) is not an object")]))
    # The accept path must stay SILENT, or the warning marks nothing: an unconditional drop, or one
    # hoisted above the guard, publishes this same aggregate and turns this row red.
    check("[#1869] a lease list whose rows all parse prints NOTHING — the warning marks a real "
          "drop, so it can never fire on the accept path",
          obs_lease_drops([copy.deepcopy(_KEPT_LEASE),
                           {"label": "ef56ab78b3c2d104", "provider": "anthropic",
                            "utilization_1h": 0.4}]),
          ({"mean": 0.6, "max": 0.8}, []))
    # One line per dropped row, naming the SHAPE that failed. The null and bare-scalar cases are
    # here because the list case does not cover them: a guard made inert for exactly the null input
    # (`item is None or not isinstance(...)`) survives a suite that only ever sends a list, which is
    # pre-flight item 3's #938 shape, and null is the likeliest thing a JSON producer emits.
    for case, row, detail in (
        ("a non-object row", ["ab12cd340a5f9e71", 0.5], "the row (type list) is not an object"),
        ("a null row", None, "the row (type NoneType) is not an object"),
        ("a bare-scalar row", 0.5, "the row (type float) is not an object"),
    ):
        check(f"[#1869] {case} is dropped LOUDLY, and with no row left the stat HIDES rather than "
              "publishing an aggregate over an empty sample",
              obs_lease_drops([row]), (None, [_LEASE_DROP.format(detail)]))
    # THE SECOND WAY A ROW LEAVES THE SAMPLE, and the likelier producer/consumer mismatch: the row
    # is a well-formed object carrying a salted label — so the guard above waves it through and the
    # decision-22 check passes — but `_obs_fraction` cannot read its `utilization_1h`. Pre-#1869
    # that row was subtracted from the sample with NO diagnostic at all, which is the same
    # confident-mean-over-the-survivors failure as a dropped non-object row and is invisible to
    # every row above (they all send readable values). Announcing only inside the `isinstance`
    # guard reds all three of these. The reject side is walked by TYPE because a guard narrowed to
    # one of them (`isinstance(raw, str)`) survives a suite that only ever sends a string.
    _LEASE_UTIL = ("dashboard-gen: dropped observability lease input (row `utilization_1h` "
                   "(type {}) is not a fraction between 0 and 1)")
    for case, value, type_name in (
        ("an unparseable string", "busy", "str"),
        ("a percentage out of the 0..1 range", 80, "int"),
        ("a boolean", True, "bool"),
        ("a nested object", {"mean": 0.4}, "dict"),
    ):
        check(f"[#1869] a lease row reporting {case} still publishes the SURVIVORS' aggregate, "
              "and the row it quietly subtracted from that sample now names itself",
              obs_lease_drops([copy.deepcopy(_KEPT_LEASE),
                               {"label": "ef56ab78b3c2d104", "provider": "anthropic",
                                "utilization_1h": value}]),
              ({"mean": 0.8, "max": 0.8}, [_LEASE_UTIL.format(type_name)]))
    # ...and the accept side of that same guard: a row that reports NO utilization is an unmeasured
    # row, not a shape mismatch, so it stays silent (#1557's reading of an explicit null, which
    # `_obs_stat` already holds one seam over). Announce every unreadable fraction unconditionally
    # — the tempting one-line form — and a collector that has simply not shipped the field yet
    # writes one warning per account per build; these two rows are what stops that.
    for case, row in (
        ("absent", {"label": "ef56ab78b3c2d104", "provider": "anthropic"}),
        ("an explicit null", {"label": "ef56ab78b3c2d104", "provider": "anthropic",
                              "utilization_1h": None}),
    ):
        check(f"[#1869] a lease row whose utilization is {case} is UNMEASURED, not malformed: it "
              "is absent from the sample and announces nothing",
              obs_lease_drops([copy.deepcopy(_KEPT_LEASE), row]),
              ({"mean": 0.8, "max": 0.8}, []))
    # DECISION 22 is why this seam is announced separately from #1571's six. A non-object row can
    # itself BE an account identity — a raw handle, or the salted fingerprint #374/#841 removed
    # from the published page — so the message may name the row's TYPE and nothing else. Echo the
    # row (or any `_obs_text` prefix of it) and the build log republishes what the page stopped
    # carrying; the last element names exactly what such a leak looks like.
    _leaky_rows = obs_lease_drops([handle, "ab12cd340a5f9e71", copy.deepcopy(_KEPT_LEASE)])
    check("[#1869] decision 22: a dropped lease row names its SHAPE and nothing out of the row — "
          "neither a raw handle nor a salted fingerprint reaches the build log diagnosing it",
          (_leaky_rows[0], _leaky_rows[1],
           [text for text in (handle, "ab12cd340a5f9e71")
            if text in "\n".join(_leaky_rows[1])]),
          ({"mean": 0.8, "max": 0.8},
           [_LEASE_DROP.format("the row (type str) is not an object")] * 2, []))
    # ...and the fatality on the rows that DO parse is untouched: turning the decision-22 raise
    # into one more drop line would read as a tolerated shape mismatch. The unreadable row comes
    # FIRST, so the drop is announced before the fatal row is reached.
    mixed_raw = copy.deepcopy(obs_fixture)
    mixed_raw["flow"]["leases"] = [None, {"label": handle, "provider": "anthropic",
                                          "utilization_1h": 0.5}]
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            _normalize_observability(mixed_raw)
            raw_still_fatal = "published"
        except DashboardError:
            raw_still_fatal = "fatal"
        except Exception as error:  # noqa: BLE001 — see `obs_lease_drops`: a guard that announces
            # the row without skipping it reaches `item.get(...)` on a non-object and raises
            # something that is NOT a DashboardError. Rendered as this row's value so it reds here
            # rather than aborting every check below (`_raises_dashboard` would let it through).
            raw_still_fatal = f"{type(error).__name__}: {error}"[:200]
    check("[#1869] announcing a dropped row does not soften the decision-22 fatality beside it — "
          "a raw handle in a row that parses is still fatal, drop diagnostic or not",
          raw_still_fatal, "fatal")
    # `flow.leases` is unbounded on the way IN and #374 publishes none of it on the way out, so
    # nothing but this seam's own `_ObsDropLog` limits the emission — the #1570 flood, exactly. The
    # 21st row still publishes: capping a WARNING must never cap the DATA. Every size and expected
    # string here is a literal; deriving either from OBS_DROP_WARN_MAX is the #941 tautology.
    check("[#1869] 20 unreadable lease rows print 12 warnings and ONE tail naming the real total, "
          "and the readable row beside them still publishes its aggregate",
          obs_lease_drops([None] * 20 + [copy.deepcopy(_KEPT_LEASE)]),
          ({"mean": 0.8, "max": 0.8},
           [_LEASE_DROP.format("the row (type NoneType) is not an object")] * 12
           + [_SUPPRESSED.format(8, _LEASE_ROWS, 20)]))
    # The lease seam and the queue seam count SEPARATELY, for the reason #1570 kept the queue and
    # evidence seams apart: one shared budget would let a flood of unreadable lease rows silence
    # the queue warning on the same document — trading one invisible loss for another — and would
    # print one tail naming the wrong seam. Ordering is fixed: the queue loop closes first.
    check("[#1869] a flooded lease seam does not consume the queue seam's budget: the lone bad "
          "queue row still names itself, and the tail names the LEASE seam",
          obs_lease_drops([None] * 20, queue_rows=[{"class": 1, "depth": 4}])[1],
          [_INT_CLASS]
          + [_LEASE_DROP.format("the row (type NoneType) is not an object")] * 12
          + [_SUPPRESSED.format(8, _LEASE_ROWS, 20)])
    try:
        with_observability = build_dashboard(
            issues, leases, usage, history, None, now, "fixture-salt", observability=obs_fixture)
    except DashboardError as error:                 # same crash-after-partial-run guard as above
        with_observability = ObsRefusal(refused=str(error))
    check("build_dashboard publishes the normalized observability key",
          with_observability.get("observability"), obs_expected)
    check("no observability input leaves data.json without the key (panel hidden)",
          "observability" in got, False)
    leak = copy.deepcopy(obs_fixture)
    leak["trigger_fires"][0]["summary"] = f"lane stalled on {handle}"
    try:
        build_dashboard(issues, leases, usage, history, None, now, "fixture-salt",
                        observability=leak)
    except DashboardError:
        leak_rejected = True
    else:
        leak_rejected = False
    check("raw handle inside observability text is caught by the privacy assertion",
          leak_rejected, True)
    empty = build_dashboard([], {"leases": []}, None, [], None, now, "fixture-salt",
                            serviced=("solo/target",))
    # [#78] Even the do-nothing case publishes a row: no catalog, no leases, no history — and the one
    # serviced repository still reports an explicit ZERO rather than being omitted, which is the
    # state pre-#78 rendered as "No agents currently active." with no repository named at all.
    check("do-nothing case", (empty["provider_quota"], empty["fleet"],
                              empty["active_by_repository"]),
          ([], {"active_agents": 0, "capacity": {}, "last_sweep_at": None,
                "dispatch_outcomes": []},
           {"models": [], "repositories": [{"repository": "solo/target", "counts": {}}]}))
    try:
        build_dashboard([], {"leases": [{
            "account": "a" * 16, "holder": "malformed", "model": "sol",
            "expires_at": now + 1,
        }]}, {}, [], None, now, "fixture-salt")
    except DashboardError:
        malformed_rejected = True
    else:
        malformed_rejected = False
    check("malformed live lease fails loudly instead of rendering empty", malformed_rejected, True)
    with tempfile.TemporaryDirectory() as directory:
        assets = Path(directory, "assets")
        assets.mkdir()
        (assets / "index.html").write_text("fixture", encoding="utf-8")
        site = Path(directory, "site")
        _write_site(empty, assets, site)
        check("site assets + JSON emitted",
              ((site / "index.html").read_text(encoding="utf-8"),
               json.loads((site / "data.json").read_text(encoding="utf-8"))["schema"]),
              ("fixture", SCHEMA))
        try:
            _write_site({"schema": SCHEMA, "poison": float("inf")}, assets, site)
        except ValueError:
            nonfinite_blocked = True
        else:
            nonfinite_blocked = False
        check("_write_site refuses non-finite numbers (allow_nan=False backstop)",
              nonfinite_blocked, True)
    print("dashboard-gen self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    # No defaults for the data-plane inputs (issue #28, review round 1): the live files sit on
    # the `ledger` branch, so a default of `data/*.json` would silently render the frozen master
    # tombstones (a falsely-empty dashboard). Callers must point at a ledger-branch checkout.
    parser.add_argument("--leases")
    parser.add_argument("--issues-file")
    parser.add_argument("--usage")
    # The probe job's persisted outcome sidecar (issue #219). REQUIRED whenever a usage snapshot is
    # in play: without it a failed probe's `{}` is indistinguishable from an idle fleet.
    parser.add_argument("--usage-status")
    parser.add_argument("--model-health")
    # Optional: the collector's observability snapshot from a `ledger`-branch checkout (issue
    # #246). Absent file => the Observability panels stay hidden; a present-but-invalid document
    # fails LOUD in _normalize_observability (never published on a guess).
    parser.add_argument("--observability")
    parser.add_argument("--assets", default="dashboard")
    parser.add_argument("--site", default="site")
    parser.add_argument("--history", type=int, default=8)
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if not args.leases or not args.model_health:
        raise DashboardError(
            "--leases and --model-health are required and must point at a `ledger`-branch "
            "checkout — the master copies under data/ are frozen tombstones (issue #28; "
            "see data/README.md)")
    if not 1 <= args.history <= 20:
        raise DashboardError("--history must be between 1 and 20")
    usage_path = _optional_usage_path(args.usage)
    if usage_path and not args.usage_status:
        # Fail-closed coupling (issue #219): dropping --usage-status from the caller would restore
        # exactly the bug — a FAILED probe's empty/partial snapshot published as fresh capacity
        # with no degradation marker — so a usage snapshot without its outcome sidecar is refused
        # rather than rendered on trust.
        raise DashboardError(
            "--usage-status is required alongside a usage snapshot (issue #219): without the "
            "probe's persisted outcome a failed measurement is indistinguishable from an idle "
            "fleet, and every catalog-available account would be published as fresh capacity")
    repo = os.environ.get("REGISTRY_REPO") or os.environ.get("GITHUB_REPOSITORY") or ""
    if args.issues_file:
        try:
            issue_text = Path(args.issues_file).read_text(encoding="utf-8")
        except OSError as exc:
            raise DashboardError("cannot read account issue fixture") from exc
        issues = _issue_list_from_text(issue_text)
    else:
        issues = _fetch_issues(repo)
    leases = _read_json(args.leases, required=True)
    usage = _read_json(usage_path, default={})
    probe_status = None
    if args.usage_status:
        try:
            # A missing or malformed sidecar degrades to the "unknown" outcome instead of taking
            # the whole public page down over one unreadable status file. `{}` and `None` are both
            # unmeasured verdicts (#612 review finding 1), so this degradation cannot publish
            # capacity either way.
            probe_status = _read_json(args.usage_status, default={})
        except DashboardError:
            probe_status = {}
        if not isinstance(probe_status, dict):
            probe_status = {}
    model_health = _read_json(args.model_health, default=None)
    observability = _read_json(args.observability, default=None)
    history, history_status = _fetch_dispatch_history(repo, args.history)
    document = build_dashboard(
        issues, leases, usage, history, model_health, int(time.time()),
        os.environ.get("PROVENANCE_SALT", ""), observability=observability,
        probe_status=probe_status, history_status=history_status)
    _write_site(document, args.assets, args.site)
    # Public workflow log: never disclose the account count (issue #184; the codebase norm in
    # model-health.py — "the public workflow log never carries provider counts").
    print(f"dashboard-gen: wrote {args.site}/data.json")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except DashboardError as exc:
        print(f"dashboard-gen: {exc}", file=sys.stderr)
        sys.exit(1)
