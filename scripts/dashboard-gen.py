#!/usr/bin/env python3
"""Build the privacy-preserving static account-fleet dashboard payload."""

import argparse
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
import zipfile


SCHEMA = "account-fleet-dashboard/v1"
WINDOWS = (("5h", "5 hour"), ("7d", "7 day"), ("fable_7d_oi", "Fable 7 day"))
ACCOUNT_REF_RE = re.compile(r"ACCT[A-Z0-9]+_TOKEN")
SAFE_PROVIDER_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")
SAFE_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}")
HOLDER_RE = re.compile(
    r"^(?:review:|fix:)?(?P<repository>"
    r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*)#\d+@\S+$")
DISPATCH_COMPLETE_RE = re.compile(
    r"^\S+\s+dispatcher complete:\s+(\d+) worker/review/fix run\(s\) launched", re.MULTILINE)
DISPATCHED_RE = re.compile(r"^\S+\s+dispatched\s", re.MULTILINE)
DEFERRED_RE = re.compile(r"^\S+\s+defer(?:red)?\s", re.MULTILINE)

# Agent-run observability (issue #246). The collector persists a snapshot of cache-effectiveness /
# per-lane run-health / flow metrics + auto-fixer trigger fires on the ledger data-plane branch
# (data/observability.json); dashboard.yml hands it in via --observability and
# _normalize_observability() validates it FAIL-CLOSED here before it may reach the public
# data.json (rendered by the dashboard's Observability panels; absent file => hidden panel).
# Decision 22: no raw account handles anywhere on the public surface — observability lease rows
# must already carry the collector's 8-hex salted label (OBS_SALTED_LABEL_RE below); anything else
# dies loudly, and _assert_private additionally backstops every known raw handle over the finished
# document. Issue #374 additionally stops the SALTED per-account rows being published at all — see
# the fleet-composition block below — but the label validation stays, because a raw handle reaching
# the collector output is a privacy incident whether or not this build would have published it.
# Issue #841: the snapshot itself is readable on the PUBLIC `ledger` branch, so this contract no
# longer REQUIRES the per-account rows either — `flow.lease_utilization_1h` may be sent already
# aggregated, and a collector that does so writes no per-account row array to a public branch.
OBS_SCHEMA = "registry-observability/v1"
OBS_SALTED_LABEL_RE = re.compile(r"[0-9a-f]{8}")
OBS_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:+-]{0,63}")
OBS_QUEUE_CLASS_RE = re.compile(r"[1-4][a-z]?")   # the #243 queue classes (1, 2, 2a..2d, 3, 4)
OBS_HISTOGRAM_KEY_RE = re.compile(r"\d{1,2}\+?")
OBS_EVIDENCE_RE = re.compile(r"https://github\.com/[A-Za-z0-9_.~!$&'()*+,;=:@/?#%-]{1,220}")
OBS_THRESHOLD_KEYS = {"workflow_failure_rate", "defer_reason_hourly",
                      "queue_age_clamp_minutes", "merge_stall_minutes"}

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
# counts it summarizes) is a count of LIVE LEASES, not of accounts — but because the catalog's
# `max_concurrent_workers` is 1, N concurrent agents implies at least N accounts, so it is a lower
# BOUND on the fleet size. It is kept because it is the dashboard's core operational number and
# because the same count is already public on the `ledger` branch (`data/leases.json`); removing it
# is a product call for the maintainer, tracked separately, not something to decide inside a
# minimization pass.
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


def _fetch_issues(repo):
    if not repo or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repo):
        raise DashboardError("REGISTRY_REPO must be an owner/repository name")
    result = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{repo}/issues?state=open&per_page=100"],
        capture_output=True, text=True, timeout=90, check=False)
    if result.returncode != 0:
        raise DashboardError("public account issue query failed")
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
    """Text of a repository file addressed relative to the repo root, independent of cwd."""
    path = Path(__file__).resolve().parent.parent.joinpath(*parts)
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DashboardError(f"wiring assertion cannot read {path}") from exc


def _strip_yaml_comments(text):
    """`text` with every whole-line `#` comment removed (YAML comments and, inside `run:` blocks,
    shell/python comments alike). A claim in prose must never satisfy an assertion about code."""
    return "\n".join(line for line in text.split("\n") if not line.lstrip().startswith("#"))


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


def _workflow_step_env(text, step_id):
    """The `env:` mapping of the step whose `id:` is `step_id`, as {NAME: raw expression text}.

    #612 review round 4: deleting `SECRETS_STEP_OUTCOME: ${{ steps.acct-secrets.outcome }}` from the
    probe step survived the suite, because the executed body reads the variable from the process
    environment the HARNESS supplies — execution can never see a missing workflow-level wiring. A
    mapping (rather than a substring search) is what makes "this step defines this variable, from
    that step's outcome" falsifiable, and resolving the step id it names is what stops the wiring
    from pointing at a step that no longer exists."""
    lines = _workflow_step(text, step_id).split("\n")
    heads = [index for index, line in enumerate(lines) if line.strip() == "env:"]
    if len(heads) != 1:
        raise DashboardError(
            f"step `id: {step_id}` has {len(heads)} `env:` mappings, expected exactly 1")
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
        raise DashboardError(f"step `id: {step_id}` has an empty `env:` mapping — refusing")
    return mapping


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


def _parse_dispatch_log(log_text):
    complete = DISPATCH_COMPLETE_RE.findall(log_text)
    dispatched = int(complete[-1]) if complete else len(DISPATCHED_RE.findall(log_text))
    deferred = len(DEFERRED_RE.findall(log_text))
    return dispatched, deferred


def _run_log_counts(repo, run_id):
    result = subprocess.run(
        ["gh", "api", f"repos/{repo}/actions/runs/{run_id}/logs"],
        capture_output=True, timeout=60, check=False)
    if result.returncode != 0:
        return None, None
    try:
        with zipfile.ZipFile(io.BytesIO(result.stdout)) as archive:
            names = [name for name in archive.namelist()
                     if "/" in name and "Strictly validate" in name and name.endswith(".txt")]
            if not names:
                return None, None
            log_text = "\n".join(
                archive.read(name).decode("utf-8", errors="replace") for name in names)
    except (OSError, zipfile.BadZipFile):
        return None, None
    return _parse_dispatch_log(log_text)


def _fetch_dispatch_history(repo, count):
    result = subprocess.run(
        ["gh", "api", f"repos/{repo}/actions/workflows/dispatch.yml/runs?per_page={count}"],
        capture_output=True, text=True, timeout=60, check=False)
    if result.returncode != 0:
        return []
    try:
        runs = json.loads(result.stdout).get("workflow_runs") or []
    except (AttributeError, json.JSONDecodeError):
        return []
    history = []
    for run in runs[:count]:
        if not isinstance(run, dict):
            continue
        dispatched, deferred = (None, None)
        if run.get("status") == "completed" and isinstance(run.get("id"), int):
            dispatched, deferred = _run_log_counts(repo, run["id"])
        history.append({
            "at": _utc_iso(run.get("run_started_at") or run.get("created_at")),
            "conclusion": str(run.get("conclusion") or run.get("status") or "unknown")[:24],
            "dispatched": dispatched,
            "deferred": deferred,
        })
    return history


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


def _normalize_ledger_health(document):
    """Canonical model-health ledger, {"records": [...]} (issue #218): validate with the shared
    model-health validator — a malformed ledger fails LOUD, never renders a fabricated check —
    then derive one status per (provider, model): the NEWEST record's exit-class, folded to
    healthy/degraded/unhealthy/unknown. Records without a model alias (zero-dispatch fleet
    signals) carry no per-model information and are skipped; account hashes never reach the
    output. Output is bounded: one check per distinct (provider, model), newest 20 pairs."""
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
    return {"generated_at": generated_at, "checks": checks}


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
    return {"generated_at": generated_at, "checks": checks}


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


def _repository_activity(live):
    counts = {}
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


def _obs_text(value, cap):
    text = str(value or "").strip()
    return text[:cap] if text and text.isprintable() else ""


def _obs_lane_rows(lanes):
    """Per-workflow (worker/review-fix/drain/groom/...) run outcomes over the 1h/24h windows.
    Lane names are declared by the collector, validated as safe tokens here — a new lane appears
    on the dashboard without a UI change. Malformed rows are dropped, not fatal."""
    rows = []
    if not isinstance(lanes, dict):
        return rows
    for name in sorted(str(key) for key in lanes):
        row = lanes.get(name)
        if (len(rows) == 12 or OBS_TOKEN_RE.fullmatch(name) is None
                or not isinstance(row, dict)):
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
    return rows


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
    return rows[:cap]


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
    return rows[:16]


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


def _obs_flow(flow):
    """Queue depth/age per class, fleet-wide lease utilization, review rounds, park rates,
    arm→merge latency, target-CI congestion. A lease row whose label is not the 8-hex salted shape
    is a raw account identity reaching the collector output — a decision-22 privacy incident,
    fatal — and since issue #374 the rows themselves are aggregated away rather than republished
    (issue #841: and since the rows sit on a PUBLIC branch, they need not be sent at all)."""
    if not isinstance(flow, dict):
        return None
    queue = []
    for item in flow.get("queue") if isinstance(flow.get("queue"), list) else []:
        if not isinstance(item, dict):
            continue
        queue_class = item.get("class")
        depth = _obs_count(item.get("depth"))
        if (not isinstance(queue_class, str)
                or OBS_QUEUE_CLASS_RE.fullmatch(queue_class) is None or depth is None):
            continue
        queue.append({"class": queue_class, "depth": depth,
                      "oldest_age_minutes": _obs_minutes(item.get("oldest_age_minutes"))})
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
    #   * rows-first precedence. A collector mid-migration that sends both keeps exactly today's
    #     published value; the new key can never silently override a fleet's real measurements.
    #   * the decision-22 label check is unconditional over the rows that ARE present. Supplying
    #     the aggregate is not a way to smuggle an unvalidated row past it, and a collector that
    #     regresses to writing rows is still caught the moment a raw handle appears in one.
    lease_utilizations = []
    for item in flow.get("leases") if isinstance(flow.get("leases"), list) else []:
        if not isinstance(item, dict):
            continue
        label = item.get("label")
        if not isinstance(label, str) or OBS_SALTED_LABEL_RE.fullmatch(label) is None:
            raise DashboardError(
                "observability lease row does not carry a salted account label (decision 22)")
        utilization = _obs_fraction(item.get("utilization_1h"))
        if utilization is not None:
            lease_utilizations.append(utilization)
    if lease_utilizations:
        lease_utilization = {
            "mean": round(sum(lease_utilizations) / len(lease_utilizations), 2),
            "max": round(max(lease_utilizations), 2),
        }
    else:
        lease_utilization = _obs_lease_aggregate(flow.get("lease_utilization_1h"))

    rounds = flow.get("review_rounds")
    review_rounds = None
    if isinstance(rounds, dict):
        mean = rounds.get("mean")
        review_rounds = {
            "mean": round(float(mean), 2)
            if isinstance(mean, (int, float)) and not isinstance(mean, bool)
            and math.isfinite(mean) and mean >= 0
            else None,
            "max": _obs_count(rounds.get("max")),
            "budget_exhausted_1h": _obs_count(rounds.get("budget_exhausted_1h")),
        }

    parks = flow.get("parks_1h")
    parks_1h = None
    if isinstance(parks, dict):
        parks_1h = {key: _obs_count(parks.get(key)) or 0
                    for key in ("needs_user", "needs_orchestrator")}

    latency = flow.get("arm_to_merge_minutes_24h")
    arm_to_merge = None
    if isinstance(latency, dict):
        arm_to_merge = {"p50": _obs_minutes(latency.get("p50")),
                        "p90": _obs_minutes(latency.get("p90")),
                        "samples": _obs_count(latency.get("samples")) or 0}

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

    return {"queue": queue[:12], "lease_utilization_1h": lease_utilization,
            "review_rounds": review_rounds,
            "parks_1h": parks_1h, "arm_to_merge_minutes_24h": arm_to_merge,
            "target_ci_queue": ci_queue[:12]}


def _obs_trigger_rows(items):
    """Auto-fixer trigger fires (fire-only alarm semantics — the collector records each fire; the
    dashboard only displays). Evidence links are pinned to github.com — anything else is dropped
    loudly rather than published on the public page."""
    rows = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        rule = item.get("rule")
        if not isinstance(rule, str) or OBS_TOKEN_RE.fullmatch(rule) is None:
            continue
        evidence = []
        for link in (item.get("evidence") if isinstance(item.get("evidence"), list) else [])[:8]:
            if isinstance(link, str) and OBS_EVIDENCE_RE.fullmatch(link):
                evidence.append(link)
            else:
                print("dashboard-gen: dropped a non-GitHub observability evidence link")
        task = item.get("enqueued_task")
        rows.append({
            "rule": rule,
            "fired_at": _utc_iso(item.get("fired_at")),
            "summary": _obs_text(item.get("summary"), 240),
            "evidence": evidence[:5],
            "enqueued_task": task if isinstance(task, str)
            and OBS_TOKEN_RE.fullmatch(task) else None,
        })
    rows.sort(key=lambda row: row["fired_at"] or "", reverse=True)
    return rows[:20]


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
        histogram = {}
        raw_histogram = cache_source.get("chain_length_histogram")
        if isinstance(raw_histogram, dict):
            for key in sorted(str(k) for k in raw_histogram)[:12]:
                count = _obs_count(raw_histogram.get(key))
                if OBS_HISTOGRAM_KEY_RE.fullmatch(key) and count is not None:
                    histogram[key] = count
        cache = {
            "prompt_cache_read_fraction_1h":
                _obs_fraction(cache_source.get("prompt_cache_read_fraction_1h")),
            "usage_samples_1h": _obs_count(cache_source.get("usage_samples_1h")) or 0,
            "warm_drain_rate_1h": _obs_fraction(cache_source.get("warm_drain_rate_1h")),
            "drained_1h": _obs_count(cache_source.get("drained_1h")) or 0,
            "chain_length_histogram": histogram,
        }

    thresholds_source = document.get("thresholds")
    thresholds = None
    if isinstance(thresholds_source, dict):
        thresholds = {}
        for key in OBS_THRESHOLD_KEYS:
            value = thresholds_source.get(key)
            if (isinstance(value, (int, float)) and not isinstance(value, bool)
                    and math.isfinite(value) and value >= 0):
                thresholds[key] = value

    return {
        "generated_at": _utc_iso(document.get("generated_at")),
        "cache": cache,
        "lanes": _obs_lane_rows(document.get("lanes")),
        "defer_reasons_1h": _obs_counted_rows(document.get("defer_reasons_1h"), "reason", 16),
        "model_exit_classes_1h": _obs_exit_rows(document.get("model_exit_classes_1h")),
        "flow": _obs_flow(document.get("flow")),
        "trigger_fires": _obs_trigger_rows(document.get("trigger_fires")),
        "thresholds": thresholds,
    }


def build_dashboard(issues, leases_document, usage, dispatch_history, model_health, now, salt,
                    observability=None, probe_status=None):
    accounts, private_values = _catalog(issues)
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
        "active_by_repository": _repository_activity(live),
        "model_health": _normalize_model_health(model_health),
    }
    # Degradation marker (issue #219): the page renders probe age + failure so a stale or failed
    # measurement is visible instead of silently looking like a fresh, idle fleet. ALWAYS present
    # (#612 review finding 1) — it used to be omitted on exactly the branch that also trusted the
    # usage map unconditionally, so the one state that most needed a warning carried none.
    document["usage_probe"] = probe
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


def _self_test():
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

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
    history = [{"at": "2025-06-15T15:05:00Z", "conclusion": "success",
                "dispatched": 2, "deferred": 3}]
    got = build_dashboard(issues, leases, usage, history, None, now, "fixture-salt",
                          probe_status=measured_sidecar)
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
    }
    check("fixture leases + limits -> expected JSON", got, expected)
    check("dispatch log counts", _parse_dispatch_log(
        "2025-01-01Z dispatched worker owner/repo#1\n"
        "2025-01-01Z defer owner/repo#2: busy\n"
        "2025-01-01Z dispatcher complete: 1 worker/review/fix run(s) launched\n"), (1, 1))
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
    def clone_fleet(size, busy=0):
        """`size` identical accounts, the first `busy` of them holding one live lease each."""
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
                clone_leases.append({
                    "account": hashlib.sha256(
                        f"{clone_handle}:fixture-salt".encode()).hexdigest()[:16],
                    "claim_id": f"{index:x}" * 32, "holder": f"owner/repo#{index + 1}@run.1",
                    "package": "pkg", "role": "impl", "model": "opus",
                    "issued_at": now - 60, "expires_at": now + 60})
        built = build_dashboard(clone_issues, {"leases": clone_leases}, clone_usage, history, None,
                                now, "fixture-salt", probe_status=measured_sidecar)
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
    ]}
    ordered = build_dashboard(
        ordered_issues, activity_leases, ordered_usage, [], health_ledger, now, "fixture-salt",
        probe_status=measured_sidecar)
    check("canonical records ledger -> per-provider/model checks", ordered["model_health"], {
        "generated_at": _utc_iso(now - 120),
        "checks": [
            {"model": "fable", "provider": "anthropic", "status": "healthy",
             "checked_at": _utc_iso(now - 600)},
            {"model": "codex", "provider": "openai", "status": "degraded",
             "checked_at": _utc_iso(now - 300)},
        ],
    })
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
    check("repo/model table parses impl + review + fix and excludes expired", [
        ordered["fleet"]["active_agents"], ordered["active_by_repository"]
    ], [3, {
        "models": ["fable", "opus", "sol"],
        "repositories": [
            {"repository": "org/alpha", "counts": {"sol": 1, "fable": 1}},
            {"repository": "org/beta", "counts": {"opus": 1}},
        ],
    }])
    check("expanded fixture preserves private account identities",
          all(account_handle not in json.dumps(ordered) for account_handle in ordered_handles), True)

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

    def main_document(sidecar):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, payload in (("issues.json", issues), ("usage.json", live_usage),
                                  ("leases.json", leases),
                                  ("model-health.json", {"records": []}),
                                  ("usage-probe.json", sidecar)):
                Path(root, name).write_text(json.dumps(payload), encoding="utf-8")
            saved_history = globals()["_fetch_dispatch_history"]
            saved_salt = os.environ.get("PROVENANCE_SALT")
            globals()["_fetch_dispatch_history"] = lambda repo, count: []
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
                           & set(re.findall(r'"([^"]+)":', json.dumps(published)))))

    check("[#612] main() forwards a FRESH sidecar, so a healthy run still publishes capacity",
          main_document({"schema": PROBE_SCHEMA, "outcome": "ok", "detail": "probe-succeeded",
                         "attempted_at": live_now}),
          (True, "available", {"anthropic": True}, []))
    check("[#612] main() forwards a FAILED sidecar, so the same run publishes none",
          main_document({"schema": PROBE_SCHEMA, "outcome": "failed",
                         "detail": "probe-exited-nonzero", "attempted_at": live_now}),
          (False, "unknown", {"anthropic": False}, []))

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
    # --- ...and the two call sites EXECUTED. The page is loaded into a minimal DOM shim under node
    # and handed the real generated document, so `if (!measured)` -> `if (measured)`, dropping
    # `summary.append(probe)`, or dropping updateFreshness's second argument each change an OUTCOME
    # rather than a substring. `fetch` is stubbed to reject (the page's own load path is not under
    # test) and `setInterval` to a no-op so node exits.
    # ------------------------------------------------------------------------------------------
    page_harness = r"""
const fs = require("fs");
const source = fs.readFileSync(__APP_JS__, "utf8");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
function element(tag) {
  const self = {
    tagName: tag, children: [], attributes: {}, style: {}, hidden: false, textContent: "",
    className: "", classes: new Set(),
    append: (...kids) => { for (const kid of kids) self.children.push(kid); },
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
  // and writes to #warning; the tick below lets that settle so it cannot be mistaken for the
  // probe notice under test, and every render below starts from a fresh #warning element.
  const scope = new Function(source + "; return { usageProbeCard, updateFreshness, render };")();
  await new Promise((resolve) => setImmediate(resolve));
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
    scope.render(document_);
    warnings[name] = {
      hidden: ids.warning.hidden,
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
  process.stdout.write(JSON.stringify({ cards, warnings }));
})().catch((error) => { console.error(error && error.stack || error); process.exit(1); });
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
    page = _node_json(
        page_harness.replace("__APP_JS__",
                             json.dumps(str(Path(__file__).resolve().parent.parent
                                            / "dashboard" / "app.js"))),
        {"probes": {"measured": measured_document["usage_probe"],
                    "failed": failed_document["usage_probe"],
                    "absent": None},
         "documents": {"measured": measured_document, "failed": failed_document,
                       "staleFailed": stale_failed_document}})
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

    health = _normalize_model_health({
        "generated_at": now,
        "models": [{"model": "fable", "provider": "anthropic", "status": "ok"}],
    })
    check("optional model-health normalization", health,
          {"generated_at": "2025-06-15T15:06:40Z",
           "checks": [{"model": "fable", "provider": "anthropic",
                       "status": "healthy", "checked_at": None}]})

    # --- observability normalization (issue #246): accept path is a GOLDEN fixture (every field
    # class exercised, every malformed row visibly dropped), reject paths are explicit. ---------
    obs_fixture = {
        "schema": "registry-observability/v1",
        "generated_at": now,
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
                 "leases": [{"label": "ab12cd34", "provider": "anthropic",
                             "utilization_1h": 0.8},
                            {"label": "ef56ab78", "provider": "anthropic",
                             "utilization_1h": 0.4},
                            {"label": "cd90ef12", "provider": "openai"}],
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
        "cache": {"prompt_cache_read_fraction_1h": 0.62, "usage_samples_1h": 7,
                  "warm_drain_rate_1h": 0.5, "drained_1h": 12,
                  "chain_length_histogram": {"1": 4, "2": 3, "5+": 1}},
        "lanes": [
            {"lane": "review-fix", "1h": {"success": 1, "failure": 0, "defer": 0}, "24h": None},
            {"lane": "worker", "1h": {"success": 3, "failure": 1, "defer": 2},
             "24h": {"success": 30, "failure": 4, "defer": 9}}],
        "defer_reasons_1h": [{"reason": "trust-gate-missing", "count": 9},
                             {"reason": "partial-disarm", "count": 7}],
        "model_exit_classes_1h": [{"model": "terra", "exit_class": "no-changes", "count": 8},
                                  {"model": "fable", "exit_class": "success", "count": 3}],
        "flow": {"queue": [{"class": "2a", "depth": 1, "oldest_age_minutes": 12.3},
                           {"class": "4", "depth": 9, "oldest_age_minutes": 3.0}],
                 # [#374] three validated lease rows in, ZERO published: only the mean/max of the
                 # utilizations that parsed (0.8, 0.4 -> 0.6/0.8). The unparseable third row proves
                 # the aggregate is taken over reporting rows, and the count itself never appears.
                 "lease_utilization_1h": {"mean": 0.6, "max": 0.8},
                 "review_rounds": {"mean": 1.44, "max": 3, "budget_exhausted_1h": 0},
                 "parks_1h": {"needs_user": 2, "needs_orchestrator": 1},
                 "arm_to_merge_minutes_24h": {"p50": 18.0, "p90": 55.5, "samples": 9},
                 "target_ci_queue": [{"repository": "sparq-org/sparq", "depth": 5}]},
        "trigger_fires": [
            {"rule": "worker-failure-rate", "fired_at": "2025-06-15T15:01:40Z",
             "summary": "worker failure rate 67% over 3 consecutive runs",
             "evidence": ["https://github.com/jeswr/agent-account-registry/actions/runs/1"],
             "enqueued_task": "heal-2a-0001"}],
        "thresholds": {"workflow_failure_rate": 0.5, "defer_reason_hourly": 4,
                       "queue_age_clamp_minutes": 10, "merge_stall_minutes": 90},
    }
    check("observability golden normalization (bad rows dropped, top-N sorted, links pinned)",
          _normalize_observability(obs_fixture), obs_expected)
    check("absent observability snapshot stays hidden (None)",
          _normalize_observability(None), None)
    overflow = copy.deepcopy(obs_fixture)
    overflow["flow"]["review_rounds"]["mean"] = 1e309       # JSON 1e309 decodes to +Infinity
    overflow["thresholds"]["workflow_failure_rate"] = 1e309
    overflow_normalized = _normalize_observability(overflow)
    check("non-finite review-round mean is rejected, never published",
          overflow_normalized["flow"]["review_rounds"]["mean"], None)
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
        return _normalize_observability(fixture)["flow"]

    one_lease = obs_leases([{"label": "ab12cd34", "provider": "anthropic",
                             "utilization_1h": 0.5}])
    four_leases = obs_leases([{"label": f"ab12cd3{index}", "provider": "anthropic",
                               "utilization_1h": 0.5} for index in range(4)])
    check("[#374] lease rows of different fleet sizes normalize to the same published flow",
          (one_lease, one_lease == four_leases,
           "ab12cd34" in json.dumps(one_lease)),
          (four_leases, True, False))
    check("[#374] no reported lease utilization publishes nothing rather than a zero",
          obs_leases([])["lease_utilization_1h"], None)
    # ---- [#841] the ROW-FREE collector contract. #374 stopped this build PUBLISHING the rows; it
    # did not stop them EXISTING at data/observability.json on the public `ledger` branch. So the
    # aggregate is accepted directly and a collector need write no per-account rows anywhere.
    def obs_flow_without_rows(aggregate):
        fixture = copy.deepcopy(obs_fixture)
        fixture["flow"].pop("leases", None)          # the collector sends NO per-account rows
        fixture["flow"]["lease_utilization_1h"] = aggregate
        return _normalize_observability(fixture)["flow"]["lease_utilization_1h"]

    check("[#841] a collector that sends NO lease rows still publishes the aggregate it computed",
          obs_flow_without_rows({"mean": 0.31, "max": 0.77}), {"mean": 0.31, "max": 0.77})
    # Precedence is ROWS-FIRST and total, so a collector mid-migration that sends both publishes
    # exactly its pre-#841 value — the new key can never silently override real measurements.
    # Flipping the precedence turns this into {0.99, 0.99}.
    both = copy.deepcopy(obs_fixture)
    both["flow"]["lease_utilization_1h"] = {"mean": 0.99, "max": 0.99}
    check("[#841] lease ROWS outrank a collector-supplied aggregate (no silent override)",
          _normalize_observability(both)["flow"]["lease_utilization_1h"],
          {"mean": 0.6, "max": 0.8})
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
    with_observability = build_dashboard(
        issues, leases, usage, history, None, now, "fixture-salt", observability=obs_fixture)
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
    empty = build_dashboard([], {"leases": []}, None, [], None, now, "fixture-salt")
    check("do-nothing case", (empty["provider_quota"], empty["fleet"],
                              empty["active_by_repository"]),
          ([], {"active_agents": 0, "capacity": {}, "last_sweep_at": None,
                "dispatch_outcomes": []}, {"models": [], "repositories": []}))
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
    history = _fetch_dispatch_history(repo, args.history)
    document = build_dashboard(
        issues, leases, usage, history, model_health, int(time.time()),
        os.environ.get("PROVENANCE_SALT", ""), observability=observability,
        probe_status=probe_status)
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
