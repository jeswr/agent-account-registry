#!/usr/bin/env python3
"""Build the privacy-preserving static account-fleet dashboard payload."""

import argparse
import copy
import datetime as dt
import hashlib
import hmac
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
# Decision 22: no raw account handles anywhere on the public surface — lease rows must already
# carry the 8-hex salted label (the _salted_labels shape); anything else dies loudly, and
# _assert_private additionally backstops every known raw handle over the finished document.
OBS_SCHEMA = "registry-observability/v1"
OBS_SALTED_LABEL_RE = re.compile(r"[0-9a-f]{8}")
OBS_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:+-]{0,63}")
OBS_QUEUE_CLASS_RE = re.compile(r"[1-4][a-z]?")   # the #243 queue classes (1, 2, 2a..2d, 3, 4)
OBS_HISTOGRAM_KEY_RE = re.compile(r"\d{1,2}\+?")
OBS_EVIDENCE_RE = re.compile(r"https://github\.com/[A-Za-z0-9_.~!$&'()*+,;=:@/?#%-]{1,220}")
OBS_THRESHOLD_KEYS = {"workflow_failure_rate", "defer_reason_hourly",
                      "queue_age_clamp_minutes", "merge_stall_minutes"}


class DashboardError(RuntimeError):
    pass


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


def _salted_labels(handles, salt):
    if not salt:
        return {handle: "salt-missing" for handle in handles}
    labels = {
        handle: hmac.new(salt.encode(), handle.encode(), hashlib.sha256).hexdigest()[:8]
        for handle in handles
    }
    if len(set(labels.values())) != len(labels):
        raise DashboardError("salted account label collision")
    return labels


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
    if not isinstance(usage_entry, dict):
        return "available"
    status = str(usage_entry.get("status") or "").strip().lower()
    if status not in {"", "allowed"}:
        return "unavailable"
    known = [_percent(usage_entry.get(f"{prefix}_util")) for prefix, _ in WINDOWS]
    if any(value is not None and value >= 100 for value in known):
        return "capped"
    return "available"


def _window_rows(account, usage_entry):
    usage_entry = usage_entry if isinstance(usage_entry, dict) else {}
    rows = []
    for prefix, name in WINDOWS:
        used = _percent(usage_entry.get(f"{prefix}_util"))
        reset = _utc_iso(usage_entry.get(f"{prefix}_reset"))
        limit = usage_entry.get(f"{prefix}_limit")
        if limit is None:
            limit = account["limits"].get(f"{prefix}_limit")
        if prefix == "fable_7d_oi" and used is None and reset is None and limit is None:
            continue
        rows.append({
            "name": name,
            "used_percent": used,
            "reset_at": reset,
            "limit": str(limit) if limit is not None else None,
        })
    return rows


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
    """Availability for the CUMULATIVE provider view: the per-account trichotomy from
    _availability, except that (a) a catalog-available account with NO usage entry — the probe
    fail-closed OMITS an account whose token is missing or whose probe failed — is "unknown":
    dispatch (select-and-claim.usage_eligible) and usage-alert treat that omission as
    UNAVAILABLE, so counting it free here would advertise quota the allocator will never use
    (sol finding 2, PR #281 fix round); and (b) a probe-exempt account under an ACTIVE reactive
    backoff (its only quota signal — issue #29) counts as capped until the backoff expires,
    with the stamp parsed by the allocator's shared `_backoff_epoch` semantics. Returns
    (state, backoff_epoch_or_None). Pure — unit-tested by --self-test."""
    availability = _availability(account, entry)
    if availability != "available":
        return availability, None
    if not isinstance(entry, dict) or not entry:
        return "unknown", None
    if entry.get("exempt") is True:
        until = _backoff_epoch(entry.get("backoff_until"))
        if until is not None and until > now:
            return "capped", until
    return "available", None


def _provider_quota(accounts, usage, now):
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
    NEVER counted free), and never in `accounts_reporting`. `soonest_reset`/`oldest_reset` span
    every known window-reset/backoff stamp for the provider: soonest = the first moment ANY
    quota refills, oldest = when the last known window has refilled. Pure — unit-tested by
    --self-test; rows carry provider names + counts only (decision 22: no account identifiers,
    salted or otherwise, on this surface)."""
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
                except (TypeError, ValueError):
                    limit_number = None
                if limit_number is not None and math.isfinite(limit_number) and limit_number >= 0:
                    window["limits_known"] += 1
                    window["limit_remaining"] += limit_number * remaining
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
        if probed and exempt:
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


def _obs_flow(flow):
    """Queue depth/age per class, salted lease utilization, review rounds, park rates, arm→merge
    latency, target-CI congestion. A lease row whose label is not the 8-hex salted shape is a raw
    account identity reaching the collector output — a decision-22 privacy incident, fatal."""
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

    leases = []
    for item in flow.get("leases") if isinstance(flow.get("leases"), list) else []:
        if not isinstance(item, dict):
            continue
        label = item.get("label")
        if not isinstance(label, str) or OBS_SALTED_LABEL_RE.fullmatch(label) is None:
            raise DashboardError(
                "observability lease row does not carry a salted account label (decision 22)")
        provider = str(item.get("provider") or "").lower()
        leases.append({"label": label,
                       "provider": provider if SAFE_PROVIDER_RE.fullmatch(provider) else None,
                       "utilization_1h": _obs_fraction(item.get("utilization_1h"))})

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

    return {"queue": queue[:12], "leases": leases[:40], "review_rounds": review_rounds,
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
                    observability=None):
    accounts, private_values = _catalog(issues)
    handles = [account["handle"] for account in accounts]
    labels = _salted_labels(handles, salt)
    usage = usage if isinstance(usage, dict) else {}
    leases = leases_document.get("leases") if isinstance(leases_document, dict) else None
    if not isinstance(leases, list):
        raise DashboardError("lease ledger must contain a leases array")
    live = _live_leases(leases, now)
    private_values.update(str(lease.get("account")) for lease in leases if lease.get("account"))
    private_values.update(str(handle) for handle in usage)

    rows = []
    capacity = {}
    for account in accounts:
        entry = usage.get(account["handle"])
        availability = _availability(account, entry)
        provider_capacity = capacity.setdefault(
            account["provider"], {"eligible": 0, "total": 0})
        provider_capacity["total"] += 1
        if availability == "available":
            provider_capacity["eligible"] += 1
        weekly_reset_at = _utc_iso(entry.get("7d_reset")) if isinstance(entry, dict) else None
        rows.append({
            "label": labels[account["handle"]],
            "provider": account["provider"],
            "availability": availability,
            "active_agents": sum(1 for lease in live if lease.get("account") == account["handle"]),
            "weekly_reset_at": weekly_reset_at,
            "windows": _window_rows(account, entry),
        })
    rows.sort(key=lambda row: (
        row["provider"], row["weekly_reset_at"] is None,
        row["weekly_reset_at"] or "", row["label"]))
    history = dispatch_history if isinstance(dispatch_history, list) else []
    document = {
        "schema": SCHEMA,
        "generated_at": _utc_iso(now),
        "accounts": rows,
        # Cumulative per-provider headroom (maintainer request 2026-07-18) — rendered by the
        # dashboard's "Provider quota (cumulative)" section, above the per-account cards.
        "provider_quota": _provider_quota(accounts, usage, now),
        "fleet": {
            "active_agents": len(live),
            "capacity": capacity,
            "last_sweep_at": history[0].get("at") if history else None,
            "dispatch_outcomes": history,
        },
        "active_by_repository": _repository_activity(live),
        "model_health": _normalize_model_health(model_health),
    }
    observability = _normalize_observability(observability)
    if observability is not None:
        # Optional key (absent => the dashboard hides the Observability panels), placed INSIDE the
        # document so the raw-identity assertion below covers every observability string too.
        document["observability"] = observability
    _assert_private(document, private_values)
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

    now = 1_750_000_000
    handle = "acct-fixture"
    email = "private@example.invalid"
    issues = [{
        "title": handle,
        "labels": [{"name": "status:available"}],
        "body": ("provider: anthropic\nmodels: [opus]\nsecret_ref: ACCTFIXTURE_TOKEN\n"
                 f"email: {email}\nlimits: 5h_limit=1000 7d_limit=7000\n"),
    }]
    leases = {"leases": [
        {"account": handle, "holder": "owner/repo#7@run.1", "model": "opus",
         "expires_at": now + 60},
        {"account": handle, "expires_at": now - 1},
    ]}
    usage = {handle: {"status": "allowed", "5h_util": "0.42", "5h_reset": now + 3600,
                      "7d_util": "0.8", "7d_reset": now + 86400}}
    history = [{"at": "2025-06-15T15:05:00Z", "conclusion": "success",
                "dispatched": 2, "deferred": 3}]
    got = build_dashboard(issues, leases, usage, history, None, now, "fixture-salt")
    expected = {
        "schema": SCHEMA,
        "generated_at": "2025-06-15T15:06:40Z",
        "accounts": [{
            "label": "b01f153c", "provider": "anthropic", "availability": "available",
            "active_agents": 1,
            "weekly_reset_at": "2025-06-16T15:06:40Z",
            "windows": [
                {"name": "5 hour", "used_percent": 42.0,
                 "reset_at": "2025-06-15T16:06:40Z", "limit": "1000"},
                {"name": "7 day", "used_percent": 80.0,
                 "reset_at": "2025-06-16T15:06:40Z", "limit": "7000"},
            ],
        }],
        "provider_quota": [{
            "provider": "anthropic", "accounts_total": 1, "accounts_available": 1,
            "accounts_capped": 0, "accounts_unavailable": 0, "accounts_unknown": 0,
            "single_account": True,
            "signal": "live rate-limit-header probe (per-window utilization)",
            "windows": [
                {"name": "5 hour", "accounts_reporting": 1, "remaining_account_windows": 0.58,
                 "limit_remaining": 580, "limits_known": 1,
                 "soonest_reset": "2025-06-15T16:06:40Z", "oldest_reset": "2025-06-15T16:06:40Z"},
                {"name": "7 day", "accounts_reporting": 1, "remaining_account_windows": 0.2,
                 "limit_remaining": 1400, "limits_known": 1,
                 "soonest_reset": "2025-06-16T15:06:40Z", "oldest_reset": "2025-06-16T15:06:40Z"},
            ],
            "soonest_reset": "2025-06-15T16:06:40Z", "oldest_reset": "2025-06-16T15:06:40Z",
        }],
        "fleet": {
            "active_agents": 1,
            "capacity": {"anthropic": {"eligible": 1, "total": 1}},
            "last_sweep_at": "2025-06-15T15:05:00Z",
            "dispatch_outcomes": history,
        },
        "active_by_repository": {
            "models": ["opus"],
            "repositories": [{"repository": "owner/repo", "counts": {"opus": 1}}],
        },
        "model_health": None,
    }
    check("fixture leases + limits -> expected JSON", got, expected)
    check("dispatch log counts", _parse_dispatch_log(
        "2025-01-01Z dispatched worker owner/repo#1\n"
        "2025-01-01Z defer owner/repo#2: busy\n"
        "2025-01-01Z dispatcher complete: 1 worker/review/fix run(s) launched\n"), (1, 1))
    check("raw identity absent", handle not in json.dumps(got) and email not in json.dumps(got), True)
    leaky = copy.deepcopy(got)
    leaky["accounts"][0]["debug"] = handle
    try:
        _assert_private(leaky, {handle})
    except DashboardError:
        rejected = True
    else:
        rejected = False
    check("privacy assertion rejects injected raw handle", rejected, True)
    no_salt = build_dashboard(issues, {"leases": []}, {}, [], None, now, "")
    check("missing salt fails closed", no_salt["accounts"][0]["label"], "salt-missing")

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
        "openai-one": {"exempt": True},
        "future-one": {"status": "allowed", "7d_reset": now + 500},
    }
    activity_leases = {"leases": [
        {"account": "anth-soon", "holder": "org/alpha#1@run.1", "model": "sol",
         "expires_at": now + 30},
        {"account": "anth-late", "holder": "review:org/alpha#2@run.1", "model": "fable",
         "expires_at": now + 20},
        {"account": "anth-unknown", "holder": "fix:org/beta#3@run.1", "model": "opus",
         "expires_at": now + 10},
        {"account": "expired-private", "holder": "org/expired#4@old", "model": "terra",
         "expires_at": now - 1},
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
        ordered_issues, activity_leases, ordered_usage, [], health_ledger, now, "fixture-salt")
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
    salted = _salted_labels(ordered_handles, "fixture-salt")
    check("providers grouped + weekly resets soonest first + unknown last", [
        (row["provider"], row["label"], row["weekly_reset_at"])
        for row in ordered["accounts"]
    ], [
        ("anthropic", salted["anth-soon"], _utc_iso(now + 100)),
        ("anthropic", salted["anth-late"], _utc_iso(now + 900)),
        ("anthropic", salted["anth-unknown"], None),
        ("future-provider", salted["future-one"], _utc_iso(now + 500)),
        ("openai", salted["openai-one"], None),
    ])
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
        "solo-openai": {"exempt": True, "backoff_until": now + 300},
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
        entry = {"exempt": True, "backoff_until": stamp}
        state, _until = _quota_state(exempt_account, entry, now)
        check(f"backoff stamp {str(stamp)[:24]!r}: dashboard capped == allocator excluded",
              (state == "capped", not allocator.usage_eligible(entry, now=now)),
              (want_capped, want_capped))
    check("cumulative quota: expired backoff no longer counts as capped",
          [(row["accounts_available"], row["accounts_capped"]) for row in _provider_quota(
              quota_accounts[3:], {"solo-openai": {"exempt": True, "backoff_until": now - 1}},
              now)],
          [(1, 0)])
    check("cumulative quota rows carry no raw account identifier (decision 22)",
          all(h not in json.dumps(quota_rows) for h in quota_handles), True)
    check("ordered fixture publishes one cumulative row per provider, single-account marked",
          [(row["provider"], row["accounts_total"], row["single_account"])
           for row in ordered["provider_quota"]],
          [("anthropic", 3, False), ("future-provider", 1, True), ("openai", 1, True)])

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
                             "utilization_1h": 0.8}],
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
                 "leases": [{"label": "ab12cd34", "provider": "anthropic",
                             "utilization_1h": 0.8}],
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
    check("do-nothing case", (empty["accounts"], empty["fleet"],
                              empty["active_by_repository"]),
          ([], {"active_agents": 0, "capacity": {}, "last_sweep_at": None,
                "dispatch_outcomes": []}, {"models": [], "repositories": []}))
    try:
        build_dashboard([], {"leases": [{
            "account": "private-live", "holder": "malformed", "model": "sol",
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
    usage = _read_json(_optional_usage_path(args.usage), default={})
    model_health = _read_json(args.model_health, default=None)
    observability = _read_json(args.observability, default=None)
    history = _fetch_dispatch_history(repo, args.history)
    document = build_dashboard(
        issues, leases, usage, history, model_health, int(time.time()),
        os.environ.get("PROVENANCE_SALT", ""), observability=observability)
    _write_site(document, args.assets, args.site)
    print(f"dashboard-gen: wrote {args.site}/data.json with {len(document['accounts'])} account(s)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except DashboardError as exc:
        print(f"dashboard-gen: {exc}", file=sys.stderr)
        sys.exit(1)
