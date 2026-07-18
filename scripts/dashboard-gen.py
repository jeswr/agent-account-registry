#!/usr/bin/env python3
"""Build the privacy-preserving static account-fleet dashboard payload."""

import argparse
import copy
import datetime as dt
import hashlib
import hmac
import io
import json
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


def _normalize_model_health(document):
    if document is None:
        return None
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
            if isinstance(mean, (int, float)) and not isinstance(mean, bool) and mean >= 0
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
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
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
        json.dump(document, handle, indent=2, sort_keys=True)
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
    ordered = build_dashboard(
        ordered_issues, activity_leases, ordered_usage, [], None, now, "fixture-salt")
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
