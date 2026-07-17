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


def build_dashboard(issues, leases_document, usage, dispatch_history, model_health, now, salt):
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
    history = _fetch_dispatch_history(repo, args.history)
    document = build_dashboard(
        issues, leases, usage, history, model_health, int(time.time()),
        os.environ.get("PROVENANCE_SALT", ""))
    _write_site(document, args.assets, args.site)
    print(f"dashboard-gen: wrote {args.site}/data.json with {len(document['accounts'])} account(s)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except DashboardError as exc:
        print(f"dashboard-gen: {exc}", file=sys.stderr)
        sys.exit(1)
