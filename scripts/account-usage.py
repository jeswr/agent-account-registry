#!/usr/bin/env python3
# [OPUS-4.8] Probe live per-account usage for usage-aware dispatch. Emits a JSON map
#   {handle: {"status","5h_util","5h_reset","7d_util","7d_reset"}}   for anthropic accounts
#   {handle: {"exempt": true}}                                        for non-metered providers (codex)
# to stdout. Each anthropic token is probed with a max_tokens:1 POST /v1/messages and the
# anthropic-ratelimit-unified-* response headers are read. Tokens come from SECRETS_JSON (toJSON(secrets))
# by each account's secret_ref and are NEVER printed. FAIL-CLOSED: an account whose token is missing or
# whose probe returns no rate-limit headers is OMITTED from the map, so choose_account() will skip it.
import importlib.util
import json
import os
import subprocess
import sys


def _probe_anthropic(token):
    try:
        proc = subprocess.run(
            ["curl", "-s", "-D", "-", "-o", "/dev/null", "--max-time", "20", "-X", "POST",
             "https://api.anthropic.com/v1/messages",
             "-H", "Authorization: Bearer " + token,
             "-H", "anthropic-version: 2023-06-01",
             "-H", "content-type: application/json",
             "-H", "anthropic-beta: oauth-2025-04-20",
             "-d", '{"model":"claude-haiku-4-5","max_tokens":1,'
                   '"messages":[{"role":"user","content":"hi"}]}'],
            capture_output=True, text=True, timeout=30, check=False)
    except (subprocess.SubprocessError, OSError):
        return None
    hdr = {}
    for line in proc.stdout.splitlines():
        low = line.lower()
        if low.startswith("anthropic-ratelimit-unified-") and ":" in line:
            key, _, val = line.partition(":")
            hdr[key.strip().lower()] = val.strip()

    def g(suffix):
        return hdr.get("anthropic-ratelimit-unified-" + suffix)

    if g("status") is None:
        return None  # no rate-limit headers (e.g. 401/blocked) -> fail-closed omit
    return {"status": g("status"),
            "5h_util": g("5h-utilization"), "5h_reset": g("5h-reset"),
            "7d_util": g("7d-utilization"), "7d_reset": g("7d-reset")}


def _load_accounts(script_dir, registry_repo):
    spec = importlib.util.spec_from_file_location(
        "registry_select_and_claim", os.path.join(script_dir, "select-and-claim.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.read_accounts(registry_repo)


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    registry_repo = os.environ["REGISTRY_REPO"]
    secrets = json.loads(os.environ.get("SECRETS_JSON", "{}"))
    pool = json.loads(os.environ.get("ACCOUNT_POOL", "[]"))  # optional handle allow-list
    usage = {}
    for account in _load_accounts(script_dir, registry_repo):
        handle = account["handle"]
        if pool and handle not in pool:
            continue
        if str(account.get("provider", "")).lower() != "anthropic":
            usage[handle] = {"exempt": True}
            continue
        token = secrets.get(account.get("secret_ref"))
        if not token:
            continue  # fail-closed omit
        probed = _probe_anthropic(token)
        if probed is not None:
            usage[handle] = probed
    json.dump(usage, sys.stdout)


if __name__ == "__main__":
    main()
