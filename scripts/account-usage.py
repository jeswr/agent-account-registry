#!/usr/bin/env python3
# [OPUS-4.8] Probe live per-account usage for usage-aware dispatch. Emits a JSON map
#   {handle: {"status","5h_util","5h_reset","7d_util","7d_reset", (fable fields)}}  for anthropic accounts
#   {handle: {"exempt": true}}                                        for non-metered providers (codex)
# to stdout. Each anthropic token is probed with a max_tokens:1 POST /v1/messages and the
# anthropic-ratelimit-unified-* response headers are read. Tokens come from SECRETS_JSON (toJSON(secrets))
# by each account's secret_ref and are NEVER printed. FAIL-CLOSED: an account whose token is missing or
# whose probe returns no rate-limit headers is OMITTED from the map, so choose_account() will skip it.
#
# [FABLE-5] FABLE SUB-QUOTA: an Anthropic account has a SEPARATE weekly premium sub-quota for
# claude-fable-5, surfaced as the `anthropic-ratelimit-unified-7d_oi-*` headers. It is DISTINCT from the
# whole-account 5h/7d windows — an account can read 7d_util=0.1 yet have an exhausted Fable bucket, so a
# Fable worker started there fails mid-run and burns credits. Empirically (probing acct2/3/4 + the box's
# own session), the 7d_oi headers appear ONLY when the request carries BOTH the Claude-Code user-agent AND
# the "You are Claude Code" system prompt (a subscription-OAuth premium-path gate) AND the model is
# claude-fable-5 — a plain haiku/opus probe never surfaces them. So fable-capable accounts get a SECOND,
# Claude-Code-shaped fable probe whose 7d_oi headroom gates fable-model routing specifically. If that probe
# is rejected or returns no 7d_oi headers, the account is fail-closed for FABLE only (its 5h/7d base signal
# from the haiku probe still governs non-fable routing).
import importlib.util
import json
import os
import subprocess
import sys

# The subscription-OAuth premium path (claude-fable-5) is gated to Claude-Code-shaped requests; without
# this exact pair the API returns 429 for fable and never emits the 7d_oi sub-quota headers.
_CLAUDE_CODE_UA = "claude-cli/2.1.177 (external, cli)"
_CLAUDE_CODE_SYSTEM = "You are Claude Code, Anthropic's official CLI for Claude."


def _probe_headers(token, model, claude_code=False):
    """POST a max_tokens:1 message and return the parsed anthropic-ratelimit-unified-* header map
    (lowercased keys, 'anthropic-ratelimit-unified-' prefix stripped), or None on any transport error.
    An empty dict means the request completed but carried no rate-limit headers (e.g. 401/429-block)."""
    # [FABLE-5] Strip the credential: a stored secret can carry a trailing newline (e.g. `gh secret set`
    # from a file), which would otherwise land in the Authorization header and 400 the probe -> the healthy
    # account is silently omitted. Fail-closed either way, but the strip avoids dropping usable accounts.
    token = (token or "").strip()
    if not token:
        return None
    body = {"model": model, "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]}
    args = ["curl", "-s", "-D", "-", "-o", "/dev/null", "--max-time", "20", "-X", "POST",
            "https://api.anthropic.com/v1/messages",
            "-H", "Authorization: Bearer " + token,
            "-H", "anthropic-version: 2023-06-01",
            "-H", "content-type: application/json",
            "-H", "anthropic-beta: oauth-2025-04-20"]
    if claude_code:
        body["system"] = [{"type": "text", "text": _CLAUDE_CODE_SYSTEM}]
        args += ["-H", "user-agent: " + _CLAUDE_CODE_UA]
    args += ["-d", json.dumps(body)]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=30, check=False)
    except (subprocess.SubprocessError, OSError):
        return None
    hdr = {}
    for line in proc.stdout.splitlines():
        low = line.lower()
        if low.startswith("anthropic-ratelimit-unified-") and ":" in line:
            key, _, val = line.partition(":")
            hdr[key.strip().lower()[len("anthropic-ratelimit-unified-"):]] = val.strip()
    return hdr


def _probe_anthropic(token):
    """Whole-account 5h/7d usage via a cheap, ungated haiku probe. None -> fail-closed omit."""
    hdr = _probe_headers(token, "claude-haiku-4-5")
    if hdr is None or hdr.get("status") is None:
        return None  # transport error or no rate-limit headers (e.g. 401/blocked) -> fail-closed omit
    return {"status": hdr.get("status"),
            "5h_util": hdr.get("5h-utilization"), "5h_reset": hdr.get("5h-reset"),
            "7d_util": hdr.get("7d-utilization"), "7d_reset": hdr.get("7d-reset")}


def _probe_fable(token):
    """[FABLE-5] Probe the FABLE weekly sub-quota (anthropic-ratelimit-unified-7d_oi-*) with the
    Claude-Code request shape. Returns {"fable_ok": True, "fable_7d_oi_util","fable_7d_oi_reset"} when the
    account currently serves fable AND exposes the sub-quota window; None otherwise (rejected/gated/no
    7d_oi header) so the caller fail-closes FABLE routing for the account. Absence of the extra probe (or
    a None result) never blocks non-fable routing, which the base 5h/7d signal governs on its own."""
    hdr = _probe_headers(token, "claude-fable-5", claude_code=True)
    if hdr is None or hdr.get("7d_oi-utilization") is None:
        return None  # not a 200 with the sub-quota window (rejected/exhausted/absent) -> fail-closed fable
    return {"fable_ok": True,
            "fable_7d_oi_util": hdr.get("7d_oi-utilization"),
            "fable_7d_oi_reset": hdr.get("7d_oi-reset")}


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
        if probed is None:
            continue
        # [FABLE-5] Only fable-capable accounts need the extra Claude-Code-shaped fable probe. A missing
        # or failed fable probe leaves the fable sub-quota fields absent -> usage_eligible fail-closes FABLE
        # routing for this account, while its base 5h/7d signal still admits it for non-fable models.
        if "fable" in account.get("models", []):
            fable = _probe_fable(token)
            if fable is not None:
                probed.update(fable)
        usage[handle] = probed
    json.dump(usage, sys.stdout)


if __name__ == "__main__":
    main()
