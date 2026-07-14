#!/usr/bin/env bash
# [OPUS-4.8] Web-login broker core: run a provider's device/token login, surface the sign-in
# URL+code for the maintainer, poll for completion, and extract the resulting token.
#
# The token is written ONLY to $OUTDIR/token (mode 600) and NEVER echoed to stdout/logs.
# The set-up-account workflow posts $OUTDIR/signin.txt to the issue, waits, then stores $OUTDIR/token
# as the account secret. See README.md.
#
# Usage: account-login.sh <openai|anthropic> <outdir> [timeout_sec]
set -euo pipefail

PROVIDER="${1:?provider (openai|anthropic)}"
OUTDIR="${2:?output dir}"
TIMEOUT="${3:-780}"   # 13 min (device codes expire ~15 min)
mkdir -p "$OUTDIR"; chmod 700 "$OUTDIR"
SIGNIN="$OUTDIR/signin.txt"; TOKEN="$OUTDIR/token"; LOG="$OUTDIR/.login.out"
: > "$SIGNIN"; rm -f "$TOKEN"

strip() { sed -e 's/\x1b\[[0-9;]*m//g'; }

case "$PROVIDER" in
  openai)
    # codex native device flow: emits a device URL + one-time code, polls automatically.
    nohup codex login --device-auth > "$LOG" 2>&1 &
    LP=$!
    # wait for the URL+code to appear
    for _ in $(seq 1 30); do grep -qiE 'auth.openai.com/codex/device' "$LOG" && break; sleep 1; done
    URL=$(strip < "$LOG" | grep -oE 'https://auth\.openai\.com/codex/device' | head -1)
    CODE=$(strip < "$LOG" | grep -oE '[A-Z0-9]{4}-[A-Z0-9]{5}' | head -1)
    {
      echo "Provider: OpenAI (codex)"
      echo "1. Open: ${URL:-https://auth.openai.com/codex/device}"
      echo "2. Enter the one-time code: ${CODE:-<see log>}"
      echo "   (expires ~15 min). Sign in with the OpenAI account to register."
    } > "$SIGNIN"
    # poll for completion
    waited=0
    while kill -0 "$LP" 2>/dev/null; do
      [ "$waited" -ge "$TIMEOUT" ] && { kill "$LP" 2>/dev/null || true; echo "TIMEOUT"; exit 2; }
      sleep 5; waited=$((waited+5))
    done
    if [ -f "$HOME/.codex/auth.json" ] && grep -q 'refresh_token' "$HOME/.codex/auth.json"; then
      cp "$HOME/.codex/auth.json" "$TOKEN"; chmod 600 "$TOKEN"; echo "OK"; exit 0
    fi
    echo "FAILED"; exit 1
    ;;
  anthropic)
    # claude long-lived token: `claude setup-token` runs an OAuth flow (emits a URL) and prints a
    # long-lived token. Run in a CLEAN environment (fresh Actions runner) so it never disturbs an
    # existing ~/.claude. Captures any URL it emits + the resulting token from stdout.
    nohup claude setup-token > "$LOG" 2>&1 &
    LP=$!
    for _ in $(seq 1 30); do grep -qiE 'https?://' "$LOG" && break; sleep 1; done
    URL=$(strip < "$LOG" | grep -oE 'https?://[^ ]+' | head -1)
    CODE=$(strip < "$LOG" | grep -oE '[A-Z0-9]{4}-[A-Z0-9]{5}' | head -1)
    {
      echo "Provider: Anthropic (claude)"
      echo "1. Open: ${URL:-<see log>}"
      [ -n "$CODE" ] && echo "2. Enter code: $CODE"
      echo "   Sign in with the Anthropic account to register."
    } > "$SIGNIN"
    waited=0
    while kill -0 "$LP" 2>/dev/null; do
      [ "$waited" -ge "$TIMEOUT" ] && { kill "$LP" 2>/dev/null || true; echo "TIMEOUT"; exit 2; }
      sleep 5; waited=$((waited+5))
    done
    # setup-token prints the long-lived token (sk-ant-...) on success; else fall back to creds file
    TOK=$(strip < "$LOG" | grep -oE 'sk-ant-[A-Za-z0-9_-]+' | tail -1 || true)
    if [ -n "$TOK" ]; then printf '%s' "$TOK" > "$TOKEN"; chmod 600 "$TOKEN"; echo "OK"; exit 0; fi
    if [ -f "$HOME/.claude/.credentials.json" ]; then
      cp "$HOME/.claude/.credentials.json" "$TOKEN"; chmod 600 "$TOKEN"; echo "OK"; exit 0; fi
    echo "FAILED"; exit 1
    ;;
  *) echo "unknown provider: $PROVIDER" >&2; exit 64 ;;
esac
