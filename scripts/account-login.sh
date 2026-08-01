#!/usr/bin/env bash
# Web-login broker core (review-hardened S4): run a provider's device/token login, surface
# the sign-in URL+code, poll for completion, and extract the token — WITHOUT ever persisting the token
# in a diagnostic log. The token is written only to $OUTDIR/token (mode 600) and the credential kind
# to $OUTDIR/credential_format. A trap shreds the transient raw capture on ANY exit.
#
# Usage: account-login.sh <openai|anthropic> <outdir> [timeout_sec]
set -euo pipefail
umask 077

PROVIDER="${1:?provider (openai|anthropic)}"
OUTDIR="${2:?output dir}"
TIMEOUT="${3:-780}"
mkdir -p "$OUTDIR"; chmod 700 "$OUTDIR"
# Isolate all CLI credential state under a dedicated HOME so nothing lands in the runner's real home
# and cleanup is a single directory removal (the workflow's always() step removes $OUTDIR).
export HOME="$OUTDIR/home"; mkdir -p "$HOME"
export CODEX_HOME="$HOME/.codex"
SIGNIN="$OUTDIR/signin.txt"; TOKEN="$OUTDIR/token"; FMT="$OUTDIR/credential_format"; RAW="$OUTDIR/.raw"
: > "$SIGNIN"; rm -f "$TOKEN" "$FMT" "$RAW"

strip() { sed -e 's/\x1b\[[0-9;]*m//g'; }
# [#879] first ERE match of $1 in the de-ANSI'd $RAW, or empty. NEVER `… | grep -oE … | head -1`:
# `head` exits on its first line, the still-running grep (and the sed feeding it) take SIGPIPE, and
# under `pipefail` (line 8) the pipeline reports 141 — which `set -e` turns into an abort of the
# login broker BEFORE $SIGNIN is written, i.e. an enrolment that dies without ever showing the
# maintainer the sign-in URL. `grep -oE` on a CLI transcript emits one line per URL, so a second
# match is the normal case, not the exotic one. Here both stages drain their input and the "first"
# is taken by a bash parameter expansion — no process exists that could exit early or be signalled.
# The `|| true` is the no-match case, which must reach the `${URL:-…}` fallbacks below rather than
# abort (before this change a missing URL aborted, making those fallbacks unreachable).
first_match() { local hits; hits="$(strip < "$RAW" | grep -oE "$1" || true)"; printf '%s' "${hits%%$'\n'*}"; }
shred_raw() { [ -f "$RAW" ] && { : > "$RAW"; rm -f "$RAW"; }; return 0; }
trap 'shred_raw' EXIT INT TERM

poll_exit() {  # wait for $1 (pid) up to TIMEOUT; kill + TIMEOUT-exit on overrun
  local lp="$1" waited=0
  while kill -0 "$lp" 2>/dev/null; do
    [ "$waited" -ge "$TIMEOUT" ] && { kill "$lp" 2>/dev/null || true; echo TIMEOUT; exit 2; }
    sleep 5; waited=$((waited+5))
  done
}

case "$PROVIDER" in
  openai)
    # codex native device flow: the TOKEN lands in $CODEX_HOME/auth.json (not on stdout), so $RAW
    # holds only URL/code diagnostics. We still shred it on exit.
    nohup codex login --device-auth > "$RAW" 2>&1 & LP=$!
    for _ in $(seq 1 30); do grep -qiE 'auth.openai.com/codex/device' "$RAW" && break; sleep 1; done
    URL=$(first_match 'https://auth\.openai\.com/codex/device')
    CODE=$(first_match '[A-Z0-9]{4}-[A-Z0-9]{5}')
    { echo "Provider: OpenAI (codex)"; echo "1. Open: ${URL:-https://auth.openai.com/codex/device}";
      echo "2. Enter code: ${CODE:-<see run>}"; echo "   Sign in with the OpenAI account to register."; } > "$SIGNIN"
    poll_exit "$LP"
    if [ -f "$CODEX_HOME/auth.json" ] && grep -q 'refresh_token' "$CODEX_HOME/auth.json"; then
      cp "$CODEX_HOME/auth.json" "$TOKEN"; chmod 600 "$TOKEN"; printf 'codex-auth-json' > "$FMT"; echo OK; exit 0
    fi
    echo FAILED; exit 1 ;;
  anthropic)
    # claude setup-token PRINTS the long-lived token at the end. Capture to $RAW, extract, SHRED $RAW
    # immediately so the token is never left in a persistent log. Run under the isolated HOME.
    nohup claude setup-token > "$RAW" 2>&1 & LP=$!
    for _ in $(seq 1 30); do grep -qiE 'https?://' "$RAW" && break; sleep 1; done
    URL=$(first_match 'https?://[^ ]+')
    { echo "Provider: Anthropic (claude)"; echo "1. Open: ${URL:-<see run>}";
      echo "   Sign in with the Anthropic account to register."; } > "$SIGNIN"
    poll_exit "$LP"
    TOK=$(strip < "$RAW" | grep -oE 'sk-ant-[A-Za-z0-9_-]+' | tail -1 || true)
    shred_raw
    if [ -n "$TOK" ]; then printf '%s' "$TOK" > "$TOKEN"; chmod 600 "$TOKEN"; printf 'claude-oauth-token' > "$FMT"; echo OK; exit 0; fi
    if [ -f "$HOME/.claude/.credentials.json" ]; then
      cp "$HOME/.claude/.credentials.json" "$TOKEN"; chmod 600 "$TOKEN"; printf 'claude-credentials-json' > "$FMT"; echo OK; exit 0; fi
    echo FAILED; exit 1 ;;
  *) echo "unknown provider: $PROVIDER" >&2; exit 64 ;;
esac
