#!/usr/bin/env bash
# [GPT-5.6] REG-2/REG-3 worker preparation. Materialize exactly one selected account credential
# into an isolated HOME, retain a private comparison baseline for rotation write-back, and install
# the policy-selected model harness. This script never runs the model.
set -euo pipefail
set +x
umask 077

die() {
  printf 'worker-prep: %s\n' "$*" >&2
  exit 1
}

unset CDPATH
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)

ACCOUNT=${WORKER_ACCOUNT:-}
PROVIDER=${WORKER_PROVIDER:-}
HARNESS=${WORKER_HARNESS:-}
CREDENTIAL_FORMAT=${WORKER_CREDENTIAL_FORMAT:-}
ACCOUNT_CREDENTIAL=${WORKER_ACCOUNT_CREDENTIAL:-}
WORKER_ROOT=${WORKER_ROOT:-}

[[ "$ACCOUNT" =~ ^acct[0-9a-z]{2,}$ ]] || die 'WORKER_ACCOUNT must name one selected acctNN account'
[[ -n "$ACCOUNT_CREDENTIAL" ]] || die "credential for selected account $ACCOUNT is missing"
[[ -n "$WORKER_ROOT" && "$WORKER_ROOT" != / ]] || die 'WORKER_ROOT must be an isolated directory'

case "$PROVIDER:$HARNESS" in
  openai:codex | anthropic:claude) ;;
  *) die "unsupported resolved provider/harness pair: $PROVIDER/$HARNESS" ;;
esac

case "$CREDENTIAL_FORMAT" in
  codex-auth-json)
    [[ "$PROVIDER:$HARNESS" == openai:codex ]] ||
      die 'codex-auth-json does not match the resolved provider/harness'
    ;;
  claude-credentials-json | claude-oauth-token | anthropic-api-key)
    [[ "$PROVIDER:$HARNESS" == anthropic:claude ]] ||
      die "$CREDENTIAL_FORMAT does not match the resolved provider/harness"
    ;;
  *) die "unsupported or missing credential format: $CREDENTIAL_FORMAT" ;;
esac

# GitHub masks the selected repository secret before this step starts. Never enable xtrace, write
# the value to stdout, or pass it as a process argument (including an add-mask command).

HOME_DIR="$WORKER_ROOT/home"
CLI_ROOT="$WORKER_ROOT/cli"
NPM_HOME="$WORKER_ROOT/npm-home"
CREDENTIAL_SOURCE="$WORKER_ROOT/.selected-credential"
CREDENTIAL_BASELINE="$WORKER_ROOT/.credential-baseline"

mkdir -p "$WORKER_ROOT" "$HOME_DIR" "$CLI_ROOT" "$NPM_HOME"
chmod 700 "$WORKER_ROOT" "$HOME_DIR" "$CLI_ROOT" "$NPM_HOME"

# A retry for the same run is idempotent, and changing the selected account cannot leave the prior
# provider's credential behind in this isolated HOME.
rm -rf -- "$HOME_DIR/.codex" "$HOME_DIR/.claude"
printf '%s' "$ACCOUNT_CREDENTIAL" > "$CREDENTIAL_SOURCE"
chmod 600 "$CREDENTIAL_SOURCE"

cleanup_source() {
  : > "$CREDENTIAL_SOURCE" 2>/dev/null || true
  rm -f -- "$CREDENTIAL_SOURCE"
}
trap cleanup_source EXIT INT TERM

case "$CREDENTIAL_FORMAT" in
  codex-auth-json | claude-credentials-json)
    # Reuse broker-refresh.py's credential-path and mode-600 isolation core. The credential travels
    # through a private file, never argv/stdout. The provider CLI may refresh it only in REG-3's
    # later model step.
    python3 - "$SCRIPT_DIR/broker-refresh.py" "$PROVIDER" "$CREDENTIAL_SOURCE" "$HOME_DIR" <<'PY'
import importlib.util
import json
from pathlib import Path
import sys

broker_path, provider, credential_path, home = sys.argv[1:]
spec = importlib.util.spec_from_file_location("broker_refresh", broker_path)
if spec is None or spec.loader is None:
    raise SystemExit("worker-prep: cannot load broker-refresh.py")
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)

try:
    with open(credential_path, encoding="utf-8") as handle:
        credential = json.load(handle)
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f"worker-prep: selected {provider} credential is not valid JSON: {exc}") from exc
if not isinstance(credential, dict) or not credential:
    raise SystemExit(f"worker-prep: selected {provider} credential must be a non-empty JSON object")
capability = broker.extract_access_token(provider, credential)
broker.assert_no_refresh_leak(capability)
if not isinstance(capability.get("access_token"), str) or not capability["access_token"]:
    raise SystemExit(f"worker-prep: selected {provider} credential has no access token")

path = Path(broker._write_isolated(provider, credential, home))
expected = Path(home, broker.cred_relpath(provider))
if path != expected or not path.is_file() or path.stat().st_mode & 0o077:
    raise SystemExit("worker-prep: broker did not produce the expected mode-600 credential")
PY
    ;;
  claude-oauth-token | anthropic-api-key)
    # account-login.sh records these opaque Anthropic formats. Keep a mode-600 copy under the
    # isolated HOME. worker-live.sh exports it only to the model process, not the whole job.
    [[ "$ACCOUNT_CREDENTIAL" != *$'\n'* && "$ACCOUNT_CREDENTIAL" != *$'\r'* ]] ||
      die "$CREDENTIAL_FORMAT must be a single-line credential"
    [[ "$ACCOUNT_CREDENTIAL" =~ ^sk-ant-[A-Za-z0-9_-]+$ ]] ||
      die "$CREDENTIAL_FORMAT has an invalid token shape"
    mkdir -p "$HOME_DIR/.claude"
    chmod 700 "$HOME_DIR/.claude"
    printf '%s' "$ACCOUNT_CREDENTIAL" > "$HOME_DIR/.claude/worker-token"
    chmod 600 "$HOME_DIR/.claude/worker-token"
    ;;
esac

case "$CREDENTIAL_FORMAT" in
  codex-auth-json) CREDENTIAL_PATH="$HOME_DIR/.codex/auth.json" ;;
  claude-credentials-json) CREDENTIAL_PATH="$HOME_DIR/.claude/.credentials.json" ;;
  claude-oauth-token | anthropic-api-key) CREDENTIAL_PATH="$HOME_DIR/.claude/worker-token" ;;
esac
[[ -f "$CREDENTIAL_PATH" && ! -L "$CREDENTIAL_PATH" ]] ||
  die 'materialized credential is missing or is a symbolic link'
[[ ! "$CREDENTIAL_PATH" -ef "$CREDENTIAL_BASELINE" ]] || die 'credential baseline aliases live credential'
cp -- "$CREDENTIAL_PATH" "$CREDENTIAL_BASELINE"
chmod 600 "$CREDENTIAL_BASELINE"

# Do not let package-manager or later child processes inherit the source secret. Credentials are
# now available only through private files under the isolated HOME.
unset WORKER_ACCOUNT_CREDENTIAL ACCOUNT_CREDENTIAL
cleanup_source
trap - EXIT INT TERM

case "$HARNESS" in
  codex)
    PACKAGE='@openai/codex@0.144.1'
    BINARY=codex
    ;;
  claude)
    PACKAGE='@anthropic-ai/claude-code@2.1.177'
    BINARY=claude
    ;;
esac

BIN_DIR="$CLI_ROOT/node_modules/.bin"
if [[ ! -x "$BIN_DIR/$BINARY" ]]; then
  command -v npm >/dev/null 2>&1 || die 'npm is required to install the pinned model CLI'
  # Package install hooks get neither the credential environment nor its HOME directory.
  HOME="$NPM_HOME" npm install --prefix "$CLI_ROOT" --no-audit --no-fund --save-exact "$PACKAGE"
fi
[[ -x "$BIN_DIR/$BINARY" ]] || die "pinned $HARNESS CLI installation did not produce $BINARY"

export HOME="$HOME_DIR"
export CODEX_HOME="$HOME_DIR/.codex"
export PATH="$BIN_DIR:$PATH"

if [[ -n ${GITHUB_ENV:-} ]]; then
  {
    printf 'HOME=%s\n' "$HOME"
    printf 'CODEX_HOME=%s\n' "$CODEX_HOME"
    printf 'WORKER_ACCOUNT=%s\n' "$ACCOUNT"
    printf 'WORKER_PROVIDER=%s\n' "$PROVIDER"
    printf 'WORKER_HARNESS=%s\n' "$HARNESS"
    printf 'WORKER_CREDENTIAL_FORMAT=%s\n' "$CREDENTIAL_FORMAT"
    printf 'WORKER_CREDENTIAL_PATH=%s\n' "$CREDENTIAL_PATH"
    printf 'WORKER_CREDENTIAL_BASELINE=%s\n' "$CREDENTIAL_BASELINE"
  } >> "$GITHUB_ENV"
fi
if [[ -n ${GITHUB_PATH:-} ]]; then
  printf '%s\n' "$BIN_DIR" >> "$GITHUB_PATH"
fi

printf 'worker-prep: prepared isolated HOME for %s with the pinned %s CLI\n' "$ACCOUNT" "$HARNESS"
