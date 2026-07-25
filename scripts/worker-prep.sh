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
# `skip` materializes the mount WITHOUT exchanging the stored refresh token. Used by worker.yml's
# DRY RUN: provider refresh tokens are one-time-use, so a dry run must not consume the account's
# grant — and it never calls the model, so a possibly-expired access token in the mount is fine. The
# refresh token is still stripped from the mount either way.
PREFLIGHT_REFRESH=${WORKER_PREFLIGHT_REFRESH:-refresh}
[[ "$PREFLIGHT_REFRESH" == refresh || "$PREFLIGHT_REFRESH" == skip ]] ||
  die 'WORKER_PREFLIGHT_REFRESH must be refresh or skip'

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
# Host-side-only artifacts of the pre-flight refresh (issue #596). These sit DIRECTLY under
# WORKER_ROOT, NOT under $WORKER_ROOT/home — only `home` and `cli` are bind-mounted into the model
# container, so the durable refresh token these carry is unreachable from inside it.
CREDENTIAL_DURABLE="$WORKER_ROOT/.credential-durable"
CREDENTIAL_ROTATED_MARKER="$WORKER_ROOT/.credential-rotated"
REFRESH_CLASS_FILE="$WORKER_ROOT/.credential-refresh-class"

mkdir -p "$WORKER_ROOT" "$HOME_DIR" "$CLI_ROOT" "$NPM_HOME"
chmod 700 "$WORKER_ROOT" "$HOME_DIR" "$CLI_ROOT" "$NPM_HOME"

# A retry for the same run is idempotent, and changing the selected account cannot leave the prior
# provider's credential behind in this isolated HOME. The pre-flight artifacts are cleared too so a
# retry can never inherit the previous attempt's rotation marker or durable material.
rm -rf -- "$HOME_DIR/.codex" "$HOME_DIR/.claude"
rm -f -- "$CREDENTIAL_DURABLE" "$CREDENTIAL_ROTATED_MARKER" "$REFRESH_CLASS_FILE"
printf '%s' "$ACCOUNT_CREDENTIAL" > "$CREDENTIAL_SOURCE"
chmod 600 "$CREDENTIAL_SOURCE"

cleanup_source() {
  : > "$CREDENTIAL_SOURCE" 2>/dev/null || true
  rm -f -- "$CREDENTIAL_SOURCE"
}
trap cleanup_source EXIT INT TERM

# A host-side refresh that could not be completed (issue #596). Surface it as its OWN loud class,
# never as `auth` — `auth` is already the bucket every in-container provider rejection lands in
# (worker-live's classifier matches the bare substring `oauth`), and it reads as "the provider
# refused the model call" when the truth may be "this account's stored grant is dead and only an
# interactive re-mint can fix it". PRIVACY (locked decision 22b): this log names NO account handle
# and NO token material — the account attribution is added downstream by the separate no-target-code
# model_health job, which holds PROVENANCE_SALT and records the salted account hash.
credential_preflight_failed() {
  local cls
  cls=$(head -n1 -- "$REFRESH_CLASS_FILE" 2>/dev/null | tr -cd 'a-z-') || cls=''
  case "$cls" in
    credential-remint-required)
      printf '::error::worker-prep: model-exit-class=%s — the stored refresh token for the selected account is dead (expired, revoked, or already used). An INTERACTIVE re-mint is required; retrying cannot fix it.\n' "$cls"
      ;;
    credential-refresh-transient)
      printf '::error::worker-prep: model-exit-class=%s — the provider token endpoint could not be reached within the bounded retry. The stored credential is probably fine; retry later.\n' "$cls"
      ;;
    *)
      # Not a refresh failure at all (e.g. a malformed stored credential). Keep the PRE-#596
      # behaviour exactly: die with the underlying message and classify nothing, so downstream
      # records the honest `unknown` rather than a refresh class this did not observe.
      die 'credential materialization failed (see the error above)'
      ;;
  esac
  # Hand the class to the existing health/alert machinery (worker.yml / review-fix.yml read
  # WORKER_EXIT_CLASS; model-health.py folds these two raw classes onto auth / transient).
  { [[ -n ${GITHUB_ENV:-} ]] && printf 'WORKER_EXIT_CLASS=%s\n' "$cls" >> "$GITHUB_ENV" ; } || true
  { [[ -n ${WORKER_OUTPUT_DIR:-} ]] && printf '%s\n' "$cls" > "$WORKER_OUTPUT_DIR/exit-class" ; } \
    2>/dev/null || true
  rm -f -- "$REFRESH_CLASS_FILE"
  die 'host-side credential pre-flight failed (see the classified error above)'
}

case "$CREDENTIAL_FORMAT" in
  codex-auth-json | claude-credentials-json)
    # Reuse broker-refresh.py's credential-path and mode-600 isolation core. The credential travels
    # through a private file, never argv/stdout.
    #
    # HOST-SIDE PRE-FLIGHT REFRESH (P0, issue #596) — codex-auth-json only. The stored secret is a
    # point-in-time snapshot of a credential whose ACCESS token expires, and the credential file is
    # bind-mounted READ-ONLY into the model container (issue #134), so the CLI's own in-place
    # refresh is impossible there (reproduced: `Failed to refresh token: Read-only file system (os
    # error 30)`). Two consequences, both fixed here:
    #   1. once the snapshot's access token expires, EVERY run dies seconds in — a permanent outage
    #      that cannot self-heal, because write_back's "did the mounted file change?" rotation
    #      trigger can never fire against a file the mount makes unchangeable;
    #   2. the mounted snapshot carried the DURABLE `tokens.refresh_token`, and `readonly` stops
    #      writes, not READS — a prompt-injected model with Bash/Read could exfiltrate a long-lived
    #      OpenAI credential from its own HOME.
    # So: exchange the refresh token for a fresh access token HERE, on the host, and mount a MINIMAL
    # credential that carries the fresh access token and NO refresh token. The refresh token never
    # enters the container, and any rotated refresh token is left host-side for write_back.
    python3 - "$SCRIPT_DIR/broker-refresh.py" "$PROVIDER" "$CREDENTIAL_SOURCE" "$HOME_DIR" \
      "$CREDENTIAL_FORMAT" "$CREDENTIAL_DURABLE" "$CREDENTIAL_ROTATED_MARKER" \
      "$REFRESH_CLASS_FILE" "$PREFLIGHT_REFRESH" <<'PY' || credential_preflight_failed
import importlib.util
import json
import os
from pathlib import Path
import sys
import time

(broker_path, provider, credential_path, home, credential_format,
 durable_path, rotated_marker, class_file, preflight_mode) = sys.argv[1:]
spec = importlib.util.spec_from_file_location("broker_refresh", broker_path)
if spec is None or spec.loader is None:
    raise SystemExit("worker-prep: cannot load broker-refresh.py")
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)


def write_private(path, document):
    """mode-600 O_EXCL-equivalent write of host-side-only credential material."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(document, handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)


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

mounted = credential
if credential_format == "codex-auth-json" and preflight_mode == "skip":
    # Dry run: strip the durable secret from the mount, but exchange nothing.
    mounted = broker.minimal_worker_credential(provider, credential)
    print("worker-prep: host-side credential pre-flight SKIPPED (dry run); "
          "the mount carries no refresh token and the stored grant was not consumed")
elif credential_format == "codex-auth-json":
    try:
        preflight = broker.refresh_credential_host_side(provider, credential, now=int(time.time()))
    except broker.RefreshFailure as failure:
        # Hand the CLASS back to the shell through a private file. The exception message is built
        # from fixed strings plus an ALLOWLISTED provider error code only — never token material,
        # never provider free text.
        with open(class_file, "w", encoding="utf-8") as handle:
            handle.write(f"{failure.kind}\n")
        raise SystemExit(f"worker-prep: {failure}") from failure
    mounted = preflight["mount"]
    if preflight["rotated"] and preflight["durable"] is not None:
        # NEW DURABLE MATERIAL exists: this — not a mutation of the mounted file — is what makes a
        # write-back necessary and correct. Kept OUTSIDE the mounted HOME.
        write_private(durable_path, preflight["durable"])
        Path(rotated_marker).write_text("rotated\n", encoding="utf-8")
        os.chmod(rotated_marker, 0o600)
    print("worker-prep: host-side credential pre-flight complete "
          f"(refreshed={str(preflight['refreshed']).lower()}, "
          f"rotated={str(preflight['rotated']).lower()})")

path = Path(broker._write_isolated(provider, mounted, home))
expected = Path(home, broker.cred_relpath(provider))
if path != expected or not path.is_file() or path.stat().st_mode & 0o077:
    raise SystemExit("worker-prep: broker did not produce the expected mode-600 credential")
if credential_format == "codex-auth-json":
    # Fail closed on the materialized FILE, not on the in-memory document: whatever ends up under
    # the mount must carry no durable refresh material, whatever refactor produced it.
    with open(path, encoding="utf-8") as handle:
        broker.assert_no_refresh_material(json.load(handle),
                                          broker.extract_refresh_token(provider, credential))
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
