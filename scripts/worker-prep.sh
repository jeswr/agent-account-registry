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
# The credential FORMAT, recorded host-side at the same instant as the rotation marker
# (retro-review of #614). write_back needs the format to validate the durable material before it
# reaches the central secret, and this file is where the live lanes get it (issue #232: the format
# used to ride the job-wide $GITHUB_ENV export at the very END of this script, long after the
# pre-flight has already consumed the one-time-use grant — so a prepare that died in between left the
# rotated credential with no format and the write-back unable to persist it). Written INSIDE the
# rotation branch and BEFORE the marker, so a marker without its format is a shape this script cannot
# produce: whenever write_back has something to persist, it has the format to validate it with.
CREDENTIAL_FORMAT_FILE="$WORKER_ROOT/.credential-format"

mkdir -p "$WORKER_ROOT" "$HOME_DIR" "$CLI_ROOT" "$NPM_HOME"
chmod 700 "$WORKER_ROOT" "$HOME_DIR" "$CLI_ROOT" "$NPM_HOME"

# A retry for the same run is idempotent, and changing the selected account cannot leave the prior
# provider's credential behind in this isolated HOME. The pre-flight artifacts are cleared too so a
# retry can never inherit the previous attempt's rotation marker or durable material.
rm -rf -- "$HOME_DIR/.codex" "$HOME_DIR/.claude"
rm -f -- "$CREDENTIAL_DURABLE" "$CREDENTIAL_ROTATED_MARKER" "$REFRESH_CLASS_FILE" \
  "$CREDENTIAL_FORMAT_FILE"
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
  # Read VERBATIM (bar trailing whitespace), never `tr -cd`-sanitised: a delete-the-bad-characters
  # read MANUFACTURES a valid value out of an invalid one instead of failing closed on it
  # (post-merge retro-review of #629, F6). An unrecognised value falls to the `*)` arm below.
  cls=$(head -n1 -- "$REFRESH_CLASS_FILE" 2>/dev/null | tr -d '\r' \
    | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//') || cls=''
  case "$cls" in
    credential-remint-required)
      # The message must NOT assert the grant "is dead": `credential-remint-required` now carries TWO
      # causes (post-merge retro-review of #629, F6). One is a provider-confirmed dead grant
      # (invalid_grant / refresh_token_reused / a grant-rejecting status); the other is an
      # INDETERMINATE outcome — the request was written and the response was lost, or the provider
      # returned a success status with an unusable body — where the grant's fate is UNKNOWN and it was
      # deliberately not re-sent. broker-refresh's own RefreshFailure message says which; this line
      # used to override it with "retrying cannot fix it", which is exactly wrong for the second cause.
      printf '::error::worker-prep: model-exit-class=%s — the host-side refresh could not produce a usable credential and this run must NOT re-send the stored one-time-use grant. Either the grant is dead (expired, revoked, already used) or its fate is unknown because the exchange was not observed to fail before delivery. See the classified broker-refresh message above for which; a MAINTAINER re-mint is the safe resolution and an unattended retry cannot be relied on to fix it.\n' "$cls"
      ;;
    credential-refresh-transient)
      printf '::error::worker-prep: model-exit-class=%s — the token exchange did not complete (the endpoint was unreachable, throttled, or returned a server error). The stored credential is probably fine; a LATER attempt re-reads it, and a grant the provider did consume will then fail closed as a dead grant. Retry later.\n' "$cls"
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
      "$REFRESH_CLASS_FILE" "$PREFLIGHT_REFRESH" "$CREDENTIAL_FORMAT_FILE" \
      <<'PY' || credential_preflight_failed
import importlib.util
import json
import os
from pathlib import Path
import sys
import time

(broker_path, provider, credential_path, home, credential_format,
 durable_path, rotated_marker, class_file, preflight_mode, format_file) = sys.argv[1:]
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
        #
        # ORDER IS LOAD-BEARING (retro-review of #614): the provider has ALREADY rotated the
        # one-time-use grant by the time this branch runs, so from here on the ONLY copy of the new
        # grant is on this runner. The durable material, the FORMAT write_back needs to validate it,
        # and the rotation marker therefore all land NOW — before the mount is materialized, before
        # the pinned CLI install, before the step-output export — so that every later failure in this
        # script still leaves the write-back a complete, self-describing job to do. Marker LAST: it
        # is the receipt write_back keys on, so it must not exist before its inputs do.
        write_private(durable_path, preflight["durable"])
        Path(format_file).write_text(f"{credential_format}\n", encoding="utf-8")
        os.chmod(format_file, 0o600)
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

# STEP OUTPUTS, NEVER $GITHUB_ENV (issue #232). $GITHUB_ENV is JOB-WIDE: everything this script
# used to write there persisted into EVERY later step of the worker job — including the policy gate,
# which executes the TARGET's own build scripts and tests on this runner. That handed
# target-controlled code the isolated HOME (whose .cargo the model itself can write), the raw
# account handle, and direct pointers to the live credential and its rotation baseline, for the
# whole span between this step and the end of the job.
#
# Step OUTPUTS are inert data the workflow must ROUTE deliberately, so the credential paths now
# reach exactly the two consumers that need them — the model run and the rotation write-back — as
# step-level `env:`, and nothing else.
#
# THAT IS HALF THE CONTAINMENT, AND ONLY HALF (issue #232 review r2). Routing decides which steps
# are HANDED the path; it does not decide which steps can FIND the file. WORKER_ROOT is
# `$RUNNER_TEMP/registry-worker` in both live lanes and GitHub supplies $RUNNER_TEMP to every step,
# so target-controlled cargo in the gate can walk this tree and read a mode-600 file owned by the
# same runner user without any environment pointer at all. The other half is `worker-live.sh
# purge-credentials`, which both lanes run in an always() step ordered after the write-back and
# BEFORE the rustup pin and the gate: it removes this HOME and every host-side credential artifact
# and fails closed if anything survives. Neither half substitutes for the other — this one shrinks
# what a step inherits, that one shrinks how long the file exists (both are the defense-in-depth
# follow-up to #124).
#
# The account handle, provider, harness and credential format are NOT re-exported at all: the
# workflow already resolved them in its account-SELECTION step and passes them straight from there
# to the steps that need them, so this script is no longer a second source for them.
#
# Nothing emitted here is derived from the credential VALUE: these are paths under WORKER_ROOT. And
# nothing is emitted that no lane routes — CODEX_HOME in particular is NOT exported, because the only
# process that needs it is the model container, which worker-live.sh gives its own (`--env
# CODEX_HOME=/home/worker/.codex`); an unrouted export would be exactly the job-wide surface this
# change removes, one indirection later.
if [[ -n ${GITHUB_OUTPUT:-} ]]; then
  {
    printf 'home=%s\n' "$HOME_DIR"
    printf 'credential_path=%s\n' "$CREDENTIAL_PATH"
    printf 'credential_baseline=%s\n' "$CREDENTIAL_BASELINE"
  } >> "$GITHUB_OUTPUT"
fi
if [[ -n ${GITHUB_PATH:-} ]]; then
  printf '%s\n' "$BIN_DIR" >> "$GITHUB_PATH"
fi

# PRIVACY (locked decision 22b, issue #91): names the HARNESS, never the account handle. This log
# is public and retained, and `acctNN` reverses directly to the `ACCTNN_TOKEN` secret reference —
# the same identifier write_back already keeps out of its own success line. The account attribution
# belongs to the no-target-code model_health job, which holds PROVENANCE_SALT and records a salted
# hash instead. The handle is still validated above; it is only not printed.
printf 'worker-prep: prepared isolated HOME with the pinned %s CLI\n' "$HARNESS"
