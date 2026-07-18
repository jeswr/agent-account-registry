#!/usr/bin/env bash
# [FABLE-5] Idempotent one-shot migration of the 14 repo-scope Actions secrets into the
# `dispatch-secrets` environment (issue #101 outage repair; extracted from
# .github/workflows/migrate-secrets-to-env.yml after the sol review of PR #275: the in-workflow
# ordered script was NOT crash-recoverable — a death between "deleted repo-scope copy" and "assert
# repo scope empty" left a state no rerun could distinguish from a missing-input failure).
#
# TWO-PHASE DESIGN (sol review round 3 of #275 — bootstrap credential loss): 2 of the 14 secrets
# (REGISTRY_ADMIN_APP_ID / REGISTRY_ADMIN_APP_KEY, the BOOTSTRAP set) are the very credentials the
# environment-UNBOUND migration job mints its App token from. A single-phase deletion of all 14
# could be cancelled after deleting the APP_ID but before the APP_KEY: a repo-scope stray keeps
# the guard red while a rerun cannot mint (the unbound job cannot read the env copies) — BRICKED.
# So `--phase` selects one of two explicit state machines:
#
#   --phase main (env-UNBOUND job; needs Secrets RW + Environments RW + Actions R):
#     M0. pre-flight: refuse (fail closed) while any live secret-WRITER workflow run is queued or
#         in_progress (worker / review-fix / set-up-account / pat-validity) — none are serialized
#         with this migration. `gh run list` sits under the fine-grained "Actions" permission
#         (read) — a token without it dies HERE, before any listing or mutation. RESIDUAL
#         (accepted + documented): a run that started BEFORE the env-binding PRs merged executes
#         an old workflow snapshot and could still write a repo-scope secret AFTER this migration
#         completes; the dispatch secrets-guard catches that loudly and re-running this
#         idempotent migration heals it.
#     M1. list the environment's secret NAMES (a failed listing is a hard refusal, never "empty").
#     M2. pre-mutation input check: every name the env does NOT yet hold must have a non-empty
#         S_<name> value — asserted for ALL 14 BEFORE any mutation. An env-held name needs no
#         value: that IS the crash-resume path.
#     M3. copy each missing name: value flows STDIN -> `gh secret set --env` (never argv), then
#         re-list and verify it landed; a set-reported-success the listing does not show is a
#         hard fail with the repo scope untouched.
#     M4. assert a fresh env listing holds all 14 (extra env names — REGISTRY_SECRETS_PAT etc. —
#         are expected and fine).
#     M5. delete ONLY the 12 NON-bootstrap repo-scope copies still present (already-absent =
#         resume path). The 2 bootstrap secrets are NEVER deleted in this phase — the argv-level
#         invariant the self-test asserts — so ANY cancellation leaves a state from which this
#         phase can re-mint and converge.
#     M6. assert repo scope holds none of the 12; the 2 bootstrap names remaining is EXPECTED
#         (BY DESIGN — the cleanup phase drains them); any OTHER name is a distinct hard fail.
#
#   --phase cleanup-bootstrap (`environment: dispatch-secrets`-BOUND job that minted FROM the
#     environment copies; needs Secrets RW + Environments R + Actions R):
#     C0. the same live-writer pre-flight.
#     C1. list the environment; assert it holds all 14 — with a DISTINCT refusal if a BOOTSTRAP
#         name is missing: deleting its repo-scope original then would destroy the last mint
#         credential (re-run the main phase first).
#     C2. delete whichever of the 2 bootstrap repo-scope secrets remain (2/1/0 — a rerun after a
#         mid-cleanup cancellation converges; zero-remaining = success no-op).
#     C3. assert repo scope holds none of the 14 and surface any stray by NAME. Only after this
#         phase succeeds does the dispatch secrets-guard go green.
#
# Any other inconsistency is a hard fail with a distinct message. Secret VALUES are never echoed,
# never traced, never placed in argv; only NAMES are printed.
#
# Inputs (from the invoking workflow): GH_TOKEN (minted App token — see
# migrate-secrets-to-env.yml for the per-phase grants), REGISTRY_REPO, one S_<name> env var per
# secret (main phase only), optional SECRETS_ENV (default dispatch-secrets).
#
# `--self-test` / `self-test`: hermetic fake-`gh` PATH-shim suite (trust-gate.py precedent) —
# fresh-main, cleanup from 2/1/0-remaining, converged reruns of both phases,
# interrupted-after-partial-copy, interrupted-mid-deletion, set-verify-mismatch, repo-stray (both
# phases), missing-input, in-flight-writer, listing-failure (both phases), env-missing-bootstrap,
# and PER-ENDPOINT PERMISSION-model failures (run-list without actions:read; env-secret write
# without environments:write) so an under-granted mint is caught by the harness, not production.
# Exact argv sequences (env set via STDIN, no --body, and — load-bearing — ZERO bootstrap deletes
# in the main phase) are asserted. The suite also STATICALLY pins the WORKFLOW's declared mint
# grants (round-4 finding 3: the fake-gh model alone never noticed a permission line deleted
# from migrate-secrets-to-env.yml): check_workflow_mint_contract asserts both mint steps'
# exact phase-specific `permission-*` sets and goes red on any removal/weakening/widening.
# Wired into pr-gate.yml and worker-live's FULL_SELFTEST_SUITE so it gates. When the migration
# workflow is deleted after its successful run, delete this script too and unenrol it from BOTH
# suite lists.
set -euo pipefail
set +x   # belt-and-braces: never trace commands while secret values are in scope
umask 077

# The BOOTSTRAP set: the credentials the env-UNBOUND main job mints from. NEVER deleted by the
# main phase; drained only by the env-bound cleanup phase.
BOOTSTRAP_NAMES=(REGISTRY_ADMIN_APP_ID REGISTRY_ADMIN_APP_KEY)
NONBOOTSTRAP_NAMES=(
  ACCOUNT_EMAIL_MAP
  ACCT01_TOKEN ACCT02_TOKEN ACCT03_TOKEN ACCT04_TOKEN
  ACCT05_TOKEN ACCT06_TOKEN ACCT07_TOKEN
  ACCT2CSS_TOKEN ACCT3CSS_TOKEN ACCT4CSS_TOKEN
  PROVENANCE_SALT
)
SECRET_NAMES=("${NONBOOTSTRAP_NAMES[@]}" "${BOOTSTRAP_NAMES[@]}")
# Every workflow that can WRITE a registry secret (rotation write-back, review-fix's write-back,
# enrolment upsert, the weekly canary write). None are serialized with this migration.
WRITER_WORKFLOWS=(worker.yml review-fix.yml set-up-account.yml pat-validity.yml)

die() {
  printf '::error::migrate-secrets: %s\n' "$*" >&2
  exit 1
}

_has_name() {  # _has_name NAME NEWLINE-LIST
  grep -qxF -- "$1" <<<"$2"
}

_in() {  # _in NAME ARRAY-ELEMENTS...
  local needle=$1; shift
  printf '%s\n' "$@" | grep -qxF -- "$needle"
}

_env_names() {
  gh api "repos/${REPO}/environments/${ENV_NAME}/secrets" --paginate --jq '.secrets[].name'
}

_repo_names() {
  gh api "repos/${REPO}/actions/secrets" --paginate --jq '.secrets[].name'
}

setup() {
  REPO=${REGISTRY_REPO:-}
  ENV_NAME=${SECRETS_ENV:-dispatch-secrets}
  [[ "$REPO" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] \
    || die 'REGISTRY_REPO is unsafe or unset (fail closed)'
  [[ "$ENV_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die 'SECRETS_ENV is unsafe (fail closed)'
}

preflight_no_live_writers() {
  local wf status count
  for wf in "${WRITER_WORKFLOWS[@]}"; do
    for status in queued in_progress; do
      count=$(gh run list -R "$REPO" --workflow "$wf" --status "$status" \
                --json databaseId --jq length) \
        || die "could not list ${status} runs of ${wf} — cannot prove no live secret writer (fail closed; NOTE: this listing needs the App token's Actions: read grant)"
      [[ "$count" =~ ^[0-9]+$ ]] \
        || die "unparseable ${status} run count for ${wf} — cannot prove no live secret writer (fail closed)"
      if [[ "$count" -gt 0 ]]; then
        die "${count} ${status} run(s) of ${wf} — a live secret writer could race the migration; wait for it to finish, then re-run (the migration is idempotent)"
      fi
    done
  done
  printf 'pre-flight: no queued/in_progress secret-writer runs\n'
}

phase_main() {
  setup
  echo '== phase M0: pre-flight — no live secret-writer runs =='
  preflight_no_live_writers

  echo '== phase M1: list the environment secret names (resume state) =='
  local env_names
  env_names=$(_env_names) \
    || die "could not list secrets of environment '${ENV_NAME}' — refusing before any mutation (fail closed)"

  echo '== phase M2: pre-mutation input check (no mutation until every needed value is proven present) =='
  local name var
  for name in "${SECRET_NAMES[@]}"; do
    if _has_name "$name" "$env_names"; then
      printf 'already in %s (resume path — repo-scope value not required): %s\n' "$ENV_NAME" "$name"
      continue
    fi
    var="S_${name}"
    if [[ -z "${!var:-}" ]]; then
      die "value for ${name} is empty/missing AND the environment does not hold it — cannot converge; aborting BEFORE any mutation (were it a crash-rerun, the environment listing would already show the name)"
    fi
    printf 'present (will copy): %s\n' "$name"
  done

  echo '== phase M3: copy each missing name into the environment (value via STDIN, never argv) =='
  local post
  for name in "${SECRET_NAMES[@]}"; do
    if _has_name "$name" "$env_names"; then
      printf 'skip copy (env already holds it): %s\n' "$name"
      continue
    fi
    var="S_${name}"
    printf '%s' "${!var}" | gh secret set "$name" --env "$ENV_NAME" --repo "$REPO" \
      || die "gh secret set ${name} --env ${ENV_NAME} failed — repo-scope copies left untouched (NOTE: env-secret writes need the App token's Environments: write grant)"
    post=$(_env_names) \
      || die "could not re-list environment secrets after setting ${name} — repo-scope copies left untouched (fail closed)"
    _has_name "$name" "$post" \
      || die "copy-verify mismatch: gh secret set ${name} reported success but the ${ENV_NAME} listing does not contain it — repo-scope copies left untouched"
    printf 'set + verified: %s -> %s\n' "$name" "$ENV_NAME"
  done

  echo '== phase M4: assert a fresh environment listing holds all 14 =='
  env_names=$(_env_names) \
    || die "could not list environment secrets for the all-present assertion (fail closed)"
  local missing=0
  for name in "${SECRET_NAMES[@]}"; do
    if ! _has_name "$name" "$env_names"; then
      printf '::error::migrate-secrets: %s missing from the %s environment listing\n' "$name" "$ENV_NAME" >&2
      missing=1
    fi
  done
  [[ "$missing" -eq 0 ]] || die "environment does not hold all 14 — repo-scope copies left untouched"
  printf 'all 14 present in %s\n' "$ENV_NAME"

  echo '== phase M5: delete ONLY the 12 non-bootstrap repo-scope copies (bootstrap NEVER deleted here) =='
  local repo_names
  repo_names=$(_repo_names) \
    || die 'could not list repo-scope secrets — refusing to delete blind (fail closed)'
  for name in "${NONBOOTSTRAP_NAMES[@]}"; do
    if _has_name "$name" "$repo_names"; then
      gh secret delete "$name" --repo "$REPO" \
        || die "gh secret delete ${name} failed — re-run to converge (the environment copy is already verified)"
      printf 'deleted repo-scope: %s\n' "$name"
    else
      printf 'skip delete (repo scope already clear): %s\n' "$name"
    fi
  done

  echo '== phase M6: assert repo scope holds none of the 12 (bootstrap remaining is BY DESIGN) =='
  repo_names=$(_repo_names) \
    || die 'could not list repo-scope secrets for the final assertion (fail closed)'
  local stray=0 leftover=0
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    if _in "$name" "${NONBOOTSTRAP_NAMES[@]}"; then
      printf '::error::migrate-secrets: non-bootstrap secret %s STILL present at repo scope after deletion\n' "$name" >&2
      leftover=1
    elif _in "$name" "${BOOTSTRAP_NAMES[@]}"; then
      printf 'bootstrap secret remains at repo scope BY DESIGN (the cleanup-bootstrap phase deletes it): %s\n' "$name"
    else
      printf '::error::migrate-secrets: unexpected non-migrated repo-scope secret: %s\n' "$name" >&2
      stray=1
    fi
  done <<<"$repo_names"
  [[ "$leftover" -eq 0 ]] || die 'repo scope still holds non-bootstrap migrated names — re-run to converge'
  [[ "$stray" -eq 0 ]] \
    || die 'the 12 non-bootstrap secrets have converged into the environment, but the secrets-guard requires an EMPTY repo scope — move or remove the stray secret(s) named above (the cleanup-bootstrap phase still has to run too)'
  printf 'MAIN PHASE COMPLETE: all 14 live in %s and the repo scope holds at most the 2 bootstrap secrets (BY DESIGN). The secrets-guard stays RED until the cleanup-bootstrap phase drains them.\n' "$ENV_NAME"
}

phase_cleanup() {
  setup
  echo '== phase C0: pre-flight — no live secret-writer runs =='
  preflight_no_live_writers

  echo '== phase C1: assert the environment holds all 14 (esp. both bootstrap mint credentials) =='
  local env_names
  env_names=$(_env_names) \
    || die "could not list secrets of environment '${ENV_NAME}' — refusing to delete the bootstrap repo copies blind (fail closed)"
  local name missing=0 boot_missing=0
  for name in "${SECRET_NAMES[@]}"; do
    if ! _has_name "$name" "$env_names"; then
      printf '::error::migrate-secrets: %s missing from the %s environment listing\n' "$name" "$ENV_NAME" >&2
      if _in "$name" "${BOOTSTRAP_NAMES[@]}"; then boot_missing=1; else missing=1; fi
    fi
  done
  [[ "$boot_missing" -eq 0 ]] \
    || die 'a BOOTSTRAP secret is missing from the environment — deleting its repo-scope original now would destroy the last mint credential; re-run the main phase first (fail closed)'
  [[ "$missing" -eq 0 ]] \
    || die 'environment does not hold all 14 — re-run the main phase first; no repo-scope deletion until it converges'
  printf 'all 14 present in %s (both bootstrap mint credentials verified)\n' "$ENV_NAME"

  echo '== phase C2: delete whichever of the 2 bootstrap repo-scope secrets remain (2/1/0) =='
  local repo_names
  repo_names=$(_repo_names) \
    || die 'could not list repo-scope secrets — refusing to delete blind (fail closed)'
  for name in "${BOOTSTRAP_NAMES[@]}"; do
    if _has_name "$name" "$repo_names"; then
      gh secret delete "$name" --repo "$REPO" \
        || die "gh secret delete ${name} failed — re-run to converge (the environment copy is already verified)"
      printf 'deleted repo-scope bootstrap: %s\n' "$name"
    else
      printf 'skip delete (repo scope already clear — zero-remaining is a success no-op): %s\n' "$name"
    fi
  done

  echo '== phase C3: assert repo scope holds none of the 14 (and surface any stray by NAME) =='
  repo_names=$(_repo_names) \
    || die 'could not list repo-scope secrets for the final assertion (fail closed)'
  local stray=0 leftover=0
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    if _in "$name" "${SECRET_NAMES[@]}"; then
      printf '::error::migrate-secrets: migrated secret %s STILL present at repo scope after cleanup\n' "$name" >&2
      leftover=1
    else
      printf '::error::migrate-secrets: unexpected non-migrated repo-scope secret: %s\n' "$name" >&2
      stray=1
    fi
  done <<<"$repo_names"
  [[ "$leftover" -eq 0 ]] || die 'repo scope still holds migrated names — re-run to converge'
  [[ "$stray" -eq 0 ]] \
    || die 'both phases have converged for the 14, but the secrets-guard requires an EMPTY repo scope — move or remove the stray secret(s) named above, then dispatch recovers'
  printf 'MIGRATION COMPLETE (both phases): all 14 live in %s and the repo scope holds none of them — the secrets-guard goes green now. Delete migrate-secrets-to-env.yml (and unenrol+delete this script).\n' "$ENV_NAME"
}

# ---------------------------------------------------------------------------------------------
# WORKFLOW MINT CONTRACT (sol review round 4 of #275, finding 3 — vacuity gap): the fake-gh
# permission model above tests the SCRIPT's behavior under an under-granted token, but nothing
# tied the WORKFLOW's declared mint grants to it — deleting both `permission-actions: read`
# lines from migrate-secrets-to-env.yml still passed every scenario. This static assertion
# (anchored awk over the stable two-space job indentation — the repo toolchain carries no
# PyYAML) pins BOTH create-github-app-token steps' EXACT phase-specific grant sets:
#   main job `migrate`:            secrets: write + environments: write + actions: read
#   job `cleanup-bootstrap`:       secrets: write + environments: read  + actions: read
# The comparison is against the FULL sorted set, so REMOVING, WEAKENING (write -> read), or
# silently WIDENING any `permission-*` declaration goes red in --self-test (wired into
# pr-gate.yml and worker-live's FULL_SELFTEST_SUITE). When the workflow is deleted after the
# migration succeeds, this script is deleted with it (see header), taking the contract along.

_mint_grants() {  # _mint_grants WORKFLOW_FILE JOB_KEY -> that job's sorted permission-* lines
  awk -v job="$2" '
    /^  [A-Za-z0-9_-]+:/ { injob = ($0 == "  " job ":") }
    injob && /^ +permission-[a-z-]+:/ { sub(/^ +/, ""); sub(/[ \t]+$/, ""); print }
  ' "$1" | sort
}

check_workflow_mint_contract() {  # check_workflow_mint_contract WORKFLOW_FILE
  local wf=$1 want got rc=0
  if [[ ! -f "$wf" ]]; then
    printf '::error::migrate-secrets: workflow contract: %s not found (delete this script together with the workflow)\n' "$wf" >&2
    return 1
  fi
  want=$(printf 'permission-actions: read\npermission-environments: write\npermission-secrets: write')
  got=$(_mint_grants "$wf" migrate)
  if [[ "$got" != "$want" ]]; then
    printf '::error::migrate-secrets: workflow contract violated — the MAIN mint (job migrate) must declare EXACTLY {permission-secrets: write, permission-environments: write, permission-actions: read}; found:\n%s\n' "${got:-<none>}" >&2
    rc=1
  fi
  want=$(printf 'permission-actions: read\npermission-environments: read\npermission-secrets: write')
  got=$(_mint_grants "$wf" cleanup-bootstrap)
  if [[ "$got" != "$want" ]]; then
    printf '::error::migrate-secrets: workflow contract violated — the CLEANUP mint (job cleanup-bootstrap) must declare EXACTLY {permission-secrets: write, permission-environments: read, permission-actions: read}; found:\n%s\n' "${got:-<none>}" >&2
    rc=1
  fi
  return "$rc"
}

# ---------------------------------------------------------------------------------------------
# Hermetic self-test: a fake `gh` on PATH (trust-gate.py precedent) records every argv line and
# every STDIN payload, serves listings from a mutable state dir, and — new in review round 3 —
# models PER-ENDPOINT fine-grained PERMISSIONS via an optional grants file (absent = fully
# granted), so an under-granted App mint (e.g. no Actions: read for the pre-flight `gh run
# list`, no Environments: write for the env-secret set) is caught by this harness instead of a
# live 403. Fresh, resumed, cleanup-remaining, mismatched, stray, under-granted, and in-flight
# states are all exercised end-to-end through CHILD invocations of this script, with exact call
# sequences asserted — including the load-bearing "the main phase NEVER deletes a bootstrap
# secret" argv invariant (the old single-phase design bricked on a cancellation after the
# APP_ID delete and before the APP_KEY delete; asserting zero main-phase bootstrap deletes
# proves that window no longer exists).
self_test() {
  local tmp
  tmp=$(mktemp -d)
  # shellcheck disable=SC2064  # expand $tmp now, deliberately
  trap "rm -rf -- '$tmp'" EXIT
  local me failures=0
  me=$(cd -- "$(dirname -- "$0")" && pwd)/$(basename -- "$0")
  chk() {
    local name=$1 got=$2 want=$3
    if [[ "$got" == "$want" ]]; then
      printf '  ok   %s\n' "$name"
    else
      printf '  FAIL %s: %s (want %s)\n' "$name" "$got" "$want"
      failures=$((failures + 1))
    fi
  }

  mkdir -p "$tmp/bin"
  cat > "$tmp/bin/gh" <<'FAKE'
#!/usr/bin/env bash
set -u
state="$FAKE_GH_STATE"
printf '%s\n' "$*" >> "$state/calls.log"
# Fine-grained-permission model: a grants file lists the token's granted permissions one per
# line (actions:read, secrets:read, secrets:write, environments:read, environments:write). An
# ABSENT grants file means fully granted (the pre-round-3 scenarios). Each endpoint checks the
# permission the REST docs put it under and answers a 403-shaped failure without it — so a
# finding-1-class defect (a mint missing a load-bearing grant) turns a scenario red here.
_grant() {
  [[ ! -f "$state/grants" ]] && return 0
  grep -qxF -- "$1" "$state/grants"
}
case "$*" in
  "run list -R o/r --workflow "*" --status "*" --json databaseId --jq length")
    _grant actions:read \
      || { echo "HTTP 403: Resource not accessible by integration (workflow-run listing needs Actions: read)" >&2; exit 1; }
    f="$state/inflight_${6}_${8}"
    if [[ -f "$f" ]]; then cat "$f"; else echo 0; fi
    exit 0 ;;
  "api repos/o/r/environments/dispatch-secrets/secrets --paginate --jq .secrets[].name")
    _grant environments:read \
      || { echo "HTTP 403: Resource not accessible by integration (env-secret listing needs Environments: read)" >&2; exit 1; }
    [[ -f "$state/fail_env_list" ]] && exit 1
    cat "$state/env_secrets" 2>/dev/null || true
    exit 0 ;;
  "api repos/o/r/actions/secrets --paginate --jq .secrets[].name")
    _grant secrets:read \
      || { echo "HTTP 403: Resource not accessible by integration (repo-secret listing needs Secrets: read)" >&2; exit 1; }
    cat "$state/repo_secrets" 2>/dev/null || true
    exit 0 ;;
  "secret set "*" --env dispatch-secrets --repo o/r")
    val=$(cat)   # the value MUST arrive on stdin (drain it before any verdict, like real gh)
    _grant environments:write \
      || { echo "HTTP 403: Resource not accessible by integration (env-secret PUT needs Environments: write)" >&2; exit 1; }
    printf '%s=%s\n' "$3" "$val" >> "$state/stdin.log"
    if [[ ! -f "$state/drop_set_$3" ]]; then
      grep -qxF -- "$3" "$state/env_secrets" 2>/dev/null || printf '%s\n' "$3" >> "$state/env_secrets"
    fi
    exit 0 ;;
  "secret delete "*" --repo o/r")
    _grant secrets:write \
      || { echo "HTTP 403: Resource not accessible by integration (repo-secret DELETE needs Secrets: write)" >&2; exit 1; }
    if [[ -f "$state/repo_secrets" ]]; then
      grep -vxF -- "$3" "$state/repo_secrets" > "$state/repo_secrets.new" || true
      mv "$state/repo_secrets.new" "$state/repo_secrets"
    fi
    exit 0 ;;
  *)
    # A --body form of `secret set` (secret in world-readable argv) lands here and hard-fails.
    echo "unexpected gh invocation: $*" >&2
    exit 9 ;;
esac
FAKE
  chmod +x "$tmp/bin/gh"

  local -a nonboot=(
    ACCOUNT_EMAIL_MAP ACCT01_TOKEN ACCT02_TOKEN ACCT03_TOKEN ACCT04_TOKEN ACCT05_TOKEN
    ACCT06_TOKEN ACCT07_TOKEN ACCT2CSS_TOKEN ACCT3CSS_TOKEN ACCT4CSS_TOKEN PROVENANCE_SALT
  )
  local -a bootstrap=(REGISTRY_ADMIN_APP_ID REGISTRY_ADMIN_APP_KEY)
  local -a names=("${nonboot[@]}" "${bootstrap[@]}")

  # run_case STATE_DIR OUT_FILE PHASE VALUE_MODE(all|none|missing-only) [EMPTY_NAME]
  run_case() {
    local state=$1 out=$2 phase=$3 mode=$4 empty_name=${5:-}
    local -a assigns=(PATH="$tmp/bin:$PATH" FAKE_GH_STATE="$state" REGISTRY_REPO=o/r)
    local n
    for n in "${names[@]}"; do
      case "$mode" in
        all) assigns+=("S_${n}=v-${n}") ;;
        none) assigns+=("S_${n}=") ;;
        missing-only)
          if grep -qxF -- "$n" "$state/env_secrets" 2>/dev/null; then
            assigns+=("S_${n}=")            # resume path: env-held names carry NO value
          else
            assigns+=("S_${n}=v-${n}")
          fi ;;
      esac
    done
    [[ -n "$empty_name" ]] && assigns+=("S_${empty_name}=")
    local rc=0
    env "${assigns[@]}" bash "$me" --phase "$phase" > "$out" 2>&1 || rc=$?
    printf '%s' "$rc"
  }

  local expected_preflight="$tmp/expected-preflight.log" wf st n
  : > "$expected_preflight"
  for wf in worker.yml review-fix.yml set-up-account.yml pat-validity.yml; do
    for st in queued in_progress; do
      printf 'run list -R o/r --workflow %s --status %s --json databaseId --jq length\n' "$wf" "$st" >> "$expected_preflight"
    done
  done

  # --- scenario 1: FRESH MAIN PHASE — env empty, repo holds all 14, no in-flight writers. Also
  # the exact argv-sequence assertion (env sets via STDIN with --env, verify listings, exactly
  # the 12 non-bootstrap deletes, asserts) — and the load-bearing NEVER-deletes-bootstrap
  # invariant: the old design's brick window (cancelled after the APP_ID delete, before the
  # APP_KEY delete, leaving an unmintable stray) cannot exist when the main phase issues ZERO
  # bootstrap deletes at any point in its argv stream.
  local s1="$tmp/s1" rc
  mkdir -p "$s1"
  printf '%s\n' "${names[@]}" > "$s1/repo_secrets"
  : > "$s1/env_secrets"
  rc=$(run_case "$s1" "$tmp/s1.out" main all)
  chk "fresh main phase succeeds" "$rc" 0
  chk "fresh main: env holds all 14 after" "$(sort "$s1/env_secrets" | paste -sd' ' -)" \
    "$(printf '%s\n' "${names[@]}" | sort | paste -sd' ' -)"
  chk "fresh main: repo scope holds EXACTLY the 2 bootstrap secrets after" \
    "$(sort "$s1/repo_secrets" | paste -sd' ' -)" "REGISTRY_ADMIN_APP_ID REGISTRY_ADMIN_APP_KEY"
  chk "fresh main: NEVER deletes a bootstrap secret (the round-3 brick window)" \
    "$(grep -cE '^secret delete REGISTRY_ADMIN_APP_(ID|KEY) ' "$s1/calls.log" || true)" 0
  chk "fresh main: says the bootstrap remainder is BY DESIGN" \
    "$(grep -c 'BY DESIGN (the cleanup-bootstrap phase deletes it): REGISTRY_ADMIN_APP_ID' "$tmp/s1.out")" 1
  chk "fresh main: every value arrived via STDIN" \
    "$(sort "$s1/stdin.log" | paste -sd' ' -)" \
    "$(for n in "${names[@]}"; do printf '%s=v-%s\n' "$n" "$n"; done | sort | paste -sd' ' -)"
  chk "fresh main: no --body anywhere (secrets never in argv)" \
    "$(grep -c -- '--body' "$s1/calls.log" || true)" 0
  chk "fresh main: no secret VALUE ever appears in argv" \
    "$(grep -c -- 'v-ACC' "$s1/calls.log" || true)" 0
  local expected="$tmp/expected-main.log"
  cat "$expected_preflight" > "$expected"
  printf 'api repos/o/r/environments/dispatch-secrets/secrets --paginate --jq .secrets[].name\n' >> "$expected"
  for n in "${names[@]}"; do
    printf 'secret set %s --env dispatch-secrets --repo o/r\n' "$n" >> "$expected"
    printf 'api repos/o/r/environments/dispatch-secrets/secrets --paginate --jq .secrets[].name\n' >> "$expected"
  done
  printf 'api repos/o/r/environments/dispatch-secrets/secrets --paginate --jq .secrets[].name\n' >> "$expected"
  printf 'api repos/o/r/actions/secrets --paginate --jq .secrets[].name\n' >> "$expected"
  for n in "${nonboot[@]}"; do
    printf 'secret delete %s --repo o/r\n' "$n" >> "$expected"
  done
  printf 'api repos/o/r/actions/secrets --paginate --jq .secrets[].name\n' >> "$expected"
  chk "fresh main: EXACT gh argv sequence (preflight -> list -> set+verify x14 -> assert -> delete x12 NON-BOOTSTRAP ONLY -> assert)" \
    "$(diff -q "$expected" "$s1/calls.log" >/dev/null 2>&1 && echo same || echo diff)" same

  # --- scenario 2: CLEANUP FROM 2-REMAINING — the state the main phase leaves. Exact argv
  # sequence asserted; only after this does the migration report COMPLETE (guard-green ordering).
  local s2="$tmp/s2"
  mkdir -p "$s2"
  cp "$s1/env_secrets" "$s2/env_secrets"
  cp "$s1/repo_secrets" "$s2/repo_secrets"
  rc=$(run_case "$s2" "$tmp/s2.out" cleanup-bootstrap none)
  chk "cleanup from 2-remaining succeeds" "$rc" 0
  chk "cleanup: repo scope empty after" "$(cat "$s2/repo_secrets")" ""
  chk "cleanup: reports MIGRATION COMPLETE (guard goes green only after this phase)" \
    "$(grep -c 'MIGRATION COMPLETE (both phases)' "$tmp/s2.out")" 1
  local expected_c="$tmp/expected-cleanup.log"
  {
    cat "$expected_preflight"
    printf 'api repos/o/r/environments/dispatch-secrets/secrets --paginate --jq .secrets[].name\n'
    printf 'api repos/o/r/actions/secrets --paginate --jq .secrets[].name\n'
    printf 'secret delete REGISTRY_ADMIN_APP_ID --repo o/r\n'
    printf 'secret delete REGISTRY_ADMIN_APP_KEY --repo o/r\n'
    printf 'api repos/o/r/actions/secrets --paginate --jq .secrets[].name\n'
  } > "$expected_c"
  chk "cleanup: EXACT gh argv sequence (preflight -> env assert -> repo list -> delete x2 bootstrap -> assert)" \
    "$(diff -q "$expected_c" "$s2/calls.log" >/dev/null 2>&1 && echo same || echo diff)" same

  # --- scenario 3: CONVERGED RERUNS of BOTH phases on the fully-migrated state, NO values
  # available: pure no-op passes with zero further mutations (a cancellation between the jobs
  # reruns the whole workflow from exactly this kind of converged state).
  rc=$(run_case "$s2" "$tmp/s3a.out" main none)
  chk "converged main rerun succeeds with zero values available" "$rc" 0
  rc=$(run_case "$s2" "$tmp/s3b.out" cleanup-bootstrap none)
  chk "converged cleanup rerun succeeds (zero-remaining = success no-op)" "$rc" 0
  chk "converged reruns perform zero further mutations (only the initial 2 cleanup deletes in this state dir)" \
    "$(grep -cE '^secret (set|delete) ' "$s2/calls.log" || true)" 2

  # --- scenario 4: MAIN INTERRUPTED AFTER PARTIAL COPY — env holds 5, repo still holds all 14,
  # and the 5 env-held names have NO values (their repo copies could already be gone on a rerun).
  local s4="$tmp/s4"
  mkdir -p "$s4"
  printf '%s\n' "${names[@]}" > "$s4/repo_secrets"
  printf '%s\n' "${names[@]:0:5}" > "$s4/env_secrets"
  rc=$(run_case "$s4" "$tmp/s4.out" main missing-only)
  chk "partial-copy main rerun converges" "$rc" 0
  chk "partial-copy main rerun copies ONLY the 9 missing names" \
    "$(grep -cE '^secret set ' "$s4/calls.log")" 9
  chk "partial-copy main rerun deletes the 12 non-bootstrap repo copies" \
    "$(grep -cE '^secret delete ' "$s4/calls.log")" 12
  chk "partial-copy main rerun leaves the 2 bootstrap at repo scope" \
    "$(sort "$s4/repo_secrets" | paste -sd' ' -)" "REGISTRY_ADMIN_APP_ID REGISTRY_ADMIN_APP_KEY"

  # --- scenario 5: MAIN INTERRUPTED MID-DELETION — env complete, 6 repo copies left (4
  # non-bootstrap + the 2 bootstrap), no values.
  local s5="$tmp/s5"
  mkdir -p "$s5"
  printf '%s\n' "${names[@]}" > "$s5/env_secrets"
  printf '%s\n' "${names[@]:8}" > "$s5/repo_secrets"
  rc=$(run_case "$s5" "$tmp/s5.out" main none)
  chk "mid-deletion main rerun converges with zero values" "$rc" 0
  chk "mid-deletion main rerun copies nothing" "$(grep -cE '^secret set ' "$s5/calls.log" || true)" 0
  chk "mid-deletion main rerun deletes exactly the 4 non-bootstrap leftovers" \
    "$(grep -cE '^secret delete ' "$s5/calls.log")" 4
  chk "mid-deletion main rerun still never touches bootstrap" \
    "$(grep -cE '^secret delete REGISTRY_ADMIN_APP_(ID|KEY) ' "$s5/calls.log" || true)" 0

  # --- scenario 6: CLEANUP FROM 1-REMAINING — the state a mid-cleanup cancellation leaves
  # (APP_ID already deleted, APP_KEY not yet). The rerun converges; in the OLD single-phase
  # design this exact state was the BRICK (unbound rerun could not mint) — here the env-bound
  # cleanup mints from the env copies and finishes the drain.
  local s6="$tmp/s6"
  mkdir -p "$s6"
  printf '%s\n' "${names[@]}" > "$s6/env_secrets"
  printf 'REGISTRY_ADMIN_APP_KEY\n' > "$s6/repo_secrets"
  rc=$(run_case "$s6" "$tmp/s6.out" cleanup-bootstrap none)
  chk "cleanup from 1-remaining converges" "$rc" 0
  chk "cleanup from 1-remaining deletes exactly the one leftover" \
    "$(grep -cE '^secret delete ' "$s6/calls.log")" 1
  chk "cleanup from 1-remaining: repo scope empty after" "$(cat "$s6/repo_secrets")" ""

  # --- scenario 7: CLEANUP FROM 0-REMAINING — a rerun after full success: success no-op.
  local s7="$tmp/s7"
  mkdir -p "$s7"
  printf '%s\n' "${names[@]}" > "$s7/env_secrets"
  : > "$s7/repo_secrets"
  rc=$(run_case "$s7" "$tmp/s7.out" cleanup-bootstrap none)
  chk "cleanup from 0-remaining is a success no-op" "$rc" 0
  chk "cleanup from 0-remaining performs zero mutations" \
    "$(grep -cE '^secret (set|delete) ' "$s7/calls.log" || true)" 0

  # --- scenario 8: MISSING INPUT on a fresh main run — hard fail BEFORE any mutation.
  local s8="$tmp/s8"
  mkdir -p "$s8"
  printf '%s\n' "${names[@]}" > "$s8/repo_secrets"
  : > "$s8/env_secrets"
  rc=$(run_case "$s8" "$tmp/s8.out" main all ACCT03_TOKEN)
  chk "missing value -> hard fail" "$rc" 1
  chk "missing value: distinct pre-mutation message" \
    "$(grep -c 'aborting BEFORE any mutation' "$tmp/s8.out")" 1
  chk "missing value: ZERO mutations performed" \
    "$(grep -cE '^secret (set|delete) ' "$s8/calls.log" || true)" 0

  # --- scenario 9: SET-VERIFY MISMATCH — a set that reports success but never lands in the
  # listing must hard-fail with the repo scope untouched.
  local s9="$tmp/s9"
  mkdir -p "$s9"
  printf '%s\n' "${names[@]}" > "$s9/repo_secrets"
  : > "$s9/env_secrets"
  touch "$s9/drop_set_ACCT01_TOKEN"
  rc=$(run_case "$s9" "$tmp/s9.out" main all)
  chk "set-verify mismatch -> hard fail" "$rc" 1
  chk "set-verify mismatch: distinct message" \
    "$(grep -c 'copy-verify mismatch' "$tmp/s9.out")" 1
  chk "set-verify mismatch: NO deletions happened" \
    "$(grep -cE '^secret delete ' "$s9/calls.log" || true)" 0
  chk "set-verify mismatch: repo scope untouched" "$(wc -l < "$s9/repo_secrets")" 14

  # --- scenario 10: REPO-SCOPE STRAY (main) — a non-migrated repo secret; the 12 converge but
  # the run hard-fails with a distinct message. Extra ENV names (REGISTRY_SECRETS_PAT's
  # post-cutover home is this environment) must NOT trip anything, and bootstrap stays put.
  local s10="$tmp/s10"
  mkdir -p "$s10"
  { printf '%s\n' "${names[@]}"; echo SOME_LEGACY_SECRET; } > "$s10/repo_secrets"
  { printf '%s\n' "${names[@]}"; echo REGISTRY_SECRETS_PAT; } > "$s10/env_secrets"
  rc=$(run_case "$s10" "$tmp/s10.out" main none)
  chk "main repo stray -> hard fail (guard requires empty repo scope)" "$rc" 1
  chk "main repo stray: surfaced by NAME with a distinct message" \
    "$(grep -c 'unexpected non-migrated repo-scope secret: SOME_LEGACY_SECRET' "$tmp/s10.out")" 1
  chk "main repo stray: the 12 non-bootstrap were still deleted" \
    "$(grep -cE '^secret delete ' "$s10/calls.log")" 12
  chk "main repo stray: the stray itself is NEVER deleted" \
    "$(grep -c 'secret delete SOME_LEGACY_SECRET' "$s10/calls.log" || true)" 0
  chk "main repo stray: bootstrap never deleted" \
    "$(grep -cE '^secret delete REGISTRY_ADMIN_APP_(ID|KEY) ' "$s10/calls.log" || true)" 0
  chk "extra env name (REGISTRY_SECRETS_PAT) is tolerated" \
    "$(grep -c 'REGISTRY_SECRETS_PAT' "$tmp/s10.out" || true)" 0

  # --- scenario 11: REPO-SCOPE STRAY (cleanup) — bootstrap drained, stray surfaced, hard fail.
  local s11="$tmp/s11"
  mkdir -p "$s11"
  printf '%s\n' "${names[@]}" > "$s11/env_secrets"
  { printf '%s\n' "${bootstrap[@]}"; echo SOME_LEGACY_SECRET; } > "$s11/repo_secrets"
  rc=$(run_case "$s11" "$tmp/s11.out" cleanup-bootstrap none)
  chk "cleanup repo stray -> hard fail" "$rc" 1
  chk "cleanup repo stray: bootstrap still drained (cleanup itself converged)" \
    "$(grep -cE '^secret delete REGISTRY_ADMIN_APP_(ID|KEY) ' "$s11/calls.log")" 2
  chk "cleanup repo stray: the stray itself is NEVER deleted" \
    "$(grep -c 'secret delete SOME_LEGACY_SECRET' "$s11/calls.log" || true)" 0

  # --- scenario 12: IN-FLIGHT WRITER — fail closed before ANY listing or mutation (main).
  local s12="$tmp/s12"
  mkdir -p "$s12"
  printf '%s\n' "${names[@]}" > "$s12/repo_secrets"
  : > "$s12/env_secrets"
  echo 1 > "$s12/inflight_worker.yml_in_progress"
  rc=$(run_case "$s12" "$tmp/s12.out" main all)
  chk "in-flight writer -> fail closed" "$rc" 1
  chk "in-flight writer: distinct message names the workflow" \
    "$(grep -c '1 in_progress run(s) of worker.yml' "$tmp/s12.out")" 1
  chk "in-flight writer: ONLY run-list calls issued (no listing, no mutation)" \
    "$(grep -cvE '^run list ' "$s12/calls.log" || true)" 0

  # --- scenario 13: ENV LISTING FAILURE (main) — a dead listing is a refusal, never "empty env".
  local s13="$tmp/s13"
  mkdir -p "$s13"
  printf '%s\n' "${names[@]}" > "$s13/repo_secrets"
  : > "$s13/env_secrets"
  touch "$s13/fail_env_list"
  rc=$(run_case "$s13" "$tmp/s13.out" main all)
  chk "failed env listing (main) -> fail closed before any mutation" "$rc" 1
  chk "failed env listing (main): zero mutations" \
    "$(grep -cE '^secret (set|delete) ' "$s13/calls.log" || true)" 0

  # --- scenario 14: ENV LISTING FAILURE (cleanup) — must NEVER delete the bootstrap repo
  # copies blind: an unverifiable environment might not hold the mint credentials at all.
  local s14="$tmp/s14"
  mkdir -p "$s14"
  printf '%s\n' "${names[@]}" > "$s14/env_secrets"
  printf '%s\n' "${bootstrap[@]}" > "$s14/repo_secrets"
  touch "$s14/fail_env_list"
  rc=$(run_case "$s14" "$tmp/s14.out" cleanup-bootstrap none)
  chk "failed env listing (cleanup) -> fail closed" "$rc" 1
  chk "failed env listing (cleanup): ZERO deletions (never drain the last mint source blind)" \
    "$(grep -cE '^secret delete ' "$s14/calls.log" || true)" 0

  # --- scenario 15: ENV MISSING A BOOTSTRAP NAME (cleanup) — deleting the repo originals then
  # would destroy the LAST mint credential: distinct refusal, zero deletions.
  local s15="$tmp/s15"
  mkdir -p "$s15"
  printf '%s\n' "${names[@]}" | grep -vxF REGISTRY_ADMIN_APP_KEY > "$s15/env_secrets"
  printf '%s\n' "${bootstrap[@]}" > "$s15/repo_secrets"
  rc=$(run_case "$s15" "$tmp/s15.out" cleanup-bootstrap none)
  chk "env missing a bootstrap name (cleanup) -> hard fail" "$rc" 1
  chk "env missing a bootstrap name: distinct last-mint-credential message" \
    "$(grep -c 'would destroy the last mint credential' "$tmp/s15.out")" 1
  chk "env missing a bootstrap name: ZERO deletions" \
    "$(grep -cE '^secret delete ' "$s15/calls.log" || true)" 0

  # --- scenario 16: PERMISSION MODEL — token WITHOUT actions:read (the finding-1 class): the
  # pre-flight `gh run list` 403s and the run fails closed before any listing or mutation. This
  # is exactly the defect the round-3 review found in the workflow's mint (secrets+environments
  # only); with this scenario the harness catches any regression to an under-granted mint shape.
  local s16="$tmp/s16"
  mkdir -p "$s16"
  printf '%s\n' "${names[@]}" > "$s16/repo_secrets"
  : > "$s16/env_secrets"
  printf 'secrets:read\nsecrets:write\nenvironments:read\nenvironments:write\n' > "$s16/grants"
  rc=$(run_case "$s16" "$tmp/s16.out" main all)
  chk "no actions:read grant -> pre-flight fails closed" "$rc" 1
  chk "no actions:read grant: distinct fail-closed message on the FIRST run-list" \
    "$(grep -c 'could not list queued runs of worker.yml' "$tmp/s16.out")" 1
  chk "no actions:read grant: zero listings, zero mutations (only the one denied run-list)" \
    "$(grep -cvE '^run list ' "$s16/calls.log" || true)" 0

  # --- scenario 17: PERMISSION MODEL — token WITHOUT environments:write: the first env-secret
  # set 403s; hard fail with the repo scope untouched (no deletions ever reached).
  local s17="$tmp/s17"
  mkdir -p "$s17"
  printf '%s\n' "${names[@]}" > "$s17/repo_secrets"
  : > "$s17/env_secrets"
  printf 'actions:read\nsecrets:read\nsecrets:write\nenvironments:read\n' > "$s17/grants"
  rc=$(run_case "$s17" "$tmp/s17.out" main all)
  chk "no environments:write grant -> env-secret set fails closed" "$rc" 1
  chk "no environments:write grant: distinct message names the grant" \
    "$(grep -c 'gh secret set ACCOUNT_EMAIL_MAP --env dispatch-secrets failed' "$tmp/s17.out")" 1
  chk "no environments:write grant: NO deletions, repo scope untouched" \
    "$(grep -cE '^secret delete ' "$s17/calls.log" || true)-$(wc -l < "$s17/repo_secrets")" 0-14

  # --- scenario 18: WORKFLOW MINT CONTRACT (round-4 finding 3) — the REAL workflow's two mint
  # steps must declare exactly the phase-specific grant sets the permission scenarios above
  # model; the fake-gh grants files prove the SCRIPT fails closed under-granted, this proves the
  # WORKFLOW actually requests the grants. Then the check's own non-vacuity: a mutated copy with
  # a REMOVED declaration and one with a WEAKENED declaration must each go red.
  local wf_real wf_mut="$tmp/wf-mut.yml"
  wf_real="$(dirname -- "$me")/../.github/workflows/migrate-secrets-to-env.yml"
  rc=0; check_workflow_mint_contract "$wf_real" > "$tmp/s18.out" 2>&1 || rc=$?
  chk "workflow mint contract holds on the real migrate-secrets-to-env.yml" "$rc" 0
  grep -v 'permission-actions: read' "$wf_real" > "$wf_mut"   # strips BOTH actions:read mints
  rc=0; check_workflow_mint_contract "$wf_mut" > "$tmp/s18b.out" 2>&1 || rc=$?
  chk "contract goes RED when the permission-actions: read declarations are removed (the exact round-4 vacuity gap)" "$rc" 1
  sed 's/permission-environments: write/permission-environments: read/' "$wf_real" > "$wf_mut"
  rc=0; check_workflow_mint_contract "$wf_mut" > "$tmp/s18c.out" 2>&1 || rc=$?
  chk "contract goes RED when the main-phase environments grant is WEAKENED to read" "$rc" 1
  sed 's/^          permission-secrets: write$/          permission-secrets: write\n          permission-contents: write/' \
    "$wf_real" > "$wf_mut"
  rc=0; check_workflow_mint_contract "$wf_mut" > "$tmp/s18d.out" 2>&1 || rc=$?
  chk "contract goes RED when an extra grant is silently WIDENED in (exact-set pin)" "$rc" 1

  if [[ "$failures" -eq 0 ]]; then
    printf 'migrate-secrets self-test PASSED\n'
    return 0
  fi
  printf 'migrate-secrets self-test FAILED (%s failure(s))\n' "$failures"
  return 1
}

case "${1:-}" in
  --self-test | self-test) self_test ;;
  --phase)
    case "${2:-}" in
      main) phase_main ;;
      cleanup-bootstrap) phase_cleanup ;;
      *) die 'usage: migrate-secrets.sh --phase main|cleanup-bootstrap | --self-test' ;;
    esac ;;
  *) die 'usage: migrate-secrets.sh --phase main|cleanup-bootstrap | --self-test' ;;
esac
