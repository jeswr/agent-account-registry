#!/usr/bin/env bash
# [FABLE-5] Idempotent one-shot migration of the 14 repo-scope Actions secrets into the
# `dispatch-secrets` environment (issue #101 outage repair; extracted from
# .github/workflows/migrate-secrets-to-env.yml after the sol review of PR #275: the in-workflow
# ordered script was NOT crash-recoverable — a death between "deleted repo-scope copy" and "assert
# repo scope empty" left a state no rerun could distinguish from a missing-input failure).
#
# PER-NAME STATE MACHINE — a rerun after ANY interruption converges:
#   0. pre-flight: refuse (fail closed) while any live secret-WRITER workflow run is queued or
#      in_progress (worker / review-fix / set-up-account / pat-validity) — none of those are
#      serialized with this migration, and a concurrent `gh secret set` could write a scope this
#      script has already verified. RESIDUAL (accepted + documented): a run that started BEFORE
#      the env-binding PRs merged executes an old workflow snapshot and could still write a
#      repo-scope secret AFTER this migration completes; the dispatch secrets-guard catches that
#      loudly (repo scope non-empty -> every tick fails closed) and re-running this idempotent
#      migration heals it.
#   1. list the environment's secret NAMES (a failed listing is a hard refusal, never "empty").
#   2. pre-mutation input check: every name the env does NOT yet hold must have a non-empty
#      S_<name> value in the invoking environment — asserted for ALL names BEFORE any mutation.
#      A name the env ALREADY holds needs no value: that IS the crash-resume path (the repo-scope
#      copy may already be deleted, so its value is legitimately unavailable on a rerun).
#   3. copy each missing name: value flows STDIN -> `gh secret set --env` (never argv — process
#      argv is world-readable on the runner), then re-list and verify the name landed; a
#      set-reported-success that the listing does not show is a hard fail with the repo scope
#      untouched.
#   4. assert a fresh env listing holds all 14 (extra env names — e.g. REGISTRY_SECRETS_PAT,
#      whose canonical post-cutover home is this environment, or enrolment-written ACCTNN
#      tokens — are expected and fine).
#   5. list repo-scope names; delete each of the 14 still present (already-absent = resume path).
#   6. assert repo listing ∩ the 14 = empty, and hard-fail (distinct message) on any OTHER
#      repo-scope name: the migration of the 14 has converged, but the secrets-guard requires an
#      EMPTY repo scope, so a stray keeps dispatch down until it is moved or removed.
# Any other inconsistency is a hard fail with a distinct message. Secret VALUES are never echoed,
# never traced, never placed in argv; only NAMES are printed.
#
# Inputs (from the invoking workflow): GH_TOKEN (minted App token: Secrets write for repo scope,
# Environments write for the env — see migrate-secrets-to-env.yml), REGISTRY_REPO, one S_<name>
# env var per secret, optional SECRETS_ENV (default dispatch-secrets).
#
# `--self-test` / `self-test`: hermetic fake-`gh` PATH-shim suite (trust-gate.py precedent) —
# fresh, converged-rerun, interrupted-after-partial-copy, interrupted-mid-deletion,
# set-verify-mismatch, repo-stray, missing-input, in-flight-writer, listing-failure states; exact
# argv sequences (env set via STDIN, no --body) asserted. Wired into pr-gate.yml and worker-live's
# FULL_SELFTEST_SUITE so it gates. When the migration workflow is deleted after its successful
# run, delete this script too and unenrol it from BOTH suite lists.
set -euo pipefail
set +x   # belt-and-braces: never trace commands while secret values are in scope
umask 077

SECRET_NAMES=(
  ACCOUNT_EMAIL_MAP
  ACCT01_TOKEN ACCT02_TOKEN ACCT03_TOKEN ACCT04_TOKEN
  ACCT05_TOKEN ACCT06_TOKEN ACCT07_TOKEN
  ACCT2CSS_TOKEN ACCT3CSS_TOKEN ACCT4CSS_TOKEN
  PROVENANCE_SALT
  REGISTRY_ADMIN_APP_ID REGISTRY_ADMIN_APP_KEY
)
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

_env_names() {
  gh api "repos/${REPO}/environments/${ENV_NAME}/secrets" --paginate --jq '.secrets[].name'
}

_repo_names() {
  gh api "repos/${REPO}/actions/secrets" --paginate --jq '.secrets[].name'
}

preflight_no_live_writers() {
  local wf status count
  for wf in "${WRITER_WORKFLOWS[@]}"; do
    for status in queued in_progress; do
      count=$(gh run list -R "$REPO" --workflow "$wf" --status "$status" \
                --json databaseId --jq length) \
        || die "could not list ${status} runs of ${wf} — cannot prove no live secret writer (fail closed)"
      [[ "$count" =~ ^[0-9]+$ ]] \
        || die "unparseable ${status} run count for ${wf} — cannot prove no live secret writer (fail closed)"
      if [[ "$count" -gt 0 ]]; then
        die "${count} ${status} run(s) of ${wf} — a live secret writer could race the migration; wait for it to finish, then re-run (the migration is idempotent)"
      fi
    done
  done
  printf 'pre-flight: no queued/in_progress secret-writer runs\n'
}

migrate() {
  REPO=${REGISTRY_REPO:-}
  ENV_NAME=${SECRETS_ENV:-dispatch-secrets}
  [[ "$REPO" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] \
    || die 'REGISTRY_REPO is unsafe or unset (fail closed)'
  [[ "$ENV_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die 'SECRETS_ENV is unsafe (fail closed)'

  echo '== phase 0: pre-flight — no live secret-writer runs =='
  preflight_no_live_writers

  echo '== phase 1: list the environment secret names (resume state) =='
  local env_names
  env_names=$(_env_names) \
    || die "could not list secrets of environment '${ENV_NAME}' — refusing before any mutation (fail closed)"

  echo '== phase 2: pre-mutation input check (no mutation until every needed value is proven present) =='
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

  echo '== phase 3: copy each missing name into the environment (value via STDIN, never argv) =='
  local post
  for name in "${SECRET_NAMES[@]}"; do
    if _has_name "$name" "$env_names"; then
      printf 'skip copy (env already holds it): %s\n' "$name"
      continue
    fi
    var="S_${name}"
    printf '%s' "${!var}" | gh secret set "$name" --env "$ENV_NAME" --repo "$REPO" \
      || die "gh secret set ${name} --env ${ENV_NAME} failed — repo-scope copies left untouched"
    post=$(_env_names) \
      || die "could not re-list environment secrets after setting ${name} — repo-scope copies left untouched (fail closed)"
    _has_name "$name" "$post" \
      || die "copy-verify mismatch: gh secret set ${name} reported success but the ${ENV_NAME} listing does not contain it — repo-scope copies left untouched"
    printf 'set + verified: %s -> %s\n' "$name" "$ENV_NAME"
  done

  echo '== phase 4: assert a fresh environment listing holds all 14 =='
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

  echo '== phase 5: delete the repo-scope copies still present (already-absent = resume path) =='
  local repo_names
  repo_names=$(_repo_names) \
    || die 'could not list repo-scope secrets — refusing to delete blind (fail closed)'
  for name in "${SECRET_NAMES[@]}"; do
    if _has_name "$name" "$repo_names"; then
      gh secret delete "$name" --repo "$REPO" \
        || die "gh secret delete ${name} failed — re-run to converge (the environment copy is already verified)"
      printf 'deleted repo-scope: %s\n' "$name"
    else
      printf 'skip delete (repo scope already clear): %s\n' "$name"
    fi
  done

  echo '== phase 6: assert repo scope holds none of the 14 (and surface any stray by NAME) =='
  repo_names=$(_repo_names) \
    || die 'could not list repo-scope secrets for the final assertion (fail closed)'
  local stray=0 leftover=0
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    if printf '%s\n' "${SECRET_NAMES[@]}" | grep -qxF -- "$name"; then
      printf '::error::migrate-secrets: migrated secret %s STILL present at repo scope after deletion\n' "$name" >&2
      leftover=1
    else
      printf '::error::migrate-secrets: unexpected non-migrated repo-scope secret: %s\n' "$name" >&2
      stray=1
    fi
  done <<<"$repo_names"
  [[ "$leftover" -eq 0 ]] || die 'repo scope still holds migrated names — re-run to converge'
  [[ "$stray" -eq 0 ]] \
    || die 'the 14 have converged into the environment, but the secrets-guard requires an EMPTY repo scope — move or remove the stray secret(s) named above, then dispatch recovers'
  printf 'MIGRATION COMPLETE: all 14 live in %s and the repo scope holds none of them. Now delete migrate-secrets-to-env.yml (and unenrol+delete this script).\n' "$ENV_NAME"
}

# ---------------------------------------------------------------------------------------------
# Hermetic self-test: a fake `gh` on PATH (trust-gate.py precedent) records every argv line and
# every STDIN payload, and serves listings from a mutable state dir — so fresh, resumed,
# mismatched, stray, and in-flight states are all exercised end-to-end through a CHILD invocation
# of this script, with the exact call sequence asserted.
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
case "$*" in
  "run list -R o/r --workflow "*" --status "*" --json databaseId --jq length")
    f="$state/inflight_${6}_${8}"
    if [[ -f "$f" ]]; then cat "$f"; else echo 0; fi
    exit 0 ;;
  "api repos/o/r/environments/dispatch-secrets/secrets --paginate --jq .secrets[].name")
    [[ -f "$state/fail_env_list" ]] && exit 1
    cat "$state/env_secrets" 2>/dev/null || true
    exit 0 ;;
  "api repos/o/r/actions/secrets --paginate --jq .secrets[].name")
    cat "$state/repo_secrets" 2>/dev/null || true
    exit 0 ;;
  "secret set "*" --env dispatch-secrets --repo o/r")
    val=$(cat)   # the value MUST arrive on stdin
    printf '%s=%s\n' "$3" "$val" >> "$state/stdin.log"
    if [[ ! -f "$state/drop_set_$3" ]]; then
      grep -qxF -- "$3" "$state/env_secrets" 2>/dev/null || printf '%s\n' "$3" >> "$state/env_secrets"
    fi
    exit 0 ;;
  "secret delete "*" --repo o/r")
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

  local -a names=(
    ACCOUNT_EMAIL_MAP ACCT01_TOKEN ACCT02_TOKEN ACCT03_TOKEN ACCT04_TOKEN ACCT05_TOKEN
    ACCT06_TOKEN ACCT07_TOKEN ACCT2CSS_TOKEN ACCT3CSS_TOKEN ACCT4CSS_TOKEN PROVENANCE_SALT
    REGISTRY_ADMIN_APP_ID REGISTRY_ADMIN_APP_KEY
  )

  # run_case STATE_DIR OUT_FILE VALUE_MODE(all|none|missing-only) [EMPTY_NAME]
  run_case() {
    local state=$1 out=$2 mode=$3 empty_name=${4:-}
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
    env "${assigns[@]}" bash "$me" > "$out" 2>&1 || rc=$?
    printf '%s' "$rc"
  }

  # --- scenario 1: FRESH — env empty, repo holds all 14, no in-flight writers. Also the exact
  # argv-sequence assertion (env sets via STDIN with --env, verify listings, deletes, asserts).
  local s1="$tmp/s1" rc
  mkdir -p "$s1"
  printf '%s\n' "${names[@]}" > "$s1/repo_secrets"
  : > "$s1/env_secrets"
  rc=$(run_case "$s1" "$tmp/s1.out" all)
  chk "fresh migration succeeds" "$rc" 0
  chk "fresh: env holds all 14 after" "$(sort "$s1/env_secrets" | paste -sd' ' -)" \
    "$(printf '%s\n' "${names[@]}" | sort | paste -sd' ' -)"
  chk "fresh: repo scope empty after" "$(cat "$s1/repo_secrets")" ""
  chk "fresh: every value arrived via STDIN" \
    "$(sort "$s1/stdin.log" | paste -sd' ' -)" \
    "$(for n in "${names[@]}"; do printf '%s=v-%s\n' "$n" "$n"; done | sort | paste -sd' ' -)"
  chk "fresh: no --body anywhere (secrets never in argv)" \
    "$(grep -c -- '--body' "$s1/calls.log" || true)" 0
  chk "fresh: no secret VALUE ever appears in argv" \
    "$(grep -c -- 'v-ACC' "$s1/calls.log" || true)" 0
  local expected="$tmp/expected.log" wf st n
  : > "$expected"
  for wf in worker.yml review-fix.yml set-up-account.yml pat-validity.yml; do
    for st in queued in_progress; do
      printf 'run list -R o/r --workflow %s --status %s --json databaseId --jq length\n' "$wf" "$st" >> "$expected"
    done
  done
  printf 'api repos/o/r/environments/dispatch-secrets/secrets --paginate --jq .secrets[].name\n' >> "$expected"
  for n in "${names[@]}"; do
    printf 'secret set %s --env dispatch-secrets --repo o/r\n' "$n" >> "$expected"
    printf 'api repos/o/r/environments/dispatch-secrets/secrets --paginate --jq .secrets[].name\n' >> "$expected"
  done
  printf 'api repos/o/r/environments/dispatch-secrets/secrets --paginate --jq .secrets[].name\n' >> "$expected"
  printf 'api repos/o/r/actions/secrets --paginate --jq .secrets[].name\n' >> "$expected"
  for n in "${names[@]}"; do
    printf 'secret delete %s --repo o/r\n' "$n" >> "$expected"
  done
  printf 'api repos/o/r/actions/secrets --paginate --jq .secrets[].name\n' >> "$expected"
  chk "fresh: EXACT gh argv sequence (preflight -> list -> set+verify x14 -> assert -> delete x14 -> assert)" \
    "$(diff -q "$expected" "$s1/calls.log" >/dev/null 2>&1 && echo same || echo diff)" same

  # --- scenario 2: CONVERGED RERUN — state after success, NO values available: pure no-op pass.
  rc=$(run_case "$s1" "$tmp/s2.out" none)
  chk "converged rerun succeeds with zero values available" "$rc" 0
  chk "converged rerun performs zero mutations" \
    "$(grep -cE '^secret (set|delete) ' "$s1/calls.log" || true)" 28

  # --- scenario 3: INTERRUPTED AFTER PARTIAL COPY — env holds 5, repo still holds all 14, and
  # the 5 env-held names have NO values (their repo copies could already be gone on a real rerun).
  local s3="$tmp/s3"
  mkdir -p "$s3"
  printf '%s\n' "${names[@]}" > "$s3/repo_secrets"
  printf '%s\n' "${names[@]:0:5}" > "$s3/env_secrets"
  rc=$(run_case "$s3" "$tmp/s3.out" missing-only)
  chk "partial-copy rerun converges" "$rc" 0
  chk "partial-copy rerun copies ONLY the 9 missing names" \
    "$(grep -cE '^secret set ' "$s3/calls.log")" 9
  chk "partial-copy rerun still deletes all 14 repo copies" \
    "$(grep -cE '^secret delete ' "$s3/calls.log")" 14

  # --- scenario 4: INTERRUPTED MID-DELETION — env complete, 6 repo copies left, no values.
  local s4="$tmp/s4"
  mkdir -p "$s4"
  printf '%s\n' "${names[@]}" > "$s4/env_secrets"
  printf '%s\n' "${names[@]:8}" > "$s4/repo_secrets"
  rc=$(run_case "$s4" "$tmp/s4.out" none)
  chk "mid-deletion rerun converges with zero values" "$rc" 0
  chk "mid-deletion rerun copies nothing" "$(grep -cE '^secret set ' "$s4/calls.log" || true)" 0
  chk "mid-deletion rerun deletes exactly the 6 leftovers" \
    "$(grep -cE '^secret delete ' "$s4/calls.log")" 6

  # --- scenario 5: MISSING INPUT on a fresh run — hard fail BEFORE any mutation.
  local s5="$tmp/s5"
  mkdir -p "$s5"
  printf '%s\n' "${names[@]}" > "$s5/repo_secrets"
  : > "$s5/env_secrets"
  rc=$(run_case "$s5" "$tmp/s5.out" all ACCT03_TOKEN)
  chk "missing value -> hard fail" "$rc" 1
  chk "missing value: distinct pre-mutation message" \
    "$(grep -c 'aborting BEFORE any mutation' "$tmp/s5.out")" 1
  chk "missing value: ZERO mutations performed" \
    "$(grep -cE '^secret (set|delete) ' "$s5/calls.log" || true)" 0

  # --- scenario 6: SET-VERIFY MISMATCH — a set that reports success but never lands in the
  # listing (the env-stray/mismatch state) must hard-fail with the repo scope untouched.
  local s6="$tmp/s6"
  mkdir -p "$s6"
  printf '%s\n' "${names[@]}" > "$s6/repo_secrets"
  : > "$s6/env_secrets"
  touch "$s6/drop_set_ACCT01_TOKEN"
  rc=$(run_case "$s6" "$tmp/s6.out" all)
  chk "set-verify mismatch -> hard fail" "$rc" 1
  chk "set-verify mismatch: distinct message" \
    "$(grep -c 'copy-verify mismatch' "$tmp/s6.out")" 1
  chk "set-verify mismatch: NO deletions happened" \
    "$(grep -cE '^secret delete ' "$s6/calls.log" || true)" 0
  chk "set-verify mismatch: repo scope untouched" "$(wc -l < "$s6/repo_secrets")" 14

  # --- scenario 7: REPO-SCOPE STRAY — a non-migrated repo secret; the 14 converge but the run
  # hard-fails with a distinct message (the guard needs an EMPTY repo scope). Extra ENV names
  # (REGISTRY_SECRETS_PAT's post-cutover home is this environment) must NOT trip anything.
  local s7="$tmp/s7"
  mkdir -p "$s7"
  { printf '%s\n' "${names[@]}"; echo SOME_LEGACY_SECRET; } > "$s7/repo_secrets"
  { printf '%s\n' "${names[@]}"; echo REGISTRY_SECRETS_PAT; } > "$s7/env_secrets"
  rc=$(run_case "$s7" "$tmp/s7.out" none)
  chk "repo stray -> hard fail (guard requires empty repo scope)" "$rc" 1
  chk "repo stray: surfaced by NAME with a distinct message" \
    "$(grep -c 'unexpected non-migrated repo-scope secret: SOME_LEGACY_SECRET' "$tmp/s7.out")" 1
  chk "repo stray: the 14 were still deleted (migration itself converged)" \
    "$(grep -cE '^secret delete ' "$s7/calls.log")" 14
  chk "repo stray: the stray itself is NEVER deleted" \
    "$(grep -c 'secret delete SOME_LEGACY_SECRET' "$s7/calls.log" || true)" 0
  chk "extra env name (REGISTRY_SECRETS_PAT) is tolerated" \
    "$(grep -c 'REGISTRY_SECRETS_PAT' "$tmp/s7.out" || true)" 0

  # --- scenario 8: IN-FLIGHT WRITER — fail closed before ANY listing or mutation.
  local s8="$tmp/s8"
  mkdir -p "$s8"
  printf '%s\n' "${names[@]}" > "$s8/repo_secrets"
  : > "$s8/env_secrets"
  echo 1 > "$s8/inflight_worker.yml_in_progress"
  rc=$(run_case "$s8" "$tmp/s8.out" all)
  chk "in-flight writer -> fail closed" "$rc" 1
  chk "in-flight writer: distinct message names the workflow" \
    "$(grep -c '1 in_progress run(s) of worker.yml' "$tmp/s8.out")" 1
  chk "in-flight writer: ONLY run-list calls issued (no listing, no mutation)" \
    "$(grep -cvE '^run list ' "$s8/calls.log" || true)" 0

  # --- scenario 9: ENV LISTING FAILURE — a dead listing is a refusal, never "empty env".
  local s9="$tmp/s9"
  mkdir -p "$s9"
  printf '%s\n' "${names[@]}" > "$s9/repo_secrets"
  : > "$s9/env_secrets"
  touch "$s9/fail_env_list"
  rc=$(run_case "$s9" "$tmp/s9.out" all)
  chk "failed env listing -> fail closed before any mutation" "$rc" 1
  chk "failed env listing: zero mutations" \
    "$(grep -cE '^secret (set|delete) ' "$s9/calls.log" || true)" 0

  if [[ "$failures" -eq 0 ]]; then
    printf 'migrate-secrets self-test PASSED\n'
    return 0
  fi
  printf 'migrate-secrets self-test FAILED (%s failure(s))\n' "$failures"
  return 1
}

case "${1:-migrate}" in
  --self-test | self-test) self_test ;;
  migrate) migrate ;;
  *) die 'usage: migrate-secrets.sh [--self-test]' ;;
esac
