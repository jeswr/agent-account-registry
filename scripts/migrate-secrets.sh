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
#   --phase main (env-UNBOUND job; needs Secrets RW + Environments RW + Actions RW):
#     M0a. QUIESCE (sol round-5 finding 1a — the late-writer race): `gh workflow disable` each of
#          the four secret-WRITER workflows (worker / review-fix / set-up-account / pat-validity)
#          BEFORE anything else — a disabled workflow cannot start a NEW run (and a `gh run
#          rerun` of an old pre-env-binding snapshot is refused too), so no writer can begin
#          mid-migration. The workflow's always() `reenable-writers` job re-enables them after
#          cleanup via `--phase resume-writers`. Workflow disable/enable sit under the
#          fine-grained "Actions" WRITE permission — an under-granted token dies HERE, before any
#          listing or mutation.
#     M0b. pre-flight: refuse (fail closed) while any secret-writer run sits in ANY nonterminal
#          status — queued / in_progress / requested / waiting / pending (round-6 finding 2: a
#          run already requested, or waiting on an environment, or pending a concurrency slot
#          when the disable lands can still execute later). Quiesce stops NEW runs; this stops
#          the migration while ALREADY-ADMITTED runs (which a disable does not cancel) are
#          still alive. `gh run list` sits under the fine-grained "Actions" permission (read),
#          and every invocation carries `--all` (round-6 finding 1): the quiesce just DISABLED
#          these workflows, and gh's name-based `--workflow` lookup excludes disabled workflows
#          without it.
#     M1. list the environment's secret NAMES and the REPO-scope secret NAMES (a failed listing
#         is a hard refusal, never "empty"). The repo listing is taken BEFORE the copy loop
#         (round-7 finding — late-writer freshness): repo-scope PRESENCE, not environment-name
#         presence, decides whether a value must be (re)copied.
#     M2. pre-mutation input check, asserted for ALL 14 BEFORE any mutation: a name whose REPO
#         copy is PRESENT requires a non-empty S_<name> (fail closed) — the env-unbound job
#         resolves S_<name> from exactly that repo copy, the authoritative/NEWEST value. An
#         environment NAME existing is NOT proof its VALUE is current (round-7 finding: env=V1,
#         a late writer rotates repo to V2, cleanup aborts on the stray + instructs a main
#         rerun; the old name-exists-skip then deleted repo V2 and left the pipeline on stale,
#         possibly revoked, V1). An env-held name needs no value ONLY when the repo copy is
#         ABSENT: that is the genuine resume-after-delete state. A name in neither scope with
#         no value is a hard fail.
#     M3. copy/refresh each name: a repo-present name is ALWAYS set (OVERWRITE) + verified from
#         S_<name> — value flows STDIN -> `gh secret set --env` (never argv), then re-list and
#         verify it landed; a set-reported-success the listing does not show is a hard fail
#         with the repo scope untouched. An env-held name is skipped ONLY when its repo copy is
#         absent — so every repo value reaches the environment BEFORE M5 deletes that name's
#         repo copy. The overwrite rule applies to the 2 bootstrap names too (env refresh yes;
#         their deletion stays cleanup-only).
#     M4. assert a fresh env listing holds all 14 (extra env names — REGISTRY_SECRETS_PAT etc. —
#         are expected and fine).
#     M5. delete ONLY the 12 NON-bootstrap repo-scope copies still present (already-absent =
#         resume path), each one guarded by the round-7 freshness rule: a name is deleted only
#         if it was in the M1 repo listing (so M3 provably refreshed its value into the
#         environment first); a name that appeared after M1 fails closed undeleted. The 2
#         bootstrap secrets are NEVER deleted in this phase — the argv-level invariant the
#         self-test asserts — so ANY cancellation leaves a state from which this phase can
#         re-mint and converge.
#     M6. assert repo scope holds none of the 12; the 2 bootstrap names remaining is EXPECTED
#         (BY DESIGN — the cleanup phase drains them); any OTHER name is a distinct hard fail.
#
#   --phase cleanup-bootstrap (`environment: dispatch-secrets`-BOUND job that minted FROM the
#     environment copies; needs Secrets RW + Environments R + Actions R):
#     C0. the same live-writer pre-flight.
#     C1. list the environment; assert it holds all 14 — with a DISTINCT refusal if a BOOTSTRAP
#         name is missing: deleting its repo-scope original then would destroy the last mint
#         credential (re-run the main phase first).
#     C2. EXACT-SET check (sol round-5 finding 1b — recoverable ordering): BEFORE deleting
#         ANYTHING, assert the repo-scope listing holds ONLY (a subset of) the 2 bootstrap names.
#         Any other name — a migrated non-bootstrap leftover (a late old-snapshot writer
#         re-created it, or the main phase did not converge) OR an unknown stray — is a hard
#         abort with a distinct message that deletes NOTHING: both bootstrap mint credentials
#         stay at repo scope, so a fresh migration remains fully MINTABLE and RERUNNABLE after
#         the stray is removed (`gh secret delete <NAME> -R <owner>/<repo>`).
#     C3. only after C2 passes: delete whichever of the 2 bootstrap repo-scope secrets remain
#         (2/1/0 — a rerun after a mid-cleanup cancellation converges; zero-remaining = success
#         no-op). RESIDUAL (tiny, documented): a stray written between C2's listing and these 2
#         deletes — eliminated in practice by the M0a quiesce (no writer workflow can start) and
#         excluded for already-running runs by C0.
#     C4. assert repo scope holds none of the 14 and surface any stray by NAME. Only after this
#         phase succeeds does the dispatch secrets-guard go green. POST-CLEANUP RUNBOOK: a stray
#         appearing LATER (e.g. an old-snapshot run re-run after re-enable) trips the dispatch
#         secrets-guard loudly; the remediation is direct admin deletion
#         (`gh secret delete <NAME> -R jeswr/agent-account-registry`) — NOT a migration rerun
#         (nothing is left to migrate, and by design the bootstrap repo copies are gone).
#
#   --phase resume-writers (the workflow's always() `reenable-writers` job, env-BOUND so its
#     mint resolves in every reachable state — repo-scope bootstrap copies before the migration,
#     environment copies after cleanup drains them; needs Actions RW ONLY): re-enable the four
#     quiesced writer workflows. Tries ALL four before failing (one failure never leaves the
#     rest disabled) and any failure names the manual remediation.
#
# Any other inconsistency is a hard fail with a distinct message. Secret VALUES are never echoed,
# never traced, never placed in argv; only NAMES are printed.
#
# Inputs (from the invoking workflow): GH_TOKEN (minted App token — see
# migrate-secrets-to-env.yml for the per-phase grants), REGISTRY_REPO, one S_<name> env var per
# secret (main phase only), optional SECRETS_ENV (default dispatch-secrets).
#
# `--self-test` / `self-test`: hermetic fake-`gh` PATH-shim suite (trust-gate.py precedent; the
# fake models PER-SCOPE VALUES — env_values/repo_values state files, round-7 — so a freshness
# regression shows up as actual VALUE loss, not just name churn) —
# fresh-main, cleanup from 2/1/0-remaining, converged reruns of both phases,
# interrupted-after-partial-copy, interrupted-mid-deletion, set-verify-mismatch, repo-stray (both
# phases — cleanup now deletes NOTHING on a stray), late-writer leftover at cleanup time,
# late-writer V1/V2 recovery (env=V1, repo=V2: a main rerun must refresh the env to V2 BEFORE
# the repo delete), repo-present-without-value fail-closed, pure-resume (env-held + repo-absent
# -> zero mutations),
# missing-input, in-flight-writer (one scenario per NONTERMINAL run status — queued /
# in_progress / requested / waiting / pending — each must abort), the fake-gh DISABLED-workflow
# model (name-based run lookup without --all fails on a disabled workflow, with --all works —
# so dropping --all from the preflight goes red), listing-failure (both phases),
# env-missing-bootstrap,
# resume-writers (happy / one-enable-fails / under-granted), and PER-ENDPOINT PERMISSION-model
# failures (workflow disable without actions:write — incl. the old actions:read-only mint shape;
# env-secret write without environments:write) so an under-granted mint is caught by the
# harness, not production. Exact argv sequences (4 disables BEFORE any set, env set via STDIN,
# no --body, ZERO bootstrap deletes in the main phase, 4 enables in the always path) are
# asserted. The suite also STATICALLY pins the WORKFLOW's declared mint grants (round-4 finding
# 3: the fake-gh model alone never noticed a permission line deleted from
# migrate-secrets-to-env.yml): check_workflow_mint_contract asserts all THREE mint steps'
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

# Quiesce (sol round-5 finding 1a): disable every writer workflow BEFORE the migration touches
# anything, so no NEW writer run — including a `gh run rerun` of an old pre-env-binding snapshot
# — can start mid-migration. Idempotent (disabling a disabled workflow succeeds). The always()
# reenable-writers job undoes this via `--phase resume-writers` even when a phase fails.
quiesce_writers() {
  local wf
  for wf in "${WRITER_WORKFLOWS[@]}"; do
    gh workflow disable "$wf" -R "$REPO" \
      || die "gh workflow disable ${wf} failed — cannot quiesce the secret writers, refusing before any listing or mutation (fail closed; NOTE: workflow disable needs the App token's Actions: write grant)"
    printf 'quiesced (workflow disabled): %s\n' "$wf"
  done
}

# The pre-flight runs AFTER quiesce_writers has DISABLED the writer workflows, and gh's
# name-based workflow lookup (`--workflow <file>`) EXCLUDES disabled workflows unless `--all`
# is supplied (round-6 finding 1) — without it the listing fails (or silently omits) for
# exactly the runs it must inspect. `--all` is therefore LOAD-BEARING on every invocation.
# And "live" means every NONTERMINAL run status GitHub models (round-6 finding 2): queued /
# in_progress / requested / waiting / pending — a run already requested, or parked waiting on
# an environment approval, or pending a concurrency slot when the disable lands can still
# execute later (the writers use concurrency groups + the dispatch-secrets environment, so
# waiting/pending are real states here). gh's `--status` flag takes ONE status per call, so
# each is queried per-status.
preflight_no_live_writers() {
  local wf status count
  for wf in "${WRITER_WORKFLOWS[@]}"; do
    for status in queued in_progress requested waiting pending; do
      count=$(gh run list --all -R "$REPO" --workflow "$wf" --status "$status" \
                --json databaseId --jq length) \
        || die "could not list ${status} runs of ${wf} — cannot prove no live secret writer (fail closed; NOTE: this listing needs the App token's Actions: read grant, and --all is load-bearing: a name-based lookup without it excludes the workflows the quiesce just DISABLED)"
      [[ "$count" =~ ^[0-9]+$ ]] \
        || die "unparseable ${status} run count for ${wf} — cannot prove no live secret writer (fail closed)"
      if [[ "$count" -gt 0 ]]; then
        die "${count} ${status} run(s) of ${wf} — a live secret writer could race the migration; wait for it to finish, then re-run (the migration is idempotent)"
      fi
    done
  done
  printf 'pre-flight: no nonterminal (queued/in_progress/requested/waiting/pending) secret-writer runs\n'
}

phase_main() {
  setup
  echo '== phase M0a: quiesce — disable the 4 secret-writer workflows (no NEW writer run can start mid-migration) =='
  quiesce_writers
  echo '== phase M0b: pre-flight — no ALREADY-RUNNING secret-writer runs (quiesce does not cancel in-flight runs) =='
  preflight_no_live_writers

  echo '== phase M1: list the environment + repo-scope secret names (resume/freshness state) =='
  local env_names repo_names
  env_names=$(_env_names) \
    || die "could not list secrets of environment '${ENV_NAME}' — refusing before any mutation (fail closed)"
  # Round-7 freshness rule (sol): the REPO listing is taken BEFORE the copy loop because
  # repo-scope PRESENCE — not environment-name presence — decides freshness. A repo copy that
  # exists at migration time carries the authoritative/NEWEST value (e.g. a late writer's token
  # rotation landed there after the env copy was made), and the env-unbound main job's S_<name>
  # input resolves exactly that repo-scope value. An environment NAME alone proves nothing
  # about its VALUE being current.
  repo_names=$(_repo_names) \
    || die 'could not list repo-scope secrets — refusing before any mutation (fail closed)'

  echo '== phase M2: pre-mutation input check (no mutation until every needed value is proven present) =='
  local name var
  for name in "${SECRET_NAMES[@]}"; do
    var="S_${name}"
    if _has_name "$name" "$repo_names"; then
      # A repo copy EXISTS, so its value is the authoritative/newest one and the environment
      # copy (whatever the name listing says) may be STALE: S_<name> is REQUIRED so M3 can
      # refresh the environment BEFORE M5 deletes the repo copy.
      [[ -n "${!var:-}" ]] \
        || die "repo-scope copy of ${name} exists (its value is the authoritative/newest one) but S_${name} is empty/missing — cannot refresh the environment copy before the repo-scope deletion; aborting BEFORE any mutation (fail closed)"
      printf 'repo copy present (authoritative value — will REFRESH the environment copy): %s\n' "$name"
    elif _has_name "$name" "$env_names"; then
      # Repo copy ABSENT + env name present: the genuine resume-after-delete state (a previous
      # attempt already refreshed + deleted this name) — the only state where the env NAME is
      # accepted as sufficient.
      printf 'already in %s AND repo scope clear (resume path — no value required): %s\n' "$ENV_NAME" "$name"
    else
      [[ -n "${!var:-}" ]] \
        || die "value for ${name} is empty/missing AND the environment does not hold it — cannot converge; aborting BEFORE any mutation (were it a crash-rerun, the environment listing would already show the name)"
      printf 'present (will copy): %s\n' "$name"
    fi
  done

  echo '== phase M3: copy/refresh into the environment (repo-present names ALWAYS overwritten; value via STDIN, never argv) =='
  local post
  for name in "${SECRET_NAMES[@]}"; do
    if ! _has_name "$name" "$repo_names" && _has_name "$name" "$env_names"; then
      printf 'skip copy (repo scope clear + env already holds it — genuine resume): %s\n' "$name"
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
  local repo_now
  repo_now=$(_repo_names) \
    || die 'could not list repo-scope secrets — refusing to delete blind (fail closed)'
  for name in "${NONBOOTSTRAP_NAMES[@]}"; do
    if _has_name "$name" "$repo_now"; then
      # Round-7 freshness guard (defense-in-depth): every name deleted here MUST have been in
      # the M1 repo listing, i.e. M3 provably refreshed its authoritative repo value into the
      # environment. A copy that appeared only AFTER M1 was never refreshed (a writer slipped
      # past the quiesce) — deleting it would destroy the newest value, so fail closed.
      _has_name "$name" "$repo_names" \
        || die "repo-scope ${name} appeared AFTER the M1 freshness listing — its value was never refreshed into the environment; refusing to delete it (fail closed; re-run the main phase so M3 refreshes it first)"
      gh secret delete "$name" --repo "$REPO" \
        || die "gh secret delete ${name} failed — re-run to converge (the environment copy is already verified)"
      printf 'deleted repo-scope: %s\n' "$name"
    else
      printf 'skip delete (repo scope already clear): %s\n' "$name"
    fi
  done

  echo '== phase M6: assert repo scope holds none of the 12 (bootstrap remaining is BY DESIGN) =='
  repo_now=$(_repo_names) \
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
  done <<<"$repo_now"
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

  echo '== phase C2: EXACT-SET check — repo scope must hold ONLY (a subset of) the 2 bootstrap names BEFORE any deletion =='
  # RECOVERABLE ORDERING (sol round-5 finding 1b): this check runs BEFORE either bootstrap
  # delete. Any non-bootstrap name in the listing — however it got there (a late old-snapshot
  # writer run, an unconverged main phase, an unrelated stray) — aborts the phase with ZERO
  # deletions, so both bootstrap mint credentials survive and a fresh migration stays mintable
  # and rerunnable once the stray is removed. The only residual window is a stray written
  # between this listing and the 2 deletes in C3 — eliminated in practice by the M0a quiesce
  # (no writer workflow can start) plus C0 (no already-running writer).
  local repo_names
  repo_names=$(_repo_names) \
    || die 'could not list repo-scope secrets — refusing to delete blind (fail closed)'
  local stray=0 leftover=0
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    if _in "$name" "${BOOTSTRAP_NAMES[@]}"; then
      printf 'repo scope holds (expected; will delete): %s\n' "$name"
    elif _in "$name" "${NONBOOTSTRAP_NAMES[@]}"; then
      printf '::error::migrate-secrets: migrated non-bootstrap secret %s present at repo scope at cleanup time (a late writer run re-created it, or the main phase did not converge)\n' "$name" >&2
      leftover=1
    else
      printf '::error::migrate-secrets: unexpected non-migrated repo-scope secret at cleanup time: %s\n' "$name" >&2
      stray=1
    fi
  done <<<"$repo_names"
  if [[ "$leftover" -ne 0 || "$stray" -ne 0 ]]; then
    die 'repo scope is NOT exactly the bootstrap set — deleting NOTHING (both bootstrap mint credentials stay at repo scope, so the migration remains fully mintable + rerunnable): remove the stray (gh secret delete <NAME> -R <owner>/<repo>) or re-run the main phase for a migrated leftover, then re-run this cleanup phase'
  fi
  printf 'repo scope holds only (a subset of) the 2 bootstrap names — safe to delete\n'

  echo '== phase C3: delete whichever of the 2 bootstrap repo-scope secrets remain (2/1/0) =='
  for name in "${BOOTSTRAP_NAMES[@]}"; do
    if _has_name "$name" "$repo_names"; then
      gh secret delete "$name" --repo "$REPO" \
        || die "gh secret delete ${name} failed — re-run to converge (the environment copy is already verified)"
      printf 'deleted repo-scope bootstrap: %s\n' "$name"
    else
      printf 'skip delete (repo scope already clear — zero-remaining is a success no-op): %s\n' "$name"
    fi
  done

  echo '== phase C4: assert repo scope holds none of the 14 (and surface any stray by NAME) =='
  repo_names=$(_repo_names) \
    || die 'could not list repo-scope secrets for the final assertion (fail closed)'
  stray=0; leftover=0
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
    || die 'both phases have converged for the 14, but the secrets-guard requires an EMPTY repo scope — an admin deletes the stray secret(s) named above directly (gh secret delete <NAME> -R <owner>/<repo>); a migration rerun is NOT the remediation here (nothing is left to migrate)'
  printf 'MIGRATION COMPLETE (both phases): all 14 live in %s and the repo scope holds none of them — the secrets-guard goes green now. Delete migrate-secrets-to-env.yml (and unenrol+delete this script). Any LATER repo-scope stray trips the secrets-guard loudly; remediation is direct admin deletion, not a migration rerun.\n' "$ENV_NAME"
}

# Re-enable the four quiesced writer workflows (the workflow's always() reenable-writers job).
# Tries ALL four before failing so one failure never leaves the rest disabled; idempotent
# (enabling an enabled workflow succeeds).
phase_resume() {
  setup
  echo '== phase R: re-enable the 4 quiesced secret-writer workflows (always path) =='
  local wf failures=0
  for wf in "${WRITER_WORKFLOWS[@]}"; do
    if gh workflow enable "$wf" -R "$REPO"; then
      printf 're-enabled: %s\n' "$wf"
    else
      printf '::error::migrate-secrets: gh workflow enable %s failed — re-enable it manually: gh workflow enable %s -R %s (NOTE: workflow enable needs the App token'"'"'s Actions: write grant)\n' "$wf" "$wf" "$REPO" >&2
      failures=1
    fi
  done
  [[ "$failures" -eq 0 ]] \
    || die 'one or more writer workflows are still DISABLED — re-enable them manually (gh workflow enable <file> -R <owner>/<repo>), then verify with gh workflow list'
  printf 'all %d writer workflows re-enabled\n' "${#WRITER_WORKFLOWS[@]}"
}

# ---------------------------------------------------------------------------------------------
# WORKFLOW MINT CONTRACT (sol review round 4 of #275, finding 3 — vacuity gap): the fake-gh
# permission model above tests the SCRIPT's behavior under an under-granted token, but nothing
# tied the WORKFLOW's declared mint grants to it — deleting both `permission-actions: read`
# lines from migrate-secrets-to-env.yml still passed every scenario. This static assertion
# (anchored awk over the stable two-space job indentation — the repo toolchain carries no
# PyYAML) pins ALL THREE create-github-app-token steps' EXACT phase-specific grant sets
# (round-5 finding 1a moved the main mint's Actions grant read -> WRITE for the quiesce
# `gh workflow disable`, and added the always() reenable job with an Actions-write-ONLY mint;
# the cleanup mint stays at Actions read — it never disables/enables):
#   main job `migrate`:            secrets: write + environments: write + actions: write
#   job `cleanup-bootstrap`:       secrets: write + environments: read  + actions: read
#   job `reenable-writers`:        actions: write ONLY (no secrets/environments power at all)
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
  want=$(printf 'permission-actions: write\npermission-environments: write\npermission-secrets: write')
  got=$(_mint_grants "$wf" migrate)
  if [[ "$got" != "$want" ]]; then
    printf '::error::migrate-secrets: workflow contract violated — the MAIN mint (job migrate) must declare EXACTLY {permission-secrets: write, permission-environments: write, permission-actions: write (round-5 quiesce: gh workflow disable)}; found:\n%s\n' "${got:-<none>}" >&2
    rc=1
  fi
  want=$(printf 'permission-actions: read\npermission-environments: read\npermission-secrets: write')
  got=$(_mint_grants "$wf" cleanup-bootstrap)
  if [[ "$got" != "$want" ]]; then
    printf '::error::migrate-secrets: workflow contract violated — the CLEANUP mint (job cleanup-bootstrap) must declare EXACTLY {permission-secrets: write, permission-environments: read, permission-actions: read}; found:\n%s\n' "${got:-<none>}" >&2
    rc=1
  fi
  want=$(printf 'permission-actions: write')
  got=$(_mint_grants "$wf" reenable-writers)
  if [[ "$got" != "$want" ]]; then
    printf '::error::migrate-secrets: workflow contract violated — the RE-ENABLE mint (job reenable-writers) must declare EXACTLY {permission-actions: write} and NOTHING else (least privilege: it only runs gh workflow enable); found:\n%s\n' "${got:-<none>}" >&2
    rc=1
  fi
  return "$rc"
}

# ---------------------------------------------------------------------------------------------
# Hermetic self-test: a fake `gh` on PATH (trust-gate.py precedent) records every argv line and
# every STDIN payload, serves listings from a mutable state dir, and — new in review round 3 —
# models PER-ENDPOINT fine-grained PERMISSIONS via an optional grants file (absent = fully
# granted), so an under-granted App mint (e.g. no Actions: write for the quiesce `gh workflow
# disable` — including the old Actions: read-only mint shape — no Environments: write for the
# env-secret set) is caught by this harness instead of a live 403. Fresh, resumed,
# cleanup-remaining, mismatched, stray, late-writer, under-granted, resume-writers, and in-flight
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
# line (actions:read, actions:write, secrets:read, secrets:write, environments:read,
# environments:write). An ABSENT grants file means fully granted (the pre-round-3 scenarios).
# Each endpoint checks the permission the REST docs put it under and answers a 403-shaped
# failure without it — so a finding-1-class defect (a mint missing a load-bearing grant) turns
# a scenario red here. Workflow disable/enable (the round-5 quiesce) sit under Actions: WRITE.
_grant() {
  [[ ! -f "$state/grants" ]] && return 0
  grep -qxF -- "$1" "$state/grants"
}
case "$*" in
  "workflow disable "*" -R o/r")
    _grant actions:write \
      || { echo "HTTP 403: Resource not accessible by integration (workflow disable needs Actions: write)" >&2; exit 1; }
    touch "$state/disabled_$3"   # model gh state: the workflow is now DISABLED
    exit 0 ;;
  "workflow enable "*" -R o/r")
    _grant actions:write \
      || { echo "HTTP 403: Resource not accessible by integration (workflow enable needs Actions: write)" >&2; exit 1; }
    [[ -f "$state/fail_enable_$3" ]] && exit 1
    rm -f "$state/disabled_$3"
    exit 0 ;;
  "run list --all -R o/r --workflow "*" --status "*" --json databaseId --jq length")
    # WITH --all, gh's name-based workflow lookup includes DISABLED workflows (round-6
    # finding 1) — serve the live count regardless of disabled state.
    _grant actions:read \
      || { echo "HTTP 403: Resource not accessible by integration (workflow-run listing needs Actions: read)" >&2; exit 1; }
    f="$state/inflight_${7}_${9}"
    if [[ -f "$f" ]]; then cat "$f"; else echo 0; fi
    exit 0 ;;
  "run list -R o/r --workflow "*" --status "*" --json databaseId --jq length")
    # WITHOUT --all, real gh EXCLUDES disabled workflows from the name-based lookup — the
    # lookup fails for a workflow the quiesce disabled. Modeling this makes the preflight's
    # --all argv contract NON-VACUOUS: strip --all from the script and scenario 1 (which
    # disables the writers first) goes red here instead of silently listing nothing.
    _grant actions:read \
      || { echo "HTTP 403: Resource not accessible by integration (workflow-run listing needs Actions: read)" >&2; exit 1; }
    if [[ -f "$state/disabled_${6}" ]]; then
      echo "could not find any workflows named ${6} (it is disabled; use --all to include disabled workflows)" >&2
      exit 1
    fi
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
      # PER-SCOPE VALUE model (round-7): the env scope now holds THIS value for the name —
      # an overwrite replaces any previous (possibly stale) value, so a freshness regression
      # in the script is observable as the env ENDING on the wrong value, not just name churn.
      if [[ -f "$state/env_values" ]]; then
        grep -v "^$3=" "$state/env_values" > "$state/env_values.new" || true
        mv "$state/env_values.new" "$state/env_values"
      fi
      printf '%s=%s\n' "$3" "$val" >> "$state/env_values"
    fi
    exit 0 ;;
  "secret delete "*" --repo o/r")
    _grant secrets:write \
      || { echo "HTTP 403: Resource not accessible by integration (repo-secret DELETE needs Secrets: write)" >&2; exit 1; }
    if [[ -f "$state/repo_secrets" ]]; then
      grep -vxF -- "$3" "$state/repo_secrets" > "$state/repo_secrets.new" || true
      mv "$state/repo_secrets.new" "$state/repo_secrets"
    fi
    # PER-SCOPE VALUE model (round-7): a repo delete destroys the repo-scope value for good —
    # if the env was never refreshed from it, that value is GONE (exactly the loss the
    # late-writer V1/V2 scenario asserts cannot happen).
    if [[ -f "$state/repo_values" ]]; then
      grep -v "^$3=" "$state/repo_values" > "$state/repo_values.new" || true
      mv "$state/repo_values.new" "$state/repo_values"
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

  # run_case STATE_DIR OUT_FILE PHASE VALUE_MODE(all|none|repo-newest) [EMPTY_NAME]
  run_case() {
    local state=$1 out=$2 phase=$3 mode=$4 empty_name=${5:-}
    local -a assigns=(PATH="$tmp/bin:$PATH" FAKE_GH_STATE="$state" REGISTRY_REPO=o/r)
    local n
    for n in "${names[@]}"; do
      case "$mode" in
        all) assigns+=("S_${n}=v-${n}") ;;
        none) assigns+=("S_${n}=") ;;
        repo-newest)
          # The production input shape: the env-UNBOUND main job resolves S_<name> from the
          # REPO-scope secret, so a present repo copy supplies its (newest, v2-) value and a
          # deleted one resolves EMPTY — exactly what a rerun after a late writer sees.
          if grep -qxF -- "$n" "$state/repo_secrets" 2>/dev/null; then
            assigns+=("S_${n}=v2-${n}")
          else
            assigns+=("S_${n}=")
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
    for st in queued in_progress requested waiting pending; do
      printf 'run list --all -R o/r --workflow %s --status %s --json databaseId --jq length\n' "$wf" "$st" >> "$expected_preflight"
    done
  done
  # The round-5 quiesce prefix: the main phase disables all 4 writer workflows BEFORE the
  # pre-flight (disable-then-check is the race-free order: no NEW run can start after the
  # disable, and the pre-flight then proves no already-running run remains).
  local expected_quiesce="$tmp/expected-quiesce.log" expected_resume="$tmp/expected-resume.log"
  : > "$expected_quiesce"
  : > "$expected_resume"
  for wf in worker.yml review-fix.yml set-up-account.yml pat-validity.yml; do
    printf 'workflow disable %s -R o/r\n' "$wf" >> "$expected_quiesce"
    printf 'workflow enable %s -R o/r\n' "$wf" >> "$expected_resume"
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
  chk "fresh main: exactly 4 workflow disables (the quiesce), each writer once" \
    "$(grep -cE '^workflow disable ' "$s1/calls.log")" 4
  chk "fresh main: EVERY workflow disable precedes the FIRST secret set (quiesce before mutation)" \
    "$(awk '/^workflow disable /{last=NR} /^secret set /{if(!first)first=NR} END{print (last && first && last<first) ? "yes" : "no"}' "$s1/calls.log")" yes
  local expected="$tmp/expected-main.log"
  {
    cat "$expected_quiesce"
    cat "$expected_preflight"
    printf 'api repos/o/r/environments/dispatch-secrets/secrets --paginate --jq .secrets[].name\n'
    # Round-7: M1 lists the REPO scope too, BEFORE the copy loop — repo presence decides freshness.
    printf 'api repos/o/r/actions/secrets --paginate --jq .secrets[].name\n'
    for n in "${names[@]}"; do
      printf 'secret set %s --env dispatch-secrets --repo o/r\n' "$n"
      printf 'api repos/o/r/environments/dispatch-secrets/secrets --paginate --jq .secrets[].name\n'
    done
    printf 'api repos/o/r/environments/dispatch-secrets/secrets --paginate --jq .secrets[].name\n'
    printf 'api repos/o/r/actions/secrets --paginate --jq .secrets[].name\n'
    for n in "${nonboot[@]}"; do
      printf 'secret delete %s --repo o/r\n' "$n"
    done
    printf 'api repos/o/r/actions/secrets --paginate --jq .secrets[].name\n'
  } > "$expected"
  chk "fresh main: EXACT gh argv sequence (quiesce x4 -> preflight -> env+repo list -> set+verify x14 -> assert -> delete x12 NON-BOOTSTRAP ONLY -> assert)" \
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

  # --- scenario 4: MAIN INTERRUPTED AFTER PARTIAL COPY — env holds 5, repo still holds all 14.
  # Round-7: repo presence (not env-name presence) decides freshness — ALL 14 are refreshed on
  # the rerun (the 5 env-held names may hold stale values; their repo copies are authoritative,
  # and the rerun's S_ inputs resolve exactly those repo copies).
  local s4="$tmp/s4"
  mkdir -p "$s4"
  printf '%s\n' "${names[@]}" > "$s4/repo_secrets"
  printf '%s\n' "${names[@]:0:5}" > "$s4/env_secrets"
  rc=$(run_case "$s4" "$tmp/s4.out" main repo-newest)
  chk "partial-copy main rerun converges" "$rc" 0
  chk "partial-copy main rerun refreshes ALL 14 (repo-present -> overwrite, incl. the 5 env-held)" \
    "$(grep -cE '^secret set ' "$s4/calls.log")" 14
  chk "partial-copy main rerun deletes the 12 non-bootstrap repo copies" \
    "$(grep -cE '^secret delete ' "$s4/calls.log")" 12
  chk "partial-copy main rerun leaves the 2 bootstrap at repo scope" \
    "$(sort "$s4/repo_secrets" | paste -sd' ' -)" "REGISTRY_ADMIN_APP_ID REGISTRY_ADMIN_APP_KEY"

  # --- scenario 5: MAIN INTERRUPTED MID-DELETION — env complete, 6 repo copies left (4
  # non-bootstrap + the 2 bootstrap). Round-7: the 6 repo-present names REQUIRE values (their
  # repo copies are authoritative) and get refreshed — including BOTH bootstrap names (env
  # refresh yes; bootstrap deletion still cleanup-only). The 8 repo-absent env-held names are
  # the genuine resume path and need nothing.
  local s5="$tmp/s5"
  mkdir -p "$s5"
  printf '%s\n' "${names[@]}" > "$s5/env_secrets"
  printf '%s\n' "${names[@]:8}" > "$s5/repo_secrets"
  rc=$(run_case "$s5" "$tmp/s5.out" main repo-newest)
  chk "mid-deletion main rerun converges (repo-present values supplied, none for the 8 resumed)" "$rc" 0
  chk "mid-deletion main rerun refreshes exactly the 6 repo-present names (4 leftovers + 2 bootstrap)" \
    "$(grep -cE '^secret set ' "$s5/calls.log")" 6
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

  # --- scenario 10: REPO-SCOPE STRAY (main) — a non-migrated repo secret; the 12 converge
  # (round-7: all 14 repo-present names are refreshed first, values from their repo copies) but
  # the run hard-fails with a distinct message. Extra ENV names (REGISTRY_SECRETS_PAT's
  # post-cutover home is this environment) must NOT trip anything, and bootstrap stays put.
  local s10="$tmp/s10"
  mkdir -p "$s10"
  { printf '%s\n' "${names[@]}"; echo SOME_LEGACY_SECRET; } > "$s10/repo_secrets"
  { printf '%s\n' "${names[@]}"; echo REGISTRY_SECRETS_PAT; } > "$s10/env_secrets"
  rc=$(run_case "$s10" "$tmp/s10.out" main repo-newest)
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

  # --- scenario 11: REPO-SCOPE STRAY (cleanup) — round-5 finding 1b RECOVERABLE ORDERING: the
  # exact-set check runs BEFORE any deletion, so a stray aborts the phase with ZERO deletions —
  # both bootstrap mint credentials survive and the migration stays mintable + rerunnable after
  # the stray is removed. (Pre-round-5 this scenario drained the bootstrap FIRST and only then
  # failed on the stray — the unrecoverable state the review found.)
  local s11="$tmp/s11"
  mkdir -p "$s11"
  printf '%s\n' "${names[@]}" > "$s11/env_secrets"
  { printf '%s\n' "${bootstrap[@]}"; echo SOME_LEGACY_SECRET; } > "$s11/repo_secrets"
  rc=$(run_case "$s11" "$tmp/s11.out" cleanup-bootstrap none)
  chk "cleanup repo stray -> hard fail BEFORE any deletion" "$rc" 1
  chk "cleanup repo stray: ZERO deletions (bootstrap mint credentials preserved — recoverable)" \
    "$(grep -cE '^secret delete ' "$s11/calls.log" || true)" 0
  chk "cleanup repo stray: distinct deleting-NOTHING message with the admin runbook" \
    "$(grep -c 'deleting NOTHING' "$tmp/s11.out")" 1
  chk "cleanup repo stray: both bootstrap names STILL at repo scope (still fully mintable)" \
    "$(sort "$s11/repo_secrets" | paste -sd' ' -)" \
    "REGISTRY_ADMIN_APP_ID REGISTRY_ADMIN_APP_KEY SOME_LEGACY_SECRET"

  # --- scenario 11b: LATE WRITER at cleanup time (the round-5 finding-1 race): a writer run
  # that slipped in AFTER the main phase's pre-flight (e.g. an old-snapshot `gh run rerun`)
  # re-created a MIGRATED non-bootstrap name at repo scope before cleanup's exact-set check.
  # Cleanup must abort with ZERO bootstrap deletes — the previously-unrecoverable ordering
  # deleted both mint credentials first and THEN discovered the stray.
  local s11b="$tmp/s11b"
  mkdir -p "$s11b"
  printf '%s\n' "${names[@]}" > "$s11b/env_secrets"
  { printf '%s\n' "${bootstrap[@]}"; echo ACCT02_TOKEN; } > "$s11b/repo_secrets"
  rc=$(run_case "$s11b" "$tmp/s11b.out" cleanup-bootstrap none)
  chk "late-writer leftover at cleanup -> hard fail BEFORE any deletion" "$rc" 1
  chk "late-writer leftover: ZERO deletions (no bootstrap delete ever issued)" \
    "$(grep -cE '^secret delete ' "$s11b/calls.log" || true)" 0
  chk "late-writer leftover: distinct message names the late-writer cause" \
    "$(grep -c 'a late writer run re-created it, or the main phase did not converge' "$tmp/s11b.out")" 1
  chk "late-writer leftover: both bootstrap names STILL at repo scope (migration rerunnable)" \
    "$(sort "$s11b/repo_secrets" | paste -sd' ' -)" \
    "ACCT02_TOKEN REGISTRY_ADMIN_APP_ID REGISTRY_ADMIN_APP_KEY"

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
  chk "in-flight writer: ONLY quiesce + run-list calls issued (no listing, no mutation)" \
    "$(grep -cvE '^(workflow disable |run list )' "$s12/calls.log" || true)" 0

  # --- scenario 12b: EVERY NONTERMINAL RUN STATUS ABORTS (round-6 finding 2) — GitHub's active
  # statuses are queued / in_progress / requested / waiting / pending, not just the first two:
  # a run already requested, or parked waiting on an environment approval, or pending a
  # concurrency slot when the disable lands can still execute later (the writers use
  # concurrency + the dispatch-secrets environment, so waiting/pending are REAL states here).
  # One scenario per status; each must fail the preflight closed with zero mutations.
  local st sN
  for st in queued in_progress requested waiting pending; do
    sN="$tmp/s12b-$st"
    mkdir -p "$sN"
    printf '%s\n' "${names[@]}" > "$sN/repo_secrets"
    : > "$sN/env_secrets"
    echo 1 > "$sN/inflight_pat-validity.yml_${st}"
    rc=$(run_case "$sN" "$tmp/s12b-$st.out" main all)
    chk "nonterminal status ${st}: in-flight writer -> fail closed" "$rc" 1
    chk "nonterminal status ${st}: distinct message names status + workflow" \
      "$(grep -c "1 ${st} run(s) of pat-validity.yml" "$tmp/s12b-$st.out")" 1
    chk "nonterminal status ${st}: zero mutations" \
      "$(grep -cE '^secret (set|delete) ' "$sN/calls.log" || true)" 0
  done

  # --- scenario 12c: the fake-gh MODELS gh's disabled-workflow lookup semantics directly
  # (round-6 finding 1 non-vacuity): after a `workflow disable`, a name-based run listing
  # WITHOUT --all fails (real gh excludes disabled workflows from the name lookup), while the
  # same listing WITH --all serves the count. This exercises the no---all fake branch IN-SUITE,
  # so the branch the mutation check relies on (strip --all from the preflight -> scenario 1
  # goes red) is itself proven live, not assumed.
  local s12c="$tmp/s12c" noall_rc=0 withall_rc=0
  mkdir -p "$s12c"
  FAKE_GH_STATE="$s12c" "$tmp/bin/gh" workflow disable worker.yml -R o/r >/dev/null
  FAKE_GH_STATE="$s12c" "$tmp/bin/gh" run list -R o/r --workflow worker.yml --status queued --json databaseId --jq length \
    > "$tmp/s12c-noall.out" 2>&1 || noall_rc=$?
  chk "fake-gh model: name-based run list WITHOUT --all on a DISABLED workflow errors out (real gh semantics)" \
    "$noall_rc" 1
  chk "fake-gh model: the no---all failure names the disabled-workflow cause" \
    "$(grep -c 'use --all to include disabled workflows' "$tmp/s12c-noall.out")" 1
  FAKE_GH_STATE="$s12c" "$tmp/bin/gh" run list --all -R o/r --workflow worker.yml --status queued --json databaseId --jq length \
    > "$tmp/s12c-all.out" 2>&1 || withall_rc=$?
  chk "fake-gh model: the same lookup WITH --all succeeds on the disabled workflow" "$withall_rc" 0
  chk "fake-gh model: --all lookup serves the live count" "$(cat "$tmp/s12c-all.out")" 0

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

  # --- scenario 16: PERMISSION MODEL — token WITHOUT any Actions grant: the quiesce's very
  # first `gh workflow disable` 403s and the run fails closed before any listing or mutation.
  local s16="$tmp/s16"
  mkdir -p "$s16"
  printf '%s\n' "${names[@]}" > "$s16/repo_secrets"
  : > "$s16/env_secrets"
  printf 'secrets:read\nsecrets:write\nenvironments:read\nenvironments:write\n' > "$s16/grants"
  rc=$(run_case "$s16" "$tmp/s16.out" main all)
  chk "no actions grant -> quiesce fails closed" "$rc" 1
  chk "no actions grant: distinct fail-closed message on the FIRST workflow disable" \
    "$(grep -c 'gh workflow disable worker.yml failed' "$tmp/s16.out")" 1
  chk "no actions grant: zero listings, zero mutations (only the one denied disable)" \
    "$(grep -cvE '^workflow disable ' "$s16/calls.log" || true)-$(grep -cE '^workflow disable ' "$s16/calls.log")" 0-1

  # --- scenario 16b: PERMISSION MODEL — token with actions:READ only (the EXACT pre-round-5
  # mint shape): quiesce needs Actions WRITE, so the old grant set now fails closed at the
  # first disable, before any listing or mutation. This is the regression class the round-5
  # contract change guards against end-to-end.
  local s16b="$tmp/s16b"
  mkdir -p "$s16b"
  printf '%s\n' "${names[@]}" > "$s16b/repo_secrets"
  : > "$s16b/env_secrets"
  printf 'actions:read\nsecrets:read\nsecrets:write\nenvironments:read\nenvironments:write\n' > "$s16b/grants"
  rc=$(run_case "$s16b" "$tmp/s16b.out" main all)
  chk "actions:read-only grant (the pre-round-5 mint shape) -> quiesce fails closed" "$rc" 1
  chk "actions:read-only grant: message names the Actions: write requirement" \
    "$(grep -c 'needs the App token.s Actions: write grant' "$tmp/s16b.out")" 1
  chk "actions:read-only grant: zero mutations" \
    "$(grep -cE '^secret (set|delete) ' "$s16b/calls.log" || true)" 0

  # --- scenario 17: PERMISSION MODEL — token WITHOUT environments:write: the first env-secret
  # set 403s; hard fail with the repo scope untouched (no deletions ever reached).
  local s17="$tmp/s17"
  mkdir -p "$s17"
  printf '%s\n' "${names[@]}" > "$s17/repo_secrets"
  : > "$s17/env_secrets"
  printf 'actions:read\nactions:write\nsecrets:read\nsecrets:write\nenvironments:read\n' > "$s17/grants"
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
  grep -v 'permission-actions: read' "$wf_real" > "$wf_mut"   # strips the cleanup mint's actions:read
  rc=0; check_workflow_mint_contract "$wf_mut" > "$tmp/s18b.out" 2>&1 || rc=$?
  chk "contract goes RED when the cleanup permission-actions: read declaration is removed (the exact round-4 vacuity gap)" "$rc" 1
  grep -v 'permission-actions: write' "$wf_real" > "$wf_mut"  # strips the migrate AND reenable actions:write mints
  rc=0; check_workflow_mint_contract "$wf_mut" > "$tmp/s18e.out" 2>&1 || rc=$?
  chk "contract goes RED when the permission-actions: write declarations (round-5 quiesce/re-enable) are removed" "$rc" 1
  chk "contract names BOTH under-granted mints when actions:write is stripped" \
    "$(grep -c 'workflow contract violated' "$tmp/s18e.out")" 2
  sed 's/permission-actions: write/permission-actions: read/' "$wf_real" > "$wf_mut"  # the pre-round-5 shape
  rc=0; check_workflow_mint_contract "$wf_mut" > "$tmp/s18f.out" 2>&1 || rc=$?
  chk "contract goes RED when actions is WEAKENED write -> read (regression to the pre-quiesce mint shape)" "$rc" 1
  sed 's/permission-environments: write/permission-environments: read/' "$wf_real" > "$wf_mut"
  rc=0; check_workflow_mint_contract "$wf_mut" > "$tmp/s18c.out" 2>&1 || rc=$?
  chk "contract goes RED when the main-phase environments grant is WEAKENED to read" "$rc" 1
  sed 's/^          permission-secrets: write$/          permission-secrets: write\n          permission-contents: write/' \
    "$wf_real" > "$wf_mut"
  rc=0; check_workflow_mint_contract "$wf_mut" > "$tmp/s18d.out" 2>&1 || rc=$?
  chk "contract goes RED when an extra grant is silently WIDENED in (exact-set pin)" "$rc" 1

  # --- scenario 19: RESUME-WRITERS happy path (the always() job after cleanup) — exactly the
  # 4 enables, in the canonical writer order, and nothing else.
  local s19="$tmp/s19"
  mkdir -p "$s19"
  rc=$(run_case "$s19" "$tmp/s19.out" resume-writers none)
  chk "resume-writers succeeds" "$rc" 0
  chk "resume-writers: EXACT gh argv sequence (4 enables, nothing else)" \
    "$(diff -q "$expected_resume" "$s19/calls.log" >/dev/null 2>&1 && echo same || echo diff)" same

  # --- scenario 20: RESUME-WRITERS with ONE enable failing — still ATTEMPTS all 4 (one failure
  # must never leave the remaining writers disabled), then fails loud with the manual runbook.
  local s20="$tmp/s20"
  mkdir -p "$s20"
  touch "$s20/fail_enable_review-fix.yml"
  rc=$(run_case "$s20" "$tmp/s20.out" resume-writers none)
  chk "resume-writers with one enable failing -> hard fail" "$rc" 1
  chk "resume-writers with one enable failing: still attempts ALL 4 enables" \
    "$(grep -cE '^workflow enable ' "$s20/calls.log")" 4
  chk "resume-writers with one enable failing: names the manual remediation" \
    "$(grep -c 'gh workflow enable review-fix.yml failed — re-enable it manually' "$tmp/s20.out")" 1

  # --- scenario 21: PERMISSION MODEL — resume-writers without actions:write fails loud (the
  # writers would silently stay disabled otherwise).
  local s21="$tmp/s21"
  mkdir -p "$s21"
  printf 'actions:read\n' > "$s21/grants"
  rc=$(run_case "$s21" "$tmp/s21.out" resume-writers none)
  chk "resume-writers without actions:write -> hard fail" "$rc" 1
  chk "resume-writers without actions:write: still attempts ALL 4 enables" \
    "$(grep -cE '^workflow enable ' "$s21/calls.log")" 4

  # --- scenario 22: LATE-WRITER V1/V2 RECOVERY (round-7 finding — the newest-credential loss):
  # env holds V1 for all 14; a late writer (token rotation) re-created ACCT02_TOKEN at repo
  # scope with V2; cleanup aborted on the stray and instructed a main rerun. The rerun's S_
  # inputs resolve the repo copies (V2 for ACCT02_TOKEN, empty for the 13 deleted ones). The
  # OLD name-exists-skip saw the env NAME, skipped the copy, deleted repo V2 — leaving the
  # pipeline on stale (possibly revoked) V1. The rule now: repo presence => REFRESH the env
  # from S_ (overwrite) BEFORE that name's repo delete. The fake's per-scope value model makes
  # the loss observable: the env must END at V2.
  local s22="$tmp/s22"
  mkdir -p "$s22"
  printf '%s\n' "${names[@]}" > "$s22/env_secrets"
  for n in "${names[@]}"; do printf '%s=v1-%s\n' "$n" "$n"; done > "$s22/env_values"
  printf 'ACCT02_TOKEN\n' > "$s22/repo_secrets"
  printf 'ACCT02_TOKEN=v2-ACCT02_TOKEN\n' > "$s22/repo_values"
  rc=$(run_case "$s22" "$tmp/s22.out" main repo-newest)
  chk "late-writer V1/V2 recovery: main rerun succeeds" "$rc" 0
  chk "late-writer V1/V2 recovery: the env ENDS at V2 (newest credential preserved)" \
    "$(grep -c '^ACCT02_TOKEN=v2-ACCT02_TOKEN$' "$s22/env_values")" 1
  chk "late-writer V1/V2 recovery: the stale V1 env value is GONE" \
    "$(grep -c '^ACCT02_TOKEN=v1-' "$s22/env_values" || true)" 0
  chk "late-writer V1/V2 recovery: the refresh was a REAL set (stdin carried V2)" \
    "$(grep -c '^ACCT02_TOKEN=v2-ACCT02_TOKEN$' "$s22/stdin.log")" 1
  chk "late-writer V1/V2 recovery: the env SET argv precedes the repo DELETE argv (refresh-before-delete)" \
    "$(awk '/^secret set ACCT02_TOKEN --env /{if(!s)s=NR} /^secret delete ACCT02_TOKEN --repo /{if(!d)d=NR} END{print (s && d && s<d) ? "yes" : "no"}' "$s22/calls.log")" yes
  chk "late-writer V1/V2 recovery: exactly ONE set + ONE delete (the 13 repo-absent names are pure resume)" \
    "$(grep -cE '^secret set ' "$s22/calls.log")-$(grep -cE '^secret delete ' "$s22/calls.log")" 1-1
  chk "late-writer V1/V2 recovery: repo scope empty after (converged)" "$(cat "$s22/repo_secrets")" ""

  # --- scenario 22b: repo-present name with NO S_ value -> FAIL CLOSED before any mutation
  # (the env NAME existing is NOT accepted as freshness proof while a repo copy exists).
  local s22b="$tmp/s22b"
  mkdir -p "$s22b"
  printf '%s\n' "${names[@]}" > "$s22b/env_secrets"
  printf 'ACCT02_TOKEN\n' > "$s22b/repo_secrets"
  rc=$(run_case "$s22b" "$tmp/s22b.out" main none)
  chk "repo-present name with no S_ value -> fail closed" "$rc" 1
  chk "repo-present-no-value: distinct cannot-refresh-before-deletion message" \
    "$(grep -c 'cannot refresh the environment copy before the repo-scope deletion' "$tmp/s22b.out")" 1
  chk "repo-present-no-value: ZERO mutations (the stale-V1 loss window never opens)" \
    "$(grep -cE '^secret (set|delete) ' "$s22b/calls.log" || true)" 0

  # --- scenario 23: PURE RESUME (round-7) — env holds all 14 (V1), repo scope ABSENT: the one
  # state where an env NAME is sufficient (nothing newer can exist — the repo copies are gone).
  # Converges with zero values, ZERO set argv, ZERO delete argv, env values untouched.
  local s23="$tmp/s23"
  mkdir -p "$s23"
  printf '%s\n' "${names[@]}" > "$s23/env_secrets"
  for n in "${names[@]}"; do printf '%s=v1-%s\n' "$n" "$n"; done > "$s23/env_values"
  : > "$s23/repo_secrets"
  rc=$(run_case "$s23" "$tmp/s23.out" main none)
  chk "pure resume (env holds all 14, repo absent): converges with zero values" "$rc" 0
  chk "pure resume: NO set argv" "$(grep -cE '^secret set ' "$s23/calls.log" || true)" 0
  chk "pure resume: NO delete argv" "$(grep -cE '^secret delete ' "$s23/calls.log" || true)" 0
  chk "pure resume: env values untouched (all 14 still V1)" \
    "$(grep -c '=v1-' "$s23/env_values")" 14

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
      resume-writers) phase_resume ;;
      *) die 'usage: migrate-secrets.sh --phase main|cleanup-bootstrap|resume-writers | --self-test' ;;
    esac ;;
  *) die 'usage: migrate-secrets.sh --phase main|cleanup-bootstrap|resume-writers | --self-test' ;;
esac
