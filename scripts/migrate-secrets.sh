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
# So `--phase` selects one of the explicit state machines below.
#
# TWO-RUN PROTOCOL (sol round-8 finding 1 — the QUEUE-TIME secrets snapshot): GitHub captures a
# run's `secrets.*` values when the run is QUEUED (documented), so an IN-RUN quiesce (the old
# M0a `gh workflow disable`) could NEVER guarantee the S_* inputs were fresher than a writer
# rotation that landed before the run was queued — the disable happens after the snapshot is
# already fixed. Quiesce is therefore its own SECRET-FREE run, and the migrate run only ASSERTS
# it happened:
#
#   --phase quiesce (SECRET-FREE job — no S_* mapping anywhere; mint = Actions RW ONLY, so the
#     token cannot read or move any secret):
#     Q1. `gh workflow disable` each of the four secret-WRITER workflows (worker / review-fix /
#         set-up-account / pat-validity) — a disabled workflow cannot start a NEW run (and a
#         `gh run rerun` of an old pre-env-binding snapshot is refused too). Idempotent.
#     Q2. COHERENT drain check (round-8 finding 2): ONE unfiltered `gh run list --all --limit
#         1000 --json status,databaseId` snapshot per writer workflow, with the five
#         NONTERMINAL statuses (queued / in_progress / requested / waiting / pending, round-6
#         finding 2) filtered CLIENT-SIDE from that single snapshot. The old per-status query
#         loop read five DIFFERENT snapshots per workflow, so a run transitioning between
#         statuses across the queries (requested -> queued is the real forward transition)
#         could be missed by every one of them; one snapshot captures every run in whatever
#         status it holds at that instant. Fails closed while any nonterminal run remains
#         (quiesce stops NEW runs; this catches ALREADY-ADMITTED ones a disable cannot cancel).
#     On success the operator dispatches phase: migrate — that FRESH queue takes a FRESH
#     secrets snapshot which postdates this drain.
#
#   --phase main (env-UNBOUND job; needs Secrets RW + Environments RW + Actions R — READ only,
#     round 8: this phase no longer disables anything):
#     M0a. QUIESCE GATE (fail closed BEFORE any secret listing or mutation): assert each writer
#          workflow's API state is `disabled_manually` — i.e. a quiesce run happened and nobody
#          resumed since. If not: "run phase: quiesce first and wait for success". WHY the
#          in-run assertion suffices for freshness: the operator queued this run AFTER
#          observing quiesce succeed, so the queue-time snapshot postdates the drain; quiesce
#          proved a moment with the writers disabled AND zero nonterminal writer runs, disabled
#          workflows admit no new run, and this gate proves they are STILL disabled + drained —
#          so no writer executed between the drain and this gate, which brackets the queue
#          instant. (Residual, accepted: an out-of-band actions-admin re-enable -> run ->
#          re-disable inside the window; that is the operator's own credential class.)
#     M0b. the same COHERENT drain check as Q2. Workflow-state reads and `gh run list` sit
#          under the fine-grained "Actions" permission (read); every listing carries `--all`
#          (round-6 finding 1): the writers ARE disabled here, and gh's name-based `--workflow`
#          lookup excludes disabled workflows without it.
#     M0c. TOTAL-ORDER ORDERING ATTESTATION (sol round-9 finding 1 — remedy b; HARDENED by sol
#          round-10: a newest-SUCCESSFUL-quiesce selection accepted a SUPERSEDED quiesce — Q1
#          succeeds -> phase: resume re-enables the writers -> a writer starts -> Q2 disables
#          but FAILS its drain (the writer is live) -> migrate queued during Q2 snapshots V1 ->
#          the writer rotates V1 -> V2 and finishes -> M0a/M0b pass at start time (disabled +
#          drained NOW) -> a success-only filter ignores failed Q2 and accepts pre-queue Q1 ->
#          M3 overwrites V2 with stale V1 and M5 deletes repo V2). A migrate run DISPATCHED
#          while a quiesce run was still executing sits PENDING in the workflow's shared
#          concurrency group with its `secrets.*` snapshot already fixed at QUEUE time — from
#          BEFORE the drain finished — so start-time state checks can never catch it. The rule:
#          fetch THIS run's created_at (GET /repos/{repo}/actions/runs/$GITHUB_RUN_ID — the
#          runner's default env var), list this workflow's runs, and consider EVERY quiesce AND
#          resume event — display_title 'migrate-secrets [quiesce]' OR 'migrate-secrets
#          [resume]', ANY conclusion, ANY actor/branch/attempt (the workflow's `run-name`
#          encodes the phase — the run-listing API does not expose workflow_dispatch inputs) —
#          whose created_at STRICTLY precedes this run's created_at. The NEWEST such event
#          must be a QUIESCE with conclusion success, FIELD-ATTESTED (sol round 12: a quiesce
#          RUN whose job was SKIPPED by its if-condition — actor/ref gate false, e.g. a
#          COLLABORATOR dispatched it — still reports run conclusion=success while disabling
#          and draining NOTHING, so displayTitle+conclusion+timestamps alone attest nothing:
#          the winning event must ALSO carry actor.login==jeswr AND
#          triggering_actor.login==jeswr AND head_branch==master AND run_attempt==1, the exact
#          conditions under which the job provably EXECUTED; the listing is therefore the REST
#          runs endpoint — `gh run list --json` exposes no actor fields), and its updated_at
#          (completion) must be STRICTLY BEFORE this run's created_at. Newest event a
#          FAILED/cancelled quiesce -> fail closed (the latest quiesce attempt did not succeed
#          — its drain is unproven). Newest event an unattested 'success' quiesce -> REJECTED,
#          fail closed (same as a failed quiesce). Newest event a RESUME -> fail closed (the
#          writers were re-enabled after the last successful quiesce) — DELIBERATELY regardless
#          of the resume's OWN fields: ANY newer quiesce-or-resume event, whatever its fields,
#          blocks unless it is a fully-attested successful quiesce (the simple fail-closed
#          direction; a collaborator-skipped resume costs one spurious re-quiesce, never a
#          stale-snapshot migrate). Newest event an IN-PROGRESS quiesce (no conclusion yet) ->
#          fail closed (unproven). All with zero mutations: quiesce must COMPLETE before
#          migrate is QUEUED (queue-time secrets snapshot) — re-run phase: quiesce, then
#          re-dispatch.
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
#     C0. the same M0a quiesce gate + M0b coherent drain check + M0c ordering attestation (a
#         cleanup-only rerun after an accidental resume must fail closed the same way —
#         re-dispatch phase: quiesce, then phase: migrate, which converges through main as a
#         no-op and re-runs this phase).
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
#   ATTEMPT GATE — ALL FOUR PHASES (sol round-11 finding — M0c is NOT attempt-aware):
#     GITHUB_RUN_ID is CONSTANT across `gh run rerun` attempts while GITHUB_RUN_ATTEMPT
#     increments, so a RE-RUN of an old migrate run fetches the ORIGINAL attempt's created_at
#     and total-orders the quiesce/resume history against THAT instant — every resume/Q2 event
#     that landed AFTER the original queue is excluded from the order by the strictly-precedes
#     filter, while the re-run attempt's own secrets-snapshot timing diverges from that
#     timestamp: M0c would attest an ordering that held for attempt 1, not for THIS attempt.
#     Rather than make the attestation attempt-aware, re-runs are PROHIBITED outright (the
#     simplest total kill): every phase asserts GITHUB_RUN_ATTEMPT == 1 as its FIRST check —
#     before setup, before any gh invocation — and fails closed otherwise: "re-runs are
#     prohibited for this workflow (queue-time attestation is attempt-unaware) — dispatch a
#     FRESH run of this phase". An UNSET GITHUB_RUN_ATTEMPT fails closed the same way (absent
#     is NEVER assumed to mean attempt 1 — pinned semantics). Recovery is always a fresh
#     workflow_dispatch of the same phase (cheap; the two-run protocol + total-order
#     attestation then apply cleanly at the fresh queue time). GITHUB_RUN_ATTEMPT is the
#     runner's default env var, exactly like GITHUB_RUN_ID — the workflow does not (and, the
#     GITHUB_* prefix being reserved, cannot) re-map it.
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
# quiesce-phase (fresh / in-flight-writer / under-granted / transitioning-run), fresh-main,
# MIGRATE-WITHOUT-QUIESCE (round-8: writers active or only partly disabled -> fail closed with
# zero mutations, naming the runbook), cleanup from 2/1/0-remaining, converged reruns of both
# phases, interrupted-after-partial-copy, interrupted-mid-deletion, set-verify-mismatch,
# repo-stray (both phases — cleanup deletes NOTHING on a stray), late-writer leftover at cleanup
# time, late-writer V1/V2 recovery (env=V1, repo=V2: a main rerun must refresh the env to V2
# BEFORE the repo delete), repo-present-without-value fail-closed, pure-resume (env-held +
# repo-absent -> zero mutations), missing-input, in-flight-writer (one scenario per NONTERMINAL
# run status — queued / in_progress / requested / waiting / pending — each must be CAUGHT by
# the client-side snapshot filter and abort; terminal `completed` runs must NOT trip it),
# TRANSITIONING-run (round-8 finding 2: the fake models a run moving requested -> queued
# between listing calls — the legal interleaving every per-status query misses; reverting the
# drain check to the old per-status loop turns this scenario red, while the single-snapshot
# check catches the run), the fake-gh DISABLED-workflow model (name-based run lookup without
# --all fails on a disabled workflow, with --all works — so dropping --all from the drain check
# goes red), listing-failure (both phases), env-missing-bootstrap, resume-writers (happy /
# one-enable-fails / under-granted), and PER-ENDPOINT PERMISSION-model failures (workflow
# disable without actions:write on the QUIESCE phase; env-secret write without
# environments:write; plus the round-8 least-privilege ACCEPT direction: the migrate phase
# converges under actions:READ) so an under-granted mint is caught by the harness, not
# production. The fake gh serves each drain listing as ONE coherent JSON snapshot and applies
# the caller's --jq expression with REAL jq, so the filter's content is exercised, not assumed.
# Exact argv sequences (the M0a/M0b gate BEFORE any listing or set, env set via STDIN, no
# --body, ZERO bootstrap deletes in the main phase, ZERO disables outside the quiesce phase, 4
# enables in the resume path) are asserted. Round 9: QUEUE-TIME ORDERING VIOLATION (migrate
# queued while quiesce was still executing — the newest successful quiesce COMPLETED after this
# run's created_at; must fail closed with zero mutations and the rotated V2 repo values
# untouched; an OLDER successful quiesce decoy in the same listing proves the check selects the
# NEWEST, and INVERTING the timestamp comparison turns the scenario red) plus
# latest-quiesce-attempt-failed (a failed quiesce as the newest event + a successful MIGRATE
# decoy — neither may satisfy the attestation) and no-quiesce/resume-event-at-all. Round 10:
# SUPERSEDED-QUIESCE total-order scenarios — sol's exact sequence (Q1 success -> resume -> Q2
# FAILED drain, migrate queued during Q2, every repo value rotated to V2: must fail closed
# with zero mutations and V2 untouched, for the main AND cleanup phases), newest-event-is-a-
# RESUME -> fail closed, newest-event-is-an-IN-PROGRESS-quiesce (null conclusion) -> fail
# closed; reverting the event filter to the old success-only-quiesce selection turns all of
# them red (the harness shows the V2 values being destroyed). Round 11: RE-RUN PROHIBITED —
# GITHUB_RUN_ATTEMPT=2 on EVERY phase fails closed with ZERO gh invocations (the gate precedes
# every call); an UNSET GITHUB_RUN_ATTEMPT fails closed identically (absent never means 1);
# and sol's exact re-run sequence (attempt=2 presenting the ORIGINAL attempt's created_at with
# a NEWER resume + failed-Q2 history the strictly-precedes filter excludes, every repo value
# rotated to V2) must fail closed with V2 untouched — commenting out the assert_first_attempt
# calls lets that scenario reach the mutation stage (rc 0, 26 mutations, V2 destroyed), which
# the harness turns red. Round 12: SKIPPED-'SUCCESS' QUIESCE (a collaborator-dispatched
# quiesce run whose job the actor/ref if-condition SKIPPED still reports run
# conclusion=success) — sol's sequence (a legit jeswr quiesce FAILS its drain, then the
# collaborator skipped-'success' quiesce supersedes it as the newest event; every repo value
# rotated to V2) must fail closed with zero mutations and V2 untouched for the main AND
# cleanup phases; plus one rejection scenario per attested field (triggering_actor mismatch /
# off-master head_branch / run_attempt 2 on an otherwise-valid newest quiesce). Dropping the
# actor pin (or any other field pin) from the winning-event check turns them red — the
# harness shows the V2 values being destroyed. The suite also STATICALLY pins the WORKFLOW's
# declared mint grants (round-4 finding 3: the fake-gh model alone never noticed a permission
# line deleted from migrate-secrets-to-env.yml): check_workflow_mint_contract asserts all FOUR
# mint steps' exact phase-specific `permission-*` sets and goes red on any
# removal/weakening/widening — and (round-9 finding 2) check_workflow_actor_contract pins BOTH
# `github.actor == 'jeswr'` AND `github.triggering_actor == 'jeswr'` on every phase job's `if:`
# (github.actor stays the ORIGINAL initiator on a re-run while triggering_actor is the
# re-runner, so actor-only lets a write-access user re-run a jeswr run under the secret-admin
# mint); dropping the triggering_actor clause goes red.
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

# ATTEMPT GATE (sol round-11 finding — M0c is NOT attempt-aware): GITHUB_RUN_ID stays CONSTANT
# across `gh run rerun` attempts while GITHUB_RUN_ATTEMPT increments, so a re-run of an old
# migrate run would fetch the ORIGINAL attempt's created_at and total-order the quiesce/resume
# history against THAT instant — every resume/Q2 event newer than the original queue excluded —
# while this attempt's own secrets-snapshot timing diverges from that timestamp. Total kill:
# EVERY phase calls this FIRST (before setup, before any gh invocation) and fails closed on
# anything but a literal attempt 1. An UNSET GITHUB_RUN_ATTEMPT fails closed too — absent is
# NEVER assumed to mean attempt 1 (pinned by the self-test's absent scenarios). Recovery is a
# FRESH workflow_dispatch of the same phase; never a re-run.
assert_first_attempt() {
  local attempt=${GITHUB_RUN_ATTEMPT:-}
  [[ -n "$attempt" ]] \
    || die "GITHUB_RUN_ATTEMPT is unset — cannot prove this is a fresh attempt-1 run (absent is NEVER assumed to mean attempt 1), and re-runs are prohibited for this workflow (queue-time attestation is attempt-unaware) — dispatch a FRESH run of this phase (fail closed before any API call)"
  [[ "$attempt" == "1" ]] \
    || die "GITHUB_RUN_ATTEMPT is ${attempt}, not 1 — re-runs are prohibited for this workflow (queue-time attestation is attempt-unaware: GITHUB_RUN_ID is constant across re-runs, so the M0c total order would run against the ORIGINAL attempt's created_at while this attempt's secrets-snapshot timing diverges from it) — dispatch a FRESH run of this phase (fail closed before any API call)"
  printf 'attempt gate: GITHUB_RUN_ATTEMPT == 1 (fresh dispatch — re-runs are prohibited for this workflow)\n'
}

# The five NONTERMINAL run statuses GitHub models (round-6 finding 2), filtered CLIENT-SIDE
# from ONE unfiltered snapshot per workflow (round-8 finding 2): a per-status query loop reads
# five DIFFERENT snapshots, so a run transitioning between statuses across the queries
# (requested -> queued is the real forward transition) can be missed by every one of them; a
# single listing captures every run in whatever status it holds at that instant. Shared with
# the self-test's expected-argv builder so the asserted call sequence is exactly what
# production issues; the filter's CONTENT is proven behaviorally — the fake gh applies it with
# REAL jq, and the per-status, transitioning-run, and terminal-run scenarios go red if a
# nonterminal status is dropped or a terminal one included.
NONTERMINAL_FILTER='[.[] | select(.status == "queued" or .status == "in_progress" or .status == "requested" or .status == "waiting" or .status == "pending")] | length'

# Quiesce (round-8: the SECRET-FREE first run of the two-run protocol): disable every writer
# workflow so no NEW writer run — including a `gh run rerun` of an old pre-env-binding snapshot
# — can start. Idempotent (disabling a disabled workflow succeeds). Re-enabled by `--phase
# resume-writers` (self-resume after a COMPLETED migrate, or a standalone phase: resume).
quiesce_writers() {
  local wf
  for wf in "${WRITER_WORKFLOWS[@]}"; do
    gh workflow disable "$wf" -R "$REPO" \
      || die "gh workflow disable ${wf} failed — cannot quiesce the secret writers, refusing before any listing or mutation (fail closed; NOTE: workflow disable needs the App token's Actions: write grant)"
    printf 'quiesced (workflow disabled): %s\n' "$wf"
  done
}

# TWO-RUN-PROTOCOL GATE (round-8 finding 1 — the queue-time secrets snapshot): the migrate and
# cleanup phases ASSERT the writers were already disabled by a prior quiesce RUN instead of
# disabling them in-run — GitHub fixes a run's `secrets.*` snapshot when the run is QUEUED, so
# an in-run disable can never make the S_* inputs fresher than a pre-queue writer rotation.
# Freshness argument: the operator queued this run AFTER observing the quiesce run succeed
# (writers disabled + drained), disabled workflows admit no new run, and this gate proves the
# writers are STILL disabled + drained — so no writer executed between the drain and this
# gate, which brackets the queue instant: the snapshot holds the newest values the writers
# ever wrote. (Residual, accepted: an out-of-band actions-admin re-enable -> run -> re-disable
# inside the window; that is the operator's own credential class, outside this threat model.)
assert_writers_quiesced() {
  local wf wf_state
  for wf in "${WRITER_WORKFLOWS[@]}"; do
    wf_state=$(gh api "repos/${REPO}/actions/workflows/${wf}" --jq .state) \
      || die "could not read the state of writer workflow ${wf} — cannot prove the writers are quiesced; Run 'phase: quiesce' first and wait for its success (fail closed; NOTE: this read needs the App token's Actions: read grant)"
    if [[ "$wf_state" != "disabled_manually" ]]; then
      die "writer workflow ${wf} is '${wf_state}', not disabled_manually — this run's QUEUE-time secrets snapshot cannot be proven fresher than a writer rotation. Run 'phase: quiesce' first and wait for its success, THEN dispatch 'phase: migrate': the fresh queue takes a fresh snapshot that postdates the drain (fail closed before any mutation)"
    fi
  done
  printf 'quiesce gate: all %d writer workflows are disabled_manually\n' "${#WRITER_WORKFLOWS[@]}"
}

# COHERENT drain check (round-8 finding 2, replacing the round-6 per-status query loop): ONE
# unfiltered listing per writer workflow, the five nonterminal statuses filtered client-side
# from that single snapshot — a run can no longer dodge the check by transitioning between
# statuses across queries. The writers are DISABLED whenever this runs, and gh's name-based
# `--workflow` lookup excludes disabled workflows unless `--all` is supplied (round-6 finding
# 1) — `--all` stays LOAD-BEARING. `--limit 1000` is gh's maximum and far above any plausible
# writer-run count (each writer serializes behind a concurrency group, so its nonterminal runs
# are bounded at a handful); the check only has to see NONTERMINAL runs, not history.
drain_check_no_live_writers() {
  local wf count
  for wf in "${WRITER_WORKFLOWS[@]}"; do
    count=$(gh run list --all -R "$REPO" --workflow "$wf" --limit 1000 \
              --json status,databaseId --jq "$NONTERMINAL_FILTER") \
      || die "could not take a run-listing snapshot of ${wf} — cannot prove no live secret writer (fail closed; NOTE: this listing needs the App token's Actions: read grant, and --all is load-bearing: a name-based lookup without it excludes the DISABLED workflows this drain check exists to inspect)"
    [[ "$count" =~ ^[0-9]+$ ]] \
      || die "unparseable nonterminal run count for ${wf} — cannot prove no live secret writer (fail closed)"
    if [[ "$count" -gt 0 ]]; then
      die "${count} nonterminal run(s) of ${wf} — a live secret writer could race the migration; wait for it to reach a terminal status, then re-run (idempotent)"
    fi
  done
  printf 'drain check: one coherent snapshot per writer workflow shows zero nonterminal (queued/in_progress/requested/waiting/pending) runs\n'
}

# QUEUE-TIME ORDERING ATTESTATION (sol round-9 finding 1 — remedy b; TOTAL-ORDERED in sol
# round 10): the M0a/M0b state checks prove the writers are disabled + drained AT START TIME,
# but a migrate run DISPATCHED while a quiesce run was still executing sat PENDING in the
# workflow's shared concurrency group with its `secrets.*` snapshot already fixed at QUEUE
# time — i.e. from BEFORE the drain finished. A writer admitted pre-drain can rotate V1 -> V2
# after that snapshot; M0a/M0b then pass and M3 copies stale V1 while M5 deletes fresh V2.
# Round 10 (sol): selecting the newest SUCCESSFUL quiesce is NOT enough — it silently accepts
# a SUPERSEDED quiesce. Killer sequence: Q1 succeeds -> phase: resume re-enables the writers
# -> a writer starts -> Q2 disables but FAILS its drain (the writer is live) -> migrate is
# queued during Q2 (snapshot = V1) -> the writer rotates V1 -> V2 and finishes -> at start
# time M0a/M0b pass (disabled + drained NOW) and the success-only filter discards failed Q2,
# accepting pre-queue Q1 — stale-copy/fresh-delete loss again. This gate therefore establishes
# a TOTAL ORDER over the attestation-relevant EVENTS: every quiesce AND resume run (ANY
# conclusion) whose created_at STRICTLY precedes this run's created_at participates, and the
# NEWEST such event must be a quiesce with conclusion success whose updated_at (completion) is
# STRICTLY BEFORE this run's created_at. A newest event that is a failed/cancelled quiesce, an
# in-progress quiesce (no conclusion yet), or a resume each fails closed with its own message
# — in every one of those histories the last proven drain is superseded, so the queue-time
# snapshot cannot be trusted. The events are discovered through the workflow's
# `run-name: migrate-secrets [<phase>]` (the run-listing API does not expose workflow_dispatch
# inputs, so the phase is machine-readable in display_title — the literals below and the
# workflow's run-name change together). Both API calls sit under the App token's Actions: read
# grant. ISO-8601 UTC timestamps of one fixed width compare correctly as strings.
#
# FIELD ATTESTATION (sol round 12 — the SKIPPED-'success' quiesce): a workflow RUN whose only
# job was SKIPPED by its `if:` condition (the actor/ref gate evaluating false — e.g. a
# COLLABORATOR dispatched phase: quiesce) still reports run conclusion=success, while
# disabling and draining NOTHING. displayTitle+conclusion+timestamps therefore attest
# nothing by themselves: the WINNING quiesce event must additionally carry the exact field
# values under which the workflow's `if:` provably let the job EXECUTE — actor.login==jeswr
# AND triggering_actor.login==jeswr AND head_branch==master AND run_attempt==1 (matching the
# actor contract pinned below and the attempt-1-only rule above). Any other combination is
# REJECTED, and the rejected event being the NEWEST means fail closed, exactly like a failed
# quiesce. RESUME events deliberately block on TITLE ALONE, regardless of their own fields:
# ANY newer quiesce-or-resume event, whatever its fields, blocks unless it is a fully-attested
# successful quiesce — the simple fail-closed direction (a collaborator-skipped resume costs
# one spurious re-quiesce, never a stale-snapshot migrate). Because `gh run list --json`
# exposes NO actor/triggering_actor fields (verified against gh 2.94.0), the listing is the
# REST runs endpoint for THIS workflow, which carries all of them. The jq emits the events
# sorted by created_at ascending, one
# 'created_at|updated_at|conclusion|title|actor|triggering_actor|head_branch|run_attempt'
# line each ('|' occurs in none of the attested values — logins/ISO timestamps/the two title
# literals cannot contain it, and a hostile branch name smuggling one only shifts fields into
# mismatches, i.e. fails closed; a missing run_attempt maps to 0, never 1 — absent is NEVER
# assumed to mean attempt 1), and the newest-preceding selection runs in bash against this
# run's created_at.
ISO_TS_RE='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
ATTESTED_ACTOR='jeswr'
ATTESTED_BRANCH='master'
QUIESCE_RESUME_EVENT_FILTER='[.workflow_runs[] | select(.display_title == "migrate-secrets [quiesce]" or .display_title == "migrate-secrets [resume]")] | sort_by(.created_at) | .[] | [.created_at // "", .updated_at // "", .conclusion // "", .display_title, .actor.login // "", .triggering_actor.login // "", .head_branch // "", (.run_attempt // 0 | tostring)] | join("|")'

assert_quiesce_completed_before_queue() {
  local run_id=${GITHUB_RUN_ID:-}
  [[ "$run_id" =~ ^[0-9]+$ ]] \
    || die "GITHUB_RUN_ID is unset or unsafe — cannot fetch this run's created_at for the queue-time ordering attestation (fail closed before any mutation)"
  local my_created
  my_created=$(gh api "repos/${REPO}/actions/runs/${run_id}" --jq .created_at) \
    || die "could not fetch this run's created_at (run ${run_id}) — cannot prove the quiesce completed before this run was queued (fail closed; NOTE: the run read needs the App token's Actions: read grant)"
  [[ "$my_created" =~ $ISO_TS_RE ]] \
    || die "unparseable created_at '${my_created}' for this run — cannot order it against the quiesce/resume history (fail closed)"
  local events
  events=$(gh api "repos/${REPO}/actions/workflows/migrate-secrets-to-env.yml/runs?per_page=100" \
             --jq "$QUIESCE_RESUME_EVENT_FILTER") \
    || die "could not list this workflow's runs — cannot total-order the quiesce/resume history for the ordering attestation (fail closed; NOTE: the listing needs the App token's Actions: read grant)"
  local ev_created ev_updated ev_conclusion ev_title ev_actor ev_trigger ev_branch ev_attempt
  local newest_created='' newest_updated='' newest_conclusion='' newest_title=''
  local newest_actor='' newest_trigger='' newest_branch='' newest_attempt=''
  while IFS='|' read -r ev_created ev_updated ev_conclusion ev_title ev_actor ev_trigger ev_branch ev_attempt; do
    [[ -n "${ev_created}${ev_updated}${ev_conclusion}${ev_title}" ]] || continue
    [[ "$ev_created" =~ $ISO_TS_RE ]] \
      || die "unparseable created_at '${ev_created}' on a '${ev_title}' run — cannot total-order the quiesce/resume history against this run's queue instant (fail closed)"
    # Only events QUEUED strictly before this run's own queue instant participate in the total
    # order: this run's secrets snapshot was fixed at ITS queue instant, so a later event can
    # neither vouch for nor invalidate that snapshot.
    [[ "$ev_created" < "$my_created" ]] || continue
    # The jq sorted ascending, so the last qualifying event is the newest. On a same-second
    # created_at TIE between a quiesce and a resume, keep the RESUME (fail-closed direction).
    if [[ -z "$newest_created" || "$ev_created" != "$newest_created" \
          || "$ev_title" == 'migrate-secrets [resume]' ]]; then
      newest_created=$ev_created
      newest_updated=$ev_updated
      newest_conclusion=$ev_conclusion
      newest_title=$ev_title
      newest_actor=$ev_actor
      newest_trigger=$ev_trigger
      newest_branch=$ev_branch
      newest_attempt=$ev_attempt
    fi
  done <<<"$events"
  [[ -n "$newest_created" ]] \
    || die "no quiesce/resume event (displayTitle 'migrate-secrets [quiesce]' / 'migrate-secrets [resume]') queued before this run's queue instant ${my_created} was found — the writers merely BEING disabled is not an attestation that a quiesce run drained them. Run 'phase: quiesce', wait for its success, THEN dispatch this phase (fail closed before any mutation)"
  if [[ "$newest_title" == 'migrate-secrets [resume]' ]]; then
    die "the writers were re-enabled after the last successful quiesce — the newest quiesce/resume event preceding this run's queue instant is a RESUME (queued ${newest_created}), so a re-enabled writer may have rotated a secret this run's queue-time S_* snapshot does not carry: re-run phase: quiesce, wait for its success, then re-dispatch this phase (fail closed before any mutation)"
  fi
  if [[ -z "$newest_conclusion" ]]; then
    die "the latest quiesce attempt has not CONCLUDED (queued ${newest_created}, no conclusion yet) — its drain is unproven and it supersedes any earlier successful quiesce: wait for it to SUCCEED, then re-dispatch this phase (fail closed before any mutation)"
  fi
  if [[ "$newest_conclusion" != 'success' ]]; then
    die "the latest quiesce attempt did not succeed — the newest quiesce/resume event preceding this run's queue instant is a quiesce that concluded '${newest_conclusion}' (queued ${newest_created}), so its drain is unproven and it supersedes any earlier successful quiesce (a writer live during that failed drain may have rotated a secret this run's queue-time S_* snapshot does not carry): re-run phase: quiesce, wait for its success, then re-dispatch this phase (fail closed before any mutation)"
  fi
  # FIELD ATTESTATION (sol round 12): conclusion 'success' on a RUN is NOT proof its job ran —
  # a job SKIPPED by the workflow's actor/ref `if:` (e.g. a collaborator-dispatched quiesce)
  # still concludes the run 'success' having disabled and drained NOTHING. The winning quiesce
  # must carry the exact field values under which the `if:` provably let the job EXECUTE.
  if [[ "$newest_actor" != "$ATTESTED_ACTOR" || "$newest_trigger" != "$ATTESTED_ACTOR" \
        || "$newest_branch" != "$ATTESTED_BRANCH" || "$newest_attempt" != '1' ]]; then
    die "the newest quiesce/resume event preceding this run's queue instant is a quiesce that reports conclusion 'success' (queued ${newest_created}) but is NOT field-attested — actor='${newest_actor}' triggering_actor='${newest_trigger}' head_branch='${newest_branch}' run_attempt='${newest_attempt}' (required: actor==${ATTESTED_ACTOR} AND triggering_actor==${ATTESTED_ACTOR} AND head_branch==${ATTESTED_BRANCH} AND run_attempt==1): a run whose job was SKIPPED by its if-condition (e.g. dispatched by a collaborator, or off-master, or a re-run attempt) still reports run conclusion=success while disabling and draining NOTHING, so this event proves no drain; it is REJECTED, and being the newest event it supersedes every earlier quiesce — re-run phase: quiesce as ${ATTESTED_ACTOR} on ${ATTESTED_BRANCH}, wait for its success, then re-dispatch this phase (fail closed before any mutation)"
  fi
  [[ "$newest_updated" =~ $ISO_TS_RE ]] \
    || die "unparseable quiesce completion timestamp '${newest_updated}' — cannot order it against this run's queue instant (fail closed)"
  if ! [[ "$newest_updated" < "$my_created" ]]; then
    die "the newest successful quiesce run completed at ${newest_updated}, NOT strictly before this run was queued at ${my_created} — this run's QUEUE-time secrets snapshot was taken before the drain finished, so a writer admitted pre-drain could have rotated a secret this run's S_* inputs do not carry (stale-copy/fresh-delete loss): quiesce must COMPLETE before migrate is queued (queue-time secrets snapshot) — re-dispatch migrate (fail closed before any mutation)"
  fi
  printf 'ordering attestation: newest successful quiesce completed %s < this run queued %s\n' \
    "$newest_updated" "$my_created"
}

# The SECRET-FREE first run of the two-run protocol (round-8 finding 1): its workflow job maps
# no S_* input and mints Actions:write ONLY — it cannot read or move a secret even if buggy.
phase_quiesce() {
  echo '== attempt gate (round 11): this must be attempt 1 — re-runs are prohibited =='
  assert_first_attempt
  setup
  echo '== phase Q1: disable the 4 secret-writer workflows (no NEW writer run can start after this) =='
  quiesce_writers
  echo '== phase Q2: coherent drain check — no ALREADY-ADMITTED writer run is still nonterminal =='
  drain_check_no_live_writers
  printf 'QUIESCE PHASE COMPLETE: writers disabled + drained. NOW dispatch phase: migrate — its fresh queue takes a fresh secrets snapshot that postdates this drain. (A failed migrate leaves the writers disabled BY DESIGN; finish with a converging migrate rerun, or dispatch phase: resume to abandon.)\n'
}

phase_main() {
  echo '== attempt gate (round 11): this must be attempt 1 — re-runs are prohibited =='
  assert_first_attempt
  setup
  echo '== phase M0a: quiesce gate — the 4 writers must already be disabled by a quiesce RUN (two-run protocol) =='
  assert_writers_quiesced
  echo '== phase M0b: coherent drain check — no admitted writer run is still nonterminal =='
  drain_check_no_live_writers
  echo '== phase M0c: total-order ordering attestation — the newest quiesce/resume event preceding this run being QUEUED must be a quiesce that SUCCEEDED and COMPLETED first (queue-time secrets snapshot) =='
  assert_quiesce_completed_before_queue

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
  echo '== attempt gate (round 11): this must be attempt 1 — re-runs are prohibited =='
  assert_first_attempt
  setup
  echo '== phase C0: quiesce gate + coherent drain check + ordering attestation (same fail-closed gate as the main phase) =='
  assert_writers_quiesced
  drain_check_no_live_writers
  assert_quiesce_completed_before_queue

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

# Re-enable the four quiesced writer workflows (the workflow's reenable-writers job — round 8:
# it runs as the self-resume after a COMPLETED migrate, or standalone via phase: resume; a
# FAILED migrate deliberately leaves the writers disabled so a rerun stays raceless).
# Tries ALL four before failing so one failure never leaves the rest disabled; idempotent
# (enabling an enabled workflow succeeds).
phase_resume() {
  echo '== attempt gate (round 11): this must be attempt 1 — re-runs are prohibited =='
  assert_first_attempt
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
# PyYAML) pins ALL FOUR create-github-app-token steps' EXACT phase-specific grant sets
# (round 8 moved the disable into the secret-free `quiesce` job — Actions write ONLY — and
# WEAKENED the migrate mint's Actions grant write -> READ: migrate now only reads workflow
# state + run listings for its gate; the cleanup mint stays at Actions read):
#   job `quiesce`:                 actions: write ONLY (secret-free phase: it can disable
#                                  workflows but cannot read or touch any secret)
#   main job `migrate`:            secrets: write + environments: write + actions: read
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
  want=$(printf 'permission-actions: write')
  got=$(_mint_grants "$wf" quiesce)
  if [[ "$got" != "$want" ]]; then
    printf '::error::migrate-secrets: workflow contract violated — the QUIESCE mint (job quiesce) must declare EXACTLY {permission-actions: write} and NOTHING else (round-8 secret-free phase: it disables workflows, it must never be able to read a secret); found:\n%s\n' "${got:-<none>}" >&2
    rc=1
  fi
  want=$(printf 'permission-actions: read\npermission-environments: write\npermission-secrets: write')
  got=$(_mint_grants "$wf" migrate)
  if [[ "$got" != "$want" ]]; then
    printf '::error::migrate-secrets: workflow contract violated — the MAIN mint (job migrate) must declare EXACTLY {permission-secrets: write, permission-environments: write, permission-actions: read (round-8: migrate only READS workflow state + run listings for its gate; the disable lives in the quiesce phase)}; found:\n%s\n' "${got:-<none>}" >&2
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

# ACTOR CONTRACT (sol round-9 finding 2 — the RE-RUN bypass): every phase job gates on
# `github.actor == 'jeswr'`, but github.actor stays the ORIGINAL initiator when a run is
# RE-RUN — `github.triggering_actor` is the re-runner. Actor-only therefore lets ANY
# write-access user re-run a jeswr-initiated run while it holds the secret-admin mint. The
# workflow requires BOTH fields on all four phase jobs' `if:`; this pin (same anchored-awk
# job-block extraction as the mint contract) goes red in --self-test if either clause is
# dropped from any job.
_job_block() {  # _job_block WORKFLOW_FILE JOB_KEY -> that job's lines (same anchor as _mint_grants)
  awk -v job="$2" '
    /^  [A-Za-z0-9_-]+:/ { injob = ($0 == "  " job ":") }
    injob { print }
  ' "$1"
}

check_workflow_actor_contract() {  # check_workflow_actor_contract WORKFLOW_FILE
  local wf=$1 job block rc=0
  if [[ ! -f "$wf" ]]; then
    printf '::error::migrate-secrets: workflow contract: %s not found (delete this script together with the workflow)\n' "$wf" >&2
    return 1
  fi
  for job in quiesce migrate cleanup-bootstrap reenable-writers; do
    block=$(_job_block "$wf" "$job")
    if ! grep -qF "github.actor == 'jeswr'" <<<"$block" \
       || ! grep -qF "github.triggering_actor == 'jeswr'" <<<"$block"; then
      printf "::error::migrate-secrets: workflow contract violated — job %s must gate on BOTH github.actor == 'jeswr' AND github.triggering_actor == 'jeswr' (round-9 finding 2: github.actor stays the ORIGINAL initiator on a re-run while triggering_actor is the RE-RUNNER, so actor-only lets any write-access user re-run a jeswr run under the secret-admin mint)\n" "$job" >&2
      rc=1
    fi
  done
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
  # The fake gh serves each drain listing as one coherent snapshot and applies the caller's
  # --jq expression with REAL jq (round-8 finding 2) — jq is a hard dependency of the harness
  # (present on ubuntu-latest and the worker images; fail loud, not mysteriously, elsewhere).
  command -v jq >/dev/null 2>&1 \
    || { printf 'migrate-secrets self-test: jq is required (the fake gh applies the drain filter with real jq)\n' >&2; return 1; }
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
  "api repos/o/r/actions/workflows/"*" --jq .state")
    # Round-8 quiesce gate: the migrate/cleanup phases READ each writer workflow's state and
    # require disabled_manually — a workflow the fake's `workflow disable` touched reports it.
    _grant actions:read \
      || { echo "HTTP 403: Resource not accessible by integration (workflow-state read needs Actions: read)" >&2; exit 1; }
    wfname=${2#repos/o/r/actions/workflows/}
    if [[ -f "$state/disabled_${wfname}" ]]; then echo disabled_manually; else echo active; fi
    exit 0 ;;
  "api repos/o/r/actions/runs/"*" --jq .created_at")
    # Round-9 ordering attestation: the migrate/cleanup gate fetches ITS OWN run's created_at
    # (the queue instant — the moment the secrets.* snapshot was fixed). Sits under Actions read.
    _grant actions:read \
      || { echo "HTTP 403: Resource not accessible by integration (run read needs Actions: read)" >&2; exit 1; }
    [[ -f "$state/run_created" ]] || { echo "HTTP 404: Not Found (no such run modeled)" >&2; exit 1; }
    cat "$state/run_created"
    exit 0 ;;
  "api repos/o/r/actions/workflows/migrate-secrets-to-env.yml/runs?per_page=100 --jq "*)
    # Round-9/round-10/round-12 ordering attestation: serve the modeled run HISTORY of this
    # migration workflow ($state/wf_runs, a REST-shaped {"workflow_runs": [...]} document whose
    # runs carry display_title/conclusion/created_at/updated_at PLUS the round-12 attested
    # fields actor.login/triggering_actor.login/head_branch/run_attempt — gh run list --json
    # exposes no actor fields, hence the REST endpoint) and apply the caller's --jq with REAL
    # jq — the quiesce/resume event selection is exercised, not assumed (a decoy
    # migrate-success, an older quiesce-success, a superseding resume, a superseding
    # failed/in-progress quiesce, or a collaborator SKIPPED-'success' quiesce must each be
    # handled as modeled).
    _grant actions:read \
      || { echo "HTTP 403: Resource not accessible by integration (workflow-run listing needs Actions: read)" >&2; exit 1; }
    [[ -f "$state/wf_runs" ]] || { echo "HTTP 404: Not Found (no run history modeled)" >&2; exit 1; }
    jq -r "$4" "$state/wf_runs"
    exit 0 ;;
  "run list --all -R o/r --workflow "*" --limit "*" --json status,databaseId --jq "*)
    # ONE COHERENT SNAPSHOT (round-8 finding 2): serve EVERY run this state dir models — the
    # per-status inflight files, the TRANSITIONING run (in whatever status it holds at this
    # instant), and terminal (completed) runs — as one JSON array, then apply the caller's
    # --jq expression with REAL jq. The script's client-side nonterminal filter is thereby
    # genuinely exercised: dropping a status from it, or counting terminal runs, turns
    # scenarios red. WITH --all the lookup includes DISABLED workflows (round-6 finding 1).
    _grant actions:read \
      || { echo "HTTP 403: Resource not accessible by integration (workflow-run listing needs Actions: read)" >&2; exit 1; }
    wfname=$7
    {
      rid=100
      for st in queued in_progress requested waiting pending; do
        f="$state/inflight_${wfname}_${st}"
        if [[ -f "$f" ]]; then
          n=$(cat "$f")
          for ((i=0; i<n; i++)); do printf '{"status":"%s","databaseId":%d}\n' "$st" "$rid"; rid=$((rid+1)); done
        fi
      done
      if [[ -f "$state/transitioning_${wfname}" ]]; then
        printf '{"status":"%s","databaseId":9001}\n' "$(cat "$state/transitioning_${wfname}")"
      fi
      if [[ -f "$state/terminal_${wfname}" ]]; then
        n=$(cat "$state/terminal_${wfname}")
        for ((i=0; i<n; i++)); do printf '{"status":"completed","databaseId":%d}\n' $((8000 + i)); done
      fi
    } | jq -cs "${13}"
    exit 0 ;;
  "run list -R o/r --workflow "*" --limit "*" --json status,databaseId --jq "*)
    # WITHOUT --all, real gh EXCLUDES disabled workflows from the name-based lookup — --all is
    # exactly as load-bearing for the snapshot listing as it was for the per-status one
    # (stripping it from the drain check turns every quiesced scenario red here).
    _grant actions:read \
      || { echo "HTTP 403: Resource not accessible by integration (workflow-run listing needs Actions: read)" >&2; exit 1; }
    if [[ -f "$state/disabled_${6}" ]]; then
      echo "could not find any workflows named ${6} (it is disabled; use --all to include disabled workflows)" >&2
      exit 1
    fi
    echo 0
    exit 0 ;;
  "run list --all -R o/r --workflow "*" --status "*" --json databaseId --jq length")
    # The OLD round-6 per-status query shape — kept so the round-8 finding-2 MUTATION CHECK
    # (revert drain_check_no_live_writers to the per-status loop) still executes: it must MISS
    # the transitioning run below and turn the transitioning-run scenario red.
    _grant actions:read \
      || { echo "HTTP 403: Resource not accessible by integration (workflow-run listing needs Actions: read)" >&2; exit 1; }
    wfname=$7; qst=$9
    n=0
    f="$state/inflight_${wfname}_${qst}"
    [[ -f "$f" ]] && n=$(cat "$f")
    # TRANSITIONING-RUN model (round-8 finding 2): the run holds a CURRENT status and a
    # per-status query only sees it when it queries exactly that status at this instant. After
    # the first per-status query for this workflow the run advances requested -> queued (its
    # real forward transition) — a status the old queued-first loop has already passed. Five
    # per-status queries are five DIFFERENT snapshots; this legal interleaving is missed by
    # ALL of them, while the single unfiltered snapshot above always captures the run.
    if [[ -f "$state/transitioning_${wfname}" ]]; then
      cur=$(cat "$state/transitioning_${wfname}")
      [[ "$cur" == "$qst" ]] && n=$((n + 1))
      [[ "$cur" == "requested" ]] && printf 'queued\n' > "$state/transitioning_${wfname}"
    fi
    echo "$n"
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
    # GITHUB_RUN_ID: the round-9 ordering attestation fetches this run's created_at from it
    # (in production it is the runner's default env var; fixed here so the fake can model it).
    local -a assigns=(PATH="$tmp/bin:$PATH" FAKE_GH_STATE="$state" REGISTRY_REPO=o/r GITHUB_RUN_ID=7777)
    # GITHUB_RUN_ATTEMPT (round 11): every child models a FRESH attempt-1 dispatch unless the
    # caller overrides RUN_ATTEMPT_OVERRIDE (a number, or 'absent' to model the variable
    # missing entirely). The `env -u` below strips any value inherited from a REAL Actions
    # runner first, so the harness stays hermetic where GITHUB_RUN_ATTEMPT is always set.
    if [[ "${RUN_ATTEMPT_OVERRIDE:-1}" != absent ]]; then
      assigns+=("GITHUB_RUN_ATTEMPT=${RUN_ATTEMPT_OVERRIDE:-1}")
    fi
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
    env -u GITHUB_RUN_ATTEMPT "${assigns[@]}" bash "$me" --phase "$phase" > "$out" 2>&1 || rc=$?
    printf '%s' "$rc"
  }

  # The migrate/cleanup phases' shared fail-closed prefix (rounds 8+9): 4 workflow-state reads
  # (the quiesce gate), 4 single-snapshot drain listings — ONE unfiltered call per workflow;
  # the client-side NONTERMINAL_FILTER is part of the asserted argv, so a --status flag
  # sneaking back in (or the filter disappearing) breaks the exact-sequence diffs — then the
  # round-9/round-10/round-12 ordering attestation: this run's created_at read + ONE REST
  # run listing of the migration workflow itself with QUIESCE_RESUME_EVENT_FILTER pinned in
  # the argv (round 10: the filter must surface quiesce AND resume events of ANY conclusion —
  # narrowing it back to successful quiesces breaks this exact-argv diff as well as the
  # behavioral scenarios; round 12: the filter must CARRY the attested
  # actor/triggering_actor/head_branch/run_attempt fields — dropping any of them from the
  # emitted lines breaks this diff too).
  local expected_gate="$tmp/expected-gate.log" wf st n
  : > "$expected_gate"
  for wf in worker.yml review-fix.yml set-up-account.yml pat-validity.yml; do
    printf 'api repos/o/r/actions/workflows/%s --jq .state\n' "$wf" >> "$expected_gate"
  done
  for wf in worker.yml review-fix.yml set-up-account.yml pat-validity.yml; do
    printf 'run list --all -R o/r --workflow %s --limit 1000 --json status,databaseId --jq %s\n' \
      "$wf" "$NONTERMINAL_FILTER" >> "$expected_gate"
  done
  printf 'api repos/o/r/actions/runs/7777 --jq .created_at\n' >> "$expected_gate"
  printf 'api repos/o/r/actions/workflows/migrate-secrets-to-env.yml/runs?per_page=100 --jq %s\n' \
    "$QUIESCE_RESUME_EVENT_FILTER" >> "$expected_gate"
  # The quiesce PHASE (round-8 two-run protocol): 4 disables then the same 4 drain snapshots
  # (disable-then-check is the race-free order: no NEW run can start after the disable, and
  # the drain check then proves no already-admitted run remains).
  local expected_quiesce="$tmp/expected-quiesce.log" expected_resume="$tmp/expected-resume.log"
  : > "$expected_quiesce"
  : > "$expected_resume"
  for wf in worker.yml review-fix.yml set-up-account.yml pat-validity.yml; do
    printf 'workflow disable %s -R o/r\n' "$wf" >> "$expected_quiesce"
    printf 'workflow enable %s -R o/r\n' "$wf" >> "$expected_resume"
  done
  for wf in worker.yml review-fix.yml set-up-account.yml pat-validity.yml; do
    printf 'run list --all -R o/r --workflow %s --limit 1000 --json status,databaseId --jq %s\n' \
      "$wf" "$NONTERMINAL_FILTER" >> "$expected_quiesce"
  done
  # Seed the state a SUCCESSFUL quiesce run leaves behind (writers disabled), plus the round-9
  # GOOD ORDERING: this run (id 7777) was queued at 12:00 and the newest successful quiesce
  # run COMPLETED at 11:50 — strictly before the queue instant, so the ordering attestation
  # passes. Every scenario that exercises the migrate/cleanup phases starts from it, because
  # those phases now fail closed without it (see the migrate-without-quiesce and queue-time
  # ordering scenarios); the ordering-violation scenarios overwrite run_created/wf_runs.
  # REST-shaped modeled runs (round 12): every wf_runs history now carries the attested
  # fields. mk_run defaults to a FULLY-ATTESTED run (actor jeswr / triggering_actor jeswr /
  # head_branch master / run_attempt 1) so each rejection scenario perturbs exactly one thing.
  mk_run() {  # mk_run ID TITLE CONCLUSION|null CREATED UPDATED [ACTOR] [TRIGGER] [BRANCH] [ATTEMPT]
    local concl=$3
    [[ "$concl" == null ]] || concl="\"$3\""
    printf '{"id":%s,"display_title":"%s","conclusion":%s,"created_at":"%s","updated_at":"%s","actor":{"login":"%s"},"triggering_actor":{"login":"%s"},"head_branch":"%s","run_attempt":%s}' \
      "$1" "$2" "$concl" "$4" "$5" "${6:-jeswr}" "${7:-jeswr}" "${8:-master}" "${9:-1}"
  }
  mk_history() {  # mk_history RUN_JSON... -> the REST {"workflow_runs": [...]} document
    local IFS=,
    printf '{"workflow_runs":[%s]}\n' "$*"
  }
  seed_quiesced() {
    local d=$1 w
    for w in worker.yml review-fix.yml set-up-account.yml pat-validity.yml; do
      touch "$d/disabled_$w"
    done
    printf '2026-07-18T12:00:00Z\n' > "$d/run_created"
    mk_history \
      "$(mk_run 7000 'migrate-secrets [quiesce]' success 2026-07-18T11:40:00Z 2026-07-18T11:50:00Z)" \
      > "$d/wf_runs"
  }

  # --- scenario 0: QUIESCE PHASE (round-8 finding 1 — the secret-free first run of the
  # two-run protocol): 4 disables then the coherent drain check, exact argv asserted; NO
  # secret endpoint of any kind is touched (the job maps no S_* input and mints actions:write
  # only — this proves the phase never needs more).
  local s0="$tmp/s0" rc
  mkdir -p "$s0"
  rc=$(run_case "$s0" "$tmp/s0.out" quiesce none)
  chk "quiesce phase succeeds" "$rc" 0
  chk "quiesce phase: EXACT gh argv sequence (4 disables -> 4 single-snapshot drain listings)" \
    "$(diff -q "$expected_quiesce" "$s0/calls.log" >/dev/null 2>&1 && echo same || echo diff)" same
  chk "quiesce phase: leaves all 4 writer workflows DISABLED" \
    "$(find "$s0" -name 'disabled_*' | wc -l)" 4
  chk "quiesce phase: touches NO secret endpoint (secret-free by construction)" \
    "$(grep -cE '(^secret |/secrets)' "$s0/calls.log" || true)" 0

  # --- scenario 0b: QUIESCE with an ALREADY-ADMITTED writer run still nonterminal — the drain
  # is not proven, so the phase fails (the operator waits and re-dispatches quiesce; the
  # writers deliberately STAY disabled so no NEW run can pile in meanwhile).
  local s0b="$tmp/s0b"
  mkdir -p "$s0b"
  echo 1 > "$s0b/inflight_worker.yml_in_progress"
  rc=$(run_case "$s0b" "$tmp/s0b.out" quiesce none)
  chk "quiesce with an admitted writer run -> fail (drain not proven)" "$rc" 1
  chk "quiesce with an admitted writer run: names count + workflow" \
    "$(grep -c '1 nonterminal run(s) of worker.yml' "$tmp/s0b.out")" 1
  chk "quiesce with an admitted writer run: writers STAY disabled (re-dispatch quiesce converges)" \
    "$(find "$s0b" -name 'disabled_*' | wc -l)" 4

  # --- scenario 0c: MIGRATE WITHOUT QUIESCE (round-8 finding 1): dispatching phase: migrate
  # with the writers still ACTIVE (no prior quiesce run) must fail closed BEFORE any secret
  # listing or mutation, instructing the operator to run phase: quiesce first — the QUEUE-time
  # secrets snapshot cannot be proven fresh otherwise.
  local s0c="$tmp/s0c"
  mkdir -p "$s0c"
  printf '%s\n' "${names[@]}" > "$s0c/repo_secrets"
  : > "$s0c/env_secrets"
  rc=$(run_case "$s0c" "$tmp/s0c.out" main all)
  chk "migrate without quiesce -> fail closed" "$rc" 1
  chk "migrate without quiesce: names the runbook (run phase: quiesce first)" \
    "$(grep -c "Run 'phase: quiesce' first" "$tmp/s0c.out")" 1
  chk "migrate without quiesce: ZERO mutations + ZERO secret listings (only the first state read)" \
    "$(grep -cvE '^api repos/o/r/actions/workflows/' "$s0c/calls.log" || true)" 0

  # --- scenario 0d: PARTIALLY-QUIESCED migrate (3 of 4 disabled) is just as unproven — fail
  # closed naming the still-active writer.
  local s0d="$tmp/s0d"
  mkdir -p "$s0d"
  printf '%s\n' "${names[@]}" > "$s0d/repo_secrets"
  : > "$s0d/env_secrets"
  touch "$s0d/disabled_worker.yml" "$s0d/disabled_review-fix.yml" "$s0d/disabled_set-up-account.yml"
  rc=$(run_case "$s0d" "$tmp/s0d.out" main all)
  chk "partially-quiesced migrate (3 of 4 disabled) -> fail closed naming the active writer" \
    "$rc-$(grep -c "pat-validity.yml is 'active'" "$tmp/s0d.out")" 1-1
  chk "partially-quiesced migrate: zero mutations" \
    "$(grep -cE '^secret (set|delete) ' "$s0d/calls.log" || true)" 0

  # --- scenario 1: FRESH MAIN PHASE — a quiesce run has succeeded (writers disabled +
  # drained), env empty, repo holds all 14. Also the exact argv-sequence assertion (the
  # M0a/M0b gate FIRST, env sets via STDIN with --env, verify listings, exactly the 12
  # non-bootstrap deletes, asserts) — and the load-bearing NEVER-deletes-bootstrap
  # invariant: the old design's brick window (cancelled after the APP_ID delete, before the
  # APP_KEY delete, leaving an unmintable stray) cannot exist when the main phase issues ZERO
  # bootstrap deletes at any point in its argv stream. The 3 terminal (completed) runs seeded
  # on worker.yml must NOT trip the drain check — the client-side filter excludes terminal
  # statuses (accept direction of finding 2).
  local s1="$tmp/s1"
  mkdir -p "$s1"
  seed_quiesced "$s1"
  echo 3 > "$s1/terminal_worker.yml"
  printf '%s\n' "${names[@]}" > "$s1/repo_secrets"
  : > "$s1/env_secrets"
  rc=$(run_case "$s1" "$tmp/s1.out" main all)
  chk "fresh main phase succeeds (terminal runs in the snapshot do not trip the drain check)" "$rc" 0
  chk "fresh main: the GOOD-ORDERING attestation passes and is reported (quiesce completed 11:50 < queued 12:00)" \
    "$(grep -c 'ordering attestation: newest successful quiesce completed 2026-07-18T11:50:00Z < this run queued 2026-07-18T12:00:00Z' "$tmp/s1.out")" 1
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
  chk "fresh main: ZERO workflow disables/enables (round-8: migrate ASSERTS quiesce, it never performs one)" \
    "$(grep -cE '^workflow (disable|enable) ' "$s1/calls.log" || true)" 0
  chk "fresh main: the ENTIRE quiesce gate + drain snapshot precede the FIRST secret set (fail closed before mutation)" \
    "$(awk '/^(api repos\/o\/r\/actions\/workflows\/|run list )/{last=NR} /^secret set /{if(!first)first=NR} END{print (last && first && last<first) ? "yes" : "no"}' "$s1/calls.log")" yes
  local expected="$tmp/expected-main.log"
  {
    cat "$expected_gate"
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
  chk "fresh main: EXACT gh argv sequence (state x4 -> snapshot x4 -> env+repo list -> set+verify x14 -> assert -> delete x12 NON-BOOTSTRAP ONLY -> assert)" \
    "$(diff -q "$expected" "$s1/calls.log" >/dev/null 2>&1 && echo same || echo diff)" same

  # --- scenario 2: CLEANUP FROM 2-REMAINING — the state the main phase leaves. Exact argv
  # sequence asserted; only after this does the migration report COMPLETE (guard-green ordering).
  local s2="$tmp/s2"
  mkdir -p "$s2"
  seed_quiesced "$s2"
  cp "$s1/env_secrets" "$s2/env_secrets"
  cp "$s1/repo_secrets" "$s2/repo_secrets"
  rc=$(run_case "$s2" "$tmp/s2.out" cleanup-bootstrap none)
  chk "cleanup from 2-remaining succeeds" "$rc" 0
  chk "cleanup: repo scope empty after" "$(cat "$s2/repo_secrets")" ""
  chk "cleanup: reports MIGRATION COMPLETE (guard goes green only after this phase)" \
    "$(grep -c 'MIGRATION COMPLETE (both phases)' "$tmp/s2.out")" 1
  local expected_c="$tmp/expected-cleanup.log"
  {
    cat "$expected_gate"
    printf 'api repos/o/r/environments/dispatch-secrets/secrets --paginate --jq .secrets[].name\n'
    printf 'api repos/o/r/actions/secrets --paginate --jq .secrets[].name\n'
    printf 'secret delete REGISTRY_ADMIN_APP_ID --repo o/r\n'
    printf 'secret delete REGISTRY_ADMIN_APP_KEY --repo o/r\n'
    printf 'api repos/o/r/actions/secrets --paginate --jq .secrets[].name\n'
  } > "$expected_c"
  chk "cleanup: EXACT gh argv sequence (state x4 -> snapshot x4 -> env assert -> repo list -> delete x2 bootstrap -> assert)" \
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
  seed_quiesced "$s4"
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
  seed_quiesced "$s5"
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
  seed_quiesced "$s6"
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
  seed_quiesced "$s7"
  printf '%s\n' "${names[@]}" > "$s7/env_secrets"
  : > "$s7/repo_secrets"
  rc=$(run_case "$s7" "$tmp/s7.out" cleanup-bootstrap none)
  chk "cleanup from 0-remaining is a success no-op" "$rc" 0
  chk "cleanup from 0-remaining performs zero mutations" \
    "$(grep -cE '^secret (set|delete) ' "$s7/calls.log" || true)" 0

  # --- scenario 8: MISSING INPUT on a fresh main run — hard fail BEFORE any mutation.
  local s8="$tmp/s8"
  mkdir -p "$s8"
  seed_quiesced "$s8"
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
  seed_quiesced "$s9"
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
  seed_quiesced "$s10"
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
  seed_quiesced "$s11"
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
  seed_quiesced "$s11b"
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

  # --- scenario 12: IN-FLIGHT WRITER — fail closed before ANY secret listing or mutation
  # (main): the writers are quiesced but an already-admitted run is still nonterminal.
  local s12="$tmp/s12"
  mkdir -p "$s12"
  seed_quiesced "$s12"
  printf '%s\n' "${names[@]}" > "$s12/repo_secrets"
  : > "$s12/env_secrets"
  echo 1 > "$s12/inflight_worker.yml_in_progress"
  rc=$(run_case "$s12" "$tmp/s12.out" main all)
  chk "in-flight writer -> fail closed" "$rc" 1
  chk "in-flight writer: distinct message names the workflow" \
    "$(grep -c '1 nonterminal run(s) of worker.yml' "$tmp/s12.out")" 1
  chk "in-flight writer: ONLY gate reads issued (no secret listing, no mutation)" \
    "$(grep -cvE '^(api repos/o/r/actions/workflows/|run list )' "$s12/calls.log" || true)" 0

  # --- scenario 12b: EVERY NONTERMINAL RUN STATUS ABORTS (round-6 finding 2) — GitHub's active
  # statuses are queued / in_progress / requested / waiting / pending, not just the first two:
  # a run already requested, or parked waiting on an environment approval, or pending a
  # concurrency slot when the disable lands can still execute later (the writers use
  # concurrency + the dispatch-secrets environment, so waiting/pending are REAL states here).
  # One scenario per status; each must be CAUGHT by the client-side snapshot filter and fail
  # closed with zero mutations — dropping any status from NONTERMINAL_FILTER turns exactly
  # that scenario green-when-it-must-fail, i.e. red here (behavioral pin of the filter).
  local st sN
  for st in queued in_progress requested waiting pending; do
    sN="$tmp/s12b-$st"
    mkdir -p "$sN"
    seed_quiesced "$sN"
    printf '%s\n' "${names[@]}" > "$sN/repo_secrets"
    : > "$sN/env_secrets"
    echo 1 > "$sN/inflight_pat-validity.yml_${st}"
    rc=$(run_case "$sN" "$tmp/s12b-$st.out" main all)
    chk "nonterminal status ${st}: caught by the single-snapshot filter -> fail closed" "$rc" 1
    chk "nonterminal status ${st}: message names count + workflow" \
      "$(grep -c "1 nonterminal run(s) of pat-validity.yml" "$tmp/s12b-$st.out")" 1
    chk "nonterminal status ${st}: zero mutations" \
      "$(grep -cE '^secret (set|delete) ' "$sN/calls.log" || true)" 0
  done

  # --- scenario 12c: the fake-gh MODELS gh's disabled-workflow lookup semantics directly
  # (round-6 finding 1 non-vacuity): after a `workflow disable`, a name-based run listing
  # WITHOUT --all fails (real gh excludes disabled workflows from the name lookup), while the
  # same listing WITH --all serves the runs. Exercised for BOTH listing shapes — the round-8
  # snapshot form the drain check uses and the retained per-status form — so the branches the
  # mutation checks rely on (strip --all from the drain check -> every quiesced scenario goes
  # red) are themselves proven live, not assumed.
  local s12c="$tmp/s12c" noall_rc=0 withall_rc=0 snap_noall_rc=0 snap_all_rc=0
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
  FAKE_GH_STATE="$s12c" "$tmp/bin/gh" run list -R o/r --workflow worker.yml --limit 1000 --json status,databaseId --jq "$NONTERMINAL_FILTER" \
    > "$tmp/s12c-snap-noall.out" 2>&1 || snap_noall_rc=$?
  chk "fake-gh model: SNAPSHOT listing without --all on a DISABLED workflow errors out too" "$snap_noall_rc" 1
  FAKE_GH_STATE="$s12c" "$tmp/bin/gh" run list --all -R o/r --workflow worker.yml --limit 1000 --json status,databaseId --jq "$NONTERMINAL_FILTER" \
    > "$tmp/s12c-snap-all.out" 2>&1 || snap_all_rc=$?
  chk "fake-gh model: SNAPSHOT listing with --all serves the filtered count on the disabled workflow" \
    "$snap_all_rc-$(cat "$tmp/s12c-snap-all.out")" 0-0

  # --- scenario 12d: TRANSITIONING RUN (round-8 finding 2 — the non-atomic drain check): a
  # writer run moves between nonterminal statuses (requested -> queued, the real forward
  # transition) BETWEEN listing calls. The fake models the legal interleaving in which every
  # per-status query misses it — the run is never in the queried status at the instant of that
  # query — so the OLD per-status loop would proceed straight into the migration. That is the
  # MUTATION CHECK: revert drain_check_no_live_writers to the per-status loop and THIS
  # scenario goes red (rc 0, mutations performed). The single-snapshot check captures the run
  # in whatever status it currently holds and fails closed.
  local s12d="$tmp/s12d"
  mkdir -p "$s12d"
  seed_quiesced "$s12d"
  printf '%s\n' "${names[@]}" > "$s12d/repo_secrets"
  : > "$s12d/env_secrets"
  printf 'requested\n' > "$s12d/transitioning_pat-validity.yml"
  rc=$(run_case "$s12d" "$tmp/s12d.out" main all)
  chk "transitioning run: the single-snapshot drain check CATCHES it -> fail closed" "$rc" 1
  chk "transitioning run: message names count + workflow" \
    "$(grep -c '1 nonterminal run(s) of pat-validity.yml' "$tmp/s12d.out")" 1
  chk "transitioning run: zero mutations" \
    "$(grep -cE '^secret (set|delete) ' "$s12d/calls.log" || true)" 0
  # ... and the QUIESCE phase's own drain check catches it identically.
  local s12e="$tmp/s12e"
  mkdir -p "$s12e"
  printf 'requested\n' > "$s12e/transitioning_worker.yml"
  rc=$(run_case "$s12e" "$tmp/s12e.out" quiesce none)
  chk "transitioning run: the quiesce phase's drain check catches it too" "$rc" 1

  # --- scenario 13: ENV LISTING FAILURE (main) — a dead listing is a refusal, never "empty env".
  local s13="$tmp/s13"
  mkdir -p "$s13"
  seed_quiesced "$s13"
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
  seed_quiesced "$s14"
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
  seed_quiesced "$s15"
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
  seed_quiesced "$s16"
  printf '%s\n' "${names[@]}" > "$s16/repo_secrets"
  : > "$s16/env_secrets"
  printf 'secrets:read\nsecrets:write\nenvironments:read\nenvironments:write\n' > "$s16/grants"
  rc=$(run_case "$s16" "$tmp/s16.out" main all)
  chk "no actions grant -> quiesce gate fails closed" "$rc" 1
  chk "no actions grant: distinct fail-closed message on the FIRST workflow-state read" \
    "$(grep -c 'could not read the state of writer workflow worker.yml' "$tmp/s16.out")" 1
  chk "no actions grant: zero listings, zero mutations (only the one denied state read)" \
    "$(grep -cvE '^api repos/o/r/actions/workflows/' "$s16/calls.log" || true)-$(grep -cE '^api repos/o/r/actions/workflows/' "$s16/calls.log")" 0-1

  # --- scenario 16b: PERMISSION MODEL — token with actions:READ only on the QUIESCE phase:
  # the disable needs Actions WRITE, so an under-granted quiesce mint fails closed at the
  # first disable, before any listing or mutation. This is the regression class the mint
  # contract guards against end-to-end.
  local s16b="$tmp/s16b"
  mkdir -p "$s16b"
  printf 'actions:read\n' > "$s16b/grants"
  rc=$(run_case "$s16b" "$tmp/s16b.out" quiesce none)
  chk "actions:read-only grant on the QUIESCE phase -> fails closed at the first disable" "$rc" 1
  chk "actions:read-only quiesce grant: message names the Actions: write requirement" \
    "$(grep -c 'needs the App token.s Actions: write grant' "$tmp/s16b.out")" 1
  chk "actions:read-only quiesce grant: zero mutations" \
    "$(grep -cE '^secret (set|delete) ' "$s16b/calls.log" || true)" 0

  # --- scenario 16c: ROUND-8 LEAST-PRIVILEGE ACCEPT DIRECTION — the migrate phase's mint was
  # deliberately WEAKENED actions write -> read (it only READS workflow state + run listings
  # for its gate; the disable lives in the quiesce phase). Prove actions:read suffices: a
  # fully-migrating main run under a no-actions-write grants file must converge.
  local s16c="$tmp/s16c"
  mkdir -p "$s16c"
  seed_quiesced "$s16c"
  printf '%s\n' "${names[@]}" > "$s16c/repo_secrets"
  : > "$s16c/env_secrets"
  printf 'actions:read\nsecrets:read\nsecrets:write\nenvironments:read\nenvironments:write\n' > "$s16c/grants"
  rc=$(run_case "$s16c" "$tmp/s16c.out" main all)
  chk "round-8 least privilege: the migrate phase converges under actions:READ (no write grant)" "$rc" 0

  # --- scenario 17: PERMISSION MODEL — token WITHOUT environments:write: the first env-secret
  # set 403s; hard fail with the repo scope untouched (no deletions ever reached).
  local s17="$tmp/s17"
  mkdir -p "$s17"
  seed_quiesced "$s17"
  printf '%s\n' "${names[@]}" > "$s17/repo_secrets"
  : > "$s17/env_secrets"
  printf 'actions:read\nactions:write\nsecrets:read\nsecrets:write\nenvironments:read\n' > "$s17/grants"
  rc=$(run_case "$s17" "$tmp/s17.out" main all)
  chk "no environments:write grant -> env-secret set fails closed" "$rc" 1
  chk "no environments:write grant: distinct message names the grant" \
    "$(grep -c 'gh secret set ACCOUNT_EMAIL_MAP --env dispatch-secrets failed' "$tmp/s17.out")" 1
  chk "no environments:write grant: NO deletions, repo scope untouched" \
    "$(grep -cE '^secret delete ' "$s17/calls.log" || true)-$(wc -l < "$s17/repo_secrets")" 0-14

  # --- scenario 18: WORKFLOW MINT CONTRACT (round-4 finding 3) — the REAL workflow's FOUR mint
  # steps must declare exactly the phase-specific grant sets the permission scenarios above
  # model; the fake-gh grants files prove the SCRIPT fails closed under-granted, this proves the
  # WORKFLOW actually requests the grants. Then the check's own non-vacuity: a mutated copy with
  # a REMOVED declaration and one with a WEAKENED declaration must each go red.
  local wf_real wf_mut="$tmp/wf-mut.yml"
  wf_real="$(dirname -- "$me")/../.github/workflows/migrate-secrets-to-env.yml"
  rc=0; check_workflow_mint_contract "$wf_real" > "$tmp/s18.out" 2>&1 || rc=$?
  chk "workflow mint contract holds on the real migrate-secrets-to-env.yml" "$rc" 0
  grep -v 'permission-actions: read' "$wf_real" > "$wf_mut"   # strips the migrate AND cleanup mints' actions:read
  rc=0; check_workflow_mint_contract "$wf_mut" > "$tmp/s18b.out" 2>&1 || rc=$?
  chk "contract goes RED when the permission-actions: read declarations are removed (the exact round-4 vacuity gap)" "$rc" 1
  chk "contract names BOTH under-granted mints when actions:read is stripped (migrate + cleanup)" \
    "$(grep -c 'workflow contract violated' "$tmp/s18b.out")" 2
  grep -v 'permission-actions: write' "$wf_real" > "$wf_mut"  # strips the quiesce AND reenable actions:write mints
  rc=0; check_workflow_mint_contract "$wf_mut" > "$tmp/s18e.out" 2>&1 || rc=$?
  chk "contract goes RED when the permission-actions: write declarations (round-8 quiesce / re-enable) are removed" "$rc" 1
  chk "contract names BOTH under-granted mints when actions:write is stripped (quiesce + reenable)" \
    "$(grep -c 'workflow contract violated' "$tmp/s18e.out")" 2
  sed 's/permission-actions: write/permission-actions: read/' "$wf_real" > "$wf_mut"  # de-fangs the quiesce + reenable mints
  rc=0; check_workflow_mint_contract "$wf_mut" > "$tmp/s18f.out" 2>&1 || rc=$?
  chk "contract goes RED when actions is WEAKENED write -> read (quiesce/reenable could no longer disable/enable)" "$rc" 1
  sed 's/permission-actions: read/permission-actions: write/' "$wf_real" > "$wf_mut"  # silently WIDENS migrate + cleanup back to write
  rc=0; check_workflow_mint_contract "$wf_mut" > "$tmp/s18g.out" 2>&1 || rc=$?
  chk "contract goes RED when actions is WIDENED read -> write (round-8 least privilege: migrate/cleanup never disable)" "$rc" 1
  sed 's/permission-environments: write/permission-environments: read/' "$wf_real" > "$wf_mut"
  rc=0; check_workflow_mint_contract "$wf_mut" > "$tmp/s18c.out" 2>&1 || rc=$?
  chk "contract goes RED when the main-phase environments grant is WEAKENED to read" "$rc" 1
  sed 's/^          permission-secrets: write$/          permission-secrets: write\n          permission-contents: write/' \
    "$wf_real" > "$wf_mut"
  rc=0; check_workflow_mint_contract "$wf_mut" > "$tmp/s18d.out" 2>&1 || rc=$?
  chk "contract goes RED when an extra grant is silently WIDENED in (exact-set pin)" "$rc" 1

  # --- scenario 18h: ACTOR CONTRACT (round-9 finding 2 — the RE-RUN bypass): github.actor
  # stays the ORIGINAL initiator when a run is re-run, while github.triggering_actor is the
  # re-runner — so an actor-only `if:` lets any write-access user re-run a jeswr-initiated run
  # while it holds the secret-admin mint. Every phase job must pin BOTH fields; dropping the
  # triggering_actor clause from any job (the sed strips it from ALL FOUR) goes red, one
  # violation per job.
  rc=0; check_workflow_actor_contract "$wf_real" > "$tmp/s18h.out" 2>&1 || rc=$?
  chk "actor contract holds on the real workflow (github.actor AND github.triggering_actor pinned on all 4 phase jobs)" "$rc" 0
  sed "s/ && github.triggering_actor == 'jeswr'//" "$wf_real" > "$wf_mut"
  rc=0; check_workflow_actor_contract "$wf_mut" > "$tmp/s18i.out" 2>&1 || rc=$?
  chk "actor contract goes RED when the triggering_actor clause is dropped (the re-run bypass reopens)" "$rc" 1
  chk "actor contract names ALL FOUR under-gated jobs when the clause is dropped" \
    "$(grep -c 'workflow contract violated' "$tmp/s18i.out")" 4
  sed "s/github\.actor == 'jeswr' && //" "$wf_real" > "$wf_mut"
  rc=0; check_workflow_actor_contract "$wf_mut" > "$tmp/s18j.out" 2>&1 || rc=$?
  chk "actor contract goes RED when the github.actor clause is dropped (both fields are load-bearing)" "$rc" 1

  # --- scenario 19: RESUME-WRITERS happy path (the self-resume after a COMPLETED migrate, or
  # the standalone phase: resume) — exactly the 4 enables, in the canonical writer order, and
  # nothing else.
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
  seed_quiesced "$s22"
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
  seed_quiesced "$s22b"
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
  seed_quiesced "$s23"
  printf '%s\n' "${names[@]}" > "$s23/env_secrets"
  for n in "${names[@]}"; do printf '%s=v1-%s\n' "$n" "$n"; done > "$s23/env_values"
  : > "$s23/repo_secrets"
  rc=$(run_case "$s23" "$tmp/s23.out" main none)
  chk "pure resume (env holds all 14, repo absent): converges with zero values" "$rc" 0
  chk "pure resume: NO set argv" "$(grep -cE '^secret set ' "$s23/calls.log" || true)" 0
  chk "pure resume: NO delete argv" "$(grep -cE '^secret delete ' "$s23/calls.log" || true)" 0
  chk "pure resume: env values untouched (all 14 still V1)" \
    "$(grep -c '=v1-' "$s23/env_values")" 14

  # --- scenario 24: QUEUE-TIME ORDERING VIOLATION (sol round-9 finding 1): a migrate run was
  # DISPATCHED while the quiesce run was still executing — it sat PENDING in the shared
  # concurrency group with its secrets snapshot fixed at QUEUE time (12:00), i.e. from BEFORE
  # the drain finished. A writer admitted pre-drain rotated every repo value to V2 AFTER the
  # snapshot; the quiesce then drained and COMPLETED at 12:05 (> 12:00). By start time the
  # writers are disabled AND drained — M0a/M0b pass — so ONLY the ordering attestation can
  # catch it: the newest successful quiesce completed AFTER this run was queued -> fail closed
  # with ZERO mutations and the rotated V2 repo values untouched. (Without the gate: M3 copies
  # the stale queue-time snapshot into the env and M5 deletes fresh V2 — the exact
  # stale-copy/fresh-delete loss.) The listing also carries an OLDER successful quiesce
  # (completed 11:00 < 12:00) as a DECOY: an any-success-before-queue check would pass on it —
  # the attestation must select the NEWEST successful quiesce, so the run still fails.
  # MUTATION CHECK: invert the timestamp comparison in assert_quiesce_completed_before_queue
  # and this scenario goes red (rc 0, mutations performed) while the good-ordering scenarios
  # (1, 2, ...) go red in the opposite direction.
  local s24="$tmp/s24"
  mkdir -p "$s24"
  seed_quiesced "$s24"
  printf '2026-07-18T12:00:00Z\n' > "$s24/run_created"
  mk_history \
    "$(mk_run 6900 'migrate-secrets [quiesce]' success 2026-07-18T10:50:00Z 2026-07-18T11:00:00Z)" \
    "$(mk_run 7000 'migrate-secrets [quiesce]' success 2026-07-18T11:58:00Z 2026-07-18T12:05:00Z)" \
    > "$s24/wf_runs"
  printf '%s\n' "${names[@]}" > "$s24/repo_secrets"
  for n in "${names[@]}"; do printf '%s=v2-%s\n' "$n" "$n"; done > "$s24/repo_values"
  : > "$s24/env_secrets"
  rc=$(run_case "$s24" "$tmp/s24.out" main all)
  chk "queue-time ordering violation: quiesce completed AFTER this run was queued -> fail closed" "$rc" 1
  chk "queue-time ordering violation: distinct re-dispatch message" \
    "$(grep -c 'quiesce must COMPLETE before migrate is queued' "$tmp/s24.out")" 1
  chk "queue-time ordering violation: the older-success DECOY did not satisfy the check (newest selected)" \
    "$(grep -c 'completed at 2026-07-18T12:05:00Z' "$tmp/s24.out")" 1
  chk "queue-time ordering violation: ZERO mutations (the stale-copy/fresh-delete loss never opens)" \
    "$(grep -cE '^secret (set|delete) ' "$s24/calls.log" || true)" 0
  chk "queue-time ordering violation: the rotated V2 repo values survive untouched" \
    "$(grep -c '=v2-' "$s24/repo_values")" 14
  # ... and the cleanup phase's C0 gate applies the same attestation.
  local s24c="$tmp/s24c"
  mkdir -p "$s24c"
  seed_quiesced "$s24c"
  cp "$s24/run_created" "$s24c/run_created"
  cp "$s24/wf_runs" "$s24c/wf_runs"
  printf '%s\n' "${names[@]}" > "$s24c/env_secrets"
  printf '%s\n' "${bootstrap[@]}" > "$s24c/repo_secrets"
  rc=$(run_case "$s24c" "$tmp/s24c.out" cleanup-bootstrap none)
  chk "queue-time ordering violation (cleanup): fail closed with zero deletions" \
    "$rc-$(grep -cE '^secret delete ' "$s24c/calls.log" || true)" 1-0

  # --- scenario 24b: NO SUCCESSFUL QUIESCE RUN in the listing — the writers being disabled
  # (M0a green) is NOT an attestation that a quiesce RUN drained them (an admin may have
  # disabled them by hand, or the only quiesce run FAILED). The listing carries a FAILED
  # quiesce and a SUCCESSFUL *migrate* decoy — the migrate decoy must not satisfy the
  # attestation, and (round 10) the failed quiesce IS the newest quiesce/resume event, so the
  # run fails closed on the latest-quiesce-attempt-did-not-succeed rule with zero mutations.
  local s24b="$tmp/s24b"
  mkdir -p "$s24b"
  seed_quiesced "$s24b"
  mk_history \
    "$(mk_run 7000 'migrate-secrets [quiesce]' failure 2026-07-18T11:40:00Z 2026-07-18T11:50:00Z)" \
    "$(mk_run 6800 'migrate-secrets [migrate]' success 2026-07-18T10:00:00Z 2026-07-18T10:10:00Z)" \
    > "$s24b/wf_runs"
  printf '%s\n' "${names[@]}" > "$s24b/repo_secrets"
  : > "$s24b/env_secrets"
  rc=$(run_case "$s24b" "$tmp/s24b.out" main all)
  chk "no successful quiesce run (failed quiesce + successful-migrate decoy) -> fail closed" "$rc" 1
  chk "no successful quiesce run: distinct latest-attempt-did-not-succeed message" \
    "$(grep -c 'the latest quiesce attempt did not succeed' "$tmp/s24b.out")" 1
  chk "no successful quiesce run: zero mutations" \
    "$(grep -cE '^secret (set|delete) ' "$s24b/calls.log" || true)" 0

  # --- scenario 24b2: NO QUIESCE/RESUME EVENT AT ALL preceding this run — only a successful
  # MIGRATE decoy in the history. The event filter must not surface it: fail closed on the
  # no-event message with zero mutations.
  local s24b2="$tmp/s24b2"
  mkdir -p "$s24b2"
  seed_quiesced "$s24b2"
  mk_history \
    "$(mk_run 6800 'migrate-secrets [migrate]' success 2026-07-18T10:00:00Z 2026-07-18T10:10:00Z)" \
    > "$s24b2/wf_runs"
  printf '%s\n' "${names[@]}" > "$s24b2/repo_secrets"
  : > "$s24b2/env_secrets"
  rc=$(run_case "$s24b2" "$tmp/s24b2.out" main all)
  chk "no quiesce/resume event at all (migrate-success decoy only) -> fail closed" "$rc" 1
  chk "no quiesce/resume event: distinct no-event message" \
    "$(grep -c 'no quiesce/resume event' "$tmp/s24b2.out")" 1
  chk "no quiesce/resume event: zero mutations" \
    "$(grep -cE '^secret (set|delete) ' "$s24b2/calls.log" || true)" 0

  # --- scenario 25: SUPERSEDED SUCCESSFUL QUIESCE (sol round-10 finding 1 — the total-order
  # attestation). The exact killer sequence: Q1 succeeds (10:00 -> 10:10) -> phase: resume
  # re-enables the writers (10:30 -> 10:33) -> a writer starts -> Q2 disables the writers but
  # FAILS its drain check (the writer is live; 11:50 -> 12:05, conclusion failure) -> migrate
  # is queued DURING Q2 (12:00 — its secrets snapshot fixes V1) -> the live writer rotates
  # every value V1 -> V2 and finishes. At migrate start time the writers are disabled AND
  # drained, so M0a/M0b pass — and a success-only quiesce filter discards failed Q2 and
  # accepts pre-queue Q1 (completed 10:10 < queued 12:00): M3 would overwrite env V2 with the
  # stale V1 snapshot and M5 would delete repo V2. The total order catches it: the newest
  # quiesce/resume event preceding 12:00 is FAILED Q2 (created 11:50) -> fail closed, zero
  # mutations, the rotated V2 repo values untouched. MUTATION CHECK: revert
  # QUIESCE_RESUME_EVENT_FILTER to the old success-only-quiesce selection and this scenario
  # (plus 25b/25c/25d) goes red — rc 0, 26 mutations, the V2 values destroyed.
  local s25="$tmp/s25"
  mkdir -p "$s25"
  seed_quiesced "$s25"
  printf '2026-07-18T12:00:00Z\n' > "$s25/run_created"
  mk_history \
    "$(mk_run 7000 'migrate-secrets [quiesce]' success 2026-07-18T10:00:00Z 2026-07-18T10:10:00Z)" \
    "$(mk_run 7001 'migrate-secrets [resume]' success 2026-07-18T10:30:00Z 2026-07-18T10:33:00Z)" \
    "$(mk_run 7002 'migrate-secrets [quiesce]' failure 2026-07-18T11:50:00Z 2026-07-18T12:05:00Z)" \
    > "$s25/wf_runs"
  printf '%s\n' "${names[@]}" > "$s25/repo_secrets"
  for n in "${names[@]}"; do printf '%s=v2-%s\n' "$n" "$n"; done > "$s25/repo_values"
  : > "$s25/env_secrets"
  rc=$(run_case "$s25" "$tmp/s25.out" main all)
  chk "superseded quiesce (Q1 ok -> resume -> Q2 FAILED, migrate queued during Q2) -> fail closed" "$rc" 1
  chk "superseded quiesce: distinct latest-attempt-did-not-succeed message (not the pre-queue Q1 accept)" \
    "$(grep -c 'the latest quiesce attempt did not succeed' "$tmp/s25.out")" 1
  chk "superseded quiesce: ZERO mutations (the stale-copy/fresh-delete loss never opens)" \
    "$(grep -cE '^secret (set|delete) ' "$s25/calls.log" || true)" 0
  chk "superseded quiesce: the rotated V2 repo values survive untouched" \
    "$(grep -c '=v2-' "$s25/repo_values")" 14
  # ... and the cleanup phase's C0 gate applies the same total order.
  local s25d="$tmp/s25d"
  mkdir -p "$s25d"
  seed_quiesced "$s25d"
  cp "$s25/run_created" "$s25d/run_created"
  cp "$s25/wf_runs" "$s25d/wf_runs"
  printf '%s\n' "${names[@]}" > "$s25d/env_secrets"
  printf '%s\n' "${bootstrap[@]}" > "$s25d/repo_secrets"
  rc=$(run_case "$s25d" "$tmp/s25d.out" cleanup-bootstrap none)
  chk "superseded quiesce (cleanup): fail closed with zero deletions" \
    "$rc-$(grep -cE '^secret delete ' "$s25d/calls.log" || true)" 1-0

  # --- scenario 25b: NEWEST EVENT IS A RESUME — Q1 succeeded, then phase: resume re-enabled
  # the writers, then someone (or an out-of-band actions-admin) re-disabled them by hand so
  # M0a/M0b pass. The last PROVEN drain is superseded by the resume: any writer run in
  # between may have rotated a secret. Fail closed, zero mutations.
  local s25b="$tmp/s25b"
  mkdir -p "$s25b"
  seed_quiesced "$s25b"
  mk_history \
    "$(mk_run 7000 'migrate-secrets [quiesce]' success 2026-07-18T10:00:00Z 2026-07-18T10:10:00Z)" \
    "$(mk_run 7001 'migrate-secrets [resume]' success 2026-07-18T10:30:00Z 2026-07-18T10:33:00Z)" \
    > "$s25b/wf_runs"
  printf '%s\n' "${names[@]}" > "$s25b/repo_secrets"
  : > "$s25b/env_secrets"
  rc=$(run_case "$s25b" "$tmp/s25b.out" main all)
  chk "newest event is a RESUME -> fail closed (writers re-enabled after the last successful quiesce)" "$rc" 1
  chk "newest-is-resume: distinct re-enabled message" \
    "$(grep -c 'the writers were re-enabled after the last successful quiesce' "$tmp/s25b.out")" 1
  chk "newest-is-resume: zero mutations" \
    "$(grep -cE '^secret (set|delete) ' "$s25b/calls.log" || true)" 0

  # --- scenario 25c: NEWEST EVENT IS AN IN-PROGRESS QUIESCE (conclusion null) — a newer
  # quiesce attempt exists but has not concluded, so its drain is unproven and it supersedes
  # Q1. Fail closed, zero mutations.
  local s25c="$tmp/s25c"
  mkdir -p "$s25c"
  seed_quiesced "$s25c"
  mk_history \
    "$(mk_run 7000 'migrate-secrets [quiesce]' success 2026-07-18T10:00:00Z 2026-07-18T10:10:00Z)" \
    "$(mk_run 7002 'migrate-secrets [quiesce]' null 2026-07-18T11:58:00Z 2026-07-18T11:59:00Z)" \
    > "$s25c/wf_runs"
  printf '%s\n' "${names[@]}" > "$s25c/repo_secrets"
  : > "$s25c/env_secrets"
  rc=$(run_case "$s25c" "$tmp/s25c.out" main all)
  chk "newest event is an IN-PROGRESS quiesce (null conclusion) -> fail closed" "$rc" 1
  chk "newest-is-in-progress: distinct not-concluded message" \
    "$(grep -c 'the latest quiesce attempt has not CONCLUDED' "$tmp/s25c.out")" 1
  chk "newest-is-in-progress: zero mutations" \
    "$(grep -cE '^secret (set|delete) ' "$s25c/calls.log" || true)" 0

  # --- scenario 26: RE-RUN PROHIBITED, EVERY PHASE (sol round 11 — M0c is not attempt-aware):
  # GITHUB_RUN_ID is constant across re-runs while GITHUB_RUN_ATTEMPT increments, so a re-run
  # would total-order the quiesce/resume history against the ORIGINAL attempt's created_at.
  # The kill is total: each of the four phases asserts attempt 1 FIRST and fails closed on
  # attempt 2 with ZERO gh invocations (the gate precedes setup and every API call — calls.log
  # is never even created), naming the prohibition + the fresh-dispatch recovery.
  local ph s26 s26b
  for ph in quiesce main cleanup-bootstrap resume-writers; do
    s26="$tmp/s26-$ph"
    mkdir -p "$s26"
    seed_quiesced "$s26"
    printf '%s\n' "${names[@]}" > "$s26/repo_secrets"
    : > "$s26/env_secrets"
    rc=$(RUN_ATTEMPT_OVERRIDE=2 run_case "$s26" "$tmp/s26-$ph.out" "$ph" all)
    chk "re-run (attempt 2) on phase ${ph} -> fail closed" "$rc" 1
    chk "re-run (attempt 2) on phase ${ph}: names the prohibition + fresh-dispatch recovery" \
      "$(grep -c 're-runs are prohibited for this workflow (queue-time attestation is attempt-unaware' "$tmp/s26-$ph.out")-$(grep -c 'dispatch a FRESH run of this phase' "$tmp/s26-$ph.out")" 1-1
    chk "re-run (attempt 2) on phase ${ph}: ZERO gh invocations (no calls.log ever created)" \
      "$(test -e "$s26/calls.log" && echo exists || echo absent)" absent
  done

  # --- scenario 26b: GITHUB_RUN_ATTEMPT ABSENT — PINNED fail-closed semantics: outside a real
  # runner (or under a harness that strips the default env) a phase cannot prove it is a fresh
  # dispatch, and absent is NEVER assumed to mean attempt 1. Same zero-invocation refusal on
  # every phase.
  for ph in quiesce main cleanup-bootstrap resume-writers; do
    s26b="$tmp/s26b-$ph"
    mkdir -p "$s26b"
    seed_quiesced "$s26b"
    printf '%s\n' "${names[@]}" > "$s26b/repo_secrets"
    : > "$s26b/env_secrets"
    rc=$(RUN_ATTEMPT_OVERRIDE=absent run_case "$s26b" "$tmp/s26b-$ph.out" "$ph" all)
    chk "GITHUB_RUN_ATTEMPT absent on phase ${ph} -> fail closed (absent never means attempt 1)" "$rc" 1
    chk "GITHUB_RUN_ATTEMPT absent on phase ${ph}: distinct unset message" \
      "$(grep -c 'GITHUB_RUN_ATTEMPT is unset' "$tmp/s26b-$ph.out")" 1
    chk "GITHUB_RUN_ATTEMPT absent on phase ${ph}: ZERO gh invocations" \
      "$(test -e "$s26b/calls.log" && echo exists || echo absent)" absent
  done

  # --- scenario 26c: SOL'S RE-RUN SEQUENCE (round-11 non-vacuity — the exact state an
  # attempt-2 re-run presents to M0a/M0b/M0c): the ORIGINAL migrate run was queued at 12:00
  # behind a good quiesce (completed 11:50) and failed for an unrelated reason; later a resume
  # re-enabled the writers (13:00) and a Q2 quiesce attempt FAILED its drain (14:00 -> 14:10);
  # the writers ended up disabled again (M0a passes, M0b drained) and every repo value rotated
  # to V2. NOW the old run is RE-RUN: GITHUB_RUN_ID is unchanged, so M0c fetches the ORIGINAL
  # created_at (12:00) and its strictly-precedes filter EXCLUDES the newer resume + failed-Q2
  # events — the stale attestation would PASS on the 11:50 quiesce while this attempt's secret
  # snapshot timing diverges from that queue instant. Only the attempt gate stands between
  # this state and the mutation stage: attempt=2 must fail closed with ZERO gh invocations and
  # the rotated V2 values untouched. MUTATION CHECK: comment out the assert_first_attempt
  # calls and THIS scenario goes red (rc 0, 26 mutations, the V2 repo values destroyed) — the
  # harness proves the gate is load-bearing, not decorative.
  local s26c="$tmp/s26c"
  mkdir -p "$s26c"
  seed_quiesced "$s26c"
  printf '2026-07-18T12:00:00Z\n' > "$s26c/run_created"
  mk_history \
    "$(mk_run 7000 'migrate-secrets [quiesce]' success 2026-07-18T11:40:00Z 2026-07-18T11:50:00Z)" \
    "$(mk_run 7001 'migrate-secrets [resume]' success 2026-07-18T13:00:00Z 2026-07-18T13:03:00Z)" \
    "$(mk_run 7002 'migrate-secrets [quiesce]' failure 2026-07-18T14:00:00Z 2026-07-18T14:10:00Z)" \
    > "$s26c/wf_runs"
  printf '%s\n' "${names[@]}" > "$s26c/repo_secrets"
  for n in "${names[@]}"; do printf '%s=v2-%s\n' "$n" "$n"; done > "$s26c/repo_values"
  : > "$s26c/env_secrets"
  rc=$(RUN_ATTEMPT_OVERRIDE=2 run_case "$s26c" "$tmp/s26c.out" main all)
  chk "sol re-run sequence (attempt 2, stale created_at vs newer resume+Q2 history) -> fail closed" "$rc" 1
  chk "sol re-run sequence: the prohibition message names the fresh-dispatch recovery" \
    "$(grep -c 'dispatch a FRESH run of this phase' "$tmp/s26c.out")" 1
  chk "sol re-run sequence: ZERO gh invocations (the stale M0c attestation is never even consulted)" \
    "$(test -e "$s26c/calls.log" && echo exists || echo absent)" absent
  chk "sol re-run sequence: the rotated V2 repo values survive untouched" \
    "$(grep -c '=v2-' "$s26c/repo_values")" 14
  # ... and an attempt-2 re-run of the CLEANUP phase fails closed identically (its C0 gate
  # shares M0c, so it shares the attempt-unawareness — and the total kill).
  local s26d="$tmp/s26d"
  mkdir -p "$s26d"
  seed_quiesced "$s26d"
  cp "$s26c/run_created" "$s26d/run_created"
  cp "$s26c/wf_runs" "$s26d/wf_runs"
  printf '%s\n' "${names[@]}" > "$s26d/env_secrets"
  printf '%s\n' "${bootstrap[@]}" > "$s26d/repo_secrets"
  rc=$(RUN_ATTEMPT_OVERRIDE=2 run_case "$s26d" "$tmp/s26d.out" cleanup-bootstrap none)
  chk "sol re-run sequence (cleanup): fail closed with zero invocations" \
    "$rc-$(test -e "$s26d/calls.log" && echo exists || echo absent)" 1-absent

  # --- scenario 27: SKIPPED-'SUCCESS' COLLABORATOR QUIESCE (sol round 12 — attested-fields
  # selection): a quiesce RUN whose only job was SKIPPED by the workflow's actor/ref
  # if-condition (a COLLABORATOR dispatched it) still reports run conclusion=success while
  # disabling and draining NOTHING. Sol's sequence: a legit jeswr quiesce FAILED its drain
  # (10:00 -> 10:10, a writer was live), then the collaborator's skipped-'success' quiesce
  # (11:40 -> 11:41, actor/triggering_actor NOT jeswr) SUPERSEDES it as the newest event; the
  # live writer rotated every repo value to V2 and finished; someone re-disabled the writers
  # so M0a/M0b pass at start time. The pre-round-12 selection (displayTitle + conclusion +
  # timestamps only) accepted the skipped run as a drain proof — a proof of NOTHING. The
  # attested-fields rule REJECTS it (actor != jeswr), and the rejected event being the newest
  # means fail closed exactly like a failed quiesce: zero mutations, rotated V2 values
  # untouched. MUTATION CHECK: drop the actor pin from the winning-event check in
  # assert_quiesce_completed_before_queue and this scenario goes red (rc 0, mutations
  # performed, the V2 values destroyed).
  local s27="$tmp/s27"
  mkdir -p "$s27"
  seed_quiesced "$s27"
  printf '2026-07-18T12:00:00Z\n' > "$s27/run_created"
  mk_history \
    "$(mk_run 7000 'migrate-secrets [quiesce]' failure 2026-07-18T10:00:00Z 2026-07-18T10:10:00Z)" \
    "$(mk_run 7003 'migrate-secrets [quiesce]' success 2026-07-18T11:40:00Z 2026-07-18T11:41:00Z collab-writeaccess collab-writeaccess)" \
    > "$s27/wf_runs"
  printf '%s\n' "${names[@]}" > "$s27/repo_secrets"
  for n in "${names[@]}"; do printf '%s=v2-%s\n' "$n" "$n"; done > "$s27/repo_values"
  : > "$s27/env_secrets"
  rc=$(run_case "$s27" "$tmp/s27.out" main all)
  chk "collaborator skipped-'success' quiesce supersedes a failed legit quiesce -> fail closed" "$rc" 1
  chk "collaborator skipped quiesce: distinct NOT-field-attested rejection naming the actor" \
    "$(grep -c "is NOT field-attested — actor='collab-writeaccess'" "$tmp/s27.out")" 1
  chk "collaborator skipped quiesce: ZERO mutations (the skipped run's 'success' proved no drain)" \
    "$(grep -cE '^secret (set|delete) ' "$s27/calls.log" || true)" 0
  chk "collaborator skipped quiesce: the rotated V2 repo values survive untouched" \
    "$(grep -c '=v2-' "$s27/repo_values")" 14
  # ... and the cleanup phase's C0 gate applies the same attested-fields rule.
  local s27d="$tmp/s27d"
  mkdir -p "$s27d"
  seed_quiesced "$s27d"
  cp "$s27/run_created" "$s27d/run_created"
  cp "$s27/wf_runs" "$s27d/wf_runs"
  printf '%s\n' "${names[@]}" > "$s27d/env_secrets"
  printf '%s\n' "${bootstrap[@]}" > "$s27d/repo_secrets"
  rc=$(run_case "$s27d" "$tmp/s27d.out" cleanup-bootstrap none)
  chk "collaborator skipped quiesce (cleanup): fail closed with zero deletions" \
    "$rc-$(grep -cE '^secret delete ' "$s27d/calls.log" || true)" 1-0

  # --- scenario 27b: EVERY ATTESTED FIELD IS LOAD-BEARING — one rejection scenario per
  # remaining field on an otherwise fully-valid newest successful quiesce (completed 11:50 <
  # queued 12:00): triggering_actor != jeswr (a collaborator RE-RUN of a jeswr dispatch whose
  # jobs then skipped), head_branch != master (a branch-copy dispatch — its job skipped on the
  # ref gate), run_attempt != 1 (a re-run attempt — attempt-1-only phases mean a later attempt
  # that reports success had its job skipped or ran against a stale queue instant). Each must
  # be REJECTED with the field-attested message and zero mutations; dropping that field's pin
  # from the winning-event check turns exactly its scenario green-when-it-must-fail, i.e. red
  # here.
  local axis s27b
  for axis in trigger branch attempt; do
    s27b="$tmp/s27b-$axis"
    mkdir -p "$s27b"
    seed_quiesced "$s27b"
    case "$axis" in
      trigger) mk_history "$(mk_run 7004 'migrate-secrets [quiesce]' success 2026-07-18T11:40:00Z 2026-07-18T11:50:00Z jeswr collab-writeaccess)" > "$s27b/wf_runs" ;;
      branch)  mk_history "$(mk_run 7004 'migrate-secrets [quiesce]' success 2026-07-18T11:40:00Z 2026-07-18T11:50:00Z jeswr jeswr not-master)" > "$s27b/wf_runs" ;;
      attempt) mk_history "$(mk_run 7004 'migrate-secrets [quiesce]' success 2026-07-18T11:40:00Z 2026-07-18T11:50:00Z jeswr jeswr master 2)" > "$s27b/wf_runs" ;;
    esac
    printf '%s\n' "${names[@]}" > "$s27b/repo_secrets"
    : > "$s27b/env_secrets"
    rc=$(run_case "$s27b" "$tmp/s27b-$axis.out" main all)
    chk "unattested ${axis} on the newest successful quiesce -> REJECTED, fail closed" "$rc" 1
    chk "unattested ${axis}: the field-attested rejection message names the requirement" \
      "$(grep -c 'is NOT field-attested' "$tmp/s27b-$axis.out")" 1
    chk "unattested ${axis}: zero mutations" \
      "$(grep -cE '^secret (set|delete) ' "$s27b/calls.log" || true)" 0
  done

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
      quiesce) phase_quiesce ;;
      main) phase_main ;;
      cleanup-bootstrap) phase_cleanup ;;
      resume-writers) phase_resume ;;
      *) die 'usage: migrate-secrets.sh --phase quiesce|main|cleanup-bootstrap|resume-writers | --self-test' ;;
    esac ;;
  *) die 'usage: migrate-secrets.sh --phase quiesce|main|cleanup-bootstrap|resume-writers | --self-test' ;;
esac
