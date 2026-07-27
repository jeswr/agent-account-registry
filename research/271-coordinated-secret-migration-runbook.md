# #271: the coordinated cutover runbook — re-measured against the tree

> 🤖 **SPARQ agent** — design record, 2026-07-27. Maintainer-review document.
> **This record changes no behaviour.** It answers #271 — *what is the coordinated, all-at-once
> procedure that moves every repo-scope secret behind the protected environment across ALL
> secret-bearing workflows?* — by first re-measuring #271's own premises against the tree (three
> are stale, §2), then writing the sequence that is actually executable today (§4), the failure
> modes it can land in (§5), and the two things it **cannot** promise (§6).
>
> **Scope note.** #271 asks for a runbook, and steps 1, 3 and 4 of its ask are *repository
> settings* + *workflow dispatches* — actions no PR can perform. What a PR can contribute is the
> written, grounded sequence. That is this record. It edits no workflow, no script and no policy.

## 1. Why a runbook is the missing piece (and what already exists)

The migration is not undesigned. Four artefacts already cover parts of it and none of them is the
operator-facing sequence:

| artefact | covers | does not cover |
|---|---|---|
| `.github/workflows/migrate-secrets-to-env.yml` (header, `:1-176`) | the phase protocol and why each phase is shaped as it is | the settings steps around it; the current aborted state |
| `scripts/migrate-secrets.sh` | the state machine M0–M6 / C0–C4 / R0 and its refusals | which phase to dispatch, in what order, from *this* tree state |
| [`research/266-protected-environment-strategy.md`](266-protected-environment-strategy.md) | *which* environment shape (one shared `dispatch-secrets`) and why | the execution order |
| [`research/329-pre-migration-writer-recovery.md`](329-pre-migration-writer-recovery.md) | how to get the writers back **without** completing the migration | completing it |

`README.md` has a runbook heading (`:200`) but it is the account-enrolment runbook, not this.

So the gap #271 names is real. It is a **sequencing** gap, not a design gap.

## 2. #271's premises, re-measured — three are stale

All three corrections point the same way (the migration is *less* work than #271 assumes), but
each changes what the runbook must say, so none is cosmetic.

### 2.1 Correction A — step (2) is already done; the bindings landed ahead of the values

#271: "worker.yml, review-fix.yml, groom.yml, dashboard.yml, pat-validity.yml, set-up-account.yml,
verify-app.yml, account-whoami.yml, fingerprint-accounts.yml and backfill-provenance.yml ALL read
repo-scope secrets today … emptying repo scope without binding their secret-bearing jobs to
protected environments breaks them silently."

Derived on this tree with the guard's own parser rather than by reading the files — importing
`scripts/dispatch-secrets-guard.py` and calling `secret_consuming_jobs` / `binding_map_verdict`
(`:1780`, `:1798`) over all 20 workflow documents:

| | count |
|---|---|
| workflow files holding a secret-consuming job | 16 |
| secret-consuming **jobs** | 37 |
| carrying `environment: dispatch-secrets` | **34** |
| `BINDING_EXCEPTIONS` (`:1691`) | 3 |
| `binding_map_verdict` | **`(True, 'ok')`** |

The three exceptions are `dispatch.yml::secrets-guard` (its unbound `toJSON(secrets)` read *is*
check 1) and `migrate-secrets-to-env.yml::{quiesce,migrate}` (they must read the repo-scope
originals to move them). Every job in the ten workflows #271 names — 24 of the 34 — is bound:

| workflow | bound secret-consuming jobs |
|---|---|
| `worker.yml` | `claim`, `final_state`, `model_health`, `provenance`, `publish`, `worker` |
| `review-fix.yml` | `claim`, `model_health`, `outcome`, `run`, `unresolvable` |
| `groom.yml` | `dispatch-stall`, `groom`, `groom-alert`, `metrics-stale` |
| `dashboard.yml` | `build`, `cron-keepalive`, `probe` |
| `pat-validity.yml` | `probe` |
| `set-up-account.yml` | `login` |
| `verify-app.yml` | `verify` |
| `account-whoami.yml` | `whoami` |
| `fingerprint-accounts.yml` | `fingerprint` |
| `backfill-provenance.yml` | `backfill` |

Note this is stronger than "34 of 37 happen to carry the line": `binding_map_verdict` **refuses**
a consumer bound to any *other* environment and refuses a `BINDING_EXCEPTIONS` entry that is stale
— and it runs in `--self-test`, which `pr-gate.yml` gates on. The bindings are not merely present,
they are pinned.

**Consequence for the runbook: step (2) is a no-op.** The cutover moves *values*; no workflow edit
sits between the two sides of it. (This restates [research/266](266-protected-environment-strategy.md)
§2; the numbers above are today's re-derivation and differ by one job — 37/34/16 vs the 36/33/15
recorded there — so a reader should re-derive rather than cite either figure.)

### 2.2 Correction B — the "no `--ref`" justification is wrong; the conclusion survives on a different chain

#271: "all are legitimately triggered from the default branch — claim launches worker/review-fix
via `gh workflow run` with no `--ref` — so nothing is starved."

That is not what the code does. Both dispatch sites pass an explicit ref:

- `scripts/dispatch-claim.py:5576-5579` — `["workflow", "run", "review-fix.yml", "--repo", registry_repo, "--ref", workflow_ref, …]`
- `scripts/dispatch-claim.py:6838-6841` — the same shape for `worker.yml`

`workflow_ref` is `--workflow-ref` (`:17850`), fed from `WORKFLOW_REF: ${{ github.ref_name }}`
(`.github/workflows/dispatch.yml:1548,1572`) — i.e. **the ref of the dispatch run doing the
launching**, whatever that is.

The conclusion still holds, but by a chain rather than by assertion: the launching `claim` job is
itself `environment: dispatch-secrets`-bound (`dispatch.yml:1245`) and gated `needs: [plan,
secrets-guard]` (`:1222`), so under a default-branch-only policy `claim` can only *execute* at the
default branch, and therefore `github.ref_name` can only *be* the default branch at the moment it
builds that argv. Worker and review-fix are launched at the default branch because their launcher
could not have run anywhere else.

This matters for the runbook because it is **conditional on the policy being correct**. If the
policy is ever relaxed to admit a second branch, `claim` becomes runnable there and will propagate
that ref into the worker/review-fix dispatch — which is precisely why `branch_policy_verdict`
(`scripts/dispatch-secrets-guard.py:165`) refuses a `names != [default_branch]` list rather than
merely requiring the default branch to be *among* them. Cite the chain, not #271's premise.

The other trigger classes were checked directly and none is starved: `schedule`, `issues` and
`workflow_run` always run the default-branch copy at `refs/heads/<default>`. Only two workflows use
`pull_request` — `pr-gate.yml` (no secret-consuming job at all) and `set-up-account.yml`, whose
`pull_request: [closed]` job is `activate` (`:1202`), which the derivation above shows is **not** a
secret consumer; its `login` job is `if: github.event_name == 'issues'` (`:133`). So no
`pull_request`-triggered job is env-bound, and the `refs/pull/N/merge` ref never meets the policy.

### 2.3 Correction C — #271's secret list does not match the migration's closed set

`SECRET_NAMES` (`scripts/migrate-secrets.sh:343-351`) is 14 names and is **closed**:

- `BOOTSTRAP_NAMES` = `REGISTRY_ADMIN_APP_ID`, `REGISTRY_ADMIN_APP_KEY`
- `NONBOOTSTRAP_NAMES` = `ACCOUNT_EMAIL_MAP`, `ACCT01..07_TOKEN`, `ACCT{2,3,4}CSS_TOKEN`, `PROVENANCE_SALT`

Against #271's list:

| #271 names | in `SECRET_NAMES`? | what the runbook must do |
|---|---|---|
| `REGISTRY_ADMIN_APP_ID` / `_KEY` | ✅ (bootstrap) | migrated by phase `main`, repo copies drained by `cleanup-bootstrap` |
| `PROVENANCE_SALT`, `ACCT*_TOKEN` | ✅ | migrated by phase `main` |
| — (`ACCOUNT_EMAIL_MAP`) | ✅, **not named by #271** | migrated; #271's list is incomplete |
| `ALERT_TOKEN` / `ALERT_REPO` | ❌ **not migrated by any phase** | see below |
| `REGISTRY_SECRETS_PAT` | ❌ | already env-only and correct — `set-up-account.yml:384` documents `--env dispatch-secrets` as its canonical home *because* "a repo-scope copy would re-trip the secrets-guard" |

`ALERT_TOKEN`/`ALERT_REPO` are read by jobs in five files (`dispatch.yml`, `groom.yml`,
`metrics.yml`, `pat-validity.yml`, `review-fix.yml`), every read `|| ''`-optional. If they are
**unset**, nothing happens. If either is set **at repo scope**, the migration does not move it and
M6 classifies it as an unexpected stray — but M6 runs *after* M5 has already deleted the 12
non-bootstrap repo copies (`scripts/migrate-secrets.sh:719-739`), so the main phase converges the
12, then hard-fails, and check 1 stays red until a human deletes or relocates the stray. That is
fail-closed and recoverable, but it is an avoidable mid-flight abort — hence pre-flight **S2**
below. This is [research/266](266-protected-environment-strategy.md) §5 rule 4 stated as an
operator action rather than as a policy.

## 3. The one invariant everything below rests on

Environment secrets **override** same-named repository secrets but do **not mask absent** ones. So
an `environment: dispatch-secrets`-bound job resolves the repo-scope value before the cutover and
the environment copy after it, with no edit in between. Three places in the tree already depend on
this and are the reason it is treated as established rather than assumed here:

- `set-up-account.yml:384` and `scripts/worker-live.sh:2522` — `REGISTRY_SECRETS_PAT` lives
  env-only *today* while the other 14 are still at repo scope, and env-bound jobs resolve it;
- `migrate-secrets-to-env.yml:475-479` — `reenable-writers` is deliberately env-bound *so that*
  its mint resolves in **both** states, and its comment says an unbound job there "would fail to
  mint exactly in the cleanup-succeeded case";
- `cleanup-bootstrap` (`:355-360`) mints from the environment copies the main phase just wrote.

If this invariant were false the migration could not work at all, in either direction.

(The rotation write-back is at `scripts/worker-live.sh:2522` on this tree. Both sibling records
cite `:2424` for it — that citation has drifted and the line moved; the surrounding argument in
each is unaffected.)

## 4. The runbook

### S0 — know the starting state (it is NOT a virgin tree)

Per [research/329](329-pre-migration-writer-recovery.md) §1, this tree is in the **aborted
pre-cutover** state: a `phase: quiesce` succeeded, `phase: main` then died **at the mint** (missing
App installation grants) before M1's first listing, so it mutated nothing. Reachable state: repo
scope holds all 14; `dispatch-secrets` holds none of them (plus the unrelated
`REGISTRY_SECRETS_PAT`); the four `WRITER_WORKFLOWS` (`worker.yml`, `review-fix.yml`,
`set-up-account.yml`, `pat-validity.yml` — `scripts/migrate-secrets.sh:354`) are
`disabled_manually`; the guard is red so `claim` never runs.

**Confirm this before starting** (`gh secret list -R jeswr/agent-account-registry`,
`gh secret list -R … --env dispatch-secrets`, `gh workflow list -R … --all`). If the observed state
differs, stop — the phases below assume it.

### S1 — grant the App installation the UNION of what the five mint steps request (this is what failed)

Grant these three repository permissions on the `sparq-orchestrator` installation for
`jeswr/agent-account-registry` **first**; without them a run dies at the mint again, exactly as
before. This is the union across every phase, and it is what
`migrate-secrets-to-env.yml:175-183` already documents:

| repository permission | level | why |
|---|---|---|
| Secrets | **Read and write** | the repo-scope list + DELETE (`migrate`, both cleanup jobs) |
| Environments | **Read and write** | the environment list / public-key / PUT (`migrate`) — a Secrets-only token 403s on every env-secret call |
| Actions | **Read and write** | `quiesce` runs `gh workflow disable` and `reenable-writers` runs `enable`, both Actions **write**; the migrate/cleanup gates' workflow-state reads are Actions read |

**Take the union, not `migrate`'s row.** The five `permission-*` blocks are deliberately per-phase
least privilege and no single one dominates the others:

| mint step | requests |
|---|---|
| `quiesce` (`:262-268`) | actions **write** |
| `migrate` (`:307-315`) | secrets write + environments write + actions **read** |
| `cleanup-bootstrap` (`:376-384`), `cleanup-standalone` (`:435-443`) | secrets write + environments read + actions read |
| `reenable-writers` (`:495-502`) | actions **write** + secrets read |

Actions **write** is not below Actions **read**, so an installation granted exactly `migrate`'s set
would mint `migrate` and then fail at S4's `quiesce` — the *first* dispatch in this runbook.
Granting write at each of the three covers every read in the table too, since a write level implies
read in GitHub's permission model; nothing else in the union needs a fourth permission. (Note this
does not widen any *token*: each mint still requests only its own row, and those rows are pinned by
the workflow-mint-contract assertion in `scripts/migrate-secrets.sh --self-test`. The installation
grant is the ceiling, not the token.)

### S2 — pre-flight the repo scope for names outside the closed set

List repo-scope secret **names** and diff against the 14 of §2.3. Any extra name (realistically
`ALERT_TOKEN`/`ALERT_REPO`) must be dealt with **now**, not mid-flight: either
`gh secret delete <NAME> -R jeswr/agent-account-registry` if unwanted, or move it —
`gh secret set <NAME> -R jeswr/agent-account-registry --env dispatch-secrets` then delete the repo
copy. Doing this before S4 is what keeps M6 from aborting after M5 has already deleted the 12.

### S3 — set the deployment-branch policy, and read it back

`branch_policy_verdict` (`scripts/dispatch-secrets-guard.py:165-201`) accepts **only**: a
`deployment_branch_policy` object with `custom_branch_policies` truthy and `protected_branches`
falsy, whose `branch_policies` list is exactly one entry with `"type": "branch"` *explicitly
present* and `"name"` equal to the repository default branch (`master`). Everything else — "All
branches", protected-branches mode, a tag-typed entry, an entry with the `type` key **missing**,
extra names — is a named refusal.

Two settings notes that are easy to get wrong:

- The environment very likely **already exists**. GitHub auto-creates an environment referenced by
  a workflow, with *no* deployment-branch policy — the default-allow shape check 2 exists to catch.
  So this step is usually "set the policy on the existing environment", not "create it".
- **Do not add required reviewers or a wait timer.** The guard reads `deployment_branch_policy`
  only; it does not look at protection rules. A reviewer rule would leave all 34 env-bound jobs
  parked in `waiting` while the guard reports green — a silent fleet stall behind a green tick.
  See the follow-up filed alongside this record.

**Read the policy back before continuing** —
`gh api repos/jeswr/agent-account-registry/environments/dispatch-secrets` and
`…/deployment-branch-policies` — and check it against the four conditions above by eye. §5.1
explains why this read-back is load-bearing rather than belt-and-braces.

**Why the policy goes before the values, not after.** Between the value move and the policy the
environment would admit *every* branch, so every one of the 14 would be readable by an env-bound
job at an arbitrary ref — the #101 hole in a new shape, and strictly wider than the ordering here.
Setting the policy first costs nothing: every legitimate trigger is already at the default branch
(§2.2), so nothing is starved by having it in place early.

### S4 — dispatch `phase: quiesce`, and wait for it to succeed

`gh workflow run migrate-secrets-to-env.yml -R jeswr/agent-account-registry -f phase=quiesce`, on
`master`, **as `jeswr`** — every job pins `github.ref == 'refs/heads/master' && github.actor ==
'jeswr' && github.triggering_actor == 'jeswr'` (`:246,286,354,416,470`), and every phase's first
act is an attempt gate requiring `GITHUB_RUN_ATTEMPT == 1`, so **never re-run a run; dispatch a
fresh one**.

Re-dispatch quiesce even though the writers are already `disabled_manually`: the phase is
idempotent (its Q1 comment covers the already-disabled writer, `:258-261`), it is secret-free (its
mint is Actions:write only, so it cannot read or move a secret), and it re-attests the drain — which
the next step's M0c ordering check consumes. Do **not** proceed until you have *observed* it
succeed: the whole two-run protocol exists because a run's `secrets.*` snapshot is captured at
**queue** time (`:15-19`), so the migrate run must be queued after the drain, not merely after the
dispatch.

### S5 — dispatch `phase: migrate` (one dispatch, three jobs)

`… -f phase=migrate`. This single run executes:

1. `migrate` (env-**UNBOUND** by design) — M0a/M0b/M0c gates, then copies all 14 into the
   environment and deletes the **12** non-bootstrap repo copies. It ends with `MAIN PHASE COMPLETE
   … the secrets-guard stays RED until the cleanup-bootstrap phase drains them`
   (`scripts/migrate-secrets.sh:738`). **The guard is still red here — that is expected, not a
   failure.**
2. `cleanup-bootstrap` (env-**BOUND**, `if: success() && …`) — mints from the environment copies
   and deletes the 2 repo-scope bootstrap secrets. Repo scope is now empty.
3. `reenable-writers` (env-**BOUND**, `always()`) — R0 re-lists repo scope, finds none of the 14,
   and re-enables the four writers.

**S5.2 is the point of no return, and nothing in the tree announces it.** `quiesce` and `migrate`
are env-unbound and mint from `secrets.REGISTRY_ADMIN_APP_ID/_KEY` (`:264-265`, `:310-311`), i.e.
from the **repo-scope** copies. Once `cleanup-bootstrap` deletes those, neither phase can ever mint
again — re-dispatching `quiesce` or `migrate` after a successful cleanup fails at the mint with no
recovery inside this workflow. Only the env-bound phases (`cleanup-bootstrap`, `resume`) remain
runnable. Everything that needs the main phase must therefore happen **before** S5.2, which is what
makes S2's pre-flight and S3's read-back preconditions rather than politeness.

### S6 — confirm the tick, then delete the one-shot machinery

The guard runs as `dispatch.yml::secrets-guard` (`:1111`) on every tick (`cron: '3,13,23,33,43,53
* * * *'`, `:26`). Watch the next run: the job should print `secrets-guard: repo scope holds no
secrets and the dispatch-secrets environment admits only master — exfil protections verified`
(`scripts/dispatch-secrets-guard.py:2131-2133`), `claim` should stop being skipped
(`needs: [plan, secrets-guard]`, `:1222`), and `plan-alert`'s
`needs.secrets-guard.result == 'success'` (`:1805`) should hold. Do not accept a green *run* as
evidence — issue #618 is exactly the case where the run was green and the guard job was red; read
the **job** conclusion.

Then, per the migration workflow's own header (`:5-7`): delete
`.github/workflows/migrate-secrets-to-env.yml` **and** `scripts/migrate-secrets.sh`, unenrolling
the script from `pr-gate.yml` and `worker-live.sh`'s `FULL_SELFTEST_SUITE` in the **same** PR —
`pr-gate` hard-fails on an enrolled-but-missing script. Deleting it also removes the two
`BINDING_EXCEPTIONS` entries for `quiesce`/`migrate`; leaving them behind is itself a
stale-exception refusal (`scripts/dispatch-secrets-guard.py:1816`), so they go in the same PR.

## 5. Failure modes this sequence can land in

### 5.1 A wrong branch policy strands the migration mid-flight

If S3's policy is set but wrong — `main` instead of `master`, protected-branches mode, a
`type`-less entry — the *unbound* phases still run (quiesce, migrate) but the *bound* ones are
refused **server-side**: `cleanup-bootstrap` never runs, so the 2 bootstrap secrets survive at repo
scope and check 1 stays red; `reenable-writers` never runs, so the four writers stay disabled. The
fleet is then down with the values already moved. Recovery is straightforward — fix the policy,
dispatch `phase: cleanup-bootstrap` standalone (`cleanup-standalone`, `:394-421`, env-bound and
designed for exactly this class of mid-cleanup recovery), then `phase: resume` — but it is an
outage window, and it is why S3 ends in a read-back rather than a click.

### 5.2 A stray repo-scope name aborts the main phase after M5

Covered in §2.3 / S2. Fail-closed, recoverable by hand, avoidable by pre-flight.

### 5.3 A failed migrate must never be "abandoned" into a dual-scope state

`phase: resume`'s R0 (`scripts/migrate-secrets.sh:908-910`) fails closed while **any** of the 14
remain at repo scope, with two distinct diagnoses (all-14 = pre-migration abort; partial =
dual-scope). Both say the same thing: re-dispatch `migrate`, then `cleanup`, and only then
`resume`. Re-enabling the writers **by hand** from either state carries the identical hazard the
refusal exists to prevent — a writer's `gh secret set --env` upsert creates an env copy that the
next migrate then overwrites from the stale repo copy and deletes. See
[research/329](329-pre-migration-writer-recovery.md) §2 for the full argument and §5 for the
invariant that would make the resume safe (not yet implemented).

### 5.4 Abandoning is not an option

[research/329](329-pre-migration-writer-recovery.md) §3.1: `repo_scope_verdict` is **total**, not a
name allowlist, so leaving the 14 at repo scope keeps the guard red on every tick and halts the
fleet permanently. Forward is the only direction.

## 6. What this runbook does not establish

Two things, stated so nobody reads more into §4 than it proves.

1. **A green guard tick does not mean every secret in the repository is protected.** The guard's
   only environment reads are `environments/dispatch-secrets` and its branch policies
   (`scripts/dispatch-secrets-guard.py:1410,2115,2120`). It never enumerates the repository's other
   environments, so a secret placed in one is invisible to it.
   [research/266](266-protected-environment-strategy.md) §6 specifies the enumerating check that
   would close this and files it; nothing here supersedes that. Completing #271 does not complete
   #266's §6.
2. **The environment's non-branch protection rules are unverified.** `branch_policy_verdict` reads
   `deployment_branch_policy` and nothing else — required reviewers, wait timers and admin-bypass
   settings are entirely outside its view, and the failure they produce (34 jobs parked in
   `waiting`) is a stall behind a *green* guard. S3 warns about it; no check enforces it. Filed as
   a follow-up.

Neither is a reason to defer the cutover. Today's repo scope is the strictly wider exposure — 14
secrets readable by any job at any ref with no binding and no branch policy at all — so the
sequence above narrows the surface monotonically. What it does not do is let anyone call the
surface *bounded*; that needs the checks in §6.

**Not verified by this record:** everything above is derived from the tree, and the one derivation
that needed executing (§2.1) was run by importing the guard's own pure functions. The full
`scripts/dispatch-secrets-guard.py --self-test` could **not** be run here — the container has no
PyYAML and the script refuses to fall back to a line parser (`:286`) — so the checks that need YAML
parsing are cited from their code, not from a passing run. No live GitHub API state was observed
(no network, no token): the current repo-scope / environment / writer-enabled state is taken from
[research/329](329-pre-migration-writer-recovery.md) §1 and **must be re-confirmed at S0** before
anyone acts on §4.

## 7. Decision

#271's ask is a sequencing document, and §4 is it. Its step (2) — "add environment bindings to
every secret-bearing job" — is **already satisfied and pinned**, so the coordinated change is
narrower than the issue assumes: grant the App installation (S1), pre-flight the repo scope (S2),
set and read back the branch policy (S3), then two dispatches (S4, S5) and a confirmation (S6).
The three premises corrected in §2 do not change that conclusion, but two of them change the
*procedure*: §2.2 makes the policy's exact name list load-bearing for worker/review-fix dispatch,
and §2.3 adds the S2 pre-flight that #271's secret list would have skipped.
