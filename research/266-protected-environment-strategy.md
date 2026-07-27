# #266: the repo-wide protected-environment strategy for the #101 secret migration

> 🤖 **SPARQ agent** — design record, 2026-07-27. Maintainer-review document.
> **This record changes no behaviour.** It answers the question #266 asks — *shared protected
> environment, or per-workflow environments?* — before the #101 cutover moves any value, so the
> migration cannot regress the account fleet. It also re-measures #266's stated premise, which
> turns out to be **already retired**, and states the one gap that keeps the chosen strategy from
> being a closed trust boundary — together with the check that must land to close it (§6).

## 1. The ask, and the state it lands in

#266: `ACCT*_TOKEN` and the other secrets are read by many workflows — `dashboard.yml` and
`fingerprint-accounts.yml` materialize `toJSON(secrets)`, `account-whoami.yml` reads
`ACCT02_TOKEN`, `worker.yml` launches account-scoped runs — so "migrating account tokens into a
dispatch-only environment would break those workflows". Decide the strategy first.

The tree state this lands in is the **aborted pre-cutover** state recorded in
[`research/329-pre-migration-writer-recovery.md`](329-pre-migration-writer-recovery.md) §1:
`--phase quiesce` succeeded, `--phase main` failed at the mint before its first listing, so all
14 `SECRET_NAMES` (`scripts/migrate-secrets.sh:341-351`) are still at **repo scope**, the
`dispatch-secrets` environment holds none of them, and the four `WRITER_WORKFLOWS` are
`disabled_manually`. The value cutover has therefore genuinely **not** happened yet, and #266 is
timely rather than retrospective.

## 2. The premise, re-measured: the consumers are already bound

The binding half of the strategy landed **ahead of** the value migration. Derived from the tree
with the guard's own parser (`secret_consuming_jobs`, `scripts/dispatch-secrets-guard.py:1780`):

| | count |
|---|---|
| workflow files holding a secret-consuming job | 15 |
| secret-consuming **jobs** | 36 |
| carrying `environment: dispatch-secrets` | **33** |
| deliberately unbound (`BINDING_EXCEPTIONS`, `:1691`) | 3 |

The three exceptions are `dispatch.yml::secrets-guard` (its unbound `toJSON(secrets)` read *is*
guard check 1) and `migrate-secrets-to-env.yml::quiesce` / `::migrate` (they must read the
repo-scope originals to copy them). Every other consumer — including all four the issue names —
is bound today:

| consumer #266 names | job | binding |
|---|---|---|
| `dashboard.yml` (`toJSON(secrets)`) | `probe` | `dispatch-secrets` (`:151`) |
| `fingerprint-accounts.yml` (`toJSON(secrets)`) | `fingerprint` | `dispatch-secrets` (`:33`) |
| `account-whoami.yml` (`ACCT02_TOKEN`) | `whoami` | `dispatch-secrets` (`:33`) |
| `worker.yml` (account-scoped run) | `worker` | `dispatch-secrets` (`:628`) |

`binding_map_verdict` is **green** on this tree.

**So the cutover moves VALUES, not consumers.** The reason a bound job works on *both* sides of
it is a GitHub semantic already relied on elsewhere in this repo (research/329 §2 point 2):
environment secrets **override** same-named repository secrets, but do **not mask absent** ones.
Pre-cutover a bound job reads the repo-scope value; post-cutover the same expression resolves the
environment copy; no workflow edit sits between the two. `set-up-account.yml:384` and
`scripts/worker-live.sh:2424` already depend on this — `REGISTRY_SECRETS_PAT` lives env-only
*today*, and env-bound jobs resolve it while the other 14 are still at repo scope.

#266's "migrating would break those workflows" is therefore **already false**, and the migration's
own M4 (`scripts/migrate-secrets.sh:115`) tolerates extra env names, so the pre-existing env-only
PAT does not obstruct it either. That is the load-bearing finding: nothing has to change in any
workflow for the cutover to be safe for the fleet.

## 3. Option A — one shared protected environment (`dispatch-secrets`)

This is the shipped shape. Its guarantees, all fail-closed and all already pinned:

1. **Repo scope empty, totally.** `repo_scope_verdict` (`:157`) is not a name allowlist — the
   unbound job's context must hold nothing but the ephemeral `github_token`. The stripped-binding
   exfil copy therefore yields nothing.
2. **One branch policy to get right.** Check 2 (`branch_policy_verdict`, `:165`) requires
   `dispatch-secrets` to carry a custom, explicitly `branch`-typed deployment-branch policy naming
   exactly the default branch. A kept-binding copy at any other ref is refused server-side.
3. **One binding target.** `binding_map_verdict` (`:1798`) requires `environment == dispatch-secrets`
   **exactly** for every derived consumer — a job bound to any *other* environment is a refusal,
   not a pass. The shared-environment choice is thus not merely conventional; it is pinned.
4. **One write target.** `secret_env_write_verdict` (`:2042`) statically pins the two env-scoped
   writes — `set-up-account.yml`'s enrolment store and `worker-live.sh:2424`'s rotation
   write-back — to `--env dispatch-secrets`, comment-stripped so prose cannot stand in as evidence.

Its cost is real and should be stated plainly: **no least privilege inside the environment.** Of
the 33 bound jobs, only 6 read an account credential at all (`account-whoami::whoami`,
`dashboard::probe`, `dispatch::claim`, `fingerprint-accounts::fingerprint`, `review-fix::run`,
`worker::worker`); the other 27 can read all 10 `ACCT*_TOKEN` values they never use.

## 4. Option B — per-workflow environments holding each subset

Rejected. Four constraints, in descending weight:

1. **`toJSON(secrets)` defeats most of the benefit.** A job binds to at most **one** environment,
   and the three biggest readers (`dispatch::claim`, `dashboard::probe`,
   `fingerprint-accounts::fingerprint`) read the *whole* context — their blast radius is "every
   secret in my environment" by construction, whatever the partition. What actually bounds them
   is orthogonal to environments and already ships: the separate materialization step whose
   `^ACCT[A-Z0-9]+_TOKEN$` filter hands the probe only the account subset, plus the parse check
   that a truncated or empty-valued subset fails closed (`dashboard.yml:178-290`,
   `dispatch.yml:1389-1497`, `fingerprint-accounts.yml:39-84`).
2. **Shared secrets must be duplicated, which multiplies the rotation surface.**
   `REGISTRY_ADMIN_APP_ID`/`_KEY` are read by 20 jobs across 11 files and `PROVENANCE_SALT` by 14
   jobs across 9 — so subsetting means the same value in ~11 environments. The rotation write-back
   is a single upsert (`worker-live.sh:2424`); against N copies it becomes a fan-out where a
   partial write strands consumers on the pre-rotation credential **silently**, because a stale
   token still authenticates until the provider expires it.
3. **Every new environment is a new default-allow hole.** GitHub **auto-creates** a referenced
   environment with *no* deployment-branch policy — the exact failure mode check 2 exists for —
   and it does so at first run, quietly. One environment means one policy to verify; N means N,
   and the first one missed reopens #101 at that subset.
4. **It widens `set-up-account.yml`'s slot union.** The enrolment store derives its slot
   allocation from four paginated listings *before* creating the irreversible `acct-claims` ref,
   one of which is the `dispatch-secrets` env secret listing (`:636-690`, pinned four ways by
   `setup_account_union_verdict`, `:1547`). With `ACCTNN_TOKEN` spread across environments, a
   listing that enumerates one of them makes an env-only token invisible and **permanently burns**
   the claimed slot.

**Verdict: Option A. One shared protected environment, referenced by every consumer.**

Adopting B later is not a config change — it is a coordinated edit to **four trust checks**
(`branch_policy_verdict` must enumerate *all* environments, `binding_map_verdict` must carry a
job→environment map that itself becomes trust surface, `secret_env_write_verdict` must prove an
all-or-nothing fan-out, and the slot union must list every environment holding `ACCTNN_TOKEN`).
All four must land together; any subset is a regression. Record that cost here so a future reader
does not treat B as cheap.

## 5. The repo-wide rules — four enforced, one not

Rules 1–4 are **enforced**: each names the check that refuses on violation. Rule 5 is **policy
only** — no check verifies it on this tree (§6), so this record does *not* establish it as an
invariant, and nothing above or below may be read as relying on it.

1. **Every secret that exists at repo scope or in `dispatch-secrets` lives in `dispatch-secrets`
   and nowhere else.** Repo scope stays empty — check 1 is total, so this binds *all* secrets at
   that scope, not just the migration's 14. It says nothing about other environments; that is
   rule 5's unenforced half.
2. **Every job that reads a secret carries `environment: dispatch-secrets`** — including a job
   reading only `toJSON(secrets)` or a dynamic `secrets[...]`. Enforced, derived, case-insensitive
   and folded-scalar-aware.
3. **A job that must be unbound needs a `BINDING_EXCEPTIONS` entry with a reason, and must carry
   no `environment:` at all** — any other binding would shadow the repo-scope originals the
   exception exists to read.
4. **A new secret is created directly in the environment** (`gh secret set <NAME> --env
   dispatch-secrets`), never at repo scope. The migration's `SECRET_NAMES` is a **closed** list;
   a secret added at repo scope outside it is not migrated by any phase and would trip check 1
   forever. Pre-cutover it is caught loudly rather than silently — M6 hard-fails on any unexpected
   repo-scope name and cleanup's C2 aborts having deleted nothing (`scripts/migrate-secrets.sh:125,152`)
   — and the remediation is direct admin deletion, not a migration rerun (C4 runbook, `:164`).
   The maintainer-settable `ALERT_REPO`/`ALERT_TOKEN` (read by 10 jobs across 5 files, each
   `|| ''`-optional) are the live instance of this rule: if ever set, they go in the environment.
5. **No second secret-bearing environment — POLICY, NOT ENFORCED.** `github-pages`
   (`dashboard.yml:419`) is a deployment environment with no secret reads and is unaffected. But
   nothing enumerates the repository's environments, so a violation of this rule is **invisible,
   not refused**. Stated here only as the intent §6's check must enforce; until that check lands it
   carries no more weight than a comment, and §6 governs.

## 6. What keeps this rule set open, and the check that closes it

Checks 1–4 prove the repo scope is empty and that **`dispatch-secrets`** is branch-protected. They
do **not** enumerate the repository's other environments — the guard's only environment reads are
`environments/dispatch-secrets` and its deployment-branch policies
(`scripts/dispatch-secrets-guard.py:1410,2115,2120`). A secret placed in some other environment is
therefore invisible to the guard: the binding-map scan reads the **default-branch** checkout, so a
consumer job bound to that environment in a modified copy dispatched at an attacker-controlled ref
is never scanned, and that environment has no verified branch policy. No other environment is known
to hold secrets today and rule 5 forbids it — but nothing *verifies* it. That is exactly the
default-allow shape check 2 exists to eliminate, so this record **does not claim the rule set is a
closed trust boundary**, and rule 5 is marked unenforced rather than asserted.

**Completion precondition.** #266's *decision* — Option A, §§3–4 — stands on its own: it turns on
`toJSON(secrets)`, rotation fan-out, auto-created environments and the slot union, none of which
depend on rule 5. What remains **blocked** is the stronger claim rule 5 would license — "every
secret in this repository is behind a verified default-branch-only policy". Nothing may cite this
record for that claim, and #266's strategy is complete only when a guard check lands that:

1. paginates `repos/{repo}/environments` to exhaustion, comparing the returned count against
   `total_count` and **failing closed** on any unreadable, error or short/truncated response —
   an incomplete listing must never read as "no other environments";
2. enumerates `environments/{name}/secrets` for **every** environment returned, under the same
   pagination and fail-closed rules;
3. **refuses** if any environment other than `dispatch-secrets` holds ≥1 secret, naming it; and
4. carries non-vacuous `--self-test` coverage of both directions — the accept path, plus a refusal
   fixture for an alternate environment holding a secret and a refusal fixture for a
   failed/truncated environment listing.

Only the enumerating read is idempotent, so it is the sole part eligible for `scripts/gh_retry.py`.

**Sequencing.** This check is a precondition on the *claim*, not a gate on the #101 value cutover.
Today's repo scope is the strictly wider exposure — 14 secrets readable by any job at any ref with
no binding and no branch policy at all — so deferring the cutover until the check lands would hold
that wider hole open longer, not shorter. The cutover narrows the surface monotonically; the check
is what lets anyone say the surface is *bounded*. It is filed as a follow-up issue on this repo
rather than folded in here, because this record changes no behaviour.
