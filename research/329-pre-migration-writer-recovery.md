# #329: in-workflow writer recovery from the pre-migration abort

> 🤖 **SPARQ agent** — design record, 2026-07-27. Maintainer-review document.
> **This record changes no behaviour.** It resolves the open question left by PR #789
> (follow-up #806): whether the named refusal shipped for #329 is the terminal answer, or
> whether a mechanism exists that makes a pre-migration writer resume *safe*. The verdict is
> that the refusal is **not** terminal — a sound mechanism exists — and this record specifies
> it, its soundness argument, its false-positive class, and the composed self-test that must
> prove it, so the implementing PR is mechanical. It also records why the two obvious
> alternatives (ABANDON, writer-side scope-aware write-back) are **not** available.

## 1. The state and the ask

`--phase quiesce` succeeded: the four writer workflows (`worker.yml`, `review-fix.yml`,
`set-up-account.yml`, `pat-validity.yml` — `WRITER_WORKFLOWS`, `scripts/migrate-secrets.sh:337`)
are `disabled_manually` and drained. `--phase main` then failed at the **mint**, before M1's
first listing — missing App installation grants — so it performed zero mutations. The reachable
state is therefore:

| scope | holds |
|---|---|
| repo | all 14 (`SECRET_NAMES`) |
| `dispatch-secrets` env | none of the 14 (plus the unrelated `REGISTRY_SECRETS_PAT`) |
| writers | all four disabled |

#329's ask: **get the writers back without completing the migration.**

`phase resume`'s R0 (`assert_repo_scope_clear_for_resume`, `scripts/migrate-secrets.sh:834`)
refuses: it requires the repo scope to hold **none** of the 14. In this state it holds all 14,
so resume fails closed before any `gh workflow enable` argv.

## 2. Why the shipped answer is a refusal

PR #789 first proposed accepting this shape at R0, on the premise that *the environment holds
none of the 14, so there is no env copy for a writer to rotate*. Review round 1 refuted it and
the accept was withdrawn. The refutation, restated precisely against the code:

1. The rotation write-back is an **upsert into the environment**, not an update of an existing
   env copy — `scripts/worker-live.sh:2424`:
   `gh secret set "$secret_ref" --repo "$registry_repo" --env dispatch-secrets < "$durable"`.
   `secret_ref` is `${ACCTNN}_TOKEN`, i.e. one of the 12 non-bootstrap names. There being no env
   copy today does not stop a writer; it makes the writer **create** one.
2. The write-back's credential, `REGISTRY_SECRETS_PAT`, lives **only** in the environment
   (`set-up-account.yml:384` — "a repo-scope copy would re-trip the secrets-guard"), and the
   worker job is `environment: dispatch-secrets`-bound, so the PAT resolves pre-migration too.
   Environment secrets *override* same-named repository secrets but do not *mask* absent ones,
   so a pre-migration env-bound job reads repo V1 fine and writes env V2. The hazard is live,
   not theoretical.
3. The result is env `<name>`=V2 beside a surviving repo `<name>`=V1 — the **env-newer /
   repo-stale** pair. The next migrate's M2/M3 apply *repo-presence-is-authoritative*
   (`scripts/migrate-secrets.sh:610-640`): a repo-present name is **always** overwritten into
   the environment from `S_<name>` (which the env-UNBOUND job resolved from that repo copy),
   and M5 then deletes the repo copy. V2 is destroyed with every gate green.
4. The structural point, and the one that kills the R0-only fix: **an emptiness check at R0 is
   only true at the instant it is taken; the enables it authorises outlive it.** R0 cannot be
   the safety barrier for a hazard that materialises minutes-to-days later.

What shipped is the *named refusal*: R0 still fails closed, the all-14-present shape gets its
own diagnosis, the `gh secret set --env` upsert is spelled out, the safe recovery is stated, and
the by-hand `gh workflow enable` is marked as carrying the identical hazard. That is correct and
must stay until §5 lands. It is not, however, an answer to #329.

## 3. Constraint survey — what the trust plane already pins

Two of the four candidate mechanisms die here, before any design work.

### 3.1 ABANDON is not available: the dispatch guard requires an empty repo scope

The tempting alternative — formally call the migration off, delete the workflow and script,
re-enable the writers, let the environment fill organically as each secret rotates — is
**foreclosed by `scripts/dispatch-secrets-guard.py` check 1**.

That check is `repo_scope_verdict` (`scripts/dispatch-secrets-guard.py:155`):

```python
offending = sorted(key for key in secret_keys if key.lower() != "github_token")
return (not offending, offending)
```

It is **total, not a name allowlist** — the unbound job's `toJSON(secrets)` context must hold
*nothing* beyond the ephemeral `github_token`. Abandoning leaves all 14 at repo scope forever,
so check 1 is red on **every** tick. And since #618/#621 the guard is **gating**, not advisory:
`dispatch.yml:1004-1015` bans `continue-on-error` at job or step level, CLAIM carries
`needs: [plan, secrets-guard]` (`dispatch.yml:1115`) and plan-alert re-states
`needs.secrets-guard.result == 'success'` (`dispatch.yml:1719`).

So **ABANDON halts the entire fleet permanently** — no claims, no workers, no reviews, no fixes
— unless the guard is *also* reverted, which reopens exactly the #101 default-allow exfiltration
path the guard exists to close (a workflow copy at an attacker-controlled ref that strips the
`environment:` binding still reads every repo-scope secret). Reverting a trust check to make an
operational abort more comfortable is the inverse of the trade this repo makes everywhere else.

**Verdict: rejected. The migration is the only forward path.** Whatever answers #329 must be
compatible with the migration eventually completing.

A second-order consequence worth stating explicitly, because it changes how urgent #329 is: in
this aborted state the guard is red, so CLAIM never runs. `worker.yml` and `review-fix.yml` are
`workflow_dispatch`-only, and their normal dispatcher is that same gated CLAIM job — so the two
writers that can rotate one of the 14 are *already* unreachable through the ordinary path. What
a resume actually buys is `set-up-account` (label-triggered enrolment) and `pat-validity` (the
weekly canary), plus manual `gh workflow run` of the other two by an actor with `actions:write`.

That is **not** a safety argument and must not be used as one — it is "safe because a different
gate is red", which is default-allow-shaped and evaporates the moment anyone dispatches
`worker.yml` by hand. It is recorded only to size the benefit: the resume is worth less than it
looks, which is why §5's cost ceiling matters.

### 3.2 Writer-side scope-aware write-back is pinned, and its failure mode is worse

The other obvious mechanism — make the pre-migration environment write *impossible* by teaching
the writer to write wherever the name currently lives (repo while the repo copy exists, env
after) — collides with three things:

1. **It weakens a statically pinned trust check.** `secret_env_write_verdict`
   (`scripts/dispatch-secrets-guard.py:2043`) locates every `gh secret set <arg>` invocation in
   the pinned write sites and requires each to carry `--env dispatch-secrets`; a write site it
   cannot locate is a refusal. A scope-aware write-back turns a *static, text-checkable* pin
   into a *dynamic, runtime* condition that no static check can verify. Round 19 of that guard
   exists precisely because comment prose was being counted as evidence for this pin — it has
   already been attacked once.
2. **The fail-closed direction bricks accounts.** Provider refresh tokens are one-time-use and
   the credential has already been rotated host-side by the time write-back runs
   (`scripts/worker-live.sh:2388-2391` documents this for the missing-PAT path). If the
   scope probe fails and the writer refuses to persist, the old stored token is dead and the new
   one is lost: the account is unusable until re-enrolment. The alternative — write to repo
   scope — re-trips guard check 1 and, post-migration, strands every env-bound consumer on the
   pre-rotation credential.
3. **It spreads the migration's state machine into four workflows**, each a trust surface, for
   a one-shot migration whose script header already instructs its own deletion on success.

**Verdict: rejected.** Cost and blast radius are both larger than the hazard, and it trades a
silent-loss risk for a brick risk.

## 4. The mechanism space

| # | mechanism | verdict |
|---|---|---|
| A | ABANDON phase — call the migration off, resume writers | **rejected** (§3.1): permanently halts dispatch via guard check 1 |
| B | Writer-side scope-aware write-back — make the env write impossible | **rejected** (§3.2): weakens a static pin; fail-closed direction bricks accounts |
| C | **Make the env write fail-closed-detectable by the next migrate** — M3 refuses to overwrite an env copy it can prove is newer than the repo copy | **recommended** (§5) |
| D | Status quo — the named refusal is terminal | **superseded** by C; correct and must stay until C lands |

C is the branch the follow-up itself points at ("either impossible or fail-closed-detectable by
the next migrate"), and its prerequisite is the sibling follow-up on M3's
repo-presence-is-authoritative rule.

## 5. The recommended invariant

### 5.1 The signal

Secret **values** are unreadable — that is the whole reason repo-presence is used as a proxy for
freshness. But secret **timestamps** are readable, and both listing endpoints the script already
calls return them:

- `GET /repos/{repo}/actions/secrets` → `.secrets[] | {name, created_at, updated_at}`
- `GET /repos/{repo}/environments/{env}/secrets` → same shape

`_repo_names` / `_env_names` (`scripts/migrate-secrets.sh:353-359`) currently project
`.secrets[].name`. Widening the jq to `.name + "|" + .updated_at` is a contained change to two
one-line helpers; the grants (`secrets: read`, `environments: read`) are unchanged, and the
existing `ISO_TS_RE` (`:502`) plus lexicographic `[[ a < b ]]` comparison — already load-bearing
in M0c — apply unchanged to these timestamps.

### 5.2 The threshold, and why a bare env-newer test is not enough

`env.updated_at > repo.updated_at` on its own is **ambiguous**. It has two causes:

- a **writer** created or rotated the env copy → the env value is genuinely newer → overwriting
  it destroys the newest credential (the hazard);
- a **previous migrate run's M3** copied the repo value into the env → the two values are
  *identical* → overwriting is value-preserving, and refusing would break the
  interrupted-after-partial-copy recovery path the suite already covers.

The disambiguator is already computed. M0c's `assert_quiesce_completed_before_queue`
(`scripts/migrate-secrets.sh:507`) proves that the newest quiesce/resume event preceding this
run's queue instant is a **field-attested successful quiesce** whose completion `updated_at`
(the local `newest_updated`, `:566-569`) is strictly before this run's `created_at`, and M0a/M0b
prove the writers are *still* disabled and drained. Call that completion instant **T_q**.
Between T_q and now, **no writer can have run**. Therefore:

> Any env write with `updated_at > T_q` was authored by a migrate run.
> Any env write with `updated_at <= T_q` *may* have been authored by a writer.

### 5.3 The rule

At M2 (pre-mutation, before any `gh secret set`), for every name present in **both** scopes:

```
accept  if  env.updated_at < repo.updated_at        # repo genuinely newer — the round-7 late-writer case
accept  if  env.updated_at > T_q                    # env copy is migrate-authored (writers provably quiesced)
REFUSE  otherwise                                   # env-newer AND pre-quiesce: a writer may have authored it
```

Equality falls to REFUSE on both comparisons: second-granularity timestamps cannot order a tie,
and the fail-closed side of an unorderable pair is refusal.

`T_q` must be **exported** from `assert_quiesce_completed_before_queue` (today `newest_updated`
is a function-local). That coupling is deliberate and should be asserted: the rule is unsound
without a proven quiesce ordering, so M3's refusal must be *unreachable* unless M0c ran. The
cleanest shape is a single global set only on M0c's success path, with M2 dying on an unset or
unparseable value rather than defaulting.

### 5.4 What the refusal says, and how the operator repairs it

The refusal must name the specific secret and the specific repair. The repair is short and
safe: **the env copy is the newest value, so delete the stale repo copy** —
`gh secret delete <NAME> -R <owner>/<repo>` — after which M1 sees repo-absent + env-present,
which is the genuine resume path M2 already accepts with no value required, M3 skips, and M5 has
nothing to delete. The migration then converges on its own.

The script must **not** auto-delete. That would be an M5-shaped deletion without the M3 copy
that normally justifies it, resting entirely on the timestamp inference being right. Refuse and
name the repair; let a human hold the irreversible step.

### 5.5 Soundness, and the known false-positive class

The hazard scenario is prevented. Writer rotates env `<name>` to V2 at T_w while enabled; the
repo copy still carries V1 written at T_r < T_w. To migrate, the operator must run quiesce,
which completes at some T_q > T_w. At the next migrate: `env.updated_at = T_w`,
`repo.updated_at = T_r`, so `env > repo` (first accept fails) and `T_w <= T_q` (second accept
fails) → **REFUSE**. The newer credential is not overwritten. This is exactly the acceptance
condition of #806.

The false-positive class is a migrate-authored env copy that predates the last quiesce — i.e.
migrate copies at T_c, someone re-enables the writers, a fresh quiesce completes at T_q > T_c,
and the next migrate now sees `env(T_c) > repo`, `T_c <= T_q` → refuse, though the values are
identical. Reaching it requires the writers to have been re-enabled while the repo copy still
existed, which R0 refuses through the workflow — so it needs an out-of-band `gh workflow enable`,
the actor class M0a already documents as an accepted residual. When it does fire it fails
**closed**, names the secret, and its repair (delete the stale repo copy) is still correct,
because at that point env and repo hold the same value.

### 5.6 Sequencing — and why the R0 relaxation is unsound on its own

Two steps, strictly ordered:

1. **M3 invariant first** (§5.3), on its own, changing no R0 behaviour. It is a pure
   strengthening: it can only turn a silent overwrite into a named refusal.
2. **Only then** relax R0 to accept the pre-migration shape — repo holds names, **env holds none
   of the 14** — in addition to today's clean-cutover shape.

Shipping 2 without 1 reintroduces the exact defect review round 1 blocked. The structural
answer to that blocker is that after step 1, R0's check is **no longer the safety barrier** —
the durable, downstream M3 refusal is. R0's emptiness test degrades to a runbook check ("are you
in the pre-migration state?"), and the objection that it "is only true at the instant it is
taken" stops mattering, because the enables it authorises are now covered by an invariant that
is re-evaluated at the moment of danger.

R0 should keep refusing the middle shape — env holds **some** of the 14 — even though step 1
makes it safe. That is a partial cutover, and the runbook answer there is "re-dispatch migrate",
never "resume".

## 6. The composed self-test that must ship with step 2

Step 1 needs its own scenarios (env-newer-pre-quiesce refuses; env-newer-post-T_q converges — the
existing interrupted-after-partial-copy path must stay green; repo-newer converges — the existing
round-7 late-writer V1/V2 path must stay green; tie refuses; unset/unparseable `T_q` refuses).
Step 2 needs the **composed** one #806 asks for, end to end in a single scenario:

1. **Seed the pre-migration accept state.** Repo holds all 14 at `T_r`; env holds none of them
   (only `REGISTRY_SECRETS_PAT`); the four writers `disabled_manually`; a field-attested
   successful quiesce in the run history.
2. **Resume.** `--phase resume-writers` must now **accept** — rc 0, exactly 4
   `workflow enable` argv, zero secret mutations.
3. **Representative writer rotation.** Drive the fake `gh` the way `worker-live.sh`'s write-back
   does: `secret set ACCT02_TOKEN --repo o/r --env dispatch-secrets` with value V2 at
   `T_w > T_r`. The fake's per-scope value model (`env_values` / `repo_values`) already makes a
   freshness regression show up as real value loss; it must now also carry per-secret
   `updated_at`.
4. **Re-quiesce**, completing at `T_q > T_w`.
5. **Next migrate must REFUSE.** rc 1; **zero** mutations; `env ACCT02_TOKEN` still V2; repo
   `ACCT02_TOKEN` still V1; the refusal names `ACCT02_TOKEN` and the
   `gh secret delete` repair.
6. **The repair converges.** Delete repo `ACCT02_TOKEN`; re-run migrate; it must succeed with
   `ACCT02_TOKEN` **still V2** in the environment (never overwritten by V1) and every other name
   copied and drained normally.

**Mutation checks — the scenario is vacuous without them.** Each of these must turn the
composed scenario **red**, with the harness showing V2 being destroyed:

- invert the `env.updated_at < repo.updated_at` comparison;
- drop the `T_q` threshold, leaving a bare env-newer test (this must instead turn the
  *interrupted-after-partial-copy* scenario red — it proves the threshold is load-bearing in
  both directions);
- remove the M2 refusal call entirely (rc 0, mutations issued, V2 destroyed);
- let an unset `T_q` default to accept rather than die.

Step 6 is what distinguishes this from a pure refusal test: it proves the invariant leaves a
**convergent** system, not a new brick.

## 7. Decision

**The refusal is not the terminal answer.** Mechanism C is sound, is confined to
`scripts/migrate-secrets.sh` and its hermetic self-test, changes no writer workflow, weakens no
pinned trust check, and converts the silent newest-credential loss into a named, repairable,
fail-closed refusal. ABANDON (A) is foreclosed by the dispatch guard's total empty-repo-scope
assertion; writer-side scope-awareness (B) costs more than the hazard and trades silent loss for
bricked accounts.

Until step 1 lands, the shipped named refusal stays exactly as it is — it is the correct
behaviour for a system that has no way to detect the hazard downstream.

## 8. What this record does not do, and open verification

- It ships **no behaviour change**. Step 1 belongs to the sibling M3 follow-up; step 2 is filed
  separately and is blocked on it.
- **Verify before implementing:** that both secrets endpoints return `updated_at` on the App
  token's `secrets: read` / `environments: read` grants, and that an idempotent
  same-value upsert does bump `updated_at`. Both are assumed here from the documented REST
  shapes and were **not** confirmed against the live API — this record was written without
  network access. If `updated_at` turns out to be unavailable or unreliable on either endpoint,
  mechanism C dies with it and the §4 verdict must be revisited, with D (the named refusal) as
  the fallback rather than A or B.
- The residual actor class is unchanged and still accepted: an operator with `actions:write` can
  `gh workflow enable` out of band at any time. Step 1 is what makes that residual *safe* rather
  than merely *documented* — which is the real reason it is worth building even if R0 is never
  relaxed.
