# A private diagnostic sink for `account-whoami` / `fingerprint-accounts` (issue #370)

> 🤖 **SPARQ agent** — design record, 2026-07-31. Maintainer-review document.
> **This record changes no behaviour.** #370 asks for a *thing to be built* (a private sink repo);
> before building it, this answers what the sink would have to acquire to work, and finds that the
> shape #370 proposes — move the workflows to a second repo — acquires a **second, unaudited,
> silently-staling copy of the whole account fleet's credentials** (§4). It proposes a different
> split that keeps the tokens where they are, and states the checks either shape owes first (§7).

## 1. The ask, and the state it lands in

#183 disabled both identity diagnostics on this PUBLIC registry with a job-level guard:

```yaml
if: ${{ github.event.repository.private == true }}
```

`account-whoami.yml:28` and `fingerprint-accounts.yml:28`. Those are the **only two** repo-privacy
guards in the tree — nothing else in `.github/workflows/` or `scripts/` tests repository
visibility. Both jobs are `workflow_dispatch`-only, singleton-concurrent, and bound to the
`dispatch-secrets` environment.

The rationale is stated in the guards themselves and is correct as far as it goes
(`fingerprint-accounts.yml:22-27`):

> fingerprinting EVERY ACCTNN_TOKEN — even as salted hashes — writes a stable per-account
> identifier for the whole fleet into a world-readable Actions log, fully enumerating it. Such
> diagnostics belong in a PRIVATE sink, never here.

The README already treats these as an operational surface, not a catalog one (`README.md:12`):
"the identity diagnostics — names an account by its salted fingerprint instead". So #183 did not
retire the diagnostics; it parked them. #370 is the un-parking.

**What the diagnostics are for.** `fingerprint-accounts` exists because a setup-token cannot
introspect its own email (403 on `/api/oauth/profile`, `fingerprint-accounts.yml:1-3`), so the only
handle→identity evidence available is the account's Anthropic **7d rate-limit reset timestamp**,
which is stable per account. `account-whoami` is the single-slot version for `ACCT02_TOKEN`. Both
are genuinely useful and neither has a replacement anywhere in the tree.

## 2. What the guard does today, and the failure mode it hides

The guard's polarity is fail-closed by construction: a missing or false `private` field yields a
false condition and the job is skipped. That is the right polarity. But the **skip is silent** —
a maintainer who dispatches `account-whoami` on this public registry gets a green run with a
skipped job and no output whatsoever, which is indistinguishable from a probe that ran and found
nothing. There is no `::warning::` and no explanatory step; #183 traded a leak for a lie.

This matters for #370 specifically, because the sink inherits the same guard. If the guard ever
evaluates false in the sink — for any reason, including the trigger question in §7.1 — the sink
degrades to exactly the state #370 was opened to fix, and does it invisibly. **Any sink must assert
its own privacy positively and fail loudly, not skip quietly.**

Note the repo already holds the stronger pattern one layer up. `scripts/pat-validity.py:534`
`_confirmed_private()` refuses to trust configuration and requires a live
`GET /repos/{repo}` returning a literal boolean `true`:

> True ONLY on a definitive `"private": true` … anything but a literal boolean true reads as NOT
> private — the caller then redacts.

with the reasoning at `pat-validity.py:67-68`: "configuration alone" is not enough. The #183 guard
trusts an event-payload field instead. For a repo's own visibility that field is authoritative
(GitHub mints it), so this is not a soundness gap — but the *availability* of the field is a real
question (§7.1), and the loud-failure discipline of `_confirmed_private` is the one to copy.

## 3. What a sink would have to acquire

For the probes to produce a usable answer, the sink needs four things. Only the first is obvious,
and the fourth is the one that turns out to matter most.

| # | dependency | where it lives today | portable? |
|---|---|---|---|
| 1 | every `ACCT[A-Z0-9]+_TOKEN` | `dispatch-secrets` env, this repo | copyable, **stales** — §4 |
| 2 | `PROVENANCE_SALT` | same | copyable; hashes stay reconcilable — §5 |
| 3 | the handle→email map | `ACCOUNT_EMAIL_MAP` secret + a maintainer gist | copyable |
| 4 | a cadence + a place to put the answer | **does not exist anywhere** | — |

**On (2):** `account_hash` is `sha256(handle + ':' + salt)[:16]` (`scripts/worker-pr.py:447-454`,
duplicated identically at `scripts/model-health.py:409-416` and inlined in both workflows'
shell at `account-whoami.yml:71` / `fingerprint-accounts.yml:80`). It is a pure function of
`(value, salt)` with nothing repo-specific in it, so a sink given the same `PROVENANCE_SALT`
produces hashes that reconcile against every `impl_account_h` minted here. Cross-repo hash
compatibility is therefore a non-problem — *provided the salt is genuinely the same value*, and
there is **no salt-rotation mechanism or documented rotation policy anywhere in the tree**, so
"the same value" is currently guaranteed only by the absence of rotation. That is a fragile
guarantee to build a second repo on top of, but it is not a blocker today.

**On (3) — the finding that reframes the issue.** `ACCOUNT_EMAIL_MAP` was migrated into
`dispatch-secrets` as one of the 14 (`scripts/migrate-secrets.sh`, `migrate-secrets-to-env.yml`),
and it has **zero runtime consumers**. A tree-wide search finds it in exactly three places, all
migration machinery:

```
scripts/migrate-secrets.sh                       (3 hits — the migration name list)
.github/workflows/migrate-secrets-to-env.yml     (1 hit — the copy step)
research/271-coordinated-secret-migration-runbook.md (2 hits — prose)
```

No script reads it. So the join that turns a `7d_reset_hash` into "this is acct04" is today an
**entirely manual, offline step** performed in the maintainer's head against a gist — which is
precisely why the hashing exists in the first place, and precisely what is tedious about these
diagnostics even when they do run.

That reframes #370. The value of a private sink is **not** "the guard evaluates true". It is that
in a private context the probe can join against `ACCOUNT_EMAIL_MAP` and print the *answer* —
`ACCT04_TOKEN -> alice@example.com` — instead of a hash the maintainer must reconcile by hand.
A sink that merely relocates the existing hash-emitting probes reproduces the manual join in a
new repo and captures none of that value. **If a sink is stood up, the automated join is the
feature; the relocation is the enabling detail.**

## 4. The decisive constraint: a sink's token copies go stale, silently

This is the finding that should drive the shape.

Account credentials are written back to secrets by the enrollment and rotation writers, and every
write-back is scoped to **this repository**. `set-up-account.yml:752`:

```
GH_TOKEN="$REGISTRY_PAT" gh secret set "$SECRET_NAME" -R "${{ github.repository }}" --env dispatch-secrets < "$LOGIN_DIR/token"
```

`github.repository` is `jeswr/agent-account-registry`, always. `REGISTRY_SECRETS_PAT` is scoped to
this repo by construction (`set-up-account.yml:360-389` describes the grant: repository Secrets
read + Environments read/write, on `${{ github.repository }}`), and `migrate-secrets-to-env.yml`
hard-codes `owner: jeswr` / `repositories: agent-account-registry` at every mint site. **There is
no cross-repo secret-write path in the tree at all.**

Consequences for a sink that holds its own `ACCT*_TOKEN` copies:

1. **Every re-enrollment and every rotation desynchronizes it.** `gh secret set` is an upsert into
   *this* repo's environment; the sink's copy is untouched and keeps the superseded value.
2. **The staleness is invisible and misreads as a finding.** A stale token returns 401, and the
   probe's own failure mode is to tolerate that (`fingerprint-accounts.yml:69`: `set +e`,
   "tolerate 401/no-header responses"). So a desynchronized sink reports a *dead account* — which
   is exactly the alarming, action-triggering result the diagnostic exists to produce. The sink
   would manufacture false positives about fleet health, and the maintainer's first instinct on
   seeing one would be to go re-enroll a perfectly healthy account.
3. **No guard covers the second copy.** `scripts/dispatch-secrets-guard.py` enforces, live on every
   dispatch tick, that the environment has a custom single-default-branch deployment policy
   (`branch_policy_verdict`, `:200-236`) and that **repo scope is empty** (`repo_scope_verdict`).
   That guard runs in `dispatch.yml` against this repo. A sink would hold ten-plus live account
   credentials under no equivalent audit, and `pat-validity.yml`'s canary would not cover it
   either.

A second copy of the fleet's credentials that no guard audits, that silently diverges from the
authoritative copy, and whose divergence presents as a fleet incident, is a worse trade than the
log-enumeration problem #183 closed. That is not a reason to abandon #370; it is a reason to pick
a shape where the sink never holds a token.

## 5. Options

### Option A — move both workflows to a private sink repo (what #370 proposes)

Copy `account-whoami.yml` + `fingerprint-accounts.yml` into a new private repo, copy the
`ACCT*_TOKEN` set + `PROVENANCE_SALT` (+ `ACCOUNT_EMAIL_MAP`, to get §3's join), run the cadence
there. The guard evaluates true and the logs are private.

- **For:** conceptually clean; the probes need no redesign; a private log can drop the salted-hash
  contortions entirely and print raw, which is most of what makes these diagnostics awkward.
- **Against:** §4 in full — a second unaudited, silently-staling credential copy, whose staleness
  presents as a fleet incident. Also duplicates the guard/branch-policy posture with nothing
  enforcing it, and Actions minutes on a private repo are **metered**, unlike this repo (the
  README's opening sentence gives free unlimited minutes as the reason this repo is public at all).
- **Verdict:** viable only if the token-sync problem is solved first, and solving it means building
  a cross-repo secret-write path that does not exist today — a new trust-plane authority, and a
  larger piece of work than #370 reads as.

### Option B — keep the probes here; route the identity-bearing output to a verified private repo

The probe job stays in this repo, keeps reading tokens from `dispatch-secrets`, prints **nothing**
identity-bearing to the log, and POSTs the result to a positively-verified private repo — the
`ALERT_REPO` + `ALERT_TOKEN` mechanism this repo already runs under locked decision 22c, with
`pat-validity.py`'s `_confirmed_private()` (`:534`) as the gate.

This is not speculative plumbing: it is the repo's established pattern for exactly this class of
payload. `pat-validity.yml:82-89` already routes "diagnostic detail + calendar expiry" this way,
and `dispatch.yml:2203` routes a "per-account alert body [that] enumerates" accounts the same way.
`ALERT_TOKEN` is the one credential in the tree that is already cross-repo.

- **For:** tokens never leave the audited environment — no second copy, no staleness, no new
  cross-repo secret-write authority. Reuses a mechanism with existing self-tests and an existing
  fail-closed redaction path. Runs on free minutes. The private destination can hold the
  `ACCOUNT_EMAIL_MAP` join in its body, so §3's value is captured.
- **Against:** the probe still *executes* in a public repo, so run metadata (that it ran, when,
  duration, exit status) stays public — a weaker but real signal than the fingerprints themselves.
  Requires the probes to be rewritten to emit to a route rather than to stdout, which is a real
  change to two security-sensitive workflows, and `_confirmed_private` currently lives inside
  `pat-validity.py` rather than in a shared module (the `_alert_route` duplication is already
  tracked as issue #591 / PR #590).
- **Verdict:** the strongest shape available today, and the one that needs no new authority.

### Option C — retire the probes and derive identity from what is already recorded

Rejected, but worth recording so it is not re-proposed. The provenance corpus already carries
`impl_account_h` per PR and `data/model-health.json` is keyed by account hash, so *some* identity
signal exists without probing. But neither answers the question these diagnostics answer: which
**secret slot** holds which **account**. Provenance records the handle the orchestrator *believed*
it used; the probe measures what the credential *actually is*. Those diverge exactly when a slot
has been misfiled — the failure the probe exists to catch. Deriving from records cannot detect a
mislabeled record.

Relatedly, the probe enumerates the **secret set** (`^ACCT[A-Z0-9]+_TOKEN$`,
`fingerprint-accounts.yml:84`), not the live pool. `policy/repos.toml:97,142` carries 8 handles
(`acct03`/`acct06` retired 2026-07-25) while the migration list carries 10 `ACCT*_TOKEN` names.
Whether the two retired secrets still exist is not knowable from the tree — and *that gap is itself
a reason to keep the probe*: it is the only thing that can find an orphaned live credential for a
retired account. No record-derived approach sees that.

## 6. Recommendation

**Pursue Option B, and treat #370's "create/host that private sink" as the destination for a
routed payload rather than as a home for the workflows.**

The reasoning is one line: §4 shows the sink's hard problem is not the log, it is the tokens, and
Option B is the only shape that does not move them. Everything #183 objected to — a stable
per-account fingerprint in a world-readable log — is closed by Option B just as completely as by
Option A, because the fingerprints stop being printed at all.

**Do not treat this as approved.** This record is one agent's reading of the tree and the change it
implies touches two secret-reading workflows and the alert-routing trust boundary. It has had no
security review, and §7 lists checks that must pass before any of it is implemented. If the
maintainer prefers Option A, §7.3 is the precondition and it is a substantial piece of work, not a
detail.

## 7. What either shape owes before implementation

**7.1 — Verify the guard field is populated under the intended trigger.** #370 says "move the probe
cadence there", and a cadence implies `schedule:`. Both workflows are `workflow_dispatch`-only
today, and `github.event.repository` is populated for that trigger. Whether it is populated for
`schedule` is **not established by anything in this tree** — no scheduled workflow here references
`github.event.repository` — and I have not verified it against GitHub's payload documentation.
Because the polarity is fail-closed (§2), an absent field yields a silently skipped job. Verify
before relying on it, and regardless of the answer, replace the silent skip with a positive
assertion that fails loudly.

**7.2 — Decide what a private destination should print.** The salted-hash convention exists solely
because the log is public. On a private route the hashing is pure friction and blocks the
`ACCOUNT_EMAIL_MAP` join (§3). But raw output makes the destination's own compromise materially
worse, and it puts PII somewhere new — which is a decision against `README.md:4-7` and locked
decision 22/22a and belongs to the maintainer, not to an implementer.

**7.3 — If Option A: solve token sync first, explicitly.** No cross-repo secret-write path exists
(§4). Either build one — a new authority, needing its own design record and its own guard, since
`dispatch-secrets-guard.py` would not cover the second repo — or accept documented staleness and
add a liveness check that distinguishes "this account is dead" from "this sink's copy is stale".
Shipping Option A without one of those two ships §4.2's false-positive generator.

**7.4 — Confirm salt stability is an intentional guarantee.** §3 notes hash reconcilability rests
on `PROVENANCE_SALT` never rotating, which is currently true only because no rotation mechanism
exists. If rotation is ever wanted, every stored `impl_account_h` breaks too — a much larger blast
radius than #370. Worth knowing which side of that the maintainer intends before a second consumer
of the salt is created.

## 8. What this record does not decide

It does not name the sink repo, choose between a new private repo and the existing `ALERT_REPO`
destination, or specify the routed payload's schema. It does not propose re-enabling either
workflow on this public registry under any condition — #183's guard should stay exactly as it is
until a chosen shape lands. It does not audit the `dispatch-secrets` posture (that is
`research/266-protected-environment-strategy.md`), and it makes no claim that the existing
salted-hash convention is sufficient protection for a public log — only that #183 judged it
insufficient and this record does not revisit that judgement.
