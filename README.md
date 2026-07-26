# agent-account-registry (public)

The single source of truth for the model accounts (Anthropic / OpenAI) that back automated coding
workers across my codebases. This repo is **public** so its GitHub Actions run on free unlimited
minutes. **Token VALUES never live in the repo** — each account's token is an encrypted GitHub
**secret** (masked in logs, blocked from fork PRs); account **emails / PII are not published**
(redacted from issues; the private handle→email map lives only in a maintainer secret + gist).
Account handles, limits, live-usage probing, and the selection logic ARE public — they carry no
secrets. Read-only to non-collaborators; only maintainer/bot-triggered workflows touch secrets.

A worker (a GitHub Actions job in some codebase, e.g. `sparq-org/sparq`) asks this registry for an
account to use; the registry applies per-account limits, a cross-codebase concurrency lock, model
fallback chains, and prompt-cache affinity, and hands back a claim. When the worker finishes it
releases the claim.

## Registry self-test suite

`scripts/selftest-suite.txt` is the authoritative self-test manifest and is checked in both
directions against scripts that advertise a self-test entrypoint. Enroll a new self-testing script
in that manifest in the same PR. Retiring a script or manifest entry requires two PRs: first add its
filename to `scripts/selftest-retirements.txt` on the base branch, then remove the script and its
manifest entry in a later PR. The gate refuses an unapproved same-PR retirement.

## One issue per account

Each model account is a GitHub **issue** in this repo. The issue **body** is structured YAML
front-matter (no secrets):

```yaml
provider: anthropic          # anthropic | openai
harness: claude              # claude | codex
credential_format: claude-oauth-token
models: [opus5, fable, opus, sonnet, haiku]   # or [sol, luna, terra] for openai; enables model-fallback routing
tier:
  weekly_limit: "..."        # human note of the plan's weekly cap
  five_hour_limit: "..."     # the rolling 5h window cap
reset_schedule: "..."        # when the windows reset (per-account; they differ)
max_concurrent_workers: 1    # how many workers may run on this account at once
secret_ref: ACCT_<HANDLE>_TOKEN   # the NAME of the GitHub secret holding this account's token
notes: "..."
```

The **token value** for each account is stored ONLY as a secret in this repo's
**`dispatch-secrets` environment**, named by `secret_ref` — never at repository/organization
scope (issue #101: the dispatch secrets-guard fails closed while ANY repo-scope secret exists),
never in the issue body, never in a comment, never in a public repo.

## Lease-based claim / release (the cross-codebase mutex)

> A GPT-5.6 review showed that **reaction-counting cannot be a mutex** — GitHub allows only one
> reaction of a given type per identity, so many same-bot workers all see one 🚀 and all believe they
> own a slot. Replaced with a **compare-and-swap lease ledger** (`scripts/select-and-claim.py`).

A single JSON ledger `data/leases.json` records every active lease. It lives on the
dedicated **`ledger` data-plane branch** — not on `master` — so branch protection on the
code branch never rejects the bot's contents-API writes, and a token that can only write
`ledger` can never push code (issue #28; `data/README.md` on master is the tombstone):

```json
{"leases": [{"account": "acct01", "claim_id": "<uuid>", "holder": "<owner/repo@run>",
             "package": "sparq-core", "role": "impl", "model": "sol",
             "issued_at": 0, "expires_at": 0}]}
```

**Claim** = a compare-and-swap: read the file **and its blob SHA**, reclaim expired leases, and if an
eligible account (serving a model in the requested chain, under `max_concurrent_workers`,
cache-affinity-preferred) has a free slot, append a lease with a **unique `claim_id` + `expires_at`**,
then `PUT` the file with the read SHA. A concurrent writer changed the SHA → the `PUT` is rejected
(409) → retry. Because every codebase CAS-updates the **same** ledger, capacity is enforced globally
without reaction counting. **Release** and **heartbeat** are keyed by the unique `claim_id`
(idempotent). The groomer **reclaims** leases past `expires_at` (a dead/cancelled worker frees its
slot automatically — no receipt-guessing).

### The `package` partition has exactly ONE derivation

A row's `package` is the single conflict partition its lease reserves, reduced from the source
issue's `area:*` labels: **exactly one** distinct area reserves that area, **zero or multiple**
reserve the serializing `__global__` partition (fail-closed — over-serialize a multi-area row rather
than free a busy sibling crate). That reduction is `lease_schema.plan_package`, and it is the **only**
copy: `dispatch-claim.py` delegates to it and review-fix.yml's `resolve` job calls
`dispatch_claim.plan_package` — the minter's own function object. `dispatch-plan.py` ships inside the
target repos (which have no `lease_schema.py`) so it keeps a local copy, pinned by an agreement
assertion in `dispatch-claim.py --self-test`.

This matters because the value is derived **twice by design** — once by the dispatcher that mints a
CAS claim, once by the review/fix run that adopts it — and review-fix.yml's `Adopt dispatcher-owned
CAS claim` step compares the two for **equality**. When `resolve` carried its own pre-#112
alphabetically-first reduction, every PR whose source issue held two `area:*` labels had its own
dispatcher's claim rejected on every tick, forever.

### Adoption rejections are CLASSIFIED, and the deterministic class has a machine exit

A rejected adoption always releases the lease inline (never `|| true` — a swallowed release strands a
scarce account slot with no signal) and then routes on its class:

| class | cause | exit |
|---|---|---|
| `transient` | the claim is gone/unreadable (TTL, groom sweep, operator release) | defer **without failing**; the doorbell re-rings and the next tick re-dispatches |
| `infra` | a registry-side capability is missing for PR-**independent** reasons (no `PROVENANCE_SALT`; a catalog row with no provider) | retry, red — but **never park**, because the cause is fleet-wide |
| `disagreement` | a field re-derived from **this PR** contradicts the claim minted for it | release + park the PR and its source issue via `worker-pr.py needs-user` (`adopt_disagreement` job) |

`disagreement` gets a terminal rather than a retry because it is deterministic in the PR: the next
tick re-derives the identical mismatch, so retrying can never converge — it only burns another
account lease. An absent or unrecognised class reads as `disagreement` (fail **loud**), so a crash in
the validator escalates instead of joining a silent retry loop.

## Selection logic (`select-and-claim`)

`scripts/select-and-claim.py` (added in Phase 3) takes `(package, role, model-chain)` and returns an
opaque claim (which secret to use) or `none-free`:

1. Walk the **model fallback chain** (e.g. `sol → opus5 → fable`) to the first provider/model with a
   non-full, non-reset-exhausted account.
2. Among eligible accounts, prefer the one with **prompt-cache affinity** — most recently used for the
   same `package`+`role` within the provider's cache window (Anthropic prompt cache ≈ 5-min TTL), to
   keep the cache warm; avoid interleaving unrelated work onto a warm account.
3. Atomically claim it (add 🚀, then **recount** to resolve the check-then-claim race — if the recount
   exceeds the cap, back off and remove the reaction), write the receipt, return the `secret_ref`.

## Cache-affinity metadata

Which skills/roles/packages ran recently on each account is tracked **here** (as receipt comments +
a rolling `data/cache-affinity.json`), never in the public repos.

## Standing routing rules (inherited by onboarded target repos)

> 🤖 Maintainer decision (2026-07-17), recorded by a SPARQ agent.

- **UI/front-end surfaces route to the openai/codex model chain** (original-builder ownership:
  **GPT-5.6 built the registry dashboard, `e4098b9`**). Repos onboarded to the registry inherit
  this default. Machine-readable form: the `role = "site"` route (`model_chain = ["sol",
  "opus5", "fable", "opus"]` — sol-led; opus5 primary Anthropic tier since 2026-07-24;
  terra/sonnet are docs-only, 2026-07-18) in this repo's
  `orchestration/routing.toml`; when onboarding a new target
  repo in `policy/repos.toml`, mirror that route into the target's own routing table
  (`sparq-org/sparq` already carries it). `scripts/triage.py` derives `role:site` from the exact
  UI-surface labels (`area:dashboard`, `dashboard`, `surface:frontend`). Implement it as a ROLE
  route, **never** a `match_labels` rule — the arm-side security classifier unions all
  `match_labels` keywords, so UI keywords there would security-classify every UI PR (post-Decision-7 revision: an audit trail, not a park).

- **Frontier-tier agents author ALL CI/infrastructure work** (maintainer decision 2026-07-17):
  GPT-5.6 sol (openai; alias `sol`) or the Anthropic frontier tier (`opus5` primary since
  2026-07-24, `fable` as its tail fallback) — explicitly including the
  self-draining pipeline infrastructure itself (dispatch, workers, gate aggregators,
  `.github/workflows`, orchestration scripts). Cheaper tiers (sonnet/haiku) no longer author
  infra, and terra/sonnet are docs-only (2026-07-18); cross-provider review is unchanged
  (whichever provider's frontier writes, the other
  reviews). Machine-readable form: the `role = "ci"` route (`model_chain = ["sol", "opus5",
  "fable"]`)
  in this repo's `orchestration/routing.toml`; mirror a frontier-only ci chain into each
  onboarded target's routing table (`sparq-org/sparq` carries it, sparq PR #3422).
  `scripts/triage.py` derives `role:ci` from the exact infra-surface labels (`area:ci`,
  `area:workflows`). The chain is frontier-ONLY rather than floor-pinned: the routing schema has
  no floor/pin field, and chain exhaustion at the claim step already **defers** the item
  (retried next tick, defer-not-fallback) instead of degrading tier — deliberately not
  `escalate = true`, which would flip a starved item to `needs:user`. Where an infra surface is
  also a trust surface (dispatch/worker/set-up-account/review-loop/groom), the security
  `match_labels` override still wins (opus + trust-surface audit; Decision 7 revised 2026-07-18) — stricter than the frontier floor,
  unchanged.

## Adding an account — step-by-step runbook (an agent can follow this verbatim)

> Goal: make one more model account usable by the workers. There are **five** required steps; the
> account is invisible to the selector until **all five** are done (notably the `account_pool` edit —
> a common miss). Every command targets the private registry `jeswr/agent-account-registry`.
> **Never print a token value** into chat, a log, an issue, or a commit.

**Naming convention.** Handle = `acctNN` (e.g. `acct05`). Its token secret is
`ACCTNN_TOKEN` (the handle upper-cased + `_TOKEN`, e.g. `ACCT05_TOKEN`). The account issue's
`secret_ref:` field MUST equal that secret name.

**Slot claim (REQUIRED before any write).** Slot numbers are allocated through the
`refs/acct-claims/` ref namespace — the canonical allocation record that EVERY account writer
(the `set-up-account` broker and this manual runbook alike) must claim in before touching a
secret or an issue. Ref creation is first-writer-wins on the server, so exactly one writer can
ever own a number:

```bash
gh api repos/jeswr/agent-account-registry/git/refs \
  -f ref='refs/acct-claims/acct05' \
  -f sha="$(gh api repos/jeswr/agent-account-registry/commits/master --jq .sha)"
```

If this fails with `Reference already exists`, the number is taken — bump `NN` and retry. Never
delete a claim ref: a claimed-but-unused slot is merely burned (safe), while reusing a number can
silently overwrite a live credential (`gh secret set` is an upsert) or mint a duplicate issue
title (GitHub does not enforce unique titles).

### Step 0 — obtain a DURABLE, NON-ROTATING token (do NOT use a subscription blob)

- **Anthropic** (Claude models): run `claude setup-token` while logged into the target account. It
  prints a long-lived `sk-ant-oat…` token (`credential_format: claude-oauth-token`). **Do NOT** copy
  `~/.claude/.credentials.json` — that subscription blob's refresh token *rotates* and dies the moment
  the interactive session refreshes (this broke the canary once). If you prefer a Console API key,
  that also works: `credential_format: anthropic-api-key` (value is the `sk-ant-api…` key).
- **OpenAI** (codex/GPT models): the codex CLI OAuth from `~/.codex/auth.json`
  (`credential_format: codex-auth-json`). Its access token expires and its **refresh token is
  ONE-TIME-USE with server-side replay detection** (`refresh_token_reused`), so the worker refreshes
  it HOST-SIDE before the model container starts and writes the rotated credential back to the secret
  (issue #596; the container only ever sees a fresh access token, never the refresh token). Two
  operational consequences:
  - **Give the registry its OWN codex login.** Refresh chains are per-authorization, not per-account.
    If the stored secret and an interactive `~/.codex` login share one chain, whichever refreshes
    second is killed with `refresh_token_reused` — so run the device-code login once *for the
    registry* and enrol that credential rather than copying a box's live `~/.codex/auth.json`.
  - **`REGISTRY_SECRETS_PAT` must be present** for the account to self-heal indefinitely. Without it
    the write-back warns and skips, the rotated refresh token is lost, and the account needs a
    re-mint the next time its access token expires.
  - **The write-back is reachable from the pre-flight's FAILURE path.** The exchange consumes the
    one-time-use grant early inside the credential-prepare step, so the write-back step is keyed to
    `always()` plus the account selection — never to that step succeeding. Any later failure in
    prepare (the no-leak assertion, the tamper baseline, the pinned CLI install, the `$GITHUB_ENV`
    export) would otherwise discard a grant the provider had already rotated, leaving the account
    permanently unable to authenticate. `worker-prep.sh` writes the durable material, the credential
    format, and the rotation marker at the moment the rotation happens, so a write-back reached with
    no mount and no exported environment still knows what to persist and how to validate it;
    `dispatch-secrets-guard.rotation_writeback_reachable_verdict` asserts that reachability in both
    worker lanes, and the obligation is **universal, not existential**: the step's `if:` must evaluate
    TRUE on every path where a rotation may already have happened, and may reference only facts settled
    *before* the pre-flight (`always()`, the dry-run input, the claim outputs, the account selection
    step). Anything else — the prepare step's own outcome, the model step's outcome, a prepare output,
    `success()` — is refused by name. An existential "there is *some* world where it runs" check
    accepted all of those, which is how a model-step guard could have been reintroduced. Each lane's
    call site is also required to be a **reachable** command, so commenting the `run:` out is a red
    tick rather than a silently discarded grant.
  - **A grant is re-sent only when the previous attempt provably did not deliver it.**
    `_post_token_endpoint` drives the exchange through `http.client` with an explicit `connect()`, so
    the pre-send / post-send boundary is a property of the code's STRUCTURE rather than a guess from
    the exception's type (`ssl.SSLError` is an `OSError` raised from *both* the handshake and the
    response read, and urllib's `URLError` conflates connect with send — no type test can be sound in
    both directions). A fault raised strictly before the request write — malformed URL, DNS failure,
    refused connection, connect timeout, failed TLS handshake — is `STATUS_NOT_SENT` and keeps its
    bounded retry; a fault raised at or after the write — send/response timeout, reset, broken pipe, a
    TLS fault from `response.read()`, a truncated body — is `STATUS_INDETERMINATE`, classed
    `credential-remint-required`, and raises on the spot.
    The two questions are deliberately separate. `classify_refresh_failure` answers "is a LATER
    attempt worth making?", which is why 429 and 5xx stay `credential-refresh-transient`: a later
    attempt re-reads the stored secret, and a grant the provider did consume then fails closed with
    `invalid_grant`. `_RESEND_SAFE_STATUSES` answers the narrower "may THIS run POST the same grant
    again?" and admits only `STATUS_NOT_SENT` plus a documented 429 throttle. A **2xx with an unusable
    body** (truncated, unparseable, or missing `access_token`) is the strongest available evidence that
    the rotation *did* commit, so it raises instead of retrying.
  - **The remint class carries two causes, and the operator message says so.** `worker-prep.sh`'s
    `::error::` line for `credential-remint-required` must not assert the grant "is dead": the class
    covers both a provider-confirmed dead grant and an indeterminate outcome whose fate is unknown and
    which was deliberately not re-sent.
- On this work box, pre-provisioned Anthropic setup-tokens already exist as files
  `~/.claude-acctN-token` (one per account). Read the file; do not echo it.

### Step 1 — save the token as a secret (via stdin, never as a visible arg)

Secrets live in the **`dispatch-secrets` environment**, NOT at repo scope (issue #101): the
dispatch secrets-guard fails every tick closed while ANY repo-scope secret exists. If you
accidentally write one at repo scope, recover by **deleting the stray directly**
(`gh secret delete <NAME> -R jeswr/agent-account-registry`) and re-running the env-scoped
command below — **never** by re-running the migration workflow: post-cleanup it cannot mint
(the bootstrap repo copies are gone by design) and there is nothing left to migrate (see the
header of `.github/workflows/migrate-secrets-to-env.yml`).

```bash
tr -d '[:space:]' < ~/.claude-acct5-token | gh secret set ACCT05_TOKEN -R jeswr/agent-account-registry --env dispatch-secrets
# or from a value you already hold, without it hitting the shell history/ps:
#   gh secret set ACCT05_TOKEN -R jeswr/agent-account-registry --env dispatch-secrets   # then paste at the prompt
```

### Step 2 — validate the token works (and see its live usage)

```bash
TOK="$(tr -d '[:space:]' < ~/.claude-acct5-token)"
curl -s -D - -o /dev/null -X POST https://api.anthropic.com/v1/messages \
  -H "Authorization: Bearer $TOK" -H "anthropic-version: 2023-06-01" \
  -H "anthropic-beta: oauth-2025-04-20" -H "content-type: application/json" \
  -d '{"model":"claude-haiku-4-5","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}' \
  | grep -iE 'HTTP/|anthropic-ratelimit-unified-(status|5h|7d)'
```
Expect `HTTP/2 200` and `anthropic-ratelimit-unified-status: allowed`. The
`…-5h-utilization` / `…-5h-reset` / `…-7d-utilization` / `…-7d-reset` headers are the live usage +
reset timestamps used for account prioritisation (see **Usage-aware selection** below).

### Step 3 — create the account issue (the catalog entry `select-and-claim.py` reads)

`read_accounts()` parses these exact keys from the issue **body**. Title = the handle.

```bash
body='provider: anthropic
harness: claude
credential_format: claude-oauth-token
email: "<the account login email — a setup-token CANNOT introspect it (403 on /api/oauth/profile); fill from the account you logged in as>"
models: [opus5, fable, opus, sonnet, haiku]
max_concurrent_workers: 1
secret_ref: ACCT05_TOKEN
notes: "claude setup-token (long-lived, non-rotating). [your-marker]"'
printf '%s\n' "$body" | python3 scripts/select-and-claim.py \
  --validate-account-record --account-handle acct05
gh issue create -R jeswr/agent-account-registry --title "acct05" --label account --body "$body"
```
For an **OpenAI** account: `provider: openai`, `harness: codex`, `credential_format: codex-auth-json`,
`models: [sol, luna, terra]` (the FULL codex alias set — `select-and-claim.py` gates on exact alias
membership, so a `terra`-only record would defer every sol/luna claim), `secret_ref: ACCTNN_TOKEN`.

### Step 4 — label the issue (REQUIRED — no label ⇒ not `available` ⇒ never selected)

```bash
gh issue edit <ISSUE#> -R jeswr/agent-account-registry \
  --add-label account --add-label status:available --add-label provider:anthropic
```
`select-and-claim.py` sets `available = (has status:available label)`; without it the account is
silently skipped.

### Step 5 — add the handle to the repo's `account_pool` (the easy-to-forget step)

Edit `policy/repos.toml` for each target repo that should be allowed to use this account, and raise
`max_concurrent` if you want more simultaneous workers:

```toml
[repos."sparq-org/sparq"]
account_pool = ["acct01", "acct02", "acct04", "acct05"]   # add the handle from the steps above
max_concurrent = 5                                                  # optional: allow more parallelism
```

Two constraints the resolver enforces, so a pool that violates either is refused outright rather
than failing later at claim time:

- **Handles must be canonical** — exactly `acct[0-9a-z]{2,}`, no surrounding whitespace and no case
  variation. `" acct04"` and `"ACCT04"` are both rejected. (A padded handle used to pass validation
  while evading the retirement check below, and downstream `select-and-claim` strips before
  matching, so it became claimable and leaked its CAS lease to TTL.)
- **Retired handles can never reappear.** `acct03` and `acct06` are retired (accounts cancelled /
  expired 2026-07-25) and are refused by `policy-resolve.RETIRED_ACCOUNTS`. Their slot names stay
  permanently reserved — `set-up-account` counts `acctNN` issues in ANY state — so a new enrolment
  always gets a NEW handle, never a recycled one.
Commit + push to `master`. An account that is available + in the catalog but **not** in a repo's
`account_pool` will never be claimed for that repo.

### Verify

```bash
gh secret list -R jeswr/agent-account-registry --env dispatch-secrets | grep ACCT  # secret present (env scope)
gh secret list -R jeswr/agent-account-registry                        # repo scope must stay EMPTY
gh issue view <ISSUE#> -R jeswr/agent-account-registry --json labels  # status:available + provider:*
grep account_pool policy/repos.toml                                   # handle present
```

> Email note: a `claude setup-token` is inference-scoped and returns **403** on
> `https://api.anthropic.com/api/oauth/profile`, so the account email cannot be derived from the
> token — record it from the login you used. (An *interactive* subscription OAuth token *can* read
> `/api/oauth/profile`, which returns `account.email`, plan tier, and `rate_limit_tier`.)

## Usage-aware selection (rate-limit headers)

Anthropic returns live usage + reset data as **response headers on every `/v1/messages` call** (so a
`max_tokens:1` probe is enough, and it works with an inference-scoped setup-token — no separate usage
API, and `/api/oauth/profile` is 403 for setup-tokens). Key headers:

| Header | Meaning |
|---|---|
| `anthropic-ratelimit-unified-status` | `allowed` \| throttled/`rejected` — is the account usable right now |
| `anthropic-ratelimit-unified-5h-utilization` | fraction (0–1) of the rolling **5-hour** window consumed |
| `anthropic-ratelimit-unified-5h-reset` | Unix ts when the 5h window resets |
| `anthropic-ratelimit-unified-7d-utilization` | fraction of the **weekly** window consumed |
| `anthropic-ratelimit-unified-7d-reset` | Unix ts when the weekly window resets |
| `anthropic-ratelimit-unified-representative-claim` | which window is currently binding (`five_hour`/`seven_day`) |
| `anthropic-ratelimit-unified-7d_oi-utilization` / `…-7d_oi-reset` | **[FABLE]** the account's SEPARATE weekly **claude-fable-5** sub-quota — distinct from `7d`; an account can read `7d-utilization=0.1` yet have this near 1.0 |

**Fable sub-quota — a whole-account probe is not enough.** `claude-fable-5` draws from its own weekly
premium bucket, surfaced as the `…-7d_oi-*` headers. Those headers appear **only** on a probe that is
`model=claude-fable-5` **and** carries BOTH the Claude-Code `user-agent` (`claude-cli/…`) **and** the
`You are Claude Code, …` system prompt (the subscription-OAuth premium path) — a plain `haiku`/`opus`
probe never emits them (and a plain fable probe 429s). `account-usage.py` therefore does a second,
Claude-Code-shaped fable probe for fable-capable accounts and merges `fable_ok` + `fable_7d_oi_util/reset`
into the usage map; `usage_eligible(u, margin, model="fable")` then requires that bucket to have headroom
**in addition to** the whole-account 5h/7d windows. Fail-closed: a rejected/absent fable probe makes the
account ineligible for **fable** only — its base signal still admits it for non-fable models.

**Prioritisation policy** (wired into `choose_account`): among eligible accounts prefer `status=allowed`
with the **soonest whole-account `7d_reset`** (use-it-or-lose-it). Accounts without that weekly reset
sort last while retaining the existing cache-affinity/load/handle order. The Fable `7d_oi` bucket remains
an additional eligibility gate for Fable routes, but does not replace the fleet-wide drain-order signal.
**Skip** an account whose status is not `allowed` or whose utilisation leaves less than
`usage_safety_margin` headroom.

### OpenAI/codex accounts — probe-EXEMPT, reactive backoff (maintainer decision 2026-07-17)

OpenAI exposes **no API to observe a codex subscription's usage**, so `provider: openai` accounts
are **exempt from health/usage probing** by maintainer decision
([issue #29](https://github.com/jeswr/agent-account-registry/issues/29)): they are eligible
**without usage data** (`{"exempt": true}` in the usage map — the fail-closed require-usage arm
applies to anthropic accounts only) and are simply **used until a run hits a rate limit**. They
remain subject to `max_concurrent_workers` caps and leases, plus a **reactive backoff** derived
from the `data/model-health.json` records the worker/review outcome jobs already CAS-append:

- **Signal (host-observable only):** the worker harness's exit class (`rate-limit`/`session-limit`)
  is derived from the CLI's own stderr + `[error]`-prefixed lines, never model-authored stdout.
- **Duration:** the provider's machine-parseable reset hint (`try again in 20s`, `retry-after: 120`)
  when present, else **15 min doubling per consecutive hit, capped at 5 h**; a successful run
  resets the multiplier.
- **Enforcement:** `account-usage.py` reads the ledger from the `ledger` **branch** via the
  pinned contents API (the job's checkout is the default ref, whose seed file is empty) and
  stamps `backoff_until` onto the exempt entry;
  `usage_eligible` excludes the account until it expires; `usage-alert.py` surfaces active
  backoffs (`BACKED OFF`) instead of flagging exempt accounts probe-missing.
- **Fail-open by design:** an unreadable ledger or missing salt disables only the backoff (loud
  `::warning::`), never the exemption — the backoff is an optimization and must not reintroduce
  fail-closed starvation.

**Exemption is NOT reachability** ([issue #639](https://github.com/jeswr/agent-account-registry/issues/639)).
Being exempt from the quota probe means *no usage token is required*; it never meant *the account is
reachable*, and reading it that way is what kept handing a `credential-remint-required` account
(#596 / alert #622) to the allocator every tick. Every exempt entry therefore **carries** a
three-valued `reachability`, derived by `model-health.credential_states` from the same 48 h health
window as the backoff:

| value | evidence | dispatch | public page |
| --- | --- | --- | --- |
| `live` | a `success` record in the window | eligible | `available` |
| `unproven` | no decisive record (also: no salt, unreadable ledger) | eligible, **bounded** | `available` |
| `dead` | ≥ `CREDENTIAL_DEAD_MIN` consecutive `auth` rejections, no later success | **ineligible** | `unavailable` |
| absent / unrecognised | the producer never stated it | **ineligible** | `unknown` |

`usage_eligible` allowlists only `{live, unproven}`, so an unstated or unrecognised value fails
CLOSED; `usage-alert.classify` and the dashboard's `_quota_state` apply the same allowlist, so
monitoring, the public page and dispatch cannot disagree. `dead` carries **no TTL** — unlike the
#596 cooldown it is evidence, not a hold — and clears the instant a `success` is recorded, which is
why it does not overturn that decision for the interleaved failure pattern it was calibrated on.
`unproven` still admits because there is no independent liveness probe for an exempt provider
(`account-whoami.yml` is manual-dispatch and disabled on a public repo), so refusing it would
self-latch: no dispatch ⇒ no records ⇒ unproven forever. What it costs is bounded to
`CREDENTIAL_DEAD_MIN` trial dispatches per health window, after which the evidence turns `dead`.
`prune` preserves a dead run's tail against the `MAX_RECORDS` cap, so a flood of unrelated records
cannot silently readmit the account.

**The probe must PROVE its materialization** (same issue). `dispatch.yml`'s probe — the lane that
spends real capacity — now applies the ledgergate the dashboard lane got in #219/#612: the ACCT_*
materialization step carries **no** `continue-on-error`, the probe step **parses** the token subset
(a substring test accepts `{"ACCT01_TOKEN":""}` and a truncated `{"ACCT01_TOKEN":`), it records an
outcome sidecar (`usage-probe.json`, schema `account-usage-probe/v1`) that `usage-alert.py` reads
fail-closed, and the exempt branch runs **after** that proof — so an unusable subset yields an
**empty** usage map and the wholesale-outage alert actually fires, instead of a non-empty map of
exempt accounts nothing was measuring.

### Credential-outage exits are not declines (issue #596)

A model launch that dies on the **worker account's credential or capacity** — exit class `auth`,
`rate-limit`, `session-limit`, `billing`, or either of `worker-prep.sh`'s host-side credential
pre-flight classes `credential-remint-required` / `credential-refresh-transient` — is a **credential
outage**, not a model decline. The model never read the task or the diff, so there is no judgment to
charge for.

The set is held by **two locks with distinct scopes** — stated precisely, because #629's "the class is
closed" was an overstatement of the first one:

1. **The consumer lock**, bidirectional between the two *constants*. A set-equality assertion in
   `worker-pr.py --self-test` requires `CREDENTIAL_OUTAGE_EXIT_CLASSES` to equal every raw exit class
   whose fold target is one of `model-health.py`'s outage decision classes, so a class can never be
   non-chargeable on one side only (the drift that made the two pre-flight classes chargeable for the
   whole acct01 outage). Its non-vacuity anchor is a required-**subset** check, so a legitimate third
   `credential-*` class does not misfire it.
2. **The emitter lock**, producer → consumer. The consumer lock alone says nothing about the
   *producers*: `broker-refresh.py` could start emitting a new raw class with it still green (folding
   to `unknown`, and therefore CHARGED — fail-safe, but the same shape of drift).
   `worker-pr._emitted_credential_exit_classes` parses `broker-refresh.py` with `ast` and requires
   every `CLASS_* = "credential-…"` constant it can emit to be a key of the fold map.

Neither lock claims the vocabulary is closed against a *new* emitter script this derivation does not
read; what they close are the two directions that actually caused #604 and #614. Two consequences,
both wired through machinery that already existed:

- **No round or attempt is consumed.** The review round marker (`worker-pr.py round-record`) and
  the worker attempt receipt (`worker-issue.py record-attempt`) are both written *before* the model
  launches, for bounded-crash accounting. On a credential-outage exit the run now records a **void**
  for its own `(round, run)` / run key (`round-void` / `void-attempt`, gated by the single shared
  predicate `worker-pr.is_credential_outage`), and `count_rounds` / `count_attempts` subtract it —
  so `decide_budget` and the deferred-retry budget see that **no round happened**. `setup` and
  `unknown` are deliberately **still charged**: an unattributable failure must keep exhausting the
  budget, or a deterministic crash loop becomes unbounded.
- **No ladder advances.** The repeated-decline escalation (`DECLINE_ESCALATION_MIN`) and the
  capped-account discriminator (`NO_CHANGE_LIMIT_MIN`) both key strictly on `no_change`, so `auth`
  records can never reach them — and `make_record` refuses to attach the no-change evidence fields
  to an `auth` record at all.

After `AUTH_COOLDOWN_MIN` (**2**) consecutive `auth` outcomes for one account with no interleaved
success, `model-health.auth_cooldowns` puts that account into a **bounded credential cooldown** —
delivered through the *same* `account_backoffs` → `backoff_until` overlay described above, for
`AUTH_COOLDOWN_SECONDS` (**15 min**, single-step, never doubling) — and raises the `ops-alert`
condition `account-auth-cooldown`, naming the **salted fingerprint only** plus the required
maintainer action (re-mint the setup-token). It is deliberately a **cooldown, not a disable**: the
account may be the fleet's only cross-provider review account, and zero reviews is worse than a
partial success rate.

## Security posture

- Tokens: only in GitHub secrets (encrypted at rest, masked in logs), and only in the
  **`dispatch-secrets` environment** — repo scope stays EMPTY, enforced fail-closed every tick by
  `scripts/dispatch-secrets-guard.py` (issue #101). The environment's custom deployment-branch
  policy admits ONLY `master`, so a modified workflow copy dispatched at any other ref is refused
  the secrets server-side. This covers the 14 pipeline secrets AND `REGISTRY_SECRETS_PAT`
  (currently unset; when restored it goes into the environment — mint it fine-grained with
  repository **Secrets: read + Environments: read/write** on this repo: least privilege, because
  post-cutover the PAT only LISTs/GETs repo-scope secrets (onboarding's both-scopes absence
  probe) and WRITEs environment secrets — env-secret endpoints sit under the fine-grained
  "Environments" permission, whose read half covers the env public-key read. Store it with
  `gh secret set REGISTRY_SECRETS_PAT --repo jeswr/agent-account-registry --env dispatch-secrets`).
- `pat-validity` (weekly cron): probes `REGISTRY_SECRETS_PAT` ahead of use — `GET /user`, the `dispatch-secrets` environment secrets public-key read, then an authoritative `gh secret set --env dispatch-secrets` on the disposable `REGISTRY_PAT_PROBE_CANARY` secret (the public-key read alone needs only read access, so it would bless a read-only PAT that onboarding's env write still breaks on; a repo-scope canary would re-trip the secrets-guard weekly) — and upserts one rolling `from:agent` alert issue on invalid/insufficient-scope. Calendar expiry is caught before onboarding stalls on it, and a transient network blip never false-alarms — consecutive network-unknowns are counted in a repository variable (silent state: below the threshold no issue is touched, since GitHub creates every issue open and even a create-then-close would notify) and page via a separate rolling issue once a small threshold is crossed (issue #207), so a permanently-stalled probe cannot leave the PAT silently unverified.
- **The exfil gate contract is decided, and fails closed when it cannot be.**
  `dispatch-secrets-guard.guard_gate_verdict` proves that a failing `secrets-guard` prevents every
  secret-consuming job in `dispatch.yml` from running. Two properties carry the weight, and both are
  *parses*, not text searches:
  - **Polarity.** A job-level `if:` is decided by exhaustive satisfiability over a propositional
    abstraction, and the guard requirement may be pinned FALSE only when it is a genuinely parsed
    **comparison**. A function call's quoted string ARGUMENTS are not conditions — recognising the
    comparison inside a string literal is how the gate was defeatable in one line — and any atom the
    grammar cannot fully parse (indexing, arithmetic, a `!` whose precedence differs from GitHub's,
    a bare string used as a condition) is reported UNDECIDED, which the gate treats as admitting: an
    unreadable gate is not a proven gate.
  - **Execution.** The guard must actually RUN both verifier invocations. Reachability is decided by
    parsing the step's shell body — comments and here-document bodies removed, `&&`/`||`
    short-circuits and `if`/`while`/`case` constructs treated as unreachable — so a commented-out or
    short-circuited invocation is a refusal that names the fact. The text of a command is not its
    execution.
- Account metadata + selection logic: only in this private repo.
- Script convention: retry via `scripts/gh_retry.py` for idempotent reads; **NEVER** wrap CAS/ledger
  writes or mutation-confirmations (their conflict/fail-loud semantics are caller-owned — a replayed
  mutation can double-dispatch a worker, #559/#558).
- Public codebases request a worker and receive an opaque claim; they never see account internals.

## Registering a new account (web-login broker)

You don't paste tokens manually. Instead:

1. Open a **"set up new account"** issue (there's a template), label it with **one
   `grant:<owner>/<repo>` label per repository the account is authorized for**, then add the
   **`set-up-account`** label. Each target must be an `enabled = true` row of `policy/repos.toml`:
   `account_pool` is the credential-authorization boundary, so an account is granted ONLY to the
   repositories the request names (#579), and a request that names none is **refused before any
   login** instead of being granted to every repository.
2. The `set-up-account` workflow (trust-gated to the maintainer) runs the provider's device/OAuth
   login and **comments a sign-in URL + one-time code** on the issue.
3. Sign in with the account you want to register. The broker captures the resulting token, stores it
   as the account **secret** (`ACCTNN_TOKEN`) in this registry's `dispatch-secrets` environment, and
   registers the account issue **`status:pending`** — not yet allocatable. The request issue stays
   **open** until the grant PR in step 4 merges (it is closed by `activate`, not here).
   **The token is never printed** — only written to a mode-600 file and set as a secret.
4. The grant lands as a **checked `account-pool/<handle>` PR** that edits only the granted rows
   (`scripts/grant-account.py`, self-tested), and the labels are **re-read live** immediately before
   that write — a target removed during the sign-in window fails closed. The authorized set is
   recorded on the account issue as `grant_targets:`; on merge, `activate` re-proves that every
   recorded target lists the handle **exactly once**, that no other row lists it at all, and — against
   the merged commit's first parent — that **every other row and field is byte-identical**, before the
   account becomes `status:available` and the request is closed. The PR's **own complete merge-base
   diff** is proved separately (position by position, and refused if the API truncated it), because
   under a multi-commit rebase the first parent is a commit of the same PR.
   If the handle is somehow already in the policy pool, activation additionally requires **every
   authorized row to be traced to a merged, row-scoped `account-pool/<handle>` PR** that provably
   added the handle to that row: matching shape is not proof that a grant was ever reviewed. That
   bound is deliberately stated as what it is — each row was *at some point* established by a checked
   PR; it does not prove the row's current bytes are the ones that PR wrote, since an unchecked later
   edit could have removed and re-added the handle. Closing that would need a per-row history walk of
   the policy document and is not attempted.

Providers: **OpenAI** via `codex login --device-auth` (native device flow); **Anthropic** via
`claude setup-token` (run in the clean Actions runner). Needs `secrets.REGISTRY_SECRETS_PAT` (a
fine-grained PAT with repository **Secrets: read + Environments: read/write** on this registry
repo — least privilege; the broker only lists/reads repo-scope secrets and writes environment
secrets — stored in the `dispatch-secrets` environment: the broker job is env-bound to resolve
it, and it stores captured tokens into that same environment). The broker **fails closed before
any login**: its preflight proves the PAT can actually store a credential by invoking the same
authoritative `pat-validity` probe the weekly cron uses (`GET /user` + `dispatch-secrets`
public-key read + repo-secret listing + an authoritative environment canary write) and requiring a
valid *write* verdict — so a revoked, expired, read-only, or wrong-repository PAT that passes a mere
nonempty check is caught here, not after a credential is already captured. If the PAT is missing,
invalid, or under-scoped, the broker exits **without ever surfacing a sign-in URL** — remediation
(the exact mint grants and the storage command
`gh secret set REGISTRY_SECRETS_PAT --repo jeswr/agent-account-registry --env dispatch-secrets`)
is posted on the issue, so a credential is never captured that cannot be stored.
