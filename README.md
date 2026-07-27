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

### The `package` partition has ONE canonical derivation (and one pinned copy)

A row's `package` is the single conflict partition its lease reserves, reduced from the source
issue's `area:*` labels: **exactly one** distinct area reserves that area, **zero or multiple**
reserve the serializing `__global__` partition (fail-closed — over-serialize a multi-area row rather
than free a busy sibling crate).

That reduction is **`lease_schema.plan_package`**. Precisely:

| deriver | how |
|---|---|
| `dispatch-claim.plan_package` (mints the CAS claim) | **delegates** to `lease_schema.plan_package` |
| `review-fix.yml` `resolve` job | **calls** `dispatch_claim.plan_package` — the minter's own function object |
| `worker.yml` self-claim shell step | **calls** `lease_schema.py --plan-package` (the CSV CLI) |
| `worker.yml` adopt validator | **imports** `lease_schema` from the registry checkout |
| `dispatch-plan.py:_plan_package` | the ONE genuine copy — it ships inside the target repos, which have no `lease_schema.py`, so it is **pinned by an executed agreement assertion** in `dispatch-claim.py --self-test`, not shared |

So there is one canonical definition, four callers, and exactly one pinned copy. Reverting any of the
**four callers** to a private reduction — even one that agrees today — turns
`dispatch-claim.py --self-test` red, because every caller carries a **shared-code** leg and not just
a value-agreement leg (value agreement is exactly what a private-but-agreeing copy also satisfies):

* the three **workflow** callers are *executed* out of the parsed YAML, and must both agree on every
  area shape **and** still contain the canonical call — re-inlining the rule removes the anchor, so
  the extraction fails with `found 0` instead of silently testing a copy;
* the **minter**'s delegation is probed directly: the self-test swaps `lease_schema.plan_package`
  out for a sentinel and requires `dispatch-claim.plan_package`'s result to follow it, which only
  shared code can do (`adopt-loop L1b`).

The fifth row, `dispatch-plan.py`, is the exception and is **agreement-pinned, not shared** — it
ships where `lease_schema.py` does not exist. A private copy *there* is caught only if it disagrees
on one of the exercised area shapes, which is weaker than the four callers above.
The routing tables `review-fix.yml` re-derives inline (`review_chain` / `fix_chain` / `ladders`) are
pinned to `dispatch-claim.REVIEW_CHAIN` / `FIX_CHAIN` / `worker-pr.ESCALATION_LADDERS` the same way.

This matters because these values are derived **twice by design** — once by the dispatcher that
mints a CAS claim, once by the review/fix (or worker) run that adopts it — and both adopt steps
compare the two for **equality**. When `resolve` carried its own pre-#112 alphabetically-first
reduction, every PR whose source issue held two `area:*` labels had its own dispatcher's claim
rejected on every tick, forever: a deterministic loop that burned an account lease and a runner per
tick and was the single largest failure class on the review lane that day.

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

- **A chain-ORDER preference belongs in the target's routing table, never in one repository's
  resolver.** Every dispatchable route is derived **twice**: PLAN runs the *target's*
  `scripts/route-resolve.py`, CLAIM re-derives it with registry-owned `scripts/policy-resolve.py`
  against the target's routing table read at its **protected** default tip, and
  `dispatch-claim._route_matches` requires **exact** equality of `model_chain` / `agent` /
  `escalate`. A rule only one side implements is therefore not a preference that half-applies — it
  raises `RouteDivergenceError`, the item defers `route-plan-claim-divergence`, and because the
  comparison is a pure function of the labels and the table it defers **identically on every
  subsequent tick**. The affected issues stop dispatching entirely. Machine-readable form —
  `orchestration/routing.toml` in the target:

  ```toml
  [[chain_preference]]
  labels   = ["area:gui"]      # EXACT labels; ANY one selects. Never a substring: "gui" in label
                               # would sweep area:guide / area:guidance into the carve-out.
  lead     = "sol"             # moved to the FRONT; every other rung keeps its relative order,
                               # so this is PREFERENCE, NOT EXCLUSION.
  requires = ["sol", "opus5"]  # fires only when the chain ALREADY contains all of these.
  ```

  `scripts/chain_preference.py` is the shared **mechanism**, imported by both registry resolvers
  and hard-coding no selector. `lead` **must** appear in `requires`, which is what makes re-order
  the only reachable effect — a preference can never inject a model into a chain that deliberately
  excludes it (e.g. turning the single-provider, escalating `role:research` chain cross-provider).
  Security `match_labels` routes are exempt on both sides: an implementor preference must never
  re-order a soundness chain. Verify a target with
  `python3 scripts/cross-resolver-agreement.py --target-root <checkout>`, which drives **both**
  resolvers over a 22-row label matrix and reports any row they decide differently.
  Live instance: the maintainer's 2026-07-26 `area:gui` carve-out (sparq PR #4211).

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

> **If the handle was enrolled by the broker, do NOT widen its grant here.** An ordinary policy PR
> takes effect for claims the moment it merges, but it establishes no row-scoped
> `account-pool/<handle>` provenance for the new row — which the broker requires per granted row —
> and it leaves the account issue's `grant_targets:` line disagreeing with policy, so that handle's
> resume and `activate` paths then refuse. Widen through the broker instead: see
> [`grant_targets:` — the recorded target set, and how to repair it](#grant_targets--the-recorded-target-set-and-how-to-repair-it).

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

### A `no_change` never re-dispatches the same tier (issue #701)

Measured 2026-07-26 over 196 completed `worker.yml` runs: **70 success / 126 failure**, dominated by
the structured exit class `no_change` — the model ran to a clean exit and produced **no diff**. The
same hard issue was then retried **up to 3x with the same model**, with no record of why the previous
attempt produced nothing, so one issue could consume three worker slots and three account leases to
produce nothing. Every sampled target was a substantive, correctly-labelled, genuinely hard task, so
this is a task-difficulty ↔ execution-mode mismatch, not a stale backlog.

Two halves, both in `scripts/no_change_routing.py` (the single declaration; `worker-live.sh` produces,
`model-health.py` stores, `dispatch-claim.py` routes):

- **`why_no_diff`.** A worker returning no edits is asked, in the stable prompt prefix, to write
  `.worker-no-diff.json` naming one of a **closed five-word vocabulary** (`underspecified`,
  `blocked_on_decision`, `too_large`, `already_done`, `other`). The file is lifted out of the tree
  **before** the change detection — otherwise writing the explanation would itself be the diff — and
  the reason rides the existing sanitized `no-change-v1` envelope as its **vocabulary index**, never
  as text, so nothing model-authored can reach the public ledger or an alert body. Absent, malformed,
  or out-of-vocabulary ⇒ `unspecified`, which is the value the router treats as *no signal*.
- **The decision**, taken in `dispatch()` on the deferred-retry path **before `allocator.claim()`**
  picks a model (the claim is what would otherwise walk the resolved chain from its head again):
  dispatch on an **untried** tier of the same chain, or — when no untried tier remains, or the
  declared reason says the task's *shape* is the blocker (`too_large` / `underspecified`) — fire
  #500's `role:impl` → `role:research` reroute at a threshold of **one**, because a second identical
  outcome cannot inform a decision the evidence has already made.

Fail-closed and bounded, in the directions that matter:

- An unreadable health window already leaves the issue deferred with **no** escalation, and `unknown`
  (the fold target for an unattributable exit) is neither `no_change` nor success — so an unreadable
  exit class can never mark an issue intractable.
- The narrowing has its **own** machine exit, `TIER_EXCLUSION_SECONDS` (**6 h**), 8x tighter than the
  48 h health window: a chain narrowed onto a tier with no capacity cannot stall the issue for the
  full window.
- Escalation terminates in `min(len(chain), DECLINE_ESCALATION_MIN)` dispatches, each on a distinct
  tier, and the terminal for an issue already on a non-implementation route is the **machine-owned**
  `status:parked` soft hold — never `needs:user` (#703).

The evidence path is itself a **YAML seam**: `worker.yml`'s `exit-class` step and the separate
no-target-code `model_health` job are the only wire carrying a `no_change` (and its `why_no_diff`)
into the ledger the dispatcher routes on. Cutting it fails **silently** — no job goes red, the
dispatcher simply sees no evidence and resumes retrying the same tier — so
`dispatch-claim._no_change_seam_violations` pins it on **parsed** nodes (`if:`, step/job presence,
the `needs:` edge, both `env:` inputs, and the `--reset-hint` argument), with each mutant applied to
the parsed document in memory and required to come back named.

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
- Worker publication is re-attested LIVE, twice (issue #568). The pre-model `trust` step runs tens
  of minutes before push/PR (the job budget is up to 90 minutes, which is why the lane mints two
  further App tokens across that span), so `worker.yml` repeats the FULL author / body-SHA /
  status-label / trust-gate revalidation in the fresh publisher immediately before
  `Commit, push, and open DRAFT target pull request` — a maintainer who closes, rewrites, or
  human-parks the issue mid-run is never published over. Three properties make it sound: the
  verifier is a **pre-model snapshot** — the trust-gate program, the `worker-issue.py` driver that
  runs the live checks and decides whether to invoke it, and the `park_policy.py` sibling the
  driver loads out of its own directory (the whole closure the path executes, or it dies on every
  run), since the local gate executes target-controlled cargo build scripts on the runner and
  could otherwise rewrite any of them — taken
  from the SHA-pinned checkouts into `RUNNER_TEMP` (outside every model-container mount) and
  re-bound to their recorded sha256s, with nothing else permitted in the snapshot directory, so the
  candidate change can never authorize its own publication — `reverify --forbid-gate-root` refuses
  at runtime if the gate path resolves into the model-mutable tree; the re-check runs in
  `--mode pre-publish`,
  which accepts **this run's own** `status:in-progress` claim (dispatch mode's `status:ready`
  demand would refuse every real run) and nothing else; and ownership is a genuine
  compare-and-swap — the run-key-bound claim receipt is posted **before** the shared
  `status:in-progress` label, so a newer run supersedes an older one even in the pre-attempt
  window, and `holds_live_claim` refuses whenever the newest receipt is not this run's. A step
  *outcome*, finally, proves only that a shell exited 0 — which those same build scripts can
  arrange without the verifier ever running, by persisting `BASH_ENV` (bash sources it before the
  block's first line) or a hijacked `PATH` out of the gate via `$GITHUB_ENV`/`$GITHUB_PATH` — so
  publication is additionally gated on a positive **attestation** the re-check emits only after the
  live re-verification returns; the re-check executes on a reset PATH with the interpreter levers
  cleared and python isolated; and the gate step's own runner command files are redirected to a
  quarantine path, removing that persistence primitive at its source. Drift ABORTS without
  mutating human-owned issue state; `final_state` returns the issue to the pool.

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

### `grant_targets:` — the recorded target set, and how to repair it

One authorization, three artifacts, read at three different times:

| Artifact | Lives on | Written by | Read by |
|---|---|---|---|
| `grant:<owner>/<repo>` labels | the **request** issue | the human opening the request | the broker's `authorize` step — and **re-read live** immediately before the pool write |
| `account_pool = [...]` rows | `policy/repos.toml` | the checked `account-pool/<handle>` PR | `policy-resolve` / `select-and-claim`, at **claim** time |
| `grant_targets: <owner>/<repo>[, ...]` | the **account** issue body (title = the handle) | the broker, when it creates the record (and an operator, by hand, in the recoveries below) | the #211 **resume** path and the post-merge **`activate`** job |

The record is not a duplicate of policy. `activate` fires on a `pull_request` event with no access to
the request issue's labels, so `grant_targets:` is the only *readable-from-there* statement of the
authorized target set that it can re-prove the merged policy against. `grant-account.verify_membership`
requires, in the merged document: **every** recorded target lists the handle **exactly once**, and **no
other row** lists it at all. Both legs are refusals — a record that cannot be read, or that disagrees
with policy, fails closed and leaves the account `status:pending` for a human.

**What the record is not.** It is an issue body an operator can edit, and nothing re-derives it from
the `grant:` labels after enrollment, so it is the broker's transcript of an authorization, never the
authorization itself. Editing it changes what the later proofs are compared *against*; it is not
evidence that the request ever authorized a target, and it cannot supply the row-scoped
`account-pool/<handle>` provenance the broker's no-op/resume path separately requires. That is why the
first recovery below is a reconstruction of a record whose grant was already reviewed, and the second
one drives the change back through the broker rather than hand-editing the line into agreement.

#### Recovery 1 — a pre-#579 account record has no `grant_targets:` line

Symptom, from `activate`:

```
refusing to activate acct07: the account record carries no `grant_targets:` line, so the
repositories this account was authorized for cannot be read — refusing to prove or activate
its grant (fail closed)
```

or, from a re-applied `set-up-account` on the bound request issue: *"…its authorized target
repositories cannot be read … Add a valid `grant_targets:` line to the issue body, then re-apply
set-up-account."*

Who is affected: an account issue created **before #579** (no such line) that is still
`status:pending` with an unmerged `account-pool/<handle>` PR. The recovery is a one-line hand edit of
the **account issue body** — not a policy edit — naming exactly the repositories whose `account_pool`
that pending entry occupies:

```
grant_targets: jeswr/agent-account-registry, sparq-org/sparq
```

Shape rules `parse_record_line` / `verify_membership` enforce: one line, comma-separated
`<owner>/<repo>`, anywhere in the body; entries are order- and duplicate-insensitive (sorted and
deduped on read), but each must name an `enabled = true` row of `policy/repos.toml`, and the set must
be **exactly** the rows the grant occupies — an extra target fails the *exactly once* leg, an omitted
occupied row fails the *no other row* leg. Then **merge the pending PR** — `activate` fires on the
merge and finishes the enrollment. There is nothing to re-run before then: the job is gated on
`pull_request.merged == true`, so re-triggering it on a still-open PR is skipped and recovers nothing.
The pre-merge resume option is re-applying `set-up-account` on the bound request issue.

Do **not** instead hand-add the handle to `policy/repos.toml` to make the two agree: that trades a
documented one-line record edit for an unreviewed write to the credential-authorization boundary, and
activation would then refuse anyway for want of a merged, row-scoped `account-pool/<handle>` PR
accounting for the membership.

#### Recovery 2 — widening (or narrowing) an enrolled handle's grant

**Do not widen a brokered handle in an ordinary policy PR.** That half takes effect for claims as soon
as it merges — `policy-resolve` / `select-and-claim` read `account_pool` and never read
`grant_targets:` — while establishing no `account-pool/<handle>` provenance for the new row, and the
next resume for that handle then refuses **either way**: with the record widened to match,
`trace_membership_provenance` finds no merged, row-scoped grant PR that established the new row; with
the record left alone, `verify_membership` sees the handle in a **non-target** row. Editing the line
afterwards does not repair that — it changes only what the proofs compare against.

Widen through the broker instead, so the audited `grant:` labels are re-proved and the addition lands
on the checked branch:

1. Add the `grant:<owner>/<repo>` label for the new repository to the **original request issue** —
   the authorization act, on the audited surface the broker actually reads.
2. Add the same `<owner>/<repo>` to that account issue's `grant_targets:` line. Resume treats the
   recorded set as the request's authorization snapshot and requires the live labels to still equal it
   (`require_same_targets`), and `activate` reads the record at merge time — so it has to be there
   before either runs.
3. Re-apply the `set-up-account` label to that request issue — a closed one is fine, the workflow
   triggers on `issues: [labeled]` and reconcile keys off the still-open **account** issue. The #211
   resume path skips login and registration (the credential is already captured, the slot is the same
   handle), re-runs `authorize` over the live labels against policy, and opens the **row-scoped**
   `account-pool/<handle>` PR whose only edit is the new row.
4. Let `gate` review that PR and merge it. `activate` then re-proves all four legs against the merged
   policy — the recorded set, the row-scoped before/after pair, the PR's file scope, and its own
   merge-base diff — and no-ops on an account that is already `status:available`.

If the broker cannot be driven (the request issue is gone, or the account issue no longer resolves as
resumable — it must be open and `status:pending`/`status:available`), the fallback is to open the
`account-pool/<handle>` PR **by hand on that branch**, record edited first: the human review of that
PR is then the authorization of record, and it is what later traces as provenance for the row. An
ordinary policy PR is never a substitute for it.

**Narrowing** is the one hand edit that stands on its own: remove the handle from the row in a policy
PR and drop that repository from `grant_targets:` in the same change window. A row the grant no longer
occupies needs no provenance, and leaving it recorded fails the *exactly once* leg the next time
resume or `activate` runs for that handle.

The fail-closed direction throughout is a refused activation rather than a silent grant: the record
decides what `activate` and resume compare the merged policy against, but what licenses a grant is the
reviewed `account-pool/<handle>` PR behind it.
