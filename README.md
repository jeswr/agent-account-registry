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

## One issue per account

Each model account is a GitHub **issue** in this repo. The issue **body** is structured YAML
front-matter (no secrets):

```yaml
provider: anthropic          # anthropic | openai
models: [opus, sonnet, haiku, fable]   # or [codex, gpt-5.6] for openai; enables model-fallback routing
tier:
  weekly_limit: "..."        # human note of the plan's weekly cap
  five_hour_limit: "..."     # the rolling 5h window cap
reset_schedule: "..."        # when the windows reset (per-account; they differ)
max_concurrent_workers: 1    # how many workers may run on this account at once
secret_ref: ACCT_<HANDLE>_TOKEN   # the NAME of the GitHub secret holding this account's token
notes: "..."
```

The **token value** for each account is stored ONLY as a repository/organization **secret** named by
`secret_ref` — never in the issue body, never in a comment, never in a public repo.

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
             "package": "sparq-core", "role": "impl", "model": "terra",
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

## Selection logic (`select-and-claim`)

`scripts/select-and-claim.py` (added in Phase 3) takes `(package, role, model-chain)` and returns an
opaque claim (which secret to use) or `none-free`:

1. Walk the **model fallback chain** (e.g. `haiku → terra`) to the first provider/model with a
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
  this default. Machine-readable form: the `role = "site"` route (`model_chain = ["terra",
  "fable", "sonnet"]`) in this repo's `orchestration/routing.toml`; when onboarding a new target
  repo in `policy/repos.toml`, mirror that route into the target's own routing table
  (`sparq-org/sparq` already carries it). `scripts/triage.py` derives `role:site` from the exact
  UI-surface labels (`area:dashboard`, `dashboard`, `surface:frontend`). Implement it as a ROLE
  route, **never** a `match_labels` rule — the arm-side security classifier unions all
  `match_labels` keywords, so UI keywords there would security-classify every UI PR (post-Decision-7 revision: an audit trail, not a park).

- **Frontier-tier agents author ALL CI/infrastructure work** (maintainer decision 2026-07-17):
  Claude Fable (`fable`) or GPT-5.6 sol (openai; wired alias `terra`) — explicitly including the
  self-draining pipeline infrastructure itself (dispatch, workers, gate aggregators,
  `.github/workflows`, orchestration scripts). Cheaper tiers (sonnet/haiku) no longer author
  infra; cross-provider review is unchanged (whichever provider's frontier writes, the other
  reviews). Machine-readable form: the `role = "ci"` route (`model_chain = ["fable", "terra"]`)
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
  (`credential_format: codex-auth-json`). (This one does rotate — used only as a cross-provider
  fallback.)
- On this work box, pre-provisioned Anthropic setup-tokens already exist as files
  `~/.claude-acctN-token` (one per account). Read the file; do not echo it.

### Step 1 — save the token as a secret (via stdin, never as a visible arg)

```bash
tr -d '[:space:]' < ~/.claude-acct5-token | gh secret set ACCT05_TOKEN -R jeswr/agent-account-registry
# or from a value you already hold, without it hitting the shell history/ps:
#   gh secret set ACCT05_TOKEN -R jeswr/agent-account-registry   # then paste at the prompt
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
gh issue create -R jeswr/agent-account-registry --title "acct05" --body 'provider: anthropic
harness: claude
credential_format: claude-oauth-token
email: "<the account login email — a setup-token CANNOT introspect it (403 on /api/oauth/profile); fill from the account you logged in as>"
models: [opus, sonnet, haiku, fable]
max_concurrent_workers: 1
secret_ref: ACCT05_TOKEN
notes: "claude setup-token (long-lived, non-rotating). [your-marker]"'
```
For an **OpenAI** account: `provider: openai`, `harness: codex`, `credential_format: codex-auth-json`,
`models: [terra]` (or the concrete GPT alias), `secret_ref: ACCTNN_TOKEN`.

### Step 4 — label the issue (REQUIRED — no label ⇒ not `available` ⇒ never selected)

```bash
gh issue edit <ISSUE#> -R jeswr/agent-account-registry \
  --add-label status:available --add-label provider:anthropic
```
`select-and-claim.py` sets `available = (has status:available label)`; without it the account is
silently skipped.

### Step 5 — add the handle to the repo's `account_pool` (the easy-to-forget step)

Edit `policy/repos.toml` for each target repo that should be allowed to use this account, and raise
`max_concurrent` if you want more simultaneous workers:

```toml
[repos."sparq-org/sparq"]
account_pool = ["acct01", "acct02", "acct03", "acct04", "acct05"]   # add the new handle
max_concurrent = 5                                                   # optional: allow more parallelism
```
Commit + push to `master`. An account that is available + in the catalog but **not** in a repo's
`account_pool` will never be claimed for that repo.

### Verify

```bash
gh secret list -R jeswr/agent-account-registry | grep ACCT           # secret present
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

## Security posture

- Tokens: only in GitHub secrets (encrypted at rest, masked in logs).
- `pat-validity` (weekly cron): probes `REGISTRY_SECRETS_PAT` ahead of use — `GET /user`, the Actions secrets public-key read, then an authoritative `gh secret set` on the disposable `REGISTRY_PAT_PROBE_CANARY` secret (the public-key read alone needs only `Secrets: read`, so it would bless a read-only PAT that onboarding's write still breaks on) — and upserts one rolling `from:agent` alert issue on invalid/insufficient-scope. Calendar expiry is caught before onboarding stalls on it, and network blips never false-alarm.
- Account metadata + selection logic: only in this private repo.
- Public codebases request a worker and receive an opaque claim; they never see account internals.

## Registering a new account (web-login broker)

You don't paste tokens manually. Instead:

1. Open a **"set up new account"** issue (there's a template) and add the **`set-up-account`** label,
   a **`provider:openai`**/**`provider:anthropic`** label, and one or more **`target:<owner>/<name>`**
   labels naming the repositories this account is authorized for (e.g. `target:sparq-org/sparq`). The
   account is added **only** to those repos' `account_pool` — a request with no target is rejected, so
   an account is never blanket-granted to every pool.
2. The `set-up-account` workflow (trust-gated to the maintainer) runs the provider's device/OAuth
   login and **comments a sign-in URL + one-time code** on the issue.
3. Sign in with the account you want to register. The broker captures the resulting token, stores it
   as the account **secret** (`ACCTNN_TOKEN`) on the token-target repo, registers the account issue,
   and closes the request. **The token is never printed** — only written to a mode-600 file and set
   as a secret.

Providers: **OpenAI** via `codex login --device-auth` (native device flow); **Anthropic** via
`claude setup-token` (run in the clean Actions runner). Needs `secrets.REGISTRY_ADMIN_TOKEN` (a
fine-grained PAT with Secrets:write on the token-target repo) — until it's set, the broker still
surfaces the URL but reports that the secret couldn't be stored.
