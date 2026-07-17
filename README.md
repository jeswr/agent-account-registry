# agent-account-registry (private)

The single, **private** source of truth for the model accounts (Anthropic / OpenAI) that back
automated coding workers across my codebases. **No public repository ever contains account
handles, limits, usage, tokens, or the selection logic** — all of that lives here.

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

A single JSON ledger `data/leases.json` records every active lease:

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

## Adding an account — step-by-step runbook (an agent can follow this verbatim)

> Goal: make one more model account usable by the workers. There are **five** required steps; the
> account is invisible to the selector until **all five** are done (notably the `account_pool` edit —
> a common miss). Every command targets the private registry `jeswr/agent-account-registry`.
> **Never print a token value** into chat, a log, an issue, or a commit.

**Naming convention.** Handle = `acctNN` (e.g. `acct05`). Its token secret is
`ACCTNN_TOKEN` (the handle upper-cased + `_TOKEN`, e.g. `ACCT05_TOKEN`). The account issue's
`secret_ref:` field MUST equal that secret name.

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

**Prioritisation policy** (to be wired into `choose_account`): among eligible accounts prefer
`status=allowed` with the **lowest** binding-window utilisation; **skip** an account whose status is
not `allowed` (or whose utilisation ≈ 1.0) until its `*-reset` timestamp passes; surface the soonest
`*-reset` so a fully-capped fleet knows exactly when capacity returns. This complements the existing
cache-affinity tie-break. (OpenAI/codex exposes analogous limits; TODO confirm its headers.)

## Security posture

- Tokens: only in GitHub secrets (encrypted at rest, masked in logs).
- Account metadata + selection logic: only in this private repo.
- Public codebases request a worker and receive an opaque claim; they never see account internals.

## Registering a new account (web-login broker)

You don't paste tokens manually. Instead:

1. Open a **"set up new account"** issue (there's a template) and add the **`set-up-account`** label.
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
