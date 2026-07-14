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

## Reaction-based claim / release (the cross-codebase mutex)

To **claim** a worker slot on an account, a dispatcher adds a **🚀 reaction** to that account's issue.
The **count of 🚀 reactions = the number of active workers** on the account. If
`count >= max_concurrent_workers`, the account is **full** and must be skipped. To **release**, the
worker removes its 🚀 reaction on completion.

Because reactions are visible to any repo the automation identity can reach, this is a **single mutex
shared across every codebase** — two repos cannot together exceed an account's cap.

Every claim also leaves a **claim-receipt comment**:

```text
CLAIM repo=<owner/repo> run=<run-id> package=<pkg> role=<role> model=<model> at=<iso8601>
```

Receipts are the audit trail and let the groomer **reclaim stale claims** (a 🚀 with a receipt whose
run has ended/failed is removed, freeing the slot).

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

## Adding an account

1. Create a repo/org **secret** with the token: `gh secret set ACCT_<HANDLE>_TOKEN`.
2. Open an issue titled `<HANDLE>` with the YAML body above (`secret_ref: ACCT_<HANDLE>_TOKEN`).
3. Label it `provider:anthropic`/`provider:openai` and `status:available`.

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
