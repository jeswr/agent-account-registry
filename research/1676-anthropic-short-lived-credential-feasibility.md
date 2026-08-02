# #1676: can the anthropic lane carry a SHORT-LIVED credential at all? (#249 increment 2)

> 🤖 **SPARQ agent** — design record, 2026-08-02. Maintainer-review document.
> **This record changes no behaviour.** It answers the provisioning question
> [`research/249-model-container-egress.md`](249-model-container-egress.md) §5.E filed separately
> from the hardening, by re-measuring §5.E's premises against the tree. It edits no script, no
> workflow and no policy.
>
> **Answer, in one line: not today, and NOT with a code-only change.** The registry records exactly
> one refreshable anthropic format, its own enrolment runbook forbids that format on measured
> operational grounds, and its enrolment broker refuses to store it. Increment 2 is a
> *provisioning* project gated on a *measurement*, and §5.E's cost estimate is too low.

## 0. The four questions, answered

| # | question | answer |
|---|---|---|
| 1 | do the recorded `claude-oauth-token` / `anthropic-api-key` accounts have a refreshable form? | **No**, and the one refreshable format this repo knows is one `README.md:437-441` tells operators **not to use**. Parity is a re-enrolment, not a code change (§2). |
| 2 | what is missing between `broker-refresh.py`'s anthropic core and a per-run capability? | §5.E says "`worker-prep.sh` applies the pre-flight to codex only". True, and **incomplete**: the anthropic core is **read-only** — every one of the five *deriving* functions is openai-only (§3). |
| 3 | is the access-token lifetime long enough for a full run? | **Unknown, and it is the hard gate.** The rule is derivable here and the number is not: TTL must exceed **90 min** (`policy/repos.toml:99`) plus queueing slack, or increment 2 is a liveness regression that also drives the anthropic pool into repeated auth cooldowns (§4). |
| 4 | sequencing | The `claude-credentials-json` hole (#249 §9 item 3) must be closed regardless, but it is **not sufficient** — two further preconditions sit in front of increment 2, and one of them is not ours to satisfy (§5). |

**Verdict: increment 2 stays deferred, and the entry condition is §4's measurement — not a PR.**
§6 says what to do instead, and it is small.

## 1. What §5.E assumed, and what the tree says

§5.E's mechanism paragraph is right about the *shape* and understates the *cost* in two ways that
change the decision. Both corrections point the same direction — increment 2 is bigger than §5.E
budgeted — so neither is cosmetic (AGENTS.md pre-flight item 10: publish the corrected count).

- §5.E: *"`broker-refresh.py` already implements both providers in its pure core."* Measured: of the
  **ten** provider-dispatching entry points in that module, **five** handle anthropic and **five**
  raise or fail closed on it, and the split is exactly reads-vs-writes (§3.1). The anthropic core
  can *read* a credential it can never *produce*.
- §5.E: *"parity requires those accounts to be re-recorded in a refreshable format first."* Measured:
  there is no re-record path. `set-up-account.yml`'s #211 resume explicitly **skips login**
  (`:573-574`, *"a second login would orphan it"*) and reads the format off the account issue
  (`:1146`, `:1159-1161`). Re-recording an account is a **fresh enrolment on a fresh handle**, and
  the old slot is burned permanently — claims are never reclaimed (`README.md:427-433`, #245).

## 2. Question 1 — is there any refreshable form? No, and it is refused by design

Three independent facts, each sufficient on its own.

**2.1 The live fleet is necessarily bare-token, and that is provable without reading any account
record.** Every anthropic alias in `orchestration/routing.toml` (`haiku:42`, `sonnet:47`,
`opus5:64`) declares `credential_format = "claude-oauth-token"`; `worker.yml:895-912` requires
**exact equality** between the routed format and the claimed account's format (#142, and it is the
last gate before a secret is exposed). So an anthropic account recorded in any *other* format
cannot run a single worker — it fails the claim, not the model call. Whatever the account issues
say, the anthropic accounts that actually execute are `claude-oauth-token`, and a bare
`sk-ant-…` has **no refresh material to exchange**. `anthropic-api-key` is the same shape and
additionally is not a grant at all.

**2.2 The enrolment broker cannot store the refreshable format.** `set-up-account.yml:619-652`
(#191) refuses, *before the irreversible secret write*, any enrolment whose captured
`credential_format` is not equal to the declared `credential_format` of **every** alias in the
account's `models` list. `account-login.sh:62-72` prefers `claude setup-token`'s printed
`sk-ant-…` and falls back to copying `~/.claude/.credentials.json` only when no token was printed —
so the `claude-credentials-json` fallback, today, produces an enrolment the broker **rejects**.
The format is not merely latent; it is actively unenrollable while routing pins the bare token.

**2.3 The runbook forbids it, and the reason is not stylistic.** `README.md:437-441`:

> **Do NOT** copy `~/.claude/.credentials.json` — that subscription blob's refresh token *rotates*
> and dies the moment the interactive session refreshes (this broke the canary once).

That is the **same** hazard the codex lane solved by provisioning, not by code: *"Give the registry
its OWN codex login. Refresh chains are per-authorization, not per-account"* (`README.md:448-452`).
So the anthropic prerequisite is not "close the mount hole" — it is **an anthropic authorization
whose refresh chain nothing else shares**. `claude setup-token`, the one anthropic minting path this
repo automates, does not produce one: it produces a bare token with no refresh material at all.
Whether a registry-dedicated, refreshable anthropic authorization can be obtained *without* copying
a human's interactive session is the load-bearing unknown, and it is a **provider/account-provisioning
question, not a repository question**.

**Migration cost, if the answer to 2.3 is yes.** Per anthropic account: a fresh `set-up-account`
enrolment on a new handle (the old slot burns), a policy PR adding the new handle to `account_pool`
in **every** target that lists it — three today, `policy/repos.toml:97`, `:156`, `:194` — and the
old handle's removal. Because §2.1's equality gate is exact and §2.2's pre-store gate compares the
captured format against **every declared alias**, the routing flip and the account re-enrolment
**cannot move independently**: flip `routing.toml` first and every existing anthropic account fails
its claim; re-enrol first and the new account fails the pre-store gate. That two-sided,
must-move-together property is precisely the shape
[`research/271-coordinated-secret-migration-runbook.md`](271-coordinated-secret-migration-runbook.md)
was written for, and an increment-2 implementation needs its own cutover sequence in that style
before it touches a line of Python.

## 3. Question 2 — what is actually missing

### 3.1 `broker-refresh.py`: the anthropic core reads, and cannot write

| function | anthropic |
|---|---|
| `cred_relpath` `:58` | ✅ `.claude/.credentials.json` |
| `extract_access_token` `:67` | ✅ `claudeAiOauth.{accessToken,expiresAt}` |
| `access_token_expiry` `:299` | ✅ (divides the millisecond `expiresAt`) |
| `needs_refresh` `:312` | ✅ (provider-agnostic; delegates) |
| `extract_refresh_token` `:323` | ✅ `claudeAiOauth.refreshToken` |
| `minimal_worker_credential` `:332` | ❌ `raise ValueError` — *"only defined for openai"* (`:342`) |
| `merge_refreshed` `:362` | ❌ `raise ValueError` — *"only implemented for openai"* (`:369`) |
| `token_endpoint` `:504` | ❌ returns `None` — `TOKEN_ENDPOINTS` (`:146`) has no anthropic entry; the refusal lands one layer up |
| `refresh_access_token` `:517` | ❌ no endpoint **and** no `OAUTH_CLIENT_IDS` entry (`:157`) → `ValueError` at `:540` |
| `refresh_credential_host_side` `:586` | ❌ composes all four of the above |

That table was derived by **calling** each entry point with a well-formed anthropic credential, not by
reading the source. Two results are sharper than reading suggests. `refresh_credential_host_side`
fails for anthropic even on the branch where **no exchange is needed** (a still-valid token), because
that branch still calls `minimal_worker_credential` (`:600`) — so there is no anthropic path through
the host-side pre-flight at all, not merely no refresh path. And `extract_access_token` returns
anthropic's `expires_at` in **milliseconds** (the raw `expiresAt`), while `access_token_expiry`
returns **seconds** for the same provider and the same field (`:307` divides). Nothing consumes
`expires_at` in the worker lane today (`worker-prep.sh:194-197` checks only `access_token`), so this
is latent rather than live — but any increment-2 implementation that starts consuming the capability's
expiry is one unit-mismatch away from a token it believes is valid for 31,000 years.

So the missing pieces, named: an anthropic **token endpoint**, an anthropic **OAuth client id**, a
`merge_refreshed` anthropic arm **with an identity-binding check** (the openai arm refuses a
response naming a different `chatgpt_account_id`, `:377-386`; the anthropic token response carries
no `id_token`, so that fail-closed check has **no anthropic analogue today** and one must be
designed — see [`research/914-account-identity-binding.md`](914-account-identity-binding.md) for why
"which account is this?" is not a question this repo answers loosely), and the two `worker-prep.sh`
call sites that gate on the literal `codex-auth-json` (`:200`, `:205`, and the materialized-file
`assert_no_refresh_material` at `:240-245`).

⚠️ **A replay assumption must be made explicitly, not inherited.** The whole
`_RESEND_SAFE_STATUSES` / `STATUS_INDETERMINATE` apparatus (`broker-refresh.py:176-211`) exists
because OpenAI's refresh token is **one-time-use with server-side replay detection**. Whether
anthropic's rotates the same way is unmeasured here. The only fail-closed default is to **assume it
does** — `README.md:437-441`'s canary incident is evidence in that direction — which means an
anthropic arm inherits the full idempotency contract rather than a simpler one.

### 3.2 The good news: the short-lived DELIVERY seam already exists

`worker-live.sh:429-443` reads a **single-line token file** and exports
`--env CLAUDE_CODE_OAUTH_TOKEN`. Nothing in that path cares whether the token is long-lived. So
increment 2 does **not** need `minimal_worker_credential` to learn anthropic, and does **not** need
the model container to hold a `.credentials.json` at all: the host derives a fresh access token and
hands it through the delivery path that already ships. That is strictly better than the codex shape
— no credential file in the container, nothing for a read-only mount to trap, and the
`claude-credentials-json` mount hole (#249 §9 item 3) never comes near the container.

⚠️ **And that is exactly where the trust check is.** Doing this splits one concept into two: the
format the account is **stored** as (refreshable) and the format the container is **delivered**
(bare token). Today they are one field, compared for exact equality at `worker.yml:895-912`. Any
implementation that introduces a second field **must pin both** with the same exact-match
discipline. Relaxing the existing equality gate to accommodate the split would be a direct
weakening of #142 and is refused in advance by this record.

## 4. Question 3 — lifetime, and why it is the gate

The number is **not derivable offline** and must not be guessed. What *is* derivable is the rule it
has to satisfy and the blast radius of getting it wrong.

**The rule.** The credential must outlive the longest run the fleet permits. `policy/repos.toml`
sets `worker_timeout_minutes` = **30** for this repo (`:196`), 45 for the TS target (`:158`) and
**90** for sparq (`:99`); `review-fix.yml:1126` allows 60 for the fix lane. The existing embodiment
of this rule is `REFRESH_LEEWAY_SECONDS = 2 * 3600` (`broker-refresh.py:162`), whose comment says so
directly: *"a worker run can last 90 minutes… an expiry mid-run is fatal (the container cannot
refresh — that is the whole point of this module)."* So:

> **TTL(anthropic access token) must exceed 90 minutes**, with margin for the gap between the
> host-side pre-flight and the model container's last API call. If it does not, increment 2 cannot
> land in this shape at all, and no amount of pre-flight refreshing fixes it — the read-only mount
> (#134) and the env-var delivery both forbid in-place renewal, which is the trap #596 documents.

**Why a mid-run expiry is worse for anthropic than it was for codex.** The codex failure was a hard,
legible one — `Failed to refresh token: Read-only file system` — and it appeared *seconds in*. An
anthropic token delivered by `--env` gives the CLI nothing to refresh *from*, so the failure is a
plain 401 partway through a run. That classifies `auth`, and `auth` is a laddered class:
`README.md:783-790` — after `AUTH_COOLDOWN_MIN` (**2**) consecutive `auth` outcomes on one account
with no interleaved success, `model-health.auth_cooldowns` puts the account into a 15-minute
credential cooldown and raises the `ops-alert` condition `account-auth-cooldown`, whose stated
maintainer action is *"re-mint the setup-token"*. A too-short TTL therefore does not merely fail
runs: it converts every long anthropic run into a false re-mint page and cycles the anthropic half
of the pool through cooldowns. **That is a worse outage than the exposure increment 2 is buying
down**, which is why this is a gate and not a risk to be accepted at implementation time.

**How to measure it, cheaply and without any code change.** From one `claude setup-token` /
interactive login performed *outside* this repo: read `claudeAiOauth.expiresAt` (milliseconds,
`broker-refresh.py:304-307`) at mint time and subtract. One number, recorded here as an appendix.
Nothing needs to be built to obtain it, and nothing should be built before it exists.

## 5. Question 4 — sequencing

The dependency chain, in the only order that is safe:

1. **A registry-dedicated, refreshable anthropic authorization must be shown to exist** (§2.3). Not
   a repository change. If the answer is no, increment 2 stops here permanently and #249's §5.E
   should be amended to say so.
2. **The TTL measurement** (§4). If TTL ≤ 90 min, stop.
3. **Close the `claude-credentials-json` hole** — #249 §9 item 3. Stated precisely, because
   "precondition" is doing different work under the two designs in §3:
   - Under the **mount** design (§3.1 read literally — the container receives a derived
     `.credentials.json`), it is a **hard precondition**: step 4 routes an alias onto the format,
     and `worker-prep.sh:139-247` mounts that format *unmodified*, which is the exact exposure
     increment 2 exists to remove.
   - Under the **delivery** design (§3.2 — the container receives only a derived bare token), the
     format is never *delivered*, so the mount path is not on the critical path. It is still
     mandatory: step 5 makes the format **live as a stored format** for the first time, and from
     then on a single routing line, or `account-login.sh:71-72`'s fallback, is all that stands
     between the stored refresh token and the container.
   Either way it must be closed, and it is **not sufficient** — fixing it changes nothing about
   §2's provisioning wall.
   ⚠️ It is cheap **today** and stops being cheap the moment step 5 lands, because the format is
   currently latent — no account stores it (§2.2) and no route selects it.
4. **The broker work** (§3.1) plus the delivery decision (§3.2), with the equality-gate constraint
   honoured.
5. **The coordinated cutover** (§2, `research/271`-shaped): re-enrol, policy PRs across all three
   `account_pool` lists, routing flip — as one sequence, because the two gates make the sides
   inseparable.

Steps 1 and 2 are measurements. Step 3 is a small, independently-valuable hardening. Steps 4 and 5
are the project, and **they are unjustified until 1 and 2 return.**

## 6. What to do now

Nothing in code, for this issue. Concretely:

- Take the §4 measurement and append the number here. It is one login and one subtraction, and it
  decides whether steps 4–5 ever happen.
- Answer §2.3 — whether a registry-dedicated refreshable anthropic authorization can be minted at
  all — before budgeting increment 2.
- Land #249 §9 item 3 (`claude-credentials-json` refresh-token mount) on its own merits, now, while
  it is latent.

An impl issue for increment 2 itself is deliberately **not** filed, for the reason §5.B of #249
gives for not filing option B: *an open issue for work whose preconditions are unmeasured is a stale
issue.* Both of increment 2's preconditions are unmeasured, and one of them may be unsatisfiable.

## 7. What this record does not authorize

- It does not authorize relaxing `worker.yml:895-912`'s exact format equality, or
  `set-up-account.yml:619-652`'s pre-store format gate, to make a cutover easier. Both are the
  reason §2's wall is *visible* rather than a silent mis-provisioning.
- It does not authorize routing any alias onto `claude-credentials-json` before that format stops
  mounting its refresh token into the container.
- It does not authorize treating "the container holds a shorter-lived token" as closing either #249
  channel. §5.E is explicit and it stays true: this changes the **value** of a stolen copy, not the
  **channel**. Landing it must not be described as containment.
