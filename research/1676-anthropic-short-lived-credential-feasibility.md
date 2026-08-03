# Can the anthropic lane carry a SHORT-LIVED credential at all? (#1676 — #249 increment 2)

> 🤖 **SPARQ agent** — design record, 2026-08-03. Maintainer-review document.
> **This record changes no behaviour.** It answers the provisioning question
> [`research/249-model-container-egress.md`](249-model-container-egress.md) §5.E filed separately
> from the hardening, re-measured against the tree *after* #1675 landed, so that increment 2 is
> either started with its cost known or abandoned on a measurement rather than on a guess.

## 1. Verdict

**Qualified yes — but it is a provisioning migration with a code change attached, not a code change,
and it is gated on one offline measurement that can kill the whole increment.**

Three findings decide it, and each is a correction to what §5.E assumed:

1. **`anthropic-api-key` can never reach parity.** It is a Console API key, not an OAuth grant;
   there is no endpoint that trades one for a short-lived capability. No code change reaches it.
   Any account recorded in that format is permanently outside increment 2 — §5.E's "re-record those
   accounts in a refreshable format" is the *only* option for it, i.e. it stops being an
   `anthropic-api-key` account.
2. **`claude-oauth-token` has no refresh material either**, so parity requires re-recording every
   live anthropic account. Today **all three** anthropic aliases pin it
   (`orchestration/routing.toml:42,47,64`), and the format is compared for **exact equality**
   against the claimed account at the last gate before the secret is exposed
   (`.github/workflows/worker.yml:912`). That equality is what makes the migration **atomic across
   the whole anthropic half of the pool** rather than per-account rolling — §5 costs it.
3. **The precondition §5.E named is already met, and it was met by REFUSAL, not by a strip.**
   #1675 made `claude-credentials-json` `die` in both places (`scripts/worker-prep.sh:65`,
   `scripts/worker-live.sh:444`). Increment 2 therefore does not build *on* the only refreshable
   anthropic format this repo records — it must **re-admit** it, and the refusal is the fail-closed
   placeholder the strip replaces. §6 says why that ordering is right and what it constrains.

**Do not start increment 2 before measurement M1 (§4).** If the nominal anthropic access-token
lifetime is under ~90 minutes the increment is a *liveness regression* and must be abandoned in
favour of §5.A/§5.B, because the read-only mount (#134) forbids in-place refresh — the exact trap
#596 documents.

## 2. Q1 — do the recorded formats have any refreshable form?

| recorded format | what the secret actually is | refresh material | reachable by a code change alone |
|---|---|---|---|
| `claude-oauth-token` | a single-line `sk-ant-oat…` from `claude setup-token`, validated as `^sk-ant-[A-Za-z0-9_-]+$` (`worker-prep.sh:291`) and copied verbatim to `~/.claude/worker-token` (`:294`) | **none** — there is no document, no `expiresAt`, nothing to exchange | **no** |
| `anthropic-api-key` | a Console `sk-ant-api…` key, same single-line arm | **none, and none is possible** — an API key is not a grant | **no, categorically** |
| `claude-credentials-json` | a `~/.claude/.credentials.json` snapshot: `claudeAiOauth.{accessToken,refreshToken,expiresAt}` | **yes** — the only refreshable anthropic form this repo records | **currently refused** (#1675) |

So §5.E's "honest constraint" is confirmed and is stronger than it stated: this is **not only** an
account-provisioning change, it is one that cannot be staged per account.

`README.md:447-451` adds a second constraint that increment 2 must design around, and it is the
reason the current guidance says *do not* enrol the refreshable format: the subscription blob's
refresh token **rotates and dies the moment an interactive session refreshes** ("this broke the
canary once"). That is the anthropic form of the per-authorization-chain hazard the README already
states for codex ("Give the registry its OWN codex login", `:458-461`). Increment 2 inherits it:
the migration must mint a **registry-owned anthropic authorization**, not copy a box's live
`~/.claude/.credentials.json`. Whether an isolated-`HOME` `claude` login yields a chain independent
of the maintainer's interactive session is **unmeasured** and is measurement **M3** (§4).

## 3. Q2 — what is actually missing between `broker-refresh.py` and a short-lived anthropic capability

§5.E is right that the pure core ships both providers, but the core that ships is the **read** side.
Every function on the **exchange / minimize / merge / deliver / write-back** side is openai-only,
and most of them say so by raising.

| piece | anthropic today | line |
|---|---|---|
| `PROVIDERS` | present | `broker-refresh.py:43` |
| `cred_relpath` | present (`.claude/.credentials.json`) | `:62` |
| `extract_access_token` | present (`claudeAiOauth.{accessToken,expiresAt}`) | `:76` |
| `access_token_expiry` | present, and correctly divides the **millisecond** `expiresAt` | `:305` |
| `extract_refresh_token` | present | `:328` |
| `assert_no_refresh_material` | provider-agnostic; already the guard the mount must clear | `:107` |
| `needs_refresh` | provider-agnostic, fails **towards** refreshing | `:312` |
| `TOKEN_ENDPOINTS` | **missing** — openai only | `:146` |
| `OAUTH_CLIENT_IDS` / `OAUTH_SCOPE` | **missing** — openai only; anthropic's scopes differ | `:157-158` |
| `refresh_access_token` | **refuses**: `no host-side token endpoint is configured for provider` | `:538-540` |
| `minimal_worker_credential` | **raises**: *"only defined for openai"* | `:342` |
| `merge_refreshed` | **raises**: *"host-side refresh is only implemented for openai"* | `:369` |
| `refresh_credential_host_side` | unusable — it calls both of the above | `:586` |
| `refresh_via_cli` | an anthropic arm **exists** (`claude --version`) but is explicitly outside `--self-test` and `--version` is not a plausible refresh trigger. **Do not assume this function works.** | `:622-630` |
| `worker-prep.sh` pre-flight | gated on `codex-auth-json` only | `worker-prep.sh:161` |
| `worker-prep.sh` admission | `claude-credentials-json` refused | `:65` |
| `worker-live.sh` delivery | `claude-credentials-json` refused at the format→delivery seam | `worker-live.sh:444` |
| `set-up-account.yml` enrolment | refuses **pre-store** any captured format that is not the declared alias format | `set-up-account.yml:635` |

### 3.1 The delivery shape is the cheap part, and it is cheaper than codex's

Two options once a fresh anthropic access token exists host-side:

- **(a) reuse the existing env delivery.** Write only `claudeAiOauth.accessToken` to
  `~/.claude/worker-token` and let `worker-live.sh:430-449` export it as `CLAUDE_CODE_OAUTH_TOKEN`
  exactly as today. **No document reaches the container at all**, so `assert_no_refresh_material`
  is satisfied by construction rather than by a guard — strictly better than the codex shape, which
  must mount a minimized document with a deliberately-empty `refresh_token` field. Unknown: whether
  the CLI accepts an OAuth **access** token in that variable, and whether the value satisfies the
  `^sk-ant-[A-Za-z0-9_-]+$` shape check at `worker-prep.sh:291`. That pair is measurement **M2**.
- **(b) mount a minimized `.credentials.json`.** Requires an anthropic `minimal_worker_credential`
  and the CLI's required-field set for that document. codex's needed `refresh_token` **present but
  empty** — a *measured* fact (`broker-refresh.py:336-340`); the anthropic analogue is unmeasured.

(a) is the recommendation if M2 passes: it needs no new mount shape, no new self-test seam at
`_credential_mount_args`, and it leaves `worker-live.sh`'s claude arm untouched.

⚠️ **But (a) collides with the exact-equality gate.** Under (a) the *stored* format
(`claude-credentials-json`) and the *delivered* format (`claude-oauth-token`) differ, while
`worker.yml:912` compares one string against `routing.toml`'s alias. Increment 2 must therefore
either (i) keep the two identical and let the alias declare the stored format — the simple option,
and the one this record recommends — or (ii) introduce a stored/delivered distinction, which adds a
second field to a gate that is deliberately one exact comparison. **(ii) weakens a trust check for
implementation convenience and should be refused.**

## 4. Q3 — the lifetime, and the measurement that gates everything

**This repo records no measurement of the anthropic access-token lifetime, and this record does not
invent one.** What it can state is the decision rule, which is already encoded in the tree:

- A run may last **90 minutes** — the largest `worker_timeout_minutes` in `policy/repos.toml:99`.
- `broker-refresh.py:159-162` already writes exactly this constraint down:
  `REFRESH_LEEWAY_SECONDS = 2 * 3600`, *"a worker run can last 90 minutes, and refreshing early
  costs nothing while an expiry mid-run is fatal (the container cannot refresh — that is the whole
  point of this module)"*.
- The credential is minted at pre-flight and must still be valid at the **end** of the container
  run, so the requirement is `nominal_lifetime > 90 min + (pre-flight → container start)`.

**M1 — nominal lifetime (offline, no network, no token printed).** From any
`~/.claude/.credentials.json`, read `claudeAiOauth.expiresAt/1000 - now`. Read it **twice with a
forced refresh in between**: a single read yields the *residual*, not the nominal lifetime, and a
residual can pass a threshold the nominal fails.

Three outcomes, and the increment's fate differs in each:

| measured nominal lifetime | consequence |
|---|---|
| **< ~90 min** | **Abandon increment 2.** A credential that expires mid-run is a liveness regression on every long run, and #134 forbids in-place refresh. |
| **~90 min – 2 h** | Viable, but `needs_refresh` (leeway 2 h) is **unconditionally true**, so *every* run forces an exchange — see the rotation coupling below. |
| **> 2 h** | Viable, and most runs mount the stored token without an exchange, as codex does. |

**The rotation coupling is the part §5.E does not mention.** Anthropic rotates the refresh token
(`README.md:449-450`). If M1 lands in the middle band, every run rotates the account's durable material,
which makes the write-back load-bearing on **every** run: `REGISTRY_SECRETS_PAT` absent ⇒ the
rotated grant is discarded and the account dies at the next expiry (`README.md:462-464` states this
for codex). Increment 2 in that band is not "parity with codex", it is "codex's worst case, always".

**M2 — delivery** (§3.1): does the pinned `@anthropic-ai/claude-code` accept a `claudeAiOauth`
access token via `CLAUDE_CODE_OAUTH_TOKEN`, and does that value match `worker-prep.sh:291`?

**M3 — chain independence** (§2): does an isolated-`HOME` `claude` login produce an authorization
chain that a maintainer's interactive session cannot kill? If not, the registry cannot hold a
refreshable anthropic credential safely at all, and the answer to #1676 becomes **no**.

## 5. What the migration costs

Same *shape* as [`research/271-coordinated-secret-migration-runbook.md`](271-coordinated-secret-migration-runbook.md)
— an all-at-once cutover with a stated abort — but a different surface, and it is worth being exact
about why it cannot be staged. Because `worker.yml:912` requires the claimed account's format to
equal the routed alias's format, and because all three anthropic aliases share one format string,
**any account re-recorded before the routing flip is unclaimable, and any account not re-recorded
after it is unclaimable.** There is no rolling window. So:

1. Every anthropic account is re-logged-in (an interactive, human-only step — no PR can do it) and
   its `ACCTNN_TOKEN` secret rewritten via stdin into the `dispatch-secrets` environment
   (`README.md` Step 1).
2. Each account issue's `credential_format:` line changes in the same wave.
3. `orchestration/routing.toml` flips all three anthropic aliases in one commit.
4. `set-up-account.yml`'s pre-store check (`:635`) then *starts* accepting the new format — until
   step 3 it refuses to enrol one, so **the migration cannot begin before the routing flip and the
   routing flip cannot land before the accounts are ready.** That circularity is resolved the same
   way #271 resolves its own: a maintenance window with the fleet drained, not a clever ordering.

The abort path is the reason to keep the old secrets: reverting steps 2+3 restores the fleet, but
only while a `claude-oauth-token` for each account still exists.

## 6. Q4 — sequencing, re-derived after #1675

§5.E's dependency ("after the latent `claude-credentials-json` hole is closed") **is satisfied**,
but not in the direction it anticipated. #1675 closed it by refusing the format outright in both
places, and each refusal is pinned by a self-test (`worker-live.sh:6837-6875`). The consequence for
increment 2:

- It must **replace the refusal with the strip in ONE diff**. "Delete the refusal now, add the
  pre-flight later" re-opens exactly the hole #1675 closed, and the interval is unbounded.
- The two self-tests that pin the refusal must be **re-pointed, not deleted**. The replacement
  assertion that goes red if the behaviour regresses is the codex one applied at the anthropic
  seam: prepare a `claude-credentials-json` fixture carrying a refresh sentinel, and assert the
  sentinel appears **nowhere** in what reaches the container — the mount under (b), or the exported
  token value under (a) — plus the negative direction, that a document still carrying
  `refreshToken` fails the prepare closed. Deleting the refusal tests and adding only an
  "it prepares successfully" test is vacuous: it passes whether or not the strip happened.
- Admitting the format **with** the strip re-creates a latent path (no routing entry selects it
  until §5 step 3). That is safe and is the opposite of what #1675 found: #1675's latency was
  *admit-without-strip*, one routing line from delivering a durable grant. *Admit-with-strip* is
  latent code that is correct when it goes live.

Order: **M1 → M3 → M2 → code (pre-flight + strip + re-admission, one diff) → §5's cutover.** M1
first because it is free, offline, and it is the only one that can end the increment.

## 7. What increment 2 is actually worth — a correction to §5.E

§5.E claims parity "degrades channel 2 almost to zero (a token that expires before a human reads
the public PR is close to worthless)". That is **conditional on M1, and the record should not carry
it unconditionally**:

- The claim holds only if the access-token lifetime is shorter than the publish→read latency of a
  draft PR. At an 8-hour lifetime and a PR read within the hour, the degradation is real but
  modest — a stolen token is worth *hours*, not *minutes*, and channel 2 stays live for that window.
- Channel 1 is unaffected either way: a stolen token is used immediately, so its **lifetime is
  nearly irrelevant to the direct-egress channel**. §5.E's "degrades *both* channels" overstates
  the first one.
- The review lane is already immune to channel 2 (§3.2 of the parent record), so the value is
  confined to the `run_model` / `run_fix` lanes.

Restated honestly: **increment 2's value is linear in the lifetime M1 measures, and it is a
channel-2 mitigation, not a channel-1 one.** If M1 comes back large, increment 2 buys much less
than §5.E implies and §5.A remains the better spend. This is stated here so the implementing PR is
not written against a benefit that was assumed rather than measured.

## 8. Risks the implementation must carry

- **Concurrent pre-flights on one account race the same grant.** Anthropic accounts run at
  `max_concurrent_workers` 4–12 (`README.md:59,587`), the pre-flight refresh is per-run, and
  nothing in `worker-prep.sh` or `broker-refresh.py` serializes it per account. With a rotating
  refresh token, two simultaneous claims both read the same stored secret and both exchange it.
  Filed as a follow-up because the same question applies to the **existing** codex lane and must be
  answered there first — it is not increment 2's to invent.
- **`refresh_via_cli`'s anthropic arm is unexercised.** `claude --version` is present in the
  provider map (`broker-refresh.py:627`) and is not a credible refresh trigger. An implementation
  that reaches for it because "the anthropic arm already exists" will ship a no-op refresh that
  mounts a stale token and dies in-container — the #596 failure verbatim.
- **`OAUTH_SCOPE` is openai's.** Reusing `"openid profile email"` for an anthropic exchange is a
  silent-wrong-scope hazard; the scope must come from the provider, not from the constant next to it.
- **The refusal must not be relaxed to make a test pass.** If the strip cannot be implemented
  safely, the correct outcome is that `claude-credentials-json` stays refused and #1676 is answered
  **no** — not that the refusal is softened.

## 9. Follow-ups this record files

1. **M1/M2/M3 as a measurement task** — the three facts above, recorded here as an appendix. M1
   alone decides whether increment 2 exists.
2. **Per-account serialization of the host-side refresh** — asked of the live codex lane first
   (§8), since the hazard predates this increment.

## 10. How this record binds

It answers a feasibility question and authorizes nothing. In particular it does **not** authorize
re-admitting `claude-credentials-json`: that is one diff, it must carry the strip, and it must
re-point rather than delete the #1675 self-tests (§6). Nothing here permits widening
`worker.yml`'s exact-equality format gate (§3.1), softening a refusal to fit an implementation
(§8), or starting the §5 cutover before M1 (§4).
