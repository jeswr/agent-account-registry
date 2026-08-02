# Model container egress: one process holds the live credential, open egress, and a writable publish surface (#249)

> 🤖 **SPARQ agent** — design record, 2026-08-01. Maintainer-review document.
> **This record changes no behaviour.** It enumerates the options for the residual channel #124
> conceded on the MODEL side, and recommends an increment, so the next author implements a decided
> shape rather than re-deriving one.
>
> **Recommendation, in one line: increment 1 is a deny-by-default container network with an
> allowlisting egress proxy, landed in two steps — OBSERVE first, ENFORCE second.** Increment 2 is
> credential blast-radius parity for the anthropic lane. The full credential broker (§5.B) is the
> endpoint and is deliberately **deferred**, with its entry conditions named. Structured-diff
> publication limits (§5.C) are **rejected as a boundary for this issue** — §7 says why that
> rejection matters more than it looks.

## 1. The question

#124 contained the GATE side: the account credential tree is purged before any target-controlled
code runs (`.github/workflows/worker.yml`, the `purge` step, `always()`, ordered before the rustup
pin and the gate), nothing token-bearing follows the gate (#575), and the model's work is
reconstructed on a separate publisher from a digest-bound bundle sealed *before* the gate.

The MODEL side was conceded, not fixed. One process — the routed CLI inside
`_run_headless_harness` (`scripts/worker-live.sh:329`) — simultaneously holds:

1. the **live provider credential** (it must, to call the API),
2. **unrestricted network egress**, and
3. **write access to the target tree** that the publish path later pushes to a **public** repo.

A fully steered model (the threat this repo already treats as live — the fix lane ships a
`.worker-fix-injection.json` escape hatch, the review lane voids a reviewer that mutates the tree)
can therefore send the credential out directly, or stash an encoded copy in the tree and let
publication carry it. #249 asks which boundary to build.

## 2. What the model process holds today — the evidence

`_run_headless_harness` builds one `docker run` (`scripts/worker-live.sh:383-399`) and is the
**single choke point for all three lanes**: `run_model` (line 625, `allow`), `run_review`
(line 2904, `deny`), `run_fix` (line 3082, `allow`). Any change here covers every lane at once —
that is the main reason this is tractable at all.

| dimension | today |
|---|---|
| rootfs | `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--pids-limit 512`, non-root `--user $(id -u):$(id -g)` |
| scratch | `--tmpfs /tmp:rw,nosuid,nodev,**exec**,size=1g` — arbitrary binaries can be written and run |
| target tree | `$TARGET_DIR → /workspace` **read-write**; `$TARGET_DIR/.git` nested **read-only** (no hook/config planting) |
| CLI | `$WORKER_ROOT/cli → /opt/model-cli` read-only, version-pinned by `worker-prep.sh` |
| GitHub token | **none, in every mode** — and an argv scan re-asserts it (`worker-live.sh:404-407`) |
| **network** | **no `--network` flag at all** → the Docker default bridge → every host the runner can reach, plus direct UDP/53 |
| **egress record** | **none.** The model log is withheld and only usage/tool-count telemetry is lifted from it; nothing on the host observes a single connection the container makes |

Credential delivery splits by format, and the two halves are **not equally exposed**:

| `credential_format` | how it reaches the model | long-lived material inside the container? |
|---|---|---|
| `codex-auth-json` | mode-600 file, **read-only** bind mount (#134), carrying a MINIMAL derived document: fresh access token, **no refresh token** (#596, `worker-prep.sh` + `broker-refresh.py`) | **no** — short-lived access token only |
| `claude-oauth-token` | `--env CLAUDE_CODE_OAUTH_TOKEN` (`worker-live.sh:442`) | **yes** — long-lived, valid until revoked |
| `anthropic-api-key` | `--env ANTHROPIC_API_KEY` (`worker-live.sh:443`) | **yes** — `sk-ant-…`, valid until revoked |
| `claude-credentials-json` | read-only bind mount of the credential **unmodified** — the `codex-auth-json`-only pre-flight in `worker-prep.sh` never rewrites it | **yes** — `claudeAiOauth.refreshToken` reaches the container |

`orchestration/routing.toml` pins `credential_format = "claude-oauth-token"` for **every** anthropic
model (`haiku`, `sonnet`, `opus5`), and the selected-model step requires exact equality between the
routed format and the claimed account's format (`worker.yml:895-912`). So today the live anthropic
fleet runs on row 2 — the worst row — and `claude-credentials-json` is **latent, not live**: it is
an accepted format in four places and `scripts/account-login.sh:72` still records it as a fallback,
so it goes live the moment a routing entry pins it. #596's own stated rationale — *"`readonly`
stops writes, not READS — a prompt-injected model with Bash/Read could exfiltrate a long-lived
credential from its own HOME"* — applies verbatim to that format and was never applied to it. §9
files it.

## 3. The two channels, stated precisely

### 3.1 Channel 1 — direct egress

One `Bash` call. `node` is on `PATH`, `/tmp` is `exec`, and the container can reach anything. Cost
to the attacker: one tool invocation. Probability of detection: **zero, now and later** — there is
no network log to read even after the fact.

### 3.2 Channel 2 — stash in the tree, let publication carry it

`bundle_work` stages the **whole worktree** (`git add -A -- .`, `worker-live.sh:2508`) into
`patch.diff`, digest-binds the bundle, and the isolated `publish` job pushes it to a **public**
repository as a draft PR. An encoded ~100-byte string inside an otherwise plausible edit survives
every check on that path: `git diff --check` (whitespace only), the `.beads` refusal, the 20 MiB
bundle cap (`worker-live.sh:2553`), the gate, and both human and cross-provider review — a reviewer
cannot distinguish base64 of a token from base64 of a fixture. Cost to the attacker: one file
write. Detection: only if someone decodes it.

**The review lane is already immune to channel 2** and only to channel 2: `run_review` enforces a
byte-identical tree and voids the verdict on any mutation (`worker-live.sh:2906-2912`). It holds
the *opposite provider's* credential and has channel 1 wide open.

### 3.3 What closing only ONE channel buys

Stated plainly, because it decides the whole recommendation: **closing channel 1 does not contain
the credential — it forces exfiltration through channel 2**, which is slower, public, attributable
to a run and a diff, and passes in front of a gate, a cross-provider reviewer and a human. That is
a large improvement in *detection and attribution* and a small one in *prevention*. It is not
containment, and the increment must not be described as containment when it lands.

Closing only channel 2 buys nothing at all: channel 1 is strictly cheaper and strictly quieter.

## 4. What is already contained (do not re-litigate)

An increment here must not spend its review round re-arguing settled ground:
no GitHub token in the container, in any mode (argv-asserted); credential file read-only mounted so
it cannot be poisoned into the rotation write-back (#134); no refresh token in the codex mount
(#596); read-only `.git`; read-only rootfs, dropped capabilities, no-new-privileges, non-root uid;
credential paths handed as step outputs rather than job-wide env (#232); the credential tree purged
before target-controlled code (#124); nothing token-bearing after the gate (#575); the trust-gate
verifier pinned outside the model-writable tree (#568); the model log withheld and exit classes
derived from host-observable signals only.

## 5. Options

### A. Deny-by-default container network + an allowlisting egress proxy

**Mechanism that is actually a boundary.** Create a per-run **internal** Docker network (no route
off-host), attach the model container to it *only*, and attach one proxy container to both that
network and a normal bridge. The model container gets `HTTPS_PROXY`/`HTTP_PROXY` pointing at the
proxy, and the proxy allows `CONNECT` only to an allowlist.

⚠️ **The env var is not the boundary and must never be shipped as one.** `HTTPS_PROXY` is honoured
only by a *cooperating* client; the model has `Bash` and an `exec` tmpfs and can trivially open its
own socket. What makes this a control is that the container has **no route** except the proxy —
the env var is merely how the legitimate CLI finds the one exit that exists. An env-var proxy over
the default bridge is pure theatre (§7).

**What it closes:** channel 1, including DNS-tunnel exfil *if* the container cannot reach an
upstream resolver. **That is the one mechanism claim in this record that must be measured rather
than assumed** — Docker's embedded resolver may still forward external queries via the daemon even
on an internal network. §8 makes it a required measurement, not a footnote.

**What it does NOT close:** channel 2, at all. And an allowlist entry is only safe if the allowed
host is not an open write-and-read-back store: `api.anthropic.com` / the codex backend are fine
(the attacker does not own the account); a paste service or `api.github.com` would re-open
channel 1 through the front door. That rule belongs in the config file's header, not in a review
comment.

**Liveness / ops cost — the real objection.** Provider endpoint churn turns into worker failures.
Mitigations, all cheap: derive the allowlist **empirically** rather than by guesswork (§6, bounded
by §6.1 item 5 — observations rank the question, a trusted operator enters the answer); give a
denied connection a **named exit class** (`egress-denied`) so churn is an operator-actionable stop
rather than the `unknown` bucket, and so `model-health.py` never books it as a provider outage;
keep the allowlist in one reviewed file with a documented one-line edit path. Note what this option
does *not* break: `CONNECT` is a raw tunnel, so streaming/SSE is unaffected and **no TLS
interception and no CA in the container are needed** — the decisive advantage over option B.

In-container `cargo`/`npm` fetches are the other liveness cost. For the registry target the
self-test suite is pure stdlib and needs nothing; for a Rust target, allowlisting the package
registries is acceptable under the write-and-read-back rule above.

**Testability under `registry-selftest`.** Strong, and by the established pattern: put the argv
construction in a PURE helper and self-test **both directions**, exactly as `_credential_mount_args`
is tested at `worker-live.sh:3879-3891` (exact expected mount string; and the out-of-HOME input
that must be `refused`). Per AUTHOR pre-flight item 6, assert the flag by **tokenised exact match
plus adjacency**, never containment — a substring check passes for `--network none-DROPPED`. The
honest gap: a self-test proves the *argv*, never the *kernel*. §8 covers that with a one-time live
measurement recorded here.

**Cost:** moderate — one function, one config file, container lifecycle + fail-closed cleanup, one
pinned sidecar image. Put the sidecar in `containers/` as a Dockerfile so the existing #145
digest-pin check (`_assert_dockerfile_pinned`) covers it automatically; a bare upstream image named
in `docker run` would sit outside that gate.

**Verdict: recommended, in two steps.**

### B. Credential broker — the raw token never enters the container

**Mechanism.** A broker process outside the container holds the credential and proxies API calls;
the container is pointed at it (`ANTHROPIC_BASE_URL`-style) and holds no secret at all.

**What it closes:** both channels, for the credential, completely. The container's capability
becomes "make provider calls for the lifetime of this run" — non-transferable, expiring when the
container does. It does *not* remove capability abuse (quota burn, arbitrary prompts on the
account); that is the right trade, but it should be said out loud.

**Why it is not the first increment.**
- It must terminate and re-originate the provider protocol. If a CLI cannot be pointed at a plain
  `http://` base URL on the internal network, the broker must MITM TLS with a locally-trusted CA —
  **shipping a CA into the model container is a worse trust surface than the one being closed.**
- Streaming must be relayed byte-for-byte; a buffering proxy breaks the harness.
- The codex lane's ChatGPT-backend auth has no equally-supported base-URL override, so this is
  provider-specific work twice over.
- `worker-prep.sh` pins `@anthropic-ai/claude-code@2.1.177` and `@openai/codex@0.144.1`; every CLI
  bump can move the auth mechanism. A home-grown proxy in the auth path of **every** worker is a
  standing liveness liability on a repo whose entire purpose is keeping accounts drainable.

**Verdict: the endpoint, deferred — with entry conditions.** Revisit when (i) §6's observe phase
shows a stable, small endpoint set per harness, and (ii) at least one lane is demonstrated to work
against a plain-`http://` base URL with no CA. Deliberately **not filed as an issue now** (§9): an
open issue for work whose preconditions are unmeasured is a stale issue, and the measurement that
decides it is increment 1a's output.

### C. Structured-diff publication limits

**Mechanism.** Constrain what the bundle may carry: paths inside the routed area, no new binary
files, per-file added-byte caps.

**Verdict: REJECTED as a boundary for #249.** A ~100-byte encoded secret fits inside a
legitimately-edited text file in a legitimately-edited path. #249 concedes this in its own text
("content scanning cannot be the boundary for encoded copies"), and every variant of C reduces to
content scanning or to human review, neither of which sees an encoding. Some of these limits may be
worth having on their **own** merits (scope discipline, blast radius of a runaway model) — but they
must not be filed under this issue, because landing them here would let #249 be closed while both
channels stay open. That is the failure mode this rejection exists to prevent.

### D. Observe only (log egress, restrict nothing)

Not a separate option: it is step 1a of A, and it is where A's value starts. Folded in.

### E. Credential blast-radius parity for the anthropic lane

**Mechanism.** Give the anthropic lane the property the codex lane already has: what enters the
container is a **short-lived access token**, not long-lived material. `broker-refresh.py` already
implements both providers in its pure core (`PROVIDERS = ("openai", "anthropic")`;
`extract_access_token` reads `claudeAiOauth.{accessToken,expiresAt}`), and `assert_no_refresh_material`
already asserts the property. What is missing is that `worker-prep.sh` applies the pre-flight to
`codex-auth-json` **only**, and that routing pins anthropic accounts to the bare
`claude-oauth-token` format, which has no short-lived form to derive.

**What it closes:** nothing, by itself — the credential is still in the process. What it changes is
the **value of a stolen copy**: minutes rather than until-revocation. That degrades *both* channels,
and it degrades channel 2 almost to zero (a token that expires before a human reads the public PR
is close to worthless), which is precisely the channel option A cannot touch.

**Honest constraint:** this may be an account-**provisioning** change, not only a code change. An
account stored as a bare `claude-oauth-token` or `anthropic-api-key` has no refresh material to
exchange, so parity requires those accounts to be re-recorded in a refreshable format first — and
`claude-credentials-json`, the only refreshable anthropic format this repo records, currently
mounts its refresh token straight into the container (§2). Sequencing therefore matters: fix the
format before routing anything onto it.

**Verdict: increment 2, and the feasibility question is filed separately from the hardening.**

📄 **ANSWERED — [`research/1676-anthropic-short-lived-credential-feasibility.md`](1676-anthropic-short-lived-credential-feasibility.md)
(2026-08-02), and it corrects two claims above.** In short: **not today, and not with a code-only
change.** (i) "the pure core already implements both providers" holds only for the **read** side —
all five *deriving* entry points (`minimal_worker_credential`, `merge_refreshed`, `token_endpoint`,
`refresh_access_token`, `refresh_credential_host_side`) are openai-only; (ii) re-recording an
account is a **fresh enrolment on a burned slot**, not a re-record — `set-up-account.yml`'s #211
resume skips login by design — and the routing flip and the re-enrolment cannot move independently,
because `worker.yml`'s exact-equality gate and `set-up-account.yml`'s pre-store format gate bind the
two sides together. Increment 2 is gated on two **measurements**, not a PR: whether a
registry-dedicated *refreshable* anthropic authorization can be minted at all (`README.md`'s
enrolment runbook forbids the one refreshable format this repo records), and whether the access-token
TTL exceeds the 90-minute `worker_timeout_minutes` ceiling.

## 6. The recommended increment

**1a — OBSERVE (the recommended first increment).** Move the model container onto a per-run
internal network behind a proxy sidecar, with the proxy in **log-only** mode: it allows everything
and records the host set **under §6.1's telemetry contract**, which is part of this increment and
not a follow-on polish item — what gets recorded is model-chosen strings, not run metadata. Fail
closed — if the network or sidecar cannot be created, `die`; never silently fall back to the default
bridge (that fallback would be the whole control, quietly absent).

Why this first, and why it is the right size:
- It changes the topology, which is where **all** the liveness risk lives, while enforcing nothing —
  so the single biggest unknown (*do the pinned CLIs work through a proxy at all?*) is answered at
  zero security cost. If the codex CLI ignores proxy env vars, option A is dead for that lane and we
  learn it here rather than in a fleet-wide outage.
- It drives the allowlist **empirically** instead of from a guessed hostname list, which is the
  direct answer to the endpoint-churn objection — the observation establishes *that* an endpoint is
  missing and how often, and §6.1 item 5 governs how a line actually enters the config.
- It delivers the observability from §5.D immediately: the first record anywhere of what the model
  container talks to.

**1b — ENFORCE.** Flip the proxy to deny-by-default with the derived allowlist, add the
`egress-denied` exit class (host-observable, classified from the proxy's own log, never from model
stdout — same rule as `_run_headless_harness`'s existing classifier), and make `model-health.py`
treat it as operator-actionable rather than a provider outage. The exit class carries the **refusal
count and the allowlist rule that failed to match — never the refused hostname**: an exit class
reaches the run summary, the issue comment and `model-health.py`, all of which are public, so a
hostname there is §6.1's leak with a shorter path.

### 6.1 The observation record is itself model-controlled — the telemetry contract

The CONNECT authority and the DNS query name are chosen by the **model**, not by the provider. A
steered model can encode the credential, or chunks of it, into subdomain labels
(`<b64-chunk>.attacker.example`) or into an arbitrary CONNECT target — and it does not need the
connection to succeed: in 1a the proxy allows everything, and in 1b a **refused** connection is
recorded too. So an observer built to answer §8.3 will faithfully copy attacker-authored bytes into
a brand-new durable surface, and 1a would have traded a covert channel for a *recorded* one while
calling it observability.

**Host-observed is not the same as model-independent.** The proxy log is observed by the host but
authored by the container. Every other host-observable signal this repo classifies from (exit
status, wall time, argv, usage counts) has host-chosen *content*; this is the first that does not,
so the "host-observable signals only" rule in §4 does **not** carry the safety it carries elsewhere.
The posture that must extend to destinations is the neighbouring one: the model log is withheld and
only usage/tool counts are lifted from it (§2, §4).

The contract, binding on any implementation of 1a and 1b:

1. **Classified as hostile model output, not as run metadata.** Every observed field — CONNECT
   authority, SNI, DNS QNAME, any path — carries the same handling class as the withheld model log.
2. **Never published.** No raw observation enters a PR body, an issue, a comment, a workflow log, a
   run artifact, `data/`, or any committed file. In-repo publication is exactly what makes channel 2
   work (§3.2); a telemetry file that lands in the tree **is** channel 2 with extra steps. If a raw
   record must leave the runner at all it goes to the positively-verified private route only —
   `ALERT_REPO`/`ALERT_TOKEN` gated by `_confirmed_private()` (`scripts/pat-validity.py:539`), the
   pattern established in `research/370-private-diagnostic-sink.md` — and never to this public repo.
3. **Ephemeral, with a named owner and a named deletion.** The raw log lives on the runner for the
   run and, if anywhere else, in that private sink under a retention stated in the implementing diff.
   No raw retention "for later analysis" without both an owner and a deletion date.
4. **Validated and bounded BEFORE it is written.** Refuse to record a name over 253 bytes, a label
   over 63, more than a stated label count, any non-LDH character, or any authority that is not
   `host:port`. A value that fails validation increments a `malformed` counter carrying its
   **length and the reason — never the value**. That is fail-closed in the telemetry sense: the
   unrecordable case loses the datum, not the boundary. ⚠️ **Validation is a bounds check, not
   redaction.** It keeps malformed telemetry from breaking the recorder; it cannot make an
   attacker-chosen value safe to publish. A name that passes every bound here may still be a
   credential encoding — items 5 and 6, not this one, are what keep it out of durable output.
5. **The allowlist is entered by a trusted operator; no observed byte is ever transcribed into it.**
   Collapsing to **registrable domain + port** discards subdomains but sanitizes nothing: a label
   under a public suffix may be 63 LDH bytes, so `<b64-chunk>.example` is a *syntactically valid,
   within-bounds* registrable domain that carries a credential chunk. Neither aggregation filter is
   a boundary either — a "seen across N independent runs" threshold is trivially met by a steered
   model emitting the **same** name every run (the steering lives in the target content, which is
   constant across those runs), and that same low cardinality is what evades the high-cardinality
   signal; and a human reading a short list makes a *relevance* judgement, not a secret-redaction
   one, because no reader can tell an encoded credential from a vendor's CDN label. So: **candidate
   domains carry the same handling class and live in the same store as raw observations**
   (items 1–3) — ephemeral on the runner or in the private sink, never durable, never public, never
   in the tree. What enters the reviewed allowlist config is typed in by a **trusted operator from
   provider documentation**; the candidate list may only tell that operator *that* an endpoint is
   missing and how often. High-cardinality subdomains under one parent remain the exfil signature
   and are reported as a **count, not enumerated**.
6. **The operational datum is the anomaly, not the address.** Durable and public telemetry carries
   `allowed`/`refused`, counts, and **host-side identifiers only** — the identifier of the reviewed
   allowlist rule that matched, with everything unmatched aggregated into a single `unlisted` bucket
   with a count. **No observed or derived hostname — full FQDN *or* registrable domain — appears
   there**, which is what makes the durable surface independent of what the model chose to name.
   That answers every question §8 actually poses for running 1b. An implementation that concludes it
   needs an observed name **durably** — at any granularity — must say so in its diff and record the
   residual in these terms — *this store now retains attacker-chosen bytes that may be a
   credential* — naming its access restriction and deletion procedure, rather than claiming
   unqualified observability value.

**2 — anthropic credential parity** (§5.E), after the latent `claude-credentials-json` hole is
closed.

**3 — reconsider B** against the §5.B entry conditions, using 1a's measured endpoint set.

## 7. Explicitly NOT increments

Recorded so a later author does not ship one of these and believe #249 is closed:

- **`HTTPS_PROXY` without an internal network.** Advisory to a cooperating client; the model has
  `Bash` and an `exec` tmpfs. It is theatre, and it is worse than nothing because it *reads* like a
  boundary in a diff.
- **Moving the anthropic credential from `--env` to a read-only file.** The two delivery shapes are
  not equally hygienic in general, but against *this* threat they are identical: the model can read
  either, and must be able to. Making this change and calling it progress on #249 would be a false
  close.
- **Scanning the diff for high-entropy strings before publishing.** Content scanning against an
  encoding is a speed bump, and #249 says so itself.
- **`--network none`.** The model needs the provider API in all three lanes, including the
  read-only reviewer posture.

## 8. What the live measurement must answer before 1b

The self-tests prove argv construction; these are the facts only a live run can establish, and each
must be recorded (as a comment at the implementation site or an appendix here) rather than assumed:

1. Does each pinned CLI (`claude`, `codex`) complete a run through a `CONNECT` proxy — including
   streaming — with no direct route?
2. **Can the container still resolve external names via the embedded resolver on an internal
   network?** If yes, DNS is a residual covert channel and 1b must either sink DNS explicitly or
   record the residual as accepted and bounded.
3. What is the actual host set per harness, over both mutation modes and both target repos?
4. Which of those hosts are write-and-read-back stores (§5.A) and must therefore be refused even
   though the CLI touches them?
5. Does anything in a normal run need a package registry from *inside* the container?
6. **Does a credential-shaped destination reach any durable output?** Required before 1a is called
   done, and adversarial rather than observational. Two probes, and **(a) is the load-bearing one
   because its input is valid** — a probe that only exercises malformed input measures the bounds
   check and calls it redaction (§6.1 item 4):
   - **(a) valid, within-bounds, and repeated to the threshold.** Drive the aggregation threshold
     number of runs, each issuing a `CONNECT` to — and a DNS query for — the **same** marker host
     `sk-ant-<40 chars>.example:443`: one 47-byte LDH label under a reserved TLD, so it passes every
     §6.1 item 4 bound, clears the repeat threshold, stays low-cardinality, and — whatever
     public-suffix rule the aggregator uses — **the marker IS the registrable label** and cannot be
     collapsed away. Then search **every durable surface those runs produce** for the marker: PR
     body, issue comments, workflow logs, run artifacts, committed files, and the aggregated
     candidate/review surface itself. Record the exact surface list that was checked. **Zero
     occurrences on every surface is the only pass; any hit means 1a is not fail-closed and must not
     land.**
   - **(b) malformed.** The same marker made overlong or non-LDH must land in the `malformed`
     counter with a length and a reason and no value.

## 9. Follow-on issues filed from this record

1. **1a — internal network + logging egress proxy sidecar, observe mode, fail-closed** — including
   §6.1's telemetry contract and §8.6's adversarial credential-shaped-destination check, which are
   part of the increment and not separable from it.
2. **1b — enforce the derived allowlist + the `egress-denied` exit class.** Blocked on 1a's
   measurement.
3. **`claude-credentials-json` mounts the anthropic refresh token into the model container.**
   #596's minimal-derived-document treatment is `codex-auth-json`-only. Latent today (no routing
   entry selects the format) and one routing line from live, which is exactly the shape that should
   be fixed while it is cheap.
4. **Feasibility: can the anthropic lane carry a short-lived credential at all?** (§5.E) — the
   provisioning question that gates increment 2. Filed as research, not implementation.
   **ANSWERED (#1676):** [`research/1676-anthropic-short-lived-credential-feasibility.md`](1676-anthropic-short-lived-credential-feasibility.md).
   No impl issue follows from it — both of increment 2's preconditions are unmeasured and one may be
   unsatisfiable, which is this record's own §5.B reason for not filing option B.

Option B is deliberately **not** filed (§5.B): its preconditions are unmeasured, and 1a measures
them.

## 10. How this record binds

It decides a **shape**, not a diff. Nothing here authorizes weakening an existing control: every
increment is additive, each fails closed (a control that cannot be established stops the run rather
than degrading to today's posture), and none of them touches the gate, the arm path, or the
credential write-back. Nor may an increment create a **new durable record of model-chosen content**
outside §6.1's contract — an observer that publishes what the model named is a channel, not a
control. If an implementation of any increment finds itself deleting or relaxing a
check in §4 to make its own change fit, that is the signal to stop and amend this record instead.
