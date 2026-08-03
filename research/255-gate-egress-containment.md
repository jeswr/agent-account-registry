# Gate egress: target-controlled code runs on the runner with the tree the model wrote, full network, and a public log (#255)

> 🤖 **SPARQ agent** — design record, 2026-08-03. Maintainer-review document.
> **This record changes no behaviour.** #255 asks for a fix whose named implementation site does not
> exist in this tree (§2), so the first thing it owes is a corrected premise; the second is a decided
> shape, so the next author implements one rather than re-deriving it.
>
> **Recommendation, in one line: increment 1 is a network-DENIED gate for the profiles that provably
> need no network — `none`, `lint-only`, `registry-selftest` — with the one host-authored fetch that
> profile does make (`actionlint`) hoisted into a pre-gate step, landed OBSERVE-first.** The cargo
> profiles (`crate-scoped`, `workspace`) are increment 2 and are blocked on a vendoring/offline
> measurement that increment 1 does not need. The credential-broker half of #255's stated direction
> is **#249's** endpoint, already deferred there with entry conditions, and is **not re-filed here**.
> **What must not ship: an output filter, a second literal scan, a read-only target mount, or an
> `HTTPS_PROXY` env var — §7 says why each is a false close.**

## 1. The question, as #255 states it

> *(1) the model runs with the LIVE credential AND a writable target mount, so it can copy an
> ENCODED credential into the tree; (2) the pre-gate purge scan is literal-fragment only and concedes
> an encoded copy evades it; (3) the gate mounts the target rw and runs target-controlled build/test
> code that reads it; (4) the gate container has NO `--network none` and streams unredacted
> stdout/stderr to the job log.*

The conclusion #255 draws from that chain is correct and is **not** what this record disputes: gate
egress is real-time and reviewed by nobody, whereas the publish path stages a diff into a DRAFT PR a
human must arm. Where #255 is stale is in **what the gate is**, and the staleness makes the residual
worse, not better.

## 2. Corrected premise — the sandboxed gate #255 names never landed

#255 asks for `--network none` on `_gate_container_argv` / `run_gate_sandboxed` in
`scripts/worker-live.sh`, and for the residual to be recorded in that function's header comment.

**Neither identifier exists in this tree, and neither does a gate container.** Verified on
`d06cbc345`: the repository contains exactly one `docker run` — `_run_headless_harness`
(`scripts/worker-live.sh:329`, its `docker run` at line 384), the MODEL container.
`run_gate` (`scripts/worker-live.sh:869`) runs its profile body **directly on the GitHub-hosted
runner, as the runner user**, in both live lanes
(`.github/workflows/worker.yml:1355`, `.github/workflows/review-fix.yml:1960`). There is likewise no
literal-fragment scan of the target tree anywhere: `_credential_residue`
(`scripts/worker-live.sh:3844`) is a *path* discovery scan rooted at `$WORKER_ROOT`, and it never
looks at `$TARGET_DIR` or at file contents at all.

What happened is visible in `research/249-model-container-egress.md` §1: **#124 was answered by the
PURGE, not by a sandbox.** PR #231's containerised gate did not merge; the credential *tree* is
deleted before any target-controlled step instead
(`purge_credentials`, `scripts/worker-live.sh:3886`; ordering asserted live by
`_purge_before_target_code` on both lanes). #255 was split out of #231's review round 3 and kept
#231's vocabulary.

**Why this matters rather than being a wording nit.** Every mitigation #255 credits the gate with —
container, uid, rootfs, mounts — is absent, so the honest statement of the residual is *stronger*
than #255's:

| #255 assumed | actually, today |
|---|---|
| gate runs in a container, missing `--network none` | gate runs **on the runner host**, no container, no namespace of any kind |
| gate mounts the target rw | gate runs **in** the target checkout as the runner user (`working-directory: target`) |
| gate streams to "the job log" | the job log of a **public** repo (`README.md:1-4` — the registry is public so Actions minutes are free), world-readable **while the run is live** |
| a literal purge scan concedes encodings | there is **no** content scan of the target tree to concede anything |

An implementation that starts from #255's text will look for a function to add a flag to, not find
it, and either invent a container in a hurry or close the issue as stale. Both are wrong.

## 3. The chain re-derived against this tree

**Link 1 — the model can write an encoded credential into the target tree.** Unchanged from #249 §3.2
and not re-litigated here. `$TARGET_DIR` is bind-mounted **read-write** into the model container
(`scripts/worker-live.sh:392`) and the anthropic lane holds a long-lived credential in the process
environment (`scripts/worker-live.sh:431`, `:435`). Cost to a steered model: one file write.

**Link 2 — the purge cannot see it.** `purge_credentials` removes `$WORKER_ROOT/home`, the
`.credential-*` pre-flight artifacts and the withheld transcript, then re-scans and dies on residue.
Its root is `$WORKER_ROOT`. A copy inside `$TARGET_DIR` is out of scope **by construction, not by
oversight** — the purge's own header says what it deliberately does not widen into. So link 2 holds
for a reason the purge is right about; the gap is real and belongs to #255, not to #232/#91.

**Link 3 — the gate executes target-controlled code beside that copy.** `crate-scoped` runs
`cargo clippy` + `cargo test` (build scripts, proc macros, test harnesses — arbitrary code, by
design); `registry-selftest` executes every enrolled `--self-test` **out of the target checkout**.
Both run as the runner user, in the directory holding the stashed bytes.

**Link 4 — egress, two ways, both live.**

- *Network.* The runner has unrestricted outbound access. No `--network`, no namespace, no proxy,
  no egress record — nothing on the host observes a connection the gate makes. One line in a
  `build.rs`.
- *The log.* The gate's stdout+stderr are surfaced **verbatim** in the job log. This is deliberate
  and documented at the step (`.github/workflows/worker.yml:1371-1378`): an earlier revision `tee`d
  the stream to a runner-local file and that was removed as a disk-exhaustion vector, leaving the
  streamed log as "a sufficient and safe crash signal". Against a *crash* it is. Against
  exfiltration it is a publication channel: GitHub masks the exact secret string, and base64 of it
  is not that string — the same reasoning `#91` already applies to `$GITHUB_STEP_SUMMARY` at
  `.github/workflows/worker.yml:1391-1399`.

**Where the chain does NOT go.** Two boundaries hold and must not be re-argued by an increment here:
nothing token-bearing follows the gate (#575, asserted live by `_tokens_after_gate` on both workflow
files), and the tree the gate validated must equal the tree sealed before it
(`_assert_worktree_unchanged_by_gate`, `scripts/worker-live.sh:841`). So gate code cannot mint a
token and cannot rewrite what gets published. It can **read**, and it can **talk**. #255 is exactly
and only about the second.

## 4. What is already contained (do not re-litigate)

The credential tree and the withheld transcript are purged before any target-controlled step, on
both lanes, under `always()`, with a fail-closed residue re-scan (#232 r2, #91). The four runner
command files are quarantined for the gate step on both lanes — explicitly labelled defence in
depth, **not** a boundary, because the gate runs at the same uid (#91 r1). Nothing token-bearing
follows the gate (#575). The publish job reconstructs the work from a digest-bound bundle sealed
*before* the gate and executes no target code. The post-gate tree-integrity seal (#248) binds the
verdict to the published content. None of these touch egress, which is why #255 survives all of
them.

## 5. Options

### A. Deny the gate its network, per profile, with the pre-fetch hoisted

**Mechanism.** Run the gate body with no route off-host, and move every *host-authored* fetch it
legitimately makes into a step that runs **before** the target's code exists to observe it.

The decisive fact, and the reason this is tractable at all: **the profiles differ enormously in what
they need the network for, and the split falls along the target boundary already in
`policy/repos.toml`.**

| profile | target using it | what it fetches at gate time |
|---|---|---|
| `none` | — | nothing |
| `lint-only` | `jeswr/solid-sdk` (`enabled = false`) | `cargo fmt` only when `Cargo.toml` exists; otherwise nothing |
| `registry-selftest` | `jeswr/agent-account-registry` | **one thing**: the pinned `actionlint` tarball, and only when a workflow changed (`_ensure_actionlint`, `scripts/worker-live.sh:2173`). The suite itself is stdlib python + preinstalled `jq`/PyYAML — `_selftest_env_blocked` refuses up front rather than installing anything. |
| `crate-scoped`, `workspace` | `sparq-org/sparq` | `cargo` dependency resolution + crates.io fetch on a cold cache, unbounded and target-controlled |

For the first three, "no egress" costs **one hoist**. `_ensure_actionlint` is entirely
host-authored: a pinned version and two sha256 digests from `scripts/actionlint.pin`, a fixed
release URL, verified twice before anything lands, cached under `$WORKER_TOOL_CACHE`. Provisioning
it in a pre-gate step and passing the *verified path* into a network-denied gate loses nothing and
removes the last reason that profile needs a route. Note the ordering constraint this creates and
that an implementation must respect: the hoisted fetch must sit **after** the credential purge is
not required, but it must sit **before** the gate; the purge and the hoist are independent and the
purge must remain the earlier of the two boundaries it already is.

**Mechanism for the denial itself is the open question and MUST be measured, not assumed.** Three
candidates, none free:

1. **A gate container** (`docker run --network none`, target bind-mounted). Closest to what #255
   asks for, reuses `containers/` and inherits the #145 digest-pin assertion
   (`_assert_dockerfile_pinned`) automatically. Cost: a second image to build and pin, and the
   gate's toolchain (python3, jq, PyYAML, git, and for cargo profiles rustup) has to exist inside
   it — for `registry-selftest` that is a small, boring image; for cargo it is not.
2. **A network namespace without a container** (`unshare --net`). No image, but on a
   GitHub-hosted runner it needs either unprivileged user namespaces (which also remaps uid, and the
   gate's uid is load-bearing for the purge's threat model) or `sudo`, and running target-controlled
   code as root to deny it a network is a strictly worse trade. **Measure before choosing; do not
   ship on the assumption that `unshare -Urn` is uid-neutral, because it is not.**
3. **Host firewall rules for the gate step's duration.** Rejected on sight: it is a whole-runner
   mutation with a failure mode (rules that outlive the step) that breaks later host-authored steps,
   and it is not scoped to the process it is meant to contain.

**What it closes:** the network half of link 4, completely, for the profiles it covers. **What it
does not close:** the log half — see §5.B — and nothing at all for the cargo profiles until
increment 2.

**Testability under `registry-selftest`.** Strong, and by the established pattern: build the
invocation in a PURE helper and self-test **both directions**, exactly as `_credential_mount_args`
is tested. Per AGENTS.md AUTHOR pre-flight item 6, assert the flag by **tokenised exact match plus
adjacency** — a containment check passes for `--network none-DROPPED`. And per item 2(d), assert the
flag's **value**, not its presence. The honest limit, stated so an implementation does not overclaim
it: **a self-test proves the argv, never the kernel.** §8 turns that into a required one-time live
measurement rather than a footnote.

**Verdict: recommended as increment 1, scoped to `none` / `lint-only` / `registry-selftest`.**

### B. Bound and structure the gate's output channel

**Mechanism.** Stop streaming raw target-controlled bytes to a public log; emit a bounded,
host-framed summary plus the exit class, retaining the tail needed to debug a crash.

**Why it is a real option and not theatre:** unlike a *filter*, a *bound* does not depend on
recognising what it is looking at. A 200-line tail cannot carry a large blob; it can still carry a
credential, which is short. So a bound is a **cost increase, not a boundary** — and it must be
described that way when it lands or it becomes exactly the "reads like a boundary in a diff" change
`research/249-model-container-egress.md` §7 rejects.

**Why it is not increment 1.** It trades directly against the deliberate crash signal
(`.github/workflows/worker.yml:1371-1378`), which is the thing that makes a failing gate
diagnosable, and the trade needs evidence about real gate failures that nobody has gathered. Doing
it *after* A also makes it cheaper to reason about: with the network denied, the log is the
*remaining* channel rather than one of two, so its bound can be evaluated on its own merits.

**Verdict: deferred, deliberately, and NOT filed as an issue** — an open issue for work whose
trade-off is unmeasured is a stale issue. Entry condition: increment 1 has landed and one
maintainer-reviewed sample of real gate-failure logs shows what a bounded tail would have cost.

### C. Offline cargo — vendored deps in a read-only `CARGO_HOME`

**Mechanism.** Pre-fetch/vendor the target's dependencies in a pre-gate step, expose them read-only,
run `cargo --offline` inside the network-denied gate.

**What makes this a separate increment rather than part of A:** the pre-fetch is driven by
`Cargo.toml`/`Cargo.lock` — **target-controlled input** — so the "trusted pre-fetch" is only trusted
in the sense that it runs before the model's tree can observe the network, not in the sense that its
*content* is host-chosen. That is still a large gain (the fetch happens with no credential resident
and no target code executing), but it is a different argument from actionlint's, and conflating them
is how a reviewer gets told cargo is as safe as `actionlint.pin`. It also has a liveness cost A does
not: a vendoring step that fails must **fail the gate closed**, and on a cold cache it is the
slowest thing in the job.

**Verdict: increment 2, blocked on A landing and on §8's cargo measurement.**

### D. Credential brokering (#255's half (a))

**Verdict: correct, and already owned by #249 — deliberately NOT re-filed here.**
`research/249-model-container-egress.md` §5.B is the same mechanism (the credential is held by a
process the model cannot read), evaluates it in far more depth than #255 does, and defers it with
named entry conditions: a stable measured endpoint set, and at least one lane demonstrated against a
plain-`http://` base URL with no CA in the container. Filing a second issue for it from #255 would
produce two issues for one deferred design whose preconditions are measured by a third
(#249 increment 1a). **What #255 adds to that record is one sentence worth carrying: brokering is
the only thing on this list that closes the chain at link 1, and everything in §5.A–C is a
downstream mitigation of a credential the model was handed anyway.**

## 6. Explicitly NOT increments

Recorded so a later author does not ship one of these and believe #255 is closed.

- **An output filter / redactor on the gate stream.** The gate's code chooses its own encoding.
  This is the argument `purge_credentials`' own header already makes for why the transcript is
  *removed* rather than redacted, and it applies verbatim here.
- **A second literal-fragment scan, of the target tree this time.** #255 rejects it in its own text
  and is right: it cannot catch a reversible encoding. Shipping it would add a check that reads like
  containment in a diff and is not.
- **A read-only target mount for the gate.** It addresses link 3's *write* side, which #248's
  post-gate seal already refuses, and does nothing whatsoever to egress — while risking legitimate
  `cargo test` failures. Two costs, zero movement on #255.
- **`HTTPS_PROXY` (or `CARGO_HTTP_PROXY`) without removing the route.** Advisory to a cooperating
  client. `research/249-model-container-egress.md` §7 already rejects this for the model container;
  it is *more* obviously wrong here, because the gate's client is target-authored code.
- **Deleting the target tree's stashed copy by scanning for high entropy.** Same class as the
  literal scan, with false positives on every fixture and lockfile.
- **Calling #255 stale and closing it.** §2 is a premise correction, not a refutation: the residual
  it describes is live and is worse than its text says.

## 7. What a landing increment 1 must NOT do

Stated separately from §6 because these are ways of getting **A itself** wrong:

1. **Do not widen the gate's blast radius to deny it a network.** Any mechanism that raises the
   gate's privilege (running it as root, granting `CAP_NET_ADMIN`, mutating host firewall state)
   trades a read-and-talk capability for a write-anything one. If the only reachable denial
   mechanism requires that, **stop and say so** — the residual documented honestly beats a
   containment bought with root.
2. **Do not let a failed denial degrade to today's posture.** A container that will not start, a
   namespace that cannot be entered, or a hoisted `actionlint` fetch that failed must **die**, not
   fall back to a networked gate. That is the difference between this and every rejected option: it
   fails closed or it is not a control.
3. **Do not silently change which profiles are covered.** If `crate-scoped` still runs networked
   after increment 1, the *code* must say so at the seam and the self-test must assert the
   per-profile split by exact match — otherwise the next reader assumes the gate is contained and it
   is contained for one target out of two enabled ones.
4. **Do not assert the flag by containment, and do not assert its presence instead of its value.**
   AGENTS.md pre-flight items 6 and 2(d); this is the exact seam that produced every uncaught mutant
   in that list.

## 8. What only a live run can answer

The self-tests prove argv/step construction. These are facts a self-test structurally cannot
establish, and each must be recorded — as a comment at the implementation site or an appendix here —
rather than assumed:

1. Does a network-denied `registry-selftest` gate actually complete, with `actionlint` hoisted? Which
   enrolled self-tests, if any, touch the network today? (The `_selftest_env_blocked` preflight
   enumerates *dependencies*, not *sockets* — it will not answer this.)
2. For mechanism 2 (`unshare --net`): what uid does the gate body observe, and does the purge's
   same-uid threat model survive it? A uid change here is a **security-relevant** side effect, not
   an implementation detail.
3. Is DNS actually unavailable, or does a resolver remain reachable? A denial that leaves DNS is a
   covert channel, and `research/249-model-container-egress.md` §8.2 asks the same question of the
   model container for the same reason.
4. For increment 2 only: on a cold runner, what does vendoring the sparq workspace cost in
   wall-clock, and does `cargo --offline` complete the `crate-scoped` profile with the vendored tree
   read-only?
5. **Adversarially, and this is the one that decides whether increment 1 is real:** with the denial
   in place, plant a marker in the target tree in a pre-gate fixture step and have the gate body
   attempt to send it out — over TCP, over DNS, and by printing it. Record which of the three
   succeeded. **A run where all three fail is the only pass for the network half; the print
   succeeding is the expected, documented residual (§5.B) and must be reported as such rather than
   quietly omitted.**

## 9. Follow-on issues filed from this record

1. **Increment 1 — network-denied gate for `none` / `lint-only` / `registry-selftest`, with the
   pinned `actionlint` fetch hoisted pre-gate, fail-closed** — including §8.1–8.3 and §8.5's
   adversarial check, which are part of the increment and not separable from it.
2. **Increment 2 — offline cargo for `crate-scoped` / `workspace`** (vendor pre-gate, read-only
   `CARGO_HOME`, `--offline`). Blocked on 1.

§5.B (bounded output) and §5.D (brokering) are deliberately **not** filed — B's trade-off is
unmeasured and A makes it cheaper to evaluate; D is #249's, with its own entry conditions.

## 10. How this record binds

It decides a **shape**, not a diff. Nothing here authorises weakening an existing control: every
increment is additive, each fails closed (a denial that cannot be established stops the run rather
than degrading to today's posture), and none of them touches the purge ordering, the #248 tree seal,
the #575 no-token-after-gate property, or the arm path. Until increment 1 lands, the residual stands
as written in §3 and is pointed at from `run_gate`'s header comment in `scripts/worker-live.sh` —
which is where #255 asked for it, at the seam that actually exists.
