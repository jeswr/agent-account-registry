# #536: rewriting the `ledger` branch history — measured, and what it can and cannot buy

> 🤖 **SPARQ agent** — design record, 2026-08-01. Maintainer-review document.
> **This record changes no behaviour.** It answers #536 — *rewrite the published `ledger` branch
> history so no raw account handle remains reachable* — by first **measuring the actual exposure on
> `origin/ledger`** (§2) rather than assuming it, then correcting three of #536's premises against
> that measurement (§3), stating the four things a rewrite **cannot** promise (§4), writing the
> sequence that is actually executable (§5), specifying what the verification step must really check
> (§6), and laying out the four options with a recommendation the maintainer can overrule (§7).
>
> **Scope note.** #536 asks for a maintenance window, a `git push --force` onto a published ref, and
> a GitHub-side garbage collection. No PR can perform any of those, and the worker checkout
> deliberately holds no token. What a PR *can* contribute is the grounded measurement and the
> sequence. That is this record. It edits no script, no workflow and no policy.
>
> All counts below were taken read-only from `refs/remotes/origin/ledger` in this checkout on
> 2026-08-01 (tip `39c8970c2`). They are reproducible; they are not quoted from the issue.

## 1. The ask, and why the ask is only half-specified

#212 (shipped as PR #535, commit `db2afcabe`) moved the operational identity of an account to the
salted fingerprint `sha256(handle + ':' + PROVENANCE_SALT)[:16]`
(`scripts/select-and-claim.py:account_fingerprint`), made `make_lease` store only that, replaced the
claim commit subject with `claim_commit_message` (`claim <cid8> <package>/<role>` — no account), and
had both `select-and-claim.validate_lease_account_identities` and `groom.validate_ledger` **drop**
legacy raw-handle rows on the next CAS write. That converges the **tip**. It cannot touch history:
every superseded blob and every old commit message stays reachable from the branch.

#536 asks for the other half. Its stated sequence — window, stop writers, rewrite
`data/leases.json` history, force-update, verify, resume — is the right *shape*. Three of its
premises do not survive measurement, and two of the corrections change what the operator must
actually do.

## 2. The measured exposure

`origin/ledger` is a **linear, orphan, data-only** branch: 27,885 commits, **zero merges**,
2026-07-17 → 2026-08-01, 27,882 of them authored by `github-actions[bot]`.

| carrier | measurement |
|---|---|
| reachable blob versions of `data/leases.json` | 14,453 |
| …of those, containing an `acct…`-shaped string | **3,040** |
| commits whose `data/leases.json` holds an `"account": "acct…"` field | **2,943** |
| reachable blob versions of `data/model-health.json` | 7,894 — **0** carry a raw handle |
| `data/metrics.json` / `data/metrics-history.json` | 744 + 744 — **0** carry a raw handle |
| `orchestration/provenance/*.json` | 1,740 — **0** carry a raw handle |
| `orchestration/review-verdicts/*.json` | 4,192 — **2** match the handle grammar (see §3.2) |
| **commit subjects** of the form `claim <cid8> acct… <pkg>/<role>` | **1,221** |
| distinct handle strings appearing anywhere in the history | **10** |

Two facts follow immediately.

**The health/metrics/provenance stores were never exposed.** `model-health.account_hash` has
fail-closed refused to derive without both handle and salt since #202, and the measurement confirms
it across every reachable version. The exposure is `data/leases.json` **and the claim commit
subjects**, and nothing else in the data plane.

**The exposure window is closed and the code fix is empirically holding.** The newest commit whose
`data/leases.json` carries a raw account field is `d9a223192` at **2026-07-22T16:15:56Z** — four
minutes after PR #535 merged (`db2afcabe`, 16:11:39Z). The newest raw-handle commit *subject* is the
same minute. In the **21,509 commits** written since, there are **zero**. #536 is therefore a
scheduled cleanup, not an incident response, and the window can be chosen for convenience.

## 3. #536's premises, re-measured — three corrections

### 3.1 Correction A — the handles are not secrets, and the rewrite does not un-publish a string

#536 is titled "purge exposed account handles". The 10 strings it would purge are, right now,
published in plaintext on `master` of this **public** repo: `policy/repos.toml:97` (and `:156`,
`:194`) lists eight of them in `account_pool`, each account's enrolment **issue title** is the
handle (`groom.ACCT_ISSUE_TITLE_RE = ^acct([0-9]+)$`), the credential secret **names** are
`ACCTNN_TOKEN` (`ACCT_SECRET_NAME_RE`), and the claim refs are `refs/acct-claims/acctNN`
(`ACCT_CLAIM_REF_RE`) in a world-readable ref namespace.

That is not an oversight. `README.md:871-877` (locked decision 22, tightened by #1091) says it
explicitly: a handle **is** public on the catalog and enrolment surface, and the invariant #212
enforces is scoped to **operational** surfaces — ledger, health records, dashboard, identity
diagnostics.

So the rewrite removes **no secret value from public view**. What it removes is the **linkage**:
which account served which `package`/`role`, for which holder issue, at which timestamp. That
linkage is exactly what the fingerprint hides on the operational surface, and 2,943 commits plus
1,221 commit subjects currently publish it in the clear. That is a real and defensible thing to
want removed. It is a *smaller* thing than the issue title implies, and the difference matters when
weighing §4's limits against the cost of the window.

**This record does not re-open locked decision 22 in either direction.** It only observes that
#536's benefit is linkage removal, not secret removal.

### 3.2 Correction B — the scope "`data/leases.json` history" is wrong in both directions

**Too narrow.** 1,221 commits carry the handle in the **commit message**, not in any blob — the
pre-#212 subject `claim <cid8> <acct> <pkg>/<role>` (`select-and-claim.py`, replaced by
`claim_commit_message`). A blob-only rewrite (`git filter-repo --path data/leases.json --blob-callback`)
leaves every one of them reachable and the verification step in §6 red. **The rewrite must carry a
message callback as well as a blob callback.**

**Too wide, in a way that will fail the acceptance test.** Two `orchestration/review-verdicts/*.json`
blobs match the handle grammar:
`jeswr--agent-account-registry--pr1167-round1.json` and `…--pr260-round1.json`. Reading them, both
are **model-authored review prose using a handle-shaped string as an illustrative example** — one
discusses `refs/acct-claims/` grammar ambiguity between two spellings of a slot, the other quotes a
`# retired "acct…"` TOML comment. Neither records that a real account did real work. They are not
exposures, but no substring scanner can tell the difference.

Consequence: **"verify no raw handles remain in reachable commits", taken literally, fails on a
rewritten branch that is in fact clean.** §6 specifies the check that does not have this problem.
(That the verdict store can carry model-authored handle-shaped text at all is a separate gap #212
did not cover — filed as a follow-up, not addressed here.)

### 3.3 Correction C — "rewrite `data/leases.json` history" is not a partial rewrite

The oldest affected commit (`d369f2447`, 2026-07-18T00:20:14Z) sits **27,883 commits from the tip**
of 27,885. Every commit but the two roots is a descendant. Any rewrite therefore re-authors
essentially the whole branch and **changes every commit SHA on it**. There is no cheap "just fix the
bad commits" variant; §7's options are the real choices.

The mechanical cost is low — linear, single-parent, no merges, no tags, no signatures observed — but
the SHA churn is total, which is what §5's post-checks exist for.

## 4. What a rewrite cannot promise

These are the reasons to decide deliberately rather than reflexively. None of them is a reason not
to do it; all of them belong in the maintainer's expectation.

1. **A force-update does not delete anything on GitHub.** The old commits become unreachable from
   the ref but remain fetchable **by SHA** through the web UI and API until GitHub runs garbage
   collection on the repository — which for a public repo requires a **GitHub Support request**.
   Until that request completes, the rewrite has hidden the history, not removed it. Any fork or
   existing clone keeps a full copy regardless, permanently.
2. **The push events are already archived off-platform.** Every one of the 1,221 raw-handle commit
   subjects was delivered as a public `PushEvent` on the Events API, which third parties
   (GH Archive and mirrors of it) ingest continuously. Those copies are outside this repo's control
   and cannot be rewritten. **This is the ceiling on what #536 can achieve**, and it is the single
   fact most worth stating to whoever asked for the purge.
3. **Pre-#212 Actions logs are a separate, expiring channel.** The claim step passes the raw handle
   through `$RUNNER_TEMP/claim.json` and validates it in-line (`worker.yml:456-476`); whether any
   pre-#212 step echoed it into a world-readable log on this public repo was **not audited for this
   record** and should not be assumed either way. Logs expire on GitHub's retention schedule, so
   this channel closes on its own; the ledger does not.
4. **The rewrite's value is entirely conditional on `PROVENANCE_SALT`.** The handle domain is 10
   published strings. Given the salt, inverting a 16-hex fingerprint is ten hash evaluations. So the
   post-rewrite ledger is pseudonymous **only** while the salt stays secret, and a future salt
   disclosure retro-deanonymises the clean history as well as the dirty one. If the linkage is worth
   a maintenance window, then **salt custody is worth strictly more attention than this window is**
   — and salt *rotation* is not free (it breaks the stable identity of every existing health and
   lease record), so it needs its own decision rather than a line in this runbook.

## 5. The sequence that is executable today

Writer set, **measured** (every workflow invoking a script that PUTs to `LEDGER_REF` —
`select-and-claim.py`, `groom.py`, `metrics.py`, `model-health.py`, `pat-validity.py`,
`worker-pr.py`, `mint-provenance.py`): **17 workflows**, of which these fire on cron —

| workflow | cron |
|---|---|
| `dashboard.yml`, `groom-leases.yml` | `*/15 * * * *` |
| `groom.yml` | `7-59/15 * * * *` |
| `metrics.yml` | `11-59/15 * * * *` |
| `dispatch.yml` | `3,13,23,33,43,53 * * * *` |
| `conflict-resolver.yml` | `1,21,41 * * * *` |
| `reconcile-conflict-park.yml` | `16,36,56 * * * *` |
| `auto-mint-provenance.yml` | `13,43 * * * *` |
| `curate.yml` | `17,47 * * * *` |
| `backfill-provenance.yml` | `23 */4 * * *` |
| `pat-validity.yml` | `41 6 * * *` |

The remaining seven (`worker.yml`, `review-fix.yml`, `set-up-account.yml`, `account-whoami.yml`,
`fingerprint-accounts.yml`, `latch-watchdog.yml`, `mint-provenance.yml`) are dispatch/doorbell-driven
and can start at any moment while `dispatch.yml` is live.

> **The existing quiesce is not sufficient.** `scripts/migrate-secrets.sh:354` disables four
> workflows (`worker`, `review-fix`, `set-up-account`, `pat-validity`) — that is the **secret**-writer
> set, not the **ledger**-writer set. Using it here would leave `groom-leases`, `groom`, `metrics`,
> `dashboard`, `dispatch` and the provenance minters writing into a branch being rewritten. There is
> no shipped mechanism that quiesces the 17; the operator disables them individually, or a small
> script is written for it first (follow-up filed).

**Q. Quiesce.** `gh workflow disable` each of the 17, then **assert** each reports
`disabled_manually` via `gh api repos/{repo}/actions/workflows/{wf} --jq .state` — the assert-don't-assume
pattern `migrate-secrets.sh:443-453` already shipped for the same class of race (#328: `gh workflow
disable` resolves against **active** workflows only, so a no-op selector miss looks like success).
Then wait out the longest in-flight worker lease TTL and confirm no queued runs remain. A run that
starts before the disable lands and PUTs during the rewrite is the one race that silently loses data.

**B. Back up.** Push the current tip to a durable ref (`git push origin origin/ledger:refs/heads/ledger-pre-536`)
**before** touching anything. It defeats the point of the purge to keep it forever — but it is the
only rollback, so keep it until §5's post-checks are green, then delete it and include it in the
Support GC request. Also archive the tip's `data/*.json` and both record trees locally: they are the
only state that must survive.

**R. Rewrite.** `git filter-repo` on a fresh mirror clone, with **both** callbacks:

- *blob callback* on `data/leases.json`: rewrite each version so every lease row's `account` is
  either the canonical 16-hex fingerprint (if it already is one) or the row is dropped — i.e. exactly
  `select-and-claim.validate_lease_account_identities`. Dropping is correct: those leases expired in
  July 2026, and both readers already discard the shape. Re-deriving the fingerprint instead would
  require `PROVENANCE_SALT` inside the rewrite, which is not worth it for expired rows.
- *message callback*: rewrite every `claim <cid8> <acct> <pkg>/<role>` subject to
  `claim_commit_message`'s form, `claim <cid8> <pkg>/<role>`. Do not invent new text; matching the
  shipped function keeps the history consistent with everything written after 2026-07-22.

Leave `orchestration/**`, `data/model-health.json` and the metrics files byte-identical — §2 proves
they are clean, and rewriting them only risks the record stores that `groom` reads live.

**V. Verify** — §6, on the rewritten mirror, **before** the push.

**P. Push.** `git push --force-with-lease=refs/heads/ledger:<recorded tip sha> origin ledger`.
Plain `--force` is wrong here for the ordinary reason (`resolve-conflicts.py:973` uses the lease form
for the same reason): if a writer slipped past step Q, the lease fails and the ledger is not
silently truncated.

**C. Post-checks, before resuming anything.**
- `python3 scripts/ledger-invariant.py` against a fresh checkout of the rewritten branch — the
  data-only tree allowlist must still pass. Four workflows (`dashboard`, `dispatch`, `groom`,
  `review-fix`) run it immediately after checkout and will go red on any tree-shape damage.
- `select-and-claim.py --claim` / `groom.py` read the tip and get the same content as before the
  rewrite (the tip's *content* is unchanged; only its SHA moved).
- Spot-check that a known `orchestration/provenance/*.json` and a known review verdict are still
  readable at the tip by path — `groom`'s live provenance read resolves `LEDGER_REF` and pins the
  commit SHA **at read time** (`groom.py:881`), so nothing durably references an old SHA; a read that
  straddles the force-update fails **closed** (`indeterminate` → never parks). That is why readers
  are safe even if one is accidentally left running, and why *writers* are the only real hazard.
- **No reader consumes the branch's git history.** Every consumer reads files at the tip through the
  contents API; nothing in `scripts/` or `.github/workflows/` runs `git log`/`rev-list` over the
  ledger. History is therefore discardable state — which is what makes §7's option C viable.

**E. Resume.** `gh workflow enable` the 17, then assert each is `active` — the mirror of step Q, and
for the same fail-closed reason. Confirm one full grooming and one dispatch tick complete green.

**G. Garbage collection.** File the GitHub Support request to GC unreachable objects, naming the
repository and stating that a force-update removed history. Until it completes, treat §4.1 as still
in force. Delete `ledger-pre-536` first, or the objects stay reachable by ref and the request is a
no-op.

## 6. What the verification step must actually check

"No raw handles remain in reachable commits" needs three refinements to be both sound and free of
the §3.2 false positive.

1. **Derive the handle set; do not hand-write a regex.** The real grammar is
   `grant-account.py:74`'s `^acct[0-9a-z]{2,}$` — measurement found **three** of the ten handles in
   the `acctNcss` family, which a naive `acct[0-9]+` pattern only partially matches and a
   hypothetical all-alpha handle would evade entirely. The authoritative set is the union of the
   account **issue titles** and every `account_pool` entry in `policy/repos.toml` — the same two
   sources the enrolment path already treats as canonical. Scanning for that literal set, rather
   than for a shape, is both stricter (catches every real handle) and looser in the right place.
2. **Scan both carriers.** Every reachable blob **and** every commit message. §3.2 exists because a
   blob-only scan would have passed a branch with 1,221 handle-bearing subjects on it.
3. **Distinguish a record from a mention.** For `data/leases.json`, assert the *structural* property
   — every `leases[].account` `fullmatch`es `lease_schema.ACCOUNT` (16 hex) — rather than searching
   for substrings. That is the invariant the readers actually enforce, it is immune to prose, and it
   leaves the two `review-verdicts` prose blobs (§3.2) correctly out of scope. If the operator also
   wants prose scanned, it must be a **separate, explicitly-acknowledged** check with those two
   blobs listed by SHA — never an unexplained allowlist.

Both halves must **fail closed**: an unreadable object or an unparseable blob is a failure, not a
skip. `scripts/ledger-invariant.py` is the natural home for this as a second mode (it already owns
"what may exist on the ledger ref"), and a self-test with a seeded dirty history is what would make
it non-vacuous. That is implementable work and is filed as a follow-up rather than done here.

## 7. The options

| | what it is | cost | what it buys | what it costs you |
|---|---|---|---|---|
| **A** | Full rewrite per §5, both callbacks, then Support GC | one window, 17 workflows quiesced, ~27.9k commits re-authored | linkage gone from the branch and (after GC) from the repo | §4's four limits still apply; the archived push events are untouched |
| **B** | "Targeted" rewrite of only the affected commits | — | — | **not a real option**: §3.3, the oldest affected commit is 27,883 from the tip, so B *is* A |
| **C** | Re-root: new orphan branch seeded from the current tip's files, old history discarded | shortest window; **precedent exists** — `82ef87eba`, "ledger: orphan data-only rewrite", did exactly this on 2026-07-17 for PR #64 | same linkage removal, far less machinery, nothing to get subtly wrong in a blob callback | loses **all** ledger history, including the clean 21.5k commits; irreversible once `ledger-pre-536` is deleted; provenance/verdict *files* survive (they are copied to the new root) but their per-record commit trail does not |
| **D** | Do nothing; document the residual; spend the effort on salt custody | none | honest posture, no window | the linkage stays published in this repo, not just in the archives |

**Recommendation: C, with A as the fallback if the maintainer wants the clean history preserved.**

The reasoning, stated so it can be argued with:

- §5's post-check established that **no consumer reads the ledger's git history** — every reader
  fetches files at the tip by path. History is a byproduct, not state. That is the fact that makes C
  cheap, and it is why the same move was already made once (`82ef87eba`) without incident.
- C's rewrite is a *copy of known-good files onto a new root*, which is verifiable by inspection.
  A's blob callback must produce the right JSON across 14,453 blob versions and its message callback
  across 1,221 subjects; both are testable, but both are places to be subtly wrong, and a subtle
  error is discovered only after the force-push.
- C's real cost — losing the audit trail of the clean period — is worth naming rather than
  dismissing. If the maintainer values the ability to answer "what did the ledger look like on
  2026-07-28", choose A. That is a preference call, not a technical one, and it is the **only**
  question in this record that a reader cannot settle from the repository.
- **D is not unreasonable.** Given §4.2 — the raw-handle commit subjects are already in third-party
  archives of the public Events API — a maintainer who concludes the window is not worth the residual
  benefit is making a defensible call, not a lazy one. This record does not claim otherwise. What it
  does claim is that D should be an explicit decision recorded on #536, not a silent lapse.

## 8. What this record does not establish

- **Whether pre-#212 Actions logs published the handle** (§4.3). Not audited; do not assume either
  way. If it matters to the decision, audit it before the window, not after.
- **Whether `PROVENANCE_SALT` has ever been exposed.** Out of scope here by construction — this
  agent does not inspect secrets — and §4.4 makes the whole exercise conditional on the answer. The
  maintainer holds this one.
- **That the resulting posture is "sound".** This record is an unaudited design survey of a
  trust-plane change. The rewrite mechanics and the §6 check both need review before anyone arms
  them; nothing here should be read as a security sign-off.
- **Any timing claim.** No wall-clock figures appear above by design: the window's length is
  dominated by the longest in-flight lease TTL and by GitHub's own force-push and GC behaviour,
  neither of which is measurable from a work box.
