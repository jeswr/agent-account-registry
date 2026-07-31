# #536: purging raw handles from the `ledger` branch history — measured scope, runbook, and the limits of a force-push

> 🤖 **SPARQ agent** — design record, 2026-07-31. Maintainer-review document.
> **This record changes no behaviour.** It answers #536 — *rewrite the published `ledger` history so
> the raw account handles left behind by the pre-#212 writers are no longer reachable* — by first
> **measuring** the exposure against the actual branch (§2), then correcting two premises in #536's
> own framing that change what the operation is worth (§3, §4), then giving the sequence a
> maintainer can execute (§7), verify (§8) and roll back (§9).
>
> **Scope note.** #536 is explicitly an operator task: the worker checkout holds no GitHub token and
> must not push or mutate remote history. What a PR can contribute is the measured scope and the
> written sequence. That is this record. It edits no script, no workflow and no policy.
>
> **Two corrections up front, because they change the decision:**
> 1. #536 scopes the rewrite to *"`data/leases.json` history"*. That is **insufficient** — **1,585
>    commit *subjects* on `ledger` embed a raw handle** (§2.2). Rewriting only blobs leaves the
>    larger and more legible surface intact.
> 2. The handles are **already public by design** — the account catalog is the set of open issues on
>    this public repo, and a handle *is* an issue title (§3). A history rewrite therefore does not
>    make `acct01` secret. What it actually removes is the **account ↔ workload ↔ timing linkage**
>    and the fleet-composition disclosure. That is a real and worthwhile objective, but it is not
>    the one #536's title states, and stating it correctly changes the acceptance criteria.

## 1. The ask, and why it is a document

#212 (shipped as `db2afcabe`, 2026-07-22T16:11:39Z) stopped *future* raw-handle ledger writes on
three fronts: leases now store a salted fingerprint (`account_fingerprint`,
`scripts/select-and-claim.py:394`), reads drop legacy rows
(`validate_lease_account_identities`, `scripts/select-and-claim.py:402`; `validate_ledger`,
`scripts/groom.py:541`), and the claim commit subject lost its handle token
(`claim_commit_message`, `scripts/select-and-claim.py:711`).

None of that touches history. The `ledger` branch is published from a **public** repository — the
code says so in as many words: *"the registry is PUBLIC, so provenance records never store the raw
`acctNN` handle"* (`scripts/worker-pr.py:427-430`), and `scripts/metrics.py:84` notes *"This
repository is PUBLIC and this document is served verbatim"*. So the pre-#212 commits remain
readable by anyone who clones the branch.

The remedy is a history rewrite plus a force-update of a ref — operations that require a
`contents: write` credential the worker deliberately does not have, executed inside a window in
which the fleet's writers are stopped. Hence a runbook.

## 2. The measured exposure

All numbers below were measured directly against `origin/ledger` in the worker checkout on
2026-07-31. They are reproducible; the commands are given so the maintainer can re-measure at
execution time rather than trusting this record.

**Branch shape.** 23,246 commits, **linear** (`git rev-list --merges --count origin/ledger` → `0`),
rooted at an orphan commit `82ef87eba` — *"ledger: orphan data-only rewrite — no executable content
at this ref (PR #64 review round 1)"*, 2026-07-17T23:23:39Z. **This branch has already been
force-rewritten once by a maintainer**; §7 is not an unprecedented operation on this ref.

**Exposure window.** First leaking commit `d369f2447` (2026-07-18T00:20:14Z); last leaking commit
`d9a223192` (2026-07-22T16:15:56Z) — **4m17s *after* the #212 fix commit**, i.e. a writer already
in flight on an older checkout. Any rewrite cutoff must be chosen from the *measured last leak*,
never from the fix commit's timestamp.

### 2.1 Blob surface — `data/leases.json`

| Measure | Value |
| --- | --- |
| Commits touching `data/leases.json` | 12,848 |
| Distinct `data/leases.json` blobs | 11,802 |
| Distinct blobs containing a raw `acctNN` handle | **3,040** |

```bash
git rev-list origin/ledger -- data/leases.json \
  | while read c; do git rev-parse "$c:data/leases.json"; done | sort -u > /tmp/blobs.txt
for b in $(cat /tmp/blobs.txt); do git cat-file -p "$b" | grep -q '"account": "acct' && echo "$b"; done | wc -l
```

The shape of a leaking blob (from `d369f2447`) is the pre-#212 lease record:

```json
{"leases": [{"account": "acct01", "claim_id": "9ab59a0cdcaf496db1631aab649a9fe3",
             "holder": "review:sparq-org/sparq#2471@dispatch-29622763814.1",
             "package": "sparq-jsonld", "role": "review", "model": "terra",
             "issued_at": 1784334013, "expires_at": 1784335213}]}
```

Note what the row discloses beyond the handle: which account served which **target repo, issue,
package, role and model**, at a timestamp. The handle is the least interesting field.

### 2.2 Commit-subject surface — outside #536's stated scope

The pre-#212 claim subject was `f"claim {cid[:8]} {acct} {package}/{role}"` (see the `db2afcabe`
diff replacing it with `claim_commit_message`). Measured:

```bash
git log --format=%s origin/ledger | grep -E "^claim [0-9a-f]{8} [^ ]+ " | awk '{print $3}' | sort | uniq -c | sort -rn
```

| Handle | Subjects | Handle | Subjects |
| --- | --- | --- | --- |
| `acct01` | 736 | `acct06` | 61 |
| `acct03` | 295 | `acct05` | 25 |
| `acct2css` | 203 | `acct02` | 21 |
| `acct3css` | 85 | `acct04` | 12 |
| `acct4css` | 76 | | |
| `acct07` | 71 | **Total** | **1,585** |

**10 distinct handles, 1,585 commit subjects.** This surface is *more* legible than the blobs: a
subject is rendered in `git log --oneline`, in the GitHub commits UI, in every API commit listing,
and in the events feed — no blob fetch required. **A rewrite scoped to `data/leases.json` content
would leave all 1,585 intact**, and would leave the per-account claim *counts* above — i.e. the
fleet composition and relative utilisation — trivially derivable. That is precisely the disclosure
`locked decision 22b` exists to prevent elsewhere (`scripts/groom.py:1668`,
`scripts/account-usage.py:544`, `scripts/dispatch-claim.py:7426`, and the truncation guard at
`scripts/select-and-claim.py:1470-1476` which refuses to disclose even a *count* of accounts).

Non-`claim` subjects were checked and are clean — `release <cid8>`, `adopt <cid8> -> worker run`,
`groom N dead lease(s)`, `drop N concluded lease(s)`, `renew N live lease(s)`,
`reclaim N expired lease(s)`, `model-health record (<provider>/<class>)`,
`metrics snapshot <ts>`, `provenance <repo>#<pr>`, `review verdict <repo>#<pr> round N @ <sha12>` —
none interpolates an identity.

### 2.3 What is *not* exposed (checked, not assumed)

A pickaxe over every other path ever present on the branch (`README.md`, `data/*`,
`orchestration/provenance/*`, `orchestration/review-verdicts/*`) found no structured handle field:

```bash
git log -S'acct0' --format='%H %s' origin/ledger -- \
  data/model-health.json data/metrics-history.json data/metrics.json data/cache-affinity.json \
  README.md orchestration/
```

- `data/model-health.json` — account stored via `account_hash(handle, salt)`; clean.
- `orchestration/provenance/*.json` — `impl_account_h` is the salted hash by construction
  (`scripts/worker-pr.py:427`); clean.
- `data/metrics*.json` — per-target aggregates, no per-account rows; clean.
- `data/cache-affinity.json` — **empty on `ledger` for the branch's entire life** (only the orphan
  root ever wrote it; content is `{"accounts":{}}`). Clean today, but its own `_comment` declares
  the schema is `{account -> [{package,role,model,at}]}` — a raw-handle-keyed map. If that file is
  ever populated it becomes a new instance of this same bug. Filed as follow-up.

### 2.4 The one incidental occurrence outside `leases.json`

`dbbf9350` — *"review verdict jeswr/agent-account-registry#260 round 1"* — contains the string
`acct08` inside the **prose body of a review finding** discussing a TOML comment example
(`# retired "acct08"`). It is not an identity field, and `acct08` appears in none of the 1,585 lease
subjects. Whether it is in scope is a maintainer judgement: purging it means rewriting a
verdict record's *text*, which changes an audit artefact for a reason unrelated to the audit. **My
recommendation is to leave it and record the decision**, but it must be a decision, not an
oversight — otherwise §8's verification will flag it and the operator will not know why.

## 3. Correction: the handles are already public by design

`read_accounts` (`scripts/select-and-claim.py:1456-1486`) builds the account catalog from
`gh issue list -R <registry> --state open`, and sets `a["handle"] = it["title"].strip()`. **The
handle is the title of an open issue on this public repository.** Anyone can read all 10 today,
without touching the ledger.

This does not make #536 pointless — it makes it a *different* control. Purging the history removes:

- the **linkage** account → (target repo, issue, package, role, model, time) across 3,040 blobs;
- the **rate and composition** signal — 1,585 subjects, per-account counts, over a 4½-day window;
- the **precedent** of an identity field in a public data plane.

It does **not** remove: the handle strings themselves, the count of accounts, or anything an
observer already recorded. **If the maintainer's threat model requires the handles to be
non-public, the remedy is rotating/renaming the catalog issues — not rewriting the ledger.** The
two operations are independent and only rotation addresses confidentiality of the strings. I do not
recommend rotation on this evidence; I record it so the choice is explicit.

## 4. Correction: a force-update does not "purge"

This must be stated plainly because #536's title says *purge* and the acceptance criterion says
*"verify no raw handles remain in reachable commits"* — a check that will pass while the data
remains retrievable.

- **Unreachable ≠ deleted on GitHub.** After a force-update the old commits become unreachable but
  remain fetchable by SHA through the API and the web UI until GitHub garbage-collects, which is
  not on a published schedule and is not operator-triggerable. The SHAs are not secret — several
  are printed in this very document, and 23,246 more are in any prior clone.
- **Forks and clones retain everything**, and are unaffected by any rewrite on the origin.
- **Third-party archives.** Public-repo event streams are mirrored by services outside this
  project's control. Commit *subjects* — the 1,585 in §2.2 — are exactly what those streams carry.
- **Only GitHub Support can request a GC / cache purge**, and that request should be filed
  explicitly if the maintainer wants more than "unreachable".

**Therefore:** §8's verification proves *"no raw handle is reachable from `refs/heads/ledger`"*.
That is the honest, achievable claim, and it is the one the closing comment on #536 should make.
Anything stronger would be false. I have not audited what third parties actually retain, and I
cannot; that is stated as a limit, not resolved.

## 5. Blast radius

### 5.1 No consumer reads ledger *history* — the rewrite is transparent

This is the finding that makes the operation low-risk, and it was checked rather than assumed:

- Every workflow-side reader checks out **by branch name**, never by SHA:
  `ref: ledger` at `dashboard.yml:169,363`, `dispatch.yml:1135,1671`, `groom.yml:48,407`,
  `review-fix.yml:221,1077`. No `fetch-depth` beyond the default shallow clone.
- Every script-side reader/writer goes through the **contents API pinned to the ref**
  (`LEDGER_REF`, `scripts/select-and-claim.py:58`, `scripts/metrics.py:81`,
  `scripts/worker-pr.py:418`) — it reads the *file at the tip*, not history.
- CAS is on the **blob SHA of the file**, not a commit SHA, so no writer holds a commit identity
  across the rewrite.
- `scripts/ledger-invariant.py` validates `HEAD`'s tree only (`git ls-tree -r -t HEAD`,
  `ledger_entries`) — a **tip** check. Nothing in the repo validates history.
- Grepping for `git log`/`rev-list` against the ledger ref in `scripts/` and `.github/workflows/`
  returns nothing.

**Consequence:** if the rewrite preserves the *tip tree*, every consumer is bit-identically
unaffected. All operational state lives in files at the tip — `data/leases.json`,
`data/model-health.json`, `data/metrics-history.json`, `data/metrics.json`,
`data/pat-probe-streak.json`, and the create-only `orchestration/{provenance,review-verdicts}/*.json`
records.

### 5.2 The write window is the only real hazard

The failure mode is not the rewrite — it is a writer landing a commit **between** the snapshot the
rewrite is computed from and the force-update, whose commit is then discarded. Losses are not
uniform:

| Lost write | Recoverable? |
| --- | --- |
| A lease claim/release/renew | **Yes, automatically.** Leases are TTL-bounded (`ttl=3600` default) and the groomer reclaims past `expires_at`. Worst case is a stranded slot for one TTL. |
| A `model-health` record | Yes in effect — the next probe re-records; a single lost datum degrades a rolling signal, it does not corrupt it. |
| A `metrics` snapshot | Yes — the next cron re-derives; one ring entry is lost. |
| A **provenance record** | **Not automatically.** Create-only, path-keyed idempotency (`worker-pr.provenance_record`); a lost record leaves a PR unminted. `scripts/backfill-provenance.py` exists precisely for this and is the recovery lever — but it must be *run*, deliberately, in S7. |
| A **review verdict** record | Same class as provenance; create-only, and drives review admission. |

Note the counter-intuitive part: because CAS keys on the *blob* SHA and not a commit, a writer that
read before the rewrite and PUTs after it can **succeed** against the new tip rather than failing
closed. Quiesce is therefore not optional and cannot be replaced by "let CAS sort it out".

## 6. The options

| | Method | Preserves | Cost / risk |
| --- | --- | --- | --- |
| **A** | Rewrite every historical `data/leases.json` blob to `{"leases": []}` + strip the handle token from the 1,585 subjects. | Commit graph, all non-lease history (metrics, provenance, model-health commits). | Destroys the lease audit trail while keeping 23,246 commits to rewrite and re-verify. Most work, middling result. |
| **B** | Map `acctNN` → `account_fingerprint(handle, PROVENANCE_SALT)` in both blobs and subjects. | Everything, in the *current* canonical format. Historical rows stay analysable and match the tip's schema. | Requires the **production salt inside the rewrite process**. And a 16-hex salted hash over a **known 10-element handle set** is only as strong as the salt's secrecy — if the salt ever leaks, every historical row de-anonymises at once. The project already treats even *salted* per-account publication as too much (the dashboard stopped publishing salted per-account rows, `scripts/dashboard-gen.py:72-77`). Recommending B would mean re-introducing, into permanent history, a disclosure the tip deliberately stopped making. |
| **C** | **New orphan root at the current tree** — one commit containing today's tip tree, force-update `ledger` to it. | The **entire operational state** (§5.1: every consumer reads the tip). | Destroys all ledger commit history. Provably complete for the branch in one step, with no 23k-commit rewrite to audit. Precedent: the branch's own root `82ef87eba` is exactly this operation. |

**C is recommended.** The argument is §5.1: nothing reads ledger history, so the history has no
consumer to protect — it is an artefact of the write path, not a record anyone depends on. C also
has the property A and B lack: **it cannot partially fail.** A single new commit either has a raw
handle in its tree or it does not, and §8 checks it in one command instead of auditing 3,040 blob
rewrites and 1,585 message rewrites for misses. Given that §4 already caps what any of these buys,
paying the highest-complexity option for a marginally-better-preserved artefact nobody reads is a
bad trade.

**The honest cost of C:** the ledger's commit-level audit trail is gone — you lose the ability to
ask "when did this metrics value change" from git. If the maintainer weighs that as load-bearing,
take **A** (not B, for the salt reason above) and accept the verification burden. **B should be
rejected** unless the maintainer explicitly re-opens the decision `scripts/dashboard-gen.py:72-77`
records.

## 7. The runbook (option C)

Every step is the maintainer's, from a machine holding a credential able to force-update
`refs/heads/ledger`. **Do not automate this.** Steps are numbered so a partial execution can be
reported precisely.

**S0 — re-measure.** Do not trust §2's numbers at execution time; the branch has moved. Re-run the
§2.1 and §2.2 commands and record the outputs. If the last leaking commit is *newer* than
`d9a223192`, stop: a writer is still emitting raw handles and #212's fix is not fully deployed —
that is a different bug and this runbook is the wrong response.

**S1 — announce the window.** In-flight workers hold leases up to `ttl=3600`. A 90-minute window is
the smallest that both drains work and leaves room for S5–S8.

**S2 — quiesce the scheduled writers.** Disable every scheduled entry point that can reach a ledger
write:

```bash
for wf in dispatch.yml groom.yml groom-leases.yml metrics.yml auto-mint-provenance.yml \
          pat-validity.yml conflict-resolver.yml curate.yml latch-watchdog.yml \
          reconcile-conflict-park.yml dashboard.yml; do
  gh workflow disable "$wf" -R jeswr/agent-account-registry
done
```

Grounding and one honesty note: `dispatch.yml` (`3,13,23,33,43,53 * * * *`), `groom.yml`
(`7-59/15`), `groom-leases.yml` (`*/15`), `metrics.yml` (`11-59/15`), `auto-mint-provenance.yml`
(`13,43`), `pat-validity.yml` (`41 6 * * *`) are verified writers. `conflict-resolver.yml`
(`1,21,41`), `curate.yml` (`17,47`), `latch-watchdog.yml` (`9,19,29,39,49,59`) and
`reconcile-conflict-park.yml` (`16,36,56`) invoke `scripts/groom.py`; **I did not verify per-callsite
whether each reaches `_release_claims`**, so they are disabled conservatively. `dashboard.yml`
(`*/15`) is a reader, disabled only to avoid publishing a mid-window snapshot. `worker.yml`,
`review-fix.yml`, `mint-provenance.yml` and `backfill-provenance.yml` are `workflow_dispatch`-only
and stop once `dispatch.yml` stops issuing the doorbell — they do **not** need disabling, but they
**do** need draining (S3).

**S3 — drain.** Wait until no run is in flight. This is the step that actually protects the
create-only records in §5.2, and it is not satisfied by S2 alone:

```bash
gh run list -R jeswr/agent-account-registry --status in_progress --limit 100
gh run list -R jeswr/agent-account-registry --status queued --limit 100
```

Proceed only when both are empty **twice, five minutes apart**. Record the time.

**S4 — snapshot for rollback.** Before touching anything:

```bash
git fetch origin +refs/heads/ledger:refs/heads/ledger-preserve-536
git push origin refs/heads/ledger-preserve-536   # a PRIVATE-repo mirror is better; see §9
git rev-parse refs/heads/ledger-preserve-536     # record this SHA
```

§9 explains why this branch is a rollback aid and *not* a place to leave the data.

**S5 — build the replacement.** One orphan commit carrying the current tip tree:

```bash
git fetch origin ledger && git checkout -B ledger-rewrite origin/ledger
git checkout --orphan ledger-new && git add -A
git commit -m "ledger: data-only re-root — history purged of pre-#212 raw account identities (#536)"
```

**S6 — validate before pushing.** The new root must satisfy the data-only invariant, or every
reader workflow fails closed on its next run (`scripts/ledger-invariant.py`, run immediately after
each `ref: ledger` checkout):

```bash
python3 /path/to/master-checkout/scripts/ledger-invariant.py --root .   # confirm flags with --help
git ls-tree -r -t HEAD | head -50    # expect only README.md, data/*.json, orchestration/{provenance,review-verdicts}/*.json
git diff --stat origin/ledger HEAD   # MUST be empty: the tree is unchanged, only history is dropped
```

The `git diff --stat` being empty is the load-bearing check — it proves S5 preserved operational
state exactly, which is the whole basis of §5.1's "transparent to consumers" claim.

**S7 — force-update, then re-enable.** Only after S6 is clean:

```bash
git push --force-with-lease=refs/heads/ledger:$(git rev-parse origin/ledger) \
    origin HEAD:refs/heads/ledger
```

`--force-with-lease` (not bare `--force`) is what makes S3's drain enforceable: if a writer did land
a commit, the push is refused rather than silently discarding it. If it is refused, **go back to
S3** — do not retry with `--force`.

Then run §8, and only then:

```bash
for wf in dispatch.yml groom.yml groom-leases.yml metrics.yml auto-mint-provenance.yml \
          pat-validity.yml conflict-resolver.yml curate.yml latch-watchdog.yml \
          reconcile-conflict-park.yml dashboard.yml; do
  gh workflow enable "$wf" -R jeswr/agent-account-registry
done
```

**S8 — reconcile provenance.** Any PR merged during the window may have lost its record (§5.2).
Run the backfill in its dry-run mode first, inspect, then apply:

```bash
python3 scripts/backfill-provenance.py --policy-file policy/repos.toml --registry-repo jeswr/agent-account-registry
# then re-run with --apply if the dry run's plan is correct
```

## 8. Verification

Run against a **fresh** clone — an existing one retains the old objects locally and will produce a
false positive.

```bash
rm -rf /tmp/ledger-verify && git clone --single-branch --branch ledger \
  https://github.com/jeswr/agent-account-registry /tmp/ledger-verify && cd /tmp/ledger-verify

# 1. no raw handle in any reachable blob
git rev-list --objects --all | awk '{print $1}' | \
  while read o; do [ "$(git cat-file -t "$o")" = blob ] && git cat-file -p "$o" \
    | grep -l 'acct' >/dev/null && echo "LEAK-BLOB $o"; done

# 2. no raw handle in any reachable commit subject or body
git log --all --format='%H%n%B' | grep -nE 'acct[0-9]' && echo "LEAK-MSG" || echo "clean"

# 3. the tree still satisfies the data-only invariant
git ls-tree -r -t HEAD
```

Expect (1) and (2) to be silent, modulo the §2.4 `acct08` verdict-record occurrence **if** the
maintainer decided to retain it — which is why that decision must be made before S5, not
discovered here. Then confirm the fleet actually resumed: one `dispatch.yml` tick producing a claim,
one `metrics.yml` snapshot, and a `dashboard.yml` publish.

**State the result accurately.** The claim proven is *"no raw account handle is reachable from
`refs/heads/ledger`"*. Per §4 it is **not** *"the handles are unrecoverable"*, and the closing
comment on #536 should say so.

## 9. Rollback

Before S7, rollback is free — discard `ledger-new` and re-enable the workflows.

After S7, restore with `git push --force origin refs/heads/ledger-preserve-536:refs/heads/ledger`.

**But note the trap:** `ledger-preserve-536` on the origin is *itself a public branch containing
every raw handle* — pushing it re-publishes exactly what S7 removed, and leaving it in place makes
the whole operation a no-op. It exists only as a same-session safety net. Keep the authoritative
copy as a **local bundle** (`git bundle create ledger-536.bundle refs/heads/ledger-preserve-536`) or
in a private mirror, and **delete the remote preserve branch in the same window** once §8 passes:

```bash
git push origin --delete ledger-preserve-536
```

An operator who skips this deletion has not purged anything. This is the most likely way for this
runbook to fail in practice, which is why it is a numbered step and not a footnote.

## 10. Decision

1. **Adopt option C** — re-root `ledger` as a single orphan commit carrying the current tip tree.
   Rationale: no consumer reads ledger history (§5.1), C cannot partially fail, and it matches the
   branch's own precedent (`82ef87eba`).
2. **Widen #536's scope to commit subjects.** The 1,585 leaking subjects (§2.2) are the larger and
   more legible surface, and a `data/leases.json`-only rewrite as literally specified would leave
   them all. Option C covers them by construction; options A and B must handle them explicitly.
3. **Restate the acceptance criterion** as *"no raw handle reachable from `refs/heads/ledger`"*
   (§8), and file a GitHub Support request separately if the maintainer wants unreachable objects
   actually collected (§4).
4. **Reject option B** on the salt-secrecy argument in §6 unless the maintainer explicitly re-opens
   the decision recorded at `scripts/dashboard-gen.py:72-77`.
5. **Decide §2.4 before S5** — retain or purge the `acct08` occurrence in verdict record
   `dbbf9350`. My recommendation is retain; either way record it, so §8 does not surprise the
   operator.
6. **Do not treat this as a confidentiality fix for the handle strings.** They are open-issue titles
   (§3). If they must be secret, that is catalog rotation, which is a separate decision I am not
   recommending on this evidence.

## 11. What this record does not establish

- **It has not been executed.** Every number in §2 is a measurement of `origin/ledger` as fetched on
  2026-07-31; S0 exists because they will be stale.
- **It is not a security review.** I have measured what is exposed and what a rewrite removes. I
  have not assessed whether the account↔workload linkage is materially harmful in this project's
  threat model, and I do not assert that the post-rewrite state is "safe" — that judgement is the
  maintainer's, and the design of the salted-fingerprint scheme it rests on has not been audited
  here.
- **Third-party retention is unaudited** (§4). I cannot enumerate who mirrored the 1,585 subjects.
- **The quiesce list in S2 is conservative, not minimal.** Four workflows are disabled because they
  invoke `scripts/groom.py` and I did not trace whether each callsite reaches `_release_claims`. A
  narrower list is derivable with that tracing; the cost of the wide list is a longer stall, which
  is the right side to err on.
- **`ledger-invariant.py`'s exact CLI flags were not exercised** in S6 — confirm with `--help`.
- **No enforcement is added.** Nothing in the repo prevents a *future* raw identity from reaching
  the ledger tip; #212's guards drop legacy rows on *read* but no invariant asserts the property at
  the tip. Filed as follow-up rather than implemented, since this record changes no behaviour.
