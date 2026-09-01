# Generating the grant-scope expected-record manifest instead of hand-authoring it (issue #1027)

> 🤖 SPARQ agent — design record. **Findings only: this record changes no behaviour and lands no
> script, workflow or policy edit.** It exists so the helper #1027 proposes is designed against the
> contract `scripts/grant-scope-audit.py` actually enforces, rather than against the sentence in
> the issue.

**Headline.** The helper is worth building, but **not in the shape the issue offers**. #1027 names
two interchangeable sources — "the `ledger` branch's provenance records, or the merged-PR list for
the target". They are not interchangeable: **deriving the manifest from the record listing makes
the completeness check vacuous by construction**, and *merged*-PR enumeration under-counts the
population the manifest must bound. Separately, two measurements taken while writing this record
say the helper is **not the first thing that should land**: the corpus the audit reads is today
**split across two branches with zero overlap**, and the ledger half is **already past the size at
which a directory listing truncates**. Both re-open the false-revocation path `--expected-records`
exists to close — mechanically, and with more confidence than a hand-typed list would carry.

Related records: `research/608-account-pool-grant-scope-audit.md` (the audit and the decision it
terminates in), `research/657-orchestrator-provenance-minting.md` (the ledger as the review loop's
root of trust).

---

## 1. The question

`scripts/grant-scope-audit.py --expected-records` will propose a revocation candidate only for a
row whose corpus is asserted complete and verified complete (`STATUS_SCOPED`,
`grant-scope-audit.py:84-86`, `339-391`). Today that assertion is a JSON file the maintainer types.
The audit validates its **shape** and verifies every record it names is **present**; it cannot
check that the manifest **enumerates the whole window**. A manifest that silently omits PRs makes a
partial corpus verify as complete, and every handle whose only evidence sat in the omitted PRs
becomes a revocation candidate. #1027 asks for a generator so the maintainer reviews a derived
artifact instead.

The question this record answers: **derived from what, and is the derivation sound?**

## 2. The contract a generated manifest must satisfy

Read out of `expected_records()` (`grant-scope-audit.py:233-285`) — these are hard refusals, not
preferences, so the generator must satisfy them or the audit exits 2:

| requirement | line | consequence for a generator |
|---|---|---|
| `{"targets": {"<owner>/<repo>": {"window": <str>, "records": [<int>, ...]}}}` | `250-251` | fixed schema; no extra top-level shape is read |
| every declared target must be an **enabled, audited** target | `253-258` | a generator sweeping targets must drop rows `policy/repos.toml` does not enable |
| `window` must be a non-empty string | `261-265` | **shape only — nothing binds the window to the records** (§5.3) |
| `records` must be non-empty | `266-270` | a target with zero in-window worker PRs must be **omitted**, never emitted as `[]` |
| positive `int` PR numbers, no duplicates, no bools | `271-279` | numbers, not filenames |
| numbers become `<owner>--<name>--pr<N>.json` under **the target they are declared for** | `280-282` | the generator cannot mis-file one row's evidence under another |

The audit then verifies presence by filename against the corpus it read
(`audit()`, `353-354`), and refuses any corpus record whose filename and internal `pr_number`
disagree (`record_fingerprint`, `194-230`). Nothing in that path inspects *where the manifest came
from*. That is the whole difficulty in §3.

## 3. The two proposed sources are not equivalent

### 3.1 A record-derived manifest is circular

The manifest's job is to answer "does the corpus contain every record it should?". If its `records`
list is derived by **listing the records**, the answer is yes by construction: every expected record
is present because the expectation was read off the same set. The audit cannot detect this — it
compares two sets and finds them equal, stamps `complete: true`, and unlocks
`revocation_candidates` (`grant-scope-audit.py:383-385`).

This is not a hypothetical mis-use. `research/608-account-pool-grant-scope-audit.md` closes by
telling the maintainer to run the audit "on a checkout that carries the `ledger` provenance
records". In exactly that gesture, a ledger-derived manifest and the audited corpus are the **same
tree**, so the completeness check is a tautology, and the flag that was added specifically to stop
"nonempty ⇒ complete" (PR #1016 review round 1) silently reinstates it — now with a generated
artifact's authority behind it.

The circularity is *conditional*, not absolute: a manifest derived from the ledger listing and
checked against a **master** corpus is a real cross-view claim. But that is the pairing nobody
wants (§4.1 shows those two sets are disjoint), and "sound only when the operator points it at a
different tree than it was generated from" is a property no machine check in this repo enforces.

**Verdict: a listing of existing records is a description of the corpus, never a bound on it.**

### 3.2 A PR-derived manifest is the only non-circular option — and it will look worse

Enumerating the target's worker PRs is independent of whether a record was ever written, so it can
say "PR #1451's record should exist and does not". That is the whole point.

The consequence must be stated honestly: **the rows will not verify as complete for a while.**
Records are written by worker.yml's dedicated `provenance` job (`.github/workflows/worker.yml:2024`,
`orchestration/provenance/README.md`), and `scripts/backfill-provenance.py` exists precisely
because that job has missed PRs. A PR-derived manifest surfaces every one of those holes as
`missing_records`, keeping the row `partial-evidence` and the candidate list empty
(`grant-scope-audit.py:386-390`). A maintainer expecting the generator to *unlock* the audit will
instead find it *blocks* the audit until the gaps are backfilled or explained.

That is the correct behaviour and it should be advertised as the feature, not apologised for: a
worker PR with no record is genuinely a hole in the evidence, and absence cannot prove disuse
across it. It is also the concrete reason hand-authoring drifts toward the circular source — the
honest list is the one that fails.

## 4. Two measurements that change the sequencing

Both were taken read-only against this checkout at `b08364598` with `git ls-tree origin/ledger`.

### 4.1 The corpus is split across two branches with **zero** overlap

```
master  orchestration/provenance/   33 records   sparq-org/sparq  #2434..#2542
                                     0 records   jeswr/agent-account-registry
ledger  orchestration/provenance/  656 records   sparq-org/sparq  #3434..#5907
                                   392 records   jeswr/agent-account-registry #228..#2007
```

No master record appears on `ledger` (checked file-by-file for master's set). The ranges do not
even touch: master holds the pre-#96 copies, `ledger` holds everything written since.

Production consumers read the **union** — `effective_record_body()` probes `ledger` first and falls
back to master (`scripts/mint-provenance.py:683-693`, mirrored in `backfill-provenance.py` and
groom's reader). **The audit does not.** `run()` reads exactly one `--provenance-dir`
(`grant-scope-audit.py:314-326`, `458-464`). So the gesture research/608 recommends — audit a
ledger checkout — drops 33 records that are *positive evidence of use*, and dropping positive
evidence of use is the one direction that manufactures revocation candidates. A ledger-derived
manifest would not expect those 33 either, so the row would verify `complete: true` and propose
narrowing on evidence that exists, is durable, and was simply not in the tree that was read.

**This defect is present today, before any generator is written.** A generator built on top of it
converts a maintainer's typing risk into a machine-endorsed one. Filed as a follow-up.

### 4.2 The ledger provenance directory is already past listing-truncation scale

`orchestration/provenance/` on `ledger` holds **1048** entries. GitHub's contents API documents a
1,000-entry ceiling on directory listings (above which it truncates and directs callers to the Git
Trees API, which sets its own `truncated` flag). The registry's only existing ledger reader,
`worker-pr._probe_registry_file()` (`scripts/worker-pr.py:2550-2566`), fetches **one path**, never a
listing — so nothing in this repo exercises that ceiling today, and the exact live behaviour should
be probed before an implementation relies on it.

What is not in doubt is the shape of the requirement: a manifest generator is a **completeness**
tool, so *any* truncation signal must be a refusal, never a shorter list. A silently clipped
listing produces exactly the omission #1027 was filed to eliminate. `git ls-tree -r origin/ledger`
(used for the measurements above, and the mechanism `scripts/ledger-invariant.py:28-31` already
uses on a ledger checkout) has no such cap and is the safer primitive — at the cost of a full
`git fetch origin ledger` in whatever runner does the work.

This matters even under the §3 recommendation: a PR-derived manifest still has to be *checked*
against a corpus, and the corpus assembly is where truncation would bite.

## 5. Designing the enumeration

### 5.1 Which PRs count

A worker PR is identified by its head branch. Two grammars exist and they are not the same:

- `worker-pr.WORKER_HEAD_RE` — `sparq-agent/issue-([1-9][0-9]*)-[A-Za-z0-9._-]+`
  (`scripts/worker-pr.py:371`), the loose test used across the arm/enumerate paths.
- `backfill-provenance.HEAD_RE` — `^sparq-agent/issue-([1-9][0-9]*)-([0-9]+)-([0-9]+)$`
  (`scripts/backfill-provenance.py:54`, parsed by `parse_head_ref`, `67-72`), the strict
  `issue-run-attempt` form.

A generator must pick one and say which. The loose form over-collects (it would expect records for
branches the strict writer never produced); the strict form under-collects any historical variant —
and under-collecting is the unsafe direction, because a missing expectation is a missing
completeness constraint. Recommendation: enumerate with the **loose** regex and report any PR that
matches loose-but-not-strict as a named, human-visible discrepancy rather than resolving it
silently.

Orchestrator-class PRs (`review_enrolment_authors`, records stamped `orchestrator:`) are a
different population, refused by `mint-provenance` inside the `sparq-agent/` namespace
(`WORKER_NAMESPACE_RE`) — they should not silently join a worker-PR manifest.

### 5.2 `merged` is the wrong filter

#1027 offers "the merged-PR list". Records are written at PR **open** (the `provenance` job
reconciles the head branch and stamps `head_sha_at_open`), so a worker PR that was closed unmerged
still consumed an account and still has a record naming it. Enumerating only merged PRs omits
those records from the expectation, which — by the §1 mechanism — lets the corpus verify complete
while missing them. **Enumerate every worker-shaped PR in the window regardless of final state**
(`state=all`).

### 5.3 The window has to become checkable

`window` is validated as a non-empty string and nothing else (`grant-scope-audit.py:261-265`); it is
echoed into `evidence_bounds` and the rendered report (`362-367`, `426-427`) purely for the reader.
So a generated manifest can stamp anything and the audit will accept it, including a window that
does not describe the records beside it, and including one generated months ago.

PR numbers are monotonic per repository, so a **PR-number range** (`#3434..#5907`) is a window the
audit could one day actually check against `records` — dates are not, without a second API read
per PR. A generator should emit both: the number range as the operative window and the date bounds
it was derived from as prose inside the same string. Tightening the audit to verify the range, and
to refuse a manifest older than some age, is a separate change (follow-up), and until it lands
**"generated" buys review-ability, not verification**.

> **Update (#1887): the range half of that has landed.** `window` must now be exactly
> `#<low>..#<high>` and every number in `records` must lie inside it — so a generator must emit the
> number range and **must not** append the derived date bounds to the same string (a window with
> trailing prose is refused; put the derivation in a separate key). The line above about the table's
> `window` row — *"shape only — nothing binds the window to the records"* — no longer describes the
> code. **Freshness is still unchecked**: nothing refuses a manifest generated months ago.

### 5.4 Enumeration hygiene the repo already fixed once

`scripts/metrics.py` is the prior art and its two rules transfer directly:

- **The search index is not authoritative.** `_list_open_rows` (`metrics.py:436-439`) states it:
  "GitHub's search index is eventually consistent, so it is forbidden for live state/label counts".
  `_search_count` (`422`) is used only for lag-tolerant 24h counts. A completeness manifest must use
  the paginated REST list, never `search/issues`.
- **No silent caps.** `_list_event_rows` (`460`) deliberately reads one bounded page and
  `_warn_truncated_window` (`499`) warns that the count is a floor. A *floor* is fine for a metric
  and fatal for a completeness claim: the generator must paginate to the window's low bound and
  **refuse** rather than warn if it cannot prove it reached it.

## 6. Options

| # | option | verdict |
|---|---|---|
| A | derive `records` from the `ledger` record listing | **reject** — circular whenever the manifest and the corpus are the same tree, which is the documented gesture (§3.1). Sound only as a *cross-view* check, which no code enforces. |
| B | derive from the target's **merged**-PR list | **reject as stated** — under-enumerates closed-unmerged worker PRs, re-opening a narrower version of the same hole (§5.2). |
| C | derive from **every worker-shaped PR in the window, any state**, via the paginated REST list | **recommend** — the only enumeration independent of the corpus. Will report real gaps and block `scoped` until they are resolved; that is the feature. |
| D | add manifest generation **inside** `grant-scope-audit.py` | **reject** — the audit's safety story is that it is offline, read-only and advisory (`grant-scope-audit.py:11-16`). Giving it a network read-path, and letting one process both assert and verify completeness, collapses the independence the manifest is *for*. |
| E | commit the generated manifest to master | **defer** — durability is genuinely wanted (#1016 asks for a *durable* manifest) and a reviewed PR is the right gate, but a committed manifest goes stale silently and the audit cannot tell (§5.3). Ship as a reviewed artifact first; commit only once the window is checkable. |

## 7. Recommendation

**Sequence matters more than the helper.**

1. **First, fix the corpus split (§4.1).** Either teach `grant-scope-audit.py` to read a union of
   provenance directories, or document a materialisation step that produces one directory holding
   `ledger ∪ master`, refusing on any conflicting duplicate. Until then, *any* manifest — hand-typed
   or generated — is checked against a corpus that is missing durable records, and a generator only
   makes the resulting proposal more credible.
2. **Then the generator**, as a standalone read-only script (`scripts/`-resident, its own
   non-vacuous `--self-test`, enrolled in `scripts/selftest-suite.txt` alongside
   `grant-scope-audit.py`), driven by a `workflow_dispatch`-only workflow that uploads the manifest
   as an artifact. `.github/workflows/mint-provenance.yml` is the closest template in the repo — a
   dispatch-only, per-gesture, read-only-by-default lane with the write mode behind an explicit
   flag; here there is no write mode at all. The maintainer downloads the artifact, reads it, and
   passes it to `--expected-records`.
3. Emit provenance **in** the manifest (which endpoint, which ref, which window, which head-branch
   regex, how many pages were read), because §3.1 means a reader cannot otherwise tell a
   PR-derived manifest from a circular one — and neither can the audit. The defence is that the
   generator is the only sanctioned producer and its output is reviewed, not that the audit checks
   it.
4. Fail closed on: any pagination truncation, any unreadable page, any target not enabled in
   `policy/repos.toml`, and any target with zero in-window worker PRs (omit the row; `records: []`
   is refused at `grant-scope-audit.py:266-270`).

The manifest carries target names and PR numbers only — no handles, no fingerprints — so it is safe
to publish in this public registry, unlike the mapped audit report.

## 8. What this record does not decide, and what is not known

- **It lands nothing.** No script, workflow or policy change is proposed here for immediate
  merge; the items above are follow-ups filed against this repo.
- **It does not claim the design is audited-sound.** The central weakness is stated plainly: no
  machine check in this repo can distinguish a manifest derived from the PR list from one derived
  from the record listing. Anyone reviewing the eventual implementation should treat that as the
  property to attack.
- **The contents-API listing ceiling is documented behaviour I did not exercise live** (this
  container holds no token and must not). The 1048-entry measurement is real; the truncation
  threshold should be probed before an implementation depends on it either way.
- **Whether every one of the 392 registry / 656 sparq ledger records corresponds to a worker PR
  that a PR-list enumeration would find** is unmeasured — the reverse direction (records with no
  matching in-window PR) would indicate a naming or window bug and is worth checking during
  implementation.
- **It does not decide the revocation.** #608 remains a maintainer decision, and nothing here
  narrows a pool.
