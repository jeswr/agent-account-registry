# Generating the grant-scope expected-record manifest (issue #1027)

> 🤖 **SPARQ agent** — design record, 2026-08-03. Maintainer-review document. **Findings only: no
> script, workflow or policy behaviour changes with this record.**

`scripts/grant-scope-audit.py --expected-records` will not propose a revocation candidate until a
durable manifest asserts which provenance records the corpus must contain, and every one of them is
present (`grant-scope-audit.py:233-285`, `:339-401`). #1027 asks for a helper that **generates**
that manifest instead of the maintainer typing PR numbers, because a transcription slip that omits
PRs makes an incomplete corpus verify as complete — the false revocation the flag exists to close.

**Answer, in one line: the manifest must NOT be generated from the `ledger` branch's provenance
records.** That source is the corpus the audit is already reading, so a manifest derived from it is
a tautology and would turn `--expected-records` from a check into a rubber stamp — a strictly worse
outcome than hand-authoring, because the resulting manifest *looks* machine-derived. The
enumeration has to come from a source that is **independent of whether a record was written**: the
target repository's own worker-PR list. #1027 names both sources as alternatives; they are not
alternatives, and only the second one works.

## 1. What the flag actually checks today

| step | code | what it proves |
|---|---|---|
| manifest shape | `expected_records` (`grant-scope-audit.py:233`) | `window` non-blank, `records` a non-empty list of distinct positive ints, target is an audited enabled row |
| number → filename | `:280-282` via `record_prefix` | an entry can only ever assert completeness with **this** row's evidence |
| presence | `audit` `:353-354` | `claim["records"] - observed` is empty |
| filename ⇔ content | `record_fingerprint` `:194-230` | a file can only witness PR *N*'s record if the document under it says `pr_number == N` |

And what it does **not** check, which is exactly #1027's gap: nothing relates the manifest to the
window it claims to cover. `window` is a free-text string that is only tested for non-blankness
(`:261-265`). A manifest listing three of a window's forty PRs passes every check above and reports
`completeness: VERIFIED` (`render`, `:426-427`).

Note also that the audit **tolerates extra** records beyond the manifest (`:350-351`) — extra
evidence can only move a handle from candidate to evidenced, the safe direction. So the manifest is
a **lower bound on required presence**, and *under*-enumeration is the only dangerous direction.
Every design choice below follows from that asymmetry.

## 2. Candidate sources

| source | independent of the record corpus? | per-target? | verdict |
|---|---|---|---|
| `ledger` branch `orchestration/provenance/` listing | **no — it IS the corpus** | yes (filename prefix) | **reject**, §3 |
| target repo worker-PR list (`/repos/<t>/pulls?state=all`) | **yes** | yes | **recommend**, §4 |
| `data/leases.json` | yes | yes (`holder`) | live state only; `groom.py`'s release path removes the row and keeps no ring (`research/608-account-pool-grant-scope-audit.md`, evidence table) |
| `data/metrics-history.json` | yes | yes | throughput only; carries no PR or account identity |
| maintainer's memory (status quo) | yes | yes | the #1027 defect |

## 3. Why the `ledger` listing cannot be the source

The audit's corpus is a directory of record files (`read_corpus`, `:314-326`), and the whole point
of a complete audit is to point it at a **`ledger` checkout** — that is where records have been
written since #96, and it is why the registry's own row reads `0 records ->
insufficient-evidence` on `master` today (`research/608-account-pool-grant-scope-audit.md`, caveat
2). The listing `mint-provenance.recorded_pr_numbers` (`mint-provenance.py:971-995`) computes is
precisely the set of PR numbers that directory holds.

So if `expected := recorded_pr_numbers(...)` and `observed := read_corpus(<ledger checkout>)`, then
`claim["records"] - observed == ∅` **by construction**, for every target, always. The row is
unconditionally `scoped`, the candidate list is unconditionally the pool minus the observed
handles, and PR #1016's review round 1 is undone in one function.

The one thing the ledger listing *can* detect is **corpus staleness**: a live listing read at audit
time against an older local checkout surfaces records the checkout is missing. That is worth having
(§5, cross-check), but it must not be confused with the property the manifest asserts. A record that
was never written appears in neither the listing nor the checkout, and staleness detection is blind
to it by definition.

## 4. The enumeration that does work — with three corrections to #1027's phrasing

#1027's second suggestion, "the merged-PR list for the target", is the right family and the wrong
predicate in three places.

**4a. Not merged-only.** The record is written when the PR is **opened** — worker.yml's dedicated
`provenance` job runs after `publish` (`orchestration/provenance/README.md`, opening paragraph), and
`backfill-provenance.py` reconstructs the same records for pre-existing PRs. Merge state is not an
input. A worker PR that was closed unmerged therefore still has a record and still evidences that
its account did work for that target. Enumerating merged PRs only would omit them — under-
enumeration, the dangerous direction. Use `state=all`.

**4b. Window on `created_at`, not `merged_at`.** Same reason: the record-bearing event is the open.
`metrics._list_event_counts_1h` already draws exactly this distinction — `prs_opened` is windowed on
`created_at` over a `state=all&sort=created` read, while `prs_merged`/`prs_closed` are windowed on
`merged_at`/`closed_at` over a `state=closed` read (`scripts/metrics.py:506-546`).

**4c. Worker PRs are identified by head-branch grammar, not by author.** `sparq-agent/issue-<N>-…`
is the deterministic shape, and `worker-pr.WORKER_HEAD_RE` (`worker-pr.py:371`) is the single
existing definition of it; `backfill-provenance.parse_head_ref` reads the same shape. A generator
must import that definition rather than restate it — a second copy of the grammar is the #958 shape
this repo has already paid for, and here a gap between the copies is an **omitted PR**, i.e. a false
`scoped`.

A fourth requirement is structural rather than a correction: **the read must be complete or refuse,
and this is the one place the closest existing precedent must be inverted rather than copied.**
`metrics._list_event_rows` deliberately reads ONE bounded newest-first page and never paginates —
"event lists MUST NOT paginate without a bound" (`metrics.py:460-465`) — and when that page is
entirely in-window it warns that "count is a floor" (`_warn_truncated_window`, `:499-503`). A floor
is the correct answer for a throughput metric and the **wrong** answer here: a floor on the expected
set is precisely the omission that makes an incomplete corpus verify as complete. `recorded_pr_numbers`
states the rule this side needs — "no record exists" and "I could not tell" must never be the same
answer (`mint-provenance.py:980-983`) — so the generator must paginate to the window boundary and
**raise** on a ceiling, the `groom.WORKER_RUN_PAGE_CEILING` shape (`groom.py:2910`, `:2930`, with
its fail-closed self-test at `:4694-4715`), never return a floor.

### What this manifest still cannot prove

Stating these plainly, because a generated artifact invites more trust than a typed one:

1. **Record history ≠ claim history.** An account claimed by a run that failed before `publish`
   leaves no PR and no record, so it is invisible to *any* PR-derived manifest and would be a
   revocation candidate on a fully verified one. The durable claim history that would close this
   does not exist — `data/leases.json` is live state only. A revocation therefore rests on "this
   handle produced no PR for this target in the window", which is narrower than "this handle was
   never used by this target", and the maintainer should read it that way.
2. **The `window` string remains unverified by the audit.** Generating it removes the transcription
   risk; it does not make the audit able to check it. See the follow-up in §7.
3. **Window choice is a place selection bias can re-enter.** If the window is narrowed *after*
   seeing which records exist — until the gap happens to be empty — the manifest is once again
   describing the corpus rather than bounding it. The window must be an **input** to the generator,
   chosen on grounds independent of the record set (e.g. "since the ledger became the writer",
   "the trailing 30 days"), and the generated artifact should record that it was supplied, not
   derived.

## 5. What the artifact should contain

The deliverable is *reviewable evidence*, not just a number list. Minimum content, beyond the
`{"targets": {...}}` the audit consumes:

- the window bounds as supplied, and the exact query issued (repo, `state`, sort, page size);
- the number of pages read and whether the ceiling was reached;
- the head-branch grammar's source (`worker-pr.WORKER_HEAD_RE`), so a reviewer can see the
  enumeration was not re-derived;
- **the gap**: the manifest's PR numbers that have no record on `ledger` today. This is the
  cross-check from §3 used for the only thing it is good for, and it is the artifact's most useful
  line, because a non-empty gap tells the maintainer in advance that the audit will report
  `partial-evidence` and why.

One caution on computing that gap: `recorded_pr_numbers` reads the ledger provenance directory with
a **single, unpaginated** contents call (`mint-provenance.py:985-986`). The contents API caps a
directory listing (documented ceiling: 1,000 entries, worth re-confirming against current API docs
before relying on it) and there were 463 records on `ledger` at 2026-07-28
(`mint-provenance.py:804`). A truncated listing would under-report which records exist and so
**over**-report the gap — noisy but safe here, and unsafe in its existing caller. Either use the Git
Trees API for this read, or read the directory out of a `ledger` checkout, which the audit needs
anyway. Filed separately as a follow-up.

That gap has exactly two honest remedies, and the record should name both: **repair** the missing
records (`scripts/backfill-provenance.py` exists for precisely this population) or **accept the
refusal**. Narrowing the window to make the gap vanish is remedy three and is the bias in §4/point 3.

Any extra keys must be additive — `expected_records` reads `targets` and ignores unknown top-level
keys (`:250-253`), and per-target it reads `window`/`records` only (`:261-279`), so a `generated`
block alongside `targets` is consumed cleanly by today's audit.

## 6. Where it should run (the `workflows` question)

Three properties make this a good fit for its own read-only workflow, and one makes it a poor fit
for a schedule.

- **It needs no salt.** The generator only ever handles PR numbers and window bounds; `PROVENANCE_SALT`
  is required by the *audit's* mapping step (`--salt-env`, `:923-927`) and by nothing here. That is
  a real separation of duties: manifest generation can run in public CI with `contents: read`, while
  the mapped audit stays a maintainer-local gesture. Do not fold the two into one job — a job that
  holds the salt and also decides completeness concentrates both halves of a revocation.
- **It writes nothing.** No ledger PUT, no policy edit, no label. Output is an Actions artifact / a
  pasteable JSON blob; the manifest becomes durable only through a reviewed PR, which is the review
  step #1027 is asking for.
- **Its own file, per the `park-stock-alert.yml` / `ledger-identity-watch.yml` standing
  recommendation** (registry #1566, quoted in `ledger-identity-watch.yml`'s header): a new workflow
  has zero blast radius on existing lanes.
- **`workflow_dispatch` only, no `schedule:`.** A cached manifest is a manifest whose window is
  drifting out of date relative to the corpus it will be checked against, and a stale manifest
  under-enumerates by construction. Generate per audit, never in advance.

Cross-repo read: the target `sparq-org/sparq` is a different repository from the registry, so the
job needs a token that can list its pulls — the same access `auto-mint-provenance.py:1390` and
`backfill-provenance.py:783` (`state=open`) and `metrics._list_event_rows` (`state=all`) already
use against a target. What is *not* established by existing usage is a **fully paginated** window
read: every current caller is either current-state-only or explicitly single-page. So the page count
and rate-limit cost of a real window are unmeasured here; measure them on the first run rather than
assuming, and pick the window with that in mind.

## 7. Recommendation

1. **Reject** the ledger-derived manifest (§3). If #1027 is implemented as literally worded, the
   flag stops being a check.
2. **Implement** a read-only generator over the target's `state=all` PR list, filtered by
   `worker-pr.WORKER_HEAD_RE`, windowed on `created_at`, complete-or-refuse (§4), emitting the
   manifest plus the review evidence and the ledger gap (§5).
3. **Ship it as its own `workflow_dispatch` workflow with `contents: read` and no salt** (§6).
4. Keep the manifest a **reviewed, committed** artifact. The audit's requirement is a *durable*
   manifest; a blob pasted into a terminal is neither reviewable nor re-derivable.
5. Treat this record as **unreviewed on the trust question**. The reasoning above says the
   PR-derived manifest is *sound in the direction that matters* (under-enumeration is what it
   protects against, and every failure it can have makes the audit refuse rather than propose). That
   argument has not been adversarially reviewed, and it is the argument a revocation would rest on.
   It needs a second reader before an implementation is merged, and the implementation needs
   `--self-test` rows with positive controls for: an omitted PR, a truncated listing, a
   merged-only filter, and a window supplied vs. derived.

## 8. Open questions for the maintainer

- **Which window?** Nothing in the repo picks one. The natural candidate is "since records moved to
  `ledger` (#96)", because before that the corpus location is ambiguous — but the pre-#96 records on
  `master` are sparq-only and gapped, so a window that reaches back past #96 is very unlikely to
  verify.
- **One manifest or one per target?** The schema is multi-target and the audit refuses a manifest
  naming an unaudited target (`:254-258`), so a single file covering both enabled rows is simplest
  — at the cost of both rows' windows moving together.
- **Does the registry row have enough history to be worth auditing at all?** Its corpus is on
  `ledger`; its `master` count is 0. Until someone runs the audit against a `ledger` checkout, the
  size of that row's evidence is unknown, and this record does not guess at it.
