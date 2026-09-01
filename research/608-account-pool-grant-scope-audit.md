# Grant-scope audit: are the pre-#579 `account_pool` grants actually needed? (issue #608)

**Status:** audit complete, **no revocation landed**. The remaining step is a maintainer decision.
**Tool:** `scripts/grant-scope-audit.py` (read-only; `--self-test` enrolled in the registry gate).

## The finding

Both enabled rows in `policy/repos.toml` still carry the **identical** 8-handle pool:

```
sparq-org/sparq            acct01 acct02 acct04 acct05 acct07 acct2css acct3css acct4css
jeswr/agent-account-registry   (byte-identical list)
```

That is not a coincidence and not a decision — it is the residue of the document-wide append
`scripts/grant-account.py` was written to retire (#579, "THE DEFECT THIS MODULE EXISTS TO
PREVENT"). #579 scoped every *new* enrollment and deliberately did not touch the existing rows, so
every pre-#579 account remains usable by every enabled target. (The pool is 8 handles, not the 10
#608 quotes: `acct03`/`acct06` were retired from both rows on 2026-07-25.)

`scripts/grant-scope-audit.py` reports the condition directly, as `shared_pool_groups`.

## What evidence exists — and what it cannot prove

#608 suggests `scripts/account-usage.py` or the leases ledger. **Neither can answer the question.**

| source | durable? | per-target? | verdict |
|---|---|---|---|
| `data/leases.json` | no | yes (`holder` = `owner/repo#N@run`) | live state only — `groom.py`'s release path *removes* the entry and keeps no ring, so it can sample the present, never the past |
| `scripts/account-usage.py` | no | **no** | a live rate-limit-headroom probe per account, with no repository attribution at all |
| `data/metrics-history.json` | yes | yes | throughput per target; carries no account identity |
| `orchestration/provenance/<owner>--<name>--pr<N>.json` | **yes** | **yes** | one record per worker PR: the filename names the target, `impl_account_h` names the account |

So the provenance corpus is the only source that answers #608, and the audit reads that.

### Today's numbers, from the corpus on `master`

```
sparq-org/sparq                33 records across 8 distinct accounts
jeswr/agent-account-registry    0 records   -> insufficient-evidence
```

Three honest caveats, all of which are why this document does not propose a revocation:

1. **8 distinct accounts is not "all 8 granted accounts".** Without `PROVENANCE_SALT` a
   fingerprint cannot be mapped to a handle, and the retired `acct03`/`acct06` served sparq during
   this window — so some of those 8 may be handles the pool no longer lists. The audit reports the
   count, and refuses to name handles, until it is given a salt.
2. **The registry's 0 is missing evidence, not disuse.** This repo demonstrably drains its own
   backlog (its own merged worker PRs), so records for it exist — on the `ledger` branch, which is
   where records have been written since #96; the copies on `master` are the pre-#96 location that
   `effective_record_body` still reads as a fallback, and they are sparq-only. A complete audit
   needs a `ledger` checkout.
3. **sparq's 33 is missing evidence too — just less obviously.** For the same #96 reason the
   `master` corpus is a partial sample of that row's history (its PR numbers have gaps), and on a
   partial corpus "no record names this handle" is indistinguishable from "the record that named
   it is not in this checkout". A *nonempty* corpus is therefore no more a licence to revoke than
   an empty one, so the audit will not propose a candidate from a corpus whose completeness has
   not been independently established (see below).

All three inputs — the salt, the `ledger` corpus, and the enumeration of the PRs that corpus must
contain — are available to the maintainer and not to a worker, which is the concrete reason this
issue terminates in a human decision rather than a PR.

## How the tool refuses to cause the accident it is auditing for

The dangerous failure mode is proposing a revocation that is really just missing evidence.

- A target with **zero records** is `insufficient-evidence` and proposes **nothing** — an
  unevidenced pool is never reported as an unused pool.
- A target with records but **no verified completeness claim** is `partial-evidence` and also
  proposes **nothing**: the handles actually observed are named (a record naming a handle proves
  use on any corpus), and the candidate list stays empty (absence proves disuse only on a corpus
  known to hold every record). Completeness is never inferred from the record count — it must be
  **asserted** by a durable expected-record manifest (`--expected-records`: per target, an
  observation `window` and the PR numbers that corpus must contain, derived from the `ledger`
  branch / PR list) and **verified** here: if any expected record is absent, the row stays
  `partial-evidence`. This is what keeps caveat 3 above from becoming a false revocation.
- Verification is **by filename**, so each filename must be worth trusting: a record's name is
  parsed exactly (`<owner>--<name>--pr<N>.json`) and must agree with the `pr_number` **inside** the
  document, or the audit refuses. Otherwise a record parked under another PR's name would witness a
  record that is really missing, and an incomplete corpus would verify as complete — the false
  revocation this whole tool exists to prevent, re-entering through the completeness check itself.
- **Mapping is opt-in** (`--salt-env`). Unmapped, *no* target ever yields a candidate, because
  every granted handle is unknown rather than unused. This is the default, so the tool is
  advisory-safe to run anywhere.
- An evidenced fingerprint that **no granted handle explains** (a retired handle, or one granted
  to another row) is counted and surfaced, never silently dropped.
- Any unreadable record **refuses the whole audit**. Skipping one would quietly shrink the evidence
  for exactly the row about to be narrowed.
- No report — text or JSON, mapped or not — ever emits a fingerprint, so it stays safe to paste
  into this public registry. Only handles `policy/repos.toml` already lists in the clear.
- Exit status is `0` whether or not candidates are found. Gating CI on this would turn an unmade
  decision into an outage.

Each of these is a `--self-test` assertion with a positive control, not a claim in this file.

## The decision, and the exact next gesture

Deciding to narrow a row is a **revocation of a live capability**: an in-flight claim against a
handle removed from a pool fails `policy-resolve` / `select-and-claim.claim()` / worker.yml's
independent re-check. A worker must not make that call unilaterally, which is why #608 is filed as
an audit and closes with this record rather than with a policy diff.

For the maintainer, on a checkout that carries the `ledger` provenance records, with
`expected.json` naming — per target — the observation window and every worker PR that window
contains
(`{"targets": {"sparq-org/sparq": {"window": "#2434..#2542", "records": [2434, 2439, ...]}}}`):

The `window` is an **inclusive PR-number range** and every number in `records` must lie inside it
(#1887) — the audit refuses a manifest whose stated scope and whose record list describe different
populations. A date range is not accepted: no provenance record carries a timestamp, so a date
window would be text the reader is asked to take on trust.

```
PROVENANCE_SALT=... python3 scripts/grant-scope-audit.py \
    --salt-env --expected-records expected.json --json
```

Both opt-ins are required: without the salt no fingerprint maps to a handle, and without a
manifest whose every record is present the row is `partial-evidence` and proposes nothing. That
is deliberate — the manifest is the maintainer *asserting* what the corpus must contain, which is
the only thing that turns "this handle appears in no record" into "this handle was not used".

Then, **one reviewed `policy/repos.toml` change per revocation** — never a batch. The scoping
primitives to prove such an edit is exactly bounded already exist in `scripts/grant-account.py`:
`verify_grant` (every other row byte-identical, every changed line inside the intended row and an
`account_pool` assignment) and `verify_membership` (per-target exactness on a single document).
Note that both are written for the *grant* direction; a revocation is the inverse edit and would
need its own postcondition helper before it is applied by anything other than a human hand.
