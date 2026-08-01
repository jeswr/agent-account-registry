# #739: the model-health ledger read is forward-INCOMPATIBLE — the decision record

> 🤖 **SPARQ agent** — design record for the change that ships alongside it in
> `scripts/model-health.py`. #739 is explicitly a *"needs a design decision"* issue that enumerates
> four options and recommends none; this record states which was taken, why the other three were
> not, what the choice does **not** buy, and the one-time obligation it leaves behind.

## 1. The defect, restated as a property

`data/model-health.json` on the `ledger` branch is a **single shared mutable blob**. A worker run's
registry checkout is pinned at **dispatch**, and its `model_health` job can execute tens of minutes
later, so **every registry deploy is a rolling upgrade with pre-merge readers still live** against
that one blob.

`validate_ledger` rejected any record carrying a field name outside a hard-coded allowlist, and it
raised on the **first** such record, so the failure was **whole-ledger**, not per-record. Therefore:

> Adding any field to a written record makes the entire ledger unreadable to every reader deployed
> before that commit, for as long as one such reader is still in flight.

#733 added `why_no_diff` to the writer and the reader in one commit (`3c79c6546`, 20:18:56Z). Three
runs dispatched at 20:02:33Z / 20:02:49Z / 20:13:18Z — before that epoch — died at 20:43 / 20:53
with `ValueError: model-health record has unexpected field(s) ['why_no_diff']`. It drained, but the
property is structural: **the next additive field repeats it automatically.**

The recorder was only the loudest victim. `validate_ledger` / `_validate_record` are also read by:

| reader | consequence of a whole-ledger raise |
| --- | --- |
| `model-health append_record` | the health record is LOST (the observed failure) |
| `dashboard-gen._normalize_ledger_health` | `DashboardError` — the public dashboard renders nothing |
| `account-usage` | the openai reactive backoff fails **open**: accounts admitted uncapped |
| `capacity_recovery_evidence` / `park_cause_provable` / `_readable_window` | fold to *no evidence* — the aged-out park exits silently freeze |

So the blast radius of an additive field was: lost capping/health telemetry, a blank dashboard, a
disabled rate-limit backoff, and frozen park exits — **precisely during a deploy**.

## 2. What is NOT in question

The strict allowlist is load-bearing and stays. #202's property — *a poisoned record must not
survive a reader* — is why the account is checked as a salted hash at **read** as well as write, why
`reset_hint` carries a Markdown-free grammar, and why `exit_class`/`provider` are catalog-bounded.
None of that moves. The tension to resolve was narrower than "strict vs lax":

> fail-closed on **hostile content** vs forward-compatible on **additive schema growth**.

## 3. The four options, and why option 3 (narrowed) wins

**Option 1 — two-phase rollout as policy** (land the reader's allowlist entry, wait out the maximum
worker-run lifetime, then land the writer). *Rejected as the primary mechanism.* It is a convention,
and there is no mechanism preventing the next one-PR addition; #739 says this itself. It is also
strictly weaker than option 3, which removes the need for the wait entirely after one bootstrap.

**Option 2 — version the records (`v`)**. *Rejected.* It does not solve the bootstrap it claims to:
a reader that predates `v` rejects `v` itself as an unexpected field, so the first deploy has the
identical outage, and every subsequent one is then free — which is exactly what option 3 delivers
**without** adding a field, a comparison rule, and a second validation mode to a trust surface.

**Option 4 — unpin the registry checkout for pure-registry jobs**. *Rejected here, not refuted.* It
would make readers always current, which addresses the cause rather than the symptom, but it changes
the **supply-chain posture** of those jobs (a job would run registry code that no reviewer of the
dispatching commit approved) and so needs security review on its own terms. It is also orthogonal:
it would not help any reader that is not a workflow job. Worth its own issue; not this change.

**Option 3 — make unknown-field rejection per-record rather than whole-ledger.** *Taken, but
narrowed in a way that removes the trade-off #739 flagged.* #739's phrasing was *drop the offending
record*, and noted that this "trades a telemetry gap for availability … a dropped record could be a
real capping signal". **We do not drop it.** The record is **read normally** — every field this
module knows is validated with the identical grammars — and the unrecognised field is carried
through untouched. There is no telemetry gap to argue about, and no soundness debt.

### 3.1 Prior art in this repo

The sibling ledger validator — `scripts/lease_schema.validate_ledger`, which guards the *lease*
ledger on the same `ledger` branch under the same CAS discipline — has **no unknown-field rejection
at all**: it validates the fields it knows and ignores the rest, and its only strict-shape rule is
at the document top level (`set(document) != {"leases"}`). So the lease plane has always been
forward-compatible, has never had this outage class, and has not been argued to be less safe for it.
The health ledger is now the *stricter* of the two, not the laxer: it additionally scans
unrecognised fields for the raw-handle pattern, which `lease_schema` does not do.

## 4. The mechanism as shipped

`_validate_record` takes an **`origin` with no default** (omitting it is a `TypeError`) that is also
**checked for membership in `RECORD_ORIGINS`** (anything else is a `ValueError`), so a future call
site must state its posture instead of inheriting the wrong one by omission *or* by typo. Requiring
the argument alone would not have been enough: `READ` is the permissive posture and would have been
the fallback of any `== ORIGIN_WRITE` test, so a misspelled write-side literal would have quietly
admitted undeclared fields. The two postures are:

- **`ORIGIN_WRITE`** — `make_record`, and the record `append_record` is introducing. The vocabulary
  (`RECORD_KNOWN_FIELDS`) is **CLOSED**; any undeclared field is refused outright, exactly as
  before. *This release can never PUT a field it has not declared.* Forward tolerance is therefore a
  property of records written by a **different** release, never a licence for this one.
- **`ORIGIN_READ`** — `validate_ledger` and the three park predicates. A field outside the
  vocabulary is tolerated when `_tolerable_unknown_field` accepts it, and refuses the whole document
  otherwise. Tolerated names are returned up to `validate_ledger`, which emits a `::warning::`
  naming them: **a reader behind its writer is never silent.**

`append_record` applies **both** at the one call site that actually PUTs — write posture on the
record it introduces, read posture on the assembled document — so a newer writer's field is neither
a blocker for the append nor silently **erased** by it (the read-modify-write rewrites the whole
blob; a stripping reader would downgrade the shared ledger on every append an older worker makes).

### 4.1 What `_tolerable_unknown_field` constrains, and what it deliberately does not

| aspect | rule | why |
| --- | --- | --- |
| field **name** | `_TOKEN_FIELD_RE`, non-empty, ≤ `RECORD_FIELD_MAX_LEN` | names are what the reader **prints**; a name carrying a newline could forge a `::` workflow annotation |
| number of unknown fields | ≤ `MAX_UNKNOWN_RECORD_FIELDS` (8) | additive growth adds one or two; an unbounded key count is a size vector on a public read |
| field **value** — handle pattern | rendered value must not embed `acct[0-9]` | **the ledger is PUBLIC**; the raw-handle invariant is universal (README *Security posture*, locked decision 22a) |
| field **value** — type / shape / length | **unconstrained** | see below |

Leaving the value's shape free is the load-bearing choice, and it is what makes this a fix rather
than a narrower repeat of the bug: constraining it to "a bounded string or int" would re-create the
**identical** incompatibility the moment a future field is a list or an object. It is sound because
an unrecognised field has **no sink** — every consumer of a health record reads fields **by name**,
so an unknown one is never folded, compared, or interpolated into an alert body. The sink-specific
grammars exist for fields that *are* republished (`reset_hint` → the Markdown alert body); an
unrecognised field is republished nowhere. Its bytes are still counted by `_record_bytes` and
bounded by `RETENTION_CEILING_BYTES`.

## 5. The one-time bootstrap obligation

Readers deployed **before** this change are still strict. This change therefore has to age out of
the in-flight worker population before the next additive field is written — the same wait option 1
would have imposed, paid **once** instead of at every field addition.

Concretely: **do not land a new written field in the same wave as this change.** After it has been
on `master` longer than the maximum worker-run lifetime, additive fields need no coordination at
all — which is the whole point of preferring this over option 1.

This record does not claim the wait is enforced by anything. It is the last time it is needed, so a
mechanism to enforce a one-off would cost more than it protects; if a field addition is proposed
before the drain completes, this section is the reason to defer it.

## 6. Verification

`scripts/model-health.py --self-test`, `_test_forward_compatibility`, pins **both** directions —
the read side tolerating a later release's field and the write side still refusing one — because a
test of only the first is indistinguishable from a relaxation. Its headline row is the regression
test #739 asks for, stated the way #739 states it:

> validate what **this** release writes with a reader **one release behind** —
> `validate_ledger({"records": [make_record(..., why_no_diff=...)]}, known=RECORD_KNOWN_FIELDS - {"why_no_diff"})`

which drives the identical allowlist line that produced the three tracebacks.

Measured on the shipped tree: **508 checks green**; a 20-mutant sweep over every guard the change
adds or touches (delete + conditionally-inert per guard, plus the cap's *value*, the `origin`
default, the `append_record` seam, and a re-strictened read posture) — **20 killed, 0 survivors**,
every kill a line-anchored named `FAIL` row, every mutant run completing all 508 checks (no
crash-after-partial-run). `trace --count --missing` reports **0 never-executed lines** in
`validate_ledger`, `_validate_record` and `_tolerable_unknown_field`; the instrument was validated
against `main`, which is never called under `--self-test` and reports 19.

Three document-shape guards in `validate_ledger`/`_validate_record` were found **never executed** by
the suite during that audit (individually deletable with everything green) and are now covered.
