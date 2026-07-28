# #914: account identity is a TITLE — bind it to a write-gated ref namespace

> 🤖 **SPARQ agent** — design record, 2026-07-28. Maintainer-review document.
> **This record changes no behaviour.** #914 asks for a cross-cutting redesign and says in its
> own body that it "wants a design record and explicit sign-off before any code moves". This is
> that record. It specifies the mechanism, argues its soundness, states plainly what it does
> **not** buy, maps the blast radius against verified line numbers, names a defect in
> `dispatch-secrets-guard.py` that the redesign would otherwise walk straight into, **removes**
> one of the four touch-points #914 assumed, and fixes the sequencing so no PR in the series is
> ever in a state where an already-enrolled account cannot activate.

## 0. State of the tree this record was written against

`master` @ `56af34c7d`. Two corrections to #914's premise, which was written from the PR #895
working tree:

- **PR #895 / #394 is NOT merged here.** The register step (`set-up-account.yml:770-827`) ends at
  `gh issue create` (`:824`) and performs **no** post-create re-read, discards the created issue
  number, and has no self-retraction path. There is no `outsider_late` self-test row anywhere in
  the tree, and the `activate_inline` alarm branch (`:1263`) does not yet carry the "retract the
  intruder, not the broker's record" recovery text.
- What **is** merged is #896 (commit `d07301db3`): both activation paths resolve the account issue
  through the authoritative, fully paginated issues API rather than the search index, from a
  sentinel-delimited fragment (`:1153` `# >>> resolve-account-issue` … `:1191` `# <<<`) that
  `scripts/grant-account.py --self-test` **extracts and executes** against a fake `gh`
  (`grant-account.py:2228`, and the merged-path twin at `:1906`/`:2019`).

Everything below is stated against this tree. Where #895 lands first, §5 and §6 compose with it
rather than conflicting: #895 hardens the *creation* side, this record replaces the *identity*.

## 1. The defect

`HANDLE` is minted at `set-up-account.yml:728` (`HANDLE=$(printf 'acct%02d' "$claimed")`) and the
account record is created with that string as its **title** (`:824-827`). Both activation paths
then resolve handle → issue number by exact title match over the issues API and require **exactly
one**:

```bash
if [ "${#nums[@]}" -ne 1 ]; then
  echo "::error::expected exactly one account issue titled '$HANDLE' in any state, found ${#nums[@]} — refusing to activate (fail closed)"; exit 1
fi
```

(`:1187-1189` inline, and the identical assertion on the merged path.)

An issue title is not a capability. On a public repo anyone may open an issue with any title at
any moment, and `.github/ISSUE_TEMPLATE/account.yml` carries `labels: [account]`, which GitHub
applies regardless of the author's permission — so the `account` label is not a barrier either.
A single drive-by issue titled `acct05` therefore drives `${#nums[@]}` to 2 **forever**, and both
activation paths refuse **forever**. The slot's claim ref is never released (by design, #186), so
the slot is burned and the credential is stranded.

The wedge is bounded but real, and it is worth being exact about the bound, because it decides how
much machinery is justified:

- The intruder is **allocator-inert**. `read_accounts` (`select-and-claim.py:946-961`) reads only
  `--state open` and sets `a["available"] = "status:available" in _issue_label_names(it)` (`:958`);
  `choose_account` dispatches on that flag. A public writer cannot apply `status:available` — that
  is a `triage`/maintainer label. So the intruder never gets claimed and never gets a token.
- The intruder is **activation-fatal**. It permanently wedges the exactly-one gate above.

So the exposure is **denial of service against enrollment and re-activation**, not credential
disclosure or misallocation. That is the honest framing, and #914's own wording ("permanently
wedge") matches it.

## 2. Why no number of reads closes it

This is the structural point, and it is the same shape as the one that killed the R0-only fix in
[`329-pre-migration-writer-recovery.md`](329-pre-migration-writer-recovery.md) §2: **a uniqueness
check is only true at the instant it is taken, and the state it authorises outlives it.**

1. GitHub exposes no atomic create-if-title-absent. `gh issue create` cannot be conditioned on the
   title being free.
2. A post-create re-read (what #895 adds) proves uniqueness *as of the read*. An issue filed one
   millisecond later, or an hour after the workflow exits, is not covered.
3. The `refs/acct-claims/` claim ref (#186) serialises only writers **inside** the protocol. It
   says nothing about what an outsider may title an issue.

Each additional read moves the window; none closes it. The window can only be closed by resolving
identity through a store an outsider **cannot write at all**.

## 3. The alternatives that die first

### 3.1 The existing claim ref cannot double as the binding

The tempting minimal move is to make `refs/acct-claims/<handle>` itself carry the issue number.
It cannot, for two independent reasons:

- **Ordering.** The claim is created at `:715`, *before* the handle exists (`:728`) and long before
  the issue exists (`:824`) — necessarily so, because the claim is what *determines* the handle,
  which determines the title. At claim time there is no issue number to encode.
- **Mutability.** Encoding it later means `PATCH`ing the ref, and the claim's entire value is that
  it is create-only and first-writer-wins (`README.md:283-287`: "never delete a claim ref"). A
  namespace that is updated in place is no longer a first-writer-wins allocation record. Making
  the claim mutable to fix a uniqueness bug would weaken the mutual exclusion that #237 installed.

A **second, separate** namespace is therefore not incidental to the design — it is forced.

### 3.2 A ref pointing at content is not available cheaply

Storing the number as ref *content* (a blob/commit whose text is the number) requires writing a
git object before the ref, doubles the failure surface, and needs a second API round-trip to read.
Putting the number in the ref **name** — `refs/acct-records/<handle>/<issue-number>` — needs no
object write and reads in one `git/matching-refs/` listing. #914's proposed shape is the right one.

### 3.3 Hardening `select_account_issues` is not a fix, and is not needed

#914 lists `select_account_issues`' `acct<digits>` grammar
(`select-and-claim.py:763` `ACCOUNT_ISSUE_TITLE_RE = re.compile(r"acct[0-9]+")`, used at `:873`)
as a touch-point. **It should not be touched, and this record recommends dropping it from scope.**

- It is not the authority. Per §1, the intruder is already inert at the allocator because it can
  never carry `status:available`. Tightening the *selector* does not un-wedge activation, which is
  the actual defect.
- Making the selector consult the ref namespace would put a network listing in the dispatch and
  worker claim hot path (`read_accounts` already shells out to `gh issue list`), adding a new
  failure mode to the busiest fail-closed boundary in the repo in exchange for no security gain.
- The selector is deliberately *structural and permissive* (its docstring: "Everything else is
  outside the catalog and is silently ignored rather than parsed-and-dropped as corruption").
  Narrowing it would be actively wrong: `acct[0-9]+` already fails to match three of the eight
  enrolled handles (`acct2css`, `acct3css`, `acct4css` — `policy/repos.toml:97`), which reach the
  catalog only via the `account` label / valid-front-matter arms at `:874-876`. The title regex is
  one of three disjuncts precisely so it does not have to be exhaustive.

Removing this touch-point takes `select-and-claim.py` — the largest and most load-bearing script in
the series — out of the change set entirely.

## 4. The mechanism

### 4.1 The namespace

```
refs/acct-records/<handle>/<issue-number>
```

e.g. `refs/acct-records/acct05/1234`. Written by the **register** step immediately after
`gh issue create`; read by both activation paths in place of the exact-title match.

**The handle component must use the canonical grammar, not `acctNN`.** The canonical account
handle is `^acct[0-9a-z]{2,}$` (`grant-account.py:71` `HANDLE_RE`, mirrored as
`policy-resolve.py:160` `ACCOUNT_HANDLE_RE`, and enforced against the pool at
`policy-resolve.py:220`). The broker only ever mints the `acct%02d` sub-shape, but the live pool
also contains `acct2css`, `acct3css`, `acct4css` (`policy/repos.toml:97`, `:142`) — which do **not**
match `select-and-claim.py:763`'s `acct[0-9]+`, nor the slot-union's `^acct[0-9]+$` jq filters. Any
regex the guard (§5.2) or the backfill (§7) applies to the handle component must therefore be
`acct[0-9a-z]{2,}`; assuming `acctNN` would silently exclude three of the eight enrolled handles.
Both grammars are ref-name-safe (lowercase alphanumerics only), so no escaping is required.

Ref creation via `POST /repos/{owner}/{repo}/git/refs` requires push access. This is the whole
point: an outsider can create an *issue* titled `acct05`, and cannot create a *ref* under
`refs/acct-records/acct05/`.

### 4.2 The write (register step, after `:824`)

```
n_created  := issue number captured from `gh issue create` output
assert n_created matches ^[0-9]+$        # fail closed; never interpolate unvalidated text into an API path
create ref refs/acct-records/$HANDLE/$n_created  -> $GITHUB_SHA
```

Three fail-closed obligations:

1. **Capture must be checked.** The register step currently discards `gh issue create`'s output.
   The number must be parsed from the returned URL and asserted digits-only before it reaches the
   ref name — an unvalidated capture is a path-injection sink into the git API.
2. **A failed binding write fails the step.** Not `|| true`, no warning-and-continue.
3. **`already exists` is a hard refusal here, unlike the claim.** At `:715-724` a colliding claim
   means "another writer took the slot, re-derive". A colliding *binding* means this handle already
   has a record bound to this number — which, given the claim ref guarantees a single protocol
   writer per handle, is a re-run, and must be treated as idempotent-success only if the existing
   ref is for the number we just created. Any other collision is a state corruption and must die.

### 4.3 The read (both activation paths, replacing `:1153-1191` and its merged-path twin)

```
list refs matching refs/acct-records/$HANDLE/     # gh api --paginate, fail closed on non-zero
parse -> numbers                                  # fail closed on parse failure, separately
require exactly one                               # fail closed on 0 and on >1, with distinct messages
num := that number
```

The three-way refusal split (**unreadable** / **unparseable** / **wrong count**) is not optional
polish — it is the invariant #896 review round 1 installed on this exact fragment, and the existing
self-test rows assert the *diagnostic text* precisely so a transient API failure can never be
reported as "found 0". A `git/matching-refs/` listing that matches nothing returns `[]` with exit
0, so zero-matches and unreadable are genuinely distinguishable and must stay so.

The sentinel comments (`# >>> resolve-account-issue` / `# <<<`) **must survive**: `workflow_block`
extracts the fragment by them and fails closed if either is removed.

### 4.4 What this buys, and what it does not — stated plainly

**Buys:** the outsider wedge is eliminated. A drive-by issue titled `acct05` becomes irrelevant
rather than fatal: activation never consults titles, resolves through a namespace the outsider
cannot write, and flips only the bound issue number. Registration no longer needs to prove title
uniqueness at all, because title uniqueness stops being load-bearing.

**Does not buy — and the implementing PR must not claim otherwise:**

- **This is not atomicity over the handle.** `refs/acct-claims/<handle>` is first-writer-wins on
  the *handle*. `refs/acct-records/<handle>/<N>` is first-writer-wins on the *pair*, so two
  different numbers are two different refs and both are creatable. What makes the binding unique is
  the composition: only the holder of the claim ref ever writes under that handle's record prefix,
  and the claim is first-writer-wins. The guarantee is therefore "**exactly one, among
  protocol-following writers with push access**", not "exactly one, unconditionally". An actor with
  push access going off-protocol can still create a second binding — and activation's exactly-one
  assertion is what catches that, fail-closed.
- **The write window survives, in fail-closed form.** GitHub assigns the issue number, so the
  binding cannot precede the issue; §4.2's window between `gh issue create` and the ref write is
  irreducible. Crashing inside it leaves a record issue with no binding. That state now **refuses
  to activate** (previously it would have activated on title alone), which is the correct
  direction, and §5.4 requires the alarm to name it with an operator recovery.

The move is a threat-model reduction from *any anonymous public writer* to *an actor who already
has push access to the registry* — who, having push access, can do considerably worse than wedge a
slot. That is the honest claim and it is the one worth making.

## 5. Blast radius

### 5.1 `.github/workflows/set-up-account.yml` — three edits

| # | Where | Change |
|---|---|---|
| A | register step, after `:824` | capture + validate the issue number; create the binding ref (§4.2) |
| B | `activate_inline`, `:1153-1191` | replace the title match with the binding read (§4.3); keep the sentinels |
| C | `activate_merged` (the `# <<<`-delimited twin near `:1337`) | the same replacement |

### 5.2 `scripts/dispatch-secrets-guard.py` — a real defect the redesign walks into

**Finding (verified, and it is the reason this record exists rather than a patch).** The
claim-shape guard captures **only the first** `git/refs` mutation it sees, at `:1589`:

```python
if claim_index is None and SETUP_ACCOUNT_CLAIM_RE.search(line):
    claim_index = index
    claim_text = joined(index)
```

and then asserts, hardcoded at `:1649-1653`, that `claim_text` contains
`refs/acct-claims/$cand`. `SETUP_ACCOUNT_CLAIM_RE` (`:1421-1422`) matches the `git/refs` *endpoint*
and is blind to the namespace.

Two consequences:

- **The binding write is entirely ungated today.** `setup_account_union_verdict` is handed
  `step_lines` for the **store** step only (`:1545`, "store step (`id: store`) not found"), so the
  register step's new `git/refs` call is invisible to it. (This is already demonstrable: the
  `refs/heads/<branch>` creation at `:1069` lives in the policy-PR step and trips nothing.) A
  binding write that bound the wrong number, or a handle the union never blessed, would pass every
  existing check green.
- **It is order-fragile if the two writes ever share a step.** Should a future edit move the
  binding write into the store step, whichever `git/refs` call appears first wins `claim_text` — so
  the binding would be checked against `refs/acct-claims/$cand` and refuse, or the real claim would
  go unchecked. Either way the guard mis-binds silently.

**Required:** a new `setup_account_binding_verdict(step_lines)` over the **register** step, asserting
(a) an issue-number capture exists and is digits-validated before use, (b) a `git/refs` creation
whose ref is `refs/acct-records/$HANDLE/$<captured>`, and (c) the create is textually **after** the
`gh issue create`. Plus, at minimum, making the namespace assertion at `:1649-1653` explicit about
*which* `git/refs` occurrence it binds, so the order-fragility is closed rather than left latent.

**Open question for sign-off (§8 Q2):** whether `git/matching-refs/acct-records/` should join
`SETUP_ACCOUNT_UNION_REQUIRED` (`:1406-1411`) as a fifth pre-claim listing. The union's doctrine is
"if an allocation record exists anywhere, the slot is taken", and a record ref is such a record.
Against: a record ref can only exist where a claim ref already exists (§4.2 writes strictly after
`:715`), so it is provably redundant, and each added listing is a new hard failure mode in the
enrollment path. This record's recommendation is **add it** — the redundancy is cheap, strictly
fail-closed, and the doctrine is worth more than the round-trip — but it is a judgement call and is
flagged as such rather than assumed. Note the mechanical constraint: `SETUP_ACCOUNT_LISTING_RE`
(`:1414-1416`) only recognises the exact form
`VAR=$(gh api --paginate "repos/${{ github.repository }}/<path>"`, so the new listing must be
written in precisely that shape or it will read as absent.

### 5.3 `scripts/grant-account.py` — the executed-fragment harness

No production-code change; the self-test grows (§6). This file already contains exactly the harness
the redesign needs: `workflow_block(workflow, "activate_inline", "resolve-account-issue")`
(`:2228`) extracts the real fragment and runs it under `bash -c` against a fake `gh`, with the
merged-path equivalent at `:1906`/`:2019`. The fake `gh` must learn to serve
`api --paginate .../git/matching-refs/acct-records/<handle>/`, including its failure and
truncated-page modes.

### 5.4 The `always()` alarm (`:1236-1266`)

The `REGISTER` branch (`:1256`) currently reads "the `status:pending` account issue was not
created". After §4.2 the register step has two distinct partial states — *issue created, binding
not* and *neither created* — with different recoveries. The alarm must distinguish them and, for
the former, tell the operator to create `refs/acct-records/<handle>/<number>` for the issue this run
created (whose number the step log carries) rather than to retract anything.

### 5.5 `README.md`

The runbook at `:242-287` documents the claim protocol as the complete manual-enrollment contract.
A manual enroller who creates a claim ref and an issue but no binding produces an account that can
never activate. The binding write must be added to that runbook in the same PR as §4.2.

### 5.6 Not touched

`scripts/select-and-claim.py` — see §3.3. `policy/repos.toml` — the account_pool is keyed by handle
and is unaffected. `scripts/policy-resolve.py` `RETIRED_ACCOUNTS` — unaffected.

## 6. The self-tests that must ship

Non-vacuous in **both** directions, per the repo's standing rule. The existing rows in
`grant-account.py` are the template: each asserts an *outcome tuple including diagnostic text*, and
several assert the **absence** of a string (`"found 1" in output` → `False`) precisely so a
fail-open cannot pass.

**Resolution (executed against the fake `gh`, both paths — inline and merged):**

| row | state | required outcome |
|---|---|---|
| resolvable | exactly one binding ref | exit 0, resolves to that number |
| absent | no binding ref (`[]`) | exit 1, "no binding" diagnostic, **not** the unreadable one |
| duplicated | two binding refs under the handle | exit 1, names the count |
| unreadable | listing exits non-zero | exit 1, refuses **as a failed enumeration**, and asserts `"found 0" not in output` |
| unparseable | listing truncated after a match | exit 1, refuses **as a parse failure**, and asserts `"found 1" not in output` |
| title-irrelevant | one binding ref **plus** a hostile same-title issue | exit 0, resolves to the **bound** number — this row is the whole point of #914 and must exist |
| near-miss | a ref under `refs/acct-records/acct050/` while resolving `acct05` | ignored, not a match |

**Guard (`dispatch-secrets-guard.py`, synthetic-workflow fixtures in the style of
`store_step_sample` at `:2204-2222`):** a good register-step sample passes, and each of these
mutations must go **red** —

- the binding `git/refs` creation deleted;
- its ref severed from the captured number (the direct analogue of the existing `unbound_claim`
  mutation at `:2270-2271`, which rewrites `ref="refs/acct-claims/$cand"` to a hardcoded handle);
- the digits-only assertion on the captured number deleted;
- the binding write moved textually **before** `gh issue create`;
- a second `git/refs` call added to the store step, proving the order-fragility of §5.2 is closed
  rather than merely described.

Every mutation row must be shown failing for the *stated* reason, not merely failing.

## 7. Sequencing — three PRs, and why it cannot be one

**Already-enrolled accounts have no binding ref.** Both `account_pool` rows in `policy/repos.toml`
(`:97`, `:142`) carry the same eight handles — `acct01`, `acct02`, `acct04`, `acct2css`, `acct3css`,
`acct4css`, `acct05`, `acct07` — with `acct03`/`acct06` retired out of the pool
(`policy-resolve.py:162-165`). Activation is not only an enrollment-time
path: the `activate` job fires on **any** merged `account-pool/*` PR, and the #211 resume path
re-drives it for a partially-enrolled handle. So a single PR that lands the read (§4.3) and the
write (§4.2) together makes every existing handle un-reactivatable the moment it merges — a
self-inflicted instance of the very wedge being fixed.

1. **PR 1 — write only.** §4.2 + §5.2's new guard + §5.4 alarm + §5.5 runbook. Activation still
   resolves by title. Nothing depends on the binding yet, so nothing can be wedged by its absence.
2. **PR 2 — backfill.** Create `refs/acct-records/<handle>/<number>` for every currently-enrolled
   handle, from a runbook with the numbers recorded in the PR body, plus a check that refuses if any
   enrolled, non-retired handle lacks a binding. Auditable by hand at this size (eight handles), and
   it must resolve each one through the canonical `acct[0-9a-z]{2,}` grammar of §4.1, not `acctNN`.
3. **PR 3 — read.** §4.3 + §5.3 self-tests + §6's resolution rows. Only now does the binding become
   load-bearing, and by then every live handle has one.

This mirrors the two-PR discipline the repo already enforces for self-test retirement
(`selftest-retirements.txt`): the thing that will be depended upon is established on the base branch
*before* the dependency lands.

## 8. Decision required

- **Q1 — proceed?** Adopt `refs/acct-records/<handle>/<issue-number>` as the account-identity
  binding, with the honest scope of §4.4 (a threat-model reduction from anonymous-public to
  push-capable, not unconditional atomicity)?
- **Q2 — union membership.** Does `git/matching-refs/acct-records/` join
  `SETUP_ACCOUNT_UNION_REQUIRED`? Record recommends **yes** (§5.2); provably redundant, cheap,
  doctrine-preserving.
- **Q3 — sequencing.** Confirm the three-PR order of §7, and that PR 2's backfill is performed by
  runbook rather than by an automated migration workflow.
- **Q4 — interaction with PR #895.** #895 hardens title-uniqueness at creation. Once PR 3 lands,
  title uniqueness is no longer load-bearing. Should #895 land first and its post-create re-read
  later be **retained** as defence in depth (recommended: yes — it is cheap, and it keeps the
  catalog clean for humans reading it), or should PR 3 remove it?

Until Q1 is answered, `#914` should keep its `needs:design` gate: `needs:design` is a hard
design-hold that `triage.py`/`ready-issues.py` refuse to auto-clear (`triage.py:18-19` — "never
auto-cleared here — a human/architect"), which is exactly the intended state for this issue.

## 9. What this record does not do

- It writes no code and changes no behaviour. Every file cited is unmodified.
- It does not verify GitHub's ref-creation permission semantics against the live API. The claim
  that `POST git/refs` requires push access is taken from the documented API and from the fact that
  the existing claim protocol (#186/#237) already relies on it; if Q1 is approved, PR 1 should
  confirm it empirically on a throwaway ref before the binding is trusted.
- It does not size the residual §4.4 write window against real workflow-cancellation rates.
- It does not establish the account **issue numbers** for the eight enrolled handles — PR 2's
  backfill must read them from live state, and this record's coverage claim is only as good as that
  read. In particular it does not confirm that each enrolled handle has exactly one open account
  issue today; if any handle is *already* wedged, PR 2 must resolve that by hand before it can bind.
