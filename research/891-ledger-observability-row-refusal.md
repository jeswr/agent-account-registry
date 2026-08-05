# #891: refusing a `flow.leases[]` row array on the public ledger — the design record

> 🤖 **SPARQ agent** — findings-only design record. Nothing in this PR changes behaviour. #891 asks
> to "consider a producer-side or ledger-invariant guard" *once the observability collector lands*,
> and then to drop the legacy rows path. This record surveys what the repo actually enforces today,
> shows why the issue's **ordering** is the expensive one, and recommends a different, smaller
> change than either half of the issue's suggestion. The maintainer should steer §5 before anyone
> writes code.

## 1. The question, restated as a property

`data/observability.json` lives on the **public, unprotected `ledger` branch**
(`data/README.md` §"`data/observability.json`"; `dashboard.yml:401` reads it as
`ledger/data/observability.json`). Since #841 the dashboard no longer *requires* per-account lease
rows — a collector may send `flow.lease_utilization_1h = {mean, max}` pre-aggregated. The property
we want:

> No per-account lease row array is ever readable at `data/observability.json` on the `ledger` ref.

Read this as the **target**, not as something any option below delivers: it is a property about the
branch, and §6/§7 conclude that nothing in this record establishes it — the achievable property is
refusal and detection. The gap is stated precisely in §7.

The property that actually holds today is much weaker:

> If a per-account lease row array is present, each row's label must be the canonical salted
> fingerprint, and the rows are not republished to Pages.

The gap is the whole issue: **`flow.leases[]` is still an accepted input.** A collector authored
against the pre-#841 prose parks the array on a public branch and every check stays green.

## 2. What the repo enforces today (grounded)

**`_obs_flow`, `scripts/dashboard-gen.py:1631`.** The rows loop (`:1695-1705`) validates every
label against `OBS_SALTED_LABEL_RE` (`:1699-1702`) and raises `DashboardError` on a non-salted one — unconditional,
even when an aggregate is also supplied (self-test `[#841] a raw lease label stays fatal even when
an aggregate is also supplied`, `:4746`). Precedence then keys on **key presence**, not on parse
success:

```python
if "leases" in flow:
    lease_utilization = {...} if lease_utilizations else None
else:
    lease_utilization = _obs_lease_aggregate(flow.get("lease_utilization_1h"))
```

So a mid-migration collector sending both publishes exactly its pre-#841 value, including the
`null` it publishes when no row carries a usable `utilization_1h` (`:4719`, `:4734`). That
precedence is correct and well self-tested. **But acceptance is not enforcement**: the rows are
consumed, validated, and thrown away — and they remain on the branch.

**`scripts/ledger-invariant.py` cannot see this.** It is a **Git tree-shape** validator only:
`ALLOWED_ENTRIES` (`:12-20`) matches mode/type/path, and `ledger_entries` (`:29`) shells out to a
single `git ls-tree -r -t -z HEAD`. It never opens a file, never parses JSON, and never looks past
`HEAD`. `data/observability.json` matches `data/[^/]+\.json` and is therefore *fully* allowed
whatever it contains.

**There is no shared write choke point.** Eleven scripts each issue their own
`gh api -X PUT repos/.../contents/...` (`select-and-claim.py:789` is the pattern). The one shared
ledger-write module states its own scope in its docstring: *"This module never runs a PUT"*
(`scripts/ledger_retry.py:18`). So "producer-side guard" cannot mean "add it to the ledger writer";
there is no such single thing.

**There is no collector.** `observability` appears in the workflows only in `dashboard.yml:391-401`,
on the read side, and that step is explicitly commented *"OPTIONAL on the ledger until its collector
lands"*. `data/observability.json` has **no producer in this repo**, and never has had one. #841's
dashboard half (`172f317b3`, PR #890) described a contract, not a live disclosure.

## 3. Two things that make "refuse on the ledger ref" weaker than it sounds

**(a) Deletion is not unpublication.** `ledger-invariant.py` inspects `HEAD` only. Ledger writes go
through the contents API, which only ever *appends* commits, and nothing in this repo force-pushes,
rewrites or prunes the `ledger` branch. A guard that fires when rows appear fires **after** those
rows are already a commit on a public branch of a public repo, and removing them in the next commit
leaves them permanently readable at the old one. A ledger-ref check is therefore an **alarm**, not
a refusal. It is still worth having as an alarm — but it must be named as one, and it must not be
the thing anyone relies on for the §1 property.

*(This is a general property of the branch, not specific to observability. It is not written down
anywhere I found; filed as a follow-up.)*

**(b) The tree guard is shared by four lanes, three of which never read this file.**
`ledger-invariant.py` runs in `dashboard.yml:175,367`, `dispatch.yml:1140,1676`, `groom-sweep.yml:54` and
`review-fix.yml:231,1204` — every one a bare `run:` with no `continue-on-error`, so its
`SystemExit(1)` fails the job. Today that fail-closed severity is justified: a tree-shape violation
means the branch has become an **execution** surface (`data/README.md`: a `workflow_dispatch` at
`ref: ledger` would execute the ledger's copy of a workflow file). A `flow.leases[]` array is a
privacy regression in one optional file — serious, but not an execution compromise. Putting it in
the shared guard means **one collector shape bug halts dispatch**, the fleet's critical path, over a
file dispatch does not read.

## 4. The options

**A — consumer-side FATAL refusal: make `"leases" in flow` a `DashboardError`.** Collapses the
issue's two asks into one change: the guard *is* the removal of the legacy path. Fail-closed, fully
self-testable today with no collector, no new file reads, no new script, and it lands in the module
`data/README.md:55` already names as the canonical contract (*"The consumer-side contract IS
`dashboard-gen._normalize_observability()` … collector authors: build against it, not this prose"*).
Severity is consistent with what that function already declares — a present document that is not the
declared schema *"dies loudly"*. **Cost:** a future collector regression takes the dashboard page
down rather than hiding a panel. That is the existing posture for this document, not a new one.

**B — content check inside `scripts/ledger-invariant.py`.** The only option that fires on the
*branch* rather than on a consumer, so it is the only one that catches rows a non-dashboard consumer
would never look at. **Cost:** §3(b) — it imposes a collector bug on dispatch/groom/review-fix; and
it changes the guard's character from "one `ls-tree`, no I/O" to "parse untrusted collector JSON
before anything trusts the branch", which needs size bounds and invites the guard to grow into a
second schema validator. The repo's standing division is that *content* schemas live with the
consumer (`lease_schema.validate_ledger`, model-health's `validate_ledger`,
`_normalize_observability`) and *shape* lives in `ledger-invariant.py`. B erodes that.

**C — producer-side guard in the collector.** The only option that acts *before* publication, because
of §3(a): once the bytes are pushed, every other option is post-hoc. But it covers exactly one write
path — the collector's. Nothing in this repo makes the contents API reachable only through that
collector (§2: eleven scripts hold their own `PUT`, and the branch is writable by anything holding
the token), so C bounds what *the collector* publishes, not what *the branch* carries. **Cost:** it
cannot be written today (no collector), it cannot be self-tested from this repo, and if the collector
ever lives outside this repo it is an unenforceable request. Necessary, insufficient alone.

**D — tolerant drop + a printed line.** Rejected. A green build plus a log line nobody reads is
exactly the failure `_obs_drop_queue` was written to end (`dashboard-gen.py:1617-1624`: *"published a
green build, a green self-test and a panel reading `no backlog`, with the loss visible nowhere"*).
Re-adopting it for a *privacy* regression is strictly worse than for a dropped queue row.

**E — the issue's literal ordering: do nothing until the collector lands.** Rejected, and this is
the load-bearing finding. See §5.

## 5. Recommendation: invert the ordering — do A **now**, before the collector lands

The stated reason to keep the legacy rows path is to keep *"a collector mid-migration"*
byte-identical (`dashboard-gen.py:1687-1691`; `data/README.md` "Legacy (rows)"; self-test `:4719`).
**There is no collector** (§2), so there is no mid-migration collector to be byte-identical *for*.
The precedence property is real, well-tested, and currently protecting a hypothetical.

This repo has already reasoned this out once, on this exact file, and written the argument down:

> *"Tightening it here is safe in exactly this order because the collector has not landed yet …
> there is no producer to break, and the shape it must be built against is now the canonical one."*
> — `dashboard-gen.py:96-98` (#375, on `OBS_SALTED_LABEL_RE`)

The same argument applies verbatim to `flow.leases`, and it has an expiry date: **the free window
closes the moment a collector lands.** #891 proposes to wait for exactly that event, which converts
a zero-cost tightening into a producer migration. That is backwards.

So: **make `flow.leases` fatal now.** Concretely — refuse the document when the key is present, with
a message that names the row-free contract, and delete the rows loop, the precedence branch, and the
`[#841]` legacy self-tests, replacing them with a refusal test.

**One thing this must NOT be read as.** "Drop the legacy rows path entirely" must not become "stop
looking at `flow.leases`". Silently ignoring the key would *lose* the unconditional decision-22 label
check (`:1699-1702`) — a raw handle in the collector's output would stop being fatal. Refusal keeps
the tripwire and strengthens it: **no rows at all is a stronger decision-22 posture than validated
rows**, because it removes the fleet-size read that #374 removed from Pages, rather than validating
it.

**Then, when the collector lands: C, as a landing obligation, not a later idea.** Its spec should
state that it never writes `flow.leases`, and its own self-test should assert that its serialized
snapshot has no such key. A is what makes that obligation *checkable* from this side.

**B: only if the maintainer wants the branch-level alarm despite §3(b)** — and if so it should be
scoped to `data/observability.json` alone, named an alarm, and its blast radius on dispatch/groom/
review-fix decided deliberately rather than inherited. I do not recommend it as part of this change.

## 6. What this does not buy, and what I do not know

- **Nothing here achieves §1, and A least of all.** A refuses to *build a dashboard from* a document
  containing rows; it cannot stop the rows being written or being public. Anyone describing A as "the
  ledger no longer carries per-account rows" would be overstating it. Neither does the set {A, B, C}:
  C constrains one writer prospectively (§4), B and A are post-publication (§3(a)), and no option in
  this record closes the remaining write paths — a direct contents-API `PUT`, a second producer, or a
  collector regression still lands readable rows on a public ref before any of them reacts. §1 as
  written is a property about the *branch*, and this repo has no pre-write control over that branch;
  achieving it would require one (see §7).
- **I have not audited this as a privacy control.** Whether the aggregate `{mean, max}` over an
  unpublished fleet size is itself non-identifying across repeated builds is a question this record
  does not answer, and #374/#841 assert rather than establish it. It needs review before anyone
  calls the resulting posture sound.
- **Unknown: where the collector will live.** If out-of-repo, C is a request, not a control, and the
  balance shifts toward B despite §3(b).
- **Unknown: whether any non-dashboard consumer will ever read this file.** If one appears, A's
  consumer-side placement stops covering the branch and B becomes necessary.
- **Not addressed here:** the live half of #841 — `data/leases.json` via `select-and-claim.py` and
  the ledger-branch visibility decision — which remains tracked in #841 and is out of scope for this
  record.

## 7. Sequencing

1. Land A (dashboard-gen refusal + `data/README.md` "Legacy (rows)" bullet replaced by the refusal),
   while there is still no producer. Self-tested; no migration.
2. Decide B explicitly — as a scoped alarm or not at all. Do not let it arrive by default.
3. When the collector is specified, write C into its spec and its self-test.

**What 1–3 actually buys — stated precisely, because it is less than §1.** After 1–3 the achieved
property is *refusal and detection*, not prevention:

> A document carrying `flow.leases[]` is refused by the canonical consumer (A), the sole in-repo
> collector is specified and self-tested not to emit the key (C), and — only if the maintainer takes
> B — its arrival on the branch raises an alarm.

That is strictly weaker than §1 in three ways the maintainer should not have to rediscover: step 2
**permits declining B**, in which case nothing watches the branch at all; C binds one writer, and any
other holder of a contents-API `PUT` (§2) is unconstrained by it; and every reaction here is
post-publication (§3(a)), so even the strongest combination alarms *after* the rows are readable, and
never unpublishes them.

**What would be needed for §1 itself — deliberately not sequenced above.** §1 is a pre-write property
over a public branch, so the only thing that could establish it is an enforceable control on the write
path: every writer of `data/observability.json` refusing the key *before* the `PUT`, with the bypass
assumption (anyone holding the token can `PUT` directly, and nothing in this repo prevents that)
written down as an accepted residual rather than waved away. No such choke point exists today (§2:
eleven independent `PUT` sites; `ledger_retry.py` explicitly never writes), and building one is a
larger change than this record scopes — **filed as a follow-up**. Until then: do not treat §1 as
delivered by 1–3. And it is never true retroactively in any case (§3(a)).
