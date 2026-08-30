# `_alert_route`: twelve copies, five shapes, and a consolidation target that does not exist

> 🤖 **SPARQ agent** — design record for issue #1021, 2026-08-02. Maintainer-review document.
> Findings only. This record changes no behaviour; it exists so the fix is sequenced deliberately
> rather than executed as #1021's "Suggested work" reads, which is **not executable as written**.

Issue #1021 reports four byte-equivalent `_alert_route` copies whose docstrings claim
`ALERT_TOKEN` "can write there" while only presence is tested, and proposes folding them onto
`scripts/alert_route.py`'s `alert_route`.

**The prose defect is real and is wider than reported. The rest of the premise is stale.** There
are **twelve** implementations of this route in **five** distinct shapes, not four in one; two of
the four named copies were already hardened by #436 and no longer match the quoted body; and
`scripts/alert_route.py` **does not exist on master**, so there is nothing to fold onto.

---

## 1. What is actually in the tree

`grep -rn "^def _alert_route" scripts/*.py` returns **eleven** definitions. `model-health.py`
carries a twelfth under a different name. Grouped by *behaviour*, not by name:

| tier | signature / return | sites |
|---|---|---|
| **T1 — presence only** | `(alert_repo, alert_token, registry_repo) -> (repo, token\|None)` | `ci-latency-alert.py:846`, `dispatch-stall-alert.py:154`, `groom-mint-alert.py:158`, `metrics-alert.py:114`, `park-stock-alert.py:196`, `triage-stock-alert.py:391` |
| **T2 — +same-repo +confirmed-private** | `(…, confirmed_private=None) -> (repo, token\|None)` | `groom-alert.py:60`, `plan-alert.py:92` |
| **T3 — T2 + redaction flag** | `(…, confirmed_private=None) -> (repo, token\|None, redact)` | `pat-validity.py:500`, `usage-alert.py:194` |
| **T4 — reads env itself, non-`None` fallback token** | `(confirmed_private=None) -> (repo, token)` | `worker-pr.py:474` |
| **T5 — routing and verification split** | `_alert_target() -> (repo, token)`, verification applied at the *call site* | `model-health.py:2379` |

T1 is the body #1021 quotes. It is **six** copies, not four.

**Two of the four copies the issue names are no longer that body.** `plan-alert.py:92` and
`groom-alert.py:60` took the #436 hardening — a case-insensitive same-repo rejection plus a live
`GET /repos/{ALERT_REPO}` under `ALERT_TOKEN`, fail-closed on every indeterminate shape
(`groom-alert.py:77-82`). The issue's line references (`plan-alert.py` ~72, `groom-alert.py` ~41)
point into unrelated code. Anyone implementing #1021 from its text will patch the wrong lines.

**T5 is the shape most likely to break a naive consolidation.** `model-health.py` does not fold
verification into routing at all: `_alert_target()` (line 2379) is presence-only, and
`_repo_confirmed_private` is consulted separately at `model-health.py:2462` to decide
*redaction*, with `_registry_fallback()` (line 2399) as a third piece. Same policy, factored
across three functions. A shared `alert_route` with one return arity cannot absorb it without
restructuring that call site.

---

## 2. The prose defect — where it is, and why two sites are wrong twice

The literal string "ONLY when `ALERT_TOKEN` can write there" appears at **eleven** places:

- **Python** — `ci-latency-alert.py:849`, `metrics-alert.py:117`, `groom-mint-alert.py:161`,
  `dispatch-stall-alert.py:157` (docstrings); `plan-alert.py:9`, `groom-alert.py:12` (headers);
  `usage-alert.py:404` (inline).
- **Workflow YAML** — `metrics.yml:200`, `dispatch.yml:2205`, `dispatch.yml:2286`,
  `groom-sweep.yml:748`.

Two more sites say "only when `ALERT_TOKEN` **is present**" — `triage-stock-alert.py:393`,
`park-stock-alert.py:198` — which is accurate. So the correct wording already exists in the tree;
the defect is that the *majority* copy is the inaccurate one.

No write capability is probed anywhere. The strongest check in the tree is
`_repo_confirmed_private`, which reads `GET /repos/{repo}` — that proves the token can **read**
the repo and that the repo is private. It proves nothing about issue-write permission. So even
the T2/T3 sites cannot honestly claim "can write there".

`plan-alert.py:9` and `groom-alert.py:12` are wrong in **both directions**: the header
under-describes the function (it omits the #436 same-repo and confirmed-private checks the code at
lines 92 / 60 actually performs) *and* asserts a write check that does not exist. A reader
reconciling header against body will mis-model the route either way.

**#1021 states the correction correctly**: the honest word is *presence*. That part of the issue
needs no re-litigation.

---

## 3. The consolidation target does not exist

Three headers carry the same forward reference:

```
# DEBT (issue #591, PR #590): `_alert_route` is the SIXTH private copy of the same locked decision
# (22c). PR #590 introduces `scripts/alert_route.py` as the shared home. It is not on master yet, so
# this file carries a byte-compatible private copy ...
```
— `metrics-alert.py:54-58`, and near-verbatim at `dispatch-stall-alert.py:64-66` and
`groom-mint-alert.py:60-62`.

`ls scripts/` confirms **there is no `alert_route.py`**. PR #590 never landed. The notes are
correct about their own state ("not on master yet") but #1021 reads them as evidence that "the
consolidation target already exists" — it does not. The shared module must be **authored**, and
that is a design decision (which tier? which arity?), not a mechanical move.

The DEBT notes also understate the migration. They call it "a one-line import swap plus adding
`scripts/alert_route.py` to both sparse-checkout lists". Two problems:

**(a) Single-file sparse checkouts.** Two live alert jobs check out exactly one file:

```yaml
# .github/workflows/dispatch.yml:2271        # .github/workflows/groom-sweep.yml:736
sparse-checkout: scripts/plan-alert.py       sparse-checkout: scripts/groom-alert.py
sparse-checkout-cone-mode: false             sparse-checkout-cone-mode: false
```

A sibling-module import in those files loads a path that is **not in the checkout**. The repo has
already been bitten by this and documents the resolution at `ci-latency-alert.py:787-810`: load
lazily, by path, and *raise* rather than degrade, because `regate-sweep.py` execs that module
under a checkout carrying no `gh_retry.py`. Its self-test asserts **both directions**
(`ci-latency-alert.py:~2055-2075`): a thin checkout must still `exec_module`, and the read path
must still raise on first use.

**Lazy loading does not help here.** The route is called at the top of `main()` in every one of
these scripts (`groom-alert.py:128`, `metrics-alert.py:331`, `dispatch-stall-alert.py:558`, …) —
the route *is* the first read. So the two sparse-checkout lists genuinely must grow, and the
growth must be **asserted** at the YAML seam or it silently regresses. `ci-latency-alert.py:2058-2064`
names this exact failure class: the live job ships without the file and reds on its first call,
while pr-gate — which has the whole tree — stays green. That is the #1140 shape.

**(b) "byte-compatible / IDENTICAL signature" is false.** `worker-pr.py:505` returns
`os.environ.get("REGISTRY_ALERT_TOKEN") or alert_token` on fallback; every T1/T2 copy returns
`None`. `worker-pr.py:487-492` explains why — the fallback destination is the *registry*, and
`ALERT_TOKEN` is minted for the private repo, so a registry write under it would be refused.
`model-health.py:2392` does the same via `_registry_fallback()`. A shared router must model the
**fallback-token axis**; a signature that only returns `None` cannot express it.

---

## 4. Finding not in #1021: one copy has no test at all

`scripts/park-stock-alert.py` contains exactly **two** occurrences of `_alert_route(`: the
definition (line 196) and the call site (line 251). Its `_self_test` asserts nothing about the
route.

`park-stock-alert.py` **is** enrolled in `scripts/selftest-suite.txt`, and the required
`registry-selftest` job (`.github/workflows/pr-gate.yml:184-252`) runs every enrolled entry
through `worker-live.sh run-selftest`. So the gate is green over a file whose router is untested.
Any edit to that copy — including a well-intentioned hardening applied to nine files and fumbled
in the tenth — ships without a red. This is #1021's stated risk ("any single copy can regress
while the suite stays green on the others") already realized in its strongest form: not *another*
copy staying green, but *this* copy having nothing to go red.

`ci-latency-alert.py:1578-1582` is the second-thinnest: three assertions (private, no-token,
neither), with no same-repo or visibility coverage — appropriate for T1, but it means the
hardening cannot be added there without also writing the tests.

---

## 5. The divergence #1021 predicts has already happened

#432 round 1 and #436 hardened the route on **four of twelve** sites (T2 + T3), plus `worker-pr.py`.
Six T1 sites were not touched. That split is not hypothetical drift — it is the current state of
master, and it is exactly the failure mode the issue describes: "a future hardening has to land
four times or silently diverge".

The operational consequence, stated plainly: on the six T1 sites, a maintainer who sets
`ALERT_REPO` to a **public** repo, or to the registry itself, gets a route that reports itself as
private and is not. `usage-alert.py:200-206` and `pat-validity.py:505-509` both spell out why that
matters — "presence of a token is not privacy".

**What that does *not* establish.** #1021 asserts the four bodies it names are handle-free. I did
not audit all twelve bodies for disclosure and this record should not be read as clearing them.
Whether any T1 body carries fleet-compositional content (the #204 concern, not just raw handles)
is an open question and the deciding input for how urgent the T1 hardening is.

---

## 6. Options

**A — Prose only.** Correct the eleven "can write there" sites to say *presence*, and fix
`plan-alert.py:9` / `groom-alert.py:12` to describe the #436 checks the code performs.
*For:* zero behaviour risk; fully in the `workflows` area; ships in one small PR; removes the
active trap for the next hardening pass. *Against:* leaves twelve copies and six fail-open routes.

**B — Author `scripts/alert_route.py` and migrate all twelve.** What #591/#590 intended.
*For:* the only option that ends the duplication. *Against:* five shapes, three return arities,
two fallback-token semantics, two sparse-checkout amendments with seam assertions, and twelve
self-test suites to re-point. This is a programme, not a PR. **And it is not a refactor:** giving
the six T1 sites the T2 router *changes their behaviour* — it adds a `GET /repos/` call per tick
and starts routing a public/same-repo `ALERT_REPO` to the registry where it previously routed
private. Landing that as "consolidation" hides a behaviour change inside a cleanup diff.

**C — Harden in place, then consolidate.** Bring the six T1 copies to T2 semantics *in their own
files*, one reviewable behaviour change per file, then consolidate a router all sites already
agree with. *For:* closes the fail-open gap now; makes B a true no-delta refactor afterwards;
each step is independently reviewable. *Against:* temporarily *increases* duplicated lines, which
reads backwards if the goal is stated as "remove duplication".

**D — Guard only.** Add a cross-file self-test counting `_alert_route` definitions, red on a new
one. The repo has the machinery (`metrics-alert.py:1051` regexes a constant out of
`scripts/metrics.py`; `groom-mint-alert.py:1488` `ast.parse`s its own source).
**Rejected as a standalone.** A counter whose passing value is twelve ratchets the wrong axis: it
freezes the duplication and asserts nothing about correctness. Useful only *after* B, pinned at one.

---

## 7. Recommendation

1. **Do A now.** It is the whole of #1021's correctness claim, it is `workflows`-area, and it
   carries no behaviour risk. Include the four YAML comments — the workflow prose repeats the same
   false claim to a different audience.
2. **Do not execute #1021's "Suggested work" as written.** It names a nonexistent module and two
   stale line numbers. Re-scope the issue against §1 of this record first.
3. **Then C, then B** — hardening before consolidation, so the behaviour change is visible in a
   diff that is about behaviour.
4. **Before B, decide the shared router's contract**: return arity (does it carry `redact`?), the
   fallback-token axis (`None` vs `REGISTRY_ALERT_TOKEN`), and whether `model-health.py`'s split
   factoring folds in or stays out. Consolidating before that decision produces a thirteenth shape.
5. **Fix `park-stock-alert.py`'s untested route** independently of all of the above (§4). It is
   the cheapest real risk reduction on this list.

## 8. Not established here

- **Whether `ALERT_REPO` is configured at all.** Seventeen workflow bindings read
  `${{ secrets.ALERT_REPO || vars.ALERT_REPO || '' }}`. If the secret is unset in this deployment,
  every route falls back to the registry, the private branch is dead code, and the priority of C
  and B drops sharply. I did not and must not inspect secrets; **this is the maintainer's call and
  it should be answered before C is scheduled.**
- **API budget.** T1→T2 adds one `GET /repos/{ALERT_REPO}` per alerting tick per script. Whether
  that is acceptable against the secondary-rate-limit posture is unmeasured. A measurement on a
  work box would not be canonical and none is offered.
- **Disclosure audit of the twelve bodies** (§5).
- **Whether `_repo_confirmed_private`'s read-scoped probe should become a write-capability probe.**
  It would make the "can write there" claim true rather than deleting it — but a write probe means
  a mutation, and no design for a non-destructive one is proposed here.
