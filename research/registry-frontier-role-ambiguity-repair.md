# Repairing the registry's routing-dead frontier: five ambiguous-role issues (U1)

> 🤖 **SPARQ agent** — design record, 2026-07-27. Maintainer-review document.
> This record documents a **live-board label repair**, not a code change. The repair has already
> been applied (five `gh issue edit --remove-label` writes, 15:37:07Z–15:37:13Z on 2026-07-27).
> It exists because a label mutation otherwise leaves **no reviewable trail** — five issues changed
> routing class on the live board and nothing in the repository records why.

## 1. The outage

The registry's dispatch planner emitted **0 rows per tick for ~8 days**. The chain, verified
end-to-end against live data:

1. The curator is pinned at depth 0 — `curate-frontier.py` computes
   `depth = max(0, target_ready - current_ready)` over RAW `status:ready`, and live
   `ready=18 target=12` gives 0 admissions indefinitely.
2. Of the 18 `status:ready`, 6 also carry `status:deferred` → 12 candidates.
3. `compute_ready` takes **one issue per `area:`** (deliberate serialization) → 3 partition heads.
4. All three heads carried **both `role:ci` and `role:impl`**. `dispatch-plan.plan_dispatch`
   rejects `len(roles) > 1` deterministically (registry issue #122) — so all three were skipped
   and **0 rows survived**.

The live planner log printed exactly `skip #406`, `skip #464`, `skip #328`.

Two issues behind the heads (#466, #329) carried the same defect and would have become heads as
soon as the first three drained, so all five were repaired together.

## 2. Why both labels were present — provenance

Identical on all five: `github-actions[bot]` applied `role:impl` via auto-triage, then `jeswr`
applied `role:ci` **and** `status:ready` together, minutes-to-hours later.

| issue | bot applied `role:impl` | `jeswr` applied `role:ci` + `status:ready` |
|---|---|---|
| #328 | 2026-07-19T05:01:19Z | 2026-07-19T11:55:02Z |
| #329 | 2026-07-19T05:02:18Z | 2026-07-19T11:55:03Z |
| #406 | 2026-07-19T11:04:30Z | 2026-07-20T00:20:01Z |
| #464 | 2026-07-19T22:54:43Z | 2026-07-19T22:54:56Z |
| #466 | 2026-07-19T23:04:44Z | 2026-07-19T23:05:46Z |

Neither actor removed the other's label, so every one of these issues has been undispatchable
since the moment it was marked ready.

## 3. The repair direction is NOT uniform — and provenance does not decide it

The tempting reading is "the maintainer said `role:ci`, so keep `role:ci` on all five". That is
**wrong for three of the five**, and the repository's own code says so.

`triage._role` derives the role, and its **first** branch — which wins over an explicit `role:*`
label — forces the trust-plane role on any issue whose labels contain a `SEC_KEYWORD` substring:

```python
def _role(labels, issue_type):
    if any(k in lb for lb in labels for k in SEC_KEYWORDS):
        return TRUST_PLANE_ROLE          # == "impl"
```

`SEC_KEYWORDS` includes `dispatch` and `review-loop`; `AREA_ROLE_DEFAULT` maps
`dispatch`/`review-loop`/`worker`/`groom`/`set-up-account` → `TRUST_PLANE_ROLE`, and only
`ci`/`workflows` → `"ci"`. Running that derivation against the live labels:

| issue | `area:` | SEC_KEYWORD hit | `_role` derives |
|---|---|---|---|
| #406 | `area:review-loop` | `review-loop` | **`impl`** |
| #464 | `area:dispatch` | `dispatch` | **`impl`** |
| #466 | `area:dispatch` | `dispatch` | **`impl`** |
| #328 | `area:workflows` | *none* | **`ci`** |
| #329 | `area:workflows` | *none* | **`ci`** |

Two further facts settle it:

- **The design post-dates the gesture.** `TRUST_PLANE_ROLE` and `AREA_ROLE_DEFAULT` landed
  2026-07-25 (`44355ffc9`, `8e641e402`, `c1a552984`, issues #582/#593/#595/#597) — **six days
  after** the maintainer's 07-19/20 labelling. The provenance argument describes a state of the
  world that the current derivation supersedes.
- **Keeping `role:ci` on a trust-plane issue is not a fixed point.** `triage` strips *all*
  `role:*` labels and re-adds the derived one (`self.labels -= {lb for lb in self.labels if
  lb.startswith(ROLE_PREFIX)}`). Any future retriage of #406/#464/#466 would replace `role:ci`
  with `role:impl`. Only the derivation-agreeing choice is stable.

So the repair applied was:

| issue | `area:` | removed | **kept** | rationale |
|---|---|---|---|---|
| #406 | `review-loop` | `role:ci` | `role:impl` | trust-plane (SEC_KEYWORD) |
| #464 | `dispatch` | `role:ci` | `role:impl` | trust-plane (SEC_KEYWORD) |
| #466 | `dispatch` | `role:ci` | `role:impl` | trust-plane (SEC_KEYWORD) |
| #328 | `workflows` | `role:impl` | `role:ci` | non-trust CI plumbing (`INFRA_SURFACE_LABELS`) |
| #329 | `workflows` | `role:impl` | `role:ci` | non-trust CI plumbing (`INFRA_SURFACE_LABELS`) |

Exactly one label was removed per issue. `status:*`, `priority:*`, `area:*` and
`self-improvement` were **not** touched on any of the five.

## 4. No fail-closed exclusion was weakened

For the three trust-plane issues the choice of role label is **routing-irrelevant**: the Phase-1
`match_labels` security override is evaluated before any role route and matches on the `area:`
label, which was not touched. Resolved through the real resolvers, both variants are identical:

| issue | variant | `model_chain` | agent | escalate |
|---|---|---|---|---|
| #406/#464/#466 | keep `role:ci` | `['opus5']` | `registry-reviewer` | `True` |
| #406/#464/#466 | keep `role:impl` | `['opus5']` | `registry-reviewer` | `True` |

The arm-side classifiers (`dispatch-claim._security_flagged`,
`worker-pr.live_security_flagged`) likewise key off **substring keywords over all labels** plus the
`trust:*` prefix — never off `role:`. So the human-arm posture of these three is carried by
`area:dispatch` / `area:review-loop` and is unchanged by this repair.

For #328/#329 the variants do differ (`role:ci` → `['opus5','sol']`/`registry-ci`/`escalate=False`
vs `role:impl` → `['opus5']`/`registry-impl`/`escalate=True`). This is not a weakening: today those
issues resolve to **nothing at all** (they are skipped), so there is no live posture to relax, and
`role:ci` is precisely what `INFRA_SURFACE_LABELS` prescribes for `.github/workflows` plumbing.

## 5. The cross-resolver contract is preserved (measured, not argued)

`_route_matches` requires exact `model_chain` equality between the PLAN resolver
(`route-resolve.resolve`) and the CLAIM resolver (`policy-resolve.resolve`); a one-sided change
causes permanent per-tick `route-policy-failed` defers. **No file was edited**, so both sides read
the identical `orchestration/routing.toml`. Resolved against the live post-repair labels:

| issue | role | PLAN chain | CLAIM chain | equal |
|---|---|---|---|---|
| #406 | `impl` | `['opus5']` | `['opus5']` | ✅ |
| #464 | `impl` | `['opus5']` | `['opus5']` | ✅ |
| #466 | `impl` | `['opus5']` | `['opus5']` | ✅ |
| #328 | `ci` | `['opus5','sol']` | `['opus5','sol']` | ✅ |
| #329 | `ci` | `['opus5','sol']` | `['opus5','sol']` | ✅ |

A label change selects a *different route row*; it never changes the chain values either side
reads. This repair does not engage that contract.

## 6. Volume

Five label writes, once. Downstream is capped **by construction**, not by tuning: the frontier is
serialized at one issue per `area:`, the registry has 3 live `area:` values among these issues, and
`max_concurrent = 3` in `policy/repos.toml`. The ceiling is exactly 3 concurrent launches — the
configured trust-plane width. No congestion risk.

## 7. Residual observation (not fixed here)

#328/#329 are `migrate-secrets` work. The label-based classifier cannot see that from
`area:workflows` alone — `secrets` is not a `SEC_KEYWORD` — so they route to the auto-armable
`role:ci` lane. This is **mitigated but not closed**: `security_paths` for this repo includes
`.github/workflows/` and `scripts/`, so any PR from these issues is path-flagged and carries the
SHA-bound post-arm audit trail. Whether label-level classification should also cover
secret-handling surfaces is a separate question and deliberately **not** decided here.

## 8. What this repair does NOT do

- It does not touch `orchestration/routing.toml` or `policy-resolve.py`.
- It does not add, remove or re-admit any `status:*` label — in particular **no `needs:user`**
  label was applied or removed by this work.
- It does not widen `compute_ready`'s one-per-area serialization or raise `max_concurrent`.
- It does not arm or merge anything.
