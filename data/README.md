# data/ — TOMBSTONE: the mutable data plane moved to the `ledger` branch

**Do not read or write the JSON files in this directory on `master`.** They are frozen
snapshots from the 2026-07-17 migration (issue #28) and are kept only so consumers deployed
before the migration do not hard-crash; removing them entirely is a tracked follow-up.

The live, bot-written data plane — `data/leases.json`, `data/model-health.json`,
`data/cache-affinity.json`, plus the provenance and review-verdict record stores
`orchestration/provenance/*.json` and `orchestration/review-verdicts/*.json` (issue #96) —
lives on the dedicated, **unprotected** [`ledger` branch](../../tree/ledger/data). Why a
separate branch:

- `master` carries required-status-check branch protection (`gate`), which rejects every
  `github-actions[bot]` contents-API `PUT` — that outage silently starved ALL dispatch,
  mislabeled as "account cap is active" (issue #28).
- Granting the bot a protection bypass instead would let a compromised workflow push **code**
  to `master`. Confining bot writes to a branch from which no workflow executes keeps master's
  protection fully intact.
- The `ledger` branch is an **orphan, DATA-ONLY branch** (only `data/*.json`,
  `orchestration/{provenance,review-verdicts}/*.json` + a README — no `.github/`, no
  `scripts/`). This is load-bearing, not cosmetic (review rounds 1–2): a
  `workflow_dispatch` at `ref: ledger` executes the **ledger's** copy of a workflow file, so
  the non-execution property requires no workflow file at that ref (a dispatch against it
  404s; no workflow in this repo triggers on `push`).
- Why the invariant HOLDS against the confined actor (review round 2): the only credential
  the bot/compromised-workflow actor holds is Actions' `GITHUB_TOKEN`, and **GitHub refuses
  every `.github/workflows/**` create/update from a token without the `workflows` permission
  — which `GITHUB_TOKEN` never has** (platform-enforced, on every branch). An actor with a
  workflow-scoped PAT (the repo owner) can already push arbitrary workflows to any unprotected
  branch repo-wide, so `ledger` adds zero net-new execution surface. Defense-in-depth on top:
  master's reader workflows assert their ledger checkout is data-only, and the scheduled
  `groom.yml` (running master's copy — outside anything ledger-controlled) sweeps the ledger
  tree and fails LOUD if executable content ever appears. (A path-restriction push ruleset
  would be stronger still, but push rulesets are not available on a user-owned repo plan.)

Every reader/writer pins the ref via the `LEDGER_REF` constant
(`REGISTRY_LEDGER_REF` env override, default `ledger`) in `scripts/select-and-claim.py`,
`scripts/groom.py`, `scripts/model-health.py`, and `scripts/worker-pr.py` (provenance +
verdict record writes, issue #96); workflow-side readers use an explicit `ref: ledger`
checkout (`dispatch.yml` PLAN + CLAIM, `review-fix.yml` resolve + run, `groom.yml`,
`dashboard.yml`). Record readers consult the ledger checkout FIRST and fall back to the
master-checkout copy so pre-outage records stay visible. Readers fail LOUD if the `ledger`
branch is missing — never silently-empty.
