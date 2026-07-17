# data/ — TOMBSTONE: the mutable data plane moved to the `ledger` branch

**Do not read or write the JSON files in this directory on `master`.** They are frozen
snapshots from the 2026-07-17 migration (issue #28) and are kept only so consumers deployed
before the migration do not hard-crash; removing them entirely is a tracked follow-up.

The live, bot-written data plane — `data/leases.json`, `data/model-health.json`,
`data/cache-affinity.json` — lives on the dedicated, **unprotected** [`ledger`
branch](../../tree/ledger/data). Why a separate branch:

- `master` carries required-status-check branch protection (`gate`), which rejects every
  `github-actions[bot]` contents-API `PUT` — that outage silently starved ALL dispatch,
  mislabeled as "account cap is active" (issue #28).
- Granting the bot a protection bypass instead would let a compromised workflow push **code**
  to `master`. Confining bot writes to a branch from which no workflow executes keeps master's
  protection fully intact.
- The `ledger` branch is an **orphan, DATA-ONLY branch** (only `data/*.json` + a README —
  no `.github/`, no `scripts/`). This is load-bearing, not cosmetic (review round 1): a
  `workflow_dispatch` at `ref: ledger` executes the **ledger's** copy of a workflow file, so
  the non-execution property is enforced structurally by there being no workflow file at that
  ref (a dispatch against it 404s; no workflow in this repo triggers on `push`). Workflow-side
  readers assert the checkout is data-only and fail LOUD if executable content ever appears.

Every reader/writer pins the ref via the `LEDGER_REF` constant
(`REGISTRY_LEDGER_REF` env override, default `ledger`) in `scripts/select-and-claim.py`,
`scripts/groom.py`, and `scripts/model-health.py`; workflow-side readers use an explicit
`ref: ledger` checkout (`dispatch.yml` PLAN, `dashboard.yml`). Readers fail LOUD if the
`ledger` branch is missing — never silently-empty.
