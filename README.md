# ledger — the bot-written data plane (DATA-ONLY by design)

Live mutable state for the account registry: `data/leases.json`, `data/model-health.json`,
`data/cache-affinity.json`. Written by github-actions[bot] via contents-API CAS PUTs
(`branch=ledger`), read via `?ref=ledger` / pinned checkouts. See `data/README.md` on master.

**This branch must NEVER carry executable content** (no `.github/`, no `scripts/`): a
`workflow_dispatch` at `ref: ledger` executes the LEDGER copy of a workflow file, so the
non-execution trust property is enforced STRUCTURALLY by there being no workflow file at this
ref (a dispatch against it 404s). Workflow-side readers assert data-only on every checkout.
