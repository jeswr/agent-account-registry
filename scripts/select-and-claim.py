#!/usr/bin/env python3
"""select-and-claim (Phase 3 stub).

Given (package, role, model-chain), walk the model fallback chain, apply per-account caps + reset
windows + prompt-cache affinity, atomically claim a non-full account via the 🚀-reaction mutex
(add-then-recount to resolve the check-then-claim race), write a claim receipt, and return the
account's secret_ref (or 'none-free'). Release removes the reaction. Full implementation lands with
the sparq dispatch engine (Phase 3).
"""
raise SystemExit("select-and-claim: implemented in Phase 3")
