#!/usr/bin/env python3
# Lease allocator (review C3): a correct, cross-codebase worker-slot lease over a
# compare-and-swap ledger — replaces the reaction "mutex" (which cannot count concurrent same-identity
# claims). Pure allocation logic is unit-tested; GitHub CAS I/O wraps it.
"""select-and-claim — allocate a model-account worker slot as a LEASE.

The ledger is a single JSON file `data/leases.json` in this private registry:
    {"leases": [{"account","claim_id","holder","package","role","model","issued_at","expires_at"}, ...]}

``account`` is the canonical salted 16-hex fingerprint, never the catalog handle.

Claiming is a compare-and-swap: read the file + its blob SHA, reclaim expired leases, if an eligible
account (serving a model in the chain, under its cap, cache-affinity-preferred) has a free slot append
a unique lease, then PUT the file with the read SHA. A concurrent writer changes the SHA → the PUT is
rejected → retry. This serializes allocation across every codebase without reaction counting. Release
and heartbeat are keyed by the unique claim_id.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import math
import os
import random
import re
import subprocess
import sys
import time


_retry_spec = importlib.util.spec_from_file_location(
    "registry_ledger_retry", os.path.join(os.path.dirname(__file__), "ledger_retry.py"))
if _retry_spec is None or _retry_spec.loader is None:
    raise RuntimeError("cannot load shared ledger retry policy")
ledger_retry = importlib.util.module_from_spec(_retry_spec)
_retry_spec.loader.exec_module(ledger_retry)

LEDGER_PATH = "data/leases.json"
# The mutable data plane lives on a dedicated NON-code branch: branch protection on the default
# (code) branch rejects the bot's contents-API PUTs (issue #28 live incident 2026-07-17 — a
# required `gate` status check on master blocked every lease write and starved all dispatch),
# and a bot that can only write `ledger` can never push code to master. Env override is for
# tests/migration only; every reader and writer threads this single constant.
LEDGER_REF = os.environ.get("REGISTRY_LEDGER_REF", "ledger")


class LeaseIOError(RuntimeError):
    """A fail-closed ledger/catalog error that never includes credential material."""


# ---- pure allocation core (unit-tested) ---------------------------------------------------------
def reclaim_expired(leases, now):
    """Drop leases whose expiry has passed (conservative reclamation)."""
    return [x for x in leases if x.get("expires_at", 0) > now]


ACCOUNT_FINGERPRINT_RE = re.compile(r"[0-9a-f]{16}")


def account_fingerprint(handle, salt=None):
    """Canonical public identity for an account. Missing salt fails closed."""
    salt = os.environ.get("PROVENANCE_SALT", "") if salt is None else salt
    if not isinstance(handle, str) or not handle or not isinstance(salt, str) or not salt:
        raise LeaseIOError("PROVENANCE_SALT and account handle are required for lease identity")
    return hashlib.sha256(f"{handle}:{salt}".encode()).hexdigest()[:16]


def validate_lease_account_identities(leases):
    """Drop legacy/raw identities so the next CAS write completes the bounded migration."""
    return [item for item in leases
            if isinstance(item.get("account"), str)
            and ACCOUNT_FINGERPRINT_RE.fullmatch(item["account"]) is not None]


def active_for(leases, account):
    fingerprint = account_fingerprint(account)
    return sum(1 for x in leases if x.get("account") == fingerprint)


# ---- usage-aware eligibility + expiry-priority (dynamic backoff) --------------------------------
# [OPUS-4.8] A worker must NOT start on an account that could hit a rate limit mid-run — that burns
# credits on a half-finished agent. So an account is eligible to START only if we KNOW its live usage
# (Anthropic anthropic-ratelimit-unified-* headers), its status is "allowed", and BOTH the 5h and 7d
# windows have >= SAFETY_MARGIN headroom. Fail closed on any missing/unknown usage. Among eligible
# accounts we prioritise the one whose WEEKLY window resets SOONEST — its unused credits are about to
# reset, so spend them before they vanish (use-it-or-lose-it).
SAFETY_MARGIN = 0.10  # default fraction of each window that must remain free to admit a new worker.
# CAVEAT: this is a POINT-IN-TIME headroom gate, not a projected-consumption model — an account admitted
# at (1 - margin) utilisation can still exceed its window mid-run if the worker's burn exceeds the
# remaining headroom. Set margin >= a typical worker's per-window burn to actually prevent half-finishes.
# Per-repo overridable via policy `usage_safety_margin`. Projected-burn admission is tracked as follow-up.

# [FABLE-5] Models whose OWN weekly sub-quota (the account-usage `fable_7d_oi_*` window) must ALSO have
# headroom before a worker starts — routing one of these to an account with low WHOLE-account usage but an
# exhausted premium bucket fails mid-run and burns credits. account-usage.py only ever emits the fable
# sub-quota fields for the claude-fable-5 alias; keep this in sync with any alias that maps to that bucket.
PREMIUM_MODELS = frozenset({"fable"})
FABLE_WINDOW = "fable_7d_oi"  # prefix of the fable sub-quota util/reset keys in the usage map


def _usage_num(v):
    # OverflowError (cross-provider review r2 finding 3): a forged `backoff_until: 10**400` is
    # valid JSON (Python ints are unbounded) but float() of it RAISES rather than returning inf —
    # uncaught, it aborted the whole dispatch instead of failing open to no-backoff.
    try:
        return float(v)
    except (TypeError, ValueError, OverflowError):
        return None


def _usage_window(u, prefix):
    """(utilization, reset_ts) for a named window, or (None, None) if absent/unparseable."""
    if not isinstance(u, dict):
        return None, None
    return _usage_num(u.get(prefix + "_util")), _usage_num(u.get(prefix + "_reset"))


def _fable_eligible(u, margin):
    """[FABLE-5] Fail-closed headroom test for the FABLE weekly sub-quota. Requires the account-usage
    fable probe to have SUCCEEDED (fable_ok) AND the 7d_oi window to have >= margin headroom. Unknown or
    unprobed -> ineligible, so a fable route never lands on an account with an exhausted (or unobserved)
    Fable bucket."""
    if not isinstance(u, dict) or not u.get("fable_ok"):
        return False
    util, _ = _usage_window(u, FABLE_WINDOW)
    return util is not None and (1.0 - util) >= margin


def usage_eligible(u, margin=SAFETY_MARGIN, model=None, now=None):
    """Fail-closed admission test for STARTING a worker (of `model`) on an account. Beyond the whole-account
    5h/7d headroom, a PREMIUM_MODELS route (fable) additionally requires FABLE sub-quota headroom.

    PROBE-EXEMPT providers (openai/codex — maintainer decision 2026-07-17, registry issue #29): their
    usage is not observable via any API, so the fail-closed require-usage arm does NOT apply to them —
    they are eligible WITHOUT usage data and are governed REACTIVELY instead: account-usage.py stamps
    `backoff_until` (derived from the model-health rate-limit records) onto an exempt entry, and the
    account is excluded while now < backoff_until. A missing or malformed stamp means NO backoff
    (fail-open — the backoff is an optimization; the exemption must never reintroduce the fail-closed
    starvation it removes). Anthropic accounts keep the fail-closed probing below unchanged."""
    if not isinstance(u, dict):
        return False                                  # no probe data -> do not risk it
    if u.get("exempt") is True:                       # STRICT: only the literal producer-set flag —
        # a forged truthy string (e.g. "false") must not ride the exempt arm (cross-provider r1).
        until = _usage_num(u.get("backoff_until"))
        # Finite stamps only (cross-provider review r1): `inf` would sideline the account FOREVER
        # (now < inf is always True) while usage-alert's nan/inf guard reports it healthy — a
        # dispatch/monitoring split. Non-finite = no backoff, matching _apply_backoff's fail-open.
        if until is not None and math.isfinite(until):
            if now is None:
                import time
                now = time.time()
            if now < until:
                return False                          # rate-limited earlier — backed off until it expires
        return True                                   # non-metered provider (e.g. codex) — not probe-gated
    if str(u.get("status", "")).strip().lower() != "allowed":
        # [ISSUE #196] require status EXACTLY `allowed`: an empty status was previously accepted
        # (the `("allowed", "")` set) and failed open as eligible capacity.
        return False                                  # empty/throttled/rejected -> not eligible
    for prefix in ("5h", "7d"):
        util, _ = _usage_window(u, prefix)
        # [ISSUE #196] Validate the SHAPE before trusting the headroom comparison: a base window of
        # `nan` (every comparison is false, so `(1 - util) < margin` never fires) or a NEGATIVE
        # utilization (looks like excess headroom) otherwise slips through and admits the account.
        # Require a finite fraction in [0,1]; anything else is fail-closed ineligible.
        if util is None or not (0.0 <= util <= 1.0) or (1.0 - util) < margin:
            return False                              # unknown, malformed, or too little headroom
    if model in PREMIUM_MODELS and not _fable_eligible(u, margin):
        return False                                  # [FABLE-5] whole-account fine, but Fable bucket isn't
    return True


def _weekly_reset(u):
    """Whole-account weekly reset used for provider-wide use-it-or-lose-it draining."""
    _, reset = _usage_window(u, "7d")
    return reset


def _order_eligible_accounts(accounts, leases, usage, package, role):
    """Deterministically order accounts that have already passed every eligibility gate.

    Preserve the allocator's cache-affinity/load/handle order, then stably promote known weekly
    resets from soonest to latest. Accounts without a 7d reset remain last in their prior relative
    order. This helper deliberately contains no availability, model, capacity, or usage gating.
    """
    def affinity(account):
        times = [lease.get("issued_at", 0) for lease in leases
                 if lease.get("account") == account_fingerprint(account["handle"])
                 and lease.get("package") == package and lease.get("role") == role]
        return max(times) if times else -1

    ordered = sorted(
        accounts,
        key=lambda account: (
            -affinity(account), active_for(leases, account["handle"]), account["handle"]),
    )
    if usage is not None:
        def weekly_key(account):
            reset = _weekly_reset(usage.get(account["handle"]))
            return reset is None, reset if reset is not None else 0.0

        ordered.sort(key=weekly_key)
    return ordered


def _choose_account_model(accounts, leases, model_chain, package, role, now, usage=None,
                          margin=SAFETY_MARGIN):
    """Return ``(account, model)`` for the first model with eligible capacity, or None.

    Each alias pass applies the complete account availability, concurrency, and usage/backoff gates
    before advancing to the next alias. Returning the alias with the account keeps the lease record
    bound to the model pass that actually admitted it.
    """
    live = reclaim_expired(leases, now)
    for model in model_chain:
        serving = [a for a in accounts
                   if a.get("available", True) and model in a.get("models", [])
                   and active_for(live, a["handle"]) < int(a.get("max_concurrent_workers", 4))]
        if usage is not None:
            serving = [a for a in serving
                       if usage_eligible(usage.get(a["handle"]), margin, model=model, now=now)]
        if not serving:
            continue

        serving = _order_eligible_accounts(serving, live, usage, package, role)
        return serving[0], model
    return None


def choose_account(accounts, leases, model_chain, package, role, now, usage=None, margin=SAFETY_MARGIN):
    """Return the account handle to claim, or None. `accounts`: list of dicts
    {handle, models:[...], max_concurrent_workers, available:bool}. Walks the model chain; within a
    model keeps accounts under their concurrency cap and — when live `usage` (a {handle: {status,
    5h_util,5h_reset,7d_util,7d_reset}} map) is supplied — only accounts that pass `usage_eligible`.
    Orders eligible accounts by EXPIRY-PRIORITY: soonest whole-account weekly reset first (use credits
    before they reset), preserving CACHE AFFINITY, least-loaded, and handle order for equal or unknown
    resets. With `usage=None` the behaviour is the original cache-affinity-then-least-loaded selection
    (backward compatible)."""
    selected = _choose_account_model(
        accounts, leases, model_chain, package, role, now, usage=usage, margin=margin)
    return selected[0]["handle"] if selected is not None else None


def dynamic_concurrency(accounts, usage, model_chain=None, absolute_cap=None, margin=SAFETY_MARGIN,
                        now=None):
    """How many workers may run right now = sum of per-account slots over accounts eligible to START
    (available, optionally serving `model_chain`, and `usage_eligible`). Starts HIGH when many accounts
    have headroom and BACKS OFF automatically as utilisation climbs (ineligible accounts drop out), so
    credits aren't spent on workers that would half-finish. `absolute_cap` is an optional hard ceiling.
    Returns 0 when `usage` is empty/None (probe unavailable) — the caller should then fall back to the
    static policy `max_concurrent`; a returned 0 WITH a non-empty usage map means every account is
    genuinely tapped out and nothing should dispatch."""
    if not usage:
        return 0
    total = 0
    for a in accounts:
        if not a.get("available", True):
            continue
        # [FABLE-5] An account counts only if it is eligible for a model it can actually serve from the
        # chain (a fable-only chain requires fable sub-quota headroom, not just whole-account headroom).
        servable = [m for m in model_chain if m in a.get("models", [])] if model_chain is not None \
            else [None]
        if model_chain is not None and not servable:
            continue
        u = usage.get(a["handle"])
        if any(usage_eligible(u, margin, model=m, now=now) for m in servable):
            total += int(a.get("max_concurrent_workers", 4))
    if absolute_cap is not None:
        total = min(total, absolute_cap)
    return total


def available_account_slots(accounts, leases, model_chain, now, account_pool=None, usage=None,
                            margin=SAFETY_MARGIN):
    """Return the live remaining worker slots able to serve ``model_chain``.

    This is the account-slot bound used by the review/fix dispatcher.  Unlike the historical
    shared ``review:`` / ``fix:`` lease-row caps, it counts each admitted account's configured
    ``max_concurrent_workers`` and subtracts that account's live leases.  Availability, policy
    pool membership, exact model membership, and the usage/backoff gate are all applied before an
    account contributes capacity.  Unknown usage therefore fails closed whenever a usage map is
    supplied, exactly like ``choose_account``; callers that deliberately allow the static path
    pass ``usage=None``.
    """
    live = reclaim_expired(leases, now)
    allowed = set(account_pool) if account_pool is not None else None
    slots = 0
    for account in accounts:
        handle = account.get("handle")
        if not isinstance(handle, str) or not handle:
            continue
        if allowed is not None and handle not in allowed:
            continue
        if not account.get("available", True):
            continue
        servable = [model for model in model_chain if model in account.get("models", [])]
        if not servable:
            continue
        if usage is not None and not any(
                usage_eligible(usage.get(handle), margin, model=model, now=now)
                for model in servable):
            continue
        try:
            cap = int(account.get("max_concurrent_workers", 4))
        except (TypeError, ValueError, OverflowError):
            continue
        slots += max(0, cap - active_for(live, handle))
    return slots


def make_lease(account, holder, package, role, model, now, ttl):
    return {"account": account_fingerprint(account), "claim_id": None, "holder": holder, "package": package,
            "role": role, "model": model, "issued_at": now, "expires_at": now + ttl}


def apply_claim(leases, account, holder, package, role, model, now, ttl, claim_id):
    live = reclaim_expired(leases, now)
    lease = make_lease(account, holder, package, role, model, now, ttl)
    lease["claim_id"] = claim_id
    live.append(lease)
    return live, lease


def apply_release(leases, claim_id, now):
    return [x for x in reclaim_expired(leases, now) if x.get("claim_id") != claim_id]


def claim_commit_message(claim_id, package, role):
    """Public ledger subject: operational identifiers only, never account identity."""
    return f"claim {claim_id[:8]} {package}/{role}"


def holder_key(holder):
    """Stable target-issue identity for duplicate suppression across dispatcher/run attempts."""
    if not isinstance(holder, str) or not holder:
        return ""
    return holder.split("@", 1)[0]


# Every dispatcher-minted holder carries this marker in its run-portion (after `@`):
# dispatch-claim.py mints `<repo>#<n>@dispatch-<run>.<attempt>` (impl lane) and
# `<lane:><repo>#<n>@dispatch-<run>.<attempt>` (review/fix). A worker run that ADOPTS the claim
# rewrites the holder to `<repo>#<n>@<run>.<attempt>` (NO marker), so the marker is what tells a
# still-dispatcher-owned claim apart from one already adopted by a worker (issue #132).
DISPATCHER_RUN_MARKER = "dispatch-"


def adoptable_holder(current, new_holder):
    """Whether the lease currently held by `current` may be CAS-adopted to `new_holder`.

    True only when the lease is STILL dispatcher-owned — its run-portion (after `@`) carries the
    `dispatch-` marker every dispatcher holder is minted with — or when it is ALREADY this exact
    worker run (idempotent re-adopt / revalidation). A holder that is a DIFFERENT worker run (one
    that has already adopted this claim) is rejected, so two runs can never both adopt the same
    claim and a queued worker cannot steal a slot a peer is actively holding (issue #132)."""
    if not isinstance(current, str):
        return False
    if current == new_holder:
        return True
    run_part = current.split("@", 1)[1] if "@" in current else ""
    return run_part.startswith(DISPATCHER_RUN_MARKER)


def partition_available(leases, holder_prefix, package):
    """Whether a repository-scoped package/global partition is free in the active ledger."""
    scoped = [
        lease for lease in leases
        if str(lease.get("holder", "")).startswith(holder_prefix)
    ]
    if package == "__global__":
        return not scoped
    return not any(lease.get("package") in {package, "__global__"} for lease in scoped)


# ---- GitHub CAS I/O -----------------------------------------------------------------------------
def ledger_read_path(repo):
    """Contents-API GET path for the lease ledger, pinned to the data-plane branch (never the
    protected default branch)."""
    return f"repos/{repo}/contents/{LEDGER_PATH}?ref={LEDGER_REF}"


def ledger_write_args(repo, message, content_b64, sha):
    """gh argv for the ledger CAS PUT, pinned to the data-plane branch (never the protected
    default branch — a PUT without `branch=` commits to the default branch and is rejected by
    its required-status-check protection)."""
    args = ["gh", "api", "-X", "PUT", f"repos/{repo}/contents/{LEDGER_PATH}",
            "-f", f"message={message}", "-f", f"content={content_b64}",
            "-f", f"branch={LEDGER_REF}"]
    if sha:
        args += ["-f", f"sha={sha}"]
    return args


def _ledger_branch_exists(repo):
    return subprocess.run(
        ["gh", "api", f"repos/{repo}/git/ref/heads/{LEDGER_REF}"],
        capture_output=True, text=True, check=False,
    ).returncode == 0


def _read_404(branch_exists):
    """Pure 404 policy: file-absent on a PRESENT ledger branch seeds an empty ledger (the first
    CAS PUT creates the file); an ABSENT/unreadable ledger branch fails LOUD — silently-empty
    would let every claim proceed against a ledger no other worker can see."""
    if branch_exists:
        return [], None
    raise LeaseIOError(
        f"ledger branch '{LEDGER_REF}' is missing or unreadable — create it from master "
        "(see data/README.md) before claiming")


def _read_ledger(repo):
    """Return (leases_list, blob_sha or None)."""
    result = subprocess.run(
        ["gh", "api", ledger_read_path(repo)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        if "HTTP 404" in result.stderr:
            return _read_404(_ledger_branch_exists(repo))
        raise LeaseIOError("lease ledger read failed")
    try:
        meta = json.loads(result.stdout)
        content = json.loads(base64.b64decode(meta["content"]).decode() or '{"leases":[]}')
        leases = content.get("leases")
        if not isinstance(leases, list) or any(not isinstance(item, dict) for item in leases):
            raise ValueError("leases must be a list of objects")
        leases = validate_lease_account_identities(leases)
        sha = meta["sha"]
        if not isinstance(sha, str) or not sha:
            raise ValueError("blob sha is missing")
        return leases, sha
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise LeaseIOError("lease ledger is malformed") from exc


# ---- CAS retry backoff (issue #179) -------------------------------------------------------------
# Every CAS writer against the shared ledger tip (claim, release, reclaim — plus groom-leases and
# model-health on their own crons) previously retried immediately, so a burst that collided once
# stayed phase-locked and re-collided on every one of its six attempts, exhausting them all. An
# exponential, FULLY JITTERED sleep between attempts decorrelates the writers so a loser backs off a
# random amount and the tip has settled by its next read. Split ceiling (deterministic, unit-tested)
# from the random draw so the schedule is asserted without depending on the RNG.
def _backoff_ceiling(attempt, base=0.5, cap=8.0):
    """Upper bound (seconds) for the sleep before CAS retry `attempt` (1-based): exponential
    base*2**(attempt-1), clamped to `cap`."""
    return ledger_retry.backoff_ceiling(attempt, base, cap)


def _backoff_delay(attempt):
    return random.uniform(0, _backoff_ceiling(attempt))


def _sleep_backoff(attempt):
    """Sleep a full-jitter exponential backoff before CAS retry `attempt` (module-level so the
    self-test can stub it without sleeping)."""
    ledger_retry.sleep_backoff(attempt, sleeper=time.sleep, draw=random.uniform)


# GitHub's contents-PUT response when a sha-less (create-if-absent) write hits a file that
# appeared concurrently: HTTP 422 with message 'Invalid request.\n\n"sha" wasn't supplied.'
_CREATE_RACE_SIGNATURE = "\"sha\" wasn't supplied"


def _is_cas_conflict(stderr, create):
    """True only for a genuine compare-and-swap conflict on the ledger PUT. HTTP 409 is always a
    lost-SHA race. HTTP 422 counts ONLY when this was a create-if-absent PUT (`create=True`) AND
    the response carries GitHub's create-race signature — any other 422 is an ordinary request-
    validation failure (bad payload/branch) that must fail loud, not be retried as contention."""
    return ledger_retry.is_cas_conflict(stderr, create=create)


def _write_ledger(repo, leases, sha, message):
    """PUT the ledger via CAS. Returns True on success and False ONLY on a genuine CAS conflict
    (HTTP 409, or the create-race 422 on a sha-less PUT) so the caller retries with backoff. ANY
    OTHER PUT failure — authorization (403), missing branch/file (404), request validation
    (non-race 422), server (5xx) — raises LeaseIOError immediately instead of being collapsed into
    a retryable conflict and mislabeled 'CAS kept conflicting' after six wasted, un-backed-off
    attempts (issue #179)."""
    body = base64.b64encode(json.dumps({"leases": leases}, indent=1).encode()).decode()
    r = subprocess.run(ledger_write_args(repo, message, body, sha), capture_output=True, text=True)
    if r.returncode == 0:
        return True
    if _is_cas_conflict(r.stderr, create=sha is None):
        return False  # lost the CAS race → caller re-reads and retries
    raise LeaseIOError(
        "lease ledger CAS PUT failed with a non-conflict error (authorization, validation, "
        "missing branch, or availability) — failing loud rather than exhausting CAS retries")


def reclaim(repo, now, retries=6):
    """CAS-remove expired leases from the ledger so crashed/cancelled workers free their slot.
    Returns the number reclaimed, 0 if none, or -1 if the CAS kept conflicting. A non-conflict PUT
    error (auth/validation/branch/5xx) raises LeaseIOError rather than masquerading as -1."""
    for attempt in range(retries):
        if attempt:
            _sleep_backoff(attempt)
        leases, sha = _read_ledger(repo)
        live = reclaim_expired(leases, now)
        n = len(leases) - len(live)
        if n == 0:
            return 0
        if _write_ledger(repo, live, sha, f"reclaim {n} expired lease(s)"):
            return n
    return -1


# ---- account catalog + live claim / release ----------------------------------------------------
def _run(args):
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise LeaseIOError("registry account catalog read failed")
    return result


def _parse_account(body):
    d = {"models": [], "max_concurrent_workers": 4}
    for line in (body or "").splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k, v = k.strip(), v.strip()
        if k == "models":
            d["models"] = [x.strip() for x in v.strip("[]").split(",") if x.strip()]
        elif k == "max_concurrent_workers":
            d[k] = int(v) if v.isdigit() else 1
        elif k in ("secret_ref", "provider", "harness", "credential_format"):
            d[k] = v
    return d


KNOWN_ACCOUNT_PROVIDERS = frozenset({"anthropic", "openai"})
KNOWN_CREDENTIAL_FORMATS = frozenset({
    "codex-auth-json",
    "claude-credentials-json",
    "claude-oauth-token",
    "anthropic-api-key",
})
ACCOUNT_ISSUE_TITLE_RE = re.compile(r"acct[0-9]+")
ACCOUNT_SECRET_REF_RE = re.compile(r"[A-Z][A-Z0-9_]*")


def _account_schema_errors(account, require_models=True):
    """Return parsed account-schema violations without emitting diagnostics."""
    reasons = []
    handle = account.get("handle")
    if not isinstance(handle, str) or not handle.strip():
        reasons.append("missing handle")
    provider = account.get("provider")
    if provider not in KNOWN_ACCOUNT_PROVIDERS:
        reasons.append("missing provider" if not provider else f"unknown provider {provider!r}")
    credential_format = account.get("credential_format")
    if credential_format not in KNOWN_CREDENTIAL_FORMATS:
        reasons.append("missing credential_format" if not credential_format else
                       f"unknown credential_format {credential_format!r}")
    secret_ref = account.get("secret_ref")
    if not secret_ref:
        reasons.append("missing secret_ref")
    elif ACCOUNT_SECRET_REF_RE.fullmatch(secret_ref) is None:
        reasons.append("unsafe secret_ref")
    if require_models and not account.get("models"):
        reasons.append("missing models")
    return reasons


def account_record_schema_errors(handle, body, require_models=True):
    """Parse a body and return its account-record schema violations without diagnostics.

    Keeping this pure lets the reader use it both for structural selection and for the loud
    validation boundary, and lets every writer reject an invalid replacement body before it
    reaches GitHub. ``require_models=False`` is the structural front-matter predicate: the three
    routing/credential fields are sufficient to identify a record even when its title is not an
    ``acctNN`` handle. Full read/write validation additionally requires a usable handle and model
    list.
    """
    account = _parse_account(body)
    account["handle"] = handle
    return _account_schema_errors(account, require_models=require_models)


def validate_account_record(handle, body):
    """Validate one complete account body for a write, returning its parsed representation.

    The exception text contains field-level corruption reasons but no credential material.
    """
    reasons = account_record_schema_errors(handle, body)
    if reasons:
        raise LeaseIOError(f"account record schema invalid: {'; '.join(reasons)}")
    account = _parse_account(body)
    account["handle"] = handle.strip()
    return account


def _issue_label_names(issue):
    return {
        label.get("name") for label in issue.get("labels", [])
        if isinstance(label, dict) and isinstance(label.get("name"), str)
    }


def select_account_issues(issues):
    """Structurally select account issues from a broad GitHub issue listing.

    A complete, schema-valid provider/credential/secret front-matter triple selects records with
    nonstandard legacy titles. Dedicated markers select fail-closed records even when that schema
    is corrupt: the exact ``account`` label or the ``acct<digits>`` title grammar. Everything else
    is outside the catalog and is silently ignored rather than parsed-and-dropped as corruption.
    This is the one selector used by dispatch claim and worker claim/adoption via ``read_accounts``;
    workflow-side dry-run validation imports it as well.
    """
    if not isinstance(issues, list):
        raise LeaseIOError("registry account catalog listing is malformed")
    selected = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        title = issue.get("title")
        title = title.strip() if isinstance(title, str) else ""
        marked = (ACCOUNT_ISSUE_TITLE_RE.fullmatch(title) is not None
                  or "account" in _issue_label_names(issue))
        front_matter_valid = not account_record_schema_errors(
            title, issue.get("body"), require_models=False)
        if marked or front_matter_valid:
            selected.append(issue)
    return selected


def _valid_catalog_account(account):
    """Reject selected records with malformed schema at the shared catalog parse boundary."""
    reasons = _account_schema_errors(account)
    if reasons:
        print(f"account catalog: dropping account {account.get('handle')!r}: "
              f"{'; '.join(reasons)}", file=sys.stderr)
        return False
    return True


# [FABLE-5] LEGACY-SHAPE NORMALIZATION (sol r3 f1), read-time only. The retired terra-era broker
# minted every openai account record as exactly `models: [terra]`; the current broker
# (set-up-account.yml) mints the FULL codex alias set. Membership gating in this file is LITERAL,
# so a legacy record that survives (or reappears via an old broker run) could never serve a
# sol/luna claim — starving every anthropic-authored PR review while the account sits available.
# Fix: an openai record whose models list is EXACTLY the legacy fingerprint `[terra]` (nothing
# else) expands, at read time, to the catalog's full codex alias set — the provider=openai aliases
# of orchestration/routing.toml ([models.sol]/[models.luna]/[models.terra]). Any OTHER explicit
# list (an operator-restricted `[terra, luna]` or `[sol]`) is preserved VERBATIM — operator
# customization wins over the expansion. The stored account issue is never mutated: the expansion
# applies to the in-memory catalog inside read_accounts — the single catalog read every membership
# consumer shares (claim selection via claim()/choose_account, dynamic-concurrency accounting in
# dispatch-claim.py, claim adoption via inspect_claim, usage probing via account-usage.py) — and
# each expansion is logged to stderr so it stays visible in dispatch/worker logs. PRIVACY (sol r4,
# locked decision 22a/22b): the registry is PUBLIC and the claim workflows redirect only stdout,
# so this stderr diagnostic lands in public Actions logs — and it runs BEFORE account_pool
# filtering, so a raw handle here could enumerate every legacy account. The diagnostic therefore
# NEVER carries a raw handle: with PROVENANCE_SALT present (every runtime path that reaches
# read_accounts exports it — the review-fix.yml claim/adopt steps, the dispatch.yml claim +
# usage-probe steps, the worker.yml claim step) it emits the provenance-record fingerprint
# sha256(handle + ':' + PROVENANCE_SALT)[:16], the exact worker-pr.py account_hash convention, so
# operators can correlate the line with provenance records; without the salt (self-test, ad-hoc
# CLI — `--reclaim` never reads the catalog) it emits a handle-free count-only line. Either way
# one line fires per expansion, so the expansion count stays visible.
LEGACY_OPENAI_SHAPE = ["terra"]              # the retired broker's exact fingerprint
CODEX_ALIAS_SET = ["sol", "luna", "terra"]   # catalog-derived: routing.toml provider=openai aliases


def _diag_account_ref(handle):
    """Public-log-safe account reference for the normalization diagnostic (locked decision 22a):
    the salted provenance fingerprint sha256(handle + ':' + PROVENANCE_SALT)[:16] — the same
    convention as worker-pr.py account_hash / the provenance records — or a handle-free marker
    when the salt is not in-context. NEVER the raw handle."""
    salt = os.environ.get("PROVENANCE_SALT", "")
    if salt and handle:
        return "hash=" + hashlib.sha256(f"{handle}:{salt}".encode()).hexdigest()[:16]
    return "[account ref withheld: PROVENANCE_SALT unset]"


def normalize_legacy_models(account):
    """Legacy-shape normalization, READ-TIME only: expand an openai record whose models list is
    EXACTLY the legacy `[terra]` broker fingerprint to the full codex alias set. Every other list
    passes through verbatim (operator customization wins). Returns a new dict on expansion and
    never mutates the input; each expansion logs one SALTED-HASH-ONLY line to stderr (visible,
    not silent, never the raw handle — stderr reaches public Actions logs)."""
    if account.get("provider") == "openai" and account.get("models") == LEGACY_OPENAI_SHAPE:
        print(f"legacy-shape normalization: 1 legacy openai record "
              f"{_diag_account_ref(account.get('handle'))} "
              f"models {LEGACY_OPENAI_SHAPE} -> {CODEX_ALIAS_SET} (read-time only; the stored "
              "record is unchanged)", file=sys.stderr)
        return {**account, "models": list(CODEX_ALIAS_SET)}
    return account


def read_accounts(repo):
    """The structurally selected account catalog from open issues.

    Non-account issues never reach the drop boundary. Selected records are validated loudly, then
    receive the shared legacy-shape normalization, so dispatch and worker adoption see one pool.
    """
    out = _run(["gh", "issue", "list", "-R", repo, "--state", "open", "--limit", "500",
                "--json", "title,body,labels"]).stdout
    accounts = []
    for it in select_account_issues(json.loads(out or "[]")):
        a = _parse_account(it.get("body"))
        a["handle"] = it["title"].strip()
        a["available"] = "status:available" in _issue_label_names(it)
        if _valid_catalog_account(a):
            accounts.append(normalize_legacy_models(a))
    return accounts


def claim(repo, package, role, model_chain, holder, now, ttl=3600, retries=6,
          account_pool=None, holder_prefix="", max_holder_concurrent=None, usage=None,
          margin=SAFETY_MARGIN, account_slot_bound=False, return_reason=False):
    """CAS-claim a lease. Returns {account, secret_ref, model, claim_id} or None (none free).
    Raises LeaseIOError when an account WAS eligible but the ledger write kept failing — that is an
    infrastructure failure (persistent CAS contention, or the contents-API PUT rejected outright,
    e.g. by a required-status-check branch protection on the ledger's branch), NOT a capacity
    signal, and must not be reported as 'no eligible account' (issue #28).

    ``account_slot_bound`` makes the live sum of remaining per-account slots the aggregate bound.
    It is used by dispatch fan-out instead of a coarse fleet-wide lease-row constant.  Every item
    still takes its own CAS lease, so the account cap, holder-key duplicate check, and package
    partition remain first-writer-wins.  ``return_reason`` is an observability-only extension:
    existing callers retain the historical claim-or-None return, while the dispatcher receives
    ``(claim, reason)`` and can distinguish capacity from single-flight deferral.
    """
    import uuid

    def result(value, reason=""):
        return (value, reason) if return_reason else value

    accounts = read_accounts(repo)
    if account_pool is not None:
        allowed = set(account_pool)
        accounts = [account for account in accounts if account["handle"] in allowed]
    for attempt in range(retries):
        if attempt:
            _sleep_backoff(attempt)
        leases, sha = _read_ledger(repo)
        live = reclaim_expired(leases, now)
        key = holder_key(holder)
        if key and any(holder_key(lease.get("holder")) == key for lease in live):
            return result(None, "pr-single-flight")
        if holder_prefix and not partition_available(live, holder_prefix, package):
            return result(None, "package-single-flight")
        if max_holder_concurrent is not None:
            if max_holder_concurrent <= 0 or not holder_prefix:
                return result(None, "lane-cap")
            active_holders = sum(
                1 for lease in live if str(lease.get("holder", "")).startswith(holder_prefix)
            )
            if active_holders >= max_holder_concurrent:
                return result(None, "lane-cap")
        if account_slot_bound and available_account_slots(
                accounts, live, model_chain, now, usage=usage, margin=margin) <= 0:
            return result(None, "no-account-slots")
        selected = _choose_account_model(
            accounts, live, model_chain, package, role, now, usage=usage, margin=margin)
        if selected is None:
            return result(None, "no-account-slots")
        a, model = selected
        acct = a["handle"]
        cid = uuid.uuid4().hex
        live, _lease = apply_claim(leases, acct, holder, package, role, model, now, ttl, cid)
        if _write_ledger(repo, live, sha, claim_commit_message(cid, package, role)):
            return result({
                "account": acct,
                "secret_ref": a.get("secret_ref"),
                "provider": a.get("provider"),
                "harness": a.get("harness"),
                "credential_format": a.get("credential_format"),
                "model": model,
                "claim_id": cid,
            })
    # Every retry found an eligible account yet the write never landed: an infra failure, not
    # a capacity condition. Raising (vs returning None) keeps the dispatcher's defer reason
    # honest — live incident 2026-07-17: a required `gate` status check added to the default
    # branch rejected every github-actions ledger PUT and every claim in BOTH target repos was
    # mislabeled "duplicate lease, repository cap, or account cap is active" for hours while
    # accounts were healthy and the lease ledger was empty.
    raise LeaseIOError(
        f"lease ledger write kept failing after {retries} attempts (persistent CAS contention, "
        f"or the {LEDGER_PATH} contents PUT is being rejected — e.g. branch protection with a "
        "required status check on the ledger branch blocks github-actions pushes)")


def inspect_claim(repo, claim_id, now, expected_holder_prefix=""):
    """Return one active lease plus its current account metadata, or None if it is not adoptable."""
    leases, _sha = _read_ledger(repo)
    matches = [
        lease for lease in reclaim_expired(leases, now)
        if lease.get("claim_id") == claim_id
    ]
    if len(matches) != 1:
        return None
    lease = matches[0]
    if expected_holder_prefix and not str(lease.get("holder", "")).startswith(expected_holder_prefix):
        return None
    accounts = [
        account for account in read_accounts(repo)
        if account_fingerprint(account.get("handle")) == lease.get("account")
        and account.get("available")
    ]
    if len(accounts) != 1 or lease.get("model") not in accounts[0].get("models", []):
        return None
    account = accounts[0]
    return {
        **lease,
        "account": account.get("handle"),
        "secret_ref": account.get("secret_ref"),
        "provider": account.get("provider"),
        "harness": account.get("harness"),
        "credential_format": account.get("credential_format"),
    }


def adopt(repo, claim_id, new_holder, now, ttl, expected_holder_prefix="", retries=6):
    """CAS-transfer a dispatcher-owned lease to this worker run — an OWNERSHIP change, not the
    read-only look inspect_claim performs (issue #132).

    Under compare-and-swap it rewrites the matched lease's holder to `new_holder` (the exact worker
    run) and re-bases its expiry to now+ttl, ONCE. It refuses — returning None — when the claim_id
    is expired/gone (reclaim_expired dropped it, so a queued worker cannot resurrect a stale,
    possibly-reallocated slot), when the holder does not start with `expected_holder_prefix` (a
    different issue), or when the lease is already adopted by another worker run (adoptable_holder),
    so no two runs ever share a lease. Returns the transferred lease plus account metadata (exactly
    the shape inspect_claim returned) on success. Raises LeaseIOError when the ledger write kept
    failing — an infrastructure failure that must fail LOUD, never masquerade as not-adoptable
    (mirrors claim()'s issue #28 contract)."""
    for attempt in range(retries):
        if attempt:
            _sleep_backoff(attempt)
        leases, sha = _read_ledger(repo)
        live = reclaim_expired(leases, now)
        matches = [lease for lease in live if lease.get("claim_id") == claim_id]
        if len(matches) != 1:
            return None
        lease = matches[0]
        holder = str(lease.get("holder", ""))
        if expected_holder_prefix and not holder.startswith(expected_holder_prefix):
            return None
        if not adoptable_holder(holder, new_holder):
            return None
        accounts = [
            account for account in read_accounts(repo)
            if account_fingerprint(account.get("handle")) == lease.get("account")
            and account.get("available")
        ]
        if len(accounts) != 1 or lease.get("model") not in accounts[0].get("models", []):
            return None
        account = accounts[0]
        transferred = {**lease, "holder": new_holder, "issued_at": now, "expires_at": now + ttl}
        next_leases = [
            transferred if row.get("claim_id") == claim_id else row
            for row in live
        ]
        if _write_ledger(repo, next_leases, sha, f"adopt {claim_id[:8]} -> worker run"):
            return {
                **transferred,
                "account": account.get("handle"),
                "secret_ref": account.get("secret_ref"),
                "provider": account.get("provider"),
                "harness": account.get("harness"),
                "credential_format": account.get("credential_format"),
            }
    raise LeaseIOError(
        f"lease ledger adopt CAS write kept failing after {retries} attempts (persistent CAS "
        f"contention, or the {LEDGER_PATH} contents PUT is being rejected) — failing loud rather "
        "than reporting an adoptable claim as not adoptable")


def release(repo, claim_id, now, retries=6):
    for attempt in range(retries):
        if attempt:
            _sleep_backoff(attempt)
        leases, sha = _read_ledger(repo)
        live = apply_release(leases, claim_id, now)
        if len(live) == len(leases):
            return True
        if _write_ledger(repo, live, sha, f"release {claim_id[:8]}"):
            return True
    return False


# ---- self-test ----------------------------------------------------------------------------------
def _self_test():
    ok = True
    # Lease identity is unusable without the production salt. A fixed test-only salt makes every
    # allocation assertion exercise the hash-only ledger representation.
    original_selftest_salt = os.environ.get("PROVENANCE_SALT")
    os.environ["PROVENANCE_SALT"] = "select-and-claim-self-test"

    def check(n, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {n}: {got} (want {want})")

    A = [
        {"handle": "acct01", "models": ["terra"], "max_concurrent_workers": 1, "available": True},
        {"handle": "acct02", "models": ["fable", "sonnet", "opus", "haiku"], "max_concurrent_workers": 2, "available": True},
    ]
    now = 1000
    check("route fable", choose_account(A, [], ["fable"], "pkg", "impl", now), "acct02")
    check("route terra", choose_account(A, [], ["terra", "fable"], "pkg", "impl", now), "acct01")
    # Broker-minted openai records (set-up-account.yml) carry the FULL codex alias set
    # [sol, luna, terra]: exact alias membership is what choose_account gates on, so the full
    # set satisfies a sol-led claim while a terra-only LIST at this pure-gate level defers it
    # (sol r2 f1). The gate stays LITERAL by design — it is read_accounts' legacy-shape
    # normalization (sol r3 f1, tested below) that rescues the exact legacy broker fingerprint
    # before it ever reaches this gate; a customized list is never expanded.
    BM = [{"handle": "acct09", "models": ["sol", "luna", "terra"], "max_concurrent_workers": 1,
           "available": True}]
    check("broker openai record [sol, luna, terra] serves a sol claim",
          choose_account(BM, [], ["sol", "luna"], "pkg", "impl", now), "acct09")
    check("un-normalized terra-only list defers a sol claim (the membership gate stays literal)",
          choose_account(A, [], ["sol", "luna"], "pkg", "impl", now), None)

    # ---- read-time legacy-shape normalization (sol r3 f1) ----
    import contextlib
    import io
    from types import SimpleNamespace

    # Pure: ONLY the exact legacy openai `[terra]` fingerprint expands; the input record is
    # never mutated (read-time only, no silent rewrite of the stored account issue).
    legacy_rec = {"handle": "acctL", "provider": "openai", "models": ["terra"]}
    with contextlib.redirect_stderr(io.StringIO()):
        norm_rec = normalize_legacy_models(legacy_rec)
    check("exact legacy [terra] expands to the full codex alias set",
          norm_rec["models"], ["sol", "luna", "terra"])
    check("normalization never mutates the input record", legacy_rec["models"], ["terra"])
    check("customized [terra, luna] preserved verbatim (operator restriction wins)",
          normalize_legacy_models({"handle": "c", "provider": "openai",
                                   "models": ["terra", "luna"]})["models"], ["terra", "luna"])
    check("restricted [sol] preserved verbatim",
          normalize_legacy_models({"handle": "c", "provider": "openai",
                                   "models": ["sol"]})["models"], ["sol"])
    check("broker-minted [sol, luna, terra] passes through unchanged",
          normalize_legacy_models({"handle": "c", "provider": "openai",
                                   "models": ["sol", "luna", "terra"]})["models"],
          ["sol", "luna", "terra"])
    check("non-openai record never expands (provider-scoped fingerprint)",
          normalize_legacy_models({"handle": "c", "provider": "anthropic",
                                   "models": ["terra"]})["models"], ["terra"])

    # End-to-end through the REAL read_accounts (gh issue list stubbed): the expansion is applied
    # at the single catalog read EVERY membership consumer shares, and it is LOGGED (visible) —
    # but SALTED-HASH-ONLY (sol r4, locked decision 22a/22b): stderr reaches public Actions logs
    # and normalization runs before account_pool filtering, so a raw handle here would enumerate
    # every legacy account. Both salt states are exercised, and a NEGATIVE sweep asserts no
    # fixture handle ever reaches the captured stderr/stdout.
    FIXTURE_HANDLES = ("acctL", "acctC")
    issue_rows = json.dumps([
        {"title": "acctL", "body": "provider: openai\nmodels: [terra]\nsecret_ref: L_TOKEN\n"
         "credential_format: codex-auth-json",
         "labels": [{"name": "status:available"}]},
        {"title": "acctC", "body": "provider: openai\nmodels: [terra, luna]\nsecret_ref: C_TOKEN\n"
         "credential_format: codex-auth-json",
         "labels": [{"name": "status:available"}]},
    ])
    real_run_fn = globals()["_run"]
    globals()["_run"] = lambda args: SimpleNamespace(stdout=issue_rows)
    saved_salt = os.environ.pop("PROVENANCE_SALT", None)
    os.environ["PROVENANCE_SALT"] = "selftest-salt"
    log_buf, out_buf = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stderr(log_buf), contextlib.redirect_stdout(out_buf):
            norm_cat = read_accounts("o/r")
    finally:
        globals()["_run"] = real_run_fn
        os.environ.pop("PROVENANCE_SALT", None)
    check("read_accounts expands ONLY the exact legacy shape",
          {a["handle"]: a["models"] for a in norm_cat},
          {"acctL": ["sol", "luna", "terra"], "acctC": ["terra", "luna"]})
    # (a) the diagnostic still fires, referencing the account ONLY by its salted provenance
    # fingerprint (the exact worker-pr.py account_hash convention: sha256(h + ':' + salt)[:16]).
    expected_hash = hashlib.sha256(b"acctL:selftest-salt").hexdigest()[:16]
    check("normalization diagnostic fires with the salted hash (no silent expansion)",
          "legacy-shape normalization" in log_buf.getvalue()
          and f"hash={expected_hash}" in log_buf.getvalue(), True)
    check("exactly one expansion line fires (count stays visible)",
          log_buf.getvalue().count("legacy-shape normalization"), 1)
    # (b) NEGATIVE (locked decision 22a): no raw fixture handle — expanded OR pass-through —
    # appears anywhere in the captured stderr/stdout.
    check("NEGATIVE: no raw fixture handle leaks into stderr/stdout",
          [h for h in FIXTURE_HANDLES
           if h in log_buf.getvalue() or h in out_buf.getvalue()], [])
    # Salt-less fallback (self-test / ad-hoc CLI context): the diagnostic still fires as a
    # handle-free count-only line — never falls back to the raw handle.
    globals()["_run"] = lambda args: SimpleNamespace(stdout=issue_rows)
    log_buf2, out_buf2 = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stderr(log_buf2), contextlib.redirect_stdout(out_buf2):
            read_accounts("o/r")
    finally:
        globals()["_run"] = real_run_fn
        if saved_salt is not None:
            os.environ["PROVENANCE_SALT"] = saved_salt
    check("salt-less diagnostic still fires, handle-free (count-only)",
          "legacy-shape normalization" in log_buf2.getvalue()
          and "PROVENANCE_SALT unset" in log_buf2.getvalue(), True)
    check("NEGATIVE: salt-less path leaks no raw fixture handle either",
          [h for h in FIXTURE_HANDLES
           if h in log_buf2.getvalue() or h in out_buf2.getvalue()], [])

    # ---- fail-closed account-catalog parse boundary (issue #424) ----
    # Reproduce the outage alongside healthy rows: the legacy acct01-shaped openai record has no
    # credential_format, while two valid records and two other malformed records share its catalog.
    boundary_rows = json.dumps([
        {"title": "healthy-openai",
         "body": "provider: openai\nharness: codex\nmodels: [sol]\n"
                 "credential_format: codex-auth-json\nsecret_ref: OPENAI_TOKEN",
         "labels": [{"name": "status:available"}]},
        {"title": "healthy-anthropic",
         "body": "provider: anthropic\nharness: claude\nmodels: [fable]\n"
                 "credential_format: claude-credentials-json\nsecret_ref: ANTHROPIC_TOKEN",
         "labels": [{"name": "status:available"}]},
        {"title": "acct01",
         "body": "provider: openai\nharness: codex\nmodels: [terra]\nsecret_ref: ACCT01_TOKEN",
         "labels": [{"name": "status:available"}]},
        {"title": "unknown-provider",
         "body": "provider: legacy\nharness: codex\nmodels: [terra]\n"
                 "credential_format: codex-auth-json\nsecret_ref: LEGACY_TOKEN",
         "labels": [{"name": "account"}, {"name": "status:available"}]},
        {"title": "bad-credential-format",
         "body": "provider: anthropic\nharness: claude\nmodels: [fable]\n"
                 "credential_format: legacy-token\nsecret_ref: BAD_TOKEN",
         "labels": [{"name": "account"}, {"name": "status:available"}]},
    ])
    globals()["_run"] = lambda args: SimpleNamespace(stdout=boundary_rows)
    boundary_log = io.StringIO()
    try:
        with contextlib.redirect_stderr(boundary_log):
            boundary_catalog = read_accounts("o/r")
    finally:
        globals()["_run"] = real_run_fn
    boundary_handles = [account["handle"] for account in boundary_catalog]
    check("valid provider+credential_format rows are kept",
          boundary_handles, ["healthy-openai", "healthy-anthropic"])
    check("missing credential_format is dropped at parse (acct01 outage regression)",
          "acct01" not in boundary_handles, True)
    check("unknown provider is dropped at parse",
          "unknown-provider" not in boundary_handles, True)
    check("out-of-set credential_format is dropped at parse",
          "bad-credential-format" not in boundary_handles, True)
    check("one bad row does not drop healthy rows", len(boundary_catalog), 2)
    check("missing credential_format warning names handle and reason",
          "dropping account 'acct01': missing credential_format" in boundary_log.getvalue(), True)
    check("unknown provider warning names handle and reason",
          "dropping account 'unknown-provider': unknown provider 'legacy'"
          in boundary_log.getvalue(), True)
    check("out-of-set credential_format warning names handle and reason",
          "dropping account 'bad-credential-format': unknown credential_format 'legacy-token'"
          in boundary_log.getvalue(), True)

    # ---- structural account-issue selection (issue #521 escalation tripwires) ----
    # A broad issue listing is expected: audit/work items live beside account records. Only the
    # shared selector may reduce it. A non-account audit issue is silent; marker-selected corruption
    # stays loud; both dispatcher reads and worker adoption resolve the identical healthy pool.
    mixed_rows = json.dumps([
        {"title": "[sol-audit ledgergate] ordinary work item",
         "body": "The dispatcher and worker policy pools need an audit.\nNo account metadata here.",
         "labels": [{"name": "role:ci"}]},
        {"title": "acct21",
         "body": "provider: openai\nmodels: [sol]\ncredential_format: codex-auth-json\n"
                 "secret_ref: ACCT21_TOKEN",
         "labels": [{"name": "status:available"}]},
        {"title": "named-anthropic",
         "body": "provider: anthropic\nmodels: [opus]\n"
                 "credential_format: claude-oauth-token\nsecret_ref: NAMED_ANTHROPIC_TOKEN",
         "labels": [{"name": "status:available"}]},
        {"title": "acct22",
         "body": "provider: openai\nmodels: [sol]\ncredential_format: codex-auth-json",
         "labels": [{"name": "status:available"}]},
        {"title": "explicitly-marked-corrupt",
         "body": "provider: retired\nmodels: [opus]\n"
                 "credential_format: claude-oauth-token\nsecret_ref: RETIRED_TOKEN",
         "labels": [{"name": "account"}, {"name": "status:available"}]},
    ])
    globals()["_run"] = lambda args: SimpleNamespace(stdout=mixed_rows)
    mixed_log = io.StringIO()
    try:
        with contextlib.redirect_stderr(mixed_log):
            dispatcher_pool = read_accounts("o/r")
    finally:
        globals()["_run"] = real_run_fn
    check("structural select: audit issue is not a candidate",
          [account["handle"] for account in dispatcher_pool],
          ["acct21", "named-anthropic"])
    check("structural select: non-account audit issue produces no drop line",
          "sol-audit ledgergate" in mixed_log.getvalue(), False)
    check("structural select: acctNN-selected corrupt record still drops loudly",
          "dropping account 'acct22': missing secret_ref" in mixed_log.getvalue(), True)
    check("structural select: account-label-selected corrupt record still drops loudly",
          "dropping account 'explicitly-marked-corrupt': unknown provider 'retired'"
          in mixed_log.getvalue(), True)

    mixed_leases = []
    mixed_claims = {}
    for index, account in enumerate(dispatcher_pool):
        claim_id = f"MIXED{index}"
        lease = make_lease(account["handle"], "o/r#21@dispatch.1", "p", "impl",
                           account["models"][0], now, 100)
        lease["claim_id"] = claim_id
        mixed_leases.append(lease)
        mixed_claims[account["handle"]] = claim_id
    saved_mixed_ledger = globals()["_read_ledger"]
    globals()["_run"] = lambda args: SimpleNamespace(stdout=mixed_rows)
    globals()["_read_ledger"] = lambda repo: (mixed_leases, "sha0")
    worker_pool = []
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            for account in dispatcher_pool:
                if inspect_claim("o/r", mixed_claims[account["handle"]], now,
                                 expected_holder_prefix="o/r#21@"):
                    worker_pool.append(account["handle"])
    finally:
        globals()["_run"] = real_run_fn
        globals()["_read_ledger"] = saved_mixed_ledger
    check("structural select: dispatcher and worker adoption resolve the same mixed-fixture pool",
          worker_pool, [account["handle"] for account in dispatcher_pool])

    valid_write_body = ("provider: openai\nmodels: [sol]\n"
                        "credential_format: codex-auth-json\nsecret_ref: ACCT23_TOKEN")
    check("account write guard accepts a schema-valid record",
          validate_account_record("acct23", valid_write_body)["secret_ref"], "ACCT23_TOKEN")
    try:
        validate_account_record(
            "acct23", "provider: openai\nmodels: [sol]\ncredential_format: codex-auth-json")
        check("account write guard rejects an invalid record before persistence",
              "no exception", "LeaseIOError")
    except LeaseIOError as exc:
        check("account write guard rejects an invalid record before persistence",
              (type(exc).__name__, "missing secret_ref" in str(exc)), ("LeaseIOError", True))

    # CLAIM SELECTION: a legacy [terra] record now serves a sol-led claim end-to-end (claim()
    # reads the catalog through read_accounts), while a customized [terra, luna] record still
    # does NOT serve a sol-only chain.
    saved_rl, saved_wl = globals()["_read_ledger"], globals()["_write_ledger"]
    globals()["_run"] = lambda args: SimpleNamespace(stdout=issue_rows)
    globals()["_read_ledger"] = lambda repo: ([], "sha0")
    globals()["_write_ledger"] = lambda repo, leases, sha, msg: True
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            legacy_claim = claim("o/r", "p", "review", ["sol", "luna"],
                                 "review:o/r#1@run", now)
            customized_claim = claim("o/r", "p", "review", ["sol"], "review:o/r#2@run", now,
                                     account_pool=["acctC"])
    finally:
        globals()["_run"] = real_run_fn
        globals()["_read_ledger"], globals()["_write_ledger"] = saved_rl, saved_wl
    check("legacy [terra] record serves a sol claim (read-time expansion)",
          (legacy_claim and legacy_claim["account"], legacy_claim and legacy_claim["model"]),
          ("acctL", "sol"))
    check("fresh claim returns the plain account handle",
          legacy_claim and legacy_claim["account"], "acctL")
    check("customized [terra, luna] does NOT serve a sol-only claim", customized_claim, None)

    # DYNAMIC-CONCURRENCY ACCOUNTING: dispatch-claim.py feeds read_accounts output straight into
    # dynamic_concurrency, so the normalized legacy record counts capacity for a sol chain
    # (openai accounts are probe-exempt) while the customized record does not.
    exempt_usage = {"acctL": {"exempt": True}, "acctC": {"exempt": True}}
    check("dynamic concurrency counts the normalized legacy record for a sol chain",
          dynamic_concurrency(norm_cat, exempt_usage, ["sol"], now=now), 4)

    # CLAIM ADOPTION: a sol lease held on the legacy account is adoptable — inspect_claim's
    # model-membership check reads the SAME normalized catalog.
    sol_lease = {**make_lease("acctL", "o/r#1@run", "p", "impl", "sol", now, 100),
                 "claim_id": "CIDL"}
    globals()["_run"] = lambda args: SimpleNamespace(stdout=issue_rows)
    globals()["_read_ledger"] = lambda repo: ([sol_lease], "sha0")
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            adopted = inspect_claim("o/r", "CIDL", now)
    finally:
        globals()["_run"] = real_run_fn
        globals()["_read_ledger"] = saved_rl
    check("sol lease on a legacy [terra] record is adoptable (adoption path normalized)",
          adopted and adopted.get("secret_ref"), "L_TOKEN")
    check("inspect_claim returns the plain account handle",
          adopted and adopted.get("account"), "acctL")

    # ---- CAS adopt: ownership TRANSFER, not a read-only inspect (issue #132) ----
    # adoptable_holder pure gate: a dispatcher-marked holder transfers; a DIFFERENT worker run is
    # refused (two runs can never both adopt); the exact same worker run re-adopts idempotently
    # (revalidation/heartbeat); a garbage/holderless value is refused.
    WORKER_HOLDER = "o/r#7@run9.1"
    check("adoptable: a dispatcher-held lease is adoptable",
          adoptable_holder("o/r#7@dispatch-42.1", WORKER_HOLDER), True)
    check("adoptable: another worker run is NOT adoptable (already adopted elsewhere)",
          adoptable_holder("o/r#7@run8.1", WORKER_HOLDER), False)
    check("adoptable: the exact same worker run re-adopts (idempotent revalidation)",
          adoptable_holder(WORKER_HOLDER, WORKER_HOLDER), True)
    check("adoptable: a garbage/holderless value is refused",
          adoptable_holder("no-at-marker", WORKER_HOLDER), False)

    # End-to-end adopt through a stubbed ledger. The holder is CAS-rewritten to the worker run and
    # the expiry is RE-BASED to now+ttl — a read-only inspect would leave both unchanged, so these
    # assertions flip red if adopt ever regresses to an inspect. Metadata mirrors inspect_claim.
    # Issued 500s ago with a still-LIVE 3600s ttl (expires now+3100), so the adopt re-base to
    # now+3600 is observably different from the dispatcher's original expiry.
    disp_lease = {**make_lease("acctL", "o/r#7@dispatch-42.1", "p", "impl", "sol", now - 500, 3600),
                  "claim_id": "ADOPTCID"}
    adopt_writes = {}

    def _capture_adopt_write(repo, leases, sha, msg):
        adopt_writes["leases"] = leases
        adopt_writes["msg"] = msg
        return True

    globals()["_run"] = lambda args: SimpleNamespace(stdout=issue_rows)
    globals()["_read_ledger"] = lambda repo: ([dict(disp_lease)], "sha0")
    globals()["_write_ledger"] = _capture_adopt_write
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            adopted_lease = adopt("o/r", "ADOPTCID", WORKER_HOLDER, now, 3600,
                                  expected_holder_prefix="o/r#7@")
    finally:
        globals()["_run"] = real_run_fn
        globals()["_read_ledger"], globals()["_write_ledger"] = saved_rl, saved_wl
    check("adopt transfers the holder to the exact worker run (CAS write, not inspect)",
          adopted_lease and adopted_lease["holder"], WORKER_HOLDER)
    check("adopt re-bases expiry to now+ttl (refreshes the lease for the worker's full run)",
          adopted_lease and adopted_lease["expires_at"], now + 3600)
    check("adopt returns the account secret_ref (metadata shape like inspect_claim)",
          adopted_lease and adopted_lease.get("secret_ref"), "L_TOKEN")
    check("adopt returns the plain account handle",
          adopted_lease and adopted_lease.get("account"), "acctL")
    expected_handle, account_pool = "acctL", ["acctL", "acctC"]
    check("adopted claim passes the worker's exact account policy check",
          (adopted_lease and adopted_lease.get("account") == expected_handle
           and adopted_lease.get("account") in account_pool), True)
    check("adopt persisted exactly the transferred holder to the ledger",
          [row["holder"] for row in adopt_writes.get("leases", [])], [WORKER_HOLDER])
    check("adopt keeps the salted account fingerprint in the persisted ledger",
          [row["account"] for row in adopt_writes.get("leases", [])],
          [account_fingerprint("acctL")])
    check("adopt preserves the stable holder_key (same target issue across the transfer)",
          holder_key(adopted_lease["holder"]), "o/r#7")

    # rejects already-adopted: a lease already held by ANOTHER worker run is refused, and the
    # ledger is never written (no CAS write is even attempted).
    other_adopted = {**disp_lease, "holder": "o/r#7@run8.1"}
    write_called = {"hit": False}

    def _forbid_write(repo, leases, sha, msg):
        write_called["hit"] = True
        return True

    globals()["_run"] = lambda args: SimpleNamespace(stdout=issue_rows)
    globals()["_read_ledger"] = lambda repo: ([dict(other_adopted)], "sha0")
    globals()["_write_ledger"] = _forbid_write
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            reject_adopted = adopt("o/r", "ADOPTCID", WORKER_HOLDER, now, 3600,
                                   expected_holder_prefix="o/r#7@")
    finally:
        globals()["_run"] = real_run_fn
        globals()["_read_ledger"], globals()["_write_ledger"] = saved_rl, saved_wl
    check("adopt REJECTS a claim already adopted by another worker run", reject_adopted, None)
    check("adopt never writes the ledger when it rejects (no lease stolen)",
          write_called["hit"], False)

    # a queued worker whose dispatcher lease has EXPIRED (reclaim_expired drops it) finds no match
    # and is refused — it cannot resurrect a stale, possibly-reallocated slot.
    expired_lease = {**disp_lease, "expires_at": now - 1}
    globals()["_run"] = lambda args: SimpleNamespace(stdout=issue_rows)
    globals()["_read_ledger"] = lambda repo: ([dict(expired_lease)], "sha0")
    globals()["_write_ledger"] = lambda repo, leases, sha, msg: True
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            reject_expired = adopt("o/r", "ADOPTCID", WORKER_HOLDER, now, 3600,
                                   expected_holder_prefix="o/r#7@")
    finally:
        globals()["_run"] = real_run_fn
        globals()["_read_ledger"], globals()["_write_ledger"] = saved_rl, saved_wl
    check("adopt refuses an EXPIRED dispatcher lease (no resurrection after reallocation)",
          reject_expired, None)

    # the claim_id exists but belongs to a DIFFERENT issue -> refused on the holder prefix.
    globals()["_run"] = lambda args: SimpleNamespace(stdout=issue_rows)
    globals()["_read_ledger"] = lambda repo: ([dict(disp_lease)], "sha0")
    globals()["_write_ledger"] = lambda repo, leases, sha, msg: True
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            reject_prefix = adopt("o/r", "ADOPTCID", WORKER_HOLDER, now, 3600,
                                  expected_holder_prefix="o/r#8@")
    finally:
        globals()["_run"] = real_run_fn
        globals()["_read_ledger"], globals()["_write_ledger"] = saved_rl, saved_wl
    check("adopt refuses when the holder prefix is a different issue", reject_prefix, None)

    # a persistent CAS write failure on an ADOPTABLE lease RAISES (infra failure) rather than
    # masquerading as not-adoptable (claim()'s #28 fail-loud contract).
    globals()["_run"] = lambda args: SimpleNamespace(stdout=issue_rows)
    globals()["_read_ledger"] = lambda repo: ([dict(disp_lease)], "sha0")
    globals()["_write_ledger"] = lambda repo, leases, sha, msg: False
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            adopt("o/r", "ADOPTCID", WORKER_HOLDER, now, 3600, expected_holder_prefix="o/r#7@")
        check("adopt raises on persistent CAS write failure", "no exception", "LeaseIOError")
    except LeaseIOError:
        check("adopt raises on persistent CAS write failure", "LeaseIOError", "LeaseIOError")
    finally:
        globals()["_run"] = real_run_fn
        globals()["_read_ledger"], globals()["_write_ledger"] = saved_rl, saved_wl

    # ---- WORKER.YML DRY-RUN PATH (round 5): the embedded "Validate dry-run account" heredoc
    # imports this module and must route its parsed record through the SAME read-time
    # legacy-shape normalization as read_accounts. It historically called _parse_account()
    # directly (literal model membership), so a legacy `models: [terra]` record failed the
    # sol-led dry-run even though the live claim path normalizes it. This extracts the REAL
    # heredoc from worker.yml and runs it against a legacy fixture that a sol route must
    # accept — red if the normalization call is ever dropped again. Fail closed: a missing
    # worker.yml / heredoc marker is a failure, not a skip (the enrolled-suite convention).
    import tempfile
    import textwrap
    from pathlib import Path

    wf_path = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "worker.yml"
    dryrun_rc, dryrun_out, dryrun_err, dryrun_gh_output = None, "", "", ""
    try:
        wf_text = wf_path.read_text(encoding="utf-8")
        step_at = wf_text.index("Validate dry-run account against resolved policy")
        hd_start = wf_text.index("<<'PY'\n", step_at) + len("<<'PY'\n")
        hd_end = wf_text.index("\n          PY\n", hd_start)
        dryrun_script = textwrap.dedent(wf_text[hd_start:hd_end])
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "target-routing").mkdir()
            (tdp / "target-routing" / "routing.toml").write_text(
                '[models.sol]\nprovider = "openai"\nharness = "codex"\n'
                'provider_model = "gpt-5.6-sol"\ncredential_format = "codex-auth-json"\n',
                encoding="utf-8")
            policy_path = tdp / "policy.json"
            policy_path.write_text(json.dumps({
                "routing": "routing.toml",
                "model_chain": ["sol", "luna", "terra"],
                "account_pool": ["acctlegacy"],
            }), encoding="utf-8")
            accounts_path = tdp / "accounts.json"
            accounts_path.write_text(json.dumps([{
                "title": "acctlegacy",
                "body": "provider: openai\nharness: codex\nmodels: [terra]\n"
                        "credential_format: codex-auth-json\nsecret_ref: ACCTLEGACY_TOKEN\n"
                        "max_concurrent_workers: 2",
                "labels": [{"name": "status:available"}],
            }]), encoding="utf-8")
            gh_output_path = tdp / "github_output"
            env = {k: v for k, v in os.environ.items() if k != "PROVENANCE_SALT"}
            env.update({"GITHUB_WORKSPACE": str(tdp), "ACCOUNT": "acctlegacy",
                        "GITHUB_OUTPUT": str(gh_output_path)})
            proc = subprocess.run(
                [sys.executable, "-", str(Path(__file__).resolve()),
                 str(policy_path), str(accounts_path)],
                input=dryrun_script, capture_output=True, text=True, env=env, check=False)
            dryrun_rc, dryrun_out, dryrun_err = proc.returncode, proc.stdout, proc.stderr
            if gh_output_path.exists():
                dryrun_gh_output = gh_output_path.read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:
        print(f"  FAIL worker.yml dry-run heredoc extraction: {exc}")
        ok = False
    dryrun_err_tail = dryrun_err.strip().splitlines()[-1] if dryrun_err.strip() else ""
    check(f"worker.yml dry-run validates a legacy [terra] record for a sol route "
          f"(stderr tail: {dryrun_err_tail!r})", dryrun_rc, 0)
    check("worker.yml dry-run resolves model=sol through the shared normalization",
          "model=sol" in dryrun_gh_output and "harness=codex" in dryrun_gh_output, True)
    check("worker.yml dry-run normalization diagnostic fires (shared function, not a re-impl)",
          "legacy-shape normalization" in dryrun_err, True)
    check("NEGATIVE: worker.yml dry-run leaks no raw handle to stdout/stderr",
          [s for s in ("stdout", "stderr")
           if "acctlegacy" in {"stdout": dryrun_out, "stderr": dryrun_err}[s]], [])

    # ---- WORKER.YML FAIL-CLOSED ROUTING METADATA (issue #142): the three embedded heredocs
    # that gate account routing metadata are trust checks with no script of their own, so the
    # enrolled suite executes the REAL workflow text. (a) The self-claim and adopt output
    # heredocs must reject a claim whose provider/harness/credential_format is missing or
    # empty instead of defaulting it to "" (the old `claim.get(...) or ""`). (b) The live
    # selected-model heredoc must require EXACT equality with protected routing — the old
    # `if claimed_provider and ...` guard skipped the comparison for an EMPTY claimed value
    # and would expose a secret on metadata the account never declared. Every EMPTY/MISSING
    # rejection below goes red if either permissive form returns; the fully-populated success
    # and mismatched-value failure controls prove the fixtures drive the real code path.
    # Fail closed: extraction or fixture failure is a FAIL, never a skip.
    try:
        wf_all = wf_path.read_text(encoding="utf-8")

        def _wf_heredoc(step_marker):
            step_at = wf_all.index(step_marker)
            start = wf_all.index("<<'PY'\n", step_at) + len("<<'PY'\n")
            end = wf_all.index("\n          PY\n", start)
            return textwrap.dedent(wf_all[start:end])

        claim_hd = _wf_heredoc("CAS claim from the policy-filtered account pool")
        adopt_hd = _wf_heredoc("Adopt dispatcher-owned CAS claim (ownership transfer)")
        selected_hd = _wf_heredoc("Resolve claimed account to concrete target model")

        def _run_hd(script, argv, extra_env, td):
            gh_out = Path(td) / "github_output"
            if gh_out.exists():
                gh_out.unlink()
            env = {k: v for k, v in os.environ.items() if k != "PROVENANCE_SALT"}
            env["GITHUB_OUTPUT"] = str(gh_out)
            env.update(extra_env)
            proc = subprocess.run([sys.executable, "-", *argv], input=script,
                                  capture_output=True, text=True, env=env, check=False)
            out = gh_out.read_text(encoding="utf-8") if gh_out.exists() else ""
            return proc.returncode, proc.stderr, out

        def _tail(err):
            return err.strip().splitlines()[-1] if err.strip() else ""

        cid = "ab" * 16
        base_claim = {"account": "acct01", "model": "sol", "claim_id": cid,
                      "secret_ref": "ACCT01_TOKEN", "provider": "openai",
                      "harness": "codex", "credential_format": "codex-auth-json"}
        adopt_env = {"ACCOUNT_POOL": "acct01,acct02", "MODELS": "sol,luna",
                     "EXPECTED_ACCOUNT": "acct01", "CLAIM_ID": cid, "ROLE": "impl",
                     "PACKAGES": "crate-a"}
        with tempfile.TemporaryDirectory() as hd_td:
            hd_tdp = Path(hd_td)
            fixture = hd_tdp / "claim.json"

            def _claim_case(record):
                fixture.write_text(json.dumps(record), encoding="utf-8")
                return _run_hd(claim_hd, [str(fixture), "acct01,acct02", "sol,luna"],
                               {}, hd_td)

            def _adopt_case(record):
                fixture.write_text(json.dumps(record), encoding="utf-8")
                return _run_hd(adopt_hd, [str(fixture)], adopt_env, hd_td)

            for label, case, record, reject_word in (
                    ("claim", _claim_case, base_claim, "allocator"),
                    ("adopt", _adopt_case,
                     {**base_claim, "role": "impl", "package": "crate-a"}, "dispatcher claim")):
                rc, err, out = case(record)
                check(f"worker.yml {label} heredoc accepts fully declared routing metadata "
                      f"(stderr tail: {_tail(err)!r})",
                      (rc, "acquired=true" in out, "provider=openai" in out), (0, True, True))
                for field in ("provider", "harness", "credential_format"):
                    rc, err, out = case({k: v for k, v in record.items() if k != field})
                    check(f"worker.yml {label} heredoc rejects MISSING {field}",
                          (rc != 0, f"{reject_word} returned an empty or missing {field}" in err,
                           "acquired=true" in out), (True, True, False))
                    rc, err, out = case({**record, field: ""})
                    check(f"worker.yml {label} heredoc rejects EMPTY {field}",
                          (rc != 0, f"{reject_word} returned an empty or missing {field}" in err,
                           "acquired=true" in out), (True, True, False))

            # Live (DRY_RUN=false) selected-model gate against a fake protected target routing.
            (hd_tdp / "target").mkdir()
            (hd_tdp / "target" / "routing.toml").write_text(
                '[models.sol]\nprovider = "openai"\nharness = "codex"\n'
                'provider_model = "gpt-5.6-sol"\ncredential_format = "codex-auth-json"\n',
                encoding="utf-8")
            live_env = {"DRY_RUN": "false", "GITHUB_WORKSPACE": hd_td,
                        "ROUTING_PATH": "routing.toml", "LIVE_ACCOUNT": "acct01",
                        "LIVE_MODEL": "sol", "LIVE_SECRET_REF": "ACCT01_TOKEN",
                        "LIVE_PROVIDER": "openai", "LIVE_HARNESS": "codex",
                        "LIVE_CREDENTIAL_FORMAT": "codex-auth-json"}
            rc, err, out = _run_hd(selected_hd, [], live_env, hd_td)
            check(f"worker.yml selected-model heredoc accepts matching live routing metadata "
                  f"(stderr tail: {_tail(err)!r})",
                  (rc, "provider=openai" in out, "secret_ref=ACCT01_TOKEN" in out),
                  (0, True, True))
            for var, wrong in (("LIVE_PROVIDER", "anthropic"), ("LIVE_HARNESS", "claude"),
                               ("LIVE_CREDENTIAL_FORMAT", "claude-oauth-token")):
                for tag, value in (("EMPTY", ""), ("mismatched", wrong)):
                    rc, err, out = _run_hd(selected_hd, [], {**live_env, var: value}, hd_td)
                    check(f"worker.yml selected-model heredoc rejects {tag} {var} "
                          f"(no output written)",
                          (rc != 0, "conflicts with protected routing" in err,
                           "secret_ref=" in out), (True, True, False))
    except (OSError, ValueError, IndexError) as exc:
        print(f"  FAIL worker.yml fail-closed routing heredoc round: {exc}")
        ok = False

    full1 = [make_lease("acct01", "h", "p", "r", "terra", now, 100)]
    check("cap fallthrough", choose_account(A, full1, ["terra", "fable"], "p", "r", now), "acct02")
    exp = [make_lease("acct01", "h", "p", "r", "terra", 0, 10)]  # expires_at=10 < now → reclaimed
    check("expiry reclaim", choose_account(A, exp, ["terra"], "p", "r", now), "acct01")
    warm2 = [make_lease("acct02", "h", "pkg", "impl", "fable", now - 1, 100)]  # acct02 warm, cap2 has room
    check("cache affinity", choose_account(A, warm2, ["fable"], "pkg", "impl", now), "acct02")
    live, _lease = apply_claim([], "acct02", "run1", "pkg", "impl", "fable", now, 100, "CID")
    check("claim adds", len(live), 1)
    check("lease stores only canonical salted account fingerprint",
          _lease["account"], account_fingerprint("acct02"))
    check("lease fingerprint is 16 lowercase hex",
          ACCOUNT_FINGERPRINT_RE.fullmatch(_lease["account"]) is not None, True)
    check("raw account identity is dropped during bounded ledger migration",
          validate_lease_account_identities([{"account": "acct02"}]), [])
    check("canonical fingerprint survives bounded ledger migration",
          validate_lease_account_identities([{"account": _lease["account"]}]),
          [{"account": _lease["account"]}])
    subject = claim_commit_message("abcdef0123456789", "pkg", "impl")
    check("claim commit subject omits raw account identity",
          subject, "claim abcdef01 pkg/impl")
    check("claim commit subject negative: raw account absent", "acct02" in subject, False)
    check("release removes", apply_release(live, "CID", now), [])
    check("holder key ignores run identity", holder_key("owner/repo#7@run.1"), "owner/repo#7")
    scoped = [make_lease("acct01", "owner/repo#1@run", "crate-a", "impl", "terra", now, 100)]
    check("package partition blocks duplicate", partition_available(scoped, "owner/repo#", "crate-a"),
          False)
    check("package partition permits sibling", partition_available(scoped, "owner/repo#", "crate-b"),
          True)
    check("global partition serializes", partition_available(scoped, "owner/repo#", "__global__"),
          False)

    class _StubLedger:
        """Drive claim()'s pure decision path without GitHub I/O (accounts + ledger stubbed)."""

        def __init__(self, accounts, leases, write_ok=True):
            self.accounts, self.leases, self.write_ok = accounts, leases, write_ok
            self.written = None

        def __enter__(self):
            self._saved = (read_accounts, _read_ledger, _write_ledger)
            globals()["read_accounts"] = lambda repo: self.accounts
            globals()["_read_ledger"] = lambda repo: (list(self.leases), "sha0")

            def write(_repo, leases, _sha, _msg):
                self.written = list(leases)
                return self.write_ok

            globals()["_write_ledger"] = write
            return self

        def __exit__(self, *a):
            (globals()["read_accounts"], globals()["_read_ledger"],
             globals()["_write_ledger"]) = self._saved

    # ---- issue #514: capacity exhaustion walks the target-owned model chain ----
    # The fixture deliberately crosses providers (sol/openai -> fable/anthropic). These drive the
    # real claim path so the chosen alias must survive into both the returned claim and CAS ledger
    # row; selecting only the lead provider, walking unconditionally, or bypassing fallback gates
    # flips the corresponding assertion red.
    chain_accounts = [
        {"handle": "acctlead", "models": ["sol"], "max_concurrent_workers": 1,
         "available": True, "secret_ref": "ACCTLEAD_TOKEN", "provider": "openai",
         "harness": "codex", "credential_format": "codex-auth-json"},
        {"handle": "acctfallback", "models": ["fable"], "max_concurrent_workers": 1,
         "available": True, "secret_ref": "ACCTFALLBACK_TOKEN", "provider": "anthropic",
         "harness": "claude", "credential_format": "claude-oauth-token"},
    ]
    chain_usage = {
        "acctlead": {"exempt": True},
        "acctfallback": {"status": "allowed", "5h_util": 0.2, "5h_reset": 2000,
                         "7d_util": 0.2, "7d_reset": 3000, "fable_ok": True,
                         "fable_7d_oi_util": 0.2, "fable_7d_oi_reset": 3000},
    }
    lead_full = make_lease("acctlead", "other#1@run", "other", "impl", "sol", now, 100)
    with _StubLedger(chain_accounts, [lead_full]) as fallback_ledger:
        fallback_claim = claim(
            "r", "p", "impl", ["sol", "fable"], "o/r#514@run", now,
            usage=chain_usage)
    check("chain walk: exhausted lead provider selects fallback and records fallback alias",
          (fallback_claim["account"], fallback_claim["model"],
           fallback_ledger.written[-1]["model"]),
          ("acctfallback", "fable", "fable"))

    fallback_full = make_lease(
        "acctfallback", "other#2@run", "other", "impl", "fable", now, 100)
    with _StubLedger(chain_accounts, [lead_full, fallback_full]):
        exhausted_claim = claim(
            "r", "p", "impl", ["sol", "fable"], "o/r#514@run", now,
            usage=chain_usage)
    check("chain walk: all providers exhausted returns none-free", exhausted_claim, None)

    with _StubLedger(chain_accounts, []):
        lead_claim = claim(
            "r", "p", "impl", ["sol", "fable"], "o/r#514@run", now,
            usage=chain_usage)
    check("chain walk: eligible lead provider wins without fallback",
          (lead_claim["account"], lead_claim["model"]), ("acctlead", "sol"))

    fallback_backoff_usage = {
        **chain_usage,
        "acctlead": {"exempt": True, "backoff_until": now + 60},
    }
    with _StubLedger(chain_accounts, [fallback_full]):
        backed_off_fallback = claim(
            "r", "p", "impl", ["fable", "sol"], "o/r#514@run", now,
            usage=fallback_backoff_usage)
    check("chain walk: per-account backoff still blocks the fallback account",
          backed_off_fallback, None)

    # ---- disjoint review:/fix: top-level lease prefixes (cross-provider review loop) ----
    # Review/fix holders are `review:<repo>#<PR>@run` / `fix:<repo>#<PR>@run`. Neither starts with
    # the impl prefix `<repo>#` (and vice-versa), so impl max_holder_concurrent never counts them,
    # review/fix caps never count impl, and partition_available never cross-blocks. Load-bearing:
    # a regression here silently masquerades as none-free.
    mixed = [
        make_lease("acct02", "owner/repo#12@r.1", "crate-a", "impl", "fable", now, 100),
        make_lease("acct01", "review:owner/repo#40@r.1", "crate-a", "review", "terra", now, 100),
        make_lease("acct02", "fix:owner/repo#41@r.1", "crate-b", "fix", "fable", now, 100),
    ]
    check("holder keys stay disjoint across namespaces",
          (holder_key("owner/repo#5@x"), holder_key("review:owner/repo#5@x"),
           holder_key("fix:owner/repo#5@x")),
          ("owner/repo#5", "review:owner/repo#5", "fix:owner/repo#5"))
    check("impl prefix counting excludes review/fix holders",
          sum(1 for x in mixed if str(x["holder"]).startswith("owner/repo#")), 1)
    check("review prefix counting excludes impl/fix holders",
          sum(1 for x in mixed if str(x["holder"]).startswith("review:")), 1)
    check("impl lease on a crate does not block a review claim (partition cross-check)",
          partition_available(mixed, "review:", "crate-b"), True)
    check("review lease invisible to the impl partition (partition cross-check)",
          partition_available([mixed[1]], "owner/repo#", "crate-a"), True)
    check("same-crate reviews still serialize under the shared review: prefix",
          partition_available(mixed, "review:", "crate-a"), False)

    # ---- issue #448: review/fix fan-out is bounded by LIVE per-account slots ----
    # The production sol account advertises its parallelism through this exact catalog field;
    # model the measured 12-slot shape and prove active leases are subtracted rather than merely
    # counting one "available account".  Foreign accounts/providers never consume sol capacity.
    sol12 = [{"handle": "acctsol", "models": ["sol", "luna"],
              "max_concurrent_workers": 12, "available": True,
              "secret_ref": "ACCTSOL_TOKEN", "provider": "openai"}]
    four_sol = [
        make_lease("acctsol", f"fix:o/r#{number}@r.1", f"crate-{number}", "fix", "sol",
                   now, 100)
        for number in range(4)
    ]
    check("12-slot sol account exposes 8 remaining slots",
          available_account_slots(sol12, four_sol, ["sol", "luna"], now,
                                  account_pool=["acctsol"]), 8)
    check("fully occupied sol account exposes zero slots (fail closed)",
          available_account_slots(sol12, four_sol + [
              make_lease("acctsol", f"fix:o/r#{number}@r.1", f"crate-{number}", "fix",
                         "sol", now, 100)
              for number in range(4, 12)
          ], ["sol"], now, account_pool=["acctsol"]), 0)
    check("unavailable sol account contributes no slots",
          available_account_slots([{**sol12[0], "available": False}], [], ["sol"], now), 0)
    check("active reactive backoff contributes no sol slots",
          available_account_slots(sol12, [], ["sol"], now,
                                  usage={"acctsol": {"exempt": True,
                                                       "backoff_until": now + 60}}), 0)

    # Reasoned claims make the telemetry's lease-conflict bucket testable without weakening the
    # historical claim-or-None API.  Same-repo package single-flight still wins before capacity.
    with _StubLedger(sol12, [
            make_lease("acctsol", "fix:o/r#40@r.1", "crate-a", "fix", "sol", now, 100)]):
        conflict, why = claim(
            "r", "crate-a", "fix", ["sol"], "fix:o/r#41@r.1", now,
            account_pool=["acctsol"], holder_prefix="fix:o/r#",
            account_slot_bound=True, return_reason=True)
    check("reasoned claim defers a package lease conflict", (conflict, why),
          (None, "package-single-flight"))
    with _StubLedger(sol12, [
            make_lease("acctsol", f"fix:o/r#{number}@r.1", f"crate-{number}", "fix", "sol",
                       now, 100)
            for number in range(12)]):
        no_slot, why = claim(
            "r", "fresh-crate", "fix", ["sol"], "fix:o/r#99@r.1", now,
            account_pool=["acctsol"], holder_prefix="fix:o/r#",
            account_slot_bound=True, return_reason=True)
    check("reasoned claim fails closed at S=0", (no_slot, why),
          (None, "no-account-slots"))

    # Two live review leases for DISTINCT PRs are bounded by the SHARED `review:` prefix cap
    # (max_holder_concurrent=2 = the static codex slot bound; codex is usage-exempt so the CLI
    # usage=None path is acceptable). A third claim must come back None, an impl claim must not.
    review_pair = [
        make_lease("acct01", "review:owner/repo#40@r.1", "crate-a", "review", "terra", now, 100),
        make_lease("acct01", "review:owner/repo#41@r.1", "crate-b", "review", "terra", now, 100),
    ]
    with _StubLedger([{"handle": "acct01", "models": ["terra"], "max_concurrent_workers": 3,
                       "available": True, "secret_ref": "ACCT01_TOKEN"}], review_pair):
        third = claim("r", "crate-c", "review", ["terra"], "review:owner/repo#42@r.1", now,
                      account_pool=["acct01"], holder_prefix="review:", max_holder_concurrent=2)
    check("third review claim bounded by the shared review: cap", third, None)
    with _StubLedger([{"handle": "acct02", "models": ["fable"], "max_concurrent_workers": 3,
                       "available": True, "secret_ref": "ACCT02_TOKEN"}], review_pair):
        impl_claim = claim("r", "crate-c", "impl", ["fable"], "owner/repo#9@r.1", now,
                           account_pool=["acct02"], holder_prefix="owner/repo#",
                           max_holder_concurrent=2)
    check("impl cap ignores the two review leases", bool(impl_claim), True)
    with _StubLedger([{"handle": "acct01", "models": ["terra"], "max_concurrent_workers": 3,
                       "available": True, "secret_ref": "ACCT01_TOKEN"}], review_pair[:1]):
        second = claim("r", "crate-c", "review", ["terra"], "review:owner/repo#41@r.1", now,
                       account_pool=["acct01"], holder_prefix="review:", max_holder_concurrent=2)
    check("second review claim under the cap succeeds", bool(second), True)
    # A persistent ledger-write failure with an ELIGIBLE account must raise LeaseIOError — never
    # return None (None = "no eligible account/slot" and the dispatcher would report the infra
    # failure as "account cap is active"; issue #28, live incident 2026-07-17).
    try:
        with _StubLedger([{"handle": "acct02", "models": ["fable"], "max_concurrent_workers": 3,
                           "available": True, "secret_ref": "ACCT02_TOKEN"}], [], write_ok=False):
            claim("r", "crate-c", "impl", ["fable"], "owner/repo#9@r.1", now,
                  account_pool=["acct02"], holder_prefix="owner/repo#", max_holder_concurrent=2)
        check("persistent ledger-write failure raises", "no exception", "LeaseIOError")
    except LeaseIOError:
        check("persistent ledger-write failure raises", "LeaseIOError", "LeaseIOError")
    check("none free", choose_account([{"handle": "a", "models": ["x"], "max_concurrent_workers": 0}],
                                      [], ["x"], "p", "r", now), None)
    pa = _parse_account("provider: openai\nmodels: [terra, gpt]\nmax_concurrent_workers: 2\n"
                        "secret_ref: ACCT01_TOKEN\ncredential_format: codex-auth-json")
    check("parse account", (pa["models"], pa["max_concurrent_workers"], pa["secret_ref"],
                            pa["credential_format"]),
          (["terra", "gpt"], 2, "ACCT01_TOKEN", "codex-auth-json"))

    # ---- usage-aware eligibility + expiry-priority + dynamic concurrency ----
    fresh = {"status": "allowed", "5h_util": 0.1, "5h_reset": 5000, "7d_util": 0.1, "7d_reset": 9000}
    check("eligible: allowed+headroom", usage_eligible(fresh), True)
    check("ineligible: missing", usage_eligible(None), False)
    check("ineligible: rejected", usage_eligible({**fresh, "status": "rejected"}), False)
    check("ineligible: 5h full", usage_eligible({**fresh, "5h_util": 0.95}), False)
    check("ineligible: 7d full", usage_eligible({**fresh, "7d_util": 0.95}), False)
    check("ineligible: unknown window", usage_eligible({"status": "allowed", "5h_util": 0.1}), False)
    check("eligible: exempt provider (codex)", usage_eligible({"exempt": True}), True)
    # [ISSUE #196] malformed base SHAPE must fail CLOSED, not fail open as eligible capacity. Each
    # of these admitted the account before the fix: a NaN window (all comparisons false, so the
    # `(1 - util) < margin` headroom test never fired), a NEGATIVE utilization (looks like excess
    # headroom), an out-of-range fraction, and an EMPTY/MISSING status (once read as `allowed`).
    check("ineligible: NaN 5h util (fails open pre-fix)",
          usage_eligible({**fresh, "5h_util": float("nan")}), False)
    check("ineligible: string NaN 5h util", usage_eligible({**fresh, "5h_util": "nan"}), False)
    check("ineligible: negative 7d util (fake headroom pre-fix)",
          usage_eligible({**fresh, "7d_util": -1}), False)
    check("ineligible: string negative util", usage_eligible({**fresh, "5h_util": "-1"}), False)
    check("ineligible: out-of-range (>1) utilization", usage_eligible({**fresh, "5h_util": 1.5}), False)
    check("ineligible: empty status (once accepted as allowed)",
          usage_eligible({**fresh, "status": ""}), False)
    check("ineligible: missing status",
          usage_eligible({"5h_util": 0.1, "5h_reset": 5000, "7d_util": 0.1, "7d_reset": 9000}), False)

    # ---- probe-exempt (openai) + reactive backoff (decision 2026-07-17, registry issue #29) ----
    # (i) openai/codex accounts are eligible WITHOUT usage data — deleting the exempt arm turns
    # this red (the entry has no 5h/7d windows, so the fail-closed arm would reject it).
    check("exempt (openai): eligible with NO usage windows at all",
          usage_eligible({"exempt": True}, now=now), True)
    # (iv) the exemption must NOT leak across providers: a non-exempt (anthropic) entry with the
    # same missing windows stays ineligible.
    check("anthropic without windows still fail-closed (no cross-provider leak)",
          usage_eligible({"status": "allowed"}, now=now), False)
    # (ii) an ACTIVE backoff excludes the account; (iii) an EXPIRED one readmits it.
    check("exempt with ACTIVE backoff excluded",
          usage_eligible({"exempt": True, "backoff_until": now + 60}, now=now), False)
    check("exempt with EXPIRED backoff eligible again",
          usage_eligible({"exempt": True, "backoff_until": now - 1}, now=now), True)
    # (v) a forged/malformed stamp fails OPEN to no-backoff (never crashes, never starves).
    check("malformed backoff stamp fails open",
          usage_eligible({"exempt": True, "backoff_until": "garbage"}, now=now), True)
    # (cross-provider review r1) non-finite stamps fail OPEN — inf must not sideline forever…
    check("inf backoff stamp fails open (no indefinite sideline)",
          usage_eligible({"exempt": True, "backoff_until": "inf"}, now=now), True)
    check("nan backoff stamp fails open",
          usage_eligible({"exempt": True, "backoff_until": "nan"}, now=now), True)
    # a huge JSON int (10**400) makes float() RAISE OverflowError, not return inf — the forged
    # stamp must fail open to no-backoff, never abort dispatch (cross-provider review r2 f3)
    check("huge-int backoff stamp fails open (OverflowError, no dispatch abort)",
          usage_eligible({"exempt": True, "backoff_until": 10**400}, now=now), True)
    # …and the exempt flag is STRICT: a forged truthy string must not exempt an account whose
    # entry otherwise lacks usage windows (would-be anthropic bypass).
    check("forged exempt='false' string does NOT exempt (fail-closed)",
          usage_eligible({"exempt": "false", "status": "allowed"}, now=now), False)
    check("forged exempt=1 does NOT exempt (fail-closed)",
          usage_eligible({"exempt": 1, "status": "allowed"}, now=now), False)
    # choose_account skips a backed-off exempt account and picks the free one; None when all backed off.
    OA = [{"handle": "cx1", "models": ["terra"], "max_concurrent_workers": 1, "available": True},
          {"handle": "cx2", "models": ["terra"], "max_concurrent_workers": 1, "available": True}]
    ousage = {"cx1": {"exempt": True, "backoff_until": now + 500}, "cx2": {"exempt": True}}
    check("choose_account skips the backed-off exempt account",
          choose_account(OA, [], ["terra"], "p", "r", now, usage=ousage), "cx2")
    check("choose_account None when every exempt account is backed off",
          choose_account(OA, [], ["terra"], "p", "r", now,
                         usage={h: {"exempt": True, "backoff_until": now + 500} for h in ("cx1", "cx2")}),
          None)
    check("dynamic concurrency excludes the backed-off exempt account",
          dynamic_concurrency(OA, ousage, ["terra"], now=now), 1)
    U = [{"handle": "soon", "models": ["fable"], "max_concurrent_workers": 1, "available": True},
         {"handle": "middle", "models": ["fable"], "max_concurrent_workers": 1, "available": True},
         {"handle": "late", "models": ["fable"], "max_concurrent_workers": 1, "available": True},
         {"handle": "full", "models": ["fable"], "max_concurrent_workers": 1, "available": True}]
    usage = {
        "soon": {"status": "allowed", "5h_util": 0.2, "5h_reset": 100, "7d_util": 0.2, "7d_reset": 3000,
                 "fable_ok": True, "fable_7d_oi_util": 0.2, "fable_7d_oi_reset": 3000},
        "middle": {"status": "allowed", "5h_util": 0.2, "5h_reset": 100, "7d_util": 0.2, "7d_reset": 5000,
                   "fable_ok": True, "fable_7d_oi_util": 0.2, "fable_7d_oi_reset": 5000},
        "late": {"status": "allowed", "5h_util": 0.2, "5h_reset": 100, "7d_util": 0.2, "7d_reset": 8000,
                 "fable_ok": True, "fable_7d_oi_util": 0.2, "fable_7d_oi_reset": 8000},
        "full": {"status": "allowed", "5h_util": 0.99, "5h_reset": 100, "7d_util": 0.99, "7d_reset": 1000},
    }
    # expiry-priority: 'soon' (7d_reset 3000) beats 'late' (8000); 'full' is ineligible (no headroom).
    check("expiry priority picks soonest reset",
          choose_account(U, [], ["fable"], "p", "r", now, usage=usage), "soon")
    # if 'soon' is removed from usage entirely -> fail-closed skip -> next reset wins.
    check("fail-closed on missing usage",
          choose_account(U, [], ["fable"], "p", "r", now, usage={k: v for k, v in usage.items() if k != "soon"}),
          "middle")
    # dynamic concurrency: 3 eligible (soon,middle,late), 'full' backs off; absolute_cap clamps.
    check("dynamic concurrency counts eligible", dynamic_concurrency(U, usage, ["fable"]), 3)
    check("dynamic concurrency absolute cap", dynamic_concurrency(U, usage, ["fable"], absolute_cap=1), 1)
    allfull = {h: {**usage["full"]} for h in ("soon", "middle", "late", "full")}
    check("dynamic concurrency backs off to 0 when tapped out",
          dynamic_concurrency(U, allfull, ["fable"]), 0)
    check("dynamic concurrency 0 without usage (caller falls back to static)",
          dynamic_concurrency(U, None, ["fable"]), 0)
    # backward compat: usage=None keeps the original cache-affinity selection.
    check("usage=None backward compatible", choose_account(A, [], ["fable"], "pkg", "impl", now), "acct02")

    # ---- [FABLE-5] fable sub-quota (7d_oi) gate ----
    fable_ok = {**fresh, "fable_ok": True, "fable_7d_oi_util": 0.1, "fable_7d_oi_reset": 9000}
    check("fable eligible: whole-account + fable headroom",
          usage_eligible(fable_ok, model="fable"), True)
    check("non-fable model ignores fable bucket (haiku on same acct)",
          usage_eligible(fresh, model="haiku"), True)
    check("fable ineligible: bucket exhausted (whole-account fine)",
          usage_eligible({**fable_ok, "fable_7d_oi_util": 0.95}, model="fable"), False)
    check("same acct still eligible for haiku when fable bucket exhausted",
          usage_eligible({**fable_ok, "fable_7d_oi_util": 0.95}, model="haiku"), True)
    # Issue #450: the premium sub-quota is model-specific. A sol-authored PR reviews on OPUS;
    # exhausting Fable on an otherwise healthy anthropic account must not erase that OPUS slot.
    fable_capped = {**fable_ok, "fable_7d_oi_util": 1.0}
    check("Fable-100% account remains eligible for opus review",
          usage_eligible(fable_capped, model="opus"), True)
    opus_account = [{"handle": "acctopus", "models": ["fable", "opus"],
                     "max_concurrent_workers": 2, "available": True}]
    check("Fable-100% account contributes its opus review slots",
          available_account_slots(opus_account, [], ["opus", "fable"], now,
                                  usage={"acctopus": fable_capped}), 2)
    check("opus review selects the healthy account despite its capped Fable bucket",
          choose_account(opus_account, [], ["opus", "fable"], "p", "review", now,
                         usage={"acctopus": fable_capped}), "acctopus")
    check("fable ineligible: probe absent (fable_ok missing) fails closed",
          usage_eligible(fresh, model="fable"), False)
    check("fable ineligible: probe failed (fable_ok False)",
          usage_eligible({**fresh, "fable_ok": False}, model="fable"), False)
    check("fable ineligible: 7d_oi window unknown",
          usage_eligible({**fresh, "fable_ok": True}, model="fable"), False)
    # choose_account: fable route skips a fable-exhausted account, picks the healthy one.
    F = [{"handle": "fa", "models": ["fable"], "max_concurrent_workers": 1, "available": True},
         {"handle": "fb", "models": ["fable"], "max_concurrent_workers": 1, "available": True}]
    fusage = {
        "fa": {**fresh, "7d_reset": 3000, "fable_ok": True, "fable_7d_oi_util": 0.99, "fable_7d_oi_reset": 3000},
        "fb": {**fresh, "7d_reset": 8000, "fable_ok": True, "fable_7d_oi_util": 0.1, "fable_7d_oi_reset": 8000},
    }
    check("fable route skips exhausted-bucket account",
          choose_account(F, [], ["fable"], "p", "r", now, usage=fusage), "fb")
    # Drain priority always follows the whole-account weekly reset; fable_7d_oi remains an eligibility
    # gate but does not replace the provider-wide 7d ordering signal.
    fusage2 = {
        "fa": {**fresh, "7d_reset": 8000, "fable_ok": True,
               "fable_7d_oi_util": 0.1, "fable_7d_oi_reset": 3000},
        "fb": {**fresh, "7d_reset": 3000, "fable_ok": True,
               "fable_7d_oi_util": 0.1, "fable_7d_oi_reset": 8000},
    }
    check("fable drain uses whole-account 7d reset, not sub-quota reset",
          choose_account(F, [], ["fable"], "p", "r", now, usage=fusage2), "fb")
    # dynamic_concurrency on a fable-only chain counts only fable-eligible accounts.
    check("dynamic concurrency (fable chain) counts fable-eligible only",
          dynamic_concurrency(F, fusage, ["fable"]), 1)
    check("dynamic concurrency (haiku chain) ignores fable bucket",
          dynamic_concurrency(
              [{"handle": "fa", "models": ["haiku"], "max_concurrent_workers": 1, "available": True}],
              {"fa": {**fresh, "fable_ok": True, "fable_7d_oi_util": 0.99}}, ["haiku"]), 1)
    # [FABLE-5] claim() model assignment must match the pass that admitted the account: an account serving
    # BOTH fable+haiku with an EXHAUSTED fable bucket, on a ["fable","haiku"] chain, must be claimed as
    # haiku (not fable), or the gate is defeated.

    class _StubClaim:
        """Drive claim()'s pure decision path without GitHub I/O by stubbing the ledger/catalog."""
        def __init__(self, accounts):
            self.accounts, self.written = accounts, None

        def __enter__(self):
            self._ra, self._rl, self._wl = read_accounts, _read_ledger, _write_ledger
            return self

        def __exit__(self, *a):
            globals()["read_accounts"], globals()["_read_ledger"], globals()["_write_ledger"] = \
                self._ra, self._rl, self._wl

    drain_accounts = [
        {"handle": "acct-late", "models": ["haiku"], "max_concurrent_workers": 2,
         "available": True},
        {"handle": "acct-middle", "models": ["haiku"], "max_concurrent_workers": 2,
         "available": True},
        {"handle": "acct-soon", "models": ["haiku"], "max_concurrent_workers": 2,
         "available": True},
        {"handle": "a-missing", "models": ["haiku"], "max_concurrent_workers": 2,
         "available": True},
        {"handle": "z-missing", "models": ["haiku"], "max_concurrent_workers": 2,
         "available": True},
    ]
    without_reset = {key: value for key, value in fresh.items() if key != "7d_reset"}
    drain_usage = {
        "acct-late": {**fresh, "7d_reset": 9000},
        "acct-middle": {**fresh, "7d_reset": 6000},
        "acct-soon": {**fresh, "7d_reset": 3000},
        "a-missing": dict(without_reset),
        "z-missing": dict(without_reset),
    }
    warm_missing = [
        make_lease("z-missing", "other/repo#1@run", "p", "impl", "haiku", now - 5, 100),
    ]
    check("weekly-drain fixture accounts are all otherwise eligible",
          [usage_eligible(drain_usage[a["handle"]], model="haiku") for a in drain_accounts],
          [True, True, True, True, True])
    check("weekly drain sorts three resets soonest and leaves missing resets last/stable",
          [account["handle"] for account in _order_eligible_accounts(
              drain_accounts, warm_missing, drain_usage, "p", "impl")],
          ["acct-soon", "acct-middle", "acct-late", "z-missing", "a-missing"])

    claim_accounts = drain_accounts[:3]
    with _StubClaim(claim_accounts):
        globals()["read_accounts"] = lambda repo: claim_accounts
        globals()["_read_ledger"] = lambda repo: ([], "sha0")
        globals()["_write_ledger"] = lambda repo, leases, sha, msg: True
        drained = claim("r", "p", "impl", ["haiku"], "o/r#1@run", now,
                        usage=drain_usage)
    check("claim picks soonest of three distinct eligible weekly resets",
          drained and drained["account"], "acct-soon")

    dual = [{"handle": "acctdual", "models": ["fable", "haiku"], "max_concurrent_workers": 1,
             "available": True}]
    dual_usage = {"acctdual": {**fresh, "fable_ok": True, "fable_7d_oi_util": 0.99,
                               "fable_7d_oi_reset": 9000}}
    with _StubClaim(dual):
        globals()["read_accounts"] = lambda repo: dual
        globals()["_read_ledger"] = lambda repo: ([], "sha0")
        globals()["_write_ledger"] = lambda repo, leases, sha, msg: True
        claimed = claim("r", "p", "impl", ["fable", "haiku"], "o/r#1@run", now,
                        account_pool=["acctdual"], usage=dual_usage, margin=0.15)
    check("claim assigns model consistent with the admitting pass (haiku, not fable)",
          claimed and claimed["model"], "haiku")

    # ---- ledger-branch targeting (issue #28: data plane off the protected code branch) ----
    # Literal "ledger" on purpose: pointing either helper back at the default branch (or changing
    # the shipped REGISTRY_LEDGER_REF default) must turn these red.
    check("ledger read targets the ledger ref",
          ledger_read_path("o/r"), f"repos/o/r/contents/{LEDGER_PATH}?ref=ledger")
    wargs = ledger_write_args("o/r", "m", "Zm9v", "sha1")
    check("ledger write pins branch=ledger", "branch=ledger" in wargs, True)
    check("ledger write carries the CAS sha", "sha=sha1" in wargs, True)
    check("ledger write without sha omits it (create-if-absent)",
          any(a.startswith("sha=") for a in ledger_write_args("o/r", "m", "Zm9v", None)), False)
    check("404 with ledger branch present seeds an empty ledger", _read_404(True), ([], None))
    try:
        _read_404(False)
        check("404 with ledger branch MISSING fails loud", "no exception", "LeaseIOError")
    except LeaseIOError:
        check("404 with ledger branch MISSING fails loud", "LeaseIOError", "LeaseIOError")

    # ---- CAS conflict-retry against the ledger ref (fixture-level, through the REAL I/O fns) ----
    class _Res:
        def __init__(self, returncode, stdout="", stderr=""):
            self.returncode, self.stdout, self.stderr = returncode, stdout, stderr

    fixture_calls = []

    def _fake_gh(args, **_kwargs):
        fixture_calls.append(list(args))
        if "-X" not in args:  # contents GET: one expired lease, fresh sha per read
            meta = {"content": base64.b64encode(json.dumps(
                {"leases": [make_lease("a1", "o/r#1@run", "p", "impl", "m", now - 100, 1)]}
            ).encode()).decode(), "sha": f"sha{len(fixture_calls)}"}
            return _Res(0, stdout=json.dumps(meta))
        puts = sum(1 for c in fixture_calls if "-X" in c)
        return _Res(1 if puts == 1 else 0, stderr="HTTP 409")  # first PUT loses the CAS race

    real_run = subprocess.run
    real_backoff = globals()["_sleep_backoff"]
    backoff_attempts = []
    subprocess.run = _fake_gh
    globals()["_sleep_backoff"] = lambda attempt: backoff_attempts.append(attempt)
    try:
        reclaimed = reclaim("o/r", now)
    finally:
        subprocess.run = real_run
        globals()["_sleep_backoff"] = real_backoff
    fixture_gets = [c for c in fixture_calls if "-X" not in c]
    fixture_puts = [c for c in fixture_calls if "-X" in c]
    check("fixture reclaim rides out one CAS conflict", reclaimed, 1)
    check("fixture reclaim re-read after the conflict (CAS retry)", len(fixture_gets), 2)
    check("fixture reads all target the ledger ref",
          all(c[2].endswith("?ref=ledger") for c in fixture_gets), True)
    check("fixture writes all pin branch=ledger",
          [sum(1 for a in c if a == "branch=ledger") for c in fixture_puts], [1, 1])
    # Backoff fires BETWEEN CAS attempts, never before the first read (issue #179): one conflict
    # here means exactly one jittered sleep, for retry attempt 1.
    check("fixture reclaim backs off once (only between attempts)", backoff_attempts, [1])

    # ---- CAS retry backoff schedule + typed PUT errors (issue #179) ----
    # Exponential, capped ceiling: dropping the exponent (linear) or the cap flips these red.
    check("backoff ceiling is exponential then capped",
          [_backoff_ceiling(a) for a in (1, 2, 3, 4, 5, 6, 10)],
          [0.5, 1.0, 2.0, 4.0, 8.0, 8.0, 8.0])
    # Full jitter: the delay must BE the RNG draw over exactly [0, ceiling]. Stubbing
    # random.uniform pins both properties — a deterministic delay (always 0, always the ceiling,
    # ceiling/2) would either never call the RNG or discard its draw, flipping these red.
    real_uniform = random.uniform
    uniform_calls = []
    sentinel = 123.456
    random.uniform = lambda lo, hi: (uniform_calls.append((lo, hi)), sentinel)[1]
    try:
        draws = [_backoff_delay(a) for a in range(1, 7)]
    finally:
        random.uniform = real_uniform
    check("backoff delay draws uniform(0, ceiling) with exact bounds",
          uniform_calls, [(0, _backoff_ceiling(a)) for a in range(1, 7)])
    check("backoff delay propagates the RNG draw unchanged", draws, [sentinel] * 6)
    # A genuine CAS conflict is retryable → False; any OTHER PUT failure fails LOUD with
    # LeaseIOError rather than being collapsed into "CAS kept conflicting" (the #179 complaint).
    # 422 is a conflict ONLY as the create-if-absent race: sha-less PUT + GitHub's
    # '"sha" wasn't supplied' signature — a bare 422 is a persistent payload/config validation
    # error that six retries would only obscure.
    race_422 = "gh: Invalid request.\n\n\"sha\" wasn't supplied. (HTTP 422)"
    real_run = subprocess.run
    subprocess.run = lambda args, **_k: _Res(0)
    try:
        check("successful PUT returns True", _write_ledger("o/r", [], "sha", "m"), True)
        subprocess.run = lambda args, **_k: _Res(1, stderr="gh: ... (HTTP 409)")
        check("CAS 409 PUT is retryable (False, not raise)", _write_ledger("o/r", [], "sha", "m"),
              False)
        subprocess.run = lambda args, **_k: _Res(1, stderr=race_422)
        check("create-race 422 on a sha-less PUT is retryable (False)",
              _write_ledger("o/r", [], None, "m"), False)
        loud_puts = [("non-conflict PUT 403 fails loud (not collapsed)",
                      "gh: ... (HTTP 403)", "sha"),
                     ("non-conflict PUT 404 fails loud (not collapsed)",
                      "gh: ... (HTTP 404)", "sha"),
                     ("non-conflict PUT 500 fails loud (not collapsed)",
                      "gh: ... (HTTP 500)", "sha"),
                     ("non-race validation 422 fails loud (not a CAS conflict)",
                      "gh: Validation Failed (HTTP 422)", "sha"),
                     ("non-race validation 422 on a sha-less create fails loud",
                      "gh: Validation Failed (HTTP 422)", None),
                     ("race-signature 422 on a sha-carrying PUT fails loud", race_422, "sha")]
        for label, stderr_text, put_sha in loud_puts:
            subprocess.run = lambda args, _s=stderr_text, **_k: _Res(1, stderr=_s)
            try:
                _write_ledger("o/r", [], put_sha, "m")
                check(label, "no exception", "LeaseIOError")
            except LeaseIOError:
                check(label, "LeaseIOError", "LeaseIOError")
    finally:
        subprocess.run = real_run

    if original_selftest_salt is None:
        os.environ.pop("PROVENANCE_SALT", None)
    else:
        os.environ["PROVENANCE_SALT"] = original_selftest_salt
    print("select-and-claim self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--validate-account-record", action="store_true",
                    help="validate an account body from stdin before a catalog write")
    ap.add_argument("--account-handle", default="",
                    help="account handle for --validate-account-record")
    ap.add_argument("--reclaim", action="store_true", help="CAS-remove expired leases (cron)")
    ap.add_argument("--claim", action="store_true", help="claim a lease")
    ap.add_argument("--adopt", metavar="CLAIM_ID",
                    help="CAS-transfer a dispatcher lease to this worker run (--holder), refreshing expiry")
    ap.add_argument("--inspect", metavar="CLAIM_ID", help="inspect an active lease for worker adoption")
    ap.add_argument("--release", metavar="CLAIM_ID", help="release a lease by claim id")
    ap.add_argument("--package", default="")
    ap.add_argument("--role", default="")
    ap.add_argument("--models", default="", help="comma-separated model fallback chain")
    ap.add_argument("--account-pool", default="",
                    help="comma-separated allow-list from the resolved repository policy")
    ap.add_argument("--holder", default="", help="owner/repo@run identifier")
    ap.add_argument("--holder-prefix", default="",
                    help="prefix used with --max-holder-concurrent for repository caps")
    ap.add_argument("--max-holder-concurrent", type=int,
                    help="CAS-enforced concurrent lease cap for --holder-prefix")
    ap.add_argument("--expected-holder-prefix", default="",
                    help="required holder prefix when inspecting a dispatcher claim")
    ap.add_argument("--ttl", type=int, default=3600, help="lease lifetime in seconds")
    ap.add_argument("--repo", default="jeswr/agent-account-registry")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()
    if args.validate_account_record:
        if not args.account_handle:
            print("account record write rejected: --account-handle is required", file=sys.stderr)
            return 2
        try:
            validate_account_record(args.account_handle, sys.stdin.read())
        except LeaseIOError as exc:
            print(f"account record write rejected: {exc}", file=sys.stderr)
            return 2
        print("account record schema valid")
        return 0
    if args.reclaim:
        n = reclaim(args.repo, int(time.time()))
        print(f"reclaimed {n} expired lease(s)" if n >= 0 else "reclaim: CAS kept conflicting")
        return 0 if n >= 0 else 1
    if args.claim:
        chain = [m.strip() for m in args.models.split(",") if m.strip()]
        pool = [a.strip() for a in args.account_pool.split(",") if a.strip()]
        if not chain or not pool or args.ttl <= 0:
            print("claim requires non-empty --models/--account-pool and positive --ttl",
                  file=sys.stderr)
            return 2
        res = claim(args.repo, args.package, args.role, chain, args.holder, int(time.time()),
                    ttl=args.ttl, account_pool=pool, holder_prefix=args.holder_prefix,
                    max_holder_concurrent=args.max_holder_concurrent)
        print(json.dumps(res) if res else "none-free")
        return 0 if res else 3
    if args.adopt:
        if not args.holder or args.ttl <= 0:
            print("adopt requires a non-empty --holder and a positive --ttl", file=sys.stderr)
            return 2
        res = adopt(args.repo, args.adopt, args.holder, int(time.time()), args.ttl,
                    expected_holder_prefix=args.expected_holder_prefix)
        print(json.dumps(res) if res else "not-adoptable")
        return 0 if res else 3
    if args.inspect:
        res = inspect_claim(args.repo, args.inspect, int(time.time()), args.expected_holder_prefix)
        print(json.dumps(res) if res else "not-adoptable")
        return 0 if res else 3
    if args.release:
        released = release(args.repo, args.release, int(time.time()))
        print("released" if released else "release-failed")
        return 0 if released else 1
    print("select-and-claim: allocation core + reclaim + live claim/release ready (wires into dispatch, Phase 3).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
