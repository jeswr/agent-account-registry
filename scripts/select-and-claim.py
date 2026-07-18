#!/usr/bin/env python3
# [OPUS-4.8] Lease allocator (review C3): a correct, cross-codebase worker-slot lease over a
# compare-and-swap ledger — replaces the reaction "mutex" (which cannot count concurrent same-identity
# claims). Pure allocation logic is unit-tested; GitHub CAS I/O wraps it.
"""select-and-claim — allocate a model-account worker slot as a LEASE.

The ledger is a single JSON file `data/leases.json` in this private registry:
    {"leases": [{"account","claim_id","holder","package","role","model","issued_at","expires_at"}, ...]}

Claiming is a compare-and-swap: read the file + its blob SHA, reclaim expired leases, if an eligible
account (serving a model in the chain, under its cap, cache-affinity-preferred) has a free slot append
a unique lease, then PUT the file with the read SHA. A concurrent writer changes the SHA → the PUT is
rejected → retry. This serializes allocation across every codebase without reaction counting. Release
and heartbeat are keyed by the unique claim_id.
"""
import argparse
import base64
import json
import math
import os
import re
import subprocess
import sys

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


def active_for(leases, account):
    return sum(1 for x in leases if x["account"] == account)


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
    if str(u.get("status", "")).lower() not in ("allowed", ""):
        return False                                  # throttled/rejected -> skip until it resets
    for prefix in ("5h", "7d"):
        util, _ = _usage_window(u, prefix)
        if util is None or (1.0 - util) < margin:
            return False                              # unknown, or too little headroom to finish
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
                 if lease["account"] == account["handle"]
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


def choose_account(accounts, leases, model_chain, package, role, now, usage=None, margin=SAFETY_MARGIN):
    """Return the account handle to claim, or None. `accounts`: list of dicts
    {handle, models:[...], max_concurrent_workers, available:bool}. Walks the model chain; within a
    model keeps accounts under their concurrency cap and — when live `usage` (a {handle: {status,
    5h_util,5h_reset,7d_util,7d_reset}} map) is supplied — only accounts that pass `usage_eligible`.
    Orders eligible accounts by EXPIRY-PRIORITY: soonest whole-account weekly reset first (use credits
    before they reset), preserving CACHE AFFINITY, least-loaded, and handle order for equal or unknown
    resets. With `usage=None` the behaviour is the original cache-affinity-then-least-loaded selection
    (backward compatible)."""
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
        return serving[0]["handle"]
    return None


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


def make_lease(account, holder, package, role, model, now, ttl):
    return {"account": account, "claim_id": None, "holder": holder, "package": package,
            "role": role, "model": model, "issued_at": now, "expires_at": now + ttl}


def apply_claim(leases, account, holder, package, role, model, now, ttl, claim_id):
    live = reclaim_expired(leases, now)
    lease = make_lease(account, holder, package, role, model, now, ttl)
    lease["claim_id"] = claim_id
    live.append(lease)
    return live, lease


def apply_release(leases, claim_id, now):
    return [x for x in reclaim_expired(leases, now) if x.get("claim_id") != claim_id]


def holder_key(holder):
    """Stable target-issue identity for duplicate suppression across dispatcher/run attempts."""
    if not isinstance(holder, str) or not holder:
        return ""
    return holder.split("@", 1)[0]


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
        sha = meta["sha"]
        if not isinstance(sha, str) or not sha:
            raise ValueError("blob sha is missing")
        return leases, sha
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise LeaseIOError("lease ledger is malformed") from exc


def _write_ledger(repo, leases, sha, message):
    body = base64.b64encode(json.dumps({"leases": leases}, indent=1).encode()).decode()
    r = subprocess.run(ledger_write_args(repo, message, body, sha), capture_output=True, text=True)
    return r.returncode == 0  # non-zero (e.g. 409 SHA conflict) → caller retries


def reclaim(repo, now, retries=6):
    """CAS-remove expired leases from the ledger so crashed/cancelled workers free their slot.
    Returns the number reclaimed, 0 if none, or -1 if the CAS kept conflicting."""
    for _ in range(retries):
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


def read_accounts(repo):
    """The account catalog from the open account issues (title=handle, YAML body, status:available)."""
    out = _run(["gh", "issue", "list", "-R", repo, "--state", "open", "--limit", "500",
                "--json", "title,body,labels"]).stdout
    accounts = []
    for it in json.loads(out or "[]"):
        a = _parse_account(it.get("body"))
        a["handle"] = it["title"].strip()
        a["available"] = any(lb["name"] == "status:available" for lb in it.get("labels", []))
        if a["handle"] and a["models"]:
            accounts.append(a)
    return accounts


# ---- catalog-derived enrollment + account-record migration --------------------------------------
# choose_account matches an account's `models:` aliases LITERALLY against the offered chain, so an
# enrollment shape narrower than the routing catalog silently starves every chain tier it omits
# (sol review r5 finding 2: openai accounts enrolled as models: [terra] could serve NEITHER the
# sol/luna review chain NOR the openai tiers of the unified fix ladder — merging the chains would
# starve the lane on every freshly enrolled account). The broker (set-up-account.yml) and the
# migration sweep below therefore both derive the models line from the catalog, never a literal.
ACCOUNT_HANDLE_RE = re.compile(r"acct[0-9a-z]{2,}")
MODELS_LINE_RE = re.compile(r"(?m)^models\s*:.*$")
# Pre-unification broker enrollment shapes. ONLY a record whose models set still EQUALS its
# provider's legacy shape is migrated: any other list is an operator edit (e.g. an alias
# deliberately withheld from one account) that a convergence sweep must never fight.
LEGACY_ENROLLMENT_MODELS = {
    "openai": frozenset({"terra"}),
    "anthropic": frozenset({"fable", "opus", "sonnet", "haiku"}),
}


def enrollment_models(provider, routing):
    """The CATALOG-DERIVED model-alias list an enrolling `provider` account must register:
    every `[models.<alias>]` whose provider matches, in catalog order. Raises when the catalog
    names none (fail closed — an empty models line makes the account invisible to
    read_accounts, so the broker must refuse the enrollment rather than register a dud)."""
    models = routing.get("models") if isinstance(routing, dict) else None
    if not isinstance(models, dict):
        models = {}
    aliases = [alias for alias, spec in models.items()
               if isinstance(spec, dict) and spec.get("provider") == provider]
    if not aliases:
        raise LeaseIOError(f"the routing catalog names no models for provider '{provider}'")
    return aliases


def migrate_models_line(body, legacy, required):
    """Pure rewrite of ONE account-record body for the models migration. Returns
    (new_body, reason); new_body is None when the record must not change:
    - the models set already covers the required catalog set (idempotent no-op),
    - the models set differs from the provider's LEGACY enrollment shape (operator-edited —
      never fought), or
    - the body is unmigratable (zero or multiple models lines) — surfaced in `reason` so the
      caller logs it loudly instead of guessing which line to edit."""
    lines = MODELS_LINE_RE.findall(body or "")
    if len(lines) != 1:
        return None, f"unmigratable body ({len(lines)} models lines)"
    current = set(_parse_account(body)["models"])
    if current >= set(required):
        return None, "already covers the catalog set"
    if legacy is None or current != set(legacy):
        return None, f"custom models line {sorted(current)} (operator-edited); left alone"
    replacement = "models: [" + ", ".join(required) + "]"
    return MODELS_LINE_RE.sub(replacement, body, count=1), "migrated"


def migrate_account_models(repo, routing):
    """Converge OPEN account records still carrying a LEGACY enrollment shape to the
    catalog-derived alias set, so accounts enrolled before the chain unification can serve the
    sol/luna review chain and the unified fix ladder. Idempotent (a migrated record no longer
    matches its legacy shape); operator-edited and unparseable records are logged and left
    alone. Every rewritten body is re-validated through the REAL _parse_account parser before
    the PATCH; a write or validation failure raises (loud, fail closed)."""
    out = _run(["gh", "issue", "list", "-R", repo, "--state", "open", "--limit", "500",
                "--json", "number,title,body,labels"]).stdout
    migrated = 0
    for it in json.loads(out or "[]"):
        handle = str(it.get("title", "")).strip()
        if not ACCOUNT_HANDLE_RE.fullmatch(handle):
            continue
        labels = {str(lb.get("name", "")) for lb in it.get("labels", [])
                  if isinstance(lb, dict)}
        label_providers = {name[len("provider:"):] for name in labels
                           if name.startswith("provider:")}
        body = it.get("body") or ""
        body_provider = _parse_account(body).get("provider", "")
        providers = {p for p in label_providers | {body_provider} if p}
        if len(providers) != 1 or not providers <= set(LEGACY_ENROLLMENT_MODELS):
            # Ambiguous/unknown provider identity: never guess which alias set applies.
            print(f"skip {handle}: ambiguous or unknown provider {sorted(providers)}")
            continue
        provider = next(iter(providers))
        required = enrollment_models(provider, routing)
        new_body, reason = migrate_models_line(
            body, LEGACY_ENROLLMENT_MODELS[provider], required)
        if new_body is None:
            print(f"skip {handle}: {reason}")
            continue
        if set(_parse_account(new_body)["models"]) != set(required):
            raise LeaseIOError(f"migrated body for {handle} does not re-parse to the "
                               "catalog alias set; refusing to write")
        result = subprocess.run(
            ["gh", "api", "-X", "PATCH", f"repos/{repo}/issues/{it['number']}",
             "--input", "-"],
            input=json.dumps({"body": new_body}), capture_output=True, text=True,
            check=False)
        if result.returncode != 0:
            raise LeaseIOError(f"account-record body PATCH failed for {handle}")
        print(f"migrated {handle}: models -> [{', '.join(required)}]")
        migrated += 1
    return migrated


def claim(repo, package, role, model_chain, holder, now, ttl=3600, retries=6,
          account_pool=None, holder_prefix="", max_holder_concurrent=None, usage=None,
          margin=SAFETY_MARGIN):
    """CAS-claim a lease. Returns {account, secret_ref, model, claim_id} or None (none free).
    Raises LeaseIOError when an account WAS eligible but the ledger write kept failing — that is an
    infrastructure failure (persistent CAS contention, or the contents-API PUT rejected outright,
    e.g. by a required-status-check branch protection on the ledger's branch), NOT a capacity
    signal, and must not be reported as 'no eligible account' (issue #28)."""
    import uuid
    accounts = read_accounts(repo)
    if account_pool is not None:
        allowed = set(account_pool)
        accounts = [account for account in accounts if account["handle"] in allowed]
    for _ in range(retries):
        leases, sha = _read_ledger(repo)
        live = reclaim_expired(leases, now)
        key = holder_key(holder)
        if key and any(holder_key(lease.get("holder")) == key for lease in live):
            return None
        if holder_prefix and not partition_available(live, holder_prefix, package):
            return None
        if max_holder_concurrent is not None:
            if max_holder_concurrent <= 0 or not holder_prefix:
                return None
            active_holders = sum(
                1 for lease in live if str(lease.get("holder", "")).startswith(holder_prefix)
            )
            if active_holders >= max_holder_concurrent:
                return None
        acct = choose_account(accounts, live, model_chain, package, role, now, usage=usage, margin=margin)
        if acct is None:
            return None
        a = next(x for x in accounts if x["handle"] == acct)
        # [FABLE-5] Assign the model CONSISTENTLY with the eligibility that admitted this account. Picking
        # the first chain-model the account merely SERVES would route fable onto an account whose fable
        # sub-quota is exhausted (choose_account admitted it only via a later, non-premium pass) — the exact
        # mid-run-failure the usage gate exists to prevent. When usage is supplied, require the model to
        # also be usage_eligible; with usage=None this is the original chain-order pick (backward compatible).
        if usage is not None:
            model = next((m for m in model_chain
                          if m in a["models"] and usage_eligible(usage.get(acct), margin, model=m,
                                                                 now=now)), None)
            if model is None:
                return None  # no chain model is eligible for the admitted account (defensive; shouldn't happen)
        else:
            model = next((m for m in model_chain if m in a["models"]), model_chain[0])
        cid = uuid.uuid4().hex
        live, _lease = apply_claim(leases, acct, holder, package, role, model, now, ttl, cid)
        if _write_ledger(repo, live, sha, f"claim {cid[:8]} {acct} {package}/{role}"):
            return {
                "account": acct,
                "secret_ref": a.get("secret_ref"),
                "provider": a.get("provider"),
                "harness": a.get("harness"),
                "credential_format": a.get("credential_format"),
                "model": model,
                "claim_id": cid,
            }
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
        if account.get("handle") == lease.get("account") and account.get("available")
    ]
    if len(accounts) != 1 or lease.get("model") not in accounts[0].get("models", []):
        return None
    account = accounts[0]
    return {
        **lease,
        "secret_ref": account.get("secret_ref"),
        "provider": account.get("provider"),
        "harness": account.get("harness"),
        "credential_format": account.get("credential_format"),
    }


def release(repo, claim_id, now, retries=6):
    for _ in range(retries):
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
    full1 = [make_lease("acct01", "h", "p", "r", "terra", now, 100)]
    check("cap fallthrough", choose_account(A, full1, ["terra", "fable"], "p", "r", now), "acct02")
    exp = [make_lease("acct01", "h", "p", "r", "terra", 0, 10)]  # expires_at=10 < now → reclaimed
    check("expiry reclaim", choose_account(A, exp, ["terra"], "p", "r", now), "acct01")
    warm2 = [make_lease("acct02", "h", "pkg", "impl", "fable", now - 1, 100)]  # acct02 warm, cap2 has room
    check("cache affinity", choose_account(A, warm2, ["fable"], "pkg", "impl", now), "acct02")
    live, _lease = apply_claim([], "acct02", "run1", "pkg", "impl", "fable", now, 100, "CID")
    check("claim adds", len(live), 1)
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

        def __enter__(self):
            self._saved = (read_accounts, _read_ledger, _write_ledger)
            globals()["read_accounts"] = lambda repo: self.accounts
            globals()["_read_ledger"] = lambda repo: (list(self.leases), "sha0")
            globals()["_write_ledger"] = lambda repo, leases, sha, msg: self.write_ok
            return self

        def __exit__(self, *a):
            (globals()["read_accounts"], globals()["_read_ledger"],
             globals()["_write_ledger"]) = self._saved

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
    subprocess.run = _fake_gh
    try:
        reclaimed = reclaim("o/r", now)
    finally:
        subprocess.run = real_run
    fixture_gets = [c for c in fixture_calls if "-X" not in c]
    fixture_puts = [c for c in fixture_calls if "-X" in c]
    check("fixture reclaim rides out one CAS conflict", reclaimed, 1)
    check("fixture reclaim re-read after the conflict (CAS retry)", len(fixture_gets), 2)
    check("fixture reads all target the ledger ref",
          all(c[2].endswith("?ref=ledger") for c in fixture_gets), True)
    check("fixture writes all pin branch=ledger",
          [sum(1 for a in c if a == "branch=ledger") for c in fixture_puts], [1, 1])

    # ---- catalog-derived enrollment + legacy-record migration (sol review r5 finding 2) ----
    catalog = {"models": {
        "haiku": {"provider": "anthropic"}, "sonnet": {"provider": "anthropic"},
        "opus": {"provider": "anthropic"}, "fable": {"provider": "anthropic"},
        "terra": {"provider": "openai"}, "sol": {"provider": "openai"},
        "luna": {"provider": "openai"},
    }}
    check("openai enrollment registers EVERY catalog alias (catalog order)",
          enrollment_models("openai", catalog), ["terra", "sol", "luna"])
    check("anthropic enrollment registers every catalog alias",
          enrollment_models("anthropic", catalog), ["haiku", "sonnet", "opus", "fable"])
    try:
        enrollment_models("mystery", catalog)
    except LeaseIOError:
        check("a provider the catalog omits fails closed", "rejected", "rejected")
    else:
        check("a provider the catalog omits fails closed", "accepted", "rejected")
    try:
        enrollment_models("openai", {"models": "nope"})
    except LeaseIOError:
        check("a malformed catalog fails closed", "rejected", "rejected")
    else:
        check("a malformed catalog fails closed", "accepted", "rejected")
    legacy_body = ("provider: openai\nharness: codex\nmodels: [terra]\n"
                   "credential_format: codex-auth-json\nmax_concurrent_workers: 1\n"
                   "secret_ref: ACCT01_TOKEN\nnotes: registered via set-up-account broker\n")
    required = enrollment_models("openai", catalog)
    migrated_body, reason = migrate_models_line(
        legacy_body, LEGACY_ENROLLMENT_MODELS["openai"], required)
    check("legacy openai record migrates to the catalog set", reason, "migrated")
    check("the migrated body re-parses to the catalog set",
          _parse_account(migrated_body)["models"], ["terra", "sol", "luna"])
    check("migration touches ONLY the models line",
          migrated_body.replace("models: [terra, sol, luna]",
                                "models: [terra]") == legacy_body, True)
    legacy_shape = LEGACY_ENROLLMENT_MODELS["openai"]
    check("migration is idempotent (a migrated body no longer changes)",
          migrate_models_line(migrated_body, legacy_shape, required)[0], None)
    check("an operator-edited models line is NEVER fought",
          migrate_models_line(legacy_body.replace("[terra]", "[terra, sol]"),
                              legacy_shape, required)[0], None)
    check("a body with no models line is unmigratable (logged, not guessed)",
          migrate_models_line("provider: openai\n", legacy_shape, required),
          (None, "unmigratable body (0 models lines)"))
    check("a body with duplicate models lines is unmigratable",
          migrate_models_line("models: [terra]\nmodels: [terra]\n",
                              legacy_shape, required)[0], None)
    # Live-driver wiring over stubbed I/O: exactly the legacy openai record is PATCHed; the
    # anthropic full-set record, an operator-edited record, a provider-conflicted record, and
    # a non-account issue are all left untouched.
    issues = [
        {"number": 1, "title": "acct01", "body": legacy_body,
         "labels": [{"name": "provider:openai"}, {"name": "status:available"}]},
        {"number": 2, "title": "acct02",
         "body": "provider: anthropic\nmodels: [fable, opus, sonnet, haiku]\n",
         "labels": [{"name": "provider:anthropic"}]},
        {"number": 3, "title": "acct03", "body": "provider: openai\nmodels: [terra, sol]\n",
         "labels": [{"name": "provider:openai"}]},
        {"number": 4, "title": "acct04", "body": "provider: openai\nmodels: [terra]\n",
         "labels": [{"name": "provider:anthropic"}]},   # label/body conflict: never guessed
        {"number": 5, "title": "set up new account", "body": "models: [terra]\n",
         "labels": [{"name": "provider:openai"}]},
    ]
    patches = []
    real_run, real_sub_run = _run, subprocess.run

    def fake_run(args):
        class _R:
            stdout = json.dumps(issues)
        return _R()

    def fake_sub_run(args, **kwargs):
        patches.append((args, kwargs.get("input")))

        class _R:
            returncode = 0
            stdout = stderr = ""
        return _R()

    try:
        globals()["_run"] = fake_run
        subprocess.run = fake_sub_run
        migrated_count = migrate_account_models("reg/repo", catalog)
    finally:
        globals()["_run"] = real_run
        subprocess.run = real_sub_run
    check("exactly the legacy-shape openai record migrates", migrated_count, 1)
    check("the PATCH targets that record",
          [args[4] for args, _ in patches], ["repos/reg/repo/issues/1"])
    check("the PATCHed body carries the catalog set",
          _parse_account(json.loads(patches[0][1])["body"])["models"],
          ["terra", "sol", "luna"])

    print("select-and-claim self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--reclaim", action="store_true", help="CAS-remove expired leases (cron)")
    ap.add_argument("--claim", action="store_true", help="claim a lease")
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
    ap.add_argument("--enrollment-models", metavar="PROVIDER",
                    help="print the catalog-derived models line for an enrolling account "
                         "(set-up-account broker)")
    ap.add_argument("--migrate-account-models", action="store_true",
                    help="converge legacy-shape open account records to the catalog-derived "
                         "models line (idempotent groom sweep)")
    ap.add_argument("--routing", default="orchestration/routing.toml",
                    help="routing catalog for --enrollment-models / --migrate-account-models")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()
    if args.enrollment_models or args.migrate_account_models:
        import tomllib
        with open(args.routing, "rb") as handle:
            routing = tomllib.load(handle)
        if args.enrollment_models:
            print("[" + ", ".join(enrollment_models(args.enrollment_models, routing)) + "]")
            return 0
        migrated = migrate_account_models(args.repo, routing)
        print(f"migrated {migrated} account record(s)")
        return 0
    import time
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
