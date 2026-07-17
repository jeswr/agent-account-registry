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
import subprocess
import sys

LEDGER_PATH = "data/leases.json"


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


def _usage_num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _usage_window(u, prefix):
    """(utilization, reset_ts) for the '5h'/'7d' window, or (None, None) if absent/unparseable."""
    if not isinstance(u, dict):
        return None, None
    return _usage_num(u.get(prefix + "_util")), _usage_num(u.get(prefix + "_reset"))


def usage_eligible(u, margin=SAFETY_MARGIN):
    """Fail-closed admission test for STARTING a worker on an account."""
    if not isinstance(u, dict):
        return False                                  # no probe data -> do not risk it
    if u.get("exempt"):
        return True                                   # non-metered provider (e.g. codex) — not gated
    if str(u.get("status", "")).lower() not in ("allowed", ""):
        return False                                  # throttled/rejected -> skip until it resets
    for prefix in ("5h", "7d"):
        util, _ = _usage_window(u, prefix)
        if util is None or (1.0 - util) < margin:
            return False                              # unknown, or too little headroom to finish
    return True


def _weekly_reset(u):
    _, reset = _usage_window(u, "7d")
    return reset if reset is not None else float("inf")


def _weekly_unused(u):
    util, _ = _usage_window(u, "7d")
    return (1.0 - util) if util is not None else 0.0


def choose_account(accounts, leases, model_chain, package, role, now, usage=None, margin=SAFETY_MARGIN):
    """Return the account handle to claim, or None. `accounts`: list of dicts
    {handle, models:[...], max_concurrent_workers, available:bool}. Walks the model chain; within a
    model keeps accounts under their concurrency cap and — when live `usage` (a {handle: {status,
    5h_util,5h_reset,7d_util,7d_reset}} map) is supplied — only accounts that pass `usage_eligible`.
    Orders eligible accounts by EXPIRY-PRIORITY: soonest weekly reset first (use credits before they
    reset), then most weekly headroom, then CACHE AFFINITY, then least-loaded. With `usage=None` the
    behaviour is the original cache-affinity-then-least-loaded selection (backward compatible)."""
    live = reclaim_expired(leases, now)
    for model in model_chain:
        serving = [a for a in accounts
                   if a.get("available", True) and model in a.get("models", [])
                   and active_for(live, a["handle"]) < int(a.get("max_concurrent_workers", 1))]
        if usage is not None:
            serving = [a for a in serving if usage_eligible(usage.get(a["handle"]), margin)]
        if not serving:
            continue

        def affinity(a):  # most recent same-(package,role) lease on this account -> warmer cache
            times = [x.get("issued_at", 0) for x in live
                     if x["account"] == a["handle"] and x.get("package") == package and x.get("role") == role]
            return max(times) if times else -1

        def sort_key(a):
            u = (usage or {}).get(a["handle"])
            return (_weekly_reset(u),                 # soonest weekly reset first (use-it-or-lose-it)
                    -_weekly_unused(u),               # then the most unused weekly credits
                    -affinity(a),                     # then warmest prompt cache
                    active_for(live, a["handle"]),    # then least-loaded
                    a["handle"])
        serving.sort(key=sort_key)
        return serving[0]["handle"]
    return None


def dynamic_concurrency(accounts, usage, model_chain=None, absolute_cap=None, margin=SAFETY_MARGIN):
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
        if model_chain is not None and not any(m in a.get("models", []) for m in model_chain):
            continue
        if usage_eligible(usage.get(a["handle"]), margin):
            total += int(a.get("max_concurrent_workers", 1))
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
def _read_ledger(repo):
    """Return (leases_list, blob_sha or None)."""
    result = subprocess.run(
        ["gh", "api", f"repos/{repo}/contents/{LEDGER_PATH}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        if "HTTP 404" in result.stderr:
            return [], None  # file absent → first write creates it
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
    args = ["gh", "api", "-X", "PUT", f"repos/{repo}/contents/{LEDGER_PATH}",
            "-f", f"message={message}", "-f", f"content={body}"]
    if sha:
        args += ["-f", f"sha={sha}"]
    r = subprocess.run(args, capture_output=True, text=True)
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
    d = {"models": [], "max_concurrent_workers": 1}
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


def claim(repo, package, role, model_chain, holder, now, ttl=3600, retries=6,
          account_pool=None, holder_prefix="", max_holder_concurrent=None, usage=None,
          margin=SAFETY_MARGIN):
    """CAS-claim a lease. Returns {account, secret_ref, model, claim_id} or None (none free / conflict)."""
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
    return None  # CAS kept conflicting


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
    U = [{"handle": "soon", "models": ["fable"], "max_concurrent_workers": 1, "available": True},
         {"handle": "late", "models": ["fable"], "max_concurrent_workers": 1, "available": True},
         {"handle": "full", "models": ["fable"], "max_concurrent_workers": 1, "available": True}]
    usage = {
        "soon": {"status": "allowed", "5h_util": 0.2, "5h_reset": 100, "7d_util": 0.2, "7d_reset": 3000},
        "late": {"status": "allowed", "5h_util": 0.2, "5h_reset": 100, "7d_util": 0.2, "7d_reset": 8000},
        "full": {"status": "allowed", "5h_util": 0.99, "5h_reset": 100, "7d_util": 0.99, "7d_reset": 1000},
    }
    # expiry-priority: 'soon' (7d_reset 3000) beats 'late' (8000); 'full' is ineligible (no headroom).
    check("expiry priority picks soonest reset",
          choose_account(U, [], ["fable"], "p", "r", now, usage=usage), "soon")
    # if 'soon' is removed from usage entirely -> fail-closed skip -> 'late' wins.
    check("fail-closed on missing usage",
          choose_account(U, [], ["fable"], "p", "r", now, usage={k: v for k, v in usage.items() if k != "soon"}),
          "late")
    # dynamic concurrency: 2 eligible (soon,late), 'full' backs off; absolute_cap clamps.
    check("dynamic concurrency counts eligible", dynamic_concurrency(U, usage, ["fable"]), 2)
    check("dynamic concurrency absolute cap", dynamic_concurrency(U, usage, ["fable"], absolute_cap=1), 1)
    allfull = {h: {**usage["full"]} for h in ("soon", "late", "full")}
    check("dynamic concurrency backs off to 0 when tapped out",
          dynamic_concurrency(U, allfull, ["fable"]), 0)
    check("dynamic concurrency 0 without usage (caller falls back to static)",
          dynamic_concurrency(U, None, ["fable"]), 0)
    # backward compat: usage=None keeps the original cache-affinity selection.
    check("usage=None backward compatible", choose_account(A, [], ["fable"], "pkg", "impl", now), "acct02")

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
    args = ap.parse_args()
    if args.self_test:
        return _self_test()
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
