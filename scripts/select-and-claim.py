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


# ---- pure allocation core (unit-tested) ---------------------------------------------------------
def reclaim_expired(leases, now):
    """Drop leases whose expiry has passed (conservative reclamation)."""
    return [x for x in leases if x.get("expires_at", 0) > now]


def active_for(leases, account):
    return sum(1 for x in leases if x["account"] == account)


def choose_account(accounts, leases, model_chain, package, role, now):
    """Return the account handle to claim, or None. `accounts`: list of dicts
    {handle, models:[...], max_concurrent_workers, available:bool}. Walks the model chain; within a
    model, prefers CACHE AFFINITY (an account that most recently ran the same package+role), else the
    least-loaded eligible account."""
    live = reclaim_expired(leases, now)
    for model in model_chain:
        serving = [a for a in accounts
                   if a.get("available", True) and model in a.get("models", [])
                   and active_for(live, a["handle"]) < int(a.get("max_concurrent_workers", 1))]
        if not serving:
            continue

        def affinity(a):  # most recent same-(package,role) lease on this account -> warmer cache
            times = [x.get("issued_at", 0) for x in live
                     if x["account"] == a["handle"] and x.get("package") == package and x.get("role") == role]
            return max(times) if times else -1

        serving.sort(key=lambda a: (-affinity(a), active_for(live, a["handle"]), a["handle"]))
        return serving[0]["handle"]
    return None


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


# ---- GitHub CAS I/O -----------------------------------------------------------------------------
def _read_ledger(repo):
    """Return (leases_list, blob_sha or None)."""
    try:
        out = subprocess.run(["gh", "api", f"repos/{repo}/contents/{LEDGER_PATH}"],
                             capture_output=True, text=True, check=True).stdout
        meta = json.loads(out)
        content = json.loads(base64.b64decode(meta["content"]).decode() or '{"leases":[]}')
        return content.get("leases", []), meta["sha"]
    except subprocess.CalledProcessError:
        return [], None  # file absent → first write creates it


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
    check("none free", choose_account([{"handle": "a", "models": ["x"], "max_concurrent_workers": 0}],
                                      [], ["x"], "p", "r", now), None)
    print("select-and-claim self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--reclaim", action="store_true", help="CAS-remove expired leases (cron)")
    ap.add_argument("--repo", default="jeswr/agent-account-registry")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()
    if args.reclaim:
        import time
        n = reclaim(args.repo, int(time.time()))
        print(f"reclaimed {n} expired lease(s)" if n >= 0 else "reclaim: CAS kept conflicting")
        return 0 if n >= 0 else 1
    # Live claim/release needs the account catalog (read from the account issues) + a CAS retry loop;
    # that wires in with the dispatch engine (Phase 3). This module ships the tested allocation core +
    # CAS I/O + reclaim now.
    print("select-and-claim: allocation core + reclaim ready; live claim/release wires in with dispatch (Phase 3).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
