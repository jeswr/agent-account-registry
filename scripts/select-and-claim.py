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


# ---- account catalog + live claim / release ----------------------------------------------------
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
        elif k in ("secret_ref", "provider", "harness"):
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


def claim(repo, package, role, model_chain, holder, now, ttl=3600, retries=6):
    """CAS-claim a lease. Returns {account, secret_ref, model, claim_id} or None (none free / conflict)."""
    import uuid
    accounts = read_accounts(repo)
    for _ in range(retries):
        leases, sha = _read_ledger(repo)
        acct = choose_account(accounts, leases, model_chain, package, role, now)
        if acct is None:
            return None
        a = next(x for x in accounts if x["handle"] == acct)
        model = next((m for m in model_chain if m in a["models"]), model_chain[0])
        cid = uuid.uuid4().hex
        live, _lease = apply_claim(leases, acct, holder, package, role, model, now, ttl, cid)
        if _write_ledger(repo, live, sha, f"claim {cid[:8]} {acct} {package}/{role}"):
            return {"account": acct, "secret_ref": a.get("secret_ref"), "model": model, "claim_id": cid}
    return None  # CAS kept conflicting


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
    check("none free", choose_account([{"handle": "a", "models": ["x"], "max_concurrent_workers": 0}],
                                      [], ["x"], "p", "r", now), None)
    pa = _parse_account("provider: openai\nmodels: [terra, gpt]\nmax_concurrent_workers: 2\nsecret_ref: ACCT01_TOKEN")
    check("parse account", (pa["models"], pa["max_concurrent_workers"], pa["secret_ref"]),
          (["terra", "gpt"], 2, "ACCT01_TOKEN"))
    print("select-and-claim self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--reclaim", action="store_true", help="CAS-remove expired leases (cron)")
    ap.add_argument("--claim", action="store_true", help="claim a lease")
    ap.add_argument("--release", metavar="CLAIM_ID", help="release a lease by claim id")
    ap.add_argument("--package", default="")
    ap.add_argument("--role", default="")
    ap.add_argument("--models", default="", help="comma-separated model fallback chain")
    ap.add_argument("--holder", default="", help="owner/repo@run identifier")
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
        chain = [m for m in args.models.split(",") if m.strip()]
        res = claim(args.repo, args.package, args.role, chain, args.holder, int(time.time()))
        print(json.dumps(res) if res else "none-free")
        return 0 if res else 3
    if args.release:
        print("released" if release(args.repo, args.release, int(time.time())) else "release-failed")
        return 0
    print("select-and-claim: allocation core + reclaim + live claim/release ready (wires into dispatch, Phase 3).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
