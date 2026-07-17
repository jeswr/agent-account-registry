#!/usr/bin/env python3
# [OPUS-4.8] Maintainer alerting — the opposite posture from the dispatcher (which FAILS CLOSED and
# silently skips a capped account): this FAILS LOUD so the maintainer learns when worker throughput is
# degraded and can act (reset a subscription usage window, rotate an expired setup-token, top up codex).
#
# It reuses the usage map account-usage.py already probes (per-account 5h/7d utilization + reset, fable
# sub-quota, or {"exempt": true} for non-metered providers; a missing entry == token invalid/expired or
# the probe failed → treated as UNAVAILABLE). The pool is the UNION of every enabled policy row's
# account_pool (read straight from policy/repos.toml — never passed through env/log lines, privacy
# d22b) and the probed handles, and the margin comes from the same policy (the MAX across enabled rows,
# so the alert is at least as conservative as the strictest admission gate). classify() mirrors
# usage_eligible's FAIL-CLOSED semantics: a missing/unparseable window or a non-allowed probe status is
# UNAVAILABLE, never "0% used". A wholesale probe failure (empty usage with a configured pool) therefore
# classifies EVERY account UNAVAILABLE and always fires the alert — the exact case that used to no-op.
#
# Privacy (locked decision 22): account handles appear ONLY in the alert-issue body, never in workflow
# logs; ALERT_REPO/ALERT_TOKEN route that body to a private repo (fallback: the registry repo).
#
# Pure classify()/_policy_pool_margin() are unit-tested (--self-test); the CLI wraps them over the
# usage file + `gh`.
import json
import os
import subprocess
import sys
import tempfile
import tomllib

ALERT_TITLE = "⚠️ Worker account availability — action may be needed"
ALERT_LABEL = "ops-alert"


def _policy_pool_margin(policy_path):
    """(pool, margin) from policy/repos.toml: the union of enabled repos' account_pool and the MAX
    usage_safety_margin. (None, None) when the file is absent/unreadable — the caller falls back to
    env/probe. NOTE (task #325 seam): the pool list is slated to move to a private location; this
    reader is the single place to repoint when it does."""
    try:
        with open(policy_path, "rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return None, None
    pool, margin = set(), None
    repos = document.get("repos") if isinstance(document, dict) else None
    for row in (repos or {}).values():
        if not isinstance(row, dict) or row.get("enabled") is not True:
            continue
        pool.update(h for h in (row.get("account_pool") or []) if isinstance(h, str) and h)
        m = row.get("usage_safety_margin")
        if isinstance(m, (int, float)) and not isinstance(m, bool):
            margin = float(m) if margin is None else max(margin, float(m))
    return (sorted(pool) or None), margin


def _util(value):
    """Parse one utilization field FAIL-CLOSED: missing/None/unparseable -> None (never 0.0)."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def classify(pool, usage, margin):
    """Return (eligible_count, rows[(handle, status_str, ok_bool)]). Mirrors usage_eligible's
    fail-closed posture: an account is usable ONLY with a positive, parseable probe result — missing
    entry, non-allowed status, or a missing/unparseable 5h/7d window is UNAVAILABLE."""
    rows = []
    eligible = 0
    for h in pool:
        u = usage.get(h)
        if u is None:
            rows.append((h, "UNAVAILABLE — token invalid/expired or probe failed (rotate setup-token)", False))
            continue
        if u.get("exempt"):
            eligible += 1
            rows.append((h, "ok — non-metered provider", True))
            continue
        if str(u.get("status", "")).lower() not in ("allowed", ""):
            rows.append((h, f"UNAVAILABLE — provider status `{u.get('status')}` (throttled/rejected)", False))
            continue
        u5 = _util(u.get("5h_util"))
        u7 = _util(u.get("7d_util"))
        if u5 is None or u7 is None:
            rows.append((h, "UNAVAILABLE — usage window missing/unparseable (fail-closed)", False))
            continue
        cap = 1.0 - margin
        if u5 >= cap or u7 >= cap:
            win, util, reset = ("5h", u5, u.get("5h_reset")) if u5 >= cap else ("7d", u7, u.get("7d_reset"))
            rows.append((h, f"CAPPED — {win} window {util:.0%} used, resets {reset}", False))
        else:
            eligible += 1
            rows.append((h, f"ok — 5h {u5:.0%}, 7d {u7:.0%}", True))
    return eligible, rows


def render(eligible, rows, pool, threshold, maintainer, probe_empty=False):
    lines = ["> 🤖 SPARQ agent — automated worker-account availability check.\n"]
    if probe_empty:
        lines.append("🚨 **The usage probe returned NO data — dispatch is holding fail-closed.** "
                     "This is a probe/secret-infrastructure failure (malformed secrets, endpoint or "
                     "header change, curl outage), not N individually capped accounts.\n")
    lines.append(f"**Usable workers: {eligible}/{len(pool)}**  (degraded below {threshold}).\n")
    for h, s, ok in rows:
        lines.append(f"- {'✅' if ok else '⛔'} `{h}`: {s}")
    if eligible < threshold:
        lines.append(f"\n@{maintainer} — autonomous worker throughput is **degraded**. To restore it: reset the "
                     "usage window on any `CAPPED` subscription account, and rotate the token for any "
                     "`UNAVAILABLE` one (`claude setup-token` / codex `login --device-auth`). This issue "
                     "updates itself and closes automatically when availability recovers.")
    return "\n".join(lines)


def _gh(args, capture=False):
    # Privacy routing (locked decision 22c): when ALERT_REPO points at a private repo, ALERT_TOKEN
    # must be able to write there; otherwise the ambient GH_TOKEN (registry workflow token) is used.
    env = dict(os.environ)
    alert_token = os.environ.get("ALERT_TOKEN", "")
    if os.environ.get("ALERT_REPO") and alert_token:
        env["GH_TOKEN"] = alert_token
    return subprocess.run(["gh"] + args, capture_output=capture, text=True, env=env)


def main():
    registry_repo = os.environ["REGISTRY_REPO"]
    repo = os.environ.get("ALERT_REPO") or registry_repo   # where the alert issue lives
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")
    usage_file = os.environ.get("WORKER_USAGE_FILE")
    usage = json.load(open(usage_file)) if usage_file and os.path.exists(usage_file) else {}
    policy_pool, policy_margin = _policy_pool_margin(
        os.environ.get("POLICY_FILE", "policy/repos.toml"))
    margin = policy_margin if policy_margin is not None \
        else float(os.environ.get("USAGE_SAFETY_MARGIN", "0.10"))
    # UNION of the configured pool and the probed handles (the docstring contract): an account whose
    # token went bad — hence MISSING from the probe — can never silently vanish from the check, and a
    # wholesale probe failure still checks (and fails) every configured account.
    env_pool = [h for h in json.loads(os.environ.get("ACCOUNT_POOL", "[]")) if isinstance(h, str)]
    pool = sorted(set(policy_pool or env_pool) | set(usage.keys()))
    if not pool:
        print("usage-alert: no accounts to check (empty pool and empty probe)")
        return 0

    eligible, rows = classify(pool, usage, margin)
    threshold = max(1, (len(pool) + 1) // 2)      # degraded if fewer than half the pool is usable
    degraded = eligible < threshold
    body = render(eligible, rows, pool, threshold, maintainer, probe_empty=not usage)

    _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", "d73a4a",
         "--description", "Autonomous worker availability alert (maintainer action)"], capture=True)
    found = json.loads(_gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", "open",
                            "--json", "number,title", "--limit", "10"], capture=True).stdout or "[]")
    num = next((i["number"] for i in found if i["title"] == ALERT_TITLE), None)

    # Privacy (locked decision 22b): NOTHING printed to the (public) workflow log carries an account
    # handle, a per-provider count, or the pool size — the detail lives only in the alert issue body.
    if degraded:
        if num:
            _gh(["issue", "edit", str(num), "-R", repo, "--body", body])
        else:
            _gh(["issue", "create", "-R", repo, "--title", ALERT_TITLE, "--label", ALERT_LABEL, "--body", body])
        print("::warning::usage-alert: degraded=true — maintainer alerted (detail in the alert issue)")
    else:
        if num:
            _gh(["issue", "comment", str(num), "-R", repo, "--body",
                 "✅ Recovered — worker availability is back above the degraded threshold. Auto-closing."])
            _gh(["issue", "close", str(num), "-R", repo])
        print("usage-alert: degraded=false")
    return 0


def _self_test():
    ok = True

    def chk(n, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {n}: {got} (want {want})")

    pool = ["a", "b", "c", "d"]
    usage = {
        "a": {"5h_util": "0.2", "7d_util": "0.3", "5h_reset": "t1", "7d_reset": "t2"},  # ok
        "b": {"exempt": True},                                                          # ok (codex)
        "c": {"5h_util": "0.95", "7d_util": "0.1", "5h_reset": "14:00"},                # capped 5h
        # "d" missing -> token bad -> UNAVAILABLE
    }
    eligible, rows = classify(pool, usage, 0.10)
    chk("eligible count", eligible, 2)
    chk("capped detected", any("CAPPED" in s for h, s, o in rows if h == "c"), True)
    chk("missing -> unavailable", any("UNAVAILABLE" in s for h, s, o in rows if h == "d"), True)
    chk("exempt ok", any(o for h, s, o in rows if h == "b"), True)
    e2, _ = classify(["a", "b"], usage, 0.10)
    chk("small pool all ok", e2, 2)
    # FAIL-CLOSED alignment with usage_eligible (the old classify read missing windows as 0.0 "ok"):
    e3, r3 = classify(["x"], {"x": {"5h_util": "0.1"}}, 0.10)          # 7d window missing
    chk("missing window -> unavailable", (e3, "UNAVAILABLE" in r3[0][1]), (0, True))
    e4, r4 = classify(["x"], {"x": {"status": "rejected", "5h_util": "0", "7d_util": "0"}}, 0.10)
    chk("rejected status -> unavailable", (e4, "UNAVAILABLE" in r4[0][1]), (0, True))
    e5, r5 = classify(["x"], {"x": {"5h_util": "nan-ish%", "7d_util": "0"}}, 0.10)
    chk("unparseable -> unavailable", (e5, r5[0][2]), (0, False))
    # Wholesale probe failure: empty usage + configured pool -> every account UNAVAILABLE -> degraded.
    e6, r6 = classify(pool, {}, 0.10)
    chk("empty probe -> all unavailable", (e6, all(not o for _h, _s, o in r6)), (0, True))
    chk("empty probe fires the alert", e6 < max(1, (len(pool) + 1) // 2), True)
    chk("probe-failure banner", "holding fail-closed" in render(0, r6, pool, 2, "m", probe_empty=True), True)
    # Policy reader: pool union + strictest (max) margin across enabled rows; disabled rows ignored.
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as fh:
        fh.write('[repos."o/a"]\nenabled = true\naccount_pool = ["acct01", "acct02"]\n'
                 'usage_safety_margin = 0.15\n'
                 '[repos."o/b"]\nenabled = true\naccount_pool = ["acct02", "acct03"]\n'
                 'usage_safety_margin = 0.10\n'
                 '[repos."o/c"]\nenabled = false\naccount_pool = ["acct99"]\n')
        policy_path = fh.name
    got_pool, got_margin = _policy_pool_margin(policy_path)
    os.unlink(policy_path)
    chk("policy pool union", got_pool, ["acct01", "acct02", "acct03"])
    chk("policy margin is the max", got_margin, 0.15)
    chk("absent policy falls back", _policy_pool_margin("/nonexistent/policy.toml"), (None, None))
    print("usage-alert self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
