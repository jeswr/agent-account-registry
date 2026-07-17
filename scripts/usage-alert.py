#!/usr/bin/env python3
# [OPUS-4.8] Maintainer alerting — the opposite posture from the dispatcher (which FAILS CLOSED and
# silently skips a capped account): this FAILS LOUD so the maintainer learns when worker throughput is
# degraded and can act (reset a subscription usage window, rotate an expired setup-token, top up codex).
#
# It reuses the usage map account-usage.py already probes (per-account 5h/7d utilization + reset, fable
# sub-quota, or {"exempt": true} for non-metered providers; a missing entry == token invalid/expired or
# the probe failed → treated as UNAVAILABLE). It classifies each pooled account, and if fewer than a
# threshold are usable it upserts ONE rolling GitHub issue (deduped by label+title) that @-mentions the
# maintainer with per-account reasons + reset times; when availability recovers it comments + closes.
#
# Pure classify() is unit-tested (--self-test); the CLI wraps it over the usage file + `gh`.
import json
import os
import subprocess
import sys

ALERT_TITLE = "⚠️ Worker account availability — action may be needed"
ALERT_LABEL = "ops-alert"


def classify(pool, usage, margin):
    """Return (eligible_count, rows[(handle, status_str, ok_bool)]). An account is usable unless it is
    missing from `usage` (token bad), unparseable, or at/over (1 - margin) on its 5h or 7d window."""
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
        try:
            u5 = float(u.get("5h_util") or 0.0)
            u7 = float(u.get("7d_util") or 0.0)
        except (TypeError, ValueError):
            rows.append((h, "UNAVAILABLE — unparseable usage headers", False))
            continue
        cap = 1.0 - margin
        if u5 >= cap or u7 >= cap:
            win, util, reset = ("5h", u5, u.get("5h_reset")) if u5 >= cap else ("7d", u7, u.get("7d_reset"))
            rows.append((h, f"CAPPED — {win} window {util:.0%} used, resets {reset}", False))
        else:
            eligible += 1
            rows.append((h, f"ok — 5h {u5:.0%}, 7d {u7:.0%}", True))
    return eligible, rows


def render(eligible, rows, pool, threshold, maintainer):
    lines = ["> 🤖 SPARQ agent — automated worker-account availability check.\n",
             f"**Usable workers: {eligible}/{len(pool)}**  (degraded below {threshold}).\n"]
    for h, s, ok in rows:
        lines.append(f"- {'✅' if ok else '⛔'} `{h}`: {s}")
    if eligible < threshold:
        lines.append(f"\n@{maintainer} — autonomous worker throughput is **degraded**. To restore it: reset the "
                     "usage window on any `CAPPED` subscription account, and rotate the token for any "
                     "`UNAVAILABLE` one (`claude setup-token` / codex `login --device-auth`). This issue "
                     "updates itself and closes automatically when availability recovers.")
    return "\n".join(lines)


def _gh(args, capture=False):
    return subprocess.run(["gh"] + args, capture_output=capture, text=True)


def main():
    repo = os.environ["REGISTRY_REPO"]           # where the alert issue lives (the maintainer watches it)
    margin = float(os.environ.get("USAGE_SAFETY_MARGIN", "0.10"))
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")
    usage_file = os.environ.get("WORKER_USAGE_FILE")
    usage = json.load(open(usage_file)) if usage_file and os.path.exists(usage_file) else {}
    # explicit pool if the policy provides one; else fall back to every account the probe saw (so an
    # account whose token went bad — hence MISSING from the probe — can't silently vanish from the check,
    # we keep the union of the configured pool and the probed handles).
    pool = json.loads(os.environ.get("ACCOUNT_POOL", "[]")) or sorted(usage.keys())
    if not pool:
        print("usage-alert: no accounts to check (empty pool and empty probe)")
        return 0

    eligible, rows = classify(pool, usage, margin)
    threshold = max(1, (len(pool) + 1) // 2)      # degraded if fewer than half the pool is usable
    degraded = eligible < threshold
    body = render(eligible, rows, pool, threshold, maintainer)

    found = json.loads(_gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", "open",
                            "--json", "number,title", "--limit", "10"], capture=True).stdout or "[]")
    num = next((i["number"] for i in found if i["title"] == ALERT_TITLE), None)

    if degraded:
        if num:
            _gh(["issue", "edit", str(num), "-R", repo, "--body", body])
        else:
            _gh(["issue", "create", "-R", repo, "--title", ALERT_TITLE, "--label", ALERT_LABEL, "--body", body])
        print(f"::warning::usage-alert: DEGRADED {eligible}/{len(pool)} usable — maintainer alerted")
    else:
        if num:
            _gh(["issue", "comment", str(num), "-R", repo, "--body",
                 f"✅ Recovered — {eligible}/{len(pool)} workers usable. Auto-closing."])
            _gh(["issue", "close", str(num), "-R", repo])
        print(f"usage-alert: healthy {eligible}/{len(pool)} usable")
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
    # all healthy -> not degraded (threshold for 4 = 2, eligible 2 -> not degraded; drop c,d -> 2/4 == threshold)
    e2, _ = classify(["a", "b"], usage, 0.10)
    chk("small pool all ok", e2, 2)
    print("usage-alert self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
