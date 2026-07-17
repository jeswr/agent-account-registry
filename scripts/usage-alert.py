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
# logs; ALERT_REPO/ALERT_TOKEN route that body to a private repo (fallback: the registry repo). A
# HALF-configured deployment (ALERT_REPO set, ALERT_TOKEN missing) falls back to the registry repo
# rather than writing to the private repo under the ambient token that can't reach it — a write that
# would fail silently and drop the alert (issue #39) — and REDACTS account handles from that fallback
# body (the registry is public and the maintainer signalled privacy intent; counts only). Writes go
# through _gh(check=True), which surfaces a non-zero gh returncode as a sanitized ::warning:: (op +
# returncode only — never gh stderr, which can echo request bodies under GH_DEBUG=api).
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
    """Parse one utilization field FAIL-CLOSED: missing/None/unparseable/NaN -> None (never 0.0).
    A literal `nan`/`inf` header would parse as a float whose comparisons are all False, so a CAPPED
    account would classify `ok` — treat any non-finite value as unparseable (issue #39). Real provider
    headers are decimal so this is a guard, not a currently-reachable path."""
    if value is None:
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if parsed != parsed or parsed in (float("inf"), float("-inf")):  # NaN (self-inequality) or ±inf
        return None
    return parsed


def _alert_route(alert_repo, alert_token, registry_repo):
    """(repo, token) for the alert issue (issue #39, privacy d22c). ALERT_REPO is the PRIMARY
    destination ONLY when ALERT_TOKEN can write there; a half-configured deployment (repo var set,
    token secret missed) must NOT try to write to the private repo under the ambient registry token
    (which has no permission there) — that write fails silently and the alert is dropped. So fall
    back to the registry repo, which the ambient token can always write. token=None means "use the
    ambient GH_TOKEN". redact_handles=True marks the HALF-configured case (ALERT_REPO set, token
    missing): the maintainer signalled privacy intent, so the fallback body must carry NO account
    handles — the registry repo is public (decision 22a) — while still failing loud (review r1)."""
    if alert_repo and alert_token:
        return alert_repo, alert_token, False
    return registry_repo, None, bool(alert_repo)


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


def render(eligible, rows, pool, threshold, maintainer, probe_empty=False, redact_handles=False):
    lines = ["> 🤖 SPARQ agent — automated worker-account availability check.\n"]
    if probe_empty:
        lines.append("🚨 **The usage probe returned NO data — dispatch is holding fail-closed.** "
                     "This is a probe/secret-infrastructure failure (malformed secrets, endpoint or "
                     "header change, curl outage), not N individually capped accounts.\n")
    lines.append(f"**Usable workers: {eligible}/{len(pool)}**  (degraded below {threshold}).\n")
    if redact_handles:
        # Half-configured private route (issue #39, review r1): this body lands on the PUBLIC
        # registry repo even though the maintainer signalled privacy intent via ALERT_REPO, so it
        # carries counts only — never an account handle (decision 22a).
        capped = sum(1 for _h, s, _ok in rows if s.startswith("CAPPED"))
        unavailable = sum(1 for _h, s, _ok in rows if s.startswith("UNAVAILABLE"))
        ok_count = len(rows) - capped - unavailable
        lines.append(f"- ⛔ capped: {capped} · unavailable: {unavailable} · ✅ ok: {ok_count}")
        lines.append("\n⚠️ Per-account detail suppressed: the private alert route is HALF-configured "
                     "(`ALERT_REPO` is set but the `ALERT_TOKEN` secret is missing), so this alert "
                     "fell back to the public registry repo. Set `ALERT_TOKEN` to receive per-account "
                     "detail privately.")
    else:
        for h, s, ok in rows:
            lines.append(f"- {'✅' if ok else '⛔'} `{h}`: {s}")
    if eligible < threshold:
        lines.append(f"\n@{maintainer} — autonomous worker throughput is **degraded**. To restore it: reset the "
                     "usage window on any `CAPPED` subscription account, and rotate the token for any "
                     "`UNAVAILABLE` one (`claude setup-token` / codex `login --device-auth`). This issue "
                     "updates itself and closes automatically when availability recovers.")
    return "\n".join(lines)


def _gh(args, capture=False, token=None, check=False):
    # Privacy routing (locked decision 22c): the caller resolves the alert repo+token via
    # _alert_route(); pass the resolved `token` here (None -> ambient GH_TOKEN). `check=True` on a
    # write surfaces a non-zero gh returncode instead of dropping the alert silently (issue #39).
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    result = subprocess.run(["gh"] + args, capture_output=capture, text=True, env=env)
    if check and result.returncode != 0:
        # Privacy (review r1): do NOT echo gh stderr — under GH_DEBUG=api it can contain the
        # request body (i.e. account handles). Log only the operation + returncode.
        print(f"::warning::usage-alert: gh {args[0]} {args[1] if len(args) > 1 else ''} "
              f"failed (rc={result.returncode})")
    return result


def main():
    registry_repo = os.environ["REGISTRY_REPO"]
    # Where the alert issue lives + which token writes it. A private ALERT_REPO is used ONLY when
    # ALERT_TOKEN can write there; otherwise fall back to the registry repo (issue #39) so a
    # half-configured deployment never silently drops the alert.
    repo, alert_token, redact_handles = _alert_route(
        os.environ.get("ALERT_REPO"), os.environ.get("ALERT_TOKEN"), registry_repo)
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
    body = render(eligible, rows, pool, threshold, maintainer, probe_empty=not usage,
                  redact_handles=redact_handles)

    _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", "d73a4a",
         "--description", "Autonomous worker availability alert (maintainer action)"],
        capture=True, token=alert_token)
    found = json.loads(_gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", "open",
                            "--json", "number,title", "--limit", "10"],
                           capture=True, token=alert_token).stdout or "[]")
    num = next((i["number"] for i in found if i["title"] == ALERT_TITLE), None)

    # Privacy (locked decision 22b): NOTHING printed to the (public) workflow log carries an account
    # handle, a per-provider count, or the pool size — the detail lives only in the alert issue body.
    if degraded:
        if num:
            _gh(["issue", "edit", str(num), "-R", repo, "--body", body], capture=True,
                token=alert_token, check=True)
        else:
            _gh(["issue", "create", "-R", repo, "--title", ALERT_TITLE, "--label", ALERT_LABEL,
                 "--body", body], capture=True, token=alert_token, check=True)
        print("::warning::usage-alert: degraded=true — maintainer alerted (detail in the alert issue)")
    else:
        if num:
            _gh(["issue", "comment", str(num), "-R", repo, "--body",
                 "✅ Recovered — worker availability is back above the degraded threshold. Auto-closing."],
                capture=True, token=alert_token, check=True)
            _gh(["issue", "close", str(num), "-R", repo], capture=True, token=alert_token, check=True)
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
    # Alert routing (issue #39): private repo used ONLY when its token is present; a half-configured
    # deployment (repo set, token missing) falls back to the registry repo so the write can't fail
    # silently under the ambient token. token=None means "use the ambient GH_TOKEN".
    chk("route: repo+token -> private + token, no redaction",
        _alert_route("org/private", "tok", "org/registry"), ("org/private", "tok", False))
    chk("route: repo but NO token -> registry fallback, REDACTED",
        _alert_route("org/private", "", "org/registry"), ("org/registry", None, True))
    chk("route: repo but None token -> registry fallback, REDACTED",
        _alert_route("org/private", None, "org/registry"), ("org/registry", None, True))
    chk("route: no repo -> registry, full body (documented d22c fallback)",
        _alert_route("", "tok", "org/registry"), ("org/registry", None, False))
    # Redacted fallback body (review r1): the half-configured route must never put an account
    # handle on the public registry repo — counts only, plus the fix-it hint.
    rrows = [("acct-priv-h1", "CAPPED — 5h window 95% used, resets t", False),
             ("acct-priv-h2", "UNAVAILABLE — token invalid/expired or probe failed", False),
             ("acct-priv-h3", "ok — 5h 10%, 7d 20%", True)]
    red = render(1, rrows, ["p", "q", "r"], 2, "m", redact_handles=True)
    chk("redacted body carries no handle",
        ("acct-priv-h1" in red, "acct-priv-h2" in red, "acct-priv-h3" in red), (False, False, False))
    chk("redacted body keeps counts + hint",
        ("capped: 1" in red, "unavailable: 1" in red, "ok: 1" in red, "ALERT_TOKEN" in red),
        (True, True, True, True))
    # _gh(check=True) fail-loud + sanitization (review r1): a non-zero gh returncode must emit a
    # ::warning:: naming the op + rc, and must NOT republish gh stderr (GH_DEBUG=api can echo the
    # request body) nor any argument content.
    import contextlib
    import io

    class _FailedRun:
        returncode = 1
        stderr = "SENTINEL-STDERR-ECHO"
        stdout = ""

    real_run = subprocess.run
    subprocess.run = lambda *a, **k: _FailedRun()
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _gh(["issue", "edit", "1", "--body", "SENTINEL-BODY-HANDLE"], capture=True, check=True)
        warned = buf.getvalue()
    finally:
        subprocess.run = real_run
    chk("gh check=True warns op+rc on failure",
        ("::warning::" in warned, "issue edit" in warned, "rc=1" in warned), (True, True, True))
    chk("gh failure warning is sanitized",
        ("SENTINEL-STDERR-ECHO" in warned, "SENTINEL-BODY-HANDLE" in warned), (False, False))
    # NaN/inf guard (issue #39): a literal `nan`/`inf` header must classify UNAVAILABLE, not `ok`
    # (NaN comparisons are all False, so it would otherwise slip past the CAPPED threshold).
    chk("nan header -> None (fail-closed)", _util("nan"), None)
    chk("inf header -> None (fail-closed)", _util("inf"), None)
    chk("decimal header still parses", _util("0.42"), 0.42)
    e7, r7 = classify(["x"], {"x": {"5h_util": "nan", "7d_util": "0"}}, 0.10)
    chk("nan util -> unavailable, not ok", (e7, r7[0][2]), (0, False))
    print("usage-alert self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
