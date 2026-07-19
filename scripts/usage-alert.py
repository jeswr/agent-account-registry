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
# Privacy (locked decision 22, issue #107): raw account handles are emitted ONLY over a VERIFIED
# private route — ALERT_REPO together with an ALERT_TOKEN that can write to it. EVERY fallback to the
# public registry repo carries aggregate counts only, never a handle (decision 22a): both the
# half-configured case (ALERT_REPO set, ALERT_TOKEN missing — writing to the private repo under the
# ambient token that can't reach it would fail silently and drop the alert, issue #39) AND the
# fully-unconfigured case (no ALERT_REPO) redact. Account handles never appear in workflow logs.
# Writes go through _gh(check=True), which surfaces a non-zero gh returncode as a sanitized
# ::warning:: (op + returncode only — never gh stderr, which can echo request bodies under
# GH_DEBUG=api).
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
    # OverflowError (cross-provider review r2 finding 3): float() of a forged huge JSON int
    # (10**400) RAISES rather than returning inf — uncaught, the monitoring tick died and the
    # alert was dropped. Unparseable, exactly like nan/inf.
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed != parsed or parsed in (float("inf"), float("-inf")):  # NaN (self-inequality) or ±inf
        return None
    return parsed


def _alert_route(alert_repo, alert_token, registry_repo):
    """(repo, token, redact_handles) for the alert issue (issue #107/#39, privacy d22c). The
    account-enumerating body is emitted ONLY over a VERIFIED private route — ALERT_REPO together
    with an ALERT_TOKEN that can write there. EVERY fallback to the registry repo REDACTS account
    handles to aggregate counts, because that repo is public (decision 22a): a public alert must
    never publish raw account identifiers (issue #107). This covers BOTH the half-configured case
    (ALERT_REPO set, ALERT_TOKEN missing — where writing to the private repo under the ambient
    registry token would fail silently and drop the alert, issue #39) AND the fully-unconfigured
    case (no ALERT_REPO at all). token=None means "use the ambient GH_TOKEN"; the write still fails
    loud via _gh(check=True) (review r1)."""
    if alert_repo and alert_token:
        return alert_repo, alert_token, False
    return registry_repo, None, True


def classify(pool, usage, margin, now=None):
    """Return (eligible_count, rows[(handle, status_str, ok_bool)]). Mirrors usage_eligible's
    fail-closed posture: an account is usable ONLY with a positive, parseable probe result — missing
    entry, non-allowed status, or a missing/unparseable 5h/7d window is UNAVAILABLE. PROBE-EXEMPT
    providers (openai/codex — maintainer decision 2026-07-17, registry issue #29) are `ok` by design
    (never flagged probe-missing) UNLESS the reactive-backoff stamp on the entry is still active, in
    which case the backoff is surfaced (BACKED OFF) so degraded exempt capacity is visible."""
    if now is None:
        import time
        now = time.time()
    rows = []
    eligible = 0
    for h in pool:
        u = usage.get(h)
        if u is None:
            rows.append((h, "UNAVAILABLE — token invalid/expired or probe failed (rotate setup-token)", False))
            continue
        if u.get("exempt") is True:  # STRICT, mirroring usage_eligible (cross-provider review r1)
            until = _util(u.get("backoff_until"))
            if until is not None and now < until:
                # A saturated chain may have been truncated in the health ledger (model-health
                # BACKOFF_CHAIN_KEEP), so its re-derived count is a LOWER BOUND — render "x6+",
                # never an exact "x6" (PR #85 finding 2). STRICT is-True, like `exempt`.
                hits = (f"x{u.get('backoff_consecutive', 1)}"
                        + ("+" if u.get("backoff_saturated") is True else ""))
                rows.append((h, f"BACKED OFF — provider rate limit hit "
                                f"({hits}); resumes at epoch "
                                f"{int(until)} (self-clearing)", False))
                continue
            eligible += 1
            rows.append((h, "ok — probe-exempt provider (reactive rate-limit backoff)", True))
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
        # Public-registry fallback (issue #107, #39, review r1): whenever the alert lands on the
        # PUBLIC registry repo — because no verified private route is configured, or only a
        # half-configured one (ALERT_REPO set, ALERT_TOKEN missing) — it carries aggregate counts
        # only, never an account handle (decision 22a). Per-account detail requires the verified
        # private ALERT_REPO+ALERT_TOKEN route.
        capped = sum(1 for _h, s, _ok in rows if s.startswith("CAPPED"))
        unavailable = sum(1 for _h, s, _ok in rows if s.startswith("UNAVAILABLE"))
        backed_off = sum(1 for _h, s, _ok in rows if s.startswith("BACKED OFF"))
        # healthy comes from ok_bool, never len-minus-categories (cross-provider review r3
        # finding 4): a BACKED OFF row is neither capped nor unavailable, so the remainder
        # arithmetic counted it healthy — "Usable workers: 0/1" alongside "✅ ok: 1".
        ok_count = sum(1 for _h, _s, ok_bool in rows if ok_bool)
        lines.append(f"- ⛔ capped: {capped} · unavailable: {unavailable} · backed off: "
                     f"{backed_off} · ✅ ok: {ok_count}")
        lines.append("\n⚠️ Per-account detail suppressed: this alert landed on the **public** "
                     "registry repo, so it lists aggregate counts only — never account handles. To "
                     "receive per-account detail privately, configure a private `ALERT_REPO` "
                     "together with an `ALERT_TOKEN` secret that can write to it (a route is used "
                     "only when BOTH are set).")
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
    # Issue #107: an UNCONFIGURED route (no ALERT_REPO) must ALSO land redacted on the public
    # registry — a lone ALERT_TOKEN is not a verified private destination, and no route at all
    # certainly is not. The public fallback must never enumerate raw account handles.
    chk("route: token but NO repo -> registry fallback, REDACTED (#107)",
        _alert_route("", "tok", "org/registry"), ("org/registry", None, True))
    chk("route: neither repo nor token -> registry fallback, REDACTED (#107)",
        _alert_route("", "", "org/registry"), ("org/registry", None, True))
    chk("route: None repo/token -> registry fallback, REDACTED (#107)",
        _alert_route(None, None, "org/registry"), ("org/registry", None, True))
    # Redacted fallback body (review r1): the half-configured route must never put an account
    # handle on the public registry repo — counts only, plus the fix-it hint.
    rrows = [("acct-priv-h1", "CAPPED — 5h window 95% used, resets t", False),
             ("acct-priv-h2", "UNAVAILABLE — token invalid/expired or probe failed", False),
             ("acct-priv-h3", "ok — 5h 10%, 7d 20%", True)]
    red = render(1, rrows, ["p", "q", "r"], 2, "m", redact_handles=True)
    chk("redacted body carries no handle",
        ("acct-priv-h1" in red, "acct-priv-h2" in red, "acct-priv-h3" in red), (False, False, False))
    chk("redacted body keeps counts + hint",
        ("capped: 1" in red, "unavailable: 1" in red, "✅ ok: 1" in red, "ALERT_TOKEN" in red),
        (True, True, True, True))
    # a BACKED OFF row is NOT healthy in the redacted render (cross-provider review r3 finding 4):
    # ok comes from ok_bool, and the backed-off state gets its own visible category — one active
    # backoff must not read as "Usable workers: 0/1" next to "✅ ok: 1"
    rback = render(0, [("acct-priv-h4", "BACKED OFF — provider rate limit hit (x2); resumes at "
                        "epoch 99 (self-clearing)", False)], ["p"], 1, "m", redact_handles=True)
    chk("redacted backed-off row counted backed-off, not ok",
        ("backed off: 1" in rback, "✅ ok: 0" in rback, "acct-priv-h4" in rback),
        (True, True, False))
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
    # END-TO-END redaction wiring (review r2): main() itself must feed _alert_route's redact flag
    # into render() AND write to the registry repo — deleting the redact_handles wiring in main()
    # (not just the pure helpers) must go red here. Half-configured env + stubbed gh.
    calls = []

    class _OkRun:
        returncode = 0
        stdout = "[]"
        stderr = ""

    def _capture_run(args, **_kw):
        calls.append(list(args))
        return _OkRun()

    wired_env = {"REGISTRY_REPO": "org/registry", "ALERT_REPO": "org/private",
                 "ACCOUNT_POOL": '["acct-wire-h1", "acct-wire-h2"]',
                 "POLICY_FILE": "/nonexistent/policy.toml"}
    saved_env = {k: os.environ.get(k)
                 for k in list(wired_env) + ["ALERT_TOKEN", "WORKER_USAGE_FILE"]}
    os.environ.update(wired_env)
    os.environ.pop("ALERT_TOKEN", None)
    os.environ.pop("WORKER_USAGE_FILE", None)
    real_run = subprocess.run
    subprocess.run = _capture_run
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            main()
    finally:
        subprocess.run = real_run
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    created = next((c for c in calls if c[:3] == ["gh", "issue", "create"]), None)
    body_arg = created[created.index("--body") + 1] if created and "--body" in created else ""
    repo_arg = created[created.index("-R") + 1] if created and "-R" in created else ""
    chk("main() half-configured: alert created on the REGISTRY repo", repo_arg, "org/registry")
    chk("main() half-configured: body is redacted END-TO-END",
        ("acct-wire-h1" in body_arg, "acct-wire-h2" in body_arg, "unavailable: 2" in body_arg),
        (False, False, True))
    # END-TO-END #107 guard: the FULLY-UNCONFIGURED case (no ALERT_REPO at all) must ALSO land on
    # the public registry repo with account handles redacted. This is the exact defect issue #107
    # names — the old `redact_handles = bool(alert_repo)` published raw handles here. Reverting the
    # fix to that expression must go RED on this assertion, not just the pure-helper ones above.
    calls2 = []

    def _capture_run2(args, **_kw):
        calls2.append(list(args))
        return _OkRun()

    unconfigured_env = {"REGISTRY_REPO": "org/registry",
                        "ACCOUNT_POOL": '["acct-wire-h1", "acct-wire-h2"]',
                        "POLICY_FILE": "/nonexistent/policy.toml"}
    saved_env2 = {k: os.environ.get(k)
                  for k in list(unconfigured_env) + ["ALERT_REPO", "ALERT_TOKEN", "WORKER_USAGE_FILE"]}
    os.environ.update(unconfigured_env)
    os.environ.pop("ALERT_REPO", None)
    os.environ.pop("ALERT_TOKEN", None)
    os.environ.pop("WORKER_USAGE_FILE", None)
    real_run = subprocess.run
    subprocess.run = _capture_run2
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            main()
    finally:
        subprocess.run = real_run
        for k, v in saved_env2.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    created2 = next((c for c in calls2 if c[:3] == ["gh", "issue", "create"]), None)
    body2 = created2[created2.index("--body") + 1] if created2 and "--body" in created2 else ""
    repo2 = created2[created2.index("-R") + 1] if created2 and "-R" in created2 else ""
    chk("main() unconfigured (#107): alert created on the public REGISTRY repo", repo2, "org/registry")
    chk("main() unconfigured (#107): body is redacted END-TO-END (no raw handles)",
        ("acct-wire-h1" in body2, "acct-wire-h2" in body2, "unavailable: 2" in body2),
        (False, False, True))
    # Probe-exempt backoff surfacing (decision 2026-07-17, registry issue #29): an exempt account
    # is `ok` by design (never probe-missing), but an ACTIVE backoff is surfaced + not eligible,
    # an EXPIRED one clears, and a forged/malformed stamp fails open to `ok` (never crashes).
    tnow = 5_000
    e8, r8 = classify(["cx"], {"cx": {"exempt": True, "backoff_until": tnow + 300,
                                      "backoff_consecutive": 2}}, 0.10, now=tnow)
    chk("active backoff surfaced + not eligible",
        (e8, "BACKED OFF" in r8[0][1], "x2" in r8[0][1], r8[0][2]), (0, True, True, False))
    chk("unsaturated backoff count stays EXACT (no lower-bound suffix)",
        "x2+" in r8[0][1], False)
    # A saturated (>6-hit, possibly ledger-truncated) chain displays the LOWER-BOUND form —
    # "x6+", never an exact "x6" (PR #85 finding 2: prune truncation floors the re-derived
    # count, so an exact display corrupts the diagnostic). Forged non-bool flags add nothing.
    e8b, r8b = classify(["cx"], {"cx": {"exempt": True, "backoff_until": tnow + 300,
                                        "backoff_consecutive": 6,
                                        "backoff_saturated": True}}, 0.10, now=tnow)
    chk("saturated backoff displays the lower-bound form (x6+, never exact x6)",
        ("(x6+)" in r8b[0][1], "(x6)" in r8b[0][1], r8b[0][2]), (True, False, False))
    e8c, r8c = classify(["cx"], {"cx": {"exempt": True, "backoff_until": tnow + 300,
                                        "backoff_consecutive": 6,
                                        "backoff_saturated": "yes"}}, 0.10, now=tnow)
    chk("forged non-bool saturated flag never adds the suffix (strict is-True)",
        ("(x6)" in r8c[0][1], "(x6+)" in r8c[0][1]), (True, False))
    e9, r9 = classify(["cx"], {"cx": {"exempt": True, "backoff_until": tnow - 1}}, 0.10, now=tnow)
    chk("expired backoff -> ok again", (e9, r9[0][2]), (1, True))
    e10, r10 = classify(["cx"], {"cx": {"exempt": True, "backoff_until": "garbage"}}, 0.10, now=tnow)
    chk("malformed backoff stamp fails open to ok", (e10, r10[0][2]), (1, True))
    # inf/nan stamps fail open to ok (matches usage_eligible's finite-only comparison, r1)
    e11, r11 = classify(["cx"], {"cx": {"exempt": True, "backoff_until": "inf"}}, 0.10, now=tnow)
    chk("inf backoff stamp fails open to ok (no dispatch/alert split)", (e11, r11[0][2]), (1, True))
    # a huge JSON int (10**400) makes float() RAISE OverflowError, not return inf — the monitoring
    # tick must survive it: exempt backoff fails OPEN to ok, a usage window fails CLOSED to
    # UNAVAILABLE (cross-provider review r2 finding 3)
    e13, r13 = classify(["cx"], {"cx": {"exempt": True, "backoff_until": 10**400}}, 0.10, now=tnow)
    chk("huge-int backoff stamp fails open to ok (no alert drop)", (e13, r13[0][2]), (1, True))
    e14, r14 = classify(["a"], {"a": {"status": "allowed", "5h_util": 10**400, "7d_util": 0.1}},
                        0.10, now=tnow)
    chk("huge-int usage window classifies fail-closed UNAVAILABLE", (e14, r14[0][2]), (0, False))
    # a forged truthy exempt STRING does not ride the exempt arm (STRICT flag, r1)
    e12, r12 = classify(["cx"], {"cx": {"exempt": "false"}}, 0.10, now=tnow)
    chk("forged exempt string classifies fail-closed UNAVAILABLE", (e12, r12[0][2]), (0, False))
    # NaN/inf guard (issue #39): a literal `nan`/`inf` header must classify UNAVAILABLE, not `ok`
    # (NaN comparisons are all False, so it would otherwise slip past the CAPPED threshold).
    chk("nan header -> None (fail-closed)", _util("nan"), None)
    chk("inf header -> None (fail-closed)", _util("inf"), None)
    chk("-inf header -> None (fail-closed)", _util("-inf"), None)
    chk("decimal header still parses", _util("0.42"), 0.42)
    e7, r7 = classify(["x"], {"x": {"5h_util": "nan", "7d_util": "0"}}, 0.10)
    chk("nan util -> unavailable, not ok", (e7, r7[0][2]), (0, False))
    print("usage-alert self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
