#!/usr/bin/env python3
# Token broker refresh core (maintainer decision 2026-07-15: private broker, and it must
# NEVER require re-authenticating sessions). The broker lives ONLY in this private registry; the
# public worker receives a SHORT-LIVED ACCESS TOKEN and never the long-lived refresh token.
#
# Design (why this satisfies both constraints):
#   * Each account's stored credential carries a long-lived REFRESH token
#       - openai/codex  : ~/.codex/auth.json         -> tokens.{access_token,refresh_token,id_token}
#       - anthropic     : ~/.claude/.credentials.json -> claudeAiOauth.{accessToken,refreshToken,expiresAt}
#   * On a worker request the broker (a) materializes the credential into an ISOLATED $HOME (never the
#     maintainer's live ~/.codex / ~/.claude), (b) performs the provider's documented refresh:
#       - openai/codex : `codex login status` — the CLI itself refreshes the access token from the
#         refresh token and rewrites auth.json, which is then re-read;
#       - anthropic    : if the stored access token is missing, expiring, or of unknown expiry, a
#         `refresh_token` grant against the OAuth token endpoint mints a fresh access token; the
#         rotated credential is persisted into the isolated HOME and re-read, and the (new or
#         still-live) access token must then pass the non-inference `/api/oauth/profile` check
#         before it is attested;
#     and REQUIRES the op to succeed before the credential is accepted, so a stale/unproven credential
#     can never be reported as a fresh one; then (c) INDEPENDENTLY of the provider op, requires the
#     re-read expiry to outlive a worker job by WORKER_TOKEN_MIN_LIFETIME_S (so a status op that
#     "succeeds" over an expired, un-rotated token is still refused) and extracts ONLY
#     {access_token, expires_at} — openai expiry derived from the access token's own `exp` claim,
#     NOT `last_refresh` — and returns that.
#     The refresh token stays inside the registry. The maintainer never re-authenticates: the refresh
#     token is valid until explicitly revoked and is what mints each short-lived access token.
#
# --self-test covers the pure parts over the real credential layouts AND the live proof paths
# (_prove_openai/_prove_anthropic/refresh_via_cli) via injected subprocess/HTTP mocks over real
# credential files in a throwaway HOME — no network, no real subprocess, no live tokens, so it never
# touches or rotates the maintainer's active login. In the registry's own Actions the same code runs
# un-mocked against an account secret.
"""broker-refresh — mint a short-lived worker access token from a stored refresh credential.

The security invariant, asserted by --self-test: the returned capability NEVER contains the refresh
token (or any key whose name implies a refresh/long-lived secret)."""
import argparse
import base64
import json
import math
import os
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

PROVIDERS = ("openai", "anthropic")


# ---- pure core (unit-tested; no network, no live tokens) ----------------------------------------
def cred_relpath(provider):
    """Where the provider CLI expects its credential inside a $HOME."""
    if provider == "openai":
        return ".codex/auth.json"
    if provider == "anthropic":
        return ".claude/.credentials.json"
    raise ValueError(f"unknown provider {provider!r}")


def _jwt_exp(access_token):
    """The Unix-seconds `exp` claim decoded from a JWT access token, or None if it cannot be read.
    OpenAI/codex access tokens are JWTs whose `exp` IS the true token expiry (unlike `last_refresh`,
    which is merely when the CLI last rewrote the file). Pure/offline: decodes, never verifies a
    signature — the signature is the provider's concern, we only read the expiry we are attesting."""
    if not isinstance(access_token, str):
        return None
    parts = access_token.split(".")
    if len(parts) != 3:
        return None  # not a JWT
    payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)  # restore base64url padding
    try:
        exp = json.loads(base64.urlsafe_b64decode(payload_b64.encode("ascii"))).get("exp")
    except (ValueError, TypeError, AttributeError):
        return None
    return int(exp) if isinstance(exp, (int, float)) else None


def extract_access_token(provider, cred):
    """Return the SHORT-LIVED capability {access_token, expires_at} from a (refreshed) credential.
    NEVER returns the refresh token. `cred` is the parsed credential JSON. Fail closed: a credential
    with no access token is not a usable capability, so reject it rather than emit access_token=None."""
    if provider == "openai":
        access_token = cred.get("tokens", {}).get("access_token")
        if not access_token:
            raise ValueError("openai credential has no tokens.access_token")
        # Real expiry comes from the access token's own `exp` claim, NOT `last_refresh`.
        return {"access_token": access_token, "expires_at": _jwt_exp(access_token)}
    if provider == "anthropic":
        o = cred.get("claudeAiOauth", {})
        access_token = o.get("accessToken")
        if not access_token:
            raise ValueError("anthropic credential has no claudeAiOauth.accessToken")
        return {"access_token": access_token, "expires_at": o.get("expiresAt")}
    raise ValueError(f"unknown provider {provider!r}")


_REFRESH_HINTS = ("refresh", "refresh_token", "refreshtoken")


def assert_no_refresh_leak(capability):
    """Fail closed: the capability handed to the worker must carry no refresh/long-lived secret."""
    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if any(h in str(k).lower() for h in _REFRESH_HINTS):
                    raise AssertionError(f"refresh secret leaked into worker capability via key {k!r}")
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(capability)
    return True


# ---- isolation + live refresh (registry Actions only; not in --self-test) -----------------------
def _write_isolated(provider, cred, home):
    """Write the credential into an isolated HOME at mode 600; returns the path."""
    rel = cred_relpath(provider)
    path = os.path.join(home, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cred, f)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return path


ANTHROPIC_PROFILE_URL = "https://api.anthropic.com/api/oauth/profile"
ANTHROPIC_TOKEN_URL = "https://console.anthropic.com/v1/oauth/token"
# Claude Code's PUBLIC OAuth client identifier (baked into the CLI's PKCE flow; not a secret).
ANTHROPIC_OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
# A worker capability must outlive a worker job by this margin; refresh_ok enforces it for BOTH
# providers on the re-read credential, so a "successful" refresh op that leaves an expired (or
# near-expiry) token on disk can never be attested as a fresh capability.
WORKER_TOKEN_MIN_LIFETIME_S = 3600
# Mint a new access token unless the stored one outlives a worker job by this margin.
ANTHROPIC_REFRESH_SKEW_S = WORKER_TOKEN_MIN_LIFETIME_S


def _http_post_json(url, payload, timeout=30):
    """POST a JSON body; parsed JSON response on HTTP 200, else None. Fail closed, never log bodies."""
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (hard-coded https host)
            return json.loads(resp.read().decode()) if resp.status == 200 else None
    except (urllib.error.URLError, ValueError):
        return None


def _http_get_status(url, headers, timeout=30):
    """GET returning the HTTP status code, or None on any error. The body is never read or logged."""
    req = urllib.request.Request(url, method="GET", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (hard-coded https host)
            return resp.status
    except urllib.error.URLError:
        return None


def _prove_openai(home, run=None):
    """Run codex's documented, authenticated, NON-INFERENCE status op so the CLI validates/refreshes
    the access token from its refresh token, then re-read the (possibly rewritten) credential.
    Returns (ok, cred): ok is a clean exit 0 (`codex whoami` was never a subcommand and could stall on
    an interactive prompt; `codex login status` is the real status command). `run` is injectable so
    --self-test can prove the re-read-after-refresh behaviour without a real subprocess."""
    run = subprocess.run if run is None else run
    env = dict(os.environ, HOME=home)
    proc = run(["codex", "login", "status"], env=env,
               capture_output=True, text=True, timeout=60)
    with open(os.path.join(home, cred_relpath("openai"))) as f:
        return proc.returncode == 0, json.load(f)


def _prove_anthropic(home, http_post=None, http_get=None, now=None):
    """Mint/validate the anthropic access token. If the stored token is missing, of unknown expiry, or
    expires within ANTHROPIC_REFRESH_SKEW_S, exchange the long-lived refresh token at the OAuth token
    endpoint (`grant_type=refresh_token`) for a fresh access token, persist the rotated credential
    into the isolated HOME, and re-read it — so on-disk state is what gets attested. The resulting
    (new or still-live) token must then pass the documented, non-inference profile check (the same op
    account-whoami trusts). Returns (ok, cred); any failure — no refresh token, failed exchange,
    unattestable expiry, non-200 profile — is (False, ...). Tokens travel only in request
    headers/bodies, never logs. `http_post`/`http_get`/`now` are injectable for --self-test."""
    http_post = _http_post_json if http_post is None else http_post
    http_get = _http_get_status if http_get is None else http_get
    now = time.time() if now is None else now
    path = os.path.join(home, cred_relpath("anthropic"))
    with open(path) as f:
        cred = json.load(f)
    o = cred.get("claudeAiOauth", {})
    if not o.get("refreshToken"):
        return False, cred  # cannot mint without the long-lived credential; fail closed
    exp = o.get("expiresAt")  # Claude Code stores milliseconds; tolerate seconds
    exp_s = exp / 1000.0 if isinstance(exp, (int, float)) and exp > 1e12 else exp
    stale = (not o.get("accessToken") or not isinstance(exp_s, (int, float))
             or exp_s <= now + ANTHROPIC_REFRESH_SKEW_S)
    if stale:
        resp = http_post(ANTHROPIC_TOKEN_URL, {
            "grant_type": "refresh_token", "refresh_token": o["refreshToken"],
            "client_id": ANTHROPIC_OAUTH_CLIENT_ID})
        minted, expires_in = (resp or {}).get("access_token"), (resp or {}).get("expires_in")
        if (not minted or not isinstance(expires_in, (int, float)) or not math.isfinite(expires_in)
                or expires_in <= ANTHROPIC_REFRESH_SKEW_S):
            # Exchange failed, expiry unattestable, or the minted lifetime cannot cover a worker job
            # (zero/negative/below-margin) — the same lifetime invariant that forced the mint.
            return False, cred  # fail closed; never persist an unusable minted token
        cred = dict(cred, claudeAiOauth=dict(
            o, accessToken=minted, expiresAt=int((now + expires_in) * 1000),
            refreshToken=resp.get("refresh_token") or o["refreshToken"]))
        _write_isolated("anthropic", cred, home)
        with open(path) as f:
            cred = json.load(f)
    token = cred["claudeAiOauth"]["accessToken"]
    status = http_get(ANTHROPIC_PROFILE_URL, {
        "Authorization": f"Bearer {token}", "anthropic-version": "2023-06-01"})
    return status == 200, cred


def refresh_via_cli(provider, home, **kwargs):
    """Trigger the provider's documented refresh op (with HOME=`home`), then re-read the credential.
    Returns (ok, cred). The provider owns the OAuth endpoints. `kwargs` pass injectable I/O through
    to the provider proof (used by --self-test); registry Actions call it bare."""
    prove = {"openai": _prove_openai, "anthropic": _prove_anthropic}[provider]
    return prove(home, **kwargs)


def refresh_ok(provider, ok, refreshed, now=None):
    """Fail-closed gate over a refresh attempt: the op must have succeeded (ok) AND the re-read
    credential must yield a usable capability — an access token (extract raises otherwise) with an
    attestable expiry that outlives a worker job by WORKER_TOKEN_MIN_LIFETIME_S. This is checked here
    for BOTH providers, independently of the provider proof, so an op that "succeeds" while leaving
    an expired or near-expiry token on disk (e.g. `codex login status` exiting 0 without rotating)
    is NEVER reported as a fresh capability. `now` is injectable for --self-test."""
    now = time.time() if now is None else now
    if not ok:
        raise RuntimeError(f"{provider} refresh op did not succeed; credential not proven refreshed")
    cap = extract_access_token(provider, refreshed)
    exp = cap["expires_at"]  # anthropic stores milliseconds; tolerate seconds
    exp_s = exp / 1000.0 if isinstance(exp, (int, float)) and exp > 1e12 else exp
    # Condition stated positively so NaN (all comparisons False) also fails closed.
    if not (isinstance(exp_s, (int, float)) and math.isfinite(exp_s)
            and exp_s > now + WORKER_TOKEN_MIN_LIFETIME_S):
        raise ValueError(f"{provider} access token expiry is unattestable or does not outlive a "
                         "worker job; refusing to attest it as a fresh capability")
    return cap


def broker(provider, cred):
    """Full path (registry Actions): isolate -> prove refresh -> extract access-token-only capability."""
    home = tempfile.mkdtemp(prefix="broker-")
    try:
        os.chmod(home, 0o700)
        _write_isolated(provider, cred, home)
        ok, refreshed = refresh_via_cli(provider, home)
        cap = refresh_ok(provider, ok, refreshed)
        assert_no_refresh_leak(cap)
        return cap
    finally:
        subprocess.run(["rm", "-rf", home], check=False)


# ---- self-test (mocked; never touches a live login) ---------------------------------------------
def _self_test():
    ok = True

    def chk(n, cond):
        nonlocal ok
        ok = ok and cond
        print(f"  {'ok  ' if cond else 'FAIL'} {n}")

    def raises(exc, fn):  # True iff fn() raises `exc` — makes the fail-closed guards non-vacuous
        try:
            fn()
        except exc:
            return True
        return False

    def mk_jwt(exp):  # a real-shape JWT (fake signature) whose payload carries `exp`
        seg = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
        return f"{seg({'alg': 'RS256', 'typ': 'JWT'})}.{seg({'exp': exp, 'sub': 'u'})}.sig"

    # real key layouts (values are fake). The codex access token is a JWT — its `exp` is the true
    # expiry; `last_refresh` is deliberately a DIFFERENT value to prove we never report last_refresh.
    access_jwt = mk_jwt(1799999999)
    codex = {"auth_mode": "oauth",
             "tokens": {"id_token": "ID", "access_token": access_jwt, "refresh_token": "REFRESH_long",
                        "account_id": "acct"}, "last_refresh": "2026-07-15T00:00:00Z"}
    claude = {"claudeAiOauth": {"accessToken": "ACCESS_short", "refreshToken": "REFRESH_long",
                                "expiresAt": 1799999999, "scopes": ["x"], "subscriptionType": "max"}}
    co = extract_access_token("openai", codex)
    cl = extract_access_token("anthropic", claude)
    chk("openai extracts access token", co["access_token"] == access_jwt)
    chk("openai expiry is the JWT exp claim", co["expires_at"] == 1799999999)
    chk("openai expiry is NOT last_refresh (non-vacuous)", co["expires_at"] != codex["last_refresh"])
    chk("anthropic extracts access token", cl["access_token"] == "ACCESS_short")
    chk("anthropic carries expiry", cl["expires_at"] == 1799999999)
    # exp decoding: reads a real JWT, None for non-JWT / missing exp (non-vacuous both ways)
    chk("jwt exp decodes", _jwt_exp(access_jwt) == 1799999999)
    chk("jwt exp None for non-jwt", _jwt_exp("ACCESS_short") is None)
    chk("jwt exp None when exp absent", _jwt_exp(mk_jwt(None)) is None)
    # reject missing access tokens (fail closed) — both providers
    chk("openai rejects missing access token",
        raises(ValueError, lambda: extract_access_token("openai", {"tokens": {}})))
    chk("anthropic rejects missing access token",
        raises(ValueError, lambda: extract_access_token("anthropic", {"claudeAiOauth": {}})))
    # refresh gate: a failed op, a token with no derivable expiry, or a token whose expiry cannot
    # outlive a worker job is NEVER reported success — for EITHER provider.
    now = 1752000000  # fixed clock (seconds) so expiry math is deterministic; exp above is later
    chk("refresh_ok passes a proven openai refresh", refresh_ok("openai", True, codex, now=now) == co)
    chk("refresh_ok passes a proven anthropic refresh",
        refresh_ok("anthropic", True, claude, now=now) == cl)
    chk("refresh_ok rejects a failed op (non-vacuous)",
        raises(RuntimeError, lambda: refresh_ok("openai", False, codex, now=now)))
    chk("refresh_ok rejects openai token with no exp (non-vacuous)",
        raises(ValueError, lambda: refresh_ok(
            "openai", True, {"tokens": {"access_token": "opaque-not-a-jwt"}}, now=now)))
    chk("refresh_ok rejects an EXPIRED openai token even when the op reported ok (non-vacuous)",
        raises(ValueError, lambda: refresh_ok(
            "openai", True, {"tokens": {"access_token": mk_jwt(now - 60)}}, now=now)))
    chk("refresh_ok rejects an openai token expiring within the worker margin",
        raises(ValueError, lambda: refresh_ok(
            "openai", True, {"tokens": {"access_token": mk_jwt(now + 600)}}, now=now)))
    chk("refresh_ok rejects an EXPIRED anthropic token even when the op reported ok (non-vacuous)",
        raises(ValueError, lambda: refresh_ok(
            "anthropic", True,
            {"claudeAiOauth": {"accessToken": "A", "expiresAt": (now - 60) * 1000}}, now=now)))
    chk("refresh_ok rejects an anthropic token with a non-numeric expiry",
        raises(ValueError, lambda: refresh_ok(
            "anthropic", True, {"claudeAiOauth": {"accessToken": "A", "expiresAt": None}}, now=now)))
    chk("refresh_ok rejects a NaN expiry (fail closed on incomparable values)",
        raises(ValueError, lambda: refresh_ok(
            "anthropic", True,
            {"claudeAiOauth": {"accessToken": "A", "expiresAt": float("nan")}}, now=now)))
    # the security invariant: NO refresh token in either capability
    chk("openai capability has NO refresh key", assert_no_refresh_leak(co))
    chk("anthropic capability has NO refresh key", assert_no_refresh_leak(cl))
    chk("no refresh value present in openai cap", "REFRESH_long" not in json.dumps(co))
    chk("no refresh value present in anthropic cap", "REFRESH_long" not in json.dumps(cl))
    # leak detector actually fires (non-vacuous)
    chk("leak detector fires on a refresh_token key (non-vacuous)",
        raises(AssertionError, lambda: assert_no_refresh_leak({"access_token": "a", "refresh_token": "R"})))
    chk("cred_relpath openai", cred_relpath("openai") == ".codex/auth.json")
    chk("cred_relpath anthropic", cred_relpath("anthropic") == ".claude/.credentials.json")

    # ---- live proof paths, mocked I/O over real credential files in a throwaway HOME ------------
    expired = {"claudeAiOauth": {"accessToken": "OLD_ACCESS", "refreshToken": "REFRESH_long",
                                 "expiresAt": (now - 60) * 1000}}  # ms, already past

    # anthropic: an EXPIRED token must be minted anew via the refresh-token exchange, the rotated
    # credential persisted + re-read from the isolated HOME, and the NEW token validated + returned.
    with tempfile.TemporaryDirectory() as home:
        _write_isolated("anthropic", expired, home)
        posts = []
        def post_mint(url, payload):
            posts.append((url, payload))
            return {"access_token": "NEW_ACCESS", "refresh_token": "REFRESH_rotated",
                    "expires_in": 28800}
        ok_live, refreshed = refresh_via_cli("anthropic", home, http_post=post_mint,
                                             http_get=lambda u, h: 200, now=now)
        cap_live = refresh_ok("anthropic", ok_live, refreshed, now=now)
        chk("anthropic expired token triggers exactly one refresh exchange",
            len(posts) == 1 and posts[0][0] == ANTHROPIC_TOKEN_URL)
        chk("anthropic exchange is a refresh_token grant with the stored refresh token",
            posts and posts[0][1].get("grant_type") == "refresh_token"
            and posts[0][1].get("refresh_token") == "REFRESH_long")
        chk("anthropic capability is the NEWLY minted token, not the expired one",
            ok_live is True and cap_live["access_token"] == "NEW_ACCESS")
        chk("anthropic minted expiry derives from expires_in, not the stale expiresAt",
            cap_live["expires_at"] == (now + 28800) * 1000)
        with open(os.path.join(home, cred_relpath("anthropic"))) as f:
            on_disk = json.load(f)["claudeAiOauth"]
        chk("rotated credential (access + refresh) persisted into the isolated HOME",
            on_disk["accessToken"] == "NEW_ACCESS" and on_disk["refreshToken"] == "REFRESH_rotated")
        chk("minted anthropic capability carries no refresh secret",
            assert_no_refresh_leak(cap_live) and "REFRESH" not in json.dumps(cap_live))

    # anthropic negatives: a 200 profile can NEVER stand in for a failed mint, and a minted token
    # that fails profile validation is rejected.
    with tempfile.TemporaryDirectory() as home:
        _write_isolated("anthropic", expired, home)
        ok_neg, cred_neg = _prove_anthropic(home, http_post=lambda u, p: None,
                                            http_get=lambda u, h: 200, now=now)
        chk("failed exchange fails closed even though the profile op would return 200 (non-vacuous)",
            ok_neg is False and cred_neg["claudeAiOauth"]["accessToken"] == "OLD_ACCESS")
        chk("refresh_ok refuses the failed anthropic mint",
            raises(RuntimeError, lambda: refresh_ok("anthropic", ok_neg, cred_neg, now=now)))
        ok_m401, _ = _prove_anthropic(home, http_post=post_mint,
                                      http_get=lambda u, h: 401, now=now)
        chk("a minted token that fails profile validation is rejected", ok_m401 is False)
        # A "successful" mint whose lifetime cannot cover a worker job is rejected BEFORE it is
        # persisted or profile-checked — zero, negative, below-margin, and non-finite expires_in.
        for label, bad_in in (("zero", 0), ("negative", -300),
                              ("below-margin", ANTHROPIC_REFRESH_SKEW_S - 1), ("inf", float("inf"))):
            _write_isolated("anthropic", expired, home)  # the ok_m401 mint above rotated the file
            ok_bad_in, cred_bad_in = _prove_anthropic(
                home, http_post=lambda u, p, e=bad_in: {"access_token": "SHORT", "expires_in": e},
                http_get=lambda u, h: 200, now=now)
            chk(f"minted token with {label} expires_in is rejected and never persisted (non-vacuous)",
                ok_bad_in is False
                and cred_bad_in["claudeAiOauth"]["accessToken"] == "OLD_ACCESS")

    # anthropic: a still-fresh token validates WITHOUT a needless refresh-token rotation, a 401
    # fails closed, and a credential with no refresh token cannot mint at all.
    with tempfile.TemporaryDirectory() as home:
        fresh = {"claudeAiOauth": {"accessToken": "LIVE_ACCESS", "refreshToken": "REFRESH_long",
                                   "expiresAt": (now + ANTHROPIC_REFRESH_SKEW_S + 7200) * 1000}}
        _write_isolated("anthropic", fresh, home)
        posts2 = []
        def post_spy(url, payload):
            posts2.append(url)
            return None
        ok_fresh, cred_fresh = _prove_anthropic(home, http_post=post_spy,
                                                http_get=lambda u, h: 200, now=now)
        chk("fresh anthropic token validates with NO needless rotation",
            ok_fresh is True and not posts2
            and cred_fresh["claudeAiOauth"]["accessToken"] == "LIVE_ACCESS")
        ok_401, _ = _prove_anthropic(home, http_post=post_spy,
                                     http_get=lambda u, h: 401, now=now)
        chk("profile 401 on a fresh token fails closed", ok_401 is False)
        _write_isolated("anthropic", {"claudeAiOauth": {"accessToken": "X", "expiresAt": 1}}, home)
        ok_norefresh, _ = _prove_anthropic(home, http_post=post_spy,
                                           http_get=lambda u, h: 200, now=now)
        chk("credential without a refresh token cannot mint (fail closed)", ok_norefresh is False)

    # openai: the proof must RE-READ the credential the (mocked) CLI rewrote — the rotated access
    # token, not the stale one, is what refresh_ok returns; a failed status op is never accepted.
    with tempfile.TemporaryDirectory() as home:
        old_jwt, new_jwt = mk_jwt(1000), mk_jwt(2200000000)
        _write_isolated("openai", {"tokens": {"access_token": old_jwt,
                                              "refresh_token": "REFRESH_long"}}, home)
        seen = []
        def codex_refreshes(cmd, env=None, **kw):
            seen.append((tuple(cmd), env.get("HOME")))
            with open(os.path.join(env["HOME"], cred_relpath("openai")), "w") as f:
                json.dump({"tokens": {"access_token": new_jwt,
                                      "refresh_token": "REFRESH_rotated"}}, f)
            return subprocess.CompletedProcess(cmd, 0)
        ok_cli, cred_cli = refresh_via_cli("openai", home, run=codex_refreshes)
        cap_cli = refresh_ok("openai", ok_cli, cred_cli, now=now)
        chk("openai proof re-reads the CLI-rewritten credential (token actually rotated)",
            ok_cli is True and cap_cli["access_token"] == new_jwt
            and cap_cli["expires_at"] == 2200000000)
        chk("openai proof runs `codex login status` against the isolated HOME",
            seen == [(("codex", "login", "status"), home)])
        ok_bad, cred_bad = _prove_openai(
            home, run=lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1))
        chk("openai failed status op is never accepted (non-vacuous)",
            ok_bad is False
            and raises(RuntimeError, lambda: refresh_ok("openai", ok_bad, cred_bad, now=now)))
        # THE critical negative: `codex login status` exits 0 but does NOT rotate the expired token
        # on disk. The status op is then "successful", yet the re-read credential is still expired —
        # refresh_ok must refuse to attest it as a fresh worker capability.
        _write_isolated("openai", {"tokens": {"access_token": old_jwt,
                                              "refresh_token": "REFRESH_long"}}, home)
        ok_noop, cred_noop = _prove_openai(
            home, run=lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0))  # exit 0, no rewrite
        chk("openai status 0 leaving an EXPIRED token unchanged is rejected (non-vacuous)",
            ok_noop is True  # the op itself reported success — the expiry gate must catch it
            and cred_noop["tokens"]["access_token"] == old_jwt
            and raises(ValueError, lambda: refresh_ok("openai", ok_noop, cred_noop, now=now)))

    print("broker-refresh self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--provider", choices=PROVIDERS)
    ap.add_argument("--cred-file", help="path to the stored credential JSON (registry Actions only)")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()
    if args.provider and args.cred_file:
        with open(args.cred_file) as f:
            cred = json.load(f)
        cap = broker(args.provider, cred)
        print(json.dumps(cap))  # access token + expiry only; refresh token never emitted
        return 0
    print("broker-refresh: pure extraction + isolation ready; live refresh runs in registry Actions "
          "against an account secret. See --self-test.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
