#!/usr/bin/env python3
# [OPUS-4.8] Token broker refresh core (maintainer decision 2026-07-15: private broker, and it must
# NEVER require re-authenticating sessions). The broker lives ONLY in this private registry; the
# public worker receives a SHORT-LIVED ACCESS TOKEN and never the long-lived refresh token.
#
# Design (why this satisfies both constraints):
#   * Each account's stored credential carries a long-lived REFRESH token
#       - openai/codex  : ~/.codex/auth.json         -> tokens.{access_token,refresh_token,id_token}
#       - anthropic     : ~/.claude/.credentials.json -> claudeAiOauth.{accessToken,refreshToken,expiresAt}
#   * On a worker request the broker (a) materializes the credential into an ISOLATED $HOME (never the
#     maintainer's live ~/.codex / ~/.claude), (b) runs the provider's documented, authenticated,
#     NON-INFERENCE op — codex `login status` (refreshes the token from the refresh token) / the
#     Anthropic OAuth `/api/oauth/profile` check — and REQUIRES it to succeed before re-reading the
#     credential, so a stale/unproven credential can never be reported as a fresh one; then (c)
#     extracts ONLY {access_token, expires_at} — openai expiry derived from the access token's own
#     `exp` claim, NOT `last_refresh` — and returns that. The refresh token stays inside the registry.
#     The maintainer never re-authenticates: the refresh token is valid until explicitly revoked, and
#     the CLI auto-refreshes the short-lived access token on demand.
#
# This module ships the PURE, security-critical parts (isolation + access-token-only extraction) with
# unit tests over the real credential layouts. The live CLI refresh (refresh_via_cli) is the mechanism
# run in the registry's own Actions against an account secret — NOT exercised by --self-test, so this
# never touches or rotates the maintainer's active login.
"""broker-refresh — mint a short-lived worker access token from a stored refresh credential.

The security invariant, asserted by --self-test: the returned capability NEVER contains the refresh
token (or any key whose name implies a refresh/long-lived secret)."""
import argparse
import base64
import json
import os
import stat
import subprocess
import sys
import tempfile
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


def _prove_openai(home):
    """Run codex's documented, authenticated, NON-INFERENCE status op so the CLI validates/refreshes
    the access token from its refresh token, then re-read the (possibly rewritten) credential.
    Returns (ok, cred): ok is a clean exit 0 (`codex whoami` was never a subcommand and could stall on
    an interactive prompt; `codex login status` is the real status command)."""
    env = dict(os.environ, HOME=home)
    proc = subprocess.run(["codex", "login", "status"], env=env,
                          capture_output=True, text=True, timeout=60)
    with open(os.path.join(home, cred_relpath("openai"))) as f:
        return proc.returncode == 0, json.load(f)


def _prove_anthropic(home):
    """Prove the anthropic access token is live via the documented, non-inference OAuth profile endpoint
    (the same op account-whoami trusts; a subscription OAuth token reads it, `claude --version` proves
    nothing). Returns (ok, cred): ok is HTTP 200. The credential already carries a real `expiresAt`, so
    it is returned unchanged. The token travels only in the Authorization header — never logged."""
    with open(os.path.join(home, cred_relpath("anthropic"))) as f:
        cred = json.load(f)
    token = cred.get("claudeAiOauth", {}).get("accessToken")
    if not token:
        return False, cred
    req = urllib.request.Request(ANTHROPIC_PROFILE_URL, method="GET", headers={
        "Authorization": f"Bearer {token}", "anthropic-version": "2023-06-01"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (hard-coded https host)
            return resp.status == 200, cred
    except urllib.error.URLError:
        return False, cred


def refresh_via_cli(provider, home):
    """Trigger the provider's documented refresh/validation op (with HOME=`home`), then re-read the
    credential. Returns (ok, cred). The provider owns the OAuth endpoints. Registry-Actions only."""
    prove = {"openai": _prove_openai, "anthropic": _prove_anthropic}[provider]
    return prove(home)


def refresh_ok(provider, ok, refreshed):
    """Fail-closed gate over a refresh attempt: the op must have succeeded (ok) AND the re-read
    credential must yield a usable capability — an access token (extract raises otherwise) and, for
    openai, a real derived expiry. Returns the validated capability; raises on any failure so a stale
    or unproven credential is NEVER re-read and reported as success."""
    if not ok:
        raise RuntimeError(f"{provider} refresh op did not succeed; credential not proven refreshed")
    cap = extract_access_token(provider, refreshed)
    if provider == "openai" and cap["expires_at"] is None:
        raise ValueError("openai access token carries no readable `exp` claim; expiry unattestable")
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
    # refresh gate: a failed op or an openai token with no derivable expiry is NEVER reported success
    chk("refresh_ok passes a proven openai refresh", refresh_ok("openai", True, codex) == co)
    chk("refresh_ok passes a proven anthropic refresh", refresh_ok("anthropic", True, claude) == cl)
    chk("refresh_ok rejects a failed op (non-vacuous)",
        raises(RuntimeError, lambda: refresh_ok("openai", False, codex)))
    chk("refresh_ok rejects openai token with no exp (non-vacuous)",
        raises(ValueError, lambda: refresh_ok(
            "openai", True, {"tokens": {"access_token": "opaque-not-a-jwt"}})))
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
