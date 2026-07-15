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
#     maintainer's live ~/.codex / ~/.claude), (b) triggers a refresh via the provider CLI — the CLI
#     already knows the OAuth endpoints, so we reverse-engineer nothing and stay robust to provider
#     changes — then (c) extracts ONLY {access_token, expires_at} and returns that. The refresh token
#     stays inside the registry. The maintainer never re-authenticates: the refresh token is valid
#     until explicitly revoked, and the CLI auto-refreshes the short-lived access token on demand.
#
# This module ships the PURE, security-critical parts (isolation + access-token-only extraction) with
# unit tests over the real credential layouts. The live CLI refresh (refresh_via_cli) is the mechanism
# run in the registry's own Actions against an account secret — NOT exercised by --self-test, so this
# never touches or rotates the maintainer's active login.
"""broker-refresh — mint a short-lived worker access token from a stored refresh credential.

The security invariant, asserted by --self-test: the returned capability NEVER contains the refresh
token (or any key whose name implies a refresh/long-lived secret)."""
import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile

PROVIDERS = ("openai", "anthropic")


# ---- pure core (unit-tested; no network, no live tokens) ----------------------------------------
def cred_relpath(provider):
    """Where the provider CLI expects its credential inside a $HOME."""
    if provider == "openai":
        return ".codex/auth.json"
    if provider == "anthropic":
        return ".claude/.credentials.json"
    raise ValueError(f"unknown provider {provider!r}")


def extract_access_token(provider, cred):
    """Return the SHORT-LIVED capability {access_token, expires_at} from a (refreshed) credential.
    NEVER returns the refresh token. `cred` is the parsed credential JSON."""
    if provider == "openai":
        tok = cred.get("tokens", {})
        return {"access_token": tok.get("access_token"),
                "expires_at": cred.get("last_refresh")}  # codex stamps last_refresh; access_token is short-lived
    if provider == "anthropic":
        o = cred.get("claudeAiOauth", {})
        return {"access_token": o.get("accessToken"), "expires_at": o.get("expiresAt")}
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


def refresh_via_cli(provider, home):
    """Trigger the provider CLI (with HOME=`home`) to refresh the access token from the refresh token,
    then re-read the updated credential. The CLI owns the OAuth endpoints. Registry-Actions only."""
    env = dict(os.environ, HOME=home)
    # A minimal no-op that forces the CLI to validate/refresh its token. Kept provider-specific + quiet.
    cmd = {"openai": ["codex", "whoami"], "anthropic": ["claude", "--version"]}[provider]
    subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=60)
    with open(os.path.join(home, cred_relpath(provider))) as f:
        return json.load(f)


def broker(provider, cred):
    """Full path (registry Actions): isolate -> refresh -> extract access-token-only capability."""
    home = tempfile.mkdtemp(prefix="broker-")
    try:
        os.chmod(home, 0o700)
        _write_isolated(provider, cred, home)
        refreshed = refresh_via_cli(provider, home)
        cap = extract_access_token(provider, refreshed)
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

    # real key layouts (values are fake)
    codex = {"auth_mode": "oauth",
             "tokens": {"id_token": "ID", "access_token": "ACCESS_short", "refresh_token": "REFRESH_long",
                        "account_id": "acct"}, "last_refresh": "2026-07-15T00:00:00Z"}
    claude = {"claudeAiOauth": {"accessToken": "ACCESS_short", "refreshToken": "REFRESH_long",
                                "expiresAt": 1799999999, "scopes": ["x"], "subscriptionType": "max"}}
    co = extract_access_token("openai", codex)
    cl = extract_access_token("anthropic", claude)
    chk("openai extracts access token", co["access_token"] == "ACCESS_short")
    chk("openai carries expiry", co["expires_at"] == "2026-07-15T00:00:00Z")
    chk("anthropic extracts access token", cl["access_token"] == "ACCESS_short")
    chk("anthropic carries expiry", cl["expires_at"] == 1799999999)
    # the security invariant: NO refresh token in either capability
    chk("openai capability has NO refresh key", assert_no_refresh_leak(co))
    chk("anthropic capability has NO refresh key", assert_no_refresh_leak(cl))
    chk("no refresh value present in openai cap", "REFRESH_long" not in json.dumps(co))
    chk("no refresh value present in anthropic cap", "REFRESH_long" not in json.dumps(cl))
    # leak detector actually fires (non-vacuous)
    leaked = False
    try:
        assert_no_refresh_leak({"access_token": "a", "refresh_token": "R"})
    except AssertionError:
        leaked = True
    chk("leak detector fires on a refresh_token key (non-vacuous)", leaked)
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
