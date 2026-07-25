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
# The refresh must be PROVEN, never assumed (#574). Three things were previously taken on faith and
# are now checked, each fail-closed:
#   1. The probe command is a documented, AUTHENTICATED, non-inference provider operation that loads
#      the stored OAuth credential (`codex login status` / `claude auth status --json`). The former
#      probes (`codex whoami`, `claude --version`) authenticated nothing, so a dead credential
#      looked healthy.
#   2. The probe's EXIT STATUS is a hard gate, and the credential must have actually MOVED — a
#      byte-identical credential means no refresh happened, so no capability is minted. To make that
#      signal meaningful the isolated COPY is backdated (force_stale) before the probe, which asks
#      the CLI to refresh now instead of only when it feels like it. Only the copy is backdated; the
#      stored credential and its refresh token are untouched, so no re-authentication is ever needed.
#   3. The reported expiry is a REAL token expiry: openai's comes from the access token's own `exp`
#      claim, never from `last_refresh` (a stamp of when a refresh last happened, which advertised
#      long-dead tokens as valid); anthropic's stays `claudeAiOauth.expiresAt`.
#
# This module ships the PURE, security-critical parts (isolation + access-token-only extraction +
# the refresh proof) with unit tests over the real credential layouts. --self-test drives
# refresh_via_cli/broker through an INJECTED runner that spawns nothing, so the suite stays hermetic
# and never touches, rotates or invalidates the maintainer's active login.
"""broker-refresh — mint a short-lived worker access token from a stored refresh credential.

The security invariant, asserted by --self-test: the returned capability NEVER contains the refresh
token (or any key whose name implies a refresh/long-lived secret)."""
import argparse
import base64
import copy
import datetime
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


def jwt_exp(access_token):
    """Return the `exp` (expiry) claim, in epoch seconds, from a JWT access token's payload.

    The signature is deliberately NOT verified: the issuer's key is not available to the registry,
    and this value authorizes nothing — it is a self-reported expiry used only to tell a worker (and
    the scheduler) when the token dies. Anything unreadable RAISES: a wrong expiry is worse than no
    capability at all, because it advertises a dead token as live (#574). The token value itself is
    never included in an error message."""
    if not isinstance(access_token, str):
        raise ValueError("access token is not a string, so no `exp` claim can be read")
    parts = access_token.split(".")
    if len(parts) != 3:
        raise ValueError("access token is not a JWT, so no `exp` claim can be read")
    payload = parts[1]
    try:  # base64url, unpadded as JWT requires; binascii.Error/JSONDecodeError are both ValueError
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except ValueError as exc:
        raise ValueError(f"access token payload is not readable base64url JSON: {type(exc).__name__}") from exc
    if not isinstance(claims, dict):
        raise ValueError("access token payload is not a JSON object")
    exp = claims.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)) or exp <= 0:
        raise ValueError("access token carries no usable `exp` claim")
    return int(exp)


def _iso_utc(epoch_seconds):
    """Epoch seconds -> the RFC3339-Z string shape the capability has always used for openai."""
    return datetime.datetime.fromtimestamp(epoch_seconds, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _require(provider, value, what, kinds):
    """Fail closed on a missing/empty/wrong-typed credential field. Never echoes the value."""
    if isinstance(value, bool) or not isinstance(value, kinds) or (isinstance(value, str) and not value.strip()):
        raise ValueError(f"{provider} credential has no usable {what}; refusing to mint a capability")
    return value


def extract_access_token(provider, cred):
    """Return the SHORT-LIVED capability {access_token, expires_at} from a (refreshed) credential.
    NEVER returns the refresh token. `cred` is the parsed credential JSON. Raises (fail closed)
    rather than returning a capability with a missing token or an expiry that is not a real token
    expiry — both were previously emitted silently and handed to a worker (#574)."""
    if provider == "openai":
        tok = cred.get("tokens") if isinstance(cred.get("tokens"), dict) else {}
        access = _require(provider, tok.get("access_token"), "access token", str)
        # NOT last_refresh: that stamps when a refresh last HAPPENED, not when this token dies. The
        # only expiry codex actually stores for the access token is the `exp` claim inside it.
        return {"access_token": access, "expires_at": _iso_utc(jwt_exp(access))}
    if provider == "anthropic":
        o = cred.get("claudeAiOauth") if isinstance(cred.get("claudeAiOauth"), dict) else {}
        access = _require(provider, o.get("accessToken"), "access token", str)
        # claudeAiOauth.expiresAt is a real token expiry already; only its presence needed checking.
        return {"access_token": access,
                "expires_at": _require(provider, o.get("expiresAt"), "token expiry", (int, float))}
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


# ---- refresh proof (pure; unit-tested) ----------------------------------------------------------
# A documented, AUTHENTICATED, non-inference operation per provider. Both subcommands load the
# stored OAuth credential and let the CLI refresh it through the provider's own token endpoint, so
# the registry still reverse-engineers no OAuth endpoint; neither runs a model, so probing costs no
# quota and cannot be billed as usage. The previous probes were not this: `claude --version` prints
# a version string and touches no credential, and `codex whoami` is not a codex subcommand — so a
# revoked or expired credential probed "fine" and was handed to a worker (#574).
REFRESH_PROBE = {
    "openai": ("codex", "login", "status"),
    "anthropic": ("claude", "auth", "status", "--json"),
}


def refresh_probe_cmd(provider):
    """The provider's refresh probe as a fresh argv list."""
    if provider not in REFRESH_PROBE:
        raise ValueError(f"unknown provider {provider!r}")
    return list(REFRESH_PROBE[provider])


_STALE_ISO = "1970-01-01T00:00:00Z"


def force_stale(provider, cred):
    """Return a COPY of `cred` marked already-expired, so the probe must refresh instead of deciding
    the token is still good enough. This is what makes "the credential did not move => no refresh
    happened" a sound test rather than a false alarm on a still-valid token.

    Only the expiry stamp moves: the REFRESH token is copied through untouched, so the CLI can still
    refresh and the maintainer never re-authenticates. The caller's dict is not mutated, and this
    only ever reaches the isolated $HOME copy — the stored account secret is never rewritten."""
    stale = copy.deepcopy(cred)
    if provider == "openai":
        stale["last_refresh"] = _STALE_ISO  # codex refreshes off this stamp
        return stale
    if provider == "anthropic":
        oauth = stale.get("claudeAiOauth")
        if isinstance(oauth, dict):
            oauth["expiresAt"] = 0
        return stale
    raise ValueError(f"unknown provider {provider!r}")


def _refresh_fingerprint(provider, cred):
    """(access token, refresh/expiry stamp) as STORED — the two fields a real refresh moves.
    `last_refresh` is the wrong field for reporting expiry but exactly the right one for "did a
    refresh happen", which is all it is used for here."""
    if provider == "openai":
        tok = cred.get("tokens") if isinstance(cred.get("tokens"), dict) else {}
        return tok.get("access_token"), cred.get("last_refresh")
    if provider == "anthropic":
        oauth = cred.get("claudeAiOauth") if isinstance(cred.get("claudeAiOauth"), dict) else {}
        return oauth.get("accessToken"), oauth.get("expiresAt")
    raise ValueError(f"unknown provider {provider!r}")


def _expiry_advanced(after, before):
    """True only when `after` is UNAMBIGUOUSLY later than `before` — unknown/mixed shapes are not
    proof, so they fail closed."""
    if isinstance(after, bool) or isinstance(before, bool):
        return False
    if isinstance(after, (int, float)) and isinstance(before, (int, float)):
        return after > before
    if isinstance(after, str) and isinstance(before, str):
        return after > before  # both providers stamp RFC3339-Z, which sorts lexicographically
    return False


def assert_refresh_happened(provider, before, after):
    """Fail closed unless the credential actually moved: a new access token, or an advanced expiry.
    An unchanged credential means the probe refreshed nothing, and re-reading the stale credential
    and calling it "refreshed" is exactly how a dead token reached a worker (#574)."""
    before_token, before_exp = _refresh_fingerprint(provider, before)
    after_token, after_exp = _refresh_fingerprint(provider, after)
    if isinstance(after_token, str) and after_token and after_token != before_token:
        return True
    if _expiry_advanced(after_exp, before_exp):
        return True
    raise AssertionError(f"{provider} refresh produced no new access token and no advanced expiry: "
                         "the CLI did not refresh the credential, so it must not reach a worker")


# ---- isolation + live refresh (registry Actions only; probed via an injected runner in --self-test)
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


def refresh_via_cli(provider, home, runner=subprocess.run):
    """Run the provider's refresh probe (with HOME=`home`) so the CLI refreshes the access token from
    the refresh token, then re-read the credential it left behind. The CLI owns the OAuth endpoints.

    Raises rather than returning a credential when the probe exits non-zero, times out, or leaves the
    credential unmoved. `runner` is injected only so --self-test can exercise both failure modes
    without spawning a provider CLI; the live path always uses subprocess.run. Registry-Actions only."""
    cred_path = os.path.join(home, cred_relpath(provider))
    with open(cred_path) as f:
        before = json.load(f)
    env = dict(os.environ, HOME=home)
    cmd = refresh_probe_cmd(provider)
    proc = runner(cmd, env=env, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        # Report the status only. The probe's stdout/stderr describes the signed-in account and can
        # quote credential material, so it must never reach a log or an exception message.
        raise RuntimeError(f"{provider} refresh probe {' '.join(cmd)!r} exited {proc.returncode}; "
                           "refusing to mint a capability from an unrefreshed credential")
    with open(cred_path) as f:
        after = json.load(f)
    assert_refresh_happened(provider, before, after)
    return after


def broker(provider, cred, runner=subprocess.run):
    """Full path (registry Actions): isolate -> force stale -> refresh (proven) -> extract the
    access-token-only capability. Every step fails closed; nothing is returned unless the provider
    CLI demonstrably refreshed the credential and the resulting token reports a real expiry."""
    home = tempfile.mkdtemp(prefix="broker-")
    try:
        os.chmod(home, 0o700)
        _write_isolated(provider, force_stale(provider, cred), home)
        refreshed = refresh_via_cli(provider, home, runner=runner)
        cap = extract_access_token(provider, refreshed)
        assert_no_refresh_leak(cap)
        return cap
    finally:
        subprocess.run(["rm", "-rf", home], check=False)


def write_capability(cap, path):
    """Persist the short-lived capability to a caller-supplied file at mode 0600.
    The capability carries the access token, so it must go to a PRIVATE file — NEVER stdout (in
    Actions or ordinary automation stdout becomes a log entry, breaking the token-never-printed
    invariant), and NEVER through a pre-existing permissive file or a symlink planted at `path`.

    Opening the destination directly with O_CREAT|O_TRUNC would (a) truncate+write the token into an
    already-existing mode-0644 file and only narrow the mode AFTERWARD — a window in which the secret
    is group/world readable — and (b) follow a symlink at `path`, redirecting the token into another
    file. Instead we stage the bytes into a fresh mode-0600 temp file in the SAME directory
    (tempfile.mkstemp => O_CREAT|O_EXCL, 0600), fsync, then os.replace() atomically into place: the
    secret only ever lands in a brand-new 0600 inode, and rename REPLACES a symlink at `path` rather
    than following it and writing the token into some other file. Returns the path."""
    dest_dir = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".broker-cap.", dir=dest_dir)  # mkstemp guarantees mode 0600
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(cap, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)  # atomic; overwrites a symlink at `path`, never follows it
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def emit_live_capability(cap, out_file):
    """Live path (registry Actions): write the capability to a mode-0600 `out_file` and return a
    human-facing confirmation that carries NO token. Fail closed if no destination is supplied —
    never fall back to printing the capability to stdout."""
    if not out_file:
        raise ValueError("refusing to emit a live capability without --out-file "
                         "(the access token must never be printed to stdout)")
    write_capability(cap, out_file)
    return f"broker-refresh: wrote capability to {out_file} (mode 0600); access token not printed"


# ---- self-test (mocked; never touches a live login) ---------------------------------------------
def _self_test():
    ok = True

    def chk(n, cond):
        nonlocal ok
        ok = ok and cond
        print(f"  {'ok  ' if cond else 'FAIL'} {n}")

    def raises(fn, exc, because=None):
        """True iff `fn()` fails closed with `exc` (a returned value is a FAILURE, not a pass).
        `because` pins WHICH check fired, so a test cannot be satisfied by an unrelated later
        failure — e.g. the missing-token check must fire on its own, not via the expiry decode."""
        try:
            fn()
        except exc as err:
            return because is None or because in str(err)
        return False

    def _jwt(claims):
        """A syntactically real (unsigned) JWT — the shape codex stores as its access token."""
        def seg(obj):
            return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
        return f"{seg({'alg': 'none', 'typ': 'JWT'})}.{seg(claims)}.sig"

    OLD_JWT = _jwt({"sub": "acct", "exp": 1799999999})  # 2027-01-15T07:59:59Z
    NEW_JWT = _jwt({"sub": "acct", "exp": 1800000600})  # 2027-01-15T08:10:00Z

    # real key layouts (values are fake)
    codex = {"auth_mode": "oauth",
             "tokens": {"id_token": "ID", "access_token": OLD_JWT, "refresh_token": "REFRESH_long",
                        "account_id": "acct"}, "last_refresh": "2026-07-15T00:00:00Z"}
    claude = {"claudeAiOauth": {"accessToken": "ACCESS_short", "refreshToken": "REFRESH_long",
                                "expiresAt": 1799999999, "scopes": ["x"], "subscriptionType": "max"}}
    co = extract_access_token("openai", codex)
    cl = extract_access_token("anthropic", claude)
    chk("openai extracts access token", co["access_token"] == OLD_JWT)
    # #574: the expiry is the TOKEN's own exp claim, never the last_refresh stamp
    chk("openai expiry comes from the token's exp claim", co["expires_at"] == "2027-01-15T07:59:59Z")
    chk("openai expiry is NOT the last_refresh stamp", co["expires_at"] != codex["last_refresh"])
    chk("anthropic extracts access token", cl["access_token"] == "ACCESS_short")
    chk("anthropic carries expiry", cl["expires_at"] == 1799999999)
    chk("capability carries access token + expiry ONLY",
        set(co) == {"access_token", "expires_at"} and set(cl) == set(co))
    # a capability is never minted from a credential with no usable token / no readable expiry
    NO_TOKEN = "no usable access token"
    chk("openai missing access token -> raise",
        raises(lambda: extract_access_token("openai", {"tokens": {}, "last_refresh": "x"}),
               ValueError, NO_TOKEN))
    chk("openai empty access token -> raise",
        raises(lambda: extract_access_token("openai", {"tokens": {"access_token": "  "}}), ValueError, NO_TOKEN))
    chk("openai non-string access token -> raise",
        raises(lambda: extract_access_token("openai", {"tokens": {"access_token": 12345}}),
               ValueError, NO_TOKEN))
    chk("openai malformed `tokens` -> raise",
        raises(lambda: extract_access_token("openai", {"tokens": "nope"}), ValueError, NO_TOKEN))
    chk("openai non-JWT access token -> raise (expiry unreadable)",
        raises(lambda: extract_access_token("openai", {"tokens": {"access_token": "opaque-token"}}),
               ValueError, "not a JWT"))
    chk("openai JWT with no exp claim -> raise",
        raises(lambda: extract_access_token("openai", {"tokens": {"access_token": _jwt({"sub": "a"})}}),
               ValueError, "no usable `exp` claim"))
    chk("openai JWT with a non-numeric exp -> raise",
        raises(lambda: extract_access_token("openai", {"tokens": {"access_token": _jwt({"exp": "soon"})}}),
               ValueError, "no usable `exp` claim"))
    chk("openai JWT with an undecodable payload -> raise",
        raises(lambda: extract_access_token("openai", {"tokens": {"access_token": "aGVhZA.!!!.sig"}}),
               ValueError, "not readable base64url JSON"))
    chk("jwt_exp reads the claim", jwt_exp(NEW_JWT) == 1800000600)
    # a rejection must never quote the credential it rejected (it lands in an Actions log)
    chk("rejection message never echoes the token",
        raises(lambda: extract_access_token("openai", {"tokens": {"access_token": "SECRET-opaque"}}),
               ValueError, "not a JWT")
        and not raises(lambda: extract_access_token("openai", {"tokens": {"access_token": "SECRET-opaque"}}),
                       ValueError, "SECRET-opaque"))
    chk("anthropic missing access token -> raise",
        raises(lambda: extract_access_token("anthropic", {"claudeAiOauth": {"expiresAt": 1}}),
               ValueError, NO_TOKEN))
    chk("anthropic empty access token -> raise",
        raises(lambda: extract_access_token("anthropic", {"claudeAiOauth": {"accessToken": "", "expiresAt": 1}}),
               ValueError, NO_TOKEN))
    chk("anthropic missing expiry -> raise",
        raises(lambda: extract_access_token("anthropic", {"claudeAiOauth": {"accessToken": "A"}}),
               ValueError, "no usable token expiry"))
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

    # ---- #574: the refresh is PROVEN, never assumed. Hermetic: the injected runner SPAWNS NOTHING,
    # so no provider CLI runs and the maintainer's ~/.codex / ~/.claude are never read or rotated.
    class _Proc:
        def __init__(self, returncode):
            self.returncode, self.stdout, self.stderr = returncode, "", ""

    def fake_cli(provider, returncode, writes=None):
        """A subprocess.run stand-in. Records the argv it was handed and the credential the CLI
        would have seen, and optionally simulates the CLI rewriting it in the isolated HOME."""
        def run(cmd, env=None, capture_output=False, text=False, timeout=None):
            run.calls.append(cmd)
            with open(os.path.join(env["HOME"], cred_relpath(provider))) as fh:
                run.seen.append(json.load(fh))
            if writes is not None:
                _write_isolated(provider, writes, env["HOME"])
            return _Proc(returncode)
        run.calls, run.seen = [], []
        return run

    refreshed_codex = {"auth_mode": "oauth",
                       "tokens": {"id_token": "ID", "access_token": NEW_JWT,
                                  "refresh_token": "REFRESH_long", "account_id": "acct"},
                       "last_refresh": "2026-07-20T00:00:00Z"}
    refreshed_claude = {"claudeAiOauth": {"accessToken": "ACCESS_new", "refreshToken": "REFRESH_long",
                                          "expiresAt": 1800000600, "scopes": ["x"], "subscriptionType": "max"}}
    # the probe is a documented, authenticated, NON-INFERENCE command — not the old no-ops
    probes = [refresh_probe_cmd(p) for p in PROVIDERS]
    chk("openai probe is `codex login status`", probes[0] == ["codex", "login", "status"])
    chk("anthropic probe is `claude auth status --json`", probes[1] == ["claude", "auth", "status", "--json"])
    chk("no no-op probe survives (codex whoami / claude --version)",
        all("whoami" not in c and "--version" not in c for c in probes))
    chk("unknown provider has no probe", raises(lambda: refresh_probe_cmd("acme"), ValueError))
    # force_stale: expires the ISOLATED COPY only, and never drops the refresh token (no re-auth)
    stale_codex, stale_claude = force_stale("openai", codex), force_stale("anthropic", claude)
    chk("force_stale backdates the openai refresh stamp", stale_codex["last_refresh"] == _STALE_ISO)
    chk("force_stale expires the anthropic access token", stale_claude["claudeAiOauth"]["expiresAt"] == 0)
    chk("force_stale keeps the refresh token (never forces a re-login)",
        stale_codex["tokens"]["refresh_token"] == "REFRESH_long"
        and stale_claude["claudeAiOauth"]["refreshToken"] == "REFRESH_long")
    chk("force_stale does not mutate the caller's credential",
        codex["last_refresh"] == "2026-07-15T00:00:00Z"
        and claude["claudeAiOauth"]["expiresAt"] == 1799999999)
    chk("force_stale rejects an unknown provider", raises(lambda: force_stale("acme", {}), ValueError))
    # happy path: the CLI refreshed, so the capability carries the NEW token and ITS expiry
    ok_run = fake_cli("openai", 0, refreshed_codex)
    ocap = broker("openai", codex, runner=ok_run)
    chk("broker mints the refreshed openai token", ocap["access_token"] == NEW_JWT)
    chk("broker expiry tracks the refreshed token's exp", ocap["expires_at"] == "2027-01-15T08:10:00Z")
    chk("broker ran exactly the documented probe", ok_run.calls == [["codex", "login", "status"]])
    chk("broker hands the CLI a backdated copy so a refresh is forced",
        ok_run.seen[0]["last_refresh"] == _STALE_ISO
        and ok_run.seen[0]["tokens"]["refresh_token"] == "REFRESH_long")
    chk("refreshed capability still leaks no refresh secret",
        assert_no_refresh_leak(ocap) and "REFRESH_long" not in json.dumps(ocap))
    acap = broker("anthropic", claude, runner=fake_cli("anthropic", 0, refreshed_claude))
    chk("broker mints the refreshed anthropic token", acap["access_token"] == "ACCESS_new")
    chk("anthropic keeps reading claudeAiOauth.expiresAt", acap["expires_at"] == 1800000600)
    # a non-zero probe exit is a hard failure EVEN IF the credential was rewritten
    chk("openai non-zero probe exit -> no capability",
        raises(lambda: broker("openai", codex, runner=fake_cli("openai", 1, refreshed_codex)), RuntimeError))
    chk("anthropic non-zero probe exit -> no capability",
        raises(lambda: broker("anthropic", claude, runner=fake_cli("anthropic", 2, refreshed_claude)),
               RuntimeError))
    # exit 0 but an UNCHANGED credential means nothing was refreshed
    chk("openai unchanged credential -> no capability",
        raises(lambda: broker("openai", codex, runner=fake_cli("openai", 0)), AssertionError))
    chk("anthropic unchanged credential -> no capability",
        raises(lambda: broker("anthropic", claude, runner=fake_cli("anthropic", 0)), AssertionError))
    # a "refreshed" credential that carries no usable token/expiry still mints nothing
    chk("refreshed-but-empty openai token -> no capability",
        raises(lambda: broker("openai", codex, runner=fake_cli(
            "openai", 0, {"tokens": {"access_token": "", "refresh_token": "REFRESH_long"},
                          "last_refresh": "2026-07-20T00:00:00Z"})), ValueError, NO_TOKEN))
    chk("refreshed-but-opaque openai token -> no capability (expiry unreadable)",
        raises(lambda: broker("openai", codex, runner=fake_cli(
            "openai", 0, {"tokens": {"access_token": "opaque", "refresh_token": "REFRESH_long"},
                          "last_refresh": "2026-07-20T00:00:00Z"})), ValueError, "not a JWT"))
    chk("refreshed-but-empty anthropic token -> no capability",
        raises(lambda: broker("anthropic", claude, runner=fake_cli(
            "anthropic", 0, {"claudeAiOauth": {"accessToken": "", "refreshToken": "REFRESH_long",
                                               "expiresAt": 1800000600}})), ValueError, NO_TOKEN))
    # the proof primitive itself: only a new token or an advanced expiry counts
    chk("proof accepts a new access token",
        assert_refresh_happened("openai", codex, refreshed_codex))
    chk("proof accepts an advanced expiry alone",
        assert_refresh_happened("anthropic", claude,
                                {"claudeAiOauth": {**claude["claudeAiOauth"], "expiresAt": 1800000600}}))
    chk("proof rejects an identical credential",
        raises(lambda: assert_refresh_happened("openai", codex, codex), AssertionError))
    chk("proof rejects a REWOUND expiry",
        raises(lambda: assert_refresh_happened("anthropic", claude,
                                               {"claudeAiOauth": {**claude["claudeAiOauth"], "expiresAt": 1}}),
               AssertionError))
    # the live capability is written to a private file, NEVER printed (the #193 invariant)
    d = tempfile.mkdtemp(prefix="broker-selftest-")
    try:
        outp = os.path.join(d, "cap.json")
        msg = emit_live_capability(co, outp)
        mode = stat.S_IMODE(os.stat(outp).st_mode)
        chk("live capability file is mode 0600", mode == 0o600)
        with open(outp) as f:
            chk("live capability round-trips to file", json.load(f) == co)
        # confirmation is safe to log: it names the destination but carries no token value
        chk("confirmation carries no access token", "ACCESS_short" not in msg)
        # fail closed: no out_file => refuse, never emit the capability anywhere
        refused = False
        try:
            emit_live_capability(co, None)
        except ValueError:
            refused = True
        chk("live path refuses without an out_file (fail closed)", refused)
        # EXISTING PERMISSIVE destination: the token must NOT be written through the old 0644 inode.
        # A hardlink pins the pre-existing inode so we can read it back after the write; the atomic
        # replace lands the secret in a fresh 0600 inode, so the old (permissive) inode stays empty.
        exist = os.path.join(d, "existing.json")
        os.close(os.open(exist, os.O_WRONLY | os.O_CREAT, 0o644))
        os.chmod(exist, 0o644)
        pin = os.path.join(d, "pinned-old-inode")
        os.link(exist, pin)  # same inode as the pre-existing permissive file
        write_capability(co, exist)
        with open(pin) as f:
            chk("existing permissive inode never receives the token", "ACCESS_short" not in f.read())
        chk("existing-dest final file is mode 0600", stat.S_IMODE(os.stat(exist).st_mode) == 0o600)
        with open(exist) as f:
            chk("existing-dest final content is the capability", json.load(f) == co)
        # SYMLINK destination: the token must NOT be redirected through the link into another file.
        victim = os.path.join(d, "victim.json")
        with open(victim, "w") as f:
            f.write("PREEXISTING")
        os.chmod(victim, 0o644)
        link = os.path.join(d, "link.json")
        os.symlink(victim, link)
        write_capability(co, link)
        with open(victim) as f:
            vbytes = f.read()
        chk("symlink target is not overwritten with the token", "ACCESS_short" not in vbytes)
        chk("symlink target retains its original content", vbytes == "PREEXISTING")
        chk("symlink dest replaced by a real (non-symlink) file", not os.path.islink(link))
        chk("symlink-dest final file is mode 0600", stat.S_IMODE(os.lstat(link).st_mode) == 0o600)
        with open(link) as f:
            chk("symlink-dest final content is the capability", json.load(f) == co)
    finally:
        subprocess.run(["rm", "-rf", d], check=False)
    print("broker-refresh self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--provider", choices=PROVIDERS)
    ap.add_argument("--cred-file", help="path to the stored credential JSON (registry Actions only)")
    ap.add_argument("--out-file", help="write the short-lived capability here at mode 0600 (REQUIRED "
                    "for the live path; the access token is never printed to stdout)")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()
    if args.provider and args.cred_file:
        if not args.out_file:
            print("broker-refresh: refusing to emit a live capability without --out-file "
                  "(the access token must never be printed to stdout)", file=sys.stderr)
            return 2
        with open(args.cred_file) as f:
            cred = json.load(f)
        cap = broker(args.provider, cred)
        print(emit_live_capability(cap, args.out_file))  # a path, never the token itself
        return 0
    print("broker-refresh: pure extraction + isolation ready; live refresh runs in registry Actions "
          "against an account secret. See --self-test.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
