#!/usr/bin/env python3
# Token broker refresh core (maintainer decision 2026-07-15: private broker, and it must
# NEVER require re-authenticating sessions). "Private" scopes the CREDENTIAL, not the repo: this
# registry is PUBLIC (README line 1) and holds no token values, so the refresh token lives only in
# an encrypted registry secret that only the registry's own Actions can read; the worker receives a
# SHORT-LIVED ACCESS TOKEN and never the long-lived refresh token.
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
import base64
import datetime
import http.client
import importlib.util
import json
import os
import re
import stat
import subprocess
import socket
import ssl
import sys
import tempfile
import urllib.parse

PROVIDERS = ("openai", "anthropic")

# Shared bounded-retry MECHANICS only (registry #563 item 4): the exponential-with-jitter ceiling
# and the sleep helper. The domain classifier below stays here, exactly as gh_retry's module
# docstring prescribes ("callers KEEP their own domain error-classification predicates"). No new
# retry stack is invented for this path.
_gh_retry_spec = importlib.util.spec_from_file_location(
    "registry_gh_retry", os.path.join(os.path.dirname(os.path.abspath(__file__)), "gh_retry.py"))
if _gh_retry_spec is None or _gh_retry_spec.loader is None:
    raise RuntimeError("cannot load shared bounded-retry mechanics")
gh_retry = importlib.util.module_from_spec(_gh_retry_spec)
_gh_retry_spec.loader.exec_module(gh_retry)


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


def _refresh_token_key(key):
    """Whether a key NAMES a refresh token, in any of the casings/separators the two provider
    layouts use (`refresh_token`, `refreshToken`, `REFRESH-TOKEN`). Deliberately narrower than
    `_REFRESH_HINTS`: a credential legitimately carries a `last_refresh` TIMESTAMP, which is not
    secret material and must not trip the guard."""
    normalized = "".join(char for char in str(key).lower() if char.isalnum())
    return "refreshtoken" in normalized or "refreshsecret" in normalized


def assert_no_refresh_material(document, refresh_token):
    """Fail closed on BOTH leak channels for a credential that is about to be handed to the model
    container: a refresh-shaped KEY carrying a value (`assert_no_refresh_leak`'s check, but here the
    empty-string CLI placeholder is permitted — see `minimal_worker_credential`), and the literal
    refresh-token VALUE appearing anywhere in the serialized document under any key name.

    The value check is what makes the guard non-vacuous: a regression that renames the field, nests
    it, or copies the refresh token into `access_token` still turns this red."""
    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if _refresh_token_key(key) and value not in ("", None):
                    raise AssertionError(
                        f"refresh secret leaked into the worker credential via key {key!r}")
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
    walk(document)
    if refresh_token:
        # Serialized-form check: catches the value under ANY key name, at any depth.
        if str(refresh_token) in json.dumps(document):
            raise AssertionError("refresh-token VALUE is present in the worker credential")
    return True


# ---- host-side pre-flight refresh (P0: registry issue #596) -------------------------------------
# WHY this exists: the selected account credential is bind-mounted READ-ONLY into the model
# container (issue #134, and that control is correct). A subscription-CLI credential holds a
# SHORT-LIVED access token that the CLI refreshes IN PLACE — which the read-only mount forbids
# (reproduced: `codex_login::auth::manager: Failed to refresh token: Read-only file system (os error
# 30)`). The stored ACCTNN_TOKEN secret is a point-in-time snapshot, so once its access token
# expires EVERY run dies seconds in, and `write_back`'s "did the mounted file change?" rotation
# trigger can never fire (the mount makes change impossible). Deterministic permanent outage.
#
# The fix: refresh on the HOST, before the container starts, and materialize a MINIMAL credential
# for the mount that carries a fresh access token and NO refresh token. The refresh token — the
# durable secret, strictly worse to leak than a short-lived access token — stays host-side, so a
# prompt-injected model with Bash/Read can no longer read it out of the mounted HOME.
TOKEN_ENDPOINTS = {"openai": "https://auth.openai.com/oauth/token"}
# Self-test seam ONLY, and deliberately LOOPBACK-ONLY: it lets the hermetic self-test exercise the
# transient-retry path against a closed local port with no network egress. Because a non-loopback
# value is REFUSED, this seam cannot be used to redirect a refresh token to an attacker's endpoint —
# unlike an unrestricted override it crosses no trust boundary at all (and an actor who controls this
# process's environment already holds the stored credential itself, the same argument the
# WORKER_GH_BIN seam documents).
TOKEN_ENDPOINT_OVERRIDE_ENV = "REGISTRY_TOKEN_ENDPOINT_OVERRIDE"
_LOOPBACK_ENDPOINT = re.compile(r"^http://(127\.0\.0\.1|\[::1\]|localhost)(:\d{1,5})?(/.*)?$")
# Public OAuth client id of the codex CLI. Not a secret: it is the `aud` claim of every id_token
# the CLI already stores, and a public/PKCE client id by construction.
OAUTH_CLIENT_IDS = {"openai": "app_EMoamEEZ73f0CkXaXp7hrann"}
OAUTH_SCOPE = "openid profile email"
# Refresh when the stored access token expires within this margin. Deliberately generous: a worker
# run can last 90 minutes, and refreshing early costs nothing while an expiry mid-run is fatal
# (the container cannot refresh — that is the whole point of this module).
REFRESH_LEEWAY_SECONDS = 2 * 3600
REFRESH_TIMEOUT_SECONDS = 20      # per-socket-operation timeout on the token exchange
REFRESH_MAX_BYTES = 1 << 20       # response-size bound (a token response is a few KB)
REFRESH_ATTEMPTS = 3              # total attempts; only TRANSIENT classes are retried

# The two NEW, deliberately distinct failure classes. Neither is `auth` — `auth` is already
# overloaded (worker-live's classifier matches the substring `oauth`, so ANY in-container refresh
# diagnostic lands there) and it reads as "the provider rejected the model call".
CLASS_REMINT = "credential-remint-required"       # MAINTAINER ACTION: interactive re-mint needed
CLASS_REFRESH_TRANSIENT = "credential-refresh-transient"   # retried, still failing; retry later

# A 4xx from the token endpoint means the GRANT is bad — the refresh token is expired, revoked, or
# (OpenAI rotates refresh tokens and detects replay) ALREADY USED. No amount of retrying fixes it;
# only an interactive re-login can. 429 and 5xx are throttle/availability and ARE retried.
_REMINT_STATUSES = frozenset({400, 401, 403})
# THE RESEND ALLOWLIST (post-merge retro-review of #629, F5(a)). The one-time-use grant may be
# re-POSTed ONLY when the previous attempt provably did not deliver it. Two cases qualify:
#   * `STATUS_NOT_SENT` — the fault was raised strictly before the request write (see the phase
#     boundary below), so no byte reached the provider;
#   * HTTP 429 — a documented THROTTLE contract, i.e. an explicit "I rejected this without processing
#     it". The retro-review accepted this one narrowly and rejected the rest.
# Everything else means A RESPONSE WAS ACTUALLY RECEIVED, and no observed status proves the rotation
# did not commit: a backend or intermediary can 5xx after an upstream commit, and — MEASURED on the
# merged tree — a **2xx** with a truncated / unparseable / access_token-less body re-POSTed the grant
# 3× on the single strongest possible evidence that the provider DID commit it. So the resend decision
# is now made HERE, from the allowlist, and is deliberately independent of the reported CLASS below:
# the class says whether a LATER attempt is worth making, this set says whether THIS run may send the
# same grant again. A later attempt is safe because it re-reads the stored secret and a spent grant
# fails closed with `invalid_grant` — resending inside one run is not, because it replays the grant
# the provider may just have consumed.
_RESEND_SAFE_STATUSES = frozenset({429})
# --- IDEMPOTENCY of the exchange (retro-review of #614) -------------------------------------------
# The refresh token is ONE-TIME-USE and the provider detects replay. So "did this request reach the
# provider?" is a load-bearing question, and the old code could not ask it: every timeout, URLError
# and OSError collapsed to `(0, "")` — indistinguishable from "never sent" — was classified TRANSIENT,
# and the SAME grant was posted again, up to REFRESH_ATTEMPTS times. If the provider had already
# committed the rotation and only the response was lost, the retry replays a spent grant and kills
# the account permanently. Retrying is therefore only safe when the outcome is OBSERVED.
#
# Two sentinel statuses stand in for "no HTTP status":
#   STATUS_NOT_SENT (0)       — the failure PROVES nothing was transmitted (DNS failure, connection
#                               refused, a TLS handshake that never completed, a malformed URL). The
#                               grant is untouched, so this is genuinely retryable.
#   STATUS_INDETERMINATE (-1) — the request may have been transmitted and no response was observed
#                               (timeout, connection reset, broken pipe, any other I/O fault). The
#                               grant MAY already be consumed, so it must NOT be sent again. Fail
#                               loudly to the maintainer instead: a false re-mint page costs minutes,
#                               a replayed grant costs the account.
STATUS_NOT_SENT = 0
STATUS_INDETERMINATE = -1
# POST-MERGE RETRO-REVIEW OF #629, findings F5(b) + F6 — WHY THE PHASE IS NOW STRUCTURAL.
# #629 decided "was this request transmitted?" from the EXCEPTION TYPE, via
#     _NOT_SENT_ERRORS = (socket.gaierror, ConnectionRefusedError, ssl.SSLError)
# and that cannot work, in both directions:
#   * `ssl.SSLError` is an `OSError` subclass and is raised from the RESPONSE READ as well as from the
#     handshake, so a TLS fault after the grant was delivered classified STATUS_NOT_SENT and the
#     one-time-use grant was re-POSTed 3× — MEASURED: `_post_token_endpoint(...) -> (0, '')`,
#     `classify_refresh_failure(0, '') -> credential-refresh-transient`, transmissions = 3;
#   * conversely CPython's urllib wraps connect **and send** in one `URLError`, so a connect-phase
#     timeout — which provably transmitted nothing — was indistinguishable from a response-phase one
#     and both paged an immediate re-mint (F6's availability regression).
# No exception type can decide the phase, so the phase is no longer inferred from it. The exchange is
# driven through `http.client` with an EXPLICIT `connect()` before the request write, and the phase is
# whichever call was in flight: everything up to and including `connect()` is provably PRE-SEND, and
# everything from the request write onward is treated as POST-SEND. That boundary is a property of the
# code's structure, not of an exception hierarchy, and it cannot drift.
_PHASE_PRE_SEND = "pre-send"
_PHASE_POST_SEND = "post-send"
# Fixed allowlist of provider error codes safe to echo into a PUBLIC log. Anything outside it is
# never printed (no provider free text, no token material, ever reaches a log line).
_REMINT_CODES = frozenset({
    "invalid_grant", "refresh_token_reused", "invalid_client", "unauthorized_client",
    "invalid_token", "access_denied", "invalid_request",
})
# Codes that are DECISIVE on their own: they name a dead grant regardless of the HTTP status the
# provider chose to wrap it in. `invalid_request` is excluded — on its own it can equally mean the
# request shape is wrong (our bug), so it is left to the status to classify.
_DECISIVE_REMINT_CODES = _REMINT_CODES - {"invalid_request"}


class RefreshFailure(Exception):
    """A host-side refresh failure carrying its CLASS (`CLASS_REMINT` / `CLASS_REFRESH_TRANSIENT`)
    and, when the provider returned one from the fixed allowlist, its error `code`. The message is
    assembled from fixed strings + the allowlisted code ONLY — never provider free text, never any
    token material."""

    # Why the grant may already be spent, when it may. Selects the operator-facing wording so a
    # maintainer reading the log knows WHICH remint cause this is; `indeterminate` stays the single
    # boolean the rest of the code branches on.
    CAUSE_UNOBSERVED = "unobserved"
    CAUSE_UNUSABLE_SUCCESS = "unusable-success"
    CAUSE_OBSERVED_ERROR = "observed-error"
    _CAUSE_DETAIL = {
        CAUSE_UNOBSERVED: (
            " — the token-endpoint request was written and no response was observed, so this "
            "ONE-TIME-USE grant may already be consumed"),
        CAUSE_UNUSABLE_SUCCESS: (
            " — the provider returned a SUCCESS status with a body this code could not use, which is "
            "the STRONGEST evidence that the rotation DID commit, so this ONE-TIME-USE grant must be "
            "assumed consumed"),
        CAUSE_OBSERVED_ERROR: (
            " — the provider returned an error status AFTER the request was delivered, which does not "
            "prove the rotation did not commit, so this ONE-TIME-USE grant may already be consumed"),
    }

    def __init__(self, kind, code=None, indeterminate=False, cause=None):
        self.kind = kind
        self.code = code if code in _REMINT_CODES else None
        # INDETERMINATE (retro-review of #614, refined by the post-merge retro-review of #629): the
        # grant's fate is unknown. Carried on the exception so the operator-facing message can say
        # which remint cause this is ("the grant is dead" vs "the grant's fate is unknown and must not
        # be gambled again"), and so worker-prep.sh's `::error::` line can stop asserting the wrong one.
        self.indeterminate = bool(indeterminate)
        self.cause = cause if self.indeterminate else None
        detail = f" (provider code: {self.code})" if self.code else ""
        if self.indeterminate:
            detail += self._CAUSE_DETAIL.get(self.cause or self.CAUSE_UNOBSERVED,
                                             self._CAUSE_DETAIL[self.CAUSE_UNOBSERVED])
            detail += "; it was NOT re-sent (replaying it would permanently kill the account)"
        super().__init__(f"host-side credential refresh failed: {kind}{detail}")


def _jwt_claims(token):
    """Best-effort UNVERIFIED claim read of a JWT payload. Signature verification is neither
    possible nor needed here: the only claim used is `exp`, and it drives a local "should I refresh
    now?" decision. A forged/short `exp` can only cause an EXTRA refresh, never an auth bypass."""
    try:
        segments = str(token).split(".")
        if len(segments) < 2:
            return {}
        payload = segments[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (ValueError, TypeError, json.JSONDecodeError):
        return {}
    return claims if isinstance(claims, dict) else {}


def access_token_expiry(provider, cred):
    """Epoch seconds at which the stored access token expires, or None when undeterminable."""
    if provider == "openai":
        exp = _jwt_claims((cred.get("tokens") or {}).get("access_token")).get("exp")
        return int(exp) if isinstance(exp, (int, float)) and not isinstance(exp, bool) else None
    if provider == "anthropic":
        expires_at = (cred.get("claudeAiOauth") or {}).get("expiresAt")
        if isinstance(expires_at, (int, float)) and not isinstance(expires_at, bool):
            return int(expires_at / 1000)  # anthropic stamps milliseconds
        return None
    raise ValueError(f"unknown provider {provider!r}")


def needs_refresh(provider, cred, now, leeway=REFRESH_LEEWAY_SECONDS):
    """True when the stored access token is expired or expires within `leeway`. An UNREADABLE expiry
    returns True (fail towards refreshing: the container cannot recover from a stale token, so the
    cost of an unnecessary refresh is a round trip while the cost of skipping a needed one is a
    dead run)."""
    expiry = access_token_expiry(provider, cred)
    if expiry is None:
        return True
    return expiry - leeway <= now


def extract_refresh_token(provider, cred):
    """The DURABLE refresh secret from a stored credential. Host-side callers only."""
    if provider == "openai":
        return (cred.get("tokens") or {}).get("refresh_token")
    if provider == "anthropic":
        return (cred.get("claudeAiOauth") or {}).get("refreshToken")
    raise ValueError(f"unknown provider {provider!r}")


def minimal_worker_credential(provider, cred):
    """Build the credential that is bind-mounted into the model container: everything the CLI needs
    to RUN, and no durable secret.

    `refresh_token` is emitted as an EMPTY STRING rather than omitted: codex's credential
    deserializer requires the field (verified — omitting it fails the run outright with
    `missing field 'refresh_token'`), and an empty string satisfies the shape while carrying no
    secret and being unmistakable for a real token. Verified end-to-end: the codex CLI completes a
    turn from this exact document under the production read-only bind mount."""
    if provider != "openai":
        raise ValueError(f"minimal worker credential is only defined for openai, not {provider!r}")
    tokens = cred.get("tokens") or {}
    for field in ("access_token", "id_token", "account_id"):
        if not isinstance(tokens.get(field), str) or not tokens[field]:
            raise ValueError(f"stored openai credential is missing tokens.{field}")
    minimal = {
        "OPENAI_API_KEY": cred.get("OPENAI_API_KEY"),
        "auth_mode": cred.get("auth_mode"),
        "tokens": {
            "id_token": tokens["id_token"],
            "access_token": tokens["access_token"],
            "refresh_token": "",   # CLI-required field, deliberately empty (see docstring)
            "account_id": tokens["account_id"],
        },
        "last_refresh": cred.get("last_refresh"),
    }
    assert_no_refresh_material(minimal, extract_refresh_token(provider, cred))
    return minimal


def merge_refreshed(provider, stored, response, now):
    """Fold a token-endpoint response into a NEW DURABLE credential in the CLI's own on-disk shape.

    Fail-closed identity check: when the response's id_token names a chatgpt account, it must be the
    SAME account as the stored credential — the registry must never write a different account's
    material into an ACCTNN_TOKEN secret."""
    if provider != "openai":
        raise ValueError(f"host-side refresh is only implemented for openai, not {provider!r}")
    tokens = dict(stored.get("tokens") or {})
    for field, value in (("access_token", response.get("access_token")),
                         ("refresh_token", response.get("refresh_token")),
                         ("id_token", response.get("id_token"))):
        if isinstance(value, str) and value:
            tokens[field] = value
    if not tokens.get("access_token"):
        raise RefreshFailure(CLASS_REFRESH_TRANSIENT)
    claims = _jwt_claims(tokens.get("id_token"))
    auth_claim = claims.get("https://api.openai.com/auth")
    if isinstance(auth_claim, dict):
        account = auth_claim.get("chatgpt_account_id")
        if isinstance(account, str) and account:
            if tokens.get("account_id") and account != tokens["account_id"]:
                raise AssertionError("refreshed credential names a DIFFERENT account; refusing it")
            tokens["account_id"] = account
    refreshed = dict(stored)
    refreshed["tokens"] = tokens
    refreshed["last_refresh"] = (
        datetime.datetime.fromtimestamp(int(now), datetime.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%S.000000000Z"))
    return refreshed


def classify_refresh_failure(status, body=""):
    """Map a token-endpoint failure onto exactly one of the two new classes.

    `status` is the HTTP status, `STATUS_NOT_SENT` (0) for "provably never transmitted", or
    `STATUS_INDETERMINATE` (-1) for "may have been transmitted, no response observed". A recognised
    remint error CODE wins over the status so a provider that reports `invalid_grant` with an unusual
    status is still routed to the maintainer instead of being retried forever.

    INDETERMINATE is REMINT, not transient (retro-review of #614): an unobserved outcome leaves the
    grant's fate unknown, so it routes to a maintainer instead of being retried.

    THE CLASS IS NOT THE RESEND DECISION (post-merge retro-review of #629, F5). This function answers
    "is a LATER attempt worth making?", which is why 429 and 5xx stay transient. Whether THIS run may
    re-POST the same one-time-use grant is a strictly narrower question answered by
    `_RESEND_SAFE_STATUSES` in `refresh_access_token` — #629 conflated the two, and the 2xx arm did not
    consult either."""
    if refresh_error_code(body) in _DECISIVE_REMINT_CODES:
        return CLASS_REMINT
    if int(status) == STATUS_INDETERMINATE:
        return CLASS_REMINT
    if int(status) in _REMINT_STATUSES:
        return CLASS_REMINT
    return CLASS_REFRESH_TRANSIENT


def refresh_error_code(body):
    """The provider error code from a token-endpoint error body, but ONLY when it is on the fixed
    allowlist — so nothing a provider (or a hostile intermediary) puts in that body can reach a
    public log. Returns None otherwise."""
    try:
        document = json.loads(body or "")
    except (ValueError, TypeError):
        return None
    if not isinstance(document, dict):
        return None
    candidates = []
    error = document.get("error")
    if isinstance(error, dict):
        candidates.extend([error.get("code"), error.get("type")])
    elif isinstance(error, str):
        candidates.append(error)
    candidates.append(document.get("code"))
    for candidate in candidates:
        if isinstance(candidate, str) and candidate in _REMINT_CODES:
            return candidate
    return None


def _open_token_connection(url, timeout):
    """The PRE-SEND half of one exchange: parse the URL and establish the connection. Returns
    (connection, path). Every fault raised from here — a malformed URL, DNS failure, refused
    connection, connect timeout, failed TLS handshake — provably transmitted nothing, because no
    request byte has been written yet. Kept a separate function so that boundary is visible."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"unsupported token endpoint scheme in {parts.scheme!r}")
    path = urllib.parse.urlunsplit(("", "", parts.path or "/", parts.query, ""))
    if parts.scheme == "https":
        connection = http.client.HTTPSConnection(
            parts.hostname, parts.port, timeout=timeout,
            context=ssl.create_default_context())
    else:
        # http is reachable ONLY through the loopback-pinned self-test override (token_endpoint
        # refuses any non-loopback override), so no credential ever crosses a network in the clear.
        connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout)
    connection.connect()
    return connection, path


def _post_token_endpoint(url, payload, timeout=REFRESH_TIMEOUT_SECONDS):
    """One token-endpoint exchange. Returns (status, body_text). Never raises for an HTTP error
    status, and never logs: the body may echo request material, so only the CALLER's allowlisted
    code extraction ever looks at it.

    A failure with no HTTP status is reported as `STATUS_NOT_SENT` when it was raised STRICTLY BEFORE
    the request was written, and `STATUS_INDETERMINATE` when it was raised at or after the write — the
    grant may then already be spent. THE PHASE IS DECIDED BY WHICH CALL WAS IN FLIGHT, never by the
    exception's type (retro-review of #629, F5(b)/F6): `ssl.SSLError` is an `OSError` and is raised
    from both the handshake and the response read, and urllib's `URLError` conflates connect with
    send, so no type-based test can be sound in both directions.

    Deliberately does NOT follow redirects (urllib's opener did). A 3xx now surfaces as its observed
    status, which stops the resend and is the right outcome twice over: re-POSTing the grant to a
    redirect target is a credential-forwarding hazard, and the token endpoint is a fixed URL that has
    no legitimate reason to move mid-flight."""
    connection = None
    try:
        connection, path = _open_token_connection(url, timeout)
    except (ValueError, OSError):
        if connection is not None:                                  # pragma: no cover - defensive
            connection.close()
        return STATUS_NOT_SENT, ""       # PRE-SEND by construction: nothing was ever transmitted
    try:
        connection.request(
            "POST", path, body=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json",
                     "Host": urllib.parse.urlsplit(url).netloc})
        response = connection.getresponse()
        return response.status, response.read(REFRESH_MAX_BYTES).decode("utf-8", "replace")
    except (OSError, http.client.HTTPException, ValueError):
        # POST-SEND by construction: the request write has begun, so the provider MAY have received
        # and committed the rotation. Never retryable with the same grant.
        return STATUS_INDETERMINATE, ""
    finally:
        try:
            connection.close()
        except OSError:                                             # pragma: no cover - defensive
            pass


def token_endpoint(provider, environ=None):
    """The token endpoint for `provider`, honouring the LOOPBACK-ONLY self-test override. A
    non-loopback override is REFUSED (fail closed) rather than silently ignored, so a
    misconfiguration can never quietly ship a refresh token to an unexpected host."""
    url = TOKEN_ENDPOINTS.get(provider)
    override = (environ if environ is not None else os.environ).get(TOKEN_ENDPOINT_OVERRIDE_ENV)
    if override:
        if not _LOOPBACK_ENDPOINT.match(override):
            raise ValueError(f"{TOKEN_ENDPOINT_OVERRIDE_ENV} must be a loopback http:// URL")
        return override
    return url


def refresh_access_token(provider, refresh_token, *, poster=_post_token_endpoint,
                         attempts=REFRESH_ATTEMPTS, sleeper=None, environ=None):
    """Exchange a refresh token for fresh material against the provider's token endpoint.

    Bounded retry on TRANSIENT classes only, reusing gh_retry's exponential-with-jitter sleep
    mechanics. A remint class fails immediately — retrying a dead grant just delays the maintainer
    signal (the exact misclassification gh_retry's docstring calls out).

    IDEMPOTENCY-AWARE (retro-review of #614, corrected by the POST-MERGE retro-review of #629 F5):
    the retry re-POSTS the SAME one-time-use grant, so it is performed ONLY when the previous attempt
    PROVABLY did not deliver it — `_RESEND_SAFE_STATUSES`. Any response actually received means the
    provider may have committed the rotation, and a 2xx is the strongest possible evidence that it DID:
    #629 treated a 2xx with a truncated / unparseable / access_token-less body as transient and
    re-POSTed the grant 3× (MEASURED: `200 + truncated JSON -> grant transmissions=3`). That arm now
    raises on the spot with the remint class and the "unusable success" cause.

    The RESEND decision and the reported CLASS are deliberately separate. A 5xx still reports
    `credential-refresh-transient` — a LATER attempt is worth making, and it is safe because it
    re-reads the stored secret and a spent grant then fails closed with `invalid_grant` — but this run
    will not send the same grant again."""
    url = token_endpoint(provider, environ)
    client_id = OAUTH_CLIENT_IDS.get(provider)
    if not url or not client_id:
        raise ValueError(f"no host-side token endpoint is configured for provider {provider!r}")
    if not isinstance(refresh_token, str) or not refresh_token:
        raise RefreshFailure(CLASS_REMINT)   # nothing to exchange: the stored snapshot is unusable
    sleep = sleeper if sleeper is not None else gh_retry.sleep_backoff
    payload = {"client_id": client_id, "grant_type": "refresh_token",
               "refresh_token": refresh_token, "scope": OAUTH_SCOPE}
    last = RefreshFailure(CLASS_REFRESH_TRANSIENT)
    for attempt in range(1, max(1, int(attempts)) + 1):
        status, body = poster(url, payload)
        if 200 <= int(status) < 300:
            try:
                document = json.loads(body or "")
            except (ValueError, TypeError):
                document = None
            if isinstance(document, dict) and document.get("access_token"):
                return document
            # A 2xx WITH AN UNUSABLE BODY. The provider reported success, so the rotation almost
            # certainly committed and the stored grant is spent; re-POSTing it is the single most
            # certain way to trip replay detection and kill the account. Raise, never resend.
            raise RefreshFailure(CLASS_REMINT, refresh_error_code(body), indeterminate=True,
                                 cause=RefreshFailure.CAUSE_UNUSABLE_SUCCESS)
        numeric, code = int(status), refresh_error_code(body)
        kind = classify_refresh_failure(status, body)
        # May the SAME grant be sent again? Only if this attempt provably did not deliver it.
        resend_safe = numeric == STATUS_NOT_SENT or numeric in _RESEND_SAFE_STATUSES
        # Is the grant PROVABLY dead (as opposed to of unknown fate)? Only a decisive provider code or
        # a grant-rejecting status says so; everything else observed leaves the fate open.
        decisive_dead = code in _DECISIVE_REMINT_CODES or numeric in _REMINT_STATUSES
        indeterminate = not resend_safe and not decisive_dead
        failure = RefreshFailure(
            kind, code, indeterminate=indeterminate,
            cause=(RefreshFailure.CAUSE_UNOBSERVED if numeric == STATUS_INDETERMINATE
                   else RefreshFailure.CAUSE_OBSERVED_ERROR))
        if kind == CLASS_REMINT:
            # A dead grant is not worth retrying, and an INDETERMINATE grant must not be retried.
            raise failure
        last = failure
        # THE RESEND GATE. Reached only on a transient class, and it still refuses to re-POST the
        # one-time-use grant unless this attempt provably did not deliver it (F5(a)).
        if not resend_safe:
            raise last
        if attempt < max(1, int(attempts)):
            sleep(attempt)
    raise last


def refresh_credential_host_side(provider, stored, *, now, force=False, **kwargs):
    """The whole host-side pre-flight in one call.

    Returns {"mount", "durable", "refreshed", "rotated"}:
      * mount    — the MINIMAL credential to bind-mount (fresh access token, NO refresh token);
      * durable  — the full credential to persist back to the account secret, or None;
      * refreshed— whether a token exchange actually happened;
      * rotated  — whether the exchange produced NEW DURABLE material (a rotated refresh token).
                   THIS, not "did the model mutate the mounted file?", is the rotation trigger.
    Raises RefreshFailure when a needed refresh could not be completed."""
    if not force and not needs_refresh(provider, stored, now):
        # Still valid: mount it as-is (minus the refresh token) and exchange nothing. With OpenAI's
        # one-time-use refresh tokens this matters — an unnecessary exchange would burn the stored
        # grant for no gain.
        return {"mount": minimal_worker_credential(provider, stored),
                "durable": None, "refreshed": False, "rotated": False}
    response = refresh_access_token(provider, extract_refresh_token(provider, stored), **kwargs)
    durable = merge_refreshed(provider, stored, response, now)
    rotated = extract_refresh_token(provider, durable) != extract_refresh_token(provider, stored)
    return {"mount": minimal_worker_credential(provider, durable),
            "durable": durable, "refreshed": True, "rotated": rotated}


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

    # ---- host-side pre-flight refresh (registry issue #596) ------------------------------------
    # Fixtures: real key layouts, fake values. The access token is a real JWT SHAPE (header.payload
    # .signature, unverified payload) because the refresh decision reads its `exp` claim.
    def _jwt(exp):
        head = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode()
        body = base64.urlsafe_b64encode(
            json.dumps({"exp": exp}).encode()).rstrip(b"=").decode()
        return f"{head}.{body}.sig"

    now = 1_800_000_000
    fresh = {"OPENAI_API_KEY": None, "auth_mode": "chatgpt",
             "tokens": {"id_token": "ID_v1", "access_token": _jwt(now + 10 * 24 * 3600),
                        "refresh_token": "REFRESH_long", "account_id": "acct-uuid"},
             "last_refresh": "2026-07-25T00:00:00.000000000Z"}
    stale = json.loads(json.dumps(fresh))
    stale["tokens"]["access_token"] = _jwt(now - 3600)   # already expired

    # (a) the MOUNTED credential carries NO refresh material — asserted on the PARSED keys.
    mount = minimal_worker_credential("openai", fresh)
    chk("mounted credential parses to the exact CLI-required key set",
        sorted(mount) == ["OPENAI_API_KEY", "auth_mode", "last_refresh", "tokens"]
        and sorted(mount["tokens"]) == ["access_token", "account_id", "id_token", "refresh_token"])
    chk("mounted credential's refresh_token key is the empty CLI placeholder",
        mount["tokens"]["refresh_token"] == "")
    chk("mounted credential carries NO refresh-token VALUE anywhere",
        "REFRESH_long" not in json.dumps(mount))
    chk("mounted credential keeps the access token the CLI must present",
        mount["tokens"]["access_token"] == fresh["tokens"]["access_token"])
    # non-vacuity of (a): the FULL stored credential must be REJECTED as a mount document.
    rejected = False
    try:
        assert_no_refresh_material(fresh, "REFRESH_long")
    except AssertionError:
        rejected = True
    chk("materialization guard REJECTS a full auth.json as a mount document (non-vacuous)", rejected)
    # ...and it catches the value under a renamed/nested key too (the regression that a key-name-only
    # check would wave through).
    renamed = False
    try:
        assert_no_refresh_material({"tokens": {"access_token": "REFRESH_long"}}, "REFRESH_long")
    except AssertionError:
        renamed = True
    chk("materialization guard catches the refresh VALUE under a DIFFERENT key (non-vacuous)",
        renamed)

    # (b) refresh-need decision: a comfortable expiry exchanges nothing (OpenAI refresh tokens are
    # one-time-use, so a needless exchange burns the stored grant); a stale one must refresh.
    chk("fresh access token needs no refresh", needs_refresh("openai", fresh, now) is False)
    chk("expired access token needs a refresh", needs_refresh("openai", stale, now) is True)
    chk("access token inside the leeway window needs a refresh",
        needs_refresh("openai", {"tokens": dict(fresh["tokens"],
                                                access_token=_jwt(now + 60))}, now) is True)
    chk("undeterminable expiry fails towards refreshing",
        needs_refresh("openai", {"tokens": {"access_token": "not-a-jwt"}}, now) is True)
    chk("anthropic expiry is read from millisecond expiresAt",
        access_token_expiry("anthropic", {"claudeAiOauth": {"expiresAt": 1_800_000_000_000}})
        == 1_800_000_000)

    # (c) failure classification: dead grant => MAINTAINER ACTION, never `auth`, never transient.
    reused = json.dumps({"error": {"code": "refresh_token_reused", "type": "invalid_request_error",
                                   "message": "Your refresh token has already been used."}})
    chk("refresh_token_reused (the live OpenAI reuse body) classifies as remint-required",
        classify_refresh_failure(400, reused) == CLASS_REMINT)
    chk("invalid_grant classifies as remint-required",
        classify_refresh_failure(400, json.dumps({"error": "invalid_grant"})) == CLASS_REMINT)
    chk("a decisive remint CODE wins over an odd status",
        classify_refresh_failure(500, reused) == CLASS_REMINT)
    chk("401 classifies as remint-required", classify_refresh_failure(401, "") == CLASS_REMINT)
    chk("500 classifies as transient", classify_refresh_failure(500, "") == CLASS_REFRESH_TRANSIENT)
    chk("503 classifies as transient", classify_refresh_failure(503, "") == CLASS_REFRESH_TRANSIENT)
    chk("429 classifies as transient (throttle, not a dead grant)",
        classify_refresh_failure(429, "") == CLASS_REFRESH_TRANSIENT)
    chk("a PROVABLY-unsent request (DNS/connection-refused/TLS) classifies as transient",
        classify_refresh_failure(STATUS_NOT_SENT, "") == CLASS_REFRESH_TRANSIENT)
    # --- IDEMPOTENCY (retro-review of #614). An UNOBSERVED outcome is not transient: "transient"
    # licenses re-POSTing the same ONE-TIME-USE grant, and that is exactly what must not happen when
    # the provider may already have consumed it. ---
    chk("an INDETERMINATE outcome (request may have landed, no response seen) classifies as "
        "remint-required, NOT transient — so it is never re-sent",
        classify_refresh_failure(STATUS_INDETERMINATE, "") == CLASS_REMINT)
    chk("the two no-status sentinels are distinct (a lost response is not an unsent request)",
        STATUS_NOT_SENT != STATUS_INDETERMINATE
        and classify_refresh_failure(STATUS_NOT_SENT, "")
        != classify_refresh_failure(STATUS_INDETERMINATE, ""))
    chk("an indeterminate RefreshFailure says the grant may already be consumed and was NOT re-sent",
        "may already be consumed" in str(RefreshFailure(CLASS_REMINT, indeterminate=True))
        and "NOT re-sent" in str(RefreshFailure(CLASS_REMINT, indeterminate=True))
        and RefreshFailure(CLASS_REMINT, indeterminate=True).indeterminate is True
        and RefreshFailure(CLASS_REMINT).indeterminate is False)
    # --- THE PHASE BOUNDARY (post-merge retro-review of #629, F5(b) + F6). The phase is decided by
    # WHICH CALL was in flight, never by the exception's type, so the probe drives a fake connection
    # that raises from a chosen method and injects the SAME exception types at BOTH phases. Under
    # #629's type-based `_NOT_SENT_ERRORS` an `ssl.SSLError` raised from `response.read()` classified
    # STATUS_NOT_SENT and the one-time-use grant was re-POSTed 3× (MEASURED), while a CONNECT-phase
    # timeout — which provably transmits nothing — was reported INDETERMINATE and paged an immediate
    # re-mint. Both are corrected here, and neither can be corrected by a type test. ---
    def phase_probe(failing_method, error, status=200, body=b'{"access_token": "A"}'):
        class FakeResponse:
            def __init__(self):
                self.status = status

            def read(self, _limit=None):
                if failing_method == "read":
                    raise error
                return body

        class FakeConnection:
            def __init__(self, *_args, **_kwargs):
                pass

            def connect(self):
                if failing_method == "connect":
                    raise error

            def request(self, *_args, **_kwargs):
                if failing_method == "request":
                    raise error

            def getresponse(self):
                if failing_method == "getresponse":
                    raise error
                return FakeResponse()

            def close(self):
                pass

        saved = http.client.HTTPSConnection
        http.client.HTTPSConnection = FakeConnection
        try:
            return _post_token_endpoint("https://auth.example/oauth/token", {"grant_type": "x"})
        finally:
            http.client.HTTPSConnection = saved

    for method, error, expected_status, label in (
            ("connect", socket.gaierror(-2, "Name or service not known"), STATUS_NOT_SENT,
             "DNS failure"),
            ("connect", ConnectionRefusedError(111, "refused"), STATUS_NOT_SENT,
             "connection refused"),
            ("connect", ssl.SSLCertVerificationError("bad cert"), STATUS_NOT_SENT,
             "TLS certificate verification failure"),
            ("connect", ssl.SSLError(1, "handshake failure"), STATUS_NOT_SENT,
             "ssl.SSLError raised from the HANDSHAKE"),
            ("connect", TimeoutError("timed out"), STATUS_NOT_SENT,
             "CONNECT-phase timeout (F6: an unreachable endpoint keeps its bounded retry)"),
            ("request", BrokenPipeError(32, "broken pipe"), STATUS_INDETERMINATE,
             "broken pipe while WRITING the request"),
            ("request", TimeoutError("timed out"), STATUS_INDETERMINATE, "send-phase timeout"),
            ("getresponse", TimeoutError("timed out"), STATUS_INDETERMINATE,
             "RESPONSE-phase timeout (F6: distinguished from the connect phase)"),
            ("getresponse", ConnectionResetError(104, "reset by peer"), STATUS_INDETERMINATE,
             "connection reset while waiting for the response"),
            ("read", ssl.SSLError(1, "decryption failed or bad record mac"), STATUS_INDETERMINATE,
             "ssl.SSLError raised from response.read() — F5(b) VERBATIM"),
            ("read", TimeoutError("timed out"), STATUS_INDETERMINATE,
             "timeout reading the response body"),
            ("read", http.client.IncompleteRead(b"{"), STATUS_INDETERMINATE,
             "truncated response body")):
        chk(f"transport: {label} at `{method}` -> "
            f"{'NOT_SENT (retryable)' if expected_status == STATUS_NOT_SENT else 'INDETERMINATE'}",
            phase_probe(method, error) == (expected_status, ""))
    chk("transport (F5(b)): the SAME `ssl.SSLError` classifies NOT_SENT from the handshake and "
        "INDETERMINATE from the response read — the phase, not the exception type, decides",
        (phase_probe("connect", ssl.SSLError(1, "x"))[0],
         phase_probe("read", ssl.SSLError(1, "x"))[0]) == (STATUS_NOT_SENT, STATUS_INDETERMINATE))
    chk("transport (F6): the SAME `TimeoutError` classifies NOT_SENT at connect (nothing "
        "transmitted, so the bounded retry is preserved) and INDETERMINATE at the response",
        (phase_probe("connect", TimeoutError())[0],
         phase_probe("getresponse", TimeoutError())[0])
        == (STATUS_NOT_SENT, STATUS_INDETERMINATE))
    chk("transport: a malformed endpoint URL is PRE-SEND (nothing was ever transmitted)",
        _post_token_endpoint("not-a-url", {"grant_type": "x"}) == (STATUS_NOT_SENT, ""))
    chk("transport: the happy path returns the observed status and body",
        phase_probe(None, None) == (200, '{"access_token": "A"}'))
    chk("transport: an HTTP error status is RETURNED, never raised",
        phase_probe(None, None, status=503, body=b"upstream") == (503, "upstream"))
    # REAL SOCKETS, loopback only, zero network egress. Two cases that pin the STRUCTURAL claim the
    # phase boundary rests on — that `_open_token_connection` completes before any request byte is
    # written — against a live kernel rather than a stub:
    #   * nothing listening -> refused during connect -> PRE-SEND, and the bounded retry is preserved
    #     (F6: #629 reported the analogous connect-phase timeout INDETERMINATE and paged a re-mint on
    #     attempt 1, because urllib wraps connect AND send in one URLError);
    #   * a server that ACCEPTS the request and then closes without answering -> POST-SEND, so the
    #     grant may be spent and must never be re-POSTed.
    import threading
    _probe = socket.socket()
    _probe.bind(("127.0.0.1", 0))
    closed_port = _probe.getsockname()[1]
    _probe.close()
    chk("transport (F6, real socket): nothing listening -> refused during CONNECT -> NOT_SENT, so an "
        "unreachable endpoint keeps its bounded retry instead of paging a re-mint",
        _post_token_endpoint(f"http://127.0.0.1:{closed_port}/oauth/token",
                             {"grant_type": "x"}, timeout=2) == (STATUS_NOT_SENT, ""))
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    silent_port = listener.getsockname()[1]

    def accept_then_close():
        try:
            connection, _peer = listener.accept()
            connection.close()          # accepted the request, answered nothing
        except OSError:                                            # pragma: no cover - teardown race
            pass

    thread = threading.Thread(target=accept_then_close, daemon=True)
    thread.start()
    try:
        silent = _post_token_endpoint(f"http://127.0.0.1:{silent_port}/oauth/token",
                                      {"grant_type": "x"}, timeout=5)
    finally:
        thread.join(timeout=5)
        listener.close()
    chk("transport (F5, real socket): a server that ACCEPTS the request and answers nothing -> "
        "INDETERMINATE (the grant may already be spent, so it must never be re-POSTed)",
        silent == (STATUS_INDETERMINATE, ""))
    chk("the two new classes are distinct from `auth`",
        CLASS_REMINT != "auth" and CLASS_REFRESH_TRANSIENT != "auth"
        and CLASS_REMINT != CLASS_REFRESH_TRANSIENT)
    # only allowlisted codes may reach a log line
    chk("a non-allowlisted provider code is never surfaced",
        refresh_error_code(json.dumps({"error": {"code": "acct-sk-live-DEADBEEF"}})) is None)
    chk("provider free text is never surfaced", refresh_error_code("total garbage") is None)
    chk("RefreshFailure message carries the class + allowlisted code and NO token material",
        "refresh_token_reused" in str(RefreshFailure(CLASS_REMINT, "refresh_token_reused"))
        and "REFRESH_long" not in str(RefreshFailure(CLASS_REMINT, "REFRESH_long"))
        and RefreshFailure(CLASS_REMINT, "REFRESH_long").code is None)

    # (d) the exchange loop: transient retries then succeeds; remint fails IMMEDIATELY (retrying a
    # dead grant only delays the maintainer signal); a persistent transient exhausts the bound.
    calls, sleeps = [], []
    def flaky(url, payload):
        calls.append(payload["grant_type"])
        if len(calls) < 3:
            return 429, ""          # documented THROTTLE: the only observed status safe to resend on
        return 200, json.dumps({"access_token": _jwt(now + 864000), "refresh_token": "REFRESH_v2",
                                "id_token": "ID_v2"})
    response = refresh_access_token("openai", "REFRESH_long", poster=flaky,
                                    sleeper=lambda attempt: sleeps.append(attempt))
    chk("throttled (429) token-endpoint failures retry then succeed",
        (len(calls), sleeps, response["refresh_token"]) == (3, [1, 2], "REFRESH_v2"))
    calls.clear(); sleeps.clear()
    kind = None
    try:
        refresh_access_token("openai", "REFRESH_long",
                            poster=lambda url, payload: (calls.append(1), (400, reused))[1],
                            sleeper=lambda attempt: sleeps.append(attempt))
    except RefreshFailure as exc:
        kind = exc.kind
    chk("a dead grant fails on the FIRST attempt with the remint class",
        (kind, len(calls), sleeps) == (CLASS_REMINT, 1, []))
    # --- THE #614 IDEMPOTENCY DEFECT, end to end through the real retry loop. A lost response used to
    # replay the SAME one-time-use grant REFRESH_ATTEMPTS times; the grant must now be TRANSMITTED
    # EXACTLY ONCE, and the failure must say the account may need a re-mint. ---
    calls.clear(); sleeps.clear()
    sent, failure = [], None
    try:
        refresh_access_token(
            "openai", "REFRESH_ONE_TIME_USE",
            poster=lambda url, payload: (sent.append(payload["refresh_token"]),
                                         (STATUS_INDETERMINATE, ""))[1],
            sleeper=lambda attempt: sleeps.append(attempt))
    except RefreshFailure as exc:
        failure = exc
    chk("a LOST RESPONSE transmits the one-time-use grant EXACTLY ONCE (never replayed)",
        sent == ["REFRESH_ONE_TIME_USE"])
    chk("a LOST RESPONSE never sleeps for a retry it must not perform", sleeps == [])
    chk("a LOST RESPONSE raises the remint class, flagged indeterminate",
        failure is not None and failure.kind == CLASS_REMINT and failure.indeterminate is True)
    chk("REFRESH_ATTEMPTS > 1, so the exactly-once assertion above is NON-VACUOUS",
        REFRESH_ATTEMPTS > 1)
    # ...and the contrast: a genuinely-unsent request (connection refused) IS still retried, so the
    # fix did not simply disable the bounded retry the transient class exists for.
    sent.clear(); sleeps.clear()
    kind = None
    try:
        refresh_access_token(
            "openai", "REFRESH_ONE_TIME_USE",
            poster=lambda url, payload: (sent.append(payload["refresh_token"]),
                                         (STATUS_NOT_SENT, ""))[1],
            sleeper=lambda attempt: sleeps.append(attempt))
    except RefreshFailure as exc:
        kind = exc.kind
    chk("a PROVABLY-unsent request is still retried to the bound (the grant was never spent)",
        (len(sent), sleeps, kind)
        == (REFRESH_ATTEMPTS, list(range(1, REFRESH_ATTEMPTS)), CLASS_REFRESH_TRANSIENT))
    calls.clear(); sleeps.clear()
    kind = None
    try:
        refresh_access_token("openai", "REFRESH_long",
                            poster=lambda url, payload: (calls.append(1), (429, ""))[1],
                            sleeper=lambda attempt: sleeps.append(attempt))
    except RefreshFailure as exc:
        kind = exc.kind
    chk("a persistent THROTTLE exhausts the bounded retry then reports transient",
        (kind, len(calls), sleeps) == (CLASS_REFRESH_TRANSIENT, REFRESH_ATTEMPTS,
                                      list(range(1, REFRESH_ATTEMPTS))))
    # --- POST-MERGE RETRO-REVIEW OF #629, F5(a): NEVER RE-POST THE GRANT AFTER A RESPONSE ARRIVED.
    # MEASURED on the merged tree:
    #     200 + truncated JSON  -> grant transmissions=3  (raised credential-refresh-transient)
    #     200 + no access_token -> grant transmissions=3
    #     204 + empty body      -> grant transmissions=3
    # A 2xx is the STRONGEST possible evidence the provider committed the rotation, so those three are
    # the highest-certainty replay cases in the file. A 5xx does not prove no grant was issued either
    # (a backend or intermediary can 5xx after an upstream commit), so it also stops the resend while
    # keeping the honest transient CLASS: a later attempt re-reads the stored secret, and a spent grant
    # then fails closed with `invalid_grant`. ---
    for status, body, expect_kind, expect_indeterminate, label in (
            (200, '{"access_to', CLASS_REMINT, True, "200 with a TRUNCATED body"),
            (200, '{"token_type": "bearer"}', CLASS_REMINT, True, "200 with NO access_token"),
            (204, "", CLASS_REMINT, True, "204 with an EMPTY body"),
            (299, "not json at all", CLASS_REMINT, True, "299 with an unparseable body"),
            (500, "", CLASS_REFRESH_TRANSIENT, True, "500 (an intermediary can 5xx post-commit)"),
            (503, "", CLASS_REFRESH_TRANSIENT, True, "503"),
            (404, "", CLASS_REFRESH_TRANSIENT, True, "404")):
        sent, sleeps, failure = [], [], None
        try:
            refresh_access_token(
                "openai", "REFRESH_ONE_TIME_USE",
                poster=lambda url, payload: (sent.append(payload["refresh_token"]), (status, body))[1],
                sleeper=lambda attempt: sleeps.append(attempt))
        except RefreshFailure as exc:
            failure = exc
        chk(f"F5(a): {label} transmits the one-time-use grant EXACTLY ONCE, never replays it, and "
            f"reports {expect_kind}",
            (sent, sleeps, failure is not None and failure.kind,
             failure is not None and failure.indeterminate)
            == (["REFRESH_ONE_TIME_USE"], [], expect_kind, expect_indeterminate))
    chk("F5(a): a 2xx-unusable failure names the SUCCESS status as the reason the grant must be "
        "assumed spent (not the generic unobserved wording)",
        "STRONGEST evidence" in str(RefreshFailure(
            CLASS_REMINT, indeterminate=True,
            cause=RefreshFailure.CAUSE_UNUSABLE_SUCCESS)))
    chk("F5(a): 429 is the ONLY observed status the grant may be re-POSTed on, and NOT_SENT the only "
        "unobserved one — so the resend allowlist is not silently widened",
        _RESEND_SAFE_STATUSES == frozenset({429}) and STATUS_NOT_SENT not in _RESEND_SAFE_STATUSES)
    # F5(b) end to end: a TLS fault from the response read used to classify NOT_SENT and replay the
    # grant 3×. Driven through the REAL poster, so it exercises the phase boundary, not a stub.
    sent_probe = []

    def counting_poster(url, payload):
        sent_probe.append(payload["refresh_token"])
        return phase_probe("read", ssl.SSLError(1, "decryption failed or bad record mac"))

    failure = None
    try:
        refresh_access_token("openai", "REFRESH_ONE_TIME_USE", poster=counting_poster,
                             sleeper=lambda attempt: None)
    except RefreshFailure as exc:
        failure = exc
    chk("F5(b): an `ssl.SSLError` from response.read() transmits the grant EXACTLY ONCE and reports "
        "the remint class (it used to be classified NOT_SENT and re-POSTed 3×)",
        (sent_probe, failure is not None and failure.kind,
         failure is not None and failure.indeterminate)
        == (["REFRESH_ONE_TIME_USE"], CLASS_REMINT, True))
    calls.clear()
    kind = None
    try:
        refresh_access_token("openai", "", poster=lambda url, payload: (calls.append(1), (200, ""))[1])
    except RefreshFailure as exc:
        kind = exc.kind
    chk("an absent stored refresh token is a remint condition and contacts nothing",
        (kind, calls) == (CLASS_REMINT, []))

    # (e) the whole pre-flight: fresh => no exchange; stale => exchange + rotation flagged, with the
    # rotated refresh token in DURABLE material only and NEVER in the mount document.
    preflight = refresh_credential_host_side("openai", fresh, now=now,
                                             poster=lambda url, payload: (500, ""))
    chk("pre-flight on a fresh credential performs NO exchange",
        (preflight["refreshed"], preflight["rotated"], preflight["durable"]) == (False, False, None))
    def rotating(url, payload):
        return 200, json.dumps({"access_token": _jwt(now + 864000),
                                "refresh_token": "REFRESH_v2", "id_token": "ID_v2"})
    preflight = refresh_credential_host_side("openai", stale, now=now, poster=rotating)
    chk("pre-flight on a stale credential refreshes and flags rotation",
        (preflight["refreshed"], preflight["rotated"]) == (True, True))
    chk("durable material carries the ROTATED refresh token (host-side only)",
        extract_refresh_token("openai", preflight["durable"]) == "REFRESH_v2")
    chk("the MOUNT document carries neither the old nor the new refresh token",
        "REFRESH_long" not in json.dumps(preflight["mount"])
        and "REFRESH_v2" not in json.dumps(preflight["mount"]))
    chk("the mount document carries the FRESH access token",
        preflight["mount"]["tokens"]["access_token"] == preflight["durable"]["tokens"]["access_token"]
        != stale["tokens"]["access_token"])
    chk("durable material keeps the CLI's on-disk shape",
        sorted(preflight["durable"]) == ["OPENAI_API_KEY", "auth_mode", "last_refresh", "tokens"]
        and preflight["durable"]["last_refresh"].endswith("Z"))
    def non_rotating(url, payload):
        return 200, json.dumps({"access_token": _jwt(now + 864000),
                                "refresh_token": "REFRESH_long"})
    preflight = refresh_credential_host_side("openai", stale, now=now, poster=non_rotating)
    chk("a provider that returns the SAME refresh token does not claim rotation",
        (preflight["refreshed"], preflight["rotated"]) == (True, False))
    # fail closed: refreshed material must never name a DIFFERENT account
    foreign = base64.urlsafe_b64encode(json.dumps(
        {"https://api.openai.com/auth": {"chatgpt_account_id": "SOMEONE-ELSE"}}).encode()
    ).rstrip(b"=").decode()
    crossed = False
    try:
        merge_refreshed("openai", stale, {"access_token": _jwt(now + 10),
                                          "id_token": f"h.{foreign}.s"}, now)
    except AssertionError:
        crossed = True
    chk("refreshed material naming a DIFFERENT account is refused (fail closed)", crossed)
    # (f) the self-test endpoint seam is LOOPBACK-ONLY: it can never redirect a refresh token off-box.
    chk("default token endpoint is the provider's own https endpoint",
        token_endpoint("openai", {}) == TOKEN_ENDPOINTS["openai"])
    chk("a loopback override is accepted (hermetic self-test seam)",
        token_endpoint("openai", {TOKEN_ENDPOINT_OVERRIDE_ENV: "http://127.0.0.1:1/oauth/token"})
        == "http://127.0.0.1:1/oauth/token")
    for hostile in ("https://evil.example/oauth/token", "http://127.0.0.1.evil.example/t",
                    "http://localhost.evil.example/t", "file:///etc/passwd"):
        refused = False
        try:
            token_endpoint("openai", {TOKEN_ENDPOINT_OVERRIDE_ENV: hostile})
        except ValueError:
            refused = True
        chk(f"a NON-loopback endpoint override is refused: {hostile}", refused)
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
