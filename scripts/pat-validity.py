#!/usr/bin/env python3
# [FABLE-5] Scheduled REGISTRY_SECRETS_PAT validity probe (issue #37).
#
# WHY: the PAT that set-up-account and the worker rotation write-back use for `gh secret set` on
# this registry repo was validated only at USE time — so a rotated/expired PAT (fine-grained PATs
# expire silently on a calendar) was discovered exactly when a new account was being onboarded,
# the one moment a human is waiting on the flow. This probe runs on a weekly cron instead.
#
# Probe targets (what the pipeline actually needs, in dependency order). Post-#101 the canonical
# secret home is the `dispatch-secrets` ENVIRONMENT (repo scope must stay EMPTY — the dispatch
# secrets-guard fails every tick closed otherwise), so BOTH the WRITE-capability probes target
# the environment: a weekly repo-scope canary write would re-trip that guard, and env-secret
# endpoints sit under the fine-grained "Environments" permission (doc-verified), which a
# Secrets-only PAT does not carry — validating repo-write would bless a PAT the real env writes
# still break on. Repo-scope `Secrets: read` is STILL load-bearing though (sol review round 3 of
# #275): onboarding's both-scopes absence probe (set-up-account.yml) LISTS repository-scope
# secrets and GETs the candidate ACCTNN_TOKEN name with this PAT, so a PAT holding
# Environments-write but no Secrets access would pass an env-only weekly probe and then fail
# onboarding closed — probe 3 covers that READ capability with a NON-MUTATING listing (no
# repo-scope canary write, which would re-trip the guard).
#   1. GET /user                                    — does the token authenticate at all
#   2. GET /repos/{repo}/environments/dispatch-secrets/secrets/public-key — the read
#      `gh secret set --env` performs before encrypting a secret (needs `Environments: read`).
#   3. GET /repos/{repo}/actions/secrets?per_page=1 — the NON-MUTATING repository-scope secrets
#      listing onboarding's both-scopes absence probe performs (needs repo `Secrets: read`).
#   4. `gh secret set --env dispatch-secrets` on a DEDICATED DISPOSABLE CANARY secret
#      (REGISTRY_PAT_PROBE_CANARY).
#      Review r3 #1: the public-key GET needs only read access, while the `gh secret set` that
#      onboarding and the rotation write-back actually run needs `Environments: write` — so a
#      read-only PAT passed probes 1–2 and was declared healthy (even auto-closing the rolling
#      alert) while onboarding stayed broken. Only a real write is authoritative for write
#      permission, so the probe overwrites a canary secret that exists solely for this purpose:
#      it holds NO secret material (a fixed marker string) and is rewritten by every probe run.
#      A read that succeeds without a completed write verdict is never `valid`.
# The expiry header (github-authentication-token-expiration) is inspected where available so a
# calendar expiry is flagged BEFORE it lands: a valid PAT within EXPIRY_WARN_DAYS of expiry
# becomes `expiring-soon`, which upserts the SAME rolling alert issue — a ::warning annotation
# alone is only a green-run log entry, not an actionable alert.
#
# Verdicts (GITHUB_OUTPUT `verdict=` — the runner-internal outputs file, rendered nowhere unless
# a later step deliberately echoes it, and none does):
#   valid | expiring-soon | invalid | insufficient-scope | network-unknown
# PUBLIC-LOG REDACTION (sol review round 1 of #432): stdout lands in the PUBLIC registry repo's
# workflow log whatever the alert route, so it carries ONLY a coarse
# {"status": "ok"|"attention-required"|"unknown"} plus generic annotations — never the exact
# verdict, the free-text detail, or the token's calendar expiry / days-left.
# FAIL-CLOSED AGAINST FALSE ALARMS: an unreachable/throttled/5xx-ing API proves nothing about the
# PAT, so `network-unknown` is NOT `invalid` — it neither opens the CREDENTIAL rolling alert NOR
# closes an existing one (unknown is not recovery either). But a PERMANENT unknown (a dead proxy,
# gh-status parse drift, or a sustained GitHub outage) would otherwise stay green-and-silent
# forever while secret writes go unverifiable and any open credential alert quietly goes stale, so
# a SEPARATE rolling "probe unavailable" alert (issue #207) tracks CONSECUTIVE network-unknowns and
# pages once the streak crosses a small threshold — distinct from the credential alert and STILL
# never reclassifying the PAT as invalid. GitHub answers 403 for primary/secondary rate
# limits too: primary carries x-ratelimit-remaining: 0 and secondary usually retry-after, but a
# secondary-limit 403 can arrive with NO retry-after and NONZERO remaining quota — there the
# DOCUMENTED discriminator is the error body's message ("You have exceeded a secondary rate
# limit"), so the JSON error message is inspected alongside the headers. A throttle-shaped
# secrets 403 is network-unknown, never insufficient-scope. Only 401 (invalid), an
# authenticated-but-denied secrets read OR canary write (insufficient-scope), and near-expiry
# alert.
#
# Alerting mirrors usage-alert.py: ONE rolling `from:agent` issue, upserted by exact title —
# edited when open, REOPENED (never duplicated) when closed, closed with a comment on recovery.
# ROUTING (sol-audit issue #204; hardened in #432 round 1): the DETAILED credential alert —
# verdict, diagnostic detail, and calendar expiry — is emitted ONLY over a POSITIVELY VERIFIED
# private route: ALERT_REPO distinct from the registry repo, ALERT_TOKEN set, AND the destination
# CONFIRMED `"private": true` via GET /repos/{ALERT_REPO} under ALERT_TOKEN — configuration alone
# (two non-empty strings) is NOT verification. EVERY other shape — unconfigured, half-configured,
# same-repo, a public destination, or a failed/indeterminate visibility lookup — fails CLOSED to
# the public registry with a REDACTED generic "needs attention" signal carrying no verdict, no
# detail, and no expiry (a public issue must never publish credential validity or lifecycle); the
# run also warns loud that the private route is absent. A verified private route whose token then
# fails at lookup/write time RETRIES a separately rendered redacted alert on the registry (never
# the detailed body), so a stale ALERT_TOKEN cannot drop the rolling credential signal. The
# probe-unavailable page (#207) and the streak variable carry no validity/expiry, so they stay on
# the registry with the ambient token.
# The lookup is the PAGINATED Issues REST API (authoritative — no fixed --limit window that an
# old closed alert could fall out of), and a FAILED lookup raises instead of writing: a blind
# create on top of an unlisted existing issue would duplicate the roll. A FAILED WRITE raises
# too (sanitized to op + returncode): a swallowed `issue create` failure would leave the run
# green while nobody was paged.
# The token is NEVER printed: a CR/LF-bearing (header-injecting) value is rejected before any
# request is built — http.client's "Invalid header value b'Bearer …'" ValueError embeds the full
# secret — and network/header-serialization failures are reduced to the exception class name so
# no request material can echo.
#
# Pure classify()/probe()/upsert_alert() are unit-tested against recorded-shape fixtures
# (--self-test, every verdict path exercised — including a read-only PAT: reads 200 + write 403,
# and an Environments-only PAT: env read 200 + repo-scope listing 403); the CLI wraps them over
# urllib + `gh`.
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

API = "https://api.github.com"
# The write probe's target: a secret that exists ONLY to be overwritten by this probe. Its value
# is a fixed non-secret marker — nothing reads it, so probing it risks nothing real. It lives in
# the dispatch-secrets ENVIRONMENT (post-#101): a repo-scope canary would re-trip the dispatch
# secrets-guard weekly, and the pipeline's real writes are env-scope, so only an env write is a
# faithful capability probe.
CANARY_SECRET = "REGISTRY_PAT_PROBE_CANARY"
CANARY_ENV = "dispatch-secrets"
CANARY_VALUE = "pat-validity write-probe canary - holds no secret material"
ALERT_TITLE = "🔑 REGISTRY_SECRETS_PAT is invalid or under-scoped — secret writes will fail"
ALERT_LABEL = "from:agent"
EXPIRY_HEADER = "github-authentication-token-expiration"
EXPIRY_WARN_DAYS = 14

# Persistent-unknown alerting (issue #207). network-unknown is deliberately no-op for the
# CREDENTIAL alert (an unreachable API is not evidence about the PAT), but a PERMANENT unknown
# would then leave the probe green-and-silent forever. So CONSECUTIVE network-unknown verdicts
# are counted in the PAT_PROBE_UNKNOWN_STREAK repository variable, and a DISTINCT rolling
# `from:agent` issue is created/reopened ONLY once the streak reaches UNKNOWN_STREAK_THRESHOLD —
# that is the page. The counter lives in a VARIABLE, not an issue body, because GitHub creates
# every issue OPEN: even a create-then-immediately-close "silent counter" notifies subscribers,
# fires issue-created automation, and flashes in open-alert views — exactly the false page the
# threshold exists to prevent. A variable write notifies nobody, so below the threshold NO issue
# operation happens at all. ANY definitive verdict (valid/invalid/insufficient-scope/
# expiring-soon, all of which prove the probe itself completed) zeroes the variable and closes an
# open page; the PAT is NEVER reclassified as invalid.
PROBE_ALERT_TITLE = ("🛰️ REGISTRY_SECRETS_PAT validity probe cannot complete — "
                     "verification has stalled")
UNKNOWN_STREAK_THRESHOLD = 3
STREAK_VAR = "PAT_PROBE_UNKNOWN_STREAK"

VALID = "valid"
EXPIRING = "expiring-soon"
INVALID = "invalid"
INSUFFICIENT = "insufficient-scope"
NETWORK_UNKNOWN = "network-unknown"


class AlertLookupError(RuntimeError):
    """The rolling-issue lookup failed. Upsert must NOT fall back to 'not found': a blind
    create on top of an existing (merely unlisted) alert would duplicate the rolling issue."""


class AlertWriteError(RuntimeError):
    """A rolling-issue write (create/reopen/edit/comment/close) failed. Must propagate to a red
    run: a swallowed write failure reports 'alerted' while nobody was paged. The message carries
    op + returncode only — gh stderr under GH_DEBUG=api can echo request bodies."""


def _body_message(raw):
    """The `message` field of a GitHub JSON error body (truncated), or "". Used only to
    discriminate rate limits from real denials — never echoed to logs, and it comes from the
    server's response, so it cannot contain the token."""
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return ""
    message = parsed.get("message") if isinstance(parsed, dict) else None
    return message[:300] if isinstance(message, str) else ""


def _get(url, token, timeout=20):
    """One authenticated GET -> {"status": int, "headers": {lowercased}, "message": str} or
    {"status": None, "error": <exception class name>}. `message` is the JSON error body's
    message field (empty on success) — a secondary rate limit's only reliable marker. The token
    exists only in the Authorization header; on failure only the exception CLASS is kept
    (URLError strings can embed proxy/request detail — never risk echoing request material into
    a public log)."""
    request = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "agent-account-registry-pat-validity",
    })
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return {"status": resp.status,
                    "headers": {k.lower(): v for k, v in resp.headers.items()},
                    "message": ""}
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(2048).decode("utf-8", "replace")
        except (OSError, ValueError, AttributeError):
            # AttributeError: a body-less HTTPError (fp=None) has no read(). No body is fine —
            # the message is a best-effort discriminator, not a required field.
            raw = ""
        return {"status": exc.code,
                "headers": {k.lower(): v for k, v in (exc.headers or {}).items()},
                "message": _body_message(raw)}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        # ValueError: http.client header serialization ("Invalid header value b'Bearer …'")
        # embeds the FULL credential in its message — class name only, like every other failure.
        # probe() rejects malformed tokens before any request, so this is belt-and-braces.
        return {"status": None, "error": type(exc).__name__}


def _throttled(resp):
    """True when a 403 is a rate limit, not a permission verdict. Headers first — primary limits
    carry x-ratelimit-remaining: 0 and secondary limits usually retry-after — but a secondary
    403 can arrive with NO retry-after and NONZERO remaining quota; there the docs say the error
    MESSAGE is the discriminator ("You have exceeded a secondary rate limit", legacy "abuse
    detection mechanism"), so the retained body message is checked too. The write probe's
    responses come from gh stderr and carry NO headers, so its primary-limit marker is the
    documented message ("API rate limit exceeded") as well."""
    headers = resp.get("headers") or {}
    message = (resp.get("message") or "").lower()
    return (headers.get("x-ratelimit-remaining") == "0"
            or "retry-after" in headers
            or "secondary rate limit" in message
            or "abuse detection" in message
            or "api rate limit exceeded" in message)


def _write_env(token):
    """Child env for the canary `gh secret set`: ONLY the probed PAT may authenticate. GH_TOKEN
    outranks every other gh auth source, and the ambient workflow token (GITHUB_TOKEN) is
    dropped so it can never mask a broken PAT by authenticating the write itself. GH_DEBUG is
    stripped because gh under GH_DEBUG=api dumps request headers — Authorization included — to
    the stderr this probe retains."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("GH_DEBUG", "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN")}
    env["GH_TOKEN"] = token
    return env


def _secret_write(token, repo, run=subprocess.run):
    """The authoritative write probe (review r3 #1): `gh secret set --env dispatch-secrets` on
    the disposable canary secret — the EXACT operation onboarding and the rotation write-back
    perform post-#101, exercising `Environments: write` which the public-key GET (read-only)
    cannot. Returns the same response shape as _get() so classify() treats it uniformly: {"status", "headers": {}, "message"} on an HTTP verdict, {"status":
    None, "error": …} when nothing conclusive happened. gh's stderr is retained ONLY as the
    throttle-vs-denial discriminator; it never carries the token (the PAT travels via GH_TOKEN
    in the child env and GH_DEBUG is stripped) and is never echoed into details or logs. The
    canary value goes via stdin — never argv — purely to keep the repo's no-secrets-in-argv
    convention, though the value is not secret."""
    try:
        result = run(["gh", "secret", "set", CANARY_SECRET, "-R", repo, "--env", CANARY_ENV],
                     input=CANARY_VALUE, capture_output=True, text=True,
                     env=_write_env(token), timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"status": None, "error": type(exc).__name__}
    if result.returncode == 0:
        return {"status": 204, "headers": {}, "message": ""}
    match = re.search(r"HTTP (\d{3})", result.stderr or "")
    if match is None:
        # gh died without an HTTP verdict (DNS, timeout, binary trouble) — proves nothing.
        return {"status": None, "error": f"gh secret set rc={result.returncode}, no HTTP status"}
    return {"status": int(match.group(1)), "headers": {},
            "message": (result.stderr or "")[:300]}


def classify(user, secrets, repo_read=None, write=None):
    """(verdict, detail) from the four probe responses. FAIL-CLOSED against false alarms: only
    a definitive credential signal (401) or an authenticated-but-denied secrets read/write
    (403/404 after a 200 /user) alerts; every throttling-shaped or server-side status is
    network-unknown — including a 403 whose headers OR error message say rate limit rather than
    missing scope. FAIL-CLOSED against false health too (review r3 #1): a 200 env public-key
    read only proves `Environments: read`; `valid` additionally requires the repo-scope secrets
    LISTING to have answered 200 (round-3 finding: onboarding's both-scopes absence probe needs
    repo `Secrets: read`, which the env probes never exercise) AND the canary write to have
    SUCCEEDED — so an env-only or read-only PAT is insufficient-scope, and a probe chain with no
    completed repo-read or write verdict is network-unknown, never valid."""
    status = user.get("status")
    if status is None:
        return NETWORK_UNKNOWN, (f"GET /user did not complete "
                                 f"({user.get('error', 'network error')}) — PAT state unknown")
    if status == 401:
        return INVALID, "GET /user returned 401 — the PAT is revoked, expired, or malformed"
    if status != 200:
        # 403/429 is throttling-shaped and 5xx is GitHub-side; a live PAT can hit both, so
        # neither is a credential verdict.
        return NETWORK_UNKNOWN, (f"GET /user returned {status} — throttling or API trouble, "
                                 "not a credential verdict")
    secrets = secrets or {}
    sstatus = secrets.get("status")
    if sstatus is None:
        return NETWORK_UNKNOWN, (f"secrets public-key read did not complete "
                                 f"({secrets.get('error', 'network error')}) — PAT state unknown")
    if sstatus == 200:
        repo_read = repo_read or {}
        rstatus = repo_read.get("status")
        if rstatus is None:
            # Env-read success alone is NEVER valid — the repo-scope Secrets: read capability
            # (onboarding's both-scopes absence probe) is still unproven.
            return NETWORK_UNKNOWN, (f"env public-key read succeeded but the repo-scope "
                                     f"secrets listing did not complete "
                                     f"({repo_read.get('error', 'no listing result')}) — "
                                     "repo Secrets: read state unknown")
        if rstatus == 401:
            return INVALID, ("repo-scope secrets listing returned 401 — the PAT is revoked "
                             "or expired")
        if rstatus == 403 and _throttled(repo_read):
            return NETWORK_UNKNOWN, ("repo-scope secrets listing returned a throttle-shaped "
                                     "403 (rate limited per its headers or documented error "
                                     "message) — not a credential verdict")
        if rstatus in (403, 404):
            # Round-3 finding: a PAT with Environments access but no Secrets access passes the
            # env probes, then set-up-account's repository-scope secrets listing/absence probe
            # fails closed mid-onboarding. Non-mutating read — never a repo-scope canary write.
            return INSUFFICIENT, (f"authenticates and reads the {CANARY_ENV} environment "
                                  f"public key, but the repository-scope secrets LISTING "
                                  f"returned {rstatus} — the PAT lacks repo-scope Secrets: "
                                  "read, which onboarding's both-scopes absence probe "
                                  "(set-up-account) performs before every credential write")
        if rstatus != 200:
            return NETWORK_UNKNOWN, (f"repo-scope secrets listing returned {rstatus} — "
                                     "not a credential verdict")
        write = write or {}
        wstatus = write.get("status")
        if wstatus is None:
            # Read success alone is NEVER valid — that is exactly the read-only false positive.
            return NETWORK_UNKNOWN, (f"secrets reads succeeded but the canary write did not "
                                     f"complete ({write.get('error', 'no write result')}) — "
                                     "write permission unknown")
        if wstatus in (201, 204):
            return VALID, ("authenticates, reads the dispatch-secrets environment public key, "
                           "lists repository-scope secrets (onboarding's both-scopes absence "
                           f"probe), AND wrote the disposable canary secret {CANARY_SECRET} "
                           f"into the {CANARY_ENV} environment — the exact write "
                           "`gh secret set --env` performs")
        if wstatus == 401:
            return INVALID, "canary secret write returned 401 — the PAT is revoked or expired"
        if wstatus == 403 and _throttled(write):
            return NETWORK_UNKNOWN, ("canary secret write returned a throttle-shaped 403 "
                                     "(rate limited per its documented error message) — not a "
                                     "credential verdict")
        if wstatus in (403, 404):
            return INSUFFICIENT, (f"authenticates and READS the environment public key, but "
                                  f"the canary environment-secret write returned {wstatus} — "
                                  "the PAT is read-only where `gh secret set --env` needs "
                                  "Environments: write (the env-secret PUT sits under the "
                                  "fine-grained 'Environments' permission)")
        return NETWORK_UNKNOWN, (f"canary secret write returned {wstatus} — "
                                 "not a credential verdict")
    if sstatus == 401:
        return INVALID, "secrets public-key read returned 401 — the PAT is revoked or expired"
    if sstatus == 403 and _throttled(secrets):
        return NETWORK_UNKNOWN, ("secrets public-key read returned a throttle-shaped 403 "
                                 "(rate limited per its headers or documented error message) "
                                 "— not a credential verdict")
    if sstatus in (403, 404):
        # A fine-grained PAT with no access to the repo (or a missing environment) 404s; one
        # with repo access but no Environments permission 403s. Both mean `gh secret set --env`
        # will fail.
        return INSUFFICIENT, (f"authenticates, but the {CANARY_ENV} environment secrets "
                              f"public-key read returned {sstatus} — the PAT lacks Environments "
                              "access to the registry repo (or the environment is missing)")
    return NETWORK_UNKNOWN, (f"secrets public-key read returned {sstatus} — "
                             "not a credential verdict")


def _expiry(headers, now=None):
    """(raw_header_value, days_left|None) from the fine-grained-PAT expiry header. Best-effort:
    an absent/unparseable header degrades to None — expiry inspection must never break the
    verdict path."""
    raw = (headers or {}).get(EXPIRY_HEADER)
    if not raw:
        return None, None
    parsed = None
    try:
        # Recorded shape: "2026-08-01 04:33:41 UTC"
        parsed = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return raw, None
    now = now or datetime.now(timezone.utc)
    return raw, round((parsed - now).total_seconds() / 86400, 1)


def _malformed(token):
    """True when the token cannot travel in an HTTP header: any control/whitespace byte or
    non-ASCII. Checked BEFORE any request is built, because http.client's rejection is a
    ValueError whose message embeds the complete header value — i.e. the secret."""
    return not token.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in token)


def probe(token, repo, fetch=_get, write=_secret_write, now=None):
    """Full probe -> {"verdict", "detail", "expires_at", "days_left"}. Staged: the env
    public-key read only runs after a 200 /user, the NON-MUTATING repo-scope secrets listing
    (round-3 finding: onboarding still needs repo Secrets: read) only after a 200 env read, and
    the canary WRITE only after BOTH reads answered 200 (no writes on a token already known
    dead, denied, or throttled). An absent or malformed secret IS the alert-worthy condition
    set-up-account's preflight fails on — verdict invalid, zero requests. A valid PAT within
    EXPIRY_WARN_DAYS of its calendar expiry downgrades to expiring-soon so the rolling alert
    (not just a log line) pages ahead of the break; an under-scoped PAT stays
    insufficient-scope regardless of expiry (broken now beats broken soon)."""
    if not token:
        return {"verdict": INVALID,
                "detail": "REGISTRY_SECRETS_PAT is not set (or empty) on the registry repo",
                "expires_at": None, "days_left": None}
    if _malformed(token):
        return {"verdict": INVALID,
                "detail": ("REGISTRY_SECRETS_PAT contains whitespace/control or non-ASCII "
                           "characters — malformed, cannot be sent as a credential "
                           "(value withheld)"),
                "expires_at": None, "days_left": None}
    user = fetch(f"{API}/user", token)
    secrets = repo_read = written = None
    if user.get("status") == 200:
        secrets = fetch(
            f"{API}/repos/{repo}/environments/{CANARY_ENV}/secrets/public-key", token)
        if secrets.get("status") == 200:
            repo_read = fetch(f"{API}/repos/{repo}/actions/secrets?per_page=1", token)
            if repo_read.get("status") == 200:
                written = write(token, repo)
    verdict, detail = classify(user, secrets, repo_read, written)
    expires_at, days_left = _expiry(user.get("headers"), now)
    if verdict == VALID and days_left is not None and days_left <= EXPIRY_WARN_DAYS:
        verdict = EXPIRING
        detail = (f"the PAT still authenticates and writes the canary secret, but its "
                  f"calendar expiry is ~{days_left} days away — rotate it before onboarding "
                  "breaks")
    return {"verdict": verdict, "detail": detail,
            "expires_at": expires_at, "days_left": days_left}


def render_alert(result, repo, redact=False):
    """The rolling credential-alert body. `redact=True` (sol-audit issue #204) is the PUBLIC-registry
    fallback: no verified private ALERT_REPO+ALERT_TOKEN route exists, so the body carries ONLY a
    generic "needs attention" signal — NO verdict, NO free-text detail, and NO calendar expiry,
    because a public issue must never publish credential validity or lifecycle. The full verdict is
    emitted only over the verified private route."""
    if redact:
        return "\n".join([
            "> 🤖 SPARQ agent — scheduled REGISTRY_SECRETS_PAT validity check (issue #37).\n",
            "⚠️ **`REGISTRY_SECRETS_PAT` needs maintainer attention.**\n",
            "The specific verdict, diagnostic detail, and the token's calendar expiry are "
            "SUPPRESSED here because this alert landed on the **public** registry repo — a public "
            "issue must never publish credential validity or lifecycle. To receive the full "
            "verdict privately, configure a private `ALERT_REPO` together with an `ALERT_TOKEN` "
            "secret that can write to it (the private route is used only when BOTH are set).\n",
            f"This PAT is what `set-up-account` and the worker rotation write-back use to run "
            f"`gh secret set` on `{repo}`; while it needs attention, account onboarding and "
            "credential write-back are at risk. This issue updates itself on the weekly probe and "
            "closes automatically once the PAT passes.",
        ])
    if result["verdict"] == EXPIRING:
        impact = (f"This PAT is what `set-up-account` and the worker rotation write-back use to "
                  f"run `gh secret set` on `{repo}`. It still works **today**, but once the "
                  f"calendar expiry lands, onboarding and credential write-back fail at exactly "
                  f"the moment someone is waiting on them — rotate now, ahead of the break.\n")
    else:
        impact = (f"This PAT is what `set-up-account` and the worker rotation write-back use to "
                  f"run `gh secret set` on `{repo}`; while it is broken, account onboarding and "
                  f"credential write-back fail at exactly the moment someone is waiting on "
                  f"them.\n")
    lines = ["> 🤖 SPARQ agent — scheduled REGISTRY_SECRETS_PAT validity check (issue #37).\n",
             f"**Verdict: `{result['verdict']}`** — {result['detail']}\n",
             impact]
    if result.get("expires_at"):
        lines.append(f"Token expiry (from the API's expiration header): {result['expires_at']}\n")
    # LEAST PRIVILEGE (sol review round 4 of #275): post-cutover the PAT only LISTs/GETs
    # repo-scope secrets (onboarding's both-scopes absence probe) and WRITEs environment
    # secrets, so the grant set is repository Secrets: READ + Environments: READ AND WRITE
    # (the env public-key read sits under Environments: read) — never Secrets: write.
    lines.append(f"**Fix:** mint a fine-grained PAT with repository **Secrets: read** AND "
                 f"**Environments: read and write** on `{repo}` — least privilege: the pipeline "
                 f"only lists/reads repo-scope secrets and writes environment secrets "
                 f"(env-secret endpoints sit under the 'Environments' permission; its read half "
                 f"covers the public-key read). Then "
                 f"`gh secret set REGISTRY_SECRETS_PAT -R {repo} --env {CANARY_ENV}` (paste at "
                 "the prompt — never as a visible argument; the environment is its canonical "
                 "home post-#101, repo scope must stay empty). This issue updates itself on the "
                 "weekly probe and closes automatically once the PAT passes.")
    return "\n".join(lines)


def _alert_route(alert_repo, alert_token, registry_repo, confirmed_private=None):
    """(repo, token, redact) for the CREDENTIAL alert (sol-audit issue #204; hardened in review
    round 1 of #432). The DETAILED body — the verdict, the free-text detail, and the token's
    calendar expiry — is emitted ONLY over a POSITIVELY VERIFIED private route: ALERT_REPO and
    ALERT_TOKEN both set, ALERT_REPO distinct from the public registry repo (case-insensitive —
    a "private route" naming the registry itself IS the public repo), AND the destination
    CONFIRMED private by a live GET /repos/{ALERT_REPO} under ALERT_TOKEN. Configuration alone
    (two non-empty strings) is NOT verification: it would fail OPEN on a same-repo or public
    ALERT_REPO. EVERY other shape — unconfigured, half-configured, same-repo, public, or a
    failed/indeterminate visibility lookup — falls back to the public registry with redact=True:
    a generic "needs attention" signal carrying no verdict, no detail, and no expiry, because a
    public issue must never publish credential validity or lifecycle. token=None means "use the
    ambient GH_TOKEN". The probe-unavailable page (issue #207) and the streak variable carry NO
    validity/expiry, so they stay on the registry with the ambient token — this route governs
    only the credential alert. `confirmed_private` is injectable for the self-test; the default
    performs the live lookup, and it is only consulted once both halves of the route are set (a
    half-configured route needs no API call to be rejected)."""
    if alert_repo and alert_token:
        same_repo = alert_repo.strip().lower() == (registry_repo or "").strip().lower()
        check = confirmed_private if confirmed_private is not None else _confirmed_private
        if not same_repo and check(alert_repo, alert_token):
            return alert_repo, alert_token, False
    return registry_repo, None, True


def _gh(args, check=False, token=None):
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    result = subprocess.run(["gh"] + args, capture_output=True, text=True, env=env)
    if check and result.returncode != 0:
        # RAISES, not warns (review r2 #2): a warned-and-swallowed write failure let a failed
        # `issue create` exit green with no alert at all. Sanitized like usage-alert.py: op +
        # returncode only — gh stderr under GH_DEBUG=api can echo request bodies.
        raise AlertWriteError(f"gh {args[0]} {args[1] if len(args) > 1 else ''} "
                              f"failed (rc={result.returncode})")
    return result


def _confirmed_private(repo, token):
    """True ONLY on a definitive `"private": true` from GET /repos/{repo} read under the route
    token (sol review round 1 of #432). FAIL-CLOSED: a failed lookup, an unparseable payload, or
    anything but a literal boolean true reads as NOT private — the caller then redacts. The
    response body is never echoed (it is only parsed), so a lookup against a wrong/hostile repo
    name can put nothing in the public log."""
    listed = _gh(["api", f"repos/{repo}"], token=token)
    if listed.returncode != 0:
        return False
    try:
        payload = json.loads(listed.stdout or "")
    except ValueError:
        return False
    return isinstance(payload, dict) and payload.get("private") is True


def _find_alert(repo, title=ALERT_TITLE, token=None):
    """(number, STATE) of a rolling `from:agent` alert issue by EXACT `title` across ALL
    states — the closed one must be found too, so recovery-then-relapse REOPENS instead of
    duplicating (the credential alert and the probe-unavailable page (issue #207) both roll this
    way). Authoritative: the PAGINATED Issues REST API (no fixed --limit window an old closed
    alert could age out of; the Search API is eventually consistent, so not it either). A failed
    or unparseable lookup raises AlertLookupError — 'lookup failed' must never degrade into 'not
    found'. `token` selects the alert route (None -> ambient GH_TOKEN); the credential lookup runs
    on the private ALERT_REPO when one is configured (issue #204)."""
    listed = _gh(["api", "--paginate", "--slurp",
                  f"repos/{repo}/issues?state=all"
                  f"&labels={urllib.parse.quote(ALERT_LABEL, safe='')}&per_page=100"], token=token)
    if listed.returncode != 0:
        raise AlertLookupError(f"rolling-alert lookup failed (gh api rc={listed.returncode})")
    try:
        pages = json.loads(listed.stdout or "[]")
    except ValueError as exc:
        raise AlertLookupError("rolling-alert lookup returned unparseable JSON") from exc
    for item in (entry for page in pages for entry in page):
        # The Issues listing endpoint interleaves PRs — a PR sharing the title must not match.
        if item.get("title") == title and "pull_request" not in item:
            return item["number"], str(item.get("state", "")).upper()
    return None, None


def upsert_alert(verdict, body, repo, token=None, redact=False):
    """Idempotent rolling-issue upsert; returns the ops that SUCCEEDED (self-tested).
    network-unknown performs NO writes at all: it must not false-alarm, and it must not close an
    existing alert either — an unreachable API is not evidence of recovery. A failed lookup
    propagates AlertLookupError before any write; a failed write propagates AlertWriteError
    (every write runs under _gh(check=True)), skipping any later ops — so `ops` never claims a
    write that didn't land. expiring-soon alerts like a bad verdict (the whole point of the
    expiry probe is a page BEFORE the break) but main() keeps the run green when the page
    lands. `token`/`repo` select the alert route (issue #204: the credential alert goes to the
    private ALERT_REPO when configured); `redact` is True on the PUBLIC-registry fallback, where
    even the recovery comment must stay generic — it must not confirm the PAT is valid again."""
    if verdict == NETWORK_UNKNOWN:
        return []
    number, state = _find_alert(repo, token=token)
    ops = []
    if verdict in (INVALID, INSUFFICIENT, EXPIRING):
        if number is None:
            _gh(["issue", "create", "-R", repo, "--title", ALERT_TITLE,
                 "--label", ALERT_LABEL, "--body", body], check=True, token=token)
            ops.append("create")
        else:
            if state != "OPEN":
                _gh(["issue", "reopen", str(number), "-R", repo], check=True, token=token)
                ops.append("reopen")
            _gh(["issue", "edit", str(number), "-R", repo, "--body", body], check=True, token=token)
            ops.append("edit")
    elif number is not None and state == "OPEN":  # valid -> recovery
        recovery = ("✅ Recovered — REGISTRY_SECRETS_PAT no longer needs attention. Auto-closing."
                    if redact else
                    "✅ Recovered — the PAT authenticates and the canary secret write succeeds. "
                    "Auto-closing.")
        _gh(["issue", "comment", str(number), "-R", repo, "--body", recovery],
            check=True, token=token)
        _gh(["issue", "close", str(number), "-R", repo], check=True, token=token)
        ops += ["comment", "close"]
    return ops


def _read_streak(repo):
    """The persisted consecutive-unknown count from the STREAK_VAR repository variable. A 404
    means the variable has never been written -> 0 (the one benign miss). ANY other failure —
    network, auth, an unparseable response, a non-numeric value — raises AlertLookupError:
    degrading a failed read to 0 would hold the streak below threshold forever and permanently
    silence the very page this state exists to trigger."""
    result = _gh(["api", f"repos/{repo}/actions/variables/{STREAK_VAR}"])
    try:
        payload = json.loads(result.stdout or "")
    except ValueError:
        payload = None
    if result.returncode != 0:
        # gh api relays the server's JSON error body on stdout; only a definitive 404 (variable
        # never created) may read as zero.
        if isinstance(payload, dict) and str(payload.get("status")) == "404":
            return 0
        raise AlertLookupError(
            f"probe-streak variable read failed (gh api rc={result.returncode})")
    value = payload.get("value") if isinstance(payload, dict) else None
    if not (isinstance(value, str) and value.strip().isdigit()):
        raise AlertLookupError("probe-streak variable holds a non-numeric value")
    return int(value.strip())


def _write_streak(repo, streak):
    """Persist the consecutive-unknown count. `gh variable set` upserts (creates on the first
    write). This write is SILENT — a repository variable notifies nobody and appears in no
    issue/alert view — which is the whole reason the counter lives here and not in an issue:
    GitHub creates every issue OPEN, so an issue-body counter pages on its own creation."""
    _gh(["variable", "set", STREAK_VAR, "-R", repo, "--body", str(streak)], check=True)


def render_probe_alert(streak, threshold, repo):
    """Body for the probe-unavailable alert (issue #207): a human explanation that this is a
    PROBE-health page, NOT a credential verdict — the PAT is explicitly not reclassified. Only
    rendered at/above the page threshold; the authoritative counter is the STREAK_VAR repository
    variable, never this body."""
    return "\n".join([
        "> 🤖 SPARQ agent — scheduled REGISTRY_SECRETS_PAT validity check "
        "(issue #37; probe health #207).\n",
        f"The weekly validity probe has returned **network-unknown for {streak} consecutive "
        f"run(s)** (page threshold: {threshold}). `network-unknown` means the probe could reach "
        f"NO verdict at all — an unreachable/throttled GitHub API, a `gh` status-parse drift, or a "
        f"persistent runner proxy/egress failure. It is therefore **not** evidence that the PAT is "
        f"invalid, and the credential has deliberately NOT been reclassified.\n",
        f"**Why this pages:** while the probe cannot complete, `REGISTRY_SECRETS_PAT` on `{repo}` "
        f"goes UNVERIFIED — a rotation or calendar expiry in the meantime would surface only when "
        f"`set-up-account` or the rotation write-back next runs `gh secret set` (the just-in-time "
        f"failure issue #37 exists to prevent). Any open credential alert is also STALE: it has "
        f"not been re-checked since verification stalled.\n",
        f"**What to check:** the latest `pat-validity` workflow run's `detail` field, "
        f"[GitHub status](https://www.githubstatus.com/), and any self-hosted-runner proxy/egress "
        f"problem. This issue updates itself on the weekly probe and closes automatically once the "
        f"probe reaches ANY definitive verdict again.",
    ])


def upsert_probe_alert(verdict, repo, threshold=UNKNOWN_STREAK_THRESHOLD):
    """Rolling 'probe unavailable' alert for CONSECUTIVE network-unknown verdicts (issue #207),
    kept DISTINCT from the credential alert and never reclassifying the PAT. Returns
    {"ops", "streak", "paging"} (self-tested). The counter is the STREAK_VAR repository variable
    (silent writes); the issue is created/reopened ONLY once the streak reaches `threshold` —
    that is the page. Below the threshold NO issue operation happens: GitHub creates every issue
    OPEN, so even a created-then-closed counter would notify subscribers and flash in open-alert
    views — a false page on a single transient blip, and one an output-parse failure between the
    create and the close would leave stranded open. ANY definitive verdict proves the probe
    itself completed, so it zeroes the variable and closes an open page. Lookup/write failures
    propagate (AlertLookupError/AlertWriteError) exactly like upsert_alert — a swallowed failure
    here would re-hide the very stall this alert exists to surface."""
    if verdict != NETWORK_UNKNOWN:
        # The probe reached a real verdict -> the consecutive-unknown streak is broken.
        ops = []
        number, state = _find_alert(repo, PROBE_ALERT_TITLE)
        if number is not None and state == "OPEN":
            _gh(["issue", "comment", str(number), "-R", repo, "--body",
                 "✅ The validity probe reached a definitive verdict again — verification has "
                 "resumed. Auto-closing (this is probe health, not a credential recovery)."],
                check=True)
            _gh(["issue", "close", str(number), "-R", repo], check=True)
            ops += ["comment", "close"]
        if _read_streak(repo) != 0:
            # Zero the counter so a future unknown restarts from 1, not from the stale streak
            # (which would re-cross the threshold and re-page after a single unknown).
            _write_streak(repo, 0)
            ops.append("reset-streak")
        return {"ops": ops, "streak": 0, "paging": False}
    # network-unknown: extend the streak, then page only once it crosses the threshold. The
    # count is persisted BEFORE any issue work: it is silent state, and if a later issue write
    # fails red, the outage run still counted — the next unknown resumes instead of undercounting.
    streak = _read_streak(repo) + 1
    paging = streak >= threshold
    _write_streak(repo, streak)
    ops = ["set-streak"]
    number, state = _find_alert(repo, PROBE_ALERT_TITLE)
    if paging:
        new_body = render_probe_alert(streak, threshold, repo)
        if number is None:
            _gh(["issue", "create", "-R", repo, "--title", PROBE_ALERT_TITLE,
                 "--label", ALERT_LABEL, "--body", new_body], check=True)
            ops.append("create")  # left OPEN — the create IS the page
        else:
            if state != "OPEN":
                _gh(["issue", "reopen", str(number), "-R", repo], check=True)
                ops.append("reopen")
            _gh(["issue", "edit", str(number), "-R", repo, "--body", new_body], check=True)
            ops.append("edit")
    elif number is not None and state == "OPEN":
        # Defensive: a below-threshold streak must never keep a page open (a raised threshold or
        # a manual reopen) — closing is a SILENCING op, the one issue write allowed sub-threshold.
        _gh(["issue", "close", str(number), "-R", repo], check=True)
        ops.append("close")
    return {"ops": ops, "streak": streak, "paging": paging}


def main(argv):
    probe_only = "--probe-only" in argv
    repo = os.environ.get("REGISTRY_REPO") or os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        print("::error::pat-validity: REGISTRY_REPO/GITHUB_REPOSITORY not set")
        return 2
    result = probe(os.environ.get("REGISTRY_PAT"), repo)
    # PUBLIC-LOG REDACTION (sol review round 1 of #432): this stdout is the PUBLIC registry
    # repo's workflow log WHATEVER the alert route, so it must never carry the verdict, the
    # free-text detail, or the calendar expiry / days-left — exactly the fields issue #204
    # suppresses from public issues. Only a coarse status prints; the full verdict travels
    # solely in the alert issue (private route when configured, generic public signal
    # otherwise). GITHUB_OUTPUT is the runner-internal outputs file — rendered nowhere unless a
    # later step deliberately echoes it (none does) — so it keeps the exact verdict for
    # workflow-internal automation.
    public_status = {VALID: "ok", NETWORK_UNKNOWN: "unknown"}.get(
        result["verdict"], "attention-required")
    print(json.dumps({"status": public_status}))
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as handle:
            handle.write(f"verdict={result['verdict']}\n")
    if result["verdict"] in (INVALID, INSUFFICIENT, EXPIRING):
        # The ahead-of-time half of issue #37: a courtesy annotation for whoever opens the run.
        # As redacted as the rest of the public log — one generic line for EVERY
        # attention-worthy verdict, naming neither the verdict class nor any expiry countdown
        # (#432 round 1: the old EXPIRING-only branch printed days_left — credential lifecycle —
        # into the public log). The ACTIONABLE alert is the rolling issue upserted below.
        print("::warning::pat-validity: REGISTRY_SECRETS_PAT needs maintainer attention — the "
              "specific verdict, detail, and any expiry live in the rolling alert issue "
              "(private ALERT_REPO route when configured), never in this public log")
    probe_paging = False
    if not probe_only:
        # Route the DETAILED credential alert ONLY to a POSITIVELY VERIFIED private repo (#204,
        # hardened #432 round 1): distinct from the registry AND confirmed `"private": true`
        # under ALERT_TOKEN. Resolved here — not before the probe — because the verification is
        # a live API call the --probe-only path must not make. The probe-unavailable page (#207)
        # and the streak variable carry no validity/expiry, so they stay on the registry with
        # the ambient token.
        alert_repo, alert_token, redact = _alert_route(
            os.environ.get("ALERT_REPO"), os.environ.get("ALERT_TOKEN"), repo)
        if redact and result["verdict"] in (INVALID, INSUFFICIENT, EXPIRING):
            # FAIL LOUD (issue #204): a bad/expiring verdict is being alerted with the verdict/
            # detail/expiry SUPPRESSED because no verified private ALERT_REPO+ALERT_TOKEN route
            # exists. The (public) log line names neither the verdict nor the expiry — only the
            # missing route.
            print("::warning::pat-validity: no verified private ALERT_REPO+ALERT_TOKEN route — "
                  "the credential verdict/detail/expiry is SUPPRESSED; the public alert carries "
                  "a generic signal only")
        try:
            try:
                upsert_alert(result["verdict"], render_alert(result, repo, redact=redact),
                             alert_repo, token=alert_token, redact=redact)
            except (AlertLookupError, AlertWriteError) as exc:
                if redact:
                    raise
                # #432 round 1 finding 5: a VERIFIED private route whose token still fails at
                # lookup/write time (revoked since verification, lost issues scope, deleted
                # repo) must not drop the rolling credential signal — retry a SEPARATELY
                # RENDERED redacted body on the public registry under the ambient token: never
                # the detailed body, and never the private route's error beyond the sanitized
                # op + rc the exception already carries.
                print(f"::warning::pat-validity: private alert route failed ({exc}) — retrying "
                      "a generic redacted alert on the public registry")
                upsert_alert(result["verdict"], render_alert(result, repo, redact=True),
                             repo, token=None, redact=True)
            # Separately track CONSECUTIVE network-unknowns so a permanently-stalled probe pages
            # instead of staying green-and-silent (issue #207). Distinct rolling issue; never
            # reclassifies the PAT. Shares the fail-red-on-failure contract above. This page carries
            # no validity/expiry, so it stays on the registry with the ambient token (issue #204).
            probe_paging = upsert_probe_alert(result["verdict"], repo)["paging"]
        except (AlertLookupError, AlertWriteError) as exc:
            # Fail red WITHOUT pretending the alert landed: creating blind on a failed lookup is
            # how the rolling issue gets duplicated, and a swallowed write failure pages nobody.
            # Both messages are sanitized at raise time (op + rc only, never gh stderr).
            print(f"::error::pat-validity: {exc} — alert not (fully) written")
            return 1
    # Red run on a definitive bad verdict (so the scheduled run itself signals), green on
    # valid AND a transient network-unknown (no false alarms). expiring-soon stays green too —
    # secret writes still succeed today; the page is the rolling issue, not a failed run. A
    # PERSISTENT unknown that has crossed the probe-unavailable threshold DOES go red: at that
    # point the probe stalling IS the signal, and a green run would keep hiding it.
    return 1 if result["verdict"] in (INVALID, INSUFFICIENT) or probe_paging else 0


def _self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got} (want {want})")

    SENTINEL = "github_pat_SENTINEL_NEVER_PRINTED"
    # Recorded-shape fixtures: status + lowercased headers exactly as _get returns them.
    U_OK = {"status": 200, "headers": {EXPIRY_HEADER: "2026-08-01 04:33:41 UTC",
                                       "x-github-request-id": "F00:BA4"}}
    U_OK_NOEXP = {"status": 200, "headers": {"x-github-request-id": "F00:BA5"}}
    U_OK_SOON = {"status": 200, "headers": {EXPIRY_HEADER: "2026-07-25 04:33:41 UTC"}}
    U_OK_EDGE = {"status": 200, "headers": {EXPIRY_HEADER: "2026-07-31 04:33:41 UTC"}}
    U_401 = {"status": 401, "headers": {"content-type": "application/json; charset=utf-8"}}
    U_403 = {"status": 403, "headers": {"retry-after": "60"}}
    S_OK = {"status": 200, "headers": {"content-type": "application/json; charset=utf-8"}}
    # The repo-scope secrets LISTING probe (round-3 finding) shares _get()'s response shape, so
    # the S_403* / S_404 / S_502 fixtures double as repo-read fixtures below.
    R_OK = {"status": 200, "headers": {"x-ratelimit-remaining": "55"}}
    S_403 = {"status": 403, "headers": {"content-type": "application/json; charset=utf-8"}}
    # GitHub answers 403 for rate limits too. Primary: x-ratelimit-remaining 0. Secondary:
    # usually retry-after — but a secondary 403 can carry NONZERO remaining quota and NO
    # retry-after (review r2 #1), where the DOCUMENTED discriminator is the error message.
    SECONDARY_MSG = ("You have exceeded a secondary rate limit. "
                     "Please wait a few minutes before you retry your request.")
    S_403_LIMIT = {"status": 403, "headers": {"x-ratelimit-remaining": "0",
                                              "x-ratelimit-reset": "1752817000"}}
    S_403_RETRY = {"status": 403, "headers": {"retry-after": "60"}}
    S_403_SECONDARY = {"status": 403, "headers": {"x-ratelimit-remaining": "42"},
                       "message": SECONDARY_MSG}
    S_403_ABUSE = {"status": 403, "headers": {"x-ratelimit-remaining": "42"},
                   "message": "You have triggered an abuse detection mechanism."}
    S_403_DENIED = {"status": 403, "headers": {"x-ratelimit-remaining": "42"},
                    "message": "Resource not accessible by personal access token"}
    S_404 = {"status": 404, "headers": {"content-type": "application/json; charset=utf-8"}}
    S_502 = {"status": 502, "headers": {}}
    NET_FAIL = {"status": None, "error": "TimeoutError"}
    # Write-probe fixtures in _secret_write's response shape: status parsed from gh stderr,
    # NO headers (gh doesn't expose them), message = retained stderr.
    W_OK = {"status": 204, "headers": {}, "message": ""}
    W_CREATED = {"status": 201, "headers": {}, "message": ""}
    W_401 = {"status": 401, "headers": {},
             "message": "HTTP 401: Bad credentials (https://api.github.com/...)"}
    W_DENIED = {"status": 403, "headers": {},
                "message": ("HTTP 403: Resource not accessible by personal access token "
                            "(https://api.github.com/repos/o/r/actions/secrets/...)")}
    W_404 = {"status": 404, "headers": {},
             "message": "HTTP 404: Not Found (https://api.github.com/...)"}
    W_PRIMARY = {"status": 403, "headers": {},
                 "message": "HTTP 403: API rate limit exceeded for user ID 1."}
    W_SECONDARY = {"status": 403, "headers": {}, "message": f"HTTP 403: {SECONDARY_MSG}"}
    W_NET = {"status": None, "error": "gh secret set rc=4, no HTTP status"}

    # --- classify: every verdict path, fail-closed edges included. `valid` REQUIRES the
    # repo-scope secrets listing (round 3: onboarding's both-scopes absence probe needs repo
    # Secrets: read) AND the canary write (review r3 #1): the public-key GET needs only
    # Environments: read, so read-success alone must never be declared healthy.
    chk("valid: reads 200 + canary write 204", classify(U_OK, S_OK, R_OK, W_OK)[0], VALID)
    chk("valid: a first-ever canary write answers 201",
        classify(U_OK, S_OK, R_OK, W_CREATED)[0], VALID)
    chk("READ-ONLY PAT: reads 200 + write 403 denial -> insufficient (the review r3 #1 false "
        "positive)", classify(U_OK, S_OK, R_OK, W_DENIED)[0], INSUFFICIENT)
    chk("reads 200 + write 404 -> insufficient",
        classify(U_OK, S_OK, R_OK, W_404)[0], INSUFFICIENT)
    chk("reads 200 + write 401 -> invalid (died mid-probe)",
        classify(U_OK, S_OK, R_OK, W_401)[0], INVALID)
    chk("network-unknown: write 403 with the primary-limit message is NOT scope",
        classify(U_OK, S_OK, R_OK, W_PRIMARY)[0], NETWORK_UNKNOWN)
    chk("network-unknown: write 403 with the secondary-limit message is NOT scope",
        classify(U_OK, S_OK, R_OK, W_SECONDARY)[0], NETWORK_UNKNOWN)
    chk("network-unknown: write never completed — read success alone is NEVER valid",
        classify(U_OK, S_OK, R_OK, W_NET)[0], NETWORK_UNKNOWN)
    chk("network-unknown: write result absent entirely — read success alone is NEVER valid",
        classify(U_OK, S_OK, R_OK)[0], NETWORK_UNKNOWN)
    chk("retained gh stderr never echoes into the detail",
        "NEVER-IN-DETAIL" in classify(U_OK, S_OK, R_OK,
                                      {"status": 403, "headers": {},
                                       "message": "HTTP 403: NEVER-IN-DETAIL"})[1],
        False)
    # --- the round-3 repo-scope Secrets: read probe: an Environments-only PAT must be caught
    # by the weekly probe, not by a failed-closed onboarding.
    chk("ENV-ONLY PAT: env read 200 + repo listing 403 denial -> insufficient (the round-3 "
        "onboarding gap)", classify(U_OK, S_OK, S_403_DENIED, W_OK)[0], INSUFFICIENT)
    chk("env-only PAT detail names the onboarding absence probe",
        "both-scopes absence probe" in classify(U_OK, S_OK, S_403, W_OK)[1], True)
    chk("repo listing 404 (no repo access for Secrets) -> insufficient",
        classify(U_OK, S_OK, S_404, W_OK)[0], INSUFFICIENT)
    chk("repo listing 401 -> invalid (died mid-probe)",
        classify(U_OK, S_OK, U_401, W_OK)[0], INVALID)
    chk("network-unknown: repo listing 403 + x-ratelimit-remaining 0 is a rate limit, NOT scope",
        classify(U_OK, S_OK, S_403_LIMIT, W_OK)[0], NETWORK_UNKNOWN)
    chk("network-unknown: repo listing secondary-limit 403 (message discriminator) is NOT scope",
        classify(U_OK, S_OK, S_403_SECONDARY, W_OK)[0], NETWORK_UNKNOWN)
    chk("network-unknown: repo listing 5xx", classify(U_OK, S_OK, S_502, W_OK)[0],
        NETWORK_UNKNOWN)
    chk("network-unknown: repo listing timeout", classify(U_OK, S_OK, NET_FAIL, W_OK)[0],
        NETWORK_UNKNOWN)
    chk("network-unknown: repo listing absent entirely — env read alone is NEVER valid",
        classify(U_OK, S_OK)[0], NETWORK_UNKNOWN)
    chk("invalid: /user 401", classify(U_401, None)[0], INVALID)
    chk("invalid: secrets 401 (died mid-probe)", classify(U_OK, U_401)[0], INVALID)
    chk("insufficient: secrets 403", classify(U_OK, S_403)[0], INSUFFICIENT)
    chk("insufficient: secrets 404 (no repo access)", classify(U_OK, S_404)[0], INSUFFICIENT)
    chk("network-unknown: secrets 403 + x-ratelimit-remaining 0 is a rate limit, NOT scope",
        classify(U_OK, S_403_LIMIT)[0], NETWORK_UNKNOWN)
    chk("network-unknown: secrets 403 + retry-after (secondary limit) is NOT scope",
        classify(U_OK, S_403_RETRY)[0], NETWORK_UNKNOWN)
    chk("network-unknown: secondary-limit 403 with NONZERO remaining + no retry-after — the "
        "documented discriminator is the error message (review r2 #1)",
        classify(U_OK, S_403_SECONDARY)[0], NETWORK_UNKNOWN)
    chk("network-unknown: legacy abuse-detection message is a secondary limit too",
        classify(U_OK, S_403_ABUSE)[0], NETWORK_UNKNOWN)
    chk("insufficient: 403 with budget left AND a denial-shaped message is a real denial",
        classify(U_OK, S_403_DENIED)[0], INSUFFICIENT)
    chk("network-unknown: /user timeout", classify(NET_FAIL, None)[0], NETWORK_UNKNOWN)
    chk("network-unknown: /user 403 throttle-shaped is NOT invalid",
        classify(U_403, None)[0], NETWORK_UNKNOWN)
    chk("network-unknown: secrets 5xx", classify(U_OK, S_502)[0], NETWORK_UNKNOWN)
    chk("network-unknown: secrets timeout", classify(U_OK, NET_FAIL)[0], NETWORK_UNKNOWN)

    # --- probe orchestration: fetch/write order, short-circuit, expiry, redaction.
    fetched = []
    writes = []

    def fake_fetch(responses):
        def fetch(url, token):
            chk_token_holder.append(token)
            fetched.append(url)
            return responses[len(fetched) - 1]
        return fetch

    def fake_write(resp):
        def wr(token, repo):
            chk_token_holder.append(token)
            writes.append(repo)
            return resp
        return wr

    chk_token_holder = []
    now = datetime(2026, 7, 17, 4, 33, 41, tzinfo=timezone.utc)
    r = probe(SENTINEL, "o/r", fetch=fake_fetch([U_OK, S_OK, R_OK]), write=fake_write(W_OK),
              now=now)
    chk("probe valid end-to-end (both reads AND canary write)", r["verdict"], VALID)
    chk("probe hits /user, the ENV public-key read, the NON-MUTATING repo-scope secrets "
        "listing, then the canary write",
        (fetched, writes),
        ([f"{API}/user",
          f"{API}/repos/o/r/environments/{CANARY_ENV}/secrets/public-key",
          f"{API}/repos/o/r/actions/secrets?per_page=1"], ["o/r"]))
    chk("expiry header inspected (15 days out)", r["days_left"], 15.0)
    fetched.clear(), writes.clear()
    r_ro = probe(SENTINEL, "o/r", fetch=fake_fetch([U_OK, S_OK, R_OK]),
                 write=fake_write(W_DENIED), now=now)
    chk("probe read-only PAT end-to-end -> insufficient (review r3 #1)",
        r_ro["verdict"], INSUFFICIENT)
    fetched.clear(), writes.clear()
    r401 = probe(SENTINEL, "o/r", fetch=fake_fetch([U_401]), write=fake_write(W_OK), now=now)
    chk("probe 401 short-circuits (no secrets reads, no write, on a dead token)",
        (r401["verdict"], fetched, writes), (INVALID, [f"{API}/user"], []))
    fetched.clear(), writes.clear()
    r_noread = probe(SENTINEL, "o/r", fetch=fake_fetch([U_OK, S_403]), write=fake_write(W_OK),
                     now=now)
    chk("denied env read never attempts the repo listing or the write (no canary churn on a "
        "broken PAT)",
        (r_noread["verdict"], len(fetched), writes), (INSUFFICIENT, 2, []))
    fetched.clear(), writes.clear()
    r_norepo = probe(SENTINEL, "o/r", fetch=fake_fetch([U_OK, S_OK, S_403_DENIED]),
                     write=fake_write(W_OK), now=now)
    chk("denied repo-scope listing -> insufficient AND never attempts the write (round-3 "
        "onboarding gap, staged short-circuit)",
        (r_norepo["verdict"], len(fetched), writes), (INSUFFICIENT, 3, []))
    fetched.clear(), writes.clear()
    rmiss = probe("", "o/r", fetch=fake_fetch([]), write=fake_write(W_OK))
    chk("absent secret -> invalid, zero fetches, zero writes",
        (rmiss["verdict"], fetched, writes), (INVALID, [], []))
    # Near-expiry transitions (review r1 #5): the 15-day probe above stays VALID (just above
    # the 14-day threshold); at and below it the verdict downgrades to expiring-soon so
    # upsert_alert pages via the rolling issue instead of a green-run log line.
    fetched.clear(), writes.clear()
    r_soon = probe(SENTINEL, "o/r", fetch=fake_fetch([U_OK_SOON, S_OK, R_OK]),
                   write=fake_write(W_OK), now=now)
    chk("8 days out -> expiring-soon", (r_soon["verdict"], r_soon["days_left"]), (EXPIRING, 8.0))
    fetched.clear(), writes.clear()
    r_edge = probe(SENTINEL, "o/r", fetch=fake_fetch([U_OK_EDGE, S_OK, R_OK]),
                   write=fake_write(W_OK), now=now)
    chk("exactly 14.0 days -> expiring-soon (boundary inclusive)", r_edge["verdict"], EXPIRING)
    fetched.clear(), writes.clear()
    r_ro_soon = probe(SENTINEL, "o/r", fetch=fake_fetch([U_OK_SOON, S_OK, R_OK]),
                      write=fake_write(W_DENIED), now=now)
    chk("read-only trumps near-expiry (broken now beats broken soon)",
        r_ro_soon["verdict"], INSUFFICIENT)
    # A header-injecting token is rejected BEFORE any request is built (review r1 #3):
    # http.client would otherwise raise a ValueError embedding the complete credential.
    fetched.clear(), writes.clear()
    rbad = probe(f"github_pat_{SENTINEL}\r\nX-Inject: 1", "o/r", fetch=fake_fetch([]),
                 write=fake_write(W_OK))
    chk("CR/LF token -> invalid, zero fetches, zero writes (never enters a header)",
        (rbad["verdict"], fetched, writes), (INVALID, [], []))
    # Redaction: the verdict JSON and the alert body must never carry the token.
    chk("verdict JSON never contains the token",
        SENTINEL in json.dumps(r) + json.dumps(r_ro) + json.dumps(r401) + json.dumps(r_norepo)
        + json.dumps(rmiss) + json.dumps(r_soon) + json.dumps(rbad), False)
    chk("alert body never contains the token",
        SENTINEL in render_alert(r401, "o/r") + render_alert(rmiss, "o/r")
        + render_alert(r_ro, "o/r") + render_alert(r_soon, "o/r") + render_alert(rbad, "o/r"),
        False)
    # Round-4 finding 2: the remediation must name the LEAST-PRIVILEGE grant set — repository
    # Secrets: read (never write) + Environments: read and write — or an operator following the
    # alert re-mints an over-privileged PAT.
    fix_body = render_alert(r_ro, "o/r")
    chk("alert Fix line names the least-privilege grants (repo Secrets: read, env read+write)",
        ("**Secrets: read**" in fix_body,
         "**Environments: read and write**" in fix_body,
         "Secrets: read and write" in fix_body),
        (True, True, False))
    chk("fetch AND write probes received the token (probe is non-vacuous)",
        all(t == SENTINEL for t in chk_token_holder) and len(chk_token_holder) == 26, True)

    # --- expiry parsing edges.
    chk("iso expiry parses", _expiry({EXPIRY_HEADER: "2026-07-18T04:33:41Z"}, now)[1], 1.0)
    chk("garbage expiry degrades to (raw, None)",
        _expiry({EXPIRY_HEADER: "soonish"}, now), ("soonish", None))
    chk("absent expiry -> (None, None)", _expiry({}, now), (None, None))

    # --- leak-proofing under failure (review r1 #3).
    import contextlib
    import io

    real_urlopen = urllib.request.urlopen

    def _boom(*_a, **_kw):  # the exact shape http.client raises for a bad header value
        raise ValueError(f"Invalid header value b'Bearer {SENTINEL}\\r\\n'")
    urllib.request.urlopen = _boom
    try:
        leaked = _get(f"{API}/user", SENTINEL)
    finally:
        urllib.request.urlopen = real_urlopen
    chk("_get reduces header-serialization ValueError to its class name",
        leaked, {"status": None, "error": "ValueError"})
    # _get must actually RETAIN the error-body message (review r2 #1) — otherwise the
    # secondary-limit fixtures above test a field the live path never populates.
    import email.message

    def _http_secondary(*_a, **_kw):
        hdrs = email.message.Message()
        hdrs["X-RateLimit-Remaining"] = "42"
        raise urllib.error.HTTPError(
            f"{API}/x", 403, "Forbidden", hdrs,
            io.BytesIO(json.dumps({"message": SECONDARY_MSG,
                                   "documentation_url": "https://docs.github.com"}).encode()))
    urllib.request.urlopen = _http_secondary
    try:
        got = _get(f"{API}/user", SENTINEL)
    finally:
        urllib.request.urlopen = real_urlopen
    chk("_get keeps status, lowercased headers AND the error-body message",
        (got["status"], got["headers"].get("x-ratelimit-remaining"),
         "secondary rate limit" in got["message"]), (403, "42", True))
    chk("_get end-to-end: a bare-budget secondary-limit 403 classifies network-unknown",
        classify(U_OK, got)[0], NETWORK_UNKNOWN)
    chk("_body_message: non-JSON body degrades to empty", _body_message("<html>oops"), "")
    chk("_body_message: non-dict JSON degrades to empty", _body_message("[1, 2]"), "")
    # End-to-end: main() with a CR/LF token must go red WITHOUT the token on stdout/stderr
    # (uncaught tracebacks land on stderr — capture both).
    saved_env = {k: os.environ.get(k) for k in ("REGISTRY_PAT", "REGISTRY_REPO",
                                                "GITHUB_OUTPUT")}
    os.environ["REGISTRY_PAT"] = f"{SENTINEL}\r\ninjected"
    os.environ["REGISTRY_REPO"] = "o/r"
    os.environ.pop("GITHUB_OUTPUT", None)
    captured = io.StringIO()
    try:
        with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            main_rc = main(["--probe-only"])
    finally:
        for key, val in saved_env.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
    chk("main() with CR/LF token: rc=1 and the token never reaches stdout/stderr",
        (main_rc, SENTINEL in captured.getvalue()), (1, False))

    # --- _secret_write: parses gh's exit into the response shape classify() consumes, and
    # authenticates the child with ONLY the probed PAT (the live half of review r3 #1).
    class _Proc:
        def __init__(self, returncode=0, stderr=""):
            self.returncode, self.stdout, self.stderr = returncode, "", stderr

    seen = {}

    def probe_run(result):
        def run(argv, **kw):
            seen["argv"], seen["kw"] = list(argv), kw
            return result
        return run

    saved_env = {k: os.environ.get(k) for k in ("GH_DEBUG", "GITHUB_TOKEN")}
    os.environ["GH_DEBUG"] = "api"  # would make gh dump auth headers to the retained stderr
    os.environ["GITHUB_TOKEN"] = "ambient-token-must-not-authenticate-the-probe"
    try:
        w_ok = _secret_write(SENTINEL, "o/r", run=probe_run(_Proc(0)))
    finally:
        for key, val in saved_env.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
    chk("_secret_write: rc 0 -> write-succeeded verdict",
        w_ok, {"status": 204, "headers": {}, "message": ""})
    chk("_secret_write: targets the ENV canary via gh (--env dispatch-secrets), value on STDIN "
        "(never argv)",
        (seen["argv"], seen["kw"].get("input")),
        (["gh", "secret", "set", CANARY_SECRET, "-R", "o/r", "--env", CANARY_ENV], CANARY_VALUE))
    env = seen["kw"].get("env") or {}
    chk("_secret_write: child env holds ONLY the probed PAT (ambient token + GH_DEBUG stripped)",
        (env.get("GH_TOKEN"), "GITHUB_TOKEN" in env, "GH_DEBUG" in env),
        (SENTINEL, False, False))
    w_denied = _secret_write(SENTINEL, "o/r", run=probe_run(_Proc(1,
        "gh: HTTP 403: Resource not accessible by personal access token (https://x)")))
    chk("_secret_write: gh 403 stderr -> status parsed, message retained for discrimination",
        (w_denied["status"], "not accessible" in w_denied["message"]), (403, True))
    chk("_secret_write end-to-end: a live-parsed read-only denial classifies insufficient",
        classify(U_OK, S_OK, R_OK, w_denied)[0], INSUFFICIENT)
    w_limit = _secret_write(SENTINEL, "o/r", run=probe_run(_Proc(1,
        f"gh: HTTP 403: {SECONDARY_MSG}")))
    chk("_secret_write end-to-end: a live-parsed throttled 403 classifies network-unknown",
        classify(U_OK, S_OK, R_OK, w_limit)[0], NETWORK_UNKNOWN)
    w_dead = _secret_write(SENTINEL, "o/r", run=probe_run(_Proc(4, "dial tcp: lookup failed")))
    chk("_secret_write: nonzero rc with NO HTTP status is inconclusive, never a verdict",
        (w_dead["status"], "error" in w_dead), (None, True))

    def raise_run(argv, **kw):
        raise OSError(f"boom {SENTINEL}")
    chk("_secret_write: runner exception reduces to its class name (never the message)",
        _secret_write(SENTINEL, "o/r", run=raise_run), {"status": None, "error": "OSError"})

    # --- upsert: idempotent rolling issue against a stubbed gh (usage-alert.py pattern).
    class _Run:
        def __init__(self, stdout="[]", returncode=0, stderr=""):
            self.returncode, self.stdout, self.stderr = returncode, stdout, stderr

    def stub_gh(list_json, list_rc=0, fail_op=None):
        calls = []

        def run(args, **_kw):
            calls.append(list(args))
            if args[1] == "api":
                return _Run(list_json, list_rc)
            if fail_op and args[2] == fail_op:
                # stderr carries a marker that must NEVER surface in the raised message.
                return _Run("", 1, stderr="gh: LEAKY-STDERR-NEVER-IN-ERRORS")
            return _Run()
        return calls, run

    # Lookup fixtures in `gh api --paginate --slurp` shape: an ARRAY OF PAGES, REST-cased.
    OPEN_HIT = json.dumps([[{"number": 7, "title": ALERT_TITLE, "state": "open"}]])
    CLOSED_HIT_P2 = json.dumps([
        [{"number": 3, "title": "some other from:agent issue", "state": "open"}],
        [{"number": 7, "title": ALERT_TITLE, "state": "closed"}]])
    # Other from:agent issues must NOT match — find is by exact title; nor may a PR that
    # shares the title (the Issues listing endpoint interleaves PRs).
    DECOYS = json.dumps([[{"number": 3, "title": "some other from:agent issue",
                           "state": "open"}]])
    PR_DECOY = json.dumps([[{"number": 9, "title": ALERT_TITLE, "state": "open",
                             "pull_request": {"url": "https://example.invalid"}}]])
    EMPTY = json.dumps([[]])
    real_run = subprocess.run
    try:
        for name, verdict, listing, want_ops in [
            ("invalid + none -> create", INVALID, EMPTY, ["create"]),
            ("invalid + decoy titles -> create (find is by exact title)",
             INVALID, DECOYS, ["create"]),
            ("invalid + same-title PR -> create (PR rows never match)",
             INVALID, PR_DECOY, ["create"]),
            ("invalid + open -> edit (no duplicate)", INVALID, OPEN_HIT, ["edit"]),
            ("insufficient + closed on page 2 -> REOPEN + edit (lookup is paginated)",
             INSUFFICIENT, CLOSED_HIT_P2, ["reopen", "edit"]),
            ("expiring + none -> create (near-expiry pages, not just a ::warning)",
             EXPIRING, EMPTY, ["create"]),
            ("expiring + open -> edit, never close", EXPIRING, OPEN_HIT, ["edit"]),
            ("expiring + closed -> REOPEN + edit", EXPIRING, CLOSED_HIT_P2,
             ["reopen", "edit"]),
            ("valid + open -> comment + close", VALID, OPEN_HIT, ["comment", "close"]),
            ("valid + none -> no-op", VALID, EMPTY, []),
        ]:
            calls, subprocess.run = stub_gh(listing)
            with contextlib.redirect_stdout(io.StringIO()):
                ops = upsert_alert(verdict, "body", "o/r")
            chk(name, ops, want_ops)
        # network-unknown must not even LIST — zero gh calls, zero writes, existing alert intact.
        calls, subprocess.run = stub_gh(OPEN_HIT)
        with contextlib.redirect_stdout(io.StringIO()):
            ops = upsert_alert(NETWORK_UNKNOWN, "body", "o/r")
        chk("network-unknown -> zero gh calls (no false alarm, no false recovery)",
            (ops, calls), ([], []))
        # A FAILED lookup must raise and write NOTHING (review r1 #4) — "lookup failed"
        # degrading into "not found" is exactly how the rolling issue gets duplicated.
        for name, listing, list_rc in [("lookup rc!=0", "", 1),
                                       ("lookup unparseable output", "gh: some error", 0)]:
            calls, subprocess.run = stub_gh(listing, list_rc)
            raised = False
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    upsert_alert(INVALID, "body", "o/r")
            except AlertLookupError:
                raised = True
            chk(f"{name} -> AlertLookupError, zero writes",
                (raised, [c for c in calls if c[1] != "api"]), (True, []))
        # A FAILED WRITE must raise AlertWriteError (review r2 #2) — pre-fix, _gh only
        # ::warning'd and upsert_alert recorded the op as done; a failed `issue create` on an
        # expiring-soon verdict exited green with no alert at all. Every write op is exercised;
        # ops AFTER the failed one must not run, and the sanitized message carries op + rc only.
        for name, verdict, listing, fail_op, want_issue_ops in [
            ("failed create raises", INVALID, EMPTY, "create", ["create"]),
            ("failed reopen raises (edit never attempted)", INVALID, CLOSED_HIT_P2,
             "reopen", ["reopen"]),
            ("failed edit raises", INVALID, OPEN_HIT, "edit", ["edit"]),
            ("failed recovery comment raises (close never attempted)", VALID, OPEN_HIT,
             "comment", ["comment"]),
            ("failed recovery close raises", VALID, OPEN_HIT, "close", ["comment", "close"]),
        ]:
            calls, subprocess.run = stub_gh(listing, fail_op=fail_op)
            raised_msg = None
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    upsert_alert(verdict, "body", "o/r")
            except AlertWriteError as exc:
                raised_msg = str(exc)
            chk(name, (raised_msg is not None,
                       [c[2] for c in calls if c[1] == "issue"]), (True, want_issue_ops))
            chk(f"  …{fail_op} message sanitized (op + rc, never gh stderr)",
                raised_msg is not None and f"gh issue {fail_op} failed (rc=1)" == raised_msg,
                True)
        # End-to-end through main() (review r2 #2): expiring-soon exits green ONLY when the
        # page lands — with a failed create the run must go red, not silently pass.
        calls, subprocess.run = stub_gh(EMPTY, fail_op="create")
        module = globals()
        real_probe = module["probe"]
        module["probe"] = lambda token, repo: {"verdict": EXPIRING, "detail": "stub",
                                               "expires_at": None, "days_left": 3.0}
        saved_env = {k: os.environ.get(k) for k in ("REGISTRY_PAT", "REGISTRY_REPO",
                                                    "GITHUB_OUTPUT", "ALERT_REPO",
                                                    "ALERT_TOKEN")}
        os.environ["REGISTRY_PAT"] = "stub"
        os.environ["REGISTRY_REPO"] = "o/r"
        os.environ.pop("GITHUB_OUTPUT", None)
        os.environ.pop("ALERT_REPO", None)   # hermetic: the redact route, not an ambient one
        os.environ.pop("ALERT_TOKEN", None)
        main_out = io.StringIO()
        try:
            with contextlib.redirect_stdout(main_out):
                failed_create_rc = main([])
        finally:
            module["probe"] = real_probe
            for key, val in saved_env.items():
                if val is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = val
        chk("main(): expiring-soon + FAILED create -> rc=1 with ::error (never a green no-page "
            "run)", (failed_create_rc, "::error::pat-validity" in main_out.getvalue()
                     and "LEAKY-STDERR" not in main_out.getvalue()), (1, True))
        # The create call must carry the rolling label + title (what find-by-title keys on).
        calls, subprocess.run = stub_gh(EMPTY)
        with contextlib.redirect_stdout(io.StringIO()):
            upsert_alert(INVALID, "body", "o/r")
        created = next(c for c in calls if c[1:3] == ["issue", "create"])
        chk("create carries exact title + from:agent label",
            (ALERT_TITLE in created, ALERT_LABEL in created), (True, True))

        # --- upsert_probe_alert: consecutive-unknown tracking (issue #207). The counter is a
        # repository variable (SILENT writes); the DISTINCT rolling issue is created/reopened
        # ONLY at threshold. Below it NO issue operation may run: GitHub creates every issue
        # OPEN, so even create-then-close would notify subscribers and flash in open-alert
        # views — the tests therefore assert on the RAW gh call list, not just the summarized
        # ops, to prove ABSENCE of issue writes. Never reclassifies the PAT.
        def probe_issue(number, state):
            return {"number": number, "title": PROBE_ALERT_TITLE, "state": state, "body": "page"}

        PA_EMPTY = json.dumps([[]])
        PA_CLOSED = json.dumps([[probe_issue(50, "closed")]])
        PA_OPEN = json.dumps([[probe_issue(50, "open")]])
        # A same-title PR row must never be mistaken for the page (the Issues listing
        # interleaves PRs); find is issue-only and by exact title.
        PA_PR_DECOY = json.dumps([[{"number": 9, "title": PROBE_ALERT_TITLE, "state": "open",
                                    "body": "page",
                                    "pull_request": {"url": "https://example.invalid"}}]])

        def stub_probe_gh(list_json, streak=None, list_rc=0, var_read="ok", fail_op=None):
            # streak None -> STREAK_VAR never written (gh api answers 404). var_read: "ok" |
            # "down" (a non-404 read failure) | "garbage" (a non-numeric value). fail_op:
            # "variable-set" or an `issue` subcommand to fail.
            calls = []

            def run(args, **_kw):
                calls.append(list(args))
                if args[1] == "api" and any("actions/variables" in a for a in args):
                    if var_read == "down":
                        return _Run("", 1, stderr="gh: LEAKY-STDERR-NEVER-IN-ERRORS")
                    if var_read == "garbage":
                        return _Run(json.dumps({"name": STREAK_VAR, "value": "not-a-number"}))
                    if streak is None:
                        return _Run(json.dumps({"message": "Not Found", "status": "404"}), 1)
                    return _Run(json.dumps({"name": STREAK_VAR, "value": str(streak)}))
                if args[1] == "api":
                    return _Run(list_json, list_rc)
                if args[1] == "variable":
                    return (_Run("", 1, stderr="gh: LEAKY-STDERR-NEVER-IN-ERRORS")
                            if fail_op == "variable-set" else _Run())
                if fail_op and args[2] == fail_op:
                    return _Run("", 1, stderr="gh: LEAKY-STDERR-NEVER-IN-ERRORS")
                return _Run()
            return calls, run

        def run_probe(verdict, listing, streak=None, threshold=UNKNOWN_STREAK_THRESHOLD):
            calls, subprocess.run = stub_probe_gh(listing, streak=streak)
            with contextlib.redirect_stdout(io.StringIO()):
                res = upsert_probe_alert(verdict, "o/r", threshold=threshold)
            issue_ops = [c[2] for c in calls if c[1] == "issue"]
            streak_writes = [c[c.index("--body") + 1] for c in calls if c[1] == "variable"]
            return res, issue_ops, streak_writes

        calls, subprocess.run = stub_probe_gh(PA_CLOSED)
        chk("_find_alert locates the probe issue by its DISTINCT title across states",
            _find_alert("o/r", PROBE_ALERT_TITLE), (50, "CLOSED"))

        # network-unknown streak progression (threshold 3): below it, ZERO issue-touching gh
        # calls — the load-bearing absence — and only the silent variable is written.
        res, iops, wrote = run_probe(NETWORK_UNKNOWN, PA_EMPTY)
        chk("unknown #1 (no state) -> streak 1: variable=1 and NO issue operation at all",
            (res["streak"], res["paging"], iops, wrote), (1, False, [], ["1"]))
        res, iops, wrote = run_probe(NETWORK_UNKNOWN, PA_EMPTY, streak=1)
        chk("unknown #2 -> streak 2: variable=2, STILL no issue operation",
            (res["streak"], res["paging"], iops, wrote), (2, False, [], ["2"]))
        res, iops, wrote = run_probe(NETWORK_UNKNOWN, PA_EMPTY, streak=2)
        chk("unknown #3 crosses threshold -> PAGES: create, left OPEN (no close after it)",
            (res["streak"], res["paging"], iops, wrote), (3, True, ["create"], ["3"]))
        res, iops, wrote = run_probe(NETWORK_UNKNOWN, PA_CLOSED, streak=2)
        chk("unknown #3 with a prior outage's closed page -> REOPEN + edit, never a duplicate",
            (res["streak"], res["paging"], iops), (3, True, ["reopen", "edit"]))
        res, iops, wrote = run_probe(NETWORK_UNKNOWN, PA_OPEN, streak=3)
        chk("unknown #4 (already-open page) -> edit only, stays paging",
            (res["streak"], res["paging"], iops), (4, True, ["edit"]))
        res, iops, wrote = run_probe(NETWORK_UNKNOWN, PA_EMPTY, threshold=1)
        chk("threshold 1: first unknown pages immediately -> create, stays OPEN",
            (res["paging"], iops), (True, ["create"]))
        res, iops, wrote = run_probe(NETWORK_UNKNOWN, PA_OPEN)
        chk("defensive: sub-threshold streak but an OPEN page (raised threshold/manual reopen) "
            "-> close it (silencing is the one sub-threshold issue write)",
            (res["streak"], res["paging"], iops), (1, False, ["close"]))

        # The page create carries the rolling label + distinct title (what find-by-title keys on).
        calls, subprocess.run = stub_probe_gh(PA_EMPTY, streak=2)
        with contextlib.redirect_stdout(io.StringIO()):
            upsert_probe_alert(NETWORK_UNKNOWN, "o/r")
        pcreate = next(c for c in calls if c[1:3] == ["issue", "create"])
        chk("page create carries the distinct title + from:agent label",
            (PROBE_ALERT_TITLE in pcreate, ALERT_LABEL in pcreate), (True, True))

        res, iops, wrote = run_probe(NETWORK_UNKNOWN, PA_PR_DECOY, streak=2)
        chk("same-title PR never matches -> treated as absent, page created fresh",
            (res["streak"], iops), (3, ["create"]))

        # ANY definitive verdict RESETS the streak — the PAT is never reclassified here.
        for name, verdict in [("valid", VALID), ("invalid", INVALID),
                              ("insufficient", INSUFFICIENT), ("expiring", EXPIRING)]:
            res, iops, wrote = run_probe(verdict, PA_OPEN, streak=3)
            chk(f"definitive({name}) + open page -> comment + close + variable zeroed",
                (res["streak"], res["paging"], iops, wrote),
                (0, False, ["comment", "close"], ["0"]))
        res, iops, wrote = run_probe(VALID, PA_EMPTY, streak=2)
        chk("definitive + stale sub-threshold count -> variable zeroed only, no issue op",
            (res["streak"], iops, wrote), (0, [], ["0"]))
        res, iops, wrote = run_probe(VALID, PA_EMPTY)
        chk("definitive + no state at all -> no writes (no churn)", (iops, wrote), ([], []))
        res, iops, wrote = run_probe(VALID, PA_CLOSED, streak=0)
        chk("definitive + closed page + zero variable -> no writes (no churn)",
            (iops, wrote), ([], []))

        # A failed (non-404) streak READ must RAISE, never degrade to 0 — degrading would hold
        # the count below threshold forever and permanently silence the page. Sanitized.
        for mode, name in [("down", "read failure"), ("garbage", "non-numeric value")]:
            calls, subprocess.run = stub_probe_gh(PA_EMPTY, var_read=mode)
            raised = False
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    upsert_probe_alert(NETWORK_UNKNOWN, "o/r")
            except AlertLookupError as exc:
                raised = "LEAKY-STDERR" not in str(exc)
            chk(f"streak-variable {name} -> AlertLookupError (sanitized), zero writes",
                (raised, [c for c in calls if c[1] in ("issue", "variable")]), (True, []))
        # A failed streak WRITE raises before any issue op (fail red, the count is never
        # silently lost); a failed page write raises too — both sanitized (never gh stderr).
        for fail_op, want_issue_ops, name in [
                ("variable-set", [], "failed streak write"),
                ("reopen", ["reopen"], "failed page reopen")]:
            calls, subprocess.run = stub_probe_gh(PA_CLOSED, streak=2, fail_op=fail_op)
            raised = False
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    upsert_probe_alert(NETWORK_UNKNOWN, "o/r")
            except AlertWriteError as exc:
                raised = "LEAKY-STDERR" not in str(exc)
            chk(f"{name} raises AlertWriteError, sanitized; ops after it never run",
                (raised, [c[2] for c in calls if c[1] == "issue"]), (True, want_issue_ops))
        # A failed page LOOKUP raises before any ISSUE write. The streak was already persisted —
        # deliberate: the outage run must still count even when the Issues API is down too.
        calls, subprocess.run = stub_probe_gh("", streak=2, list_rc=1)
        raised = False
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                upsert_probe_alert(NETWORK_UNKNOWN, "o/r")
        except AlertLookupError:
            raised = True
        chk("failed page lookup -> AlertLookupError, zero issue writes",
            (raised, [c for c in calls if c[1] == "issue"]), (True, []))

        # End-to-end through main(): a persistent unknown at threshold goes RED and pages; a
        # single transient unknown stays GREEN with ZERO issue operations (nothing is created,
        # so nothing can notify or be stranded open). network-unknown never touches the
        # CREDENTIAL alert (upsert_alert short-circuits), so every issue call is the page's.
        module = globals()
        real_probe2 = module["probe"]
        module["probe"] = lambda token, repo: {"verdict": NETWORK_UNKNOWN, "detail": "stub",
                                               "expires_at": None, "days_left": None}
        saved_env = {k: os.environ.get(k) for k in ("REGISTRY_PAT", "REGISTRY_REPO",
                                                    "GITHUB_OUTPUT", "ALERT_REPO",
                                                    "ALERT_TOKEN")}
        os.environ["REGISTRY_PAT"] = "stub"
        os.environ["REGISTRY_REPO"] = "o/r"
        os.environ.pop("GITHUB_OUTPUT", None)
        os.environ.pop("ALERT_REPO", None)   # hermetic: the redact route, not an ambient one
        os.environ.pop("ALERT_TOKEN", None)
        try:
            calls, subprocess.run = stub_probe_gh(PA_CLOSED, streak=2)  # 2 -> 3: threshold
            with contextlib.redirect_stdout(io.StringIO()):
                red_rc = main([])
            paged_ops = [c[2] for c in calls if c[1] == "issue"]
            calls, subprocess.run = stub_probe_gh(PA_EMPTY)  # first unknown ever -> silent
            with contextlib.redirect_stdout(io.StringIO()):
                green_rc = main([])
            silent_issue_ops = [c[2] for c in calls if c[1] == "issue"]
        finally:
            module["probe"] = real_probe2
            for key, val in saved_env.items():
                if val is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = val
        chk("main(): persistent unknown crossing threshold -> rc=1 and pages (reopen+edit)",
            (red_rc, paged_ops), (1, ["reopen", "edit"]))
        chk("main(): a single transient unknown -> rc=0 (green) and ZERO issue operations",
            (green_rc, silent_issue_ops), (0, []))

        # --- sol-audit issue #204 (+ #432 round 1): the DETAILED credential alert routes ONLY
        #     to a POSITIVELY VERIFIED private repo — distinct from the registry AND confirmed
        #     `"private": true` under the route token; the PUBLIC-registry fallback carries ONLY
        #     a generic signal (no verdict, detail, or expiry). Pure route + render first, then
        #     END-TO-END through main().
        vis_calls = []
        chk("route: repo+token+CONFIRMED private -> private + token, no redact",
            _alert_route("org/private", "tok", "org/registry",
                         confirmed_private=lambda r, t: vis_calls.append((r, t)) or True),
            ("org/private", "tok", False))
        chk("route: the visibility check runs against the ALERT repo under the ALERT token",
            vis_calls, [("org/private", "tok")])
        # #432 round 1 finding 2: configuration alone is NOT verification — both fail-open
        # shapes (same-repo and unverified-visibility) must land redacted on the registry even
        # though ALERT_REPO and ALERT_TOKEN are both non-empty.
        chk("route: ALERT_REPO == REGISTRY_REPO -> REDACT (the registry is never private)",
            _alert_route("org/registry", "tok", "org/registry",
                         confirmed_private=lambda r, t: True), ("org/registry", None, True))
        chk("route: same-repo rejection is case-insensitive (GitHub repo names are)",
            _alert_route("Org/Registry", "tok", "org/registry",
                         confirmed_private=lambda r, t: True), ("org/registry", None, True))
        chk("route: UNCONFIRMED visibility (public repo or failed lookup) -> REDACT, fail closed",
            _alert_route("org/other-public", "tok", "org/registry",
                         confirmed_private=lambda r, t: False), ("org/registry", None, True))
        half_calls = []
        chk("route: repo but NO token -> registry fallback, REDACT, and NO visibility call "
            "(#39/#204)",
            (_alert_route("org/private", "", "org/registry",
                          confirmed_private=lambda r, t: half_calls.append(r) or True),
             half_calls),
            (("org/registry", None, True), []))
        chk("route: token but NO repo -> registry fallback, REDACT",
            _alert_route("", "tok", "org/registry",
                         confirmed_private=lambda r, t: True), ("org/registry", None, True))
        chk("route: neither repo nor token -> registry fallback, REDACT",
            _alert_route(None, None, "org/registry",
                         confirmed_private=lambda r, t: True), ("org/registry", None, True))
        # _confirmed_private itself: True ONLY on a definitive `"private": true`; every failure
        # shape is False (fail closed), and the lookup runs under the ROUTE token.
        vis_seen = []

        def vis_gh(rc, stdout):
            def run(args, **kw):
                vis_seen.append((list(args), (kw.get("env") or {}).get("GH_TOKEN")))
                return _Run(stdout, rc)
            return run

        subprocess.run = vis_gh(0, json.dumps({"private": True, "full_name": "org/private"}))
        chk("_confirmed_private: definitive private=true -> True, GET /repos under the route "
            "token",
            (_confirmed_private("org/private", "route-tok"), vis_seen[0]),
            (True, (["gh", "api", "repos/org/private"], "route-tok")))
        subprocess.run = vis_gh(0, json.dumps({"private": False, "full_name": "org/pub"}))
        chk("_confirmed_private: a PUBLIC destination -> False (fail closed)",
            _confirmed_private("org/pub", "t"), False)
        subprocess.run = vis_gh(1, "")
        chk("_confirmed_private: failed lookup -> False (fail closed, never assumed private)",
            _confirmed_private("org/private", "t"), False)
        subprocess.run = vis_gh(0, "gh: not json")
        chk("_confirmed_private: unparseable payload -> False (fail closed)",
            _confirmed_private("org/private", "t"), False)
        subprocess.run = vis_gh(0, json.dumps({"visibility": "private"}))
        chk("_confirmed_private: anything but a literal private=true bool -> False",
            _confirmed_private("org/private", "t"), False)
        res_bad = {"verdict": INVALID,
                   "detail": "GET /user returned 401 — the PAT is revoked, expired, or malformed",
                   "expires_at": "2026-08-01 04:33:41 UTC", "days_left": None}
        full_b = render_alert(res_bad, "o/r")
        red_b = render_alert(res_bad, "o/r", redact=True)
        chk("full credential body carries the verdict + detail + expiry (private route)",
            ("`invalid`" in full_b, "revoked" in full_b, "2026-08-01" in full_b),
            (True, True, True))
        chk("redacted credential body SUPPRESSES verdict + detail + expiry (#204)",
            ("Verdict:" in red_b, "revoked" in red_b, "2026-08-01" in red_b, "invalid" in red_b),
            (False, False, False, False))
        chk("redacted credential body keeps a generic signal + private-route hint",
            ("SUPPRESSED" in red_b, "ALERT_REPO" in red_b, "ALERT_TOKEN" in red_b,
             "needs maintainer attention" in red_b),
            (True, True, True, True))
        # END-TO-END main(): a capturing gh records the create's -R repo, GH_TOKEN and body, and
        # answers the visibility verification per `visibility` / fails routes per `fail`. The
        # probe-unavailable page (#207) makes no create on a definitive verdict, so every create
        # captured is the credential alert's.
        captured = []
        visibility = {}   # "repos/<repo>" -> (stdout, rc) for the GET /repos verification
        fail = set()      # "private-lookup" | "private-create" | "registry-create"

        def cap_gh(args, **_kw):
            r = args[args.index("-R") + 1] if "-R" in args else None
            env = _kw.get("env") or {}
            if args[1] == "api" and any("actions/variables" in a for a in args):
                return _Run(json.dumps({"message": "Not Found", "status": "404"}), 1)
            if args[1] == "api" and args[2] in visibility:
                return _Run(*visibility[args[2]])
            if args[1] == "api":
                if ("private-lookup" in fail
                        and any("repos/org/private/issues" in a for a in args)):
                    return _Run("", 1)
                return _Run("[]")
            if args[1] == "variable":
                return _Run()
            if args[1:3] == ["issue", "create"]:
                captured.append({"repo": r, "token": env.get("GH_TOKEN"),
                                 "body": args[args.index("--body") + 1]})
                if (r == "org/private" and "private-create" in fail) or \
                        (r == "o/r" and "registry-create" in fail):
                    return _Run("", 1)
            return _Run()

        module = globals()
        real_probe3 = module["probe"]
        module["probe"] = lambda token, repo: dict(res_bad)
        saved_env = {k: os.environ.get(k) for k in
                     ("REGISTRY_PAT", "REGISTRY_REPO", "GITHUB_OUTPUT", "ALERT_REPO",
                      "ALERT_TOKEN", "GH_TOKEN")}
        try:
            os.environ.update(REGISTRY_PAT="stub", REGISTRY_REPO="o/r")
            os.environ.pop("GITHUB_OUTPUT", None)
            os.environ.pop("GH_TOKEN", None)
            subprocess.run = cap_gh
            # (a) UNCONFIGURED: no ALERT_REPO -> credential alert on the public REGISTRY, generic.
            os.environ.pop("ALERT_REPO", None)
            os.environ.pop("ALERT_TOKEN", None)
            captured.clear()
            pub_out = io.StringIO()
            with contextlib.redirect_stdout(pub_out):
                rc_pub = main([])
            pub = captured[0] if captured else {}
            chk("main() unconfigured (#204): ONE credential create on the public REGISTRY repo",
                (len(captured), pub.get("repo")), (1, "o/r"))
            chk("main() unconfigured (#204): body is generic END-TO-END — no verdict/detail/expiry",
                ("revoked" in pub.get("body", ""), "2026-08-01" in pub.get("body", ""),
                 "SUPPRESSED" in pub.get("body", "")),
                (False, False, True))
            chk("main() unconfigured (#204): definitive bad verdict still exits red", rc_pub, 1)
            # (b) CONFIGURED + CONFIRMED-private route -> FULL body on the PRIVATE repo, written
            # with ALERT_TOKEN.
            os.environ["ALERT_REPO"] = "org/private"
            os.environ["ALERT_TOKEN"] = "priv"
            visibility["repos/org/private"] = (json.dumps({"private": True}), 0)
            captured.clear()
            priv_out = io.StringIO()
            with contextlib.redirect_stdout(priv_out):
                main([])
            priv = captured[0] if captured else {}
            chk("main() configured (#204): ONE credential create on the PRIVATE repo w/ ALERT_TOKEN",
                (len(captured), priv.get("repo"), priv.get("token")),
                (1, "org/private", "priv"))
            chk("main() configured (#204): private body is FULL (verdict + detail + expiry)",
                ("revoked" in priv.get("body", ""), "2026-08-01" in priv.get("body", ""),
                 "SUPPRESSED" in priv.get("body", "")),
                (True, True, False))
            # #432 round 1 finding 1: the PUBLIC workflow log (stdout) must be generic on EVERY
            # route — the configured-private run above included — never the verdict, the detail,
            # or the expiry the issue body carries.
            for label, text in [("unconfigured", pub_out.getvalue()),
                                ("configured-private", priv_out.getvalue())]:
                chk(f"main() {label}: stdout carries NO verdict/detail/expiry — coarse status "
                    "only (#432 r1)",
                    ("revoked" in text, "2026-08-01" in text, f'"{INVALID}"' in text,
                     json.dumps({"status": "attention-required"}) in text),
                    (False, False, False, True))
            # (c) #432 round 1 finding 2: ALERT_REPO whose visibility is NOT confirmed private
            # (public repo / failed or unparseable lookup) fails CLOSED to the generic registry
            # alert — configuration alone must never select the detailed route.
            for label, answer in [("public repo", (json.dumps({"private": False}), 0)),
                                  ("failed lookup", ("", 1))]:
                visibility["repos/org/private"] = answer
                captured.clear()
                with contextlib.redirect_stdout(io.StringIO()):
                    main([])
                unver = captured[0] if captured else {}
                chk(f"main() unverified private route ({label}): generic create on the REGISTRY, "
                    "ambient token (#432 r1)",
                    (len(captured), unver.get("repo"), unver.get("token"),
                     "SUPPRESSED" in unver.get("body", ""), "revoked" in unver.get("body", "")),
                    (1, "o/r", None, True, False))
            # (d) ALERT_REPO naming the registry itself is the fail-open the finding names: the
            # visibility stub is not even consulted (same-repo rejection comes first).
            os.environ["ALERT_REPO"] = "o/r"
            visibility["repos/o/r"] = (json.dumps({"private": True}), 0)
            captured.clear()
            with contextlib.redirect_stdout(io.StringIO()):
                main([])
            same = captured[0] if captured else {}
            chk("main() ALERT_REPO == REGISTRY_REPO: generic create on the registry, never the "
                "detailed body (#432 r1)",
                (len(captured), same.get("repo"), "SUPPRESSED" in same.get("body", ""),
                 "revoked" in same.get("body", "")),
                (1, "o/r", True, False))
            del visibility["repos/o/r"]
            # (e) #432 round 1 finding 5: a VERIFIED private route whose token fails at RUN time
            # (issue lookup or write) retries a REDACTED generic alert on the registry with the
            # ambient token instead of dropping the rolling signal; only both routes failing
            # goes red with no page.
            os.environ["ALERT_REPO"] = "org/private"
            visibility["repos/org/private"] = (json.dumps({"private": True}), 0)
            for mode in ("private-lookup", "private-create"):
                fail.clear()
                fail.add(mode)
                captured.clear()
                fb_out = io.StringIO()
                with contextlib.redirect_stdout(fb_out):
                    rc_fb = main([])
                fallback = captured[-1] if captured else {}
                chk(f"main() {mode} failure: REDACTED retry lands on the registry with the "
                    "ambient token (#432 r1)",
                    (fallback.get("repo"), fallback.get("token"),
                     "SUPPRESSED" in fallback.get("body", ""),
                     "revoked" in fallback.get("body", "")),
                    ("o/r", None, True, False))
                chk(f"main() {mode} failure: warns, stays sanitized, and still exits red on the "
                    "bad verdict",
                    (rc_fb, "private alert route failed" in fb_out.getvalue(),
                     "revoked" in fb_out.getvalue()), (1, True, False))
            # expiring-soon distinguishes rc: the page landing via the fallback keeps the run
            # green (the page IS the signal); both routes failing must go red.
            module["probe"] = lambda token, repo: {"verdict": EXPIRING, "detail": "stub-detail",
                                                   "expires_at": "2099-01-02 03:04:05 UTC",
                                                   "days_left": 3.5}
            fail.clear()
            fail.add("private-lookup")
            captured.clear()
            with contextlib.redirect_stdout(io.StringIO()):
                rc_green = main([])
            chk("main() expiring + fallback delivered -> green run, page on the registry",
                (rc_green, (captured[-1] if captured else {}).get("repo")), (0, "o/r"))
            fail.add("registry-create")
            captured.clear()
            both_out = io.StringIO()
            with contextlib.redirect_stdout(both_out):
                rc_both = main([])
            chk("main() expiring + BOTH routes fail -> rc=1 with ::error (never a green no-page "
                "run)",
                (rc_both, "::error::pat-validity" in both_out.getvalue()), (1, True))
            # #432 round 1 finding 1, per-verdict: stdout stays generic for every
            # attention-worthy verdict — a distinctive detail, the expiry, the days-left count,
            # and the verdict string itself must never print.
            fail.clear()
            for verdict in (INVALID, INSUFFICIENT, EXPIRING):
                module["probe"] = lambda token, repo, v=verdict: {
                    "verdict": v, "detail": "DISTINCTIVE-DETAIL-NEVER-PUBLIC",
                    "expires_at": "2099-01-02 03:04:05 UTC", "days_left": 3.5}
                captured.clear()
                verdict_out = io.StringIO()
                with contextlib.redirect_stdout(verdict_out):
                    main([])
                text = verdict_out.getvalue()
                chk(f"main() stdout for {verdict}: no detail/expiry/days-left/verdict string, "
                    "coarse status only (#432 r1)",
                    ("DISTINCTIVE-DETAIL-NEVER-PUBLIC" in text, "2099-01-02" in text,
                     "3.5" in text, verdict in text,
                     json.dumps({"status": "attention-required"}) in text),
                    (False, False, False, False, True))
                chk(f"main() private-route body for {verdict} still carries the detail "
                    "(suppression is log-side, not alert-side)",
                    "DISTINCTIVE-DETAIL-NEVER-PUBLIC" in (captured[0] if captured
                                                          else {}).get("body", ""), True)
        finally:
            module["probe"] = real_probe3
            for key, val in saved_env.items():
                if val is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = val
    finally:
        subprocess.run = real_run

    print("pat-validity self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main(sys.argv[1:]))
