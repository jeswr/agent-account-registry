#!/usr/bin/env python3
# [FABLE-5] Scheduled REGISTRY_SECRETS_PAT validity probe (issue #37).
#
# WHY: the PAT that set-up-account and the worker rotation write-back use for `gh secret set` on
# this registry repo was validated only at USE time — so a rotated/expired PAT (fine-grained PATs
# expire silently on a calendar) was discovered exactly when a new account was being onboarded,
# the one moment a human is waiting on the flow. This probe runs on a weekly cron instead.
#
# Probe targets (the minimal reads the pipeline actually needs):
#   1. GET /user                                    — does the token authenticate at all
#   2. GET /repos/{repo}/actions/secrets/public-key — the exact read `gh secret set` performs
#      before encrypting a secret, so it exercises precisely the Secrets access the PAT exists
#      for, without writing anything.
# The expiry header (github-authentication-token-expiration) is inspected where available so a
# calendar expiry is flagged BEFORE it lands: a valid PAT within EXPIRY_WARN_DAYS of expiry
# becomes `expiring-soon`, which upserts the SAME rolling alert issue — a ::warning annotation
# alone is only a green-run log entry, not an actionable alert.
#
# Verdicts (machine-readable JSON on stdout + GITHUB_OUTPUT `verdict=`):
#   valid | expiring-soon | invalid | insufficient-scope | network-unknown
# FAIL-CLOSED AGAINST FALSE ALARMS: an unreachable/throttled/5xx-ing API proves nothing about the
# PAT, so `network-unknown` is NOT `invalid` — it neither opens the rolling alert issue NOR closes
# an existing one (unknown is not recovery either). GitHub answers 403 for primary/secondary rate
# limits too: primary carries x-ratelimit-remaining: 0 and secondary usually retry-after, but a
# secondary-limit 403 can arrive with NO retry-after and NONZERO remaining quota — there the
# DOCUMENTED discriminator is the error body's message ("You have exceeded a secondary rate
# limit"), so the JSON error message is inspected alongside the headers. A throttle-shaped
# secrets 403 is network-unknown, never insufficient-scope. Only 401 (invalid), an
# authenticated-but-denied secrets read (insufficient-scope), and near-expiry alert.
#
# Alerting mirrors usage-alert.py: ONE rolling `from:agent` issue, upserted by exact title —
# edited when open, REOPENED (never duplicated) when closed, closed with a comment on recovery.
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
# (--self-test, every verdict path exercised); the CLI wraps them over urllib + `gh`.
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

API = "https://api.github.com"
ALERT_TITLE = "🔑 REGISTRY_SECRETS_PAT is invalid or under-scoped — secret writes will fail"
ALERT_LABEL = "from:agent"
EXPIRY_HEADER = "github-authentication-token-expiration"
EXPIRY_WARN_DAYS = 14

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
    detection mechanism"), so the retained body message is checked too."""
    headers = resp.get("headers") or {}
    message = (resp.get("message") or "").lower()
    return (headers.get("x-ratelimit-remaining") == "0"
            or "retry-after" in headers
            or "secondary rate limit" in message
            or "abuse detection" in message)


def classify(user, secrets):
    """(verdict, detail) from the two probe responses. FAIL-CLOSED against false alarms: only a
    definitive credential signal (401) or an authenticated-but-denied secrets read (403/404 after
    a 200 /user) alerts; every throttling-shaped or server-side status is network-unknown —
    including a secrets 403 whose headers OR error-body message say rate limit rather than
    missing scope."""
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
        return VALID, ("authenticates and can read the Actions secrets public key "
                       "(the exact read `gh secret set` performs)")
    if sstatus == 401:
        return INVALID, "secrets public-key read returned 401 — the PAT is revoked or expired"
    if sstatus == 403 and _throttled(secrets):
        return NETWORK_UNKNOWN, ("secrets public-key read returned a throttle-shaped 403 "
                                 "(rate limited per its headers or documented error message) "
                                 "— not a credential verdict")
    if sstatus in (403, 404):
        # A fine-grained PAT with no access to the repo 404s; one with repo access but no
        # Secrets permission 403s. Both mean `gh secret set` will fail.
        return INSUFFICIENT, (f"authenticates, but the Actions secrets public-key read returned "
                              f"{sstatus} — the PAT lacks Secrets access to the registry repo")
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


def probe(token, repo, fetch=_get, now=None):
    """Full probe -> {"verdict", "detail", "expires_at", "days_left"}. The secrets read only
    runs after a 200 /user (no point scoping a token that doesn't authenticate). An absent or
    malformed secret IS the alert-worthy condition set-up-account's preflight fails on —
    verdict invalid, zero requests. A valid PAT within EXPIRY_WARN_DAYS of its calendar expiry
    downgrades to expiring-soon so the rolling alert (not just a log line) pages ahead of
    the break."""
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
    secrets = None
    if user.get("status") == 200:
        secrets = fetch(f"{API}/repos/{repo}/actions/secrets/public-key", token)
    verdict, detail = classify(user, secrets)
    expires_at, days_left = _expiry(user.get("headers"), now)
    if verdict == VALID and days_left is not None and days_left <= EXPIRY_WARN_DAYS:
        verdict = EXPIRING
        detail = (f"the PAT still authenticates and reads the secrets public key, but its "
                  f"calendar expiry is ~{days_left} days away — rotate it before onboarding "
                  "breaks")
    return {"verdict": verdict, "detail": detail,
            "expires_at": expires_at, "days_left": days_left}


def render_alert(result, repo):
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
    lines.append(f"**Fix:** mint a fine-grained PAT with **Secrets: read and write** on `{repo}`, "
                 f"then `gh secret set REGISTRY_SECRETS_PAT -R {repo}` (paste at the prompt — "
                 "never as a visible argument). This issue updates itself on the weekly probe and "
                 "closes automatically once the PAT passes.")
    return "\n".join(lines)


def _gh(args, check=False):
    result = subprocess.run(["gh"] + args, capture_output=True, text=True)
    if check and result.returncode != 0:
        # RAISES, not warns (review r2 #2): a warned-and-swallowed write failure let a failed
        # `issue create` exit green with no alert at all. Sanitized like usage-alert.py: op +
        # returncode only — gh stderr under GH_DEBUG=api can echo request bodies.
        raise AlertWriteError(f"gh {args[0]} {args[1] if len(args) > 1 else ''} "
                              f"failed (rc={result.returncode})")
    return result


def _find_alert(repo):
    """(number, STATE) of the rolling alert issue by EXACT title across ALL states — the closed
    one must be found too, so recovery-then-relapse REOPENS instead of duplicating. Authoritative:
    the PAGINATED Issues REST API (no fixed --limit window an old closed alert could age out of;
    the Search API is eventually consistent, so not it either). A failed or unparseable lookup
    raises AlertLookupError — 'lookup failed' must never degrade into 'not found'."""
    listed = _gh(["api", "--paginate", "--slurp",
                  f"repos/{repo}/issues?state=all"
                  f"&labels={urllib.parse.quote(ALERT_LABEL, safe='')}&per_page=100"])
    if listed.returncode != 0:
        raise AlertLookupError(f"rolling-alert lookup failed (gh api rc={listed.returncode})")
    try:
        pages = json.loads(listed.stdout or "[]")
    except ValueError as exc:
        raise AlertLookupError("rolling-alert lookup returned unparseable JSON") from exc
    for item in (entry for page in pages for entry in page):
        # The Issues listing endpoint interleaves PRs — a PR sharing the title must not match.
        if item.get("title") == ALERT_TITLE and "pull_request" not in item:
            return item["number"], str(item.get("state", "")).upper()
    return None, None


def upsert_alert(verdict, body, repo):
    """Idempotent rolling-issue upsert; returns the ops that SUCCEEDED (self-tested).
    network-unknown performs NO writes at all: it must not false-alarm, and it must not close an
    existing alert either — an unreachable API is not evidence of recovery. A failed lookup
    propagates AlertLookupError before any write; a failed write propagates AlertWriteError
    (every write runs under _gh(check=True)), skipping any later ops — so `ops` never claims a
    write that didn't land. expiring-soon alerts like a bad verdict (the whole point of the
    expiry probe is a page BEFORE the break) but main() keeps the run green when the page
    lands."""
    if verdict == NETWORK_UNKNOWN:
        return []
    number, state = _find_alert(repo)
    ops = []
    if verdict in (INVALID, INSUFFICIENT, EXPIRING):
        if number is None:
            _gh(["issue", "create", "-R", repo, "--title", ALERT_TITLE,
                 "--label", ALERT_LABEL, "--body", body], check=True)
            ops.append("create")
        else:
            if state != "OPEN":
                _gh(["issue", "reopen", str(number), "-R", repo], check=True)
                ops.append("reopen")
            _gh(["issue", "edit", str(number), "-R", repo, "--body", body], check=True)
            ops.append("edit")
    elif number is not None and state == "OPEN":  # valid -> recovery
        _gh(["issue", "comment", str(number), "-R", repo, "--body",
             "✅ Recovered — the PAT authenticates and the secrets public-key read succeeds. "
             "Auto-closing."], check=True)
        _gh(["issue", "close", str(number), "-R", repo], check=True)
        ops += ["comment", "close"]
    return ops


def main(argv):
    probe_only = "--probe-only" in argv
    repo = os.environ.get("REGISTRY_REPO") or os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        print("::error::pat-validity: REGISTRY_REPO/GITHUB_REPOSITORY not set")
        return 2
    result = probe(os.environ.get("REGISTRY_PAT"), repo)
    print(json.dumps(result))  # the machine-readable verdict; never contains the token
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as handle:
            handle.write(f"verdict={result['verdict']}\n")
    if result["verdict"] == EXPIRING:
        # The ahead-of-time half of issue #37. The annotation is a courtesy for whoever opens
        # the run; the ACTIONABLE alert is the rolling issue upserted below.
        print(f"::warning::pat-validity: REGISTRY_SECRETS_PAT expires in "
              f"~{result['days_left']} days — rotate it before the calendar does")
    if not probe_only:
        try:
            upsert_alert(result["verdict"], render_alert(result, repo), repo)
        except (AlertLookupError, AlertWriteError) as exc:
            # Fail red WITHOUT pretending the alert landed: creating blind on a failed lookup is
            # how the rolling issue gets duplicated, and a swallowed write failure pages nobody.
            # Both messages are sanitized at raise time (op + rc only, never gh stderr).
            print(f"::error::pat-validity: {exc} — alert not (fully) written")
            return 1
    # Red run on a definitive bad verdict (so the scheduled run itself signals), green on
    # valid AND network-unknown (no false alarms). expiring-soon stays green too — secret
    # writes still succeed today; the page is the rolling issue, not a failed run.
    return 1 if result["verdict"] in (INVALID, INSUFFICIENT) else 0


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

    # --- classify: every verdict path, fail-closed edges included.
    chk("valid", classify(U_OK, S_OK)[0], VALID)
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

    # --- probe orchestration: fetch order, short-circuit, expiry, redaction.
    fetched = []

    def fake_fetch(responses):
        def fetch(url, token):
            chk_token_holder.append(token)
            fetched.append(url)
            return responses[len(fetched) - 1]
        return fetch

    chk_token_holder = []
    now = datetime(2026, 7, 17, 4, 33, 41, tzinfo=timezone.utc)
    r = probe(SENTINEL, "o/r", fetch=fake_fetch([U_OK, S_OK]), now=now)
    chk("probe valid end-to-end", r["verdict"], VALID)
    chk("probe hits /user then the secrets public-key read",
        fetched, [f"{API}/user", f"{API}/repos/o/r/actions/secrets/public-key"])
    chk("expiry header inspected (15 days out)", r["days_left"], 15.0)
    fetched.clear()
    r401 = probe(SENTINEL, "o/r", fetch=fake_fetch([U_401]), now=now)
    chk("probe 401 short-circuits (no secrets read on a dead token)",
        (r401["verdict"], fetched), (INVALID, [f"{API}/user"]))
    fetched.clear()
    rmiss = probe("", "o/r", fetch=fake_fetch([]))
    chk("absent secret -> invalid, zero fetches", (rmiss["verdict"], fetched), (INVALID, []))
    # Near-expiry transitions (review r1 #5): the 15-day probe above stays VALID (just above
    # the 14-day threshold); at and below it the verdict downgrades to expiring-soon so
    # upsert_alert pages via the rolling issue instead of a green-run log line.
    fetched.clear()
    r_soon = probe(SENTINEL, "o/r", fetch=fake_fetch([U_OK_SOON, S_OK]), now=now)
    chk("8 days out -> expiring-soon", (r_soon["verdict"], r_soon["days_left"]), (EXPIRING, 8.0))
    fetched.clear()
    r_edge = probe(SENTINEL, "o/r", fetch=fake_fetch([U_OK_EDGE, S_OK]), now=now)
    chk("exactly 14.0 days -> expiring-soon (boundary inclusive)", r_edge["verdict"], EXPIRING)
    # A header-injecting token is rejected BEFORE any request is built (review r1 #3):
    # http.client would otherwise raise a ValueError embedding the complete credential.
    fetched.clear()
    rbad = probe(f"github_pat_{SENTINEL}\r\nX-Inject: 1", "o/r", fetch=fake_fetch([]))
    chk("CR/LF token -> invalid, zero fetches (never enters a header)",
        (rbad["verdict"], fetched), (INVALID, []))
    # Redaction: the verdict JSON and the alert body must never carry the token.
    chk("verdict JSON never contains the token",
        SENTINEL in json.dumps(r) + json.dumps(r401) + json.dumps(rmiss)
        + json.dumps(r_soon) + json.dumps(rbad), False)
    chk("alert body never contains the token",
        SENTINEL in render_alert(r401, "o/r") + render_alert(rmiss, "o/r")
        + render_alert(r_soon, "o/r") + render_alert(rbad, "o/r"), False)
    chk("fetch received the token (probe is non-vacuous)",
        all(t == SENTINEL for t in chk_token_holder) and len(chk_token_holder) == 7, True)

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
                                                    "GITHUB_OUTPUT")}
        os.environ["REGISTRY_PAT"] = "stub"
        os.environ["REGISTRY_REPO"] = "o/r"
        os.environ.pop("GITHUB_OUTPUT", None)
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
    finally:
        subprocess.run = real_run

    print("pat-validity self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main(sys.argv[1:]))
