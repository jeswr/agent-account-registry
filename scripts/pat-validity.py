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
# calendar expiry is flagged BEFORE it lands.
#
# Verdicts (machine-readable JSON on stdout + GITHUB_OUTPUT `verdict=`):
#   valid | invalid | insufficient-scope | network-unknown
# FAIL-CLOSED AGAINST FALSE ALARMS: an unreachable/throttled/5xx-ing API proves nothing about the
# PAT, so `network-unknown` is NOT `invalid` — it neither opens the rolling alert issue NOR closes
# an existing one (unknown is not recovery either). Only 401 (invalid) and an authenticated-but-
# denied secrets read (insufficient-scope) alert.
#
# Alerting mirrors usage-alert.py: ONE rolling `from:agent` issue, upserted by exact title —
# edited when open, REOPENED (never duplicated) when closed, closed with a comment on recovery.
# The token is NEVER printed: it travels only in the Authorization header; network-error details
# are reduced to the exception class name so no request material can echo.
#
# Pure classify()/probe()/upsert_alert() are unit-tested against recorded-shape fixtures
# (--self-test, all four verdict paths exercised); the CLI wraps them over urllib + `gh`.
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

API = "https://api.github.com"
ALERT_TITLE = "🔑 REGISTRY_SECRETS_PAT is invalid or under-scoped — secret writes will fail"
ALERT_LABEL = "from:agent"
EXPIRY_HEADER = "github-authentication-token-expiration"
EXPIRY_WARN_DAYS = 14

VALID = "valid"
INVALID = "invalid"
INSUFFICIENT = "insufficient-scope"
NETWORK_UNKNOWN = "network-unknown"


def _get(url, token, timeout=20):
    """One authenticated GET -> {"status": int, "headers": {lowercased}} or
    {"status": None, "error": <exception class name>}. The token exists only in the
    Authorization header; on failure only the exception CLASS is kept (URLError strings can
    embed proxy/request detail — never risk echoing request material into a public log)."""
    request = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "agent-account-registry-pat-validity",
    })
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return {"status": resp.status,
                    "headers": {k.lower(): v for k, v in resp.headers.items()}}
    except urllib.error.HTTPError as exc:
        return {"status": exc.code,
                "headers": {k.lower(): v for k, v in (exc.headers or {}).items()}}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"status": None, "error": type(exc).__name__}


def classify(user, secrets):
    """(verdict, detail) from the two probe responses. FAIL-CLOSED against false alarms: only a
    definitive credential signal (401) or an authenticated-but-denied secrets read (403/404 after
    a 200 /user) alerts; every throttling-shaped or server-side status is network-unknown."""
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


def probe(token, repo, fetch=_get, now=None):
    """Full probe -> {"verdict", "detail", "expires_at", "days_left"}. The secrets read only
    runs after a 200 /user (no point scoping a token that doesn't authenticate). An absent
    secret IS the alert-worthy condition set-up-account's preflight fails on — verdict invalid."""
    if not token:
        return {"verdict": INVALID,
                "detail": "REGISTRY_SECRETS_PAT is not set (or empty) on the registry repo",
                "expires_at": None, "days_left": None}
    user = fetch(f"{API}/user", token)
    secrets = None
    if user.get("status") == 200:
        secrets = fetch(f"{API}/repos/{repo}/actions/secrets/public-key", token)
    verdict, detail = classify(user, secrets)
    expires_at, days_left = _expiry(user.get("headers"), now)
    return {"verdict": verdict, "detail": detail,
            "expires_at": expires_at, "days_left": days_left}


def render_alert(result, repo):
    lines = ["> 🤖 SPARQ agent — scheduled REGISTRY_SECRETS_PAT validity check (issue #37).\n",
             f"**Verdict: `{result['verdict']}`** — {result['detail']}\n",
             f"This PAT is what `set-up-account` and the worker rotation write-back use to run "
             f"`gh secret set` on `{repo}`; while it is broken, account onboarding and credential "
             f"write-back fail at exactly the moment someone is waiting on them.\n"]
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
        # Sanitized like usage-alert.py: op + returncode only — gh stderr under GH_DEBUG=api can
        # echo request bodies.
        print(f"::warning::pat-validity: gh {args[0]} {args[1] if len(args) > 1 else ''} "
              f"failed (rc={result.returncode})")
    return result


def _find_alert(repo):
    """(number, STATE) of the rolling alert issue by EXACT title across ALL states — the closed
    one must be found too, so recovery-then-relapse REOPENS instead of duplicating."""
    listed = json.loads(_gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL,
                             "--state", "all", "--json", "number,title,state",
                             "--limit", "100"]).stdout or "[]")
    for item in listed:
        if item.get("title") == ALERT_TITLE:
            return item["number"], str(item.get("state", "")).upper()
    return None, None


def upsert_alert(verdict, body, repo):
    """Idempotent rolling-issue upsert; returns the ops performed (self-tested). network-unknown
    performs NO writes at all: it must not false-alarm, and it must not close an existing alert
    either — an unreachable API is not evidence of recovery."""
    if verdict == NETWORK_UNKNOWN:
        return []
    number, state = _find_alert(repo)
    ops = []
    if verdict in (INVALID, INSUFFICIENT):
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
    days_left = result.get("days_left")
    if result["verdict"] == VALID and days_left is not None and days_left <= EXPIRY_WARN_DAYS:
        # The ahead-of-time half of issue #37: a still-valid PAT nearing its calendar expiry.
        print(f"::warning::pat-validity: REGISTRY_SECRETS_PAT expires in ~{days_left} days — "
              "rotate it before the calendar does")
    if not probe_only:
        upsert_alert(result["verdict"], render_alert(result, repo), repo)
    # Red run on a definitive bad verdict (so the scheduled run itself signals), green on
    # valid AND network-unknown (no false alarms).
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
    U_401 = {"status": 401, "headers": {"content-type": "application/json; charset=utf-8"}}
    U_403 = {"status": 403, "headers": {"retry-after": "60"}}
    S_OK = {"status": 200, "headers": {"content-type": "application/json; charset=utf-8"}}
    S_403 = {"status": 403, "headers": {"content-type": "application/json; charset=utf-8"}}
    S_404 = {"status": 404, "headers": {"content-type": "application/json; charset=utf-8"}}
    S_502 = {"status": 502, "headers": {}}
    NET_FAIL = {"status": None, "error": "TimeoutError"}

    # --- classify: every verdict path, fail-closed edges included.
    chk("valid", classify(U_OK, S_OK)[0], VALID)
    chk("invalid: /user 401", classify(U_401, None)[0], INVALID)
    chk("invalid: secrets 401 (died mid-probe)", classify(U_OK, U_401)[0], INVALID)
    chk("insufficient: secrets 403", classify(U_OK, S_403)[0], INSUFFICIENT)
    chk("insufficient: secrets 404 (no repo access)", classify(U_OK, S_404)[0], INSUFFICIENT)
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
    # Redaction: the verdict JSON and the alert body must never carry the token.
    chk("verdict JSON never contains the token",
        SENTINEL in json.dumps(r) + json.dumps(r401) + json.dumps(rmiss), False)
    chk("alert body never contains the token",
        SENTINEL in render_alert(r401, "o/r") + render_alert(rmiss, "o/r"), False)
    chk("fetch received the token (probe is non-vacuous)",
        all(t == SENTINEL for t in chk_token_holder) and len(chk_token_holder) == 3, True)

    # --- expiry parsing edges.
    chk("iso expiry parses", _expiry({EXPIRY_HEADER: "2026-07-18T04:33:41Z"}, now)[1], 1.0)
    chk("garbage expiry degrades to (raw, None)",
        _expiry({EXPIRY_HEADER: "soonish"}, now), ("soonish", None))
    chk("absent expiry -> (None, None)", _expiry({}, now), (None, None))

    # --- upsert: idempotent rolling issue against a stubbed gh (usage-alert.py pattern).
    import contextlib
    import io

    class _Run:
        def __init__(self, stdout="[]"):
            self.returncode, self.stdout, self.stderr = 0, stdout, ""

    def stub_gh(list_json):
        calls = []

        def run(args, **_kw):
            calls.append(list(args))
            return _Run(list_json if args[1:3] == ["issue", "list"] else "[]")
        return calls, run

    OPEN_HIT = json.dumps([{"number": 7, "title": ALERT_TITLE, "state": "OPEN"}])
    CLOSED_HIT = json.dumps([{"number": 7, "title": ALERT_TITLE, "state": "CLOSED"}])
    # Other from:agent issues must NOT match — find is by exact title.
    DECOYS = json.dumps([{"number": 3, "title": "some other from:agent issue", "state": "OPEN"}])
    real_run = subprocess.run
    try:
        for name, verdict, listing, want_ops in [
            ("invalid + none -> create", INVALID, "[]", ["create"]),
            ("invalid + decoy titles -> create (find is by exact title)",
             INVALID, DECOYS, ["create"]),
            ("invalid + open -> edit (no duplicate)", INVALID, OPEN_HIT, ["edit"]),
            ("insufficient + closed -> REOPEN + edit (no duplicate)",
             INSUFFICIENT, CLOSED_HIT, ["reopen", "edit"]),
            ("valid + open -> comment + close", VALID, OPEN_HIT, ["comment", "close"]),
            ("valid + none -> no-op", VALID, "[]", []),
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
        # The create call must carry the rolling label + title (what find-by-title keys on).
        calls, subprocess.run = stub_gh("[]")
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
