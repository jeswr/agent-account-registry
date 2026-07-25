#!/usr/bin/env python3
"""Shared bounded-retry layer for IDEMPOTENT GitHub reads (registry #563 adoption item 4).

Kills the transient-availability red class (sparq#3759's 5xx reds, the #558 tick that was
MISclassified as a lease defect but started as a transient-network storm): one gateway blip on a
read must cost a bounded retry, never the whole scheduled run.

This module owns ONLY the retry loop/sleep MECHANICS — bounded attempts, exponential backoff with
jitter, an optional capped Retry-After honour — plus a conservative transient classifier for
`gh` CLI stderr text. Callers KEEP their own domain error-classification predicates and their own
fail-loud error types; they delegate just the loop/sleep skeleton here so there is one tuned copy
instead of N drifting ones.

Retry policy (all callers inherit it):
  * bounded: at most ``MAX_ATTEMPTS`` (5) total attempts, then the failure propagates loud;
  * backoff: exponential 2s -> 30s ceiling plus uniform jitter, decorrelating parallel lanes;
  * transient-ONLY: HTTP 5xx (and 502/503/504 gateway text), HTTP 429, "secondary rate limit" /
    Retry-After-bearing 403s, network timeouts, and connection-reset/EOF drops;
  * NEVER retried: 401/404/422, permission/credential 403s, and every other non-transient
    failure — retrying a validation or auth error just burns five slow attempts to reach the
    same loud failure (the exact misclassification #558's postmortem calls out).

HARD SCOPE RULE (do not widen):
  * ``run_gh`` wraps IDEMPOTENT READS only (``gh api`` GETs, --paginate list/search reads,
    actions-run reads).
  * NEVER call ``run_gh`` on a compare-and-swap / ledger CAS write (the contents-API PUTs on the
    ``ledger`` branch): their 409/422 conflict semantics are handled by the callers' own bounded
    re-read loops (``ledger_retry.py`` + each writer's CAS loop) — a transparent replay here would
    consume the very conflict signal those loops key on, and it would replay a now-stale
    expected-SHA. The CLASSIFIER and the SLEEP SCHEDULE below are nevertheless shared with those
    writers via ``ledger_retry`` (issue #558): deciding whether an error is a throttle/availability
    blip, and how long to wait, is provider knowledge with no CAS semantics in it, while the
    re-read/re-derive step stays owned by each writer's own loop.
  * NEVER wrap mutations or mutation-confirmations (POST/PATCH/PUT/DELETE, ``gh workflow run``,
    label edits, comments): an ambiguous transient failure does not prove GitHub skipped the
    attempt — a replay duplicates comments, repeats state transitions, or double-dispatches a
    worker (incident #559's storm class). Their fail-loud semantics are deliberate (#558).

Vendored mechanics, NOT tenacity: the scheduler workflows (dispatch/groom/metrics/curate/...)
run ``python3 scripts/<x>.py`` on the bare runner with NO pip-install step, so tenacity is not
importable there. This module therefore vendors the small stdlib-only equivalent of
``tenacity.Retrying(stop=stop_after_attempt(5), wait=wait_exponential_jitter(initial=2, max=30),
retry=retry_if(<transient>))`` with the same semantics and zero dependencies.
"""

import random
import re
import subprocess
import sys
import time

MAX_ATTEMPTS = 5      # total attempts (4 retries) before the transient failure propagates loud
BASE_DELAY = 2.0      # seconds; first-retry exponential ceiling
MAX_DELAY = 30.0      # seconds; exponential ceiling clamp
JITTER = 1.0          # seconds of additive uniform jitter (tenacity wait_exponential_jitter shape)
RETRY_AFTER_CAP = 60.0  # never let a hostile/confused Retry-After stall a whole scheduled run

# Fatal classes are checked FIRST and always win: a 422 whose message happens to mention a proxy
# must still fail loud. 403 is fatal by default (auth/permission); only the secondary-rate-limit /
# Retry-After shapes below reclassify it as transient.
_FATAL_HTTP = re.compile(r"HTTP[ :]*(401|403|404|422)\b|\((401|403|404|422)\)")
_TRANSIENT_HTTP = re.compile(r"HTTP[ :]*(5\d\d|429)\b|\((5\d\d|429)\)")
_TRANSIENT_TEXT = (
    "502 bad gateway", "503 service", "504 gateway",
    "timed out", "timeout awaiting response", "tls handshake timeout", "i/o timeout",
    "context deadline exceeded",
    "connection reset", "remote end closed connection", "broken pipe", "unexpected eof",
    "connection closed before",
)
# THROTTLE-shaped 403s. GitHub answers a *secondary* rate limit (the burst limiter that a fan-out
# of concurrent contents-API PUTs to one branch trips — incident #558) with 403 and one of these
# markers, and a *primary* limit exhaustion with 'API rate limit exceeded'. Both are throttle
# signals that clear by waiting; a permission/credential 403 ('Resource not accessible by
# integration', 'Bad credentials') carries none of them and stays FATAL.
_THROTTLE_403 = (
    "rate limit",           # 'secondary rate limit' (the #558 PUT-burst limiter) AND
                            # 'API rate limit exceeded' (primary-window exhaustion)
    "abuse detection",      # the legacy name for the secondary limiter
    "temporarily blocked",  # '...temporarily blocked from content creation' — the PUT-burst form
    "retry-after",          # any throttle that sent an explicit wait
    "retry later",
)
_RETRY_AFTER_RE = re.compile(r"retry[-_ ]?after[\"'\s:=]+(\d+(?:\.\d+)?)", re.IGNORECASE)


def is_transient_stderr(text):
    """Conservative transient classifier for `gh` CLI stderr. Fatal classes short-circuit.

    Shared with the ledger CAS writers through ``ledger_retry.is_transient`` (issue #558) — one
    classifier, so a throttle shape learned in one lane is understood in all of them. HTTP 409 is
    deliberately NEITHER fatal nor transient here: it is the CAS-conflict signal each ledger writer
    owns, and it must reach that writer's re-read loop unchanged.
    """
    raw = text or ""
    lowered = raw.lower()
    if _FATAL_HTTP.search(raw):
        # The one 403 exception: GitHub's secondary/primary rate-limit and Retry-After 403s are
        # throttle signals, not permission verdicts. 401/404/422 have no such exception — NEVER
        # retried.
        return (("403" in raw) and any(marker in lowered for marker in _THROTTLE_403))
    if _TRANSIENT_HTTP.search(raw):
        return True
    return any(marker in lowered for marker in _TRANSIENT_TEXT)


def retry_after_seconds(text):
    """The server's requested wait from a `gh` error body/headers, capped at RETRY_AFTER_CAP.

    Returns None when absent, unparseable, or negative so the caller falls back to the exponential
    schedule. HTTP-date Retry-After forms (rare from GitHub) are treated as absent rather than
    mis-parsed into a wrong delay.
    """
    match = _RETRY_AFTER_RE.search(text or "")
    if match is None:
        return None
    try:
        seconds = float(match.group(1))
    except (TypeError, ValueError):  # pragma: no cover - the regex already constrains the shape
        return None
    if seconds < 0:
        return None
    return min(seconds, RETRY_AFTER_CAP)


def backoff_ceiling(attempt, base=BASE_DELAY, cap=MAX_DELAY):
    """Deterministic exponential ceiling for one-based retry `attempt`: base*2**(attempt-1), capped."""
    if attempt < 1 or base <= 0 or cap <= 0:
        raise ValueError("gh_retry backoff inputs must be positive")
    return min(cap, base * (2 ** (attempt - 1)))


def sleep_backoff(attempt, retry_after=None, *, sleeper=time.sleep, draw=random.uniform):
    """Sleep before retry `attempt`: honour a (capped) server Retry-After when given, else the
    exponential ceiling plus additive uniform jitter, clamped to MAX_DELAY. Injection points keep
    callers' self-tests deterministic and sleepless."""
    if retry_after is not None:
        sleeper(min(max(0.0, retry_after), RETRY_AFTER_CAP))
    else:
        sleeper(min(MAX_DELAY, backoff_ceiling(attempt) + draw(0, JITTER)))


def run_gh(args, *, env=None, input=None, attempts=MAX_ATTEMPTS,
           classify=is_transient_stderr, sleep=sleep_backoff):
    """Run ``gh <args>`` (capture_output, text, check=False), retrying ONLY transient failures.

    Returns the final CompletedProcess — callers keep their own returncode handling and error
    types, exactly as with a bare subprocess.run. `classify` receives stderr text and must return
    True only for transient classes; `sleep`/`attempts` are injectable for self-tests.
    IDEMPOTENT READS ONLY — see the module docstring's hard scope rule.
    """
    result = None
    for attempt in range(1, attempts + 1):
        result = subprocess.run(["gh", *args], capture_output=True, text=True,
                                check=False, env=env, input=input)
        if result.returncode == 0 or not classify(result.stderr or ""):
            return result
        if attempt < attempts:
            sleep(attempt)
    return result


def _self_test():
    checks = []

    def check(name, got, want):
        passed = got == want
        checks.append(passed)
        print(f"  {'ok  ' if passed else 'FAIL'} {name}: {got!r} (want {want!r})")

    # ---- classification: transient classes retry, fatal classes never ----
    check("5xx transient", is_transient_stderr("gh: Service Unavailable (HTTP 503)"), True)
    check("HTTP 502 prefix form transient", is_transient_stderr("HTTP 502: Bad Gateway"), True)
    check("429 transient", is_transient_stderr("HTTP 429: too many requests"), True)
    check("secondary-rate-limit 403 transient",
          is_transient_stderr("HTTP 403: You have exceeded a secondary rate limit"), True)
    check("Retry-After 403 transient",
          is_transient_stderr("HTTP 403: rate limited; Retry-After: 30"), True)
    # The exact #558 shape: a burst of concurrent contents-API PUTs to one branch.
    check("content-creation secondary-limit 403 transient",
          is_transient_stderr("gh: You have exceeded a secondary rate limit and have been "
                              "temporarily blocked from content creation. Please retry your "
                              "request again later. (HTTP 403)"), True)
    check("primary rate-limit 403 transient",
          is_transient_stderr("HTTP 403: API rate limit exceeded for installation"), True)
    check("abuse-detection 403 transient",
          is_transient_stderr("HTTP 403: You have triggered an abuse detection mechanism"), True)
    check("timeout transient", is_transient_stderr("Post ...: net/http: TLS handshake timeout"), True)
    check("connection reset transient", is_transient_stderr("connection reset by peer"), True)
    check("RemoteDisconnected transient",
          is_transient_stderr("Remote end closed connection without response"), True)
    check("401 fatal", is_transient_stderr("HTTP 401: Bad credentials"), False)
    check("404 fatal", is_transient_stderr("gh: Not Found (HTTP 404)"), False)
    check("422 fatal", is_transient_stderr("HTTP 422: Validation Failed"), False)
    check("422 mentioning a gateway is still fatal",
          is_transient_stderr("HTTP 422: upstream 502 bad gateway text"), False)
    check("permission 403 fatal", is_transient_stderr("HTTP 403: Resource not accessible"), False)
    check("bad-credentials 403 fatal", is_transient_stderr("HTTP 403: Bad credentials"), False)
    check("empty stderr not transient", is_transient_stderr(""), False)
    # 409 is the ledger CAS-conflict signal: neither fatal nor transient here, so it reaches the
    # writer's own re-read loop untouched (issue #558 / #179).
    check("409 is NOT classified transient (CAS conflict belongs to the writer)",
          is_transient_stderr("gh: Conflict (HTTP 409)"), False)

    # ---- Retry-After extraction (shared with the ledger writers via ledger_retry) ----
    check("Retry-After header parsed", retry_after_seconds("HTTP 403: ... Retry-After: 30"), 30.0)
    check("retry_after JSON-ish form parsed",
          retry_after_seconds('{"retry-after":"12"}'), 12.0)
    check("Retry-After capped", retry_after_seconds("Retry-After: 9999"), RETRY_AFTER_CAP)
    check("absent Retry-After is None", retry_after_seconds("HTTP 503: unavailable"), None)
    check("HTTP-date Retry-After treated as absent",
          retry_after_seconds("Retry-After: Wed, 21 Oct 2026 07:28:00 GMT"), None)
    check("empty text Retry-After is None", retry_after_seconds(""), None)

    # ---- backoff: exponential 2->30 ceiling, monotonic, jitter bounded ----
    ceilings = [backoff_ceiling(i) for i in range(1, 7)]
    check("exponential ceilings 2..30 capped", ceilings, [2.0, 4.0, 8.0, 16.0, 30.0, 30.0])
    check("ceilings monotonic non-decreasing",
          all(a <= b for a, b in zip(ceilings, ceilings[1:])), True)
    slept = []
    sleep_backoff(3, sleeper=slept.append, draw=lambda a, b: b)  # max jitter draw
    sleep_backoff(3, sleeper=slept.append, draw=lambda a, b: a)  # zero jitter draw
    check("jitter bounded within [ceiling, ceiling+JITTER]",
          (slept[0], slept[1]), (backoff_ceiling(3) + JITTER, backoff_ceiling(3)))
    slept.clear()
    sleep_backoff(1, retry_after=9999.0, sleeper=slept.append)
    check("Retry-After honoured but capped", slept, [RETRY_AFTER_CAP])

    # ---- run_gh loop mechanics (stubbed subprocess.run; no live gh) ----
    real_run = subprocess.run
    calls = {"n": 0}
    sleeps = []

    def fake_sleep(attempt, retry_after=None):
        sleeps.append(attempt)

    try:
        def flaky(cmd, **kwargs):  # 503 twice, then success
            calls["n"] += 1
            rc, err = (1, "HTTP 503: unavailable") if calls["n"] <= 2 else (0, "")
            return subprocess.CompletedProcess(cmd, rc, stdout="{}", stderr=err)

        subprocess.run = flaky
        result = run_gh(["api", "repos/o/r"], sleep=fake_sleep)
        check("transient retries then succeeds",
              (result.returncode, calls["n"], sleeps), (0, 3, [1, 2]))

        calls["n"] = 0
        sleeps.clear()

        def not_found(cmd, **kwargs):  # fatal class: exactly one attempt
            calls["n"] += 1
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="HTTP 404: Not Found")

        subprocess.run = not_found
        result = run_gh(["api", "repos/o/r"], sleep=fake_sleep)
        check("fatal class is not retried", (result.returncode, calls["n"], sleeps), (1, 1, []))

        calls["n"] = 0
        sleeps.clear()

        def always_503(cmd, **kwargs):  # attempt bound respected, last result returned loud
            calls["n"] += 1
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="HTTP 503: unavailable")

        subprocess.run = always_503
        result = run_gh(["api", "repos/o/r"], sleep=fake_sleep)
        check("attempt bound respected (persistent transient fails loud)",
              (result.returncode, calls["n"], sleeps), (1, MAX_ATTEMPTS, [1, 2, 3, 4]))
    finally:
        subprocess.run = real_run

    ok = all(checks)
    print("gh-retry self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(_self_test())
    raise SystemExit("gh_retry is an import-only helper; use --self-test")
