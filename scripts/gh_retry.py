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
  * Wrap IDEMPOTENT READS only (``gh api`` GETs, --paginate list/search reads, actions-run reads).
  * NEVER wrap compare-and-swap / ledger CAS writes (the contents-API PUTs on the ``ledger``
    branch): their 409/422 conflict semantics are handled by the callers' own bounded re-read
    loops (``ledger_retry.py`` + each writer's CAS loop) — a transparent replay here would
    consume the very conflict signal those loops key on.
  * NEVER wrap mutations or mutation-confirmations (POST/PATCH/PUT/DELETE, ``gh workflow run``,
    label edits, comments): an ambiguous transient failure does not prove GitHub skipped the
    attempt — a replay duplicates comments, repeats state transitions, or double-dispatches a
    worker (incident #559's storm class). Their fail-loud semantics are deliberate (#558).

SHELL CALLERS (PR #595 finding 6): `python3 scripts/gh_retry.py read <gh args...>` runs ONE
idempotent read through this same policy and exits with gh's own status, so a workflow step gets the
bounded backoff without hand-rolling (and drifting from) the loop in bash. The subcommand is
STRUCTURALLY reads-only — `read_cli_reject` refuses any non-read verb, any `gh api` with a
non-GET method, and any request-body flag — so the hard scope rule above cannot be violated by
routing a mutation through the wrapper.

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
    # TRUNCATED / EMPTY RESPONSE BODY (registry #772). Go's encoding/json raises
    # `unexpected end of JSON input` when it decodes a body that ended early, so `gh` surfaces a
    # dropped or empty HTTP response as THAT text and NOT as a status line — `_GH_STATUS_RE`
    # finds nothing, the caller logs `http=unknown`, and the class fell through to PERMANENT.
    # It is the same availability blip as `unexpected eof` one layer up the stack, and it was the
    # dominant real cause of lost worker-provenance records: MEASURED 6 of 59 publishing
    # worker.yml runs (10.2%) after #729 merged, every one reporting `class=permanent
    # attempts=1/5` — i.e. #729's retry apparatus was inert against the very failure it was
    # built for. A read is idempotent and the budget is bounded, so re-reading a truncated body
    # is safe; a 4xx that happens to mention it still short-circuits FATAL above.
    "unexpected end of json input",
)
_SECONDARY_403 = ("secondary rate limit", "abuse detection", "retry-after", "retry later")


def is_transient_stderr(text):
    """Conservative transient classifier for `gh` CLI stderr. Fatal classes short-circuit."""
    raw = text or ""
    lowered = raw.lower()
    if _FATAL_HTTP.search(raw):
        # The one 403 exception: GitHub's secondary-rate-limit / Retry-After 403s are throttle
        # signals, not permission verdicts. 401/404/422 have no such exception — NEVER retried.
        return (("403" in raw) and any(marker in lowered for marker in _SECONDARY_403))
    if _TRANSIENT_HTTP.search(raw):
        return True
    return any(marker in lowered for marker in _TRANSIENT_TEXT)


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


# ---------------------------------------------------------------------------------------------------
# `read` CLI for SHELL callers (PR #595 finding 6). Reads-only BY CONSTRUCTION: the allowlist below
# is the complete set of gh read verbs a workflow may route through this layer, and `gh api` is
# admitted only for GET without a request body. Anything else is a usage error, never a retried call.
_READ_VERBS = frozenset({
    ("api",), ("issue", "view"), ("issue", "list"), ("pr", "view"), ("pr", "list"),
    ("pr", "checks"), ("pr", "diff"), ("label", "list"), ("run", "view"), ("run", "list"),
    ("search", "issues"), ("search", "prs"), ("release", "view"), ("release", "list"),
})
_BODY_FLAGS = frozenset({"-f", "-F", "--field", "--raw-field", "--input"})


def read_cli_reject(args):
    """Return a rejection reason for `args`, or None when it is an admissible IDEMPOTENT READ."""
    if not args:
        return "usage: gh_retry.py read <gh read args...>"
    key = (args[0],) if args[0] == "api" else tuple(args[:2])
    if key not in _READ_VERBS:
        return (f"refusing to retry {' '.join(args[:2])!r}: the read wrapper admits only "
                f"{sorted(' '.join(verb) for verb in _READ_VERBS)} (mutations must stay "
                "single-attempt and fail loud — see this module's hard scope rule)")
    for index, arg in enumerate(args):
        if arg in {"-X", "--method"}:
            method = args[index + 1] if index + 1 < len(args) else ""
            if method.upper() != "GET":
                return f"refusing to retry a non-GET gh api call (--method {method!r})"
        if arg in _BODY_FLAGS or any(arg.startswith(f"{flag}=") for flag in _BODY_FLAGS):
            return f"refusing to retry a gh api call carrying a request body ({arg})"
    return None


def read_cli(args, runner=None, out=None, err=None):
    """`gh_retry.py read <args>`: one bounded-retry READ; returns gh's exit status."""
    out, err = out if out is not None else sys.stdout, err if err is not None else sys.stderr
    reason = read_cli_reject(args)
    if reason:
        print(f"gh_retry read: {reason}", file=err)
        return 2
    result = (runner or run_gh)(list(args))
    out.write(result.stdout or "")
    err.write(result.stderr or "")
    return result.returncode


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
    check("empty stderr not transient", is_transient_stderr(""), False)
    # [registry #772] The truncated-body class, verbatim from the six worker.yml runs that lost a
    # provenance record. It carries NO HTTP status, so it reaches the text table or nothing at all.
    check("truncated JSON body transient",
          is_transient_stderr("unexpected end of JSON input"), True)
    # ...and the FATAL short-circuit still wins over it. This is the quantifier-direction guard:
    # "some truncated-body errors are transient" must never widen into "every stderr mentioning it
    # is", or a 404/422 would burn five slow attempts to reach the same loud refusal (#558).
    check("404 mentioning a truncated body is still fatal",
          is_transient_stderr("gh: Not Found (HTTP 404): unexpected end of JSON input"), False)
    check("422 mentioning a truncated body is still fatal",
          is_transient_stderr("HTTP 422: unexpected end of JSON input"), False)

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

        # [registry #772] THE PRODUCTION LEG, end to end. Asserting only
        # `is_transient_stderr(...) is True` would stay green if the marker were in the table but
        # the retry never actually re-invoked `gh` — and "the string is in a tuple" is not the
        # property that lost six provenance records. This drives the REAL loop with the REAL
        # stderr those runs emitted and counts SUBPROCESS INVOCATIONS: pre-fix this was 1.
        calls["n"] = 0
        sleeps.clear()

        def truncated_body(cmd, **kwargs):
            calls["n"] += 1
            return subprocess.CompletedProcess(
                cmd, 1, stdout="", stderr="unexpected end of JSON input")

        subprocess.run = truncated_body
        result = run_gh(["api", "repos/sparq-org/sparq/pulls/4528"], sleep=fake_sleep)
        check("truncated-body read is RETRIED to the attempt bound (was 1/5 in production)",
              (result.returncode, calls["n"], sleeps), (1, MAX_ATTEMPTS, [1, 2, 3, 4]))

        # The same leg must still make exactly ONE attempt when the truncated body comes with a
        # fatal status — deleting the fatal short-circuit reds here, not just in the table above.
        calls["n"] = 0
        sleeps.clear()

        def truncated_but_404(cmd, **kwargs):
            calls["n"] += 1
            return subprocess.CompletedProcess(
                cmd, 1, stdout="",
                stderr="gh: Not Found (HTTP 404): unexpected end of JSON input")

        subprocess.run = truncated_but_404
        result = run_gh(["api", "repos/o/r"], sleep=fake_sleep)
        check("truncated body with a FATAL status is still single-attempt",
              (result.returncode, calls["n"], sleeps), (1, 1, []))
    finally:
        subprocess.run = real_run

    # ---- `read` CLI: reads retry, everything else is REFUSED (never retried) ----
    import io

    class _Stub:
        def __init__(self, code=0):
            self.calls, self.code = [], code

        def __call__(self, args):
            self.calls.append(list(args))
            return subprocess.CompletedProcess(["gh", *args], self.code, stdout="{}", stderr="")

    stub, out, err = _Stub(), io.StringIO(), io.StringIO()
    code = read_cli(["label", "list", "-R", "o/r", "--limit", "500", "--json", "name"],
                    runner=stub, out=out, err=err)
    check("read CLI runs an admissible read through run_gh",
          (code, stub.calls, out.getvalue()), (0, [["label", "list", "-R", "o/r", "--limit", "500",
                                                    "--json", "name"]], "{}"))
    stub2, out2 = _Stub(1), io.StringIO()
    check("read CLI propagates gh's exit status",
          read_cli(["issue", "view", "7", "-R", "o/r", "--json", "labels"], runner=stub2, out=out2,
                   err=io.StringIO()), 1)
    check("read CLI admits a plain gh api GET",
          read_cli_reject(["api", "repos/o/r/collaborators/x/permission", "--jq", ".permission"]),
          None)
    # the HARD SCOPE RULE, enforced structurally: a mutation routed through the wrapper is refused
    # (not retried), so a workflow cannot give a label edit / comment / dispatch replay semantics.
    mutating = _Stub()
    for argv in (["issue", "edit", "7", "-R", "o/r", "--add-label", "role:impl"],
                 ["issue", "comment", "7", "-R", "o/r", "--body", "x"],
                 ["pr", "merge", "7"], ["workflow", "run", "dispatch.yml"],
                 ["api", "-X", "PATCH", "repos/o/r/issues/7"],
                 ["api", "--method", "PUT", "repos/o/r/contents/x"],
                 ["api", "repos/o/r/issues/7/labels", "-f", "labels[]=role:impl"],
                 ["label", "create", "x"], []):
        refused = read_cli_reject(argv) is not None
        code = read_cli(argv, runner=mutating, out=io.StringIO(), err=io.StringIO())
        check(f"read CLI refuses {' '.join(argv) or '(empty)'}", (refused, code), (True, 2))
    check("a refused call never reached gh", mutating.calls, [])

    ok = all(checks)
    print("gh-retry self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(_self_test())
    # `read <gh args...>`: the SHELL entrypoint for one bounded-retry idempotent READ (finding 6).
    if len(sys.argv) > 1 and sys.argv[1] == "read":
        raise SystemExit(read_cli(sys.argv[2:]))
    raise SystemExit("gh_retry is an import-first helper; use --self-test or `read <gh args...>`")
