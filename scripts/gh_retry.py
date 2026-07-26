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
  * transient: HTTP 5xx (and 502/503/504 gateway text), HTTP 429, "secondary rate limit" /
    Retry-After-bearing 403s, network timeouts, and connection-reset/EOF drops;
  * NEVER retried: 401/404/422, permission/credential 403s, gh usage/flag errors, and — for
    anything that is NOT an idempotent read — every failure, transient or not;
  * STATUSLESS reads ARE retried (registry #748; see `classify_read_failure`): when the status
    cannot be recovered at all, an IDEMPOTENT READ retries rather than fails closed.

STATUS RECOVERY (registry #748 — the defect that made #729's own retry vacuous). MEASURED on
`gh 2.94.0`: for any response with a JSON content-type and an EMPTY or TRUNCATED body, gh prints a
bare ``unexpected end of JSON input`` and DISCARDS the status — 403/404/429/500/502/503 are
byte-identical on that path, so a status regex sees nothing and a text-table classifier sees no
marker. #729 routed the provenance read through this layer and then logged ``attempts=1/5`` on
4/4 real failures: the retry never engaged for the one error shape that actually occurs.
Two independent mechanisms close it, and they compose:
  1. ``GH_DEBUG=api`` (forced on every read here by `debug_env`) makes gh print
     ``< HTTP/2.0 502 …`` on STDERR while leaving STDOUT byte-identical, so the status is
     recoverable in the common case (verified: unlike ``--include``, which corrupts JSON parsing).
     The whole debug trace is then STRIPPED by `scrub_debug_trace` before any text is handed back
     to a caller, so no request/response header — and no response body — can reach a public run
     log. That guarantee does NOT rest on gh's own credential redaction.
  2. When even the trace yields no status, an idempotent READ retries (reason ``statusless``).
     The asymmetry is one-directional: retrying a permanent 404 costs four bounded, jittered
     attempts to reach the SAME loud failure, while not retrying a transient 502 costs a
     provenance record, a ``__global__`` lane stall and a human intervention. Bounded to reads by
     `read_cli_reject`, so it cannot make a write replayable.

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
STRUCTURALLY reads-only — `read_cli_reject` refuses any non-read verb, any `gh api` whose EFFECTIVE
method is not GET, and any request body — so the hard scope rule above cannot be violated by
routing a mutation through the wrapper. `run_gh` applies the SAME predicate: a non-read gets exactly
ONE attempt and a `GH-RETRY-SCOPE-REFUSED` log line, never a replay.

The method/body parse lives in ONE place (`gh_request_shape`) because two copies drifted: registry
#731 measured that the previous flag scan saw only the DETACHED forms, so `-XPUT`, `--method=POST`,
`-X=DELETE` and `-fkey=val` (gh's implicit POST) were all admitted as "reads", while a legitimate
`-X GET … -f q=…` search read was refused. Verified against gh 2.94.0 with a local echo server:
fields under an explicit `-X GET` are sent as QUERY PARAMETERS with no body, while fields with no
`-X` make gh POST a JSON body.

Vendored mechanics, NOT tenacity: the scheduler workflows (dispatch/groom/metrics/curate/...)
run ``python3 scripts/<x>.py`` on the bare runner with NO pip-install step, so tenacity is not
importable there. This module therefore vendors the small stdlib-only equivalent of
``tenacity.Retrying(stop=stop_after_attempt(5), wait=wait_exponential_jitter(initial=2, max=30),
retry=retry_if(<transient>))`` with the same semantics and zero dependencies.
"""

import os
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
# Statusless failures that retrying CANNOT fix: gh usage/flag errors and "no credential configured".
# Everything ELSE that is statusless is retried on a read (registry #748) — this table exists so a
# typo'd flag does not cost four jittered attempts, NOT to decide availability questions.
_FATAL_TEXT = (
    "unknown flag", "unknown shorthand flag", "unknown command", "unknown subcommand",
    "accepts at most", "accepts between", "requires at least", "required flag",
    "must be authenticated", "gh_token environment variable", "not logged into",
)
# Statuses that are a REFUSAL, not an availability blip. 403 has one exception (below).
_REFUSAL_STATUSES = frozenset({"401", "403", "404", "422"})
# The status as printed in gh's OWN message: `HTTP 404: ...` and `gh: Not Found (HTTP 404)`.
_MESSAGE_STATUS_RE = re.compile(r"HTTP[ :]*([1-5]\d\d)\b|\(HTTP ([1-5]\d\d)\)")


def is_transient_stderr(text):
    """Conservative transient classifier for `gh` CLI stderr. Fatal classes short-circuit.

    Unchanged by registry #748 and deliberately so: callers that only want a LABEL for a failure
    (worker-pr's `class=`, groom's domain predicate) keep the historical answer, and the widened
    read-scoped decision lives in `classify_read_failure`."""
    raw = text or ""
    lowered = raw.lower()
    if _FATAL_HTTP.search(raw):
        # The one 403 exception: GitHub's secondary-rate-limit / Retry-After 403s are throttle
        # signals, not permission verdicts. 401/404/422 have no such exception — NEVER retried.
        return (("403" in raw) and any(marker in lowered for marker in _SECONDARY_403))
    if _TRANSIENT_HTTP.search(raw):
        return True
    return any(marker in lowered for marker in _TRANSIENT_TEXT)


# ---------------------------------------------------------------------------------------------------
# Registry #748: STATUS RECOVERY off gh's debug channel, and the read-scoped classifier.
GH_DEBUG_MODE = "api"                       # the gh debug mode that prints the response status line
SCOPE_REFUSED_MARKER = "GH-RETRY-SCOPE-REFUSED"   # a non-read reached run_gh: 1 attempt, no replay
BLIND_READ_MARKER = "GH-RETRY-BLIND-READ"         # retried a read whose status we could NOT recover

# One debug "request block" is `* Request at …` … `* Request took …`; gh's OWN diagnostic is whatever
# follows the LAST such block. Response BODIES are printed inside a block, unprefixed, so keeping
# only the post-block tail drops them too — see scrub_debug_trace.
_TRACE_END_RE = re.compile(r"^\* Request took .*$", re.M)
_TRACE_LINE_RE = re.compile(r"^[*<>](?:$| )", re.M)
_TRACE_STATUS_RE = re.compile(r"^< HTTP/[0-9.]+[ ]+([1-5]\d\d)\b", re.M)
# Belt-and-braces for a gh format change: response BODIES are printed unprefixed, so if gh ever
# stops emitting the `* Request took` terminator the block-based drop below would leave one behind.
# gh's own one-line diagnostics never start with a JSON/indent character, so dropping these can only
# ever cost log detail, never correctness — and the direction of that trade is not negotiable when
# the sink is a public run log.
_BODYISH_LINE_RE = re.compile(r"^(?:[\s{}\[\]\"]|$)")


def debug_env(env=None):
    """Child env for a read: `GH_DEBUG` is forced to CONTAIN `api` so the response status line
    reaches stderr and the failure is classifiable.

    Ambient `GH_DEBUG` can only WIDEN this, never disable it. That direction is load-bearing at the
    YAML seam: a job- or workflow-level `GH_DEBUG: ""` (or any other mode) would otherwise silently
    restore the exact statusless blindness registry #748 fixes, and nothing would go red."""
    merged = dict(os.environ if env is None else env)
    modes = [mode for mode in re.split(r"[,\s]+", merged.get("GH_DEBUG") or "") if mode]
    if GH_DEBUG_MODE not in modes:
        modes.append(GH_DEBUG_MODE)
    merged["GH_DEBUG"] = ",".join(modes)
    return merged


def scrub_debug_trace(text):
    """gh's own diagnostic with the ENTIRE `GH_DEBUG=api` trace removed.

    This is the credential/PII boundary, and it is deliberately structural rather than a redaction
    list: everything up to and including the last `* Request took …` line is dropped, which removes
    every request header (`> Authorization: …`), every response header, AND the response body gh
    dumps for a failed request. Only the parsed 3-digit status escapes the trace, via
    `trace_status`. gh 2.94.0 does redact `Authorization` itself (measured: `token ████…`, zero
    hits for the live token) — but these run logs are PUBLIC and unrecoverable once written, so the
    guarantee here must not depend on a vendor behaviour that a gh upgrade could change."""
    raw = text or ""
    end = None
    for match in _TRACE_END_RE.finditer(raw):
        end = match
    tail = raw[end.end():] if end else raw
    traced = end is not None or bool(_TRACE_LINE_RE.search(raw))
    kept = [line for line in tail.splitlines()
            if not _TRACE_LINE_RE.match(line)
            and not (traced and _BODYISH_LINE_RE.match(line))]
    return "\n".join(kept).strip()


def trace_status(text):
    """The LAST response status in a `GH_DEBUG=api` trace, or None. Last, not first: gh follows
    redirects and paginates in-process, and it ABORTS on the first failure, so the final response
    line is the one that decided the exit status."""
    found = _TRACE_STATUS_RE.findall(text or "")
    return found[-1] if found else None


def failure_status(message, trace=None):
    """The HTTP status of a failed `gh` call: gh's own message when it printed one, else recovered
    from the debug trace. None means the status is genuinely unrecoverable — the shape registry
    #748 is about."""
    match = _MESSAGE_STATUS_RE.search(message or "")
    if match:
        return match.group(1) or match.group(2)
    return trace_status(trace if trace is not None else message)


def classify_read_failure(message, status=None):
    """Classify a FAILED IDEMPOTENT READ. Returns `(retry: bool, reason: str)`.

    The retry DIRECTION for an unrecoverable status is the whole point of registry #748, and it is
    justified by a one-directional asymmetry that holds only for reads: retrying a permanent 404
    costs four bounded, jittered attempts to reach the same loud failure, whereas NOT retrying a
    transient 502 costs a provenance record, a `__global__` lane reservation and a human
    intervention. So the default for an unclassifiable read failure is RETRY, and the exceptions are
    the two things retrying provably cannot fix: a recovered REFUSAL status, and a gh usage error.

    It is NOT a blanket "retry every unparseable error": this function is only ever consulted for
    argv that `read_cli_reject` admits, i.e. a read verb (or `gh api` whose effective method is GET)
    with no request body. A write cannot become non-idempotent through this branch because a write
    never reaches it — `run_gh` selects the conservative `is_transient_stderr` for anything the
    read predicate refuses, and caps it at one attempt."""
    lowered = (message or "").lower()
    if status in _REFUSAL_STATUSES:
        if status == "403" and any(marker in lowered for marker in _SECONDARY_403):
            return True, "secondary-rate-limit-403"
        return False, f"refused-http-{status}"
    if status and (status.startswith("5") or status == "429"):
        return True, f"transient-http-{status}"
    if is_transient_stderr(message or ""):
        return True, "transient-text"
    if any(marker in lowered for marker in _FATAL_TEXT):
        return False, "usage-error"
    if status:
        # A non-refusal status that still failed: the HTTP exchange is not what refused us, so this
        # is a truncated body or a local decode failure — the transient case, same as statusless.
        return True, f"unparsed-http-{status}"
    return True, "statusless"


def is_retryable_read_stderr(text, status=None):
    """`classify_read_failure`'s boolean, for callers that want the predicate shape."""
    return classify_read_failure(text, status)[0]


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


class GhResult(subprocess.CompletedProcess):
    """A `CompletedProcess` whose `stderr` has the `GH_DEBUG` trace REMOVED (so no caller can leak
    it into a public log by echoing an error message) plus the retry-layer's own observations:

      * `gh_http_status`  — the status, recovered from gh's message OR the debug trace, or None;
      * `gh_attempts`     — attempts actually spent (1 means "not retried");
      * `gh_retry_reason` — the `classify_read_failure` reason for the LAST failure, or None;
      * `gh_read_scoped`  — whether `read_cli_reject` admitted this argv as an idempotent read.

    `gh_attempts` + `gh_http_status` are what make the registry #729 failure mode ASSERTABLE by a
    caller: `attempts == 1 and gh_http_status is None` on a failed read is exactly the shape that
    shipped broken, and worker-pr now raises a distinct alarm on it instead of logging it quietly.
    """

    def __init__(self, args, returncode, stdout, stderr, *, status=None, attempts=1,
                 reason=None, read_scoped=True):
        super().__init__(args, returncode, stdout, stderr)
        self.gh_http_status = status
        self.gh_attempts = attempts
        self.gh_retry_reason = reason
        self.gh_read_scoped = read_scoped


def run_gh(args, *, env=None, input=None, attempts=MAX_ATTEMPTS,
           classify=None, sleep=sleep_backoff, debug_status=True, log=None):
    """Run ``gh <args>`` (capture_output, text, check=False), retrying only retryable failures.

    Returns the final `GhResult` — callers keep their own returncode handling and error types,
    exactly as with a bare subprocess.run, and `stderr` is gh's own diagnostic with the debug trace
    scrubbed out. `classify` (legacy shape: `classify(stderr_text) -> bool`) overrides the decision;
    when it is None the layer uses `classify_read_failure` with the RECOVERED status.
    `sleep`/`attempts`/`log` are injectable for self-tests.

    IDEMPOTENT READS ONLY — and now enforced here, not only by convention: when
    `read_cli_reject` refuses the argv, this runs it EXACTLY ONCE with the conservative historical
    classifier and prints `GH-RETRY-SCOPE-REFUSED`. That keeps a mis-adopted write at today's
    fail-loud single-attempt semantics (registry #731's "one adopter away" hazard) without a
    refusal that could red a scheduled run outright.
    """
    listed = list(args)
    report = log if log is not None else (lambda line: print(line, file=sys.stderr, flush=True))
    scope_reason = read_cli_reject(listed)
    read_scoped = scope_reason is None
    if not read_scoped:
        report(f"gh_retry: {SCOPE_REFUSED_MARKER} {scope_reason}")
        attempts = 1
    child_env = debug_env(env) if debug_status else env
    result = None
    for attempt in range(1, attempts + 1):
        raw = subprocess.run(["gh", *listed], capture_output=True, text=True,
                             check=False, env=child_env, input=input)
        raw_stderr = raw.stderr or ""
        message = scrub_debug_trace(raw_stderr)
        status = failure_status(message, raw_stderr) if raw.returncode != 0 else None
        if raw.returncode == 0:
            retry, reason = False, None
        elif classify is not None:
            retry, reason = bool(classify(message)), "caller-classifier"
        elif read_scoped:
            retry, reason = classify_read_failure(message, status)
        else:
            retry, reason = is_transient_stderr(message), "non-read-conservative"
        result = GhResult(["gh", *listed], raw.returncode, raw.stdout, message,
                          status=status, attempts=attempt, reason=reason,
                          read_scoped=read_scoped)
        if raw.returncode == 0 or not retry:
            return result
        if attempt < attempts:
            if reason == "statusless":
                # Counted, greppable signal that we retried BLIND. Registry #748's deeper defect was
                # not the missing retry, it was that a whole error class could report `attempts=1/5`
                # with nobody able to see it; every caller of this layer now emits a line when the
                # status could not be recovered, so the class is visible on its first occurrence.
                report(f"gh_retry: {BLIND_READ_MARKER} endpoint="
                       f"{listed[1] if len(listed) > 1 else listed[0]} attempt={attempt}"
                       f"/{attempts} — no HTTP status recoverable from gh's message or its debug "
                       f"trace; retrying because this argv is an idempotent read")
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
_METHOD_FLAGS = frozenset({"-X", "--method"})
_FIELD_FLAGS = frozenset({"-f", "-F", "--field", "--raw-field"})
# `-XPUT`, `--method=POST`, `-fkey=val`, `--field=k=v`: the ATTACHED forms pflag accepts, which the
# pre-#731 scan (equality + `flag=` prefix only) did not see. `-X=PUT` is also accepted by pflag.
_ATTACHED_METHOD_RE = re.compile(r"^(?:--method=|-X=?)(.+)$")
_ATTACHED_FIELD_RE = re.compile(r"^(?:--(?:field|raw-field)=|-[fF]=?)(.+)$")
_INPUT_FLAG_RE = re.compile(r"^--input(?:=.*)?$")


def gh_request_shape(args):
    """Parse a `gh` argv into `{verb, method, effective_method, fields, body}` — the SINGLE parser
    behind every read-scope decision in this module (registry #731: two hand-rolled scans drifted).

    `effective_method` is gh's real behaviour, MEASURED against gh 2.94.0 with a local echo server:
      * `-X GET … -f q=…`  -> GET, fields become QUERY PARAMETERS, no request body (a real read);
      * `… -f a=b` with no `-X` -> POST with a JSON body (gh's implicit method — NOT a read);
      * `-XPUT` / `--method=POST` / `-X=DELETE` -> the attached forms are real methods.
    So field flags are admissible ONLY under an explicit GET, and `--input` never is."""
    listed = list(args)
    verb = (listed[0],) if listed and listed[0] == "api" else tuple(listed[:2])
    method, fields, body = None, [], None
    index = 0
    while index < len(listed):
        arg = listed[index]
        if arg in _METHOD_FLAGS:
            method = (listed[index + 1] if index + 1 < len(listed) else "").upper()
            index += 2
            continue
        attached_method = _ATTACHED_METHOD_RE.match(arg)
        if attached_method:
            method = attached_method.group(1).upper()
            index += 1
            continue
        if _INPUT_FLAG_RE.match(arg):
            body = arg
        elif arg in _FIELD_FLAGS:
            fields.append(arg)
            index += 2
            continue
        elif _ATTACHED_FIELD_RE.match(arg):
            fields.append(arg)
        index += 1
    effective = method or ("POST" if fields or body else "GET")
    return {"verb": verb, "method": method, "effective_method": effective,
            "fields": fields, "body": body}


def read_cli_reject(args):
    """Return a rejection reason for `args`, or None when it is an admissible IDEMPOTENT READ."""
    if not args:
        return "usage: gh_retry.py read <gh read args...>"
    shape = gh_request_shape(args)
    if shape["verb"] not in _READ_VERBS:
        return (f"refusing to retry {' '.join(args[:2])!r}: the read wrapper admits only "
                f"{sorted(' '.join(verb) for verb in _READ_VERBS)} (mutations must stay "
                "single-attempt and fail loud — see this module's hard scope rule)")
    if shape["body"] is not None:
        return (f"refusing to retry a gh api call carrying a request body ({shape['body']}) — a "
                "replayed body is a replayed write")
    if shape["effective_method"] != "GET":
        detail = (f"--method {shape['method']!r}" if shape["method"]
                  else f"implicit POST from {shape['fields'][0]!r} (gh sends fields with no -X as a "
                       "POST body)")
        return f"refusing to retry a non-GET gh api call ({detail})"
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


# ---------------------------------------------------------------------------------------------------
# Registry #748: the stderr shapes `gh` ACTUALLY emits, captured from gh 2.94.0 against a local
# server that reproduces each response shape (and against api.github.com for the authenticated
# ones). `retry` is the required verdict for an IDEMPOTENT READ; None for `status` means gh printed
# no status anywhere. This table exists so the classifier is checked against the tool's real output
# instead of against the classifier's own assumptions — the #729 failure was precisely a table that
# did not contain the one shape that occurs.
OBSERVED_GH_FAILURES = (
    # (label, gh stderr, recoverable status, must-retry-on-a-read)
    ("empty-json-body 403", "unexpected end of JSON input", None, True),
    ("empty-json-body 404", "unexpected end of JSON input", None, True),
    ("empty-json-body 429", "unexpected end of JSON input", None, True),
    ("empty-json-body 500", "unexpected end of JSON input", None, True),
    ("empty-json-body 502", "unexpected end of JSON input", None, True),
    ("empty-json-body 503", "unexpected end of JSON input", None, True),
    ("truncated-json-body 404", "unexpected end of JSON input", None, True),
    ("non-json 502", "gh: HTTP 502", "502", True),
    ("real GitHub 404 body", "gh: Not Found (HTTP 404)", "404", False),
    ("real GitHub 401 body", "gh: Bad credentials (HTTP 401)", "401", False),
    ("connection refused",
     'Get "https://api.github.com/x": dial tcp 140.82.121.6:443: connect: connection refused',
     None, True),
    ("secondary rate limit",
     "HTTP 403: You have exceeded a secondary rate limit (https://api.github.com/x)", "403", True),
    ("permission 403", "HTTP 403: Resource not accessible by integration", "403", False),
    ("usage error", "unknown flag: --jsonn", None, False),
)

# The same 502 failure WITH `GH_DEBUG=api` on, verbatim in shape from the local reproduction: this is
# the stream `scrub_debug_trace` must reduce to gh's one-line diagnostic and `trace_status` must
# mine the status out of. The `Authorization` line here is deliberately NOT redacted (gh 2.94.0 does
# redact it) so the guard proves the scrub does not DEPEND on that redaction.
DEBUG_TRACE_SAMPLE = """* Request at 2026-07-26 21:30:08.998188174 +0000 UTC m=+0.051081984
* Request to https://api.github.com/repos/o/r/pulls/4308
> GET /repos/o/r/pulls/4308 HTTP/1.1
> Host: api.github.com
> Accept: */*
> Authorization: token ghs_SENTINELTOKENVALUE0123456789
> User-Agent: GitHub CLI 2.94.0
< HTTP/2.0 502 Bad Gateway
< Content-Length: 0
< Content-Type: application/json
< X-Github-Request-Id: C6F8:24195E:40B739:4D4493:6A667C85
* body cannot be formatted: unexpected EOF
{"message": "secret-response-body"}
* Request took 987.59µs
unexpected end of JSON input"""


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

    # ---- registry #748: STATUSLESS read failures, status recovery, and the scope boundary --------
    # G1 — THE mutant that matters. `unexpected end of JSON input` with no status anywhere is the
    # exact byte-for-byte shape that shipped broken in #729 (`http=unknown class=permanent
    # attempts=1/5` on 4/4 real failures). On an idempotent read it must now be RETRIED.
    _STATUSLESS = "unexpected end of JSON input"
    check("#748 a STATUSLESS 'unexpected end of JSON input' is RETRYABLE on an idempotent read",
          classify_read_failure(_STATUSLESS), (True, "statusless"))
    check("#748 the pre-fix conservative classifier still says NO to it "
          "(so the two classifiers are genuinely different and the widening is the fix)",
          is_transient_stderr(_STATUSLESS), False)

    real_run = subprocess.run
    try:
        calls, sleeps, logged = [], [], []

        def _statusless_then_ok(cmd, **kwargs):
            calls.append(list(cmd))
            if len(calls) <= 2:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=_STATUSLESS)
            return subprocess.CompletedProcess(cmd, 0, stdout="{}", stderr="")

        subprocess.run = _statusless_then_ok
        result = run_gh(["api", "repos/o/r/pulls/4308"], sleep=lambda a, r=None: sleeps.append(a),
                        log=logged.append)
        check("#748 a statusless read failure is RETRIED and then SUCCEEDS "
              "(the #729 vacuity: this used to be 1 attempt)",
              (result.returncode, len(calls), sleeps, result.gh_attempts), (0, 3, [1, 2], 3))
        check("#748 retrying BLIND emits the counted GH-RETRY-BLIND-READ signal for every caller "
              "of this layer, naming the endpoint",
              (len([line for line in logged if BLIND_READ_MARKER in line]),
               all("repos/o/r/pulls/4308" in line for line in logged)), (2, True))

        # G2 — the status RECOVERED from the debug channel is what decides, and it decides in BOTH
        # directions: a 502 trace retries, a 404 trace does NOT (one attempt, still distinguishable).
        for label, trace_status_line, want_calls, want_status, want_reason in (
                ("502", "< HTTP/2.0 502 Bad Gateway", MAX_ATTEMPTS, "502", "transient-http-502"),
                ("404", "< HTTP/2.0 404 Not Found", 1, "404", "refused-http-404")):
            calls.clear()
            sleeps.clear()
            stream = (f"* Request at t\n> GET /x HTTP/1.1\n> Authorization: token ghs_SENTINEL\n"
                      f"{trace_status_line}\n* Request took 1ms\n{_STATUSLESS}")

            def _traced(cmd, _stream=stream, **kwargs):
                calls.append(list(cmd))
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=_stream)

            subprocess.run = _traced
            traced = run_gh(["api", "repos/o/r/pulls/7"], sleep=lambda a, r=None: sleeps.append(a))
            check(f"#748 the status recovered from the DEBUG channel is used ({label}) — "
                  f"and it is the only thing that escapes the trace",
                  (len(calls), traced.gh_http_status, traced.gh_retry_reason, traced.stderr),
                  (want_calls, want_status, want_reason, _STATUSLESS))

        # G3 — a GENUINE permanent refusal that gh DID classify is still refused in one attempt.
        calls.clear()
        sleeps.clear()

        def _refused(cmd, **kwargs):
            calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 1, stdout="",
                                               stderr="gh: Not Found (HTTP 404)")

        subprocess.run = _refused
        refusal = run_gh(["api", "repos/o/r/pulls/7"], sleep=lambda a, r=None: sleeps.append(a))
        check("#748 a genuine permanent refusal is STILL refused in one attempt and stays "
              "DISTINGUISHABLE from the statusless class",
              (len(calls), sleeps, refusal.gh_http_status, refusal.gh_retry_reason),
              (1, [], "404", "refused-http-404"))

        # G4 — a gh USAGE error is statusless but unfixable by retrying: still one attempt.
        calls.clear()

        def _usage(cmd, **kwargs):
            calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="unknown flag: --jsonn")

        subprocess.run = _usage
        usage = run_gh(["api", "repos/o/r", "--jsonn"], sleep=lambda a, r=None: None)
        check("#748 a gh USAGE error is not retried even though it is statusless",
              (len(calls), usage.gh_retry_reason), (1, "usage-error"))

        # G5 — the SCOPE boundary: a non-read that reaches run_gh gets exactly ONE attempt (today's
        # write semantics) plus a counted refusal marker. A retried write is what registry #731
        # called "one adopter away"; this is the layer-level backstop for it.
        for argv in (["api", "-X", "POST", "repos/o/r/issues"],
                     ["api", "-XPUT", "repos/o/r/contents/x"],
                     ["api", "--method=PATCH", "repos/o/r/issues/7"],
                     ["api", "repos/o/r/issues", "-fbody=x"],
                     ["issue", "comment", "7", "-R", "o/r", "--body", "x"]):
            calls.clear()
            sleeps.clear()
            logged.clear()

            def _flaky_write(cmd, **kwargs):
                calls.append(list(cmd))
                return subprocess.CompletedProcess(cmd, 1, stdout="",
                                                   stderr="gh: Service Unavailable (HTTP 503)")

            subprocess.run = _flaky_write
            written = run_gh(argv, sleep=lambda a, r=None: sleeps.append(a), log=logged.append)
            check(f"#748 run_gh REFUSES to replay {' '.join(argv[:3])} — one attempt, counted",
                  (len(calls), sleeps, written.gh_read_scoped,
                   any(SCOPE_REFUSED_MARKER in line for line in logged)),
                  (1, [], False, True))
    finally:
        subprocess.run = real_run

    # G6 — the credential/PII boundary, asserted against the REAL debug-stream shape with an
    # UNREDACTED Authorization line and a response body. These run logs are PUBLIC and unrecoverable
    # once written, so the guarantee must be structural, not a dependency on gh's own redaction.
    scrubbed = scrub_debug_trace(DEBUG_TRACE_SAMPLE)
    check("#748 scrub_debug_trace keeps ONLY gh's own diagnostic",
          scrubbed, "unexpected end of JSON input")
    check("#748 NO credential material, header, or response body survives the scrub "
          "(asserted even though gh 2.94.0 redacts Authorization itself)",
          ("SENTINELTOKEN" in scrubbed, "Authorization" in scrubbed,
           "secret-response-body" in scrubbed, "X-Github-Request-Id" in scrubbed,
           "api.github.com" in scrubbed),
          (False, False, False, False, False))
    check("#748 the status is STILL recovered from the very trace that was scrubbed away",
          (trace_status(DEBUG_TRACE_SAMPLE), failure_status(scrubbed, DEBUG_TRACE_SAMPLE)),
          ("502", "502"))
    check("#748 trace_status takes the LAST response (redirects/pagination end on the deciding one)",
          trace_status("< HTTP/2.0 301 Moved\n< HTTP/1.1 502 Bad Gateway\n"), "502")
    # If a gh upgrade ever drops the `* Request took` terminator, the block-based drop above loses
    # its anchor — the body must STILL not survive. A public run log is unrecoverable once written,
    # so this direction is not allowed to depend on gh keeping its output format.
    truncated_trace = DEBUG_TRACE_SAMPLE.replace("* Request took 987.59µs\n", "")
    check("#748 a trace with NO terminator still leaks nothing (format-change safety)",
          (scrub_debug_trace(truncated_trace), trace_status(truncated_trace)),
          ("unexpected end of JSON input", "502"))
    check("#748 the body-ish filter is scoped to DEBUG streams only — a plain gh message is never "
          "mangled", (scrub_debug_trace("unexpected end of JSON input"),
                      scrub_debug_trace('  {"message": "x"} not a trace')),
          ("unexpected end of JSON input", '{"message": "x"} not a trace'))

    # G7 — GH_DEBUG can only be WIDENED by the environment, never disabled. This is the YAML seam:
    # a job-level `GH_DEBUG: ""` would otherwise silently restore statusless blindness with nothing
    # going red.
    for ambient, want in (({}, "api"), ({"GH_DEBUG": ""}, "api"), ({"GH_DEBUG": "oauth"},
                                                                  "oauth,api"),
                          ({"GH_DEBUG": "api"}, "api"), ({"GH_DEBUG": "false"}, "false,api")):
        check(f"#748 debug_env forces the api mode on regardless of ambient {ambient!r}",
              debug_env({**ambient}).get("GH_DEBUG"), want)
    check("#748 debug_env preserves the rest of the caller's env",
          debug_env({"GH_TOKEN": "t"}).get("GH_TOKEN"), "t")

    # G8 — registry #731, fixed here because this PR's whole retry-direction justification rests on
    # "a write never reaches the widened branch". ATTACHED method/field forms are real methods.
    for argv, admissible in (
            (["api", "-XPUT", "repos/o/r/contents/x"], False),
            (["api", "-X=DELETE", "repos/o/r/x"], False),
            (["api", "--method=POST", "repos/o/r/issues"], False),
            (["api", "-fbody=hello", "repos/o/r/issues/7/comments"], False),
            (["api", "-Fbody=hello", "repos/o/r/issues/7/comments"], False),
            (["api", "--field=body=x", "repos/o/r/issues/7/comments"], False),
            (["api", "--input=payload.json", "repos/o/r/x"], False),
            (["api", "-XGET", "repos/o/r/pulls/7"], True),
            (["api", "-X", "GET", "search/issues", "-f", "q=repo:o/r", "-f", "per_page=1"], True),
            (["api", "--paginate", "repos/o/r/issues?state=open"], True)):
        check(f"#731 read scope on {' '.join(argv[:3])}: "
              f"{'admitted' if admissible else 'REFUSED'}",
              read_cli_reject(argv) is None, admissible)
    check("#731 the effective method is parsed once, and fields under an explicit GET are QUERY "
          "params (measured against gh 2.94.0), while fields with no -X are gh's implicit POST",
          (gh_request_shape(["api", "-X", "GET", "x", "-f", "q=1"])["effective_method"],
           gh_request_shape(["api", "x", "-f", "q=1"])["effective_method"],
           gh_request_shape(["api", "-XPUT", "x"])["effective_method"]),
          ("GET", "POST", "PUT"))

    # G9 — the UNIVERSAL property over the measured corpus, not a per-case list. Any future stderr
    # shape added here that the classifier gets wrong goes red, which is the guard the #729 table
    # lacked: it could not notice that the one shape it omitted was the only one that occurs.
    corpus_status = [(label, failure_status(text), want_status)
                     for label, text, want_status, _retry in OBSERVED_GH_FAILURES]
    check("#748 every MEASURED gh failure shape recovers exactly the status it printed "
          "(None where gh printed none)",
          [row for row in corpus_status if row[1] != row[2]], [])
    corpus_verdicts = [(label, classify_read_failure(text, failure_status(text))[0], want)
                       for label, text, _status, want in OBSERVED_GH_FAILURES]
    check("#748 every MEASURED gh failure shape is classified as the read policy requires",
          [row for row in corpus_verdicts if row[1] != row[2]], [])
    unretried_statusless = [label for label, text, status, _want in OBSERVED_GH_FAILURES
                            if status is None and failure_status(text) is None
                            and not classify_read_failure(text)[0]
                            and not any(m in text.lower() for m in _FATAL_TEXT)]
    check("#748 INVARIANT: no statusless, non-usage failure shape is ever refused on a read — the "
          "rule that makes an omitted table entry harmless",
          unretried_statusless, [])
    check("#748 the corpus actually EXERCISES the statusless class (an empty corpus would pass "
          "the invariant above vacuously)",
          len([1 for _l, text, status, _w in OBSERVED_GH_FAILURES
               if status is None and failure_status(text) is None]) >= 8, True)

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
