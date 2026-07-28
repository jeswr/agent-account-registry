#!/usr/bin/env python3
"""Shared, credential-free retry policy for GitHub contents-ledger writers.

Three decisions live here, and every ledger CAS writer (select-and-claim's leases, worker-pr's
provenance/verdict records, model-health's window) takes all three from this one module:

  * ``is_cas_conflict`` — is this failure the compare-and-swap race the writer's re-read loop owns?
  * ``is_transient``    — is it a THROTTLE/AVAILABILITY blip that clears by waiting? Delegated to
    ``gh_retry.is_transient_stderr`` so the fleet has ONE classifier (issue #558): a secondary
    rate limit learned on the read paths is understood on the write paths too.
  * how long to wait — ``sleep_backoff`` for CAS contention (sub-second, 0.5s→8s full jitter: the
    ledger tip settles in one round trip), ``sleep_transient`` for a throttle (gh_retry's 2s→30s
    exponential-jitter schedule, honouring a capped server Retry-After: a burst limiter needs
    seconds-to-a-minute, and re-firing in 0.5s just re-trips it).

What is deliberately NOT here: the re-read. A retry that replayed the same expected blob SHA would
be a blind retry of a stale revision, so each writer's own loop re-reads the ledger and re-derives
BOTH the expected SHA and the payload before the next PUT. This module never runs a PUT.
"""

import importlib.util
import os
import random
import sys
import time


def _load_gh_retry():
    """Load the sibling gh_retry policy by PATH (not ``import gh_retry``).

    This module is itself loaded via ``importlib.util.spec_from_file_location`` from callers whose
    ``sys.path[0]`` is not ``scripts/`` (worker.yml runs an inline ``python3 -`` heredoc from the
    workspace root), so a name-based import would raise there. Path loading is the same pattern
    every other script in this repo uses for its siblings.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gh_retry.py")
    spec = importlib.util.spec_from_file_location("registry_gh_retry_for_ledger", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load shared gh retry policy")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gh_retry = _load_gh_retry()

CREATE_RACE_SIGNATURE = "\"sha\" wasn't supplied"

# Total PUT attempts a writer may spend on the THROTTLE/AVAILABILITY class before failing loud —
# gh_retry's fleet-wide bound (5), not a second knob. Bounded on purpose: an outage is not
# contention, and a persistent one must page a human inside a tight budget rather than spin.
TRANSIENT_MAX_ATTEMPTS = gh_retry.MAX_ATTEMPTS


def backoff_ceiling(attempt, base=0.5, cap=8.0):
    """Return the full-jitter exponential ceiling for a one-based retry number."""
    if attempt < 1 or base <= 0 or cap <= 0:
        raise ValueError("ledger retry backoff inputs must be positive")
    return min(cap, base * (2 ** (attempt - 1)))


def sleep_backoff(attempt, *, sleeper=time.sleep, draw=random.uniform):
    """Sleep a full-jitter delay for CAS CONTENTION.  Injection points keep callers' self-tests
    deterministic."""
    sleeper(draw(0, backoff_ceiling(attempt)))


def sleep_transient(attempt, retry_after=None, *, sleeper=time.sleep, draw=random.uniform):
    """Sleep before retrying a THROTTLE/AVAILABILITY rejection (issue #558).

    Uses gh_retry's shared schedule — exponential 2s→30s plus jitter, or a capped server
    Retry-After when one was sent — NOT the sub-second contention schedule above: GitHub's
    secondary limiter blocks for seconds-to-a-minute, so re-firing in 0.5s re-trips it and burns
    the budget without ever landing the write.
    """
    gh_retry.sleep_backoff(attempt, retry_after, sleeper=sleeper, draw=draw)


def is_cas_conflict(error_text, *, create):
    """Classify only genuine contents-API CAS races as retryable conflicts.

    A generic 422 is validation failure and therefore fails closed.  GitHub's specific sha-less
    create race is the sole retryable 422 form.
    """
    text = error_text or ""
    return "HTTP 409" in text or (
        create and "HTTP 422" in text and CREATE_RACE_SIGNATURE in text
    )


def is_transient(error_text):
    """Classify availability/rate-limit failures which may safely be retried.

    Delegates to gh_retry's fleet classifier (issue #558) so the write paths recognise every
    throttle shape the read paths do — including the secondary-rate-limit 403 a burst of concurrent
    contents-API PUTs to one branch trips, which is 403-shaped and was previously read as an
    authorization verdict and failed loud. 401/404/422 and permission/credential 403s stay FATAL;
    HTTP 409 stays the caller's CAS-conflict signal (never "transient").
    """
    return gh_retry.is_transient_stderr(error_text)


def retry_after_seconds(error_text):
    """The server's requested wait (capped) parsed out of a gh error, or None when it sent none.

    None also covers a NON-POSITIVE value: `Retry-After: 0` from an already-throttling endpoint
    would otherwise zero this writer's backoff and hot-loop the contents API. See
    `gh_retry.retry_after_seconds`.
    """
    return gh_retry.retry_after_seconds(error_text)


def _self_test():
    checks = [
        ("409 accepted", is_cas_conflict("HTTP 409: Conflict", create=False), True),
        ("signed create 422 accepted",
         is_cas_conflict("HTTP 422: Invalid request. \"sha\" wasn't supplied", create=True), True),
        ("update 422 rejected",
         is_cas_conflict("HTTP 422: \"sha\" wasn't supplied", create=False), False),
        ("validation 422 rejected", is_cas_conflict("HTTP 422: bad branch", create=True), False),
        ("rate limit transient", is_transient("HTTP 403: secondary rate limit"), True),
        ("auth 403 permanent", is_transient("HTTP 403: bad credentials"), False),
        ("server transient", is_transient("HTTP 503: unavailable"), True),
        ("bounded exponential", [backoff_ceiling(i) for i in range(1, 7)],
         [0.5, 1.0, 2.0, 4.0, 8.0, 8.0]),
        # ---- issue #558: the write-burst throttle classes the lease writer now retries ----
        ("content-creation secondary limit transient",
         is_transient("gh: You have exceeded a secondary rate limit and have been temporarily "
                      "blocked from content creation. Please retry your request again later. "
                      "(HTTP 403)"), True),
        ("primary rate-limit 403 transient",
         is_transient("HTTP 403: API rate limit exceeded for installation"), True),
        ("Retry-After 403 transient", is_transient("HTTP 403: throttled; Retry-After: 20"), True),
        ("5xx transient", is_transient("gh: Internal Server Error (HTTP 500)"), True),
        ("429 transient", is_transient("HTTP 429: too many requests"), True),
        ("network timeout transient", is_transient("net/http: TLS handshake timeout"), True),
        ("connection reset transient", is_transient("connection reset by peer"), True),
        ("permission 403 stays fatal",
         is_transient("HTTP 403: Resource not accessible by integration"), False),
        ("401 stays fatal", is_transient("HTTP 401: Bad credentials"), False),
        ("404 stays fatal", is_transient("gh: Not Found (HTTP 404)"), False),
        ("422 stays fatal", is_transient("HTTP 422: Validation Failed"), False),
        ("409 is the caller's CAS signal, never transient",
         is_transient("gh: Conflict (HTTP 409)"), False),
        ("empty error is not transient", is_transient(""), False),
        # Retry-After passthrough (capped by gh_retry so a hostile value cannot stall a run).
        ("Retry-After parsed", retry_after_seconds("HTTP 403: ... Retry-After: 25"), 25.0),
        ("Retry-After capped", retry_after_seconds("Retry-After: 100000"),
         gh_retry.RETRY_AFTER_CAP),
        ("absent Retry-After is None", retry_after_seconds("HTTP 500: oops"), None),
        # A zero wait is ABSENT at this boundary too: the ledger writers feed this straight into
        # their throttle sleep, so a literal 0 would hot-loop the contents API that is already
        # rate-limiting the fleet.
        ("Retry-After 0 is ABSENT at the ledger boundary",
         retry_after_seconds("gh: temporarily blocked; Retry-After: 0 (HTTP 403)"), None),
        ("a positive Retry-After still parses at the ledger boundary (control)",
         retry_after_seconds("gh: temporarily blocked; Retry-After: 3 (HTTP 403)"), 3.0),
    ]
    # ---- the two schedules are DISTINCT and both bounded ----
    contention, throttle = [], []
    sleep_backoff(3, sleeper=contention.append, draw=lambda lo, hi: hi)
    sleep_transient(3, sleeper=throttle.append, draw=lambda lo, hi: hi)
    checks.append(("contention sleep uses the sub-second ledger schedule",
                   contention, [backoff_ceiling(3)]))
    checks.append(("throttle sleep uses gh_retry's 2->30s schedule",
                   throttle, [gh_retry.backoff_ceiling(3) + gh_retry.JITTER]))
    checks.append(("throttle schedule is strictly slower than contention",
                   throttle[0] > contention[0], True))
    served = []
    sleep_transient(1, 99999.0, sleeper=served.append)
    checks.append(("throttle honours a capped Retry-After", served, [gh_retry.RETRY_AFTER_CAP]))
    # A `Retry-After: 0` must NOT zero the throttle wait — the writer would then re-PUT immediately
    # against the very limiter that just rejected it. Asserted on a NON-ZERO sleep end to end
    # (parse -> sleep), which is how the writers actually compose these two.
    zeroed = []
    sleep_transient(1, retry_after_seconds("gh: temporarily blocked; Retry-After: 0 (HTTP 403)"),
                    sleeper=zeroed.append, draw=lambda lo, hi: hi)
    checks.append(("a zero Retry-After never zeroes the throttle sleep",
                   (zeroed, bool(zeroed) and zeroed[0] > 0.0),
                   ([gh_retry.backoff_ceiling(1) + gh_retry.JITTER], True)))
    jittered = []
    sleep_transient(2, sleeper=jittered.append, draw=lambda lo, hi: lo)
    checks.append(("throttle jitter bounded below by the ceiling",
                   jittered, [gh_retry.backoff_ceiling(2)]))
    ok = True
    for name, got, want in checks:
        passed = got == want
        ok = ok and passed
        print(f"  {'ok  ' if passed else 'FAIL'} {name}: {got} (want {want})")
    print("ledger-retry self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(_self_test())
    raise SystemExit("ledger_retry is an import-only helper; use --self-test")
