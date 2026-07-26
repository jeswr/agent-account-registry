#!/usr/bin/env python3
"""Shared, credential-free retry policy for GitHub contents-ledger writers."""

import random
import re
import sys
import time


CREATE_RACE_SIGNATURE = "\"sha\" wasn't supplied"


def backoff_ceiling(attempt, base=0.5, cap=8.0):
    """Return the full-jitter exponential ceiling for a one-based retry number."""
    if attempt < 1 or base <= 0 or cap <= 0:
        raise ValueError("ledger retry backoff inputs must be positive")
    return min(cap, base * (2 ** (attempt - 1)))


def sleep_backoff(attempt, *, sleeper=time.sleep, draw=random.uniform):
    """Sleep a full-jitter delay.  Injection points keep callers' self-tests deterministic."""
    sleeper(draw(0, backoff_ceiling(attempt)))


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
    """Classify availability/rate-limit failures which may safely be retried."""
    text = error_text or ""
    return bool(re.search(r"HTTP 5\d\d", text)) or "HTTP 429" in text or (
        "HTTP 403" in text and "rate limit" in text.lower()
    )


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
    ]
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
