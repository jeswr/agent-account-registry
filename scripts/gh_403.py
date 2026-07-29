#!/usr/bin/env python3
"""THE 403 TAXONOMY — one classifier, for every component that has to read a GitHub 403.

WHY THIS FILE EXISTS (registry #1208). A 403 is not one condition. It is three server answers
wearing the same number, and the correct RESPONSE to each is different — one of them is the exact
opposite of the others:

  secondary   GitHub is throttling a burst. Carries `Retry-After` (or says "secondary rate limit" /
              "abuse detection" / "temporarily blocked"). RETRY, after the wait it asks for.
  budget      The token's hourly request budget is spent. Body says "API rate limit exceeded",
              `x-ratelimit-remaining: 0`, and — measured, 0 of 27 observed failures on 2026-07-27 —
              NO `Retry-After` at all. DO NOT RETRY: the reset is a clock up to an hour away, and
              every retry spends a request from a bucket that has none. The wait is machine-cleared;
              nothing a human does shortens it.
  permission  The token cannot do this. NOT retryable, and never was.

Before this module the taxonomy existed only inside `plan-snapshot.py` (#819), which reads real
`urllib` response headers. `dispatch-secrets-guard.py` sees a 403 too — through `gh` CLI stderr,
where there are no headers — and it had a SECOND, coarser classifier that put every 403 in one
"transient/availability" bucket. MEASURED 2026-07-29, 06:00-09:00Z: GUARD failed on 16 of 51 started
dispatch runs (31%) reporting "failed for an availability reason", and in 4 of those PLAN reached
the same 403 and printed the truth — `request budget exhausted, x-ratelimit-remaining=0/5000`. One
403, two components, two diagnoses, and the guard's motivated a retry against a bucket at zero.

So: ONE taxonomy, TWO entry points, because the two callers genuinely have different evidence.

  classify_403(headers, body)   the authoritative form. Headers are positive evidence.
  classify_403_text(text)       the degraded form, for a caller that only ever sees `gh` stderr.
                                Markers only — NO header evidence exists on this path, so a caller
                                using it must NOT claim to have read `x-ratelimit-remaining`.

BOTH ORDERS ARE THE CONTRACT, and they are the same order:
  * `secondary` is tested FIRST because a secondary-limit 403 can also carry rate-limit headers;
    calling one `budget` would stop a sweep that only needed to wait the few seconds GitHub asked
    for.
  * `budget` is tested before `permission` because `permission` is the RESIDUAL class — the one
    with no positive evidence — and a residual class must never be inferred from the ABSENCE of a
    header that a truncated response might simply have dropped.

MARKERS ARE SPECIFIC PHRASES, DELIBERATELY. A bare `"rate limit"` substring matches BOTH limits at
once (it is a prefix of "secondary rate limit"), and it also matches GitHub's own documentation URL
— "...for more information about rate limiting..." — which appears in the body of unrelated errors.
That marker cannot express the distinction this module exists to draw. `scripts/gh_retry.py` still
carries one; see `_test_gh_retry_marker_is_ambiguous` for the demonstration and the note on why it
is a separate decision from this one.

Pure functions only. No I/O, no imports beyond the standard library, so the fail-closed
`dispatch-secrets-guard` can load it without widening its own attack surface.
"""
import sys

# ---------------------------------------------------------------------------------------------
# MARKERS. Positive evidence only, in the wording GitHub actually emits.

# The burst limiter. `retry later` is GitHub's own phrasing in the content-creation form.
SECONDARY_403_MARKERS = ("secondary rate limit", "abuse detection", "retry later")

# TEXT-PATH-ONLY secondary markers. On the header path these two are read from the `Retry-After`
# HEADER, which is stronger evidence than prose; on the `gh` CLI path there is no header to read,
# so the same facts have to be recovered from the message. Kept as a separate tuple so the header
# path's evidence rules stay exactly what #819 pinned them to.
SECONDARY_403_TEXT_ONLY_MARKERS = ("retry-after", "temporarily blocked")

# The PRIMARY (core/installation) budget. Both wordings GitHub emits:
#   `API rate limit exceeded for installation` (an App installation token, i.e. dispatch's)
#   `API rate limit exceeded for user ID <n>`  (a user token)
# NOT a bare "rate limit" — see the module docstring.
BUDGET_403_MARKERS = ("rate limit exceeded", "rate limit for installation")


def header(headers, name):
    """Case-insensitive single header read over anything dict-like (http.client.HTTPMessage, a
    plain dict, or the dict a test hands an HTTPError). -> str|None.

    Lifted VERBATIM from plan-snapshot's `_header`, which is now an alias of this. The `.get`
    probe before the `.items()` scan is load-bearing and is kept: an `HTTPMessage` answers `.get`
    case-insensitively itself, and a caller may hand in an object with `.get` and no `.items()`.
    Anything with neither reads as "no headers", never as a match."""
    if headers is None:
        return None
    if hasattr(headers, "get"):
        got = headers.get(name)
        if got is not None:
            return str(got)
    try:
        items = headers.items()
    except AttributeError:
        return None
    lowered = name.lower()
    for key, value in items:
        if str(key).lower() == lowered:
            return str(value)
    return None


def int_header(headers, name):
    """A header value as an int, or None when absent or unparseable."""
    raw = header(headers, name)
    if raw is None:
        return None
    try:
        return int(raw.strip())
    except ValueError:
        return None


def retry_after_seconds(headers):
    """The `Retry-After` header as a POSITIVE int, or 0. A date-form or malformed value is 0 — the
    caller falls back to its own ladder rather than guessing at an HTTP-date.

    Zero is "absent", not "wait zero seconds": honouring a literal `Retry-After: 0` converts a
    back-off into a hot loop against the endpoint that is already throttling us."""
    raw = header(headers, "Retry-After")
    if raw is None:
        return 0
    try:
        seconds = int(raw.strip())
    except ValueError:
        return 0
    return seconds if seconds > 0 else 0


def classify_403(headers, body=""):
    """-> 'secondary' | 'budget' | 'permission'. The AUTHORITATIVE form: headers are evidence.

    Order is the contract — see the module docstring."""
    text = (body or "").lower()
    if retry_after_seconds(headers) or any(m in text for m in SECONDARY_403_MARKERS):
        return "secondary"
    if int_header(headers, "x-ratelimit-remaining") == 0:
        return "budget"
    if any(m in text for m in BUDGET_403_MARKERS):
        return "budget"
    return "permission"


def classify_403_text(text):
    """-> 'secondary' | 'budget' | 'permission', from MESSAGE TEXT ALONE.

    For a caller whose only evidence is `gh` CLI stderr, where the response headers are gone by the
    time the error is visible. Same order, same markers, minus the two header tests it cannot make.

    THE CALLER MUST HAVE ESTABLISHED THE STATUS. This function does not parse one: it answers "if
    this failure IS a 403, which 403 is it". Feeding it an unrelated 404 body that happens to say
    "retry later" yields 'secondary' — the status test is the caller's job, and both callers in
    this repository make it.

    A caller on this path has NOT read `x-ratelimit-remaining` and must not report that it has.
    `permission` is still the residual: no marker means no positive evidence of a throttle."""
    lowered = (text or "").lower()
    if any(m in lowered for m in SECONDARY_403_MARKERS + SECONDARY_403_TEXT_ONLY_MARKERS):
        return "secondary"
    if any(m in lowered for m in BUDGET_403_MARKERS):
        return "budget"
    return "permission"


def is_budget_exhaustion_text(text):
    """`classify_403_text(...) == 'budget'` as a predicate, for call sites that want the boolean.

    Named separately because the CALLER-facing question is "may I retry this", and the answer for
    this one class is a flat no — not "how long should I wait"."""
    return classify_403_text(text) == "budget"


# ---------------------------------------------------------------------------------------------
# Self-test. Every check names what it protects; deleting the guard it names must red the row.

# MEASURED WORDINGS. Left verbatim (bar the truncation noted) so a check cannot pass against a
# convenient paraphrase of a message GitHub does not send.
MEASURED_INSTALLATION_BUDGET_STDERR = (
    "gh: API rate limit exceeded for installation. (HTTP 403)")
MEASURED_USER_BUDGET_STDERR = (
    "gh: API rate limit exceeded for user ID 4783300. (HTTP 403)")
MEASURED_SECONDARY_STDERR = (
    "gh: You have exceeded a secondary rate limit and have been temporarily blocked from content "
    "creation. Please retry your request again later. (HTTP 403)")
MEASURED_PERMISSION_STDERR = (
    "gh: Resource not accessible by integration (HTTP 403)")
# The TRUNCATED form (registry #710 measured worker-pr capping its stderr excerpt at 200 chars):
# the status has been cut off entirely, so a status-first classifier sees nothing at all.
MEASURED_TRUNCATED_BUDGET_STDERR = (
    "gh: API rate limit exceeded for installation. For more information about rate limiting, see "
    "https://docs.github.com/rest/overview/resources-in-the-rest-api#rate-l")


def _self_test():
    failures = []

    def chk(name, got, want):
        good = got == want
        if not good:
            failures.append(name)
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    # --- the three classes, on the HEADER path (the #819 contract, unchanged) -----------------
    chk("header: Retry-After -> secondary", classify_403({"Retry-After": "7"}, ""), "secondary")
    chk("header: secondary marker in body -> secondary",
        classify_403({}, "You have exceeded a secondary rate limit"), "secondary")
    chk("header: x-ratelimit-remaining 0 -> budget",
        classify_403({"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1785182238"}, ""),
        "budget")
    chk("header: budget marker in body -> budget",
        classify_403({}, '{"message":"API rate limit exceeded for installation"}'), "budget")
    chk("header: case-insensitive header lookup",
        classify_403({"X-RateLimit-Remaining": "0"}, ""), "budget")
    chk("header: healthy remaining + no marker -> permission (the RESIDUAL class)",
        classify_403({"x-ratelimit-remaining": "4931"},
                     "Resource not accessible by integration"), "permission")
    chk("header: no evidence at all -> permission", classify_403({}, ""), "permission")
    # ORDER. A secondary limit that also reports remaining=0 must stay 'secondary' — waiting the
    # few seconds GitHub asked for is right, stopping the sweep for an hour is not.
    chk("header: ORDER — Retry-After beats remaining=0 (secondary, not budget)",
        classify_403({"Retry-After": "5", "x-ratelimit-remaining": "0"}, ""), "secondary")

    # --- the three classes, on the TEXT path (new; this is what the guard can see) ------------
    chk("text: the MEASURED installation-budget stderr -> budget",
        classify_403_text(MEASURED_INSTALLATION_BUDGET_STDERR), "budget")
    chk("text: the MEASURED user-token budget stderr -> budget",
        classify_403_text(MEASURED_USER_BUDGET_STDERR), "budget")
    chk("text: the MEASURED secondary stderr -> secondary (it says 'temporarily blocked' and "
        "'retry ... later'; classifying it 'budget' would stop a sweep that needed to wait 30s)",
        classify_403_text(MEASURED_SECONDARY_STDERR), "secondary")
    chk("text: the MEASURED permission stderr -> permission",
        classify_403_text(MEASURED_PERMISSION_STDERR), "permission")
    chk("text: a TRUNCATED budget stderr (status cut off) is still budget",
        classify_403_text(MEASURED_TRUNCATED_BUDGET_STDERR), "budget")
    chk("text: Retry-After in prose -> secondary", classify_403_text("Retry-After: 30"),
        "secondary")
    chk("text: no marker -> permission (the RESIDUAL class — never inferred from absence)",
        classify_403_text(""), "permission")
    chk("text: ORDER — a message carrying BOTH a secondary marker and the budget phrase is "
        "secondary", classify_403_text("secondary rate limit: API rate limit exceeded"),
        "secondary")

    # --- the two entry points must AGREE on the same evidence ---------------------------------
    # The whole point of one module: a body that the header path calls X must not be Y on the text
    # path. Run the shared marker corpus through both and require identical verdicts.
    for label, body in (("installation budget", MEASURED_INSTALLATION_BUDGET_STDERR),
                        ("user budget", MEASURED_USER_BUDGET_STDERR),
                        ("secondary", MEASURED_SECONDARY_STDERR),
                        ("permission", MEASURED_PERMISSION_STDERR),
                        ("truncated budget", MEASURED_TRUNCATED_BUDGET_STDERR)):
        chk(f"agreement: header path and text path agree on the {label} wording (headerless)",
            classify_403({}, body), classify_403_text(body))

    # --- NON-VACUITY of the marker sets -------------------------------------------------------
    # A marker tuple that quietly became empty would send every 403 to 'permission' and this file
    # would pass every check above that expects 'permission'. Pin the sets themselves.
    chk("markers: the budget set is non-empty and holds no bare 'rate limit'",
        (bool(BUDGET_403_MARKERS), "rate limit" in BUDGET_403_MARKERS), (True, False))
    chk("markers: the secondary set is non-empty and holds no bare 'rate limit'",
        (bool(SECONDARY_403_MARKERS), "rate limit" in SECONDARY_403_MARKERS), (True, False))
    # THE AMBIGUITY DEMONSTRATION. A bare "rate limit" marker cannot tell the two limits apart:
    # it matches the secondary wording AND the budget wording. This is the shape
    # `scripts/gh_retry.py::_THROTTLE_403` carries on master, and the reason this module does not
    # reuse it. Kept as an executable demonstration so the claim in the docstring is checked, not
    # asserted.
    chk("markers: a bare 'rate limit' marker matches BOTH limits — it cannot express the "
        "distinction (this is why gh_retry's `_THROTTLE_403` is not this module's home)",
        ("rate limit" in MEASURED_SECONDARY_STDERR.lower(),
         "rate limit" in MEASURED_INSTALLATION_BUDGET_STDERR.lower()), (True, True))
    # ...and the specific markers DO tell them apart. Without this row the check above is just a
    # complaint; together they are a comparison.
    chk("markers: the SPECIFIC markers do tell them apart",
        (classify_403_text(MEASURED_SECONDARY_STDERR),
         classify_403_text(MEASURED_INSTALLATION_BUDGET_STDERR)), ("secondary", "budget"))

    # --- the predicate ------------------------------------------------------------------------
    chk("predicate: is_budget_exhaustion_text is true ONLY for budget",
        tuple(is_budget_exhaustion_text(t) for t in (MEASURED_INSTALLATION_BUDGET_STDERR,
                                                     MEASURED_SECONDARY_STDERR,
                                                     MEASURED_PERMISSION_STDERR, "")),
        (True, False, False, False))

    # --- header helpers -----------------------------------------------------------------------
    chk("headers: a non-mapping reads as absent, never as a match", header(None, "Retry-After"),
        None)
    chk("headers: Retry-After 0 is ABSENT, not 'wait zero seconds' (a literal 0 turns a back-off "
        "into a hot loop)", retry_after_seconds({"Retry-After": "0"}), 0)
    chk("headers: a date-form Retry-After is absent, not mis-parsed",
        retry_after_seconds({"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}), 0)
    chk("headers: int_header parses, and refuses garbage",
        (int_header({"x-ratelimit-remaining": "12"}, "x-ratelimit-remaining"),
         int_header({"x-ratelimit-remaining": "n/a"}, "x-ratelimit-remaining")), (12, None))

    print(("gh_403 self-test: PASS" if not failures
           else f"gh_403 self-test: FAIL ({len(failures)} check(s))"))
    return not failures


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        raise SystemExit(0 if _self_test() else 1)
    raise SystemExit("gh_403 is a library; run it with --self-test")
