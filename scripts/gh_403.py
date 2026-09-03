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

THE DEPENDENCY-SURFACE DECISION (registry #2032, stated explicitly because #1410 asked for it
either way). This module now shares the fleet's ONE Retry-After numeric contract with
`gh_retry.retry_after_seconds` / `gh_retry.retry_after_header_seconds`, and the obvious way to
share it would be `import gh_retry` and call `_bounded_retry_after`. THAT IS REFUSED. This file is
a declared sparse-checkout input of dispatch.yml's `secrets-guard` job and a declared entry of
`dispatch-secrets-guard.SELF_TEST_LIVE_INPUTS`; importing `gh_retry` would add
`scripts/gh_retry.py` — a module carrying `subprocess`, an argv scope parser and a live `gh`
runner — to the dependency surface of the fail-closed control that decides whether dispatch may
hand out a credential. A four-line numeric bound is not worth that. So the CAP VALUE and the
NUMERIC GRAMMAR below are MIRRORED from `gh_retry`, deliberately, and the mirror is held by a
self-test rather than by this comment: `groom.py` is the one module in the tree that loads BOTH,
and its `#2032 …` rows assert `RETRY_AFTER_CAP` and the value grammar are byte-identical to
`gh_retry`'s. Change either side alone and groom's suite reds.
"""
import re
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

# THE FLEET'S Retry-After CEILING. MIRRORED from `gh_retry.RETRY_AFTER_CAP`, not imported — see the
# module docstring's dependency-surface decision — and pinned equal to it by groom's self-test.
# Never let a hostile or confused `Retry-After` stall a whole scheduled run.
RETRY_AFTER_CAP = 60.0
# THE FLEET'S Retry-After VALUE GRAMMAR. MIRRORED from `gh_retry._RETRY_AFTER_VALUE_RE`, and
# `fullmatch`ed for the same reason it is there: a header LOOKUP yields ONE COMPLETE field value,
# so `7junk`, `7 seconds`, `nan`, and a value smuggling its own `Retry-After: 9999` token are
# MALFORMED. A searching parser would honour their numeric prefix / embedded number as a real wait.
_RETRY_AFTER_VALUE_RE = re.compile(r"\d+(?:\.\d+)?")


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


def retry_after_seconds(headers, cap=RETRY_AFTER_CAP):
    """The `Retry-After` header as a POSITIVE, CAPPED wait -> `float | None`.

    ONE NUMERIC CONTRACT (registry #1410/#2032). This was the last of the fleet's three
    Retry-After parsers to disagree on CONTRACT rather than on policy: it answered `int`-or-`0`,
    it was UNCAPPED, and `int(raw.strip())` raised on a fractional `Retry-After: 2.5` so a real
    server-requested wait read as ABSENT here while every other parser honoured it as 2.5s. All
    three now answer the same thing, differing only in the WITNESS they read:

      gh_retry.retry_after_seconds(text)          arbitrary `gh` stderr — SEARCH grammar
      gh_retry.retry_after_header_seconds(raw)    one complete header field value — FULL-MATCH
      gh_403.retry_after_seconds(headers)         a headers mapping — lookup + FULL-MATCH

      absent / unparseable / HTTP-date / non-positive  ->  None
      positive                                          ->  float, capped

    NONE IS ABSENT — and it is `None` now, not `0`, so "the server sent no wait" cannot be confused
    with a number. `Retry-After: 0` only ever arrives from an endpoint that is ALREADY throttling
    us, and honouring it literally converts the back-off into a HOT LOOP against exactly that
    endpoint, so it maps to absent too. An HTTP-date form fails the grammar and is absent rather
    than mis-parsed — `Wed, 21 Oct 2026 07:28:00 GMT` must never become 21 seconds.

    THE CAP IS THE CALLER'S, AND IT IS APPLIED HERE, ONCE. `cap` defaults to the fleet ceiling
    `RETRY_AFTER_CAP`; a caller whose job has a tighter deadline than the fleet passes its own
    (plan-snapshot's read walk lives inside a 15-minute job and passes `RETRY_AFTER_CAP_SECONDS`).
    Passing it in is what RECONCILES the two ceilings instead of STACKING them: before #2032
    plan-snapshot re-applied its own `min(...)` on top of an uncapped return, so the bound that was
    actually in force could not be read off either site alone.

    A DEGENERATE CAP IS ABSENT, NEVER A ZERO WAIT. The positive bound is re-checked AFTER the cap,
    so a caller that passes `cap=0` gets `None` — a fall back to its exponential ladder — rather
    than a zero-second sleep, which is the hot loop this function exists to prevent."""
    raw = header(headers, "Retry-After")
    if raw is None:
        return None
    value = raw.strip()
    if not _RETRY_AFTER_VALUE_RE.fullmatch(value):
        return None
    # `float(cap)` as well as `float(value)`: `min(3600.0, 30)` returns the INT 30, and the
    # contract is `float | None` on every path — including the capped one, which is the path
    # plan-snapshot takes, with an integer cap.
    #
    # THE `except` IS NOT DEAD WEIGHT even though the grammar above already constrains `value`
    # (mutation run, #2032): weakening `fullmatch` to `match` makes `float("7junk")` raise, and the
    # raise comes out of `classify_403` — i.e. out of a CALLER'S RETRY LOOP, which is the shape
    # that cost a whole groom sweep in #1410. A parse this module cannot make must read as "the
    # server sent no wait", never as an exception. It also fails a MIS-CONFIGURED `cap` closed to
    # the caller's own ladder rather than to a traceback.
    try:
        seconds = min(float(value), float(cap))
    except (TypeError, ValueError):
        return None
    return seconds if seconds > 0 else None


def classify_403(headers, body=""):
    """-> 'secondary' | 'budget' | 'permission'. The AUTHORITATIVE form: headers are evidence.

    Order is the contract — see the module docstring."""
    text = (body or "").lower()
    # TRUTHINESS, deliberately, not `is not None` (registry #2032). This test asks only "did the
    # server send a wait", so the numeric value is irrelevant here — but the two forms differ under
    # a REGRESSION of the absent sentinel, and they differ in opposite directions: if
    # `retry_after_seconds` ever went back to answering a number for "absent", `is not None` would
    # call EVERY 403 'secondary' and retry against a budget at zero, while truthiness still reads
    # the falsey sentinel as absent and lets the `remaining == 0` evidence below decide. The
    # fail-closed form wins. The ORDER itself is pinned by `_self_test`'s `#2032 ORDER` rows.
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

    # --- #2032: THE ORDER CONTRACT, RE-DEMONSTRATED ACROSS THE WHOLE Retry-After DOMAIN ----------
    # `classify_403` consumes `retry_after_seconds` for TRUTHINESS ALONE, so every change to that
    # function's return silently re-weights the secondary-vs-budget order #819/#1208 pinned — and a
    # mis-called `budget` stops a sweep for up to an hour. One row per class of Retry-After value,
    # each against a response that ALSO carries `remaining: 0`, so each row is a genuine ORDER
    # decision rather than a restatement of the single-evidence rows above: get the sentinel wrong
    # in either direction and the answer flips to the other class here.
    #
    # Row 1 is the behaviour change #2032 makes and is RED on the pre-#2032 tree ('budget'): the
    # old `int(raw.strip())` raised on `2.5`, so a fractional server-requested wait read as ABSENT
    # and the sweep stood down for an hour on a throttle that asked for 2.5 seconds.
    chk("#2032 ORDER — a FRACTIONAL Retry-After is a wait, so secondary beats remaining=0 "
        "(pre-#2032 this read 'budget': int('2.5') raised and the wait vanished)",
        classify_403({"Retry-After": "2.5", "x-ratelimit-remaining": "0"}, ""), "secondary")
    # Over-cap: the CAP must bound the wait, never erase it. Return None above the cap instead of
    # the ceiling and this reds to 'budget'.
    chk("#2032 ORDER — an OVER-CAP Retry-After is still a wait (capping must not erase evidence)",
        classify_403({"Retry-After": "9999", "x-ratelimit-remaining": "0"}, ""), "secondary")
    # ...and the three ABSENT forms must NOT be read as waits, or every budget 403 in the fleet
    # becomes 'secondary' and retries into a bucket at zero. Zero is the one that actually reaches
    # the wire; drop the `> 0` bound and this row reds to 'secondary'.
    chk("#2032 ORDER — Retry-After 0 / date-form / absent are NOT waits, so remaining=0 decides",
        (classify_403({"Retry-After": "0", "x-ratelimit-remaining": "0"}, ""),
         classify_403({"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT",
                       "x-ratelimit-remaining": "0"}, ""),
         classify_403({"x-ratelimit-remaining": "0"}, "")),
        ("budget", "budget", "budget"))
    # ...and a malformed value must not be MINED for a number it merely contains. `7junk` under a
    # searching parser is a 7-second wait, which would re-weight this response to 'secondary'.
    chk("#2032 ORDER — a MALFORMED Retry-After is not a wait (never substring-parsed)",
        (classify_403({"Retry-After": "7junk", "x-ratelimit-remaining": "0"}, ""),
         classify_403({"Retry-After": "junk Retry-After: 9999",
                       "x-ratelimit-remaining": "0"}, "")),
        ("budget", "budget"))

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
    # The `.items()` fallback's OWN failure exit — the only never-executed lines this file had
    # before #2032. An object with neither `.get` nor `.items()` must read "no headers", never
    # raise out of a caller's retry loop (the shape that killed a whole groom sweep, #1410).
    chk("headers: an object with neither `.get` nor `.items()` reads as absent, never raises",
        header(object(), "Retry-After"), None)
    chk("headers: int_header parses, and refuses garbage",
        (int_header({"x-ratelimit-remaining": "12"}, "x-ratelimit-remaining"),
         int_header({"x-ratelimit-remaining": "n/a"}, "x-ratelimit-remaining")), (12, None))

    # --- #2032: THE SHARED NUMERIC CONTRACT ----------------------------------------------------
    # `float | None`, zero-is-absent, capped. Asserted as a TUPLE against literals so a regression
    # in any one form is a named row rather than a silently-absorbed change of shape.
    chk("#2032 contract: honoured / fractional / capped, and every absent form is None (not 0)",
        (retry_after_seconds({"Retry-After": "7"}),
         retry_after_seconds({"Retry-After": "2.5"}),
         retry_after_seconds({"Retry-After": "9999"}),
         retry_after_seconds({}),
         retry_after_seconds(None),
         retry_after_seconds({"Retry-After": "0"}),
         retry_after_seconds({"Retry-After": "0.0"}),
         retry_after_seconds({"Retry-After": "-5"}),
         retry_after_seconds({"Retry-After": "soon"}),
         retry_after_seconds({"Retry-After": "nan"}),
         retry_after_seconds({"Retry-After": "7junk"}),
         retry_after_seconds({"Retry-After": "7 seconds"}),
         retry_after_seconds({"Retry-After": "junk Retry-After: 9999"}),
         retry_after_seconds({"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}),
         # THE GRAMMAR, not just `float()`. RFC 9110's `delta-seconds` is `1*DIGIT`, so the two
         # forms below are MALFORMED even though Python's `float()` accepts both — and they are
         # the only inputs that separate this module's `fullmatch` from a prefix `match` now that
         # the conversion fails closed (mutation run, #2032: without these rows, weakening
         # `fullmatch` to `match` survives every other row here). `7e2` would otherwise become
         # 700s (capped to the ceiling) and `1_0` would become 10s.
         retry_after_seconds({"Retry-After": "7e2"}),
         retry_after_seconds({"Retry-After": "1_0"})),
        (7.0, 2.5, RETRY_AFTER_CAP, None, None, None, None, None, None, None, None, None, None,
         None, None, None))
    # THE SENTINEL AND THE TYPE, pinned separately — and they have to be, because Python compares
    # `0 == 0.0` and `7 == 7.0` as equal. Every row above would pass unchanged against the
    # pre-#2032 `int`-or-`0` implementation for the integer cases; these two rows are what actually
    # go red on it. `0 == None` is False, and `int` is not `float`.
    chk("#2032 contract: ABSENT is the None sentinel, not 0 (an int-or-0 return reds this row)",
        (retry_after_seconds({}) is None, retry_after_seconds({"Retry-After": "0"}) is None),
        (True, True))
    # The CAPPED path is typed separately on purpose: `min(3600.0, 30)` returns the INT 30, so a
    # caller with an integer cap (plan-snapshot's `RETRY_AFTER_CAP_SECONDS = 30`) is exactly where
    # the `float | None` contract would silently leak an int back into the fleet.
    chk("#2032 contract: a present wait is a float, not an int — on the capped path too",
        (type(retry_after_seconds({"Retry-After": "7"})).__name__,
         type(retry_after_seconds({"Retry-After": "9999"})).__name__,
         type(retry_after_seconds({"Retry-After": "3600"}, 30)).__name__), ("float",) * 3)
    # THE CAP IS THE CALLER'S, APPLIED HERE, ONCE (the plan-snapshot reconciliation). A tighter cap
    # must bind, and it must bind at THIS layer — drop the `cap` parameter and fall back to the
    # module default and row 1 reads 60.0 instead of 30.0. `90` is deliberately LOOSER than the
    # fleet default: if this function silently clamped at `RETRY_AFTER_CAP` first, row 2 would read
    # 60.0. Neither 30 nor 90 is derived from a constant this module reads.
    chk("#2032 cap: the CALLER's cap binds, tighter and looser than the fleet default alike",
        (retry_after_seconds({"Retry-After": "3600"}, 30),
         retry_after_seconds({"Retry-After": "3600"}, 90),
         retry_after_seconds({"Retry-After": "7"}, 30)),
        (30.0, 90.0, 7.0))
    # ...and a DEGENERATE cap is ABSENT, never a zero-second sleep: the positive bound is
    # re-checked AFTER the cap. Move the `> 0` test back above the `min()` and this row returns
    # 0.0 — a hot loop against the endpoint that is already throttling us.
    chk("#2032 cap: a non-positive cap yields ABSENT, never a zero wait (hot-loop guard)",
        (retry_after_seconds({"Retry-After": "7"}, 0),
         retry_after_seconds({"Retry-After": "7"}, -1)), (None, None))
    chk("#2032 cap: the mirrored fleet ceiling is positive and finite",
        (RETRY_AFTER_CAP > 0, RETRY_AFTER_CAP == float(RETRY_AFTER_CAP)), (True, True))
    # ...and an UNPARSEABLE cap fails to ABSENT, not to a traceback. This row exists because the
    # mutation run found the real hazard it also covers: this function is called from inside
    # `classify_403`, which is called from inside a caller's RETRY LOOP, so any exception it lets
    # escape kills the sweep that loop exists to survive (#1410's AttributeError, exactly).
    #
    # RENDERED, not propagated — the #1410 harness shape. Deleting the fail-closed `except` makes
    # this call raise, and an uncaught raise aborts this suite where it stands: the mutant would
    # record as a KILL while every row below it never ran. Comparing a marker keeps the mutant
    # run's check count equal to the pristine run's, so the kill is a real comparison.
    def _rendered(headers, cap=RETRY_AFTER_CAP):
        try:
            return retry_after_seconds(headers, cap)
        except BaseException as exc:  # noqa: BLE001 — naming the class IS the assertion here
            return f"raised {type(exc).__name__}"

    chk("#2032 cap: an unparseable cap is ABSENT, never an exception out of a caller's retry loop",
        _rendered({"Retry-After": "7"}, "soon"), None)
    # ...and `_rendered`'s rendering is PROVEN, not assumed: on the pristine tree nothing above
    # makes it raise, so an `except` that had drifted into re-raising would silently restore the
    # abort-mid-suite shape and every future mutant here would bank a kill with rows unrun. Force
    # the raise through the one collaborator this function has.
    _real_header = globals()["header"]
    globals()["header"] = lambda headers, name: (_ for _ in ()).throw(AttributeError("no headers"))
    try:
        _rendering = _rendered({"Retry-After": "7"})
    finally:
        globals()["header"] = _real_header
    chk("#2032 the harness RENDERS a raise as a value rather than aborting the suite",
        (_rendering, header is _real_header), ("raised AttributeError", True))
    # THE TRUTHINESS CHOICE IN `classify_403`, DEMONSTRATED rather than asserted in prose. Stub the
    # parser to answer a FALSEY NUMBER for a response that also reports `remaining: 0` — the exact
    # shape a regression of the absent sentinel would produce. Truthiness reads it as absent and
    # lets the budget evidence decide; `is not None` would call it 'secondary' and retry into a
    # bucket at zero. Rewrite the test as `is not None` and this row reds.
    _real_parser = globals()["retry_after_seconds"]
    globals()["retry_after_seconds"] = lambda headers, cap=RETRY_AFTER_CAP: 0.0
    try:
        falsey_sentinel = classify_403({"x-ratelimit-remaining": "0"}, "")
    finally:
        globals()["retry_after_seconds"] = _real_parser
    chk("#2032 ORDER — a FALSEY numeric wait is read as absent, so budget still wins (the "
        "fail-closed reason classify_403 tests truthiness and not `is not None`)",
        (falsey_sentinel, retry_after_seconds is _real_parser), ("budget", True))

    print(("gh_403 self-test: PASS" if not failures
           else f"gh_403 self-test: FAIL ({len(failures)} check(s))"))
    return not failures


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        raise SystemExit(0 if _self_test() else 1)
    raise SystemExit("gh_403 is a library; run it with --self-test")
