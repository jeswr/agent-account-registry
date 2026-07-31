#!/usr/bin/env python3
"""THE TRANSIENT-RETRY TAXONOMY for the registry's DIRECT-HTTP (`urllib`) read paths.

WHY THIS FILE EXISTS (registry #552). "Is this failure a blip I may replay?" was being answered in
several places at once, by hand-written tables that did not agree and had no single place where
the disagreement was visible:

  * `groom.py`         `_is_transient_status` — the WHOLE 5xx family, and no 4xx at all. 429 and
                       403 are EXCLUDED on purpose (#494 established the fail-closed 4xx posture;
                       #291 widened the 5xx half after a plain HTTP 500 killed two sweeps in 4.5h,
                       having fallen outside a `{502, 503, 504}` allow-list).
  * `plan-snapshot.py` `RETRYABLE = {429, 500, 502, 503, 504}` — 429 IS opted in, and 403 never
                       reaches a status test at all: it is routed to the `gh_403` taxonomy first
                       (#819), because one 403 in three is a request-BUDGET exhaustion that must
                       not be replayed into the empty bucket that just refused it.

THE DIVERGENCE IS DELIBERATE AND IS PRESERVED HERE BYTE FOR BYTE. groom sweeps a whole repo on a
cron, and a 429 there means "you are asking too fast" — a bounded replay makes that worse, so it
fails closed. plan-snapshot's read walk is the one that has to survive a burst limiter to produce a
plan at all, so it opts 429 in and sizes the wait off `Retry-After`. What was NOT deliberate is
that the two tables were written twice, in two files, with nothing comparing them: a change to one
drifted from the other silently, and every omission costs a whole scheduled run in the
fail-CLOSED direction (a transient status that is missing from a table is FATAL).

So: ONE classifier, and each caller DECLARES which statuses it opts into as a named
`StatusPolicy`. The policies sit side by side below, the exact set of statuses they disagree on is
enumerated and asserted by this file's self-test, and the two failure shapes that motivated the
consolidation are not expressible at all — the constructor refuses them, loudly, at import time:

  * a policy that opts into NOTHING. A table that quietly emptied would disable its caller's retry
    completely while every behavioural "X is not retried" check stayed green — the vacuous
    direction, and the one a self-test cannot catch after the fact.
  * a policy that opts into a NON-ERROR status. `304 Not Modified` is plan-snapshot's
    conditional-request CACHE HIT (#1207); replaying it is not a retry, it is a loop.

WHAT IS DELIBERATELY NOT HERE — these are different evidence, not the same decision:

  * the `gh` CLI STDERR path (`gh_retry.is_transient_stderr`, `gh_retry.classify_read_failure`,
    and `ledger_retry.is_transient`, which already delegates to it). Those callers never hold a
    status object or a response header; they regex a message, and #748 measured that the status is
    frequently not recoverable from it at all — which is why their read-side default is RETRY,
    the opposite of the fail-closed default that is correct when the status IS known. One shared
    classifier over two evidence models would have to pick one of those defaults for both.
  * THE 403 TAXONOMY (`gh_403`). A 403 is three server answers wearing one number and it is not a
    status decision at all; a caller must route it there BEFORE consulting a policy here. That is
    why no policy below may opt 403 in — see `REFUSED_STATUSES`.
  * the loop/sleep MECHANICS — attempt bound, exponential-jitter schedule, `Retry-After` cap. Those
    are `gh_retry`'s (registry #563 adoption item 4) and both callers already take them from there.
  * the CAS-conflict decision (409 / the create-race 422): `ledger_retry.is_cas_conflict`. A
    conflict is owned by the writer's re-read loop and must never read as "transient".

Pure functions and one small value type. Stdlib only, no I/O, so a fail-closed caller can load it
without widening its own attack surface.
"""

import sys
from urllib.error import HTTPError, URLError

# Statuses NO policy may opt into, and why. These are fail-closed refusals at CONSTRUCTION time,
# not documentation: each one is a status where a replay is known to be wrong, and the whole reason
# this module exists is that such a rule written in prose in two files is a rule that drifts.
REFUSED_STATUSES = {
    403: "a 403 is three different answers wearing one number — route it to the gh_403 taxonomy "
         "BEFORE any status test (registry #819/#1208); replaying a budget-exhaustion 403 spends "
         "requests from a bucket that has none",
    409: "409 is the ledger compare-and-swap CONFLICT signal, owned by the writer's own re-read "
         "loop (ledger_retry.is_cas_conflict) — a transparent replay consumes the signal and "
         "re-sends a now-stale expected SHA",
}


class StatusPolicy:
    """WHICH HTTP statuses one caller opts into replaying, as a declared, named value.

    `server_errors` opts into the whole 5xx family as a RANGE rather than an enumeration. That is
    the shape #291 chose for a reason: forgetting a code in an allow-list does not make a permanent
    failure retryable, it makes a TRANSIENT one fatal, and the cost of each omission is a whole
    scheduled run. `extra` carries the individually opted-in statuses on top of it.
    """

    __slots__ = ("name", "server_errors", "extra", "rationale")

    def __init__(self, name, *, server_errors=False, extra=(), rationale):
        if not name or not str(name).strip():
            raise ValueError("a transient status policy must be named")
        if not rationale or not str(rationale).strip():
            # The rationale is REQUIRED, and required at construction. The divergence between the
            # policies below is the thing this module exists to make legible; an unexplained new
            # policy would put it straight back to being invisible.
            raise ValueError(f"transient status policy {name!r} must state its rationale")
        codes = set()
        for code in extra:
            if isinstance(code, bool) or not isinstance(code, int):
                raise ValueError(
                    f"transient status policy {name!r}: {code!r} is not an HTTP status")
            if code in REFUSED_STATUSES:
                raise ValueError(
                    f"transient status policy {name!r} may not opt into HTTP {code}: "
                    f"{REFUSED_STATUSES[code]}")
            if not 400 <= code < 600:
                # 2xx/3xx are not failures, so "retrying" one is a loop, not a retry — and 304 is a
                # live example, not a hypothetical: it is plan-snapshot's conditional-request cache
                # HIT (registry #1207), delivered by urllib as an HTTPError like any other.
                raise ValueError(
                    f"transient status policy {name!r} may not opt into HTTP {code}: only 4xx/5xx "
                    "statuses are failures; a 2xx/3xx replay is a loop (304 is a CACHE HIT)")
            codes.add(code)
        if not server_errors and not codes:
            # THE VACUOUS POLICY. A table that silently emptied disables its caller's retry
            # completely while every "X is not retried" check in that caller stays green.
            raise ValueError(
                f"transient status policy {name!r} opts into no status at all — that is not a "
                "conservative policy, it is a DISABLED retry, and it is green against every "
                "negative check its caller has")
        self.name = str(name)
        self.server_errors = bool(server_errors)
        self.extra = frozenset(codes)
        self.rationale = str(rationale)

    def retries(self, code):
        """True when `code` is a status THIS caller opted into replaying on an idempotent read.

        The caller still owns the two gates around this one: that the request was idempotent, and
        that the attempt budget is not spent. This answers only "is the status a blip"."""
        if self.server_errors and 500 <= code < 600:
            return True
        return code in self.extra

    def retried_statuses(self, low=100, high=600):
        """Every status in `[low, high)` this policy replays, as a sorted tuple. For self-tests and
        diagnostics: it makes a policy's REAL surface assertable as a value, so a widening cannot
        hide behind a handful of spot checks."""
        return tuple(code for code in range(low, high) if self.retries(code))

    def __repr__(self):
        return (f"StatusPolicy({self.name!r}, server_errors={self.server_errors}, "
                f"extra={sorted(self.extra)})")


# ---------------------------------------------------------------------------------------------
# THE POLICIES. One per caller, side by side, so the difference between them is READABLE — that
# adjacency is most of the point of this module.

GROOM_SWEEP = StatusPolicy(
    "groom-sweep",
    server_errors=True,
    rationale=(
        "The WHOLE 5xx family and NO 4xx — 429 and 403 excluded deliberately. groom's sweep is an "
        "O(issues) cron walk, so a 429 means it is already asking too fast and a bounded replay "
        "deepens exactly the condition it is answering; every 4xx is a refusal and fails closed "
        "(issue #494). The 5xx half is a RANGE and not the original {502, 503, 504} allow-list "
        "because a plain HTTP 500 fell outside that enumeration and killed two sweeps in 4.5h "
        "(issue #291). Consulted only for GET/HEAD: no mutation reaches it."),
)

PLAN_SNAPSHOT_READ = StatusPolicy(
    "plan-snapshot-read",
    extra=(429, 500, 502, 503, 504),
    rationale=(
        "429 IS opted in, unlike groom: this read walk has to survive a burst limiter to produce a "
        "plan at all, and it sizes the wait off the server's own Retry-After. 403 is absent "
        "because it is NOT a status decision here — `classify_403` runs first (issue #819) and "
        "raises BudgetExhausted for the class that must never be replayed. The 5xx half stays the "
        "measured allow-list rather than the whole range: widening it is a real behaviour change "
        "for a budget-critical sweep and is a separate decision from consolidating the tables."),
)

ALL_POLICIES = (GROOM_SWEEP, PLAN_SNAPSHOT_READ)


def is_transient_network(exc):
    """True for the connection-dropped / timeout family — a failure with NO response at all.

    The other half of the same question as `StatusPolicy.retries`, and it belongs beside it: when
    the connection dies there is no status to consult, so a caller that shares its status table but
    keeps a private copy of this predicate has only half-consolidated.

    `http.client.RemoteDisconnected` is a `ConnectionResetError` subclass, so it is covered whether
    it propagates raw or wrapped in a `URLError`. A `URLError` for anything ELSE — DNS failure,
    connection refused, a bad certificate — stays FATAL: those do not clear by waiting a few
    seconds, and the fail-closed direction is the reviewed one (issue #494). An `HTTPError` is a
    `URLError` subclass but it IS a response, so it is never a network transient — its caller must
    take the status branch and consult a `StatusPolicy`.
    """
    if isinstance(exc, (ConnectionResetError, TimeoutError)):
        return True
    if isinstance(exc, URLError) and not isinstance(exc, HTTPError):
        return isinstance(exc.reason, (ConnectionResetError, TimeoutError))
    return False


# ---------------------------------------------------------------------------------------------
# Self-test. Every row names the guard it protects; deleting that guard must red the row.

def _self_test():
    import http.client

    failures = []

    def chk(name, got, want, brief=None):
        """`brief` only shortens what is PRINTED — the comparison is ALWAYS on the full value.
        Used for the whole-5xx-range rows, whose exact tuples run to a hundred entries."""
        good = got == want
        if not good:
            failures.append(name)
        if good and brief:
            print(f"  ok   {name}: {brief}")
        else:
            print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    def refused(build):
        """The ValueError message a rejected policy raises, or None when it was ACCEPTED."""
        try:
            build()
        except ValueError as exc:
            return str(exc)
        return None

    # --- the classifier itself, on both policies, over the FULL status surface ----------------
    # `retried_statuses` is asserted as a whole VALUE, not spot-checked: a widening (or a
    # narrowing) anywhere in 100..599 reds these two rows, which is what a handful of individual
    # `retries(503) is True` checks cannot do.
    chk("groom-sweep retries EXACTLY the 5xx range (issue #291: a range, never an allow-list)",
        GROOM_SWEEP.retried_statuses(), tuple(range(500, 600)), brief="500..599, and nothing else")
    chk("plan-snapshot-read retries EXACTLY {429, 500, 502, 503, 504} (issue #819, unchanged)",
        PLAN_SNAPSHOT_READ.retried_statuses(), (429, 500, 502, 503, 504))

    # THE DIVERGENCE, enumerated. This is the row the whole module exists for: the two policies
    # differ, the difference is intentional, and it is now asserted in ONE place instead of being
    # implied by two tables in two files. Unifying them "helpfully" — in either direction — reds
    # here, and so does silently widening one.
    _groom = set(GROOM_SWEEP.retried_statuses())
    _plan = set(PLAN_SNAPSHOT_READ.retried_statuses())
    chk("the two policies disagree on EXACTLY the documented statuses: 429 (plan-snapshot only, "
        "it must survive a burst limiter) and the 5xx codes outside the measured gateway set "
        "(groom only, issue #291)",
        (sorted(_plan - _groom),
         sorted(_groom - _plan)),
        ([429],
         sorted(set(range(500, 600)) - {500, 502, 503, 504})),
        brief="plan-snapshot-only: [429]; groom-only: the 5xx codes outside {500,502,503,504}")
    # ...and the AGREEMENT half, so the row above is a comparison rather than a complaint: the four
    # measured gateway/server codes are retried by BOTH, and no 4xx other than 429 is retried by
    # either.
    chk("both policies retry the measured gateway/server codes",
        [(GROOM_SWEEP.retries(c), PLAN_SNAPSHOT_READ.retries(c)) for c in (500, 502, 503, 504)],
        [(True, True)] * 4)
    chk("no policy retries any 4xx except plan-snapshot's 429",
        {p.name: [c for c in range(400, 500) if p.retries(c)] for p in ALL_POLICIES},
        {"groom-sweep": [], "plan-snapshot-read": [429]})
    # groom's fail-closed 4xx posture, named explicitly (issue #494): these are the two statuses a
    # reviewer will reach for first, and both must stay FATAL for the sweep.
    chk("groom-sweep fails closed on 429 and 403 (issue #494) while retrying the 500 that killed "
        "two sweeps (issue #291)",
        (GROOM_SWEEP.retries(429), GROOM_SWEEP.retries(403), GROOM_SWEEP.retries(500)),
        (False, False, True))
    chk("no policy retries a success/redirect status",
        {p.name: [c for c in (200, 201, 204, 301, 302, 304) if p.retries(c)] for p in ALL_POLICIES},
        {"groom-sweep": [], "plan-snapshot-read": []})

    # --- the CONSTRUCTOR guards: the two shapes that must be inexpressible -------------------
    # THE VACUOUS POLICY. This is the guard that protects every negative check in every consumer:
    # a policy that opts into nothing retries nothing, and "nothing is retried" is what a
    # fail-closed suite is full of assertions for.
    _empty = refused(lambda: StatusPolicy("empty", rationale="x"))
    chk("a policy that opts into NOTHING is refused at construction (a disabled retry is green "
        "against every negative check its caller has)",
        (_empty is not None, "DISABLED" in (_empty or "")), (True, True))
    # 304 is not a hypothetical: it is plan-snapshot's conditional-request CACHE HIT, delivered by
    # urllib as an HTTPError exactly like a 502.
    _cache_hit = refused(lambda: StatusPolicy("cache", extra=(304,), rationale="x"))
    chk("opting into 304 is refused (it is plan-snapshot's cache HIT — replaying it is a loop)",
        (_cache_hit is not None, "CACHE HIT" in (_cache_hit or "")), (True, True))
    chk("opting into a 2xx is refused",
        refused(lambda: StatusPolicy("ok", extra=(200,), rationale="x")) is not None, True)
    # The two statuses another component OWNS. Neither may be re-decided by a status table here.
    _403 = refused(lambda: StatusPolicy("throttle", extra=(403,), rationale="x"))
    _409 = refused(lambda: StatusPolicy("cas", extra=(409,), rationale="x"))
    chk("opting into 403 is refused — it belongs to the gh_403 taxonomy (#819/#1208)",
        (_403 is not None, "gh_403" in (_403 or "")), (True, True))
    chk("opting into 409 is refused — it is the ledger CAS-conflict signal, owned by the writer's "
        "re-read loop",
        (_409 is not None, "compare-and-swap" in (_409 or "")), (True, True))
    chk("REFUSED_STATUSES is non-empty and every entry states a reason",
        (bool(REFUSED_STATUSES), all(bool(v.strip()) for v in REFUSED_STATUSES.values())),
        (True, True))
    chk("a policy must be named and must state a rationale",
        (refused(lambda: StatusPolicy("", server_errors=True, rationale="x")) is not None,
         refused(lambda: StatusPolicy("n", server_errors=True, rationale=" ")) is not None),
        (True, True))
    # A bool is an int in Python: `extra=(True,)` would otherwise become "status 1".
    chk("a non-status opt-in is refused (a bool is an int — it must not become 'status 1')",
        (refused(lambda: StatusPolicy("b", extra=(True,), rationale="x")) is not None,
         refused(lambda: StatusPolicy("s", extra=("503",), rationale="x")) is not None),
        (True, True))
    # THE ACCEPT DIRECTION, so the guards above are not simply "refuse everything": the two real
    # policies construct, and so does a fresh well-formed one.
    chk("a well-formed policy is ACCEPTED (the guards refuse shapes, not policies)",
        StatusPolicy("probe", server_errors=True, extra=(429,),
                     rationale="probe").retried_statuses(400, 600),
        (429,) + tuple(range(500, 600)), brief="429 plus 500..599")

    # --- registry non-vacuity ------------------------------------------------------------------
    chk("ALL_POLICIES is non-empty, uniquely named, and every policy carries a rationale",
        (len(ALL_POLICIES) > 1,
         len({p.name for p in ALL_POLICIES}) == len(ALL_POLICIES),
         all(p.rationale.strip() for p in ALL_POLICIES)),
        (True, True, True))

    # --- the network half (no response at all) -------------------------------------------------
    chk("RemoteDisconnected is a network transient (the raw exception that killed a whole sweep, "
        "issue #494)",
        is_transient_network(
            http.client.RemoteDisconnected("Remote end closed connection without response")), True)
    chk("a URLError-WRAPPED reset is a network transient (urllib wraps it on some paths)",
        is_transient_network(URLError(ConnectionResetError("reset by peer"))), True)
    chk("a bare timeout is a network transient", is_transient_network(TimeoutError("timed out")),
        True)
    chk("DNS / connection-refused URLErrors stay FATAL — they do not clear by waiting",
        (is_transient_network(URLError("Name or service not known")),
         is_transient_network(URLError(ConnectionRefusedError("refused")))), (False, False))
    chk("an HTTPError is NEVER a network transient (it IS a response — its caller must take the "
        "status branch and consult a StatusPolicy)",
        (is_transient_network(HTTPError("https://x", 503, "u", {}, None)),
         is_transient_network(HTTPError("https://x", 404, "u", {}, None))), (False, False))
    chk("an unrelated exception is not a network transient",
        is_transient_network(ValueError("nope")), False)

    print("http_transient self-test: "
          + ("PASS" if not failures else f"FAIL ({len(failures)} check(s))"))
    return not failures


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        raise SystemExit(0 if _self_test() else 1)
    raise SystemExit("http_transient is a library; run it with --self-test")
