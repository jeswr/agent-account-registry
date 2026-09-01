#!/usr/bin/env python3
# [SPARQ agent] ALARM ON THE SHARED REST BUDGET, BEFORE IT IS SPENT (registry #1123).
#
# WHY THIS FILE EXISTS. Registry #1088 — groom losing sweeps to a spent request budget — was
# diagnosed only AFTER ~9 % of groom sweeps had already been lost, by sampling failed runs by hand.
# Nothing watched the budget itself, and that budget is SHARED: groom, dispatch, worker, curate,
# triage and every other lane that runs on the ambient Actions token draw from ONE bucket set. So
# the next component whose cost grows with the backlog gets found exactly the same way — after it
# has already cost sweeps. This file makes the budget a CENSUSED population instead of a
# retrospective diagnosis.
#
# WHAT IT IS NOT. It does not stop, throttle or reroute anything, and it changes no gate. The
# authoritative in-band control stays exactly where #819 put it: `plan-snapshot.py` reads
# `x-ratelimit-remaining` off the RESPONSE it was actually charged for and stops at
# `RATE_LIMIT_RESERVE`. This is the leading indicator in front of that hard stop, and the self-test
# pins that relationship (`alarm_threshold(MEASURED_CORE_LIMIT)` must be strictly ABOVE the reserve)
# so an alarm that fires only once the sweep is already refusing cannot ship.
#
# TWO HAZARDS, both named by plan-snapshot's own comments, both load-bearing here:
#
#   1. `/rate_limit` REPORTS PER-RESOURCE BUCKETS, and a call may be charged to a bucket other than
#      `core`. plan-snapshot's #819 note is blunt about the consequence: that endpoint "reports a
#      different bucket and read healthy throughout the 2026-07-27 outage while every snapshot
#      request 403'd". A census that reads `core` alone therefore reproduces the exact blindness it
#      exists to end. So EVERY resource the payload reports is measured, and a bucket at zero
#      breaches whatever `core` says. `_test_census` makes that the headline red test.
#
#      The buckets differ in SIZE by two orders of magnitude (`core` 5000/h against `search` 30/min
#      and `code_search` 10/min), so the alarm point is a FRACTION of each bucket's own limit, never
#      one absolute floor. An absolute 100 would page forever on `search` and would be silent on
#      `core` until the moment plan-snapshot already refuses.
#
#   2. AN ALARM THAT ONLY SPEAKS WHEN UNHAPPY IS INDISTINGUISHABLE FROM ONE THAT HAS STOPPED
#      RUNNING (AGENTS.md pre-flight item 8). Every tick emits the census line — healthy, breached,
#      all-inapplicable, and read-failed alike — and `_test_end_to_end` reds on the conditionally
#      inert form (`if reasons: print(...)`), not just on deleting the emission.
#
# SCOPE, MEASURED AND STATED — this is a SUBSET and the body says so. It censuses the bucket set
# the AMBIENT Actions token is charged against, which is the one plan-snapshot watched go to zero on
# 2026-07-27. The per-owner App INSTALLATION tokens groom mints for target repos (`SPARQ_TOKEN` /
# `JESWR_TOKEN`, issue #168) are a SEPARATE bucket set and are NOT covered: reading them needs the
# App private key, which would put the signing key in a watchdog job. Naming the wider population
# while measuring the narrower one is how an alert closes as healthy while the thing it names is
# still broken (`park-stock-alert.py`'s "13 of 24" lesson), so the body carries the caveat.
#
# AUTHORITY. This script may create/edit/comment/close ONE `ops-alert` issue and nothing else. It
# never labels a PR, never writes the ledger, never arms, and never applies a hold.
"""Alarm on the SHARED REST request budget, per RESOURCE bucket (registry #1123)."""

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ALERT_LABEL = "ops-alert"
ALERT_TITLE = "⚠️ The shared REST request budget is heading toward exhaustion"
# Stable marker: it is the dedupe key, so renaming it orphans every open alert.
ALERT_MARKER = "<!-- ratelimit-alert:v1 key=shared-rest-budget -->"

SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent

GROOM_WORKFLOW = ".github/workflows/groom-sweep.yml"
GROOM_JOB = "ratelimit-budget"
PLAN_SNAPSHOT = "scripts/plan-snapshot.py"
SUITE_FILE = "scripts/selftest-suite.txt"
# KEEP IN SYNC with the sparse-checkout in groom-sweep.yml's `ratelimit-budget` job. The self-test
# asserts both directions, so a checkout that drops an input reds instead of making the YAML-seam
# assertions silently unreachable on the live path.
REQUIRED_FILES = (
    "scripts/ratelimit-alert.py",
    "scripts/yaml_dependency.py",
    # Every read here runs through the shared bounded-retry layer (#1502): a watchdog that loses a
    # whole tick to one transient 5xx is the failure it exists to report.
    "scripts/gh_retry.py",
    # The cross-file contract below is derived from this file's RATE_LIMIT_RESERVE. Without it in
    # the checkout that assertion would be unreachable on the live path while staying green in
    # pr-gate — the silent divergence #1140 was about.
    PLAN_SNAPSHOT,
    SUITE_FILE,
    GROOM_WORKFLOW,
)

# THE ALARM POINT, as a fraction of each bucket's OWN limit. Per-bucket because the buckets differ
# by two orders of magnitude; see hazard 1 above.
ALARM_FRACTION = 0.20

# The `core` ceiling MEASURED for this token class on 2026-07-29 (plan-snapshot's ETag probe read
# `x-ratelimit-limit: 5000`, `x-ratelimit-resource: core`). Used ONLY to state the alarm point in
# the body and to assert the lead over plan-snapshot's hard reserve — never to decide a breach,
# which always reads the limit the live payload reports.
MEASURED_CORE_LIMIT = 5000


class RateLimitError(RuntimeError):
    """The budget could not be READ. Never resolved into a report of health."""


# ------------------------------------------------------------------------------------------------
# PURE core


def alarm_threshold(limit):
    """Remaining at or below this is a breach for a bucket whose ceiling is `limit`.

    A FRACTION of the bucket's own limit, floored at 1. One absolute floor cannot serve both a
    5000/h `core` bucket and a 10/min `code_search` one: at 100 it pages forever on the small
    buckets, and it stays silent on `core` until plan-snapshot is already refusing reads.

    KNOWN LIMITATION, stated rather than hidden. The small buckets are per-MINUTE, so a burst can
    legitimately push `search` to 5/30 for a few seconds and this would page on it. It is not live
    today — a full-tree grep for `gh search` / `/search/` over every script and workflow finds ZERO
    production consumers, so those buckets sit at their ceiling — and a transient dip self-closes
    on the next tick, because the alert is rolling and `decide` closes on the first healthy census.
    Suppressing it properly needs the `reset` clock, which means a `now` this function does not
    take; that is follow-up work, not a reason to special-case the small buckets into silence.
    """
    return max(1, int(limit * ALARM_FRACTION))


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def census(payload):
    """PURE. -> {"rows", "inapplicable", "unreadable", "buckets"}.

    Raises RateLimitError when the payload carries no usable `resources` map AT ALL — a budget that
    was never read must not resolve into "healthy", which is the branch that would close a live
    alert on the tick the endpoint broke.

    Three per-bucket classes, and the distinction is the whole point:
      rows          well-formed and measurable, each carrying its own `threshold`/`breached`
      inapplicable  `limit == 0` — the token is not entitled to that resource, so there is no
                    budget to exhaust. Reported, never breached: a permanently-firing row is a
                    silenced alarm within a week. PER BUCKET only — a census where EVERY bucket is
                    inapplicable measures nothing, so it is no evidence of health either; `decide`
                    refuses the tick rather than reading it as recovery.
      unreadable    present but malformed. FAIL CLOSED: it counts as a breach reason, because a
                    bucket this cannot parse is a bucket it cannot prove healthy.
    """
    if not isinstance(payload, dict):
        raise RateLimitError("/rate_limit did not return a JSON object")
    resources = payload.get("resources")
    if not isinstance(resources, dict) or not resources:
        raise RateLimitError("/rate_limit returned no `resources` map")
    rows, inapplicable, unreadable = [], [], []
    for name in sorted(resources):
        row = resources[name]
        limit = row.get("limit") if isinstance(row, dict) else None
        remaining = row.get("remaining") if isinstance(row, dict) else None
        if not _is_int(limit) or not _is_int(remaining) or limit < 0 or remaining < 0:
            unreadable.append(name)
            continue
        if limit == 0:
            inapplicable.append(name)
            continue
        threshold = alarm_threshold(limit)
        rows.append({
            "resource": name,
            "limit": limit,
            "remaining": remaining,
            "used": row.get("used") if _is_int(row.get("used")) else None,
            "reset": row.get("reset") if _is_int(row.get("reset")) else None,
            "threshold": threshold,
            "breached": remaining <= threshold,
        })
    return {"rows": rows, "inapplicable": sorted(inapplicable),
            "unreadable": sorted(unreadable), "buckets": len(resources)}


def breached(counts):
    """The reasons this budget is unhealthy, deterministically ordered ([] == healthy).

    EVERY resource bucket, not `core` alone — hazard 1 in the header. A bucket at zero is a real
    outage for whatever is charged to it no matter how healthy `core` reads.
    """
    reasons = []
    for row in counts.get("rows") or []:
        if row.get("breached"):
            reasons.append(
                f"`{row['resource']}` is at {row['remaining']}/{row['limit']} remaining "
                f"(alarm at <= {row['threshold']})")
    for name in counts.get("unreadable") or []:
        reasons.append(f"`{name}` reports an unparseable budget — it cannot be proved healthy")
    return reasons


def decide(reasons, has_open_alert, measured):
    """Pure: 'upsert' | 'close' | 'noop' | 'defer'.

    Close ONLY on an explicitly healthy census computed from a budget actually read. `main()` never
    reaches here on a failed read — the ABSENCE of evidence of a breach is not evidence of
    recovery, and closing on it is how an alert silently disarms itself (plan-alert.py's rule).

    `measured` is the number of MEASURABLE buckets (`counts["rows"]`), and zero of them is the
    second, quieter form of that same absence. A payload whose every bucket is `limit: 0` parses
    fine and produces no breach reasons, so a rule keyed on `reasons` alone reads it as recovery
    and closes a live alert — while what it actually says is that the ambient token is entitled to
    NO bucket this can measure, which is a fault, not health. So it DEFERS: no lifecycle decision
    at all, the open alert left exactly as the read-failed path leaves it. A breach still outranks
    this — an all-UNREADABLE census has zero measurable rows AND real reasons, and must alarm.
    """
    if reasons:
        return "upsert"
    if measured <= 0:
        return "defer"
    if has_open_alert:
        return "close"
    return "noop"


def census_line(summary):
    """The row EVERY tick emits — healthy, breached and read-failed alike.

    A census that only speaks up when it is unhappy cannot be distinguished from one that has
    stopped running (AGENTS.md pre-flight item 8), and this alarm exists precisely because the
    previous budget signal was a log line on a path most ticks never took.
    """
    return "ratelimit-alert: " + json.dumps(summary, sort_keys=True, default=str)


def summarise(counts, reasons):
    """PURE. The census payload: every bucket, plus the worst headroom seen, so an operator can
    TREND the budget from the log instead of only learning about it at the alarm point."""
    worst = None
    for row in counts["rows"]:
        # A bucket with no ceiling has no headroom to trend. `census` already routes those to
        # `inapplicable`, but this function takes a counts dict from any caller, and a bare
        # division here turns a weakened classifier into a ZeroDivisionError that ABORTS the tick
        # — i.e. it takes the census down instead of reporting the mistake.
        if not row.get("limit"):
            continue
        fraction = row["remaining"] / row["limit"]
        if worst is None or fraction < worst[1]:
            worst = (row["resource"], fraction)
    return {
        "read": "ok",
        "buckets": counts["buckets"],
        "measured": len(counts["rows"]),
        "inapplicable": counts["inapplicable"],
        "unreadable": counts["unreadable"],
        "breaches": len(reasons),
        "worst": None if worst is None else {"resource": worst[0],
                                             "headroom_pct": round(worst[1] * 100, 2)},
        "rows": counts["rows"],
    }


def render_body(counts, reasons, run_url, maintainer):
    table = ["| resource | remaining | limit | used | alarm at | state |",
             "|---|---|---|---|---|---|"]
    for row in counts["rows"]:
        table.append(
            f"| `{row['resource']}` | {row['remaining']} | {row['limit']} | "
            f"{'?' if row['used'] is None else row['used']} | {row['threshold']} | "
            f"{'**BREACHED**' if row['breached'] else 'ok'} |")
    for name in counts["unreadable"]:
        table.append(f"| `{name}` | ? | ? | ? | ? | **UNREADABLE** |")
    return "\n".join([
        ALERT_MARKER,
        "> 🤖 SPARQ agent — automated ops-alert (shared REST request budget)",
        "",
        f"**{len(reasons)} REST budget bucket(s) are heading toward exhaustion.** This budget is "
        "SHARED: groom, dispatch, worker, curate, triage and every other lane running on the "
        "ambient Actions token draw from these same buckets, so the component that spends it is "
        "usually not the component that fails.",
        "",
        *(f"- {reason}" for reason in reasons),
        "",
        *table,
        "",
        f"Buckets with `limit: 0` are reported as inapplicable, never as a breach "
        f"(the token is not entitled to them): {', '.join(counts['inapplicable']) or '(none)'}.",
        "",
        "⚠️ **This is a SUBSET, and the gap is deliberate.** It censuses the buckets the AMBIENT "
        "Actions token is charged against. The per-owner App INSTALLATION tokens groom mints for "
        "target repos (issue #168) are a SEPARATE bucket set and are NOT measured here — reading "
        "them needs the App signing key, which does not belong in a watchdog job. Do not read a "
        "closed alert as \"no budget anywhere is short\".",
        "",
        "⚠️ **`/rate_limit` is not authoritative for any single request.** Registry #819 measured "
        "it reading healthy throughout the 2026-07-27 outage while every snapshot request 403'd, "
        "because a call may be charged to a bucket other than the one being read. That is why "
        "EVERY reported bucket is measured here, and why the in-band control stays where it is: "
        "`plan-snapshot.py` stops on the `x-ratelimit-remaining` of the response it was actually "
        f"charged for. This alarm LEADS that stop (alarm at "
        f"{alarm_threshold(MEASURED_CORE_LIMIT)} remaining on a {MEASURED_CORE_LIMIT} bucket); it "
        "does not replace it.",
        "",
        "**What is needed:** find the lane whose request cost is growing (registry #1088 is the "
        "worked example) and cut it, or raise the reserve it stops at. Nothing here throttles or "
        "reroutes anything — no gate changed.",
        "",
        f"Run: {run_url}" if run_url else "",
        f"cc @{maintainer}",
    ])


# ------------------------------------------------------------------------------------------------
# gh plumbing — mirrors scripts/ci-latency-alert.py


def _gh(args, capture=False, token=None, check=False):
    """THE ALERT-TRANSPORT path — SINGLE-ATTEMPT and fail-loud. The `issue create/edit/comment/
    close` and `label create` calls below are MUTATIONS, and gh_retry's hard scope rule keeps them
    here: an ambiguous transient failure does not prove GitHub skipped the attempt, so a replay
    duplicates a comment or a state transition. The IDEMPOTENT reads go through `_gh_json`.

    Sanitized fail-loud wrapper: op + returncode only — never stderr (GH_DEBUG=api can echo request
    bodies into a PUBLIC run log) and never argument content beyond the gh subcommand words.
    """
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    result = subprocess.run(["gh"] + args, capture_output=capture, text=True, env=env, check=False)
    if check and result.returncode != 0:
        print(f"::warning::ratelimit-alert: gh {args[0]} "
              f"{args[1] if len(args) > 1 else ''} failed (rc={result.returncode})")
    return result


def _load_gh_retry():
    """The shared bounded-retry policy for IDEMPOTENT reads (scripts/gh_retry.py).

    BY PATH because the module name has no hyphen while its siblings do. RAISES rather than
    degrading to an unretried read: a missing retry layer is a broken detector, and REQUIRED_FILES
    reds on the same absence one step earlier.
    """
    path = SCRIPTS_DIR / "gh_retry.py"
    spec = importlib.util.spec_from_file_location("registry_gh_retry_for_ratelimit", str(path))
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RateLimitError(f"cannot load the shared gh retry policy at {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _gh_json(args):
    """Parsed JSON from ONE IDEMPOTENT `gh` READ, or None when the read never landed.

    RETRIED, BOUNDED, through scripts/gh_retry.py. Returning None rather than a default is what
    keeps the fail-loud posture: a population that was never read must never be resolved into a
    report of health.
    """
    result = _load_gh_retry().run_gh(list(args))
    if result.returncode != 0:
        print(f"::warning::ratelimit-alert: gh {args[0]} "
              f"{args[1] if len(args) > 1 else ''} failed after "
              f"{getattr(result, 'gh_attempts', 1)} attempt(s) (rc={result.returncode}, "
              f"http={getattr(result, 'gh_http_status', None)})")
        return None
    try:
        return json.loads(result.stdout or "null")
    except ValueError:
        print(f"::warning::ratelimit-alert: gh {args[0]} succeeded but returned unparseable JSON")
        return None


def _alert_route(alert_repo, alert_token, registry_repo):
    """(repo, token) — identical semantics to groom-alert/ci-latency-alert/park-stock-alert: the
    private ALERT_REPO only when ALERT_TOKEN can write there; a half-configured deployment (repo
    set, token missing) falls back to the registry repo instead of silently losing the alert."""
    if alert_repo and alert_token:
        return alert_repo, alert_token
    return registry_repo, None


def read_rate_limit():
    """GET /rate_limit for the ambient token. Raises when the read never landed.

    The endpoint itself is not charged against any bucket, so the census costs nothing it measures.
    """
    payload = _gh_json(["api", "-H", "Accept: application/vnd.github+json", "/rate_limit"])
    if payload is None:
        raise RateLimitError("gh api /rate_limit failed or returned no JSON")
    return payload


# ------------------------------------------------------------------------------------------------


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    # The workflow-seam self-test scans for exactly this declaration, so it must stay an argparse
    # option and not a hand-rolled sys.argv check.
    parser.add_argument("--self-test", action="store_true",
                        help="run the hermetic self-test and exit")
    return parser


def main(argv=None):
    args = build_parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    if args.self_test:
        return _self_test()

    registry_repo = os.environ["REGISTRY_REPO"]
    repo, token = _alert_route(
        os.environ.get("ALERT_REPO"), os.environ.get("ALERT_TOKEN"), registry_repo)
    run_url = os.environ.get("RUN_URL", "")
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")

    try:
        counts = census(read_rate_limit())
    except RateLimitError as exc:
        # STILL EMIT A ROW. "the budget could not be read" and "this watchdog stopped running" are
        # different facts and an operator must be able to tell them apart from the log alone.
        print(census_line({"read": "FAILED", "detail": str(exc)}))
        print(f"::warning::ratelimit-alert: {exc} — skipping this tick "
              "(no census; an open alert is left exactly as it is)")
        return 1

    reasons = breached(counts)
    print(census_line(summarise(counts, reasons)))

    listed = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", "open",
                  "--json", "number,title,body", "--limit", "100"],
                 capture=True, token=token, check=True)
    if listed.returncode != 0:
        return 1
    try:
        found = json.loads(listed.stdout or "[]")
        if not isinstance(found, list):
            raise ValueError("expected a JSON array")
    except ValueError:
        print("::warning::ratelimit-alert: gh issue list succeeded but returned unparseable JSON "
              "— skipping this tick (no dedupe/recovery data; next tick retries)")
        return 0
    num = next((i["number"] for i in found if ALERT_MARKER in (i.get("body") or "")), None)
    if num is None:
        num = next((i["number"] for i in found if i.get("title") == ALERT_TITLE), None)

    action = decide(reasons, num is not None, len(counts["rows"]))
    if action == "defer":
        # Same posture as the read-failed branch above: the census row is already out, so this tick
        # is distinguishable from a dead watchdog, and nothing is mutated.
        print("::warning::ratelimit-alert: the payload reported NO measurable bucket "
              f"({counts['buckets']} bucket(s), all inapplicable) — deferring this tick "
              "(no evidence of budget health; an open alert is left exactly as it is)")
        return 1
    if action == "upsert":
        _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", "d73a4a",
             "--description", "Autonomous ops alert (maintainer action)"],
            capture=True, token=token)  # idempotent
        body = render_body(counts, reasons, run_url, maintainer)
        if num:
            wrote = _gh(["issue", "edit", str(num), "-R", repo, "--body", body],
                        capture=True, token=token, check=True)
        else:
            wrote = _gh(["issue", "create", "-R", repo, "--title", ALERT_TITLE,
                         "--label", ALERT_LABEL, "--body", body],
                        capture=True, token=token, check=True)
        if wrote.returncode != 0:
            return 1
        print(f"::warning::ratelimit-alert: {'; '.join(reasons)} — maintainer alerted")
        return 0
    if action == "close":
        commented = _gh(["issue", "comment", str(num), "-R", repo, "--body",
                         "✅ Recovered — every measured REST budget bucket is back above its "
                         "alarm point. Auto-closing."],
                        capture=True, token=token, check=True)
        closed = _gh(["issue", "close", str(num), "-R", repo], capture=True, token=token,
                     check=True)
        if commented.returncode != 0 or closed.returncode != 0:
            return 1
        print("ratelimit-alert: budget healthy — closed the alert")
        return 0
    print("ratelimit-alert: budget healthy, no open alert — nothing to do")
    return 0


# ------------------------------------------------------------------------------------------------
# HERMETIC SELF-TEST — no network, no gh.


def _payload(**resources):
    return {"resources": {name: dict(row) for name, row in resources.items()}}


def _bucket(limit, remaining, used=None, reset=1785182238):
    return {"limit": limit, "remaining": remaining,
            "used": limit - remaining if used is None else used, "reset": reset}


def _test_threshold(chk):
    # HAND-WRITTEN expected values, not `int(limit * ALARM_FRACTION)` recomputed here: an assertion
    # that derives its expectation from the constant the code reads cannot fail (AGENTS.md
    # pre-flight 2b), and every one of these dies if ALARM_FRACTION moves.
    chk("threshold: a 5000 `core` bucket alarms at 1000 remaining", alarm_threshold(5000), 1000)
    chk("threshold: a 30 `search` bucket alarms at 6 — NOT at one absolute floor shared with core",
        alarm_threshold(30), 6)
    chk("threshold: a 10 `code_search` bucket alarms at 2", alarm_threshold(10), 2)
    # Without the floor, a 1- or 2-request bucket alarms at 0 and can only be reported once it is
    # already spent, which is the whole failure mode this file exists for.
    chk("threshold: a tiny bucket still alarms at >= 1, never at 0", alarm_threshold(2), 1)


def _test_census(chk):
    # ---- THE HEADLINE RED TEST (hazard 1). A NON-core bucket at zero MUST breach while `core`
    # reads perfectly healthy. This is the exact shape #819 measured `/rate_limit` missing, and a
    # census that reads `core` alone passes every other check in this file and fails this one.
    mixed = _payload(core=_bucket(5000, 4980), search=_bucket(30, 0), graphql=_bucket(5000, 4999))
    reasons = breached(census(mixed))
    chk("[RED] a non-core bucket at ZERO breaches while core is healthy", len(reasons), 1)
    chk("[RED] ...and the reason NAMES the offending bucket, not `core`",
        bool(reasons) and "`search`" in reasons[0] and "core" not in reasons[0], True)

    # ---- CONTROL: the fraction is per-bucket. A 30-limit bucket at 20 remaining is HEALTHY; one
    # absolute floor (plan-snapshot's core reserve of 100, say) would call it breached and this
    # alarm would page on every tick forever until somebody muted it.
    chk("[CONTROL] a small bucket well inside its OWN fraction is healthy",
        breached(census(_payload(search=_bucket(30, 20)))), [])
    # ...and the same absolute number on `core` IS a breach. The two rows together are what pins
    # "fraction of its own limit" rather than any single number.
    chk("[CONTROL] 20 remaining on a 5000 bucket IS a breach (same number, different bucket)",
        len(breached(census(_payload(core=_bucket(5000, 20))))), 1)

    # ---- boundary: `<=` not `<`, checked from BOTH sides.
    chk("boundary: remaining exactly AT the threshold breaches",
        len(breached(census(_payload(core=_bucket(5000, 1000))))), 1)
    chk("boundary: one request above the threshold is healthy",
        breached(census(_payload(core=_bucket(5000, 1001)))), [])

    # ---- limit 0 is INAPPLICABLE, never a breach. A token not entitled to a resource has no
    # budget there to exhaust; treating it as "0 remaining" pages on every tick, and an alarm that
    # pages on every tick is a muted alarm inside a week.
    zero = census(_payload(core=_bucket(5000, 4900), scim=_bucket(0, 0)))
    chk("limit 0 is reported as INAPPLICABLE", zero["inapplicable"], ["scim"])
    chk("...and does NOT breach", breached(zero), [])
    chk("...and is NOT counted as a measured row", [r["resource"] for r in zero["rows"]], ["core"])

    # ---- malformed bucket: FAIL CLOSED. It cannot be proved healthy, so it breaches.
    for label, row in (("a missing `remaining`", {"limit": 5000}),
                       ("a string `remaining`", {"limit": 5000, "remaining": "4000"}),
                       ("a boolean `remaining`", {"limit": 5000, "remaining": True}),
                       ("a negative `remaining`", {"limit": 5000, "remaining": -1}),
                       ("a non-dict row", "nonsense")):
        got = census({"resources": {"core": _bucket(5000, 4900), "odd": row}})
        chk(f"malformed bucket ({label}) is UNREADABLE, never silently healthy",
            got["unreadable"], ["odd"])
        chk(f"...and breaches ({label}) — fail closed", len(breached(got)), 1)

    # ---- payload-level refusal. "no resources" is NOT "healthy": that branch is the one that
    # would CLOSE a live alert on the tick the endpoint broke.
    for label, bad in (("a JSON array", []),
                       ("a scalar", 7),
                       ("no `resources` key", {"rate": {"limit": 5000, "remaining": 10}}),
                       ("an EMPTY `resources` map", {"resources": {}}),
                       ("a non-dict `resources`", {"resources": []})):
        raised = False
        try:
            census(bad)
        except RateLimitError:
            raised = True
        chk(f"payload refusal: {label} RAISES rather than reading as healthy", raised, True)

    # ---- the deprecated top-level `rate` mirror must NOT be counted as a second bucket.
    both = census({"resources": {"core": _bucket(5000, 4900)},
                   "rate": {"limit": 5000, "remaining": 0}})
    chk("the deprecated top-level `rate` mirror is not censused as a bucket",
        [r["resource"] for r in both["rows"]], ["core"])

    # ---- bookkeeping
    full = census(_payload(core=_bucket(5000, 4900), search=_bucket(30, 29)))
    chk("every reported bucket is counted", full["buckets"], 2)
    chk("rows are sorted by resource name (a stable census diffs)",
        [r["resource"] for r in full["rows"]], ["core", "search"])
    chk("`used` is carried through for trending",
        [r["used"] for r in full["rows"]][:1], [100])

    # ---- MULTIPLE breaches are all reported, in order. A census that reported only the first
    # would hide the second bucket for as long as the first stayed red.
    two = breached(census(_payload(core=_bucket(5000, 0), search=_bucket(30, 0))))
    chk("every breached bucket is named, not just the first", len(two), 2)
    chk("...in resource order",
        len(two) == 2 and "`core`" in two[0] and "`search`" in two[1], True)


def _test_summary(chk):
    counts = census(_payload(core=_bucket(5000, 4000), search=_bucket(30, 3)))
    summary = summarise(counts, breached(counts))
    chk("summary: `worst` is the LOWEST-headroom bucket, not the first or the biggest",
        (summary["worst"] or {}).get("resource"), "search")
    chk("summary: ...and states its headroom as a percentage of its OWN limit",
        (summary["worst"] or {}).get("headroom_pct"), 10.0)
    chk("summary: the healthy bucket is still carried in the rows (trending needs both)",
        [r["resource"] for r in summary["rows"]], ["core", "search"])
    chk("summary: a fully inapplicable census reports worst=None rather than crashing",
        summarise(census(_payload(scim=_bucket(0, 0))), [])["worst"], None)
    # A zero-ceiling row reaching `rows` means the classifier was weakened. It must be SKIPPED for
    # trending, never divided by: a ZeroDivisionError here aborts the whole tick, so the census
    # would go silent on exactly the change that broke it.
    chk("summary: a zero-ceiling row that reached `rows` is skipped, not divided by",
        summarise({"rows": [{"resource": "scim", "limit": 0, "remaining": 0},
                            {"resource": "core", "limit": 5000, "remaining": 500}],
                   "inapplicable": [], "unreadable": [], "buckets": 2}, [])["worst"],
        {"resource": "core", "headroom_pct": 10.0})
    chk("summary: `read` is `ok` on a census that was actually computed", summary["read"], "ok")


def _test_decide(chk):
    chk("decide: breach -> upsert", decide(["r"], False, 2), "upsert")
    chk("decide: breach with an open alert -> upsert (edit in place, never a duplicate)",
        decide(["r"], True, 2), "upsert")
    chk("decide: healthy with an open alert -> close", decide([], True, 2), "close")
    chk("decide: healthy with no alert -> noop", decide([], False, 2), "noop")
    # ---- [RED] NO MEASURABLE BUCKET IS NOT RECOVERY. An all-`limit: 0` payload parses, breaches
    # nothing, and on a `reasons`-only rule closes a live alert on the tick the ambient token lost
    # its entitlements — the same silent disarm as closing on a failed read, one layer quieter.
    chk("[RED] decide: zero measurable buckets with an open alert DEFERS, never closes",
        decide([], True, 0), "defer")
    chk("decide: ...and defers with no open alert too (nothing was measured, so nothing is known)",
        decide([], False, 0), "defer")
    # ANTI-VACUITY for the row above: `defer` must not swallow the alarm. An ALL-UNREADABLE census
    # also has zero measurable rows, and it must still page.
    chk("decide: a breach with zero measurable rows (all-unreadable) still UPSERTS",
        decide(["r"], True, 0), "upsert")
    # Boundary from both sides: ONE measurable bucket is enough evidence to act on.
    chk("decide: exactly one measurable bucket is enough to close on", decide([], True, 1), "close")


def _test_body(chk):
    counts = census(_payload(core=_bucket(5000, 4900), search=_bucket(30, 0), scim=_bucket(0, 0)))
    reasons = breached(counts)
    body = render_body(counts, reasons, "http://run", "jeswr")
    chk("body: carries the stable dedupe marker", ALERT_MARKER in body, True)
    chk("body: NAMES the breached bucket", "`search`" in body, True)
    chk("body: tabulates the HEALTHY buckets too — the reader needs the whole budget, not the "
        "one row that tripped", "`core`" in body, True)
    chk("body: names the inapplicable bucket as inapplicable rather than as a breach",
        "scim" in body and "**BREACHED**" not in body.split("scim")[-1].split("\n")[0], True)
    chk("body: says the budget is SHARED — the spender is usually not the failer",
        "SHARED" in body, True)
    # The subset caveat is load-bearing: a reader who takes a closed alert as "no budget anywhere
    # is short" stops looking, which is exactly the park-stock-alert failure.
    chk("body: states the per-owner App installation buckets are NOT measured",
        "SUBSET" in body and "App INSTALLATION" in body, True)
    chk("body: states that /rate_limit is not authoritative for a single request",
        "not authoritative" in body, True)
    chk("body: carries the model-agnostic SPARQ self-ID", "🤖 SPARQ agent" in body, True)
    # A model marker in an authored body goes stale the moment the harness routes elsewhere (#2504).
    chk("body: hard-codes NO model marker",
        bool(re.search(r"\b(OPUS|FABLE|HAIKU|SONNET)[- ]?\d", body)), False)
    chk("body: carries the run link", "http://run" in body, True)
    # An UNREADABLE bucket must appear in the table. It is the one class with no numbers to show,
    # so a table built only from `rows` drops it silently while the reason list still cites it.
    odd = census({"resources": {"core": _bucket(5000, 4900), "odd": {"limit": 5000}}})
    chk("body: an UNREADABLE bucket is rendered in the table, not dropped",
        "**UNREADABLE**" in render_body(odd, breached(odd), "", "jeswr"), True)


def _test_gh_plumbing(chk):
    """THE REAL TRANSPORT WRAPPERS. `python3 -m trace --count --missing` put every line of `_gh`,
    `_load_gh_retry` and `_gh_json` at ZERO — the shape AGENTS.md pre-flight item 1 names: helpers
    get tested because they are easy to call, and the wrappers that touch the real world get
    skipped, which is exactly where a FABRICATING bug survives. `_gh_json` returning `{}` instead
    of None on a failed read turns "never read" into "no buckets, all healthy" and would CLOSE a
    live alert.
    """
    import contextlib
    import io

    class _P:
        def __init__(self, rc=0, out=""):
            self.returncode, self.stdout, self.stderr = rc, out, ""

    # ---- _gh: argv shape, token routing, and the SANITIZED failure line -------------------------
    real_run = subprocess.run
    seen = {"rc": 0}

    def fake_run(argv, **kwargs):
        seen["argv"] = list(argv)
        seen["env"] = kwargs.get("env") or {}
        return _P(seen["rc"])

    out = io.StringIO()
    try:
        subprocess.run = fake_run
        with contextlib.redirect_stdout(out):
            _gh(["issue", "list", "-R", "o/r"], capture=True, token="tok-abc")
            chk("_gh: prepends the `gh` binary exactly once", seen["argv"],
                ["gh", "issue", "list", "-R", "o/r"])
            chk("_gh: routes the alert token through GH_TOKEN", seen["env"].get("GH_TOKEN"),
                "tok-abc")
            _gh(["issue", "list"], capture=True)
            chk("_gh: ...and does NOT leave the previous call's token on a tokenless call",
                seen["env"].get("GH_TOKEN"), os.environ.get("GH_TOKEN"))
            seen["rc"] = 1
            _gh(["issue", "create", "-R", "o/r", "--body", "SUPER-SECRET-BODY"],
                capture=True, check=True)
        text = out.getvalue()
    finally:
        subprocess.run = real_run
    chk("_gh: a failed call WARNS, naming the op and the return code",
        "gh issue create" in text and "rc=1" in text, True)
    # The sanitization claim, asserted rather than left in prose: this runs in a PUBLIC run log,
    # and argument content is exactly what must not reach it.
    chk("_gh: ...and the warning carries NO argument content beyond the subcommand words",
        "SUPER-SECRET-BODY" in text, False)

    # ---- _load_gh_retry: the shared bounded-retry layer, loaded for real (offline) --------------
    retry = _load_gh_retry()
    chk("_load_gh_retry: returns the shared layer with its run_gh",
        callable(getattr(retry, "run_gh", None)), True)
    # CROSS-MODULE CONTRACT. gh_retry refuses to retry anything it cannot prove is an idempotent
    # read and silently downgrades it to a SINGLE attempt. If this argv ever stopped being
    # admitted, every budget read would lose its backoff while every assertion here stayed green.
    chk("_load_gh_retry: gh_retry ADMITS this watchdog's argv as an idempotent read, so the "
        "bounded backoff actually applies to it",
        retry.read_cli_reject(["api", "-H", "Accept: application/vnd.github+json",
                               "/rate_limit"]), None)

    # ---- _gh_json: a read that did not land must be None, NEVER an empty container --------------
    real_loader = _load_gh_retry
    calls = []

    class _FakeRetry:
        rc, out = 0, ""

        @staticmethod
        def run_gh(args):
            calls.append(list(args))
            return _P(_FakeRetry.rc, _FakeRetry.out)

    try:
        globals()["_load_gh_retry"] = lambda: _FakeRetry
        _FakeRetry.rc, _FakeRetry.out = 0, '{"resources": {}}'
        with contextlib.redirect_stdout(io.StringIO()):
            chk("_gh_json: a landed read is parsed", _gh_json(["api", "/rate_limit"]),
                {"resources": {}})
            chk("_gh_json: ...through the bounded-retry layer, not a bare subprocess",
                calls, [["api", "/rate_limit"]])
            _FakeRetry.rc, _FakeRetry.out = 1, ""
            chk("_gh_json: a FAILED read is None — never `{}`, which would census as "
                "'no buckets, all healthy'", _gh_json(["api", "/rate_limit"]), None)
            _FakeRetry.rc, _FakeRetry.out = 0, "not json at all"
            chk("_gh_json: an unparseable body is None, never a partial read",
                _gh_json(["api", "/rate_limit"]), None)
            _FakeRetry.rc, _FakeRetry.out = 0, ""
            chk("_gh_json: an EMPTY body is None — silence is not evidence",
                _gh_json(["api", "/rate_limit"]), None)
        # ...and read_rate_limit must turn every one of those Nones into a RAISE, not a default.
        for label, (rc, body) in (("a failed read", (1, "")),
                                  ("an unparseable body", (0, "{{{")),
                                  ("an empty body", (0, ""))):
            _FakeRetry.rc, _FakeRetry.out = rc, body
            raised = False
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    read_rate_limit()
            except RateLimitError:
                raised = True
            chk(f"read_rate_limit: {label} RAISES rather than returning a defaulted payload",
                raised, True)
    finally:
        globals()["_load_gh_retry"] = real_loader


def _test_end_to_end(chk):
    """The alarm driven through main() with gh stubbed — the layer where the conditionally-inert
    mutants live (AGENTS.md pre-flight item 3)."""
    import io
    import contextlib

    real_json, real_gh = _gh_json, _gh
    base_env = {"REGISTRY_REPO": "o/r", "RUN_URL": "http://run", "MAINTAINER_HANDLE": "jeswr"}
    # Seed one of the borrowed variables so the restore-to-previous-value branch is EXERCISED and
    # not only the pop-if-absent one. A harness that leaks ALERT_REPO would route a later caller's
    # alert into a repository this test invented.
    os.environ["ALERT_REPO"] = "sentinel/preexisting"
    saved = {k: os.environ.get(k) for k in ("REGISTRY_REPO", "RUN_URL", "MAINTAINER_HANDLE",
                                            "ALERT_REPO", "ALERT_TOKEN")}

    class _Result:
        def __init__(self, stdout="", returncode=0):
            self.stdout, self.returncode = stdout, returncode

    def run(payload, open_alerts, *, read_fails=False, list_result=None, write_rc=0):
        calls = []

        def fake_json(args):
            calls.append(("read", list(args)))
            return None if read_fails else payload

        def fake_gh(args, capture=False, token=None, check=False):
            calls.append(("gh", list(args), token))
            if args[:2] == ["issue", "list"]:
                return _Result(json.dumps(open_alerts)) if list_result is None else list_result
            if args[0] == "issue" and args[1] in ("create", "edit", "comment", "close"):
                return _Result(returncode=write_rc)
            return _Result()

        globals()["_gh_json"], globals()["_gh"] = fake_json, fake_gh
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                rc = main([])
        finally:
            globals()["_gh_json"], globals()["_gh"] = real_json, real_gh
        return rc, out.getvalue(), calls

    for key, value in base_env.items():
        os.environ[key] = value
    os.environ.pop("ALERT_REPO", None)
    os.environ.pop("ALERT_TOKEN", None)
    try:
        healthy = _payload(core=_bucket(5000, 4900), search=_bucket(30, 29))
        # ---- THE CENSUS IS UNCONDITIONAL. This is the assertion that reds on the mutant AGENTS.md
        # item 3 names: `if reasons: print(census_line(...))` deletes nothing visible on a breached
        # tick and blinds every healthy one — i.e. it vanishes on exactly the tick an operator
        # interrogates to ask "is this thing still running?".
        rc, out, calls = run(healthy, [])
        chk("e2e: a HEALTHY tick still emits the census line", "ratelimit-alert: {" in out, True)
        chk("e2e: ...naming every measured bucket, healthy ones included",
            '"core"' in out and '"search"' in out, True)
        chk("e2e: ...and reports zero breaches rather than staying silent",
            '"breaches": 0' in out, True)
        chk("e2e: a healthy tick with no open alert writes NOTHING but the list read",
            [c[1][:2] for c in calls if c[0] == "gh"], [["issue", "list"]])
        chk("e2e: ...and exits 0", rc, 0)

        # ---- an ALL-INAPPLICABLE census still emits a row. Without this, a token entitled to
        # nothing looks identical to a dead watchdog.
        marked = [{"number": 77, "title": "whatever", "body": "x " + ALERT_MARKER + " y"}]
        nothing_measurable = _payload(scim=_bucket(0, 0), core=_bucket(0, 0))
        rc_zero, out_zero, calls_zero = run(nothing_measurable, [])
        chk("e2e: an all-inapplicable census STILL emits its row (a zero row is a row)",
            "ratelimit-alert: {" in out_zero and '"measured": 0' in out_zero, True)
        # ---- ...AND IT IS NOT A RECOVERY. Every bucket at `limit: 0` breaches nothing, so a
        # lifecycle rule keyed on reasons alone would comment-and-close a live alert on the tick
        # the ambient token could measure no budget at all. Driven through main() because that is
        # the layer that spends the mutation.
        rc_open, out_open, calls_open = run(nothing_measurable, marked)
        chk("[RED] e2e: an all-inapplicable census NEVER comments on or closes the open alert",
            [c[1][:3] for c in calls_open if c[0] == "gh" and c[1][0] == "issue"],
            [["issue", "list", "-R"]])
        chk("e2e: ...and writes nothing else either (no label create, no create/edit)",
            [c[1][:2] for c in calls_open if c[0] == "gh"], [["issue", "list"]])
        chk("e2e: ...exits NONZERO so the deferred tick is visible", (rc_open, rc_zero), (1, 1))
        chk("e2e: ...naming the deferral rather than reporting health",
            "deferring this tick" in out_open, True)
        chk("e2e: ...and STILL emits the census row (a deferred tick is not a silent one)",
            "ratelimit-alert: {" in out_open and '"measured": 0' in out_open, True)
        chk("e2e: ...and with no alert open it stays a no-write tick too",
            [c[1][:2] for c in calls_zero if c[0] == "gh"], [["issue", "list"]])
        # ANTI-VACUITY: an ALL-UNREADABLE census ALSO has zero measurable rows. It must still
        # alarm — a deferral that swallowed the fail-closed path would be worse than the bug.
        _, _, calls_odd = run({"resources": {"odd": {"limit": 5000}}}, marked)
        chk("e2e: an all-UNREADABLE census still EDITS the alert — the deferral does not swallow "
            "the fail-closed path",
            [c[1][:3] for c in calls_odd if c[0] == "gh" and c[1][0] == "issue"],
            [["issue", "list", "-R"], ["issue", "edit", "77"]])

        # ---- breach -> create
        breach = _payload(core=_bucket(5000, 4900), search=_bucket(30, 0))
        rc, out, calls = run(breach, [])
        created = [c[1] for c in calls if c[0] == "gh" and c[1][:2] == ["issue", "create"]]
        chk("e2e: a breach CREATES the alert", len(created), 1)
        chk("e2e: ...labelled ops-alert", [a for c in created for a in c if a == ALERT_LABEL],
            [ALERT_LABEL])
        chk("e2e: ...with the marker in the body",
            any(ALERT_MARKER in a for c in created for a in c), True)
        chk("e2e: ...and the census line is emitted on the breached tick too",
            '"breaches": 1' in out, True)
        chk("e2e: ...exit 0 (the alarm fired; the WATCHDOG did not fail)", rc, 0)

        # ---- breach with an open alert -> EDIT, never a duplicate
        open_alert = [{"number": 77, "title": "whatever", "body": "x " + ALERT_MARKER + " y"}]
        _, _, calls = run(breach, open_alert)
        chk("e2e: a breach with an open alert EDITS it",
            [c[1][:3] for c in calls if c[0] == "gh" and c[1][0] == "issue"],
            [["issue", "list", "-R"], ["issue", "edit", "77"]])

        # ---- recovery -> close
        _, _, calls = run(healthy, open_alert)
        chk("e2e: recovery comments AND closes the open alert",
            [c[1][:3] for c in calls if c[0] == "gh" and c[1][0] == "issue"],
            [["issue", "list", "-R"], ["issue", "comment", "77"], ["issue", "close", "77"]])

        # ---- THE FAIL-CLOSED PATH. A failed read must NOT reach decide(): an unread budget has no
        # census, and the `close` branch would read it as recovery and silently disarm the alarm
        # on exactly the tick GitHub stopped answering.
        rc, out, calls = run(healthy, open_alert, read_fails=True)
        chk("e2e: an unreadable budget NEVER closes the open alert",
            [c for c in calls if c[0] == "gh"], [])
        chk("e2e: ...exits NONZERO so the failure is visible", rc, 1)
        chk("e2e: ...and STILL emits a census row saying the read failed",
            '"read": "FAILED"' in out, True)

        # ---- THE OTHER TWO WAYS THE DEDUPE READ CAN FAIL. Both are silent-disarm vectors: a
        # tick that cannot enumerate the open alerts knows nothing about recovery, so it must
        # leave whatever is open exactly as it is rather than deciding from an empty list.
        rc, _, calls = run(healthy, open_alert, list_result=_Result(returncode=1))
        chk("e2e: an alert LISTING that failed never closes the open alert",
            [c[1][:2] for c in calls if c[0] == "gh"], [["issue", "list"]])
        chk("e2e: ...and exits NONZERO", rc, 1)
        rc, _, calls = run(healthy, open_alert, list_result=_Result(stdout="{not json"))
        chk("e2e: an UNPARSEABLE alert listing never closes the open alert either",
            [c[1][:2] for c in calls if c[0] == "gh"], [["issue", "list"]])
        rc2, _, calls2 = run(healthy, open_alert, list_result=_Result(stdout='{"a": 1}'))
        chk("e2e: ...nor does a listing that parses but is not the expected ARRAY",
            [c[1][:2] for c in calls2 if c[0] == "gh"], [["issue", "list"]])

        # ---- a write that did not land must not be reported as an alert that did ---------------
        rc, _, _ = run(breach, [], write_rc=1)
        chk("e2e: a FAILED issue create exits NONZERO (an alert nobody received is not a page)",
            rc, 1)
        rc, _, _ = run(healthy, open_alert, write_rc=1)
        chk("e2e: a FAILED close exits NONZERO", rc, 1)

        # ---- PRIVATE ALERT ROUTING, through main() rather than only through _alert_route -------
        os.environ["ALERT_REPO"], os.environ["ALERT_TOKEN"] = "priv/ops", "alert-tok"
        _, _, calls = run(breach, [])
        writes = [(c[1], c[2]) for c in calls if c[0] == "gh" and c[1][:2] == ["issue", "create"]]
        chk("e2e: with ALERT_REPO+ALERT_TOKEN the alert is created in the PRIVATE repo",
            len(writes) == 1 and "priv/ops" in writes[0][0], True)
        chk("e2e: ...under the ALERT_TOKEN, not the ambient one",
            [w[1] for w in writes], ["alert-tok"])
        os.environ["ALERT_TOKEN"] = ""
        _, _, calls = run(breach, [])
        writes = [(c[1], c[2]) for c in calls if c[0] == "gh" and c[1][:2] == ["issue", "create"]]
        chk("e2e: ALERT_REPO with no token falls back to the REGISTRY repo rather than losing "
            "the alert", len(writes) == 1 and "o/r" in writes[0][0], True)
        chk("e2e: ...under the ambient token", [w[1] for w in writes], [None])
        os.environ.pop("ALERT_REPO", None)
        os.environ.pop("ALERT_TOKEN", None)

        # ---- the read is the documented endpoint, through the bounded-retry layer
        _, _, calls = run(healthy, [])
        reads = [c[1] for c in calls if c[0] == "read"]
        chk("e2e: exactly one budget read per tick", len(reads), 1)
        chk("e2e: ...and it is GET /rate_limit (no method flag, so gh_retry admits it as a read)",
            reads[0][0] == "api" and "/rate_limit" in reads[0] and "-X" not in reads[0], True)

        # ---- the dedupe read must ask for `body`, or the marker match is vacuous
        listed = [c[1] for c in calls if c[0] == "gh" and c[1][:2] == ["issue", "list"]]
        chk("e2e: the dedupe read fetches `body` — without it the marker match cannot work",
            [a for c in listed for a in c if a == "number,title,body"], ["number,title,body"])

        # ---- ALERT ROUTING. A half-configured deployment must not lose the alert.
        chk("route: repo+token -> the private alert repo", _alert_route("p/q", "t", "o/r"),
            ("p/q", "t"))
        chk("route: repo WITHOUT a token falls back to the registry repo, never silently drops",
            _alert_route("p/q", "", "o/r"), ("o/r", None))
        chk("route: no repo -> the registry repo", _alert_route("", "", "o/r"), ("o/r", None))
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    chk("e2e: the harness restores every environment variable it borrowed",
        os.environ.get("ALERT_REPO"), "sentinel/preexisting")
    os.environ.pop("ALERT_REPO", None)


def _test_workflow_seam(chk):
    """THE YAML SEAM. Every guard above is Python, and Python mutants die easily. MEASURED across
    this estate: the mutants that SURVIVE live in a workflow `if:`, a step, or a call site — the
    wiring that decides whether the Python runs at all (AGENTS.md pre-flight item 6). Pinned by
    EXACT match, never containment: `--self-test-DISABLED` contains `--self-test`.
    """
    missing = [p for p in REQUIRED_FILES if not (REPO_ROOT / p).exists()]
    if missing:
        # A sparse checkout that dropped an input would make every assertion below silently
        # unreachable on the live path, which is worse than failing here.
        chk(f"seam: REQUIRED_FILES present (missing: {missing})", False, True)
        return

    from yaml_dependency import require_yaml
    yaml = require_yaml("ratelimit-alert workflow-seam checks")

    # ---- CROSS-FILE: the alarm must LEAD the hard stop it warns about ---------------------------
    # plan-snapshot.py STOPS the dispatch snapshot at RATE_LIMIT_RESERVE remaining. An alarm that
    # fires at or below that point tells the maintainer about an outage that has already started —
    # the retrospective diagnosis this file exists to replace. Both sides of this comparison are
    # defined independently, in different files, so neither can be read off the other.
    reserve = re.search(r"^RATE_LIMIT_RESERVE\s*=\s*(\d+)",
                        (REPO_ROOT / PLAN_SNAPSHOT).read_text(encoding="utf-8"), re.M)
    chk("seam: plan-snapshot.py still declares RATE_LIMIT_RESERVE (the pattern is not vacuous)",
        reserve is not None, True)
    chk(f"seam: the core-bucket alarm point ({alarm_threshold(MEASURED_CORE_LIMIT)}) LEADS "
        f"plan-snapshot's hard reserve ({reserve and reserve.group(1)}) — an alarm that fires "
        "after the sweep already refuses is a post-mortem, not an alarm",
        reserve is not None and alarm_threshold(MEASURED_CORE_LIMIT) > int(reserve.group(1)), True)

    wf = yaml.safe_load((REPO_ROOT / GROOM_WORKFLOW).read_text(encoding="utf-8"))
    jobs = wf.get("jobs") or {}
    chk(f"seam: groom-sweep.yml hosts a `{GROOM_JOB}` job", GROOM_JOB in jobs, True)
    job = jobs.get(GROOM_JOB) or {}

    # A watcher hosted inside the watched job cannot observe the watched job's absence — and a
    # budget alarm suppressed by the failure of the sweep whose budget it watches is precisely
    # inverted: the tick it must speak on is the tick it would be skipped.
    chk("seam: the watchdog job declares NO `needs:` — an edge is invisible to any `if:`-only "
        "assertion", "needs" in job, False)
    chk("seam: ...and NO job-level `if:`", "if" in job, False)
    chk("seam: ...and no job-level `continue-on-error` (only the ALERT step carries one)",
        "continue-on-error" in job, False)

    perms = job.get("permissions") or {}
    chk("seam: repair authority only — contents:read + issues:write and nothing else",
        perms, {"contents": "read", "issues": "write"})
    for forbidden in ("pull-requests", "checks", "id-token", "packages", "actions"):
        chk(f"seam: no `{forbidden}` permission (no arming authority)", forbidden in perms, False)
    chk("seam: bound to the default-branch-only dispatch-secrets environment (#101) — it reads "
        "ALERT_TOKEN/ALERT_REPO", job.get("environment"), "dispatch-secrets")

    steps = job.get("steps") or []
    runs = [str(step.get("run", "")).strip() for step in steps]
    self_test_cmd = f"python3 registry/scripts/{Path(__file__).name} --self-test"
    live_cmd = f"python3 registry/scripts/{Path(__file__).name}"
    chk("seam: the job runs the self-test EXACTLY (exact match: `--self-test-DISABLED` contains "
        "`--self-test`)", self_test_cmd in runs, True)
    chk("seam: the job runs the alarm EXACTLY", live_cmd in runs, True)
    # Guarded rather than indexed straight into `runs`: a DELETED step must red this row and let
    # every row below it still run. An exception raised by the assertion itself records as a kill
    # while the rest of the suite never executes (AGENTS.md pre-flight item 4, crash-after-partial-
    # run), which is how a second, real defect hides behind the first.
    chk("seam: the self-test runs BEFORE the alarm — a detector is never trusted to watch "
        "anything before it has proved itself on this tick's code",
        self_test_cmd in runs and live_cmd in runs
        and runs.index(self_test_cmd) < runs.index(live_cmd), True)

    self_test_steps = [s for s in steps if str(s.get("run", "")).strip() == self_test_cmd]
    chk("seam: exactly one self-test step", len(self_test_steps), 1)
    chk("seam: the self-test step carries NO `continue-on-error` — it is the only thing between "
        "a broken detector and a live tick",
        [s for s in self_test_steps if "continue-on-error" in s], [])
    chk("seam: the self-test step carries NO `if:`",
        [s for s in self_test_steps if "if" in s], [])

    # ANTI-VACUITY for the two checks above: the ALERT step legitimately DOES carry
    # continue-on-error (a watchdog fault must never red the grooming sweep). The ASYMMETRY between
    # the two steps is the invariant; a blanket "none anywhere" would pin the wrong thing.
    alert_steps = [s for s in steps if str(s.get("run", "")).strip() == live_cmd]
    chk("seam: exactly one alarm step, and it DOES carry continue-on-error (the asymmetry is "
        "deliberate)",
        len(alert_steps) == 1 and alert_steps[0].get("continue-on-error") is True, True)
    env = (alert_steps[0].get("env") or {}) if alert_steps else {}
    for name in ("GH_TOKEN", "REGISTRY_REPO", "RUN_URL", "MAINTAINER_HANDLE",
                 "ALERT_REPO", "ALERT_TOKEN"):
        chk(f"seam: the alarm step passes {name} (main() reads it; a dropped var is an alert that "
            f"never lands, or a KeyError)", name in env, True)

    for step in steps:
        uses = step.get("uses")
        if uses:
            chk(f"seam: {uses} is SHA-pinned", bool(re.search(r"@[0-9a-f]{40}$", uses)), True)
        if str(uses or "").startswith("actions/checkout@"):
            with_ = step.get("with") or {}
            chk("seam: the checkout does not persist credentials",
                with_.get("persist-credentials"), False)
            # EXACT LINE match, never containment: `scripts/ratelimit-alert.py` contains
            # `scripts/ratelimit-alert.p`, and `.github/workflows` is a substring of every workflow
            # path under it. A containment check passes over a dropped entry.
            sparse = [ln.strip() for ln in str(with_.get("sparse-checkout", "")).splitlines()
                      if ln.strip()]
            for required in REQUIRED_FILES:
                chk(f"seam: sparse-checkout names {required} on its own line", required in sparse,
                    True)

    # Enrolled in the suite the gate actually runs, so it cannot silently leave CI.
    chk("seam: enrolled in scripts/selftest-suite.txt",
        Path(__file__).name in (REPO_ROOT / SUITE_FILE).read_text(encoding="utf-8").split(), True)

    # ---- THE MISSING-INPUTS GUARD, EXERCISED ---------------------------------------------------
    # Inverting it (`if missing: pass`) makes every assertion above SILENTLY UNREACHABLE under a
    # thinned checkout while this suite still reads green — the #1140 shape, and the reason the
    # guard exists at all. Coverage put both of its lines at zero, which is exactly the state in
    # which that mutant survives. Drive it against a tree carrying none of the inputs.
    import contextlib
    import io
    import tempfile

    probe, real_root = [], globals()["REPO_ROOT"]
    with tempfile.TemporaryDirectory() as empty:
        try:
            globals()["REPO_ROOT"] = Path(empty)
            with contextlib.redirect_stdout(io.StringIO()):
                _test_workflow_seam(_checker(probe))
        finally:
            globals()["REPO_ROOT"] = real_root
    chk("seam: a checkout missing the watchdog's inputs REDS this suite rather than skipping "
        "every seam assertion in it", len(probe), 1)
    chk("seam: ...and the failure NAMES the missing inputs",
        bool(probe) and probe[0].startswith("seam: REQUIRED_FILES present (missing: ["), True)


def _checker(failures):
    """The ONE assertion recorder. A factory, not a closure inside `_self_test`, so `_test_harness`
    can drive the REAL implementation rather than a copy of it — two copies of one guard make each
    copy individually unkillable (AGENTS.md pre-flight item 4)."""
    def chk(name, got, want=True):
        ok = got == want
        print(f"  {'ok  ' if ok else 'FAIL'} {name}: {got!r}" + ("" if ok else f" (want {want!r})"))
        if not ok:
            failures.append(name)
    return chk


def _report(failures):
    """Render the verdict and return the process exit code."""
    if failures:
        for name in failures:
            print(f"FAIL: {name}")
        print(f"::error::ratelimit-alert self-test: {len(failures)} failure(s)")
        return 1
    print("ratelimit-alert self-test: all checks passed")
    return 0


def _test_harness(chk):
    """ANTI-VACUITY FOR THE SUITE ITSELF. Every row in this file is worth exactly what `chk` and
    `_report` are worth: a recorder that cannot record, or a verdict that cannot return 1, makes
    all of them pass unconditionally. Coverage put the `failures.append` line and the whole
    failure-report branch at ZERO, which is precisely the state in which that mutant survives.

    Driven under a redirected stdout so the deliberate mismatch does NOT put a `FAIL` line into a
    green gate log — AGENTS.md pre-flight item 7 measured 44 passing rows containing `FAIL` as a
    substring on one real gate log, and this suite must not add to that.
    """
    import contextlib
    import io

    probe, sink = [], io.StringIO()
    with contextlib.redirect_stdout(sink):
        _checker(probe)("deliberate mismatch", 1, 2)
    chk("harness: chk RECORDS a mismatch — without this, every assertion in this file is vacuous",
        probe, ["deliberate mismatch"])
    chk("harness: ...and RENDERS it, line-anchored, so a kill is extractable without substring "
        "grepping", sink.getvalue().startswith("  FAIL deliberate mismatch"), True)
    with contextlib.redirect_stdout(io.StringIO()):
        _checker(probe)("a matching row", 1, 1)
    chk("harness: ...and records NOTHING on a match", len(probe), 1)
    with contextlib.redirect_stdout(io.StringIO()):
        red, green = _report(["x"]), _report([])
    chk("harness: a suite with failures exits 1", red, 1)
    chk("harness: ...and a clean one exits 0", green, 0)


def _self_test():
    failures = []
    chk = _checker(failures)

    _test_harness(chk)
    _test_threshold(chk)
    _test_census(chk)
    _test_summary(chk)
    _test_decide(chk)
    _test_body(chk)
    _test_gh_plumbing(chk)
    _test_end_to_end(chk)
    _test_workflow_seam(chk)

    return _report(failures)


if __name__ == "__main__":
    sys.exit(main())
