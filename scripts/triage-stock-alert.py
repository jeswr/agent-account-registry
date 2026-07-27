#!/usr/bin/env python3
# [OPUS-5] ALERT ON THE STOCK, NOT THE RUN.
#
# `retriage.yml` reported `success` on every one of its ~48 scheduled runs a day while the
# population it exists to drain grew for two weeks. Nothing was broken about any individual run:
# each one genuinely swept its window and genuinely decided, per issue, to do nothing. A per-run
# success signal STRUCTURALLY CANNOT express a missing state exit, because the missing exit is a
# property of the POPULATION over time, not of any run.
#
# MEASURED, 2026-07-27T17:14Z, run 30288369320: the sweep visited its full 80-issue window and
# emitted 80 skips and ZERO writes — 65 `classifier-incomplete`, 9 `gated:needs:design`, 6
# `not-retriageable`. Board census the same minute: 274 of 339 open issues `status:untriaged`,
# oldest created 2026-07-13, 158 authored by the orchestrator App and 116 by the maintainer.
#
# WHY `classifier-incomplete` IS A FIXED POINT, not a slow lane. `triage.triage()` is the ONLY
# completeness classifier in the estate and the ONLY writer `retriage.py --apply` has. Enumerated
# exhaustively over 11,625 (label-set x issue-type) combinations, the complete set of labels it
# can EVER add is {needs:area, role:ci, role:docs, role:impl, status:ready, status:untriaged} —
# it can never mint a `priority:*` or an `area:*` label. And it declares `ready` only when a valid
# `priority:P0..P4` AND some `area:*` are already present. 263 of the 274 stuck issues were
# missing `priority:*`. So for them, no number of retriage ticks can ever change the verdict: the
# classifier cannot produce its own missing input. That is what this alert measures, and it is why
# the count it reports separates "the machine owes this issue an exit" from "the classifier
# provably cannot give it one".
#
# SCOPE + AUTHORITY. This script may create/edit/comment/close ONE `ops-alert` issue and nothing
# else. It writes no `needs:`/`status:`/`role:`/`priority:`/`area:` label to any work issue —
# asserted by _test_no_work_labels below rather than by convention — and it has no arming, merge
# or PR path. `needs:user` in particular is HUMAN-owned (park_policy.py invariant 3) and appears
# here only as a READ that EXCLUDES an issue from the machine-owed count.
#
# CEILING. Exactly ONE issue, ever, deduped by hidden HTML marker and re-used across ticks. A tick
# with a healthy board does one bare `gh issue list` and exits. It never touches the work issues,
# so it cannot stampede the installation's hourly budget the way a 274-issue sweep would.
#
# HOSTED AS ITS OWN JOB (retriage.yml, `if: always()`), not as a step of the sweep. The sweep is
# exactly the thing whose silence this is watching: an `always()` step inside a job that failed
# early — or a job cancelled by its own `timeout-minutes` — does not run (plan-alert.py, issue
# #778). A watcher hosted inside the watched job cannot observe the watched job's absence.
#
# Mirrors scripts/groom-alert.py / scripts/plan-alert.py hardening exactly: `_alert_route` privacy
# routing, close-ONLY-on-an-explicitly-healthy-census, sanitized fail-loud `gh` wrapper, and a
# soft-fail on a successful-but-malformed `gh issue list`.
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import triage as static_triage          # noqa: E402  (path insert must precede the import)

ALERT_LABEL = "ops-alert"
ALERT_TITLE = "⚠️ The status:untriaged queue has no working exit — the frontier is starving at its input"
# Dedupe keyed on the TITLE alone breaks the moment anyone (a human, or a later wording tweak)
# renames the open alert — the next tick files a duplicate and recovery cannot find the issue to
# close. The body carries this stable machine marker; dedupe matches the marker first and falls
# back to the exact title only for pre-marker legacy alerts.
ALERT_MARKER = "<!-- triage-stock-alert:v1 key=untriaged-stock -->"

UNTRIAGED = "status:untriaged"
# A `needs:*` gate or `trust:untrusted` means a HUMAN owes this issue its next move, so it is not
# evidence of a broken machine exit. `kind:epic` is deliberately never dispatchable. The remaining
# `status:*` labels mean some other lane already owns the row.
GATE_PREFIXES = ("needs:", "trust:untrusted")
NON_DISPATCHABLE = "kind:epic"
OTHER_OWNED_STATUS = {"status:deferred", "status:parked", "status:in-progress",
                      "status:in-progress-review", "status:blocked", "status:available",
                      "status:capped", "status:ready"}

# THRESHOLDS. Two, because a queue can be broken in two independent ways and each hides the other:
#   * STOCK — a large machine-owed population is a broken exit even if every member is young
#     (a burst that nothing drains).
#   * AGE   — a SMALL population is a broken exit if its oldest member has sat for days
#     (a slow leak, which never trips a stock bar and is exactly how this one survived two weeks).
# Set from the healthy shape of this board, not from the broken one: the curator stocks the
# frontier to target_ready=12 and the sweep visits 80 issues per run twice an hour, so a working
# exit never leaves dozens of machine-owed rows standing, and never leaves one standing for days.
STOCK_THRESHOLD = 25
MAX_AGE_DAYS = 3.0


def _labels(issue):
    raw = issue.get("labels") or []
    names = set()
    for label in raw:
        name = label.get("name") if isinstance(label, dict) else label
        if isinstance(name, str) and name:
            names.add(name)
    return names


def _age_days(created_at, now):
    """Age in days, or None when the timestamp is unusable.

    FAILS TOWARD ALERTING, deliberately: an unparseable timestamp yields None, which the census
    treats as "no age evidence" for THAT row while still counting it in the stock. The opposite
    default (treat it as age 0) would let a malformed payload silence the age half."""
    if not isinstance(created_at, str) or not created_at:
        return None
    try:
        stamp = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return (now - stamp).total_seconds() / 86400.0


def census(issues, now, classify=static_triage.triage, known_labels=None):
    """The POPULATION measurement, per state, with timestamps. Pure.

    Returns a dict with `machine_owed` (the count this alert keys on), `unclassifiable` (the
    subset the classifier provably can never complete — see the module header), `oldest_*`, and
    the raw `untriaged` total. `machine_owed` deliberately EXCLUDES every row a human or another
    lane owns, so the number that goes loud is only ever the machine's own debt.
    """
    untriaged = machine_owed = unclassifiable = 0
    oldest_age = None
    oldest_number = None
    for issue in issues:
        if not isinstance(issue, dict) or "pull_request" in issue:
            continue
        labels = _labels(issue)
        if UNTRIAGED not in labels:
            continue
        untriaged += 1
        if any(label == gate or label.startswith(gate)
               for label in labels for gate in GATE_PREFIXES):
            continue                                   # a human owes this one its next move
        if NON_DISPATCHABLE in labels or (labels & OTHER_OWNED_STATUS):
            continue                                   # another lane owns the row
        machine_owed += 1
        try:
            result = classify(labels, "task", trusted=True, known_labels=known_labels)
            complete = bool(result.get("ready"))
        except Exception:
            complete = False                           # a classifier that raises cannot complete it
        if not complete:
            unclassifiable += 1
        age = _age_days(issue.get("created_at"), now)
        if age is not None and (oldest_age is None or age > oldest_age):
            oldest_age, oldest_number = age, issue.get("number")
    return {
        "untriaged": untriaged,
        "machine_owed": machine_owed,
        "unclassifiable": unclassifiable,
        "oldest_age_days": oldest_age,
        "oldest_number": oldest_number,
    }


def breached(counts, stock_threshold=STOCK_THRESHOLD, max_age_days=MAX_AGE_DAYS):
    """The reasons this census is unhealthy, as a sorted list ([] == healthy).

    Two INDEPENDENT conditions, OR-ed. Either one alone is a broken exit, so neither may mask the
    other: a stock bar alone misses a slow leak, and an age bar alone misses an undrained burst.
    """
    reasons = []
    if counts["machine_owed"] > stock_threshold:
        reasons.append(
            f"stock: {counts['machine_owed']} machine-owed {UNTRIAGED} issue(s) > {stock_threshold}")
    age = counts["oldest_age_days"]
    if age is not None and age > max_age_days:
        reasons.append(
            f"age: #{counts['oldest_number']} has been {UNTRIAGED} for {age:.1f} days "
            f"> {max_age_days}")
    return sorted(reasons)


def decide(reasons, has_open_alert):
    """Pure decision: 'upsert' | 'close' | 'noop'.

    Close ONLY on an explicitly healthy census — an empty `reasons` computed from a board we
    actually read. `main()` never calls this on a failed/unparseable read, for the plan-alert.py
    reason: "close only on an explicit success" — the ABSENCE of evidence of a breach is not
    evidence of recovery, and closing on it is how an alert silently disarms itself.
    """
    if reasons:
        return "upsert"
    if has_open_alert:
        return "close"
    return "noop"


def render_body(counts, reasons, run_url, maintainer):
    lines = [
        ALERT_MARKER,
        "> 🤖 SPARQ agent — automated ops-alert (registry: untriaged-stock watchdog)",
        "",
        f"@{maintainer} the `{UNTRIAGED}` queue is not draining. Every `retriage` run is still "
        "reporting `success`: each run genuinely sweeps its window and genuinely decides, per "
        "issue, to do nothing. A per-run signal cannot express a missing state exit — this alert "
        "keys on the POPULATION instead.",
        "",
        "**Census**",
        "",
        f"- `{UNTRIAGED}` open issues: **{counts['untriaged']}**",
        f"- of those, MACHINE-owed (no `needs:*` / `trust:untrusted` gate, no other owning "
        f"`status:*`, not `kind:epic`): **{counts['machine_owed']}**",
        f"- of those, the classifier provably cannot complete: **{counts['unclassifiable']}** "
        "— `triage.triage()` can never mint a `priority:*` or an `area:*` label, and requires "
        "both to declare an issue ready, so for these rows `classifier-incomplete` is a FIXED "
        "POINT, not a slow lane",
    ]
    if counts["oldest_age_days"] is not None:
        lines.append(
            f"- oldest member: #{counts['oldest_number']}, {counts['oldest_age_days']:.1f} days")
    lines += ["", "**Breached**", ""]
    lines += [f"- {reason}" for reason in reasons]
    lines += [
        "",
        "The lane that mints `priority:*` / `area:*` / `status:ready` is "
        "`scripts/curate-frontier.py`. If this alert is open, check that its candidate filter "
        "still admits `status:untriaged` (`is_staged`) and that its depth budget is computed from "
        "readiness the dispatcher can actually enumerate — either one pinned at zero re-creates "
        "this exact deadlock.",
        "",
        "This alert auto-closes on the first tick whose census is healthy.",
    ]
    if run_url:
        lines += ["", f"- Run: {run_url}"]
    return "\n".join(lines) + "\n"


def _gh(args, capture=False, token=None, check=False):
    # Sanitized fail-loud wrapper: op + returncode only — never stderr (GH_DEBUG=api can echo
    # request bodies) and never argument content beyond the gh subcommand words.
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    result = subprocess.run(["gh"] + args, capture_output=capture, text=True, env=env)
    if check and result.returncode != 0:
        print(f"::warning::triage-stock-alert: gh {args[0]} "
              f"{args[1] if len(args) > 1 else ''} failed (rc={result.returncode})")
    return result


def _alert_route(alert_repo, alert_token, registry_repo):
    """(repo, token) for the alert issue — identical semantics to groom-alert/usage-alert: the
    private ALERT_REPO only when ALERT_TOKEN is present; otherwise the registry repo under the
    ambient token (token=None means "use the ambient GH_TOKEN")."""
    if alert_repo and alert_token:
        return alert_repo, alert_token
    return registry_repo, None


def read_board(repo, max_pages=20):
    """Every open issue, paged EXPLICITLY with a request ceiling.

    `gh api --paginate` concatenates one JSON document per page with NO separator, so a single
    `json.loads` of the combined stream raises and a bare `except` renders that as "zero issues"
    — which for THIS script means "healthy", the most dangerous possible misread. Page explicitly
    and prove completeness the only way the API offers: read until a page comes back short. A
    board that does not fit inside the ceiling raises, so a board we could not read completely is
    never mistaken for a drained one.
    """
    issues = []
    for page in range(1, max_pages + 1):
        result = _gh(["api", f"repos/{repo}/issues?state=open&per_page=100&page={page}"],
                     capture=True, check=True)
        if result.returncode != 0:
            raise RuntimeError(f"could not read page {page} of the {repo} board")
        payload = json.loads(result.stdout or "[]")
        if not isinstance(payload, list):
            raise RuntimeError(f"page {page} of the {repo} board is not a JSON array")
        issues.extend(payload)
        if len(payload) < 100:
            return issues
    raise RuntimeError(
        f"the {repo} board is larger than {max_pages} pages — refusing to report on a board this "
        "run could not read completely (fail closed)")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--self-test" in argv:
        return _self_test()

    registry_repo = os.environ["REGISTRY_REPO"]
    repo, token = _alert_route(
        os.environ.get("ALERT_REPO"), os.environ.get("ALERT_TOKEN"), registry_repo)
    run_url = os.environ.get("RUN_URL", "")
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")

    try:
        board = read_board(registry_repo)
    except (RuntimeError, ValueError) as exc:
        # Never `decide()` on a board we could not read: an unread board has no census, and the
        # 'close' branch would read it as recovery.
        print(f"::warning::triage-stock-alert: {exc} — skipping this tick")
        return 1
    counts = census(board, datetime.now(timezone.utc))
    reasons = breached(counts)
    print(f"triage-stock-alert: {json.dumps(counts, default=str)}")

    # --limit 100: `ops-alert` is SHARED with the plan/groom/metrics/usage alerts, so a 20-issue
    # window could push this one out of the dedupe scan (duplicate on breach, uncloseable on
    # recovery).
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
        print("::warning::triage-stock-alert: gh issue list succeeded but returned unparseable "
              "JSON — skipping this tick (no dedupe/recovery data; next tick retries)")
        return 0
    num = next((i["number"] for i in found if ALERT_MARKER in (i.get("body") or "")), None)
    if num is None:
        num = next((i["number"] for i in found if i.get("title") == ALERT_TITLE), None)

    action = decide(reasons, num is not None)
    if action == "upsert":
        _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", "d73a4a",
             "--description", "Autonomous ops alert (maintainer action)"],
            capture=True, token=token)  # idempotent; a pre-existing label is fine
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
        print(f"::warning::triage-stock-alert: {'; '.join(reasons)} — maintainer alerted")
        return 0
    if action == "close":
        commented = _gh(["issue", "comment", str(num), "-R", repo, "--body",
                         "✅ Recovered — the `status:untriaged` census is healthy again "
                         f"({counts['machine_owed']} machine-owed). Auto-closing."],
                        capture=True, token=token, check=True)
        closed = _gh(["issue", "close", str(num), "-R", repo], capture=True, token=token,
                     check=True)
        if commented.returncode != 0 or closed.returncode != 0:
            return 1
        print("triage-stock-alert: census healthy — closed the alert")
        return 0
    print("triage-stock-alert: census healthy, no open alert — nothing to do")
    return 0


# ------------------------------------------------------------------------------------------------


def _self_test():
    failures = []

    def chk(name, got, want):
        if got == want:
            print(f"  ok   {name}")
        else:
            print(f"  FAIL {name}: {got!r} != {want!r}")
            failures.append(name)

    now = datetime(2026, 7, 27, 18, 0, tzinfo=timezone.utc)

    def iss(number, labels, created="2026-07-27T17:00:00Z", pr=False):
        row = {"number": number, "labels": [{"name": n} for n in labels], "created_at": created}
        if pr:
            row["pull_request"] = {}
        return row

    # ---- census -------------------------------------------------------------------------------
    stuck = [iss(n, ["status:untriaged", "role:impl"], "2026-07-13T00:00:00Z")
             for n in range(1, 31)]
    counts = census(stuck, now)
    chk("census counts the machine-owed stock", counts["machine_owed"], 30)
    chk("census flags every incompletable row", counts["unclassifiable"], 30)
    chk("census reports the oldest member", counts["oldest_number"], 1)
    chk("census ages the oldest member", round(counts["oldest_age_days"]), 15)

    gated = census([iss(1, ["status:untriaged", "role:impl", "needs:user"])], now)
    chk("a needs:user row is NOT machine-owed (human-owned; never counted, never written)",
        gated["machine_owed"], 0)
    chk("but it IS still in the raw untriaged total", gated["untriaged"], 1)
    chk("a needs:design row is not machine-owed",
        census([iss(1, ["status:untriaged", "needs:design"])], now)["machine_owed"], 0)
    chk("an untrusted-quarantined row is not machine-owed",
        census([iss(1, ["status:untriaged", "trust:untrusted"])], now)["machine_owed"], 0)
    chk("an epic is not machine-owed",
        census([iss(1, ["status:untriaged", "kind:epic"])], now)["machine_owed"], 0)
    chk("a deferred row is owned by the dispatcher, not this alert",
        census([iss(1, ["status:untriaged", "status:deferred"])], now)["machine_owed"], 0)
    chk("a status:available account record is not machine-owed",
        census([iss(1, ["status:untriaged", "status:available"])], now)["machine_owed"], 0)
    chk("a PR row is never censused", census([iss(1, ["status:untriaged"], pr=True)], now),
        {"untriaged": 0, "machine_owed": 0, "unclassifiable": 0,
         "oldest_age_days": None, "oldest_number": None})
    chk("a triage-COMPLETE untriaged row is machine-owed but NOT unclassifiable",
        census([iss(1, ["status:untriaged", "role:impl", "priority:P2", "area:ci"])],
               now)["unclassifiable"], 0)
    chk("a classifier that RAISES counts the row as incompletable (fail-closed)",
        census([iss(1, ["status:untriaged"])], now,
               classify=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
               )["unclassifiable"], 1)
    chk("an unparseable created_at yields no age evidence but still counts in the stock",
        census([iss(1, ["status:untriaged"], created="not-a-date")], now)["machine_owed"], 1)
    chk("...and leaves oldest_age_days None rather than 0",
        census([iss(1, ["status:untriaged"], created="not-a-date")], now)["oldest_age_days"], None)

    # ---- breached: BOTH conditions, independently ---------------------------------------------
    big_and_young = {"machine_owed": 26, "unclassifiable": 26, "untriaged": 26,
                     "oldest_age_days": 0.5, "oldest_number": 9}
    chk("STOCK alone breaches (a big, young, undrained burst)",
        [r.split(":")[0] for r in breached(big_and_young)], ["stock"])
    small_and_old = {"machine_owed": 1, "unclassifiable": 1, "untriaged": 1,
                     "oldest_age_days": 14.0, "oldest_number": 9}
    chk("AGE alone breaches (the slow leak a stock bar can never see)",
        [r.split(":")[0] for r in breached(small_and_old)], ["age"])
    healthy = {"machine_owed": 3, "unclassifiable": 0, "untriaged": 3,
               "oldest_age_days": 0.2, "oldest_number": 9}
    chk("a healthy census breaches nothing", breached(healthy), [])
    chk("stock is a STRICT threshold (== the bar is healthy)",
        breached({**healthy, "machine_owed": STOCK_THRESHOLD}), [])
    chk("one over the bar breaches",
        len(breached({**healthy, "machine_owed": STOCK_THRESHOLD + 1})), 1)
    chk("a missing age never breaches on its own",
        breached({**healthy, "oldest_age_days": None}), [])

    # THE LIVE SHAPE. The board that produced this script must trip it — a threshold pair that
    # calls the measured outage healthy would be a vacuous alert.
    live = census([iss(n, ["status:untriaged", "role:impl"], "2026-07-13T23:49:56Z")
                   for n in range(1, 275)], now)
    chk("the MEASURED 2026-07-27 board trips both conditions", len(breached(live)), 2)

    # ---- decide -------------------------------------------------------------------------------
    chk("breach with no open alert -> upsert", decide(["stock: x"], False), "upsert")
    chk("breach with an open alert -> upsert (refresh the census)", decide(["stock: x"], True),
        "upsert")
    chk("healthy with an open alert -> close", decide([], True), "close")
    chk("healthy with no open alert -> noop", decide([], False), "noop")

    # ---- routing ------------------------------------------------------------------------------
    chk("private route when repo AND token are present",
        _alert_route("o/p", "t", "o/r"), ("o/p", "t"))
    chk("half-configured private route falls back to the registry",
        _alert_route("o/p", "", "o/r"), ("o/r", None))
    chk("no private repo -> registry", _alert_route("", "t", "o/r"), ("o/r", None))

    # ---- read_board: the pagination trap ------------------------------------------------------
    pages = {}

    def fake_gh(args, capture=False, token=None, check=False):
        class R:
            returncode = 0
            stdout = ""
        page = int(args[1].rsplit("page=", 1)[1])
        R.stdout = json.dumps(pages.get(page, []))
        return R

    global _gh
    real_gh = _gh
    try:
        _gh = fake_gh
        pages = {1: [{"number": i} for i in range(100)], 2: [{"number": 100}]}
        chk("read_board pages until a short page", len(read_board("o/r")), 101)
        pages = {i: [{"number": i}] * 100 for i in range(1, 22)}
        try:
            read_board("o/r", max_pages=3)
            chk("a board over the page ceiling raises", "no raise", "RuntimeError")
        except RuntimeError:
            chk("a board over the page ceiling raises", "RuntimeError", "RuntimeError")
    finally:
        _gh = real_gh

    # ---- body ---------------------------------------------------------------------------------
    body = render_body(live, breached(live), "https://run", "jeswr")
    chk("the body carries the dedupe marker", ALERT_MARKER in body, True)
    chk("the body carries the SPARQ agent self-id", "🤖 SPARQ agent" in body, True)
    chk("the body names the fixed-point count", str(live["unclassifiable"]) in body, True)

    # ---- AUTHORITY: this script writes no work-issue label ------------------------------------
    # Scan the OPERATIONAL half only — everything above `def _self_test(` — so the assertion is
    # not satisfied (or defeated) by its own predicate text.
    source = Path(__file__).read_text(encoding="utf-8").split("def _self_test(", 1)[0]
    marker = "--" + "add-label"          # split so this line is not its own counter-example
    writes = [line.strip() for line in source.splitlines()
              if marker in line or ("--" + "remove-label") in line]
    chk("no code path adds or removes a label on a work issue", writes, [])
    creates = [line.strip() for line in source.splitlines() if '"label", "create"' in line]
    chk("exactly one label-create call site", len(creates), 1)
    chk("and it creates ALERT_LABEL, never a literal", "ALERT_LABEL" in creates[0], True)

    # ---- THE YAML SEAM ------------------------------------------------------------------------
    # Every guard above is Python, and Python mutants die easily. MEASURED across this estate: the
    # mutants that SURVIVE live in a workflow `if:`, a step, or a call site — the wiring that
    # decides whether the Python runs at all. `retriage.py --self-test` asserts its own step body
    # against `retriage.yml` for exactly this reason; this does the same for the watchdog job, so
    # deleting the job, the `always()` guard, the `needs:` edge or the invocation is a RED gate
    # and not a silently-disarmed alert.
    workflow = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "retriage.yml"
    if not workflow.exists():
        chk("retriage.yml is present to assert against", str(workflow), "a readable file")
    else:
        import yaml  # noqa: PLC0415 — self-test only; the runner image ships PyYAML
        spec = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        jobs = spec.get("jobs", {})
        job = jobs.get("stock-alert", {})
        chk("retriage.yml hosts a `stock-alert` job", "stock-alert" in jobs, True)
        # `True` because YAML parses a bare `on:`/`always()`-style scalar as a string; compare the
        # rendered text, not a truthiness.
        chk("...guarded by if: always(), so a FAILED or CANCELLED sweep still gets censused",
            str(job.get("if", "")).strip(), "always()")
        chk("...and sequenced AFTER the sweep it watches",
            job.get("needs"), "retriage")
        steps = job.get("steps", []) or []
        runs = [str(step.get("run", "")) for step in steps]
        chk("...whose steps actually INVOKE this script (not just its self-test)",
            any(r.strip() == "python3 scripts/triage-stock-alert.py" for r in runs), True)
        chk("...and verify it first",
            any("--self-test" in r for r in runs), True)
        chk("the watchdog is a SEPARATE job from the sweep (a step inside it cannot see its "
            "own job being cancelled)", "stock-alert" != "retriage" and "retriage" in jobs, True)

    print(("triage-stock-alert self-test: FAILED " + ", ".join(failures)) if failures
          else "triage-stock-alert self-test: all checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
