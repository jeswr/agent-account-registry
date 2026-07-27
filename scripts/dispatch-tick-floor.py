#!/usr/bin/env python3
# [OPUS-5] MINIMUM INTERVAL BETWEEN EXECUTED DISPATCH TICKS (issue #819).
#
# WHAT BROKE. PR #787 cut the PLAN snapshot step from 10m02s to ~1m30s and the whole tick from
# 15-28 min to ~7 min. That is a real 6.4x and it is NOT being reverted. What it removed by
# accident was a RATE LIMITER: `concurrency: group registry-dispatcher` serialises ticks, so tick
# DURATION was the only thing bounding how often the doorbell could start one. Executed ticks per
# hour (success+failure, coalesced-cancellations excluded) on 2026-07-27, from the runs API:
#
#     04Z 2 | 05Z 6 | 06Z 6 | 07Z 4 | 08Z 5 | 09Z 6 | 10Z 7 | 11Z 5 | 12Z 6 | 13Z 6
#     14Z 4 | 15Z 4 | 16Z 6 | 17Z 4 | 18Z 13   <- #787 merged 17:38:42Z
#
# At 18:26:17Z every authenticated read started returning HTTP 403 and has ever since: the request
# budget for the token this pipeline reads with was exhausted. PLAN dies on the first listing and
# `secrets-guard` dies resolving the default branch, so CLAIM and ALERT are both skipped and the
# pipeline does zero work while it holds.
#
# THE BUDGET ARITHMETIC, and why the constant below is what it is.
#
#   requests per executed tick  = 613
#       measured 2026-07-27 by the instrumented run recorded in scripts/plan-snapshot.py's module
#       docstring (issue #721): 613 requests, 28,334 rows, median request 0.843 s.
#   observed SAFE band          = 4-7 executed ticks/h, i.e. ~2,450-4,291 requests/h,
#       sustained for the thirteen hours 04Z-17Z above with zero rate-limit failures.
#   observed BREAKING rate      = 13 executed ticks/h, i.e. ~7,969 requests/h -> 403 at 18:26:17Z.
#
# So the true ceiling lies somewhere in (4.3k, 8.0k] requests/hour. GitHub does not publish the
# effective ceiling for this token in this configuration, and `GET /rate_limit` reports a DIFFERENT
# bucket that reads healthy while every request 403s (issue #796) — so the floor is derived from
# the OBSERVED band, never from a recalled documented constant.
#
#   floor F minutes  =>  at most 60/F executed ticks/h  =>  at most (60/F) * 613 requests/h
#   F = 10  ->  6 ticks/h  ->  ~3,678 requests/h
#
# which is (a) inside the 4-7 tick/h band that ran clean all day, (b) 46% of the rate that broke
# it, and (c) exactly the rate the cron alone already schedules (`3,13,23,33,43,53`). That last
# equality is the invariant worth stating: THE FLOOR MAKES THE DOORBELL STRUCTURALLY UNABLE TO
# EXCEED THE SCHEDULE. _test_budget_arithmetic below asserts the multiplication, so the constant
# cannot drift away from the reasoning that produced it.
#
# #787's win survives: a tick still completes in ~1.5 min of step time instead of ~10, and the
# doorbell still starts a tick the moment the floor expires instead of waiting for the next cron
# edge. What it no longer buys is a THIRTEENTH tick in an hour.
#
# HOW A WITHIN-FLOOR TICK EXITS. `proceed=false` on this job's output, exit 0. `plan` is gated on
# it, `claim` needs `plan`, so both skip and the run ends green in ~30 s having issued ONE API
# request (the anchor read below). It deliberately does NOT sleep until the floor expires: a
# sleeping job occupies a runner AND holds the `registry-dispatcher` concurrency group for the
# whole wait, which is the waiter-starvation shape ci-summary.yml documents. A no-op tick releases
# the group in seconds, so the doorbell ring behind it is served immediately (and, if it is also
# inside the floor, no-ops just as cheaply).
#
# THE ANCHOR. `last executed tick` is read from the `dispatch-tick` artifacts this same job uploads
# at the moment it decides to proceed — BEFORE the snapshot runs, so a tick that later FAILS still
# counts as executed and still holds the floor. Deriving it from run conclusions instead cannot
# work: a no-op tick concludes `success` exactly like a real one.
#
# FAIL-OPEN, deliberately, and this is the one polarity in this file that is not fail-closed. If
# the anchor cannot be read — artifacts expired, listing refused, malformed page — this proceeds
# and says so loudly. A rate limiter that can permanently stop the pipeline is a worse failure than
# the burst it prevents (a human-only unpark turns a transient outage into a permanent stall), and
# the blast radius of the fail-open is exactly ONE tick: that tick writes a fresh anchor. Note the
# honest residual — during a total budget outage this read 403s too, so the floor stops bounding
# and every tick costs the ~3 requests it takes to die. That is deliberate: it is what lets the
# pipeline notice its own recovery without a human.
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------------------------
# THE FLOOR. Derived in the header block above; NOT a tuning knob and deliberately NOT
# env-overridable (a threshold readable from the workflow is a second place to get it wrong).
MIN_TICK_INTERVAL_SECONDS = 10 * 60

# The instrumented per-tick request count the arithmetic above is built on (issue #721).
MEASURED_REQUESTS_PER_TICK = 613
# The highest hourly request rate observed to run clean, and the rate that broke. Both are
# measured, both are asserted against the floor by _test_budget_arithmetic.
OBSERVED_SAFE_REQUESTS_PER_HOUR = 7 * MEASURED_REQUESTS_PER_TICK      # 10Z: 7 executed ticks
OBSERVED_BREAKING_REQUESTS_PER_HOUR = 13 * MEASURED_REQUESTS_PER_TICK  # 18Z: 13 executed ticks

# The artifact whose creation time IS the "this tick executed" record. Uploaded by the floor job
# itself, immediately after it decides to proceed and before any target read happens.
TICK_MARKER_ARTIFACT = "dispatch-tick"
# One page is plenty: at the floor's own ceiling of 6/h with 1-day retention there are at most
# ~144 of these, and the newest is always on the first page.
ARTIFACT_PAGE_SIZE = 100

DISPATCH_WORKFLOW = ".github/workflows/dispatch.yml"
FLOOR_JOB = "tick-floor"
GATED_JOB = "plan"
FLOOR_STEP_ID = "floor"

# Every file the self-test asserts against. The floor job sparse-checks-out exactly this set and
# _test_selftest_inputs_are_checked_out asserts that it does — a trimmed checkout would make the
# YAML-seam assertions silently unreachable in the live path, which is the exact fail-open class
# this unit exists to close.
REQUIRED_FILES = (
    "scripts/dispatch-tick-floor.py",
    DISPATCH_WORKFLOW,
)


class TickFloorError(Exception):
    """A contract this script refuses to guess about."""


# ---------------------------------------------------------------------------------------------
# pure decision
# ---------------------------------------------------------------------------------------------
def decide(last_executed_epoch, now, interval=MIN_TICK_INTERVAL_SECONDS):
    """-> ('run'|'hold', age_seconds|None, reason).

    `hold` is returned ONLY for an anchor that was actually parsed and is inside the floor. Every
    other outcome runs (see the FAIL-OPEN note in the header). A future-dated anchor (runner clock
    skew) runs rather than holding out an unbounded number of ticks on a bad clock."""
    if last_executed_epoch is None:
        return "run", None, "no readable executed-tick anchor"
    age = int(now) - int(last_executed_epoch)
    if age < 0:
        return "run", age, "anchor is in the future (clock skew)"
    if age < interval:
        return "hold", age, "inside the minimum interval between executed ticks"
    return "run", age, "ok"


def newest_marker_epoch(payload, marker=TICK_MARKER_ARTIFACT):
    """Newest `created_at` among non-expired artifacts named exactly `marker`. -> epoch|None.

    Name matching is EQUALITY, never a prefix: `dispatch-plan-<run>-<attempt>` also starts with
    `dispatch-` and reading it as a tick marker would anchor the floor on the wrong event. Every
    malformed shape returns None, which decide() reads as `run` — the fail-open polarity."""
    if not isinstance(payload, dict):
        return None
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        return None
    best = None
    for entry in artifacts:
        if not isinstance(entry, dict) or entry.get("name") != marker:
            continue
        if entry.get("expired") is True:
            continue
        epoch = parse_rfc3339(entry.get("created_at"))
        if epoch is not None and (best is None or epoch > best):
            best = epoch
    return best


def parse_rfc3339(raw):
    """GitHub's `2026-07-27T18:26:17Z` -> epoch int, or None for anything else."""
    if not isinstance(raw, str) or not raw:
        return None
    try:
        stamp = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return int(stamp.timestamp())


# ---------------------------------------------------------------------------------------------
# live path
# ---------------------------------------------------------------------------------------------
def _gh_json(args, label="tick-floor"):
    """Run `gh <args>` and parse stdout as JSON. -> parsed|None (never raises).

    Sanitized: only the subcommand words and the return code are ever printed — `GH_DEBUG=api`
    echoes request bodies into stderr, so stderr is never surfaced."""
    result = subprocess.run(["gh"] + args, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print(f"::warning::{label}: gh {args[0]} failed (rc={result.returncode})")
        return None
    try:
        return json.loads(result.stdout or "null")
    except ValueError:
        print(f"::warning::{label}: gh {args[0]} succeeded but returned unparseable JSON")
        return None


def read_anchor(repo, runner=None):
    """Newest executed-tick marker for `repo`, as an epoch. One API request.

    `runner` is resolved at CALL time, not bound as a default: a default argument captures the
    function object at definition, which makes the live path unpatchable and every stubbed-flow
    assertion below quietly exercise the real `gh`."""
    runner = runner or _gh_json
    payload = runner(["api", "-H", "Accept: application/vnd.github+json",
                      f"/repos/{repo}/actions/artifacts"
                      f"?name={TICK_MARKER_ARTIFACT}&per_page={ARTIFACT_PAGE_SIZE}"])
    return newest_marker_epoch(payload)


def _now():
    """Wall clock, isolated so the self-test can pin it."""
    return int(datetime.now(tz=timezone.utc).timestamp())


def _emit(proceed):
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"proceed={'true' if proceed else 'false'}\n")


def main():
    repo = os.environ["REGISTRY_REPO"]
    anchor = read_anchor(repo)
    action, age, reason = decide(anchor, _now())
    minutes = "unknown" if age is None else f"{age // 60}m{age % 60:02d}s"
    if action == "hold":
        print(f"tick-floor: HOLD — last executed tick was {minutes} ago, floor is "
              f"{MIN_TICK_INTERVAL_SECONDS // 60} min ({reason}). This tick is a clean no-op: "
              "PLAN and CLAIM will be skipped and no snapshot request will be issued.")
        _emit(False)
        return 0
    if anchor is None:
        print(f"::warning::tick-floor: {reason} — proceeding (fail-open). The floor is a rate "
              "limiter, not a safety control; refusing here would stall the pipeline until a "
              "human intervened. This tick writes a fresh anchor.")
    else:
        print(f"tick-floor: RUN — last executed tick was {minutes} ago (floor "
              f"{MIN_TICK_INTERVAL_SECONDS // 60} min).")
    _emit(True)
    return 0


# =============================================================================================
# self-test
# =============================================================================================
def _repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _require(path):
    """Read a file the self-test asserts against. FAIL CLOSED: a missing input aborts the
    self-test loudly rather than making its assertions quietly unreachable."""
    full = os.path.join(_repo_root(), path)
    if not os.path.isfile(full):
        raise TickFloorError(
            f"self-test input {path} is missing from the working copy at {_repo_root()} — the "
            "YAML-seam assertions cannot run, and a self-test that silently stops asserting is "
            "worse than no self-test. Add it to the job's sparse-checkout list.")
    with open(full, encoding="utf-8") as handle:
        return handle.read()


def _load_workflow(path):
    import yaml  # hard requirement: regex-over-YAML is how five permissive misparses got in
    return yaml.safe_load(_require(path))


def _job(workflow, name):
    jobs = (workflow or {}).get("jobs") or {}
    if name not in jobs:
        raise TickFloorError(
            f"workflow has no job named `{name}` — refusing to assert against a job that does not "
            "exist (a deleted floor must go RED here, not silently pass)")
    return jobs[name]


def _declared_needs(job):
    declared = job.get("needs")
    if declared is None:
        return []
    return [declared] if isinstance(declared, str) else list(declared)


# The ONE grammar of job-level `if:` this gate uses. Anchored and single-comparison on purpose: a
# gate rewritten into a form this harness cannot reason about must RAISE, not be waved through —
# an unevaluatable gate is an UNCHECKED polarity on a surface no runtime check can reach. Copied
# deliberately from scripts/metrics-alert.py's reviewed `_eval_job_if`.
_JOB_IF_COMPARISON = re.compile(
    r"^needs\.([A-Za-z0-9_-]+)\.(result|outputs\.[A-Za-z0-9_.-]+)\s*(==|!=)\s*'([^']*)'$")


def _eval_job_if(expr, needs):
    """EVALUATE a job-level `if:` against a hypothetical `needs` context. -> bool.

    `expr is None` models GitHub's default for a job with `needs:` and no `if:` — an implicit
    success() over the needed jobs. That is what makes DELETING the gate visible here rather than
    only in production, on the one tick that matters."""
    def _success():
        return all((ctx or {}).get("result") == "success" for ctx in needs.values())

    if expr is None:
        return _success()
    if isinstance(expr, bool):  # `if: false` parses as a YAML boolean, not the string "false"
        return expr
    text = str(expr).strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2].strip()
    if text == "always()":
        return True
    if text in ("true", "false"):
        return text == "true"
    if text == "success()":
        return _success()
    match = _JOB_IF_COMPARISON.match(text)
    if not match:
        raise TickFloorError(
            f"unmodelled job `if:` expression {expr!r} — this harness only evaluates the restricted "
            "grammar the dispatch gates use. Extend _eval_job_if deliberately, or keep the gate in "
            "the modelled grammar; an expression it cannot evaluate is an unchecked polarity.")
    job, field, operator, want = match.groups()
    context = needs.get(job)
    if context is None:
        raise TickFloorError(
            f"job `if:` reads needs.{job}, which is not among the modelled needs {sorted(needs)} — "
            "a gate that names a job it does not depend on always reads the empty string")
    got = (context.get("result", "") if field == "result"
           else (context.get("outputs") or {}).get(field.split(".", 1)[1], ""))
    return (got == want) if operator == "==" else (got != want)


def _plan_runs(workflow, proceed):
    """Does `plan` execute when the floor job succeeds with `proceed`? Models BOTH seams at once —
    the `needs:` edge AND the `if:`. A gate expressed only as an `if:` is defeated by cutting
    `needs:` (the output then reads as the empty string, which happens to hold, but the job also
    stops WAITING for the floor, so it can run before the anchor is written); a gate expressed only
    as a `needs:` edge is defeated by deleting the `if:`."""
    plan = _job(workflow, GATED_JOB)
    if FLOOR_JOB not in _declared_needs(plan):
        return True  # no dependency at all: `plan` starts regardless of the floor
    needs = {name: {"result": "success", "outputs": {}} for name in _declared_needs(plan)}
    needs[FLOOR_JOB] = {"result": "success", "outputs": {"proceed": proceed}}
    return _eval_job_if(plan.get("if"), needs)


def _invocations(step, script):
    """Executable `python3 .../<script>` command lines in a step's `run:` body, COMMENTS STRIPPED.
    A filename grep over a shell body is satisfied by a comment or a backslash-continuation tail —
    two separate ways a wiring assertion has gone vacuous in this estate."""
    body = step.get("run") or ""
    live = "\n".join(line for line in body.replace("\\\n", " ").splitlines()
                     if not line.strip().startswith("#"))
    pattern = re.compile(rf"^\s*python3\s+(?:\S*/)?{re.escape(script)}([^\n]*)$", re.M)
    return [m.group(1).split() for m in pattern.finditer(live)]


def _steps(job):
    return job.get("steps") or []


def _step_by_id(job, step_id):
    found = [s for s in _steps(job) if s.get("id") == step_id]
    if len(found) != 1:
        raise TickFloorError(
            f"expected exactly one step with `id: {step_id}`, found {len(found)} — refusing to "
            "assert against a step that cannot be located")
    return found[0]


def _sparse_paths(job, path="registry"):
    found = [(step.get("with") or {}) for step in _steps(job)
             if str(step.get("uses", "")).startswith("actions/checkout@")
             and (step.get("with") or {}).get("path") == path]
    if len(found) != 1:
        raise TickFloorError(
            f"expected exactly one actions/checkout with `path: {path}`, found {len(found)}")
    spec = found[0].get("sparse-checkout") or ""
    return {line.strip() for line in str(spec).splitlines() if line.strip()}


def _cron_minutes(workflow):
    """The set of minutes-past-the-hour an explicit-minute cron fires at."""
    triggers = workflow.get("on", workflow.get(True)) or {}
    crons = [entry["cron"] for entry in (triggers.get("schedule") or []) if "cron" in entry]
    if len(crons) != 1:
        raise TickFloorError(f"expected exactly one cron schedule, found {len(crons)}")
    minute = crons[0].split()[0]
    if "/" in minute:
        step = int(minute.split("/")[1])
        return set(range(0, 60, step))
    return {int(part) for part in minute.split(",")}


def _self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got} (want {want})")

    _test_budget_arithmetic(chk)
    _test_floor_predicate(chk)
    _test_anchor_parsing(chk)
    _test_a_too_soon_tick_issues_no_snapshot_requests(chk)
    _test_live_path(chk)
    _test_workflow_seam(chk)

    print("dispatch-tick-floor self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def _test_budget_arithmetic(chk):
    """The constant must keep agreeing with the reasoning that produced it. Every number here is
    measured (see the header); this asserts the MULTIPLICATION, so nobody can quietly halve the
    floor and leave the justification standing."""
    ticks_per_hour = 3600 / MIN_TICK_INTERVAL_SECONDS
    ceiling = ticks_per_hour * MEASURED_REQUESTS_PER_TICK
    chk("budget: the floor admits at most 6 executed ticks/hour", ticks_per_hour, 6.0)
    chk("budget: 6 ticks/h x 613 requests = 3678 requests/h", ceiling, 3678.0)
    chk("budget: the ceiling is at or under the highest rate observed to run CLEAN "
        f"({OBSERVED_SAFE_REQUESTS_PER_HOUR}/h)", ceiling <= OBSERVED_SAFE_REQUESTS_PER_HOUR, True)
    chk("budget: the ceiling is at most half the rate that BROKE it "
        f"({OBSERVED_BREAKING_REQUESTS_PER_HOUR}/h)",
        ceiling <= OBSERVED_BREAKING_REQUESTS_PER_HOUR / 2, True)
    # The invariant the header states in words: the doorbell cannot outpace the schedule.
    workflow = _load_workflow(DISPATCH_WORKFLOW)
    scheduled_per_hour = len(_cron_minutes(workflow))
    chk("budget: the floor admits no more ticks/hour than the cron alone already schedules",
        (ticks_per_hour, scheduled_per_hour <= ticks_per_hour), (6.0, True))


def _test_floor_predicate(chk):
    now = 1_800_000_000
    floor = MIN_TICK_INTERVAL_SECONDS
    chk("floor: a tick 3 min after the last executed tick HOLDS",
        decide(now - 3 * 60, now)[0], "hold")
    chk("floor: a tick 11 min after the last executed tick RUNS",
        decide(now - 11 * 60, now)[0], "run")
    chk("floor: EXACTLY at the floor runs; one second inside it holds (the comparison is `<`, and "
        "an off-by-one here is either a stalled pipeline or an unbounded one)",
        (decide(now - floor, now)[0], decide(now - floor + 1, now)[0]), ("run", "hold"))
    chk("floor: no anchor at all RUNS (fail-open — a rate limiter must never be able to stall the "
        "pipeline permanently)", decide(None, now)[0], "run")
    chk("floor: a FUTURE-dated anchor runs rather than holding out ticks on a skewed clock",
        decide(now + 600, now)[0], "run")
    chk("floor: the held tick reports its real age", decide(now - 120, now)[1], 120)


def _test_anchor_parsing(chk):
    page = {"artifacts": [
        {"name": "dispatch-plan-30295860510-1", "created_at": "2026-07-27T18:54:14Z"},
        {"name": "dispatch-tick", "created_at": "2026-07-27T18:20:00Z"},
        {"name": "dispatch-tick", "created_at": "2026-07-27T18:40:00Z"},
        {"name": "dispatch-tick", "created_at": "2026-07-27T18:50:00Z", "expired": True},
    ]}
    chk("anchor: takes the NEWEST non-expired `dispatch-tick`",
        newest_marker_epoch(page), parse_rfc3339("2026-07-27T18:40:00Z"))
    chk("anchor: `dispatch-plan-*` is NOT a tick marker (name matching is equality, not prefix — "
        "anchoring on the plan artifact would silently move the floor to a different event)",
        newest_marker_epoch({"artifacts": [
            {"name": "dispatch-plan-1-1", "created_at": "2026-07-27T18:54:14Z"}]}), None)
    for label, payload in (
            ("payload is not an object", ["nope"]),
            ("payload has no artifacts list", {"total_count": 0}),
            ("artifacts is not a list", {"artifacts": "nope"}),
            ("every entry is malformed", {"artifacts": [None, 7, {"name": "dispatch-tick"}]}),
            ("created_at is not RFC3339",
             {"artifacts": [{"name": "dispatch-tick", "created_at": "yesterday"}]}),
    ):
        chk(f"anchor: {label} -> None (and therefore RUN, fail-open)",
            newest_marker_epoch(payload), None)


def _test_a_too_soon_tick_issues_no_snapshot_requests(chk):
    """THE REGRESSION THIS UNIT EXISTS FOR (#819): a tick arriving faster than the floor must not
    issue the snapshot's API calls.

    The composition is exercised end to end against a counting fake — the floor's decision, the
    anchor it writes when it proceeds, and the snapshot that runs only when it proceeds. Asserting
    `decide()` alone would not pin this: the defect class is a gate that returns the right answer
    into a pipeline that ignores it."""
    clock = {"now": 1_800_000_000}
    store = []          # the `dispatch-tick` artifacts, as the artifacts endpoint would return them
    snapshot_calls = {"n": 0}

    def tick():
        """One dispatch run, wired exactly as dispatch.yml wires it: floor first, PLAN only when it
        says proceed, and the marker written by the floor BEFORE the snapshot (so a tick that dies
        in the snapshot still holds the floor)."""
        action, _age, _reason = decide(newest_marker_epoch({"artifacts": store}), clock["now"])
        if action != "run":
            return "noop"
        store.append({"name": TICK_MARKER_ARTIFACT,
                      "created_at": datetime.fromtimestamp(clock["now"], tz=timezone.utc)
                      .strftime("%Y-%m-%dT%H:%M:%SZ")})
        snapshot_calls["n"] += MEASURED_REQUESTS_PER_TICK   # PLAN's 613 authenticated reads
        return "executed"

    first = tick()
    chk("regression: the first tick executes (no anchor yet)", first, "executed")
    baseline = snapshot_calls["n"]

    clock["now"] += 3 * 60
    chk("regression: a tick 3 min later is a NO-OP", tick(), "noop")
    chk("regression: ... and it issued ZERO snapshot requests",
        snapshot_calls["n"] - baseline, 0)

    # The doorbell shape that actually caused #819: a burst of rings inside the floor.
    for _ in range(9):
        clock["now"] += 30
        tick()
    chk("regression: nine more doorbell rings inside the floor issue ZERO snapshot requests "
        "between them", snapshot_calls["n"] - baseline, 0)

    clock["now"] += 10 * 60
    chk("regression: the first tick PAST the floor executes again", tick(), "executed")

    # And the rate the whole composition actually admits, over a full simulated hour of a doorbell
    # ringing every 30 s — the number the budget arithmetic is about.
    clock, store, snapshot_calls = {"now": 1_800_000_000}, [], {"n": 0}
    executed = 0
    for _ in range(120):
        if tick() == "executed":
            executed += 1
        clock["now"] += 30
    chk("regression: a doorbell ringing every 30 s for an hour executes at most 6 ticks",
        executed <= 6, True)
    chk("regression: ... i.e. at most 3678 snapshot requests in that hour",
        snapshot_calls["n"] <= 3678, True)


def _test_live_path(chk):
    """read_anchor()/main() over a stubbed `gh`: the anchor read is ONE request, and every failure
    mode of it lands on the fail-open side rather than raising."""
    calls = []

    def fake(args, label="tick-floor"):
        calls.append(args)
        return {"artifacts": [{"name": TICK_MARKER_ARTIFACT,
                               "created_at": "2026-07-27T18:40:00Z"}]}

    got = read_anchor("jeswr/agent-account-registry", runner=fake)
    chk("live: the anchor read is exactly ONE API request", len(calls), 1)
    chk("live: ... filtered to the marker name server-side",
        f"name={TICK_MARKER_ARTIFACT}" in calls[0][-1], True)
    chk("live: ... and scoped to the registry repo",
        "/repos/jeswr/agent-account-registry/actions/artifacts" in calls[0][-1], True)
    chk("live: it returns the marker's epoch", got, parse_rfc3339("2026-07-27T18:40:00Z"))
    chk("live: a REFUSED listing (the 403 outage itself) reads as no anchor -> RUN",
        read_anchor("o/r", runner=lambda *a, **k: None), None)

    # The workflow output contract, written the way GitHub reads it.
    import tempfile
    for label, anchor, want in (("hold", 60, "proceed=false\n"), ("run", 4000, "proceed=true\n")):
        with tempfile.NamedTemporaryFile("w+", suffix=".txt", delete=False) as handle:
            out_path = handle.name
        env_backup = {k: os.environ.get(k) for k in ("GITHUB_OUTPUT", "REGISTRY_REPO")}
        try:
            os.environ["GITHUB_OUTPUT"] = out_path
            os.environ["REGISTRY_REPO"] = "o/r"
            stamp = datetime.fromtimestamp(_now() - anchor, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ")
            saved = globals()["_gh_json"]
            globals()["_gh_json"] = lambda *a, **k: {
                "artifacts": [{"name": TICK_MARKER_ARTIFACT, "created_at": stamp}]}
            try:
                code = main()
            finally:
                globals()["_gh_json"] = saved
            with open(out_path, encoding="utf-8") as handle:
                written = handle.read()
        finally:
            for key, value in env_backup.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            os.unlink(out_path)
        chk(f"live: a {label} tick exits 0 and writes {want.strip()!r}", (code, written),
            (0, want))


def _test_workflow_seam(chk):
    """THE YAML SEAM. Measured on this estate: every Python mutant died while every UNCAUGHT one
    lived in a workflow `if:`, a step, or a call site. The floor lives at that seam, so mutate it
    here — job deleted, `if:` flipped, `needs:` cut, `continue-on-error` added, call site removed."""
    workflow = _load_workflow(DISPATCH_WORKFLOW)
    floor = _job(workflow, FLOOR_JOB)
    plan = _job(workflow, GATED_JOB)

    # --- the gate itself, evaluated in BOTH directions -------------------------------------
    chk("seam: PLAN runs when the floor says proceed", _plan_runs(workflow, "true"), True)
    chk("seam: PLAN does NOT run when the floor says hold (delete the `if:` or cut the `needs:` "
        "edge and this goes red)", _plan_runs(workflow, "false"), False)
    chk("seam: PLAN declares the floor as a `needs:` dependency",
        FLOOR_JOB in _declared_needs(plan), True)
    # A gate that admits on an ABSENT/empty output is a fail-open gate. GitHub renders an
    # unset job output as the empty string, so this is the shape a deleted `_emit` produces.
    chk("seam: PLAN does NOT run when the floor emits NOTHING (an unset output is the empty "
        "string, and admitting on it is fail-open)", _plan_runs(workflow, ""), False)

    # --- the floor job's own shape ----------------------------------------------------------
    chk("seam: the floor job exposes `proceed` as a job output",
        (floor.get("outputs") or {}).get("proceed"),
        "${{ steps.%s.outputs.proceed }}" % FLOOR_STEP_ID)
    chk("seam: the floor job holds exactly {actions:read, contents:read} — actions:read is what "
        "lets it LIST the marker artifacts, and nothing else is needed",
        floor.get("permissions"), {"actions": "read", "contents": "read"})
    # `continue-on-error` discards exactly the exit status that would report a broken floor, and a
    # step can never red its own neutering — so something ELSE has to assert its absence.
    chk("seam: no truthy `continue-on-error` at the floor job or step level",
        [floor.get("continue-on-error")] + [s.get("continue-on-error") for s in _steps(floor)],
        [None] * (1 + len(_steps(floor))))

    # --- the call site ----------------------------------------------------------------------
    decision = _step_by_id(floor, FLOOR_STEP_ID)
    tails = _invocations(decision, "dispatch-tick-floor.py")
    chk("seam: the decision step calls this script twice — once `--self-test`, once live",
        (len(tails), tails[0] if tails else None, tails[-1] if tails else None),
        (2, ["--self-test"], []))
    chk("seam: the decision step is not `continue-on-error`",
        decision.get("continue-on-error"), None)

    # --- the anchor WRITE: the floor is only sound if a proceeding tick records itself --------
    uploads = [s for s in _steps(floor)
               if str(s.get("uses", "")).startswith("actions/upload-artifact@")
               and (s.get("with") or {}).get("name") == TICK_MARKER_ARTIFACT]
    chk("seam: exactly one step uploads the executed-tick marker", len(uploads), 1)
    if uploads:
        upload = uploads[0]
        chk("seam: the marker upload is gated on the SAME proceed output the plan gate reads (a "
            "marker written on a no-op tick would ratchet the floor forward forever)",
            str(upload.get("if")).strip(),
            "${{ steps.%s.outputs.proceed == 'true' }}" % FLOOR_STEP_ID)
        chk("seam: the marker upload fails loud when it has nothing to upload",
            (upload.get("with") or {}).get("if-no-files-found"), "error")
        chk("seam: the marker upload is not `continue-on-error` (a silently dropped anchor "
            "un-floors every subsequent tick)", upload.get("continue-on-error"), None)
        marker_index = _steps(floor).index(upload)
        snapshot_index = next(
            (i for i, s in enumerate(_steps(_job(workflow, GATED_JOB)))), None)
        chk("seam: the marker is written inside the FLOOR job, before PLAN can start at all "
            "(so a tick that dies in the snapshot still holds the floor)",
            (marker_index > _steps(floor).index(decision), snapshot_index is not None),
            (True, True))

    # --- the self-test's own inputs ---------------------------------------------------------
    _test_selftest_inputs_are_checked_out(chk, floor)


def _test_selftest_inputs_are_checked_out(chk, floor):
    """Every file the assertions above read must be in the live job's sparse-checkout, or the whole
    YAML-seam section is unreachable on the live path while still passing in pr-gate."""
    for path in REQUIRED_FILES:
        _require(path)
    declared = _sparse_paths(floor)
    chk("seam: the floor job sparse-checks-out every file its self-test asserts against",
        sorted(declared), sorted(REQUIRED_FILES))


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
