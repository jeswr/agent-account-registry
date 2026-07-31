#!/usr/bin/env python3
# Hard-PLAN-failure ops alert (issue #38): every always()/ops-alert step in dispatch.yml lives
# inside the `claim` job (`needs: plan`), so when PLAN itself fails or is cancelled, claim is
# SKIPPED and none of them run — a persistent PLAN failure means zero dispatching fleet-wide yet
# presents only as skipped jobs on a cron nobody watches. The standalone plan-alert job calls this
# script, which keys on needs.plan.result and upserts/auto-closes a rolling `ops-alert` issue.
#
# Cross-provider review r1 (GPT-5.6 codex) hardening, mirroring usage-alert.py (issue #39):
#  - _alert_route: locked decision 22c / issue #39 — the private ALERT_REPO is the destination ONLY
#    when ALERT_TOKEN can write there; a half-configured deployment (repo set, token missing) falls
#    back to the registry repo under the ambient token instead of silently failing the private
#    write. The plan-alert body carries NO account handles, so the fallback needs no redaction
#    variant. Issue #591: the decision itself now lives ONCE, in scripts/alert_route.py, and this
#    name is bound to it rather than restating it.
#  - decide(): close ONLY on an explicit `success` — needs.<job>.result also permits `skipped`,
#    which proves nothing about recovery, so an open alert must survive a skipped PLAN.
#  - _gh(check=True): a non-zero gh returncode is surfaced as a sanitized ::warning:: (op +
#    returncode only — never stderr, which can echo request bodies under GH_DEBUG=api) and main()
#    returns non-zero so the step outcome goes red (continue-on-error isolates the dispatcher).
#  - Codex r4: a SUCCESSFUL `gh issue list` returning MALFORMED JSON (truncation, HTML error page)
#    fails SOFT — sanitized ::warning:: (payload never echoed) and a graceful no-mutation skip,
#    never an uncaught JSONDecodeError crashing the alert; the next scheduled tick retries.
#
# CLAIM termination (issue #778): the premise above — "every always() step lives inside claim, so
# a job that never runs is invisible" — has a SECOND instance the PLAN-only key cannot see. GitHub
# does NOT run a job's `if: always()` steps once the JOB ITSELF is cancelled (its own
# `timeout-minutes`, or a run-level cancel). CLAIM hosts the CAS lease claim, the worker launch AND
# the `always()` "Surface + record the dispatch-tick health state" step (the #756 per-tick
# telemetry), so a cancelled CLAIM records NOTHING: no telemetry row, no defer histogram, no alert.
# Worse, because PLAN itself SUCCEEDED, the PLAN-only decide() returned `close` and this job
# actively CLOSED any open ops-alert on the very tick CLAIM was killed mid-write.
#
# MEASURED on run 30245515435 (2026-07-27): PLAN success (444 s), then CLAIM cancelled after
# exactly 1200 s = its `timeout-minutes: 15` plus GitHub's 5-minute post-cancel grace. Step 13
# ("Strictly validate, CAS claim, and dispatch live workers") never completed; steps 14 (the
# `always()` health-state recorder) and 15 never ran at all. Run-level conclusion: `cancelled` —
# byte-identical to the 116 of 117 cancellations in the same window that were FREE
# concurrency-group coalescing with zero started jobs. No aggregate over run conclusions can tell
# the two apart, which is why this needs an alert keyed on the JOB result, not the run conclusion.
#
# So decide() now keys on BOTH stage results and names the failing stage. Scope, stated honestly:
# this covers a cancelled CLAIM *job* (the measured case), because a job killed by its own timeout
# does not cancel the run and `if: always()` dependents still run. It does NOT cover a
# RUN-level cancellation, which cancels this job too — nothing inside the run can observe that.
#
# Pure decide()/_alert_route() + a stubbed-gh flow test run under --self-test (registry-selftest).
import importlib.util
import json
import os
import subprocess
import sys

ALERT_LABEL = "ops-alert"
ALERT_TITLE = "⚠️ Dispatch PLAN job is failing — fleet-wide dispatch is stalled"
CLAIM_ALERT_TITLE = "⚠️ Dispatch CLAIM job died mid-tick — leases/launches unrecorded"
# Review r3 residual: dedupe keyed on the TITLE alone breaks the moment anyone (human or a later
# wording tweak) renames the open alert — the next failing tick files a duplicate and recovery
# can't find the issue to close. The body carries this stable machine marker; dedupe matches the
# marker first and falls back to the exact title only for pre-marker legacy alerts.
#
# #778 keeps ONE marker for BOTH stages deliberately: a single rolling "the dispatch tick is
# broken" alert. Splitting markers would let a PLAN alert and a CLAIM alert sit open at once and
# each close independently, and the recovery condition is joint anyway (both stages green). The
# marker string is unchanged so alerts opened before #778 still dedupe and still close.
ALERT_MARKER = "<!-- plan-alert:v1 key=dispatch-plan-failure -->"

STAGE_PLAN = "PLAN"
STAGE_CLAIM = "CLAIM"
# `needs.<job>.result` is one of success | failure | cancelled | skipped. Only these two are a
# fault: `skipped` proves nothing (review r1) and `success` is the healthy case.
_BAD_RESULTS = ("failure", "cancelled")
_STAGE_TITLE = {STAGE_PLAN: ALERT_TITLE, STAGE_CLAIM: CLAIM_ALERT_TITLE}


def _load_alert_route():
    """The shared ops-alert destination router (scripts/alert_route.py, issue #591), loaded BY
    PATH: the plan-alert job sparse-checks-out an explicit file list, so there is no importable
    package here and the module can simply be absent from the working copy.

    An absent module is a sparse-checkout omission in dispatch.yml, NOT a "route unavailable" to be
    guessed around — picking a default destination is exactly the fail-open locked decision 22c
    forbids. Die, and name the fix. (alert_route.py's own --self-test asserts the other direction:
    a sparse job that names this script without naming the module goes red in pr-gate.)"""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alert_route.py")
    spec = importlib.util.spec_from_file_location("registry_alert_route", path)
    if not os.path.exists(path) or spec is None or spec.loader is None:
        raise SystemExit(
            "plan-alert: cannot load scripts/alert_route.py — add it to the plan-alert job's "
            "sparse-checkout list in .github/workflows/dispatch.yml")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Locked decision 22c / issue #39, defined ONCE in scripts/alert_route.py and bound to the private
# name every call site and self-test row below already uses.
_alert_route_module = _load_alert_route()
_alert_route = _alert_route_module.alert_route


def failing_stage(plan_result, claim_result):
    """The dispatch stage that terminated badly, or None if neither did.

    PLAN is tested FIRST on purpose: a bad PLAN *skips* CLAIM, so CLAIM's result is then a
    consequence, not an independent fault. Naming the consequence would point the maintainer at
    the wrong job. (`skipped` is not in _BAD_RESULTS, so a PLAN-caused skip cannot be reported
    as a CLAIM fault either way — the ordering is belt-and-braces for the failure/cancelled case
    where a run-level cancel marks BOTH jobs cancelled.)"""
    if plan_result in _BAD_RESULTS:
        return STAGE_PLAN
    if claim_result in _BAD_RESULTS:
        return STAGE_CLAIM
    return None


def decide(plan_result, claim_result, has_open_alert):
    """Pure decision: 'upsert' | 'close' | 'noop'. Upsert when EITHER stage ended
    failure/cancelled; close ONLY when BOTH ended in an explicit success with an alert open
    (review r1: `skipped` must NOT close — it is not a recovery; #778: a green PLAN must not
    close an alert while CLAIM is the thing that died); anything else is a no-op.

    Requiring BOTH green to close cannot strand an alert: neither `plan` nor `claim` carries a
    job-level `if:`, so on any tick where this job runs at all (its own `if:` requires
    secrets-guard success) CLAIM is skipped ONLY when PLAN failed — which is an upsert, not a
    close."""
    if failing_stage(plan_result, claim_result) is not None:
        return "upsert"
    if plan_result == "success" and claim_result == "success" and has_open_alert:
        return "close"
    return "noop"


def _render_body(stage, result, run_url, maintainer):
    if stage == STAGE_CLAIM:
        detail = (
            f"@{maintainer} the dispatch **CLAIM** job ended `{result}`. CLAIM holds the CAS "
            "lease claim, the worker launch, **and** the `always()` per-tick telemetry step "
            "(#756) — and GitHub does not run `always()` steps once the job itself is "
            "cancelled. So this tick recorded **nothing**: no telemetry row, no defer "
            "histogram, and it may have written leases and launched only SOME of the workers "
            "it claimed.\n\n"
            "Check for leases claimed against issues with no live worker (groom-leases "
            "reclaims them on TTL, but not promptly). Common cause: the CAS-claim/dispatch "
            "step hanging until `timeout-minutes` — the run-level conclusion is then "
            "`cancelled`, indistinguishable from ordinary concurrency-group coalescing, which "
            "is why this alert exists.\n\n"
        )
    else:
        detail = (
            f"@{maintainer} the dispatch **PLAN** job ended `{result}`, so the CLAIM job (and "
            "every `always()` alert step it hosts) was **skipped** — nothing dispatched this "
            "tick, and a sustained PLAN failure means **zero dispatching fleet-wide**.\n\n"
            "Common cause: sustained snapshot 403s / GitHub secondary rate-limit on the "
            "authenticated snapshot step.\n\n"
        )
    return (
        f"{ALERT_MARKER}\n"
        "> 🤖 SPARQ agent — automated ops-alert (issue #38, #778)\n\n"
        + detail
        + "Check the run below; the next scheduled tick retries automatically and this alert "
        "auto-closes once a tick completes with BOTH stages green.\n\n"
        f"- Failing run: {run_url}\n"
    )


def workflow_wiring_verdict(workflow_text):
    """(ok, detail) — does dispatch.yml's `plan-alert` job actually WIRE the CLAIM result?

    Issue #592 asks for a regression test on these alert jobs' wiring, and #778 is precisely a
    wiring defect: the decision logic below is INERT unless the workflow both depends on `claim`
    and passes its result in. Every uncaught mutant in this estate has lived at the YAML seam, so
    this asserts the seam structurally (parsed jobs/needs/step-env), not by substring-scanning the
    file — a match anywhere in 1600 lines would prove nothing about the plan-alert job."""
    try:
        import yaml  # lazy: same shape as dispatch-secrets-guard.py's parse
    except ImportError as error:  # pragma: no cover - CI installs PyYAML
        return False, f"cannot import yaml to verify the wiring ({error}) — fail closed"
    try:
        document = yaml.safe_load(workflow_text or "")
    except Exception as error:  # noqa: BLE001 - any parse fault is a fail-closed verdict
        return False, f"dispatch.yml does not parse as YAML ({type(error).__name__})"
    jobs = (document or {}).get("jobs")
    if not isinstance(jobs, dict):
        return False, "cannot locate a `jobs:` mapping in dispatch.yml (fail closed)"
    job = jobs.get("plan-alert")
    if not isinstance(job, dict):
        return False, "dispatch.yml has no `plan-alert` job (fail closed)"
    needs = job.get("needs")
    needs = [needs] if isinstance(needs, str) else list(needs or [])
    missing = [n for n in ("plan", "secrets-guard", "claim") if n not in needs]
    if missing:
        return False, ("the plan-alert job does not depend on " + ", ".join(missing) +
                       " — it cannot read a result it does not need")
    steps = job.get("steps")
    if not isinstance(steps, list) or not steps:
        return False, "the plan-alert job has no steps (fail closed)"
    seen = {}
    for step in steps:
        env = (step or {}).get("env") if isinstance(step, dict) else None
        for key in ("PLAN_RESULT", "CLAIM_RESULT"):
            value = (env or {}).get(key)
            if isinstance(value, str):
                seen[key] = value
    for key, job_name in (("PLAN_RESULT", "plan"), ("CLAIM_RESULT", "claim")):
        value = seen.get(key)
        if value is None:
            return False, f"no plan-alert step sets {key} — the {job_name} result never arrives"
        # Brace-free assertion text (secret masking mangles braces in Actions logs).
        if f"needs.{job_name}.result" not in value:
            return False, (f"{key} is set but does not read needs.{job_name}.result "
                           f"(got a value that never references it)")
    return True, "ok"


def _gh(args, capture=False, token=None, check=False):
    # Sanitized fail-loud wrapper (review r1): op + returncode only — never stderr (GH_DEBUG=api
    # can echo request bodies) and never argument content beyond the gh subcommand words.
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    result = subprocess.run(["gh"] + args, capture_output=capture, text=True, env=env)
    if check and result.returncode != 0:
        print(f"::warning::plan-alert: gh {args[0]} {args[1] if len(args) > 1 else ''} "
              f"failed (rc={result.returncode})")
    return result


def main():
    registry_repo = os.environ["REGISTRY_REPO"]
    repo, token = _alert_route(
        os.environ.get("ALERT_REPO"), os.environ.get("ALERT_TOKEN"), registry_repo)
    result = os.environ.get("PLAN_RESULT", "")
    # #778: if CLAIM_RESULT is not wired at all, MIRROR the plan result rather than defaulting it
    # to "". Mirroring makes decide(p, p, open) reduce EXACTLY to the pre-#778 PLAN-only decision
    # for every one of the four `needs.<job>.result` values (asserted in the self-test), so a
    # half-deployed workflow degrades to the old behaviour. Defaulting to "" instead would block
    # `close` forever and strand an open alert with no machine exit. The miswiring is still caught
    # BEFORE it ships: the self-test asserts the live dispatch.yml wires this env var.
    claim_result = os.environ.get("CLAIM_RESULT")
    if claim_result is None:
        print("::warning::plan-alert: CLAIM_RESULT is not wired by the workflow — falling back "
              "to PLAN-only alerting; a cancelled CLAIM will NOT be reported")
        claim_result = result
    run_url = os.environ.get("RUN_URL", "")
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")

    # --limit 100 (review r2): the `ops-alert` label is SHARED with the account-availability alert
    # and anything else ops-flavoured; a 20-issue window could push this alert out of the dedupe
    # scan (duplicate on failure, uncloseable on recovery). 100 comfortably exceeds any plausible
    # open ops-alert count; the marker/title match below still scans every returned row.
    listed = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", "open",
                  "--json", "number,title,body", "--limit", "100"],
                 capture=True, token=token, check=True)
    if listed.returncode != 0:
        # Fail loud (review r1): without the list we can neither dedupe an upsert nor prove
        # recovery — go red (the job's continue-on-error keeps the dispatcher isolated).
        return 1
    # Codex r4: a SUCCESSFUL gh call can still hand back malformed JSON (truncated output, an HTML
    # error page, a proxy interposing). That must degrade, not crash the whole alert: without a
    # parseable list we can neither dedupe nor prove recovery, so warn (sanitized — never echo the
    # payload, which is remote/user-controlled) and skip this tick; the next tick retries.
    try:
        found = json.loads(listed.stdout or "[]")
        if not isinstance(found, list):
            raise ValueError("expected a JSON array")
    except ValueError:  # json.JSONDecodeError is a ValueError
        print("::warning::plan-alert: gh issue list succeeded but returned unparseable "
              "JSON — skipping this tick (no dedupe/recovery data; next tick retries)")
        return 0
    # r3 residual: match the stable body MARKER first (survives a retitled alert), exact title
    # second (legacy alerts filed before the marker existed).
    num = next((i["number"] for i in found if ALERT_MARKER in (i.get("body") or "")), None)
    if num is None:
        # #778: match EITHER stage title here. Every alert this script writes carries the marker,
        # so in practice only pre-marker legacy alerts reach this line — but an alert whose body
        # was hand-edited past the marker must still dedupe rather than spawn a twin.
        num = next((i["number"] for i in found
                    if i.get("title") in _STAGE_TITLE.values()), None)

    action = decide(result, claim_result, num is not None)
    if action == "upsert":
        stage = failing_stage(result, claim_result)
        stage_result = result if stage == STAGE_PLAN else claim_result
        title = _STAGE_TITLE[stage]
        _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", "d73a4a",
             "--description", "Autonomous ops alert (maintainer action)"],
            capture=True, token=token)  # idempotent; pre-existing label is fine
        body = _render_body(stage, stage_result, run_url, maintainer)
        if num:
            # #778: retitle on edit as well. One rolling alert covers both stages, so an alert
            # opened for a PLAN failure that is now a CLAIM failure must not keep announcing the
            # wrong job. Dedupe already happened above (marker-first), so retitling is safe.
            wrote = _gh(["issue", "edit", str(num), "-R", repo, "--title", title,
                         "--body", body],
                        capture=True, token=token, check=True)
        else:
            wrote = _gh(["issue", "create", "-R", repo, "--title", title,
                         "--label", ALERT_LABEL, "--body", body],
                        capture=True, token=token, check=True)
        if wrote.returncode != 0:
            return 1
        print("::warning::plan-alert: {} job {} — maintainer alerted".format(stage, stage_result))
        return 0
    if action == "close":
        commented = _gh(["issue", "comment", str(num), "-R", repo, "--body",
                         "✅ Recovered — the dispatch PLAN and CLAIM jobs both succeeded again. "
                         "Auto-closing."],
                        capture=True, token=token, check=True)
        closed = _gh(["issue", "close", str(num), "-R", repo],
                     capture=True, token=token, check=True)
        if commented.returncode != 0 or closed.returncode != 0:
            return 1
        print("plan-alert: PLAN+CLAIM recovered — closed the alert")
        return 0
    print("plan-alert: PLAN result={} CLAIM result={} — nothing to do".format(
        result or "unknown", claim_result or "unknown"))
    return 0


def _self_test():
    ok = True

    def chk(n, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {n}: {got} (want {want})")

    # The loader's fail-closed branch: an ABSENT scripts/alert_route.py must DIE naming the fix,
    # never fall back to a guessed destination — guessing is the fail-open locked decision 22c
    # forbids, and this branch is otherwise never executed by anything.
    _saved_exists = os.path.exists
    os.path.exists = lambda p: False if p.endswith("alert_route.py") else _saved_exists(p)
    try:
        _load_alert_route()
        _loader_verdict = "loaded a module that is not there"
    except SystemExit as error:
        _loader_verdict = ("alert_route.py" in str(error), "dispatch.yml" in str(error))
    finally:
        os.path.exists = _saved_exists
    chk("loader: absent scripts/alert_route.py -> SystemExit naming the module and the fix",
        _loader_verdict, (True, True))
    # Routing (mirrors usage-alert.py's audited matrix). The rows below now exercise the SHARED
    # router; this first row is what reds if a private copy is ever reintroduced below and shadows
    # the binding — the drift issue #591 exists to close.
    chk("route: bound to the shared scripts/alert_route.py, not a local copy",
        (_alert_route is _alert_route_module.alert_route,
         os.path.basename(_alert_route_module.__file__)), (True, "alert_route.py"))
    chk("route: repo+token -> private + token",
        _alert_route("org/private", "tok", "org/registry"), ("org/private", "tok"))
    chk("route: repo but NO token -> registry fallback",
        _alert_route("org/private", "", "org/registry"), ("org/registry", None))
    chk("route: repo but None token -> registry fallback",
        _alert_route("org/private", None, "org/registry"), ("org/registry", None))
    chk("route: no repo -> registry",
        _alert_route("", "tok", "org/registry"), ("org/registry", None))
    # decide(): success-only closure (review r1 — `skipped` must not close), upsert on hard fail.
    # PLAN axis, CLAIM green throughout (the pre-#778 matrix, preserved exactly).
    chk("decide: PLAN failure -> upsert", decide("failure", "success", False), "upsert")
    chk("decide: PLAN failure w/ open -> upsert", decide("failure", "success", True), "upsert")
    chk("decide: PLAN cancelled -> upsert", decide("cancelled", "success", True), "upsert")
    chk("decide: both success + open -> close", decide("success", "success", True), "close")
    chk("decide: both success + none -> noop", decide("success", "success", False), "noop")
    chk("decide: PLAN SKIPPED + open -> noop (not a recovery)",
        decide("skipped", "success", True), "noop")
    chk("decide: PLAN empty + open -> noop", decide("", "success", True), "noop")
    # ---- #778: the CLAIM axis. THE defect: a green PLAN with a dead CLAIM used to read as a
    # healthy tick and CLOSE the alert. Each of these is red against the pre-#778 PLAN-only decide.
    chk("decide[#778]: PLAN success + CLAIM CANCELLED -> upsert (NOT close)",
        decide("success", "cancelled", True), "upsert")
    chk("decide[#778]: PLAN success + CLAIM cancelled + no open alert -> upsert",
        decide("success", "cancelled", False), "upsert")
    chk("decide[#778]: PLAN success + CLAIM FAILURE -> upsert (NOT close)",
        decide("success", "failure", True), "upsert")
    chk("decide[#778]: PLAN success + CLAIM skipped + open -> noop (never a close)",
        decide("success", "skipped", True), "noop")
    # Attribution: a bad PLAN skips CLAIM, so PLAN is the CAUSE and must be the named stage even
    # when a run-level cancel marks BOTH jobs cancelled.
    chk("failing_stage: PLAN failure + CLAIM skipped -> PLAN",
        failing_stage("failure", "skipped"), STAGE_PLAN)
    chk("failing_stage: BOTH cancelled -> PLAN (the cause, not the consequence)",
        failing_stage("cancelled", "cancelled"), STAGE_PLAN)
    chk("failing_stage: PLAN success + CLAIM cancelled -> CLAIM",
        failing_stage("success", "cancelled"), STAGE_CLAIM)
    chk("failing_stage: both green -> None", failing_stage("success", "success"), None)
    # main() mirrors PLAN into CLAIM when CLAIM_RESULT is unwired. Prove that reduction is exact
    # over EVERY `needs.<job>.result` value, so a half-deployed workflow keeps the old behaviour
    # (and in particular keeps its `close` machine-exit) rather than stranding an alert open.
    def _legacy_decide(plan_result, has_open):
        if plan_result in ("failure", "cancelled"):
            return "upsert"
        if plan_result == "success" and has_open:
            return "close"
        return "noop"
    mirrored = {(r, o): (decide(r, r, o), _legacy_decide(r, o))
                for r in ("success", "failure", "cancelled", "skipped", "")
                for o in (True, False)}
    chk("mirror: decide(p, p, open) == pre-#778 PLAN-only decide, for all 10 (result, open)",
        [k for k, (new, old) in mirrored.items() if new != old], [])
    # body: run link + maintainer mention, no secrets/handles by construction
    body = _render_body(STAGE_PLAN, "failure", "https://example.test/run/1", "jeswr")
    chk("body carries run url + mention",
        ("https://example.test/run/1" in body, "@jeswr" in body), (True, True))
    # r3 residual: every rendered body must carry the stable dedupe marker.
    chk("body carries the stable dedupe marker", ALERT_MARKER in body, True)
    # #778: the CLAIM body must name CLAIM (not PLAN) as the dead stage and must carry the same
    # marker, or the two stages cannot share one rolling alert.
    claim_body = _render_body(STAGE_CLAIM, "cancelled", "https://example.test/run/2", "jeswr")
    chk("CLAIM body names CLAIM, carries marker + run url, does not blame PLAN",
        ("**CLAIM**" in claim_body, ALERT_MARKER in claim_body,
         "https://example.test/run/2" in claim_body, "**PLAN**" in claim_body),
        (True, True, True, False))
    chk("PLAN and CLAIM alert titles are distinct",
        _STAGE_TITLE[STAGE_PLAN] != _STAGE_TITLE[STAGE_CLAIM], True)
    # Stubbed-gh flow (review r1 finding 4 + r2 finding 2): full main() paths with a fake
    # subprocess.run that records the COMPLETE command and env per call, and can inject a failure
    # for any individual gh subcommand — so repo/token wiring and every mutation return-code check
    # are asserted, not assumed.
    import contextlib
    import io

    class _Result:
        def __init__(self, rc=0, stdout=""):
            self.returncode = rc
            self.stdout = stdout
            self.stderr = "SENTINEL-STDERR"

    calls = []          # [(cmd_list, env_dict)]
    responses = {}      # (sub, sub2) -> _Result

    def fake_run(cmd, capture_output=False, text=False, env=None):
        calls.append((list(cmd), dict(env or {})))
        return responses.get(tuple(cmd[1:3]), _Result())

    def find(sub):
        return next(((c, e) for c, e in calls if tuple(c[1:3]) == sub), (None, None))

    def subs():
        return [tuple(c[1:3]) for c, _e in calls]

    real_run = subprocess.run
    # #778: CLAIM_RESULT is wired HERE, defaulting to `success`, for two reasons. (1) It keeps
    # every pre-#778 flow assertion below semantically identical (PLAN drives the outcome).
    # (2) Leaving it unset would take main()'s unwired-mirror path, whose ::warning:: would make
    # the "sanitized warning" assertions below pass VACUOUSLY. The mirror path is exercised in its
    # own case instead, where the warning is the thing under test.
    base_env = {"REGISTRY_REPO": "org/registry", "PLAN_RESULT": "", "CLAIM_RESULT": "success",
                "RUN_URL": "u", "MAINTAINER_HANDLE": "m", "ALERT_REPO": "", "ALERT_TOKEN": ""}

    def run_main(plan_result, list_json="[]", fail=(), alert_repo="", alert_token="",
                 claim_result="success", wire_claim=True):
        calls.clear()
        responses.clear()
        responses[("issue", "list")] = _Result(1 if ("issue", "list") in fail else 0, list_json)
        for key in fail:
            if key != ("issue", "list"):
                responses[key] = _Result(1)
        os.environ.update(base_env)
        os.environ["PLAN_RESULT"] = plan_result
        os.environ["ALERT_REPO"] = alert_repo
        os.environ["ALERT_TOKEN"] = alert_token
        if wire_claim:
            os.environ["CLAIM_RESULT"] = claim_result
        else:
            os.environ.pop("CLAIM_RESULT", None)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main()
        return rc, buf.getvalue()

    subprocess.run = fake_run
    try:
        rc_a, _ = run_main("failure")
        chk("flow: failure + no open -> create", (rc_a, ("issue", "create") in subs()), (0, True))
        open_json = json.dumps([{"number": 7, "title": ALERT_TITLE}])
        rc_b, _ = run_main("failure", open_json)
        chk("flow: failure + open -> edit not create",
            (rc_b, ("issue", "edit") in subs(), ("issue", "create") in subs()), (0, True, False))
        rc_c, _ = run_main("success", open_json)
        chk("flow: success + open -> comment+close",
            (rc_c, ("issue", "comment") in subs(), ("issue", "close") in subs()), (0, True, True))
        rc_d, _ = run_main("skipped", open_json)
        chk("flow: skipped + open -> NO mutation",
            (rc_d, [s for s in subs() if s != ("issue", "list")]), (0, []))
        rc_e, out_e = run_main("failure", fail=(("issue", "list"),))
        chk("flow: list failure -> rc=1 + sanitized warning",
            (rc_e, "::warning::" in out_e, "SENTINEL-STDERR" in out_e), (1, True, False))
        # Codex r4: a SUCCESSFUL list handing back malformed JSON must fail SOFT — warning +
        # graceful no-mutation skip (rc=0, no exception), and the payload is never echoed.
        rc_m, out_m = run_main("failure", "SENTINEL-MALFORMED-PAYLOAD {not json")
        chk("flow: malformed list JSON -> warning + graceful skip, payload not echoed",
            (rc_m, "::warning::" in out_m, "SENTINEL-MALFORMED-PAYLOAD" in out_m,
             [s for s in subs() if s != ("issue", "list")]),
            (0, True, False, []))
        # ...and valid-JSON-but-not-a-list (e.g. a gh/API error OBJECT) takes the same soft path.
        rc_n, out_n = run_main("success", '{"message": "sentinel-error-object"}')
        chk("flow: non-array list JSON -> warning + graceful skip, payload not echoed",
            (rc_n, "::warning::" in out_n, "sentinel-error-object" in out_n,
             [s for s in subs() if s != ("issue", "list")]),
            (0, True, False, []))
        # r2 finding 2: EVERY mutation's returncode must fail the run (not just the list's).
        for failing in (("issue", "create"), ("issue", "edit")):
            rc_f, out_f = run_main("failure", open_json if failing == ("issue", "edit") else "[]",
                                   fail=(failing,))
            chk(f"flow: {failing[0]} {failing[1]} failure -> rc=1 + warning",
                (rc_f, "::warning::" in out_f), (1, True))
        for failing in (("issue", "comment"), ("issue", "close")):
            rc_g, out_g = run_main("success", open_json, fail=(failing,))
            chk(f"flow: {failing[0]} {failing[1]} failure -> rc=1 + warning",
                (rc_g, "::warning::" in out_g), (1, True))
        # r2 finding 2: repo/token WIRING. Private route: every command targets ALERT_REPO and
        # runs under ALERT_TOKEN; fallback route: registry repo under the ambient token.
        run_main("failure", alert_repo="org/private", alert_token="sentinel-alert-tok")
        create_cmd, create_env = find(("issue", "create"))
        chk("wiring: private route -> -R org/private under ALERT_TOKEN",
            (create_cmd is not None and create_cmd[create_cmd.index("-R") + 1],
             (create_env or {}).get("GH_TOKEN")),
            ("org/private", "sentinel-alert-tok"))
        ambient = os.environ.get("GH_TOKEN")  # whatever the harness ambient is (None locally, set in CI)
        run_main("failure", alert_repo="org/private", alert_token="")
        create_cmd2, create_env2 = find(("issue", "create"))
        chk("wiring: half-config -> -R org/registry under UNCHANGED ambient token",
            (create_cmd2 is not None and create_cmd2[create_cmd2.index("-R") + 1],
             (create_env2 or {}).get("GH_TOKEN") == ambient,
             (create_env2 or {}).get("GH_TOKEN") == "sentinel-alert-tok"),
            ("org/registry", True, False))
        # r2 finding 1: the dedupe scan uses --limit 100 and matches a title past position 20.
        crowd = [{"number": i, "title": f"unrelated ops alert {i}"} for i in range(25)]
        rc_h, _ = run_main("failure", json.dumps(crowd + [{"number": 99, "title": ALERT_TITLE}]))
        list_cmd, _list_env = find(("issue", "list"))
        edit_cmd, _ = find(("issue", "edit"))
        chk("dedupe: --limit 100 + title found past position 20 -> edit #99, no create",
            (rc_h, "100" in (list_cmd or []), ("issue", "create") in subs(),
             edit_cmd is not None and "99" in edit_cmd),
            (0, True, False, True))
        # r3 residual: a RENAMED alert (same underlying failure, retitled by a human or a wording
        # tweak) must still dedupe via the body marker — edit the open issue, never file a twin.
        renamed = json.dumps([{"number": 55, "title": "PLAN broke again (renamed by maintainer)",
                               "body": "legacy prose\n" + ALERT_MARKER + "\nmore prose"}])
        rc_i, _ = run_main("failure", renamed)
        edit_i, _ = find(("issue", "edit"))
        chk("dedupe: RENAMED alert -> marker match edits #55, no create",
            (rc_i, ("issue", "create") in subs(), edit_i is not None and "55" in edit_i),
            (0, False, True))
        # ...and recovery must find the renamed alert too (close via marker, not title).
        rc_j, _ = run_main("success", renamed)
        close_j, _ = find(("issue", "close"))
        chk("close: RENAMED alert -> marker match closes #55",
            (rc_j, close_j is not None and "55" in close_j), (0, True))
        # Legacy fallback: a pre-marker alert (exact title, marker-less body) still dedupes.
        legacy = json.dumps([{"number": 8, "title": ALERT_TITLE, "body": "old body, no marker"}])
        rc_k, _ = run_main("failure", legacy)
        edit_k, _ = find(("issue", "edit"))
        chk("dedupe: legacy title-only alert -> fallback edits #8, no create",
            (rc_k, ("issue", "create") in subs(), edit_k is not None and "8" in edit_k),
            (0, False, True))
        # The list request must fetch `body` or the marker match is silently vacuous.
        list_cmd_k, _ = find(("issue", "list"))
        chk("dedupe: list fetches number,title,body",
            "number,title,body" in (list_cmd_k or []), True)
        # ---- #778 end-to-end: the measured run-30245515435 shape (PLAN green, CLAIM cancelled).
        # Pre-#778 this took the CLOSE path; it must now file/keep an alert naming CLAIM.
        rc_p, out_p = run_main("success", "[]", claim_result="cancelled")
        create_p, _ = find(("issue", "create"))
        chk("flow[#778]: PLAN success + CLAIM cancelled -> CREATE a CLAIM alert, never close",
            (rc_p, ("issue", "create") in subs(), ("issue", "close") in subs(),
             create_p is not None and CLAIM_ALERT_TITLE in create_p,
             "CLAIM job cancelled" in out_p),
            (0, True, False, True, True))
        # The regression in its sharpest form: an OPEN alert must SURVIVE a green PLAN whose
        # CLAIM died. Pre-#778 this closed the alert on the very tick the fleet was broken.
        open_marked = json.dumps([{"number": 7, "title": ALERT_TITLE,
                                   "body": ALERT_MARKER + "\nbody"}])
        rc_q, _ = run_main("success", open_marked, claim_result="cancelled")
        edit_q, _ = find(("issue", "edit"))
        chk("flow[#778]: green PLAN + cancelled CLAIM must NOT close an OPEN alert -> edit it",
            (rc_q, ("issue", "close") in subs(), ("issue", "comment") in subs(),
             edit_q is not None and "7" in edit_q,
             edit_q is not None and CLAIM_ALERT_TITLE in edit_q),
            (0, False, False, True, True))
        # Recovery still works once BOTH stages are green — the alert has a machine exit.
        rc_r, _ = run_main("success", open_marked, claim_result="success")
        chk("flow[#778]: both stages green -> comment+close (the machine exit survives)",
            (rc_r, ("issue", "comment") in subs(), ("issue", "close") in subs()),
            (0, True, True))
        # Unwired CLAIM_RESULT: warn LOUDLY and degrade to pre-#778 PLAN-only behaviour, including
        # keeping the close path (a stranded-open alert would be a hold with no machine exit).
        rc_s, out_s = run_main("success", open_marked, wire_claim=False)
        chk("flow[#778]: UNWIRED CLAIM_RESULT -> warns + still closes on a green PLAN",
            (rc_s, "CLAIM_RESULT is not wired" in out_s, ("issue", "close") in subs()),
            (0, True, True))
    finally:
        subprocess.run = real_run
        for key in base_env:
            os.environ.pop(key, None)

    # ---- THE YAML SEAM (#778, and the regression test issue #592 asks for) ----------------
    # Everything above is inert unless dispatch.yml wires it. Synthetic accept + each reject
    # direction first, then the LIVE workflow.
    wired_sample = "\n".join([
        "jobs:",
        "  plan-alert:",
        "    needs: [plan, secrets-guard, claim]",
        "    steps:",
        "      - run: python3 scripts/plan-alert.py",
        "        env:",
        "          PLAN_RESULT: ${{ needs.plan.result }}",
        "          CLAIM_RESULT: ${{ needs.claim.result }}",
    ])
    chk("seam: fully wired plan-alert job -> ok", workflow_wiring_verdict(wired_sample),
        (True, "ok"))

    def _drop(sample, needle):
        """Delete the one line containing `needle`. Raises if it matches 0 or >1 lines — a
        mutation helper that silently no-ops produces a green 'the mutant was refused' assertion
        that proves nothing. (This caught a real vacuous case while writing these tests: a
        trailing-newline `.replace` matched nothing on the sample's LAST line.)"""
        lines = sample.split("\n")
        hits = [i for i, line in enumerate(lines) if needle in line]
        if len(hits) != 1:
            raise AssertionError(f"mutation helper matched {len(hits)} lines for {needle!r}")
        return "\n".join(lines[:hits[0]] + lines[hits[0] + 1:])

    verdict_need = workflow_wiring_verdict(
        wired_sample.replace("[plan, secrets-guard, claim]", "[plan, secrets-guard]"))
    chk("seam: `needs` without claim -> REFUSE (cannot read a result it does not need)",
        (verdict_need[0], "claim" in verdict_need[1]), (False, True))
    verdict_env = workflow_wiring_verdict(_drop(wired_sample, "CLAIM_RESULT:"))
    chk("seam: CLAIM_RESULT env deleted -> REFUSE (the claim result never arrives)",
        (verdict_env[0], "CLAIM_RESULT" in verdict_env[1]), (False, True))
    rewired = wired_sample.replace("CLAIM_RESULT: ${{ needs.claim.result }}",
                                   "CLAIM_RESULT: ${{ needs.plan.result }}")
    chk("seam: CLAIM_RESULT set from the PLAN result -> REFUSE (silently re-reports PLAN)",
        workflow_wiring_verdict(rewired)[0], False)
    chk("seam: PLAN_RESULT env deleted -> REFUSE (the pre-#778 contract still holds)",
        workflow_wiring_verdict(_drop(wired_sample, "PLAN_RESULT:"))[0], False)
    chk("seam: whole plan-alert job renamed away -> REFUSE",
        workflow_wiring_verdict(wired_sample.replace("  plan-alert:", "  some-other-job:"))[0],
        False)
    chk("seam: unparseable workflow -> REFUSE (fail closed, never skip)",
        workflow_wiring_verdict("jobs:\n  plan-alert:\n   - [unbalanced")[0], False)
    chk("seam: empty workflow -> REFUSE (fail closed)", workflow_wiring_verdict("")[0], False)
    # LIVE. The plan-alert JOB sparse-checks-out only scripts/plan-alert.py, so at dispatch
    # runtime there is no workflow tree to read; that must not go red every tick. Discriminate on
    # the WORKFLOWS DIRECTORY, not on dispatch.yml itself: no directory => sparse checkout (skip
    # with a notice); directory present but dispatch.yml missing => it was renamed or moved, which
    # is a real defect and fails. A bare `exists(dispatch.yml)` guard would silently skip on
    # exactly the rename it is supposed to catch.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    workflows_dir = os.path.join(root, ".github", "workflows")
    live_path = os.path.join(workflows_dir, "dispatch.yml")
    if not os.path.isdir(workflows_dir):
        print(f"  note .github/workflows absent at {root} — sparse checkout, live seam check "
              "not applicable (the pr-gate full checkout enforces it)")
    else:
        try:
            with open(live_path, encoding="utf-8") as handle:
                live_text = handle.read()
        except OSError as error:
            live_text = None
            chk("seam: LIVE dispatch.yml is readable (a rename must fail, not skip)",
                f"{type(error).__name__}", None)
        if live_text is not None:
            chk("seam: LIVE dispatch.yml wires plan-alert -> needs claim + CLAIM_RESULT",
                workflow_wiring_verdict(live_text), (True, "ok"))

    print("plan-alert self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
