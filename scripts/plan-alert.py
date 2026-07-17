#!/usr/bin/env python3
# Hard-PLAN-failure ops alert (issue #38): every always()/ops-alert step in dispatch.yml lives
# inside the `claim` job (`needs: plan`), so when PLAN itself fails or is cancelled, claim is
# SKIPPED and none of them run — a persistent PLAN failure means zero dispatching fleet-wide yet
# presents only as skipped jobs on a cron nobody watches. The standalone plan-alert job calls this
# script, which keys on needs.plan.result and upserts/auto-closes a rolling `ops-alert` issue.
#
# Cross-provider review r1 (GPT-5.6 codex) hardening, mirroring usage-alert.py (issue #39):
#  - _alert_route: the private ALERT_REPO is the destination ONLY when ALERT_TOKEN can write there;
#    a half-configured deployment (repo set, token missing) falls back to the registry repo under
#    the ambient token instead of silently failing the private write. The plan-alert body carries
#    NO account handles, so the fallback needs no redaction variant.
#  - decide(): close ONLY on an explicit `success` — needs.<job>.result also permits `skipped`,
#    which proves nothing about recovery, so an open alert must survive a skipped PLAN.
#  - _gh(check=True): a non-zero gh returncode is surfaced as a sanitized ::warning:: (op +
#    returncode only — never stderr, which can echo request bodies under GH_DEBUG=api) and main()
#    returns non-zero so the step outcome goes red (continue-on-error isolates the dispatcher).
#
# Pure decide()/_alert_route() + a stubbed-gh flow test run under --self-test (registry-selftest).
import json
import os
import subprocess
import sys

ALERT_LABEL = "ops-alert"
ALERT_TITLE = "⚠️ Dispatch PLAN job is failing — fleet-wide dispatch is stalled"


def _alert_route(alert_repo, alert_token, registry_repo):
    """(repo, token) for the alert issue — same semantics as usage-alert.py's router (privacy
    d22c + issue #39): private ALERT_REPO only when ALERT_TOKEN is present; otherwise the registry
    repo under the ambient token (token=None means "use the ambient GH_TOKEN")."""
    if alert_repo and alert_token:
        return alert_repo, alert_token
    return registry_repo, None


def decide(plan_result, has_open_alert):
    """Pure decision: 'upsert' | 'close' | 'noop'. Upsert on failure/cancelled; close ONLY on an
    explicit success with an alert open (review r1: `skipped` must NOT close — a skipped PLAN is
    not a recovery); anything else is a no-op."""
    if plan_result in ("failure", "cancelled"):
        return "upsert"
    if plan_result == "success" and has_open_alert:
        return "close"
    return "noop"


def _render_body(result, run_url, maintainer):
    return (
        "> 🤖 SPARQ agent — automated ops-alert (issue #38)\n\n"
        f"@{maintainer} the dispatch **PLAN** job ended `{result}`, so the CLAIM job (and "
        "every `always()` alert step it hosts) was **skipped** — nothing dispatched this "
        "tick, and a sustained PLAN failure means **zero dispatching fleet-wide**.\n\n"
        "Common cause: sustained snapshot 403s / GitHub secondary rate-limit on the "
        "authenticated snapshot step. Check the run below; the next scheduled tick retries "
        "automatically and this alert auto-closes once a PLAN succeeds.\n\n"
        f"- Failing run: {run_url}\n"
    )


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
    run_url = os.environ.get("RUN_URL", "")
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")

    listed = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", "open",
                  "--json", "number,title", "--limit", "20"], capture=True, token=token, check=True)
    if listed.returncode != 0:
        # Fail loud (review r1): without the list we can neither dedupe an upsert nor prove
        # recovery — go red (the job's continue-on-error keeps the dispatcher isolated).
        return 1
    found = json.loads(listed.stdout or "[]")
    num = next((i["number"] for i in found if i.get("title") == ALERT_TITLE), None)

    action = decide(result, num is not None)
    if action == "upsert":
        _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", "d73a4a",
             "--description", "Autonomous ops alert (maintainer action)"],
            capture=True, token=token)  # idempotent; pre-existing label is fine
        body = _render_body(result, run_url, maintainer)
        if num:
            wrote = _gh(["issue", "edit", str(num), "-R", repo, "--body", body],
                        capture=True, token=token, check=True)
        else:
            wrote = _gh(["issue", "create", "-R", repo, "--title", ALERT_TITLE,
                         "--label", ALERT_LABEL, "--body", body],
                        capture=True, token=token, check=True)
        if wrote.returncode != 0:
            return 1
        print("::warning::plan-alert: PLAN job {} — maintainer alerted".format(result))
        return 0
    if action == "close":
        commented = _gh(["issue", "comment", str(num), "-R", repo, "--body",
                         "✅ Recovered — the dispatch PLAN job succeeded again. Auto-closing."],
                        capture=True, token=token, check=True)
        closed = _gh(["issue", "close", str(num), "-R", repo],
                     capture=True, token=token, check=True)
        if commented.returncode != 0 or closed.returncode != 0:
            return 1
        print("plan-alert: PLAN recovered — closed the alert")
        return 0
    print("plan-alert: PLAN result={} — nothing to do".format(result or "unknown"))
    return 0


def _self_test():
    ok = True

    def chk(n, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {n}: {got} (want {want})")

    # Routing (mirrors usage-alert.py's audited matrix)
    chk("route: repo+token -> private + token",
        _alert_route("org/private", "tok", "org/registry"), ("org/private", "tok"))
    chk("route: repo but NO token -> registry fallback",
        _alert_route("org/private", "", "org/registry"), ("org/registry", None))
    chk("route: repo but None token -> registry fallback",
        _alert_route("org/private", None, "org/registry"), ("org/registry", None))
    chk("route: no repo -> registry",
        _alert_route("", "tok", "org/registry"), ("org/registry", None))
    # decide(): success-only closure (review r1 — `skipped` must not close), upsert on hard fail
    chk("decide: failure -> upsert", decide("failure", False), "upsert")
    chk("decide: failure w/ open -> upsert", decide("failure", True), "upsert")
    chk("decide: cancelled -> upsert", decide("cancelled", True), "upsert")
    chk("decide: success + open -> close", decide("success", True), "close")
    chk("decide: success + none -> noop", decide("success", False), "noop")
    chk("decide: SKIPPED + open -> noop (not a recovery)", decide("skipped", True), "noop")
    chk("decide: empty result + open -> noop", decide("", True), "noop")
    # body: run link + maintainer mention, no secrets/handles by construction
    body = _render_body("failure", "https://example.test/run/1", "jeswr")
    chk("body carries run url + mention",
        ("https://example.test/run/1" in body, "@jeswr" in body), (True, True))
    # Stubbed-gh flow (review r1 finding 4): full main() paths with a fake subprocess.run.
    import contextlib
    import io

    class _Result:
        def __init__(self, rc=0, stdout=""):
            self.returncode = rc
            self.stdout = stdout
            self.stderr = "SENTINEL-STDERR"

    calls = []
    responses = {}

    def fake_run(cmd, capture_output=False, text=False, env=None):
        sub = tuple(cmd[1:3])
        calls.append(sub)
        return responses.get(sub, _Result())

    real_run = subprocess.run
    base_env = {"REGISTRY_REPO": "org/registry", "PLAN_RESULT": "", "RUN_URL": "u",
                "MAINTAINER_HANDLE": "m", "ALERT_REPO": "", "ALERT_TOKEN": ""}

    def run_main(plan_result, list_json="[]", list_rc=0):
        calls.clear()
        responses.clear()
        responses[("issue", "list")] = _Result(list_rc, list_json)
        os.environ.update(base_env)
        os.environ["PLAN_RESULT"] = plan_result
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main()
        return rc, list(calls), buf.getvalue()

    subprocess.run = fake_run
    try:
        rc_a, calls_a, _ = run_main("failure")
        chk("flow: failure + no open -> create", (rc_a, ("issue", "create") in calls_a), (0, True))
        open_json = json.dumps([{"number": 7, "title": ALERT_TITLE}])
        rc_b, calls_b, _ = run_main("failure", open_json)
        chk("flow: failure + open -> edit not create",
            (rc_b, ("issue", "edit") in calls_b, ("issue", "create") in calls_b), (0, True, False))
        rc_c, calls_c, _ = run_main("success", open_json)
        chk("flow: success + open -> comment+close",
            (rc_c, ("issue", "comment") in calls_c, ("issue", "close") in calls_c), (0, True, True))
        rc_d, calls_d, _ = run_main("skipped", open_json)
        chk("flow: skipped + open -> NO mutation",
            (rc_d, [c for c in calls_d if c != ("issue", "list")]), (0, []))
        rc_e, _, out_e = run_main("failure", "[]", list_rc=1)
        chk("flow: list failure -> rc=1 + sanitized warning",
            (rc_e, "::warning::" in out_e, "SENTINEL-STDERR" in out_e), (1, True, False))
    finally:
        subprocess.run = real_run
        for key in base_env:
            os.environ.pop(key, None)
    print("plan-alert self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
