#!/usr/bin/env python3
# Hard-GROOM-failure ops alert (issue #176): the model-access health decision is the LAST step of
# the `groom` job and runs under the default success() guard, so ANY earlier failure — the ledger
# data-only invariant sweep, a target-token mint, the main sweep (dead-lease CAS exhaustion,
# target-repo errors), or the 15-minute timeout — SKIPS it. groom is the ONLY crash-recovery path
# and the ONLY health-alert evaluator, so a persistent groom failure means recovery has stopped AND
# health alerts are no longer evaluated, yet it presents only as a skipped step on a cron nobody
# watches. The standalone groom-alert job calls this script, which keys on needs.groom.result and
# upserts/auto-closes a rolling `ops-alert` issue.
#
# Mirrors plan-alert.py (issue #38) / usage-alert.py (issue #39) hardening exactly:
#  - _alert_route: the private ALERT_REPO is the destination ONLY when ALERT_TOKEN can write there;
#    a half-configured deployment (repo set, token missing) falls back to the registry repo under
#    the ambient token instead of silently failing the private write. The groom-alert body carries
#    NO account handles (it reports only the job RESULT + run link), so the fallback needs no
#    redaction variant.
#  - decide(): close ONLY on an explicit `success` — needs.<job>.result also permits `skipped`,
#    which proves nothing about recovery, so an open alert must survive a skipped GROOM.
#  - _gh(check=True): a non-zero gh returncode is surfaced as a sanitized ::warning:: (op +
#    returncode only — never stderr, which can echo request bodies under GH_DEBUG=api) and main()
#    returns non-zero so the step outcome goes red (continue-on-error isolates the groomer).
#  - a SUCCESSFUL `gh issue list` returning MALFORMED JSON (truncation, HTML error page) fails
#    SOFT — sanitized ::warning:: (payload never echoed) and a graceful no-mutation skip, never an
#    uncaught JSONDecodeError crashing the alert; the next scheduled tick retries.
#
# Pure decide()/_alert_route() + a stubbed-gh flow test run under --self-test (registry-selftest).
import json
import os
import subprocess
import sys

ALERT_LABEL = "ops-alert"
ALERT_TITLE = "⚠️ Scheduled GROOM job is failing — crash-recovery and health alerts are stalled"
# Dedupe keyed on the TITLE alone breaks the moment anyone (human or a later wording tweak) renames
# the open alert — the next failing tick files a duplicate and recovery can't find the issue to
# close. The body carries this stable machine marker; dedupe matches the marker first and falls
# back to the exact title only for pre-marker legacy alerts.
ALERT_MARKER = "<!-- groom-alert:v1 key=groom-job-failure -->"


def _alert_route(alert_repo, alert_token, registry_repo):
    """(repo, token) for the alert issue — same semantics as usage-alert.py's router (privacy
    d22c + issue #39): private ALERT_REPO only when ALERT_TOKEN is present; otherwise the registry
    repo under the ambient token (token=None means "use the ambient GH_TOKEN")."""
    if alert_repo and alert_token:
        return alert_repo, alert_token
    return registry_repo, None


def decide(groom_result, has_open_alert):
    """Pure decision: 'upsert' | 'close' | 'noop'. Upsert on failure/cancelled; close ONLY on an
    explicit success with an alert open (`skipped` must NOT close — a skipped GROOM is not a
    recovery); anything else is a no-op."""
    if groom_result in ("failure", "cancelled"):
        return "upsert"
    if groom_result == "success" and has_open_alert:
        return "close"
    return "noop"


def _render_body(result, run_url, maintainer):
    return (
        f"{ALERT_MARKER}\n"
        "> 🤖 SPARQ agent — automated ops-alert (issue #176)\n\n"
        f"@{maintainer} the scheduled **GROOM** job ended `{result}`. groom is the ONLY "
        "crash-recovery path (dead-lease release, orphaned-PR/exhausted-attempt repair) AND it "
        "hosts the ONLY model-access health-alert evaluator as its final step — the default "
        "`success()` guard means that evaluator was **skipped** by this failure, so health "
        "alerts are not being raised or closed either.\n\n"
        "Likely cause: the ledger data-only invariant sweep, a target-token mint, the main sweep "
        "(dead-lease CAS exhaustion / target-repo errors), or the 15-minute timeout. Check the "
        "run below; the next scheduled tick retries automatically and this alert auto-closes once "
        "a GROOM succeeds.\n\n"
        f"- Failing run: {run_url}\n"
    )


def _gh(args, capture=False, token=None, check=False):
    # Sanitized fail-loud wrapper: op + returncode only — never stderr (GH_DEBUG=api can echo
    # request bodies) and never argument content beyond the gh subcommand words.
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    result = subprocess.run(["gh"] + args, capture_output=capture, text=True, env=env)
    if check and result.returncode != 0:
        print(f"::warning::groom-alert: gh {args[0]} {args[1] if len(args) > 1 else ''} "
              f"failed (rc={result.returncode})")
    return result


def main():
    registry_repo = os.environ["REGISTRY_REPO"]
    repo, token = _alert_route(
        os.environ.get("ALERT_REPO"), os.environ.get("ALERT_TOKEN"), registry_repo)
    result = os.environ.get("GROOM_RESULT", "")
    run_url = os.environ.get("RUN_URL", "")
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")

    # --limit 100: the `ops-alert` label is SHARED with the plan-failure alert, the
    # account-availability alert, and anything else ops-flavoured; a 20-issue window could push
    # this alert out of the dedupe scan (duplicate on failure, uncloseable on recovery). 100
    # comfortably exceeds any plausible open ops-alert count; the marker/title match below still
    # scans every returned row.
    listed = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", "open",
                  "--json", "number,title,body", "--limit", "100"],
                 capture=True, token=token, check=True)
    if listed.returncode != 0:
        # Fail loud: without the list we can neither dedupe an upsert nor prove recovery — go red
        # (the job's continue-on-error keeps the groomer isolated).
        return 1
    # A SUCCESSFUL gh call can still hand back malformed JSON (truncated output, an HTML error
    # page, a proxy interposing). That must degrade, not crash the whole alert: without a parseable
    # list we can neither dedupe nor prove recovery, so warn (sanitized — never echo the payload,
    # which is remote/user-controlled) and skip this tick; the next tick retries.
    try:
        found = json.loads(listed.stdout or "[]")
        if not isinstance(found, list):
            raise ValueError("expected a JSON array")
    except ValueError:  # json.JSONDecodeError is a ValueError
        print("::warning::groom-alert: gh issue list succeeded but returned unparseable "
              "JSON — skipping this tick (no dedupe/recovery data; next tick retries)")
        return 0
    # Match the stable body MARKER first (survives a retitled alert), exact title second (legacy
    # alerts filed before the marker existed).
    num = next((i["number"] for i in found if ALERT_MARKER in (i.get("body") or "")), None)
    if num is None:
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
        print("::warning::groom-alert: GROOM job {} — maintainer alerted".format(result))
        return 0
    if action == "close":
        commented = _gh(["issue", "comment", str(num), "-R", repo, "--body",
                         "✅ Recovered — the scheduled GROOM job succeeded again. Auto-closing."],
                        capture=True, token=token, check=True)
        closed = _gh(["issue", "close", str(num), "-R", repo],
                     capture=True, token=token, check=True)
        if commented.returncode != 0 or closed.returncode != 0:
            return 1
        print("groom-alert: GROOM recovered — closed the alert")
        return 0
    print("groom-alert: GROOM result={} — nothing to do".format(result or "unknown"))
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
    # decide(): success-only closure (`skipped` must not close), upsert on hard fail
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
    # every rendered body must carry the stable dedupe marker.
    chk("body carries the stable dedupe marker", ALERT_MARKER in body, True)
    # Stubbed-gh flow: full main() paths with a fake subprocess.run that records the COMPLETE
    # command and env per call, and can inject a failure for any individual gh subcommand — so
    # repo/token wiring and every mutation return-code check are asserted, not assumed.
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
    base_env = {"REGISTRY_REPO": "org/registry", "GROOM_RESULT": "", "RUN_URL": "u",
                "MAINTAINER_HANDLE": "m", "ALERT_REPO": "", "ALERT_TOKEN": ""}

    def run_main(groom_result, list_json="[]", fail=(), alert_repo="", alert_token=""):
        calls.clear()
        responses.clear()
        responses[("issue", "list")] = _Result(1 if ("issue", "list") in fail else 0, list_json)
        for key in fail:
            if key != ("issue", "list"):
                responses[key] = _Result(1)
        os.environ.update(base_env)
        os.environ["GROOM_RESULT"] = groom_result
        os.environ["ALERT_REPO"] = alert_repo
        os.environ["ALERT_TOKEN"] = alert_token
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
        # A SUCCESSFUL list handing back malformed JSON must fail SOFT — warning + graceful
        # no-mutation skip (rc=0, no exception), and the payload is never echoed.
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
        # EVERY mutation's returncode must fail the run (not just the list's).
        for failing in (("issue", "create"), ("issue", "edit")):
            rc_f, out_f = run_main("failure", open_json if failing == ("issue", "edit") else "[]",
                                   fail=(failing,))
            chk(f"flow: {failing[0]} {failing[1]} failure -> rc=1 + warning",
                (rc_f, "::warning::" in out_f), (1, True))
        for failing in (("issue", "comment"), ("issue", "close")):
            rc_g, out_g = run_main("success", open_json, fail=(failing,))
            chk(f"flow: {failing[0]} {failing[1]} failure -> rc=1 + warning",
                (rc_g, "::warning::" in out_g), (1, True))
        # repo/token WIRING. Private route: every command targets ALERT_REPO and runs under
        # ALERT_TOKEN; fallback route: registry repo under the ambient token.
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
        # the dedupe scan uses --limit 100 and matches a title past position 20.
        crowd = [{"number": i, "title": f"unrelated ops alert {i}"} for i in range(25)]
        rc_h, _ = run_main("failure", json.dumps(crowd + [{"number": 99, "title": ALERT_TITLE}]))
        list_cmd, _list_env = find(("issue", "list"))
        edit_cmd, _ = find(("issue", "edit"))
        chk("dedupe: --limit 100 + title found past position 20 -> edit #99, no create",
            (rc_h, "100" in (list_cmd or []), ("issue", "create") in subs(),
             edit_cmd is not None and "99" in edit_cmd),
            (0, True, False, True))
        # a RENAMED alert (same underlying failure, retitled by a human or a wording tweak) must
        # still dedupe via the body marker — edit the open issue, never file a twin.
        renamed = json.dumps([{"number": 55, "title": "GROOM broke again (renamed by maintainer)",
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
    finally:
        subprocess.run = real_run
        for key in base_env:
            os.environ.pop(key, None)
    print("groom-alert self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
