#!/usr/bin/env python3
# Hard-RETRIAGE-failure ops alert (issue #577). The retriage cron (`7,37 * * * *`) is the ONLY path
# that returns `status:untriaged` issues to dispatch (issue #415, built to end the stranding outage
# #414 measured: 120 untriaged + 63 deferred). Until now it had NO failure-alert leg at all, unlike
# the other two engine crons (scripts/plan-alert.py for dispatch PLAN, scripts/groom-alert.py for
# groom): a `gh issue edit` permission error, a `jq` shape change or a `retriage.py --self-test`
# regression takes the sweep offline INDEFINITELY under `set -euo pipefail`, and the only signal is
# the untriaged backlog growing on the dashboard.
#
# The keepalive does not cover this either: .github/workflows/dashboard.yml re-dispatches workflows
# whose last run is STALE, and a cron that runs punctually every tick and FAILS every time is never
# stale — the keepalive stays silent by design. So this standalone job keys on
# `needs.retriage.result` and upserts/auto-closes a rolling `ops-alert` issue.
#
# Mirrors groom-alert.py / plan-alert.py / usage-alert.py hardening exactly:
#  - routing: the shared scripts/alert_route.py helper (issue #577 AC3 — NOT a sixth copy of
#    `_alert_route`). Private ALERT_REPO only when ALERT_TOKEN can write there; otherwise the
#    registry repo under the ambient token. This body carries NO account handles (only the job
#    RESULT + run link), so that fallback needs no redaction variant.
#  - decide(): close ONLY on an explicit `success` — needs.<job>.result also permits `skipped`,
#    which proves nothing about recovery, so an open alert must survive a skipped RETRIAGE.
#  - _gh(check=True): a non-zero gh returncode is surfaced as a sanitized ::warning:: (op +
#    returncode only — never stderr, which can echo request bodies under GH_DEBUG=api) and main()
#    returns non-zero so the step outcome goes red (continue-on-error isolates the sweep).
#  - a SUCCESSFUL `gh issue list` returning MALFORMED JSON (truncation, HTML error page) fails
#    SOFT — sanitized ::warning:: (payload never echoed) and a graceful no-mutation skip, never an
#    uncaught JSONDecodeError crashing the alert; the next scheduled tick retries.
#
# Pure decide()/alert_wiring_problems() + a stubbed-gh flow test run under --self-test
# (registry-selftest).
import importlib.util
import json
import os
import re
import subprocess
import sys

# Fail CLOSED on a missing shared helper: the alert job sparse-checks-out both this script and
# scripts/alert_route.py, so an absent module means the checkout is wrong. Dying loudly beats
# falling back to an inlined guess at the routing decision.
_route_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alert_route.py")
_route_spec = importlib.util.spec_from_file_location("registry_alert_route", _route_path)
if _route_spec is None or _route_spec.loader is None:
    raise SystemExit(f"retriage-alert: cannot load the shared alert router at {_route_path}")
_alert_route_mod = importlib.util.module_from_spec(_route_spec)
_route_spec.loader.exec_module(_alert_route_mod)
alert_route = _alert_route_mod.alert_route

ALERT_LABEL = "ops-alert"
ALERT_TITLE = "⚠️ Scheduled RETRIAGE sweep is failing — untriaged issues are stranded"
# Dedupe keyed on the TITLE alone breaks the moment anyone (human or a later wording tweak) renames
# the open alert — the next failing tick files a duplicate and recovery can't find the issue to
# close. The body carries this stable machine marker; dedupe matches the marker first and falls
# back to the exact title only for pre-marker legacy alerts.
ALERT_MARKER = "<!-- retriage-alert:v1 key=retriage-sweep-failure -->"


def decide(retriage_result, has_open_alert):
    """Pure decision: 'upsert' | 'close' | 'noop'. Upsert on failure/cancelled; close ONLY on an
    explicit success with an alert open (`skipped` must NOT close — a skipped RETRIAGE is not a
    recovery); anything else is a no-op."""
    if retriage_result in ("failure", "cancelled"):
        return "upsert"
    if retriage_result == "success" and has_open_alert:
        return "close"
    return "noop"


def _job_blocks(workflow_text):
    """Split a workflow's `jobs:` mapping into {job_name: block_text}. Deliberately textual — this
    runs in the alert job, which has no PyYAML and a sparse two-file checkout.

    COMMENT LINES ARE DROPPED, and that is load-bearing rather than cosmetic: this file documents
    its own guards in prose ("Without this always() ...", "aborts the sweep under `set -euo
    pipefail`"), and a comment mentioning a guard would otherwise satisfy the substring check for
    the guard itself — making every assertion below vacuous. A comment block introducing the NEXT
    job is also indented into the PREVIOUS job's text, so prose leaks across jobs too."""
    body = workflow_text.split("\njobs:\n", 1)
    if len(body) != 2:
        return {}
    blocks, name, buf = {}, None, []
    for line in body[1].splitlines():
        if line and not line.startswith(" ") and not line.startswith("#"):
            break  # a new top-level key ends the jobs mapping
        if line.lstrip().startswith("#"):
            continue
        match = re.match(r"^  ([A-Za-z_][\w-]*):\s*$", line)
        if match:
            if name is not None:
                blocks[name] = "\n".join(buf)
            name, buf = match.group(1), []
            continue
        if name is not None:
            buf.append(line)
    if name is not None:
        blocks[name] = "\n".join(buf)
    return blocks


def alert_wiring_problems(workflow_text):
    """Audit retriage.yml's failure legs (issue #577 AC5). Returns a sorted list of problems — []
    means a failed OR cancelled sweep provably reaches this alert.

    The failure path being asserted: the sweep runs under `set -euo pipefail`, so a mid-loop `gh`
    failure AFTER some issues were already promoted aborts the step (a partial sweep is NOT
    swallowed) -> the `retriage` job goes red -> the always()-guarded `retriage-alert` job still
    runs and reads that red result. Drop any one of those links and the outage is silent again."""
    jobs = _job_blocks(workflow_text)
    problems = []
    sweep, alert = jobs.get("retriage"), jobs.get("retriage-alert")
    if sweep is None:
        problems.append("missing job: retriage")
    elif "set -euo pipefail" not in sweep:
        problems.append("retriage sweep does not run under `set -euo pipefail` — a mid-loop gh "
                        "failure would be swallowed and the job would stay green")
    if alert is None:
        problems.append("missing job: retriage-alert")
        return sorted(problems)
    if "needs: [retriage]" not in alert:
        problems.append("retriage-alert does not declare `needs: [retriage]`")
    if "always()" not in alert:
        problems.append("retriage-alert is not always()-guarded — GitHub implicitly success()-gates "
                        "it, so the FAILING tick would skip the alert entirely")
    if "RETRIAGE_RESULT: ${{ needs.retriage.result }}" not in alert:
        problems.append("retriage-alert does not wire RETRIAGE_RESULT from needs.retriage.result")
    return sorted(problems)


def _render_body(result, run_url, maintainer):
    return (
        f"{ALERT_MARKER}\n"
        "> 🤖 SPARQ agent — automated ops-alert (issue #577)\n\n"
        f"@{maintainer} the scheduled **RETRIAGE** sweep ended `{result}`. Retriage is the ONLY "
        "path that returns `status:untriaged` issues to dispatch, so while it stays red the "
        "untriaged backlog is **stranded** — it presents as a quietly growing dashboard count, "
        "not as an outage.\n\n"
        "Likely cause: an `issues: write` permission error on `gh issue edit`, a `gh`/`jq` output "
        "shape change, or a `retriage.py --self-test` regression — any of which aborts the sweep "
        "under `set -euo pipefail`, possibly PART-WAY through (some issues promoted, the rest "
        "left untriaged). Check the run below; the next scheduled tick retries automatically and "
        "this alert auto-closes once a RETRIAGE succeeds.\n\n"
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
        print(f"::warning::retriage-alert: gh {args[0]} {args[1] if len(args) > 1 else ''} "
              f"failed (rc={result.returncode})")
    return result


def main():
    registry_repo = os.environ["REGISTRY_REPO"]
    repo, token = alert_route(
        os.environ.get("ALERT_REPO"), os.environ.get("ALERT_TOKEN"), registry_repo)
    result = os.environ.get("RETRIAGE_RESULT", "")
    run_url = os.environ.get("RUN_URL", "")
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")

    # --limit 100: the `ops-alert` label is SHARED with the plan-failure alert, the groom-failure
    # alert, the account-availability alert, and anything else ops-flavoured; a 20-issue window
    # could push this alert out of the dedupe scan (duplicate on failure, uncloseable on recovery).
    # 100 comfortably exceeds any plausible open ops-alert count; the marker/title match below
    # still scans every returned row.
    listed = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", "open",
                  "--json", "number,title,body", "--limit", "100"],
                 capture=True, token=token, check=True)
    if listed.returncode != 0:
        # Fail loud: without the list we can neither dedupe an upsert nor prove recovery — go red
        # (the job's continue-on-error keeps the sweep isolated).
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
        print("::warning::retriage-alert: gh issue list succeeded but returned unparseable "
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
        print("::warning::retriage-alert: RETRIAGE sweep {} — maintainer alerted".format(result))
        return 0
    if action == "close":
        commented = _gh(["issue", "comment", str(num), "-R", repo, "--body",
                         "✅ Recovered — the scheduled RETRIAGE sweep succeeded again. "
                         "Auto-closing."],
                        capture=True, token=token, check=True)
        closed = _gh(["issue", "close", str(num), "-R", repo],
                     capture=True, token=token, check=True)
        if commented.returncode != 0 or closed.returncode != 0:
            return 1
        print("retriage-alert: RETRIAGE recovered — closed the alert")
        return 0
    print("retriage-alert: RETRIAGE result={} — nothing to do".format(result or "unknown"))
    return 0


# A minimal well-wired retriage.yml, used as the POSITIVE control for alert_wiring_problems() and
# as the base every negative control below is mutated from. Keeping it inline means the audit's
# assertions stay non-vacuous in the alert job's one-file sparse checkout, where the real workflow
# file is absent; the real file is additionally audited whenever it IS present.
_WIRING_FIXTURE = """name: retriage

on:
  schedule:
    - cron: '7,37 * * * *'

jobs:
  retriage:
    runs-on: ubuntu-latest
    steps:
      - name: Sweep at most 40 untriaged issues
        run: |
          set -euo pipefail
          gh issue edit 1

  retriage-alert:
    needs: [retriage]
    if: ${{ always() }}
    runs-on: ubuntu-latest
    steps:
      - name: Alert
        env:
          RETRIAGE_RESULT: ${{ needs.retriage.result }}
        run: python3 registry/scripts/retriage-alert.py
"""


def _self_test():
    ok = True

    def chk(n, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {n}: {got} (want {want})")

    # Routing comes from the SHARED helper (issue #577 AC3). Re-assert the boundary here so this
    # emitter's destination decision is covered by its own suite, not only alert_route.py's.
    chk("route: repo+token -> private + token",
        alert_route("org/private", "tok", "org/registry"), ("org/private", "tok"))
    chk("route: repo but NO token -> registry fallback",
        alert_route("org/private", "", "org/registry"), ("org/registry", None))
    chk("route: no repo -> registry",
        alert_route("", "tok", "org/registry"), ("org/registry", None))
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

    # --- AC5: the workflow's failure legs must actually REACH this alert. Positive control first,
    # then one negative control per link — each mutation must be NAMED in the problem list, so a
    # regression to implicit-success gating (or a swallowed mid-loop gh failure) flips this red. ---
    chk("wiring: a well-wired retriage.yml has no problems",
        alert_wiring_problems(_WIRING_FIXTURE), [])
    no_always = _WIRING_FIXTURE.replace("    if: ${{ always() }}\n", "")
    chk("wiring: alert job WITHOUT always() is caught (the failing tick would skip it)",
        any("always()" in p for p in alert_wiring_problems(no_always)), True)
    no_needs = _WIRING_FIXTURE.replace("    needs: [retriage]\n", "")
    chk("wiring: alert job WITHOUT needs: [retriage] is caught",
        any("needs: [retriage]" in p for p in alert_wiring_problems(no_needs)), True)
    no_result = _WIRING_FIXTURE.replace(
        "          RETRIAGE_RESULT: ${{ needs.retriage.result }}\n", "")
    chk("wiring: alert job that never reads needs.retriage.result is caught",
        any("RETRIAGE_RESULT" in p for p in alert_wiring_problems(no_result)), True)
    no_errexit = _WIRING_FIXTURE.replace("          set -euo pipefail\n", "")
    chk("wiring: a sweep without `set -euo pipefail` is caught (partial sweep swallowed)",
        any("set -euo pipefail" in p for p in alert_wiring_problems(no_errexit)), True)
    # ...and PROSE must never satisfy a guard check. The real retriage.yml documents each guard in
    # a comment ("Without this always() ...", "aborts the sweep under `set -euo pipefail`"), and a
    # comment block introducing the alert job is indented into the SWEEP job's text — so without
    # comment-stripping in _job_blocks every assertion above passes on a workflow that has the
    # words but not the wiring. This mutant carries both comments and neither guard.
    prose_only = (_WIRING_FIXTURE
                  .replace("    if: ${{ always() }}\n", "")
                  .replace("          set -euo pipefail\n",
                           "          # the sweep aborts under `set -euo pipefail`\n")
                  .replace("  retriage-alert:",
                           "  # Without this always() the failing tick would skip the alert.\n"
                           "  retriage-alert:"))
    chk("wiring: comments MENTIONING the guards do not satisfy them (non-vacuous)",
        sorted(p.split(" —")[0] for p in alert_wiring_problems(prose_only)),
        ["retriage sweep does not run under `set -euo pipefail`",
         "retriage-alert is not always()-guarded"])
    no_alert_job = _WIRING_FIXTURE.split("  retriage-alert:")[0]
    chk("wiring: a retriage.yml with NO alert job at all is caught (the #577 pre-fix state)",
        alert_wiring_problems(no_alert_job), ["missing job: retriage-alert"])
    chk("wiring: an empty/unparseable workflow is caught, not silently accepted",
        alert_wiring_problems(""),
        ["missing job: retriage", "missing job: retriage-alert"])
    # ...and the REAL workflow, whenever this runs from a full checkout (the gate suites). The
    # alert job itself sparse-checks-out only the two scripts, so the file is legitimately absent
    # there; that skip is announced rather than silent.
    real_wf = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           os.pardir, ".github", "workflows", "retriage.yml")
    if os.path.exists(real_wf):
        with open(real_wf, encoding="utf-8") as handle:
            chk("wiring: the REAL .github/workflows/retriage.yml is correctly wired",
                alert_wiring_problems(handle.read()), [])
    else:
        print("  note .github/workflows/retriage.yml absent (sparse checkout) — fixture "
              "controls above still cover the audit")

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
    base_env = {"REGISTRY_REPO": "org/registry", "RETRIAGE_RESULT": "", "RUN_URL": "u",
                "MAINTAINER_HANDLE": "m", "ALERT_REPO": "", "ALERT_TOKEN": ""}

    def run_main(retriage_result, list_json="[]", fail=(), alert_repo="", alert_token=""):
        calls.clear()
        responses.clear()
        responses[("issue", "list")] = _Result(1 if ("issue", "list") in fail else 0, list_json)
        for key in fail:
            if key != ("issue", "list"):
                responses[key] = _Result(1)
        os.environ.update(base_env)
        os.environ["RETRIAGE_RESULT"] = retriage_result
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
        chk("flow: failure + open -> edit not create (ONE alert issue, re-used per tick)",
            (rc_b, ("issue", "edit") in subs(), ("issue", "create") in subs()), (0, True, False))
        rc_c, _ = run_main("success", open_json)
        chk("flow: success + open -> comment+close",
            (rc_c, ("issue", "comment") in subs(), ("issue", "close") in subs()), (0, True, True))
        rc_d, _ = run_main("skipped", open_json)
        chk("flow: skipped + open -> NO mutation",
            (rc_d, [s for s in subs() if s != ("issue", "list")]), (0, []))
        rc_l, _ = run_main("cancelled")
        chk("flow: cancelled -> create (a cancelled sweep strands issues too)",
            (rc_l, ("issue", "create") in subs()), (0, True))
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
        renamed = json.dumps([{"number": 55, "title": "retriage broke (renamed by maintainer)",
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
        # A SIBLING cron's alert (groom/plan) shares the ops-alert label and must NOT be mistaken
        # for this one — otherwise a failing retriage would edit groom's alert instead of filing.
        sibling = json.dumps([{"number": 21,
                               "title": "⚠️ Scheduled GROOM job is failing — crash-recovery and "
                                        "health alerts are stalled",
                               "body": "<!-- groom-alert:v1 key=groom-job-failure -->"}])
        rc_s, _ = run_main("failure", sibling)
        chk("dedupe: a sibling cron's ops-alert is NOT adopted -> create, no edit",
            (rc_s, ("issue", "create") in subs(), ("issue", "edit") in subs()), (0, True, False))
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
    print("retriage-alert self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
