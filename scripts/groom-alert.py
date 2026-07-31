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
# SECOND CONDITION — the crashing evaluator (issue #331). The health-decision step is
# `continue-on-error: true`, so when model-health.py exits nonzero and every other step succeeds
# the groom JOB result is still `success`: the result-keyed alarm above CANNOT see it, and a
# sustained evaluator crash is visibly red on a cron nobody watches while health alerts stop being
# raised or closed entirely. The step OUTCOME (the pre-continue-on-error result) is the only
# surviving signal, so groom.yml publishes it as a job output and this script raises a SECOND,
# independently-closing rolling alert on it. The two conditions share one `gh issue list` and are
# deliberately separate issues: they have different causes, different blast radii and recover
# independently.
#   POSTURE, stated rather than implied: like the job-level alert, this one upserts on the FIRST
#   failing tick and auto-closes on the first recovering one. A one-tick blip therefore files an
#   issue that closes ~15 min later — the same trade #176 already made, and the alternative
#   (a consecutive-failure streak) needs cross-run state that only `mint-gap`'s artifact-name
#   protocol provides. Never missing a sustained crash is worth one self-closing issue.
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
# Pure decide()/decide_health()/_alert_route() + a stubbed-gh flow test + the groom.yml WIRING seam
# (the step id, the job output and the env line the second condition rides on — un-wire any one of
# them and the alarm silently never fires) run under --self-test (registry-selftest).
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ALERT_LABEL = "ops-alert"
ALERT_TITLE = "⚠️ Scheduled GROOM job is failing — crash-recovery and health alerts are stalled"
# Dedupe keyed on the TITLE alone breaks the moment anyone (human or a later wording tweak) renames
# the open alert — the next failing tick files a duplicate and recovery can't find the issue to
# close. The body carries this stable machine marker; dedupe matches the marker first and falls
# back to the exact title only for pre-marker legacy alerts.
ALERT_MARKER = "<!-- groom-alert:v1 key=groom-job-failure -->"
# The second condition (issue #331): the health evaluator STEP crashing under a green job. Its own
# title/marker pair, so the two alerts dedupe and recover independently.
HEALTH_TITLE = ("⚠️ Scheduled GROOM model-access health evaluator is failing — "
                "health alerts are no longer being evaluated")
HEALTH_MARKER = "<!-- groom-alert:v1 key=groom-health-step-failure -->"
# ONE definition of the carrier's name (#958's lesson: a literal with several definitions drifts
# and the consumers go blind). main() READS this name, the stubbed-gh harness DRIVES it, and the
# YAML seam asserts groom.yml sets exactly THIS name — so renaming it on either side of the seam
# reds instead of silently leaving the outcome permanently empty.
HEALTH_OUTCOME_ENV = "GROOM_HEALTH_OUTCOME"

WORKFLOW = ".github/workflows/groom.yml"
# KEEP IN SYNC with the sparse-checkout in groom.yml's `groom-alert` job — the self-test asserts
# both directions, so a trimmed checkout goes red instead of making the seam section below
# silently unreachable on the live path.
REQUIRED_FILES = ("scripts/groom-alert.py", WORKFLOW)


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


def decide_health(health_outcome, has_open_alert):
    """Pure decision for the model-health EVALUATOR STEP (issue #331), keyed on its `outcome` —
    the PRE-continue-on-error result, which is the only place a crashing evaluator is visible at
    all. 'upsert' | 'close' | 'noop'.

    Everything other than an explicit failure/success is deliberately a NO-OP:
      * `skipped`   — an earlier step failed, so the evaluator never ran. That tick is a hard GROOM
                      failure decide() above already reports, and a skip proves nothing about
                      recovery, so an open health alert must SURVIVE it.
      * `cancelled` — the job was cancelled (the 15-minute timeout, or by hand), so
                      needs.groom.result is `cancelled` too and decide() already upserts. Paging
                      twice for one event is noise, not coverage.
      * `''`        — the output never arrived (GROOM skipped, or the wiring was removed). Absence
                      of evidence is not evidence in either direction: never page on it, and never
                      close on it either.
    """
    if health_outcome == "failure":
        return "upsert"
    if health_outcome == "success" and has_open_alert:
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


def _render_health_body(outcome, run_url, maintainer):
    # Same privacy posture as the body above: a step outcome and a run link, no account handles, no
    # ledger content, nothing token-derived — so the registry-repo fallback route stays safe.
    return (
        f"{HEALTH_MARKER}\n"
        "> 🤖 SPARQ agent — automated ops-alert (issue #331)\n\n"
        f"@{maintainer} the **Decide + raise/close model-access health alerts** step of the "
        f"scheduled **GROOM** job ended `{outcome}` while the job around it reported "
        "`success`.\n\n"
        "That step is `continue-on-error: true` — deliberately, so a health-alert fault can never "
        "abort the only crash-recovery path — which also means this failure never reaches the job "
        "result the GROOM-failure alert keys on. For as long as it persists, model-access health "
        "alerts are neither raised NOR closed: a provider outage would go unreported, and an "
        "already-open health alert would never auto-close.\n\n"
        "Likely cause: an unreadable or missing health ledger (`data/model-health.json` on the "
        "`ledger` branch), a failed policy/fleet read, or a crash inside `scripts/model-health.py "
        "decide`. Read the step log in the run below; the next scheduled tick retries "
        "automatically and this alert auto-closes once the evaluator completes again.\n\n"
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


def _find_open(found, marker, title):
    """The open alert's number, or None. Match the stable body MARKER first (survives a retitled
    alert), exact title second (legacy alerts filed before the marker existed)."""
    num = next((i["number"] for i in found if marker in (i.get("body") or "")), None)
    if num is None:
        num = next((i["number"] for i in found if i.get("title") == title), None)
    return num


def _apply(action, num, repo, token, title, body, recovery, subject):
    """Execute one 'upsert' | 'close' | 'noop' decision. Returns 0, or 1 if any MUTATION failed —
    callers OR the results so a failure on one condition can neither mask nor suppress the other."""
    if action == "upsert":
        _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", "d73a4a",
             "--description", "Autonomous ops alert (maintainer action)"],
            capture=True, token=token)  # idempotent; pre-existing label is fine
        if num:
            wrote = _gh(["issue", "edit", str(num), "-R", repo, "--body", body],
                        capture=True, token=token, check=True)
        else:
            wrote = _gh(["issue", "create", "-R", repo, "--title", title,
                         "--label", ALERT_LABEL, "--body", body],
                        capture=True, token=token, check=True)
        if wrote.returncode != 0:
            return 1
        print(f"::warning::groom-alert: {subject} — maintainer alerted")
        return 0
    if action == "close":
        commented = _gh(["issue", "comment", str(num), "-R", repo, "--body", recovery],
                        capture=True, token=token, check=True)
        closed = _gh(["issue", "close", str(num), "-R", repo], capture=True, token=token, check=True)
        if commented.returncode != 0 or closed.returncode != 0:
            return 1
        print(f"groom-alert: {subject} recovered — closed the alert")
        return 0
    print(f"groom-alert: {subject} — nothing to do")
    return 0


def main():
    registry_repo = os.environ["REGISTRY_REPO"]
    repo, token = _alert_route(
        os.environ.get("ALERT_REPO"), os.environ.get("ALERT_TOKEN"), registry_repo)
    result = os.environ.get("GROOM_RESULT", "")
    # The health evaluator's own step outcome (issue #331). Absent/empty is a no-op in BOTH
    # directions — see decide_health.
    health = os.environ.get(HEALTH_OUTCOME_ENV, "")
    run_url = os.environ.get("RUN_URL", "")
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")

    # --limit 100: the `ops-alert` label is SHARED with the plan-failure alert, the
    # account-availability alert, and anything else ops-flavoured; a 20-issue window could push
    # these alerts out of the dedupe scan (duplicate on failure, uncloseable on recovery). 100
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

    # (1) the hard GROOM-JOB failure (issue #176).
    num = _find_open(found, ALERT_MARKER, ALERT_TITLE)
    rc = _apply(
        decide(result, num is not None), num, repo, token, ALERT_TITLE,
        _render_body(result, run_url, maintainer),
        "✅ Recovered — the scheduled GROOM job succeeded again. Auto-closing.",
        "GROOM job {}".format(result or "unknown"))
    # (2) the health EVALUATOR STEP failing under a green job (issue #331). Evaluated on every tick
    # regardless of what (1) did: the two conditions are independent, and the whole defect being
    # fixed is that a green job result hides this one.
    health_num = _find_open(found, HEALTH_MARKER, HEALTH_TITLE)
    rc |= _apply(
        decide_health(health, health_num is not None), health_num, repo, token, HEALTH_TITLE,
        _render_health_body(health, run_url, maintainer),
        "✅ Recovered — the GROOM model-access health evaluator completed again. Auto-closing.",
        "GROOM health-evaluator step {}".format(health or "unknown"))
    return rc


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
    # decide_health(): THE issue #331 case — the evaluator step outcome, which the job result
    # cannot carry because that step is continue-on-error.
    chk("decide_health: step failure -> upsert (the job is GREEN; this is the whole defect)",
        decide_health("failure", False), "upsert")
    chk("decide_health: step failure w/ open -> upsert", decide_health("failure", True), "upsert")
    chk("decide_health: step success + open -> close", decide_health("success", True), "close")
    chk("decide_health: step success + none -> noop", decide_health("success", False), "noop")
    chk("decide_health: SKIPPED + open -> noop (an earlier step failed; not a recovery, and the "
        "result-keyed alarm already covers that tick)", decide_health("skipped", True), "noop")
    chk("decide_health: cancelled + open -> noop (needs.groom.result is cancelled too, so decide() "
        "already pages — no double-page for one event)", decide_health("cancelled", True), "noop")
    chk("decide_health: cancelled + none -> noop", decide_health("cancelled", False), "noop")
    chk("decide_health: MISSING outcome + open -> noop (absence of evidence never closes)",
        decide_health("", True), "noop")
    chk("decide_health: MISSING outcome + none -> noop (and never pages)",
        decide_health("", False), "noop")
    # body: run link + maintainer mention, no secrets/handles by construction
    body = _render_body("failure", "https://example.test/run/1", "jeswr")
    chk("body carries run url + mention",
        ("https://example.test/run/1" in body, "@jeswr" in body), (True, True))
    # every rendered body must carry the stable dedupe marker.
    chk("body carries the stable dedupe marker", ALERT_MARKER in body, True)
    health_body = _render_health_body("failure", "https://example.test/run/2", "jeswr")
    chk("health body carries run url + mention + its OWN dedupe marker",
        ("https://example.test/run/2" in health_body, "@jeswr" in health_body,
         HEALTH_MARKER in health_body), (True, True, True))
    # The two markers/titles must be DISTINCT, or the conditions collide: one would edit the
    # other's issue and a single recovery would close both.
    chk("the two alerts are distinguishable (distinct markers AND titles)",
        (HEALTH_MARKER == ALERT_MARKER, HEALTH_TITLE == ALERT_TITLE, ALERT_MARKER in health_body),
        (False, False, False))
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

    def find_with(sub, needle):
        """The first `sub` call whose command CONTAINS `needle` — the two conditions issue the same
        gh subcommands, so every per-condition assertion below matches on the alert's own title."""
        return next(((c, e) for c, e in calls
                     if tuple(c[1:3]) == sub and any(needle in str(a) for a in c)), (None, None))

    real_run = subprocess.run
    base_env = {"REGISTRY_REPO": "org/registry", "GROOM_RESULT": "", HEALTH_OUTCOME_ENV: "",
                "RUN_URL": "u", "MAINTAINER_HANDLE": "m", "ALERT_REPO": "", "ALERT_TOKEN": ""}

    def run_main(groom_result, list_json="[]", fail=(), alert_repo="", alert_token="", health=""):
        calls.clear()
        responses.clear()
        responses[("issue", "list")] = _Result(1 if ("issue", "list") in fail else 0, list_json)
        for key in fail:
            if key != ("issue", "list"):
                responses[key] = _Result(1)
        os.environ.update(base_env)
        os.environ["GROOM_RESULT"] = groom_result
        os.environ[HEALTH_OUTCOME_ENV] = health
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

        # ---- issue #331: the crashing evaluator under a GREEN job ---------------------------
        # THE regression test. Before this change the tick below was completely silent: the step
        # is continue-on-error, so GROOM_RESULT is `success` and decide() alone says "noop".
        rc_p, out_p = run_main("success", health="failure")
        create_p, _ = find_with(("issue", "create"), HEALTH_TITLE)
        chk("flow #331: GREEN job + FAILED health step -> creates the health alert, warns, and "
            "touches nothing belonging to the job alert",
            (rc_p, create_p is not None, "::warning::" in out_p,
             find_with(("issue", "create"), ALERT_TITLE)[0] is not None),
            (0, True, True, False))
        # ...and it is filed with the HEALTH body: the wrong body would carry the wrong marker, so
        # the next tick could neither dedupe it nor close it on recovery.
        body_p = (create_p or [])[(create_p or []).index("--body") + 1] if create_p else ""
        chk("flow #331: the created alert carries the HEALTH body/marker, not the job alert's",
            (HEALTH_MARKER in body_p, ALERT_MARKER in body_p, "health" in body_p),
            (True, False, True))
        health_open = json.dumps([{"number": 21, "title": "renamed by a human",
                                   "body": "prose\n" + HEALTH_MARKER}])
        rc_q, _ = run_main("success", health_open, health="failure")
        edit_q, _ = find_with(("issue", "edit"), "21")
        chk("flow #331: FAILED health step + open (renamed) health alert -> marker match edits "
            "#21, no duplicate",
            (rc_q, edit_q is not None, ("issue", "create") in subs()), (0, True, False))
        rc_r, _ = run_main("success", health_open, health="success")
        close_r, _ = find_with(("issue", "close"), "21")
        chk("flow #331: health step SUCCEEDS + open health alert -> comment + close",
            (rc_r, ("issue", "comment") in subs(), close_r is not None), (0, True, True))
        rc_s, _ = run_main("failure", health_open, health="skipped")
        chk("flow #331: a hard GROOM failure SKIPS the evaluator -> the open health alert is left "
            "ALONE (no close, no second page) while the job alert is filed",
            (rc_s, find_with(("issue", "close"), "21")[0] is not None,
             find_with(("issue", "edit"), "21")[0] is not None,
             find_with(("issue", "create"), ALERT_TITLE)[0] is not None),
            (0, False, False, True))
        rc_t, _ = run_main("failure", health="failure")
        chk("flow #331: BOTH conditions -> two distinct alerts, one per condition",
            (rc_t, find_with(("issue", "create"), ALERT_TITLE)[0] is not None,
             find_with(("issue", "create"), HEALTH_TITLE)[0] is not None),
            (0, True, True))
        rc_u, _ = run_main("success", health="success")
        chk("flow #331: a fully healthy tick with nothing open stays side-effect-free (one bare "
            "list, no mutations)",
            (rc_u, subs()), (0, [("issue", "list")]))
        rc_v, out_v = run_main("success", fail=(("issue", "create"),), health="failure")
        chk("flow #331: the health alert's create failure fails the run",
            (rc_v, "::warning::" in out_v), (1, True))
        rc_w, _ = run_main("failure", fail=(("issue", "create"),), health="failure")
        chk("flow #331: a failed job-alert mutation does NOT suppress the health condition — both "
            "are still attempted and the run is red",
            (rc_w, len([s for s in subs() if s == ("issue", "create")])), (1, 2))
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

    _test_workflow_seam(chk)
    # GUARD on the seam's own fail-closed handler. A seam section that SKIPS when its input is
    # missing is worse than no seam at all — a trimmed sparse-checkout would then read as green
    # forever. Drive the whole block against an unreadable workflow (recording its rows instead of
    # scoring them) and require exactly one row, failing.
    global WORKFLOW
    real_workflow = WORKFLOW
    rows = []
    try:
        WORKFLOW = ".github/workflows/no-such-workflow.yml"
        _test_workflow_seam(lambda name, got, want: rows.append((name, got == want)))
    finally:
        WORKFLOW = real_workflow
    chk("seam guard: an unreadable groom.yml yields a FAIL row, never a silent skip",
        (len(rows), all(passed for _name, passed in rows)), (1, False))
    print("groom-alert self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def _test_workflow_seam(chk):
    """THE YAML SEAM. The measured lesson of this estate is that the uncaught mutants live one
    level ABOVE the Python — a dropped `id:`, a deleted job output, a removed env line, an `if:`
    that suppresses the alert job. None of those is visible to a single check above: main() would
    keep passing with GROOM_HEALTH_OUTCOME permanently empty, decide_health() would keep returning
    'noop', and the #331 alarm would be silently disarmed on exactly the tick it exists for.

    Line-scanning, NOT PyYAML, on purpose: the `groom-alert` job installs no dependencies (only the
    watchdog jobs do), so a parser import would make this whole section unrunnable where it must
    run. Every match is ANCHORED on its exact key indentation and evaluated COMMENT-BLIND, and the
    whole block fails CLOSED — anything unlocatable is a FAIL, never a silent skip."""
    try:
        lines = (Path(__file__).resolve().parent.parent / WORKFLOW).read_text(
            encoding="utf-8").splitlines()

        def job_block(name):
            start = lines.index(f"  {name}:")
            end = next((i for i in range(start + 1, len(lines))
                        if re.match(r"^  [A-Za-z]", lines[i])), len(lines))
            return lines[start:end]

        def code(block):
            # COMMENT-BLIND: the rationale comments around these steps QUOTE the very expressions
            # asserted here, so a commented-out `# id: health` must never read as real wiring.
            return [line for line in block if not line.lstrip().startswith("#")]

        def steps(block):
            starts = [i for i, line in enumerate(block) if re.match(r"^ {6}- name:", line)]
            return [block[s:(starts + [len(block)])[p + 1]] for p, s in enumerate(starts)]

        def has(block, pattern):
            return any(re.fullmatch(pattern, line) for line in code(block))

        groom = job_block("groom")
        alert = job_block("groom-alert")

        # (1) THE PRODUCER: the evaluator step is identified, and its OUTCOME leaves the job.
        health_steps = [s for s in steps(groom) if has(s, r" {8}id: health")]
        chk("seam: exactly one step in the `groom` job carries `id: health`",
            len(health_steps), 1)
        health_step = health_steps[0] if health_steps else []
        chk("seam: ...and it IS the model-health evaluator (an id moved onto a different step "
            "would key the alarm on an unrelated outcome)",
            any("model-health.py decide" in line for line in code(health_step)), True)
        chk("seam: ...which is continue-on-error, i.e. its failure genuinely does NOT reach "
            "needs.groom.result — the precondition this whole alarm exists for",
            has(health_step, r" {8}continue-on-error: true"), True)
        chk("seam: the `groom` job publishes that step's OUTCOME (the pre-continue-on-error "
            "result) as a job output — delete this and the alarm is silently disarmed",
            (has(groom, r" {4}outputs:"),
             has(groom, r" {6}health_outcome: \$\{\{ steps\.health\.outcome \}\}")),
            (True, True))

        # (2) THE CONSUMER: the alert job runs at all, and both signals reach this script.
        chk("seam: the alert job keys on the groom job and is gated EXACTLY on always() — under "
            "GitHub's implicit success() a failing GROOM would silence its own alarm",
            (has(alert, r" {4}needs: \[groom\]"), has(alert, r" {4}if: \$\{\{ always\(\) \}\}")),
            (True, True))
        def invocations(step):
            # EXECUTABLE lines only — a `sparse-checkout:` path or a comment naming this script is
            # not a call site (comments are already stripped by code()).
            return [line.strip() for line in code(step)
                    if line.strip().startswith("python3 ") and "groom-alert.py" in line]

        alert_steps = [s for s in steps(alert) if invocations(s)]
        chk("seam: exactly one step invokes this script, and it runs the self-test FIRST, then "
            "the live alert",
            (len(alert_steps), invocations(alert_steps[0] if alert_steps else [])),
            (1, ["python3 registry/scripts/groom-alert.py --self-test",
                 "python3 registry/scripts/groom-alert.py"]))
        call = alert_steps[0] if alert_steps else []
        chk("seam: BOTH signals reach the script — the job result AND the health step's outcome. "
            "A missing GROOM_HEALTH_OUTCOME line reads as an empty outcome, which decide_health "
            "treats as a permanent no-op: the exact silent failure of issue #331",
            (has(call, r" {10}GROOM_RESULT: \$\{\{ needs\.groom\.result \}\}"),
             has(call, " {10}" + re.escape(HEALTH_OUTCOME_ENV)
                 + r": \$\{\{ needs\.groom\.outputs\.health_outcome \}\}")),
            (True, True))

        # (3) THE INPUTS: this seam section must be REACHABLE on the live path. The alert job
        # sparse-checks-out only what it lists, so a trimmed list would make every assertion above
        # unrunnable in production while the gate's full checkout stayed green.
        sparse = [line.strip() for line in code(alert) if re.match(r"^ {12}\S+$", line)]
        chk("inputs: the alert job sparse-checks-out every file this --self-test asserts against",
            sorted(set(REQUIRED_FILES) - set(sparse)), [])
        chk("inputs: ...with no persisted token and no cone mode (the pinned-checkout posture)",
            (has(alert, r" {10}persist-credentials: false"),
             has(alert, r" {10}sparse-checkout-cone-mode: false")), (True, True))
    except Exception as exc:                       # noqa: BLE001 - fail CLOSED, never skip
        chk(f"seam: groom.yml health-evaluator wiring is inspectable "
            f"({type(exc).__name__}: {exc})", False, True)


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
