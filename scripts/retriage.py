#!/usr/bin/env python3
# Registry self-management: the SCHEDULED re-triage sweep + its rolling failure alert for
# jeswr/agent-account-registry (issue #178). Applied by .github/workflows/retriage.yml.
"""retriage.py — re-run static triage on open issues that label-only events missed.

.github/workflows/triage-issue.yml fires ONLY on issues.{opened,edited,reopened}; a LABEL change
never re-runs it. So an issue that is `status:untriaged` only because it was still missing a
priority/area/role, an issue whose `needs:design` design-hold a human has just cleared, or an issue
that somehow lost `status:ready`, stays permanently outside the dispatch frontier — ready-issues.py
requires the POSITIVE `status:ready` attestation, which nothing re-sets on a bare label edit. This
scheduled sweep closes that gap: it recomputes scripts/triage.py's deterministic, no-LLM verdict for
every open issue and applies ONLY the drift — promoting a now-complete issue to `status:ready` and
re-parking a regressed one.

FAIL-CLOSED, identical trust posture to triage-issue.yml: an issue already carrying
`trust:untrusted` is a no-op (triage() never inspects quarantined content), and this sweep NEVER
re-derives author trust nor un-quarantines — it only re-applies the deterministic label verdict to
already-admitted issues. It reuses scripts/triage.py's own triage() (never a private copy of the
rules) with the same `--type task` triage-issue.yml passes, so retriage can never disagree with what
an edit event would have produced for the same labels.

--alert mode is the rolling ops-alert for a FAILED scheduled run (mirrors plan-alert.py, issue #38):
a silently failing retriage cron re-strands every label-changed issue while presenting only as a
skipped/red job on a cron nobody watches, so a standalone alert job keys on the retriage job result
and upserts/auto-closes ONE rolling `ops-alert` issue @-mentioning the maintainer.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

# Rolling failure-alert identity. The ops-alert label is SHARED with the dispatch/usage alerts, so
# dedupe keys on the stable body MARKER (survives a human retitling the issue) and falls back to the
# exact title only for a hypothetical pre-marker alert — same discipline as plan-alert.py.
ALERT_LABEL = "ops-alert"
ALERT_TITLE = "⚠️ Scheduled re-triage sweep is failing — label-changed issues are stranded"
ALERT_MARKER = "<!-- retriage-alert:v1 key=retriage-sweep-failure -->"


def _load_triage():
    """Import the sibling scripts/triage.py by path so retriage always applies triage.py's LIVE
    rules (never a drifting private copy). triage.py has no import-time side effects."""
    path = Path(__file__).resolve().parent / "triage.py"
    spec = importlib.util.spec_from_file_location("registry_triage", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---- pure sweep logic (unit-tested by --self-test) -----------------------------------------------
def _label_names(issue):
    return [lb["name"] if isinstance(lb, dict) else lb for lb in issue.get("labels", [])]


def plan(issues, triage_fn, issue_type="task"):
    """PURE re-triage drift. For every OPEN issue recompute triage_fn(labels, type) — which already
    returns only the ADD/REMOVE drift and no-ops a trust:untrusted issue — and keep the ones whose
    verdict is non-empty. Returns [{number, add:[sorted], remove:[sorted]}] in input order (so a
    higher-priority board position is not implied — triage is per-issue and order-independent)."""
    out = []
    for it in issues:
        if str(it.get("state", "OPEN")).upper() != "OPEN":
            continue
        verdict = triage_fn(_label_names(it), issue_type)
        add = sorted(verdict["add"])
        remove = sorted(verdict["remove"])
        if add or remove:
            out.append({"number": it.get("number"), "add": add, "remove": remove})
    return out


# ---- GitHub I/O ----------------------------------------------------------------------------------
def _gh(args, capture=False, token=None):
    """Sanitized gh wrapper: on the failure paths callers surface op + returncode only, never
    stderr (GH_DEBUG=api can echo request bodies) and never remote/user-controlled payloads."""
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    return subprocess.run(["gh"] + args, capture_output=capture, text=True, env=env)


def _flatten_pages(pages):
    """Flatten `gh api --paginate --slurp` output (a list of pages), dropping PRs — mirrors
    ready-issues.py so the two readers treat the issue stream identically."""
    return [i for page in pages for i in (page if isinstance(page, list) else [])
            if isinstance(i, dict) and "pull_request" not in i]


def _fetch(repo, ceiling=10000):
    """Open-issue snapshot via REAL cursor pagination; the explicit ceiling fails closed on a
    runaway snapshot (a partial page must never look like the whole board)."""
    out = subprocess.run(
        ["gh", "api", "--paginate", "--slurp",
         f"repos/{repo}/issues?state=open&per_page=100"],
        capture_output=True, text=True, check=True).stdout
    raw = _flatten_pages(json.loads(out or "[]"))
    if len(raw) >= ceiling:
        raise SystemExit(f"refusing: fetched {len(raw)} >= ceiling {ceiling} — snapshot looks "
                         "runaway (fail-closed).")
    return [{"number": i.get("number"), "state": i.get("state", "open"),
             "labels": _label_names(i)} for i in raw]


def apply(repo, planned, gh=_gh):
    """Apply each planned re-triage as a single `gh issue edit` with the add/remove label flags.
    Fail-LOUD: a failed edit warns (sanitized) and forces a non-zero return so the job goes red and
    the rolling alert fires; the remaining issues are still processed (one flaky edit never strands
    the rest of the board)."""
    rc = 0
    for entry in planned:
        num = entry["number"]
        args = ["issue", "edit", str(num), "-R", repo]
        for lb in entry["add"]:
            args += ["--add-label", lb]
        for lb in entry["remove"]:
            args += ["--remove-label", lb]
        result = gh(args, capture=True)
        if result.returncode != 0:
            print(f"::warning::retriage: gh issue edit #{num} failed (rc={result.returncode})")
            rc = 1
        else:
            print(f"retriage: #{num} add={entry['add']} remove={entry['remove']}")
    return rc


def run_sweep(repo, dry_run=False):
    triage_module = _load_triage()
    planned = plan(_fetch(repo), triage_module.triage)
    if dry_run:
        for entry in planned:
            print(f"#{entry['number']}  add={entry['add']}  remove={entry['remove']}")
        print(f"retriage: {len(planned)} issue(s) would change (dry-run)")
        return 0
    if not planned:
        print("retriage: no drift — every open issue already matches triage")
        return 0
    rc = apply(repo, planned)
    print(f"retriage: re-triaged {len(planned)} issue(s)")
    return rc


# ---- rolling failure alert (mirrors plan-alert.py) -----------------------------------------------
def _alert_route(alert_repo, alert_token, registry_repo):
    """(repo, token) for the alert issue — same semantics as plan-alert.py/usage-alert.py's router:
    the private ALERT_REPO is the destination ONLY when ALERT_TOKEN can write there; otherwise the
    registry repo under the ambient token (token=None). The retriage-failure body carries NO account
    handles, so the fallback needs no redaction variant."""
    if alert_repo and alert_token:
        return alert_repo, alert_token
    return registry_repo, None


def alert_step_fails_loud(workflow_text):
    """Pure fail-CLOSED workflow assertion (review round 1): True iff the retriage workflow's
    `alert` job has a step invoking `--alert` and NO such step carries a `continue-on-error`
    other than an explicit false — GitHub would otherwise convert run_alert()'s fail-loud
    nonzero exits into a green scheduled run, the exact silent-cron failure mode this job
    closes. Deliberately dependency-free (same rationale as dispatch-secrets-guard.py's
    workflow parser — the gate host and runner image need not share a PyYAML install): a
    NARROW line parser over the two/six-space-indented block this repo controls, not a general
    YAML reader. Any failure to locate the job or an --alert step returns False."""
    lines = workflow_text.splitlines()
    try:
        start = lines.index("  alert:")
    except ValueError:
        return False
    steps, current = [], None
    for line in lines[start + 1:]:
        stripped = line.split("#", 1)[0].rstrip()
        if not stripped.strip():
            continue
        if not line.startswith("    "):
            break  # dedented out of the alert job
        if line.startswith("      - "):  # a new step (exact step-list indent)
            current = []
            steps.append(current)
        if current is not None:
            entry = stripped.strip()
            current.append(entry[2:] if entry.startswith("- ") else entry)
    alert_steps = [s for s in steps if any("--alert" in ln for ln in s)]
    if not alert_steps:
        return False
    for step in alert_steps:
        for ln in step:
            key, sep, value = ln.partition(":")
            if sep and key.strip() == "continue-on-error" and value.strip() != "false":
                return False
    return True


def decide(result, has_open_alert):
    """Pure decision: 'upsert' | 'close' | 'noop'. Upsert on failure/cancelled; close ONLY on an
    explicit success with an alert open (a `skipped` retriage is not a recovery — the alert must
    survive it); anything else is a no-op."""
    if result in ("failure", "cancelled"):
        return "upsert"
    if result == "success" and has_open_alert:
        return "close"
    return "noop"


def _render_body(result, run_url, maintainer):
    return (
        f"{ALERT_MARKER}\n"
        "> 🤖 SPARQ agent — automated ops-alert (issue #178)\n\n"
        f"@{maintainer} the scheduled **retriage** sweep ended `{result}`. While it is down, a "
        "label change never re-runs triage, so any issue whose missing priority/area/role was just "
        "supplied — or whose `needs:design` hold was just cleared — stays `status:untriaged` and "
        "**outside the dispatch frontier**.\n\n"
        "Check the run below; the next scheduled tick retries automatically and this alert "
        "auto-closes once a retriage run succeeds.\n\n"
        f"- Failing run: {run_url}\n"
    )


def run_alert():
    registry_repo = os.environ["REGISTRY_REPO"]
    repo, token = _alert_route(
        os.environ.get("ALERT_REPO"), os.environ.get("ALERT_TOKEN"), registry_repo)
    result = os.environ.get("RETRIAGE_RESULT", "")
    run_url = os.environ.get("RUN_URL", "")
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")

    # --limit 100: the ops-alert label is shared, so a small window could push this alert out of the
    # dedupe scan (duplicate on failure, uncloseable on recovery).
    listed = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", "open",
                  "--json", "number,title,body", "--limit", "100"], capture=True, token=token)
    if listed.returncode != 0:
        # Fail loud: without the list we can neither dedupe an upsert nor prove recovery.
        print(f"::warning::retriage-alert: gh issue list failed (rc={listed.returncode})")
        return 1
    try:
        found = json.loads(listed.stdout or "[]")
        if not isinstance(found, list):
            raise ValueError("expected a JSON array")
    except ValueError:  # json.JSONDecodeError is a ValueError
        # A successful gh call can still hand back malformed JSON (truncation, an HTML error page).
        # Degrade — never crash the alert or echo the remote payload — and retry next tick.
        print("::warning::retriage-alert: gh issue list returned unparseable JSON — skipping this "
              "tick (no dedupe/recovery data; next tick retries)")
        return 0
    num = next((i["number"] for i in found if ALERT_MARKER in (i.get("body") or "")), None)
    if num is None:
        num = next((i["number"] for i in found if i.get("title") == ALERT_TITLE), None)

    action = decide(result, num is not None)
    if action == "upsert":
        _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", "d73a4a",
             "--description", "Autonomous ops alert (maintainer action)"],
            capture=True, token=token)  # idempotent; a pre-existing label is fine
        body = _render_body(result, run_url, maintainer)
        if num:
            wrote = _gh(["issue", "edit", str(num), "-R", repo, "--body", body],
                        capture=True, token=token)
        else:
            wrote = _gh(["issue", "create", "-R", repo, "--title", ALERT_TITLE,
                         "--label", ALERT_LABEL, "--body", body], capture=True, token=token)
        if wrote.returncode != 0:
            print(f"::warning::retriage-alert: alert upsert failed (rc={wrote.returncode})")
            return 1
        print(f"::warning::retriage-alert: retriage sweep {result} — maintainer alerted")
        return 0
    if action == "close":
        commented = _gh(["issue", "comment", str(num), "-R", repo, "--body",
                         "✅ Recovered — the scheduled retriage sweep succeeded again. "
                         "Auto-closing."], capture=True, token=token)
        closed = _gh(["issue", "close", str(num), "-R", repo], capture=True, token=token)
        if commented.returncode != 0 or closed.returncode != 0:
            print("::warning::retriage-alert: alert recovery close failed")
            return 1
        print("retriage-alert: retriage recovered — closed the alert")
        return 0
    print(f"retriage-alert: retriage result={result or 'unknown'} — nothing to do")
    return 0


# ---- self-test -----------------------------------------------------------------------------------
def _self_test():
    ok = True

    def chk(n, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {n}: {got} (want {want})")

    # plan() is exercised against the REAL scripts/triage.py verdict (never a stub), so the sweep
    # can never silently drift from the triage rules it claims to re-run.
    triage_module = _load_triage()

    def iss(n, labels, state="OPEN"):
        return {"number": n, "state": state, "labels": labels}

    fixtures = [
        # 1) untriaged only because an edit-less label add completed it -> PROMOTE to ready.
        iss(1, ["status:untriaged", "priority:P2", "role:impl", "area:usage"]),
        # 2) already ready + consistent -> no drift, left untouched.
        iss(2, ["status:ready", "priority:P2", "role:impl", "area:usage"]),
        # 3) trust:untrusted, even with an otherwise-complete set -> no-op (content never inspected).
        iss(3, ["status:untriaged", "priority:P2", "role:impl", "area:usage", "trust:untrusted"]),
        # 4) still design-held AND already correctly untriaged -> NOT promoted, no drift.
        iss(4, ["status:untriaged", "priority:P2", "role:impl", "area:usage", "needs:design"]),
        # 5) regressed: carried status:ready but lost its priority -> RE-PARK to untriaged.
        iss(5, ["status:ready", "role:impl", "area:usage"]),
        # 6) closed issue -> skipped entirely.
        iss(6, ["status:untriaged", "priority:P2", "role:impl", "area:usage"], state="CLOSED"),
    ]
    planned = plan(fixtures, triage_module.triage)
    by_num = {e["number"]: e for e in planned}
    chk("plan touches only 1 and 5", [e["number"] for e in planned], [1, 5])
    chk("promote: #1 add status:ready / remove status:untriaged",
        (by_num.get(1, {}).get("add"), by_num.get(1, {}).get("remove")),
        (["status:ready"], ["status:untriaged"]))
    chk("regress: #5 add status:untriaged / remove status:ready",
        (by_num.get(5, {}).get("add"), by_num.get(5, {}).get("remove")),
        (["status:untriaged"], ["status:ready"]))
    chk("consistent ready #2 untouched", 2 in by_num, False)
    chk("untrusted #3 no-op", 3 in by_num, False)
    chk("design-held #4 not promoted", 4 in by_num, False)
    chk("closed #6 skipped", 6 in by_num, False)

    # apply(): a stub gh records argv; the exact --add-label/--remove-label wiring is asserted, and a
    # failing edit forces rc=1 (fail loud) while the sweep still processes the rest.
    class _R:
        def __init__(self, rc=0):
            self.returncode = rc
            self.stdout = ""
            self.stderr = "SENTINEL-STDERR"

    calls = []

    def fake_gh(args, capture=False, token=None):
        calls.append(list(args))
        # fail the edit for issue #5 only, to prove partial-failure isolation + rc propagation.
        return _R(1 if ("5" in args) else 0)

    calls.clear()
    rc_apply = apply("o/r", planned, gh=fake_gh)
    chk("apply: #1 issue-edit argv wired",
        calls[0], ["issue", "edit", "1", "-R", "o/r",
                   "--add-label", "status:ready", "--remove-label", "status:untriaged"])
    chk("apply: every planned issue is edited", [c[2] for c in calls], ["1", "5"])
    chk("apply: a failed edit forces rc=1 (fail loud)", rc_apply, 1)
    calls.clear()
    chk("apply: empty plan makes no gh call + rc=0", (apply("o/r", [], gh=fake_gh), calls), (0, []))

    # Workflow fail-loud assertion — both directions on synthetic YAML, then the LIVE file (same
    # discipline as dispatch-secrets-guard.py's static permission check): re-masking the --alert
    # step with continue-on-error must go red HERE, not silently green the alerting outage.
    def wf(extra=""):
        return ("jobs:\n  alert:\n    steps:\n"
                "      - name: self-test\n        run: python3 scripts/retriage.py --self-test\n"
                "      - name: alert\n" + extra +
                "        run: python3 scripts/retriage.py --alert\n")

    chk("workflow: unmasked --alert step accepted", alert_step_fails_loud(wf()), True)
    chk("workflow: continue-on-error on the --alert step rejected",
        alert_step_fails_loud(wf("        continue-on-error: true\n")), False)
    chk("workflow: explicit continue-on-error false still accepted",
        alert_step_fails_loud(wf("        continue-on-error: false\n")), True)
    chk("workflow: missing --alert step rejected (fail closed)",
        alert_step_fails_loud("jobs:\n  alert:\n    steps:\n      - run: 'true'\n"), False)
    chk("workflow: no alert job at all rejected (fail closed)", alert_step_fails_loud("{"), False)
    workflow_path = (Path(__file__).resolve().parent.parent
                     / ".github" / "workflows" / "retriage.yml")
    try:
        live_text = workflow_path.read_text(encoding="utf-8")
    except OSError:
        live_text = ""
    chk("workflow: LIVE retriage.yml alert step fails loud", alert_step_fails_loud(live_text), True)

    # decide()/route() — same audited matrix as plan-alert.py.
    chk("route: repo+token -> private", _alert_route("o/p", "t", "o/r"), ("o/p", "t"))
    chk("route: repo, no token -> registry fallback", _alert_route("o/p", "", "o/r"), ("o/r", None))
    chk("route: no repo -> registry", _alert_route("", "t", "o/r"), ("o/r", None))
    chk("decide: failure -> upsert", decide("failure", False), "upsert")
    chk("decide: cancelled -> upsert", decide("cancelled", True), "upsert")
    chk("decide: success + open -> close", decide("success", True), "close")
    chk("decide: success + none -> noop", decide("success", False), "noop")
    chk("decide: SKIPPED + open -> noop (not a recovery)", decide("skipped", True), "noop")
    body = _render_body("failure", "https://example.test/run/1", "jeswr")
    chk("body: run url + mention + stable marker",
        ("https://example.test/run/1" in body, "@jeswr" in body, ALERT_MARKER in body),
        (True, True, True))

    # run_alert(): stubbed-gh flow — the full upsert/edit/close/skip paths and rc propagation.
    import contextlib
    import io

    responses = {}
    acalls = []

    def fake_run(cmd, capture_output=False, text=False, env=None):
        acalls.append(list(cmd))
        return responses.get(tuple(cmd[1:3]), _R())

    def subs():
        return [tuple(c[1:3]) for c in acalls]

    real_run = subprocess.run
    base_env = {"REGISTRY_REPO": "o/r", "RETRIAGE_RESULT": "", "RUN_URL": "u",
                "MAINTAINER_HANDLE": "m", "ALERT_REPO": "", "ALERT_TOKEN": ""}

    def run_alert_with(result, list_json="[]", fail=()):
        acalls.clear()
        responses.clear()
        responses[("issue", "list")] = _RJson(1 if ("issue", "list") in fail else 0, list_json)
        for key in fail:
            if key != ("issue", "list"):
                responses[key] = _R(1)
        os.environ.update(base_env)
        os.environ["RETRIAGE_RESULT"] = result
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run_alert()
        return rc, buf.getvalue()

    class _RJson(_R):
        def __init__(self, rc, stdout):
            super().__init__(rc)
            self.stdout = stdout

    subprocess.run = fake_run
    try:
        rc_a, _ = run_alert_with("failure")
        chk("alert: failure + none -> create", (rc_a, ("issue", "create") in subs()), (0, True))
        open_json = json.dumps([{"number": 7, "title": ALERT_TITLE}])
        rc_b, _ = run_alert_with("failure", open_json)
        chk("alert: failure + open -> edit not create",
            (rc_b, ("issue", "edit") in subs(), ("issue", "create") in subs()), (0, True, False))
        rc_c, _ = run_alert_with("success", open_json)
        chk("alert: success + open -> comment+close",
            (rc_c, ("issue", "comment") in subs(), ("issue", "close") in subs()), (0, True, True))
        rc_d, _ = run_alert_with("skipped", open_json)
        chk("alert: skipped + open -> no mutation",
            (rc_d, [s for s in subs() if s != ("issue", "list")]), (0, []))
        rc_e, out_e = run_alert_with("failure", fail=(("issue", "list"),))
        chk("alert: list failure -> rc=1 + sanitized warning (no stderr echoed)",
            (rc_e, "::warning::" in out_e, "SENTINEL-STDERR" in out_e), (1, True, False))
        rc_f, out_f = run_alert_with("failure", "NOT-JSON {")
        chk("alert: malformed list JSON -> graceful skip, payload not echoed",
            (rc_f, "::warning::" in out_f, "NOT-JSON" in out_f,
             [s for s in subs() if s != ("issue", "list")]), (0, True, False, []))
        rc_g, _ = run_alert_with("failure", open_json, fail=(("issue", "edit"),))
        chk("alert: upsert edit failure -> rc=1", rc_g, 1)
    finally:
        subprocess.run = real_run
        for key in base_env:
            os.environ.pop(key, None)

    print("retriage self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="jeswr/agent-account-registry")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--dry-run", action="store_true",
                    help="compute + print the re-triage plan without applying any label change")
    ap.add_argument("--alert", action="store_true",
                    help="rolling ops-alert mode: upsert/close on the retriage job RESULT")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()
    if args.alert:
        return run_alert()
    return run_sweep(args.repo, dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
