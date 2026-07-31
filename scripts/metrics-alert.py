#!/usr/bin/env python3
# [OPUS-5] WATCH THE WATCHER — the metrics cron is the one workflow in the estate with no watchdog.
#
# MEASURED job census across the crons that carry an alert leg:
#   dispatch.yml = {plan, secrets-guard, claim, plan-alert}
#   groom.yml    = {groom, groom-alert}
#   metrics.yml  = {metrics, dashboard-publish}   <-- NO alert job
# If the metrics job dies, ledger:data/metrics.json keeps its last good content, dashboard.yml keeps
# copying that content to site/metrics.json, and the published page renders a full snapshot with an
# EMPTY alert stack. Nothing is red. The dashboard looks healthier than it has ever looked. That is
# strictly worse than having no dashboard, because "no alerts" is indistinguishable from "the
# evaluator that raises alerts stopped running".
#
# This script is BOTH halves of the watchdog, because one half structurally cannot catch the other:
#
#   (A) JOB-FAILURE  (`python3 scripts/metrics-alert.py`, hosted in metrics.yml)
#       Keys on `needs.metrics.result`. Catches a metrics job that RAN and FAILED.
#
#   (B) STALENESS    (`python3 scripts/metrics-alert.py --stale-check`, hosted in groom.yml)
#       Keys on the age of ledger:data/metrics.json. Catches a metrics job that never ran at all —
#       which produces NO failed job for (A) to key on. A workflow cannot detect its own
#       non-execution, so this half MUST live on an independent schedule in a different workflow.
#       Delivery here is measurably imperfect: on the live ring at 2026-07-27T15:50Z, 24 snapshots
#       spanned 550.0 min => 23.91 min effective cadence against a */15 cron, with a 30.0 min worst
#       observed gap. STALE_THRESHOLD_SECONDS is set well clear of that (see the constant).
#
# The shape that matters is a RING, not a chain — a chain of watchers always terminates in an
# unwatched one. Live mesh, verified in the checked-in workflows:
#   metrics job FAILS          -> metrics.yml   `metrics-alert`   (A, this script)
#   metrics never RUNS         -> groom.yml     `metrics-stale`   (B, this script)
#   groom never RUNS           -> dashboard.yml `cron-keepalive`  (re-dispatches groom.yml at 1800s)
#   dashboard never RUNS       -> metrics.yml   `dashboard-publish` staleness fallback
# No participant is its own watcher. Honest residual: a SIMULTANEOUS stall of dashboard.yml AND
# groom.yml is unobserved; that is a strictly smaller hole than the one this unit closes.
#
# PAGING POLICY. This is one of only two things in the whole estate permitted to reach the
# maintainer, because it is the single failure that makes every OTHER signal invisible. Everything
# else terminates in an issue inside the pipeline. Both alerts auto-close on an explicit recovery.
#
# AUTHORITY. This script may create/edit/comment/close ONE `ops-alert` issue per marker and nothing
# else. It has no arming path, no merge path, no PR path, and — enforced by _test_no_hold_labels
# below rather than by convention — no code path that can write a `needs:`/`status:`/`role:` label.
# Its jobs carry `contents: read` + `issues: write` and nothing else.
#
# CEILING. Exactly TWO issues, ever: one per marker, deduped by hidden HTML marker, re-used across
# ticks. A tick with a healthy metrics job and a fresh snapshot does one bare `gh issue list` and
# exits (the groom-alert idiom). First-tick volume on today's live state: 0 — run 30279870348
# succeeded and the snapshot read 2026-07-27T15:50:13Z, ~0 min old.
#
# Mirrors scripts/groom-alert.py / scripts/plan-alert.py hardening exactly: _alert_route privacy
# routing, close-ONLY-on-explicit-success, sanitized fail-loud `gh` wrapper, and a soft-fail on a
# successful-but-malformed `gh issue list`.
#
# DEBT (issue #591): `_alert_route` is another private copy of the same locked decision (22c). The
# shared home `scripts/alert_route.py` now EXISTS on master with the IDENTICAL signature
# `(alert_repo, alert_token, registry_repo)` — #591 migrated the four emitters it named and stopped
# there, because this file's self-test cannot run where PyYAML is absent and an unverifiable
# migration of a live alerting path is not worth the swap. Discharging this is
# `_alert_route = <module>.alert_route` plus adding `scripts/alert_route.py` to BOTH sparse-checkout
# lists (groom.yml's metrics-stale job and metrics.yml's metrics-alert job), which alert_route.py's
# own census then enforces once this file is added to its CONSUMERS tuple.
import ast
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

ALERT_LABEL = "ops-alert"

# --- (A) the metrics JOB-FAILURE alert ------------------------------------------------------
JOB_ALERT_TITLE = "⚠️ Scheduled METRICS job is failing — every dashboard signal is now stale-blind"
# Dedupe keyed on the TITLE alone breaks the moment anyone (a human, or a later wording tweak)
# renames the open alert — the next failing tick files a duplicate and recovery cannot find the
# issue to close. The body carries this stable machine marker; dedupe matches the marker first and
# falls back to the exact title only for pre-marker legacy alerts.
JOB_ALERT_MARKER = "<!-- metrics-alert:v1 key=metrics-job-failure -->"

# --- (B) the SNAPSHOT-STALENESS alert -------------------------------------------------------
STALE_ALERT_TITLE = "⚠️ The metrics snapshot has gone STALE — the dashboard is serving a frozen picture"
STALE_ALERT_MARKER = "<!-- metrics-alert:v1 key=metrics-snapshot-stale -->"

# 75 minutes. NOT a tuning knob and deliberately NOT env-overridable: a threshold readable from the
# workflow is a second place to get it wrong, and this alert is permitted to page a human. Sizing,
# from the live ring at 2026-07-27T15:50Z (24 snapshots / 550.0 min): 3.1x the 23.91 min effective
# cadence and 2.5x the 30.0 min worst observed gap, i.e. roughly three consecutively missed
# deliveries. _test_threshold_vs_cadence asserts this stays >= 3 metrics cron periods AND that the
# host workflow fires at least as often as the threshold, so neither side can drift silently.
STALE_THRESHOLD_SECONDS = 75 * 60

# The published snapshot, relative to the checked-out ledger worktree. Cross-checked against
# scripts/metrics.py's own PUBLISHED_PATH in the self-test — if the collector's write path and this
# watchdog's read path ever diverge, the watchdog would page FOREVER on a file nothing updates,
# which is precisely the "paged for something that does not need it" failure the maintainer has
# complained about. That is why scripts/metrics.py is in both sparse-checkout lists.
SNAPSHOT_RELATIVE_PATH = "data/metrics.json"

# Every file the self-test asserts against. Both host jobs sparse-check-out exactly this set, and
# _test_selftest_inputs_are_checked_out asserts that they do — a trimmed checkout would make the
# YAML-seam assertions below silently unreachable in the live path, which is the exact fail-open
# class this unit exists to close.
REQUIRED_FILES = (
    "scripts/metrics-alert.py",
    "scripts/metrics.py",
    ".github/workflows/metrics.yml",
    ".github/workflows/groom.yml",
)

GENERATED_AT_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class MetricsAlertError(Exception):
    """A contract this script refuses to guess about."""


def _alert_route(alert_repo, alert_token, registry_repo):
    """(repo, token) for the alert issue — locked decision 22c / issue #39, identical semantics and
    signature to scripts/alert_route.py's `alert_route` (see the DEBT note in the header): the
    private ALERT_REPO is the destination ONLY when ALERT_TOKEN can write there; a half-configured
    deployment (repo set, token missing) falls back to the registry repo under the ambient token
    (token=None means "use the ambient GH_TOKEN") instead of silently losing the alert."""
    if alert_repo and alert_token:
        return alert_repo, alert_token
    return registry_repo, None


# ---------------------------------------------------------------------------------------------
# (A) pure decision: the metrics JOB result
# ---------------------------------------------------------------------------------------------
def decide(metrics_result, has_open_alert):
    """'upsert' | 'close' | 'noop'. Upsert on failure/cancelled; close ONLY on an explicit success
    with an alert open — `needs.<job>.result` also permits `skipped`, which proves nothing about
    recovery, so an open alert must survive a skipped METRICS job."""
    if metrics_result in ("failure", "cancelled"):
        return "upsert"
    if metrics_result == "success" and has_open_alert:
        return "close"
    return "noop"


# ---------------------------------------------------------------------------------------------
# (B) pure decision: the published snapshot's AGE
# ---------------------------------------------------------------------------------------------
def read_generated_at(snapshot_text):
    """-> (epoch:int|None, reason:str). FAIL-CLOSED in the alerting direction.

    Every unreadable outcome — file absent, unparseable JSON, wrong top-level type, missing or
    malformed `generated_at` — returns epoch=None, which stale_verdict() treats as STALE. A metrics
    snapshot that cannot be read is at least as broken as one that is merely old, and the opposite
    polarity (unreadable => assume fresh) is how a watchdog goes quiet exactly when it is needed.

    The reason strings are FIXED. The snapshot is remote content written by another job; nothing
    derived from its bytes is ever returned here or rendered into an issue body."""
    if snapshot_text is None:
        return None, "the published snapshot file is missing from the ledger branch"
    try:
        parsed = json.loads(snapshot_text)
    except ValueError:  # json.JSONDecodeError is a ValueError
        return None, "the published snapshot is not parseable JSON"
    if not isinstance(parsed, dict):
        return None, "the published snapshot is not a JSON object"
    raw = parsed.get("generated_at")
    if not isinstance(raw, str) or not raw:
        return None, "the published snapshot carries no `generated_at` timestamp"
    try:
        stamp = datetime.strptime(raw, GENERATED_AT_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None, "the published snapshot's `generated_at` is not an RFC3339 UTC timestamp"
    return int(stamp.timestamp()), "ok"


def stale_verdict(epoch, reason, now, threshold=STALE_THRESHOLD_SECONDS):
    """-> ('stale'|'fresh', detail_reason, age_seconds|None).

    'fresh' is only ever returned for a timestamp that was actually PARSED and is inside the
    threshold, which is what makes closing a stale-alert on 'fresh' a real recovery signal rather
    than an absence of evidence.

    A snapshot stamped in the FUTURE (runner clock skew) reads as fresh rather than as an alert:
    the failure this watchdog exists for is under-delivery, and paging a human about a few seconds
    of clock skew is exactly the noise the paging policy forbids."""
    if epoch is None:
        return "stale", reason, None
    age = int(now) - int(epoch)
    if age > threshold:
        return "stale", "the published snapshot has not been refreshed", age
    return "fresh", "ok", age


def decide_stale(verdict, has_open_alert):
    """'upsert' | 'close' | 'noop' for the staleness alert."""
    if verdict == "stale":
        return "upsert"
    if verdict == "fresh" and has_open_alert:
        return "close"
    return "noop"


# ---------------------------------------------------------------------------------------------
# issue bodies — fixed templates over a closed set of machine-derived scalars. No account handle,
# no token, and no byte of the snapshot payload can reach either of these.
# ---------------------------------------------------------------------------------------------
def _render_job_body(result, run_url, maintainer):
    return (
        f"{JOB_ALERT_MARKER}\n"
        "> 🤖 SPARQ agent — automated ops-alert (watch the watcher)\n\n"
        f"@{maintainer} the scheduled **METRICS** job ended `{result}`.\n\n"
        "metrics.yml is the ONLY evaluator of the backlog-vs-drain alert rules and the ONLY writer "
        "of `ledger:data/metrics.json`. When it stops, the dashboard keeps serving the LAST GOOD "
        "snapshot with an EMPTY alert stack — so every other signal in the estate silently reads "
        "healthy. This alert is the only thing standing between that and a silent outage.\n\n"
        "The next scheduled tick retries automatically and this alert auto-closes once a METRICS "
        "job succeeds. Nothing here is armed, merged, or re-admitted by machine.\n\n"
        f"- Failing run: {run_url}\n"
    )


def _render_stale_body(reason, age_seconds, generated_at, run_url, workflow_url, maintainer):
    age = "unknown" if age_seconds is None else f"{age_seconds // 60} min"
    stamp = generated_at or "unreadable"
    return (
        f"{STALE_ALERT_MARKER}\n"
        "> 🤖 SPARQ agent — automated ops-alert (watch the watcher)\n\n"
        f"@{maintainer} the published metrics snapshot is **stale**: {reason}.\n\n"
        f"- Snapshot `generated_at`: `{stamp}`\n"
        f"- Age at check time: **{age}** (threshold {STALE_THRESHOLD_SECONDS // 60} min)\n"
        f"- Checked by: {run_url}\n"
        f"- The workflow that should be refreshing it: {workflow_url}\n\n"
        "A cron that silently UNDER-DELIVERS produces no failed job, so the job-failure alert "
        "cannot see this: a workflow cannot detect its own non-execution. This check therefore runs "
        "from a different workflow on an independent schedule.\n\n"
        "Until it clears, the dashboard is serving a FROZEN picture — an empty alert stack there "
        "means nothing. This alert auto-closes as soon as a fresh snapshot lands.\n"
    )


def _gh(args, capture=False, token=None, check=False, label="metrics-alert"):
    # Sanitized fail-loud wrapper: op + returncode only — never stderr (GH_DEBUG=api can echo
    # request bodies) and never argument content beyond the gh subcommand words.
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    result = subprocess.run(["gh"] + args, capture_output=capture, text=True, env=env)
    if check and result.returncode != 0:
        print(f"::warning::{label}: gh {args[0]} {args[1] if len(args) > 1 else ''} "
              f"failed (rc={result.returncode})")
    return result


def _find_open_alert(repo, token, marker, title, label):
    """-> (issue_number|None, hard_error:bool, soft_skip:bool).

    --limit 100: the `ops-alert` label is SHARED with the plan-failure alert, the groom-failure
    alert, the account-availability alert and anything else ops-flavoured; a 30-issue default window
    could push this alert out of the dedupe scan (duplicate on failure, uncloseable on recovery)."""
    listed = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", "open",
                  "--json", "number,title,body", "--limit", "100"],
                 capture=True, token=token, check=True, label=label)
    if listed.returncode != 0:
        # Fail loud: without the list we can neither dedupe an upsert nor prove recovery.
        return None, True, False
    # A SUCCESSFUL gh call can still hand back malformed JSON (truncated output, an HTML error page,
    # a proxy interposing). Degrade rather than crash: warn (sanitized — the payload is remote
    # content and is never echoed) and skip this tick; the next tick retries.
    try:
        found = json.loads(listed.stdout or "[]")
        if not isinstance(found, list):
            raise ValueError("expected a JSON array")
    except ValueError:
        print(f"::warning::{label}: gh issue list succeeded but returned unparseable JSON — "
              "skipping this tick (no dedupe/recovery data; next tick retries)")
        return None, False, True
    # Match the stable body MARKER first (survives a retitled alert), exact title second (legacy
    # alerts filed before the marker existed).
    num = next((i["number"] for i in found if marker in (i.get("body") or "")), None)
    if num is None:
        num = next((i["number"] for i in found if i.get("title") == title), None)
    return num, False, False


def _apply(action, repo, token, num, title, body, recovered_note, label):
    """Execute an upsert/close/noop. -> process exit code."""
    if action == "upsert":
        _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", "d73a4a",
             "--description", "Autonomous ops alert (maintainer action)"],
            capture=True, token=token, label=label)  # idempotent; a pre-existing label is fine
        if num:
            wrote = _gh(["issue", "edit", str(num), "-R", repo, "--body", body],
                        capture=True, token=token, check=True, label=label)
        else:
            wrote = _gh(["issue", "create", "-R", repo, "--title", title,
                         "--label", ALERT_LABEL, "--body", body],
                        capture=True, token=token, check=True, label=label)
        return 1 if wrote.returncode != 0 else 0
    if action == "close":
        commented = _gh(["issue", "comment", str(num), "-R", repo, "--body", recovered_note],
                        capture=True, token=token, check=True, label=label)
        closed = _gh(["issue", "close", str(num), "-R", repo],
                     capture=True, token=token, check=True, label=label)
        return 1 if (commented.returncode != 0 or closed.returncode != 0) else 0
    return 0


def main_job_alert():
    """(A) the metrics JOB-FAILURE alert. Hosted in metrics.yml, keyed on needs.metrics.result."""
    registry_repo = os.environ["REGISTRY_REPO"]
    repo, token = _alert_route(
        os.environ.get("ALERT_REPO"), os.environ.get("ALERT_TOKEN"), registry_repo)
    result = os.environ.get("METRICS_RESULT", "")
    run_url = os.environ.get("RUN_URL", "")
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")

    num, hard, soft = _find_open_alert(repo, token, JOB_ALERT_MARKER, JOB_ALERT_TITLE,
                                       "metrics-alert")
    if hard:
        return 1
    if soft:
        return 0
    action = decide(result, num is not None)
    code = _apply(action, repo, token, num, JOB_ALERT_TITLE,
                  _render_job_body(result, run_url, maintainer),
                  "✅ Recovered — the scheduled METRICS job succeeded again. Auto-closing.",
                  "metrics-alert")
    if code:
        return code
    if action == "upsert":
        print(f"::warning::metrics-alert: METRICS job {result} — maintainer alerted")
    elif action == "close":
        print("metrics-alert: METRICS recovered — closed the alert")
    else:
        print(f"metrics-alert: METRICS result={result or 'unknown'} — nothing to do")
    return 0


def main_stale_check():
    """(B) the SNAPSHOT-STALENESS alert. Hosted in groom.yml on an INDEPENDENT schedule, because a
    workflow cannot detect its own non-execution and a cron that silently under-delivers produces no
    failed job for (A) to key on."""
    registry_repo = os.environ["REGISTRY_REPO"]
    repo, token = _alert_route(
        os.environ.get("ALERT_REPO"), os.environ.get("ALERT_TOKEN"), registry_repo)
    run_url = os.environ.get("RUN_URL", "")
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    workflow_url = f"{server}/{registry_repo}/actions/workflows/metrics.yml"
    snapshot_path = os.environ["SNAPSHOT_PATH"]

    try:
        with open(snapshot_path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        text = None  # fail-closed: an unreadable snapshot is treated as stale, never as fresh
    epoch, reason = read_generated_at(text)
    verdict, detail, age = stale_verdict(epoch, reason, _now())
    stamp = (datetime.fromtimestamp(epoch, tz=timezone.utc).strftime(GENERATED_AT_FORMAT)
             if epoch is not None else None)

    num, hard, soft = _find_open_alert(repo, token, STALE_ALERT_MARKER, STALE_ALERT_TITLE,
                                       "metrics-stale")
    if hard:
        return 1
    if soft:
        return 0
    action = decide_stale(verdict, num is not None)
    code = _apply(action, repo, token, num, STALE_ALERT_TITLE,
                  _render_stale_body(detail, age, stamp, run_url, workflow_url, maintainer),
                  "✅ Recovered — a fresh metrics snapshot has landed on the ledger. Auto-closing.",
                  "metrics-stale")
    if code:
        return code
    if action == "upsert":
        print(f"::warning::metrics-stale: published metrics snapshot is STALE ({detail}) — "
              "maintainer alerted")
    elif action == "close":
        print("metrics-stale: a fresh snapshot has landed — closed the alert")
    else:
        age_note = "unknown" if age is None else f"{age // 60} min"
        print(f"metrics-stale: snapshot is fresh (age {age_note}) — nothing to do")
    return 0


def _now():
    """Wall clock, isolated so the self-test can pin it."""
    return int(datetime.now(tz=timezone.utc).timestamp())


def main():
    if "--stale-check" in sys.argv:
        return main_stale_check()
    return main_job_alert()


# =============================================================================================
# self-test
# =============================================================================================
def _repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _require(path):
    """Read a file the self-test asserts against. FAIL CLOSED: a missing input must abort the
    self-test loudly, never make its assertions quietly unreachable. This is what stops the whole
    YAML-seam section from evaporating if someone trims a sparse-checkout list."""
    full = os.path.join(_repo_root(), path)
    if not os.path.isfile(full):
        raise MetricsAlertError(
            f"self-test input {path} is missing from the working copy at {_repo_root()} — the "
            "YAML-seam assertions cannot run, and a self-test that silently stops asserting is "
            "worse than no self-test. Add it to the job's sparse-checkout list.")
    with open(full, encoding="utf-8") as handle:
        return handle.read()


# The ONE grammar of job-level `if:` this repo's alert legs use, copied deliberately from
# scripts/metrics.py's reviewed `_eval_job_if` (round-2 mutants A and C there). Anchored and
# single-comparison on purpose: a gate rewritten into a form this harness cannot reason about must
# RAISE, not be waved through — an unevaluatable gate is an UNCHECKED polarity on a surface no
# runtime check can reach.
_JOB_IF_COMPARISON = re.compile(
    r"^needs\.([A-Za-z0-9_-]+)\.(result|outputs\.[A-Za-z0-9_.-]+)\s*(==|!=)\s*'([^']*)'$")


def _eval_job_if(expr, needs):
    """EVALUATE a job-level `if:` against a hypothetical `needs` context. -> bool.

    `expr is None` models GitHub's default for a job with `needs:` and no `if:` — an implicit
    success() over the needed jobs. That is what makes DELETING `if: always()` visible here rather
    than only in production, on the one tick that matters."""
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
        raise MetricsAlertError(
            f"unmodelled job `if:` expression {expr!r} — this harness only evaluates the restricted "
            "grammar the alert legs use. Extend _eval_job_if deliberately, or keep the gate in the "
            "modelled grammar; an expression it cannot evaluate is an unchecked polarity.")
    job, field, operator, want = match.groups()
    context = needs.get(job)
    if context is None:
        raise MetricsAlertError(
            f"job `if:` reads needs.{job}, which is not among the modelled needs {sorted(needs)} — "
            "a gate that names a job it does not depend on always reads the empty string")
    got = (context.get("result", "") if field == "result"
           else (context.get("outputs") or {}).get(field.split(".", 1)[1], ""))
    return (got == want) if operator == "==" else (got != want)


def _declared_needs(job):
    declared = job.get("needs")
    if declared is None:
        return []
    return [declared] if isinstance(declared, str) else list(declared)


def _job_runs(job, outcomes):
    """Does `job` execute, given upstream job results? Models BOTH seams at once: the `needs:` edge
    the job declares AND its `if:`. Adding a `needs:` edge to an unconditional job is invisible to
    an `if:`-only assertion, and that is precisely how a watchdog gets silently suppressed by the
    failure of the thing it is meant to survive."""
    needs = {name: {"result": outcomes.get(name, "success")} for name in _declared_needs(job)}
    return _eval_job_if(job.get("if"), needs)


def _job(workflow, name):
    jobs = (workflow or {}).get("jobs") or {}
    if name not in jobs:
        raise MetricsAlertError(
            f"workflow has no job named `{name}` — refusing to assert against a job that does not "
            "exist (a deleted watchdog must go RED here, not silently pass)")
    return jobs[name]


def _step(job, step_id):
    """The parsed step mapping with `id: step_id`. Fails closed on 0 or >1 matches."""
    found = [s for s in (job.get("steps") or []) if s.get("id") == step_id]
    if len(found) != 1:
        raise MetricsAlertError(
            f"expected exactly one step with `id: {step_id}`, found {len(found)} — refusing to "
            "assert against a step that cannot be located")
    return found[0]


def _invocations(step, script):
    """Executable `python3 .../<script>` command lines in a step's `run:` body, COMMENTS STRIPPED.

    A filename grep over a shell body is satisfied by a comment, by an adjacent lint invocation, or
    by a backslash-continuation tail — three separate ways a wiring assertion has gone vacuous in
    this estate. Anchoring per line, dropping comment lines, and returning the argument tails is
    what makes "this step actually calls this script, twice, once with --self-test" falsifiable."""
    body = step.get("run") or ""
    live = "\n".join(line for line in body.replace("\\\n", " ").splitlines()
                     if not line.strip().startswith("#"))
    pattern = re.compile(rf"^\s*python3\s+(?:\S*/)?{re.escape(script)}([^\n]*)$", re.M)
    return [m.group(1).split() for m in pattern.finditer(live)]


def _checkout(job, path):
    """The `with:` mapping of the actions/checkout step that materialises `path`. Fails closed on 0
    or >1 matches — selecting by POSITION would silently follow a reordered step list."""
    found = [(step.get("with") or {}) for step in (job.get("steps") or [])
             if str(step.get("uses", "")).startswith("actions/checkout@")
             and (step.get("with") or {}).get("path") == path]
    if len(found) != 1:
        raise MetricsAlertError(
            f"expected exactly one actions/checkout with `path: {path}`, found {len(found)}")
    return found[0]


def _sparse_paths(job, path="registry"):
    spec = _checkout(job, path).get("sparse-checkout") or ""
    return {line.strip() for line in str(spec).splitlines() if line.strip()}


def _cron_period_minutes(workflow):
    """Minutes between fires for a `m-59/N * * * *` or `*/N * * * *` schedule."""
    triggers = workflow.get("on", workflow.get(True)) or {}
    crons = [entry["cron"] for entry in (triggers.get("schedule") or []) if "cron" in entry]
    if len(crons) != 1:
        raise MetricsAlertError(f"expected exactly one cron schedule, found {len(crons)}")
    minute = crons[0].split()[0]
    return int(minute.split("/")[1]) if "/" in minute else 60


def _self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got} (want {want})")

    # --- routing (mirrors the audited plan-alert/groom-alert/usage-alert matrix) --------------
    chk("route: repo+token -> private + token",
        _alert_route("org/private", "tok", "org/registry"), ("org/private", "tok"))
    chk("route: repo but NO token -> registry fallback",
        _alert_route("org/private", "", "org/registry"), ("org/registry", None))
    chk("route: repo but None token -> registry fallback",
        _alert_route("org/private", None, "org/registry"), ("org/registry", None))
    chk("route: no repo -> registry",
        _alert_route("", "tok", "org/registry"), ("org/registry", None))

    # --- (A) decide(): success-only closure ---------------------------------------------------
    chk("decide: failure -> upsert", decide("failure", False), "upsert")
    chk("decide: failure w/ open -> upsert", decide("failure", True), "upsert")
    chk("decide: cancelled -> upsert", decide("cancelled", True), "upsert")
    chk("decide: success + open -> close", decide("success", True), "close")
    chk("decide: success + none -> noop", decide("success", False), "noop")
    chk("decide: SKIPPED + open -> noop (a skipped METRICS is not a recovery)",
        decide("skipped", True), "noop")
    chk("decide: empty result + open -> noop", decide("", True), "noop")

    # --- (B) the staleness predicate ----------------------------------------------------------
    _test_staleness_predicate(chk)
    # --- (A)+(B) the stubbed-gh flows ---------------------------------------------------------
    _test_gh_flows(chk)
    # --- the structural authority denial ------------------------------------------------------
    _test_no_hold_labels(chk)
    # --- THE YAML SEAM: where vacuity actually lives ------------------------------------------
    _test_workflow_seam(chk)

    print("metrics-alert self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def _test_staleness_predicate(chk):
    now = 1_800_000_000
    fresh = json.dumps({"generated_at": datetime.fromtimestamp(now - 300, tz=timezone.utc)
                        .strftime(GENERATED_AT_FORMAT)})
    old = json.dumps({"generated_at": datetime.fromtimestamp(now - 90 * 60, tz=timezone.utc)
                      .strftime(GENERATED_AT_FORMAT)})
    edge = json.dumps({"generated_at": datetime.fromtimestamp(
        now - STALE_THRESHOLD_SECONDS, tz=timezone.utc).strftime(GENERATED_AT_FORMAT)})
    chk("stale: a 5-min-old snapshot is FRESH",
        stale_verdict(*read_generated_at(fresh), now)[0], "fresh")
    chk("stale: a 90-min-old snapshot is STALE",
        stale_verdict(*read_generated_at(old), now)[0], "stale")
    chk("stale: EXACTLY at the threshold is still fresh; one second past it is stale (the "
        "comparison is `>`, and an off-by-one here is a page or a blind spot)",
        (stale_verdict(*read_generated_at(edge), now)[0],
         stale_verdict(*read_generated_at(edge), now + 1)[0]),
        ("fresh", "stale"))
    # FAIL-CLOSED matrix. Every unreadable input must land on 'stale'. The inverse polarity is a
    # watchdog that goes quiet exactly when the thing it watches breaks hardest.
    unreadable = {
        "file missing": None,
        "not JSON": "SENTINEL-PAYLOAD not json {",
        "JSON but not an object": "[1, 2, 3]",
        "object with no generated_at": '{"targets": {}}',
        "generated_at is not a string": '{"generated_at": 1800000000}',
        "generated_at is malformed": '{"generated_at": "SENTINEL-PAYLOAD-not-a-timestamp"}',
        "generated_at is empty": '{"generated_at": ""}',
    }
    chk("stale: EVERY unreadable snapshot fails CLOSED to stale (missing / non-JSON / non-object / "
        "no timestamp / non-string timestamp / malformed timestamp / empty timestamp)",
        {label: stale_verdict(*read_generated_at(text), now)[0]
         for label, text in unreadable.items()},
        {label: "stale" for label in unreadable})
    chk("stale: no unreadable-snapshot reason echoes the remote payload (the snapshot is written by "
        "another job; its bytes must never reach an issue body)",
        [label for label, text in unreadable.items()
         if "SENTINEL-PAYLOAD" in read_generated_at(text)[1]],
        [])
    chk("stale: a FUTURE timestamp reads fresh, not as an alert (clock skew must not page a human)",
        stale_verdict(now + 600, "ok", now)[0], "fresh")
    chk("stale: the age reported alongside a fresh verdict is the real age in seconds",
        stale_verdict(*read_generated_at(fresh), now)[2], 300)
    # decide_stale(): closure requires a POSITIVE freshness assertion, never mere silence.
    chk("decide_stale: stale -> upsert", decide_stale("stale", False), "upsert")
    chk("decide_stale: stale w/ open -> upsert", decide_stale("stale", True), "upsert")
    chk("decide_stale: fresh + open -> close", decide_stale("fresh", True), "close")
    chk("decide_stale: fresh + none -> noop", decide_stale("fresh", False), "noop")
    # bodies: the closed scalar set, and nothing from the payload.
    body = _render_stale_body("the published snapshot has not been refreshed", 5400,
                              "2026-07-27T14:00:00Z", "https://example.test/run/1",
                              "https://example.test/wf", "jeswr")
    chk("stale body carries the marker, the mention, the age and both links",
        (STALE_ALERT_MARKER in body, "@jeswr" in body, "90 min" in body,
         "https://example.test/run/1" in body, "https://example.test/wf" in body),
        (True, True, True, True, True))
    job_body = _render_job_body("failure", "https://example.test/run/2", "jeswr")
    chk("job body carries the marker, the mention and the run link",
        (JOB_ALERT_MARKER in job_body, "@jeswr" in job_body,
         "https://example.test/run/2" in job_body), (True, True, True))
    chk("the two markers are DISTINCT — a shared marker would make each alert close the other",
        JOB_ALERT_MARKER != STALE_ALERT_MARKER, True)


def _test_no_hold_labels(chk):
    """STRUCTURAL denial of hold/admission authority (hard constraint: the responder may never
    apply `needs:user`, and park_policy invariant 3 exists because the orchestrator once re-applied
    it 37 times). This is an AST fact about the module, not a convention a later edit can erode: no
    string literal anywhere in this file may name an orchestration label namespace, and the only
    label this script can pass to `gh` is the ops-alert one."""
    source = _require("scripts/metrics-alert.py")
    tree = ast.parse(source)
    literals = [node.value for node in ast.walk(tree)
                if isinstance(node, ast.Constant) and isinstance(node.value, str)]
    forbidden = sorted({text for text in literals
                        if re.match(r"^(needs|status|role|area|review):", text)})
    chk("STRUCTURAL: no code path can write a needs:/status:/role:/area:/review: label — there is "
        "no such string literal in the module at all (this is the hard deny-list, enforced by the "
        "AST rather than by convention)", forbidden, [])
    chk("...and the only label the script hands to `gh` is the ops-alert one",
        ALERT_LABEL, "ops-alert")
    # The ENTIRE authority surface, read off the AST rather than asserted about: every `gh` command
    # this module can construct. Adding a `gh pr merge`, a `gh pr review`, an `--auto` arming call
    # or an `issue edit --add-label` path changes this vocabulary and goes red here. This is the
    # structural form of "an auto-responder must not become an auto-merger".
    nouns, verbs = set(), set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and getattr(node.func, "id", getattr(node.func, "attr", "")) == "_gh"):
            continue
        argv = node.args[0] if node.args else None
        if not isinstance(argv, ast.List):
            raise MetricsAlertError(
                "a _gh() call passes a non-literal argv — the authority surface would stop being "
                "statically readable, which is how this guard fails open")
        words = [e.value for e in argv.elts if isinstance(e, ast.Constant)]
        if words:
            nouns.add(words[0])
        if len(words) > 1:
            verbs.add(words[1])
    chk("STRUCTURAL: the COMPLETE set of gh commands this module can construct — no `pr`, no merge, "
        "no arming, no label mutation beyond creating the ops-alert label itself",
        (sorted(nouns), sorted(verbs)),
        (["issue", "label"], ["close", "comment", "create", "edit", "list"]))


def _test_gh_flows(chk):
    """Full main() paths under a fake subprocess.run that records the COMPLETE command and env per
    call and can inject a failure for any individual gh subcommand — so repo/token wiring and every
    mutation return-code check are asserted, not assumed."""
    import contextlib
    import io
    import tempfile

    class _Result:
        def __init__(self, rc=0, stdout=""):
            self.returncode = rc
            self.stdout = stdout
            self.stderr = "SENTINEL-STDERR"

    calls = []
    responses = {}

    def fake_run(cmd, capture_output=False, text=False, env=None):
        calls.append((list(cmd), dict(env or {})))
        return responses.get(tuple(cmd[1:3]), _Result())

    def find(sub):
        return next(((c, e) for c, e in calls if tuple(c[1:3]) == sub), (None, None))

    def subs():
        return [tuple(c[1:3]) for c, _e in calls]

    real_run = subprocess.run
    base_env = {"REGISTRY_REPO": "org/registry", "METRICS_RESULT": "", "RUN_URL": "u",
                "MAINTAINER_HANDLE": "m", "ALERT_REPO": "", "ALERT_TOKEN": "",
                "SNAPSHOT_PATH": "", "GITHUB_SERVER_URL": "https://example.test"}

    def run_main(argv, list_json="[]", fail=(), alert_repo="", alert_token="",
                 metrics_result="", snapshot=None):
        calls.clear()
        responses.clear()
        responses[("issue", "list")] = _Result(1 if ("issue", "list") in fail else 0, list_json)
        for key in fail:
            if key != ("issue", "list"):
                responses[key] = _Result(1)
        os.environ.update(base_env)
        os.environ["METRICS_RESULT"] = metrics_result
        os.environ["ALERT_REPO"] = alert_repo
        os.environ["ALERT_TOKEN"] = alert_token
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "metrics.json")
            if snapshot is not None:
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(snapshot)
            os.environ["SNAPSHOT_PATH"] = path
            saved, sys.argv = sys.argv, ["metrics-alert.py"] + list(argv)
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    rc = main()
            finally:
                sys.argv = saved
        return rc, buf.getvalue()

    fresh_snapshot = json.dumps({"generated_at": datetime.now(tz=timezone.utc)
                                 .strftime(GENERATED_AT_FORMAT)})
    stale_snapshot = json.dumps({"generated_at": "2020-01-01T00:00:00Z"})
    open_job = json.dumps([{"number": 7, "title": JOB_ALERT_TITLE}])
    open_stale = json.dumps([{"number": 9, "title": STALE_ALERT_TITLE}])

    subprocess.run = fake_run
    try:
        # ---- (A) job-failure flow ----------------------------------------------------------
        rc, _ = run_main([], metrics_result="failure")
        chk("flow A: failure + no open -> create", (rc, ("issue", "create") in subs()), (0, True))
        rc, _ = run_main([], open_job, metrics_result="failure")
        chk("flow A: failure + open -> edit not create",
            (rc, ("issue", "edit") in subs(), ("issue", "create") in subs()), (0, True, False))
        rc, _ = run_main([], open_job, metrics_result="success")
        chk("flow A: success + open -> comment+close",
            (rc, ("issue", "comment") in subs(), ("issue", "close") in subs()), (0, True, True))
        rc, _ = run_main([], open_job, metrics_result="skipped")
        chk("flow A: skipped + open -> NO mutation",
            (rc, [s for s in subs() if s != ("issue", "list")]), (0, []))
        rc, out = run_main([], metrics_result="failure", fail=(("issue", "list"),))
        chk("flow A: list failure -> rc=1 + sanitized warning (stderr never echoed)",
            (rc, "::warning::" in out, "SENTINEL-STDERR" in out), (1, True, False))
        rc, out = run_main([], "SENTINEL-MALFORMED {not json", metrics_result="failure")
        chk("flow A: malformed list JSON -> soft skip, payload not echoed",
            (rc, "::warning::" in out, "SENTINEL-MALFORMED" in out,
             [s for s in subs() if s != ("issue", "list")]), (0, True, False, []))
        rc, out = run_main([], '{"message": "sentinel-error-object"}', metrics_result="success")
        chk("flow A: non-array list JSON -> soft skip, payload not echoed",
            (rc, "::warning::" in out, "sentinel-error-object" in out,
             [s for s in subs() if s != ("issue", "list")]), (0, True, False, []))
        for failing in (("issue", "create"), ("issue", "edit")):
            rc, out = run_main([], open_job if failing == ("issue", "edit") else "[]",
                               fail=(failing,), metrics_result="failure")
            chk(f"flow A: {failing[1]} failure -> rc=1 + warning", (rc, "::warning::" in out),
                (1, True))
        for failing in (("issue", "comment"), ("issue", "close")):
            rc, out = run_main([], open_job, fail=(failing,), metrics_result="success")
            chk(f"flow A: {failing[1]} failure -> rc=1 + warning", (rc, "::warning::" in out),
                (1, True))

        # ---- (B) staleness flow ------------------------------------------------------------
        rc, _ = run_main(["--stale-check"], snapshot=stale_snapshot)
        chk("flow B: stale snapshot + no open -> create",
            (rc, ("issue", "create") in subs()), (0, True))
        rc, _ = run_main(["--stale-check"], open_stale, snapshot=stale_snapshot)
        chk("flow B: stale + open -> edit not create",
            (rc, ("issue", "edit") in subs(), ("issue", "create") in subs()), (0, True, False))
        rc, _ = run_main(["--stale-check"], open_stale, snapshot=fresh_snapshot)
        chk("flow B: fresh snapshot + open -> comment+close",
            (rc, ("issue", "comment") in subs(), ("issue", "close") in subs()), (0, True, True))
        rc, _ = run_main(["--stale-check"], snapshot=fresh_snapshot)
        chk("flow B: fresh + none open -> bare list, no mutation (a green tick stays cheap)",
            (rc, subs()), (0, [("issue", "list")]))
        rc, _ = run_main(["--stale-check"], snapshot=None)
        chk("flow B: MISSING snapshot file -> alert (fail-closed end-to-end, not just in the "
            "predicate)", (rc, ("issue", "create") in subs()), (0, True))
        created_cmd, _ = find(("issue", "create"))
        chk("flow B: the missing-file alert is titled as the STALENESS alert, not the job alert",
            created_cmd is not None and STALE_ALERT_TITLE in created_cmd, True)
        # The two alerts must not collide on one issue: a stale tick must not close a job alert.
        rc, _ = run_main(["--stale-check"], open_job, snapshot=fresh_snapshot)
        chk("flow B: a FRESH snapshot does NOT close an open JOB-failure alert (distinct markers, "
            "distinct titles — one watchdog must never silence the other)",
            (rc, [s for s in subs() if s != ("issue", "list")]), (0, []))
        rc, _ = run_main([], open_stale, metrics_result="success")
        chk("flow A: a METRICS success does NOT close an open STALENESS alert",
            (rc, [s for s in subs() if s != ("issue", "list")]), (0, []))
        # No byte of the snapshot may reach the issue body.
        rc, _ = run_main(["--stale-check"],
                         snapshot='{"generated_at": "SENTINEL-SNAPSHOT-PAYLOAD"}')
        body_cmd, _ = find(("issue", "create"))
        chk("flow B: a poisoned snapshot payload never reaches the issue body",
            (rc, any("SENTINEL-SNAPSHOT-PAYLOAD" in arg for arg in (body_cmd or []))),
            (0, False))

        # ---- repo/token WIRING, both modes ---------------------------------------------------
        for argv, kwargs in (([], {"metrics_result": "failure"}),
                             (["--stale-check"], {"snapshot": stale_snapshot})):
            mode = "A" if not argv else "B"
            run_main(argv, alert_repo="org/private", alert_token="sentinel-alert-tok", **kwargs)
            cmd, env = find(("issue", "create"))
            chk(f"wiring {mode}: private route -> -R org/private under ALERT_TOKEN",
                (cmd is not None and cmd[cmd.index("-R") + 1], (env or {}).get("GH_TOKEN")),
                ("org/private", "sentinel-alert-tok"))
            ambient = os.environ.get("GH_TOKEN")
            run_main(argv, alert_repo="org/private", alert_token="", **kwargs)
            cmd2, env2 = find(("issue", "create"))
            chk(f"wiring {mode}: half-config -> -R org/registry under the UNCHANGED ambient token",
                (cmd2 is not None and cmd2[cmd2.index("-R") + 1],
                 (env2 or {}).get("GH_TOKEN") == ambient,
                 (env2 or {}).get("GH_TOKEN") == "sentinel-alert-tok"),
                ("org/registry", True, False))

        # ---- dedupe: --limit 100, marker-first, legacy title fallback -------------------------
        crowd = [{"number": i, "title": f"unrelated ops alert {i}"} for i in range(25)]
        rc, _ = run_main([], json.dumps(crowd + [{"number": 99, "title": JOB_ALERT_TITLE}]),
                         metrics_result="failure")
        list_cmd, _ = find(("issue", "list"))
        edit_cmd, _ = find(("issue", "edit"))
        chk("dedupe: --limit 100 + title found past position 20 -> edit #99, no create",
            (rc, "100" in (list_cmd or []), ("issue", "create") in subs(),
             edit_cmd is not None and "99" in edit_cmd), (0, True, False, True))
        renamed = json.dumps([{"number": 55, "title": "metrics broke (renamed by a human)",
                               "body": "prose\n" + JOB_ALERT_MARKER + "\nmore prose"}])
        rc, _ = run_main([], renamed, metrics_result="failure")
        edit_r, _ = find(("issue", "edit"))
        chk("dedupe: RENAMED alert -> marker match edits #55, no create",
            (rc, ("issue", "create") in subs(), edit_r is not None and "55" in edit_r),
            (0, False, True))
        rc, _ = run_main([], renamed, metrics_result="success")
        close_r, _ = find(("issue", "close"))
        chk("close: RENAMED alert -> marker match closes #55",
            (rc, close_r is not None and "55" in close_r), (0, True))
        legacy = json.dumps([{"number": 8, "title": JOB_ALERT_TITLE, "body": "old, no marker"}])
        rc, _ = run_main([], legacy, metrics_result="failure")
        edit_l, _ = find(("issue", "edit"))
        chk("dedupe: legacy title-only alert -> fallback edits #8, no create",
            (rc, ("issue", "create") in subs(), edit_l is not None and "8" in edit_l),
            (0, False, True))
        list_l, _ = find(("issue", "list"))
        chk("dedupe: the list request fetches `body` — without it the marker match is vacuous",
            "number,title,body" in (list_l or []), True)
    finally:
        subprocess.run = real_run
        for key in base_env:
            os.environ.pop(key, None)


def _test_workflow_seam(chk):
    """THE YAML SEAM. Registry #592 records that the dispatch PLAN and groom alert jobs have NO
    always()-guard regression test at all: their `if:` could be deleted or inverted and every check
    in the repo would stay green, because the executed Python never sees the gate. Measured in this
    estate: every uncaught mutant lives HERE, one level above the shell body — in an `if:`, a
    `needs:` edge, a permissions block, or a call site — not in the Python.

    So each condition is pinned EXACTLY and then EVALUATED across every upstream outcome."""
    import yaml  # lazy: available on ubuntu-latest (verified live, run 30279870348) and in pr-gate

    metrics_wf = yaml.safe_load(_require(".github/workflows/metrics.yml"))
    groom_wf = yaml.safe_load(_require(".github/workflows/groom.yml"))
    collector = _job(metrics_wf, "metrics")
    alert = _job(metrics_wf, "metrics-alert")
    stale = _job(groom_wf, "metrics-stale")

    # --- (A) the job-failure watchdog runs on the tick that MATTERS -------------------------
    chk("A/seam: the alert job keys on the METRICS JOB, not the workflow rollup (a rollup carries "
        "this very job, so an alert-leg failure would suppress the alert for a real outage)",
        _declared_needs(alert), ["metrics"])
    chk("A/seam: its gate is EXACTLY always()", str(alert.get("if")).strip(), "${{ always() }}")
    chk("A/seam: ...and it is EVALUATED over every metrics-job outcome — DELETING the gate (leaving "
        "GitHub's implicit success()), inverting it, or pinning it false all go red HERE rather "
        "than on the one tick nobody is watching",
        {result: _job_runs(alert, {"metrics": result})
         for result in ("success", "failure", "cancelled", "skipped")},
        {"success": True, "failure": True, "cancelled": True, "skipped": True})
    unmodelled = False
    try:
        _eval_job_if("github.event_name == 'schedule' && needs.metrics.result == 'failure'",
                     {"metrics": {"result": "failure"}})
    except MetricsAlertError:
        unmodelled = True
    chk("A/seam: a gate rewritten outside the modelled grammar RAISES rather than silently ceasing "
        "to be checked — the evaluator must not be the next thing that fails open", unmodelled, True)

    # --- (B) the staleness watchdog survives the failure of its own host ---------------------
    chk("B/seam: the staleness job declares NO `needs:` — it must run even when the groom sweep it "
        "shares a workflow with has died, and a `needs: [groom]` edge is invisible to any "
        "`if:`-only assertion", _declared_needs(stale), [])
    chk("B/seam: ...and carries no `if:` of its own", "if" in stale, False)
    chk("B/seam: ...EVALUATED over every groom outcome, so adding a `needs:` edge or any suppressing "
        "`if:` goes red here",
        {result: _job_runs(stale, {"groom": result})
         for result in ("success", "failure", "cancelled", "skipped")},
        {"success": True, "failure": True, "cancelled": True, "skipped": True})

    # --- THE RING PROPERTY: this is the headline claim of the unit ---------------------------
    stale_hosts = sorted(
        name for name, job in (metrics_wf.get("jobs") or {}).items()
        if any(_invocations(step, "metrics-alert.py") and
               any("--stale-check" in args for args in _invocations(step, "metrics-alert.py"))
               for step in (job.get("steps") or [])))
    chk("RING: the staleness assertion is NOT hosted anywhere in metrics.yml — a workflow cannot "
        "detect its own non-execution, so moving this check 'next to the thing it watches' would "
        "make it useless in exactly the failure it exists for", stale_hosts, [])

    # --- CALL SITES: the step bodies actually invoke this script -----------------------------
    alert_step = _step(alert, "metrics-alert")
    stale_step = _step(stale, "metrics-stale")
    chk("call site A: the step is not itself conditional — a step-level `if:` would leave this "
        "harness exercising a body production can skip", alert_step.get("if"), None)
    chk("call site B: same for the staleness step", stale_step.get("if"), None)
    chk("call site A: the step runs the self-test AND the live alert, in that order, with no "
        "`--stale-check` (comments and lint lines cannot satisfy this — it is a per-line anchored "
        "match on executable lines only)",
        _invocations(alert_step, "metrics-alert.py"), [["--self-test"], []])
    chk("call site B: the step runs the self-test AND the live check WITH --stale-check (a missing "
        "flag would silently run the JOB-failure path against an empty METRICS_RESULT and report "
        "everything healthy forever)",
        _invocations(stale_step, "metrics-alert.py"), [["--self-test"], ["--stale-check"]])
    chk("call site A: the metrics job RESULT reaches the script through METRICS_RESULT",
        (alert_step.get("env") or {}).get("METRICS_RESULT"), "${{ needs.metrics.result }}")
    chk("call site B: the snapshot path reaches the script through SNAPSHOT_PATH, pointing at the "
        "ledger worktree copy of the collector's own published file",
        (stale_step.get("env") or {}).get("SNAPSHOT_PATH"), f"ledger/{SNAPSHOT_RELATIVE_PATH}")
    chk("call site: both steps are continue-on-error, so a watchdog fault can never take down the "
        "sweep it rides on",
        (alert_step.get("continue-on-error"), stale_step.get("continue-on-error")), (True, True))

    # --- CROSS-FILE contract: the path this watchdog reads is the path metrics.py writes ------
    published = re.search(r'^PUBLISHED_PATH\s*=\s*"([^"]+)"', _require("scripts/metrics.py"), re.M)
    chk("cross-file: the read path IS scripts/metrics.py's PUBLISHED_PATH — if the collector's "
        "write path ever moved, this watchdog would page forever about a file nothing updates, "
        "which is worse than the outage it watches for",
        published and published.group(1), SNAPSHOT_RELATIVE_PATH)

    # --- AUTHORITY, enforced by the permissions block, not by intent -------------------------
    chk("authority: the alert job holds contents:read + issues:write and NOTHING else — no "
        "pull-requests, no actions, no arming or merge surface (repair authority and admission "
        "authority stay separate)",
        alert.get("permissions"), {"contents": "read", "issues": "write"})
    chk("authority: same closed permission set on the staleness job",
        stale.get("permissions"), {"contents": "read", "issues": "write"})
    chk("secret-exfil guard (#101): both jobs read ALERT_TOKEN/ALERT_REPO and are therefore bound "
        "to the default-branch-only dispatch-secrets environment",
        (alert.get("environment"), stale.get("environment")),
        ("dispatch-secrets", "dispatch-secrets"))

    # --- the self-test's own inputs are actually present in the live jobs --------------------
    for name, job in (("metrics-alert", alert), ("metrics-stale", stale)):
        chk(f"inputs: the {name} job sparse-checks-out every file its --self-test asserts against — "
            "a trimmed list makes the whole seam section unreachable in the live path",
            sorted(set(REQUIRED_FILES) - _sparse_paths(job)), [])

    # The OTHER false-page vector, and the one the cross-file path check above cannot see: the
    # ledger checkout could stop materialising the file while the path constant stays correct. An
    # empty sparse pattern, a wrong branch, or a persisted-credential regression would each make the
    # watchdog page forever about a file it simply never fetched.
    ledger = _checkout(stale, "ledger")
    chk("ledger checkout: the staleness job fetches EXACTLY the collector's published file from the "
        "ledger data-plane branch, with no persisted token — a pattern that matches nothing reads "
        "as a missing snapshot and would page forever",
        (ledger.get("ref"), str(ledger.get("sparse-checkout") or "").strip(),
         ledger.get("sparse-checkout-cone-mode"), ledger.get("persist-credentials")),
        ("ledger", SNAPSHOT_RELATIVE_PATH, False, False))

    _test_threshold_vs_cadence(chk, metrics_wf, groom_wf)


def _test_threshold_vs_cadence(chk, metrics_wf, groom_wf):
    """The threshold is only meaningful relative to two crons it does not control."""
    metrics_period = _cron_period_minutes(metrics_wf)
    groom_period = _cron_period_minutes(groom_wf)
    threshold = STALE_THRESHOLD_SECONDS // 60
    chk("cadence: the staleness threshold allows at least THREE missed metrics deliveries — a "
        "tighter one pages on ordinary cron jitter (measured: 23.91 min effective cadence, 30.0 min "
        "worst gap, against a 15 min schedule), which is the noise the paging policy forbids",
        (metrics_period, threshold >= 3 * metrics_period), (15, True))
    chk("cadence: the HOST workflow fires at least as often as the threshold — a watchdog on a "
        "slower schedule than the condition it detects reports the outage late or not at all",
        (groom_period, groom_period <= threshold), (15, True))


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
