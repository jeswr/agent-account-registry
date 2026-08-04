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
#  - _alert_route: the private ALERT_REPO is the destination ONLY when ALERT_TOKEN can write there
#    AND that destination is POSITIVELY VERIFIED private (issue #436, matching the #432 round-1
#    hardening of usage-alert/model-health/pat-validity); a half-configured deployment (repo set,
#    token missing), a same-repo misconfiguration, or an unverifiable destination falls back to the
#    registry repo under the ambient token instead of silently failing the private write or
#    silently degrading the private channel to the public registry. The groom-alert body carries
#    NO account handles (it reports only the job RESULT + run link), so the fallback needs no
#    redaction variant — the verification exists so that a misconfigured ALERT_REPO is not read as
#    "private" here, and so a future body change cannot start leaking under a weaker route.
#  - decide(): close ONLY on an explicit `success` — needs.<job>.result also permits `skipped`,
#    which proves nothing about recovery, so an open alert must survive a skipped GROOM.
#  - _gh(check=True): a non-zero gh returncode is surfaced as a sanitized ::warning:: (op +
#    returncode only — never stderr, which can echo request bodies under GH_DEBUG=api) and main()
#    returns non-zero so the step outcome goes red (continue-on-error isolates the groomer).
#  - a SUCCESSFUL `gh issue list` returning MALFORMED JSON (truncation, HTML error page) fails
#    SOFT — sanitized ::warning:: (payload never echoed) and a graceful no-mutation skip, never an
#    uncaught JSONDecodeError crashing the alert; the next scheduled tick retries.
#
# [SPARQ agent] SECOND CONDITION — THE WATCHER RING'S OWN HEALTH (issue #1391). groom.yml also
# hosts the watchdog jobs that watch the OTHER lanes (metrics delivery, dispatcher liveness, CI
# execution latency, the shared REST budget, the per-owner token mint). Each runs its alert script
# in a `continue-on-error: true` step — deliberate and right, a watchdog fault must never red the
# sweep it rides on — but that also left the JOB result at `success` when the script exited
# nonzero, and NOTHING keyed on those jobs at all: they have no dependents, and this alert read
# only `needs.groom.result`. A watchdog that crashed on every tick was therefore a green tick
# forever while the lane it watches went unobserved — the ring silently losing a node, which is
# strictly worse than the outage each node exists to page on, because the ring is what makes the
# other alarms trustworthy.
#
# So groom.yml now publishes each watchdog's alert-step OUTCOME (the pre-continue-on-error result,
# and the only surviving signal) as an `alert_outcome` job output, this job `needs:` every one of
# them under `if: always()`, and the whole `needs` context arrives here as WATCHDOG_NEEDS. Both
# legs are alarmed per watchdog, on a rolling ops-alert each:
#   * the JOB result   — checkout, the PyYAML install, the NOT-continue-on-error `--self-test`
#                        step, the 10-minute timeout;
#   * the STEP outcome — the one step whose failure the job result structurally cannot see.
# Recovery requires BOTH legs explicitly `success`; `skipped`, `cancelled` and an unpublished
# output prove nothing and must never close an open alert. _test_workflow_seam() asserts the whole
# wiring against groom.yml itself, deriving the watchdog set from that file's own job map, so a
# watchdog added there without an alarm edge reds in the gate instead of joining the ring unwatched.
#
# Pure decide()/_alert_route() + a stubbed-gh flow test run under --self-test (registry-selftest).
import json
import os
import re
import subprocess
import sys

ALERT_LABEL = "ops-alert"
ALERT_TITLE = "⚠️ Scheduled GROOM job is failing — crash-recovery and health alerts are stalled"

GROOM_WORKFLOW = ".github/workflows/groom.yml"
# This job's own key in that file, and the jobs in it that are NOT watchdogs. The partition is the
# fail-closed half of the seam: every OTHER job in groom.yml must be wired into this alarm, so a
# new job there is either alarmed or explicitly declared non-watchdog HERE — a visible, reviewed
# edit — and can never join the ring silently. Each watchdog's continued EXISTENCE is pinned by its
# own script's self-test (metrics-alert, dispatch-stall-alert, ci-latency-alert, ratelimit-alert,
# groom-mint-alert each assert `groom.yml hosts a <x> job`), so it is deliberately not re-asserted.
ALERT_JOB = "groom-alert"
NON_WATCHDOG_JOBS = frozenset({"groom", ALERT_JOB})
# The job-output key every watchdog publishes its alert step's outcome under.
WATCHDOG_OUTPUT_KEY = "alert_outcome"
# Evidence floor for the seam section: groom.yml hosted five watchdogs when this landed. A thin
# checkout, a truncated read or a broken parse yields a job map with none, and every per-watchdog
# row below would then pass over an empty loop — vacuously green (AGENTS.md pre-flight #8).
MIN_WATCHDOGS = 5
# Files _test_workflow_seam() reads. KEEP IN SYNC with the sparse-checkout list in groom.yml's
# `groom-alert` job — the seam asserts both directions, so a trimmed checkout reds instead of
# making these assertions silently unreachable on the live path.
REQUIRED_FILES = (
    "scripts/groom-alert.py",
    GROOM_WORKFLOW,
)


class GroomAlertError(Exception):
    """A self-test input or gate expression this harness refuses to reason about."""
# Dedupe keyed on the TITLE alone breaks the moment anyone (human or a later wording tweak) renames
# the open alert — the next failing tick files a duplicate and recovery can't find the issue to
# close. The body carries this stable machine marker; dedupe matches the marker first and falls
# back to the exact title only for pre-marker legacy alerts.
ALERT_MARKER = "<!-- groom-alert:v1 key=groom-job-failure -->"


def watchdog_title(job):
    return f"⚠️ WATCHDOG `{job}` is failing — the groom.yml watcher ring has lost a node"


def watchdog_marker(job):
    """The per-watchdog dedupe marker. One rolling alert per node, keyed on the job name and
    trailed by ` -->` so no node's marker can be a prefix-match inside another's body."""
    return f"<!-- groom-alert:v1 key=watchdog-failure job={job} -->"


def watchdog_states(needs_json, non_watchdog=NON_WATCHDOG_JOBS):
    """Pure: sorted [(job, job_result, step_outcome)] for every WATCHDOG entry in a `toJSON(needs)`
    payload — i.e. every needed job outside the `non_watchdog` partition.

    FAIL CLOSED on anything unreadable — an absent env var, unparseable JSON, a non-object payload,
    a malformed per-job entry. The result is no evidence, which yields neither a page nor (the leg
    that actually matters) a CLOSE: a tick that could not read the ring must never be mistaken for
    a tick on which the ring recovered."""
    try:
        payload = json.loads(needs_json or "")
    except ValueError:  # json.JSONDecodeError is a ValueError
        return []
    if not isinstance(payload, dict):
        return []
    states = []
    for job in sorted(payload):
        if job in non_watchdog:
            continue
        entry = payload[job] if isinstance(payload[job], dict) else {}
        outputs = entry.get("outputs")
        outputs = outputs if isinstance(outputs, dict) else {}
        result = entry.get("result")
        outcome = outputs.get(WATCHDOG_OUTPUT_KEY)
        states.append((job,
                       result if isinstance(result, str) else "",
                       outcome if isinstance(outcome, str) else ""))
    return states


def decide_watchdog(job_result, step_outcome, has_open_alert):
    """Pure decision for ONE node of the ring: 'upsert' | 'close' | 'noop'.

    A watchdog fails in two INDEPENDENT ways and neither leg subsumes the other. The job result
    covers the checkout, the PyYAML install, the NOT-continue-on-error `--self-test` step and the
    job timeout; the alert step's published outcome covers the one step that is deliberately
    `continue-on-error: true`, whose failure therefore never reaches the job result at all — the
    whole defect of issue #1391.

    Recovery demands BOTH legs be explicitly `success`. `skipped`, `cancelled` and the empty string
    (an unpublished output, an un-wired job, an unreadable needs payload) are absence of evidence,
    not evidence of health, so an open alert survives every one of them."""
    if job_result in ("failure", "cancelled") or step_outcome == "failure":
        return "upsert"
    if job_result == "success" and step_outcome == "success" and has_open_alert:
        return "close"
    return "noop"


def _repo_confirmed_private(repo, token):
    """True ONLY on a definitive `"private": true` from GET /repos/{repo} read under the route
    token (issue #436, mirroring usage-alert.py's #432 round-1 helper). FAIL-CLOSED: a failed
    lookup, an unparseable payload, or anything but a literal boolean true reads as NOT private
    and the caller falls back to the registry. The response body is parsed, never echoed."""
    proc = _gh(["api", f"repos/{repo}"], capture=True, token=token)
    if proc.returncode != 0:
        return False
    try:
        payload = json.loads(proc.stdout or "")
    except ValueError:  # json.JSONDecodeError is a ValueError
        return False
    return isinstance(payload, dict) and payload.get("private") is True


def _alert_route(alert_repo, alert_token, registry_repo, confirmed_private=None):
    """(repo, token) for the alert issue — same semantics as usage-alert.py's router (privacy
    d22c + issue #39, hardened for issue #436): the ALERT_REPO destination is selected ONLY when
    ALERT_TOKEN is present, ALERT_REPO is distinct from the public registry repo (case-insensitive
    — a "private route" naming the registry IS the public repo), AND the destination is CONFIRMED
    private by a live GET /repos/{ALERT_REPO} under ALERT_TOKEN. Every other shape falls back to
    the registry repo under the ambient token (token=None means "use the ambient GH_TOKEN").

    Presence of both env vars is CONFIGURATION, not verification (#432 round 1): the pair can name
    the public registry itself or any other public repository, and token presence proves nothing
    about destination visibility. This body carries no account handles, so the fallback is a
    delivery choice rather than a redaction one — but a misconfigured ALERT_REPO must not be
    reported or relied on as a private channel, and a future body change must not inherit a route
    that was never verified.

    `confirmed_private` is injectable for the self-test; the default performs the live lookup,
    consulted only once both halves of the route are set and the same-repo case is excluded."""
    if alert_repo and alert_token:
        same_repo = alert_repo.strip().lower() == (registry_repo or "").strip().lower()
        check = confirmed_private if confirmed_private is not None else _repo_confirmed_private
        if not same_repo and check(alert_repo, alert_token):
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


def _render_watchdog_body(job, job_result, step_outcome, run_url, maintainer):
    return (
        f"{watchdog_marker(job)}\n"
        "> 🤖 SPARQ agent — automated ops-alert (issue #1391)\n\n"
        f"@{maintainer} the **`{job}`** watchdog job in `groom.yml` is not reporting healthily: "
        f"job result `{job_result or 'unknown'}`, alert-step outcome "
        f"`{step_outcome or 'unpublished'}`.\n\n"
        "Its live alert step is `continue-on-error: true` — deliberately, so a watchdog fault can "
        "never red the grooming sweep it rides on — so a crash there does **not** reach the job "
        "result, and nothing else keys on this job at all. While this is open, the lane "
        f"`{job}` watches is effectively UNOBSERVED, and the watcher ring is what makes the other "
        "alarms trustworthy.\n\n"
        "The next scheduled tick retries automatically; this alert auto-closes once that job "
        "reports an explicit `success` on BOTH legs (job result and alert-step outcome) — a "
        "`skipped`, a `cancelled` or an unpublished outcome is not a recovery.\n\n"
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


def _ensure_label(repo, token):
    _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", "d73a4a",
         "--description", "Autonomous ops alert (maintainer action)"],
        capture=True, token=token)  # idempotent; pre-existing label is fine


def _find_alert(found, marker, title=None):
    """The open alert's number, matched on the stable body MARKER first (so a retitled alert still
    dedupes and can still be closed) and on the exact TITLE second, for alerts filed before the
    marker existed. A malformed row is skipped, never crashed on — the list is remote data."""
    rows = [row for row in found if isinstance(row, dict) and isinstance(row.get("number"), int)]
    num = next((row["number"] for row in rows if marker in (row.get("body") or "")), None)
    if num is None and title is not None:
        num = next((row["number"] for row in rows if row.get("title") == title), None)
    return num


def _handle_watchdogs(repo, token, found, needs_json, run_url, maintainer):
    """The #1391 leg: one rolling ops-alert per watchdog node of the ring. -> 0 | 1."""
    rc = 0
    labelled = False
    for job, job_result, step_outcome in watchdog_states(needs_json):
        marker = watchdog_marker(job)
        num = _find_alert(found, marker)
        action = decide_watchdog(job_result, step_outcome, num is not None)
        if action == "upsert":
            if not labelled:
                _ensure_label(repo, token)
                labelled = True
            body = _render_watchdog_body(job, job_result, step_outcome, run_url, maintainer)
            if num:
                wrote = _gh(["issue", "edit", str(num), "-R", repo, "--body", body],
                            capture=True, token=token, check=True)
            else:
                wrote = _gh(["issue", "create", "-R", repo, "--title", watchdog_title(job),
                             "--label", ALERT_LABEL, "--body", body],
                            capture=True, token=token, check=True)
            rc |= 1 if wrote.returncode != 0 else 0
            print(f"::warning::groom-alert: WATCHDOG {job} result={job_result or 'unknown'} "
                  f"alert-step={step_outcome or 'unpublished'} — maintainer alerted")
        elif action == "close":
            commented = _gh(["issue", "comment", str(num), "-R", repo, "--body",
                             f"✅ Recovered — the `{job}` watchdog reported success on both its "
                             "job result and its alert-step outcome. Auto-closing."],
                            capture=True, token=token, check=True)
            closed = _gh(["issue", "close", str(num), "-R", repo], capture=True, token=token,
                         check=True)
            rc |= 1 if (commented.returncode != 0 or closed.returncode != 0) else 0
            print(f"groom-alert: WATCHDOG {job} recovered — closed the alert")
    return rc


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
    num = _find_alert(found, ALERT_MARKER, ALERT_TITLE)

    rc = 0
    action = decide(result, num is not None)
    if action == "upsert":
        _ensure_label(repo, token)
        body = _render_body(result, run_url, maintainer)
        if num:
            wrote = _gh(["issue", "edit", str(num), "-R", repo, "--body", body],
                        capture=True, token=token, check=True)
        else:
            wrote = _gh(["issue", "create", "-R", repo, "--title", ALERT_TITLE,
                         "--label", ALERT_LABEL, "--body", body],
                        capture=True, token=token, check=True)
        rc |= 1 if wrote.returncode != 0 else 0
        print("::warning::groom-alert: GROOM job {} — maintainer alerted".format(result))
    elif action == "close":
        commented = _gh(["issue", "comment", str(num), "-R", repo, "--body",
                         "✅ Recovered — the scheduled GROOM job succeeded again. Auto-closing."],
                        capture=True, token=token, check=True)
        closed = _gh(["issue", "close", str(num), "-R", repo],
                     capture=True, token=token, check=True)
        rc |= 1 if (commented.returncode != 0 or closed.returncode != 0) else 0
        print("groom-alert: GROOM recovered — closed the alert")
    else:
        print("groom-alert: GROOM result={} — nothing to do".format(result or "unknown"))

    # The ring's own health (issue #1391), on the SAME already-fetched listing — a green tick still
    # costs exactly one `gh issue list`. Deliberately NOT short-circuited by the GROOM leg above:
    # the whole point of these watchdogs is that they are independent of the sweep they share a
    # file with, and a failed groom must not suppress the alarm for a failed watchdog.
    rc |= _handle_watchdogs(repo, token, found,
                            os.environ.get("WATCHDOG_NEEDS", ""), run_url, maintainer)
    return 1 if rc else 0


# =============================================================================================
# self-test helpers (YAML seam)
# =============================================================================================
def _repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _require(path):
    """Read a file the self-test asserts against. FAIL CLOSED: a missing input aborts the self-test
    loudly rather than making its assertions quietly unreachable — which is exactly what would
    happen if someone trimmed the job's sparse-checkout list."""
    full = os.path.join(_repo_root(), path)
    if not os.path.isfile(full):
        raise GroomAlertError(
            f"self-test input {path} is missing from the working copy at {_repo_root()} — the "
            "YAML-seam assertions cannot run, and a self-test that silently stops asserting is "
            "worse than no self-test. Add it to the job's sparse-checkout list.")
    with open(full, encoding="utf-8") as handle:
        return handle.read()


def _declared_needs(job):
    declared = job.get("needs")
    if declared is None:
        return []
    return [declared] if isinstance(declared, str) else list(declared)


def _eval_job_if(expr, needs):
    """EVALUATE a job-level `if:` against a hypothetical `needs` context (the restricted grammar
    this repo's alert legs use — mirrors scripts/metrics-alert.py's reviewed evaluator).

    `expr is None` models GitHub's default for a job WITH `needs:` and no `if:` — an implicit
    success() over every needed job. Modelling that is the entire point here: with the #1391
    watchdog edges, DELETING `if: always()` would silently suppress this alarm on exactly the ticks
    it now exists to report, and only an evaluation (not a string match) makes that visible.

    An expression outside the modelled grammar RAISES rather than being waved through: an
    unevaluatable gate is an unchecked polarity on a surface no runtime check can reach."""
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
    raise GroomAlertError(
        f"unmodelled job `if:` expression {expr!r} — this harness only evaluates the restricted "
        "grammar the alert legs use. Extend _eval_job_if deliberately, or keep the gate in the "
        "modelled grammar; an expression it cannot evaluate is an unchecked polarity.")


def _job_runs(job, outcomes):
    """Does `job` execute, given upstream job results? Models BOTH seams at once — the `needs:`
    edges the job declares AND its `if:`. An `if:`-only assertion cannot see an added edge, and an
    edge-only assertion cannot see a deleted gate."""
    needs = {name: {"result": outcomes.get(name, "success")} for name in _declared_needs(job)}
    return _eval_job_if(job.get("if"), needs)


def _invocations(step, script):
    """Executable `python3 .../<script>` command lines in a step's `run:` body, COMMENTS STRIPPED,
    returned as argument tails. A filename grep over a shell body is satisfied by a comment, an
    adjacent lint invocation, or a backslash-continuation tail — three separate ways a wiring
    assertion has gone vacuous in this estate."""
    body = step.get("run") or ""
    live = "\n".join(line for line in body.replace("\\\n", " ").splitlines()
                     if not line.strip().startswith("#"))
    pattern = re.compile(rf"^\s*python3\s+(?:\S*/)?{re.escape(script)}([^\n]*)$", re.M)
    return [match.group(1).split() for match in pattern.finditer(live)]


def _sparse_paths(job, path="registry"):
    """The sparse-checkout entries of the actions/checkout step materialising `path`, as EXACT
    lines — never a containment test over the raw block, since `.github/workflows` is a substring
    of `.github/workflows/groom.yml` and `scripts/groom-alert.py` of `scripts/groom-alert.pyc`.
    Fails closed on 0 or >1 matching checkouts: selecting by POSITION would follow a reordered
    step list into asserting against the wrong one."""
    found = [(step.get("with") or {}) for step in (job.get("steps") or [])
             if str(step.get("uses", "")).startswith("actions/checkout@")
             and (step.get("with") or {}).get("path") == path]
    if len(found) != 1:
        raise GroomAlertError(
            f"expected exactly one actions/checkout with `path: {path}`, found {len(found)}")
    spec = found[0].get("sparse-checkout") or ""
    return {line.strip() for line in str(spec).splitlines() if line.strip()}


def _test_workflow_seam(chk):
    """THE YAML SEAM (issue #1391). Every uncaught mutant measured in this estate lives one level
    above the Python — in a job `outputs:` block, a `needs:` edge, an `if:`, or a step `env:` line.
    The alarm this file implements is worth exactly as much as that wiring, so each half is pinned
    against groom.yml itself, and the watchdog SET is derived from that file's own job map rather
    than restated here: a watchdog added there without an alarm edge reds HERE."""
    import yaml  # lazy: present on ubuntu-latest and in the registry-selftest gate

    # THE HARNESS ITSELF, exercised directly and FIRST. Everything below runs the evaluator only
    # against the gate that IS there (`always()`), so under a green tree the branches that make the
    # marquee claim — "deleting the gate goes red here" — true are NEVER EXECUTED, and a bug in
    # them would be invisible until the tick it mattered (AGENTS.md pre-flight #1/#9: measured
    # line-granular, these were the only unexecuted lines this file had).
    unconditional = {"needs": ["groom", "w"]}
    chk("harness: a DELETED gate (`if:` absent) is modelled as GitHub's implicit success() over "
        "EVERY needed job — all-green upstream runs it, any non-success upstream does not",
        (_job_runs(unconditional, {}), _job_runs(unconditional, {"w": "failure"}),
         _job_runs(unconditional, {"groom": "skipped"})),
        (True, False, False))
    chk("harness: always() runs regardless of upstream; an explicit success() does not; `if: false` "
        "never runs; `if: true` always does",
        (_job_runs({"needs": ["w"], "if": "${{ always() }}"}, {"w": "failure"}),
         _job_runs({"needs": ["w"], "if": "success()"}, {"w": "failure"}),
         _job_runs({"needs": ["w"], "if": False}, {}),
         _job_runs({"needs": ["w"], "if": "true"}, {"w": "failure"})),
        (True, False, False, True))
    missing = None
    try:
        _require("scripts/no-such-self-test-input.py")
    except GroomAlertError:
        missing = "refused"
    chk("harness: a MISSING self-test input REFUSES loudly — a seam section that silently stops "
        "asserting is worse than no seam section", missing, "refused")
    ambiguous = None
    try:
        _sparse_paths({"steps": []})
    except GroomAlertError:
        ambiguous = "refused"
    chk("harness: zero (or more than one) matching checkout REFUSES rather than asserting against "
        "a step picked by position out of a reordered list", ambiguous, "refused")

    workflow = yaml.safe_load(_require(GROOM_WORKFLOW)) or {}
    jobs = workflow.get("jobs") or {}
    alert = jobs.get(ALERT_JOB) or {}
    watchdogs = sorted(set(jobs) - NON_WATCHDOG_JOBS)

    # EVIDENCE FLOOR first. A thin checkout, a truncated read or a broken parse yields a job map
    # with nothing in it, and every per-watchdog row below would then loop zero times and pass.
    chk(f"seam/floor: groom.yml parses, hosts `groom` and `{ALERT_JOB}`, and hosts at least "
        f"{MIN_WATCHDOGS} watchdog jobs (an empty parse makes every row below vacuously green)",
        (sorted(NON_WATCHDOG_JOBS - set(jobs)), len(watchdogs) >= MIN_WATCHDOGS), ([], True))

    # --- the ring is COMPLETE: every watchdog groom.yml hosts is alarmed -----------------------
    chk("seam: `needs:` is EXACTLY the sweep plus every watchdog job groom.yml hosts — the expected "
        "set comes from the job MAP, not from this list, so adding a watchdog without an alarm "
        "edge (or leaving an edge naming a job that no longer exists) reds here",
        sorted(_declared_needs(alert)), sorted(["groom"] + watchdogs))

    # --- ...and the gate that keeps those edges from SUPPRESSING the alarm ---------------------
    chk("seam: the gate is EXACTLY `${{ always() }}` (exact match: a substring test is satisfied "
        "by `always() && false`)", str(alert.get("if")).strip(), "${{ always() }}")
    chk("seam: ...and it is EVALUATED over every upstream outcome — DELETING the gate (leaving "
        "GitHub's implicit success() over six needed jobs), inverting it, or pinning it false all "
        "go red HERE instead of on the one tick nobody is watching",
        {f"{job}={result}": _job_runs(alert, {job: result})
         for job in ["groom"] + watchdogs
         for result in ("success", "failure", "cancelled", "skipped")},
        {f"{job}={result}": True
         for job in ["groom"] + watchdogs
         for result in ("success", "failure", "cancelled", "skipped")})
    unmodelled = False
    try:
        _eval_job_if("needs.groom.result == 'failure'", {"groom": {"result": "failure"}})
    except GroomAlertError:
        unmodelled = True
    chk("seam: a gate rewritten outside the modelled grammar RAISES rather than silently ceasing "
        "to be checked — the evaluator must not be the next thing that fails open", unmodelled, True)

    # --- each watchdog publishes the ONLY signal its continue-on-error crash leaves behind ------
    for name in watchdogs:
        job = jobs.get(name) or {}
        chk(f"seam/{name}: publishes its alert step's outcome as the `{WATCHDOG_OUTPUT_KEY}` job "
            "output — with this block gone the job result is `success` and the crash is invisible",
            (job.get("outputs") or {}).get(WATCHDOG_OUTPUT_KEY),
            "${{ steps.%s.outcome }}" % name)
        ided = [step for step in (job.get("steps") or []) if step.get("id") == name]
        chk(f"seam/{name}: hosts EXACTLY ONE step with `id: {name}` — the output above names that "
            "id, and an output keyed on an id no step carries evaluates to the empty string on "
            "every tick, which this script reads as 'no evidence' forever", len(ided), 1)
        chk(f"seam/{name}: that step still carries `continue-on-error: true` — the asymmetry IS "
            "the invariant: the fault must not red the sweep, which is precisely why the outcome "
            "has to be published instead of relied on through the job result",
            [step.get("continue-on-error") for step in ided], [True])
        chk(f"seam/{name}: the watchdog itself declares no `needs:` and no `if:` — a node "
            "suppressed by the failure of the sweep it shares a file with is not a watchdog",
            (_declared_needs(job), "if" in job), ([], False))

    # --- the call site: the outcomes actually REACH this script --------------------------------
    invoking = [step for step in (alert.get("steps") or [])
                if _invocations(step, "groom-alert.py")]
    chk("seam/call site: exactly one step in the alert job invokes this script", len(invoking), 1)
    step = invoking[0] if invoking else {}
    chk("seam/call site: it runs `--self-test` and then the live alert, in that order, matched on "
        "TOKENISED argv (containment is satisfied by `--self-test-DISABLED`)",
        _invocations(step, "groom-alert.py"), [["--self-test"], []])
    env = step.get("env") or {}
    chk("seam/call site: the GROOM job result arrives as GROOM_RESULT",
        env.get("GROOM_RESULT"), "${{ needs.groom.result }}")
    chk("seam/call site: the WHOLE needs context arrives as WATCHDOG_NEEDS — drop this ONE line "
        "and watchdog_states() reads an empty payload, so every node silently reports 'no "
        "evidence' and the #1391 alarm is disarmed with nothing else changing",
        env.get("WATCHDOG_NEEDS"), "${{ toJSON(needs) }}")
    chk("seam/call site: the alert step is continue-on-error, so an alarm fault can never red the "
        "run that hosts the sweep and the ring", step.get("continue-on-error"), True)

    # --- this self-test's own inputs are actually materialised in the live job ------------------
    for path in REQUIRED_FILES:
        _require(path)
    chk("seam/inputs: the alert job sparse-checks-out every file this self-test reads, each on its "
        "own EXACT line — a trimmed list would make the whole seam section unreachable on the live "
        "path instead of red", sorted(set(REQUIRED_FILES) - _sparse_paths(alert)), [])
    chk("seam/inputs: enrolled in scripts/selftest-suite.txt, so this cannot silently leave the "
        "gate", os.path.basename(__file__) in _require("scripts/selftest-suite.txt").split(), True)


def _self_test():
    ok = True

    def chk(n, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {n}: {got} (want {want})")

    # Routing (mirrors usage-alert.py's audited matrix, incl. the #432 round-1 / issue #436
    # positive private-destination verification: configuration alone never selects ALERT_REPO).
    vis_calls = []
    chk("route: repo+token+CONFIRMED private -> private + token",
        _alert_route("org/private", "tok", "org/registry",
                     confirmed_private=lambda r, t: vis_calls.append((r, t)) or True),
        ("org/private", "tok"))
    chk("route: the visibility check runs against the ALERT repo under the ALERT token",
        vis_calls, [("org/private", "tok")])
    chk("route: ALERT_REPO == REGISTRY_REPO -> registry fallback (the registry is never private)",
        _alert_route("org/registry", "tok", "org/registry",
                     confirmed_private=lambda r, t: True), ("org/registry", None))
    chk("route: same-repo rejection is case-insensitive (GitHub repo names are)",
        _alert_route("Org/Registry", "tok", "org/registry",
                     confirmed_private=lambda r, t: True), ("org/registry", None))
    chk("route: UNCONFIRMED visibility (public repo or failed lookup) -> registry, fail closed",
        _alert_route("org/other-public", "tok", "org/registry",
                     confirmed_private=lambda r, t: False), ("org/registry", None))
    half_calls = []
    chk("route: repo but NO token -> registry fallback, and NO visibility call (#39)",
        (_alert_route("org/private", "", "org/registry",
                      confirmed_private=lambda r, t: half_calls.append(r) or True),
         half_calls),
        (("org/registry", None), []))
    chk("route: repo but None token -> registry fallback",
        _alert_route("org/private", None, "org/registry",
                     confirmed_private=lambda r, t: True), ("org/registry", None))
    chk("route: no repo -> registry",
        _alert_route("", "tok", "org/registry",
                     confirmed_private=lambda r, t: True), ("org/registry", None))
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

    # ---- the ring's own health (issue #1391) -------------------------------------------------
    # watchdog_states(): the partition, the two legs, and fail-closed on unreadable evidence.
    def _needs(jobs):
        """A `toJSON(needs)` payload from {job: (result, outcome)}. `outcome=None` omits the output
        entirely — what an un-wired, skipped or cancelled job actually produces."""
        return json.dumps({
            name: ({"result": result, "outputs": {}} if outcome is None
                   else {"result": result, "outputs": {WATCHDOG_OUTPUT_KEY: outcome}})
            for name, (result, outcome) in jobs.items()})

    chk("states: the non-watchdog partition is dropped and every other needed job is kept, sorted",
        watchdog_states(_needs({"groom": ("success", None), "z-late": ("success", "success"),
                                "a-early": ("failure", "skipped")})),
        [("a-early", "failure", "skipped"), ("z-late", "success", "success")])
    chk("states: `groom-alert` (this job itself, were it ever to appear) is not a watchdog",
        watchdog_states(json.dumps({ALERT_JOB: {"result": "success", "outputs": {}}})), [])
    chk("states: a job whose output is ABSENT reads as the empty string, never as healthy",
        watchdog_states(_needs({"w": ("success", None)})), [("w", "success", "")])
    chk("states: an unparseable payload yields NO evidence (fail closed)",
        watchdog_states("SENTINEL-NOT-JSON {"), [])
    chk("states: a payload that is valid JSON but not an object yields NO evidence",
        (watchdog_states('["metrics-stale"]'), watchdog_states('"x"')), ([], []))
    chk("states: an absent/empty WATCHDOG_NEEDS yields NO evidence",
        (watchdog_states(""), watchdog_states(None)), ([], []))
    chk("states: a malformed per-job entry degrades to empty legs, never crashes",
        watchdog_states(json.dumps({"w": 42, "x": {"result": 7, "outputs": "nope"}})),
        [("w", "", ""), ("x", "", "")])

    # decide_watchdog(): BOTH legs independently raise, and recovery needs BOTH explicitly green.
    chk("watchdog: the CONTINUE-ON-ERROR HOLE — job success + alert step FAILED -> upsert (this "
        "single row is the whole of issue #1391; without it a crashing watchdog is green forever)",
        decide_watchdog("success", "failure", False), "upsert")
    chk("watchdog: job failure (checkout / PyYAML / the self-test step / timeout) -> upsert",
        decide_watchdog("failure", "", False), "upsert")
    chk("watchdog: job cancelled -> upsert", decide_watchdog("cancelled", "", False), "upsert")
    chk("watchdog: both legs green + open alert -> close",
        decide_watchdog("success", "success", True), "close")
    chk("watchdog: both legs green + nothing open -> noop",
        decide_watchdog("success", "success", False), "noop")
    chk("watchdog: job success but the outcome is UNPUBLISHED -> noop, and specifically NOT close "
        "(an un-wired output must never be mistaken for a recovery)",
        decide_watchdog("success", "", True), "noop")
    chk("watchdog: job success + step SKIPPED -> noop, not close",
        decide_watchdog("success", "skipped", True), "noop")
    chk("watchdog: job SKIPPED + step success -> noop, not close",
        decide_watchdog("skipped", "success", True), "noop")
    chk("watchdog: job failure wins over a green step outcome -> upsert",
        decide_watchdog("failure", "success", True), "upsert")
    # ANTI-VACUITY for the two legs: neither is redundant. Flip one leg at a time from the healthy
    # pair and the verdict must move — a decide_watchdog that ignored either input would show a
    # constant here.
    chk("watchdog: each leg is load-bearing — flipping EITHER one away from success changes the "
        "verdict from close",
        (decide_watchdog("success", "success", True),
         decide_watchdog("failure", "success", True),
         decide_watchdog("success", "failure", True)),
        ("close", "upsert", "upsert"))

    # markers/titles/bodies are per-node and mutually non-containing, or two nodes share one alert.
    names = ["metrics-stale", "dispatch-stall", "ci-latency", "ratelimit-budget", "mint-gap"]
    chk("watchdog: every node gets a distinct marker and a distinct title",
        (len({watchdog_marker(n) for n in names}), len({watchdog_title(n) for n in names})),
        (len(names), len(names)))
    chk("watchdog: no node's marker occurs inside another node's marker (a prefix collision would "
        "make two nodes dedupe onto one issue)",
        [(a, b) for a in names for b in names
         if a != b and watchdog_marker(a) in watchdog_marker(b)], [])
    chk("watchdog: the GROOM alert's marker is not found in a watchdog body, and vice versa — the "
        "two conditions must never dedupe onto each other's issue",
        (ALERT_MARKER in _render_watchdog_body("ci-latency", "success", "failure", "u", "m"),
         watchdog_marker("ci-latency") in _render_body("failure", "u", "m")), (False, False))
    wbody = _render_watchdog_body("ci-latency", "success", "failure",
                                  "https://example.test/run/9", "jeswr")
    chk("watchdog body: carries its own marker, the node name, BOTH legs, the run link and the "
        "mention (and no account handle or ledger content by construction)",
        (watchdog_marker("ci-latency") in wbody, "ci-latency" in wbody, "`success`" in wbody,
         "`failure`" in wbody, "https://example.test/run/9" in wbody, "@jeswr" in wbody),
        (True, True, True, True, True, True))
    chk("watchdog body: an unpublished outcome is rendered as `unpublished`, never as a blank the "
        "maintainer has to guess at",
        "`unpublished`" in _render_watchdog_body("mint-gap", "success", "", "u", "m"), True)

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
                "MAINTAINER_HANDLE": "m", "ALERT_REPO": "", "ALERT_TOKEN": "",
                "WATCHDOG_NEEDS": ""}

    def run_main(groom_result, list_json="[]", fail=(), alert_repo="", alert_token="",
                 visibility='{"private": true}', needs_json=""):
        calls.clear()
        responses.clear()
        responses[("issue", "list")] = _Result(1 if ("issue", "list") in fail else 0, list_json)
        # The route's live GET /repos/{ALERT_REPO}: private by default so the pre-#436 flow
        # assertions keep exercising the private route; `visibility` injects the other shapes.
        if alert_repo:
            responses[("api", f"repos/{alert_repo}")] = _Result(0, visibility)
        for key in fail:
            if key != ("issue", "list"):
                responses[key] = _Result(1)
        os.environ.update(base_env)
        os.environ["GROOM_RESULT"] = groom_result
        os.environ["ALERT_REPO"] = alert_repo
        os.environ["ALERT_TOKEN"] = alert_token
        os.environ["WATCHDOG_NEEDS"] = needs_json
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
        # #436 END-TO-END: a fully-configured but UNVERIFIABLE destination must not become the
        # alert repo — the alert still lands (fail closed on privacy, not on delivery), on the
        # registry, and never under the alert token.
        run_main("failure", alert_repo="org/public", alert_token="sentinel-alert-tok",
                 visibility='{"private": false}')
        create_pub, env_pub = find(("issue", "create"))
        chk("wiring: PUBLIC ALERT_REPO -> registry fallback, alert still lands, no ALERT_TOKEN",
            (create_pub is not None and create_pub[create_pub.index("-R") + 1],
             (env_pub or {}).get("GH_TOKEN") == "sentinel-alert-tok",
             ("api", "repos/org/public") in subs()),
            ("org/registry", False, True))
        # ...and a same-repo ALERT_REPO is rejected WITHOUT spending a visibility probe.
        run_main("failure", alert_repo="ORG/Registry", alert_token="sentinel-alert-tok")
        create_same, env_same = find(("issue", "create"))
        chk("wiring: ALERT_REPO == REGISTRY_REPO -> registry fallback, NO visibility probe",
            (create_same is not None and create_same[create_same.index("-R") + 1],
             (env_same or {}).get("GH_TOKEN") == "sentinel-alert-tok",
             [s for s in subs() if s[0] == "api"]),
            ("org/registry", False, []))
        # _repo_confirmed_private itself: True ONLY on a definitive `"private": true`; every
        # failure shape is False (fail closed), and the lookup runs under the ROUTE token.
        vis_seen = []

        def vis_gh(rc, stdout):
            def run(cmd, capture_output=False, text=False, env=None):
                vis_seen.append((list(cmd), (env or {}).get("GH_TOKEN")))
                return _Result(rc, stdout)
            return run

        subprocess.run = vis_gh(0, json.dumps({"private": True, "full_name": "org/private"}))
        chk("visibility: definitive private=true -> True, GET repos/{repo} under the route token",
            (_repo_confirmed_private("org/private", "route-tok"), vis_seen[0]),
            (True, (["gh", "api", "repos/org/private"], "route-tok")))
        subprocess.run = vis_gh(0, json.dumps({"private": False}))
        chk("visibility: a PUBLIC destination -> False (fail closed)",
            _repo_confirmed_private("org/pub", "t"), False)
        subprocess.run = vis_gh(1, "")
        chk("visibility: failed lookup -> False (fail closed, never assumed private)",
            _repo_confirmed_private("org/private", "t"), False)
        subprocess.run = vis_gh(0, "SENTINEL-NOT-JSON")
        chk("visibility: unparseable payload -> False (fail closed)",
            _repo_confirmed_private("org/private", "t"), False)
        subprocess.run = vis_gh(0, json.dumps({"private": "true"}))
        chk("visibility: anything but a literal private=true bool -> False",
            _repo_confirmed_private("org/private", "t"), False)
        subprocess.run = fake_run
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

        # ---- THE RING'S OWN HEALTH, end to end through main() (issue #1391) ------------------
        def created_field(flag):
            return [cmd[cmd.index(flag) + 1] for cmd, _e in calls
                    if tuple(cmd[1:3]) == ("issue", "create") and flag in cmd]

        rc_w0, _ = run_main("success", needs_json=_needs({"metrics-stale": ("success", "success"),
                                                          "ci-latency": ("success", "success")}))
        chk("flow/watchdog: a fully healthy ring with nothing open costs the ONE `issue list` "
            "already fetched and mutates nothing",
            (rc_w0, subs()), (0, [("issue", "list")]))
        rc_w1, _ = run_main("success", needs_json=_needs({"ci-latency": ("success", "failure"),
                                                          "mint-gap": ("success", "success")}))
        chk("flow/watchdog: THE HOLE #1391 CLOSES — a job whose RESULT is `success` but whose "
            "continue-on-error alert step FAILED files exactly one alert, for that node only "
            "(the healthy sibling on the same tick files nothing)",
            (rc_w1, created_field("--title")), (0, [watchdog_title("ci-latency")]))
        chk("flow/watchdog: ...and the filed body carries that node's own dedupe marker",
            [watchdog_marker("ci-latency") in body for body in created_field("--body")], [True])
        open_w = json.dumps([{"number": 31, "title": "renamed by a maintainer",
                              "body": "prose\n" + watchdog_marker("ci-latency") + "\nmore"}])
        rc_w2, _ = run_main("success", open_w,
                            needs_json=_needs({"ci-latency": ("success", "failure")}))
        edit_w, _ = find(("issue", "edit"))
        chk("flow/watchdog: an already-open (even RENAMED) node alert is edited, never twinned",
            (rc_w2, ("issue", "create") in subs(), edit_w is not None and "31" in edit_w),
            (0, False, True))
        rc_w3, _ = run_main("success", open_w,
                            needs_json=_needs({"ci-latency": ("success", "success")}))
        close_w, _ = find(("issue", "close"))
        chk("flow/watchdog: BOTH legs explicitly green -> comment + close THAT node's alert",
            (rc_w3, ("issue", "comment") in subs(), close_w is not None and "31" in close_w),
            (0, True, True))
        rc_w4, _ = run_main("success", open_w,
                            needs_json=_needs({"ci-latency": ("success", None)}))
        chk("flow/watchdog: an open alert + an UNPUBLISHED outcome -> NO mutation. This is the "
            "fail-closed direction: un-wiring the `outputs:` block must not silently CLOSE every "
            "node alert and report the ring healthy",
            (rc_w4, [s for s in subs() if s != ("issue", "list")]), (0, []))
        rc_w5, _ = run_main("failure", needs_json=_needs({"ci-latency": ("success", "failure")}))
        chk("flow/watchdog: a FAILING groom sweep does not suppress the ring's alarm — both "
            "conditions file on the same tick, each on its own issue",
            (rc_w5, sorted(created_field("--title"))),
            (0, sorted([ALERT_TITLE, watchdog_title("ci-latency")])))
        rc_w6, _ = run_main("success", needs_json=_needs({"ci-latency": ("success", "failure"),
                                                          "mint-gap": ("failure", "")}))
        chk("flow/watchdog: N faulty nodes -> N alerts, and the idempotent label create is spent "
            "ONCE for the tick rather than once per node",
            (rc_w6, sorted(created_field("--title")),
             len([s for s in subs() if s == ("label", "create")])),
            (0, sorted([watchdog_title("ci-latency"), watchdog_title("mint-gap")]), 1))
        rc_w7, out_w7 = run_main("success",
                                 needs_json=_needs({"ci-latency": ("success", "failure")}),
                                 fail=(("issue", "create"),))
        chk("flow/watchdog: a failed node-alert write -> rc=1 + sanitized warning (stderr never "
            "echoed)",
            (rc_w7, "::warning::" in out_w7, "SENTINEL-STDERR" in out_w7), (1, True, False))
        run_main("success", needs_json=_needs({"ci-latency": ("success", "failure")}),
                 alert_repo="org/private", alert_token="sentinel-alert-tok")
        wcmd, wenv = find(("issue", "create"))
        chk("flow/watchdog: node alerts take the SAME verified-private route as the groom alert",
            (wcmd is not None and wcmd[wcmd.index("-R") + 1], (wenv or {}).get("GH_TOKEN")),
            ("org/private", "sentinel-alert-tok"))
        rc_w8, _ = run_main("success", fail=(("issue", "list"),),
                            needs_json=_needs({"ci-latency": ("success", "failure")}))
        chk("flow/watchdog: an unreadable listing refuses BOTH conditions — without it a node "
            "alert could neither be deduped nor proven absent",
            (rc_w8, [s for s in subs() if s != ("issue", "list")]), (1, []))
    finally:
        subprocess.run = real_run
        for key in base_env:
            os.environ.pop(key, None)
    # LAST, deliberately: the seam reads files and raises loudly when one is missing, so every row
    # above has already printed by the time it can abort (AGENTS.md pre-flight #4 — a run that dies
    # part-way records as a pass for every check it never reached).
    _test_workflow_seam(chk)
    print("groom-alert self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
