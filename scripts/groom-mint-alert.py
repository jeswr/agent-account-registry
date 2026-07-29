#!/usr/bin/env python3
# [OPUS-5] A DURABLE CREDENTIAL GAP ON ONE OWNER MUST NOT LOOK LIKE A GREEN TICK (issue #269).
#
# THE DEFECT THIS EXISTS FOR. The issue #168 fix made each per-owner target App-token mint in
# groom.yml `continue-on-error`, and that is correct: policy enables targets under two distinct
# owners, and one owner's missing install must never abort the sweep before dead leases are
# released. groom.py then resolves the token for each target repo's OWNER and, finding none,
# DEFERS that owner's issue/PR repair with a log line:
#
#     skip target grooming for <owner>/<repo>: no App token minted for owner '<owner>' —
#     its issue/PR repair defers this tick (dead-lease release still runs)
#
# Fail-closed and right. But it is a DEFER, and a defer that repeats forever is an outage wearing
# a green check: if the install is removed from an owner (or its key is rotated out, or the App is
# no longer granted that owner's repos), the registry silently stops self-grooming HALF its target
# surface while every tick reports success, every step is green, and the only evidence is one line
# in a cron log nobody reads. groom-alert.py cannot see it — it keys on the groom job RESULT, and
# the job succeeds. That is exactly the shape scripts/dispatch-stall-alert.py exists for on the
# dispatch side, so this is the same posture applied to groom: alarm on the CONDITION, not on the
# run.
#
# THE SIGNAL, and why it is an artifact NAME. A consecutive-tick streak is cross-run state, and
# there are only three places to keep it. Run conclusions cannot express it (the tick concludes
# `success` either way). Step conclusions cannot be trusted to express it (whether the REST jobs
# endpoint reports `failure` for a step that failed under `continue-on-error` is an undocumented
# detail, and a detector that silently reads "healthy" if that guess is wrong is a fail-OPEN
# detector — the one kind this repo may not ship). So groom.yml records it itself, in the one
# place a listing can read without downloading anything and without a token: the artifact NAME.
#
#     groom-mint-tick ( .ok-<owner> | .skip-<owner> )*
#
# A GitHub owner login is `[A-Za-z0-9-]+`, so `.` cannot occur inside one and separates
# unambiguously. The bare `groom-mint-tick` prefix is load-bearing on its own: it proves the tick
# REACHED the mint stage, so a run that died earlier (ledger data-only invariant sweep, the
# per-owner repo resolve) is not counted as evidence of a mint gap rather than being miscounted as
# two skipped owners. And recording the `.ok-` side as well as the `.skip-` side is what makes
# RECOVERY observable: an owner that starts minting again — or that is dropped from the workflow
# entirely — stops appearing in any skip set on the newest tick, which is the close signal.
#
# WHERE IT IS HOSTED. groom.yml, as its own job with NO `needs:` and NO `if:`, exactly like the
# `metrics-stale` and `dispatch-stall` watchdogs it sits beside and for the same reason: a watchdog
# suppressed by the failure of the sweep it shares a workflow file with is not a watchdog. The cost
# of that choice is bounded and stated — the job runs CONCURRENTLY with the sweep, so this tick's
# own marker may not be uploaded yet and detection can lag by one tick (~15 min against a
# multi-hour credential gap). _test_threshold_vs_cadence asserts the resulting page latency band.
#
# PAGING POLICY / AUTHORITY CEILING: identical to scripts/dispatch-stall-alert.py. This script may
# create/edit/comment/close ONE `ops-alert` issue per OWNER and nothing else — no arming path, no
# merge path, no PR path, and no code path that can write a `needs:`/`status:`/`role:` label
# (enforced by _test_authority_ceiling below, not by convention). Alerts auto-close on an explicit
# recovery. Its job carries `actions: read` + `contents: read` + `issues: write`.
#
# PRIVACY. The alert body names an OWNER LOGIN (`sparq-org`, `jeswr`) and nothing else that is not
# a machine-derived integer or a run URL. That is not an account handle in the locked-decision-22
# sense: owner logins are already public in this repo's `policy/repos.toml`, already teed into this
# very run log by groom.yml's own per-owner repo resolve, and already printed by groom.py's skip
# line. No provider account handle, no token, and no byte of any remote payload can reach a body
# here — so the registry-repo fallback in _alert_route is safe.
#
# DEBT (issue #591, PR #590): `_alert_route` is another private copy of locked decision 22c.
# scripts/alert_route.py is not on master, so this file carries a byte-compatible copy with the
# IDENTICAL signature; migration is a one-line import swap.
import ast
import json
import os
import re
import subprocess
import sys

ALERT_LABEL = "ops-alert"

# The artifact-name grammar. Written by groom.yml's `mint-marker` step and by nothing else; both
# halves are asserted against the LIVE workflow by _test_workflow_seam, so a rename on either side
# reds instead of silently emptying the detector.
TICK_MARKER_PREFIX = "groom-mint-tick"
MARKER_SEPARATOR = "."
MARKER_OK = "ok"
MARKER_SKIP = "skip"
# GitHub logins: 1-39 chars, alphanumerics and hyphens, no leading/trailing hyphen. Anchored, so a
# token that is not a well-formed `<ok|skip>-<login>` makes the WHOLE marker unparseable and the
# tick is dropped as non-evidence rather than half-read.
MARKER_TOKEN_RE = re.compile(
    rf"^({MARKER_OK}|{MARKER_SKIP})-([A-Za-z0-9](?:[A-Za-z0-9-]{{0,37}}[A-Za-z0-9])?)$")
OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")

# FOUR consecutive ticks. groom's cron is `7-59/15`, i.e. one tick every 15 minutes, so this is a
# full hour of an owner's issue/PR repair deferring before anyone is paged — and with the one-tick
# lag the no-`needs:` hosting costs, at most ~75 minutes. Sizing, both directions:
#   - lower bound: the mint is one call to GitHub's App API. A transient 5xx or a rate blip takes
#     ONE tick; two would page on an unlucky pair, which is the noise the paging policy forbids.
#   - upper bound: this is a credential gap, not a stall — nothing recovers it without a human, so
#     a threshold past a couple of hours only delays the page it was always going to send.
# _test_threshold_vs_cadence asserts both against the LIVE cron in groom.yml.
SKIP_STREAK_THRESHOLD = 4

ARTIFACT_PAGE_SIZE = 100
ARTIFACT_MAX_PAGES = 3

ALERT_MARKER_PREFIX = "<!-- groom-mint-alert:v1 key=groom-mint-gap owner="
ALERT_MARKER_RE = re.compile(
    re.escape(ALERT_MARKER_PREFIX) + r"([A-Za-z0-9][A-Za-z0-9-]{0,38}) -->")

GROOM_WORKFLOW = ".github/workflows/groom.yml"
HOST_JOB = "mint-gap"
GROOM_JOB = "groom"
MARKER_STEP_ID = "mint-marker"
UPLOAD_STEP_ID = "mint-marker-upload"
SWEEP_STEP_ID = "sweep"
MINT_STEP_IDS = ("target-token-sparq", "target-token-jeswr")

# Every file the self-test asserts against. The host job sparse-checks-out exactly this set and
# _test_workflow_seam asserts that it does — a trimmed checkout would make the YAML-seam
# assertions silently unreachable on the live path.
REQUIRED_FILES = (
    "scripts/groom-mint-alert.py",
    GROOM_WORKFLOW,
)


class GroomMintAlertError(Exception):
    """A contract this script refuses to guess about."""


def _alert_route(alert_repo, alert_token, registry_repo):
    """(repo, token) for the alert issue — locked decision 22c / issue #39, identical semantics and
    signature to scripts/dispatch-stall-alert.py's private copy: the private ALERT_REPO is the
    destination ONLY when ALERT_TOKEN can write there; a half-configured deployment (repo set,
    token missing) falls back to the registry repo under the ambient token instead of silently
    losing the alert."""
    if alert_repo and alert_token:
        return alert_repo, alert_token
    return registry_repo, None


# ---------------------------------------------------------------------------------------------
# pure derivations over the artifacts listing
# ---------------------------------------------------------------------------------------------
def parse_marker_name(name):
    """`groom-mint-tick(.ok-<owner>|.skip-<owner>)*` -> (ok_owners, skip_owners), else None.

    None means "not evidence" and is returned for anything that is not EXACTLY this grammar —
    another workflow's artifact, a truncated name, an owner token this reader cannot classify.
    Partial credit is the dangerous answer here: a name whose second half failed to parse would
    otherwise contribute a phantom "not skipped" tick and silently reset a real streak."""
    if not isinstance(name, str) or not name:
        return None
    parts = name.split(MARKER_SEPARATOR)
    if parts[0] != TICK_MARKER_PREFIX:
        return None
    ok, skip = set(), set()
    for token in parts[1:]:
        matched = MARKER_TOKEN_RE.match(token)
        if matched is None:
            return None
        (ok if matched.group(1) == MARKER_OK else skip).add(matched.group(2))
    # One owner cannot be both minted and skipped on one tick; a name claiming it is malformed.
    if ok & skip:
        return None
    return ok, skip


def _artifacts(payload):
    if not isinstance(payload, dict):
        return []
    entries = payload.get("artifacts")
    if not isinstance(entries, list):
        return []
    return [entry for entry in entries if isinstance(entry, dict)]


def tick_records(payload, into=None):
    """-> {run_id: (created_at, ok_owners, skip_owners)} for every parseable, unexpired marker.

    Keyed on the RUN id, not on the artifact id: a re-run uploads a second marker under the same
    run, and counting one tick twice would let a two-tick outage reach a four-tick threshold. The
    newest `created_at` for a run wins, so a re-run's marker supersedes the original's."""
    records = {} if into is None else into
    for entry in _artifacts(payload):
        if entry.get("expired") is True:
            continue
        parsed = parse_marker_name(entry.get("name"))
        if parsed is None:
            continue
        run = entry.get("workflow_run")
        run_id = run.get("id") if isinstance(run, dict) else None
        if not isinstance(run_id, int) or isinstance(run_id, bool):
            continue
        created = entry.get("created_at")
        if not isinstance(created, str) or not created:
            continue
        previous = records.get(run_id)
        if previous is None or created > previous[0]:
            records[run_id] = (created, parsed[0], parsed[1])
    return records


def ordered_ticks(records):
    """Marker ticks NEWEST FIRST -> [(ok_owners, skip_owners)].

    Sorted on (created_at, run_id) rather than trusting the endpoint's ordering: the artifacts
    listing returns newest-first today, but a watchdog should not have a correctness dependency on
    an undocumented ordering, and the run id breaks ties between two markers stamped in the same
    second. The timestamps are RFC3339 in UTC with fixed width, so a lexical sort IS a chronological
    one."""
    ordered = sorted(records.items(), key=lambda item: (item[1][0], item[0]), reverse=True)
    return [(ok, skip) for _run_id, (_created, ok, skip) in ordered]


def owners_seen(ticks):
    """Every owner any visible tick minted for, whether it succeeded or was skipped."""
    seen = set()
    for ok, skip in ticks:
        seen |= ok | skip
    return seen


def skip_streaks(ticks, owners):
    """-> {owner: consecutive newest-first ticks on which that owner was SKIPPED}.

    An owner named by NEITHER set on a tick ends its streak. That is deliberate and is the whole
    close path for an owner groom no longer mints for at all (dropped from policy, or the workflow
    step removed): it is not skipped, there is no repair deferring for it, and an open alert about
    it must be closeable rather than immortal."""
    streaks = {}
    for owner in owners:
        streak = 0
        for _ok, skip in ticks:
            if owner not in skip:
                break
            streak += 1
        streaks[owner] = streak
    return streaks


def gap_verdict(streak, ticks_seen, threshold=SKIP_STREAK_THRESHOLD):
    """'gap' | 'flapping' | 'recovered' | 'unknown'.

    'unknown' when no tick is visible at all — with no evidence the honest answer is neither a page
    nor a close, and closing on it would let an artifact-retention edge silently retire a live
    alert. 'recovered' requires a streak of ZERO (the newest visible tick minted that owner, or no
    longer mints it), not merely a streak under threshold: a mint that fails on three ticks out of
    four is still broken, and closing on that would flap the alert open and shut."""
    if not isinstance(ticks_seen, int) or ticks_seen <= 0:
        return "unknown"
    if streak >= threshold:
        return "gap"
    if streak == 0:
        return "recovered"
    return "flapping"


def decide(verdict, has_open_alert):
    """'upsert' | 'close' | 'noop'."""
    if verdict == "gap":
        return "upsert"
    if verdict == "recovered" and has_open_alert:
        return "close"
    return "noop"


# ---------------------------------------------------------------------------------------------
# issue bodies — fixed templates over a closed set of machine-derived scalars. No provider account
# handle, no token, and no byte of any remote payload can reach one.
# ---------------------------------------------------------------------------------------------
def alert_marker(owner):
    return f"{ALERT_MARKER_PREFIX}{owner} -->"


def alert_title(owner):
    return (f"⚠️ groom cannot mint a target App token for `{owner}` — that owner's issue/PR "
            "repair is deferring on every tick")


def _render_body(owner, streak, run_url, workflow_url, maintainer):
    return (
        f"{alert_marker(owner)}\n"
        "> 🤖 SPARQ agent — automated ops-alert (issue #269)\n\n"
        f"@{maintainer} groom has failed to mint a target-scoped App token for the owner "
        f"`{owner}` on the last **{streak}** scheduled ticks in a row (threshold "
        f"**{SKIP_STREAK_THRESHOLD}**).\n\n"
        "Every one of those ticks was GREEN, and that is the point of this alert. The per-owner "
        "mint is `continue-on-error` on purpose (issue #168) so one owner's credential gap cannot "
        "abort the sweep before dead leases are released — so groom simply logs `skip target "
        f"grooming for {owner}/...` and defers that owner's ENTIRE issue/PR repair: no stale "
        "in-progress issue is returned to `ready`, no orphaned worker PR is closed, no exhausted "
        "attempt budget is repaired, on any repo under that owner. Dead-lease release and the "
        "other owners' grooming are unaffected.\n\n"
        f"- groom runs: {workflow_url}\n"
        f"- Detected by: {run_url}\n\n"
        "This is a credential gap, not a transient — nothing recovers it without a maintainer. "
        "Check, in order:\n"
        f"1. **Is the registry App still installed on `{owner}`?** An install removed or "
        "transferred is the shape this alert was written for.\n"
        f"2. **Does the install still grant every repo policy enables under `{owner}`?** The mint "
        "requests them by name, so one repo added to `policy/repos.toml` but not to the install "
        "fails the whole mint for that owner.\n"
        "3. **`REGISTRY_ADMIN_APP_ID` / `REGISTRY_ADMIN_APP_KEY`** — a rotated or expired key "
        "fails every owner at once, so expect a sibling alert if that is the cause.\n\n"
        "The failing step is `Mint <owner> target-scoped maintenance App token` in the `groom` "
        "job; its own log line names the API refusal. This alert auto-closes as soon as one tick "
        f"mints a token for `{owner}` again.\n"
    )


def _recovered_note(owner):
    return (f"✅ Recovered — groom minted a target App token for `{owner}` again (or no longer "
            "mints for that owner at all). Auto-closing.")


# ---------------------------------------------------------------------------------------------
# gh plumbing — mirrors scripts/dispatch-stall-alert.py exactly
# ---------------------------------------------------------------------------------------------
def _gh(args, capture=False, token=None, check=False, label="groom-mint"):
    # Sanitized fail-loud wrapper: op + returncode only — never stderr (GH_DEBUG=api can echo
    # request bodies) and never argument content beyond the gh subcommand words.
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    result = subprocess.run(["gh"] + args, capture_output=capture, text=True, env=env, check=False)
    if check and result.returncode != 0:
        print(f"::warning::{label}: gh {args[0]} "
              f"{args[1] if len(args) > 1 else ''} failed (rc={result.returncode})")
    return result


def _gh_json(args, label="groom-mint"):
    result = _gh(args, capture=True, check=True, label=label)
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout or "null")
    except ValueError:
        print(f"::warning::{label}: gh {args[0]} succeeded but returned unparseable JSON")
        return None


def read_ticks(repo, runner=None, threshold=SKIP_STREAK_THRESHOLD):
    """The artifacts listing this watchdog costs -> (ticks_newest_first, truncated).

    Pages only until it has THRESHOLD+1 ticks — one more than the streak can consume, so the tick
    that would BREAK the streak is always in view — or the page runs dry. At today's density page
    one reaches back hours and covers that in a single request; the bound exists so an artifact
    storm from an unrelated workflow costs a couple more requests instead of an unbounded crawl.
    `truncated` reports that the crawl stopped short of that many ticks, so a bounded read is
    stated in the log rather than silently read as a short history.

    `runner` is resolved at CALL time, not bound as a default: a default argument captures the
    function object at definition, which makes the live path unpatchable and every stubbed-flow
    assertion below quietly exercise the real `gh`. -> (None, False) if the FIRST page is refused;
    without it there is no evidence at all and the caller must fail loud, not read "healthy"."""
    runner = runner or _gh_json
    records, wanted = {}, threshold + 1
    for page in range(1, ARTIFACT_MAX_PAGES + 1):
        payload = runner(["api", "-H", "Accept: application/vnd.github+json",
                          f"/repos/{repo}/actions/artifacts"
                          f"?per_page={ARTIFACT_PAGE_SIZE}&page={page}"])
        if payload is None:
            return (None, False) if page == 1 else (ordered_ticks(records), True)
        entries = _artifacts(payload)
        tick_records(payload, into=records)
        if len(records) >= wanted or not entries:
            return ordered_ticks(records), False
    return ordered_ticks(records), len(records) < wanted


def _open_alerts(repo, token, label="groom-mint"):
    """-> ({owner: issue_number}, hard_error, soft_skip).

    ONE listing for every owner. --limit 100: the `ops-alert` label is SHARED with the plan,
    metrics, dispatch-stall, ci-latency and groom-failure alerts, and a 30-issue default window
    could push these out of the dedupe scan (duplicate on failure, uncloseable on recovery).

    The owner is read back out of the body MARKER, whose grammar is anchored to `[A-Za-z0-9-]` —
    so an issue body, which any repo collaborator can edit, can name an owner but can never inject
    anything else through this reader. There is deliberately no title fallback: unlike the
    single-instance alerts this file's marker is the ONLY place the owner is machine-readable, and
    guessing an owner out of a human-retitled heading is how the wrong alert gets closed."""
    listed = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", "open",
                  "--json", "number,body", "--limit", "100"],
                 capture=True, token=token, check=True, label=label)
    if listed.returncode != 0:
        return {}, True, False
    try:
        found = json.loads(listed.stdout or "[]")
        if not isinstance(found, list):
            raise ValueError("expected a JSON array")
    except ValueError:
        print(f"::warning::{label}: gh issue list succeeded but returned unparseable JSON — "
              "skipping this tick (no dedupe/recovery data; next tick retries)")
        return {}, False, True
    alerts = {}
    for issue in found:
        if not isinstance(issue, dict):
            continue
        number = issue.get("number")
        if not isinstance(number, int) or isinstance(number, bool):
            continue
        matched = ALERT_MARKER_RE.search(issue.get("body") or "")
        if matched and matched.group(1) not in alerts:
            alerts[matched.group(1)] = number
    return alerts, False, False


def _apply(action, repo, token, num, title, body, recovered_note, label="groom-mint"):
    """Execute an upsert/close/noop. -> process exit code."""
    if action == "upsert":
        _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", "d73a4a",
             "--description", "Autonomous ops alert (maintainer action)"],
            capture=True, token=token, label=label)  # idempotent
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


def main():
    registry_repo = os.environ["REGISTRY_REPO"]
    repo, token = _alert_route(
        os.environ.get("ALERT_REPO"), os.environ.get("ALERT_TOKEN"), registry_repo)
    run_url = os.environ.get("RUN_URL", "")
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    workflow_url = f"{server}/{registry_repo}/actions/workflows/groom.yml"

    ticks, truncated = read_ticks(registry_repo)
    if ticks is None:
        # Fail loud: without the listing there is no evidence at all, so neither a page nor a
        # close is defensible. The step's continue-on-error keeps the alarm isolated.
        print("::warning::groom-mint: the artifacts listing was refused — no mint evidence this "
              "tick (next tick retries)")
        return 1
    if truncated:
        print(f"::warning::groom-mint: only {len(ticks)} mint-outcome tick(s) were reachable "
              f"within {ARTIFACT_MAX_PAGES} artifact pages (wanted {SKIP_STREAK_THRESHOLD + 1}) — "
              "a longer streak than that cannot be proved this tick")

    alerts, hard, soft = _open_alerts(repo, token)
    if hard:
        return 1
    if soft:
        return 0

    # The owners with an OPEN alert are evaluated even if no visible tick names them any more:
    # skip_streaks scores an unnamed owner 0, which is the `recovered` verdict that closes an
    # alert about an owner groom has stopped minting for. Without this union such an alert could
    # never be closed by anything but a human.
    owners = owners_seen(ticks) | set(alerts)
    streaks = skip_streaks(ticks, owners)

    code = 0
    for owner in sorted(owners):
        streak = streaks[owner]
        verdict = gap_verdict(streak, len(ticks))
        num = alerts.get(owner)
        action = decide(verdict, num is not None)
        result = _apply(action, repo, token, num, alert_title(owner),
                        _render_body(owner, streak, run_url, workflow_url, maintainer),
                        _recovered_note(owner))
        code = result or code
        if action == "upsert":
            print(f"::warning::groom-mint: {owner} skipped on {streak} consecutive ticks "
                  f"(threshold {SKIP_STREAK_THRESHOLD}) — maintainer alerted")
        elif action == "close":
            print(f"groom-mint: {owner} minted again — closed the alert")
        else:
            print(f"groom-mint: {owner} verdict={verdict} streak={streak} — nothing to do")
    if not owners:
        print(f"groom-mint: {len(ticks)} tick(s) visible, no owner named by any of them — "
              "nothing to evaluate")
    return code


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
        raise GroomMintAlertError(
            f"self-test input {path} is missing from the working copy at {_repo_root()} — the "
            "YAML-seam assertions cannot run, and a self-test that silently stops asserting is "
            "worse than no self-test. Add it to the job's sparse-checkout list.")
    with open(full, encoding="utf-8") as handle:
        return handle.read()


def _load_workflow(path):
    import yaml  # hard requirement: regex-over-YAML is how permissive misparses get in
    return yaml.safe_load(_require(path))


def _job(workflow, name):
    jobs = (workflow or {}).get("jobs") or {}
    if name not in jobs:
        raise GroomMintAlertError(
            f"workflow has no job named `{name}` — refusing to assert against a job that does not "
            "exist (a deleted watchdog must go RED here, not silently pass)")
    return jobs[name]


def _steps(job):
    return job.get("steps") or []


def _step_index(job, step_id):
    found = [i for i, step in enumerate(_steps(job)) if step.get("id") == step_id]
    if len(found) != 1:
        raise GroomMintAlertError(
            f"expected exactly one step with `id: {step_id}`, found {len(found)} — the ordering "
            "and wiring assertions key on that id and must not silently match nothing")
    return found[0]


def _step(job, step_id):
    return _steps(job)[_step_index(job, step_id)]


def _invocations(job, script):
    """Executable `python3 .../<script>` command lines across a job's steps, COMMENTS STRIPPED. A
    filename grep over a shell body is satisfied by a comment or a backslash-continuation tail."""
    pattern = re.compile(rf"^\s*python3\s+(?:\S*/)?{re.escape(script)}([^\n]*)$", re.M)
    tails = []
    for step in _steps(job):
        body = step.get("run") or ""
        live = "\n".join(line for line in body.replace("\\\n", " ").splitlines()
                         if not line.strip().startswith("#"))
        tails += [match.group(1).split() for match in pattern.finditer(live)]
    return tails


def _sparse_paths(job, path="registry"):
    found = [(step.get("with") or {}) for step in _steps(job)
             if str(step.get("uses", "")).startswith("actions/checkout@")
             and (step.get("with") or {}).get("path") == path]
    if len(found) != 1:
        raise GroomMintAlertError(
            f"expected exactly one actions/checkout with `path: {path}`, found {len(found)}")
    spec = found[0].get("sparse-checkout") or ""
    return {line.strip() for line in str(spec).splitlines() if line.strip()}


def _cron_period_minutes(workflow):
    """Minutes between fires for `m-59/N * * * *`, `*/N * * * *`, or an explicit minute list."""
    triggers = workflow.get("on", workflow.get(True)) or {}
    crons = [entry["cron"] for entry in (triggers.get("schedule") or []) if "cron" in entry]
    if len(crons) != 1:
        raise GroomMintAlertError(f"expected exactly one cron schedule, found {len(crons)}")
    minute = crons[0].split()[0]
    if "/" in minute:
        return int(minute.split("/")[1])
    minutes = sorted(int(part) for part in minute.split(","))
    if len(minutes) < 2:
        return 60
    gaps = {b - a for a, b in zip(minutes, minutes[1:])} | {60 - minutes[-1] + minutes[0]}
    return max(gaps)


def _self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got} (want {want})")

    # --- routing (mirrors the audited metrics/plan/groom/usage/dispatch-stall matrix) ----------
    chk("route: repo+token -> private + token",
        _alert_route("org/private", "tok", "org/registry"), ("org/private", "tok"))
    chk("route: repo but NO token -> registry fallback",
        _alert_route("org/private", "", "org/registry"), ("org/registry", None))
    chk("route: repo but None token -> registry fallback",
        _alert_route("org/private", None, "org/registry"), ("org/registry", None))
    chk("route: no repo -> registry", _alert_route("", "tok", "org/registry"),
        ("org/registry", None))

    _test_marker_grammar(chk)
    _test_tick_records(chk)
    _test_streaks(chk)
    _test_verdict_and_decide(chk)
    _test_body(chk)
    _test_paging(chk)
    _test_readers(chk)
    _test_gh_flows(chk)
    _test_selftest_guards(chk)
    _test_authority_ceiling(chk)
    _test_threshold_vs_cadence(chk)
    _test_workflow_seam(chk)

    print("groom-mint-alert self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def _test_marker_grammar(chk):
    chk("marker: both owners minted",
        parse_marker_name("groom-mint-tick.ok-sparq-org.ok-jeswr"),
        ({"sparq-org", "jeswr"}, set()))
    chk("marker: one minted, one skipped",
        parse_marker_name("groom-mint-tick.ok-sparq-org.skip-jeswr"),
        ({"sparq-org"}, {"jeswr"}))
    chk("marker: an owner login may itself start with the classifier word",
        parse_marker_name("groom-mint-tick.skip-ok-corp"), (set(), {"ok-corp"}))
    chk("marker: bare prefix parses to a tick that named no owner",
        parse_marker_name("groom-mint-tick"), (set(), set()))
    # Everything below must be NON-evidence, not partial credit.
    for label, name in (
            ("another workflow's artifact", "dispatch-tick"),
            ("a prefix that merely STARTS with ours", "groom-mint-tickle.ok-jeswr"),
            ("a prefix that merely CONTAINS ours", "x-groom-mint-tick.ok-jeswr"),
            ("an unclassified token", "groom-mint-tick.maybe-jeswr"),
            ("a classifier with no owner", "groom-mint-tick.skip-"),
            ("an owner with an illegal character", "groom-mint-tick.skip-jes_wr"),
            ("an owner with a trailing hyphen", "groom-mint-tick.skip-jeswr-"),
            ("an over-long owner", "groom-mint-tick.skip-" + "a" * 40),
            ("one good token and one bad one", "groom-mint-tick.ok-sparq-org.junk"),
            ("the same owner both minted and skipped", "groom-mint-tick.ok-jeswr.skip-jeswr"),
            ("an empty name", ""),
            ("a non-string name", None),
    ):
        chk(f"marker: {label} -> not evidence", parse_marker_name(name), None)


def _artifact(name, run_id=101, created_at="2026-07-29T18:00:00Z", expired=False):
    return {"name": name, "created_at": created_at, "expired": expired,
            "workflow_run": {"id": run_id}}


def _test_tick_records(chk):
    payload = {"artifacts": [
        _artifact("groom-mint-tick.ok-sparq-org.skip-jeswr", 101, "2026-07-29T18:00:00Z"),
        _artifact("groom-mint-tick.ok-sparq-org.ok-jeswr", 102, "2026-07-29T18:15:00Z"),
        _artifact("dispatch-tick", 103),                       # another workflow's marker
        _artifact("groom-mint-tick.ok-jeswr", 104, expired=True),   # expired -> not evidence
        {"name": "groom-mint-tick.ok-jeswr", "created_at": "2026-07-29T18:30:00Z"},  # no run
        {"name": "groom-mint-tick.ok-jeswr", "workflow_run": {"id": 105}},  # no created_at
        _artifact("groom-mint-tick.ok-jeswr", True, "2026-07-29T18:45:00Z"),  # bool run id
        "not-a-dict",
    ]}
    chk("records: only well-formed unexpired markers with a real run id count",
        sorted(tick_records(payload)), [101, 102])
    chk("records: a malformed payload yields no ticks (and therefore no streak)",
        (tick_records({"artifacts": "nope"}), tick_records(None), tick_records({})),
        ({}, {}, {}))

    # A RE-RUN uploads a second marker under the SAME run id. Counting it twice would let a
    # two-tick outage reach a four-tick threshold; the NEWEST marker for a run must win outright.
    rerun = {"artifacts": [
        _artifact("groom-mint-tick.skip-jeswr", 200, "2026-07-29T18:00:00Z"),
        _artifact("groom-mint-tick.ok-jeswr", 200, "2026-07-29T19:00:00Z"),
    ]}
    chk("records: a re-run is ONE tick, and its newest marker wins",
        tick_records(rerun), {200: ("2026-07-29T19:00:00Z", {"jeswr"}, set())})

    # ORDERING is derived, never inherited from the endpoint. Feed the pages scrambled.
    scrambled = {"artifacts": [
        _artifact("groom-mint-tick.skip-jeswr", 301, "2026-07-29T17:00:00Z"),
        _artifact("groom-mint-tick.ok-jeswr", 303, "2026-07-29T19:00:00Z"),
        _artifact("groom-mint-tick.skip-jeswr", 302, "2026-07-29T18:00:00Z"),
    ]}
    chk("records: ticks come back NEWEST FIRST regardless of listing order",
        [sorted(skip) for _ok, skip in ordered_ticks(tick_records(scrambled))],
        [[], ["jeswr"], ["jeswr"]])
    chk("records: owners_seen unions both classifications across every tick",
        sorted(owners_seen(ordered_ticks(tick_records(payload))))
        , ["jeswr", "sparq-org"])


def _test_streaks(chk):
    def ticks(*rows):
        """Newest-first rows of skipped-owner tuples; every row names both owners."""
        both = {"sparq-org", "jeswr"}
        return [(both - set(row), set(row)) for row in rows]

    four_down = ticks(("jeswr",), ("jeswr",), ("jeswr",), ("jeswr",), ())
    chk("streak: four consecutive skips for one owner, none for the other",
        skip_streaks(four_down, {"sparq-org", "jeswr"}), {"sparq-org": 0, "jeswr": 4})
    chk("streak: a SUCCESS on the newest tick ends it, however long the run behind it",
        skip_streaks(ticks((), ("jeswr",), ("jeswr",), ("jeswr",), ("jeswr",)), {"jeswr"}),
        {"jeswr": 0})
    chk("streak: an intervening success truncates it to the leading run",
        skip_streaks(ticks(("jeswr",), ("jeswr",), (), ("jeswr",), ("jeswr",)), {"jeswr"}),
        {"jeswr": 2})
    chk("streak: both owners down at once are counted independently",
        skip_streaks(ticks(("jeswr", "sparq-org"), ("jeswr", "sparq-org")),
                     {"sparq-org", "jeswr"}), {"sparq-org": 2, "jeswr": 2})
    # An owner NAMED BY NEITHER set — groom no longer mints for it. Not skipped, so not a gap;
    # this is the path that lets an alert about a retired owner be closed at all.
    chk("streak: an owner no tick names at all scores 0, not a gap",
        skip_streaks([({"sparq-org"}, set())] * 5, {"jeswr"}), {"jeswr": 0})
    chk("streak: an owner whose skip run is interrupted by a tick that omits it stops there",
        skip_streaks([(set(), {"jeswr"}), ({"sparq-org"}, set()), (set(), {"jeswr"})],
                     {"jeswr"}), {"jeswr": 1})
    chk("streak: no ticks at all -> every owner scores 0",
        skip_streaks([], {"jeswr"}), {"jeswr": 0})


def _test_verdict_and_decide(chk):
    # The THRESHOLD is load-bearing: derive the inputs from arithmetic on it, never from a literal
    # that happens to equal today's value, or raising SKIP_STREAK_THRESHOLD leaves these green.
    below, at, above = (SKIP_STREAK_THRESHOLD - 1, SKIP_STREAK_THRESHOLD,
                        SKIP_STREAK_THRESHOLD + 1)
    chk("verdict: at the threshold -> gap", gap_verdict(at, at), "gap")
    chk("verdict: past the threshold -> gap", gap_verdict(above, above), "gap")
    chk("verdict: one short of the threshold -> flapping, NOT a gap and NOT a recovery",
        gap_verdict(below, at), "flapping")
    # A streak of exactly ONE is the boundary that matters for the CLOSE path, and it is not the
    # same experiment as `below`: measured, widening the recovery test from `== 0` to `<= 1`
    # survived every other check here, and it would let one successful mint in two ticks close a
    # live alert about a mint that is still broken.
    chk("verdict: a streak of exactly ONE is flapping, never a recovery",
        gap_verdict(1, at), "flapping")
    chk("verdict: a zero streak on visible evidence -> recovered", gap_verdict(0, at), "recovered")
    chk("verdict: NO visible tick -> unknown, whatever the streak says",
        (gap_verdict(0, 0), gap_verdict(above, 0), gap_verdict(0, None)),
        ("unknown", "unknown", "unknown"))
    chk("decide: gap -> upsert, open or not",
        (decide("gap", False), decide("gap", True)), ("upsert", "upsert"))
    chk("decide: recovered + open -> close", decide("recovered", True), "close")
    chk("decide: recovered + none open -> noop", decide("recovered", False), "noop")
    chk("decide: flapping must NOT close an open alert (a mint failing 3 ticks in 4 is broken)",
        decide("flapping", True), "noop")
    chk("decide: unknown must NOT close an open alert (absence of evidence is not a recovery)",
        decide("unknown", True), "noop")


def _test_body(chk):
    body = _render_body("jeswr", 4, "https://example.test/run/1",
                        "https://example.test/wf", "maintainer-x")
    chk("body: carries the owner-keyed dedupe marker",
        alert_marker("jeswr") in body, True)
    chk("body: the marker regex reads its own owner back out",
        ALERT_MARKER_RE.search(body).group(1), "jeswr")
    chk("body: two different owners get two DIFFERENT markers and titles",
        (alert_marker("jeswr") == alert_marker("sparq-org"),
         alert_title("jeswr") == alert_title("sparq-org")), (False, False))
    chk("body: names the owner, the streak, the threshold, the run and the workflow",
        ("`jeswr`" in body, "**4**" in body, f"**{SKIP_STREAK_THRESHOLD}**" in body,
         "https://example.test/run/1" in body, "https://example.test/wf" in body),
        (True, True, True, True, True))
    chk("body: mentions the maintainer it was handed, not a baked-in handle",
        ("@maintainer-x" in body, "@jeswr" in body), (True, False))
    chk("body: model-agnostic self-ID, no model marker", "> 🤖 SPARQ agent" in body, True)
    # PRIVACY / EXFIL: the template's only inputs are the five scalars above, so no provider
    # account handle and no token can reach it. Prove it the way that can actually fail — render
    # with sentinels in every slot and assert nothing else survived.
    sentinel = _render_body("OWNER-S", 7, "RUN-S", "WF-S", "MAINT-S")
    leaked = [word for word in ("SENTINEL-TOKEN", "ghs_", "ghp_", "github_pat_")
              if word in sentinel]
    chk("body: nothing token-shaped can reach a body — every slot is a closed scalar", leaked, [])
    chk("body: the recovered note names the owner and asserts why it may also be a retirement",
        ("`jeswr`" in _recovered_note("jeswr"),
         "no longer mints" in _recovered_note("jeswr")), (True, True))


def _test_paging(chk):
    """The listing is repo-wide and shared with dispatch's, dashboard's and worker's artifacts, so
    a page can be full of something else entirely. The crawl must keep going until the tick that
    would BREAK the streak is in view — THRESHOLD+1 ticks — and must SAY SO when it cannot."""
    def pager(pages):
        calls = []

        def runner(args):
            # `[?&]page=` — a bare `page=(\d+)` matches `per_page=100` first, which silently
            # collapses every page of this fixture onto one key and makes the crawl untested.
            page = int(re.search(r"[?&]page=(\d+)", args[-1]).group(1))
            calls.append(page)
            return pages.get(page, {"artifacts": []})
        return runner, calls

    def marker(run_id, minute):
        return _artifact("groom-mint-tick.skip-jeswr", run_id,
                         f"2026-07-29T18:{minute:02d}:00Z")

    # One dense page: THRESHOLD+1 ticks found, so exactly ONE request.
    dense = {1: {"artifacts": [marker(300 + i, i) for i in range(SKIP_STREAK_THRESHOLD + 1)]}}
    runner, calls = pager(dense)
    ticks, truncated = read_ticks("o/r", runner=runner)
    chk("paging: a page carrying THRESHOLD+1 ticks costs exactly one request",
        (len(calls), len(ticks), truncated), (1, SKIP_STREAK_THRESHOLD + 1, False))

    # Exactly THRESHOLD ticks on a FULL page is one short of what the crawl wants: the tick that
    # would BREAK the streak is not yet in view, so it must page on rather than stopping on a
    # history it cannot prove the edges of. (Measured: without this row, `wanted = threshold`
    # survived the whole suite.)
    edge = {1: {"artifacts": [marker(700 + i, i) for i in range(SKIP_STREAK_THRESHOLD)]
                + [_artifact("publish-bundle", 800)]}}
    runner, calls = pager(edge)
    ticks, truncated = read_ticks("o/r", runner=runner)
    chk("paging: THRESHOLD ticks is one short of what the crawl wants, so it pages on",
        (calls, len(ticks), truncated), ([1, 2], SKIP_STREAK_THRESHOLD, False))

    # An artifact storm: one groom tick per page. The crawl must walk on, and then REPORT that it
    # stopped short rather than presenting a 3-tick history as the whole truth.
    storm = {page: {"artifacts": [_artifact("publish-bundle", 900 + page)] * 40
                    + [marker(400 + page, page)]}
             for page in range(1, ARTIFACT_MAX_PAGES + 1)}
    runner, calls = pager(storm)
    ticks, truncated = read_ticks("o/r", runner=runner)
    chk("paging: under an artifact storm it pages to the cap and REPORTS the short history",
        (calls, len(ticks), truncated),
        (list(range(1, ARTIFACT_MAX_PAGES + 1)), ARTIFACT_MAX_PAGES, True))

    # A dry page ends the crawl without claiming truncation — the history really is that short.
    runner, calls = pager({1: {"artifacts": [marker(500, 1)]}})
    ticks, truncated = read_ticks("o/r", runner=runner)
    chk("paging: a page that runs dry ends the crawl and is NOT reported as truncated",
        (calls, len(ticks), truncated), ([1, 2], 1, False))

    # A REFUSED first page is no evidence at all -> None, so main() fails loud instead of reading
    # an empty history as "every owner recovered" and closing live alerts.
    chk("paging: a refused FIRST page yields no evidence, never an empty history",
        read_ticks("o/r", runner=lambda *a, **k: None), (None, False))
    # A refusal PART WAY through keeps what it has and flags it as short.
    half = {1: {"artifacts": [marker(600, 1)] * 1 + [_artifact("other", 1)] * 99}}
    runner, _calls = pager(half)

    def flaky(args):
        # `&page=1`, anchored on the separator for the same reason as above: `per_page=100`
        # contains the substring `page=1`, so a looser test here would answer EVERY page and the
        # mid-crawl refusal would never actually be exercised.
        return runner(args) if "&page=1" in args[-1] else None
    chk("paging: a refusal after page one keeps the evidence it has and flags it short",
        (lambda pair: (len(pair[0]), pair[1]))(read_ticks("o/r", runner=flaky)), (1, True))


def _test_readers(chk):
    """The two LIVE readers, exercised for real rather than stubbed past.

    Line coverage put `_gh_json` and every malformed-row skip in `_open_alerts` at zero: the
    stubbed-flow test below replaces the runner, so the code that actually turns a `gh` process
    into evidence had never run once. That is precisely the region a fabricating bug survives in."""
    import contextlib
    import io

    class _Result:
        def __init__(self, code=0, out=""):
            self.returncode, self.stdout = code, out
            self.stderr = "SENTINEL-STDERR"

    scripted = {"result": _Result(0, "{}")}
    seen = []

    def fake_run(cmd, capture_output=False, text=False, env=None, check=False):
        seen.append(list(cmd))
        return scripted["result"]

    saved_run = subprocess.run
    try:
        subprocess.run = fake_run

        # --- _gh_json ------------------------------------------------------------------------
        scripted["result"] = _Result(0, '{"artifacts": []}')
        chk("reader: _gh_json parses a successful listing", _gh_json(["api", "/x"]),
            {"artifacts": []})
        scripted["result"] = _Result(1, "SENTINEL-PAYLOAD")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            refused = _gh_json(["api", "/x"])
        chk("reader: a REFUSED listing is None, warned about, and never echoes stderr/stdout",
            (refused, "::warning::" in buffer.getvalue(),
             "SENTINEL-PAYLOAD" in buffer.getvalue(),
             "SENTINEL-STDERR" in buffer.getvalue()), (None, True, False, False))
        scripted["result"] = _Result(0, "SENTINEL-PAYLOAD {not json")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            garbled = _gh_json(["api", "/x"])
        chk("reader: a SUCCESSFUL listing of unparseable JSON degrades to None without crashing, "
            "payload not echoed",
            (garbled, "::warning::" in buffer.getvalue(),
             "SENTINEL-PAYLOAD" in buffer.getvalue()), (None, True, False))

        # read_ticks must reach the API through _gh_json when no runner is injected — otherwise
        # every paging assertion above is about a function the live path never calls.
        seen.clear()
        scripted["result"] = _Result(0, json.dumps({"artifacts": [
            _artifact("groom-mint-tick.skip-jeswr", 700, "2026-07-29T18:00:00Z")]}))
        ticks, _truncated = read_ticks("o/r")
        chk("reader: read_ticks with NO injected runner goes through the real gh api reader",
            (seen and seen[0][:2], "/repos/o/r/actions/artifacts" in (seen[0][-1] if seen else ""),
             [sorted(skip) for _ok, skip in ticks]),
            (["gh", "api"], True, [["jeswr"]]))

        # --- _open_alerts --------------------------------------------------------------------
        scripted["result"] = _Result(0, json.dumps([
            "not-a-dict",
            {"number": True, "body": "prose " + alert_marker("bool-number-row")},
            {"number": None, "body": "prose " + alert_marker("null-number-row")},
            {"number": 5, "body": "no marker here at all"},
            {"number": 6, "title": alert_title("title-only-row"), "body": ""},
            {"number": 7, "body": "prose\n" + alert_marker("jeswr") + "\ntail"},
            {"number": 8, "body": alert_marker("jeswr")},
            {"number": 9, "body": alert_marker("sparq-org")},
        ]))
        alerts, hard, soft = _open_alerts("o/r", None)
        chk("reader: only well-formed marker rows map to an owner; the FIRST wins on a duplicate",
            (alerts, hard, soft), ({"jeswr": 7, "sparq-org": 9}, False, False))
        chk("reader: an alert with the right TITLE but no marker is NOT matched — guessing an "
            "owner out of a heading is how the wrong alert gets closed",
            "title-only-row" in alerts, False)
        scripted["result"] = _Result(1, "")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            chk("reader: a refused issue listing is a HARD error, never an empty alert set",
                _open_alerts("o/r", None), ({}, True, False))
        scripted["result"] = _Result(0, '{"message": "SENTINEL-PAYLOAD"}')
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            soft_result = _open_alerts("o/r", None)
        chk("reader: a non-array issue listing is a SOFT skip, payload not echoed",
            (soft_result, "SENTINEL-PAYLOAD" in buffer.getvalue()), (({}, False, True), False))
    finally:
        subprocess.run = saved_run


def _test_selftest_guards(chk):
    """The self-test's OWN fail-closed helpers. If `_step_index` matched nothing quietly, or
    `_job` returned an empty dict for a deleted job, every seam assertion above would pass against
    thin air — the exact vacuity this file exists to prevent elsewhere."""
    def raises(thunk):
        try:
            thunk()
        except GroomMintAlertError:
            return True
        except Exception:  # noqa: BLE001 - any other exception is NOT the fail-closed contract
            return False
        return False

    workflow = _load_workflow(GROOM_WORKFLOW)
    chk("guards: a missing JOB raises rather than asserting against nothing",
        raises(lambda: _job(workflow, "no-such-job")), True)
    groom = _job(workflow, GROOM_JOB)
    chk("guards: a missing STEP id raises rather than matching nothing",
        raises(lambda: _step_index(groom, "no-such-step")), True)
    chk("guards: a checkout path with no matching step raises",
        raises(lambda: _sparse_paths(_job(workflow, HOST_JOB), path="no-such-path")), True)
    chk("guards: a missing self-test INPUT raises (never a silently skipped assertion)",
        raises(lambda: _require("scripts/no-such-file.py")), True)
    chk("guards: a workflow with no cron raises rather than scoring a period of 0",
        raises(lambda: _cron_period_minutes({"on": {}})), True)
    # The explicit-minute-list branch of the cadence reader is unreachable from groom's own
    # `7-59/15` cron, so it is exercised directly — an untested branch here would silently
    # mis-scale the threshold the day someone rewrites that schedule as a list.
    chk("guards: the cadence reader handles an explicit minute list, not just `*/N`",
        (_cron_period_minutes({"on": {"schedule": [{"cron": "7,22,37,52 * * * *"}]}}),
         _cron_period_minutes({"on": {"schedule": [{"cron": "7 * * * *"}]}})), (15, 60))


def _test_gh_flows(chk):
    """The whole live path over a stubbed `gh`, at the subprocess boundary — so repo/token wiring
    and every mutation return-code check is asserted, not assumed."""
    class _Result:
        def __init__(self, code=0, out=""):
            self.returncode, self.stdout = code, out
            self.stderr = "SENTINEL-STDERR"

    state = {"list": _Result(0, "[]"), "fail": set(), "ticks": ([], False)}
    issued = []

    # Stubbed at the SUBPROCESS boundary, not at `_gh`. Stubbing `_gh` would take the real
    # wrapper's sanitized `::warning::` out of the picture, and every "a failed mutation warns"
    # row below would then pass on main()'s UNRELATED upsert warning instead — a false kill on
    # four checks. Going through the real `_gh` also puts its token/env wiring under test.
    def fake_run(cmd, capture_output=False, text=False, env=None, check=False):
        args = list(cmd[1:])
        issued.append((args, (env or {}).get("GH_TOKEN")))
        if args[:2] == ["issue", "list"]:
            return state["list"]
        return _Result(1 if tuple(args[:2]) in state["fail"] else 0, "")

    def fake_read_ticks(repo, runner=None, threshold=SKIP_STREAK_THRESHOLD):
        return state["ticks"]

    def subs():
        return [tuple(args[:2]) for args, _token in issued]

    def find(sub):
        return next((args for args, _t in issued if tuple(args[:2]) == sub), None)

    def run_main(ticks, listing="[]", fail=(), alert_repo=None, alert_token=None):
        issued.clear()
        state["ticks"] = ticks
        state["list"] = _Result(1 if ("issue", "list") in fail else 0, listing)
        state["fail"] = {tuple(f) for f in fail}
        os.environ["REGISTRY_REPO"] = "o/r"
        os.environ["RUN_URL"] = "https://example.test/run/9"
        os.environ["MAINTAINER_HANDLE"] = "m"
        for key, value in (("ALERT_REPO", alert_repo), ("ALERT_TOKEN", alert_token)):
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        import contextlib
        import io
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main()
        return code, buffer.getvalue()

    def down(owner, count):
        """`count` newest ticks with `owner` skipped, then a clean one behind them."""
        other = "sparq-org" if owner != "sparq-org" else "jeswr"
        return [({other}, {owner})] * count + [({owner, other}, set())]

    saved_run, saved_read = subprocess.run, globals()["read_ticks"]
    ambient = os.environ.get("GH_TOKEN")  # None locally, set in CI — either way, UNCHANGED
    # Seeded so the restore path for an ALREADY-SET variable is exercised and asserted, not just
    # the delete path. A self-test that leaks env into the rest of the suite is its own defect.
    os.environ["MAINTAINER_HANDLE"] = "PRE-EXISTING-HANDLE"
    env_backup = {key: os.environ.get(key) for key in
                  ("REGISTRY_REPO", "RUN_URL", "MAINTAINER_HANDLE", "ALERT_REPO", "ALERT_TOKEN")}
    try:
        subprocess.run = fake_run
        globals()["read_ticks"] = fake_read_ticks

        code, out = run_main((down("jeswr", SKIP_STREAK_THRESHOLD), False))
        created = find(("issue", "create"))
        chk("flow: a threshold-length gap with no open alert files exactly ONE issue",
            (code, subs().count(("issue", "create")), ("issue", "edit") in subs()),
            (0, 1, False))
        chk("flow: ... titled and bodied for the OFFENDING owner only",
            (alert_title("jeswr") in created, alert_marker("jeswr") in created[-1],
             "sparq-org" in created[created.index("--title") + 1]),
            (True, True, False))
        chk("flow: ... and says so on the run log as a ::warning::",
            ("::warning::" in out, "jeswr" in out), (True, True))

        code, _out = run_main((down("jeswr", SKIP_STREAK_THRESHOLD - 1), False))
        chk("flow: one tick short of the threshold mutates NOTHING",
            (code, [s for s in subs() if s != ("issue", "list")]), (0, []))

        open_alert = json.dumps([{"number": 42, "body": "prose\n" + alert_marker("jeswr")}])
        code, _out = run_main((down("jeswr", SKIP_STREAK_THRESHOLD), False), open_alert)
        edited = find(("issue", "edit"))
        chk("flow: an ongoing gap EDITS the open alert rather than filing a twin",
            (code, ("issue", "create") in subs(), edited is not None and "42" in edited),
            (0, False, True))

        # RECOVERY. The newest tick minted the owner again -> comment + close.
        code, _out = run_main(([({"jeswr", "sparq-org"}, set())] * 3, False), open_alert)
        chk("flow: a recovered owner is commented on and CLOSED",
            (code, ("issue", "comment") in subs(), ("issue", "close") in subs(),
             ("issue", "create") in subs()), (0, True, True, False))

        # RETIREMENT. No visible tick names the owner at all, but its alert is open. It must still
        # be reachable and closeable — this is the union in main() doing its job.
        code, _out = run_main(([({"sparq-org"}, set())] * 3, False), open_alert)
        chk("flow: an alert about an owner no tick names any more is still closed",
            (code, ("issue", "close") in subs()), (0, True))

        # NO EVIDENCE. Zero visible ticks must neither page nor close.
        code, _out = run_main(([], False), open_alert)
        chk("flow: zero visible ticks mutate NOTHING (no page, and no false recovery)",
            (code, [s for s in subs() if s != ("issue", "list")]), (0, []))

        # A TRUNCATED read must SAY SO on the log. A bounded crawl presented as a complete history
        # is how "covered everything" gets read off a run that did not.
        code, out = run_main((down("jeswr", 1), True), open_alert)
        chk("flow: a truncated artifact crawl is announced, not silently read as a short history",
            (code, "::warning::" in out, "reachable" in out), (0, True, True))

        # A tick that named NO owner at all (the workflow stopped minting entirely) must census a
        # zero row rather than printing nothing — a silent tick reads identically to a healthy one.
        code, out = run_main(([(set(), set())], False))
        chk("flow: a tick naming no owner still emits a zero row",
            (code, "no owner named by any of them" in out), (0, True))

        # A REFUSED artifacts listing is a hard, sanitized failure — never a silent green tick.
        code, out = run_main((None, False), open_alert)
        chk("flow: a refused artifacts listing exits 1 and mutates nothing",
            (code, "::warning::" in out, [s for s in subs() if s != ("issue", "list")]),
            (1, True, []))

        # A refused ISSUE listing: no dedupe data, so neither page nor close, and go red.
        code, _out = run_main((down("jeswr", SKIP_STREAK_THRESHOLD), False),
                              fail=(("issue", "list"),))
        chk("flow: a refused issue listing exits 1 and mutates nothing",
            (code, [s for s in subs() if s != ("issue", "list")]), (1, []))

        # Malformed / non-array issue listings fail SOFT, and never echo the payload.
        for label, payload in (("malformed", "SENTINEL-PAYLOAD {not json"),
                               ("non-array", '{"message": "SENTINEL-PAYLOAD"}')):
            code, out = run_main((down("jeswr", SKIP_STREAK_THRESHOLD), False), payload)
            chk(f"flow: a {label} issue listing skips the tick without echoing the payload",
                (code, "::warning::" in out, "SENTINEL-PAYLOAD" in out,
                 [s for s in subs() if s != ("issue", "list")]), (0, True, False, []))

        # EVERY mutation's return code must fail the run.
        for failing, ticks, listing in (
                (("issue", "create"), down("jeswr", SKIP_STREAK_THRESHOLD), "[]"),
                (("issue", "edit"), down("jeswr", SKIP_STREAK_THRESHOLD), open_alert),
                (("issue", "comment"), [({"jeswr", "sparq-org"}, set())], open_alert),
                (("issue", "close"), [({"jeswr", "sparq-org"}, set())], open_alert)):
            code, out = run_main((ticks, False), listing, fail=(failing,))
            chk(f"flow: a failed `{failing[1]}` exits 1 with a sanitized warning",
                (code, "::warning::" in out, "SENTINEL-STDERR" in out), (1, True, False))

        # BOTH owners down at once -> two independent alerts, one per owner, in one run.
        both = [(set(), {"jeswr", "sparq-org"})] * SKIP_STREAK_THRESHOLD
        code, _out = run_main((both, False))
        titles = [args[args.index("--title") + 1] for args, _t in issued
                  if tuple(args[:2]) == ("issue", "create")]
        chk("flow: two owners down file two SEPARATE alerts",
            (code, sorted(titles) == sorted([alert_title("jeswr"), alert_title("sparq-org")])),
            (0, True))

        # WIRING. Private route: every mutation targets ALERT_REPO under ALERT_TOKEN.
        run_main((down("jeswr", SKIP_STREAK_THRESHOLD), False),
                 alert_repo="org/private", alert_token="sentinel-alert-tok")
        created = find(("issue", "create"))
        token_used = next(t for args, t in issued if tuple(args[:2]) == ("issue", "create"))
        chk("wiring: private route -> -R org/private under ALERT_TOKEN",
            (created[created.index("-R") + 1], token_used),
            ("org/private", "sentinel-alert-tok"))
        run_main((down("jeswr", SKIP_STREAK_THRESHOLD), False),
                 alert_repo="org/private", alert_token="")
        created = find(("issue", "create"))
        token_used = next(t for args, t in issued if tuple(args[:2]) == ("issue", "create"))
        chk("wiring: half-config (repo, no token) -> registry repo under the AMBIENT token",
            (created[created.index("-R") + 1], token_used == ambient,
             token_used == "sentinel-alert-tok"), ("o/r", True, False))
        # The dedupe scan must fetch the BODY and a wide window, or the owner marker match is
        # silently vacuous and every tick files a twin.
        listing_cmd = find(("issue", "list"))
        chk("wiring: the dedupe listing asks for number,body with --limit 100",
            ("number,body" in listing_cmd, "100" in listing_cmd), (True, True))
    finally:
        subprocess.run, globals()["read_ticks"] = saved_run, saved_read
        for key, value in env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    chk("flow: the harness restores an already-set variable instead of deleting it",
        os.environ.get("MAINTAINER_HANDLE"), "PRE-EXISTING-HANDLE")
    os.environ.pop("MAINTAINER_HANDLE", None)


def _test_authority_ceiling(chk):
    """STRUCTURAL AUTHORITY DENIAL, mirroring scripts/dispatch-stall-alert.py. This script may
    touch ONE ops-alert issue per owner; it must have no code path that writes a hold/role/status
    label, no merge path and no PR path. Asserted over the AST, not by convention."""
    tree = ast.parse(_require("scripts/groom-mint-alert.py"))
    # Scan the LIVE half only. The self-test necessarily names the very literals it forbids (that
    # is what makes it an assertion), and a scan that included them could never pass — so it would
    # be deleted, and with it the check.
    tree.body = [node for node in tree.body
                 if not (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                         and (node.name == "_self_test" or node.name.startswith("_test_")))]
    literals = {node.value for node in ast.walk(tree)
                if isinstance(node, ast.Constant) and isinstance(node.value, str)}
    forbidden = sorted(lit for lit in literals
                       if re.match(r"^(needs:|status:|role:|review:|priority:|area:)", lit)
                       or lit in {"merge", "pr", "--auto", "--admin", "--squash"})
    chk("authority: no hold/role/status label literal and no merge/PR verb anywhere in the source",
        forbidden, [])
    argv_heads = {node.elts[0].value for node in ast.walk(tree)
                  if isinstance(node, ast.List) and node.elts
                  and isinstance(node.elts[0], ast.Constant)
                  and isinstance(node.elts[0].value, str)}
    chk("authority: the only argv heads this script can build are `gh` and the issue/label/api "
        "subcommands — no pr, no run, no workflow, no repo",
        sorted(argv_heads), ["api", "gh", "issue", "label"])


def _test_threshold_vs_cadence(chk):
    """CROSS-FILE, against the LIVE cron. The threshold is denominated in TICKS; how long N ticks
    take is set entirely by groom.yml's schedule. Retuning that cron without touching this file
    would silently move the page latency by hours in either direction."""
    period = _cron_period_minutes(_load_workflow(GROOM_WORKFLOW))
    gap_minutes = SKIP_STREAK_THRESHOLD * period
    chk("cadence: groom's own cron period, read from the live workflow", period, 15)
    chk("cadence: the threshold is long enough that a single transient mint failure cannot page",
        (SKIP_STREAK_THRESHOLD >= 2, gap_minutes >= 30), (True, True))
    chk("cadence: ... and short enough that a credential gap pages within two hours, INCLUDING "
        "the one-tick lag the no-`needs:` hosting costs",
        gap_minutes + period <= 120, True)


def _test_workflow_seam(chk):
    """THE YAML SEAM — where the vacuity lives. Both ends of the artifact-name contract, the
    ordering that makes the marker mean "this tick reached the mint stage", and the watchdog's own
    ungated hosting."""
    workflow = _load_workflow(GROOM_WORKFLOW)

    # --- the PRODUCER half, in the `groom` job ------------------------------------------------
    groom = _job(workflow, GROOM_JOB)
    for mint_id in MINT_STEP_IDS:
        chk(f"seam: the `{mint_id}` mint is still continue-on-error (the whole premise: a mint "
            "failure DEFERS one owner instead of failing the sweep)",
            _step(groom, mint_id).get("continue-on-error"), True)

    marker_step = _step(groom, MARKER_STEP_ID)
    chk("seam: the marker step declares NO `if:` — the default success() guard IS the 'this tick "
        "reached the mint stage' predicate, and `always()` would turn every earlier failure into "
        "a false all-owners-skipped tick",
        marker_step.get("if"), None)
    chk("seam: the marker step is continue-on-error (an observability aid must never abort the "
        "crash-recovery sweep it precedes)",
        marker_step.get("continue-on-error"), True)

    # EXACT MATCH, NOT CONTAINMENT — measured: an `f"name={TICK_MARKER_PREFIX}" in run_body`
    # containment check passes happily against `name=groom-mint-tickX`, and a renamed prefix on
    # the producer side is precisely the mutation that empties this detector while every other
    # check stays green. Tokenise the assignment and compare for equality (AGENTS.md item 6).
    run_body = marker_step.get("run") or ""
    assigned = set(re.findall(r"^\s*name=([A-Za-z0-9._-]+)\s*$", run_body, re.M))
    chk("seam: the workflow seeds the artifact name with EXACTLY this file's prefix",
        assigned, {TICK_MARKER_PREFIX})
    suffixes = set(re.findall(r"\$name\.([A-Za-z]+)-\$owner", run_body))
    chk("seam: ... and appends EXACTLY this file's two classifier words, no more and no fewer",
        suffixes, {MARKER_OK, MARKER_SKIP})
    chk("seam: the separator the workflow writes is the one this file splits on",
        set(re.findall(r"\$name(.)" + MARKER_OK + r"-", run_body)), {MARKER_SEPARATOR})
    # The mint OUTCOMES arrive through the step's `env:`, so that is where this has to look — the
    # earlier version of this check read the `run:` body, where the expressions never appear, and
    # so asserted nothing at all in either direction.
    marker_env = " ".join(str(value) for value in (marker_step.get("env") or {}).values())
    chk("seam: the marker keys on the mint OUTCOME and never on its token output",
        [f"steps.{mint_id}.outcome" in marker_env for mint_id in MINT_STEP_IDS]
        + ["outputs.token" in (marker_env + run_body)], [True, True, False])

    # ROUND TRIP against the LIVE owner list. Every check above tests one END of the contract;
    # this one tests what the transition DELIVERS INTO — it takes the owners the workflow actually
    # mints for, builds the exact names that shell emits for them, and pushes them through the
    # live parser. A grammar both halves agree on but that yields no owners would satisfy
    # everything above and still detect nothing (AGENTS.md item 11).
    minted_owners = {str((_step(groom, mint_id).get("with") or {}).get("owner"))
                     for mint_id in MINT_STEP_IDS}
    chk("seam: every mint step names a well-formed owner login",
        sorted(owner for owner in minted_owners if OWNER_RE.match(owner)),
        sorted(minted_owners))
    for word, expected in ((MARKER_OK, (minted_owners, set())),
                           (MARKER_SKIP, (set(), minted_owners))):
        built = TICK_MARKER_PREFIX + "".join(
            f"{MARKER_SEPARATOR}{word}-{owner}" for owner in sorted(minted_owners))
        chk(f"seam: a live all-`{word}` marker round-trips to exactly the minted owner set",
            parse_marker_name(built), expected)

    upload = _step(groom, UPLOAD_STEP_ID)
    chk("seam: the upload is a SHA-pinned actions/upload-artifact",
        bool(re.fullmatch(r"actions/upload-artifact@[0-9a-f]{40}", str(upload.get("uses")))), True)
    chk("seam: the uploaded artifact NAME is exactly the marker step's computed output — a "
        "literal here would publish one name forever and empty the detector",
        (upload.get("with") or {}).get("name"),
        "${{ steps.%s.outputs.name }}" % MARKER_STEP_ID)
    chk("seam: the upload fails loudly on a missing file rather than publishing an empty marker",
        (upload.get("with") or {}).get("if-no-files-found"), "error")
    # Denominated in the LIVE cron period, not a duplicated `15`: retention and threshold are only
    # coherent together, and slowing the cron is exactly how a retention window that looks generous
    # silently stops covering a threshold-length streak.
    chk("seam: the marker is retained long enough to prove a threshold-length streak",
        int((upload.get("with") or {}).get("retention-days") or 0) * 24 * 60
        >= (SKIP_STREAK_THRESHOLD + 1) * _cron_period_minutes(workflow), True)

    # ORDER. The marker must be written AFTER both mints (or it cannot know their outcome) and
    # BEFORE the sweep (or a sweep failure erases the tick's only mint evidence).
    order = [_step_index(groom, step_id) for step_id in
             (*MINT_STEP_IDS, MARKER_STEP_ID, UPLOAD_STEP_ID, SWEEP_STEP_ID)]
    chk("seam: mints -> name marker -> upload marker -> sweep, in that order",
        order == sorted(order), True)

    # --- the CONSUMER half: the watchdog job --------------------------------------------------
    job = _job(workflow, HOST_JOB)
    chk("seam: the watchdog declares NO `needs:` (it must survive a failed groom sweep)",
        job.get("needs"), None)
    chk("seam: the watchdog declares NO `if:` (an `if:` is how a watchdog gets silently gated "
        "off)", job.get("if"), None)
    chk("seam: permissions are exactly {actions:read, contents:read, issues:write} — repair "
        "authority, never admission authority",
        job.get("permissions"), {"actions": "read", "contents": "read", "issues": "write"})
    chk("seam: the watchdog JOB is not continue-on-error", job.get("continue-on-error"), None)
    chk("seam: it is bound to the default-branch-only dispatch-secrets environment",
        job.get("environment"), "dispatch-secrets")

    tails = _invocations(job, "groom-mint-alert.py")
    chk("seam: the job calls this script exactly twice — `--self-test` FIRST, then live",
        (len(tails), tails[0] if tails else None, tails[-1] if tails else None),
        (2, ["--self-test"], []))
    selftest_steps = [step for step in _steps(job)
                      if "--self-test" in (step.get("run") or "")]
    chk("seam: the self-test step is NOT continue-on-error — a detector that has not proved "
        "itself on this tick's code may not go on to watch anything",
        [step.get("continue-on-error") for step in selftest_steps], [None])
    live_steps = [step for step in _steps(job)
                  if "groom-mint-alert.py" in (step.get("run") or "")
                  and "--self-test" not in (step.get("run") or "")]
    chk("seam: the live alert step IS continue-on-error — a watchdog fault may never red the "
        "grooming sweep",
        [step.get("continue-on-error") for step in live_steps], [True])

    for path in REQUIRED_FILES:
        _require(path)
    chk("seam: the job sparse-checks-out every file its self-test asserts against",
        sorted(_sparse_paths(job)), sorted(REQUIRED_FILES))
    suite = _require("scripts/selftest-suite.txt").split()
    chk("seam: enrolled in scripts/selftest-suite.txt, so pr-gate runs this self-test",
        "groom-mint-alert.py" in suite, True)


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
