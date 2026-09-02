#!/usr/bin/env python3
# [SPARQ agent] DOES A CHECK-RUN'S RECORDED `pull_requests[].base.sha` EVER *LEAD* THE TREE THE RUN
# ACTUALLY GRADED? (issue #1238). MEASURES; PROPOSES NOTHING.
#
# THE QUESTION, AND WHOSE IT IS. `dispatch-claim.gate_freshness` (#940, landed as #950) refuses to
# arm on a green whose deciding run did not compose the live base tip. Its BINDING clause is
# structural and clock-free:
#
#   "(1) the deciding run's OWN recorded base sha equals the live base tip sha ... this is not a
#    proxy for the question, it IS the question"
#
# and its stated residual is one sentence long: "if GitHub ever starts live-recomputing
# `pull_requests[].base.sha`, a run that started after the tip landed but composed an older base
# reads FRESH here". #920 then measured something adjacent on the EVENT-payload side —
# `github.event.pull_request.base.sha` mispredicted 5 of 7 failures while the merge-ref base tip
# separated them 40/40 — so "the check-run field might behave like the event field" stopped being
# hypothetical and became a thing to measure.
#
# WHAT IS COMPARED, AND WHY THESE TWO OPERANDS.
#   * `recorded` — `pull_requests[].base.sha` off the `gate` CHECK-RUN, read through
#     `dispatch-claim._run_recorded_base_sha` ITSELF. The guard's own reader, not a second copy of
#     it: the claim under test is "the field the guard binds on can lead", so the guard has to be
#     the thing that says what the field is (the same rule readme-runbook-check.py runs under).
#   * `tested`  — the merge-ref base tip, i.e. `HEAD^1` of the checked-out `refs/pull/N/merge`
#     commit. #920's header states plainly that this is observable ONLY from inside the run and no
#     API field reports it, which is why the operand here is `gate-staleness.py`'s per-run receipt
#     mined out of the run log, parsed with the PRODUCER'S OWN `parse_receipt`.
#
# THE THREE OUTCOMES THE ISSUE ASKS FOR, and what each one means for #940:
#   LAGS     the recorded field is an ANCESTOR of the graded tree — the #940 header's own two
#            measurements (153s, 2m33s). The guard errs toward calling a fresh gate stale. Safe.
#   EQUAL    the field IS the graded tree. Clause (1) is exactly right, verbatim.
#   LEADS    the graded tree is an ancestor of the recorded field — the run composed an OLDER base
#            than the one GitHub stamped on it. This is #940's named residual, live: clause (1)
#            can read FRESH about a run that graded an older tree, and the fix would have to make
#            the merge-ref reading (this receipt, or a check-run annotation carrying it) the
#            operand. NOT proposed here; #1238 says measure first.
#   DIVERGED neither contains the other. Not a lag, so it is reported in the hazard direction.
#
# THE DIRECTION IS THE WHOLE MEASUREMENT, so it is pinned by an asymmetric self-test fixture:
# swapping the two operands turns every `lags` row into a `leads` row and reds the suite.
#
# FAIL-CLOSED, IN THE DIRECTION A MEASUREMENT FAILS CLOSED. Every unresolvable operand is
# `unprovable` and counts as NO evidence — never as "equal", which would read as a clean bill of
# health for the guard. A population claim ("the field never leads") additionally needs
# MIN_EVIDENCE_ROWS conclusive rows, so a sweep that resolved three runs reports `insufficient`
# and exits non-zero rather than exonerating clause (1) on three rows. A single `leads` row, by
# contrast, is a counterexample and needs no population behind it.
#
# WHO WRITES WHAT THIS READS, AND THEREFORE WHICH ROWS ARE EVIDENCE (AGENTS.md pre-flight item 5).
# For a `pull_request` event GitHub runs the workflow — and every script that workflow invokes —
# out of the PULL REQUEST'S OWN merge tree. So the receipt is not merely "a line any step of the
# `gate` job could print": the reporting step itself, `scripts/gate-staleness.py`, and anything
# `scripts/` can shadow on that script's `sys.path` (`python3 scripts/gate-staleness.py` puts that
# directory first) are ALL author-controlled for the duration of the run. Mining the log on the
# reporting (job, step) pair — which this module does, with the step name taken from the live
# workflow through `gate-staleness.report_step_name` — only excludes lines printed by OTHER steps.
# It establishes nothing about who wrote the code behind that one, so it is not on its own an
# author filter and is never treated as one here.
#
# A row is ADMITTED AS EVIDENCE only when GitHub's own diff for that run
# (`compare/<the recorded base sha>...<the run's head sha>` — API metadata at both ends, never
# anything the run printed) shows the pull touched NO part of that surface. Anything else — a
# touched path, a file list at GitHub's truncation cap, a diff that cannot be read, a run listing
# with no head sha — refuses the row as `unprovable`, i.e. as NO evidence, in BOTH directions: a
# forged `leads` row would indict #940 clause (1) exactly as wrongly as a forged `equal` row would
# exonerate it. Two DIFFERENT receipts under the one reporting step (what a re-run's log carries)
# refuse the row as well, rather than picking one.
#
# THE COST, STATED. On a repository whose pulls routinely edit `scripts/` — this one — most rows
# refuse and the sweep reports `insufficient`. That is the honest reading of this evidence path,
# not a defect in it: a population claim assembled out of receipts the population itself could
# have written would not be a measurement.
#
# READS ONLY, and every one of them idempotent: `gh api` GETs plus `gh run view --log`, through
# `gh_retry.run_gh`. This module writes nothing, arms nothing, and is wired into no workflow — it
# is an operator instrument for producing #1238's crosstab.
"""gate-base-lead — can a check-run's recorded base.sha lead the merge-ref base tip? (#1238)

Usage:
  gate-base-lead.py --repo <owner/name> [--limit N]   # crosstab the last N pr-gate runs
  gate-base-lead.py --self-test
"""
import argparse
import importlib.util
import json
import os
import re
import sys

WORKFLOW_FILE = "pr-gate.yml"
DEFAULT_LIMIT = 40
MAX_LIMIT = 100
# "A few dozen runs" (#1238). The floor a POPULATION claim needs; a counterexample needs none.
MIN_EVIDENCE_ROWS = 24


def _import_sibling(module_name, filename):
    """Import a sibling script by path (the #715 idiom — these scripts have no package)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_gate_staleness = _import_sibling("registry_gate_staleness_1238", "gate-staleness.py")
_gh_retry = _import_sibling("registry_gh_retry_1238", "gh_retry.py")
# The GUARD'S OWN field reader and sha grammar. Imported, never re-declared: a second copy of
# "which base sha does this check-run record for this pull request" is a second answer, and the
# whole point of this measurement is to interrogate the one the guard binds on.
_dispatch_claim = _import_sibling("registry_dispatch_claim_1238", "dispatch-claim.py")
_recorded_base_sha = _dispatch_claim._run_recorded_base_sha
_SHA = _dispatch_claim.SAFE_SHA
GATE_JOB = _gate_staleness.GATE_JOB

EQUAL = "equal"
LAGS = "lags"
LEADS = "leads"
DIVERGED = "diverged"
UNPROVABLE = "unprovable"
INSUFFICIENT = "insufficient"
ROW_STATES = (EQUAL, LAGS, LEADS, DIVERGED, UNPROVABLE)

# `GET /repos/{repo}/compare/{base}...{head}` reports `status` RELATIVE TO `base`. This module
# always asks with base=<the recorded field> and head=<the tested tree>, so:
#   ahead     the tested tree is ahead of the recorded field  -> the field LAGS
#   behind    the tested tree is behind the recorded field    -> the field LEADS (#940's residual)
#   identical the same commit (only reachable on equal shas, which never get here)
#   diverged  neither contains the other
COMPARE_STATES = {"ahead": LAGS, "behind": LEADS, "identical": EQUAL, "diverged": DIVERGED}

# THE RECEIPT-PRODUCING SURFACE — the paths a pull request cannot touch and still be quoted as
# evidence about its own run (see "WHO WRITES WHAT THIS READS" above). `scripts/` is a PREFIX, not
# the one reporter file: the reporter is started as `python3 scripts/gate-staleness.py`, which puts
# that directory first on `sys.path`, so a pull adding `scripts/re.py` or `scripts/subprocess.py`
# rewrites what the untouched reporter does. The workflow file is here because it defines the step.
REPORTER_SURFACE_PREFIXES = ("scripts/",)
REPORTER_SURFACE_PATHS = (_gate_staleness.PR_GATE_WORKFLOW,)
# `GET /compare` reports at most 300 files. AT the cap the list may be truncated, so "the reporter
# surface is untouched" stops being provable — and an unprovable attribution refuses.
COMPARE_FILE_CAP = 300

REPO_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
CHECK_RUN_URL_RE = re.compile(
    r"https://api\.github\.com/repos/(?P<repo>[^/]+/[^/]+)/check-runs/(?P<id>[0-9]{1,20})")


class MeasureError(RuntimeError):
    """A read this measurement cannot do without. Never downgraded to a verdict."""


# ---- PURE READERS ------------------------------------------------------------------------------
def check_run_path(repo, url):
    """PURE: the api path of a job's check run, RE-DERIVED from the captured id, or "".

    The url is API output rather than author text, but it is still the operand this walk splices
    into a request, so it is matched against the expected host AND this repository and rebuilt
    from the id. A url naming another repository yields "" and the row refuses."""
    match = CHECK_RUN_URL_RE.fullmatch(str(url or ""))
    if not match or match.group("repo") != repo:
        return ""
    return f"repos/{repo}/check-runs/{match.group('id')}"


def sole_pull_number(check_run):
    """PURE: the ONE pull request number this check-run is bound to, or None.

    Two entries is one head opened against two bases. The guard reads the field FOR A GIVEN pull
    request number, so a measurement that guessed which entry to take would be measuring a
    different question — refuse instead."""
    entries = check_run.get("pull_requests") if isinstance(check_run, dict) else None
    if not isinstance(entries, list) or len(entries) != 1:
        return None
    number = entries[0].get("number") if isinstance(entries[0], dict) else None
    if not isinstance(number, int) or isinstance(number, bool):
        return None
    return number


def untrusted_receipt_reason(comparison):
    """PURE: "" when a run's receipt is admissible evidence, else the reason it is not.

    `comparison` is GitHub's own `compare/<recorded base>...<head sha>` document — the pull
    request's diff as the API reports it, NOT anything the run printed. A pull that touched no part
    of the receipt-producing surface could not have written its own receipt, so the merge parent
    that receipt names is GitHub's composition rather than the author's claim about it. Every other
    outcome is UNPROVABLE attribution and refuses: a truncated file list, a malformed document and
    a touched reporter path are all "this receipt cannot be quoted", never "it can"."""
    files = comparison.get("files") if isinstance(comparison, dict) else None
    if not isinstance(files, list):
        return ("the pull request's own diff carries no file list, so the code that printed this "
                "run's receipt cannot be established")
    if len(files) >= COMPARE_FILE_CAP:
        return (f"the pull request's diff reports {len(files)} file(s), at or over GitHub's "
                f"{COMPARE_FILE_CAP}-file cap, so it cannot be read as a complete file list")
    for entry in files:
        filename = entry.get("filename") if isinstance(entry, dict) else None
        if not isinstance(filename, str) or not filename:
            return "the pull request's diff carries a file entry with no usable filename"
        if filename in REPORTER_SURFACE_PATHS or filename.startswith(REPORTER_SURFACE_PREFIXES):
            return (f"this pull request changes {filename}, which is code its own reporting step "
                    "runs — the receipt is then the author's claim about the tree, not evidence "
                    "of it")
    return ""


def receipt_from_log(log_text, job_name, step_name):
    """PURE: (receipt, "") for the ONE receipt the reporting step printed, else (None, reason).

    `gh run view --log` emits `<job>\\t<step>\\t<timestamp> <content>`. Only lines whose job AND
    step columns match exactly are considered, which excludes a line printed by any OTHER step —
    and NOTHING MORE THAN THAT. It does not establish who wrote the code behind the matched step,
    which is `attribution_refusal`'s job and is what admits the row as evidence at all (see this
    module's "WHO WRITES WHAT THIS READS"). Two DIFFERENT receipts under that one step (a re-run's
    log carries both attempts) refuse the row: which tree the deciding run graded is then
    genuinely ambiguous."""
    if not isinstance(log_text, str):
        return None, "the run log is unreadable"
    found = []
    for line in log_text.splitlines():
        columns = line.split("\t", 2)
        if len(columns) != 3 or columns[0] != job_name or columns[1] != step_name:
            continue
        fields = _gate_staleness.parse_receipt(columns[2])
        if fields is not None and fields not in found:
            found.append(fields)
    if not found:
        return None, (f"no `{_gate_staleness.RECEIPT_MARKER}` receipt appears under the "
                      f"{job_name!r} job's {step_name!r} step")
    if len(found) > 1:
        return None, (f"the {step_name!r} step printed {len(found)} DIFFERENT receipts, so which "
                      "tree this run graded is ambiguous")
    return found[0], ""


def classify(recorded_base, tested_base, compare_status):
    """PURE: (state, reason) for one run — how the recorded field sits relative to the graded tree.

    `compare_status` is GitHub's own `status` for `compare/<recorded>...<tested>`; it is consulted
    ONLY when the two shas differ, so an equal row costs no request."""
    if not isinstance(recorded_base, str) or not _SHA.fullmatch(recorded_base):
        return UNPROVABLE, "the gate check-run records no base sha for this pull request"
    if not isinstance(tested_base, str) or not _SHA.fullmatch(tested_base):
        return UNPROVABLE, "the run's receipt names no merge-ref base tip"
    if recorded_base == tested_base:
        return EQUAL, "the recorded base sha IS the tree this run graded"
    state = COMPARE_STATES.get(compare_status) if isinstance(compare_status, str) else None
    if state is None:
        return UNPROVABLE, ("the recorded base and the graded tree could not be ordered (compare "
                            f"status {str(compare_status)[:32]!r})")
    if state == EQUAL:
        return UNPROVABLE, ("GitHub reports two DIFFERENT shas as `identical`, which cannot be "
                            "read either way")
    if state == LEADS:
        return LEADS, ("the graded tree is an ANCESTOR of the recorded base sha — this run "
                       "composed an older base than GitHub stamped on it (#940's residual)")
    if state == DIVERGED:
        return DIVERGED, ("the recorded base sha and the graded tree diverge — neither contains "
                          "the other, so the field does not merely lag")
    return LAGS, "the recorded base sha is an ancestor of the tree this run graded"


def crosstab(rows):
    """PURE: the counts, the refusal reasons, and #1238's verdict over a set of measured rows.

    A single `leads` (or `diverged`) row is a COUNTEREXAMPLE and settles the question on its own.
    The two exonerating verdicts are POPULATION claims and additionally require
    MIN_EVIDENCE_ROWS conclusive rows — so an empty sweep, or one that refused most of its runs,
    reports `insufficient` rather than reading as "the field never leads"."""
    counts = {state: 0 for state in ROW_STATES}
    refusals = {}
    for row in rows:
        state = row.get("state")
        counts[state] = counts.get(state, 0) + 1
        if state == UNPROVABLE:
            reason = str(row.get("reason") or "unstated")
            refusals[reason] = refusals.get(reason, 0) + 1
    evidence = counts[EQUAL] + counts[LAGS] + counts[LEADS] + counts[DIVERGED]
    if counts[LEADS]:
        verdict = LEADS
        reason = (f"{counts[LEADS]} run(s) recorded a base sha that LEADS the tree they graded — "
                  "#940 clause (1) can read FRESH for a run that graded an older tree, so the "
                  "guard needs the merge-ref reading as its operand")
    elif counts[DIVERGED]:
        verdict = DIVERGED
        reason = (f"{counts[DIVERGED]} run(s) recorded a base sha that DIVERGES from the tree "
                  "they graded — not a lag, so #940 clause (1) is not exonerated by this sweep")
    elif evidence < MIN_EVIDENCE_ROWS:
        verdict = INSUFFICIENT
        reason = (f"only {evidence} conclusive row(s) — a claim that the field never leads needs "
                  f"at least {MIN_EVIDENCE_ROWS}, so this sweep exonerates nothing")
    elif counts[LAGS]:
        verdict = LAGS
        reason = (f"the recorded base sha LAGS or equals the graded tree on all {evidence} "
                  "conclusive row(s) — it errs toward calling a fresh gate stale, which is the "
                  "safe direction and what #940's header already measured twice")
    else:
        verdict = EQUAL
        reason = (f"the recorded base sha IS the graded tree on all {evidence} conclusive row(s) "
                  "— #940 clause (1) is exactly right as written")
    return {"counts": counts, "evidence": evidence, "verdict": verdict, "reason": reason,
            "refusals": sorted(refusals.items())}


def render(repo, rows, table):
    """PURE: the machine-readable report — one receipt per run, then the roll-up (#920's idiom)."""
    lines = [f"gate-base-lead: repo={repo} runs={len(rows)} (issue #1238)"]
    for row in rows:
        lines.append("gate-base-lead: run={run} pr={pr} recorded={recorded} tested={tested} "
                     "live_tip={tip} state={state}".format(
                         run=row["run"], pr=row["pr"], recorded=row["recorded_base"] or "-",
                         tested=row["tested_base"] or "-", tip=row["live_tip"] or "-",
                         state=row["state"]))
    counts = table["counts"]
    lines.append("gate-base-lead: verdict={verdict} equal={equal} lags={lags} leads={leads} "
                 "diverged={diverged} unprovable={unprovable} evidence={evidence}".format(
                     verdict=table["verdict"], equal=counts[EQUAL], lags=counts[LAGS],
                     leads=counts[LEADS], diverged=counts[DIVERGED],
                     unprovable=counts[UNPROVABLE], evidence=table["evidence"]))
    lines.append(f"gate-base-lead: {table['reason']}")
    for reason, count in table["refusals"]:
        lines.append(f"gate-base-lead: refused x{count}: {reason}")
    return lines


# ---- THE WALK ----------------------------------------------------------------------------------
def attribution_refusal(repo, recorded_base, head_sha, api):
    """The reason this run's receipt may NOT be quoted as evidence, or "" when it may.

    BOTH operands are API metadata — the base sha GitHub stamped on the check-run and the head sha
    the run listing carries — so this asks GitHub whether the pull request could have written its
    own receipt, and never asks the run log. One idempotent GET per row."""
    if not isinstance(head_sha, str) or not _SHA.fullmatch(head_sha):
        return ("the run listing names no head sha for this run, so the code that printed its "
                "receipt cannot be identified")
    try:
        comparison = api(f"repos/{repo}/compare/{recorded_base}...{head_sha}")
    except MeasureError as exc:
        return ("the pull request's own diff is unreadable, so its receipt is unattributable "
                f"({exc})")
    return untrusted_receipt_reason(comparison)


def row_for_run(repo, run, api, log_reader, step_name):
    """One measured row. EVERY degradation is `unprovable` with a named reason — one unreadable
    run must neither abort the sweep nor be silently counted as agreement."""
    row = {"run": "-", "pr": "-", "recorded_base": "", "tested_base": "", "live_tip": "",
           "state": UNPROVABLE, "reason": ""}
    run_id = run.get("id") if isinstance(run, dict) else None
    head_sha = run.get("head_sha") if isinstance(run, dict) else None
    if not isinstance(run_id, int) or isinstance(run_id, bool):
        row["reason"] = "the run listing carries a row with no numeric id"
        return row
    row["run"] = run_id
    try:
        jobs = api(f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=100")
    except MeasureError as exc:
        row["reason"] = f"the run's job listing is unreadable ({exc})"
        return row
    listing = jobs.get("jobs") if isinstance(jobs, dict) else None
    if not isinstance(listing, list):
        row["reason"] = "the run's job listing is malformed"
        return row
    gates = [job for job in listing if isinstance(job, dict) and job.get("name") == GATE_JOB]
    if len(gates) != 1:
        row["reason"] = f"the run has {len(gates)} job(s) named {GATE_JOB!r}, want exactly one"
        return row
    path = check_run_path(repo, gates[0].get("check_run_url"))
    if not path:
        row["reason"] = (f"the {GATE_JOB!r} job's check_run_url is absent or does not name a "
                         f"check run on {repo}")
        return row
    try:
        check_run = api(path)
    except MeasureError as exc:
        row["reason"] = f"the gate check-run is unreadable ({exc})"
        return row
    number = sole_pull_number(check_run)
    if number is None:
        row["reason"] = ("the gate check-run does not carry exactly one pull request entry, so "
                         "its base sha cannot be attributed to a pull request")
        return row
    row["pr"] = number
    row["recorded_base"] = _recorded_base_sha(check_run, number)
    # WHOSE CODE PRINTED THE RECEIPT — asked BEFORE the log is read, because a row this pull could
    # have written is not evidence and the log has nothing to add to it. A row with no recorded
    # base is already `unprovable` at `classify` below, so it needs no diff read to refuse it.
    if row["recorded_base"]:
        refusal = attribution_refusal(repo, row["recorded_base"], head_sha, api)
        if refusal:
            row["reason"] = refusal
            return row
    receipt, refusal = receipt_from_log(log_reader(run_id), GATE_JOB, step_name)
    if receipt is None:
        row["reason"] = refusal
        return row
    for key, field in (("tested_base", "tested_base"), ("live_tip", "live_tip")):
        value = receipt.get(field, "")
        row[key] = value if _SHA.fullmatch(value or "") else ""
    status, compare_error = None, ""
    if row["recorded_base"] and row["tested_base"] and row["recorded_base"] != row["tested_base"]:
        try:
            comparison = api(f"repos/{repo}/compare/{row['recorded_base']}..."
                             f"{row['tested_base']}")
        except MeasureError as exc:
            comparison, compare_error = None, f"the two bases could not be compared ({exc})"
        status = comparison.get("status") if isinstance(comparison, dict) else None
    state, reason = classify(row["recorded_base"], row["tested_base"], status)
    row["state"] = state
    row["reason"] = compare_error if (state == UNPROVABLE and compare_error) else reason
    return row


def collect(repo, limit, api, log_reader, step_name):
    """The last `limit` completed `pull_request` runs of pr-gate, one measured row each."""
    listing = api(f"repos/{repo}/actions/workflows/{WORKFLOW_FILE}/runs"
                  f"?event=pull_request&status=completed&per_page={limit}")
    runs = listing.get("workflow_runs") if isinstance(listing, dict) else None
    if not isinstance(runs, list):
        raise MeasureError(f"the {WORKFLOW_FILE} run listing for {repo} is malformed")
    return [row_for_run(repo, run, api, log_reader, step_name) for run in runs[:limit]]


# ---- LIVE READS (idempotent only) --------------------------------------------------------------
def _gh_json(path, run=None):
    """One idempotent `gh api` GET, parsed. `run` is injectable so the failure directions below
    are self-tested without a `gh` on PATH — bound at CALL time, never as a default argument
    (a default binds the function object and cannot be reached by patching, which is how a
    self-test's "faked" reads shipped real writes twice in one night; see worker-live.sh)."""
    result = (run or _gh_retry.run_gh)(["api", path])
    if result.returncode != 0:
        raise MeasureError(f"`gh api {path}` failed: {(result.stderr or '').strip()[:200]}")
    try:
        return json.loads(result.stdout or "")
    except ValueError as exc:
        raise MeasureError(f"`gh api {path}` returned unparseable JSON ({exc})")


def _gh_run_log(repo, run_id, run=None):
    """The run's log text, or None when it cannot be read. None is a REFUSAL downstream, never an
    empty log — an empty log parses as "this run printed no receipt", which is a different claim."""
    result = (run or _gh_retry.run_gh)(["run", "view", str(run_id), "--repo", repo, "--log"])
    return result.stdout if result.returncode == 0 else None


def report_step_name_of(document):
    """PURE: the receipt step's name from a PARSED pr-gate document, or MeasureError.

    Separated from the file read below so the identification — the part that can silently point a
    log filter at the wrong step — is exercised offline, with no PyYAML and no workflow on disk."""
    job = ((document or {}).get("jobs") or {}).get(GATE_JOB) if isinstance(document, dict) else None
    try:
        return _gate_staleness.report_step_name(job)
    except AssertionError as exc:
        raise MeasureError(f"{WORKFLOW_FILE}'s receipt step cannot be identified ({exc})")


def live_report_step_name():
    """The name of pr-gate's receipt-printing step, read from the LIVE workflow."""
    workflow = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                            _gate_staleness.PR_GATE_WORKFLOW)
    try:
        import yaml
    except ImportError as exc:
        raise MeasureError(f"PyYAML is needed to read {WORKFLOW_FILE} ({exc})")
    try:
        with open(workflow, encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as exc:
        raise MeasureError(f"{WORKFLOW_FILE} is unreadable ({exc})")
    return report_step_name_of(document)


# ---- SELF-TEST ---------------------------------------------------------------------------------
# Shas chosen to appear nowhere else in this harness, so a substituted value can never collide
# with one a fixture already uses (AGENTS.md pre-flight item 4, "value-identical survivor").
_TESTED = "1c2d" * 10
_OLDER = "3e4f" * 10
_NEWER = "5a6b" * 10
_OTHER = "7c8d" * 10
_TIP = "9e0f" * 10
# One head sha per fixture run, so a run's attribution diff is its OWN document: two runs sharing
# one key would let a clean pull's diff answer for a forging pull's row.
_HEAD_PREFIX = "4d5e" * 9
_SELFTEST_REPO = "registry-selftest-invalid/does-not-exist-1238"
_STEP = "Report whether this run graded the tree the PR will land on (#920)"
# A pull that touches neither `scripts/` nor the gate workflow: the only shape admitted as evidence.
_CLEAN_DIFF = {"files": [{"filename": "README.md"}, {"filename": "policy/routing.toml"}]}


def _head_sha(index):
    return f"{_HEAD_PREFIX}{index:04x}"


def _log_line(job, step, content):
    """One `gh run view --log` line, in the shape the runner actually emits."""
    return f"{job}\t{step}\t2026-08-01T00:00:00.0000000Z {content}\n"


def _receipt_line(tested, tip, job=GATE_JOB, step=_STEP):
    """A log line carrying a receipt built by the PRODUCER — never a hand-spelled imitation."""
    line = _gate_staleness.receipt(
        {"state": _gate_staleness.STALE if tested != tip else _gate_staleness.FRESH,
         "tested_base": tested, "live_tip": tip, "behind": 1 if tested != tip else 0}, "master")
    return _log_line(job, step, line)


def _self_test():
    ok = True
    checks = 0

    def chk(name, got, want):
        nonlocal ok, checks
        checks += 1
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    # ---- check_run_path: the url is rebuilt from its id, and a foreign repo refuses.
    chk("a well-formed check_run_url is rebuilt as an api path",
        check_run_path(_SELFTEST_REPO,
                       f"https://api.github.com/repos/{_SELFTEST_REPO}/check-runs/4242"),
        f"repos/{_SELFTEST_REPO}/check-runs/4242")
    for label, url in (
            ("another repository", "https://api.github.com/repos/other/repo/check-runs/4242"),
            ("another host", f"https://evil.example/repos/{_SELFTEST_REPO}/check-runs/4242"),
            ("a trailing path segment",
             f"https://api.github.com/repos/{_SELFTEST_REPO}/check-runs/4242/annotations"),
            ("a non-numeric id",
             f"https://api.github.com/repos/{_SELFTEST_REPO}/check-runs/../../x"),
            ("nothing at all", None)):
        chk(f"a check_run_url naming {label} is refused", check_run_path(_SELFTEST_REPO, url), "")

    # ---- sole_pull_number: exactly one entry, or refuse.
    chk("one pull request entry yields its number",
        sole_pull_number({"pull_requests": [{"number": 1238, "base": {"sha": _OLDER}}]}), 1238)
    for label, doc in (
            ("two entries (one head, two bases)",
             {"pull_requests": [{"number": 1238}, {"number": 1239}]}),
            ("no entries", {"pull_requests": []}),
            ("a malformed listing", {"pull_requests": "nope"}),
            ("a boolean number", {"pull_requests": [{"number": True}]}),
            ("a non-dict entry", {"pull_requests": ["1238"]}),
            ("a non-dict check-run", None)):
        chk(f"a check-run with {label} refuses", sole_pull_number(doc), None)

    # ---- receipt_from_log. The (job, step) filter is what stops a line printed by ANY other step
    # of the same job — i.e. by the pull request's own code — being read as this run's receipt.
    log = ("".join(_log_line(GATE_JOB, "Set up Python (pinned)", "installing"))
           + _receipt_line(_TESTED, _TIP)
           + _log_line(GATE_JOB, _STEP, "some other output"))
    chk("the receipt is mined out of a realistic log, at the graded tip",
        receipt_from_log(log, GATE_JOB, _STEP)[0],
        # `event_base` is the producer's appended tail (#1431): this module builds its lines through
        # `_receipt_line`, which states no event base, so it reads `-` here. This sweep binds on the
        # CHECK-RUN's `pull_requests[].base.sha`, which is a DIFFERENT object from that event field
        # — see this module's header; the tail is carried, not consumed.
        {"state": "stale", "base_ref": "master", "tested_base": _TESTED, "live_tip": _TIP,
         "behind": "1", "event_base": "-"})
    chk("a receipt REPEATED identically (a retried step) is still one receipt",
        receipt_from_log(log + _receipt_line(_TESTED, _TIP), GATE_JOB, _STEP)[0]["tested_base"],
        _TESTED)
    conflicting = receipt_from_log(log + _receipt_line(_OTHER, _TIP), GATE_JOB, _STEP)
    chk("two DIFFERENT receipts refuse the row and say which tree is ambiguous",
        (conflicting[0], "DIFFERENT receipts" in conflicting[1]), (None, True))
    forged = _log_line(GATE_JOB, "Run the full registry self-test suite",
                       _gate_staleness.receipt({"state": "fresh", "tested_base": _OTHER,
                                                "live_tip": _OTHER, "behind": 0}, "master"))
    chk("a receipt printed by ANOTHER STEP of the gate job is not this run's receipt",
        receipt_from_log(forged, GATE_JOB, _STEP)[0], None)
    chk("a receipt printed by another JOB is not this run's receipt",
        receipt_from_log(_receipt_line(_OTHER, _OTHER, job="lint"), GATE_JOB, _STEP)[0], None)
    chk("a log with no receipt at all refuses, and names the marker it looked for",
        (receipt_from_log(_log_line(GATE_JOB, _STEP, "nothing here"), GATE_JOB, _STEP)[0],
         _gate_staleness.RECEIPT_MARKER
         in receipt_from_log("", GATE_JOB, _STEP)[1]), (None, True))
    chk("an unreadable log refuses rather than reading as an empty one",
        receipt_from_log(None, GATE_JOB, _STEP), (None, "the run log is unreadable"))

    # ---- classify. THE DIRECTION IS THE MEASUREMENT: the fixture is asymmetric, so reading the
    # compare status the other way round turns every row below into its opposite.
    chk("`ahead` (the graded tree is ahead of the field) is a LAG — the safe direction",
        classify(_OLDER, _TESTED, "ahead")[0], LAGS)
    leads = classify(_NEWER, _TESTED, "behind")
    chk("`behind` (the graded tree is behind the field) is a LEAD — #940's residual",
        (leads[0], "ANCESTOR" in leads[1]), (LEADS, True))
    chk("`diverged` is reported as diverged, not folded into either direction",
        classify(_OTHER, _TESTED, "diverged")[0], DIVERGED)
    chk("identical shas are EQUAL, and need no compare status at all",
        (classify(_TESTED, _TESTED, None)[0], classify(_TESTED, _TESTED, "diverged")[0]),
        (EQUAL, EQUAL))
    for label, args in (
            ("no recorded base sha", ("", _TESTED, "ahead")),
            ("a short recorded base sha", ("abc", _TESTED, "ahead")),
            ("an uppercase recorded base sha", (_OLDER.upper(), _TESTED, "ahead")),
            ("no tested base", (_OLDER, "", "ahead")),
            ("a dash for the tested base", (_OLDER, "-", "ahead")),
            ("an unreadable compare status", (_OLDER, _TESTED, None)),
            ("an unknown compare status", (_OLDER, _TESTED, "sideways")),
            ("`identical` on two DIFFERENT shas", (_OLDER, _TESTED, "identical"))):
        chk(f"{label} is UNPROVABLE, never equal", classify(*args)[0], UNPROVABLE)

    # ---- crosstab. The boundary literals below are written OUT, never derived from
    # MIN_EVIDENCE_ROWS: an input derived from the constant the code reads cannot detect that
    # constant moving (AGENTS.md pre-flight item 2c).
    def _rows(**counts):
        out = []
        for state, count in counts.items():
            out.extend({"state": state, "reason": f"{state} reason"} for _ in range(count))
        return out

    chk("ONE leads row settles it, even buried in a hundred equal ones",
        crosstab(_rows(equal=100, leads=1))["verdict"], LEADS)
    chk("a diverged row also refuses to exonerate the guard",
        crosstab(_rows(equal=100, diverged=1))["verdict"], DIVERGED)
    chk("leads OUTRANKS diverged — the named residual is the finding",
        crosstab(_rows(leads=1, diverged=1))["verdict"], LEADS)
    chk("24 equal rows is a population claim: clause (1) is exactly right",
        crosstab(_rows(equal=24))["verdict"], EQUAL)
    chk("23 equal rows is NOT enough — one below the floor still exonerates nothing",
        crosstab(_rows(equal=23))["verdict"], INSUFFICIENT)
    chk("24 rows of equal+lags reads LAGS, the #940 header's own measurement",
        crosstab(_rows(equal=20, lags=4))["verdict"], LAGS)
    chk("unprovable rows are NOT evidence: 23 conclusive + 40 refusals is still insufficient",
        crosstab(_rows(equal=23, unprovable=40))["verdict"], INSUFFICIENT)
    empty = crosstab([])
    chk("an EMPTY sweep is insufficient and says so — a zero row never reads as a clean bill",
        (empty["verdict"], empty["evidence"], empty["counts"][EQUAL]), (INSUFFICIENT, 0, 0))
    counted = crosstab(_rows(equal=2, lags=3, leads=1, diverged=4, unprovable=5))
    chk("every class is counted, and `evidence` excludes only the refusals",
        (counted["counts"], counted["evidence"]),
        ({EQUAL: 2, LAGS: 3, LEADS: 1, DIVERGED: 4, UNPROVABLE: 5}, 10))
    chk("refusal reasons are rolled up with their counts, deduplicated",
        crosstab([{"state": UNPROVABLE, "reason": "no receipt"},
                  {"state": UNPROVABLE, "reason": "no receipt"},
                  {"state": UNPROVABLE, "reason": "no gate job"}])["refusals"],
        [("no gate job", 1), ("no receipt", 2)])

    # ---- untrusted_receipt_reason: WHO COULD HAVE WRITTEN THE RECEIPT. The (job, step) filter
    # above narrows WHICH step spoke; this is the control that decides whether what it said is
    # evidence at all, and it reads GitHub's diff rather than anything the run printed.
    chk("a pull that touches nothing its reporting step runs is admissible evidence",
        untrusted_receipt_reason(_CLEAN_DIFF), "")
    for label, filename in (
            ("the reporter itself", "scripts/gate-staleness.py"),
            ("a stdlib name the reporter's own sys.path would shadow", "scripts/subprocess.py"),
            ("a brand-new file under scripts/", "scripts/whatever-new.py"),
            ("the workflow that defines the reporting step", _gate_staleness.PR_GATE_WORKFLOW)):
        reason = untrusted_receipt_reason(
            {"files": [{"filename": "README.md"}, {"filename": filename}]})
        chk(f"a pull that changes {label} is NOT admissible, and the refusal names the path",
            (bool(reason), filename in reason), (True, True))
    capped = untrusted_receipt_reason(
        {"files": [{"filename": f"docs/{n}.md"} for n in range(COMPARE_FILE_CAP)]})
    chk("a diff AT GitHub's file cap may be truncated, so it cannot clear the reporter surface",
        (bool(capped), str(COMPARE_FILE_CAP) in capped), (True, True))
    chk("one file below the cap is still a complete list, and still admissible",
        untrusted_receipt_reason(
            {"files": [{"filename": f"docs/{n}.md"} for n in range(COMPARE_FILE_CAP - 1)]}), "")
    for label, document in (("a document with no file list", {"files": None}),
                            ("a document with no files key at all", {}),
                            ("a file entry that is not an object", {"files": ["README.md"]}),
                            ("a file entry with no filename", {"files": [{"status": "added"}]}),
                            ("a file entry with an empty filename", {"files": [{"filename": ""}]}),
                            ("nothing at all", None)):
        chk(f"{label} is inadmissible — an unreadable diff proves nothing about the reporter",
            bool(untrusted_receipt_reason(document)), True)

    # ---- the WALK, over a fake API. Every fixture below is a shape this sweep really meets.
    def _fixture(limit, population):
        """(api, log_reader) over `population` = [(run_id, kind)] — no network, no gh."""
        runs, docs, logs = [], {}, {}
        for index, (run_id, kind) in enumerate(population):
            head = _head_sha(index)
            runs.append({"id": run_id} if kind == "no-head-sha" else {"id": run_id,
                                                                     "head_sha": head})
            check_id = 900000 + index
            url = f"https://api.github.com/repos/{_SELFTEST_REPO}/check-runs/{check_id}"
            if kind == "no-gate-job":
                docs[f"repos/{_SELFTEST_REPO}/actions/runs/{run_id}/jobs?per_page=100"] = {
                    "jobs": [{"name": "lint", "check_run_url": url}]}
                continue
            if kind == "two-gate-jobs":
                # A re-run, or a matrix that renamed a leg into the aggregator's name: WHICH run
                # recorded the base sha is then ambiguous, and picking the first is a guess.
                docs[f"repos/{_SELFTEST_REPO}/actions/runs/{run_id}/jobs?per_page=100"] = {
                    "jobs": [{"name": GATE_JOB, "check_run_url": url},
                             {"name": GATE_JOB, "check_run_url": url}]}
                continue
            if kind == "malformed-jobs":
                docs[f"repos/{_SELFTEST_REPO}/actions/runs/{run_id}/jobs?per_page=100"] = {
                    "jobs": "nope"}
                continue
            if kind == "unreadable-check-run":
                # The jobs listing resolves; the check-run itself does not (no doc is registered,
                # so the fake api raises exactly as a 5xx-exhausted read would).
                docs[f"repos/{_SELFTEST_REPO}/actions/runs/{run_id}/jobs?per_page=100"] = {
                    "jobs": [{"name": GATE_JOB, "check_run_url": url}]}
                logs[run_id] = _receipt_line(_TESTED, _TIP)
                continue
            if kind == "foreign-check-run-url":
                url = f"https://api.github.com/repos/other/repo/check-runs/{check_id}"
            docs[f"repos/{_SELFTEST_REPO}/actions/runs/{run_id}/jobs?per_page=100"] = {
                "jobs": [{"name": GATE_JOB, "check_run_url": url}]}
            entries = [{"number": 1238, "base": {"sha": _OLDER}}]
            recorded, status = _OLDER, "ahead"
            if kind in ("equal", "forged"):
                # `forged` is the adversarial row: a pull that EDITED the reporter and whose
                # designated step then printed a flawless receipt naming the recorded base as the
                # tree it graded — i.e. manufactured `equal`, the exonerating direction.
                entries, recorded = [{"number": 1238, "base": {"sha": _TESTED}}], _TESTED
            elif kind == "leads":
                entries, recorded, status = ([{"number": 1238, "base": {"sha": _NEWER}}],
                                             _NEWER, "behind")
            elif kind == "diverged":
                entries, recorded, status = ([{"number": 1238, "base": {"sha": _OTHER}}],
                                             _OTHER, "diverged")
            elif kind == "two-pulls":
                entries = [{"number": 1238, "base": {"sha": _OLDER}},
                           {"number": 1239, "base": {"sha": _OTHER}}]
            docs[f"repos/{_SELFTEST_REPO}/check-runs/{check_id}"] = {"pull_requests": entries}
            # `unreadable-compare` registers no comparison so the fake api raises exactly as a
            # retry-exhausted read would; `unprovable-receipt` registers none because a correct
            # reader never asks for one — an ASKED comparison is the kill for that row.
            # `unreadable-diff`/`no-head-sha`/`forged` are excluded because they refuse BEFORE
            # classification: registering a comparison for them would also register it for any
            # OTHER row sharing those operands, which is how `unreadable-compare` stops being
            # unreadable.
            if kind not in ("unreadable-compare", "unprovable-receipt", "forged",
                            "unreadable-diff", "no-head-sha"):
                docs[f"repos/{_SELFTEST_REPO}/compare/{recorded}...{_TESTED}"] = {"status": status}
            # The pull's OWN diff, which decides whether its receipt is evidence at all.
            # `unreadable-diff` registers none, so the fake api raises as a retry-exhausted read
            # would; `forged` touches the reporter the run's own step executes.
            if kind != "unreadable-diff":
                docs[f"repos/{_SELFTEST_REPO}/compare/{recorded}...{head}"] = (
                    {"files": [{"filename": "README.md"},
                               {"filename": "scripts/gate-staleness.py"}]}
                    if kind == "forged" else _CLEAN_DIFF)
            if kind == "no-receipt":
                logs[run_id] = _log_line(GATE_JOB, "Set up Python (pinned)", "installing")
            elif kind == "unprovable-receipt":
                # gate-staleness could not establish the graded tree, so its receipt carries `-`
                # where the shas go. `-` is TRUTHY: a reader that skipped the sha grammar would
                # splice it straight into a compare request.
                logs[run_id] = _log_line(GATE_JOB, _STEP, _gate_staleness.receipt(
                    {"state": _gate_staleness.UNPROVABLE, "tested_base": "", "live_tip": "",
                     "behind": None}, "master"))
            else:
                logs[run_id] = _receipt_line(_TESTED, _TIP)
        docs[f"repos/{_SELFTEST_REPO}/actions/workflows/{WORKFLOW_FILE}/runs"
             f"?event=pull_request&status=completed&per_page={limit}"] = {"workflow_runs": runs}
        asked = []

        def api(path):
            asked.append(path)
            if path not in docs:
                raise MeasureError(f"unexpected request {path}")
            return docs[path]

        return api, (lambda run_id: logs.get(run_id)), asked

    population = [(101, "equal"), (102, "lags"), (103, "leads"), (104, "diverged"),
                  (105, "no-gate-job"), (106, "two-pulls"), (107, "no-receipt"),
                  (108, "foreign-check-run-url")]
    api, log_reader, asked = _fixture(8, population)
    rows = collect(_SELFTEST_REPO, 8, api, log_reader, _STEP)
    chk("the walk measures every run in the listing, in order, with its run id",
        [row["run"] for row in rows], [run_id for run_id, _ in population])
    chk("each run is classified from its OWN operands",
        [row["state"] for row in rows],
        [EQUAL, LAGS, LEADS, DIVERGED, UNPROVABLE, UNPROVABLE, UNPROVABLE, UNPROVABLE])
    chk("a measured row carries both operands and the pull request it is attributed to",
        (rows[2]["pr"], rows[2]["recorded_base"], rows[2]["tested_base"], rows[2]["live_tip"]),
        (1238, _NEWER, _TESTED, _TIP))
    chk("each refusal names its OWN cause, never a generic one",
        [("job(s) named" in rows[4]["reason"]), ("exactly one pull request entry"
                                                 in rows[5]["reason"]),
         ("receipt appears under" in rows[6]["reason"]), ("check_run_url" in rows[7]["reason"])],
        [True, True, True, True])
    chk("an EQUAL row costs no compare beyond the one attributing its receipt (the shas answer it)",
        sorted(path for path in asked if f"/compare/{_TESTED}..." in path),
        [f"repos/{_SELFTEST_REPO}/compare/{_TESTED}...{_head_sha(0)}"])
    chk("a non-equal row asks compare with the RECORDED base first — the direction is the reading",
        sorted(path for path in asked if path.endswith("..." + _TESTED)),
        sorted(f"repos/{_SELFTEST_REPO}/compare/{sha}...{_TESTED}"
               for sha in (_OLDER, _NEWER, _OTHER)))
    # And the OTHER compare: every row that got as far as a recorded base asks GitHub for the
    # PULL'S OWN diff before quoting its receipt, from the recorded base to that RUN's head sha —
    # both operands API metadata. Pinned as an exact set, so a row that skipped the attribution
    # read (or asked it with the wrong head) reds here rather than quietly becoming evidence.
    chk("each measurable row asks for the pull's own diff, at the RECORDED base and its OWN head",
        sorted({path for path in asked
                if "/compare/" in path and not path.endswith("..." + _TESTED)}),
        sorted({f"repos/{_SELFTEST_REPO}/compare/{sha}...{_head_sha(index)}"
                for sha, index in ((_TESTED, 0), (_OLDER, 1), (_NEWER, 2), (_OTHER, 3),
                                   (_OLDER, 6))}))
    chk("the sweep's verdict is driven by the rows it measured", crosstab(rows)["verdict"], LEADS)

    # ---- THE ADVERSARIAL ROW, and the whole reason the attribution read exists. The receipt below
    # is printed by the DESIGNATED step of the DESIGNATED job, is well-formed, parses, and is
    # internally consistent — and it claims the exonerating direction (`equal`). It is refused
    # anyway, because the pull that produced the run edited the code that printed it. Compare the
    # second row: same shape, same receipt, a pull that touched neither `scripts/` nor the
    # workflow — that one IS evidence, so the refusal is attributable to the diff and nothing else.
    forged_api, forged_log, _ = _fixture(2, [(301, "forged"), (302, "equal")])
    forged_rows = collect(_SELFTEST_REPO, 2, forged_api, forged_log, _STEP)
    chk("a FLAWLESS receipt from a pull that edited its own reporter is refused, not counted",
        (forged_rows[0]["state"], "scripts/gate-staleness.py" in forged_rows[0]["reason"],
         forged_rows[1]["state"]), (UNPROVABLE, True, EQUAL))
    chk("and the forged row reports no operands from that receipt at all",
        (forged_rows[0]["tested_base"], forged_rows[0]["live_tip"]), ("", ""))

    # The degradations that are read FAILURES rather than shape problems. Kept in their own
    # population so the row indices asserted above stay pinned to the population that produced
    # them. Every one of them must refuse THAT row, with its own cause, and never fabricate a
    # verdict from operands it does not have.
    degraded = [(201, "malformed-jobs"), (202, "unreadable-check-run"),
                (203, "unreadable-compare"), (204, "two-gate-jobs"),
                (205, "unprovable-receipt"), (206, "unreadable-diff"), (207, "no-head-sha")]
    api_bad, log_bad, asked_bad = _fixture(7, degraded)
    bad_rows = collect(_SELFTEST_REPO, 7, api_bad, log_bad, _STEP)
    chk("a read failure at ANY stage of a row refuses that row, never guesses at its class",
        [row["state"] for row in bad_rows], [UNPROVABLE] * 7)
    chk("and each of the seven names its own stage",
        [("job listing is malformed" in bad_rows[0]["reason"]),
         ("check-run is unreadable" in bad_rows[1]["reason"]),
         ("could not be compared" in bad_rows[2]["reason"]),
         ("2 job(s) named" in bad_rows[3]["reason"]),
         ("no merge-ref base tip" in bad_rows[4]["reason"]),
         # The two attribution failures. An UNREADABLE diff and a run listing with NO head sha both
         # leave "could this pull have written its own receipt?" unanswered, and unanswered is a
         # refusal — never an admitted row.
         ("diff is unreadable" in bad_rows[5]["reason"]),
         ("names no head sha" in bad_rows[6]["reason"])], [True] * 7)
    chk("a row whose bases could not be compared still reports both operands it DID read",
        (bad_rows[2]["recorded_base"], bad_rows[2]["tested_base"]), (_OLDER, _TESTED))
    # The `-` an unprovable receipt carries is TRUTHY. It must never reach a request path, and it
    # must never be reported as a sha this run graded.
    chk("an UNPROVABLE receipt yields no tested base, and issues no compare request for it",
        (bad_rows[4]["tested_base"], bad_rows[4]["live_tip"],
         [path for path in asked_bad if "/compare/" in path and path.endswith("-")]),
        ("", "", []))

    api_short, log_short, _ = _fixture(2, population[:2])
    chk("--limit bounds the walk: the listing is asked for exactly that many runs",
        len(collect(_SELFTEST_REPO, 2, api_short, log_short, _STEP)), 2)

    def _raise(path):
        raise MeasureError("boom")

    try:
        collect(_SELFTEST_REPO, 8, _raise, log_reader, _STEP)
    except MeasureError:
        chk("an unreadable RUN LISTING aborts the sweep loudly, never returns zero rows", True,
            True)
    else:
        chk("an unreadable RUN LISTING aborts the sweep loudly, never returns zero rows", False,
            True)
    malformed = {f"repos/{_SELFTEST_REPO}/actions/workflows/{WORKFLOW_FILE}/runs"
                 f"?event=pull_request&status=completed&per_page=8": {"workflow_runs": "nope"}}
    try:
        collect(_SELFTEST_REPO, 8, lambda path: malformed[path], log_reader, _STEP)
    except MeasureError:
        chk("a MALFORMED run listing aborts too, rather than measuring nothing quietly", True,
            True)
    else:
        chk("a MALFORMED run listing aborts too, rather than measuring nothing quietly", False,
            True)
    per_row = [row_for_run(_SELFTEST_REPO, run, _raise, log_reader, _STEP)
               for run in ({"id": 101}, {"id": True}, {"id": "101"}, "not-a-dict")]
    chk("a per-run read failure refuses THAT ROW only, and a malformed row id refuses too",
        [(row["state"], row["run"]) for row in per_row],
        [(UNPROVABLE, 101), (UNPROVABLE, "-"), (UNPROVABLE, "-"), (UNPROVABLE, "-")])

    # ---- render + the CLI. `main` is where a measurement can be computed correctly and then
    # printed wrong, or exited on wrongly; it is driven here with the same fakes.
    lines = render(_SELFTEST_REPO, rows, crosstab(rows))
    chk("every measured run gets exactly one receipt line, plus header, roll-up and verdict note",
        (len(lines) >= len(rows) + 3, lines[0].endswith("runs=8 (issue #1238)")), (True, True))
    chk("a receipt line states both operands and the verdict for that run",
        lines[3], f"gate-base-lead: run=103 pr=1238 recorded={_NEWER} tested={_TESTED} "
                  f"live_tip={_TIP} state=leads")
    chk("the roll-up counts every class machine-readably",
        [line for line in lines if line.startswith("gate-base-lead: verdict=")],
        ["gate-base-lead: verdict=leads equal=1 lags=1 leads=1 diverged=1 unprovable=4 "
         "evidence=4"])
    chk("an unmeasured run renders dashes, never a sha it does not have",
        lines[6], "gate-base-lead: run=106 pr=- recorded=- tested=- live_tip=- "
                  "state=unprovable")

    import contextlib
    import io

    def run_main(population, limit=None, api_override=None):
        api, log_reader, _ = _fixture(limit or len(population), population)
        argv = ["--repo", _SELFTEST_REPO, "--limit", str(limit or len(population))]
        buffered = io.StringIO()
        with contextlib.redirect_stdout(buffered):
            code = main(argv, api=api_override or api, log_reader=log_reader, step_name=_STEP)
        return code, buffered.getvalue()

    code, out = run_main(population)
    chk("CLI on a sweep that FOUND a lead: exit 0, verdict printed, the finding named",
        (code, "verdict=leads" in out, "#940 clause (1) can read FRESH" in out), (0, True, True))
    code, out = run_main([(200 + n, "equal") for n in range(24)])
    chk("CLI on 24 clean rows: exit 0 and clause (1) is exonerated in as many words",
        (code, "verdict=equal" in out, "exactly right as written" in out), (0, True, True))
    code, out = run_main([(400 + n, "forged") for n in range(24)])
    chk("CLI on 24 rows whose pulls could have written their OWN receipts: NON-ZERO, no evidence, "
        "and nothing exonerated (PR #1961 review r1)",
        (code, "verdict=insufficient" in out, "equal=0" in out, "unprovable=24" in out),
        (1, True, True, True))
    code, out = run_main([(300 + n, "equal") for n in range(23)])
    chk("CLI on 23 clean rows: NON-ZERO, because too little evidence must not read as safe",
        (code, "verdict=insufficient" in out, "exonerates nothing" in out), (1, True, True))
    code, out = run_main(population, api_override=_raise)
    chk("CLI on an unreadable estate: non-zero and LOUD, never a silent empty crosstab",
        (code, "::error::" in out, "verdict=" in out), (1, True, False))
    chk("a missing or malformed --repo is a usage error (exit 2), never a verdict",
        (main([]), main(["--repo", "not-a-repo"]), main(["--repo", "a/b", "--limit", "0"]),
         main(["--repo", "a/b", "--limit", str(MAX_LIMIT + 1)])), (2, 2, 2, 2))

    # ---- THE READ WRAPPERS, driven by an injected runner rather than a real `gh`. A wrapper that
    # swallowed a non-zero exit, or read `{}` out of a truncated body, would fabricate rows that
    # look exactly like measured ones.
    def _runner(returncode, stdout, stderr=""):
        seen = []

        def run(args):
            seen.append(list(args))
            return _gh_retry.GhResult(["gh", *args], returncode, stdout, stderr)

        return run, seen

    good_run, argv_seen = _runner(0, '{"status": "behind"}')
    chk("a successful api read is parsed, and issued as a plain `gh api <path>` GET",
        (_gh_json("repos/o/n/compare/a...b", run=good_run), argv_seen),
        ({"status": "behind"}, [["api", "repos/o/n/compare/a...b"]]))
    for label, run in (("a non-zero exit", _runner(1, "", "gh: Not Found (HTTP 404)")[0]),
                       ("a truncated body", _runner(0, '{"status": ')[0]),
                       ("an empty body", _runner(0, "")[0])):
        try:
            _gh_json("repos/o/n/x", run=run)
        except MeasureError:
            chk(f"an api read that returns {label} RAISES, never a silent empty document",
                True, True)
        else:
            chk(f"an api read that returns {label} RAISES, never a silent empty document",
                False, True)
    log_run, log_argv = _runner(0, "the log")
    chk("a successful log read returns the text, over `gh run view <id> --repo <r> --log`",
        (_gh_run_log("o/n", 4242, run=log_run), log_argv),
        ("the log", [["run", "view", "4242", "--repo", "o/n", "--log"]]))
    chk("a FAILED log read returns None — a refusal, not an empty log",
        _gh_run_log("o/n", 4242, run=_runner(1, "", "boom")[0]), None)

    # ---- identifying the receipt step out of a PARSED workflow document. The shape comes from
    # gate-staleness's own seam fixture, so this cannot drift away from what that module accepts.
    seam = {"jobs": {GATE_JOB: _gate_staleness._seam_fixture()}}
    chk("the receipt step is identified from a parsed pr-gate document",
        report_step_name_of(seam), "Report staleness")
    for label, document in (("a document with no gate job", {"jobs": {"lint": {}}}),
                            ("a document with no jobs at all", {}),
                            ("a document whose gate job lost the reporting step",
                             {"jobs": {GATE_JOB: {"steps": []}}}),
                            ("nothing at all", None)):
        try:
            report_step_name_of(document)
        except MeasureError:
            chk(f"{label} REFUSES — a log filter must never point at a guessed step", True, True)
        else:
            chk(f"{label} REFUSES — a log filter must never point at a guessed step", False, True)

    # ---- and the LIVE workflow: the step name this sweep filters run logs on must be readable
    # from the shipped pr-gate.yml, or the instrument silently measures nothing.
    try:
        live_step = live_report_step_name()
    except MeasureError as exc:
        live_step = f"unavailable ({exc})"
    if live_step.startswith("unavailable (PyYAML is needed"):
        chk("PyYAML is available to read the LIVE workflow's receipt step", live_step, "")
    else:
        chk("the LIVE pr-gate.yml names a receipt step this sweep can filter run logs on",
            (live_step.startswith("unavailable"), bool(live_step.strip())), (False, True))

    print("gate-base-lead self-test", "PASSED" if ok else "FAILED", f"({checks} checks)")
    return 0 if ok else 1


def main(argv=None, api=None, log_reader=None, step_name=None):
    parser = argparse.ArgumentParser(
        description="Can a check-run's recorded base.sha lead the merge-ref base tip? (#1238)")
    parser.add_argument("--repo", default="", help="owner/name to measure")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                        help=f"how many recent pr-gate runs to cross-tab (default {DEFAULT_LIMIT})")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if not REPO_RE.fullmatch(args.repo or ""):
        print("error: --repo must be a plain owner/name", file=sys.stderr)
        return 2
    if not 1 <= args.limit <= MAX_LIMIT:
        print(f"error: --limit must be between 1 and {MAX_LIMIT}", file=sys.stderr)
        return 2
    try:
        rows = collect(args.repo, args.limit, api or _gh_json,
                       log_reader or (lambda run_id: _gh_run_log(args.repo, run_id)),
                       step_name or live_report_step_name())
    except MeasureError as exc:
        # LOUD, and no crosstab: a measurement that could not be taken must never print a table
        # whose zeros read as "no lead was found" (issue #1238).
        print(f"::error::gate-base-lead: the measurement could not be taken — {exc}")
        return 1
    table = crosstab(rows)
    for line in render(args.repo, rows, table):
        print(line)
    return 1 if table["verdict"] == INSUFFICIENT else 0


if __name__ == "__main__":
    sys.exit(main())
