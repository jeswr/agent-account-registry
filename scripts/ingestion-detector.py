#!/usr/bin/env python3
"""Detect workflows GitHub has REFUSED TO INGEST (#1353).

THE FAILURE THIS CATCHES. Four times in 18 hours (2026-07-30/31) a commit to a workflow file made
GitHub reject the workflow outright: every run concludes `action_required` with **zero jobs created**,
in about one second, on the DEFAULT branch. Cost so far: dispatch 18 h, dashboard/keepalive ~90 min,
groom ~33 min, and dispatch+groom together ~66 min. Every one was found by a human noticing; nothing
in the estate alarms on it.

⚠️ WHY `conclusion` IS NOT THE SIGNAL. A rejected run's conclusion is `action_required`, which is
indistinguishable from an ordinary approval gate — that is exactly why all four sat unnoticed. The
discriminator is `jobs.total_count == 0` on a **completed** run, and it is exact.

⚠️ WHY `status=completed` IS LOAD-BEARING. A queued or in-progress run legitimately has zero jobs,
because they have not been created yet. Reading the latest run of ANY status false-positives on every
busy workflow — measured while designing this: `dispatch` flagged as rejected while its most recent
COMPLETED run had jobs=5. A detector that cries wolf on the busiest lane is muted within a day, which
is worse than no detector.

⚠️ PREVENTION IS IMPOSSIBLE, SO THIS DETECTS. A pre-merge probe cannot work: any branch whose workflow
file differs from the default branch is gated to `action_required` regardless of validity (control: a
branch changing only README.md ran fine, 5 jobs). Ingestion is only observable where the file lands.
Detecting within one cron interval recovers almost all of an 18-hour loss.

MECHANISM UNKNOWN. Four instances, four diff shapes (+25/-1 comments; +20/-1 comments; +38/-6 a job
`outputs:` block; +11/-4 a sparse-checkout list). Refuted by measurement: file size (35 KB fails,
156 KB works), YAML validity (files parse), intermittency (3/3 and 3/3 on repeated probes), comment
blocks, and the branch-vs-default artifact. This script asserts the SYMPTOM and takes no view on cause.
"""
import argparse
import json
import subprocess
import sys

# The lanes whose loss stops the fleet. Ordered by blast radius.
LOAD_BEARING = [
    "dispatch.yml", "groom.yml", "review-fix.yml", "worker.yml",
    "dashboard.yml", "metrics.yml", "retriage.yml", "conflict-resolver.yml",
]


def _api(path):
    out = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"gh api {path} failed: {out.stderr.strip()[:200]}")
    return json.loads(out.stdout or "{}")


def latest_completed(repo, workflow, branch):
    """The most recent COMPLETED run on `branch`, or None. `status=completed` is filtered at the API
    so pending rows never enter the sample — a busy workflow can otherwise hide its last completed run
    beyond the page window."""
    runs = _api(f"repos/{repo}/actions/workflows/{workflow}/runs"
                f"?per_page=20&branch={branch}&status=completed").get("workflow_runs") or []
    # [MEASURED 2026-07-31] `cancelled` runs must be SKIPPED, not judged. A run killed by the
    # `concurrency` group before its jobs were created is `completed/cancelled` with jobs=0 — byte
    # identical to a rejection under this predicate. Observed live: dispatch had four such rows
    # sitting NEWER than a `completed/success jobs=5`, so taking the single most recent completed
    # run reported a healthy workflow as uningestible for 6+ minutes. A detector that cries wolf on
    # the busiest lane is muted within a day, which is the failure this whole script exists to avoid.
    # Walk back to the newest run that actually reached a verdict about its own content.
    for run in runs:
        if run.get("conclusion") != "cancelled":
            return run
    return None


def job_count(repo, run_id):
    return int(_api(f"repos/{repo}/actions/runs/{run_id}/jobs").get("total_count", 0))


def check(repo, branch, workflows, log=print):
    """Returns (rejected, checked). `rejected` is [(workflow, run_id, created_at)]."""
    rejected, checked = [], []
    for wf in workflows:
        try:
            run = latest_completed(repo, wf, branch)
        except RuntimeError as exc:
            log(f"::warning::ingestion-detector: {wf}: {exc}")
            continue
        if run is None:
            log(f"ingestion-detector: {wf}: no completed run on {branch} — skipped")
            continue
        n = job_count(repo, run["id"])
        checked.append(wf)
        if n == 0:
            rejected.append((wf, run["id"], run.get("created_at", "?")))
            log(f"::error::ingestion-detector: {wf} is NOT INGESTIBLE — run {run['id']} "
                f"({run.get('created_at')}) concluded {run.get('conclusion')} with jobs=0. "
                f"GitHub refused the workflow file. See #1353.")
        else:
            log(f"ingestion-detector: {wf}: jobs={n} ok")
    return rejected, checked


def _self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok ' if good else 'FAIL'}  {name}: {got!r} (want {want!r})")

    # The headline guard: a COMPLETED run with zero jobs is the only rejection signal, and a
    # non-zero count is never one — mutate either half and this reds.
    calls = []

    def fake(repo, wf, branch, runs=None):
        calls.append(wf)
        return {"id": 1, "created_at": "T", "conclusion": "action_required"}

    import types
    mod = sys.modules[__name__]
    real_latest, real_jobs = mod.latest_completed, mod.job_count
    try:
        mod.latest_completed = lambda r, w, b: {"id": 7, "created_at": "T",
                                                "conclusion": "action_required"}
        mod.job_count = lambda r, i: 0
        rej, chkd = check("o/r", "master", ["a.yml"], log=lambda m: None)
        chk("zero jobs on a completed run IS a rejection", [x[0] for x in rej], ["a.yml"])

        mod.job_count = lambda r, i: 5
        rej, _ = check("o/r", "master", ["a.yml"], log=lambda m: None)
        chk("non-zero jobs is NEVER a rejection, even when conclusion=action_required",
            rej, [])

        # A workflow with no completed run must be SKIPPED, not reported — a brand-new or
        # never-run workflow is not a rejection.
        mod.latest_completed = lambda r, w, b: None
        rej, chkd = check("o/r", "master", ["a.yml"], log=lambda m: None)
        chk("no completed run -> skipped, not rejected", (rej, chkd), ([], []))

        # An API failure must not be read as a rejection (fail-open on the READ, loud).
        def boom(r, w, b):
            raise RuntimeError("boom")
        mod.latest_completed = boom
        rej, chkd = check("o/r", "master", ["a.yml"], log=lambda m: None)
        chk("read failure -> skipped, not rejected", (rej, chkd), ([], []))
    finally:
        mod.latest_completed, mod.job_count = real_latest, real_jobs

    # [MEASURED 2026-07-31] The regression that made this detector report a HEALTHY dispatch as
    # uningestible for 6+ minutes: `completed/cancelled` runs have jobs=0 because the concurrency
    # group killed them before job creation, and they can sit NEWER than a real verdict. Skipping
    # them is what makes the signal trustworthy; delete the skip and this reds.
    seq = [{"id": 1, "conclusion": "cancelled", "created_at": "T3"},
           {"id": 2, "conclusion": "cancelled", "created_at": "T2"},
           {"id": 3, "conclusion": "success", "created_at": "T1"}]
    mod2 = sys.modules[__name__]
    real_api = mod2._api
    try:
        mod2._api = lambda path: {"workflow_runs": seq} if "/runs" in path else {}
        picked = mod2.latest_completed("o/r", "w.yml", "master")
        chk("cancelled runs are SKIPPED — the newest real verdict wins",
            picked["id"] if picked else None, 3)
        mod2._api = lambda path: {"workflow_runs": [{"id": 9, "conclusion": "cancelled"}]}
        chk("all-cancelled -> no verdict available, skipped rather than reported",
            mod2.latest_completed("o/r", "w.yml", "master"), None)
    finally:
        mod2._api = real_api

    chk("the load-bearing list names dispatch and groom",
        ("dispatch.yml" in LOAD_BEARING, "groom.yml" in LOAD_BEARING), (True, True))
    print("ingestion-detector self-test " + ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="jeswr/agent-account-registry")
    ap.add_argument("--branch", default="master")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()
    rejected, checked = check(args.repo, args.branch, LOAD_BEARING)
    print(f"ingestion-detector: checked {len(checked)}, rejected {len(rejected)}")
    return 1 if rejected else 0


if __name__ == "__main__":
    sys.exit(main())
