#!/usr/bin/env python3
"""PLAN-side authenticated target snapshot (the REG-4 registry-inline half).

Runs BEFORE any target planner code executes and holds the only token the PLAN job ever
sees; the target-planner and assemble steps consume the raw-*.json files this writes.
Extracted from the dispatch.yml heredoc so the per-item degradation below is enforced by
--self-test (the pr-gate suite) instead of living untested inside the workflow.

Per-item degradation (dispatch run 29617040167, 2026-07-17): one pathological PR whose
head had accumulated >=1000 check runs (sparq merge-queue concurrency-cancel churn kept
re-running CI on the same head) tripped the runaway-snapshot ceiling and killed the
ENTIRE sweep — PLAN failed, CLAIM was skipped, zero dispatch fleet-wide. The ceiling is
now a PER-ITEM backstop: an oversized or unreadable per-PR read skips THAT PR with a
recorded reason (raw-prstatus `skips` -> plan `snapshot_skips` -> the dispatch summary's
defer_reasons) and the sweep continues.

Degradation is two-tier (round-1 review of PR #60): a check-run failure AFTER the PR
detail read succeeded must not throw the detail away, because the #42 armed-SHA-mismatch
DISARM consumes only detail data (head_sha + the auto_merge armed bit) — and for disarm
the ACT is the safety measure, so a full stand-down there is fail-OPEN (an armed PR whose
head advanced past its reviewed-sha marker would keep its stale arm latched just because
its head churned past the check-run ceiling — cheap to induce via merge-queue cancel
churn, the exact scenario this file exists for). So:
- POST-detail failure (check-runs-overflow/-malformed/-read-failed): the record is EMITTED
  with the detail fields intact, `check_runs` EMPTY, and an explicit
  `check_runs_degraded: <reason>` marker; the skip row is still recorded for visibility.
  pr_ci_status forces gate="missing" on the marker, and enumerate_review_items stands the
  check-run-DEPENDENT admissions (ci-fix, stranded) down on it while the detail-derived
  ones (the needs-rebase conflict repair, and the disarm net) still evaluate on sound
  data — monotone: a degraded record yields the undegraded outcome or do-nothing, never
  a different act.
- PRE-detail failure (pr-detail-read-failed/-malformed, worker-pr-census-overflow):
  nothing sound is derivable — NO record, every snapshot-derived admission including
  disarm stands down for that PR this tick. Residual, accepted: the detail read failing
  is a GitHub API outage/malformed-response condition, not attacker-inducible by
  inflating check-run volume on a head.

Blowup reduced at source: the check-run read is gate-filtered (check_name=CI_GATE_CHECK,
the d2c0dd0 pattern — an unfiltered listing both grows without bound under churn and can
lose the gate run entirely); the unfiltered walk that names advisory failing legs runs
ONLY when the filtered gate is a concluded failure (the only state that admits a ci-fix).

Repo-level listings (issues / pulls) keep their sweep-fatal 5000-entry ceiling: the
target planner step requires a complete issue snapshot for every manifest repo, so a
per-repo degradation there needs a cross-step design (follow-up; see the PR record).
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

RETRYABLE = {403, 429, 500, 502, 503, 504}
LIST_PAGE_LIMIT = 50        # issues/pulls ceiling: 5000 entries, repo-level, sweep-fatal
# Per-SHA ceiling backstop: 4000 entries (the f37d13f emergency bump — churned sparq heads
# really do pass 1000, e.g. PR #2540 at 1061), and it now degrades PER ITEM, never per sweep.
CHECK_RUN_PAGE_LIMIT = 40
WORKER_PR_STATUS_LIMIT = 100
WORKER_HEAD_PREFIX = "sparq-agent/"
SAFE_SHA = re.compile(r"[0-9a-f]{40}")


class FetchError(Exception):
    """A GitHub read failed for good (retries exhausted) or returned a malformed page."""


class SnapshotItemError(Exception):
    """A single PR's status snapshot failed: skip THAT PR with a reason, never the sweep.
    Raised out of _pr_status_record only for PRE-detail failures (no sound record is
    derivable); post-detail check-run failures degrade the record instead of raising.
    The reason must be a member of dispatch-claim.py's SNAPSHOT_SKIP_REASONS (validated
    there when the plan artifact is re-checked as hostile data)."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _load_claim():
    """Load dispatch-claim.py (same checkout) for CI_GATE_CHECK + interpret_check_runs —
    the snapshot must fetch exactly what those PURE interpreters later re-derive from."""
    path = Path(__file__).resolve().parent / "dispatch-claim.py"
    spec = importlib.util.spec_from_file_location("registry_dispatch_claim_snapshot", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load registry helper dispatch-claim.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_fetch(token):
    """Authenticated single-page reader with retry/backoff; raises FetchError, never exits
    (the caller decides sweep-fatal vs per-item)."""

    def fetch(url):
        for attempt in range(3):
            request = Request(url, headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "reg4-plan-snapshot",
                "X-GitHub-Api-Version": "2022-11-28",
            })
            try:
                with urlopen(request, timeout=30) as response:
                    return json.load(response)
            except HTTPError as exc:
                if exc.code in RETRYABLE and attempt < 2:
                    time.sleep(5 * (attempt + 1))
                    continue
                raise FetchError(
                    f"authenticated GitHub read failed (HTTP {exc.code}) for "
                    + url.split("?")[0]) from exc
            except (URLError, TimeoutError, json.JSONDecodeError) as exc:
                if attempt < 2:
                    time.sleep(5 * (attempt + 1))
                    continue
                raise FetchError(
                    "authenticated GitHub read failed for " + url.split("?")[0]) from exc

    return fetch


def _paginated(fetch, path):
    """Repo-level page walk to a short page. The explicit ceiling only guards a runaway
    snapshot (5000 covers the migrated backlog with organic-growth margin) and stays
    SWEEP-fatal: the target planner step needs a complete listing for every repo."""
    items = []
    for page in range(1, LIST_PAGE_LIMIT + 1):
        separator = "&" if "?" in path else "?"
        result = fetch(f"https://api.github.com{path}{separator}per_page=100&page={page}")
        if not isinstance(result, list):
            raise FetchError("GitHub API returned a non-list page")
        items.extend(result)
        if len(result) < 100:
            return items
    raise FetchError("refusing a target snapshot at or above 5000 entries")


def _fetch_check_runs(fetch, repo, sha, check_name=None):
    """Per-SHA check-runs walk. Every failure mode here is PER-ITEM (SnapshotItemError):
    the ceiling is a backstop, not a sweep-killer. check_name filtering keeps the common
    case to one small page even on churned heads with hundreds of runs."""
    filter_query = f"&check_name={check_name}" if check_name else ""
    runs_out = []
    for page in range(1, CHECK_RUN_PAGE_LIMIT + 1):
        try:
            doc = fetch(f"https://api.github.com/repos/{repo}/commits/{sha}"
                        f"/check-runs?per_page=100&page={page}{filter_query}")
        except FetchError as exc:
            raise SnapshotItemError("check-runs-read-failed") from exc
        runs = doc.get("check_runs") if isinstance(doc, dict) else None
        if not isinstance(runs, list):
            raise SnapshotItemError("check-runs-malformed")
        runs_out.extend({
            "name": run.get("name"),
            "status": run.get("status"),
            "conclusion": run.get("conclusion"),
            "started_at": run.get("started_at"),
        } for run in runs if isinstance(run, dict))
        if len(runs) < 100:
            return runs_out
    raise SnapshotItemError("check-runs-overflow")


def _pr_status_record(fetch, claim, repo, number):
    """One worker PR's CI/merge status: detail read (mergeable + auto_merge + fresh head)
    plus the gate-filtered check-run read; the unfiltered listing (advisory failing-leg
    names for the ci-fix prompt) is fetched ONLY when the gate is a concluded failure —
    the one state that admits a ci-fix.

    Raises SnapshotItemError ONLY for pre-detail failures. Once the detail read has
    succeeded, a check-run failure DEGRADES the record (empty check_runs + an explicit
    `check_runs_degraded` reason) instead of discarding it: the detail fields are exactly
    what the #42 armed-SHA-mismatch disarm needs, and dropping them on check-run VOLUME
    would let an armed PR defeat its own safety net by churning past the ceiling."""
    try:
        detail = fetch(f"https://api.github.com/repos/{repo}/pulls/{number}")
    except FetchError as exc:
        raise SnapshotItemError("pr-detail-read-failed") from exc
    if not isinstance(detail, dict):
        raise SnapshotItemError("pr-detail-malformed")
    sha = str((detail.get("head") or {}).get("sha", ""))
    record = {
        "head_sha": sha,
        "mergeable": detail.get("mergeable"),
        "auto_merge": detail.get("auto_merge"),
        "check_runs": [],
    }
    if SAFE_SHA.fullmatch(sha):
        try:
            check_runs = _fetch_check_runs(fetch, repo, sha, check_name=claim.CI_GATE_CHECK)
            if claim.interpret_check_runs(check_runs)["gate"] == "failure":
                check_runs = check_runs + _fetch_check_runs(fetch, repo, sha)
            record["check_runs"] = check_runs
        except SnapshotItemError as exc:
            # POST-detail degradation: keep the detail (disarm still fires), blank the
            # check runs entirely (a partial gate-only listing must not admit a ci-fix
            # whose advisory legs walk overflowed), mark the reason for the skip row.
            record["check_runs_degraded"] = exc.reason
    return record


def _pr_status_snapshot(fetch, claim, repo, pulls):
    """Per-worker-PR CI/merge status (GAP-A/B/C inputs) with per-item degradation.
    Returns (status_items, skips). Two tiers: a PRE-detail failure records a skip and NO
    status record (every snapshot-derived admission stands down); a POST-detail check-run
    failure records the SAME skip row for visibility but ALSO emits a degraded record
    (detail intact, check_runs empty + marked) so the #42 disarm net still fires."""
    worker_pulls = [
        pull for pull in pulls
        if isinstance(pull, dict) and pull.get("state") == "open"
        and isinstance(pull.get("number"), int) and pull["number"] > 0
        and str((pull.get("head") or {}).get("ref", "")).startswith(WORKER_HEAD_PREFIX)
        and ((pull.get("head") or {}).get("repo") or {}).get("full_name") == repo
    ]
    if len(worker_pulls) > WORKER_PR_STATUS_LIMIT:
        # Repo-level census overflow degrades to NO prstatus for this repo (pr_number 0
        # marks the repo-wide skip): issue dispatch continues, every snapshot-derived PR
        # admission stands down. Better a status-blind tick than a dead sweep.
        return {}, [{"pr_number": 0, "reason": "worker-pr-census-overflow"}]
    status_items = {}
    skips = []
    for pull in worker_pulls:
        number = pull["number"]
        try:
            record = _pr_status_record(fetch, claim, repo, number)
        except SnapshotItemError as exc:
            # THE per-item catch (run 29617040167): one unreadable PR detail defers
            # itself with a recorded reason; its siblings and the sweep continue.
            skips.append({"pr_number": number, "reason": exc.reason})
            continue
        status_items[str(number)] = record
        if "check_runs_degraded" in record:
            # Post-detail degradation stays VISIBLE in the same skip histogram even
            # though the (detail-only) record is emitted for the disarm net.
            skips.append({"pr_number": number, "reason": record["check_runs_degraded"]})
    return status_items, skips


def snapshot_targets(fetch, claim, repos, out_dir):
    """Per-repo degradation (registry pipeline-failure-visibility, audit modes #2/#3): the
    repo-level issues/pulls listing was SWEEP-FATAL — one repo's real 5xx/403/429/timeout (after
    retries), a non-list page, or a target legitimately grown past the 5000-entry ceiling raised a
    FetchError that killed PLAN for EVERY target (and, because CLAIM's always() alarm steps are
    skipped on a PLAN crash, silenced the whole tick). Now a repo whose listing fails writes an
    INCOMPLETE snapshot (`complete: False` + `snapshot_error`) for ITSELF and the sweep continues to
    the other target; the downstream planner skips that repo with a recorded reason routed into
    `snapshot_skips`, so it surfaces in the always() alarm instead of dying silently. A degraded
    repo emits ZERO ready rows (fail-closed): a listing we could not complete must never look
    empty-and-therefore-groomable to a downstream consumer."""
    degraded = 0
    for index, repo in enumerate(repos):
        try:
            issues = _paginated(fetch, f"/repos/{repo}/issues?state=open")
            pulls = _paginated(fetch, f"/repos/{repo}/pulls?state=open")
        except FetchError as exc:
            # Per-repo degrade: mark THIS repo incomplete (fail-closed: no items) and keep going.
            # The recorded reason is the STABLE token dispatch-claim.py allowlists
            # (`repo-degraded:listing-failed` after the assemble step's fold) — raw exception
            # text would mint a dynamic reason validate_plan rejects, re-killing the sweep this
            # degradation exists to save. The human diagnostic stays in the ::warning:: line.
            degraded += 1
            reason = "listing-failed"
            print(f"::warning::SNAPSHOT repo {repo} DEGRADED (listing failed): {exc}")
            Path(out_dir, f"raw-issues-{index}.json").write_text(
                json.dumps({"complete": False, "items": [], "snapshot_error": reason}),
                encoding="utf-8")
            Path(out_dir, f"raw-pulls-{index}.json").write_text(
                json.dumps({"complete": False, "items": [], "snapshot_error": reason}),
                encoding="utf-8")
            Path(out_dir, f"raw-prstatus-{index}.json").write_text(
                json.dumps({"complete": False, "items": {}, "skips": [],
                            "snapshot_error": reason}),
                encoding="utf-8")
            continue
        Path(out_dir, f"raw-issues-{index}.json").write_text(
            json.dumps({"complete": True, "items": issues}), encoding="utf-8")
        Path(out_dir, f"raw-pulls-{index}.json").write_text(
            json.dumps({"complete": True, "items": pulls}), encoding="utf-8")
        status_items, skips = _pr_status_snapshot(fetch, claim, repo, pulls)
        for skip in skips:
            print(f"SNAPSHOT skip {repo}#{skip['pr_number']}: {skip['reason']}")
        Path(out_dir, f"raw-prstatus-{index}.json").write_text(
            json.dumps({"complete": True, "items": status_items, "skips": skips}),
            encoding="utf-8")
    if degraded == len(repos) and repos:
        # EVERY target failed to list — that is a fleet-wide fetch outage, not a per-repo blip;
        # keep the sweep FATAL so the dispatch alarm job fires on the PLAN failure (a silently
        # all-empty plan would look like a healthy empty backlog).
        raise SystemExit(
            f"every target repo ({len(repos)}) failed its listing — fleet-wide fetch failure")
    print(f"SNAPSHOT complete for {len(repos)} target repo(s) "
          f"({degraded} degraded per-repo)")


def _self_test():
    import tempfile

    claim = _load_claim()
    gate = claim.CI_GATE_CHECK
    repo = "example/repo"

    def gate_run(conclusion="success", status="completed", name=None):
        return {"name": gate if name is None else name, "status": status,
                "conclusion": conclusion, "started_at": "2026-07-17T00:00:00Z"}

    def worker_pull(number, sha):
        return {"number": number, "state": "open",
                "head": {"ref": f"sparq-agent/issue-{number}-1-1", "sha": sha,
                         "repo": {"full_name": repo}}}

    sha_ok, sha_red, sha_over, sha_legs_over = "1" * 40, "2" * 40, "3" * 40, "4" * 40
    pulls = [
        worker_pull(7, sha_over),        # gate-filtered listing never shortens -> overflow
        worker_pull(9, sha_ok),          # healthy sibling: must still be planned
        worker_pull(11, sha_red),        # concluded gate failure: legs fetched + interpretable
        worker_pull(13, sha_ok),         # detail read hard-fails -> per-item skip
        worker_pull(15, sha_legs_over),  # gate failure but the unfiltered legs walk overflows
        {"number": 90, "state": "open",  # non-worker head: excluded from the census entirely
         "head": {"ref": "topic", "sha": sha_ok, "repo": {"full_name": repo}}},
    ]

    def fake_fetch(url):
        if url.split("?")[0].endswith(f"/repos/{repo}/issues"):
            return []
        if url.split("?")[0].endswith(f"/repos/{repo}/pulls"):
            return pulls if "page=1" in url else []
        if "/pulls/13" in url:
            raise FetchError("boom")
        for number, sha in ((7, sha_over), (9, sha_ok), (11, sha_red), (15, sha_legs_over)):
            if url.split("?")[0].endswith(f"/pulls/{number}"):
                # PR 7 is ARMED (auto_merge latched) — the round-1 disarm-under-overflow case.
                return {"head": {"sha": sha}, "mergeable": True,
                        "auto_merge": {"merge_method": "squash"} if number == 7 else None}
        if f"/commits/{sha_over}/" in url:
            return {"check_runs": [gate_run() for _ in range(100)]}     # never a short page
        if f"/commits/{sha_ok}/" in url:
            assert "check_name=" in url, "healthy head must be read gate-filtered"
            return {"check_runs": [gate_run()]}
        if f"/commits/{sha_red}/" in url:
            if "check_name=" in url:
                return {"check_runs": [gate_run(conclusion="failure")]}
            return {"check_runs": [gate_run(conclusion="failure"),
                                   gate_run(conclusion="failure", name="leg-a")]}
        if f"/commits/{sha_legs_over}/" in url:
            if "check_name=" in url:
                return {"check_runs": [gate_run(conclusion="failure")]}
            return {"check_runs": [gate_run(conclusion="failure") for _ in range(100)]}
        raise AssertionError(f"unexpected fetch {url}")

    with tempfile.TemporaryDirectory() as out_dir:
        snapshot_targets(fake_fetch, claim, [repo], out_dir)
        doc = json.loads(Path(out_dir, "raw-prstatus-0.json").read_text(encoding="utf-8"))

    # (i) oversized/unreadable PRs are skipped WITH a reason; the sweep did not die.
    assert doc["complete"] is True
    assert doc["skips"] == [{"pr_number": 7, "reason": "check-runs-overflow"},
                            {"pr_number": 13, "reason": "pr-detail-read-failed"},
                            {"pr_number": 15, "reason": "check-runs-overflow"}], doc["skips"]
    assert all(skip["reason"] in claim.SNAPSHOT_SKIP_REASONS for skip in doc["skips"])
    # (ii) siblings are still planned, and their records interoperate with the PURE
    # claim-side interpreters (a pre-detail-skipped PR has NO record: nothing to guess from).
    healthy = claim.pr_ci_status(doc["items"]["9"])
    assert healthy["gate"] == "success" and healthy["conflicting"] is False
    assert healthy["check_runs_degraded"] is False
    red = claim.pr_ci_status(doc["items"]["11"])
    assert red["gate"] == "failure" and red["failing_legs"] == ["leg-a"]
    # (iii) POST-detail degradation (PR #60 round-1 fix): a check-run overflow KEEPS the
    # detail record — check_runs EMPTY + an explicit marker — while the pre-detail
    # failure (13) stays a full skip with no record at all.
    assert sorted(doc["items"]) == ["11", "15", "7", "9"], sorted(doc["items"])
    assert doc["items"]["7"] == {"head_sha": sha_over, "mergeable": True,
                                 "auto_merge": {"merge_method": "squash"},
                                 "check_runs": [],
                                 "check_runs_degraded": "check-runs-overflow"}
    degraded = claim.pr_ci_status(doc["items"]["7"])
    assert degraded["gate"] == "missing" and degraded["armed"] is True
    assert degraded["check_runs_degraded"] is True
    # The PARTIAL gate=failure read whose advisory-legs walk overflowed is blanked too:
    # a degraded record must never admit a ci-fix (gate reads missing, not failure).
    assert doc["items"]["15"]["check_runs"] == []
    assert claim.pr_ci_status(doc["items"]["15"])["gate"] == "missing"

    # (iv) THE round-1 point — the degraded record restores the #42 disarm under overflow:
    # an ARMED worker PR whose churned head advanced past its reviewed-sha marker IS
    # enumerated for disarm even though its check-run listing blew the ceiling. Deleting
    # the degraded-record preservation in _pr_status_record turns this red (mutation-
    # checked): no record -> the disarm net stands down -> fail-OPEN.
    def bot_pull(number, sha, body, draft=False):
        return {"number": number, "state": "open", "draft": draft,
                "user": {"login": "sparq-agent[bot]"}, "labels": [], "body": body,
                "head": {"ref": f"sparq-agent/issue-{number}-1-1", "sha": sha,
                         "repo": {"full_name": repo}}}

    pr_status = {int(number): claim.pr_ci_status(record)
                 for number, record in doc["items"].items()}
    provenance = {7: {"pr_number": 7}, 13: {"pr_number": 13}}
    moved = bot_pull(7, sha_over, f"x <!-- sparq-reviewed-sha:{sha_ok} -->")
    assert [item["pr_number"] for item in claim.enumerate_disarm_items(
        repo, [moved], pr_status, provenance)] == [7]

    # (v) the PRE-detail residual (documented, accepted): PR 13's detail read itself
    # failed, so nothing sound is derivable — no record, and the disarm stands down even
    # for an armed mismatch this tick. A detail-read failure is a GitHub API outage
    # condition, NOT attacker-inducible by inflating check-run volume on a head (the
    # vector the round-1 fix closes).
    moved13 = bot_pull(13, sha_ok, f"x <!-- sparq-reviewed-sha:{sha_red} -->")
    assert claim.enumerate_disarm_items(repo, [moved13], pr_status, provenance) == []

    # Repo-level census overflow degrades to a pr_number-0 skip, not a dead sweep.
    census = [worker_pull(1000 + n, sha_ok) for n in range(WORKER_PR_STATUS_LIMIT + 1)]
    items, skips = _pr_status_snapshot(fake_fetch, claim, repo, census)
    assert items == {} and skips == [{"pr_number": 0, "reason": "worker-pr-census-overflow"}]

    # Repo-level listings stay sweep-fatal AT THE _paginated LAYER: a runaway issues walk still
    # refuses the snapshot (the ceiling itself is unchanged). The per-repo DEGRADATION below is a
    # LAYER ABOVE it in snapshot_targets — the FetchError no longer kills the whole sweep.
    def endless(url):
        return [{"n": 1} for _ in range(100)]
    try:
        _paginated(endless, f"/repos/{repo}/issues?state=open")
    except FetchError:
        pass
    else:
        raise AssertionError("runaway repo listing must stay fail-closed")

    # PER-REPO DEGRADATION (audit modes #2/#3): one target whose listing fails must NOT kill the
    # sweep — it degrades to complete:False + a recorded reason, and the OTHER target still snapshots
    # fully. Mutation-checked: reverting snapshot_targets to re-raise turns this red.
    good, bad = "example/good", "example/bad"

    def two_repo_fetch(url):
        base = url.split("?")[0]
        if base.endswith(f"/repos/{bad}/issues") or base.endswith(f"/repos/{bad}/pulls"):
            raise FetchError("simulated 503 after retries")
        if base.endswith(f"/repos/{good}/issues"):
            return []
        if base.endswith(f"/repos/{good}/pulls"):
            return []
        raise AssertionError(f"unexpected fetch {url}")

    with tempfile.TemporaryDirectory() as out_dir:
        # good is index 0, bad is index 1
        snapshot_targets(two_repo_fetch, claim, [good, bad], out_dir)
        good_doc = json.loads(Path(out_dir, "raw-issues-0.json").read_text(encoding="utf-8"))
        bad_doc = json.loads(Path(out_dir, "raw-issues-1.json").read_text(encoding="utf-8"))
        bad_pulls = json.loads(Path(out_dir, "raw-pulls-1.json").read_text(encoding="utf-8"))
        bad_prstatus = json.loads(Path(out_dir, "raw-prstatus-1.json").read_text(encoding="utf-8"))
    assert good_doc["complete"] is True, "the healthy target must still snapshot fully"
    assert bad_doc["complete"] is False, "the failing target must degrade, not kill the sweep"
    assert "snapshot_error" in bad_doc and bad_doc["items"] == [], "degraded repo is fail-closed"
    # every degraded file for that repo is marked (issues, pulls, prstatus) so the planner + the
    # assemble step both see it and route it into snapshot_skips (the always() alarm).
    assert bad_pulls["complete"] is False and bad_prstatus["complete"] is False
    # END-TO-END allowlist link (review P1): the recorded reason must be the STABLE token whose
    # `repo-degraded:`-prefixed form the CLAIM-side validator accepts — raw exception text here
    # would make the degraded plan FAIL final validation and re-kill the sweep. The fold below is
    # exactly what the dispatch.yml assemble step runs.
    assert bad_doc["snapshot_error"] == "listing-failed", bad_doc["snapshot_error"]
    folded = claim.fold_degraded_repos(
        [{"target_repo": bad, "reason": bad_doc["snapshot_error"]}])
    assert folded == [{"repo": bad, "pr_number": 0, "reason": "repo-degraded:listing-failed"}]
    assert all(skip["reason"] in claim.SNAPSHOT_SKIP_REASONS for skip in folded)

    # FIRST-target degradation (round-3 review: only the LAST-target case was exercised): the
    # degraded repo at index 0 must degrade IN PLACE — the healthy second target still snapshots
    # fully into ITS OWN index-1 artifacts (the index-shift regression made the second target
    # read index 0). The full index-sensitive ASSEMBLY of both orderings runs in
    # dispatch-claim.py's end-to-end self-test against the actual dispatch.yml heredocs.
    with tempfile.TemporaryDirectory() as out_dir:
        # bad is index 0 (FIRST), good is index 1
        snapshot_targets(two_repo_fetch, claim, [bad, good], out_dir)
        first_bad = json.loads(Path(out_dir, "raw-issues-0.json").read_text(encoding="utf-8"))
        second_good = json.loads(Path(out_dir, "raw-issues-1.json").read_text(encoding="utf-8"))
        second_good_pulls = json.loads(
            Path(out_dir, "raw-pulls-1.json").read_text(encoding="utf-8"))
    assert first_bad["complete"] is False and first_bad["snapshot_error"] == "listing-failed", \
        "a FIRST-target failure must degrade in place at index 0"
    assert second_good["complete"] is True and second_good_pulls["complete"] is True, \
        "a FIRST-target degradation must leave the second target fully snapshotted at index 1"

    # BUT a FLEET-WIDE listing failure (EVERY target fails) stays FATAL: an all-empty plan must not
    # masquerade as a healthy empty backlog — the dispatch alarm job needs the PLAN failure to fire.
    def all_fail_fetch(url):
        raise FetchError("simulated global outage")
    with tempfile.TemporaryDirectory() as out_dir:
        try:
            snapshot_targets(all_fail_fetch, claim, [good, bad], out_dir)
        except SystemExit:
            pass
        else:
            raise AssertionError("a fleet-wide listing failure must stay sweep-fatal")

    print("plan-snapshot self-test PASSED")
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("repos_file", nargs="?", help="newline-delimited owner/repo manifest")
    parser.add_argument("out_dir", nargs="?", help="directory for the raw-*.json snapshots")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    if not args.repos_file or not args.out_dir:
        parser.error("repos_file and out_dir are required unless --self-test is used")
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        raise SystemExit("GH_TOKEN is required for the authenticated snapshot")
    repos = [line for line in
             Path(args.repos_file).read_text(encoding="utf-8").splitlines() if line]
    try:
        snapshot_targets(make_fetch(token), _load_claim(), repos, args.out_dir)
    except FetchError as exc:
        raise SystemExit(str(exc)) from exc
    return 0


if __name__ == "__main__":
    sys.exit(main())
