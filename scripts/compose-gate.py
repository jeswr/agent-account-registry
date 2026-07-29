#!/usr/bin/env python3
# GRADE THE COMPOSITION `PR ⊕ CURRENT BASE TIP`, LOCALLY, AND SEPARATE THE TWO WAYS IT BREAKS.
#
# WHAT IS ALREADY BUILT, AND THE HOLE THIS FILLS. `pr-gate` DOES test a composition ref —
# `refs/pull/N/merge` — so the defect is not "nothing grades PR ⊕ master". It is that the graded
# composition GOES STALE and the recorded verdict is never invalidated: GitHub binds the check-run
# to the PR HEAD sha, which does not move when the base moves; `rulesets: []` and branch protection
# `strict: false` mean nothing requires a re-run. gate-staleness.py (#920) already REPORTS that
# staleness from inside the run, and dispatch-claim.`gate_freshness` (#940) already refuses an arm
# on it. Both answer "is this verdict stale?" — a SHA comparison. Neither answers the question that
# decides whether the staleness MATTERS: "does the composition actually still pass?"
#
# That distinction is the whole point. On this repository staleness is the COMMON case (master
# advanced four times on the evening of 2026-07-29 alone), so a guard that refuses every stale
# verdict refuses nearly every arm and gets switched off within a day. A guard that grades the
# composition refuses only the ones that are actually broken.
#
# MEASURED, on the real #756 against the real master tip 45ada45a4 (2026-07-29):
#
#   tree                                    dispatch-claim --self-test   dispatch-telemetry --self-test
#   master 45ada45a4 alone                  PASS                         (file does not exist)
#   #756 head 8241bbd1f alone               PASS                         PASS
#   the composition (merge is CLEAN)        FAIL  NameError: repository   FAIL  ({}, 2, [7, 8])
#
#   * `git merge` reports ZERO conflicts. Both sides are green in isolation. Neither is wrong.
#   * dispatch-claim: master's `_partition_starvation_record_seam_self_test` regex-extracts the
#     `assemble-census` block out of dispatch.yml and `exec`s it with a namespace of
#     {repo, rows_before_assemble, partition_census}; #756 inserted code referencing `repository`
#     INSIDE that extraction window. `NameError: name 'repository' is not defined`.
#   * dispatch-telemetry: master's #1104 added `NON_RESERVING_PARTITIONS = frozenset({"ci","docs"})`
#     (0 occurrences on #756's head, 8 on master) while #756's fixture asserts `area:ci` RESERVES.
#
# THE GENERAL SHAPE, and why this repository specifically: a CORRECT fix landing on master silently
# invalidates an in-flight PR's FIXTURE. No conflict, no signal — `git merge` succeeding is exactly
# what makes it invisible — and the faster the repo merges, the more often it happens. This repo IS
# the self-maintenance machinery, so a composition break degrades the sweeper, the dispatcher or the
# review lane, and those failures present as "the pipeline is just slow".
#
# ⚠️ THE TWO FAILURE MODES REPORT DIFFERENTLY, DELIBERATELY. They are not one red.
#
#   CONFLICT — `git merge` fails. This is the author's ROUTINE problem. It is already visible in
#     three places (`mergeable_state: DIRTY`, the conflict-resolver lane, the PR's own merge box),
#     the author already knows how to fix it, and a base branch that moves textually would red
#     every open PR at once. So: `::warning::`, the conflicted paths named, EXIT 0. NOT blocking.
#   BROKEN — the merge is clean and the composition FAILS the suite. This is the mode nothing in
#     the estate currently sees. So: `::error::`, EXIT 1.
#
# HOW EXIT 1 ENFORCES WITHOUT A REPOSITORY SETTING. This runs as a step of the `gate` job, and
# `gate` is ALREADY the one required status check the arming latch waits on. So a composition break
# reds a REQUIRED context and `enablePullRequestAutoMerge` cannot fire — no ruleset edit, no
# `strict: true`, no merge queue. Those remain the maintainer's calls (#920's options (1) and (2)).
#
# COST, AND WHY IT IS NOT PAID TWICE ON A HEALTHY PR. If the graded base already IS the live tip the
# composition is the tree `pr-gate` just tested, so this exits immediately having run NO tests at
# all — the common case for a PR pushed to a quiet master costs one `rev-parse`. When stale, the
# suite is restricted to the OVERLAP: enrolled entries that EITHER side touched since the merge
# base. That set grows with staleness, which is the right shape — a PR one commit behind pays for
# almost nothing, and #756 at 24 commits behind selects 41 of 55, where the full suite is what you
# would want anyway. `--full` overrides. NO API CALLS AT ALL: every operand comes from the local
# object store that `fetch-depth: 0` already fetched, so this adds nothing to any rate-limit route.
#
# ⚠️ THE RESIDUAL, NAMED, BECAUSE IT IS THE HALF THIS CANNOT CLOSE. This grades the composition at
# RUN TIME. It does not make the verdict self-invalidating afterwards: master can move one second
# after this passes and the recorded green is stale again. What it buys is that the window shrinks
# from "the entire life of the PR" to "since the last gate run", and that the verdict is about the
# tree that existed then rather than about GitHub's frozen merge ref, which on #756 was 24 commits
# and 12 hours out of date. Closing the window fully requires re-running the gate when the BASE
# moves, and the only mechanisms for that are a repository setting (`strict: true` / a merge queue)
# or moving the head (regate-sweep.py's primitive). Neither is this script's call.
#
# A SECOND RESIDUAL, EQUALLY NAMED: the overlap set is a heuristic about WHICH tests can see the
# break, not a proof. A break in an enrolled entry that NEITHER side touched — reachable only
# through a cross-file dependency, which is how the dispatch-telemetry failure above works — is
# selected here only because #756 touched dispatch-telemetry.py itself. `--full` is the answer when
# that matters, and the receipt always prints `entries=` so a small selection is never invisible.
"""compose-gate — does PR ⊕ the CURRENT base tip still pass? (registry #1304)

Usage:
  compose-gate.py --base-ref <branch> [--full] [--suite <manifest>]   # grade; exit 1 iff BROKEN
  compose-gate.py --self-test
"""
import argparse
import copy
import os
import re
import subprocess
import sys
import tempfile

FRESH = "fresh"              # the graded base IS the live tip — nothing to compose
CLEAN = "composes-clean"     # stale, merges cleanly, the overlap suite passes
CONFLICT = "conflict"        # stale, TEXTUAL conflict — the author's routine problem, not a red
BROKEN = "composes-broken"   # stale, merges cleanly, the composition FAILS — the invisible mode
UNPROVABLE = "unprovable"    # an operand could not be established
STATES = (FRESH, CLEAN, CONFLICT, BROKEN, UNPROVABLE)

# Only BROKEN reds the gate. See "THE TWO FAILURE MODES REPORT DIFFERENTLY" in the header.
BLOCKING_STATES = (BROKEN,)

RECEIPT_PREFIX = "compose-gate:"

# The workflow seam this check is wired into, and the exact wiring the self-test pins.
PR_GATE_WORKFLOW = ".github/workflows/pr-gate.yml"
GATE_JOB = "gate"
INVOCATION = "scripts/compose-gate.py"
BASE_REF_ENV = "PR_BASE_REF"
BASE_REF_EXPR = "${{ github.event.pull_request.base.ref }}"
CHECKOUT_ACTION = "actions/checkout@"
SUITE_MANIFEST = "scripts/selftest-suite.txt"

SHA_RE = re.compile(r"[0-9a-f]{40}")
# Deliberately narrower than git's own ref grammar, for gate-staleness.py's reason: this value
# arrives from the event payload and is spliced into a ref name handed to `git`, so a leading `-`
# would be read as an OPTION and a `..` would turn a ref into a range. Anything outside the narrow
# shape is refused as `unprovable` rather than sanitised.
BASE_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,254}")


class GitError(RuntimeError):
    pass


def valid_base_ref(ref):
    """PURE: may this value be spliced into a ref name and handed to git?"""
    ref = ref or ""
    return bool(BASE_REF_RE.fullmatch(ref)) and ".." not in ref


def _git(args, cwd, check=True):
    """Run one git command. Returns (returncode, stdout). Raises GitError when check and non-zero."""
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-1:] or ["no output"]
        raise GitError(tail[0])
    return proc.returncode, proc.stdout.strip()


def suite_entries(manifest_text):
    """PURE: the enrolled entries of a selftest manifest, comments and blanks dropped."""
    entries = []
    for line in (manifest_text or "").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entries.append(line)
    return entries


def overlap_entries(enrolled, pr_paths, base_paths, prefix="scripts/"):
    """PURE: which enrolled entries did EITHER side touch since the merge base?

    Returns a sorted list. The union is deliberate: the measured #756 break needs BOTH sides —
    master changed dispatch-claim.py and the PR changed dispatch-telemetry.py, and grading only
    the PR's own files or only the base's would each have missed one of the two failures."""
    touched = set()
    for path in list(pr_paths or []) + list(base_paths or []):
        if path.startswith(prefix):
            touched.add(path[len(prefix):])
    return sorted(entry for entry in (enrolled or []) if entry in touched)


def classify(graded_base, live_tip, merge_rc=None, conflicted=(), failures=(), entries=()):
    """PURE: the composition verdict.

    `graded_base` is the base tip the recorded verdict was computed against (HEAD^1 of the merge
    ref). `live_tip` is the base branch tip now. Every unresolvable operand is UNPROVABLE — never
    FRESH and never CLEAN, because both of those are readings that would let the arm proceed."""
    result = {"state": UNPROVABLE, "reason": "", "graded_base": graded_base or "",
              "live_tip": live_tip or "", "conflicted": list(conflicted or []),
              "failures": list(failures or []), "entries": list(entries or [])}
    if not SHA_RE.fullmatch(graded_base or ""):
        result["reason"] = ("the base tip this run's merge ref was composed from is unresolvable, "
                           "so which tree the verdict grades cannot be established")
        return result
    if not SHA_RE.fullmatch(live_tip or ""):
        result["reason"] = "the live base branch tip is unresolvable"
        return result
    if graded_base == live_tip:
        result["state"] = FRESH
        result["reason"] = (f"the graded base {graded_base[:12]} IS the current base tip — this "
                            "verdict is about the tree the PR would land on")
        return result
    if merge_rc is None:
        result["reason"] = "the composition was never attempted"
        return result
    if merge_rc != 0:
        result["state"] = CONFLICT
        result["reason"] = (f"the graded base {graded_base[:12]} is superseded by "
                            f"{live_tip[:12]}, and composing with it CONFLICTS textually")
        return result
    if failures:
        result["state"] = BROKEN
        result["reason"] = (f"the verdict graded {graded_base[:12]}; composed with the current tip "
                            f"{live_tip[:12]} the merge is CLEAN but {len(failures)} enrolled "
                            f"self-test(s) FAIL: {', '.join(sorted(failures))}")
        return result
    result["state"] = CLEAN
    result["reason"] = (f"the verdict graded {graded_base[:12]}, which is superseded by "
                        f"{live_tip[:12]}, but the composition merges cleanly and the "
                        f"{len(result['entries'])} overlapping self-test(s) pass")
    return result


def receipt(result, base_ref=""):
    """PURE: the one machine-readable line. `grep '^compose-gate:'` is the whole measurement."""
    return (f"{RECEIPT_PREFIX} state={result.get('state', UNPROVABLE)} "
            f"base_ref={base_ref or 'unknown'} "
            f"graded_base={(result.get('graded_base') or 'none')[:12]} "
            f"live_tip={(result.get('live_tip') or 'none')[:12]} "
            f"entries={len(result.get('entries') or [])} "
            f"failures={len(result.get('failures') or [])} "
            f"conflicts={len(result.get('conflicted') or [])} "
            f"blocking={'true' if result.get('state') in BLOCKING_STATES else 'false'}")


def annotation(result):
    """PURE: the workflow annotation, or "" when the state needs none.

    ⚠️ The two failure modes get DIFFERENT severities on purpose — a textual conflict is the
    author's routine problem and must not read like the invisible one."""
    state = result.get("state")
    reason = result.get("reason", "")
    if state == BROKEN:
        listed = ", ".join(sorted(result.get("failures") or []))
        return (f"::error::composition break — {reason}. Neither side need be wrong on its own: "
                f"this is master and this PR disagreeing. Merge the base branch in and re-run "
                f"{listed} locally.")
    if state == CONFLICT:
        paths = ", ".join(sorted(result.get("conflicted") or [])[:8]) or "unreported paths"
        return (f"::warning::textual conflict with the current base tip ({paths}) — {reason}. "
                "This is the ordinary rebase, NOT a composition break; it is not failing this "
                "gate, and the conflict-resolver lane already sees it.")
    if state == UNPROVABLE:
        return (f"::error::compose-gate could not establish its operands — {reason}. This run's "
                "green is NOT evidence about the tree this PR would land on.")
    return ""


def summary_markdown(result, base_ref=""):
    """PURE: the job-summary block."""
    state = result.get("state", UNPROVABLE)
    verdict = {FRESH: "the verdict grades the current tree",
               CLEAN: "stale, but the composition still passes",
               CONFLICT: "stale, and textually conflicting (author's rebase)",
               BROKEN: "**STALE AND BROKEN — this green is about a tree that no longer exists**",
               UNPROVABLE: "**could not be established**"}.get(state, state)
    lines = [f"### compose-gate — `{state}`", "", verdict, "",
             f"- graded base: `{(result.get('graded_base') or 'none')[:12]}`",
             f"- current `{base_ref or 'base'}` tip: `{(result.get('live_tip') or 'none')[:12]}`",
             f"- overlapping enrolled self-tests run: {len(result.get('entries') or [])}"]
    if result.get("failures"):
        lines.append(f"- FAILING on the composition: `{'`, `'.join(sorted(result['failures']))}`")
    if result.get("conflicted"):
        lines.append(f"- conflicted paths: `{'`, `'.join(sorted(result['conflicted'])[:12])}`")
    return "\n".join(lines) + "\n"


def _append_step_summary(text):
    """Best-effort: a summary write must never decide the gate."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text)
    except OSError:
        pass


def compose(base_ref, cwd, full=False, manifest=SUITE_MANIFEST, git=_git, run_suite=None):
    """Grade `PR ⊕ live tip` from inside a pr-gate checkout of refs/pull/N/merge.

    Reads its operands the ONLY way they are observable — from the local object store, which
    `fetch-depth: 0` has already fetched. No API call, on any route."""
    if not valid_base_ref(base_ref):
        return classify("", "", None)
    try:
        parents = git(["rev-list", "--parents", "-n", "1", "HEAD"], cwd)[1].split()
    except GitError as exc:
        return dict(classify("", "", None), reason=f"the checked-out commit is unreadable ({exc})")
    if len(parents) != 3:
        return dict(classify("", "", None),
                    reason=(f"the checked-out commit has {max(len(parents) - 1, 0)} parent(s), so "
                            "it is not the two-parent refs/pull/N/merge commit this gate grades — "
                            "no base tip can be attributed to it"))
    graded_base, pr_head = parents[1], parents[2]
    try:
        live_tip = git(["rev-parse", "--verify", "--end-of-options",
                        f"refs/remotes/origin/{base_ref}^{{commit}}"], cwd)[1]
    except GitError:
        return dict(classify(graded_base, "", None),
                    reason=(f"refs/remotes/origin/{base_ref} does not resolve — the checkout "
                            "fetched no base branch, so the live tip cannot be read"))
    verdict = classify(graded_base, live_tip)
    if verdict["state"] != UNPROVABLE and graded_base == live_tip:
        return verdict          # FRESH: no composition work at all.

    # ---- compose in a THROWAWAY worktree. The gate's own checkout has later steps depending on
    # it, so the merge must not happen in place. Base first, PR head merged into it, which is
    # GitHub's own merge-ref orientation — so a conflict here presents the same ours/theirs the
    # author sees.
    with tempfile.TemporaryDirectory(prefix="compose-gate-") as tmp:
        tree = os.path.join(tmp, "compose")
        try:
            git(["worktree", "add", "--quiet", "--detach", tree, live_tip], cwd)
        except GitError as exc:
            return dict(classify(graded_base, live_tip, None),
                        reason=f"the composition worktree could not be created ({exc})")
        try:
            merge_rc = git(["-c", "user.name=compose-gate", "-c", "user.email=compose@invalid",
                            "merge", "--no-edit", "--no-ff", pr_head], tree, check=False)[0]
            conflicted = []
            if merge_rc != 0:
                conflicted = sorted({line.split("\t")[-1]
                                     for line in git(["ls-files", "-u"], tree,
                                                     check=False)[1].splitlines() if line})
                return classify(graded_base, live_tip, merge_rc, conflicted=conflicted)
            try:
                with open(os.path.join(tree, manifest), encoding="utf-8") as handle:
                    enrolled = suite_entries(handle.read())
            except OSError as exc:
                return dict(classify(graded_base, live_tip, None),
                            reason=f"the composed self-test manifest is unreadable ({exc})")
            merge_base = git(["merge-base", pr_head, live_tip], cwd, check=False)[1]
            if not SHA_RE.fullmatch(merge_base or ""):
                return dict(classify(graded_base, live_tip, None),
                            reason="the merge base of the head and the live tip is unresolvable")
            pr_paths = git(["diff", "--name-only", merge_base, pr_head], cwd,
                           check=False)[1].splitlines()
            base_paths = git(["diff", "--name-only", merge_base, live_tip], cwd,
                             check=False)[1].splitlines()
            chosen = (sorted(enrolled) if full
                      else overlap_entries(enrolled, pr_paths, base_paths))
            failures = (run_suite or _run_suite)(tree, chosen)
            return classify(graded_base, live_tip, merge_rc, failures=failures, entries=chosen)
        finally:
            git(["worktree", "remove", "--force", tree], cwd, check=False)


def _run_suite(tree, entries):
    """Run each enrolled entry on the COMPOSED tree, through the same sandbox pr-gate.yml uses.

    `worker-live.sh run-selftest` puts a refusing `gh` shim first on PATH; a self-test that reached
    the real binary is exactly the escape that control exists for, and a composition run must not
    be the one place it is skipped. A non-zero exit is a failure; so is the escape row."""
    failures = []
    for entry in entries:
        proc = subprocess.run(["bash", "scripts/worker-live.sh", "run-selftest", entry],
                              cwd=tree, capture_output=True, text=True)
        escaped = "::error::gh-escape " in (proc.stdout + proc.stderr)
        if proc.returncode != 0 or escaped:
            failures.append(entry)
            tail = (proc.stdout or proc.stderr or "").strip().splitlines()[-6:]
            print(f"== composition FAILURE: {entry} ==")
            for line in tail:
                print(f"   {line}")
    return failures


# ---------------------------------------------------------------------------------------------
# THE WORKFLOW SEAM. A composition check that is present but INERT is worse than none, because the
# receipt keeps printing. These assertions are what make the wiring itself testable, and they are
# mutation-tested below in the same shape gate-staleness.py established.
def _refused(check, job):
    try:
        check(job)
    except AssertionError as exc:
        return str(exc)
    return ""


def assert_compose_seam(job):
    """The gate job runs this script, unconditionally, fed from base.ref, able to fail the job."""
    assert isinstance(job, dict), f"the {GATE_JOB!r} job is absent or not a mapping"
    assert not job.get("if"), f"the {GATE_JOB!r} job is conditional, so the check can be skipped"
    steps = job.get("steps")
    assert isinstance(steps, list), f"the {GATE_JOB!r} job has no steps list"
    matches = [s for s in steps if isinstance(s, dict) and INVOCATION in str(s.get("run", ""))]
    assert len(matches) == 1, f"expected exactly ONE {INVOCATION} step, found {len(matches)}"
    step = matches[0]
    assert not step.get("if"), "the composition step is conditional"
    assert not step.get("continue-on-error"), (
        "the composition step carries continue-on-error, so a composition break cannot red the "
        "required gate — which is the ONLY enforcement this check has without a settings change")
    body = str(step.get("run", ""))
    assert "set -euo pipefail" in body, "the composition step body drops `set -euo pipefail`"
    lines = [ln.strip() for ln in body.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    invocations = [ln for ln in lines if INVOCATION in ln]
    assert len(invocations) == 1, f"expected ONE invocation line, found {len(invocations)}"
    line = invocations[0]
    assert line == f'python3 {INVOCATION} --base-ref "${BASE_REF_ENV}"', (
        f"the invocation line is not exactly the documented argv: {line!r}")
    assert set(lines) == {"set -euo pipefail", line}, (
        f"the step body carries an unexpected non-blank line: {sorted(set(lines))}")
    env = step.get("env")
    assert isinstance(env, dict), "the composition step has no env block"
    assert env.get(BASE_REF_ENV) == BASE_REF_EXPR, (
        f"{BASE_REF_ENV} is not fed from {BASE_REF_EXPR} (got {env.get(BASE_REF_ENV)!r}) — a "
        "base SHA would name the stale tree this check exists to detect")


def assert_merge_ref_inputs(job):
    """The two operands: the job must check out refs/pull/N/merge WITH full history."""
    assert isinstance(job, dict), f"the {GATE_JOB!r} job is absent or not a mapping"
    steps = job.get("steps")
    assert isinstance(steps, list), f"the {GATE_JOB!r} job has no steps list"
    checkouts = [s for s in steps if isinstance(s, dict) and CHECKOUT_ACTION in str(s.get("uses"))]
    assert checkouts, "the gate job has no checkout step, so there is no tree to compose"
    with_block = checkouts[0].get("with")
    assert isinstance(with_block, dict), "the checkout step has no with: block"
    assert with_block.get("fetch-depth") == 0, (
        f"fetch-depth is {with_block.get('fetch-depth')!r}, not 0 — without full history "
        "refs/remotes/origin/<base> is not fetched and the live tip cannot be read")
    assert "ref" not in with_block, (
        "the checkout pins a ref: override, so HEAD is not refs/pull/N/merge and HEAD^1 is not a "
        "base tip at all")


def _self_test():
    ok = True
    checks = 0

    def chk(label, got, want):
        nonlocal ok, checks
        checks += 1
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {label}: {got!r}" + ("" if good else f" (want {want!r})"))

    A, B = "a" * 40, "b" * 40

    # ---- classify: the state table, and the fail direction on every unresolvable operand -------
    chk("an equal graded base and live tip is FRESH", classify(A, A)["state"], FRESH)
    chk("a clean merge with no failures is CLEAN",
        classify(A, B, 0, failures=[], entries=["x.py"])["state"], CLEAN)
    chk("a clean merge with a failure is BROKEN",
        classify(A, B, 0, failures=["dispatch-claim.py"])["state"], BROKEN)
    chk("a non-zero merge is CONFLICT", classify(A, B, 1, conflicted=["a"])["state"], CONFLICT)
    chk("a stale pair whose composition was never attempted is UNPROVABLE",
        classify(A, B, None)["state"], UNPROVABLE)
    for label, bad in (("empty", ""), ("short", "abc"), ("None", None),
                       ("uppercase hex", "A" * 40), ("41 hex", "a" * 41)):
        chk(f"a {label} graded base is UNPROVABLE, never FRESH", classify(bad, bad)["state"],
            UNPROVABLE)
        chk(f"a {label} live tip is UNPROVABLE, never CLEAN", classify(A, bad, 0)["state"],
            UNPROVABLE)

    # ⚠️ THE HEADLINE CLAIM: exactly ONE state blocks, and it is the invisible one.
    chk("ONLY the semantic composition break blocks", sorted(BLOCKING_STATES), [BROKEN])
    chk("a textual CONFLICT does NOT block", CONFLICT in BLOCKING_STATES, False)
    chk("...and its receipt says so", "blocking=false" in receipt(classify(A, B, 1)), True)
    chk("...while a BROKEN receipt says blocking=true",
        "blocking=true" in receipt(classify(A, B, 0, failures=["x"])), True)
    chk("the two modes carry DIFFERENT annotation severities",
        (annotation(classify(A, B, 1, conflicted=["p"])).split("::")[1],
         annotation(classify(A, B, 0, failures=["x"])).split("::")[1]), ("warning", "error"))
    chk("the CONFLICT annotation says it is not failing the gate",
        "not failing this gate" in annotation(classify(A, B, 1, conflicted=["p"])), True)
    chk("the BROKEN annotation says neither side need be wrong alone",
        "Neither side need be wrong" in annotation(classify(A, B, 0, failures=["x"])), True)
    chk("an UNPROVABLE operand is an ERROR annotation, never silence",
        annotation(classify("", ""))[:9], "::error::")
    chk("a FRESH state needs no annotation", annotation(classify(A, A)), "")

    # ---- the receipt must never let a small selection pass for a full one --------------------
    chk("the receipt prints the entry count so a vacuous selection is visible",
        "entries=0" in receipt(classify(A, B, 0, failures=[], entries=[])), True)
    chk("...and the CLEAN reason states how many entries it actually ran",
        "0 overlapping self-test(s) pass" in classify(A, B, 0, entries=[])["reason"], True)
    chk("the receipt is greppable on one prefix", receipt(classify(A, A)).startswith(RECEIPT_PREFIX),
        True)

    # ---- suite parsing + the overlap rule ----------------------------------------------------
    chk("the manifest parser drops comments and blanks",
        suite_entries("# c\n\na.py\n b.py \n#x\n"), ["a.py", "b.py"])
    enrolled = ["dispatch-claim.py", "dispatch-telemetry.py", "groom.py", "metrics.py"]
    chk("an entry touched by the PR side is selected",
        overlap_entries(enrolled, ["scripts/dispatch-telemetry.py"], []), ["dispatch-telemetry.py"])
    chk("an entry touched by the BASE side is selected too — the #756 break needs both",
        overlap_entries(enrolled, [], ["scripts/dispatch-claim.py"]), ["dispatch-claim.py"])
    chk("the real #756 pair is selected from the real two-sided diff",
        overlap_entries(enrolled, ["scripts/dispatch-telemetry.py"], ["scripts/dispatch-claim.py"]),
        ["dispatch-claim.py", "dispatch-telemetry.py"])
    chk("a path outside scripts/ selects nothing",
        overlap_entries(enrolled, ["data/README.md"], []), [])
    chk("an unenrolled script is not invented", overlap_entries(enrolled, ["scripts/nope.py"], []), [])
    chk("a non-enrolled prefix collision is not selected",
        overlap_entries(enrolled, ["scripts/sub/dispatch-claim.py"], []), [])

    # ---- base-ref hostility ------------------------------------------------------------------
    for bad, why in (("--upload-pack=sh", "an option-looking ref"), ("a..b", "a range"),
                     ("", "an empty ref"), (None, "a None ref"), ("/x", "a leading slash")):
        chk(f"{why} is refused", valid_base_ref(bad), False)
    chk("a plain branch name is accepted", valid_base_ref("master"), True)
    chk("a slashed branch name is accepted", valid_base_ref("release/1.x"), True)

    # ---- compose(): the operand refusals, driven through the real entry point ----------------
    def fake_git(rows):
        def git(args, cwd, check=True):
            for pattern, rc, out in rows:
                if pattern in " ".join(args):
                    if check and rc != 0:
                        raise GitError("fake")
                    return rc, out
            return 0, ""
        return git

    chk("a non-merge HEAD (one parent) is UNPROVABLE, never graded",
        compose("master", ".", git=fake_git([("rev-list", 0, f"{A} {B}")]))["state"], UNPROVABLE)
    chk("...and says WHY, naming the parent count",
        "1 parent(s)" in compose("master", ".",
                                 git=fake_git([("rev-list", 0, f"{A} {B}")]))["reason"], True)
    chk("an unresolvable origin/<base> is UNPROVABLE, never FRESH",
        compose("master", ".", git=fake_git([("rev-list", 0, f"{'c' * 40} {A} {B}"),
                                             ("rev-parse", 1, "")]))["state"], UNPROVABLE)
    chk("a hostile base ref never reaches git", compose("a..b", ".", git=fake_git([]))["state"],
        UNPROVABLE)
    fresh = compose("master", ".", git=fake_git([("rev-list", 0, f"{'c' * 40} {A} {B}"),
                                                ("rev-parse", 0, A)]))
    chk("a graded base equal to the live tip short-circuits to FRESH", fresh["state"], FRESH)
    chk("...having run NO self-tests at all (the zero-cost path)", fresh["entries"], [])

    # ---- THE WORKFLOW SEAM, mutation-tested. Each mutant leaves a step that LOOKS wired. ----
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    live = None
    try:
        import yaml
    except ImportError as exc:
        chk("PyYAML is available to read the LIVE workflow seam", f"unavailable ({exc})", "")
    else:
        try:
            with open(os.path.join(root, PR_GATE_WORKFLOW), encoding="utf-8") as handle:
                live = ((yaml.safe_load(handle) or {}).get("jobs") or {}).get(GATE_JOB)
        except OSError as exc:
            chk("the live pr-gate workflow is readable", f"unreadable ({exc})", "")

    chk("LIVE pr-gate.yml wires the composition step unconditionally, from base.ref",
        _refused(assert_compose_seam, live), "")
    chk("LIVE pr-gate.yml still checks out the merge ref with full history",
        _refused(assert_merge_ref_inputs, live), "")

    if isinstance(live, dict):
        def mutate(fn):
            job = copy.deepcopy(live)
            fn(job)
            return job

        def _step(job):
            return [s for s in job["steps"]
                    if isinstance(s, dict) and INVOCATION in str(s.get("run", ""))][0]

        def _sub(job, old, new):
            step = _step(job)
            step["run"] = step["run"].replace(old, new)

        def seam_mutants():
            yield ("the step is dropped",
                   lambda j: j["steps"].remove(_step(j)))
            yield ("the step is duplicated",
                   lambda j: j["steps"].append(copy.deepcopy(_step(j))))
            yield ("the step is made conditional", lambda j: _step(j).update({"if": "false"}))
            yield ("the JOB is made conditional", lambda j: j.update({"if": "false"}))
            yield ("the step may fail silently — the ONLY enforcement is disabled",
                   lambda j: _step(j).update({"continue-on-error": True}))
            yield ("`set -euo pipefail` is dropped",
                   lambda j: _sub(j, "set -euo pipefail\n", ""))
            yield ("the failure is swallowed by `|| true`",
                   lambda j: _step(j).update({"run": _step(j)["run"].rstrip("\n") + " || true\n"}))
            yield ("the invocation is short-circuited by `true ||`",
                   lambda j: _sub(j, "python3 ", "true || python3 "))
            yield ("the invocation is commented out", lambda j: _sub(j, "python3 ", "# python3 "))
            yield ("the body exits before reaching the invocation",
                   lambda j: _sub(j, "set -euo pipefail\n", "set -euo pipefail\nexit 0\n"))
            yield ("the base ref flag is dropped",
                   lambda j: _sub(j, f' --base-ref "${BASE_REF_ENV}"', ""))
            yield ("the flag is renamed", lambda j: _sub(j, "--base-ref", "--base-sha"))
            yield ("the script is run by something other than python3",
                   lambda j: _sub(j, "python3 scripts/", "bash scripts/"))
            yield ("an extra argument is appended",
                   lambda j: _step(j).update({"run": _step(j)["run"].rstrip("\n") + " --full\n"}))
            yield ("the env block is dropped", lambda j: _step(j).pop("env"))
            yield ("the ref is fed from base.sha — the stale tree this check exists to detect",
                   lambda j: _step(j)["env"].update(
                       {BASE_REF_ENV: "${{ github.event.pull_request.base.sha }}"}))
            yield ("the event field is interpolated straight into run:",
                   lambda j: _sub(j, f'"${BASE_REF_ENV}"',
                                  '"${{ github.event.pull_request.base.ref }}"'))

        for name, mutation in seam_mutants():
            chk(f"the seam check REFUSES when {name}",
                bool(_refused(assert_compose_seam, mutate(mutation))), True)

        def checkout_mutants():
            yield ("fetch-depth is dropped",
                   lambda j: [s for s in j["steps"]
                              if CHECKOUT_ACTION in str(s.get("uses"))][0]["with"].pop("fetch-depth"))
            yield ("fetch-depth is shallow",
                   lambda j: [s for s in j["steps"]
                              if CHECKOUT_ACTION in str(s.get("uses"))][0]["with"].update(
                                  {"fetch-depth": 1}))
            yield ("a ref: override is pinned",
                   lambda j: [s for s in j["steps"]
                              if CHECKOUT_ACTION in str(s.get("uses"))][0]["with"].update(
                                  {"ref": "${{ github.head_ref }}"}))

        for name, mutation in checkout_mutants():
            chk(f"the checkout check REFUSES when {name}",
                bool(_refused(assert_merge_ref_inputs, mutate(mutation))), True)

    for shape, job in (("an absent job", None), ("a step-less job", {}),
                       ("a malformed steps: block", {"steps": "not-a-list"})):
        chk(f"the seam check REFUSES {shape}", bool(_refused(assert_compose_seam, job)), True)
        chk(f"the checkout check REFUSES {shape}",
            bool(_refused(assert_merge_ref_inputs, job)), True)

    # ---- the manifest this script is itself enrolled in --------------------------------------
    try:
        with open(os.path.join(root, SUITE_MANIFEST), encoding="utf-8") as handle:
            chk("compose-gate.py is enrolled in the self-test manifest",
                "compose-gate.py" in suite_entries(handle.read()), True)
    except OSError as exc:
        chk("the self-test manifest is readable", f"unreadable ({exc})", "")

    print("compose-gate self-test", "PASSED" if ok else "FAILED", f"({checks} checks)")
    return 0 if ok else 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Does PR ⊕ the current base tip still pass? (registry #1304)")
    parser.add_argument("--base-ref", default="",
                        help="the base BRANCH name (github.event.pull_request.base.ref)")
    parser.add_argument("--full", action="store_true",
                        help="run every enrolled self-test, not just the overlap")
    parser.add_argument("--suite", default=SUITE_MANIFEST)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if not args.base_ref:
        print("error: --base-ref is required", file=sys.stderr)
        return 2
    result = compose(args.base_ref, os.getcwd(), full=args.full, manifest=args.suite)
    print(receipt(result, args.base_ref))
    note = annotation(result)
    if note:
        print(note)
    _append_step_summary(summary_markdown(result, args.base_ref))
    # ⚠️ ONLY a semantic composition break reds the gate. A textual conflict is the author's
    # routine problem and is reported as a warning; see the header. An UNPROVABLE operand does not
    # red either — the structural guard against this check going vacuous is the mutation-tested
    # YAML seam above, which reds the SUITE step instead, exactly as gate-staleness.py's is.
    return 1 if result.get("state") in BLOCKING_STATES else 0


if __name__ == "__main__":
    sys.exit(main())
