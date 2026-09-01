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
#   PREEXISTING — it fails on the tree this gate ALREADY graded, so the base move did not cause it.
#     Reported, never blamed on the composition, and non-blocking so the two steps do not
#     double-report one tree. See `annotation` for why that reading INVERTS in production.
#   UNPROVABLE — an operand or a verdict could not be established. ⚠️ THIS BLOCKS, and that is a
#     RETRACTION: it first exited 0 behind an `::error::` no gate consults, which let the arm proceed
#     exactly as a green would. Every runtime path to it is a violated PINNED invariant.
#
# ⚠️ AND A VERDICT IS NOT AN EXIT CODE. worker-live.sh exits a bare `1` for manifest-validation
# failure, a usage error, a not-enrolled entry, ENV-BLOCKED, an mktemp failure and a sandbox that is
# not intercepting `gh` — none of which is a test result. Read as one on the BASELINE side, each
# silently converts a real `composes-broken` into `pre-existing-red blocking=false`. Faults are
# therefore detected by MARKER, the way a gh-escape already was, and a marker-bearing run is NOT
# GRADEABLE: not a pass, not a failure. `runner_available` proving the arm's TEXT exists was one
# layer too shallow — the same defect class, twice, which is why both are pinned by self-test rows.
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
# would want anyway. `--full` overrides. A FAILURE additionally costs a baseline re-run of just the
# failing entries, so the stale worst case approaches 2x the suite step rather than 1x. The real
# bound is the job's own `timeout-minutes: 15`, and ⚠️ its overrun mode is a RED GATE — i.e. a false
# block — which is the cost that actually matters here. NO API CALLS AT ALL: every operand comes from
# the local object store that `fetch-depth: 0` already fetched, so nothing lands on any rate-limit
# route.
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
                                                                      # or UNPROVABLE
  compose-gate.py --self-test
"""
import argparse
import contextlib
import copy
import io
import os
import re
import subprocess
import sys
import tempfile

FRESH = "fresh"              # the graded base IS the live tip — nothing to compose
CLEAN = "composes-clean"     # stale, merges cleanly, the overlap suite passes
CONFLICT = "conflict"        # stale, TEXTUAL conflict — the author's routine problem, not a red
BROKEN = "composes-broken"   # stale, merges cleanly, the composition FAILS — the invisible mode
PREEXISTING = "pre-existing-red"  # it fails on the GRADED tree too, so the base move did not do it
UNPROVABLE = "unprovable"    # an operand could not be established
STATES = (FRESH, CLEAN, CONFLICT, BROKEN, PREEXISTING, UNPROVABLE)

# ⚠️ WHAT REDS THE GATE. BROKEN, plainly. And UNPROVABLE — which is a RETRACTION of this file's
# first cut, where it exited 0 behind an `::error::` annotation no gate consults. `classify`'s own
# docstring already said an unresolvable operand must never read FRESH or CLEAN "because both of
# those are readings that would let the arm proceed"; exiting 0 lets the arm proceed IDENTICALLY, so
# the annotation was the whole consequence and the reading was decorative. Every runtime path to
# UNPROVABLE is also a VIOLATED PINNED INVARIANT — the seam assertions pin `fetch-depth: 0`, no
# `ref:` override and a two-parent HEAD, so a non-merge HEAD, an unresolvable `origin/<base>`, a
# deleted base ref or a harness that will not run are all "the thing that was supposed to be
# impossible happened", which is precisely the case that must not be waved through.
# CONFLICT and PREEXISTING deliberately do NOT block; see the header.
BLOCKING_STATES = (BROKEN, UNPROVABLE)

RECEIPT_PREFIX = "compose-gate:"


def exit_code(result):
    """PURE: the process exit status for a verdict — the ONE place the fail direction is decided.

    ⚠️ EXTRACTED SO IT CAN BE TESTED AGAINST SOMETHING OTHER THAN ITSELF. The row that claimed to pin
    "the receipt's blocking= field cannot drift from the exit code" derived its expected value from
    `1 if state in BLOCKING_STATES else 0` and compared it against that same expression, and never
    invoked `main()`. Mutating `main()` to `state == BROKEN` left the self-test passing 123/123 while
    the receipt printed `blocking=true` and the process exited 0 — the exact drift the row was named
    after, and a one-token re-opening of the fail-open retracted in 4a3a3bfeb. A test that derives its
    expectation from the expression under test measures nothing. `main()` now returns THIS, the
    receipt reads the same predicate, and the self-test pins both against a LITERAL table.

    ⚠️ AN UNDECLARED STATE BLOCKS, and that clause is what makes `STATES` load-bearing rather than
    decorative. Before it, `STATES` had exactly two references — its definition and one self-test row
    comparing it to the fail-direction table — and NO functional consumer, so a new `classify` branch
    returning e.g. "suite-too-large" was TRIPLE-silent: `exit_code` 0, `blocking=false`, and
    `annotation()` "" — a fail-open reachable by adding a branch and forgetting a constant, with the
    row named "so a new state cannot skip it" passing. A reading nothing declared cannot be known
    safe, so it is treated exactly as `unprovable`."""
    state = (result or {}).get("state")
    if state not in STATES:
        return 1
    return 1 if state in BLOCKING_STATES else 0

# The workflow seam this check is wired into, and the exact wiring the self-test pins.
PR_GATE_WORKFLOW = ".github/workflows/pr-gate.yml"
GATE_JOB = "gate"
INVOCATION = "scripts/compose-gate.py"
BASE_REF_ENV = "PR_BASE_REF"
BASE_REF_EXPR = "${{ github.event.pull_request.base.ref }}"
CHECKOUT_ACTION = "actions/checkout@"
SUITE_MANIFEST = "scripts/selftest-suite.txt"
# The sandboxed runner pr-gate.yml's own suite loop uses, and the case arm that proves a given tree
# implements it. Never invoke a self-test directly: the sandbox puts a REFUSING `gh` shim first on
# PATH, and a composition run must not be the one place that control is skipped.
RUNNER_SCRIPT = "scripts/worker-live.sh"
RUNNER_ARM = "run-selftest)"
# ⚠️ THE HARNESS'S OWN FAULT MARKERS, and the second half of a lesson learned twice. Proving the
# `run-selftest` ARM EXISTS (`runner_available`) is not proving the harness RAN: worker-live.sh's
# `die()` prints `worker-live: <msg>` and exits a bare **1** for manifest-validation failure, a
# usage error, a not-enrolled entry, and ENV-BLOCKED (whose own message says it is "NOT a test
# failure and NOT a pass"); `run_enrolled_selftest` prints `::error::self-test sandbox: mktemp
# failed` and `::error::self-test sandbox is NOT intercepting `gh`` and returns 1 likewise. Every
# one of those is INDISTINGUISHABLE from a failing self-test by exit code alone — which on the
# BASELINE side silently converts a real `composes-broken` into `pre-existing-red blocking=false`.
# So a fault is detected the way `_run_suite` already detects a gh-escape: by the marker in the
# output, never by the status. A marker-bearing run is NOT GRADEABLE, which is a third outcome —
# not a pass, not a failure.
# ⚠️ AN OPEN-WORLD ALLOWLIST, SO IT CANNOT BE COMPLETE — and that is stated rather than papered over.
# Uncovered shapes exist (a bare `Traceback`, `command not found`, an OOM `Killed`, and note that
# `worker-live.sh: line N: syntax error` is NOT the `worker-live: ` marker). None is a reachable
# FAIL-OPEN: on the composed side every one reads as a failure, which is fail-closed and visible; on
# the baseline side excusing one would require the graded tree to fault on an entry that PASSED in the
# same job minutes earlier, which the step ordering prevents. So all KNOWN instances are pinned and
# the CLASS is not claimed closed.
#   ⚠️ `Traceback` is deliberately NOT a marker, and this is measured: the known-positive composition
#   failure (`dispatch-claim.py`, `NameError: name 'repository' is not defined`) PRINTS a Traceback,
#   because a failing Python self-test normally does. Adding it would reclassify the marquee case from
#   a precise `composes-broken` to `unprovable` — trading exact attribution for a vaguer red. The
#   structurally complete fix is INVERSE POLARITY (require a recognised positive verdict line), which
#   needs 7 of 56 entries normalised onto a `PASSED/FAILED`-shaped terminal line first; a follow-up,
#   not a one-token addition here.
#   ⚠️ AND THAT NORMALISATION HAS THREE TERMINAL SHAPES TO COVER, NOT TWO — enumerate them, do not
#   infer them from `PASSED`'s absence. Since #1740 `retriage.py --self-test` prints a third terminal
#   line, `retriage self-test ENV-BLOCKED`, beside `PASSED`/`FAILED` (a dependency its EXECUTED rows
#   shell out to is missing), and the sibling follow-up would give the other dependency-bearing
#   entries the same class, so expect the shape to spread. It is emphatically NOT a positive verdict:
#   it exits non-zero, and a genuine row failure OUTRANKS it and still prints `FAILED`. So the
#   inverse-polarity check must list it as a RECOGNISED NON-POSITIVE verdict — a refusal, graded as a
#   failure, exactly as today — and never let it fall through the unrecognised-shape branch into NOT
#   GRADEABLE. Neither reading is fail-open (both block), but ungradeable loses the attribution: it
#   asserts the HARNESS faulted when the harness worked and the entry returned a considered refusal,
#   and its receipt tells the operator re-running clears it, which a missing dependency does not.
#   ⚠️ An entry's own ENV-BLOCKED is a DIFFERENT OBJECT from the harness's (`worker-live:
#   registry-selftest gate: ENV-BLOCKED`, a fault by the marker below, because there the SANDBOX
#   could not run the entry at all). The two are told apart ONLY by the `worker-live: ` prefix, so a
#   bare `"ENV-BLOCKED"` added to the markers would swallow the entry's verdict line with it; both
#   directions are pinned by self-test rows. Nothing to change on the composed side today —
#   compose-gate runs on ubuntu-latest, where jq and PyYAML are present, so the entry-level class is
#   not reachable there.
#   The broad `"worker-live: "` substring is a latent FAIL-CLOSED trip: a future self-test that echoes
#   such a line ON SUCCESS would be read as ungradeable. Measured zero false positives across all 56
#   known-PASS logs today, and the failure direction is a visible red, never a silent green.
HARNESS_FAULT_MARKERS = ("worker-live: ", "::error::self-test sandbox")
# An escape is NOT a harness fault: the sandbox worked and caught a self-test reaching the real gh.
# That is a genuine failure of the entry and stays one.
ESCAPE_MARKER = "::error::gh-escape "

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


def select_entries(enrolled, pr_paths, base_paths, full=False):
    """PURE: which enrolled entries will this run grade?

    Split out so `--full` is a TESTED path rather than a documented one: an escape hatch nothing
    exercises is an escape hatch nobody can rely on."""
    return sorted(enrolled or []) if full else overlap_entries(enrolled, pr_paths, base_paths)


def classify(graded_base, live_tip, merge_rc=None, conflicted=(), failures=(), entries=(),
             preexisting=(), baseline_established=True):
    """PURE: the composition verdict.

    `graded_base` is the base tip the recorded verdict was computed against (HEAD^1 of the merge
    ref). `live_tip` is the base branch tip now. Every unresolvable operand is UNPROVABLE — never
    FRESH and never CLEAN, because both of those are readings that would let the arm proceed.

    ⚠️ `failures` must ALREADY be the DIFFERENTIAL — entries that pass on the graded tree and fail
    on the composition. `preexisting` are the ones that were red before the base ever moved; they
    are reported, never blamed on the composition. Measured on #1277, which composes cleanly and
    fails `ci-latency-alert.py` — and fails it identically on its own graded merge ref, so the base
    move did not do it. Calling that a composition break is a false attribution, and false
    attributions are how a check earns a reputation for crying wolf."""
    result = {"state": UNPROVABLE, "reason": "", "graded_base": graded_base or "",
              "live_tip": live_tip or "", "conflicted": list(conflicted or []),
              "failures": list(failures or []), "entries": list(entries or []),
              "preexisting": list(preexisting or []),
              "baseline_established": bool(baseline_established)}
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
                            f"self-test(s) that PASS on the graded tree FAIL on the composition: "
                            f"{', '.join(sorted(failures))}")
        return result
    if result["preexisting"]:
        result["state"] = PREEXISTING
        result["reason"] = (f"{len(result['preexisting'])} enrolled self-test(s) fail on the "
                            f"composition, but fail on the GRADED tree {graded_base[:12]} too, so "
                            f"the base move to {live_tip[:12]} did not cause them: "
                            f"{', '.join(sorted(result['preexisting']))}")
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
            f"preexisting={len(result.get('preexisting') or [])} "
            f"baseline={'ok' if result.get('baseline_established', True) else 'unestablished'} "
            f"conflicts={len(result.get('conflicted') or [])} "
            f"blocking={'true' if exit_code(result) else 'false'}")


def annotation(result):
    """PURE: the workflow annotation, or "" when the state needs none.

    ⚠️ The two failure modes get DIFFERENT severities on purpose — a textual conflict is the
    author's routine problem and must not read like the invisible one."""
    state = result.get("state")
    reason = result.get("reason", "")
    if state == BROKEN:
        listed = ", ".join(sorted(result.get("failures") or []))
        # ⚠️ If no baseline could be established, SAY SO in the same breath as the accusation. On a
        # tree predating the sandboxed runner arm these failures cannot be shown to postdate the
        # base move, and telling an author "the composition broke this" without that caveat is the
        # same false attribution in the other direction.
        # Deliberately does NOT name a cause: there are four (no runner arm, an unreadable manifest,
        # an entry master added, a harness fault), the per-entry reason is already printed above, and
        # a caveat that asserts the wrong one of the four is its own small false statement.
        caveat = ("" if result.get("baseline_established", True) else
                  " ⚠️ NO BASELINE could be established for at least one of these (see the baseline "
                  "rows above for which and why), so they cannot be shown to POSTDATE the base move; "
                  "they are attributed to the composition because an unverifiable excuse is not an "
                  "excuse. Merging the base branch in produces a gradeable baseline.")
        return (f"::error::composition break — {reason}. Neither side need be wrong on its own: "
                f"this is master and this PR disagreeing. Merge the base branch in and re-run "
                f"{listed} locally.{caveat}")
    if state == CONFLICT:
        paths = ", ".join(sorted(result.get("conflicted") or [])[:8]) or "unreported paths"
        return (f"::warning::textual conflict with the current base tip ({paths}) — {reason}. "
                "This is the ordinary rebase, NOT a composition break; it is not failing this "
                "gate, and the conflict-resolver lane already sees it.")
    if state == PREEXISTING:
        listed = ", ".join(sorted(result.get("preexisting") or []))
        # ⚠️ THE PRODUCTION SEMANTICS, stated because they INVERT the local reading. This step runs
        # only AFTER the suite step passed on the graded tree, so in production a `pre-existing-red`
        # is ALWAYS a flake report. MEASURED: `print-selftest-suite` derives from the CURRENT
        # manifest, not the base copy — handed a base copy with an entry removed it still printed all
        # 56 including that entry (the base copy governs removal APPROVAL only) — so the "entry absent
        # from the base-derived manifest" escape hatch this comment once claimed does not exist. It
        # stays non-blocking because the flake argument alone carries it: the suite step owns that
        # tree, and blocking would red a PR for something its author cannot fix.
        return (f"::warning::{listed} fail(s) on the composition, but fail(s) on the tree this gate "
                "already graded too — so this is NOT a composition break and the base move did not "
                "cause it. The self-test suite step above owns it. NOTE: that step already passed on "
                "this very tree in this very job, so this IS a flake report — the same tree gave two "
                "different answers minutes apart.")
    if state == UNPROVABLE:
        return (f"::error::compose-gate could not establish its operands — {reason}. This run's "
                "green is NOT evidence about the tree this PR would land on.")
    if state not in STATES:
        # The third of the three silences described in `exit_code`. FRESH and CLEAN reach here too,
        # and legitimately need no annotation — an UNDECLARED state is the one that must speak.
        return (f"::error::compose-gate produced the UNDECLARED state {str(state)[:64]!r}. It is "
                "treated as unprovable and BLOCKS, because a reading nothing declared cannot be "
                "known safe. Add it to STATES and to the fail-direction table in --self-test.")
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
            chosen = select_entries(enrolled, pr_paths, base_paths, full)
            # ⚠️ An absent runner in the COMPOSED tree must not read as "the suite passed" — that is
            # the same usage-error-as-test-result confusion, in the direction that greens the gate.
            if chosen and not runner_available(tree):
                return dict(classify(graded_base, live_tip, None),
                            reason=(f"the composed tree's {RUNNER_SCRIPT} has no sandboxed "
                                    f"`{RUNNER_ARM[:-1]}` arm, so the composition cannot be graded "
                                    "without bypassing the gh sandbox"))
            runner = run_suite or _run_suite
            failures, ungradeable = runner(tree, chosen, "composition")
            # An entry the harness could not grade on the COMPOSED side leaves the composition
            # unverified. Fail closed: `unprovable`, which blocks — never "the suite passed".
            if ungradeable:
                return dict(classify(graded_base, live_tip, None),
                            reason=("the harness faulted rather than returning a verdict for "
                                    f"{len(ungradeable)} composed entr(y/ies) "
                                    f"({', '.join(sorted(ungradeable))}), so the composition is "
                                    "unverified — this is transient, and re-running the job clears "
                                    "it (unlike a staleness refusal, which it cannot)"))
            # ---- THE DIFFERENTIAL. A failure is only a COMPOSITION break if it PASSES on the tree
            # `pr-gate` already graded. Paid only on failure, and only for the entries that failed.
            preexisting, baseline_ok = (_baseline_failures(cwd, failures, runner) if failures
                                        else ([], True))
            return classify(graded_base, live_tip, merge_rc,
                            failures=[e for e in failures if e not in preexisting],
                            preexisting=preexisting, entries=chosen,
                            baseline_established=baseline_ok)
        finally:
            git(["worktree", "remove", "--force", tree], cwd, check=False)


def runner_available(tree):
    """Does THIS tree's worker-live.sh implement the sandboxed `run-selftest` arm?

    ⚠️ MEASURED, and it is why this function exists. #756's head tree (2026-07-28) has a
    worker-live.sh with NO `run-selftest` arm — that arm landed on master later. Invoking it there
    exits 1 with `worker-live: usage: ...`, i.e. a USAGE error indistinguishable, to a bare exit
    code, from a failing self-test. Consuming that as "the baseline fails too" excused every
    composition failure as pre-existing and the check FAILED OPEN — on PRs based on an older
    master, which is precisely the stale population it exists for. Structural check, no execution:
    a usage error must never be readable as a test result."""
    try:
        with open(os.path.join(tree, RUNNER_SCRIPT), encoding="utf-8") as handle:
            return RUNNER_ARM in handle.read()
    except OSError:
        return False


def _baseline_failures(cwd, entries, runner, manifest=SUITE_MANIFEST):
    """Which of `entries` were ALREADY failing on the tree pr-gate graded?

    ⚠️ FAIL CLOSED, and this is the whole subtlety. An entry with NO establishable baseline must NOT
    be excused as pre-existing. Three ways a baseline fails to exist, all measured or reachable:
    the entry is one MASTER ADDED (absent or unenrolled in the graded tree); or the graded tree's
    harness cannot run it at all (`runner_available` above). Excusing any of them would mask exactly
    the break this check exists for. Only an entry that demonstrably EXISTS, is ENROLLED, and FAILS
    on the graded tree under a WORKING runner is pre-existing."""
    if not runner_available(cwd):
        print("== baseline UNAVAILABLE: the graded tree has no sandboxed run-selftest arm, so no "
              "failure can be shown pre-existing — attributing all of them to the composition ==")
        return [], False
    try:  # noqa: SIM105 — the manifest read below is the second unestablishable-baseline case
        with open(os.path.join(cwd, manifest), encoding="utf-8") as handle:
            enrolled = set(suite_entries(handle.read()))
    except OSError:
        return [], False   # no graded manifest -> nothing can be PROVEN pre-existing -> fail closed
    testable = [e for e in entries
                if e in enrolled and os.path.exists(os.path.join(cwd, "scripts", e))]
    if not testable:
        return [], len(testable) == len(entries)
    print(f"== baseline: re-running {len(testable)} failing entr(y/ies) on the GRADED tree ==")
    baseline_failures, ungradeable = runner(cwd, testable, "baseline")
    # ⚠️ THE THIRD UNESTABLISHABLE-BASELINE CASE, and the one that reads as a verdict. An entry whose
    # baseline run hit a HARNESS fault has no baseline — it is not "failing here too". Excusing it
    # is exactly the fail-open this whole function exists to prevent, one layer deeper.
    established = not ungradeable and len(testable) == len(entries)
    return [entry for entry in baseline_failures if entry not in ungradeable], established


def harness_fault(output):
    """PURE: did the HARNESS fail, rather than the self-test returning a verdict?

    See HARNESS_FAULT_MARKERS. An infrastructure fault and a failing test are the same bare `1`, so
    the exit status cannot answer this and only the output can."""
    return any(marker in (output or "") for marker in HARNESS_FAULT_MARKERS)


def _run_suite(tree, entries, label="composition"):
    """Run each enrolled entry through the same sandbox pr-gate.yml uses.

    Returns `(failures, ungradeable)`. `worker-live.sh run-selftest` puts a refusing `gh` shim first
    on PATH; a self-test that reached the real binary is exactly the escape that control exists for,
    and a composition run must not be the one place it is skipped. THREE outcomes, not two: a pass,
    a failure (non-zero, or an escape row), and NOT GRADEABLE (the harness itself faulted)."""
    failures, ungradeable = [], []
    for entry in entries:
        proc = subprocess.run(["bash", "scripts/worker-live.sh", "run-selftest", entry],
                              cwd=tree, capture_output=True, text=True)
        output = proc.stdout + proc.stderr
        tail = (proc.stdout or proc.stderr or "").strip().splitlines()[-6:]
        if harness_fault(output):
            ungradeable.append(entry)
            print(f"== {label} NOT GRADEABLE (harness fault, not a verdict): {entry} ==")
            for line in tail:
                print(f"   {line}")
            continue
        if proc.returncode != 0 or ESCAPE_MARKER in output:
            failures.append(entry)
            print(f"== {label} FAILURE: {entry} ==")
            for line in tail:
                print(f"   {line}")
    return failures, ungradeable


# ---------------------------------------------------------------------------------------------
# THE WORKFLOW SEAM. A composition check that is present but INERT is worse than none, because the
# receipt keeps printing. These assertions are what make the wiring itself testable, and they are
# mutation-tested below in the same shape gate-staleness.py established.
def _quiet(fn, *args, **kwargs):
    """Run a PRODUCTION function inside --self-test without letting its operational prints escape.

    ⚠️ MEASURED HARM, not hypothetical. `receipt()` documents itself as "the one machine-readable
    line; `grep '^compose-gate:'` is the whole measurement" — and the self-test's `main()` rows print
    six SYNTHETIC receipts (`graded_base=aaaaaaaaaaaa`, one of them `state=composes-broken
    blocking=true`) into the gate log, where the ONE real receipt is not even first. A reviewer pulling
    receipts from run 90740570695 got fixtures. The self-test already pops `GITHUB_STEP_SUMMARY` to
    avoid exactly this class of side effect; stdout needed the same treatment. This matters more than
    tidiness: the receipt is the surface an operator reads to decide whether the gate is working, so a
    fixture that outranks the real line makes the diagnostic unreliable."""
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args, **kwargs)


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
    # ⚠️ JOB scope as well as step scope. A step-level `continue-on-error` is the obvious mutant and
    # was covered; `continue-on-error` on the JOB makes the whole required check advisory while every
    # other assertion here still passes — a structure-preserving survivor. dispatch-plan.py refuses
    # it at BOTH scopes (:820, :887) and documents it as one of three measured survivors; this was
    # one clause short of the pattern this repository already established.
    assert not job.get("continue-on-error"), (
        f"the {GATE_JOB!r} JOB carries continue-on-error, so the required check reports success "
        "however this step exits — the enforcement is gone while the receipt keeps printing")
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
    # ⚠️ EVERY checkout, not `checkouts[0]`. Inspecting only the first is a structure-preserving
    # survivor: a LATER checkout into the workspace pinning `head.sha` leaves this assertion passing
    # while HEAD becomes single-parent, so the check reads `unprovable` forever with its receipt
    # still printing. The last write to the workspace is what HEAD is, so all of them are pinned.
    for index, checkout in enumerate(checkouts):
        with_block = checkout.get("with")
        assert isinstance(with_block, dict), f"checkout step #{index} has no with: block"
        assert with_block.get("fetch-depth") == 0, (
            f"checkout step #{index} has fetch-depth {with_block.get('fetch-depth')!r}, not 0 — "
            "without full history refs/remotes/origin/<base> is not fetched and the live tip "
            "cannot be read")
        # A checkout into a SEPARATE `path:` does not redefine the workspace HEAD, so it is free to
        # pin a ref (regate-sweep.yml relies on this); one into the workspace is not. ⚠️ `path: '.'`
        # and `path: './'` ARE the workspace — they clobber HEAD while looking scoped — so the
        # allowance is granted only to a path that normalises to something other than the root.
        checkout_path = str(with_block.get("path") or "").strip()
        scoped = bool(checkout_path) and os.path.normpath(checkout_path) not in (".", "/")
        assert "ref" not in with_block or scoped, (
            f"checkout step #{index} pins a ref: override into the workspace "
            f"(path={with_block.get('path')!r} resolves to the root), so HEAD is not "
            "refs/pull/N/merge and HEAD^1 is not a base tip at all")


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

    # ---- THE DIFFERENTIAL: a failure that was ALREADY red is not blamed on the base move -------
    chk("a failure that also fails on the GRADED tree is PREEXISTING, not BROKEN",
        classify(A, B, 0, failures=[], preexisting=["ci-latency-alert.py"])["state"], PREEXISTING)
    chk("...and does NOT block", PREEXISTING in BLOCKING_STATES, False)
    chk("...and its annotation says the base move did not cause it",
        "did not" in annotation(classify(A, B, 0, preexisting=["x.py"])), True)
    chk("a MIXED result still BLOCKS on the composition-attributable one",
        classify(A, B, 0, failures=["new.py"], preexisting=["old.py"])["state"], BROKEN)
    chk("the BROKEN reason names the differential, not merely 'fails'",
        "PASS on the graded tree" in classify(A, B, 0, failures=["n.py"])["reason"], True)
    chk("an unestablished baseline is stated in the receipt, never silent",
        "baseline=unestablished" in receipt(classify(A, B, 0, failures=["x"],
                                                    baseline_established=False)), True)
    chk("...and the accusation itself carries the caveat",
        "NO BASELINE" in annotation(classify(A, B, 0, failures=["x"],
                                             baseline_established=False)), True)
    chk("...while an established baseline adds no caveat",
        "NO BASELINE" in annotation(classify(A, B, 0, failures=["x"])), False)
    chk("the receipt reports both populations separately",
        ("failures=1" in receipt(classify(A, B, 0, failures=["a"], preexisting=["b", "c"])),
         "preexisting=2" in receipt(classify(A, B, 0, failures=["a"], preexisting=["b", "c"]))),
        (True, True))
    chk("a stale pair whose composition was never attempted is UNPROVABLE",
        classify(A, B, None)["state"], UNPROVABLE)
    for label, bad in (("empty", ""), ("short", "abc"), ("None", None),
                       ("uppercase hex", "A" * 40), ("41 hex", "a" * 41)):
        chk(f"a {label} graded base is UNPROVABLE, never FRESH", classify(bad, bad)["state"],
            UNPROVABLE)
        chk(f"a {label} live tip is UNPROVABLE, never CLEAN", classify(A, bad, 0)["state"],
            UNPROVABLE)

    # ⚠️ THE HEADLINE CLAIM: exactly ONE state blocks, and it is the invisible one.
    chk("the blocking set is EXACTLY the break and the unverifiable",
        sorted(BLOCKING_STATES), sorted([BROKEN, UNPROVABLE]))
    chk("a textual CONFLICT does NOT block", CONFLICT in BLOCKING_STATES, False)
    chk("a PRE-EXISTING red does NOT block", PREEXISTING in BLOCKING_STATES, False)
    chk("FRESH and CLEAN never block",
        [FRESH in BLOCKING_STATES, CLEAN in BLOCKING_STATES], [False, False])
    # ⚠️ THE RETRACTION, pinned: unprovable used to exit 0 behind an ::error:: nothing consults.
    chk("an UNPROVABLE state BLOCKS — an annotation is not a consequence",
        UNPROVABLE in BLOCKING_STATES, True)
    chk("...and its receipt says blocking=true", "blocking=true" in receipt(classify("", "")), True)
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

    # ⚠️ THE FAIL DIRECTION, PINNED AGAINST A LITERAL — and against `main()` itself.
    # The previous version of this block derived its expected value from `1 if _state in
    # BLOCKING_STATES else 0` and compared it to that same expression, and never called `main()`.
    # Mutating `main()` to `state == BROKEN` kept it passing 123/123 while the receipt said
    # `blocking=true` and the process exited 0. So: the expectation is a hand-written TABLE (a change
    # to BLOCKING_STATES must be argued for here, not silently ratified), and the assertion runs the
    # real entry point.
    EXPECTED_EXIT = {FRESH: 0, CLEAN: 0, CONFLICT: 0, PREEXISTING: 0, BROKEN: 1, UNPROVABLE: 1}
    chk("the fail-direction table covers every declared state, so a new state cannot skip it",
        sorted(EXPECTED_EXIT), sorted(STATES))
    for _state, _want in sorted(EXPECTED_EXIT.items()):
        _row = {"state": _state}
        chk(f"exit_code is the LITERAL expected status for {_state!r}", exit_code(_row), _want)
        chk(f"...and the receipt's blocking= field says the same thing for {_state!r}",
            f"blocking={'true' if _want else 'false'}" in receipt(_row), True)

    # ⚠️ AN UNDECLARED STATE — the fourth layer, and the row above ("a new state cannot skip it") only
    # observed a constant, so it could not catch this. A `classify` branch returning a state nobody
    # declared was TRIPLE-silent: exit 0, blocking=false, annotation "". These three rows are also what
    # give `STATES` a functional consumer, which it did not have.
    _UNDECLARED = {"state": "suite-too-large", "reason": "invented"}
    chk("an UNDECLARED state blocks, because a reading nothing declared cannot be known safe",
        exit_code(_UNDECLARED), 1)
    chk("...its receipt agrees", "blocking=true" in receipt(_UNDECLARED), True)
    chk("...and it is NOT silent, unlike FRESH/CLEAN which legitimately are",
        (annotation(_UNDECLARED)[:9], annotation({"state": FRESH}), annotation({"state": CLEAN})),
        ("::error::", "", ""))
    chk("a missing state key is undeclared too, not a pass", exit_code({}), 1)

    # ⚠️ AND THE SELF-TEST MUST NOT WRITE OPERATIONAL OUTPUT INTO THE GATE LOG. `receipt()` is the one
    # machine-readable line an operator greps; six synthetic receipts from the `main()` rows below
    # outranked the real one in run 90740570695 and misled a reviewer within minutes.
    _leak = io.StringIO()
    with contextlib.redirect_stdout(_leak):
        _rc = _quiet(lambda: (print(receipt({"state": BROKEN})), 7)[1])
    chk("_quiet suppresses a production function's stdout while returning its value",
        (_rc, _leak.getvalue()), (7, ""))

    # ...and the ENTRY POINT returns it. `compose` is stubbed at the module attribute `main` resolves
    # through, so this exercises the real argument parsing, the real receipt print and the real
    # return — the three things a pure-function assertion cannot reach.
    _module = sys.modules[__name__]
    _real_compose, _real_summary = compose, os.environ.pop("GITHUB_STEP_SUMMARY", None)
    try:
        for _state, _want in sorted(EXPECTED_EXIT.items()):
            _module.compose = (lambda *a, _s=_state, **k:
                               {"state": _s, "reason": "stub", "graded_base": "a" * 40,
                                "live_tip": "b" * 40})
            _got = _quiet(main, ["--base-ref", "master"])
            chk(f"main() RETURNS the blocking status for {_state!r} (mutating it must red)",
                _got, _want)
    finally:
        _module.compose = _real_compose
        if _real_summary is not None:
            os.environ["GITHUB_STEP_SUMMARY"] = _real_summary
    chk("a usage error is neither of the two verdict statuses", _quiet(main, []), 2)

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
    # `--full` is an escape hatch, so it is pinned rather than merely documented.
    chk("--full selects EVERY enrolled entry regardless of what either side touched",
        select_entries(enrolled, [], [], full=True), sorted(enrolled))
    chk("...and without it the overlap still governs",
        select_entries(enrolled, ["scripts/groom.py"], [], full=False), ["groom.py"])
    chk("--full on an empty manifest still selects nothing (no invention)",
        select_entries([], ["scripts/groom.py"], [], full=True), [])
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

    # ---- _baseline_failures FAILS CLOSED. An entry master ADDED has no baseline in the graded
    # tree, and excusing it as pre-existing would mask exactly the break this check exists for.
    with tempfile.TemporaryDirectory() as _bt:
        os.makedirs(os.path.join(_bt, "scripts"))
        with open(os.path.join(_bt, SUITE_MANIFEST), "w", encoding="utf-8") as handle:
            handle.write("enrolled.py\n")
        open(os.path.join(_bt, "scripts", "enrolled.py"), "w").close()
        # The runner contract is (failures, ungradeable). `every` = a real verdict of FAIL for each.
        every = lambda _cwd, entries, _label="x": (list(entries), [])   # noqa: E731

        # ⚠️ THE SECOND FAIL-OPEN OF THE SAME CLASS, found by review. `runner_available` proves the
        # ARM'S TEXT, not that the harness RAN. worker-live.sh exits a bare 1 with a `worker-live: `
        # line for manifest-validation failure, usage, not-enrolled and ENV-BLOCKED, and with an
        # `::error::self-test sandbox` line for mktemp failure and a non-intercepting sandbox. Read
        # as a baseline verdict, EVERY one of those excused a genuine break as pre-existing.
        for marker, why in (("worker-live: registry-selftest gate: self-test manifest validation "
                             "failed (fail closed)", "manifest validation"),
                            ("worker-live: usage: worker-live.sh run-selftest <x>", "a usage error"),
                            ("worker-live: registry-selftest gate: ENV-BLOCKED -- a dependency",
                             "ENV-BLOCKED"),
                            ("::error::self-test sandbox: mktemp failed", "mktemp failure"),
                            ("::error::self-test sandbox is NOT intercepting `gh`", "a blind sandbox")):
            chk(f"{why} is a HARNESS FAULT, never a verdict", harness_fault(marker), True)
        chk("a plain failing self-test is NOT a harness fault",
            harness_fault("  FAIL something: 1 (want 2)\ndispatch-claim self-test FAILED"), False)
        # ⚠️ THE OTHER ENV-BLOCKED, and the pair is the point. The loop above pins the HARNESS's
        # ENV-BLOCKED (the sandbox could not run the entry) as a fault; an ENTRY's own #1740 terminal
        # line is a considered REFUSAL the harness delivered intact, so it stays a verdict — graded a
        # failure, which is the fail-closed direction. The two differ ONLY by the `worker-live: `
        # prefix, so a bare `"ENV-BLOCKED"` marker would swallow this one; that mutant reds here and
        # nowhere else. See the INVERSE POLARITY note by HARNESS_FAULT_MARKERS.
        chk("an ENTRY's own ENV-BLOCKED verdict line is NOT a harness fault",
            harness_fault("ENV-BLOCKED jq is unavailable — the EXECUTED sweep-paging rows run the "
                          "workflow's own step body\nretriage self-test ENV-BLOCKED"), False)
        chk("a gh-escape is NOT a harness fault — the sandbox WORKED and caught a real escape",
            harness_fault("::error::gh-escape dispatch-claim.py reached the real gh"), False)
        chk("clean output is not a fault", harness_fault(""), False)

        # ⚠️ THE REVIEWER'S ATTACK, end to end: a tree that PASSES runner_available and still exits
        # non-zero from an infrastructure fault must excuse NOTHING.
        def faulting(_cwd, entries, _label="x"):
            return list(entries), list(entries)      # every entry faulted, so none is a verdict
        chk("a baseline whose harness FAULTS excuses nothing (the review finding)",
            _quiet(_baseline_failures, _bt, ["enrolled.py"], faulting), ([], False))
        chk("...and reports the baseline as NOT established, so the receipt cannot say baseline=ok",
            _quiet(_baseline_failures, _bt, ["enrolled.py"], faulting)[1], False)

        # ⚠️ THE MEASURED FAIL-OPEN. #756's graded tree has a worker-live.sh with no run-selftest
        # arm; invoking it exits 1 with a USAGE error, which as a bare exit code is
        # indistinguishable from a failing test. Read as a baseline it excused every composition
        # failure and the check blocked NOTHING — on exactly the stale PRs it targets.
        chk("a graded tree with NO run-selftest arm excuses NOTHING (the measured fail-open)",
            _quiet(_baseline_failures, _bt, ["enrolled.py"], every), ([], False))
        chk("...and runner_available says why", runner_available(_bt), False)
        with open(os.path.join(_bt, RUNNER_SCRIPT), "w", encoding="utf-8") as handle:
            handle.write("case $1 in\n  run-selftest)\n    :\n    ;;\nesac\n")
        chk("...while a tree that DOES implement the arm is usable as a baseline",
            runner_available(_bt), True)
        chk("an enrolled+present entry that fails on the graded tree IS pre-existing",
            _quiet(_baseline_failures, _bt, ["enrolled.py"], every), (["enrolled.py"], True))
        chk("an entry master ADDED (absent from the graded tree) is NOT excused",
            _quiet(_baseline_failures, _bt, ["added-by-master.py"], every), ([], False))
        chk("an entry present but NOT enrolled in the graded tree is NOT excused",
            _quiet(_baseline_failures, _bt, ["unenrolled.py"], every), ([], False))
        chk("a mixed set only excuses the one with a real baseline, and is NOT established",
            _quiet(_baseline_failures, _bt, ["enrolled.py", "added-by-master.py"], every),
            (["enrolled.py"], False))
        chk("an entry that PASSES on the graded tree is not pre-existing either",
            _quiet(_baseline_failures, _bt, ["enrolled.py"], lambda _c, _e, _l="x": ([], [])),
            ([], True))
    chk("an unreadable graded manifest excuses NOTHING (fail closed)",
        _quiet(_baseline_failures, os.path.join(tempfile.gettempdir(), "compose-gate-nonexistent"),
               ["x.py"], lambda _c, e, _l="x": (list(e), [])), ([], False))

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
            # ⚠️ THE STRUCTURE-PRESERVING SURVIVOR found by review: JOB scope, not step scope.
            yield ("the JOB may fail silently, which no other assertion here notices",
                   lambda j: j.update({"continue-on-error": True}))
            yield ("the JOB's continue-on-error is the string 'true'",
                   lambda j: j.update({"continue-on-error": "true"}))
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
            # ⚠️ THE SECOND STRUCTURE-PRESERVING SURVIVOR: a LATER checkout into the workspace.
            # checkouts[0] stays perfect; HEAD becomes single-parent; the check reads `unprovable`
            # forever with its receipt still printing.
            yield ("a SECOND workspace checkout pins head.sha",
                   lambda j: j["steps"].insert(
                       1, {"uses": "actions/checkout@abc", "with": {"fetch-depth": 0,
                                                                    "ref": "${{ github.event.pull_request.head.sha }}"}}))
            yield ("a SECOND workspace checkout is shallow",
                   lambda j: j["steps"].insert(
                       1, {"uses": "actions/checkout@abc", "with": {"fetch-depth": 1}}))

        for name, mutation in checkout_mutants():
            chk(f"the checkout check REFUSES when {name}",
                bool(_refused(assert_merge_ref_inputs, mutate(mutation))), True)

        # ...and does NOT over-block: a checkout into a SEPARATE `path:` cannot redefine the
        # workspace HEAD, so pinning a ref there is legitimate (regate-sweep.yml does exactly this).
        def _extra_checkout(**with_kv):
            return mutate(lambda j: j["steps"].insert(
                1, {"uses": "actions/checkout@abc", "with": dict({"fetch-depth": 0}, **with_kv)}))

        chk("a path-scoped sibling checkout pinning a ref is ALLOWED",
            _refused(assert_merge_ref_inputs,
                     _extra_checkout(path="other", ref="master")), "")
        # ⚠️ ...but `path:` values that RESOLVE TO THE ROOT are the workspace, and clobber HEAD while
        # looking scoped. Found by review: the allowance admitted `.` and `./`.
        for _root_path in (".", "./", "././", ""):
            chk(f"a second workspace checkout with path={_root_path!r} + a ref is REFUSED",
                bool(_refused(assert_merge_ref_inputs,
                              _extra_checkout(path=_root_path,
                                              ref="${{ github.event.pull_request.head.sha }}"))),
                True)
        chk("a path-scoped checkout with NO ref is allowed regardless of path",
            _refused(assert_merge_ref_inputs, _extra_checkout(path=".")), "")

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
    # A semantic composition break reds the gate, and so does an UNPROVABLE reading — see
    # BLOCKING_STATES for why the latter is a RETRACTION of this file's first position rather than an
    # oversight. A textual conflict and a pre-existing red are the author's business, reported as
    # warnings, and do not red. The fail direction lives in `exit_code` and nowhere else.
    return exit_code(result)


if __name__ == "__main__":
    sys.exit(main())
