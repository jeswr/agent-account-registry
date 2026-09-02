#!/usr/bin/env python3
# REPORT WHETHER THIS `pr-gate` RUN GRADED THE TREE THE PULL REQUEST WILL LAND ON (issue #920).
#
# MEASURED (issue #920). `pr-gate` tests `refs/pull/N/merge`, and GitHub does NOT recompute that
# ref when the base branch moves. #900's own gate checked out `Merge 674695d30... into a3f88e5db...`
# — a base tip one commit BEFORE #888's merge commit — even though that run was created 10m18s
# AFTER #888 landed. The scanner #888 added was simply absent from the tree #900 was graded on.
# Crosstab over the last 40 `pr-gate` runs, keyed on the merge-ref base tip: 33 green / 0 red
# WITHOUT #900's commit in the tested tree, 0 green / 7 red WITH it. Perfect separation, 40/40.
# Neither PR was faulty in isolation; the COMPOSITION was never tested by anything, and `master`
# stayed red for over an hour while every open PR was blocked on it.
#
# WHAT THIS IS AND WHAT IT DELIBERATELY IS NOT. #920 lists four repairs: (1) require branches to be
# up to date before merging, (2) a merge queue, (3) a staleness check inside `pr-gate` that
# REPORTS, (4) a post-merge `master` run. (1) and (2) are repository-SETTINGS decisions and remain
# the maintainer's call; this script is (3), the half that needs no settings change. Its whole job
# is to make a green CARRY ITS CAVEAT instead of being silently misread — "was this PR green?" is
# the wrong question, "was this PR green against the tip it will actually land on?" is the right
# one, and until now nothing in CI could answer the second.
#
# ⚠️ THE DISCRIMINATOR IS THE MERGE-REF BASE TIP, NOT `base.sha`. `github.event.pull_request.base.sha`
# is NOT the tested tree: #920 measured it mispredicting 5 of the 7 failures, and pr-gate.yml uses
# it for one unrelated purpose (fetching the baseline self-test manifest). The tree that was
# actually graded is `HEAD^1` of the checked-out merge commit — the base tip GitHub composed the
# merge ref from. That is read here from git, from inside the run, which is the ONLY place it is
# observable; no API field reports it.
#
# ⚠️ AND "THE GRADED TREE IS HEAD^1 OF THE MERGE REF" IS NOT SPELLED HERE (registry #1429). That one
# literal fact had two independent definitions — this module's and compose-gate.py's — each with its
# own git argv, its own `parents[1]` and its own parent-count refusal, so a repoint had to be made in
# both at once or the two gates would silently read different commits. It now lives ONCE, in
# `scripts/graded_base.py`, which this module IMPORTS. What stays here is this module's own
# FAIL-CLOSED SHAPE (`unprovable`, annotated, exit 0), which is deliberately not compose-gate's.
#
# HOW THE READING IS DERIVED, and the two operands it needs from pr-gate.yml's checkout:
#   * `fetch-depth: 0` — without it only the merge ref is fetched and `refs/remotes/origin/<base>`
#     does not exist, so there is nothing to compare against;
#   * no `ref:` override — the job must be checking out `refs/pull/N/merge`, or `HEAD^1` is not a
#     base tip at all.
# Both are asserted at the YAML seam by this module's own self-test, so the configuration change
# that would blind this check reds `pr-gate` instead of quietly turning it into a no-op.
#
# THE FAIL DIRECTION, STATED PLAINLY. `stale` is a WARNING and the step still exits 0: a hard red
# on every base-branch move is option (1) by the back door, at option (1)'s cost, and taken here
# rather than by the maintainer. An operand that cannot be established is NOT treated as fresh —
# it is `unprovable`, annotated with `::error::` (an error annotation on the check, visible in the
# PR's Checks tab), never silently omitted. The exit code is therefore always 0 outside usage
# errors; the guard against this becoming vacuous is structural (the seam assertions above), not
# the exit code.
#
# THE RECEIPT. Every run prints one machine-readable line — `gate-staleness: state=... base_ref=...
# tested_base=... live_tip=... behind=...`. #920's 40-run crosstab had to be reconstructed by hand
# from `Merge X into Y` checkout banners; with the receipt the same measurement is one grep.
#
# RESIDUALS, NAMED. (a) `refs/remotes/origin/<base>` is fetched when the job starts, so a base move
# DURING the run reads fresh — the reading is a lower bound on staleness, never an over-report.
# (b) This reports; it does not prevent. The arm-side refusal of a stale green (#940, landed as
# #950) and the recovery sweep for a stale red (#927 / regate-sweep.py) are the two halves that
# act on the same property; this is the one that says so where the failure is produced.
"""gate-staleness — is this pr-gate run grading the tree the PR will actually land on? (#920)

Usage:
  gate-staleness.py --head-sha <40-hex> --base-ref <branch>   # report (always exits 0)
  gate-staleness.py --self-test
"""
import argparse
import copy
import os
import re
import shlex
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# THE graded-base derivation, IMPORTED and never re-declared (registry #1429). Bound as a MODULE,
# not as `from ... import graded_base`: the self-test below probes the delegation by swapping the
# attribute, and a from-import would have captured the function and made a private copy
# indistinguishable from this one.
import graded_base as _graded_base  # noqa: E402 — the sys.path arm above has to run first

FRESH = "fresh"
STALE = "stale"
UNPROVABLE = "unprovable"

# The workflow seam this report is wired into, and the exact wiring the self-test pins.
PR_GATE_WORKFLOW = ".github/workflows/pr-gate.yml"
GATE_JOB = "gate"
INVOCATION = "scripts/gate-staleness.py"
CHECKOUT_ACTION = "actions/checkout@"
HEAD_SHA_ENV = "PR_HEAD_SHA"
BASE_REF_ENV = "PR_BASE_REF"
HEAD_SHA_EXPR = "${{ github.event.pull_request.head.sha }}"
BASE_REF_EXPR = "${{ github.event.pull_request.base.ref }}"

# THE RECEIPT GRAMMAR, declared ONCE and shared by the renderer and the parser below (#1238).
RECEIPT_MARKER = "gate-staleness:"
RECEIPT_KEYS = ("state", "base_ref", "tested_base", "live_tip", "behind")

SHA_RE = re.compile(r"[0-9a-f]{40}")
# Deliberately narrower than git's own ref grammar. The base ref reaches this script from the event
# payload and is spliced into a ref name handed to `git`, so a value starting with `-` would be read
# by git as an OPTION (`--upload-pack=...`) and a `..` would turn a ref into a range. Everything
# outside the narrow shape is refused as `unprovable` rather than sanitised.
BASE_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,254}")


class GitError(RuntimeError):
    pass


def valid_base_ref(ref):
    """PURE: may this value be spliced into a ref name and handed to git?"""
    ref = ref or ""
    return bool(BASE_REF_RE.fullmatch(ref)) and ".." not in ref


def _git(args, cwd, env=None):
    """Run one read-only git command. Raises GitError on any non-zero exit."""
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, env=env)
    if proc.returncode != 0:
        raise GitError((proc.stderr or proc.stdout or "").strip().splitlines()[-1:] or ["no output"])
    return proc.stdout.strip()


def freshness(head_sha, base_ref, cwd, git=_git):
    """Which base tip was this run graded against, and is it still the tip?

    Returns {"state": fresh|stale|unprovable, "tested_base", "live_tip", "behind", "reason"}.
    EVERY unresolvable operand yields `unprovable` — never `fresh`."""
    result = {"state": UNPROVABLE, "tested_base": "", "live_tip": "", "behind": None, "reason": ""}
    if not SHA_RE.fullmatch(head_sha or ""):
        result["reason"] = f"the pull request head {str(head_sha)[:64]!r} is not a 40-hex commit id"
        return result
    if not valid_base_ref(base_ref):
        result["reason"] = f"the base ref {str(base_ref)[:64]!r} is not a plain branch name"
        return result
    try:
        parents = git(list(_graded_base.GRADED_BASE_ARGV), cwd)
    except GitError as exc:
        result["reason"] = f"the checked-out commit is unreadable ({str(exc)[:120]})"
        return result
    # The ONE owner of "which parent is the graded base", argv included (#1429). Its refusal is
    # already the sentence an operator needs, and it hands back NO shas when it refuses — so this
    # module's `unprovable` cannot be built on a tip the derivation declined to attribute.
    tested_base, composed_head, refusal = _graded_base.graded_base(parents)
    if refusal:
        result["reason"] = refusal
        return result
    if composed_head != head_sha:
        result["reason"] = (f"the checked-out merge composes {composed_head} as its head, which is "
                            f"not this pull request's head {head_sha}")
        return result
    result["tested_base"] = tested_base
    try:
        live_tip = git(["rev-parse", "--verify", "--end-of-options",
                        f"refs/remotes/origin/{base_ref}^{{commit}}"], cwd)
    except GitError:
        result["reason"] = (f"refs/remotes/origin/{base_ref} is unresolvable, so the live base tip "
                            "is unknown (pr-gate.yml's checkout needs fetch-depth: 0 for it)")
        return result
    result["live_tip"] = live_tip
    if tested_base == live_tip:
        result["state"] = FRESH
        result["behind"] = 0
        return result
    result["state"] = STALE
    try:
        result["behind"] = int(git(["rev-list", "--count", "--end-of-options",
                                    f"{tested_base}..{live_tip}"], cwd))
    except (GitError, ValueError):
        result["behind"] = None
    return result


def receipt(result, base_ref):
    """PURE: the one machine-readable line every run prints, stale or not (#920's crosstab)."""
    values = {"state": result["state"],
              "base_ref": base_ref if valid_base_ref(base_ref) else "-",
              "tested_base": result["tested_base"] or "-",
              "live_tip": result["live_tip"] or "-",
              "behind": "-" if result["behind"] is None else result["behind"]}
    return RECEIPT_MARKER + " " + " ".join(f"{key}={values[key]}" for key in RECEIPT_KEYS)


def parse_receipt(line):
    """PURE: the five fields of one receipt line as strings, or None when it is not a receipt.

    The exact INVERSE of `receipt()`, and it lives BESIDE it deliberately (issue #1238): the only
    retrospective reading of the merge-ref base tip is this line in a run log, so a consumer that
    mined it with its own grammar would be a second definition of the receipt — and the producer
    moving one field would silently make that consumer measure something else.

    STRICT, AND THE KEY SEQUENCE IS PINNED EXACTLY rather than searched for. `gh run view --log`
    prefixes every line with `<job>\\t<step>\\t<timestamp> `, so the marker is FOUND rather than
    anchored at column 0 — but everything after it must be exactly the documented five
    `key=value` words in the documented order. A line carrying four of them, six of them, a
    renamed field or the same five reordered is not a receipt this parser will speak for."""
    if not isinstance(line, str):
        return None
    marker = line.find(RECEIPT_MARKER)
    if marker < 0:
        return None
    words = line[marker + len(RECEIPT_MARKER):].split()
    if len(words) != len(RECEIPT_KEYS):
        return None
    fields = {}
    for key, word in zip(RECEIPT_KEYS, words):
        if not word.startswith(key + "="):
            return None
        fields[key] = word[len(key) + 1:]
    return fields


def annotation(result, base_ref):
    """PURE: the single-line workflow annotation for a verdict, or "" when there is nothing to say.

    `fresh` is deliberately silent in the annotation channel — an advisory that annotates every run
    is one nobody reads. The receipt above still states it."""
    if result["state"] == FRESH:
        return ""
    if result["state"] == STALE:
        behind = result["behind"]
        moved = "an unknown number of commits" if behind is None else f"{behind} commit(s)"
        return (f"::warning::gate-staleness: this run graded this pull request's head composed with "
                f"{result['tested_base']}, but {base_ref} is now at {result['live_tip']} "
                f"({moved} later). GitHub does not recompute refs/pull/N/merge when the base moves "
                f"(issue #920), so this result is evidence about a tree that is NOT what this pull "
                f"request will merge into. Re-running the job re-tests the same tree; only a new "
                f"pull_request event (e.g. updating the branch) re-composes it.")
    return (f"::error::gate-staleness: could not establish which tree this run graded — "
            f"{result['reason']}. Treat this run's verdict as unattributed (issue #920).")


def summary_markdown(result, base_ref):
    """PURE: one markdown line for the job summary, so a green carries its caveat (#920)."""
    if result["state"] == FRESH:
        return (f"- ✅ `gate-staleness`: graded against the current `{base_ref}` tip "
                f"`{result['live_tip'][:12]}` — this green is evidence about the tree this pull "
                f"request will land on.")
    if result["state"] == STALE:
        behind = result["behind"]
        moved = "an unknown number of commits" if behind is None else f"{behind} commit(s)"
        return (f"- ⚠️ `gate-staleness`: **graded against a stale base** — "
                f"`{result['tested_base'][:12]}`, {moved} behind the current `{base_ref}` tip "
                f"`{result['live_tip'][:12]}`. This result does not speak for the composition this "
                f"pull request will land as (issue #920).")
    return (f"- ⛔ `gate-staleness`: **unattributed** — {result['reason']} (issue #920).")


def _append_step_summary(line, env=None):
    """Append one line to $GITHUB_STEP_SUMMARY. Never fatal: a summary write failure must not
    change a required gate's verdict, so it degrades to a warning on stdout."""
    env = os.environ if env is None else env
    path = env.get("GITHUB_STEP_SUMMARY", "")
    if not path:
        return False
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError as exc:
        print(f"::warning::gate-staleness: could not write the job summary ({exc})")
        return False
    return True


# ---- THE YAML SEAM -----------------------------------------------------------------------------
# Every uncaught mutant this repo has measured sat at a workflow `if:`, a step, or a call site.
# These two assertions are pinned EXACTLY (whole `run:` body, tokenised argv, exact env
# expressions), because a report that is wired to the wrong field, made conditional, or fed by a
# checkout that cannot resolve its operands is a report that says nothing while looking present.
#
# ⚠️ THE BODY IS PINNED WHOLE, NOT SEARCHED. A `run:` body is a shell script, so "the invocation is
# in there somewhere, spelled right" is not the same claim as "the invocation runs". `true ||
# python3 scripts/gate-staleness.py ...` contains the exact argv, in the exact order, preceded by
# the exact interpreter — and never executes the reporter. Nothing downstream would notice, because
# this command always exits 0 BY DESIGN (see "THE FAIL DIRECTION"), so its absence is silent by
# construction. That is the whole reason the seam, not the exit code, is this report's guard against
# vacuity: the guard has to refuse a body that merely CONTAINS the command.
def _assert_unconditional(scope, mapping):
    if "if" in mapping:
        raise AssertionError(f"{scope} carries an `if:` — this report must run on every gate run")
    if mapping.get("continue-on-error"):
        raise AssertionError(f"{scope} carries a truthy `continue-on-error:`")


def assert_report_seam(job):
    """RAISES unless pr-gate's `gate` job invokes this script unconditionally, with exactly the
    documented flags, fed from exactly the documented event fields."""
    if not isinstance(job, dict):
        raise AssertionError(f"the `{GATE_JOB}` job is missing from the workflow")
    _assert_unconditional(f"the `{GATE_JOB}` job", job)
    steps = job.get("steps")
    if not isinstance(steps, list):
        raise AssertionError(f"the `{GATE_JOB}` job declares no steps")
    found = [s for s in steps if isinstance(s, dict) and INVOCATION in str(s.get("run") or "")]
    if len(found) != 1:
        raise AssertionError(f"expected exactly one `{GATE_JOB}` step invoking {INVOCATION}, "
                             f"found {len(found)}")
    step = found[0]
    _assert_unconditional(f"the step invoking {INVOCATION}", step)
    run = str(step.get("run") or "")
    if "${{" in run:
        raise AssertionError("the step interpolates `${{ }}` into its `run:` body — event fields "
                             "must reach it through `env:`")
    # The body must BE the two documented commands — not merely contain them somewhere. See the
    # section comment above: a shell prefix costs one token and silently deletes the report.
    lines = [line.strip() for line in run.splitlines() if line.strip()]
    if len(lines) != 2:
        raise AssertionError(
            f"the step's `run:` body has {len(lines)} non-blank line(s), want exactly 2 — "
            f"`set -euo pipefail` then the {INVOCATION} invocation, and nothing else")
    if lines[0] != "set -euo pipefail":
        raise AssertionError(f"the step's `run:` body opens with {lines[0]!r}, want the exact line "
                             "`set -euo pipefail`")
    try:
        tokens = shlex.split(lines[1])
    except ValueError as exc:
        raise AssertionError(f"the step's invocation line does not tokenise as shell words ({exc})")
    want = ["python3", INVOCATION, "--head-sha", f"${HEAD_SHA_ENV}", "--base-ref",
            f"${BASE_REF_ENV}"]
    if tokens != want:
        raise AssertionError(
            f"the step's invocation line tokenises to {tokens}, want exactly {want} — the whole "
            f"line must BE the invocation, because a `true ||` prefix, a `|| true` suffix or a "
            f"leading `#` leaves every token in place while the report never runs")
    env = step.get("env")
    if not isinstance(env, dict):
        raise AssertionError("the step declares no `env:` block")
    for name, expression in ((HEAD_SHA_ENV, HEAD_SHA_EXPR), (BASE_REF_ENV, BASE_REF_EXPR)):
        if env.get(name) != expression:
            raise AssertionError(f"env {name} is {env.get(name)!r}, want {expression!r} — the "
                                 "merge-ref base tip is not `base.sha` (issue #920)")
    return True


def report_step_name(job):
    """RAISES unless the seam holds; returns the `name:` of the ONE step that prints the receipt.

    WHY A CONSUMER NEEDS THIS (issue #1238). A run log is written by the pull request's own code:
    any step of the `gate` job can print a line spelling `gate-staleness:`, so a retrospective
    crosstab needs to know WHICH step is the reporting one — and that step is named HERE, by
    `assert_report_seam`'s own exactly-one search, never by a second copy of "which step reports"
    that could start pointing at a different one.

    WHAT THIS DOES NOT ESTABLISH, stated so no consumer mistakes it for an author filter: for a
    `pull_request` event this script is checked out from the pull request's OWN merge tree, so the
    designated step's output is author-controlled too. Naming the step excludes the other steps
    and NOTHING MORE. Deciding whether the receipt may be quoted as evidence is the consumer's
    own job, against trusted metadata (AGENTS.md pre-flight item 5) — see
    `gate-base-lead.attribution_refusal`, which admits a run's receipt only when GitHub's own diff
    for it shows the pull touched no part of the code this step runs."""
    assert_report_seam(job)
    step = [s for s in job["steps"] if INVOCATION in str(s.get("run") or "")][0]
    name = step.get("name")
    if not isinstance(name, str) or not name.strip():
        raise AssertionError(
            f"the step invoking {INVOCATION} carries no usable `name:` — a run-log consumer "
            "filters the receipt on the step column, so an unnamed step makes it unattributable "
            "(issue #1238)")
    return name


def assert_merge_ref_inputs(job):
    """RAISES unless the `gate` job's checkout still produces this report's two operands: the
    merge commit itself (no `ref:` override) and `refs/remotes/origin/<base>` (fetch-depth: 0)."""
    if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
        raise AssertionError(f"the `{GATE_JOB}` job declares no steps")
    found = [s for s in job["steps"]
             if isinstance(s, dict) and str(s.get("uses") or "").startswith(CHECKOUT_ACTION)]
    if len(found) != 1:
        raise AssertionError(f"expected exactly one `{CHECKOUT_ACTION}...` step in the "
                             f"`{GATE_JOB}` job, found {len(found)}")
    with_block = found[0].get("with")
    if not isinstance(with_block, dict):
        raise AssertionError("the checkout step declares no `with:` block")
    depth = with_block.get("fetch-depth")
    if depth != 0 or isinstance(depth, bool):
        raise AssertionError(f"the checkout step's fetch-depth is {depth!r}, want the integer 0 — "
                             "without it refs/remotes/origin/<base> is never fetched and this "
                             "report has nothing to compare the graded tree against")
    if "ref" in with_block:
        raise AssertionError("the checkout step pins a `ref:` — the report needs the default "
                             "refs/pull/N/merge checkout for HEAD^1 to be a base tip")
    return True


# ---- SELF-TEST ---------------------------------------------------------------------------------
def _fixture_repo(root, git):
    """Build a real git repository shaped exactly like a pr-gate checkout: HEAD detached at a
    two-parent merge of the PR head into a base tip that `master` has since moved past."""
    shas = {}

    def commit(message, path, body):
        with open(os.path.join(root, path), "w", encoding="utf-8") as handle:
            handle.write(body)
        git(["add", "--", path], root)
        git(["commit", "-m", message], root)
        return git(["rev-parse", "HEAD"], root)

    git(["init", "--initial-branch=master", "--quiet"], root)
    shas["A"] = commit("base 0", "base.txt", "0\n")
    git(["checkout", "--quiet", "-b", "feature"], root)
    shas["H"] = commit("pull request head", "head.txt", "head\n")
    git(["checkout", "--quiet", "master"], root)
    shas["B1"] = commit("base 1", "base.txt", "1\n")
    shas["B2"] = commit("base 2", "base.txt", "2\n")
    git(["checkout", "--quiet", "--detach", shas["A"]], root)
    git(["merge", "--no-ff", "--no-edit", "-m", "Merge head into base", shas["H"]], root)
    shas["M"] = git(["rev-parse", "HEAD"], root)
    git(["update-ref", "refs/remotes/origin/master", shas["B2"]], root)
    return shas


def _seam_fixture():
    """The wiring this module requires, as the parsed shape yaml.safe_load produces."""
    return {"steps": [
        {"name": "Checkout PR head",
         "uses": CHECKOUT_ACTION + "0" * 40,
         "with": {"persist-credentials": False, "fetch-depth": 0}},
        {"name": "Report staleness",
         "env": {HEAD_SHA_ENV: HEAD_SHA_EXPR, BASE_REF_ENV: BASE_REF_EXPR},
         "run": ("set -euo pipefail\n"
                 f'python3 {INVOCATION} --head-sha "${HEAD_SHA_ENV}" --base-ref "${BASE_REF_ENV}"\n')},
    ]}


def _refused(assertion, job):
    """"" when `assertion` accepted the job, else its refusal message."""
    try:
        assertion(job)
    except AssertionError as exc:
        return str(exc) or "refused"
    return ""


def _self_test():
    import tempfile
    ok = True
    checks = 0

    def chk(name, got, want):
        nonlocal ok, checks
        checks += 1
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    # ---- the base-ref validator, both directions. The rejects are argument- and range-injection
    # shapes; the accepts are branch names this estate actually uses, so an over-tight pattern that
    # refused every real base (and made every run `unprovable`) fails here too.
    for ref in ("master", "main", "release/2.0", "dependabot/pip/pyyaml-6.0.2", "a.b-c_"[:5]):
        chk(f"base ref {ref!r} is accepted", valid_base_ref(ref), True)
    for ref in ("", "-x", "--upload-pack=/bin/sh", "a..b", "has space", "a\nb", "/leading",
                "x" * 256):
        chk(f"base ref {ref!r} is refused", valid_base_ref(ref), False)

    with tempfile.TemporaryDirectory() as tmp:
        repo = os.path.join(tmp, "repo")
        os.mkdir(repo)
        env = dict(os.environ, HOME=tmp,
                   GIT_CONFIG_GLOBAL=os.path.join(tmp, "no-such-gitconfig"),
                   GIT_CONFIG_SYSTEM=os.path.join(tmp, "no-such-gitconfig"),
                   GIT_AUTHOR_NAME="selftest", GIT_AUTHOR_EMAIL="selftest@example.invalid",
                   GIT_COMMITTER_NAME="selftest", GIT_COMMITTER_EMAIL="selftest@example.invalid",
                   GIT_AUTHOR_DATE="2026-07-29T00:00:00+00:00",
                   GIT_COMMITTER_DATE="2026-07-29T00:00:00+00:00")
        sha = _fixture_repo(repo, lambda args, cwd: _git(args, cwd, env=env))
        # Every reading below goes through the PRODUCTION `_git` (reads need no identity), so the
        # exact git invocations are what is under test, not a stand-in for them.
        stale = freshness(sha["H"], "master", repo)
        chk("a base that moved two commits reads STALE, at the graded tip, two behind",
            (stale["state"], stale["tested_base"], stale["live_tip"], stale["behind"]),
            (STALE, sha["A"], sha["B2"], 2))
        _git(["update-ref", "refs/remotes/origin/master", sha["B1"]], repo)
        chk("the distance is the real count, not a constant",
            freshness(sha["H"], "master", repo)["behind"], 1)
        # THE FRESH DIRECTION IS LOAD-BEARING: it is what kills a reading taken from the WRONG
        # parent. HEAD^2 is the pull request head, which differs from the tip in every stale case
        # too, so only this row separates "reads the base tip" from "reads any parent".
        _git(["update-ref", "refs/remotes/origin/master", sha["A"]], repo)
        fresh = freshness(sha["H"], "master", repo)
        chk("a base that has not moved reads FRESH, zero behind",
            (fresh["state"], fresh["tested_base"], fresh["live_tip"], fresh["behind"]),
            (FRESH, sha["A"], sha["A"], 0))
        _git(["update-ref", "refs/remotes/origin/master", sha["B2"]], repo)
        # Every operand failure is UNPROVABLE — never fresh, never silently stale.
        mismatched = freshness(sha["B2"], "master", repo)
        chk("a merge that does not compose THIS head is unprovable, and names both heads",
            (mismatched["state"], sha["H"] in mismatched["reason"],
             sha["B2"] in mismatched["reason"]),
            (UNPROVABLE, True, True))
        chk("an unknown base branch is unprovable (no live tip to compare)",
            freshness(sha["H"], "no-such-branch", repo)["state"], UNPROVABLE)
        chk("a malformed head sha is unprovable",
            (freshness("not-a-sha", "master", repo)["state"],
             freshness("", "master", repo)["state"]), (UNPROVABLE, UNPROVABLE))
        chk("an injection-shaped base ref is unprovable",
            freshness(sha["H"], "--upload-pack=/bin/sh", repo)["state"], UNPROVABLE)
        _git(["checkout", "--quiet", "--detach", sha["H"]], repo)
        one_parent = freshness(sha["H"], "master", repo)
        chk("a NON-merge checkout is unprovable (1 parent), not fresh",
            (one_parent["state"], "1 parent(s)" in one_parent["reason"]), (UNPROVABLE, True))
        _git(["checkout", "--quiet", "--detach", sha["A"]], repo)
        chk("a root-commit checkout is unprovable (0 parents), not fresh",
            (freshness(sha["A"], "master", repo)["state"],
             "0 parent(s)" in freshness(sha["A"], "master", repo)["reason"]), (UNPROVABLE, True))
        _git(["checkout", "--quiet", "--detach", sha["M"]], repo)
        _git(["update-ref", "-d", "refs/remotes/origin/master"], repo)
        chk("a missing remote-tracking base ref is unprovable, not fresh",
            freshness(sha["H"], "master", repo)["state"], UNPROVABLE)
        _git(["update-ref", "refs/remotes/origin/master", sha["B2"]], repo)
        outside = os.path.join(tmp, "not-a-repo")
        os.mkdir(outside)
        chk("a working directory that is not a repository is unprovable, not fresh",
            freshness(sha["H"], "master", outside)["state"], UNPROVABLE)

        # ---- [#1429] THE SHARED-CODE LEG. Every parent-count row above is satisfied just as well
        # by the PRIVATE copy of the derivation this module used to carry, so long as the copy
        # agrees today — which is precisely the #958 shape #1429 removed, and #945 measured why it
        # survives (two copies of one rule make each copy INDIVIDUALLY unkillable, because removing
        # either alone leaves the suite green). So the delegation itself is probed: swap the shared
        # owner's members for sentinels and require this module's verdict to follow them. Only
        # shared code can. Restored in a `finally`, and the restoration is its own row — a leaked
        # sentinel would silently poison every row below.
        _real_reader, _real_argv = _graded_base.graded_base, _graded_base.GRADED_BASE_ARGV
        try:
            _graded_base.graded_base = lambda _line: ("", "", "SENTINEL-REFUSAL")
            _sentinel = freshness(sha["H"], "master", repo)
            chk("the graded-base reading DELEGATES to graded_base.graded_base (a re-inlined "
                "private copy would not follow this sentinel)",
                (_sentinel["state"], _sentinel["reason"]), (UNPROVABLE, "SENTINEL-REFUSAL"))
        finally:
            _graded_base.graded_base = _real_reader
        try:
            # ...and so does the git ARGV. Sharing the parser while keeping a private invocation
            # leaves the repoint half-done, and this mutant is what shows it: `rev-parse HEAD`
            # prints ONE token, so the shared parser refuses with a parent count of 0.
            _graded_base.GRADED_BASE_ARGV = ("rev-parse", "HEAD")
            chk("...and so does the git ARGV (a private invocation would still read three tokens)",
                "0 parent(s)" in freshness(sha["H"], "master", repo)["reason"], True)
        finally:
            _graded_base.GRADED_BASE_ARGV = _real_argv
        chk("...and BOTH sentinels are UNDONE, so every row below reads the real shared owner",
            freshness(sha["H"], "master", repo)["state"], STALE)

        # The distance is the one NICE-TO-HAVE operand: if `rev-list --count` fails, the verdict
        # must still be STALE with the distance reported as unknown — never fresh, and never a
        # zero that reads as "the base has not moved".
        def _count_fails(args, cwd):
            if args[:2] == ["rev-list", "--count"]:
                raise GitError("injected count failure")
            return _git(args, cwd)

        countless = freshness(sha["H"], "master", repo, git=_count_fails)
        chk("a failed distance count stays STALE, at the graded tip, with an unknown distance",
            (countless["state"], countless["tested_base"], countless["behind"]),
            (STALE, sha["A"], None))
        chk("an unknown distance still warns, and says the distance is unknown",
            (annotation(countless, "master").startswith("::warning::"),
             "unknown number of commits" in annotation(countless, "master")), (True, True))

        # ---- rendering. The channels are separate: a mutant that reports every run as fine, or
        # that annotates every run, has to move one of these rows.
        chk("STALE renders exactly one ::warning:: naming both tips and the distance",
            (annotation(stale, "master").count("::warning::"),
             annotation(stale, "master").startswith("::warning::"),
             sha["A"] in annotation(stale, "master"), sha["B2"] in annotation(stale, "master"),
             "2 commit(s)" in annotation(stale, "master"),
             "\n" in annotation(stale, "master")),
            (1, True, True, True, True, False))
        chk("FRESH renders NO annotation at all (control)", annotation(fresh, "master"), "")
        unprovable = freshness("not-a-sha", "master", repo)
        chk("UNPROVABLE renders an ::error:: carrying the reason",
            (annotation(unprovable, "master").startswith("::error::"),
             unprovable["reason"] in annotation(unprovable, "master")), (True, True))
        chk("the receipt states the verdict and both tips machine-readably",
            receipt(stale, "master"),
            f"gate-staleness: state=stale base_ref=master tested_base={sha['A']} "
            f"live_tip={sha['B2']} behind=2")
        chk("the receipt of an unresolved reading has no shas to claim",
            receipt(unprovable, "master"),
            "gate-staleness: state=unprovable base_ref=master tested_base=- live_tip=- behind=-")

        # ---- THE PARSER, the inverse of the two rows above (#1238). It is DRIVEN by the
        # producer's own output — a parser must speak for what `receipt()` actually emits, not for
        # a hand-written approximation of it — while every EXPECTED value is a fixture sha read out
        # of the git repository, so the round trip cannot be satisfied tautologically.
        chk("the receipt parses back to the fields it was rendered from",
            parse_receipt(receipt(stale, "master")),
            {"state": STALE, "base_ref": "master", "tested_base": sha["A"],
             "live_tip": sha["B2"], "behind": "2"})
        chk("a receipt carried on a `gh run view --log` line still parses, tip included",
            parse_receipt("gate\tReport staleness\t2026-08-01T00:00:00.0000000Z "
                          + receipt(fresh, "master")),
            {"state": FRESH, "base_ref": "master", "tested_base": sha["A"],
             "live_tip": sha["A"], "behind": "0"})
        chk("an unresolved receipt parses to the dashes it claims, never to a sha",
            parse_receipt(receipt(unprovable, "master")),
            {"state": UNPROVABLE, "base_ref": "master", "tested_base": "-", "live_tip": "-",
             "behind": "-"})
        # The reject direction. Each of these is a line a log realistically carries, and every one
        # of them would hand a crosstab a WRONG tested_base if the parser searched instead of
        # pinning the exact word sequence.
        for label, line in (
                ("a log line with no marker at all", "gate\tstep\t2026-08-01 nothing here"),
                ("a truncated receipt", f"{RECEIPT_MARKER} state=stale base_ref=master"),
                ("a receipt with an extra trailing word", receipt(stale, "master") + " behind=0"),
                ("a reordered receipt",
                 f"{RECEIPT_MARKER} base_ref=master state=stale tested_base=- live_tip=- behind=-"),
                ("a receipt with a renamed field",
                 f"{RECEIPT_MARKER} state=stale base_ref=master base=- live_tip=- behind=-"),
                ("a non-string line", None)):
            chk(f"{label} is NOT a receipt", parse_receipt(line), None)
        chk("the summary line of a stale run says so, and a fresh one does not",
            ("stale base" in summary_markdown(stale, "master"),
             "stale base" in summary_markdown(fresh, "master")), (True, False))
        chk("the summary line of an unattributed run says so, and claims no tip",
            ("unattributed" in summary_markdown(unprovable, "master"),
             "stale base" in summary_markdown(unprovable, "master")), (True, False))

        # ---- the summary CHANNEL itself. It must APPEND (a job summary is shared with every other
        # step), it must be a no-op when unset, and a write failure must degrade to a warning: this
        # advisory must never change a required gate's verdict by raising.
        direct = os.path.join(tmp, "direct-summary.md")
        with open(direct, "w", encoding="utf-8") as handle:
            handle.write("PRIOR-CONTENT\n")
        wrote = _append_step_summary("APPENDED", {"GITHUB_STEP_SUMMARY": direct})
        with open(direct, encoding="utf-8") as handle:
            chk("summary: appends without truncating, and says it wrote",
                (wrote, handle.read()), (True, "PRIOR-CONTENT\nAPPENDED\n"))
        chk("summary: no destination configured is a no-op", _append_step_summary("X", {}), False)
        # The warning is captured, never printed: a self-test must not publish a workflow
        # annotation of its own (the #1222 lesson).
        import contextlib
        import io

        buffered = io.StringIO()
        with contextlib.redirect_stdout(buffered):
            unwritable = _append_step_summary("X", {"GITHUB_STEP_SUMMARY": repo})
        chk("summary: an unwritable destination warns and returns False, never raises",
            (unwritable, buffered.getvalue().startswith("::warning::")), (False, True))

        # ---- THE CLI, end to end, in the fixture repository. `main` is where a report can be
        # computed correctly and then not printed, not summarised, or exited on.
        me = os.path.abspath(__file__)
        summary = os.path.join(tmp, "summary.md")
        with open(summary, "w", encoding="utf-8") as handle:
            handle.write("SENTINEL-PRIOR-SUMMARY\n")

        def run_cli(*args, with_summary=True):
            cli_env = dict(os.environ)
            cli_env.pop("GITHUB_STEP_SUMMARY", None)
            if with_summary:
                cli_env["GITHUB_STEP_SUMMARY"] = summary
            proc = subprocess.run([sys.executable, me, *args], cwd=repo, capture_output=True,
                                  text=True, env=cli_env)
            return proc.returncode, proc.stdout

        rc, out = run_cli("--head-sha", sha["H"], "--base-ref", "master")
        with open(summary, encoding="utf-8") as handle:
            written = handle.read()
        chk("CLI on a stale base: exit 0, warning + receipt on stdout",
            (rc, "::warning::" in out,
             f"state=stale base_ref=master tested_base={sha['A']}" in out), (0, True, True))
        chk("CLI APPENDS the caveat to the job summary (the prior content survives)",
            ("SENTINEL-PRIOR-SUMMARY" in written, "stale base" in written), (True, True))
        _git(["update-ref", "refs/remotes/origin/master", sha["A"]], repo)
        rc, out = run_cli("--head-sha", sha["H"], "--base-ref", "master")
        chk("CLI on a fresh base: exit 0, receipt, and NO warning or error annotation",
            (rc, "state=fresh" in out, "::warning::" in out, "::error::" in out),
            (0, True, False, False))
        _git(["update-ref", "refs/remotes/origin/master", sha["B2"]], repo)
        rc, out = run_cli("--head-sha", sha["H"], "--base-ref", "no-such-branch")
        chk("CLI on an unresolvable operand: exit 0 but LOUD (::error:: + unprovable receipt)",
            (rc, "::error::" in out, "state=unprovable" in out), (0, True, True))
        rc, out = run_cli("--head-sha", sha["H"], "--base-ref", "master", with_summary=False)
        chk("CLI without a job summary still reports and exits 0",
            (rc, "state=stale" in out), (0, True))
        chk("a missing operand is a usage error (exit 2), never a verdict",
            (run_cli()[0], run_cli("--head-sha", sha["H"])[0],
             run_cli("--base-ref", "master")[0]), (2, 2, 2))

    # ---- the YAML seam, as parsed shapes. Every mutant is a live wiring regression that would
    # leave the step present and the report silent.
    good = _seam_fixture()
    chk("the documented wiring is accepted", _refused(assert_report_seam, good), "")
    chk("the documented checkout is accepted", _refused(assert_merge_ref_inputs, good), "")

    def mutate(fn):
        job = copy.deepcopy(good)
        fn(job)
        return job

    def report_mutants():
        yield "the step is dropped", lambda j: j["steps"].pop(1)
        yield "the step is duplicated", lambda j: j["steps"].append(copy.deepcopy(j["steps"][1]))
        yield "the step is made conditional", lambda j: j["steps"][1].update({"if": "false"})
        yield "the JOB is made conditional", lambda j: j.update({"if": "false"})
        yield ("the step may fail silently",
               lambda j: j["steps"][1].update({"continue-on-error": True}))
        yield ("`set -euo pipefail` is dropped",
               lambda j: j["steps"][1].update(
                   {"run": j["steps"][1]["run"].replace("set -euo pipefail\n", "")}))
        yield ("a flag is dropped",
               lambda j: j["steps"][1].update(
                   {"run": j["steps"][1]["run"].replace(f' --base-ref "${BASE_REF_ENV}"', "")}))
        yield ("a flag is renamed",
               lambda j: j["steps"][1].update(
                   {"run": j["steps"][1]["run"].replace("--base-ref", "--base-sha")}))
        yield ("the script is run by something other than python3",
               lambda j: j["steps"][1].update(
                   {"run": j["steps"][1]["run"].replace("python3 scripts/", "bash scripts/")}))
        yield ("the script path is not its own argv token",
               lambda j: j["steps"][1].update(
                   {"run": j["steps"][1]["run"].replace(f"python3 {INVOCATION}",
                                                        f"python3 ./{INVOCATION}")}))
        yield ("an extra argument is appended",
               lambda j: j["steps"][1].update(
                   {"run": j["steps"][1]["run"].rstrip("\n") + " --strict\n"}))
        yield ("the value is fed from base.sha instead of base.ref",
               lambda j: j["steps"][1]["env"].update(
                   {BASE_REF_ENV: "${{ github.event.pull_request.base.sha }}"}))
        yield ("the env block is dropped", lambda j: j["steps"][1].pop("env"))
        yield ("the event field is interpolated straight into `run:`",
               lambda j: j["steps"][1].update(
                   {"run": j["steps"][1]["run"].replace(f'"${BASE_REF_ENV}"',
                                                        '"${{ github.event.pull_request.base.ref }}"')}))

    for name, mutation in report_mutants():
        chk(f"the seam check REFUSES when {name}",
            bool(_refused(assert_report_seam, mutate(mutation))), True)

    # ---- SHELL-LEVEL INERTNESS is a SEPARATE experiment from the YAML `if: false` above, and the
    # one this seam exists for. Each mutant below leaves the step present, unconditional, without
    # `continue-on-error`, spelling the exact interpreter and the exact argv in the exact order —
    # and exits 0 with the reporter never run. None of them crashes, so nothing else in the gate
    # could notice. Each row asserts WHICH assertion refused it, so a refusal for an unrelated
    # reason cannot be banked as a kill (AGENTS.md pre-flight item 4, "false kill").
    LINE_COUNT = "non-blank line"      # the body is not the two documented commands
    INVOCATION_LINE = "invocation line"  # the line is not exactly the invocation

    def _sub(job, old, new):
        job["steps"][1].update({"run": job["steps"][1]["run"].replace(old, new)})

    def inert_mutants():
        yield ("the invocation is short-circuited by a `true ||` prefix", INVOCATION_LINE,
               lambda j: _sub(j, "python3 ", "true || python3 "))
        yield ("the invocation's failure is swallowed by a `|| true` suffix", INVOCATION_LINE,
               lambda j: j["steps"][1].update(
                   {"run": j["steps"][1]["run"].rstrip("\n") + " || true\n"}))
        yield ("the invocation is commented out", INVOCATION_LINE,
               lambda j: _sub(j, "python3 ", "# python3 "))
        yield ("the body exits before reaching the invocation", LINE_COUNT,
               lambda j: _sub(j, "set -euo pipefail\n", "set -euo pipefail\nexit 0\n"))

    for name, fragment, mutation in inert_mutants():
        chk(f"the seam check REFUSES when {name}, naming the {fragment!r} requirement",
            fragment in _refused(assert_report_seam, mutate(mutation)), True)

    def checkout_mutants():
        yield "the checkout step is dropped", lambda j: j["steps"].pop(0)
        yield ("fetch-depth is dropped", lambda j: j["steps"][0]["with"].pop("fetch-depth"))
        yield ("fetch-depth is shallow", lambda j: j["steps"][0]["with"].update({"fetch-depth": 1}))
        yield ("fetch-depth is the string '0'",
               lambda j: j["steps"][0]["with"].update({"fetch-depth": "0"}))
        yield ("fetch-depth is False (yaml `no`)",
               lambda j: j["steps"][0]["with"].update({"fetch-depth": False}))
        yield ("a ref: override is pinned",
               lambda j: j["steps"][0]["with"].update({"ref": "${{ github.head_ref }}"}))
        yield ("the whole with: block is dropped", lambda j: j["steps"][0].pop("with"))

    for name, mutation in checkout_mutants():
        chk(f"the checkout check REFUSES when {name}",
            bool(_refused(assert_merge_ref_inputs, mutate(mutation))), True)

    # ---- WHICH step prints the receipt (#1238). A consumer filters a run log on this name, so
    # naming the wrong step, or no step, must refuse rather than return something plausible.
    chk("the reporting step names itself, and it is the step invoking this script",
        report_step_name(good), "Report staleness")
    for name, mutation in (
            ("the step's name is dropped", lambda j: j["steps"][1].pop("name")),
            ("the step's name is blank", lambda j: j["steps"][1].update({"name": "   "})),
            ("the step's name is not a string", lambda j: j["steps"][1].update({"name": 920})),
            ("the reporting step is duplicated, so `which step` is ambiguous",
             lambda j: j["steps"].append(copy.deepcopy(j["steps"][1]))),
            ("the reporting step is gone", lambda j: j["steps"].pop(1))):
        chk(f"report_step_name REFUSES when {name}",
            bool(_refused(report_step_name, mutate(mutation))), True)

    # A job that is absent or step-less must REFUSE, not read as satisfied: this is the shape a
    # renamed job or a trimmed workflow presents, and it is exactly where a checker fails open.
    for shape, job in (("an absent job", None), ("a step-less job", {}),
                       ("a malformed steps: block", {"steps": "not-a-list"})):
        chk(f"the seam check REFUSES {shape}", bool(_refused(assert_report_seam, job)), True)
        chk(f"the checkout check REFUSES {shape}",
            bool(_refused(assert_merge_ref_inputs, job)), True)

    # ---- and the LIVE workflow, which is the only row that speaks for what actually runs.
    # An absent PyYAML is REPORTED AS A FAILING ROW, not raised: an exception here would abort the
    # harness with the rows below never run and no roll-up printed, which reads like a kill while
    # measuring nothing (AGENTS.md pre-flight item 4). "We could not check this" is a refusal.
    workflow = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", PR_GATE_WORKFLOW)
    chk("the live pr-gate workflow is readable", os.path.isfile(workflow), True)
    document = None
    try:
        import yaml
    except ImportError as exc:
        chk("PyYAML is available to read the LIVE workflow seam", f"unavailable ({exc})", "")
    else:
        with open(workflow, encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    live_job = ((document or {}).get("jobs") or {}).get(GATE_JOB)
    chk("LIVE pr-gate.yml wires this report unconditionally, from base.ref, with these flags",
        _refused(assert_report_seam, live_job), "")
    chk("LIVE pr-gate.yml still checks out the merge ref with full history",
        _refused(assert_merge_ref_inputs, live_job), "")
    chk("LIVE pr-gate.yml's reporting step is NAMED — a log consumer filters on it (#1238)",
        _refused(report_step_name, live_job), "")

    print("gate-staleness self-test", "PASSED" if ok else "FAILED", f"({checks} checks)")
    return 0 if ok else 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Report whether this pr-gate run graded the tree the PR will land on (#920)")
    parser.add_argument("--head-sha", default="",
                        help="the pull request's head sha (github.event.pull_request.head.sha)")
    parser.add_argument("--base-ref", default="",
                        help="the base BRANCH name (github.event.pull_request.base.ref)")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if not args.head_sha or not args.base_ref:
        print("error: --head-sha and --base-ref are both required", file=sys.stderr)
        return 2
    result = freshness(args.head_sha, args.base_ref, os.getcwd())
    print(receipt(result, args.base_ref))
    note = annotation(result, args.base_ref)
    if note:
        print(note)
    _append_step_summary(summary_markdown(result, args.base_ref))
    # ALWAYS 0 outside a usage error — see "THE FAIL DIRECTION" in this file's header. This is an
    # advisory channel; turning a base-branch move into a hard red is issue #920's option (1) and
    # is the maintainer's decision, not this script's.
    return 0


if __name__ == "__main__":
    sys.exit(main())
