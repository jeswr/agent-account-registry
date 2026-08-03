#!/usr/bin/env python3
# [SPARQ agent] [issue #1315] A COPY CENSUS PER NAMED PREDICATE — the guard for "a fix narrowed
# N-1 copies and the suite stayed green".
#
# THE MEASURED PATTERN (#1315: four instances in ONE session, four agents, four code paths). A
# predicate exists in N places; a fix narrows N-1; the suite stays green, because every fixture
# exercises the copy that was fixed. #1275 is the clearest case: the worker head-ref shape gate had
# FOUR copies, three were found, and the fourth — worker-live.sh's own copy in `run_review`, 29
# lines above the `git fetch` the design record cites as the only thing on that path — was left
# strict. The string `unsafe pull request head branch` appears ONLY at that script's `die` sites,
# every worker-live.sh fixture uses a worker-shaped branch, so the copy had ZERO coverage: 55/55
# passed while the lane delivered ZERO. A mutation sweep does not rescue it either — #1313's author
# found this exact class twice, but only inside the module they were editing.
#
# ⚠️ THE MISS FAILS IN THE EXPENSIVE DIRECTION, which is why it is worth a required gate. The
# ADMISSION leg now says yes, so work dispatches, a round is charged and a model runs; a LATER copy
# still says no, so the product is discarded and the item parks. A cheap refusal becomes an
# expensive one with the same outcome plus a worse terminal state. The question to ask of any
# narrowing is "if a later copy still refuses, what have I spent by the time it does?" — and when
# the answer includes a model run, an account lease or a park, the narrowing must be complete or
# not ship at all.
#
# WHAT IS DECLARED AND WHAT IS DERIVED. #1315 names the anti-pattern explicitly: "do not build it
# as two hand-maintained lists checked against each other — a guard comparing two hand-maintained
# lists verifies their AGREEMENT, not their TRUTH. Derive one side from the artefact." So:
#
#   DECLARED here, by hand: for each governed predicate, its distinguishing LITERAL (the regex
#     source) and a PARTITION of its copies into named CELLS. A cell is an INTENT — "these copies
#     are governed the same way", and "copies in different cells are governed differently".
#   DERIVED from the tree on every run: WHICH files contain the literal, at which enclosing unit,
#     and each copy's GUARD SIGNATURE — its own source line plus the chain of block-openers that
#     encloses it inside that unit.
#
# The declaration never states what a copy's guard IS; that fact only ever comes out of the source.
# So none of the three assertions can be satisfied by editing this file to agree with itself:
#
#   1. CENSUS       — the derived site set equals the declared site set. A NEW copy anywhere in the
#                     repository, or a declared copy that vanished, fails loudly.
#   2. HOMOGENEITY  — every copy in a cell derives the SAME guard. This is the "narrowed 2 of 3"
#                     direction: waive `run_fix`, leave `stage_fix`/`push_fix`, and the cell stops
#                     agreeing with itself.
#   3. DISTINCTNESS — copies in DIFFERENT cells derive DIFFERENT guards. This is #1275's own
#                     direction: the review-admission copy is declared distinct from the write-path
#                     copies, so a narrowing that leaves `run_review` byte-identical to `run_fix`
#                     collapses two cells into one and reds. #1275's fix is exactly the edit that
#                     makes them distinct again — which is why a COMPLETE narrowing stays green.
#
# ⚠️ IT SCANS `.py`, `.sh`, `.yml` AND `.yaml`, over the WHOLE repository rather than `scripts/`
# (the #1314 shape — "the check cannot see the file where the break lives"). #1275's miss was in
# shell twice and #756's was in a regex-extracted YAML block, so a `.py`-only or `scripts/`-only
# census would have missed all three. A scan that reads zero files of a scanned language, and a
# predicate whose literal matches nothing, are REFUSALS — never a vacuous pass.
#
# WHAT THIS DELIBERATELY IS NOT. It is not a semantic analysis and it does not decide whether a
# narrowing is CORRECT — only whether it is COMPLETE, and whether the asymmetries someone wrote
# down still hold. It governs the predicates enrolled below and says nothing about any other.
# #1315's closing constraint is the binding one — "a guard that fires on everything is worse than
# none" — so a signature is built from a copy's own line and its ENCLOSING block-openers ALONE,
# where an opener is identified BY SYNTAX and never by indentation alone: a sibling statement, a
# continuation of a multi-line statement, a closing `fi`/`esac`, a comment, a blank line, a renamed
# local, or a reflow elsewhere in the same function moves nothing — at ANY column, including one
# further LEFT than the copy. That noise floor is asserted in the self-test, in both directions, and
# both directions were live defects before it was: a dedented line that governs nothing could
# conceal a copy left behind by a narrowing, and could equally invent a disagreement between two
# byte-identical copies.
#
# THIS FILE IS SCANNED TOO, and carries no copy of anything it governs: every shell/YAML fixture
# below is COMPOSED from a fragment that does not match the detector, so the census can read its
# own source without becoming its own consumer. That is asserted, not assumed.
#
# WHO CAN WRITE WHAT THIS READS (AGENTS.md item 5). It reads the CHECKED-OUT TREE, which on a
# `pull_request` run is author-controlled — so a PR that adds a copy AND enrols it here passes. That
# is deliberate and it is not a hole: this grants nothing and admits nothing, so the worst an author
# buys is a visible diff to a trust-surface file, which the arm-side `trust_surface_paths_touched`
# classifier already routes to the human gate. Nothing read here is ever executed, imported,
# `eval`-ed or shelled out to — every input is treated as TEXT, and the only network- or
# credential-touching thing in this module is nothing at all.
#
# RESIDUALS, NAMED. (a) ONE predicate is enrolled today: #1275's head-ref shape gate, the one
# #1315's acceptance names. #1313's `needs:*` glob and #1201's machine-hold exclusion need their own
# cell analysis and are filed as follow-up rather than declared here on a guess — a cell partition
# nobody argued for is a guard that fires on everything. (b) This sees a copy that shares the
# literal; a SEMANTICALLY equivalent copy spelled differently is invisible to it, exactly as
# #1315's option 1 describes. Option 2 (coverage-per-copy) is the complement, not a substitute.
"""predicate-census — no copy of a governed predicate may be left behind by a narrowing (#1315).

Usage:
  predicate-census.py --census      # audit the live tree; exits 1 on any finding
  predicate-census.py --self-test
"""
import argparse
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PR_GATE_WORKFLOW = ".github/workflows/pr-gate.yml"
GATE_JOB = "gate"
INVOCATION = "scripts/predicate-census.py"
CENSUS_FLAG = "--census"

# The kinds of source a copy of a trust predicate has actually hidden in. Every one is measured,
# not guessed: `.sh` (#1275, twice), `.py` (#1313), `.yml` (#756's regex-extracted block, and
# dispatch.yml's own inline planner).
SCANNED_SUFFIXES = (".py", ".sh", ".yml", ".yaml")
# `.yaml` is an accepted spelling with no instance in this tree, so its absence is not a blinding.
REQUIRED_SUFFIXES = (".py", ".sh", ".yml")
SKIPPED_DIRS = frozenset({".git"})

# ---- how a copy is located and fingerprinted (ALL DERIVED) --------------------------------------
# A copy's SITE is `<repo-relative path>::<kind>:<name>` — a name, never a line number. #1275's
# copy has moved twice since it was filed, and a line-numbered allowlist would need re-approval on
# every unrelated edit, which is how a guard gets switched off inside a week.
_PY_DEF = re.compile(r"^\s*(?:def|class)\s+([A-Za-z_]\w*)")
_PY_CONST = re.compile(r"^([A-Za-z_]\w*)\s*(?::[^=]+)?=")
_SH_FN = re.compile(r"^\s*([A-Za-z_][\w:.-]*)\s*\(\)\s*\{")
_YML_STEP = re.compile(r"^\s*-\s*name:\s*(\S.*?)\s*$")
_UNIT_ANCHORS = {
    ".py": (("def", _PY_DEF), ("const", _PY_CONST)),
    ".sh": (("fn", _SH_FN),),
    ".yml": (("step", _YML_STEP),),
    ".yaml": (("step", _YML_STEP),),
}


def unit_at(path, lines, index):
    """PURE: (unit name, anchor line index) for the enclosing named unit of ``lines[index]``.

    The nearest anchor AT OR ABOVE the line wins, so a module-level constant is named by the
    constant it defines (`const:REVIEW_FIX_HEAD_REF_RE`) rather than collapsing every constant in a
    26k-line module into one indistinguishable module-scope site."""
    anchors = _UNIT_ANCHORS.get(os.path.splitext(path)[1], ())
    for line_no in range(index, -1, -1):
        for kind, pattern in anchors:
            found = pattern.match(lines[line_no])
            if found:
                return f"{kind}:{found.group(1)}", line_no
    return "<file>", -1


def _indent(line):
    return len(line) - len(line.lstrip())


# ---- what SYNTACTICALLY OPENS A BLOCK ------------------------------------------------------------
# Decreasing indentation alone does NOT identify an enclosing block. Two kinds of line dedent
# without opening anything, and both are live in this tree:
#
#   a CONTINUATION of a multi-line statement — dispatch.yml's governed copy is the second physical
#     line of `app_pr = (head_repo == repo` / `and re.match(r"^sparq-agent/…", ref) is not None)`,
#     so the copy's own line is indented TEN columns deeper than the statement it belongs to; and
#   an UNRELATED STATEMENT at an outer level — anything earlier in the same unit that happens to be
#     less indented than the copy.
#
# Admitting either into a signature is the defect this block fixes, and it fails in BOTH directions.
# MEASURED on the shipped tree: reconstruct #1275 (leave `run_review`'s copy strict) and add one
# unrelated `unrelated_marker=1` at column 0 inside `run_review`, and the census reported ZERO
# findings — the copy left behind by the narrowing was hidden by a line that governs nothing. The
# mirror is a false alarm: the same line beside `push_fix` alone made the write-path cell
# "DISAGREE WITH ITSELF" while all three copies were byte-identical and unguarded.
#
# So a line joins a guard only if it is a block opener BY SYNTAX. The classifier is deliberately NOT
# selected by file suffix: every file here is already multi-lingual, and reading an inner language
# with the outer one's grammar is what admitted the continuation line above. dispatch.yml is YAML
# holding a shell `run:` body holding a python heredoc — the governed copy is three languages deep —
# and dispatch-claim.py quotes worker-live.sh's shell inside python string literals. A line is an
# opener if ANY of the three grammars says so.
_PY_OPENER = re.compile(
    r"^(?:async\s+)?(?:if|elif|else|for|while|with|try|except|finally|def|class|match|case)\b"
    # ...then either the `:` that opens the suite (a trailing comment is still the same line), or an
    # unclosed bracket/comma/backslash where the HEADER ITSELF continues onto the next line
    # (`for _why, _wl_broken in (` — dispatch-claim's #1288 probe opens a real block that way).
    r".*(?::\s*(?:#.*)?$|[(\[{,\\]$)")
_SH_OPENER = re.compile(
    r"^(?:if|elif|while|until|for|select)\b.*(?:\bthen|\bdo|&&|\|\||\\|\()\s*$"
    r"|^case\b.*\bin\s*$"
    r"|^(?:then|do|else)\s*$"
    r"|^(?:(?:function\s+)?[A-Za-z_][\w:.-]*\s*(?:\(\s*\))?\s*)?\{\s*$")
# A `case` ARM opens a block too, and a narrowing is free to use one. Its pattern is a bare glob
# alternation ending in `)`, so it is admitted only with NO whitespace and no `(` of its own —
# `verdict|ci|rebase)` yes, `linked.update(int(number) for number in re.findall(` no.
_SH_CASE_ARM = re.compile(r"^[^\s()#]+\)\s*$")
# A YAML key whose value is a nested block or a block scalar (`run: |`). A key with an INLINE value
# opens nothing, so `shell: bash` is not an opener and `- name: <step>` — which is the unit anchor
# anyway — is not either. The key must be a PLAIN scalar name: allowing any text before the `:`
# would read the `):` that closes a multi-line python `def` header as a block opener of its own.
_YAML_OPENER = re.compile(r"^(?:-\s+)?[A-Za-z_][\w.-]*\s*:\s*(?:[|>][-+]?\d*)?\s*$")


def is_block_opener(stripped):
    """PURE: does this line OPEN a block that more-indented lines below it sit INSIDE?

    False for a continuation line, a sibling statement, a closer (`fi`/`esac`/`)`) and a comment —
    every one of which can dedent without enclosing anything."""
    return bool(_PY_OPENER.match(stripped) or _SH_OPENER.match(stripped)
                or _SH_CASE_ARM.match(stripped) or _YAML_OPENER.match(stripped))


def guard_prefix(lines, index, anchor):
    """PURE: the chain of BLOCK-OPENERS enclosing ``lines[index]``, outermost first.

    Walking up from the copy, a line at strictly lower indentation BOUNDS the copy's scope — nothing
    at or above that column can be entered again — so it always lowers the threshold; but it joins
    the guard only if `is_block_opener` says it opens a block. A sibling statement, a continuation
    of a multi-line statement, a closing `fi`/`esac`, a comment and a blank line therefore move
    NOTHING, which is what keeps this from firing on every unrelated edit. Lowering the threshold on
    a non-opener is load-bearing in its own right: it is what stops a continuation line's deep
    column from re-admitting an `if` that closed before the copy (dispatch.yml, exactly).

    It is also precisely the fact a narrowing changes. #1275's fix wrapped ONE of four identical
    copies in `if [[ "$self_attested" != true ]]; then` and left the other three alone; this
    function is where that shows up as a difference.

    RESIDUAL, NAMED: enclosure is inferred from INDENTATION, which is the real structure in python
    and YAML and a convention in shell. A block opener spelled in a form no grammar above matches is
    read as a plain statement, so a copy it encloses looks unguarded — the same direction as a
    narrowing left behind, and the reason the opener forms are asserted directly in the self-test
    rather than only through a census row."""
    current, openers = _indent(lines[index]), []
    for line_no in range(index - 1, anchor, -1):
        stripped = lines[line_no].strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _indent(lines[line_no]) < current:
            current = _indent(lines[line_no])
            if is_block_opener(stripped):
                openers.append(stripped)
    return tuple(reversed(openers))


def derive_sites(files, detector):
    """PURE: {site -> signature} for every copy of ``detector`` in ``files`` ({path -> text}).

    A signature is the tuple of (enclosing block-openers, the copy's own stripped line) for each
    copy in that unit, in source order. Two units carrying byte-identical copies under
    byte-identical guards derive byte-identical signatures — which is the whole discriminator."""
    pattern = re.compile(detector)
    sites = {}
    for path in sorted(files):
        lines = files[path].splitlines()
        for index, line in enumerate(lines):
            if not pattern.search(line):
                continue
            unit, anchor = unit_at(path, lines, index)
            sites.setdefault(f"{path}::{unit}", []).append(
                (guard_prefix(lines, index, anchor), line.strip()))
    return {site: tuple(copies) for site, copies in sites.items()}


# ---- the DECLARED half: which predicates are governed, and how their copies are partitioned ------
class Predicate:
    """One governed predicate: its distinguishing literal plus a partition of its copies."""

    def __init__(self, name, detector, cost, cells):
        self.name = name
        self.detector = detector
        self.cost = cost              # what a missed copy SPENDS before it refuses (#1315)
        self.cells = cells            # {cell name -> (site, ...)}

    @property
    def declared_sites(self):
        return {site for sites in self.cells.values() for site in sites}


GOVERNED_PREDICATES = (
    Predicate(
        name="worker-head-ref-shape",
        # THE DISTINGUISHING LITERAL IS THE REGEX SOURCE, not the branch namespace. The namespace
        # alone occurs 206 times in this repository — overwhelmingly as fixture branch names — and
        # a census over it would fire on everything. The namespace followed IMMEDIATELY by the
        # issue-number character class occurs only where the SHAPE is being asserted. The optional
        # `\(` `\)` admit the capturing spelling the module-level constants use.
        detector=r"sparq-agent/issue-\(?\[1-9\]\[0-9\]\*\)?-",
        cost="a review dispatch, a charged round and a real cross-provider model run — discarded "
             "in the shell after every earlier layer admitted — then a terminal park (#1275)",
        cells={
            # #1275/#1288's FOURTH copy. Waived for the #657 self-attested orchestrator class; this
            # cell exists so the waiver cannot silently evaporate. With the `if` gone, this
            # signature equals the write path's and DISTINCTNESS reds.
            "worker-live/review — waived for the self-attested class": (
                "scripts/worker-live.sh::fn:run_review",
            ),
            # The asymmetry worker-live.sh states in prose beside run_review ("run_fix and push_fix
            # keep this line byte-for-byte, because they PUSH COMMITS and a self-attested record
            # must never buy write access to its own branch — design record §3"), made executable.
            # All three must agree with each other, and all three must differ from `review`.
            "worker-live/write path — strict, byte-for-byte (these push commits)": (
                "scripts/worker-live.sh::fn:run_fix",
                "scripts/worker-live.sh::fn:stage_fix",
                "scripts/worker-live.sh::fn:push_fix",
            ),
            "dispatch-claim/review-fix admission constant": (
                "scripts/dispatch-claim.py::const:REVIEW_FIX_HEAD_REF_RE",
            ),
            "dispatch-claim/claim + plan lane constant": (
                "scripts/dispatch-claim.py::const:HEAD_REF_RE",
            ),
            # Quotations of worker-live.sh's own source inside #1288's differential probe. Declared
            # rather than exempted: an undeclared copy here would read as a real consumer, and a
            # copy that disappears from the probe is the probe going vacuous.
            "dispatch-claim/#1288 differential-probe quotations": (
                "scripts/dispatch-claim.py::def:_enable_states",
            ),
            "worker-pr/publish-lane constant": (
                "scripts/worker-pr.py::const:WORKER_HEAD_RE",
            ),
            "worker-pr/provenance reconciler gate": (
                "scripts/worker-pr.py::def:reconcile_provenance",
            ),
            "dispatch/PLAN advisory link derivation": (
                ".github/workflows/dispatch.yml::step:Build ready + deferred issue rows and "
                "snapshot pull requests (target planner code)",
            ),
            "reconcile-conflict-park/lane head constant": (
                "scripts/reconcile-conflict-park.py::const:LANE_HEAD_RE",
            ),
            # The VERSIONED worker branch grammar — a stricter shape (`-<run>-<attempt>`) that
            # parses historical branches rather than admitting a live head. Its own cells, so a
            # change to it is never confused with a change to the gates.
            "backfill-provenance/versioned branch grammar": (
                "scripts/backfill-provenance.py::const:HEAD_RE",
            ),
            "backfill-provenance/versioned branch fragment": (
                "scripts/backfill-provenance.py::const:_BRANCH_V",
            ),
        }),
)


# ---- the audit ----------------------------------------------------------------------------------
def read_tree(root=REPO_ROOT):
    """{repo-relative path -> text} for every scannable source file. An unreadable file RAISES: a
    copy this cannot read is a copy it cannot census."""
    files = {}
    for directory, subdirs, names in os.walk(root):
        subdirs[:] = sorted(name for name in subdirs if name not in SKIPPED_DIRS)
        for name in sorted(names):
            if not name.endswith(SCANNED_SUFFIXES):
                continue
            full = os.path.join(directory, name)
            relative = os.path.relpath(full, root).replace(os.sep, "/")
            with open(full, encoding="utf-8") as handle:
                files[relative] = handle.read()
    return files


def audit_scan(files):
    """Findings about the SCAN itself. A census over a tree it could not see must refuse."""
    if not files:
        return ["the scan read no files at all — census refused (fail closed)"]
    return [f"the scan read zero `{suffix}` files — a census blind to a whole language is the "
            f"#1314 shape (the check cannot see the file where the break lives); refused"
            for suffix in REQUIRED_SUFFIXES
            if not any(path.endswith(suffix) for path in files)]


def audit_predicate(predicate, files):
    """Findings for ONE governed predicate. An empty list means its copies are complete and
    coherent — every other return value names the copy and what missing it costs."""
    findings = []
    derived = derive_sites(files, predicate.detector)
    if not derived:
        return [f"{predicate.name}: the declared literal matches NOTHING in the tree — either the "
                f"predicate was renamed away from its literal or the scan is broken. A census that "
                f"finds no copies is vacuous, never green"]

    declared = predicate.declared_sites
    for site in sorted(set(derived) - declared):
        findings.append(
            f"{predicate.name}: UNDECLARED copy at {site} — a new copy of a governed predicate. "
            f"Enrol it in a cell (and say which existing cell it must agree with), or it is the "
            f"copy the next narrowing misses. Missing it costs {predicate.cost}")
    for site in sorted(declared - set(derived)):
        findings.append(
            f"{predicate.name}: DECLARED copy at {site} is gone — if it moved, re-declare it; if "
            f"it was deleted, retire it here in the same change. Otherwise this census silently "
            f"stops watching a copy it was built to watch")

    signatures = {}
    for cell, sites in sorted(predicate.cells.items()):
        present = {site: derived[site] for site in sites if site in derived}
        if not present:
            continue                                   # already reported as declared-but-gone
        distinct = set(present.values())
        if len(distinct) > 1:
            detail = "; ".join(f"{site} -> {present[site]!r}" for site in sorted(present))
            findings.append(
                f"{predicate.name}: cell {cell!r} DISAGREES WITH ITSELF — its copies are declared "
                f"to be governed identically but derive {len(distinct)} different guards. That is "
                f"a narrowing that stopped part-way through one cell: {detail}")
            continue                                   # do not cascade into a distinctness finding
        signatures[cell] = next(iter(distinct))        # the cell agrees, so this IS its guard

    seen = {}
    for cell, signature in sorted(signatures.items()):
        if signature in seen:
            findings.append(
                f"{predicate.name}: cells {seen[signature]!r} and {cell!r} are declared to be "
                f"governed DIFFERENTLY but now derive the SAME guard {signature!r} — the copy in "
                f"one of them was left behind by a narrowing that changed the other. This is "
                f"#1275 exactly, and it costs {predicate.cost}")
        else:
            seen[signature] = cell
    return findings


def census(files, predicates=GOVERNED_PREDICATES):
    """Every finding about ``files``, deterministically ordered. An empty list means every governed
    predicate's copies are complete and coherent."""
    findings = list(audit_scan(files))
    if findings:
        return findings
    if not predicates:
        return ["no predicate is enrolled — a census over an empty registry is vacuous, never "
                "green (fail closed)"]
    for predicate in predicates:
        findings.extend(audit_predicate(predicate, files))
    return findings


def receipt(files, predicates=GOVERNED_PREDICATES):
    """One machine-readable line, ALWAYS printed — including on the clean run (AGENTS.md item 8: a
    census must always emit, zero row included), so "did this look at anything?" is one grep."""
    copies = sum(len(derive_sites(files, predicate.detector)) for predicate in predicates)
    return (f"predicate-census: files={len(files)} predicates={len(predicates)} "
            f"cells={sum(len(predicate.cells) for predicate in predicates)} sites={copies}")


# ---- the pr-gate seam ---------------------------------------------------------------------------
def assert_census_seam(job):
    """RAISES unless pr-gate's `gate` job runs this census unconditionally, as its whole step body.

    Pinned EXACT-MATCH on the step body, never by containment (AGENTS.md item 6 — every uncaught
    mutant measured on 2026-07-27/28 sat at a workflow `if:`, a step or a call site): `if: false`, a
    `|| true` suffix, a `true ||` prefix, a dropped flag or a leading `#` each leave every token of
    a substring check in place while the census stops deciding."""
    if not isinstance(job, dict):
        raise AssertionError(f"the `{GATE_JOB}` job is missing from the workflow")
    if "if" in job:
        raise AssertionError(f"the `{GATE_JOB}` job carries an `if:` — this census must run on "
                             "every gate run")
    steps = job.get("steps")
    if not isinstance(steps, list):
        raise AssertionError(f"the `{GATE_JOB}` job declares no steps")
    found = [step for step in steps
             if isinstance(step, dict) and INVOCATION in str(step.get("run") or "")]
    if len(found) != 1:
        raise AssertionError(
            f"expected exactly one `{GATE_JOB}` step invoking {INVOCATION}, found {len(found)}")
    step = found[0]
    if "if" in step:
        raise AssertionError(f"the step invoking {INVOCATION} carries an `if:` — a census that can "
                             "be skipped decides nothing")
    if step.get("continue-on-error"):
        raise AssertionError(f"the step invoking {INVOCATION} carries a truthy "
                             "`continue-on-error:` — its findings would annotate and not block")
    lines = [line.strip() for line in str(step.get("run") or "").splitlines() if line.strip()]
    want = ["set -euo pipefail", f"python3 {INVOCATION} {CENSUS_FLAG}"]
    if lines != want:
        raise AssertionError(
            f"the step's `run:` body is {lines!r}, want exactly {want!r} — the whole body must BE "
            f"the invocation, because a prefix, a suffix, a dropped flag or a comment character "
            f"leaves every token in place while the census stops deciding")
    return True


# ---- SELF-TEST ----------------------------------------------------------------------------------
# The shell fixtures are COMPOSED from a namespace fragment that does not itself match the detector
# (it needs the issue-number character class immediately after), so this module carries no copy of
# any predicate it governs. Asserted below — otherwise the census would be its own consumer and
# every reflow of a fixture here would red the gate.
_NS = "sparq-agent/issue-"
_SHAPE = _NS + "[1-9][0-9]*-[A-Za-z0-9._-]+"
_DIE = "die 'unsafe pull request head branch'"
# The four byte-identical worker-live.sh copies, in the two spellings #1275 turns on: the strict
# form the write path keeps, and the form `run_review` takes once the waiver wraps it.
_STRICT_COPY = (f'  [[ "$head_branch" =~ ^{_SHAPE}$ ]] ||\n'
                f"    {_DIE}\n")
_WAIVED_COPY = ('  if [[ "$self_attested" != true ]]; then\n'
                f'    [[ "$head_branch" =~ ^{_SHAPE}$ ]] ||\n'
                f"      {_DIE}\n"
                "  fi\n")
# The line immediately above ONE write-path copy, so an edit can be aimed at that copy alone.
_PUSH_FIX_ANCHOR = '  mkdir -p "$worker_root"\n'
# A statement that dedents PAST the copies it sits beside and opens nothing at all — the shape that
# concealed a left-behind copy in one direction and invented a disagreement in the other.
_DEDENTED_NOISE = "unrelated_marker=1\n"
WORKER_LIVE = "scripts/worker-live.sh"


def _replace_once(files, path, old, new, expect):
    """Apply ONE textual mutant and PROVE it applied. AGENTS.md mutation hygiene: a whole-file
    replace that lands on the wrong occurrence reports a phantom survivor, so the anchor count is
    asserted first and the change is verified afterwards. Returns a NEW overlay."""
    if path not in files:
        raise AssertionError(f"{path} is not in the scanned tree, so this mutant cannot be built — "
                             "the scan stopped reading the file the fixture lives in")
    text = files[path]
    if text.count(old) != expect:
        raise AssertionError(f"the mutant anchor occurs {text.count(old)} times in {path}, want "
                             f"{expect} — it would have landed somewhere unintended")
    mutated = dict(files)
    mutated[path] = text.replace(old, new, 1)
    if mutated[path] == text:
        raise AssertionError(f"the mutant did not change {path}")
    return mutated


def _self_test():
    import contextlib
    import io

    ok = True
    checks = 0

    def chk(name, got, want):
        nonlocal ok, checks
        checks += 1
        good = got == want
        ok = ok and good
        # Values are truncated because one of them is a 6.6k-line shell script; the verdict never
        # is. Rows are extracted line-anchored (`^  FAIL `), never by substring — this suite prints
        # every row's name on the PASS path too (AGENTS.md item 7).
        def brief(value):
            text = repr(value)
            return text if len(text) <= 300 else f"{text[:300]}… ({len(text)} chars)"
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {brief(got)} (want {brief(want)})")

    def reds_with(name, files, needle):
        """A mutant must red, and red for the NAMED reason — not merely produce some finding."""
        findings = census(files)
        chk(f"{name}: reds", bool(findings), True)
        chk(f"{name}: names the defect", any(needle in finding for finding in findings), True)
        return findings

    live = read_tree()

    # ---- (0) THE DERIVATION, before anything is asserted on top of it ----------------------------
    lines = ["fn_a() {", "  if [[ x ]]; then", "    GATE here", "  fi", "}",
             "fn_b() {", "  GATE here", "}"]
    unit_a, anchor_a = unit_at("x.sh", lines, 2)
    unit_b, anchor_b = unit_at("x.sh", lines, 6)
    chk("a shell copy is named by its enclosing function", (unit_a, unit_b), ("fn:fn_a", "fn:fn_b"))
    chk("an enclosed copy derives its block-opener",
        guard_prefix(lines, 2, anchor_a), ("if [[ x ]]; then",))
    chk("an unenclosed copy derives an EMPTY guard", guard_prefix(lines, 6, anchor_b), ())
    # ...and the NOISE FLOOR, asserted rather than hoped (#1315: "a guard that fires on everything
    # is worse than none"): a sibling statement, a comment, a blank line and a closing `fi` all sit
    # at the same or greater indent and must move nothing.
    noisy = ["fn_a() {", "  if [[ x ]]; then", "    local unrelated=1", "", "    # a comment",
             "    GATE here", "  fi", "  local after=2", "}"]
    chk("sibling statements, comments and blanks do not enter the guard",
        guard_prefix(noisy, 5, 0), ("if [[ x ]]; then",))
    # ...and the floor holds at LOWER indentation too, which `noisy` cannot test because every line
    # in it sits at or below the copy's own column. A line that DEDENTS without opening a block
    # governs nothing, so adding or removing it must leave the signature BYTE-IDENTICAL — asserted
    # against the same fixture WITHOUT the line, never against a hand-copied expectation.
    nested = ["fn_a() {", "  if [[ x ]]; then", "    GATE here", "  fi", "}"]
    dedented = ["fn_a() {", "unrelated_marker=1", "  if [[ x ]]; then", "    GATE here",
                "  fi", "}"]
    chk("a lower-indented NON-OPENER before a nested copy leaves the signature unchanged",
        guard_prefix(dedented, 3, 0), guard_prefix(nested, 2, 0))
    chk("...and that unchanged signature is still the REAL enclosing block, not an empty one",
        guard_prefix(dedented, 3, 0), ("if [[ x ]]; then",))
    # The CONTINUATION case, which is dispatch.yml's governed copy exactly: the copy is the second
    # physical line of a statement whose own column is ten to its left. Neither that statement nor
    # the `if` that closed before it began encloses the copy, so the guard is the `for` alone.
    continued = ["def linked(pulls, repo):", "    for pull in pulls:", "        if not ok(pull):",
                 "            raise SystemExit('malformed')", "        app_pr = (head_repo == repo",
                 "                  and re.match('GATE', ref) is not None)"]
    chk("a copy on a CONTINUATION line derives its enclosing block, not its own statement",
        guard_prefix(continued, 5, 0), ("for pull in pulls:",))
    # THE CLASSIFIER ITSELF, both ways — an opener form it fails to recognise reads as a plain
    # statement, so a copy that form encloses looks UNGUARDED, which is the same direction as a
    # narrowing left behind. Every form below is one this repository actually writes.
    for opener in ('if [[ "$x" != true ]]; then', "while read -r line; do", 'case "$x" in',
                   "verdict|ci|rebase)", "else", "run_review() {", "if not ok(head):", "try:",
                   "for _why, _wl_broken in (", "def linked_issue_numbers(pulls, repo):", "run: |"):
        chk(f"a block opener is recognised: {opener!r}", is_block_opener(opener), True)
    for plain in ("app_pr = (head_repo == repo", "unrelated_marker=1", "local fix_round=${X:-}",
                  "fi", "esac", "done", "}", ";;", "_wl_live.replace(", "shell: bash",
                  "):", '"the waiver is REVIEW-ONLY": {',
                  '("the waiver is deleted — the shipped defect this row exists to catch",',
                  "die 'unsafe pull request head branch'",
                  '[[ "$head_branch" =~ ^x$ ]] ||'):
        chk(f"a line that opens NO block is rejected: {plain!r}", is_block_opener(plain), False)
    chk("a module-level python copy is named by its constant, not by the module",
        unit_at("x.py", ["import re", "HEAD_RE = re.compile(r'GATE')"], 1)[0], "const:HEAD_RE")
    chk("a python copy inside a function is named by that function",
        unit_at("x.py", ["def admit(head):", "    if not re.match('GATE', head):"], 1)[0],
        "def:admit")
    chk("a YAML copy is named by its step",
        unit_at("x.yml", ["      - name: Plan rows", "        run: |", "          'GATE'"], 2)[0],
        "step:Plan rows")

    # ---- (1) THE LIVE TREE. #1275's COMPLETE narrowing, as shipped, stays GREEN. -----------------
    chk("the shipped tree — a COMPLETE narrowing — is clean", census(live), [])
    chk("the census read a real tree and a real site set (the receipt cannot report a scan that "
        "did not happen)",
        receipt(live).split(" ", 2)[2], "predicates=1 cells=11 sites=13")
    chk("...and it read more than a handful of files", len(live) > 50, True)
    # ...and the site count TRACKS the tree rather than being a constant the receipt asserts about
    # itself: a receipt that reports the same census whatever it scanned is a fabrication (#937's
    # `apply=false` "census-only preview" that wrote real ledger records). One copy added, one more
    # site reported.
    one_more = dict(live)
    one_more["scripts/zz-receipt-probe.py"] = f'GATE = r"^{_NS}[1-9][0-9]*-"\n'
    chk("the receipt's site count follows the tree it actually scanned",
        receipt(one_more).split(" sites=")[1], "14")
    chk("this module carries no copy of anything it governs, so it is never its own consumer",
        [site for site in derive_sites(live, GOVERNED_PREDICATES[0].detector)
         if site.startswith(INVOCATION)], [])

    # ---- (2) #1275 RECONSTRUCTED: a narrowing that leaves worker-live.sh's copy untouched --------
    # The pre-#1275 tree exactly: every other consumer narrowed, `run_review`'s copy still
    # byte-for-byte identical to the write path's. This is the shipped defect the whole issue is
    # about; it had ZERO test coverage, and 55/55 was green while the lane delivered nothing.
    left_behind = _replace_once(live, WORKER_LIVE, _WAIVED_COPY, _STRICT_COPY, 1)
    findings = reds_with("#1275 reconstructed (run_review left strict)", left_behind,
                         "are declared to be governed DIFFERENTLY but now derive the SAME guard")
    chk("#1275 reconstructed: the finding names the review cell",
        any("worker-live/review" in finding for finding in findings), True)
    chk("#1275 reconstructed: the finding names the write-path cell",
        any("worker-live/write path" in finding for finding in findings), True)
    chk("#1275 reconstructed: the CENSUS half stays silent — the copy is still exactly where it "
        "was, which is why a file-set census alone cannot see this and is not the only assertion",
        any("UNDECLARED" in finding or " is gone" in finding for finding in findings), False)
    # ...and COMPLETING that same narrowing goes green again: one edit, opposite verdict. So the red
    # above is about the narrowing being incomplete, not about the mutant having touched the file.
    completed = _replace_once(left_behind, WORKER_LIVE, _STRICT_COPY, _WAIVED_COPY, 4)
    chk("...and COMPLETING that narrowing is GREEN again", census(completed), [])
    chk("...having restored the shipped text (the completion is #1275's fix, not a different one)",
        completed[WORKER_LIVE] == live[WORKER_LIVE], True)
    # ...and the SAME reconstruction with one unrelated, dedented, non-opening line inside
    # `run_review` ALONE — text that governs nothing and that now differs between the two units.
    # MEASURED on the shipped tree before the opener classifier existed: this census returned ZERO
    # findings, so a line no reviewer would look twice at concealed the exact defect the gate is
    # for. The cells named must be the same two, or the unrelated line moved a signature.
    hidden = _replace_once(live, WORKER_LIVE, _WAIVED_COPY, _DEDENTED_NOISE + _STRICT_COPY, 1)
    findings = reds_with("#1275 reconstructed BEHIND an unrelated dedented line", hidden,
                         "are declared to be governed DIFFERENTLY but now derive the SAME guard")
    chk("...and it collapses the SAME two cells, so the unrelated line altered no signature",
        [cell for cell in ("worker-live/review", "worker-live/write path")
         if not any(cell in finding for finding in findings)], [])

    # ---- (3) the OTHER direction: a narrowing that stops part-way through ONE cell ---------------
    # #1288's own known mutant — the waiver LEAKS into run_fix, which pushes commits. run_fix is
    # then governed differently from stage_fix/push_fix, which are declared to agree with it.
    leaked = _replace_once(live, WORKER_LIVE, _STRICT_COPY, _WAIVED_COPY, 3)
    findings = reds_with("the waiver leaks into run_fix alone", leaked, "DISAGREES WITH ITSELF")
    chk("the leak finding names the copies that now differ",
        all(name in " ".join(findings) for name in ("fn:run_fix", "fn:stage_fix", "fn:push_fix")),
        True)

    # ---- (4) the CENSUS half: a NEW copy, and a DELETED one --------------------------------------
    # In all three scanned languages: #1275's miss was in shell twice and #756's was a
    # regex-extracted YAML block, so a `.py`-only census would have seen none of them.
    for path, body, site in (
            ("scripts/zz-new-consumer.py",
             f'import re\nGATE = re.compile(r"^{_NS}([1-9][0-9]*)-[A-Za-z0-9._-]+$")\n',
             "scripts/zz-new-consumer.py::const:GATE"),
            (".github/workflows/zz-new.yml",
             "      - name: Admit\n        run: |\n"
             f"          re.match(r'^{_NS}[1-9][0-9]*-', ref)\n",
             ".github/workflows/zz-new.yml::step:Admit"),
            ("scripts/zz-new.sh",
             f'zz_gate() {{\n  [[ "$b" =~ ^{_SHAPE}$ ]] || {_DIE}\n}}\n',
             "scripts/zz-new.sh::fn:zz_gate")):
        overlay = dict(live)
        overlay[path] = body
        reds_with(f"a NEW copy in {path}", overlay, f"UNDECLARED copy at {site}")
    dropped = _replace_once(live, WORKER_LIVE, _STRICT_COPY, "  : 'the gate was deleted'\n", 3)
    reds_with("a DECLARED copy deleted", dropped,
              "DECLARED copy at scripts/worker-live.sh::fn:run_fix is gone")
    # ...and when a cell's ONLY copy goes, the census reports the loss and nothing else: an emptied
    # cell must not also fabricate a coherence finding about copies that no longer exist.
    emptied = _replace_once(live, WORKER_LIVE, _WAIVED_COPY, "  : 'the waived copy was deleted'\n", 1)
    findings = reds_with("a whole cell's only copy deleted", emptied,
                         "DECLARED copy at scripts/worker-live.sh::fn:run_review is gone")
    chk("...and the emptied cell fabricates no coherence finding",
        any("DISAGREES" in finding or "SAME guard" in finding for finding in findings), False)

    # THE MUTATION HARNESS ITSELF. A `str.replace` that lands on the wrong occurrence, or on none,
    # reports a phantom survivor — so the guard that prevents it is exercised in both directions,
    # or every "killed" row above is unproven (AGENTS.md mutation hygiene).
    for why, arguments in (
            ("an anchor whose occurrence count is wrong",
             (live, WORKER_LIVE, _STRICT_COPY, "  : 'x'\n", 99)),
            ("a mutant that leaves the text unchanged",
             (live, WORKER_LIVE, _STRICT_COPY, _STRICT_COPY, 3))):
        try:
            _replace_once(*arguments)
            refusal = ""
        except AssertionError as exc:
            refusal = str(exc) or "refused"
        chk(f"the mutation harness refuses {why}", bool(refusal), True)

    # ---- (5) the NOISE FLOOR on the REAL tree. Unrelated edits must stay green. -------------------
    quiet = dict(live)
    quiet[WORKER_LIVE] = (live[WORKER_LIVE]
                          + "\n# an unrelated trailing comment\nzz_unrelated() {\n  :\n}\n")
    chk("an unrelated addition to a governed file stays GREEN", census(quiet), [])
    adjacent = _replace_once(
        live, "scripts/worker-pr.py",
        '    owner = target_repo.split("/", 1)[0]\n',
        '    # an unrelated comment adjacent to a governed copy\n'
        '    owner = target_repo.split("/", 1)[0]\n', 1)
    chk("an unrelated edit ADJACENT to a governed copy stays GREEN", census(adjacent), [])
    # ...including one that DEDENTS past the copy — the false-alarm mirror of the hidden-defect row
    # in (2). The same line beside push_fix's copy alone previously made the write-path cell
    # DISAGREE WITH ITSELF while all three of its copies stayed byte-identical and unguarded, which
    # is a required gate reding on an edit that changed no guard anywhere.
    outdented = _replace_once(live, WORKER_LIVE, _PUSH_FIX_ANCHOR + _STRICT_COPY,
                              _PUSH_FIX_ANCHOR + _DEDENTED_NOISE + _STRICT_COPY, 1)
    chk("an unrelated DEDENTED line beside ONE copy of a cell stays GREEN", census(outdented), [])

    # ---- (5b) THE ENTRY POINT, driven for real ---------------------------------------------------
    # AGENTS.md item 1: helpers get tested because they are easy to call; ENTRY POINTS get skipped
    # because the test has to construct the real world — which is exactly where a fabricating bug
    # survives. So `main` is executed on all three of its routes, and its OUTPUT is read, not only
    # its exit code: a census that exits 1 while printing nothing an operator can act on has
    # reported a defect nobody can locate.
    def run_main(argv, tree=None):
        saved = globals()["read_tree"]
        if tree is not None:
            globals()["read_tree"] = lambda *args, **kwargs: tree
        stream = io.StringIO()
        try:
            with contextlib.redirect_stdout(stream):
                code = main(argv)
        finally:
            globals()["read_tree"] = saved
        # `or [""]` so a mutant that prints NOTHING reds a named row instead of raising an
        # IndexError that aborts the suite — a crash records as a kill while every row below it
        # never runs (AGENTS.md item 4, crash-after-partial-run). Measured: without this, deleting
        # the receipt emission survived with zero named rows.
        return code, (stream.getvalue().splitlines() or [""])

    code, printed = run_main(["--census"])
    chk("main --census exits 0 on the shipped tree", code, 0)
    chk("...and emits its receipt first, on the CLEAN run too (AGENTS.md item 8)",
        printed[0].split(" files=")[0], "predicate-census:")
    chk("...with no error annotation", any("::error::" in line for line in printed), False)
    code, printed = run_main(["--census"], tree=left_behind)
    chk("main --census exits 1 on #1275's incomplete narrowing", code, 1)
    chk("...naming the defect on the annotation channel",
        any(line.startswith("::error::predicate-census: ") and "SAME guard" in line
            for line in printed), True)
    chk("...and STILL emitting the receipt, so the finding carries its scan",
        printed[0].split(" files=")[0], "predicate-census:")
    chk("main with no mode selected is a usage error, never a silent pass", run_main([])[0], 2)

    # ---- (6) FAIL-CLOSED. Every way of seeing less must refuse, never report a clean tree. -------
    chk("an empty scan refuses", bool(census({})), True)
    # The suffixes are spelled out HERE rather than read from REQUIRED_SUFFIXES: an input derived
    # from the same constant the code reads makes the row unfalsifiable (AGENTS.md item 2c — #941's
    # over-cap inputs all derived from STUCK_UNPARK_MAX, so raising it left 76/76 green). Measured
    # on this very suite: with the list read from the constant, emptying REQUIRED_SUFFIXES SURVIVED,
    # because the loop simply stopped running.
    for suffix in (".py", ".sh", ".yml"):
        chk(f"a scan that read no `{suffix}` files refuses",
            any(f"`{suffix}` files" in finding
                for finding in census({path: text for path, text in live.items()
                                       if not path.endswith(suffix)})), True)
    chk("an empty predicate registry refuses", bool(census(live, predicates=())), True)
    # Composed, for the same reason the shell fixtures above are: written as one literal it would
    # occur in this file and the probe would silently stop being a no-match probe.
    blinded = Predicate(name="blinded", detector="zz-no-such" + "-literal-anywhere-in-this-tree",
                        cost="x", cells={"only": ("scripts/worker-live.sh::fn:run_review",)})
    chk("a predicate whose literal matches nothing refuses rather than reading clean",
        any("matches NOTHING" in finding for finding in census(live, predicates=(blinded,))), True)

    # ---- (7) THE INSTRUMENT. A discriminator that cannot report a difference proves nothing. -----
    shape_sites = derive_sites(live, GOVERNED_PREDICATES[0].detector)
    chk("the bare namespace censuses far more sites than the shape gate, so the distinguishing "
        "literal is load-bearing rather than decorative",
        len(derive_sites(live, _NS)) > 3 * len(shape_sites), True)
    chk("the shipped tree carries exactly the declared sites, by name",
        sorted(shape_sites), sorted(GOVERNED_PREDICATES[0].declared_sites))
    chk("...and #1275's own copy is one of them",
        "scripts/worker-live.sh::fn:run_review" in shape_sites, True)

    # ---- (8) the seams: the suite manifest, then the LIVE workflow -------------------------------
    # The census runs in `gate` twice over — once as `--census` (the named, legible step) and once
    # through this self-test, which asserts the shipped tree is clean. Enrolment is what makes the
    # second true, so it is asserted here rather than assumed; a suite entry can only be RETIRED
    # with base-branch approval in scripts/selftest-retirements.txt.
    with open(os.path.join(REPO_ROOT, "scripts", "selftest-suite.txt"), encoding="utf-8") as handle:
        chk("seam: enrolled in scripts/selftest-suite.txt, so pr-gate runs this self-test",
            "predicate-census.py" in handle.read().split(), True)


    document = None
    try:
        import yaml
    except ImportError as exc:
        chk("PyYAML is available to read the LIVE workflow seam", f"unavailable ({exc})", "")
    else:
        with open(os.path.join(REPO_ROOT, PR_GATE_WORKFLOW), encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    live_job = ((document or {}).get("jobs") or {}).get(GATE_JOB)

    def refused(job):
        try:
            assert_census_seam(job)
        except AssertionError as exc:
            return str(exc) or "refused"
        return ""

    chk("LIVE pr-gate.yml runs this census unconditionally, as the whole step body",
        refused(live_job), "")
    if live_job:
        def with_step(mutate):
            job = {key: value for key, value in live_job.items() if key != "steps"}
            job["steps"] = [dict(step) if isinstance(step, dict) else step
                            for step in live_job["steps"]]
            for step in job["steps"]:
                if isinstance(step, dict) and INVOCATION in str(step.get("run") or ""):
                    mutate(step)
            return job

        without_step = {key: value for key, value in live_job.items() if key != "steps"}
        without_step["steps"] = [step for step in live_job["steps"]
                                 if not (isinstance(step, dict)
                                         and INVOCATION in str(step.get("run") or ""))]
        for name, job in (
                ("the census step is deleted", without_step),
                ("the census step is made conditionally inert",
                 with_step(lambda step: step.update({"if": "${{ false }}"}))),
                ("the census step is made advisory",
                 with_step(lambda step: step.update({"continue-on-error": True}))),
                ("the census verdict is suppressed with a `|| true` suffix",
                 with_step(lambda step: step.update(
                     {"run": f"set -euo pipefail\npython3 {INVOCATION} {CENSUS_FLAG} || true\n"}))),
                (f"the `{CENSUS_FLAG}` flag is DROPPED, leaving a bare invocation",
                 with_step(lambda step: step.update(
                     {"run": f"set -euo pipefail\npython3 {INVOCATION}\n"}))),
                ("the whole gate job is made conditional",
                 dict(live_job, **{"if": "${{ false }}"}))):
            chk(f"the seam assertion REDS when {name}", bool(refused(job)), True)

    print("predicate-census self-test", "PASSED" if ok else "FAILED", f"({checks} checks)")
    return 0 if ok else 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="No copy of a governed predicate may be left behind by a narrowing (#1315)")
    parser.add_argument("--census", action="store_true",
                        help="audit the live tree; exit 1 on any finding")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if not args.census:
        print("error: one of --census or --self-test is required", file=sys.stderr)
        return 2
    files = read_tree()
    findings = census(files)
    print(receipt(files))
    for finding in findings:
        print(f"::error::predicate-census: {finding}")
    if findings:
        print(f"::error::predicate-census: {len(findings)} finding(s) — a governed predicate's "
              f"copies are incomplete or incoherent (issue #1315)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
