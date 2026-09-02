#!/usr/bin/env python3
# [SPARQ agent] registry #2184: ONE owner for the workflow-`if:` seam idiom that the provenance
# lane's three YAML-seam readers each carried a private copy of.
"""workflow_if.py — read a workflow node's `if:`, and the canonical text of the default-branch ref
guard the provenance lane's secret-reading jobs are pinned to.

WHY THIS EXISTS (registry #2184 — the AGENTS.md §#958 shape). Three readers derive the SAME two
facts about a job-level `if:`:

  * `backfill-provenance.backfill_workflow_seam_report` (#1619),
  * `mint-provenance.mint_workflow_seam_report`, and
  * `auto-mint-provenance.sweep_workflow_seam_report` (both #223, the sol-audit arbitrary-ref
    follow-through).

Each derived `(declared, text)` with its own four private lines, and each pinned its workflow's
guard with its own hand-transcribed constant — two of the three byte-identical. One rule, three
definitions, no owner: a change to what a default-branch guard must look like had to be found in
three places, and #945 measured the cost of exactly that shape directly (two copies of one guard
make each copy INDIVIDUALLY UNKILLABLE, because removing either alone leaves the suite green).

WHAT THIS MODULE OWNS

  * `if_condition(node)` — PRESENCE and VALUE as two separate facts. They are DIFFERENT failures
    (#1619) and must never collapse into one finding. A **missing** job `if:` runs a
    secret-reading job from ANY ref — the arbitrary-ref class the guard exists for, the
    fail-OPEN direction. `if: false`, or the shipped guard with `&& false` appended, keeps a guard
    that READS as hardened while disabling the lane entirely — the fail-CLOSED-forever direction,
    indistinguishable from a drained population (sparq #4743 shipped exactly that). A containment
    probe over the text (`"github.ref ==" in guard`) is blind to the second AND to
    `always() || <the guard>`, which re-admits every ref while satisfying every substring.

  * `DEFAULT_BRANCH_REF_EXPR` / `DEFAULT_BRANCH_REF_GUARD` — the guard text, transcribed BY HAND
    from `.github/workflows/*.yml` and NEVER derived from any reader (AGENTS.md pre-flight 2b: an
    expected value read back out of the code that produces it is a tautology that cannot fail).
    This module reads no workflow and produces no `if:`, so a consumer asserting a live workflow
    against these constants is still comparing two independent derivations.

WHAT IT DOES NOT OWN. The per-workflow EXPECTATION stays with the reader that asserts it — the
mint job's guard is exactly `DEFAULT_BRANCH_REF_GUARD`, the sweep's is that expression with its
`schedule` carve-out disjoined in front, and each reader's own `--self-test` is what pins its own
workflow. This module is the shared spelling, not a shared assertion.

WHITESPACE, AND ONLY WHITESPACE, IS NORMALISED. GitHub's expression evaluation does not depend on
it, so a YAML reflow is not a security event and must not red a consumer: `auto-mint-provenance.yml`
writes its guard as a `>-` folded scalar whose line breaks PyYAML may legitimately render as either
a space or a newline. Every TOKEN and its ORDER stay pinned exactly — normalising whitespace is not
normalising structure, and `<guard> && false`, `always() || <guard>` and a reordered disjunction all
stay distinct from the canonical text. (#2184 reconciled the one difference between the three
copies here: `backfill-provenance._if_condition` returned the RAW parsed text, which was adequate
only because its workflow writes plain single-line scalars.)
"""
import sys

# Transcribed BY HAND from the `if:` of every secret-reading provenance job —
# `.github/workflows/mint-provenance.yml`, `backfill-provenance.yml` (both jobs) and
# `auto-mint-provenance.yml` (as the second disjunct). The EXPRESSION is kept bare so a consumer
# whose guard carries extra clauses can compose it into a `${{ }}` of its own without nesting one.
DEFAULT_BRANCH_REF_EXPR = ("github.ref == format('refs/heads/{0}', "
                          "github.event.repository.default_branch)")
DEFAULT_BRANCH_REF_GUARD = "${{ " + DEFAULT_BRANCH_REF_EXPR + " }}"


def if_condition(node):
    """`(declared, condition)` for one workflow node's `if:` — presence AND value, never a
    containment probe over the value (#1619, #223, AGENTS.md pre-flight 6).

    `condition` is the whitespace-normalised text of the declared expression, and `""` when none is
    declared. `str()` on the declared value, NOT `value or ""`: PyYAML parses `if: false` to the
    boolean `False` and a bare `if:` to `None`, so the `or ""` form would report a NEUTERED job
    identically to one carrying no guard at all — collapsing the two directions this function
    exists to keep apart.

    A node that is not a mapping (a malformed or deleted job) reports `(False, "")` rather than
    raising: a seam reader that raises aborts its caller's self-test mid-run, and a crash records
    as a kill while every check below it never runs (AGENTS.md pre-flight 4). `(False, "")` is also
    the fail-CLOSED answer — every consumer asserts `declared is True`, so an unreadable node reds
    a named row instead of vanishing."""
    if not isinstance(node, dict) or "if" not in node:
        return (False, "")
    return (True, " ".join(str(node["if"]).split()))


def _self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    def reports(name, node, want, reader=None):
        """A RAISE is a named FAIL row, never an abort: this module's whole job is to keep three
        self-test suites running over a workflow that has been mutated underneath them, and a
        mutant that dies inside the assertion itself records as a kill while every row below it
        never runs (AGENTS.md pre-flight 4)."""
        nonlocal ok
        try:
            got = (reader or if_condition)(node)
        except Exception as exc:                      # noqa: BLE001 — a raise IS the finding here
            got = f"RAISED {type(exc).__name__}"
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    guard = DEFAULT_BRANCH_REF_GUARD

    # ---- PRESENCE and VALUE are two facts (#1619) ------------------------------------------------
    reports("a node with no `if:` reports NOT declared, with an empty condition", {}, (False, ""))
    reports("a declared guard reports declared, with its text", {"if": guard}, (True, guard))
    # The `or ""` form this replaces reported the next two IDENTICALLY to the row above.
    reports("`if: false` — the BOOLEAN PyYAML parses it into — is DECLARED, not absent",
            {"if": False}, (True, "False"))
    reports("a bare `if:` (PyYAML: None) is DECLARED too", {"if": None}, (True, "None"))
    chk("...so a NEUTERED job is distinguishable from a job with NO guard at all "
        "(the `value or \"\"` form collapses exactly these)",
        if_condition({"if": False}) == if_condition({}), False)
    chk("...and from a job whose guard is the shipped one",
        if_condition({"if": False}) == if_condition({"if": guard}), False)

    # ---- a non-mapping node must FAIL CLOSED, and must not abort the caller's suite --------------
    for _node in (None, [], ["if"], "if: false", 7, False):
        reports(f"a node that is not a mapping ({_node!r}) reports no declared guard, and no raise",
                _node, (False, ""))

    def _raising_reader(node):
        raise RuntimeError("this reader is broken")

    # POSITIVE CONTROL for the six rows above: they are the only rows here that assert an ABSENCE
    # of raising, so a harness that silently swallowed a raise would pass them while measuring
    # nothing. This row drives the same harness with a reader that DOES raise and requires the
    # raise to come back as a value — i.e. the rows above are reading `if_condition`'s behaviour,
    # not the harness's.
    reports("CONTROL: a reader that RAISES becomes a named row, it does not abort this suite",
            {"if": guard}, "RAISED RuntimeError", reader=_raising_reader)

    # ---- whitespace, and ONLY whitespace, is normalised ------------------------------------------
    # The `>-` fold in auto-mint-provenance.yml: PyYAML may render its break as either of these.
    _folded_space = "${{ github.event_name == 'schedule' || " + DEFAULT_BRANCH_REF_EXPR + " }}"
    _folded_newline = ("${{ github.event_name == 'schedule'\n          || "
                       + DEFAULT_BRANCH_REF_EXPR + " }}")
    chk("both renderings PyYAML may give a `>-` folded guard normalise to ONE condition",
        if_condition({"if": _folded_newline})[1], _folded_space)
    chk("...and leading/trailing whitespace normalises away as well",
        if_condition({"if": f"\n  {guard}  \n"})[1], guard)
    chk("the canonical guard is ALREADY normalised — a stray double space in the constant would "
        "red every consumer's exact-match against a CORRECT workflow",
        if_condition({"if": guard})[1], guard)
    chk("the shared EXPRESSION is bare, so a consumer composing it into its own `${{ }}` "
        "(the sweep's schedule carve-out) cannot nest a second wrapper",
        ("${{" in DEFAULT_BRANCH_REF_EXPR, "}}" in DEFAULT_BRANCH_REF_EXPR), (False, False))

    # ---- normalising whitespace is NOT normalising STRUCTURE -------------------------------------
    # Every mutant below keeps the shipped guard spelled out in full, so the containment probe this
    # idiom replaced (`"github.ref ==" in guard and "default_branch" in guard`) is True on all of
    # them. Each must still come back DIFFERENT from the canonical text.
    _widened = {
        "&& false": "hardened-looking, but permanently skipped",
        "|| always()": "runs from ANY ref — the arbitrary-ref class itself",
        "|| github.event_name == 'workflow_dispatch'": "the dispatch path re-admitted from any ref",
    }
    for _tail, _effect in _widened.items():
        _mutant = f"${{{{ {DEFAULT_BRANCH_REF_EXPR} {_tail} }}}}"
        chk(f"a guard that keeps every substring but gains `{_tail}` is NOT the canonical guard "
            f"({_effect})",
            if_condition({"if": _mutant})[1] == guard, False)
    chk("...and the CONTROL: a containment probe would have passed every one of them",
        all("github.ref ==" in f"{tail}{DEFAULT_BRANCH_REF_EXPR}"
            and "default_branch" in f"{tail}{DEFAULT_BRANCH_REF_EXPR}" for tail in _widened),
        True)
    chk("TOKEN ORDER survives normalisation (a reordered disjunction is a different condition)",
        if_condition({"if": "${{ b || a }}"})[1] == if_condition({"if": "${{ a || b }}"})[1],
        False)
    chk("...and so does every token (a dropped conjunct is a different condition)",
        if_condition({"if": "${{ a && b }}"})[1] == if_condition({"if": "${{ a }}"})[1], False)

    # ---- the ENTRY POINT, which nothing above reaches (AGENTS.md pre-flight 1) -------------------
    # `main` is 4 lines and the suite would otherwise leave half of them at zero — the region where
    # a mutant survives, measured four times on this repo. Driven with a real argv, restored after.
    _argv = sys.argv
    try:
        sys.argv = ["workflow_if.py"]
        chk("`main` without --self-test summarises the module and exits 0 (it never mints, reads "
            "a workflow, or touches the network)", main(), 0)
    finally:
        sys.argv = _argv

    print("workflow_if self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    if "--self-test" in sys.argv:
        return _self_test()
    print(__doc__.strip().splitlines()[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
