#!/usr/bin/env python3
"""ONE reader for the `run-name:` a workflow renders — shared by every script that parses it.

WHY THIS FILE EXISTS
--------------------
Several scripts read an Actions run's `display_title` to learn something the orchestration needs:

  * ``groom.py``            claim id  <- ``worker.yml``      (``WORKER_RUN_NAME``, issue #1130)
  * ``select-and-claim.py`` claim id  <- ``review-fix.yml``  (``REVIEW_FIX_RUN_NAME``, issue #1128)
  * ``metrics.py``          target    <- BOTH                (``_run_matches``, issue #1144)

Every one of those is a parse of a string that a **different file** composes. That seam has already
failed once in production: `worker.yml`'s `run-name:` gained a `${{ inputs.target_repo }}` segment
on 2026-07-21 and `groom.py`'s regex did not follow, so for eight days the claim->run correlation
`fullmatch`ed **0 of 100** live worker titles (#1130). Nothing went red, because each consumer's
self-test rendered its OWN hand-written fixture of the title rather than the title the workflow
actually produces.

#1130 and #1128 each fixed their own consumer by hand-writing a renderer of the workflow's
`run-name:` inside that consumer's self-test. That left **two copies of the renderer** and a third
consumer (`metrics.py`) with none — the same shape as #1155's three disagreeing closing-reference
grammars, which was fixed by IMPORTING one definition rather than copying it. This module is that
one definition:

  * :func:`read_run_name` / :func:`render` — the only place that knows how to read a workflow's
    own ``run-name:`` and substitute its ``${{ }}`` expressions.
  * :data:`LANES` — the registry of run-name-carrying lanes and the sample values to render them
    with, so every consumer renders the SAME title from the SAME source.
  * :func:`unregistered_claim_lanes` — a new workflow whose run-name carries a ``claim=``
    correlation token but that no consumer pins is reported here, so a new lane cannot arrive
    un-seamed.
  * :func:`local_run_name_readers` — the AST guard: a consumer that re-declares a renderer of its
    own (the very duplication this module removes) is reported here and its self-test goes red.

FAIL-CLOSED, ALWAYS. An unreadable workflow, a missing `run-name:`, an empty one, or an expression
with no registered sample is an ERROR or a reported ``unknown``, never a silently empty string —
an empty rendering matches nothing and would read as "the seam is fine" to a `fullmatch` assertion
that is only ever asked whether it matched.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
import tempfile
from pathlib import Path
from typing import Iterable, NamedTuple

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"

# Substituted for a `${{ }}` expression that has no registered sample. It is deliberately a string
# no run-name grammar can match, so an unregistered expression breaks the consumer's `fullmatch`
# assertion as well as being reported in `Rendering.unknown` — two independent signals.
UNRENDERED = "<<unrendered-expression>>"

_RUN_NAME_LINE = re.compile(r"(?m)^run-name:[ \t]*(?P<value>[^\r\n]*)$")
_EXPRESSION = re.compile(r"\$\{\{\s*(?P<expr>.*?)\s*\}\}")


# `re` entry points whose literal string arguments are patterns. Used by the AST guard to tell a
# run-name RENDERER's `${{ }}` substitution from an unrelated `${{ }}` string test.
_RE_PATTERN_FUNCS = frozenset(
    {"compile", "sub", "subn", "search", "match", "fullmatch", "findall", "finditer", "split"}
)


class RunNameError(Exception):
    """A workflow's `run-name:` could not be read. Never raised for a MISMATCH — only for a source
    this module cannot honestly render, which callers must surface rather than treat as no match."""


class Rendering(NamedTuple):
    """The result of rendering one workflow's own `run-name:`.

    ``unknown`` is the tuple of ``${{ }}`` expressions with no registered sample — a NEW or RENAMED
    workflow input lands here. ``reached`` is the sample values that actually appear in ``text``,
    which is what lets a consumer assert its render is not vacuous: a run-name that DROPS a segment
    still renders to a perfectly matchable string, and only the missing sample value reveals it.
    """

    text: str
    unknown: tuple[str, ...]
    reached: tuple[str, ...]


class Lane(NamedTuple):
    """One orchestration lane whose `run-name:` a consumer parses."""

    name: str
    workflow: str
    samples: dict[str, str]
    target: str
    claim: str


# The sample values are the ones the existing consumer self-tests already assert against, so this
# module is a change of SOURCE, not of expectation: `select-and-claim.py` still renders
# `review-fix fix o/r#1102 claim=ff..` and `groom.py` still renders `worker sparq-org/sparq
# claim=ee..`. A sample keyed by the expression's EXACT text (not a substring) means a renamed
# input reports as `unknown` instead of quietly reusing the old input's value.
WORKER_LANE = Lane(
    name="worker",
    workflow=".github/workflows/worker.yml",
    samples={
        "inputs.target_repo": "sparq-org/sparq",
        "inputs.claim_id || 'self'": "e" * 32,
    },
    target="sparq-org/sparq",
    claim="e" * 32,
)
REVIEW_FIX_LANE = Lane(
    name="review-fix",
    workflow=".github/workflows/review-fix.yml",
    samples={
        "inputs.mode": "fix",
        "inputs.target_repo": "o/r",
        "inputs.pr_number": "1102",
        "inputs.claim_id || 'self'": "f" * 32,
    },
    target="o/r",
    claim="f" * 32,
)
LANES: tuple[Lane, ...] = (WORKER_LANE, REVIEW_FIX_LANE)

# The scripts that parse a run title. `local_run_name_readers` is applied to each of these by this
# module's self-test, so a consumer that grows its own renderer reds HERE even if its own suite is
# happy with it.
CONSUMERS: tuple[str, ...] = ("groom.py", "select-and-claim.py", "metrics.py")

def _resolve(workflow: str | Path) -> Path:
    path = Path(workflow)
    return path if path.is_absolute() else REPO_ROOT / path


def _read_folded(text: str, value: str, after: int) -> str:
    """Join a YAML folded (`>`) or literal (`|`) block scalar's continuation lines.

    `mint-provenance.yml` really does write its run-name this way, so refusing the shape outright
    would make the lane census below blind to exactly the workflows most likely to grow long.
    """
    chomp = value[:1]
    lines: list[str] = []
    for raw in text[after:].splitlines():
        if raw.strip() and not raw[:1].isspace():
            break
        if raw.strip():
            lines.append(raw.strip())
        elif lines:
            break
    return ("\n" if chomp == "|" else " ").join(lines)


def read_run_name(workflow: str | Path) -> str:
    """Return a workflow's top-level `run-name:` value, unrendered. Fail-closed on every other
    outcome: callers must never receive `""` for a workflow whose run-name they could not read."""
    path = _resolve(workflow)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RunNameError(f"{path}: run-name is unreadable ({exc})") from exc
    match = _RUN_NAME_LINE.search(text)
    if not match:
        raise RunNameError(f"{path}: no top-level run-name:")
    value = match.group("value").strip()
    if value[:1] in (">", "|"):
        value = _read_folded(text, value, match.end())
    elif len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1]
    if not value:
        raise RunNameError(f"{path}: run-name: is empty")
    return value


def render(workflow: str | Path, samples: dict[str, str]) -> Rendering:
    """Render a workflow's own `run-name:` with `samples`, keyed by exact expression text."""
    value = read_run_name(workflow)
    unknown: list[str] = []

    def _substitute(match: re.Match[str]) -> str:
        expression = match.group("expr")
        if expression in samples:
            return samples[expression]
        unknown.append(expression)
        return UNRENDERED

    text = _EXPRESSION.sub(_substitute, value)
    reached = tuple(sorted(v for v in samples.values() if v in text))
    return Rendering(text, tuple(unknown), reached)


def render_lane(lane: Lane) -> Rendering:
    """Render a registered lane's workflow with that lane's sample table."""
    return render(lane.workflow, lane.samples)


def unregistered_claim_lanes() -> list[str]:
    """Workflows whose run-name carries a `claim=` correlation token but that no lane registers.

    This is the census a rename cannot answer: #1130 was a lane that CHANGED, but a lane that
    ARRIVES with a correlation token and no consumer seam is silently uncorrelated from birth, and
    every existing seam stays green through it.
    """
    registered = {lane.workflow for lane in LANES}
    missing: list[str] = []
    for path in sorted(WORKFLOW_DIR.glob("*.yml")):
        try:
            value = read_run_name(path)
        except RunNameError:
            continue  # not a run-name-carrying workflow; nothing to correlate against
        relative = path.relative_to(REPO_ROOT).as_posix()
        if "claim=" in value and relative not in registered:
            missing.append(relative)
    return missing


def local_run_name_readers(source: str | Path) -> list[str]:
    """String literals in `source` that re-implement this module's job.

    AST, not text containment: a whole-file `"run-name:" in text` scan matches this docstring and
    every explanatory comment, so it can only ever fire — the vacuous shape of this guard class.
    This walks the literals the file actually evaluates, with DOCSTRINGS excluded, so prose about
    the seam is free while code that reads the seam is not.

    Two shapes count, because a second renderer needs both halves and the first draft of this
    guard MISSED the half that was actually in the tree:

      * any literal carrying ``run-name:`` — LOCATING the line. This is not always a regex
        (`select-and-claim.py` used `str.startswith`), so it is not restricted to `re.*` arguments.
      * a literal carrying ``${{`` that is an argument to an ``re.*`` call — SUBSTITUTING the
        expressions. Regex literals spell it ``\\$\\{\\{``, which does NOT contain ``${{``, so the
        literal is compared with its backslashes stripped: `select-and-claim.py`'s renderer was
        `re.sub(r"\\$\\{\\{[^}]*\\}\\}", ...)` and a naive scan reported that file CLEAN.

    The ``re.*`` restriction on the second shape is deliberate and load-bearing. `metrics.py`
    legitimately strips ``${{ }}`` from a job `if:` expression with `str.startswith("${{")`, which
    has nothing to do with run-names; flagging that would make this guard cry wolf on a file it
    should pass. A renderer, by contrast, must SUBSTITUTE — and every substitution in this tree is
    a regex. A hand-rolled non-regex substitution is still caught by the locator half, because it
    must find the `run-name:` line before it can render it.
    """
    path = Path(source)
    if not path.is_absolute():
        path = _resolve(source)
    if not path.exists():
        path = REPO_ROOT / "scripts" / str(source)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    }
    regex_literals = {
        id(arg)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", ""))
        in _RE_PATTERN_FUNCS
        for arg in node.args
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
    }
    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if id(node) in docstrings:
            continue
        locates = "run-name:" in node.value
        # A regex spells `${{` as `\$\{\{`; strip the escapes before asking.
        substitutes = "${{" in node.value.replace("\\", "") and id(node) in regex_literals
        if locates or substitutes:
            found.append(node.value)
    return found


def _renders_a_lane(function: ast.AST) -> bool:
    """True if `function` ITSELF calls `render_lane` — nested functions are attributed to
    themselves, so an enclosing function is not credited with its helper's work."""
    stack = list(getattr(function, "body", []))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Attribute) and node.attr == "render_lane":
            return True
        stack.extend(ast.iter_child_nodes(node))
    return False


def _parse_consumer(source: str | Path) -> ast.Module:
    path = Path(source)
    if not path.is_absolute():
        path = _resolve(source)
    if not path.exists():
        path = REPO_ROOT / "scripts" / str(source)
    return ast.parse(path.read_text(encoding="utf-8"))


def lane_rendering_functions(source: str | Path) -> list[str]:
    """The functions in `source` that render a lane's run-name through this module."""
    tree = _parse_consumer(source)
    return sorted(
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _renders_a_lane(node)
    )


def unwired_seam_functions(source: str | Path) -> list[str]:
    """Lane-rendering functions that NOTHING in their own file ever calls.

    A seam check is only a control while something RUNS it. Deleting the one
    `_test_run_name_seam(chk)` line from metrics.py's self-test runner disables the entire #1144
    control while every remaining row stays green — measured: that mutant SURVIVED the first draft
    of this change, which is why this guard exists and why it lives in THIS file rather than in the
    consumer, so silencing it takes an edit to two files instead of one.
    """
    tree = _parse_consumer(source)
    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    return sorted(
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and _renders_a_lane(node)
        and node.name not in called
    )


def _self_test() -> int:
    ok = True

    def check(name: str, got: object, want: object) -> None:
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    # ---- The reader, against the workflows this repo really ships -----------------------------
    for lane in LANES:
        rendering = render_lane(lane)
        check(
            f"[#1144] every {lane.name} run-name expression has a registered sample",
            rendering.unknown,
            (),
        )
        # NOT a restatement of the render: a run-name that DROPS a segment still renders to a
        # matchable string, and this is the only assertion that sees the drop. #1130's defect was
        # exactly a segment appearing; the inverse — one disappearing — must red too.
        check(
            f"[#1144] the {lane.name} render is not vacuous — every sample value reached the title",
            rendering.reached,
            tuple(sorted(lane.samples.values())),
        )
        check(
            f"[#1144] the {lane.name} lane's correlation token survives rendering",
            f"claim={lane.claim}" in rendering.text,
            True,
        )

    check(
        "[#1144] worker.yml renders the title groom.py correlates against",
        render_lane(WORKER_LANE).text,
        f"worker sparq-org/sparq claim={'e' * 32}",
    )
    check(
        "[#1144] review-fix.yml renders the title select-and-claim.py correlates against",
        render_lane(REVIEW_FIX_LANE).text,
        f"review-fix fix o/r#1102 claim={'f' * 32}",
    )

    # ---- Fail-closed: no caller may receive an empty rendering for an unreadable source --------
    with tempfile.TemporaryDirectory() as tmp:
        absent = Path(tmp) / "absent.yml"
        empty = Path(tmp) / "empty.yml"
        empty.write_text("name: x\non: push\n", encoding="utf-8")
        blank = Path(tmp) / "blank.yml"
        blank.write_text("run-name:\n", encoding="utf-8")
        folded = Path(tmp) / "folded.yml"
        folded.write_text(
            "run-name: >-\n  worker ${{ inputs.target_repo }}\n  claim=${{ inputs.claim_id }}\n"
            "on: push\n",
            encoding="utf-8",
        )
        quoted = Path(tmp) / "quoted.yml"
        quoted.write_text('run-name: "worker [${{ inputs.target_repo }}]"\n', encoding="utf-8")
        for label, path in (
            ("a missing workflow", absent),
            ("a workflow with no run-name", empty),
            ("an empty run-name", blank),
        ):
            try:
                got: object = read_run_name(path)
            except RunNameError:
                got = "RunNameError"
            check(f"{label} RAISES rather than rendering to an unmatchable empty string",
                  got, "RunNameError")
        check(
            "a folded (>-) run-name is joined, not truncated to its chomp marker",
            render(folded, {"inputs.target_repo": "o/r", "inputs.claim_id": "a" * 32}).text,
            f"worker o/r claim={'a' * 32}",
        )
        check(
            "a quoted run-name is unquoted",
            render(quoted, {"inputs.target_repo": "o/r"}).text,
            "worker [o/r]",
        )

    # An expression with no sample must be REPORTED, and must also poison the rendering so a
    # consumer that only ever asks "did it match" still goes red.
    unregistered = render(WORKER_LANE.workflow, {"inputs.target_repo": "o/r"})
    check(
        "an expression with no registered sample is reported",
        unregistered.unknown,
        ("inputs.claim_id || 'self'",),
    )
    check(
        "...and poisons the rendered title so a match-only assertion cannot pass through it",
        UNRENDERED in unregistered.text,
        True,
    )

    # ---- Lane census: a new correlation lane cannot arrive un-seamed --------------------------
    check(
        "[#1144] every workflow whose run-name carries `claim=` is a registered lane",
        unregistered_claim_lanes(),
        [],
    )
    # The census is only trustworthy if it can SEE a workflow — a glob that matched nothing would
    # report the same empty list. Validate the instrument against the known population.
    _scanned = [
        p.relative_to(REPO_ROOT).as_posix()
        for p in sorted(WORKFLOW_DIR.glob("*.yml"))
        if _has_run_name(p)
    ]
    check(
        "...and the census is not vacuous: it read every run-name-carrying workflow, "
        "including both registered lanes",
        (len(_scanned) >= len(LANES), sorted(lane.workflow for lane in LANES if lane.workflow in _scanned)),
        (True, sorted(lane.workflow for lane in LANES)),
    )

    # ---- The renderer is IMPORTED, not copied -------------------------------------------------
    # If a consumer ever fails this, it has grown a second renderer and the two will drift — which
    # is how #1130 and #1128 came to need the same fix twice.
    for consumer in CONSUMERS:
        check(
            f"{consumer} declares no run-name reader of its own — it imports this module",
            local_run_name_readers(REPO_ROOT / "scripts" / consumer),
            [],
        )
    # ---- ...and the seam each consumer holds is actually WIRED ---------------------------------
    # Importing this module buys nothing if the function that uses it is never called. Naming the
    # expected function pins WHERE each seam lives, so deleting it, renaming it, or quietly moving
    # the render out of the self-test path reds here rather than passing on an empty list.
    for consumer, expected in (
        ("groom.py", ["_self_test"]),
        ("select-and-claim.py", ["_self_test"]),
        ("metrics.py", ["_test_run_name_seam"]),
    ):
        check(
            f"{consumer} renders a lane through this module, and the check is not vacuous — "
            "the rendering function is named, not merely counted",
            lane_rendering_functions(REPO_ROOT / "scripts" / consumer),
            expected,
        )
        check(
            f"{consumer}'s run-name seam is INVOKED — an unwired control is not a control",
            unwired_seam_functions(REPO_ROOT / "scripts" / consumer),
            [],
        )

    # KNOWN POSITIVES. This detector fails toward "nothing to report", and its first draft did
    # exactly that: it scanned only `re.*` arguments for a literal `${{`, which a regex spells
    # `\$\{\{`, so it reported select-and-claim.py — a file that DID hold a second renderer —
    # clean. Validate it against both real shapes before believing an empty result.
    with tempfile.TemporaryDirectory() as tmp:
        escaped_renderer = Path(tmp) / "escaped_renderer.py"
        escaped_renderer.write_text(
            'import re\n'
            'def render(line):\n'
            '    return re.sub(r"\\$\\{\\{[^}]*\\}\\}", lambda m: "x", line)\n',
            encoding="utf-8",
        )
        plain_locator = Path(tmp) / "plain_locator.py"
        plain_locator.write_text(
            'def find(text):\n'
            '    return [l for l in text.splitlines() if l.startswith("run-name:")]\n',
            encoding="utf-8",
        )
        unrelated_expr = Path(tmp) / "unrelated_expr.py"
        unrelated_expr.write_text(
            '"""Prose is free: this module talks about run-name: seams and ${{ }} all it likes."""\n'
            'def strip_if(text):\n'
            '    # metrics.py\'s REAL shape — an unrelated `if:` expression, not a run-name reader.\n'
            '    return text[3:-2] if text.startswith("${{") and text.endswith("}}") else text\n',
            encoding="utf-8",
        )
        check(
            "KNOWN POSITIVE: the guard sees an ESCAPED-regex renderer "
            "(the shape its first draft missed)",
            local_run_name_readers(escaped_renderer),
            [r"\$\{\{[^}]*\}\}"],
        )
        check(
            "KNOWN POSITIVE: the guard sees a non-regex `run-name:` locator",
            local_run_name_readers(plain_locator),
            ["run-name:"],
        )
        # The other direction. A guard that fired on any `${{` would flag metrics.py's job-`if:`
        # evaluator, and a guard that scanned raw text would flag every comment about the seam.
        check(
            "KNOWN NEGATIVE: unrelated `${{` handling and prose about the seam do NOT fire it",
            local_run_name_readers(unrelated_expr),
            [],
        )

        # Known positive for the WIRING detector, which likewise fails toward an empty list.
        unwired = Path(tmp) / "unwired_seam.py"
        unwired.write_text(
            "def _test_seam(chk):\n"
            "    chk('seam', grammar.render_lane(LANE).text, 'x')\n"
            "\n"
            "def _self_test():\n"
            "    pass  # the seam function above is never called\n",
            encoding="utf-8",
        )
        wired = Path(tmp) / "wired_seam.py"
        wired.write_text(
            "def _test_seam(chk):\n"
            "    chk('seam', grammar.render_lane(LANE).text, 'x')\n"
            "\n"
            "def _self_test():\n"
            "    _test_seam(print)\n",
            encoding="utf-8",
        )
        check(
            "KNOWN POSITIVE: the wiring guard sees a seam function nothing calls",
            unwired_seam_functions(unwired),
            ["_test_seam"],
        )
        check(
            "KNOWN NEGATIVE: ...and passes the identical file once that call exists — it reads "
            "the CALL, not the function's name",
            unwired_seam_functions(wired),
            [],
        )

    print("run_name_grammar self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def _has_run_name(path: Path) -> bool:
    try:
        read_run_name(path)
    except RunNameError:
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true", help="run the self-test suite")
    parser.add_argument("--print-lane", help="print a lane's rendered run-name")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if args.print_lane:
        for lane in LANES:
            if lane.name == args.print_lane:
                print(render_lane(lane).text)
                return 0
        print(f"unknown lane {args.print_lane!r}", file=sys.stderr)
        return 2
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
