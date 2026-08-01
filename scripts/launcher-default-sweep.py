#!/usr/bin/env python3
"""Standing check: no parameter default in `scripts/*.py` may BIND A PROCESS LAUNCHER.

WHY THIS FILE EXISTS
--------------------
A Python default is evaluated ONCE, at import. So::

    def _secret_write(token, repo, run=subprocess.run):   # issue #992, pat-validity.py
        run(["gh", "secret", "set", ...])                 # ...a WRITE

captures the real launcher permanently, and that has two consequences that only ever bite in
production:

  * **One forgotten keyword is a live mutation.** Every call site today passes ``run=`` a fake, so
    the module measures zero escapes. A NEW call site that omits it gets the real
    ``subprocess.run`` and issues a live ``gh secret set --env dispatch-secrets``.
  * **The seam a test can actually reach does not reach it.** Patching ``subprocess.run`` on the
    module — the only interception available without editing the call site — cannot touch a
    default already bound at import. The test goes green having intercepted nothing.

The runtime control for this class is the self-test sandbox, which catches an escape however it is
spelled. This is the SOURCE-level half: the shape is reported before it ships, and a new instance
cannot arrive silently.

WHAT IS AND IS NOT REPORTED
---------------------------
Only **process launchers** (:data:`LAUNCHERS`) — the callables whose accidental invocation runs a
command against the real world. Defaults binding ``time.sleep``, ``random.uniform`` or
``sys.stderr`` are legitimate injection seams whose worst accidental outcome is a slow or noisy
test, and this repo has 17 such Attribute-shaped defaults; flagging them would make the check cry
wolf on every retry helper in the tree. The rule is about *reachable damage*, not about the syntax.

BOTH NODE TYPES, AND THAT IS THE POINT
--------------------------------------
The first sweep for this class matched only :class:`ast.Name` defaults (``gh=run_gh``) and
therefore reported CLEAN on :class:`ast.Attribute` ones (``run=subprocess.run``) — that is, it
failed toward "nothing to report" on exactly the spelling the live defect was written in. So both
arms exist here and both are pinned by a KNOWN POSITIVE:

  * :class:`ast.Attribute` — ``run=subprocess.run``, including an aliased module
    (``import subprocess as sp`` -> ``run=sp.Popen``).
  * :class:`ast.Name` — ``run=_run`` where ``_run`` is bound to a launcher by
    ``from subprocess import run as _run`` or by ``_run = subprocess.run``.

⚠️ The Name arm has **no live instance in this repo today** (measured: 288 Name-shaped defaults,
none resolving to a launcher). It is proven by synthetic fixtures only, and that is stated rather
than left to be read as coverage.

FAIL-CLOSED. A script that cannot be parsed raises :class:`SweepError` — it is never skipped,
because a skipped file and a clean file produce the identical empty result.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import io
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
SUITE_MANIFEST = "scripts/selftest-suite.txt"

# The `subprocess` attributes that START A PROCESS. `PIPE`/`DEVNULL`/`CompletedProcess` are inert
# constants and types, so binding one as a default can do no damage and is not reported.
LAUNCHERS = frozenset({
    "run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput",
})


class SweepError(RuntimeError):
    """A file the sweep could not read. Raised, never swallowed: an unparseable script must not
    reduce to the same empty finding list as a clean one."""


class Finding(NamedTuple):
    """`lineno` is the OFFENDING PARAMETER's line; `def_lineno` is the enclosing `def`'s.

    They are the same line for a one-line signature and different for a wrapped one, and #992
    measured the confusion that costs: an AST sweep reporting only the `def` line (246) and a
    reader citing the parameter (251) described the SAME finding with two numbers, and the
    mismatch was read as two disagreeing claims. Both are rendered whenever they differ, so a
    finding can be cited either way without anyone having to reconcile them."""

    path: str
    lineno: int
    def_lineno: int
    function: str
    parameter: str
    default: str

    def render(self) -> str:
        where = (f"{self.path}:{self.lineno}" if self.lineno == self.def_lineno
                 else f"{self.path}:{self.lineno} (def at {self.path}:{self.def_lineno})")
        return f"{where} {self.function}({self.parameter}={self.default})"


class Census(NamedTuple):
    """Findings PLUS the population they were drawn from.

    The counts are not decoration. `findings == []` is the answer this check wants to give and
    also the answer it gives when it read nothing at all, so a caller (and the self-test) can only
    trust an empty list next to evidence that the walker reached real parameter defaults of BOTH
    node shapes."""

    findings: tuple[Finding, ...]
    files: int
    defaults: int
    attribute_defaults: int
    name_defaults: int


def _module_launcher_aliases(tree: ast.AST) -> tuple[set[str], set[str]]:
    """(names bound to the `subprocess` MODULE, names bound to a launcher CALLABLE).

    Both import spellings and the assignment spelling, because the Name arm is worthless if it
    only recognises the literal identifiers a launcher happens to be called today:

        import subprocess as sp            -> module alias  {"subprocess", "sp"}
        from subprocess import run as _run -> callable alias {"_run"}
        _run = subprocess.run              -> callable alias {"_run"}

    Assignments are collected from ANYWHERE in the file, not just module level. A function-local
    ``run = subprocess.run`` used as a nested default is exotic, but the direction of the error
    matters more than the tidiness: over-collecting names can only make this check report MORE,
    and this check's failure mode of record is reporting less.
    """
    module_aliases = {"subprocess"}
    callable_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "subprocess":
                    module_aliases.add(alias.asname or "subprocess")
        elif isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            for alias in node.names:
                if alias.name in LAUNCHERS:
                    callable_aliases.add(alias.asname or alias.name)
    # A second pass: `_run = sp.run` can only be resolved once the module aliases are known.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        if not (isinstance(value, ast.Attribute)
                and value.attr in LAUNCHERS
                and isinstance(value.value, ast.Name)
                and value.value.id in module_aliases):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                callable_aliases.add(target.id)
    return module_aliases, callable_aliases


def _binds_launcher(default: ast.expr, module_aliases: set[str], callable_aliases: set[str]) -> bool:
    """The two-node-type test. Attribute: `<subprocess-alias>.<launcher>`. Name: an identifier this
    file bound to a launcher. Anything else — a literal, a call, a lambda, `time.sleep`, a local
    helper — is not a launcher and is not this check's business."""
    if isinstance(default, ast.Attribute):
        return (default.attr in LAUNCHERS
                and isinstance(default.value, ast.Name)
                and default.value.id in module_aliases)
    if isinstance(default, ast.Name):
        return default.id in callable_aliases
    return False


def _defaults_of(node: ast.AST) -> list[tuple[str, ast.expr]]:
    """Every (parameter, default) pair of one def/lambda, positional and keyword-only alike.

    Keyword-only defaults live in a parallel list padded with `None` for the parameters that have
    none — a `def f(*, run=subprocess.run)` is the same defect as the positional spelling and is
    invisible to a walker that reads `args.defaults` only.
    """
    spec = node.args
    positional = spec.posonlyargs + spec.args
    bound = positional[len(positional) - len(spec.defaults):] if spec.defaults else []
    pairs = [(arg.arg, default) for arg, default in zip(bound, spec.defaults)]
    pairs += [(arg.arg, default)
              for arg, default in zip(spec.kwonlyargs, spec.kw_defaults)
              if default is not None]
    return pairs


def scan_source(text: str, label: str) -> tuple[list[Finding], int, int, int]:
    """(findings, defaults seen, Attribute-shaped defaults, Name-shaped defaults) for one file."""
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        raise SweepError(f"{label}: unparseable ({exc.__class__.__name__}) — refusing to "
                         "report it as clean") from exc
    module_aliases, callable_aliases = _module_launcher_aliases(tree)
    findings: list[Finding] = []
    seen = attributes = names = 0
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        function = getattr(node, "name", "<lambda>")
        for parameter, default in _defaults_of(node):
            seen += 1
            attributes += isinstance(default, ast.Attribute)
            names += isinstance(default, ast.Name)
            if _binds_launcher(default, module_aliases, callable_aliases):
                findings.append(Finding(label, default.lineno, node.lineno, function, parameter,
                                        ast.unparse(default)))
    return findings, seen, attributes, names


def scan_file(path: Path, label: str | None = None) -> list[Finding]:
    """The findings of one file on disk."""
    name = label if label is not None else path.name
    return scan_source(path.read_text(encoding="utf-8"), name)[0]


def sweep(root: Path = SCRIPTS_DIR) -> Census:
    """Every `*.py` under `root`, with the population it was drawn from."""
    findings: list[Finding] = []
    files = defaults = attributes = names = 0
    for path in sorted(root.glob("*.py")):
        found, seen, attrs, plain = scan_source(path.read_text(encoding="utf-8"), path.name)
        findings.extend(found)
        files += 1
        defaults += seen
        attributes += attrs
        names += plain
    if files == 0:
        raise SweepError(f"no *.py found under {root} — an empty sweep is not a clean sweep")
    return Census(tuple(findings), files, defaults, attributes, names)


def _report(census: Census, stream=None) -> int:
    # `stream=sys.stdout` would be the same import-time binding this module exists to report, one
    # LAUNCHERS membership test away from being reportable — and it bites immediately: bound at
    # import, it is deaf to `contextlib.redirect_stdout`, so this module's own self-test could not
    # capture its output. Resolve at call time, like every seam should.
    stream = sys.stdout if stream is None else stream
    for finding in census.findings:
        print(f"launcher-default-sweep: {finding.render()}", file=stream)
    print(f"launcher-default-sweep: {len(census.findings)} finding(s) across {census.files} file(s)"
          f"; {census.defaults} parameter defaults read"
          f" ({census.attribute_defaults} attribute-shaped, {census.name_defaults} name-shaped)",
          file=stream)
    return 1 if census.findings else 0


def _self_test() -> int:
    ok = True

    def check(name: str, got: object, want: object) -> None:
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    census = sweep()

    # ---- The standing assertion ---------------------------------------------------------------
    check("[#992] no scripts/*.py binds a process launcher as a parameter default",
          [f.render() for f in census.findings], [])

    # ---- ...and the instrument that produced it is not blind -----------------------------------
    # An empty finding list is also what a glob that matched nothing, a walker that never reached a
    # default, or an arm that never fired returns. Each of these pins a DIFFERENT way to get a
    # false clean, and the attribute count is the one the first draft of this sweep failed.
    check("the sweep read every scripts/*.py on disk (a glob that matched nothing reports clean)",
          census.files, len(list(SCRIPTS_DIR.glob("*.py"))))
    check("...and that population is the real tree, not a stub",
          census.files >= 40, True)
    check("...and the walker actually reached parameter defaults",
          census.defaults >= 500, True)
    check("...including ATTRIBUTE-shaped ones — the spelling the first sweep for this class "
          "matched zero of, so it reported clean on the live defect",
          census.attribute_defaults >= 5, True)
    check("...and NAME-shaped ones", census.name_defaults >= 50, True)

    # ---- The issue's named subject -------------------------------------------------------------
    check("[#992] pat-validity.py's _secret_write no longer binds subprocess.run — the write probe "
          "resolves its runner at call time",
          [f.render() for f in scan_file(SCRIPTS_DIR / "pat-validity.py")], [])

    # ---- KNOWN POSITIVES: both node types, both alias spellings, both parameter kinds -----------
    # This detector fails toward "nothing to report", so an empty result is worth nothing until it
    # has been shown to fire on every shape it claims to cover.
    attribute_case = (
        "import subprocess\n"
        "def _secret_write(token, repo, run=subprocess.run):\n"
        "    return run(['gh', 'secret', 'set', 'X'])\n"
    )
    check("KNOWN POSITIVE (ast.Attribute): the #992 shape verbatim",
          [f.render() for f in scan_source(attribute_case, "fixture.py")[0]],
          ["fixture.py:2 _secret_write(run=subprocess.run)"])

    aliased_module = (
        "import subprocess as sp\n"
        "def launch(argv, spawn=sp.Popen):\n"
        "    return spawn(argv)\n"
    )
    check("KNOWN POSITIVE (ast.Attribute, aliased module): `import subprocess as sp` does not "
          "hide it — the arm resolves the alias, it does not match the literal 'subprocess'",
          [f.render() for f in scan_source(aliased_module, "fixture.py")[0]],
          ["fixture.py:2 launch(spawn=sp.Popen)"])

    imported_name = (
        "from subprocess import check_output as _out\n"
        "def read(argv, runner=_out):\n"
        "    return runner(argv)\n"
    )
    check("KNOWN POSITIVE (ast.Name, from-import alias): the arm the two-node-type rule exists "
          "for — a bare identifier that IS a launcher",
          [f.render() for f in scan_source(imported_name, "fixture.py")[0]],
          ["fixture.py:2 read(runner=_out)"])

    assigned_name = (
        "import subprocess\n"
        "_LAUNCH = subprocess.check_call\n"
        "def go(argv, runner=_LAUNCH):\n"
        "    return runner(argv)\n"
    )
    check("KNOWN POSITIVE (ast.Name, module-level assignment)",
          [f.render() for f in scan_source(assigned_name, "fixture.py")[0]],
          ["fixture.py:3 go(runner=_LAUNCH)"])

    wrapped_signature = (
        "import subprocess\n"
        "def run_gh_read(\n"
        "    argv,\n"
        "    timeout=30,\n"
        "    run=subprocess.run,\n"
        "):\n"
        "    return run(argv)\n"
    )
    check("[#992] a WRAPPED signature is cited BOTH ways — the parameter's line and the def's — "
          "so an AST report and a human reading the offending line describe the same finding",
          [f.render() for f in scan_source(wrapped_signature, "fixture.py")[0]],
          ["fixture.py:5 (def at fixture.py:2) run_gh_read(run=subprocess.run)"])

    keyword_only = (
        "import subprocess\n"
        "def go(argv, *, quiet=True, runner=subprocess.run):\n"
        "    return runner(argv)\n"
    )
    check("KNOWN POSITIVE (keyword-only default): kw_defaults is a SEPARATE list, and a walker "
          "that reads args.defaults alone cannot see this one",
          [f.render() for f in scan_source(keyword_only, "fixture.py")[0]],
          ["fixture.py:2 go(runner=subprocess.run)"])

    # ---- KNOWN NEGATIVES: the check must not fire on the legitimate seams this repo runs on -----
    injection_seams = (
        "import random\n"
        "import sys\n"
        "import time\n"
        "def sleep_backoff(n, sleeper=time.sleep, draw=random.uniform):\n"
        "    sleeper(draw(0, n))\n"
        "def report(msg, stream=sys.stderr):\n"
        "    print(msg, file=stream)\n"
    )
    check("KNOWN NEGATIVE: time.sleep / random.uniform / sys.stderr defaults are legitimate "
          "seams — an accidental call runs no command, and this repo has 17 of them",
          [f.render() for f in scan_source(injection_seams, "fixture.py")[0]], [])

    repaired = (
        "import subprocess\n"
        "def _secret_write(token, repo, run=None):\n"
        "    if run is None:\n"
        "        run = subprocess.run\n"
        "    return run(['gh', 'secret', 'set', 'X'])\n"
    )
    check("KNOWN NEGATIVE: the repaired shape (run=None, resolved in the body) passes — the "
          "check reads the DEFAULT, not the presence of subprocess.run in the file",
          [f.render() for f in scan_source(repaired, "fixture.py")[0]], [])

    same_name_not_a_launcher = (
        "def _helper(argv):\n"
        "    return None\n"
        "def go(argv, run=_helper):\n"
        "    return run(argv)\n"
    )
    check("KNOWN NEGATIVE: a parameter literally named `run` defaulting to a NON-launcher does "
          "not fire — the Name arm resolves the binding, never the parameter's name",
          [f.render() for f in scan_source(same_name_not_a_launcher, "fixture.py")[0]], [])

    inert_attributes = (
        "import subprocess\n"
        "def go(argv, pipe=subprocess.PIPE, kind=subprocess.CompletedProcess):\n"
        "    return pipe\n"
    )
    check("KNOWN NEGATIVE: subprocess PIPE/CompletedProcess are inert — the arm keys on the "
          "LAUNCHER set, not on the module",
          [f.render() for f in scan_source(inert_attributes, "fixture.py")[0]], [])

    # ---- FAIL-CLOSED: an unreadable file must not read as a clean one ---------------------------
    try:
        scan_source("def broken(:\n", "fixture.py")
        unparseable = "returned"
    except SweepError:
        unparseable = "SweepError"
    check("an unparseable script RAISES rather than contributing an empty finding list",
          unparseable, "SweepError")
    try:
        sweep(REPO_ROOT / "policy")   # a real directory with no *.py in it
        empty_root = "returned"
    except SweepError:
        empty_root = "SweepError"
    check("a root with no *.py RAISES — an empty sweep is not a clean sweep", empty_root,
          "SweepError")

    # ---- The exit code is the control, and it must have both values ----------------------------
    # A `--report` that always returned 0 would print findings into a green log forever.
    # Deliberately NOT near the real tree's counts (58 files, ~1850 defaults): a `_report` that
    # ignored its argument and re-swept `scripts/` would render numbers that collide with a
    # realistic fixture and pass. These values appear nowhere else in this repo.
    clean = Census((), 3, 11, 2, 5)
    dirty = Census((Finding("x.py", 1, 1, "f", "run", "subprocess.run"),), 3, 11, 2, 5)
    quiet, loud = io.StringIO(), io.StringIO()
    check("--report exits 0 on a clean census and NONZERO on a finding",
          (_report(clean, stream=quiet), _report(dirty, stream=loud)), (0, 1))
    check("...and the finding is RENDERED with its file:line, not merely counted",
          [line for line in loud.getvalue().splitlines() if "x.py" in line],
          ["launcher-default-sweep: x.py:1 f(run=subprocess.run)"])
    # A census that goes silent when it has nothing to say is indistinguishable from one that did
    # not run — and the quiet tick is exactly when an operator interrogates it. Zero-seal.
    check("a CLEAN census still emits its population line, so silence never means 'clean'",
          quiet.getvalue().strip(),
          "launcher-default-sweep: 0 finding(s) across 3 file(s); 11 parameter defaults read "
          "(2 attribute-shaped, 5 name-shaped)")

    # ---- ...and the CLI carries that exit code out ----------------------------------------------
    # `_report` is a helper; `main` is what a workflow or an operator invokes. Testing the helper
    # alone leaves the arm that reaches it — the branch that decides WHAT is swept and whether the
    # status is returned at all — unexecuted, which is where a `return 0` survives every check.
    with tempfile.TemporaryDirectory() as tmp:
        dirty_root = Path(tmp) / "dirty"
        dirty_root.mkdir()
        (dirty_root / "offender.py").write_text(attribute_case, encoding="utf-8")
        clean_root = Path(tmp) / "clean"
        clean_root.mkdir()
        (clean_root / "repaired.py").write_text(repaired, encoding="utf-8")
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            dirty_rc = main(["--report", "--root", str(dirty_root)])
            clean_rc = main(["--report", "--root", str(clean_root)])
            help_rc = main([])
        check("main --report returns 1 on a tree holding the #992 shape and 0 on the repaired "
              "one, and names the offender",
              (dirty_rc, clean_rc,
               "offender.py:2 _secret_write(run=subprocess.run)" in printed.getvalue()),
              (1, 0, True))
        check("main with no mode prints help and exits 0 (it never silently sweeps)",
              (help_rc, "--report" in printed.getvalue()), (0, True))

    # ---- The seam: this check only stands while something RUNS it -------------------------------
    manifest = (REPO_ROOT / SUITE_MANIFEST).read_text(encoding="utf-8").split()
    check(f"enrolled in {SUITE_MANIFEST}, so pr-gate's sandboxed suite runs this self-test every "
          "wave — an unenrolled standing check is not standing",
          Path(__file__).name in manifest, True)

    print("launcher-default-sweep self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true",
                        help="run the sweep against this repo plus its known positives and exit")
    parser.add_argument("--report", action="store_true",
                        help="print every launcher-bound default under --root (exit 1 if any)")
    parser.add_argument("--root", default=str(SCRIPTS_DIR),
                        help="directory of *.py to sweep (default: this repo's scripts/)")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if args.report:
        return _report(sweep(Path(args.root)))
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
