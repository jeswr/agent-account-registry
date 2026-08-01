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
    ``from subprocess import run as _run``, by ``_run = subprocess.run``, by the ANNOTATED
    spelling of that assignment (``_run: object = subprocess.run``, an :class:`ast.AnnAssign`),
    TRANSITIVELY (``_run = subprocess.run`` then ``_alias = _run``), or from inside a function
    body that says ``global _run`` / ``nonlocal _run`` — which binds in an OUTER namespace, not
    locally.

Those are the same hazard with a rename, a colon, a comma or a keyword in front of it, and a
resolver that recognised only the direct ``_run = subprocess.run`` reported CLEAN on all of them —
handing anyone a one-token bypass of the standing assertion. A default is also read wherever it is
written, including a lambda inside another def's signature. Every spelling above is pinned by its
own known positive below.

A NAME IS RESOLVED WHERE AND WHEN PYTHON WOULD RESOLVE IT
---------------------------------------------------------
A default is evaluated when the ``def`` statement executes, in the scope the ``def`` executes in.
Reading every assignment in the file as one flat, order-free set gets that wrong in three ways that
all report a defect where none exists — ``def helper(): runner = subprocess.run`` taints an
unrelated module-level ``def f(run=runner)``; an assignment written BELOW a def taints the default
above it, which Python evaluated first; and a same-named binding in a sibling function taints a def
that never sees it. So each default is resolved against the bindings its own ``def`` can actually
see: this scope's bindings that precede it, in order and with rebinding respected, layered on the
scopes that enclose it.

Enclosing scopes are the one place order is deliberately NOT enforced, because statically it is not
known: ``def outer(): def inner(r=_LAUNCH)`` genuinely captures a module-level
``_LAUNCH = subprocess.run`` written below ``outer``, since ``outer()`` is called later still. That
case is a known positive below. Over-collection is kept exactly there and nowhere else, because
there the alternative is a MISS, and a miss is this check's failure mode of record.

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


# What one name is bound to, as far as this check cares. A table maps name -> one of these, and a
# name absent from the table is bound to something that is neither (or to nothing yet).
_MODULE = "module"
_LAUNCHER = "launcher"

# Scopes: a name bound inside one of these is NOT visible to its siblings, and the node's own body
# does not execute in the scope the node is written in. `ast.ClassDef` is here because a class body
# is a namespace too — `class C: run = subprocess.run; def m(self, r=run)` resolves `run` in it.
_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


class _ImportedAs(NamedTuple):
    """A binding made by an `import`, which has no value expression to resolve — the import
    statement itself says what the name now holds."""

    kind: str


_IMPORTED_MODULE = _ImportedAs(_MODULE)
_IMPORTED_LAUNCHER = _ImportedAs(_LAUNCHER)


def _assigned_names(targets: list[ast.expr], value: ast.expr) -> list[tuple[str, ast.expr]]:
    """The ``<Name> = <expr>`` pairs one assignment makes, however it is spelled.

    ``ast.Assign`` is not the only assignment node: ``runner: object = subprocess.run`` is an
    :class:`ast.AnnAssign` and binds exactly the same launcher, so a resolver that reads only
    ``Assign`` reports CLEAN on the annotated spelling — a one-colon bypass of the whole check.
    Parallel unpacking (``runner, flag = subprocess.run, True``) is the same bypass with a comma,
    and is split element-wise here.

    KNOWN BOUND, stated rather than implied: a STARRED target (``a, *rest = ...``) makes the two
    sides different lengths and is skipped, and a launcher reached through a call, a container or
    an attribute (``functools.partial(subprocess.run, ...)``, ``TABLE['run']``) is not a Name
    binding at all. Those are under-collection — the direction this check is weakest in — so they
    are named here and tracked, not quietly assumed absent.
    """
    pairs: list[tuple[str, ast.expr]] = []
    for target in targets:
        if isinstance(target, ast.Name):
            pairs.append((target.id, value))
        elif (isinstance(target, ast.Tuple) and isinstance(value, ast.Tuple)
                and len(target.elts) == len(value.elts)):
            pairs.extend((element.id, bound)
                         for element, bound in zip(target.elts, value.elts)
                         if isinstance(element, ast.Name))
    return pairs


def _evaluated_here(node: ast.AST) -> list[ast.expr]:
    """The parts of a nested def/lambda/class that are evaluated in the ENCLOSING scope.

    The walk stops at a nested scope because its BODY runs elsewhere — but its decorators, base
    classes and parameter defaults run right here, and a lambda can hide in one of them
    (``def register(make=lambda argv, runner=subprocess.run: runner(argv))`` binds the launcher at
    import exactly like any other default). Stopping dead at the `def` would lose it, and losing a
    binding is the direction that reports CLEAN on a live defect.
    """
    parts: list[ast.expr] = list(getattr(node, "decorator_list", []))
    parts += list(getattr(node, "bases", []))
    parts += [keyword.value for keyword in getattr(node, "keywords", [])]
    spec = getattr(node, "args", None)
    if spec is not None:
        parts += list(spec.defaults)
        parts += [default for default in spec.kw_defaults if default is not None]
    return parts


def _own_nodes(scope: ast.AST):
    """Every node that executes in ONE scope's own namespace.

    Descends through that scope's statements and expressions but does NOT enter a nested scope's
    body, because those statements run in that scope's namespace, not this one — that is the whole
    reason a function-local ``runner = subprocess.run`` can no longer taint a module-level default.
    The nested node itself is still yielded, along with the parts of it that :func:`_evaluated_here`
    says run out here.
    """
    roots = [scope.body] if isinstance(scope, ast.Lambda) else list(scope.body)
    stack = list(reversed(roots))
    while stack:
        node = stack.pop()
        yield node
        children = (_evaluated_here(node) if isinstance(node, _SCOPE_NODES)
                    else list(ast.iter_child_nodes(node)))
        stack.extend(reversed(children))


def _scope_events(scope: ast.AST) -> list[tuple[tuple[int, int], int, object]]:
    """Everything that happens in ONE scope's own namespace, in source order.

    Two event kinds, tagged 0 and 1 so the sort is total and stable:

      * ``(pos, 0, (name, value))`` — a name binding, from an `import` or any assignment spelling.
      * ``(pos, 1, node)``          — a nested def/lambda/class whose DEFAULTS are evaluated here.
    """
    events: list[tuple[tuple[int, int], int, object]] = []
    for node in _own_nodes(scope):
        pos = (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))
        if isinstance(node, _SCOPE_NODES):
            events.append((pos, 1, node))
        elif isinstance(node, ast.Import):
            events += [(pos, 0, (alias.asname or "subprocess", _IMPORTED_MODULE))
                       for alias in node.names if alias.name == "subprocess"]
        elif isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            events += [(pos, 0, (alias.asname or alias.name, _IMPORTED_LAUNCHER))
                       for alias in node.names if alias.name in LAUNCHERS]
        elif isinstance(node, ast.Assign):
            events += [(pos, 0, pair) for pair in _assigned_names(node.targets, node.value)]
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            events += [(pos, 0, pair) for pair in _assigned_names([node.target], node.value)]
    events.sort(key=lambda event: event[:2])
    return events


def _index_scopes(scope: ast.AST, index: dict[int, tuple[list, list]]) -> tuple[list, list]:
    """One bottom-up pass over every scope: cache its events, and route bindings a scope pushes OUT
    of its own namespace to the scope that receives them.

    ``def _install(): global _RUN; _RUN = subprocess.run`` binds a launcher at MODULE level from
    inside a function body, and the ``nonlocal`` spelling does the same into the enclosing function.
    Reading a function's assignments as purely local reports CLEAN on both — the same one-keyword
    bypass this file already refuses for `as`, for `:` and for `,`, and the one hole that scoping
    the walk would otherwise open. Only the names a declaration actually names are lifted.

    Fills ``index[id(scope)] = (events, bindings received via `nonlocal`)`` and returns
    ``(published upward via `nonlocal`, published to module scope via `global`)``. A `nonlocal`
    receipt also keeps travelling up — one over-collecting hop per level, kept because the
    alternative is a miss.
    """
    events = _scope_events(scope)
    declared: dict[type, set[str]] = {ast.Global: set(), ast.Nonlocal: set()}
    for node in _own_nodes(scope):
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            declared[type(node)].update(node.names)
    received: list = []
    from_below: list = []
    for _pos, kind, payload in events:
        if kind == 1:
            up, out = _index_scopes(payload, index)
            received += up
            from_below += out
    index[id(scope)] = (events, received)

    def published(declaration: type) -> list:
        return [event for event in events
                if event[1] == 0 and event[2][0] in declared[declaration]]

    return published(ast.Nonlocal) + received, published(ast.Global) + from_below


def _publish_into(base: dict[str, str],
                  published: list[tuple[tuple[int, int], int, object]],
                  own_events: list[tuple[tuple[int, int], int, object]],
                  ) -> tuple[dict[str, str], frozenset[str]]:
    """`base` plus the names a nested scope published into it, resolved ORDER-FREE, and the set of
    names that publication PINS.

    A published binding lands whenever its function is CALLED, so its order relative to the
    receiving scope's own statements is not knowable here. That cuts both ways, and the pin is the
    second half: an ordered ``_RUN = None`` in the receiving scope must not clear a published
    launcher, because the publication may land after it. Listing the published bindings FIRST is
    deliberate: a chain that resolved only in list order would be answering by luck, and the
    fixpoint is what makes the answer order-independent. Names the declaration did not name keep
    the ordered treatment — a publication elsewhere is not licence to flatten the whole scope.
    """
    if not published:
        return base, frozenset()
    resolved = _visible_from_within(published + own_events, base)
    names = {event[2][0] for event in published} & resolved.keys()
    table = dict(base)
    table.update({name: resolved[name] for name in names})
    return table, frozenset(names)


def _bound_kind(value: object, table: dict[str, str]) -> str | None:
    """What ``<name> = value`` binds, read against the names visible right now.

        import subprocess as sp            -> _MODULE    {"sp"}
        sp2 = sp                           -> _MODULE    {"sp2"}
        from subprocess import run as _run -> _LAUNCHER  {"_run"}
        _run = subprocess.run              -> _LAUNCHER  {"_run"}
        _run: object = subprocess.run      -> _LAUNCHER  {"_run"}   (ast.AnnAssign)
        _alias = _run                      -> _LAUNCHER  {"_alias"} (transitive)

    The last three are not hypotheticals: each binds the real launcher at import exactly as the
    direct spelling does, so a resolver that recognises only ``name = subprocess.run`` hands anyone
    a rename or a type annotation as a way past the standing assertion. Anything else — a literal,
    a call, a lambda, ``time.sleep``, a local helper — returns None, which at a rebinding CLEARS
    the name rather than leaving a stale alias behind.
    """
    if isinstance(value, _ImportedAs):
        return value.kind
    if isinstance(value, ast.Attribute):
        if (value.attr in LAUNCHERS and isinstance(value.value, ast.Name)
                and table.get(value.value.id) == _MODULE):
            return _LAUNCHER
        return None
    if isinstance(value, ast.Name):
        return table.get(value.id)
    return None


def _visible_from_within(events: list[tuple[tuple[int, int], int, object]],
                         inherited: dict[str, str]) -> dict[str, str]:
    """What a scope nested INSIDE this one may see: this scope's bindings resolved order-FREE.

    Source order fixes when a statement of THIS scope runs relative to the others, but not when a
    nested def runs — that happens when this scope is CALLED, which may be after every line of it.
    ``def outer(): def inner(r=_LAUNCH)`` really does capture a module-level
    ``_LAUNCH = subprocess.run`` written below ``outer``. So for deeper scopes every binding counts,
    resolved as a fixpoint (a chain may be written in any order) and never removed (a rebinding may
    not have happened yet at the moment the nested def runs).

    This is the ONE place over-collection survives, and it survives because the alternative here is
    a MISS. Bounded: each round either resolves a name from the scope's finite identifiers or ends
    the loop, so at most one round per binding is ever needed.
    """
    table = dict(inherited)
    bindings = [payload for _pos, kind, payload in events if kind == 0]
    for _round in range(len(bindings) + 1):
        before = dict(table)
        for name, value in bindings:
            kind = _bound_kind(value, table)
            if kind is not None:
                table[name] = kind
        if table == before:
            break
    return table


def _binds_launcher(default: ast.expr, table: dict[str, str]) -> bool:
    """The two-node-type test, against the names the default's own `def` can see. Attribute:
    `<subprocess-alias>.<launcher>`. Name: an identifier resolved to a launcher in scope."""
    return _bound_kind(default, table) == _LAUNCHER


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


def _scan_scope(scope: ast.AST, inherited: dict[str, str], label: str,
                findings: list[Finding], counts: dict[str, int],
                index: dict[int, tuple[list, list]],
                pinned: frozenset[str] = frozenset()) -> None:
    """Walk one scope, resolving each default against what its `def` can actually see.

    Within this scope the table is built IN ORDER: a binding written below a def cannot reach that
    def's default, because Python evaluated the default first, and a rebinding replaces what the
    name held rather than accumulating onto it. Scopes nested inside get the order-free view
    instead — see :func:`_visible_from_within` for why that asymmetry is deliberate.

    `pinned` names are the exception to the ordered rebinding: a value published in from another
    scope has no knowable position, so nothing in this scope's own order may clear it. Pins do not
    propagate inward — a nested scope assigning the same name is shadowing it locally, which really
    does clear it there.
    """
    events, received = index[id(scope)]
    # `nonlocal` lands in THIS scope from a function nested in it, so it is folded in before
    # anything reads the table — the same lift `scan_source` does for `global` at module level.
    inherited, local_pins = _publish_into(inherited, received, events)
    pinned = pinned | local_pins
    nested_view = _visible_from_within(events, inherited)
    table = dict(inherited)
    for _pos, kind, payload in events:
        if kind == 0:
            name, value = payload
            bound = _bound_kind(value, table)
            if bound is not None:
                table[name] = bound
            elif name not in pinned:
                table.pop(name, None)
            continue
        if not isinstance(payload, ast.ClassDef):
            function = getattr(payload, "name", "<lambda>")
            for parameter, default in _defaults_of(payload):
                counts["defaults"] += 1
                counts["attributes"] += isinstance(default, ast.Attribute)
                counts["names"] += isinstance(default, ast.Name)
                if _binds_launcher(default, table):
                    findings.append(Finding(label, default.lineno, payload.lineno, function,
                                            parameter, ast.unparse(default)))
        _scan_scope(payload, nested_view, label, findings, counts, index)


def scan_source(text: str, label: str) -> tuple[list[Finding], int, int, int]:
    """(findings, defaults seen, Attribute-shaped defaults, Name-shaped defaults) for one file."""
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        raise SweepError(f"{label}: unparseable ({exc.__class__.__name__}) — refusing to "
                         "report it as clean") from exc
    findings: list[Finding] = []
    counts = {"defaults": 0, "attributes": 0, "names": 0}
    # `subprocess` is seeded as the module even before its import is read: without one the name is
    # a NameError at runtime, so the only shape this can add is code that could never have run.
    index: dict[int, tuple[list, list]] = {}
    _, hoisted = _index_scopes(tree, index)
    base, pinned = _publish_into({"subprocess": _MODULE}, hoisted, index[id(tree)][0])
    _scan_scope(tree, base, label, findings, counts, index, pinned=pinned)
    findings.sort(key=lambda finding: (finding.lineno, finding.def_lineno, finding.parameter))
    return findings, counts["defaults"], counts["attributes"], counts["names"]


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

    annotated_name = (
        "import subprocess\n"
        "_LAUNCH: object = subprocess.run\n"
        "def go(argv, runner=_LAUNCH):\n"
        "    return runner(argv)\n"
    )
    check("KNOWN POSITIVE (ast.Name, ANNOTATED assignment): `_LAUNCH: object = subprocess.run` is "
          "an ast.AnnAssign, so a resolver reading only ast.Assign is bypassed by one colon",
          [f.render() for f in scan_source(annotated_name, "fixture.py")[0]],
          ["fixture.py:3 go(runner=_LAUNCH)"])

    transitive_name = (
        "import subprocess\n"
        "_LAUNCH = subprocess.check_call\n"
        "_ALIAS = _LAUNCH\n"
        "def go(argv, runner=_ALIAS):\n"
        "    return runner(argv)\n"
    )
    check("KNOWN POSITIVE (ast.Name, TRANSITIVE rebinding): a launcher renamed once still binds "
          "the launcher — one hop of indirection is not a fix",
          [f.render() for f in scan_source(transitive_name, "fixture.py")[0]],
          ["fixture.py:4 go(runner=_ALIAS)"])

    late_outer_binding = (
        "import subprocess\n"
        "def outer():\n"
        "    def inner(argv, runner=_LAUNCH):\n"
        "        return runner(argv)\n"
        "    return inner\n"
        "_ALIAS = subprocess.run\n"
        "_LAUNCH = _ALIAS\n"
        "go = outer()\n"
    )
    check("KNOWN POSITIVE (ENCLOSING scope, resolved order-free): `inner`'s default runs when "
          "`outer()` is CALLED — below both assignments — so a module-level launcher written after "
          "`outer` really is captured. This is the row that goes red if order is enforced on "
          "enclosing scopes too, and it is EXECUTABLE, unlike a reverse-order module-level chain "
          "(which raises NameError and can never capture anything)",
          [f.render() for f in scan_source(late_outer_binding, "fixture.py")[0]],
          ["fixture.py:3 inner(runner=_LAUNCH)"])

    global_publication = (
        "import subprocess\n"
        "def _install():\n"
        "    global _RUN\n"
        "    _RUN = subprocess.run\n"
        "_install()\n"
        "def go(argv, run=_RUN):\n"
        "    return run(argv)\n"
    )
    check("KNOWN POSITIVE (`global` publication): an assignment inside a function body binds at "
          "MODULE level when it says `global`, so reading a function's assignments as purely local "
          "is a one-keyword bypass — this is the row that goes red if scoping the walk drops it",
          [f.render() for f in scan_source(global_publication, "fixture.py")[0]],
          ["fixture.py:6 go(run=_RUN)"])

    global_publication_transitive = (
        "import subprocess\n"
        "def _install():\n"
        "    global _RUN\n"
        "    _RUN = _ALIAS\n"
        "_ALIAS = subprocess.run\n"
        "_install()\n"
        "def go(argv, run=_RUN):\n"
        "    return run(argv)\n"
    )
    check("KNOWN POSITIVE (`global` publication of an alias resolved LATER in the list): the "
          "published binding is read before `_ALIAS` is known, so one pass resolves nothing — this "
          "is the row that goes red if the order-free fixpoint degrades to a single sweep",
          [f.render() for f in scan_source(global_publication_transitive, "fixture.py")[0]],
          ["fixture.py:7 go(run=_RUN)"])

    nonlocal_publication = (
        "import subprocess\n"
        "def outer():\n"
        "    _RUN = None\n"
        "    def _install():\n"
        "        nonlocal _RUN\n"
        "        _RUN = subprocess.run\n"
        "    _install()\n"
        "    def go(argv, run=_RUN):\n"
        "        return run(argv)\n"
        "    return go\n"
        "captured = outer()\n"
    )
    check("KNOWN POSITIVE (`nonlocal` publication): `global`'s sibling keyword, publishing into "
          "the ENCLOSING function instead of the module — the same one-keyword bypass, and it must "
          "not be closed on only one of the two spellings",
          [f.render() for f in scan_source(nonlocal_publication, "fixture.py")[0]],
          ["fixture.py:8 go(run=_RUN)"])

    lambda_in_default = (
        "import subprocess\n"
        "def register(name, make=lambda argv, runner=subprocess.run: runner(argv)):\n"
        "    return make\n"
    )
    check("KNOWN POSITIVE (lambda hiding in another def's default): the scope walk stops at a "
          "nested `def`, and a lambda written INSIDE its signature still binds its own default out "
          "here — stopping dead at the `def` loses it",
          [f.render() for f in scan_source(lambda_in_default, "fixture.py")[0]],
          ["fixture.py:2 <lambda>(runner=subprocess.run)"])

    unpacked_name = (
        "import subprocess\n"
        "_LAUNCH, _QUIET = subprocess.run, True\n"
        "def go(argv, runner=_LAUNCH):\n"
        "    return runner(argv)\n"
    )
    check("KNOWN POSITIVE (ast.Name, PARALLEL UNPACKING): `a, b = subprocess.run, True` binds the "
          "launcher to `a` — a resolver reading the target as one Name sees a Tuple and moves on",
          [f.render() for f in scan_source(unpacked_name, "fixture.py")[0]],
          ["fixture.py:3 go(runner=_LAUNCH)"])

    aliased_module_by_assignment = (
        "import subprocess\n"
        "sp = subprocess\n"
        "def launch(argv, spawn=sp.Popen):\n"
        "    return spawn(argv)\n"
    )
    check("KNOWN POSITIVE (ast.Attribute over an ASSIGNED module alias): `sp = subprocess` hides "
          "the launcher from a resolver that only reads `import subprocess as sp`",
          [f.render() for f in scan_source(aliased_module_by_assignment, "fixture.py")[0]],
          ["fixture.py:3 launch(spawn=sp.Popen)"])

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

    transitive_non_launcher = (
        "import json\n"
        "_HELPER = json.dumps\n"
        "_ALIAS = _HELPER\n"
        "def go(argv, run=_ALIAS):\n"
        "    return run(argv)\n"
    )
    check("KNOWN NEGATIVE: a transitive chain ending at a NON-launcher stays silent — the "
          "fixpoint propagates a resolved binding, it does not treat indirection itself as guilt",
          [f.render() for f in scan_source(transitive_non_launcher, "fixture.py")[0]], [])

    # ---- KNOWN NEGATIVES (scope and order): the three false positives a flat, order-free set of
    # every assignment in the file produces. Each fixture below RUNS, and at the moment its `def`
    # statement executes the default provably is not a launcher — so a finding here is not a
    # cautious over-report, it is a wrong answer about executable code.
    bound_after_the_def = (
        "import subprocess\n"
        "_LAUNCH = None\n"
        "def go(argv, runner=_LAUNCH):\n"
        "    return runner\n"
        "_LAUNCH = subprocess.run\n"
    )
    check("KNOWN NEGATIVE (ORDER): a launcher assigned BELOW the def does not reach the default "
          "above it — Python evaluated `runner=_LAUNCH` as None before that line ever ran",
          [f.render() for f in scan_source(bound_after_the_def, "fixture.py")[0]], [])

    # Both SCOPE fixtures put the function-local launcher assignment BELOW the module-level (or
    # outer) binding and ABOVE the def that reads it, so source order alone cannot excuse the
    # finding. Flatten the walk and each reports a defect against a default that is provably not a
    # launcher; only the scope boundary keeps them silent.
    launcher_local_to_another_function = (
        "import subprocess\n"
        "def _noop(argv):\n"
        "    return None\n"
        "runner = _noop\n"
        "def helper():\n"
        "    runner = subprocess.run\n"
        "    return runner\n"
        "def go(argv, run=runner):\n"
        "    return run(argv)\n"
    )
    check("KNOWN NEGATIVE (SCOPE): a FUNCTION-LOCAL `runner = subprocess.run` is invisible outside "
          "its own body, so it cannot taint a module-level `run=runner` whose `runner` is a safe "
          "helper — the module-level binding is the only one `go` can see",
          [f.render() for f in scan_source(launcher_local_to_another_function, "fixture.py")[0]],
          [])

    rebound_to_something_inert = (
        "import subprocess\n"
        "_LAUNCH = subprocess.run\n"
        "_LAUNCH = None\n"
        "def go(argv, runner=_LAUNCH):\n"
        "    return runner\n"
    )
    check("KNOWN NEGATIVE (REBINDING): a name that HELD a launcher and was reassigned to something "
          "inert before the def no longer holds one — an alias that is never un-resolved reports a "
          "defect against a default that is None",
          [f.render() for f in scan_source(rebound_to_something_inert, "fixture.py")[0]], [])

    same_name_in_a_sibling_scope = (
        "import subprocess\n"
        "def outer():\n"
        "    launch = print\n"
        "    def _sibling():\n"
        "        launch = subprocess.Popen\n"
        "        return launch\n"
        "    def _inner(argv, run=launch):\n"
        "        return run(argv)\n"
        "    return _sibling, _inner\n"
    )
    check("KNOWN NEGATIVE (SHADOWING in a SIBLING scope): `_sibling` binds its own `launch` to a "
          "launcher on the line above `_inner`, and `_inner` still captures `outer`'s `print` — "
          "siblings do not see each other's locals, however the source is ordered",
          [f.render() for f in scan_source(same_name_in_a_sibling_scope, "fixture.py")[0]], [])

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
