#!/usr/bin/env python3
"""ADVISORY per-site coverage census for shared mechanisms introduced by a pull request.

THE DEFECT CLASS (registry #939, five measured instances in one night). N call sites share a
mechanism and the suite asserts the property ONCE. The other sites are covered only
TRANSITIVELY, and that coverage vanishes the instant the mechanism is removed from one of them —
which is exactly the mutation nobody runs, because the suite is green and the feature
demonstrably works:

    #594  `budget` on the CAS writers ......... droppable from claim()/adopt()/release()   1/4
    #594  `_pre_write_jitter()` ............... pinned only by a suite-wide "at least one"  1/N
    #886  `--park-cause` forwarding ........... one line reverted 3 of the 5 write sites    2/5
    #886  `oc_kwargs.clear()` ................. two of three call sites droppable           1/3
    #941  `_escalate_two_head` call sites ..... either site re-pointable, 44 scripts green  1/3

It is invisible to every signal this repo has except one-at-a-time mutation: CI is green, and a
reviewer reading the diff sees the mechanism present at every site. It is currently caught only
because the orchestrator keeps typing "mutate them one at a time" into briefs by hand. That is a
habit, not a control.

WHAT THIS DOES. Given the PR diff, it enumerates the call sites of every symbol the PR
introduced or changed, and reports the sites that no DISTINCT named check can be pointed at. The
walk is the one `#797`'s stray-call-site detector already does (`_deferred_issue_ladder_self_test`
in dispatch-claim.py); only the assertion differs — that one says "this symbol is reached from
exactly ONE place", this one says "each of the N places is separately named".

THE TRIGGER, exactly (and it is scoped to the DIFF — a repo-wide sweep would flag every shared
helper and be ignored within a day). A repo-defined symbol is reported when BOTH hold:
  (1) CALL-SHAPED TOUCH — this PR changed the way it is CALLED: either its signature, from `def`
      to the line before its first statement, or the source span of at least one of its call
      expressions. A BODY-only edit is deliberately not a way in; see `touched_symbols`.
  (2) SHARED — it has at least two production call sites (harness probes and its own recursion
      excluded).
Symbols the repo does not define — `.clear()`, `.append()`, stdlib calls — are out of scope: the
"call sites" of a common attribute name are every use of that name, and the census would drown.
That is a known blind spot; #886's `oc_kwargs.clear()` row is on the wrong side of it.

WHY DISTINCT, AND WHY MATCHING. A single suite-wide literal — pre-fix #886 shipped
`"every _pr_needs_user call site must be pinned to its (park_class, park_cause) pair"` — mentions
every site at once and therefore proves ONE of them. So evidence is ASSIGNED to sites by a
maximum bipartite matching: one piece of evidence covers at most one site, and the sites left
unmatched are the report. That is the mechanical reading of the rule this repo learnt the hard
way: an assertion quantified over a set gives 1/N coverage at N/N confidence.

ADVISORY, DELIBERATELY (#939). It emits findings and a census; it never fails the gate. The
false-positive rate against a real tree is not yet known well enough to enforce, and a lint that
gets disabled is worth less than no lint. `--self-test` IS enrolled in the required suite, so a
broken analyser reds the gate even though a finding does not.

USAGE
    callsite-coverage.py --self-test
    callsite-coverage.py --advisory --base <sha> [--root <dir>]
    callsite-coverage.py --advisory --diff-file <path> [--root <dir>] [--json <path>]
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path


# A function belongs to the TEST HARNESS, not to production, if it (or any function enclosing it)
# is named like a self-test. Calls inside the harness are probes, never write sites — the same
# exclusion #869's `_park_cause_call_sites` makes, and for the same reason: without it the
# harness's own probe calls masquerade as sites, and, worse, let a real site hide behind one.
HARNESS_FUNCTION = re.compile(r"(?:^|_)(?:self_test|selftest|test)_|(?:^|_)(?:self_test|selftest)$")

# The nested check helpers this repo's self-tests define. Measured over the current tree: 4387 of
# the 4389 BARE calls to these names sit inside a harness function, so restricting the evidence
# pool to harness bodies costs essentially nothing — while keeping the 24 PRODUCTION `assert`
# messages (against 1081 harness ones) out of it, so a production invariant cannot be mistaken
# for a test that names a site.
CHECK_HELPERS = frozenset({"check", "chk", "sub", "rejects", "case", "ok", "expect"})

# Token floors. A fingerprint shorter than this cannot discriminate one site from another (`repo`,
# `main`, `pr`), and a short evidence slice would match everything.
MIN_NAME_TOKEN = 4      # enclosing-function names, underscores stripped
MIN_ARG_TOKEN = 12      # string literals the call site itself passes
MIN_SLICE_TOKEN = 12    # evidence that is a SLICE of a site literal (#869's site table)

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

SCRIPTS_DIR = "scripts"


class CoverageError(RuntimeError):
    """The census could not be computed, so no claim about coverage may be made."""


# ---------------------------------------------------------------------------------------------
# Diff parsing
# ---------------------------------------------------------------------------------------------

def changed_lines(diff_text: str) -> dict[str, set[int]]:
    """`{path: {line numbers present in the HEAD side of a hunk}}` for a `--unified=0` diff.

    Only the `+` side is collected: a symbol is "touched" by the lines the PR leaves behind, and
    a pure deletion leaves no site to name."""
    files: dict[str, set[int]] = {}
    path: str | None = None
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            path = None if target == "/dev/null" else target[2:] if target[:2] in ("b/", "a/") \
                else target
            if path is not None:
                files.setdefault(path, set())
            continue
        match = HUNK.match(line)
        if match and path is not None:
            start, count = int(match.group(1)), int(match.group(2) or 1)
            files[path].update(range(start, start + count))
    return files


# ---------------------------------------------------------------------------------------------
# Parsed-tree index
# ---------------------------------------------------------------------------------------------

def literal_text(node: ast.AST | None) -> str | None:
    """The static text of a string node: a `str` constant, or an f-string's CONSTANT chunks with
    its holes removed — the text the source actually commits to. Anything else is `None`."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        chunks = [v.value for v in node.values
                  if isinstance(v, ast.Constant) and isinstance(v.value, str)]
        return "".join(chunks) if chunks else None
    return None


def is_harness(stack: tuple[str, ...]) -> bool:
    """True if any enclosing definition in `stack` is a self-test."""
    return any(HARNESS_FUNCTION.search(name) for name in stack)


def _stacks(tree: ast.AST) -> tuple[dict[int, tuple[str, ...]], set[int]]:
    """`{id(node): the tuple of def/class names enclosing it}`, plus the ids of the nodes that sit
    inside a FUNCTION.

    The AST answer to "where is this?", so a call cannot hide in a lambda, a nested def, a dead
    branch or a reflow. The function-nesting set is what keeps a local closure — `append` defined
    inside `_legacy_global_append` — from claiming every `list.append(...)` in the repo as one of
    its call sites; measured, that one collision alone produced 399 phantom sites."""
    stacks: dict[int, tuple[str, ...]] = {}
    in_function: set[int] = set()

    def walk(node: ast.AST, stack: tuple[str, ...], nested: bool) -> None:
        for child in ast.iter_child_nodes(node):
            stacks[id(child)] = stack
            if nested:
                in_function.add(id(child))
            is_function = isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            deeper = stack + (child.name,) if is_function or isinstance(child, ast.ClassDef) \
                else stack
            walk(child, deeper, nested or is_function)

    walk(tree, (), False)
    return stacks, in_function


class TreeIndex:
    """One parse of the whole `scripts/*.py` surface: production defs, production call sites, and
    the evidence pool of harness-visible names."""

    def __init__(self, sources: dict[str, str]) -> None:
        self.defs: dict[str, list[dict]] = {}
        self.calls: dict[str, list[dict]] = {}
        self.evidence: set[str] = set()
        for path in sorted(sources):
            try:
                tree = ast.parse(sources[path], filename=path)
            except SyntaxError as exc:  # a tree we cannot parse must not read as "no findings"
                raise CoverageError(f"{path}: {exc}") from exc
            stacks, in_function = _stacks(tree)
            self.defs[path] = self._defs_of(tree, stacks, in_function)
            self._collect_calls(path, tree, stacks)
            self.evidence |= self._evidence_of(tree, stacks)

    @staticmethod
    def _defs_of(tree: ast.AST, stacks: dict[int, tuple[str, ...]],
                 in_function: set[int]) -> list[dict]:
        found = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            stack = stacks.get(id(node), ())
            if is_harness(stack + (node.name,)) or id(node) in in_function:
                continue
            body_start = node.body[0].lineno if node.body else node.lineno
            found.append({
                "name": node.name,
                "qual": ".".join(stack + (node.name,)),
                "start": min([node.lineno] + [d.lineno for d in node.decorator_list]),
                "end": node.end_lineno or node.lineno,
                # The signature is everything from `def` to the line before the first statement,
                # so a keyword added on a continuation line counts as a signature change.
                "sig_end": body_start - 1,
            })
        return found

    def _collect_calls(self, path: str, tree: ast.AST,
                       stacks: dict[int, tuple[str, ...]]) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            stack = stacks.get(id(node), ())
            if is_harness(stack):
                continue
            bare = isinstance(node.func, ast.Name)
            name = node.func.id if bare else getattr(node.func, "attr", None)
            if not name:
                continue
            self.calls.setdefault(name, []).append({
                "path": path,
                "stack": stack,
                "line": node.lineno,
                "end": node.end_lineno or node.lineno,
                # A BARE `foo()` resolves in its own module; an `x.foo()` is how this repo reaches
                # a sibling script (`_park_policy().park_ladder_decision(...)`). Keeping the two
                # apart stops a bare local `census()` in one script from claiming the call sites
                # of an unrelated `census()` in another.
                "bare": bare,
                "args": self._arg_literals(node),
            })

    @staticmethod
    def _arg_literals(node: ast.Call) -> list[str]:
        """The string literals the CALL ITSELF passes — what this site SAYS, which is how #869
        keys its write sites (`park_cause="history-rewritten"`, a reason's literal chunks)."""
        out = []
        for operand in list(node.args) + [kw.value for kw in node.keywords]:
            text = literal_text(operand)
            if text and len(text.strip()) >= MIN_ARG_TOKEN:
                out.append(text.strip())
        return out

    def _evidence_of(self, tree: ast.AST, stacks: dict[int, tuple[str, ...]]) -> set[str]:
        """Every string a self-test can put a NAME to.

        Two populations, and both are needed to keep the false-positive rate honest:
          (a) CHECK NAMES — the first argument of a bare `check`/`chk`/... call, and the message
              of an `assert`, inside a harness function. This is the repo's dominant convention
              (`check("[#869] SITE review_outcome/injection: ...", ...)`).
          (b) HARNESS-CONSUMED SITE TABLES — module-level string constants whose binding is
              referenced from inside a harness function. #869 pins its five write sites through
              `PARK_CAUSE_SITES_869`, a module-level tuple whose rows are interpolated into the
              printed check name; without (b) that per-site table would read as no evidence at
              all and the fixed state would still be flagged."""
        names: set[str] = set()
        harness_names: set[str] = set()
        for node in ast.walk(tree):
            stack = stacks.get(id(node), ())
            harness = is_harness(stack)
            if harness and isinstance(node, ast.Name):
                harness_names.add(node.id)
            if not harness:
                continue
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id in CHECK_HELPERS and node.args:
                text = literal_text(node.args[0])
                if text:
                    names.add(text)
            elif isinstance(node, ast.Assert) and node.msg is not None:
                text = literal_text(node.msg)
                if text:
                    names.add(text)
        for node in ast.iter_child_nodes(tree):
            targets = node.targets if isinstance(node, ast.Assign) else \
                ([node.target] if isinstance(node, ast.AnnAssign) else [])
            bound = {t.id for t in targets if isinstance(t, ast.Name)}
            if not (bound & harness_names) or node.value is None:
                continue
            for inner in ast.walk(node.value):
                text = literal_text(inner)
                if text and len(text.strip()) >= MIN_SLICE_TOKEN:
                    names.add(text.strip())
        return names


# ---------------------------------------------------------------------------------------------
# Site fingerprints and the evidence assignment
# ---------------------------------------------------------------------------------------------

def site_fingerprints(site: dict) -> list[str]:
    """The strings that could name this call site: the functions enclosing it, and the literals
    it passes.

    The called symbol's own name is deliberately NOT a fingerprint. A literal that merely names
    the mechanism ("every _pr_needs_user call site is pinned") is the quantified assertion this
    check exists to catch; letting it count as evidence would make the check agree with the
    defect."""
    prints = [name.strip("_") for name in site["stack"] if len(name.strip("_")) >= MIN_NAME_TOKEN]
    return prints + [arg for arg in site["args"] if len(arg) >= MIN_ARG_TOKEN]


def discriminating_fingerprints(sites: list[dict]) -> list[list[str]]:
    """Per site, the fingerprints that are UNIQUE to it among this symbol's sites.

    MEASURED on the real pre-fix head of #886: without this filter the check reported all eight
    `_pr_needs_user` write sites as covered, because eight sites shared the enclosing lane
    `_dispatch_review_items` and three shared the literal `"capacity"` — and the suite happens to
    contain literals mentioning both. A property every site has cannot tell one site from
    another, which is the whole failure mode: "some caller does X" is 1/N coverage at N/N
    confidence, and a fingerprint all N callers share is the same sentence in fingerprint form."""
    raw = [site_fingerprints(site) for site in sites]
    seen: dict[str, int] = {}
    for prints in raw:
        for value in set(p.lower() for p in prints):
            seen[value] = seen.get(value, 0) + 1
    return [[p for p in prints if seen[p.lower()] == 1] for prints in raw]


def _covers(evidence: str, fingerprint: str) -> bool:
    low_e, low_f = evidence.lower(), fingerprint.lower()
    if low_f in low_e:
        return True
    # A site table stores a distinctive SLICE of the site's own literal (#869 keys sites by the
    # first words of the reason each one writes), so the containment runs the other way too —
    # but only for a slice long enough to name one site rather than all of them.
    return len(low_e) >= MIN_SLICE_TOKEN and low_e in low_f


def assign_evidence(sites: list[dict], evidence: set[str]) -> dict[int, str]:
    """Maximum bipartite matching from site index to a piece of evidence.

    ONE piece of evidence covers AT MOST ONE site. That is the whole point: a suite-wide literal
    mentioning the mechanism, or an enclosing function that holds eight of the call sites, proves
    exactly one of them. Sites left unmatched are what gets reported."""
    candidates: list[list[str]] = []
    for prints in discriminating_fingerprints(sites):
        candidates.append(sorted({e for e in evidence
                                  if any(_covers(e, f) for f in prints)}))
    matched: dict[str, int] = {}

    def augment(index: int, seen: set[str]) -> bool:
        for option in candidates[index]:
            if option in seen:
                continue
            seen.add(option)
            if option not in matched or augment(matched[option], seen):
                matched[option] = index
                return True
        return False

    for index in range(len(sites)):
        augment(index, set())
    return {site_index: option for option, site_index in matched.items()}


# ---------------------------------------------------------------------------------------------
# The audit
# ---------------------------------------------------------------------------------------------

def production_sites(index: TreeIndex, name: str, path: str, symbols: list[dict],
                     *, unique_owner: bool) -> list[dict]:
    """Every production call of the `name` DEFINED IN `path`.

    A symbol is identified by (defining module, name), not by name alone. Measured on this
    check's own diff, name-alone identity attributed all 42 module-level `main()` calls in the
    repo to one script's `main`, and three unrelated `_git` helpers to each other. So:
      * a BARE `name()` is a site only in the module that defines it — Python resolved it there;
      * an ATTRIBUTE `x.name()` is how this repo reaches a sibling script, so it counts from
        anywhere — but only when exactly ONE module defines the name. With two definitions the
        base is not resolvable from the tree and guessing would re-import the collision.
    Calls inside the symbol's own body are dropped: recursion is not a second site."""
    return [site for site in index.calls.get(name, [])
            if (site["path"] == path if site["bare"] else unique_owner)
            and not (site["path"] == path
                     and any(s["start"] <= site["line"] <= s["end"] for s in symbols))]


def touched_symbols(index: TreeIndex, changed: dict[str, set[int]],
                    owners: dict[str, dict[str, list[dict]]]) -> dict[tuple[str, str], str]:
    """`{(defining module, name): how}` for the symbols whose CALL SHAPE this PR changed.

    Two ways in, and no third:
      * the PR touched a production def's SIGNATURE — everything from `def` to the line before
        its first statement, so a keyword added on a continuation line counts; or
      * the PR touched the SPAN of a production CALL — the shape where a mechanism is added at
        three of four writers and the fourth is forgotten, which no def-only trigger can see.
        The call is resolved to the module that defines it, by the rule in `production_sites`;
        an unresolvable call implicates nothing.

    A BODY-only edit is deliberately NOT a way in. That is the false-positive valve: a pure
    helper whose internals changed while its signature and its callers stood still is not this
    defect class — its callers pass it nothing new, so there is nothing to drop from exactly one
    of them. Without the valve every shared helper in a changed file becomes a finding, and a
    lint that flags everything gets disabled.

    Both arms key on the DEFINING MODULE, never on the bare name. Measured on this check's own
    diff, keying on the name alone dragged in every other script's identically named `main`,
    `_git` and `render` — files the PR does not touch at all."""
    touched: dict[tuple[str, str], str] = {}
    for path in sorted(changed):
        lines = changed[path]
        if not lines:
            continue
        for symbol in index.defs.get(path, []):
            if lines & set(range(symbol["start"], symbol["sig_end"] + 1)):
                touched.setdefault((path, symbol["name"]), "signature")
    for name, sites in index.calls.items():
        by_path = owners.get(name)
        if not by_path:
            continue
        for site in sites:
            if not (changed.get(site["path"], set())
                    & set(range(site["line"], site["end"] + 1))):
                continue
            if site["bare"]:
                owner = site["path"] if site["path"] in by_path else None
            else:
                owner = next(iter(by_path)) if len(by_path) == 1 else None
            if owner is not None:
                touched.setdefault((owner, name), "call-site")
    return touched


def audit(sources: dict[str, str], changed: dict[str, set[int]], *,
          min_sites: int = 2) -> dict:
    """The census. See `touched_symbols` for the trigger and `assign_evidence` for the rule."""
    index = TreeIndex(sources)
    owners_by_name: dict[str, dict[str, list[dict]]] = {}
    for path, symbols in index.defs.items():
        for symbol in symbols:
            owners_by_name.setdefault(symbol["name"], {}).setdefault(path, []).append(symbol)
    findings, examined = [], 0
    total_sites = uncovered_total = mute_total = 0
    for (path, name), trigger in sorted(touched_symbols(index, changed, owners_by_name).items()):
        by_path = owners_by_name[name]
        symbols = by_path[path]
        examined += 1
        sites = production_sites(index, name, path, symbols, unique_owner=len(by_path) == 1)
        if len(sites) < min_sites:
            continue
        assigned = assign_evidence(sites, index.evidence)
        distinct = discriminating_fingerprints(sites)
        rows = []
        for position, site in enumerate(sites):
            rows.append({
                "path": site["path"],
                "line": site["line"],
                "enclosing": ".".join(site["stack"]) or "<module>",
                "evidence": assigned.get(position),
                # A site with no fingerprint of its own — same enclosing function as its
                # siblings, no literal it alone passes — cannot be told from them BY NAME.
                # Reporting that as "unnamed" would be a claim this check cannot support, so it
                # is counted separately: the honest answer is "give these sites something that
                # distinguishes them, then this check can hold you to it".
                "distinguishable": bool(distinct[position]),
            })
        total_sites += len(rows)
        uncovered = [r for r in rows if r["evidence"] is None and r["distinguishable"]]
        muted = [r for r in rows if not r["distinguishable"]]
        uncovered_total += len(uncovered)
        mute_total += len(muted)
        findings.append({
            "symbol": symbols[0]["qual"],
            "path": path,
            "line": symbols[0]["start"],
            "trigger": trigger,
            "touched_sites": sum(1 for site in sites
                                 if changed.get(site["path"], set())
                                 & set(range(site["line"], site["end"] + 1))),
            "sites": rows,
            "uncovered": len(uncovered),
            "indistinguishable": len(muted),
        })
    return {
        "files_changed": len([p for p in changed if p.endswith(".py")]),
        "symbols_examined": examined,
        "symbols_triggered": len(findings),
        "sites_found": total_sites,
        "sites_without_distinct_named_check": uncovered_total,
        "sites_indistinguishable": mute_total,
        "findings": findings,
    }


CENSUS_KEYS = ("files_changed", "symbols_examined", "symbols_triggered", "sites_found",
               "sites_without_distinct_named_check", "sites_indistinguishable")


def census_line(census: dict) -> str:
    """The one line this check emits on EVERY run, finding or not. A silent lint is worthless."""
    return "callsite-coverage census: " + " ".join(
        f"{key}={census[key]}" for key in CENSUS_KEYS)


def render(census: dict) -> list[str]:
    lines = [census_line(census)]
    for finding in census["findings"]:
        if not finding["uncovered"]:
            lines.append(f"  ok      {finding['path']}:{finding['line']} {finding['symbol']} — "
                         f"{len(finding['sites'])} site(s), "
                         f"{finding['indistinguishable']} indistinguishable, none unnamed")
            continue
        lines.append(
            f"::warning file={finding['path']},line={finding['line']}::callsite-coverage "
            f"[#939 advisory]: `{finding['symbol']}` is {finding['trigger']}-changed in this PR "
            f"and called from {len(finding['sites'])} production site(s) "
            f"({finding['touched_sites']} of them touched here); "
            f"{finding['uncovered']} of them have no DISTINCT named check. Remove the mechanism "
            f"from exactly one of these sites — if no test that NAMES that site goes red, the "
            f"coverage is 1/N at N/N confidence.")
        for row in finding["sites"]:
            if row["evidence"] is not None:
                mark, detail = "named by ", repr(row["evidence"][:60])
            elif row["distinguishable"]:
                mark, detail = "UNCOVERED", ""
            else:
                mark, detail = "no-name  ", "(shares every fingerprint with a sibling site)"
            lines.append(f"    {mark} {row['path']}:{row['line']} in {row['enclosing']} {detail}")
    return lines


# ---------------------------------------------------------------------------------------------
# git plumbing
# ---------------------------------------------------------------------------------------------

def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *args],
                            capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise CoverageError(f"git {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


def diff_against(root: Path, base: str) -> str:
    merge_base = _git(root, "merge-base", base, "HEAD").strip() or base
    return _git(root, "diff", "--unified=0", merge_base, "HEAD", "--", SCRIPTS_DIR)


def read_sources(root: Path) -> dict[str, str]:
    sources = {}
    for path in sorted((root / SCRIPTS_DIR).glob("*.py")):
        sources[f"{SCRIPTS_DIR}/{path.name}"] = path.read_text(encoding="utf-8")
    if not sources:
        raise CoverageError(f"no {SCRIPTS_DIR}/*.py under {root} — refusing a vacuous census")
    return sources


def run_advisory(root: Path, base: str | None, diff_file: str | None,
                 json_path: str | None) -> int:
    diff_text = Path(diff_file).read_text(encoding="utf-8") if diff_file \
        else diff_against(root, base or "HEAD~1")
    changed = {p: v for p, v in changed_lines(diff_text).items()
               if p.startswith(f"{SCRIPTS_DIR}/") and p.endswith(".py")}
    census = audit(read_sources(root), changed)
    text = render(census)
    print("\n".join(text))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("\n".join(["### callsite-coverage (#939, advisory)", "```"]
                                   + text + ["```", ""]))
    if json_path:
        Path(json_path).write_text(json.dumps(census, indent=2), encoding="utf-8")
    return 0


# ---------------------------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------------------------

def _self_test() -> int:
    failures = []

    def check(name, got, want):
        if got == want:
            print(f"  ok   {name}")
        else:
            failures.append(name)
            print(f"  FAIL {name}: {got!r} != {want!r}")

    # ---- THIS CHECK'S OWN SHARED MECHANISMS, ONE NAMED CHECK PER CALL SITE -------------------
    # #939 applies to #939. `literal_text` and `is_harness` are each called from several places
    # in this module, so a suite-wide "the helper works" would be 1/N coverage at N/N confidence
    # — the exact defect. Each row below is named after the CALL SITE it pins and reds when the
    # call is removed from THAT site alone; `--advisory` run against this PR's own diff reports
    # zero uncovered sites, which is the point.
    check("literal_text unit: a plain str constant is its own text",
          literal_text(ast.parse("'the reason text'").body[0].value), "the reason text")
    check("literal_text unit: an f-string's HOLES are dropped and its committed chunks kept",
          literal_text(ast.parse("f'park {cause} at site'").body[0].value), "park  at site")
    check("literal_text unit: a number is not evidence and is not a fingerprint",
          literal_text(ast.parse("42").body[0].value), None)
    check("is_harness unit: `_park_cause_site_self_test` is harness",
          is_harness(("_park_cause_site_self_test",)), True)
    check("is_harness unit: `_test_gh_flows` is harness — the leading underscore does not make "
          "a test-flow helper production code",
          is_harness(("_test_gh_flows",)), True)
    check("is_harness unit: a plain def INSIDE a self-test is harness too",
          is_harness(("_deferred_issue_ladder_self_test", "observing")), True)
    check("is_harness unit: a production def that merely mentions a test is not",
          is_harness(("attest_route", "protest", "latest_run")), False)

    # is_harness SITE _defs_of — a module-level self-test entry point is not an auditable symbol.
    harness_symbol = ("def _self_test():\n    return 0\n"
                      "def main():\n    return _self_test()\n"
                      "def run():\n    return _self_test()\n")
    check("is_harness SITE _defs_of: a module-level `_self_test` called from two production "
          "functions is NOT a symbol — the harness is not a mechanism under audit",
          audit({"scripts/h.py": harness_symbol},
                {"scripts/h.py": set(range(1, 10))})["symbols_examined"], 2)

    # ---- changed_lines --------------------------------------------------------------------
    diff = ("--- a/scripts/x.py\n+++ b/scripts/x.py\n"
            "@@ -10 +10,3 @@\n+a\n+b\n+c\n"
            "@@ -40,2 +43 @@\n+d\n")
    check("changed_lines reads the HEAD side of every hunk",
          changed_lines(diff), {"scripts/x.py": {10, 11, 12, 43}})
    check("changed_lines ignores a deleted file (no HEAD side to name)",
          changed_lines("--- a/scripts/x.py\n+++ /dev/null\n@@ -1,3 +0,0 @@\n"), {})

    # ---- THE KNOWN SHAPE: one suite-wide literal over N sites --------------------------------
    # This is #886 in miniature: one helper, three call sites in ONE enclosing function, each
    # passing its own cause, and a single quantified assertion mentioning the helper.
    QUANTIFIED = ("def _quantified_self_test():\n"
                  "    assert True, 'every _pr_needs_user call site in _dispatch_review_items "
                  "is pinned to its cause'\n")
    shared = (
        "def _pr_needs_user(repo, reason, park_cause=None):\n"
        "    return reason\n"
        "def _dispatch_review_items(items):\n"
        "    _pr_needs_user('r', 'the PR head no longer descends', park_cause='history-rewritten')\n"
        "    _pr_needs_user('r', 'round-budget marker validation failed', park_cause='marker-corrupt')\n"
        "    _pr_needs_user('r', 'the fix lane cannot honour the route', park_cause='routing-x')\n"
        + QUANTIFIED)
    every_line = {"scripts/q.py": set(range(1, 40))}
    quantified = audit({"scripts/q.py": shared}, every_line)
    check("discriminating_fingerprints SITE assign_evidence: a literal naming the mechanism "
          "and the LANE all three sites share names NONE of them — all three UNCOVERED "
          "(1/N coverage at N/N confidence), which is #886 in miniature",
          [(f["symbol"], len(f["sites"]), f["uncovered"]) for f in quantified["findings"]],
          [("_pr_needs_user", 3, 3)])
    check("#886 SHAPE: the census counts the sites it examined, not just the findings",
          (quantified["sites_found"], quantified["sites_without_distinct_named_check"]), (3, 3))
    one_named = shared.replace(
        "'every _pr_needs_user call site in _dispatch_review_items is pinned to its cause'",
        "'the PR head no longer descends: park_cause is history-rewritten'")
    check("#886 SHAPE: a literal naming ONE site's own words covers exactly that one",
          [f["uncovered"] for f in
           audit({"scripts/q.py": one_named}, every_line)["findings"]], [2])

    # ...and the SAME tree with a per-site table goes quiet. The table is module-level and
    # harness-referenced, exactly like PARK_CAUSE_SITES_869.
    per_site = shared.replace(
        QUANTIFIED,
        "SITES = ('the PR head no longer descends', 'round-budget marker validation',\n"
        "         'the fix lane cannot honour the route')\n"
        "def _table_self_test():\n"
        "    assert SITES, 'each write site states its own cause'\n")
    named = audit({"scripts/q.py": per_site}, every_line)
    check("#886 FIXED: a harness-consumed per-site table covers every site and the check "
          "goes QUIET",
          [(f["symbol"], f["uncovered"]) for f in named["findings"]], [("_pr_needs_user", 0)])
    unconsumed = per_site.replace("    assert SITES,", "    assert True,")
    check("#886 FIXED: ...but a table NO self-test consumes is not evidence",
          [f["uncovered"] for f in
           audit({"scripts/q.py": unconsumed}, every_line)["findings"]], [3])

    # ---- The DISTINCTNESS half, isolated ----------------------------------------------------
    # THE HEADLINE GUARD, and therefore the one to mutate first. `assign_evidence` is a maximum
    # bipartite MATCHING, not a "does any evidence mention me" test, and only a fixture where one
    # literal is a candidate for TWO sites can tell the two apart.
    def dup_audit(source):
        return [(f["symbol"], f["uncovered"]) for f in
                audit({"scripts/d.py": source}, {"scripts/d.py": set(range(1, 30))})["findings"]]

    duplicate = (
        "def _mech(x):\n    return x\n"
        "def alpha_writer():\n    _mech(1)\n"
        "def beta_writer():\n    _mech(2)\n"
        "def _dup_self_test():\n"
        "    assert True, 'alpha_writer passes the mechanism'\n"
        "    assert True, 'alpha_writer still passes it after a retry'\n")
    check("DISTINCTNESS: two checks naming the SAME site cover one site, not two",
          dup_audit(duplicate), [("_mech", 1)])
    quantified_over_both = duplicate.replace(
        "    assert True, 'alpha_writer passes the mechanism'\n"
        "    assert True, 'alpha_writer still passes it after a retry'\n",
        "    assert True, 'alpha_writer and beta_writer both pass the mechanism'\n")
    check("DISTINCTNESS: ONE literal naming BOTH sites proves ONE of them — this is the whole "
          "#939 rule, and the fixture that separates a MATCHING from a mentions-me test",
          dup_audit(quantified_over_both), [("_mech", 1)])
    # And the augmenting path: alpha can be named by either literal, beta only by the shared one.
    # A greedy first-fit that hands the shared literal to alpha strands beta; the matching
    # re-points alpha at its exclusive literal and covers both.
    contended = duplicate.replace(
        "    assert True, 'alpha_writer still passes it after a retry'\n",
        "    assert True, 'alpha_writer and beta_writer both pass the mechanism'\n")
    check("DISTINCTNESS: a contended literal is re-assigned so an exclusively-named site is not "
          "stranded (the augmenting path, not first-fit)",
          dup_audit(contended), [("_mech", 0)])
    both = duplicate.replace("'alpha_writer still passes it after a retry'",
                             "'beta_writer passes the mechanism too'")
    check("DISTINCTNESS: one named check per site covers both and goes quiet",
          dup_audit(both), [("_mech", 0)])

    # ---- The TRIGGER, one discriminating fixture per way in and per way out ------------------
    # (1) CALL-SHAPED TOUCH, arm A: the signature. (2) SHARED. And the valve.
    signature_only = {"scripts/q.py": {1}}                 # the `def` line only
    check("TRIGGER signature: a helper whose SIGNATURE this PR changed is examined",
          audit({"scripts/q.py": shared}, signature_only)["symbols_triggered"], 1)
    call_only = {"scripts/q.py": {4}}                      # one call site only
    check("TRIGGER call-site: ...and so is one whose def stood still while a CALL SITE changed "
          "— the add-it-to-three-of-four-writers shape a def-only trigger cannot see",
          audit({"scripts/q.py": shared}, call_only)["symbols_triggered"], 1)
    # THE FALSE-POSITIVE VALVE. A pure helper whose BODY changed, whose signature and call sites
    # the PR did not touch, is not this defect class — its callers pass nothing new, so there is
    # nothing to drop from exactly one of them. Without this condition every shared helper in a
    # changed file becomes a finding and the check gets disabled.
    body_only = {"scripts/q.py": {2}}                      # the `return reason` line only
    check("TRIGGER valve: a BODY-only edit to a shared helper is NOT flagged",
          audit({"scripts/q.py": shared}, body_only)["symbols_triggered"], 0)
    check("TRIGGER valve: an untouched file contributes nothing",
          audit({"scripts/q.py": shared}, {})["symbols_triggered"], 0)
    # (2) shared. One call site cannot have a per-site coverage gap.
    single = ("def _mech(x):\n    return x\n"
              "def only_writer():\n    _mech(1)\n")
    check("TRIGGER shared: a single-call-site symbol is examined but never a finding",
          [audit({"scripts/s.py": single}, {"scripts/s.py": {1}})[key]
           for key in ("symbols_examined", "symbols_triggered")], [1, 0])
    check("TRIGGER scope: a call the repo does not DEFINE (`.clear()`) is out of scope",
          audit({"scripts/s.py": "def a(d):\n    d.clear()\ndef b(d):\n    d.clear()\n"},
                {"scripts/s.py": {2}})["symbols_examined"], 0)

    # ---- Exclusions -------------------------------------------------------------------------
    recursive = ("def _mech(x):\n    return _mech(x - 1) if x else 0\n"
                 "def only_writer():\n    _mech(1)\n")
    closure = {"scripts/c.py": ("def outer(items):\n"
                                "    def append(x):\n        items.append(x)\n"
                                "    append(1)\n    append(2)\n"),
               "scripts/d.py": "def unrelated(rows):\n    rows.append(1)\n    rows.append(2)\n"}
    check("EXCLUSION: a CLOSURE is not a repo symbol — a local `append` must not claim every "
          "`list.append(...)` in the tree as one of its call sites (measured on the real #886 "
          "diff: one such collision produced 399 phantom sites)",
          audit(closure, {"scripts/c.py": {2}})["symbols_examined"], 0)
    check("EXCLUSION: a recursive self-call is not a second site",
          audit({"scripts/r.py": recursive},
                {"scripts/r.py": set(range(1, 10))})["symbols_triggered"], 0)
    probed = (single + "def _probe_self_test():\n    _mech(2)\n    _mech(3)\n")
    check("is_harness SITE _collect_calls: the harness's own probe calls are not write sites — without the exclusion a real site hides behind a probe",
          audit({"scripts/p.py": probed},
                {"scripts/p.py": set(range(1, 20))})["symbols_triggered"], 0)
    check("is_harness SITE _evidence_of: a PRODUCTION assert message is not evidence — only a self-test can NAME a site",
          audit({"scripts/e.py": (
              "def _mech(x):\n    return x\n"
              "def alpha_writer():\n    assert 1, 'alpha_writer holds'\n    _mech(1)\n"
              "def beta_writer():\n    assert 1, 'beta_writer holds'\n    _mech(2)\n")},
              {"scripts/e.py": set(range(1, 20))})["sites_without_distinct_named_check"], 2)

    # ---- SYMBOL IDENTITY is (module, name), not name --------------------------------------
    # Measured on this check's own diff: name-alone identity attributed all 42 module-level
    # `main()` calls in the repo to one script's `main`, and three unrelated `_git` helpers to
    # each other.
    twin = {"scripts/one.py": "def main():\n    pass\ndef a():\n    main()\ndef b():\n    main()\n",
            "scripts/two.py": "def main():\n    pass\ndef c():\n    main()\n"}
    twin_census = audit(twin, {"scripts/one.py": {1}, "scripts/two.py": {1}})
    check("IDENTITY: a BARE call resolves to the `main` its OWN module defines — two modules, "
          "two symbols, not one symbol with three sites",
          sorted((f["path"], len(f["sites"])) for f in twin_census["findings"]),
          [("scripts/one.py", 2)])
    check("IDENTITY: a symbol of the same name in an UNTOUCHED module is not dragged in — the "
          "trigger keys on (module, name), and only one module here was changed",
          audit(twin, {"scripts/two.py": {1}})["symbols_examined"], 1)
    solo = {"scripts/lib.py": "def helper():\n    pass\n",
            "scripts/user.py": "def a(m):\n    m.helper()\ndef b(m):\n    m.helper()\n"}
    check("IDENTITY: an ATTRIBUTE call reaches a sibling module when exactly ONE module defines "
          "the name",
          [len(f["sites"]) for f in audit(solo, {"scripts/lib.py": {1}})["findings"]], [2])
    ambiguous = dict(solo, **{"scripts/lib2.py": "def helper():\n    pass\n"})
    check("IDENTITY: ...and does NOT when two modules define it — the base is unresolvable and "
          "guessing would re-import the collision",
          audit(ambiguous, {"scripts/lib.py": {1}})["symbols_triggered"], 0)
    foreign = {"scripts/lib.py": ("def render():\n    pass\n"
                                  "def p():\n    render()\ndef q():\n    render()\n"),
               "scripts/app.py": "from lib import render\ndef r():\n    render()\n"}
    check("IDENTITY: a BARE call in a module that does not DEFINE the name implicates nothing — "
          "the changed line is in app.py, and lib.py's `render` is not this PR's mechanism",
          audit(foreign, {"scripts/app.py": {3}})["symbols_examined"], 0)

    # ---- INDISTINGUISHABLE sites are counted apart from UNNAMED ones ------------------------
    # Two calls in the SAME function passing no literal of their own share every fingerprint.
    # Calling them "unnamed" would be a claim this check cannot support.
    twinned = ("def _mech(x):\n    return x\n"
               "def one_writer(a, b):\n    _mech(a)\n    _mech(b)\n")
    twin_sites = audit({"scripts/t.py": twinned}, {"scripts/t.py": {1}})
    check("discriminating_fingerprints SITE audit: sites sharing every fingerprint are NOT reported as unnamed",
          (twin_sites["sites_without_distinct_named_check"],
           twin_sites["sites_indistinguishable"]), (0, 2))
    told_apart = twinned.replace("_mech(a)", "_mech('the first writer path')")
    apart = audit({"scripts/t.py": told_apart}, {"scripts/t.py": {1}})
    check("literal_text SITE _arg_literals: give one site a literal of its own and it becomes "
          "nameable — and is then reported as UNNAMED until something names it",
          (apart["sites_without_distinct_named_check"], apart["sites_indistinguishable"]),
          (1, 1))

    # ---- The MECHANISM's own name is not a site fingerprint ---------------------------------
    check("`_mech` itself is not a fingerprint: a check that names only the MECHANISM covers "
          "no site",
          site_fingerprints({"stack": ("alpha_writer",), "args": []}), ["alpha_writer"])

    # ---- Fail-closed ------------------------------------------------------------------------
    unparseable = False
    try:
        audit({"scripts/broken.py": "def ((:\n"}, {"scripts/broken.py": {1}})
    except CoverageError:
        unparseable = True
    check("FAIL CLOSED: an unparseable script refuses rather than reporting no findings",
          unparseable, True)
    missing = False
    try:
        read_sources(Path(os.devnull).parent / "definitely-not-a-repo")
    except CoverageError:
        missing = True
    check("FAIL CLOSED: an empty scripts/ refuses rather than reporting a vacuous census",
          missing, True)

    # ---- The census is emitted on EVERY run -------------------------------------------------
    empty = audit({"scripts/q.py": shared}, {})
    check("CENSUS: every key is present even when nothing triggered",
          all(key in empty for key in CENSUS_KEYS), True)
    check("CENSUS: the line names each counter",
          census_line(empty),
          "callsite-coverage census: files_changed=0 symbols_examined=0 symbols_triggered=0 "
          "sites_found=0 sites_without_distinct_named_check=0 sites_indistinguishable=0")
    check("CENSUS: a finding renders as an ADVISORY warning, never an error",
          any(line.startswith("::warning") for line in render(quantified))
          and not any("::error" in line for line in render(quantified)), True)

    # ---- The gate wiring is real ------------------------------------------------------------
    # #939 requires that a workflow change be pinned at the `if:`, the step AND the call site.
    # This is the call-site half: pr-gate.yml must actually invoke this script, in ADVISORY mode,
    # in a step that cannot fail the required check.
    workflow = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "pr-gate.yml"
    if workflow.exists():
        text = workflow.read_text(encoding="utf-8")
        check("WIRING: pr-gate.yml invokes this script's ADVISORY mode",
              "scripts/callsite-coverage.py --advisory" in text, True)
        check("WIRING: the advisory step cannot fail the required gate",
              "|| echo \"::warning::callsite-coverage (advisory) could not run\"" in text, True)
        check("WIRING: the census reaches the log unconditionally (no `if:` can skip it)",
              re.search(r"\n      - name: [^\n]*callsite-coverage[^\n]*\n        run:", text)
              is not None, True)

    print(f"callsite-coverage self-test: {'FAILED' if failures else 'ok'} "
          f"({len(failures)} failure(s))")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--advisory", action="store_true")
    parser.add_argument("--base", help="base commit to diff HEAD against")
    parser.add_argument("--diff-file", help="read a --unified=0 diff from here instead of git")
    parser.add_argument("--root", default=".", help="tree to analyse")
    parser.add_argument("--json", dest="json_path", help="write the census as JSON")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if not args.advisory:
        parser.error("one of --self-test or --advisory is required")
    try:
        return run_advisory(Path(args.root), args.base, args.diff_file, args.json_path)
    except CoverageError as exc:
        print(f"::warning::callsite-coverage could not run: {exc}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
