#!/usr/bin/env python3
# [issue #670] Keep README.md's enrolment runbook executable VERBATIM against the LIVE policy rules.
"""readme-runbook-check — validate the documented enrolment runbook against the real resolver.

`README.md` promises its "Adding an account" runbook can be followed verbatim. Twice on 2026-07-27
it could not be: its `account_pool` example named the retired `acct03`, and later its steps created
`acct05` while the pool example named `acct08` — so following it authorised a slot other than the
one just enrolled. Both were fixed in the prose; nothing stopped a future retirement, handle-shape
change, or runbook edit from silently invalidating the documented steps again.

THE DESIGN CONSTRAINT, which is the whole reason this is a separate module (#660 produced a defect
in three consecutive rounds, each caused by the previous fix):

  * **Parse, do not split.** Every fenced toml block is handed to `tomllib` UNCHANGED. A documented
    block that is not valid TOML is a defect to REPORT, never something to normalise past. Round 6
    text-split the block and stripped quotes, so `account_pool = [acct01, acct02]` — invalid TOML —
    normalised into valid handles and passed.
  * **Ask the resolver, never re-derive its rules.** The claim under test is "policy-resolve would
    accept this pool", so `policy-resolve.resolve()` is the thing that says so. Round 5 checked
    individual HANDLES against a handle regex, so `[]` and `["acct01","acct01"]` passed a test
    claiming the resolver accepts them — it rejects both. Any rule this module re-implements is a
    second, worse copy of the resolver, and every gap between the two is a FALSE GREEN.
  * **Correlate per SECTION, not over global sets.** The invariant is "the handle THIS runbook
    creates appears in THIS runbook's pool example". Round 6 unioned handles across the whole
    README, which proves only that each handle appears SOMEWHERE — two runbooks with swapped
    handles would both pass.
  * **Pin each extraction source separately.** A source that silently stops matching must FAIL,
    not narrow the check. #660 hit this too: neutering one of two handle regexes left the union
    non-empty via the other, so the check kept passing while seeing less.

The enforcement path is `--self-test`, which runs the live check over the real README/policy/
routing. Deleting the check entirely is caught one level up, by the gate's own `ran -gt 0` suite
guard plus the base-branch retirement approval in `scripts/selftest-retirements.txt` — no assertion
can detect its own deletion.

Offline and pure: reads files, performs no network access, no `gh`, and no secret handling.
"""
import argparse
import copy
import importlib.util
import io
import re
import sys
import tomllib
from pathlib import Path


def _import_sibling(module_name, filename):
    """Import a sibling script by path (the #715 idiom — these scripts have no package)."""
    path = Path(__file__).resolve().with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# THE RESOLVER ITSELF. Imported, never re-declared: the assertion this module makes is "the
# resolver accepts the documented pool", so the resolver must be the thing that answers.
_policy_resolve = _import_sibling("registry_policy_resolve", "policy-resolve.py")
PolicyError = _policy_resolve.PolicyError
resolve = _policy_resolve.resolve

REPO_ROOT = Path(__file__).resolve().parent.parent
README_PATH = REPO_ROOT / "README.md"
POLICY_FILE = REPO_ROOT / "policy" / "repos.toml"
ROUTING_FILE = REPO_ROOT / "orchestration" / "routing.toml"

# A level-2 heading opens a new section; the section runs to the next level-2 heading. Deeper
# headings (`### Step 1`) stay INSIDE their runbook, which is the granularity the invariant needs.
SECTION_RE = re.compile(r"^## +\S")
FENCE_OPEN_RE = re.compile(r"^[ \t]*```toml[ \t]*$")
FENCE_ANY_RE = re.compile(r"^[ \t]*```")

# THE EXTRACTION SOURCES. Each names one place a runbook step COMMITS to a slot number, and each is
# checked SEPARATELY: a source that stops matching fails the check rather than quietly narrowing it
# to the sources that still match.
#
# Every source captures DIGITS ONLY, which is the README's own stated naming convention ("Handle =
# `acctNN`"). That is what keeps the documentation-only placeholder forms — `acctNN` and
# `ACCTNN_TOKEN`, which the README states its convention with, right beside the concrete steps —
# from masquerading as a second slot commitment: `acctnn` would otherwise be a perfectly canonical
# handle by the resolver's own ACCOUNT_HANDLE_RE and would contradict the real one. A handle with a
# non-numeric suffix (the pool carries legacy `acct2css`-shaped names) is therefore not extractable
# here, and a runbook documenting one fails VISIBLY as `missing-handle-source` rather than being
# silently truncated to a shorter handle.
HANDLE_SOURCES = (
    # `gh api .../git/refs -f ref='refs/acct-claims/acct05'` — the slot claim.
    ("claim-ref", re.compile(r"refs/acct-claims/acct([0-9]+)")),
    # `select-and-claim.py --validate-account-record --account-handle acct05`.
    ("validate-handle", re.compile(r"--account-handle +acct([0-9]+)")),
    # `gh issue create --title "acct05"` — the catalog entry read_accounts() reads.
    ("issue-title", re.compile(r'--title +"acct([0-9]+)"')),
    # The account record's own `secret_ref:` line, anchored to a line start so the surrounding
    # prose's inline `secret_ref: ACCTNN_TOKEN` example is not mistaken for a commitment.
    ("secret-ref", re.compile(r"^secret_ref: ACCT([0-9]+)_TOKEN[ \t]*$", re.M)),
)


def split_sections(text):
    """Split markdown into (heading, body, first_line_number) at every level-2 heading.

    The body INCLUDES the heading line, so a source that appears in a heading still binds to the
    section it heads. Text before the first level-2 heading is its own leading section. Sections are
    returned in document order and are never merged by heading text — two sections that happen to
    share a heading must still be correlated separately.
    """
    sections = []
    heading = ""
    lines = []
    first = 1
    for number, line in enumerate(text.splitlines(), start=1):
        if SECTION_RE.match(line):
            sections.append((heading, "\n".join(lines), first))
            heading, lines, first = line.strip(), [line], number
        else:
            lines.append(line)
    sections.append((heading, "\n".join(lines), first))
    return sections


def toml_blocks(text, first_line=1):
    """Every fenced toml block, as (line_number, body) with the body UNCHANGED.

    The body is returned exactly as written — not dedented, not unquoted, not normalised. TOML
    tolerates leading whitespace, so an indented fence parses as-is; anything that does not parse is
    a documentation defect this module reports rather than repairs. A block whose fence is never
    closed is returned with a body of ``None``: the reader cannot tell where it ends either.
    """
    blocks = []
    open_line = None
    body = []
    for offset, line in enumerate(text.splitlines()):
        number = first_line + offset
        if open_line is None:
            if FENCE_OPEN_RE.match(line):
                open_line, body = number, []
        elif FENCE_ANY_RE.match(line):
            blocks.append((open_line, "\n".join(body) + "\n"))
            open_line = None
        else:
            body.append(line)
    if open_line is not None:
        blocks.append((open_line, None))
    return blocks


def section_handles(body):
    """{source name: set of handles} for one section — one entry per source, empty sets included."""
    return {name: {f"acct{digits}" for digits in pattern.findall(body)}
            for name, pattern in HANDLE_SOURCES}


def _overlay_documented_row(policy_doc, target_repo, documented_row):
    """The live policy with ONE repo row overlaid by the documented edit, deep-copied.

    Step 5 tells the reader to EDIT `policy/repos.toml`, so the documented block is an overlay on
    the live row, not a standalone document. Applying it and resolving is the faithful simulation of
    following the runbook. Returns None when the documented row names a repo the live policy does
    not carry — fail closed rather than invent a row.
    """
    merged = copy.deepcopy(policy_doc)
    repos = merged.get("repos")
    if not isinstance(repos, dict) or target_repo not in repos:
        return None
    row = repos[target_repo]
    if not isinstance(row, dict):
        return None
    row.update(copy.deepcopy(documented_row))
    return merged


def check_readme(readme_text, policy_doc, routing_doc, resolver=None):
    """Validate the documented runbooks. Returns (problems, census).

    `problems` is a list of stable, prefixed strings — empty means every documented runbook can be
    followed verbatim. `census` ALWAYS emits, including zero rows, so a check that silently stopped
    seeing anything is visible instead of reading as a pass.

    `resolver` is an injected probe with `policy-resolve.resolve`'s signature. Production passes
    nothing; the self-test injects a resolver that ignores the overlay in order to drive the
    `overlay-not-applied` guard, which is otherwise unreachable from a fixture.
    """
    resolver = resolve if resolver is None else resolver
    problems = []
    census = {"toml_blocks": 0, "runbook_sections": 0, "pool_rows": 0, "handles": []}
    handles_seen = set()

    for heading, body, first_line in split_sections(readme_text):
        label = heading or "(preamble)"

        # 1. PARSE, DO NOT SPLIT — every documented TOML block in this section, unchanged, through
        # tomllib. Every section is parsed, including ones that document no runbook: a block that
        # does not parse is a defect wherever it sits.
        documented = []
        for line_no, block in toml_blocks(body, first_line):
            census["toml_blocks"] += 1
            if block is None:
                problems.append(f"unterminated-toml-fence:{label}:line {line_no}")
                continue
            try:
                documented.append((line_no, tomllib.loads(block)))
            except tomllib.TOMLDecodeError as exc:
                problems.append(f"invalid-toml:{label}:line {line_no}: {exc}")

        found = section_handles(body)
        if not any(found.values()):
            continue                      # not a runbook: it commits to no slot at all
        census["runbook_sections"] += 1

        # 2. EACH SOURCE PINNED SEPARATELY — a source that stopped matching FAILS here rather than
        # leaving the union non-empty via the sources that still match.
        for name in sorted(found):
            if not found[name]:
                problems.append(f"missing-handle-source:{label}:{name}")
        union = set().union(*found.values())
        if len(union) != 1:
            problems.append(f"ambiguous-handle:{label}:{sorted(union)}")
            continue
        handle = union.pop()
        handles_seen.add(handle)

        # 3. CORRELATE WITHIN THIS SECTION ONLY. Scoping the pool examples to `documented` — this
        # section's blocks — is what stops two runbooks with swapped handles from vouching for each
        # other, which a whole-README union cannot distinguish from a correct pair.
        rows = []
        for line_no, doc in documented:
            repos_table = doc.get("repos")
            if not isinstance(repos_table, dict):
                continue          # valid TOML, but not the shape Step 5 documents
            for repo, row in repos_table.items():
                if isinstance(row, dict) and "account_pool" in row:
                    rows.append((line_no, repo, row))
        if not rows:
            problems.append(f"no-pool-example:{label}:{handle}")
            continue
        for line_no, repo, row in rows:
            census["pool_rows"] += 1
            merged = _overlay_documented_row(policy_doc, repo, row)
            if merged is None:
                problems.append(f"unknown-repo:{label}:line {line_no}:{repo}")
                continue
            # 4. ASK THE RESOLVER. Roleless, so routing resolves through [defaults]: the claim being
            # validated is about the POOL, and re-implementing the pool rules here is exactly the
            # second-implementation failure this module exists to avoid.
            try:
                resolved = resolver(repo, [], merged, routing_doc)
            except PolicyError as exc:
                problems.append(f"resolver-refused:{label}:line {line_no}:{repo}: {exc}")
                continue
            # The overlay must be what the resolver actually saw. Without this the LIVE pool would
            # answer for the documented one, and since the live pool already contains the enrolled
            # handle the correlation below would pass no matter what the block says.
            if resolved["account_pool"] != row["account_pool"]:
                problems.append(f"overlay-not-applied:{label}:line {line_no}:{repo}")
                continue
            if handle not in resolved["account_pool"]:
                problems.append(
                    f"handle-not-in-pool:{label}:line {line_no}:{repo}: steps enrol {handle} but "
                    f"the documented pool is {resolved['account_pool']}")

    if census["runbook_sections"] == 0:
        # Fail closed: no runbook found means the extraction stopped matching, not that the
        # documentation became correct.
        problems.append("no-runbook-section: no section commits to an account handle")
    census["handles"] = sorted(handles_seen)
    return problems, census


def _load_toml(path):
    with open(path, "rb") as handle:
        return tomllib.load(handle)


def _check_live():
    return check_readme(README_PATH.read_text(encoding="utf-8"),
                        _load_toml(POLICY_FILE), _load_toml(ROUTING_FILE))


def report(problems, census, stream=sys.stderr):
    """Print the verdict and return the process exit code. The census ALWAYS emits, including a
    zero row, so a run that saw nothing is distinguishable from a run that saw a clean runbook."""
    for problem in problems:
        print(f"readme-runbook-check: {problem}", file=stream)
    print(f"readme-runbook-check: census {census}", file=stream)
    return 1 if problems else 0


# ─── self-test ───────────────────────────────────────────────────────────────────────────────
# The fixture policy's LIVE pools deliberately EXCLUDE the handles the fixture runbooks enrol, so
# every pass below is earned by the documented overlay rather than by the live row.
_FIXTURE_POLICY = '''
[repos."o/alpha"]
enabled = true
routing = "orchestration/routing.toml"
account_pool = ["acct01"]
max_concurrent = 2
worker_timeout_minutes = 90
gate_profile = "lint-only"
arm_auto_merge = false
max_attempts = 2
trust = "collaborators"

[repos."o/beta"]
enabled = true
routing = "orchestration/routing.toml"
account_pool = ["acct01"]
max_concurrent = 2
worker_timeout_minutes = 90
gate_profile = "lint-only"
arm_auto_merge = false
max_attempts = 2
trust = "collaborators"
'''

_FIXTURE_ROUTING = '''
[models.opus5]
provider = "anthropic"
[defaults]
model_chain = ["opus5"]
agent = "registry-impl"
'''

# Composed rather than written literally so this module's own source carries no fenced toml block
# that a reader (or a future doc extractor pointed at scripts/) could mistake for documentation.
_FENCE = "`" * 3


def _fixture_runbook(heading, repo, handle, pool):
    """One synthetic runbook section that exercises all four extraction sources."""
    return f"""## {heading}

{_FENCE}bash
gh api repos/o/r/git/refs -f ref='refs/acct-claims/{handle}'
printf '%s' "$body" | python3 scripts/select-and-claim.py \\
  --validate-account-record --account-handle {handle}
gh issue create --title "{handle}" --label account --body "$body"
{_FENCE}

The record body:

{_FENCE}text
secret_ref: {handle.upper()}_TOKEN
{_FENCE}

{_FENCE}toml
[repos."{repo}"]
account_pool = {pool}
{_FENCE}
"""


# The source names this suite expects, written out independently of HANDLE_SOURCES so that a
# deleted or renamed source reds a named assertion instead of shrinking the sweep below.
_EXPECTED_SOURCES = ["claim-ref", "issue-title", "secret-ref", "validate-handle"]

# The README states its naming convention in `acctNN` / `ACCTNN_TOKEN` placeholder form right
# beside the concrete steps, so every source must read a placeholder as documentation rather than
# as a second slot commitment — `acctnn` is itself a canonical handle by ACCOUNT_HANDLE_RE. Both
# cases are present: a source widened to accept letters admits one or the other, never neither.
_PLACEHOLDER_PROSE = (
    'The slot is `acctNN`; its claim ref is `refs/acct-claims/acctNN`, its secret is\n'
    '`ACCTNN_TOKEN`, and the steps read `--title "acctNN"` / `--account-handle acctNN`.\n'
    'secret_ref: ACCTNN_TOKEN\n'
    'Lower-cased, the same placeholders read `refs/acct-claims/acctnn`, `--title "acctnn"`,\n'
    '`--account-handle acctnn`.\n'
    'secret_ref: ACCTnn_TOKEN\n')

_POOL_A = '["acct01", "acct21"]'
_POOL_B = '["acct01", "acct22"]'
_BLOCK_A = f'{_FENCE}toml\n[repos."o/alpha"]\naccount_pool = {_POOL_A}\n{_FENCE}\n'
_FIXTURE_README = (
    "# Fixture\n\nPreamble with no handle commitment.\n\n"
    + _fixture_runbook("Adding an account — runbook A", "o/alpha", "acct21", _POOL_A)
    + "\n"
    + _fixture_runbook("Registering an account — runbook B", "o/beta", "acct22", _POOL_B)
)


def _self_test():
    policy = tomllib.loads(_FIXTURE_POLICY)
    routing = tomllib.loads(_FIXTURE_ROUTING)
    policy_before = copy.deepcopy(policy)
    routing_before = copy.deepcopy(routing)
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    def run(readme, resolver=None):
        return check_readme(readme, policy, routing, resolver=resolver)

    def refuses(name, readme, needle, resolver=None):
        nonlocal ok
        problems, _ = run(readme, resolver=resolver)
        good = any(needle in problem for problem in problems)
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {problems!r} "
              f"(want a problem containing {needle!r})")

    # ---- THE EXTRACTION-SOURCE TABLE IS PINNED AGAINST A LITERAL. The per-source neutering loop
    # below iterates HANDLE_SOURCES, so deleting a source would silently shrink the loop to a
    # smaller, still-green sweep. The expected set is written out here, independently of the code
    # under test, so a deleted or renamed source reds instead of narrowing the check.
    check("the extraction sources are exactly the four documented commitments",
          sorted(name for name, _ in HANDLE_SOURCES), _EXPECTED_SOURCES)
    check("no source name is declared twice (a duplicate would make one copy unkillable)",
          len({name for name, _ in HANDLE_SOURCES}), len(HANDLE_SOURCES))
    check("the documentation-only placeholder forms are NOT read as a slot commitment by ANY "
          "source — `acctnn` would otherwise be a canonical handle and contradict the real steps",
          {name: sorted(found) for name, found in section_handles(_PLACEHOLDER_PROSE).items()},
          {name: [] for name in _EXPECTED_SOURCES})

    # ---- THE TWO EXTRACTORS, DIRECTLY. The section body must CONTAIN its heading (a source
    # written into a heading still belongs to that runbook), and block line numbers must be FILE
    # lines — a diagnostic that points at the wrong line sends the reader to the wrong runbook.
    check("split_sections keeps each heading inside its own body and reports the heading's line",
          [(heading, body.splitlines()[0] if body.splitlines() else "", first)
           for heading, body, first in split_sections("a\n## H1\nb\n## H2\nc\n")],
          [("", "a", 1), ("## H1", "## H1", 2), ("## H2", "## H2", 4)])
    check("toml_blocks offsets by the section's first line, returns the body UNCHANGED, and "
          "reports an unterminated fence as a None body",
          toml_blocks(f"x\n{_FENCE}toml\n  a = 1\n{_FENCE}\ny\n{_FENCE}toml\nb = 2\n",
                      first_line=10),
          [(11, "  a = 1\n"), (15, None)])

    # ---- BASELINE: the fixture runbooks are followable, and the census says what was examined.
    problems, census = run(_FIXTURE_README)
    check("BASELINE — two consistent fixture runbooks raise no problem", problems, [])
    check("...and the census reports BOTH sections, both pool rows, and both handles",
          census, {"toml_blocks": 2, "runbook_sections": 2, "pool_rows": 2,
                   "handles": ["acct21", "acct22"]})

    # ---- THE OVERLAY IS LOAD-BEARING, PROVED TWICE. The fixture's live pools are ["acct01"], so a
    # resolver that read the LIVE row instead of the documented one could never satisfy the
    # correlation above; and if the two were ever to diverge, `overlay-not-applied` says so.
    check("the fixture's LIVE pools do not contain the enrolled handles (so the baseline pass is "
          "earned by the documented overlay, not by the live row)",
          sorted(policy["repos"]["o/alpha"]["account_pool"]
                 + policy["repos"]["o/beta"]["account_pool"]),
          ["acct01", "acct01"])
    refuses("a resolver that IGNORES the overlay is caught by overlay-not-applied rather than "
            "silently answering for the live row", _FIXTURE_README, "overlay-not-applied",
            resolver=lambda repo, labels, _merged, routing_doc: resolve(
                repo, labels, policy, routing_doc))

    # ---- CORRELATION IS PER SECTION. Swapping the two runbooks' pool handles leaves every handle
    # present SOMEWHERE in the README — the exact state a global-union check calls clean.
    swapped = _FIXTURE_README.replace(_POOL_A, "<A>").replace(_POOL_B, _POOL_A).replace(
        "<A>", _POOL_B)
    check("the swap fixture really swapped (each pool present exactly once, now bound to the "
          "other runbook)",
          (swapped.count(_POOL_A), swapped.count(_POOL_B), swapped != _FIXTURE_README),
          (1, 1, True))
    swapped_problems, _ = run(swapped)
    check("SWAPPED handles across two runbook sections are refused — for BOTH sections, which a "
          "global-union check would call clean",
          sorted(p.split(":")[0] for p in swapped_problems),
          ["handle-not-in-pool", "handle-not-in-pool"])

    # ---- EACH DOCUMENTED RULE OF THE RESOLVER, ASKED OF THE RESOLVER.
    def pool_variant(pool):
        variant = _FIXTURE_README.replace(_POOL_A, pool)
        assert variant != _FIXTURE_README, "pool variant anchor stopped matching"
        return variant

    refuses("an EMPTY documented pool is refused (a per-handle regex would have passed it)",
            pool_variant("[]"), "must be a non-empty string list")
    refuses("a DUPLICATED handle is refused (a per-handle regex would have passed it)",
            pool_variant('["acct21", "acct21"]'), "contains duplicates")
    refuses("a RETIRED handle in the documented pool is refused",
            pool_variant('["acct21", "acct03"]'), "RETIRED")
    refuses("a PADDED handle is refused as non-canonical",
            pool_variant('[" acct21"]'), "non-canonical")
    refuses("an UNQUOTED handle is INVALID TOML and fails as such — never normalised into a valid "
            "handle (the round-6 defect)",
            pool_variant("[acct01, acct21]"), "invalid-toml")
    bad_toml_problems, _ = run(pool_variant("[acct01, acct21]"))
    check("...and the refusal names the fence's FILE line, derived here from the fixture rather "
          "than from the extractor, so a section-relative number reds",
          [p.split(":line ")[1].split(":")[0]
           for p in bad_toml_problems if p.startswith("invalid-toml")],
          [str(_FIXTURE_README.splitlines().index(f"{_FENCE}toml") + 1)])
    refuses("an UNTERMINATED fence is reported, not silently swallowed",
            _FIXTURE_README.replace(f"account_pool = {_POOL_A}\n{_FENCE}\n",
                                    f"account_pool = {_POOL_A}\n"),
            "unterminated-toml-fence")
    refuses("a documented pool for a repo the live policy does not know fails closed",
            _FIXTURE_README.replace('[repos."o/alpha"]', '[repos."o/ghost"]'), "unknown-repo")
    check("...and the overlay refuses that repo at its own boundary, in BOTH shapes it can be "
          "absent — no row, and a row that is not a table",
          (_overlay_documented_row({"repos": {}}, "o/ghost", {}),
           _overlay_documented_row({"repos": {"o/alpha": "not-a-table"}}, "o/alpha", {})),
          (None, None))

    # ---- SOURCES THAT DISAGREE ARE AMBIGUOUS, and the section is NOT correlated against a handle
    # picked arbitrarily from among them. This is the #660 r5 shape at source granularity: the steps
    # would enrol one slot and authorise another.
    disagreeing = _FIXTURE_README.replace("refs/acct-claims/acct21", "refs/acct-claims/acct23")
    check("the disagreement fixture really changed one source and only one",
          (disagreeing != _FIXTURE_README, disagreeing.count("acct23")), (True, 1))
    disagree_problems, _ = run(disagreeing)
    check("sources that DISAGREE about the slot are refused as ambiguous, and no handle is "
          "correlated for that section",
          sorted(p.split(":")[0] for p in disagree_problems), ["ambiguous-handle"])
    refuses("a runbook with NO pool example at all is refused (the #660 r5 shape: steps that "
            "enrol a handle no documented pool authorises)",
            _FIXTURE_README.replace(_BLOCK_A, ""), "no-pool-example")
    for shape, replacement in (("a non-table `repos`", 'repos = "not-a-table"'),
                               ("a `repos` row that is not a table", '[repos]\nalpha = "x"')):
        refuses(f"a block that is valid TOML but carries {shape} is no pool example — the runbook "
                f"is refused rather than the block being read past",
                _FIXTURE_README.replace(f'[repos."o/alpha"]\naccount_pool = {_POOL_A}',
                                        replacement),
                "no-pool-example")

    # ---- A NEUTERED EXTRACTION SOURCE FAILS, ONE SOURCE AT A TIME. Each source is disabled in the
    # fixture by deleting the lines it matches; the other three still match, so a check that merely
    # unions its sources would stay green on every iteration here.
    # It iterates the LITERAL _EXPECTED_SOURCES, never HANDLE_SOURCES: driving the loop from the
    # code under test would let a deleted source shrink the sweep to a smaller, still-green run —
    # the mutant would then change the CHECK COUNT, and a suite whose size moves with the code
    # cannot distinguish "fewer checks" from "fewer defects" (AGENTS.md pre-flight item 4).
    by_name = dict(HANDLE_SOURCES)
    for name in _EXPECTED_SOURCES:
        pattern = by_name.get(name)
        lines = _FIXTURE_README.splitlines()
        kept = [line for line in lines
                if pattern is None or not pattern.search(line + "\n")]
        neutered = "\n".join(kept) + "\n"
        check(f"the {name} source is declared AND actually present in the fixture (a neutering "
              f"that deletes nothing would prove nothing)",
              (pattern is not None, len(lines) - len(kept)), (True, 2))
        neutered_problems, _ = run(neutered)
        check(f"neutering the {name} source FAILS the check, naming that source, rather than "
              f"narrowing it to the three that still match",
              sorted({p.rsplit(":", 1)[1] for p in neutered_problems
                      if p.startswith("missing-handle-source")}),
              [name])

    # ---- A README THAT COMMITS TO NO HANDLE AT ALL FAILS CLOSED (a census that always emits).
    empty_problems, empty_census = run("# Fixture\n\nNothing here.\n")
    check("a README with no runbook fails closed instead of reporting a clean zero",
          (sorted(empty_problems), empty_census["runbook_sections"]),
          (["no-runbook-section: no section commits to an account handle"], 0))

    # ---- THE LIVE README, THROUGH THE LIVE POLICY AND ROUTING. This is the assertion the gate
    # actually enforces; everything above establishes that it can fail.
    live_problems, live_census = _check_live()
    check("the LIVE README enrolment runbook is followable verbatim", live_problems, [])
    check("...and the live census proves the check BOUND to a real runbook rather than seeing "
          "nothing: one runbook section, at least one documented pool row, exactly one handle",
          (live_census["runbook_sections"], live_census["pool_rows"] >= 1,
           [h for h in live_census["handles"] if re.fullmatch(r"acct[0-9]+", h)]
           == live_census["handles"], len(live_census["handles"])),
          (1, True, True, 1))
    check("...and every fenced toml block in the live README parsed (block discovery did not "
          "narrow to the pool example alone)", live_census["toml_blocks"] >= 3, True)

    # ---- THE CLI ENTRY POINT ITSELF — the region a fixture-only suite never executes. `report`
    # must carry the verdict into the exit code in BOTH directions, and must emit the census either
    # way: a run that reports "clean" and a run that saw nothing must not look the same.
    clean_out, dirty_out = io.StringIO(), io.StringIO()
    check("report() exits 0 on a clean run and 1 when a problem was found",
          (report([], {"runbook_sections": 1}, clean_out),
           report(["handle-not-in-pool:x"], {"runbook_sections": 0}, dirty_out)), (0, 1))
    check("...and the census emits on BOTH paths, with the problem named on the failing one",
          ("census {'runbook_sections': 1}" in clean_out.getvalue(),
           "census {'runbook_sections': 0}" in dirty_out.getvalue(),
           "handle-not-in-pool:x" in dirty_out.getvalue(),
           "handle-not-in-pool" in clean_out.getvalue()), (True, True, True, False))
    argv_before = list(sys.argv)
    try:
        sys.argv = ["readme-runbook-check.py"]
        check("main() with no arguments runs the LIVE check and exits 0 (the wiring the operator "
              "and any future CI step actually invoke)", main(), 0)
    finally:
        sys.argv = argv_before

    check("pure core leaves fixtures unchanged",
          policy == policy_before and routing == routing_before, True)
    print("readme-runbook-check self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(
        description="Validate README.md's enrolment runbook against the live policy resolver.")
    ap.add_argument("--self-test", action="store_true", help="run offline fixture tests")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()
    return report(*_check_live())


if __name__ == "__main__":
    sys.exit(main())
