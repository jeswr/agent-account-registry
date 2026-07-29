#!/usr/bin/env python3
# [OPUS-5] The WRITE half of the #657 orchestrator-PR review admission (registry issue #929).
#
# WHAT #937 LEFT OPEN. `auto-mint-provenance.py` is the trigger that mints the provenance record an
# orchestrator-class PR needs before the cross-provider review lane can enumerate it. Its one hard
# input is the source issue, and it DERIVES that from the PR's own declared closing reference — it
# never guesses. Measured on the live board the night #937 merged: of 15 enrolled-class pulls, 12
# refused with `no-issue-reference`. The reader was working exactly as designed; the writers were
# not declaring.
#
# WHICH WRITERS. Every PR body this repository COMPOSES IN CODE already declares one:
#
#   * scripts/worker-live.sh `_write_pr_title_body` emits `Fixes #{issue_number}` (24/24 of the
#     open bot-authored pulls carried a closing reference when measured);
#   * .github/workflows/set-up-account.yml emits `... and closes #{request_issue}.`
#
# and BOTH are structurally outside the enrolled class anyway — `mint-provenance.pr_mint_refusal`
# refuses a `[bot]` author, a `sparq-agent/` head namespace and a draft. The enrolled class is
# `policy/repos.toml:review_enrolment_authors`, and every member of it is a pull whose body was
# composed BY HAND by an orchestrator-class agent running `gh pr create`. There is no template to
# fix, because there was no template. This file is that template.
#
# WHY A HELPER AND NOT A RULE IN PROSE. The reference has to satisfy three independent consumers
# that do NOT agree with each other, and a hand-written line only satisfies them by luck:
#
#   * auto-mint-provenance.CLOSING_REF_RE  — `close[sd]?|fix(e[sd])?|resolve[sd]?`, then
#     `[ \t]*:?[ \t]*`, then `#[1-9][0-9]*`, matched against GitHub's OWN rendering of the body and
#     cross-checked against the raw source. Leading zeros are refused; a second closing pair
#     ANYWHERE — including inside a fenced code block, which the raw side does not strip — refuses
#     the whole pull as `ambiguous-issue-reference`.
#   * groom.LINKED_ISSUE — the same keywords, but `\s+` before the `#`.
#   * GitHub's own auto-close, which is what actually closes the issue on merge.
#
# THE SEPARATOR IS THE WHOLE CONSTRAINT, and the two readers disagree in BOTH directions — neither
# grammar contains the other, so a form that satisfies one can be invisible to the other. Measured
# against both regexes and GitHub's live renderer:
#
#     Closes #929      space(s) or tab   auto-mint YES   groom YES   binds   <- the safe form
#     Closes: #929     colon             auto-mint YES   groom NO    binds   <- groom is blind
#     Closes\n#929     newline           auto-mint NO    groom YES   no bind <- auto-mint is blind
#     Closes#929       nothing           auto-mint YES   groom NO    no bind
#
# So: one or more SPACES OR TABS, and nothing else, between the keyword and the `#`.
#
# WHAT IS *NOT* CONSTRAINED, also measured — stated because an over-tight rule gets cited later as
# a reason to rework something that was always fine:
#
#   * the KEYWORD is free. close/closes/closed/fix/fixes/fixed/resolve/resolves/resolved, any case,
#     all clear both regexes and all bind live. `worker-live.sh` emits `Fixes #<n>` and is 24/24
#     compliant. `Closes` is this file's arbitrary pick, not a requirement.
#   * PLACEMENT is free. Inline mid-sentence, end of a sentence, inside a list item, bold-wrapped,
#     or alone in a paragraph all bind. This file appends a paragraph because appending is the
#     only edit that cannot disturb an existing body, not because the reader wants a paragraph.
#
# IT NEVER RE-IMPLEMENTS THE GRAMMAR. `CLOSING_REF_RE`, `derivation_texts` and `closing_references`
# are IMPORTED from auto-mint-provenance. A second copy of a regex is a second grammar, and the two
# would drift in the permissive direction exactly once and then stay there. This file can only ever
# emit LESS than the reader accepts, never more.
"""pr-body-ref — compose the closing reference an orchestrator-class PR must declare.

THE SOURCE ISSUE IS AN INPUT, NEVER A DERIVATION. It comes from the dispatch the agent was given.
This file will not read it off the branch name, out of the body's prose, or from the numbers the
body happens to mention — #937's refusal comments name those mentions precisely so a HUMAN can
choose between them, and automating that choice is the one thing that turns a recoverable missed
mint into a silent, permanent binding to somebody else's issue.

So every doubt emits NOTHING, with a named reason:

  no-proven-source-issue      no issue number was supplied, or it was not a bare positive integer
  source-is-a-pull-request    the supplied number resolves to a PR (GitHub's own discriminator)
  source-issue-unreadable     the number could not be read, or read back as a different number
  body-declares-another       the body already closes a DIFFERENT issue — never silently rebind
  body-already-ambiguous      the body already holds >1 closing pair; adding one cannot help

Emitting nothing is safe: the pull refuses as `no-issue-reference`, which is visible on the pull,
censused every tick, and fixable by a human in one edit. Emitting the WRONG number is not — it
mis-partitions the review lease and points the human-hold surface at an unrelated object.
"""

import argparse
import importlib.util
import io
import json
from pathlib import Path
import re
import sys

SCRIPTS_DIR = Path(__file__).resolve().parent


class ComposeError(RuntimeError):
    """A concise, credential-free operational error."""


def _load_sibling_module(name, filename):
    """Load a sibling script by path. The scripts/ dir is not a package and several filenames are
    hyphenated, so a plain `import` is not available.

    The `sys.modules` registration is load-bearing, not tidiness: `@dataclass` resolves its own
    annotations through `sys.modules[cls.__module__]`, so groom.py fails to import without it."""
    spec = importlib.util.spec_from_file_location(name, SCRIPTS_DIR / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# THE READER IS THE AUTHORITY. Imported, never re-declared — see the header note.
_auto_mint = _load_sibling_module("registry_auto_mint_provenance", "auto-mint-provenance.py")
CLOSING_REF_RE = _auto_mint.CLOSING_REF_RE
derivation_texts = _auto_mint.derivation_texts
closing_references = _auto_mint.closing_references

# `\s+` rather than auto-mint's `[ \t]*:?[ \t]*`: groom.LINKED_ISSUE is the STRICTER of the two on
# the separator, so the form this file emits has to clear groom's bar to clear both. Imported the
# same way for the same reason.
_groom = _load_sibling_module("registry_groom", "groom.py")
LINKED_ISSUE_RE = _groom.LINKED_ISSUE

# An ARBITRARY pick among nine equivalent keywords — see the header table. Nothing downstream reads
# this constant's value, only the separator that follows it, so changing it to `Fixes` would be
# equally correct. It is a constant so the emitted form is uniform, not because the form is forced.
CLOSING_KEYWORD = "Closes"
ISSUE_NUMBER_RE = re.compile(r"^[1-9][0-9]*$")

REASON_NO_PROVEN_ISSUE = "no-proven-source-issue"
REASON_SOURCE_IS_PULL = "source-is-a-pull-request"
REASON_SOURCE_UNREADABLE = "source-issue-unreadable"
REASON_DECLARES_ANOTHER = "body-declares-another"
REASON_ALREADY_AMBIGUOUS = "body-already-ambiguous"

REASONS = (REASON_NO_PROVEN_ISSUE, REASON_SOURCE_IS_PULL, REASON_SOURCE_UNREADABLE,
           REASON_DECLARES_ANOTHER, REASON_ALREADY_AMBIGUOUS)


def proven_issue_number(value):
    """The supplied source issue as an int, or None if it is not a bare positive integer.

    STRICT ON PURPOSE. `"0929"` is rejected rather than normalised to 929: auto-mint's
    `CLOSING_REF_RE` starts at `[1-9]`, so a zero-padded input that we silently renumbered would
    emit a reference for an issue the CALLER did not name. `bool` is rejected because `True` is an
    `int` in Python and `Closes #1` is not what a caller passing a flag meant."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value if value >= 1 else None
    text = str(value).strip()
    return int(text) if ISSUE_NUMBER_RE.match(text) else None


def closing_reference(issue_number):
    """The reference line for `issue_number`, or "" when there is no proven source issue.

    THE WHOLE WRITE SIDE IS THIS FUNCTION. Everything else decides whether it is safe to call."""
    number = proven_issue_number(issue_number)
    return f"{CLOSING_KEYWORD} #{number}" if number is not None else ""


def declared_closing_numbers(title, body):
    """Every number the RAW title+body already closes, via the reader's own regex.

    The raw side is deliberate: auto-mint seeds its ambiguity set from the raw text, which applies
    no markdown stripping at all. A `Closes #123` inside a fenced code block is invisible to a
    reader looking at rendered prose but still counts toward ambiguity, so this file has to see it
    too or it would append a second pair and turn a `no-issue-reference` refusal into an
    `ambiguous-issue-reference` one."""
    return sorted({int(m.group(1))
                   for m in CLOSING_REF_RE.finditer(f"{title or ''}\n{body or ''}")})


def source_is_pull_request(payload):
    """GitHub's own discriminator: the Issues API returns a `pull_request` sub-object only for PRs.

    Not a heuristic and not a number-range guess — `/issues/{n}` answers for both kinds, and this
    key is the difference. #710 declared `fixed #729` where #729 is a pull request; that is the
    class this refuses."""
    return isinstance(payload, dict) and "pull_request" in payload


def resolve_source_issue(issue_number, read_issue):
    """(number, None) when `issue_number` is a proven, real, non-PR issue; (None, reason) otherwise.

    `read_issue(number)` is the live `GET /repos/{repo}/issues/{number}`. FAILS CLOSED: an
    unreadable source is a refusal, never an assumption that it was fine."""
    number = proven_issue_number(issue_number)
    if number is None:
        return None, REASON_NO_PROVEN_ISSUE
    try:
        payload = read_issue(number)
    except Exception:                                  # noqa: BLE001 — any read failure refuses
        return None, REASON_SOURCE_UNREADABLE
    if not isinstance(payload, dict) or payload.get("number") != number:
        return None, REASON_SOURCE_UNREADABLE
    if source_is_pull_request(payload):
        return None, REASON_SOURCE_IS_PULL
    # Deliberately NOT refused here: a CLOSED source issue. Closed-ness is a property of the issue
    # NOW, not of whether it is the issue this work came from, and it changes under us. auto-mint
    # refuses it under its own name (`reference-is-closed`) — a different, visible, recoverable
    # refusal — and GitHub's auto-close is a no-op on an already-closed issue. Suppressing the
    # reference here would instead destroy the only true provenance the pull has.
    return number, None


def compose(body, issue_number, *, title=""):
    """(body, reason) — `body` with the closing reference appended, or UNCHANGED plus a reason.

    APPEND-ONLY, and only ever after the existing text. Two consumers read this repository's PR
    bodies positionally or by marker and neither may be disturbed:

      * groom.WORKER_PR_MARKER is checked with `body.lstrip().startswith("> 🤖 SPARQ agent")`, so
        nothing may be inserted ahead of the self-ID line;
      * `worker-pr.REVIEWED_SHA_RE` / `replace_reviewed_sha` splice the
        `<!-- sparq-reviewed-sha:... -->` marker in place, and `set_reviewed_sha` re-reads and
        verifies the PATCH byte for byte. Both are position-independent searches, so appending
        after them leaves every marker byte-identical.

    Idempotent: composing twice, or over a body that already declares exactly this issue, is a
    no-op rather than a second pair."""
    number = proven_issue_number(issue_number)
    if number is None:
        return body, REASON_NO_PROVEN_ISSUE
    declared = declared_closing_numbers(title, body)
    if declared == [number]:
        return body, None                              # already correct — do not add a second
    if len(declared) > 1:
        return body, REASON_ALREADY_AMBIGUOUS
    if declared:
        return body, REASON_DECLARES_ANOTHER
    reference = closing_reference(number)
    kept = (body or "").rstrip("\n")
    return (f"{kept}\n\n{reference}\n" if kept else f"{reference}\n"), None


def binds_to(title, body, render_markdown, repo):
    """The issue numbers the READER would derive from this title+body, using the reader's own code.

    This is the verification that matters: not "does my string look right" but "does
    auto-mint-provenance, unmodified, declare exactly the number I meant". `render_markdown(text)`
    is GitHub's `POST /markdown` — the same authority the sweep uses."""
    return closing_references(*derivation_texts(title, body, render_markdown, repo)).declared


def _gh_json(args):
    import subprocess
    result = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise ComposeError(f"gh {args[0]} failed with status {result.returncode}")
    return json.loads(result.stdout or "null")


def _live_readers(repo):
    def read_issue(number):
        return _gh_json(["api", f"repos/{repo}/issues/{number}"])

    def render_markdown(text):
        import subprocess
        result = subprocess.run(
            ["gh", "api", "-X", "POST", "/markdown", "-f", f"text={text}", "-f", "mode=gfm",
             "-f", f"context={repo}"], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise ComposeError("GitHub's markdown renderer did not answer")
        return result.stdout

    return read_issue, render_markdown


def _cmd_compose(args, readers=None):
    """Compose, then PROVE the result binds before writing it. A composer that cannot verify its
    own output is just a string template with extra steps.

    `readers` is injectable ONLY so the self-test can drive this entry point offline. It is the
    entry point, so it is the region where a fabricating bug survives: measured on #937, `main` +
    `_gh_readers` at 0 % coverage let 13 of 13 one-line edits survive a 248-check suite. The
    default is still the live pair — nothing about the shipped path changes."""
    body = Path(args.body_file).read_text(encoding="utf-8")
    read_issue, render_markdown = readers or _live_readers(args.repo)
    number, reason = resolve_source_issue(args.issue, read_issue)
    if reason:
        print(f"pr-body-ref: emitting NO reference [{reason}]", file=sys.stderr)
        return 1
    composed, reason = compose(body, number, title=args.title)
    if reason:
        print(f"pr-body-ref: emitting NO reference [{reason}]", file=sys.stderr)
        return 1
    declared = binds_to(args.title, composed, render_markdown, args.repo)
    if declared != [number]:
        raise ComposeError(
            f"composed body does not bind: the reader declares {declared}, wanted [{number}]")
    Path(args.out or args.body_file).write_text(composed, encoding="utf-8")
    print(f"pr-body-ref: declared #{number} (verified against auto-mint-provenance)")
    return 0


ORACLE_PATH = SCRIPTS_DIR / "fixtures" / "pr-body-ref" / "rendered-oracle.json"
ORACLE_REPO = "jeswr/agent-account-registry"
ORACLE_ISSUE = 929                      # the issue #937 itself was opened against; open, not a PR

# A realistic orchestrator-class body: the self-ID line groom pins, prose, a fenced block quoting
# another pull (the shape that makes hand-written references ambiguous), and the two body markers.
SAMPLE_TITLE = "fix(lane): declare the source issue on orchestrator pulls"
SAMPLE_BODY = """> 🤖 SPARQ agent

## What / why

The review lane cannot enumerate a pull it has no provenance record for.

<!-- sparq-impl-provider:anthropic model:opus5 -->
<!-- sparq-reviewed-sha:none -->
"""


def _capture_raise(fn):
    """The exception `fn` raised, or None. Keeps a raising assertion on one readable line."""
    try:
        fn()
    except Exception as exc:                           # noqa: BLE001 — the object IS the assertion
        return exc
    return None


def _self_test():  # noqa: C901 — a flat sequence of assertions, deliberately not factored
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    oracle = json.loads(ORACLE_PATH.read_text(encoding="utf-8"))
    documents = oracle["documents"]

    requested = []

    def frozen_render(text):
        """GitHub's REAL rendering of `text`, recorded by `--refresh-oracle`.

        A document the corpus has never seen RAISES rather than returning something plausible: a
        renderer stub that invents HTML is a second grammar, which is the thing this file exists
        not to have.

        Every request is RECORDED. The corpus-agreement assertion below reads this list — what the
        suite actually asked for — rather than re-walking `_oracle_documents()`. Checking the
        hand-kept list against the corpus cannot detect a document the suite renders but the list
        forgot, which is precisely the gap that assertion is named for."""
        requested.append(text)
        if text not in documents:
            raise ComposeError(f"no recorded rendering for {text!r} — refresh the oracle")
        return documents[text]

    def declared(title, body):
        """`binds_to`, but an unrecorded document becomes a VALUE, not a traceback.

        A mutant that changes the emitted string renders a document the corpus lacks. If that
        escapes as an exception the mutant dies on the oracle rather than on an assertion, which
        is not evidence that anything was detected — three mutants in this file's first battery
        died exactly that way."""
        try:
            return binds_to(title, body, frozen_render, ORACLE_REPO)
        except ComposeError as exc:
            return f"UNRECORDED-DOCUMENT ({exc})"

    # ---- CONTROL: the instrument answers a KNOWN POSITIVE and a KNOWN NEGATIVE ----------------
    # Run BEFORE anything this file emits is asserted on. An instrument that cannot say "yes" to a
    # string auto-mint's own corpus says binds is not measuring the grammar, and every "no" below
    # would then be vacuous agreement with a broken oracle.
    chk("CONTROL known-positive: auto-mint's own corpus form binds",
        declared("", f"Closes #{ORACLE_ISSUE}."), [ORACLE_ISSUE])
    chk("CONTROL known-negative: `Closing` is not a closing keyword",
        declared("", f"Closing #{ORACLE_ISSUE}."), [])
    chk("CONTROL known-negative: a reference inside a fenced block is not declared",
        declared("", f"```\nCloses #{ORACLE_ISSUE}\n```"), [])

    # ---- AC1: what this file emits is accepted by the READER'S OWN grammar --------------------
    composed, reason = compose(SAMPLE_BODY, ORACLE_ISSUE, title=SAMPLE_TITLE)
    chk("a composed body is not refused", reason, None)
    chk("AC1 the READER declares exactly the dispatched issue",
        declared(SAMPLE_TITLE, composed), [ORACLE_ISSUE])
    chk("AC1 the emitted line is the intersection form (one space, no colon)",
        closing_reference(ORACLE_ISSUE), f"Closes #{ORACLE_ISSUE}")
    chk("AC1 groom.LINKED_ISSUE — the STRICTER separator — also sees it",
        [m.group("issue") for m in LINKED_ISSUE_RE.finditer(composed)], [str(ORACLE_ISSUE)])
    chk("a colon form would be invisible to groom, which is why it is not emitted",
        LINKED_ISSUE_RE.search(f"Closes: #{ORACLE_ISSUE}"), None)

    # ---- AC2: no proven source issue emits NOTHING --------------------------------------------
    for label, value in (("None", None), ("empty", ""), ("zero", 0), ("negative", -3),
                         ("zero-padded", "0929"), ("non-numeric", "sq-abc"),
                         ("a bool, not a number", True), ("a float", 92.9)):
        chk(f"AC2 {label} emits no reference", closing_reference(value), "")
        chk(f"AC2 {label} leaves the body byte-identical",
            compose(SAMPLE_BODY, value)[0], SAMPLE_BODY)
    chk("AC2 the refusal is NAMED, not silent",
        compose(SAMPLE_BODY, None)[1], REASON_NO_PROVEN_ISSUE)
    chk("AC2 a body with no proven issue declares nothing to the reader",
        declared(SAMPLE_TITLE, SAMPLE_BODY), [])

    # ---- AC3: existing markers survive byte for byte -------------------------------------------
    worker_pr = _load_sibling_module("registry_worker_pr", "worker-pr.py")
    chk("AC3 the reviewed-sha marker still parses to the same value",
        (worker_pr.reviewed_sha_of(SAMPLE_BODY), worker_pr.reviewed_sha_of(composed)),
        ("none", "none"))
    chk("AC3 the impl-provider marker is byte-identical",
        "<!-- sparq-impl-provider:anthropic model:opus5 -->" in composed, True)
    chk("AC3 groom's WORKER_PR_MARKER gate still passes (nothing inserted above line 1)",
        composed.lstrip().startswith(_groom.WORKER_PR_MARKER), True)
    chk("AC3 the original body is an unmodified PREFIX — append-only, no rewriting",
        composed.startswith(SAMPLE_BODY.rstrip("\n")), True)
    chk("AC3 and the ONLY addition is the reference",
        composed[len(SAMPLE_BODY.rstrip("\n")):], f"\n\nCloses #{ORACLE_ISSUE}\n")

    # ---- The PR-vs-issue guard (the #710 `fixed #729` class) ------------------------------------
    chk("a source that is a PULL REQUEST is refused",
        resolve_source_issue(929, lambda n: {"number": n, "pull_request": {"url": "..."}}),
        (None, REASON_SOURCE_IS_PULL))
    chk("a plain issue resolves", resolve_source_issue(929, lambda n: {"number": n, "state": "open"}),
        (929, None))
    chk("a CLOSED issue still resolves — closed-ness is auto-mint's call, not ours",
        resolve_source_issue(929, lambda n: {"number": n, "state": "closed"}), (929, None))
    chk("a read that answers about ANOTHER number is refused",
        resolve_source_issue(929, lambda n: {"number": 930}), (None, REASON_SOURCE_UNREADABLE))
    chk("a read that raises is refused, not assumed fine",
        resolve_source_issue(929, lambda n: (_ for _ in ()).throw(RuntimeError("502"))),
        (None, REASON_SOURCE_UNREADABLE))
    chk("the PR discriminator is GitHub's key, not a guess",
        (source_is_pull_request({"number": 1, "pull_request": {}}),
         source_is_pull_request({"number": 1})), (True, False))

    # ---- Ambiguity: appending must never make the refusal WORSE ---------------------------------
    # auto-mint seeds its ambiguity set from the RAW text, which strips nothing. A body quoting
    # another pull inside a fence already carries a closing pair the rendered view cannot see.
    quoted = SAMPLE_BODY + "\nEarlier attempt:\n\n```\nCloses #700\n```\n"
    chk("a body already closing ANOTHER issue is refused, never silently rebound",
        compose(quoted, ORACLE_ISSUE)[1], REASON_DECLARES_ANOTHER)
    chk("...and it is left byte-identical", compose(quoted, ORACLE_ISSUE)[0], quoted)
    chk("the raw-side scan sees the fenced pair the RENDERED view does not",
        (declared_closing_numbers("", quoted), declared("", quoted)), ([700], []))
    two = SAMPLE_BODY + "\nCloses #700 and closes #703.\n"
    chk("an already-ambiguous body is refused under its own name",
        compose(two, ORACLE_ISSUE)[1], REASON_ALREADY_AMBIGUOUS)
    chk("composing is idempotent — a second call adds no second pair",
        compose(composed, ORACLE_ISSUE), (composed, None))
    chk("...and the twice-composed body still declares exactly one issue",
        declared(SAMPLE_TITLE, compose(composed, ORACLE_ISSUE)[0]), [ORACLE_ISSUE])

    # ---- THE ENTRY POINT, driven end to end offline ---------------------------------------------
    # Coverage put `_cmd_compose` at 0 % on the first pass. It is the only thing here that WRITES,
    # so a bug that fabricates a reference survives everywhere else and lands only here.
    import tempfile
    from types import SimpleNamespace

    def run_cmd(issue, *, body=SAMPLE_BODY, issue_payload=None, render=None):
        """(exit_code, reported_reason, bytes-on-disk) for one real invocation of the command.

        The REASON is in the tuple deliberately. Asserting only (code, bytes) let a mutant that
        deleted an early `return 1` survive this battery: control fell through to a later refusal,
        the exit code and the file were identical, and the only thing destroyed was WHICH of the
        five named reasons the operator was told. That diagnosis is the entire recovery path — it
        is what tells an author that they wrote `fixed #729` at a pull request (#710) rather than
        that they wrote nothing."""
        import contextlib
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "body.md")
            path.write_text(body, encoding="utf-8")
            args = SimpleNamespace(issue=issue, body_file=str(path), title=SAMPLE_TITLE,
                                   repo=ORACLE_REPO, out=None)
            readers = (lambda n: (issue_payload if issue_payload is not None
                                  else {"number": n, "state": "open"}),
                       render or frozen_render)
            captured = io.StringIO()
            try:
                with contextlib.redirect_stderr(captured):
                    code = _cmd_compose(args, readers=readers)
            except ComposeError:
                code = "ComposeError"
            reported = [r for r in REASONS if f"[{r}]" in captured.getvalue()]
            return code, (reported[0] if len(reported) == 1 else reported), \
                path.read_text(encoding="utf-8")

    chk("ENTRY the happy path writes the composed body and exits 0",
        run_cmd(ORACLE_ISSUE), (0, [], composed))
    chk("ENTRY an unproven issue exits non-zero, says WHY, and leaves the file UNTOUCHED",
        run_cmd(None), (1, REASON_NO_PROVEN_ISSUE, SAMPLE_BODY))
    chk("ENTRY a PULL REQUEST source is refused UNDER ITS OWN NAME, file UNTOUCHED",
        run_cmd(ORACLE_ISSUE, issue_payload={"number": ORACLE_ISSUE, "pull_request": {}}),
        (1, REASON_SOURCE_IS_PULL, SAMPLE_BODY))
    chk("ENTRY a body already closing another issue is refused under ITS own name",
        run_cmd(ORACLE_ISSUE, body=quoted), (1, REASON_DECLARES_ANOTHER, quoted))
    # The last-mile guard: if the reader would NOT declare what we meant, nothing is written. This
    # is the check that makes the whole file honest rather than hopeful.
    chk("ENTRY a body the reader would not bind is REFUSED, and nothing is written",
        run_cmd(ORACLE_ISSUE, render=lambda _t: "<p>nothing here</p>"),
        ("ComposeError", [], SAMPLE_BODY))
    chk("ENTRY resolve refuses an unproven number before any read happens",
        resolve_source_issue(None, lambda n: (_ for _ in ()).throw(AssertionError("read!"))),
        (None, REASON_NO_PROVEN_ISSUE))
    chk("the oracle fails LOUDLY on a document it never recorded (never silently 'no match')",
        isinstance(_capture_raise(lambda: frozen_render(UNRECORDED_PROBE)), ComposeError), True)
    chk("main() with no subcommand exits 2 rather than doing something", main([]), 2)
    chk("_capture_raise reports None when nothing raises — it can say 'no'",
        _capture_raise(lambda: None), None)

    # ---- Bodies that SWALLOW an appended reference ----------------------------------------------
    # The case that justifies verifying the composed body instead of trusting the string. A body
    # ending inside an unterminated construct absorbs whatever follows it, so the appended line is
    # present and correct in the raw text, reads correctly to a human, and binds to NOTHING.
    # Measured: of six shapes, exactly these two swallow. An unterminated inline code span, a
    # trailing blockquote and an indented code block all bind normally — appending a blank line and
    # a new paragraph escapes them.
    for label, body in (("an unterminated fenced block", UNTERMINATED_FENCE),
                        ("an unclosed HTML comment", UNCLOSED_COMMENT)):
        swallowed, reason = compose(body, ORACLE_ISSUE)
        chk(f"{label}: the reference IS present in the raw text", f"Closes #{ORACLE_ISSUE}"
            in swallowed and reason is None, True)
        chk(f"{label}: ...but the reader binds NOTHING — the string was never the guarantee",
            declared("", swallowed), [])
        chk(f"{label}: so the entry point writes NOTHING",
            run_cmd(ORACLE_ISSUE, body=body)[0::2], ("ComposeError", body))

    # ---- The grammar is IMPORTED, not copied ----------------------------------------------------
    # If this ever fails, someone has re-declared the regex locally and the two will drift.
    chk("CLOSING_REF_RE is auto-mint's object, not a copy",
        CLOSING_REF_RE is _auto_mint.CLOSING_REF_RE, True)
    chk("LINKED_ISSUE_RE is groom's object, not a copy", LINKED_ISSUE_RE is _groom.LINKED_ISSUE, True)
    # AST, not text containment: a whole-file `"re.compile" in line` scan matches the assertion's
    # OWN source and can only ever fail, which is the vacuous shape of this guard class. This walks
    # every `re.compile(...)` this module actually declares and reads its literal pattern.
    import ast
    local_patterns = [arg.value
                      for node in ast.walk(ast.parse(Path(__file__).read_text(encoding="utf-8")))
                      if isinstance(node, ast.Call)
                      and isinstance(node.func, ast.Attribute) and node.func.attr == "compile"
                      for arg in node.args if isinstance(arg, ast.Constant)
                      and isinstance(arg.value, str)]
    chk("this file declares no closing-keyword regex of its own — the grammar is imported",
        [p for p in local_patterns
         if any(word in p.lower() for word in ("close", "fix", "resolve"))], [])
    chk("...and the AST scan is not vacuous: it DOES see this file's own patterns",
        local_patterns, [r"^[1-9][0-9]*$"])

    # ---- Corpus/fixture agreement — LAST, because it reads what was actually rendered ----------
    # `requested` is only complete once every assertion above has run. Placed anywhere earlier it
    # silently under-reports, which is the failure mode the earlier hand-kept version had by
    # construction: it could not see a document the suite renders but the list forgot.
    asked = sorted(set(requested) - {UNRECORDED_PROBE})
    chk("every document the suite ACTUALLY rendered has a recorded rendering",
        [d[:48] for d in asked if d not in documents], [])
    # ONE direction only. Everything the suite renders must be in the recorder's list, or
    # `--refresh-oracle` would not record it and the gap would surface as a mutant dying on the
    # oracle. The REVERSE is intentional: the list also carries near-miss forms (`Closing`,
    # `Closes:`, zero-padded, prepended) that only a MUTANT renders, so that a mutant dies on an
    # assertion rather than on a missing document.
    chk("everything the suite renders is in the recorder's list, so a refresh records it",
        [d[:48] for d in asked if d not in _oracle_documents()], [])
    chk("...and the check is not vacuous: the suite really did render documents",
        len(asked), EXPECTED_RENDERED_DOCUMENTS)

    print("pr-body-ref self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


# Bodies ending inside an unterminated construct: the appended reference is swallowed by it, so it
# reads correctly and binds to nothing. These are inputs to the self-test, not forms this file emits.
UNTERMINATED_FENCE = "> 🤖 SPARQ agent\n\nEarlier diff:\n\n```\nsome code\n"
UNCLOSED_COMMENT = "> 🤖 SPARQ agent\n\n<!-- sparq-impl-provider:anthropic\n"
# Deliberately absent from the corpus: the input that proves the oracle refuses loudly.
UNRECORDED_PROBE = "a document the oracle has deliberately never recorded"
# The number of DISTINCT documents a clean run renders. Pinned so that deleting an assertion that
# renders one is caught here rather than silently shrinking the corpus check.
EXPECTED_RENDERED_DOCUMENTS = 9


def _oracle_documents():
    """Every document the self-test renders — INCLUDING the near-miss forms a mutant would emit.

    The near-misses are not decoration. Without a recorded rendering for `Closing #929` or
    `Closes: #929`, a mutant that emits one dies because the oracle has never seen it, and a kill
    by "the corpus does not cover this" is not evidence that any assertion detected anything. With
    them recorded, the mutant renders exactly as GitHub would render it and dies on the assertion
    it is supposed to die on."""
    composed, _ = compose(SAMPLE_BODY, ORACLE_ISSUE, title=SAMPLE_TITLE)
    reference = f"Closes #{ORACLE_ISSUE}"
    kept = SAMPLE_BODY.rstrip("\n")
    return [
        SAMPLE_TITLE, SAMPLE_BODY, composed,
        SAMPLE_BODY + "\nEarlier attempt:\n\n```\nCloses #700\n```\n",
        SAMPLE_BODY + "\nCloses #700 and closes #703.\n",
        f"Closes #{ORACLE_ISSUE}.", f"Closing #{ORACLE_ISSUE}.",
        f"```\nCloses #{ORACLE_ISSUE}\n```",
        # near-miss mutant forms
        composed.replace(reference, f"Closing #{ORACLE_ISSUE}"),
        composed.replace(reference, f"Closes: #{ORACLE_ISSUE}"),
        composed.replace(reference, f"Closes #{ORACLE_ISSUE:04d}"),
        composed.replace(reference, "Closes #1"),
        f"{reference}\n\n{kept}\n",
        # bodies that swallow the appended reference
        compose(UNTERMINATED_FENCE, ORACLE_ISSUE)[0],
        compose(UNCLOSED_COMMENT, ORACLE_ISSUE)[0],
    ]


def _refresh_oracle():
    """Re-record GitHub's REAL rendering of every self-test document. Needs a token."""
    _, render_markdown = _live_readers(ORACLE_REPO)
    documents = {text: render_markdown(text) for text in dict.fromkeys(_oracle_documents())}
    ORACLE_PATH.parent.mkdir(parents=True, exist_ok=True)
    ORACLE_PATH.write_text(
        json.dumps({"repo": ORACLE_REPO, "issue": ORACLE_ISSUE, "documents": documents},
                   indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"recorded {len(documents)} documents to {ORACLE_PATH}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--refresh-oracle", action="store_true")
    sub = parser.add_subparsers(dest="command")
    compose_cmd = sub.add_parser("compose", help="append a verified closing reference to a body")
    compose_cmd.add_argument("--issue", required=True, help="the DISPATCHED source issue number")
    compose_cmd.add_argument("--body-file", required=True)
    compose_cmd.add_argument("--title", default="")
    compose_cmd.add_argument("--repo", required=True)
    compose_cmd.add_argument("--out")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if args.refresh_oracle:
        return _refresh_oracle()
    if args.command == "compose":
        return _cmd_compose(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
