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
#
# ---------------------------------------------------------------------------------------------
# THE `check` HALF (registry issue #1115) — the same knowledge, delivered at AUTHORING TIME.
#
# #1155 landed the composer and AGENTS.md item 13 landed the rule, and neither reaches an author who
# did not think to look. Re-measured for #1115 with #937 merged: of the 17 live orchestrator-class
# open pulls the review lane could enumerate, **8** refuse `no-issue-reference` and **6** are drafts
# — the lane admits 1, and that one is #937 itself. Both populations are refusals the author can
# see and fix in one edit, and NOTHING TOLD THEM. `check` is that telling: pr-gate already runs on
# every pull, so the note lands on the object that is wrong, while it is being written.
#
# IT RUNS WHENEVER THE FACTS IT READS CHANGE, which is not the same as "on every push". The two
# inputs it diagnoses — the closing references in the title/body, and draftness — move WITHOUT the
# head sha moving, so pr-gate.yml subscribes to `edited` and `converted_to_draft` as well (see the
# note on its `on:` block). Both the invocation and that exact activity-type set are pinned by
# `advisory_workflow_seam_report` below: a `check` that is perfect and never invoked, or invoked
# only at `opened`, delivers a note that is stale against the very edit it asked for.
#
# IT IS ADVISORY AND IT IS SOUND — it warns only where the reader is GUARANTEED to refuse.
# `closing_references` computes `declared = resolved & raw_refs` and `all_refs = seen ⊇ raw_refs`,
# so over the RAW text alone, with no renderer and no network:
#
#     0 raw closing refs  =>  declared ⊆ raw_refs = {} => `candidate_refusal` refuses, always
#     2+ raw closing refs =>  |all_refs| >= 2          => `ambiguous-issue-reference`, always
#     exactly 1           =>  UNDECIDABLE offline — the rendered half may still drop it
#
# The third row is why `check` says NOTHING at 1 rather than "looks good": a body whose only
# reference sits in a fenced block is raw-declared and rendered-invisible, and an advisory that
# called that fine would be worse than silence. So `check` has NO false alarms by construction and
# accepts false NEGATIVES, which is the only asymmetry an advisory may have.
#
# IT NEVER BLOCKS, and it sits inside a REQUIRED gate, so it also never RAISES: every failure path
# returns 0 with a `::notice::`. That is not a weakened trust check — `check` grants nothing,
# admits nothing and writes nothing; the authority is still `auto-mint-provenance`, which re-derives
# all of this against GitHub's own renderer and refuses on its own. A bug here must not be able to
# red the gate for every pull in the repository.
#
# IT ECHOES NO AUTHOR TEXT. The PR title and body are attacker-controlled and the annotation stream
# is a control channel — a body containing `::error::` would forge a gate failure. Every value that
# reaches an annotation is an int (a PR number, an issue number parsed from `[0-9]+`) or a constant
# in this file. The payload is read from `$GITHUB_EVENT_PATH` in Python for the same reason: no
# `${{ }}` expansion of untrusted text into a shell ever happens.
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

`check` is the advisory read half (#1115): it names, on the pull request itself, the refusals the
review lane is CERTAIN to produce for an orchestrator-class pull. See the header note.
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

# `check` asks two questions it must not answer for itself: "is this pull in the orchestrator class
# the review lane mints for" and "who may this repo enrol". Both are decided by the SAME code the
# minter is subject to — `pr_mint_refusal` is the class predicate, `review_enrolment_authors` is the
# master-protected allowlist. A local re-derivation of either would be an advisory about a lane that
# does not exist, which is the one failure an advisory cannot be allowed to have.
_mint = _load_sibling_module("registry_mint_provenance", "mint-provenance.py")
_policy = _load_sibling_module("registry_policy_resolve", "policy-resolve.py")

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

# The advisory's two reference codes are the READER'S OWN, imported for the same reason the grammar
# is: an advisory that names a refusal by a spelling the census does not use cannot be correlated
# with the census, and the two would drift apart silently.
ADVISORY_NO_REFERENCE = _auto_mint.REASON_NO_REFERENCE           # "no-issue-reference"
ADVISORY_AMBIGUOUS = _auto_mint.REASON_AMBIGUOUS                 # "ambiguous-issue-reference"
# The draft refusal has no constant on the reader side — it is `pr_mint_refusal`'s inline prose, and
# it is a REFUSAL OF THE PULL SHAPE rather than of a derivation, so it never reaches the derivation's
# reason enum. Named here so the advisory can be asserted on by code rather than by substring.
ADVISORY_DRAFT = "draft-not-enumerable"

ADVISORY_CODES = (ADVISORY_DRAFT, ADVISORY_NO_REFERENCE, ADVISORY_AMBIGUOUS)


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


def orchestrator_class_error(pull, repo, enrolled_authors):
    """Why `pull` is not a pull the review lane would ever mint for, IGNORING draftness — or None.

    THE PREDICATE IS `mint_provenance.pr_mint_refusal`, UNMODIFIED. It is asked about a copy of the
    payload with `draft` cleared, which is the whole trick: the draft clause is the one refusal in
    that function an AUTHOR can act on, so it has to be separated from the ten that are facts about
    the pull (a fork head, a `[bot]` login, a login this repo does not enrol, a closed pull). Those
    ten mean the advisory has nothing to say and must stay SILENT — an unenrolled contributor being
    told their body is malformed for a lane they are not in is noise, and noise is how an advisory
    stops being read.

    Clearing `draft` cannot make a refusing pull admissible for any other reason: `pr_mint_refusal`
    is a flat sequence of independent clauses over distinct keys, and this touches exactly one."""
    if not isinstance(pull, dict):
        return "the pull request payload is malformed"
    undrafted = dict(pull)
    undrafted["draft"] = False
    return _mint.pr_mint_refusal(repo, undrafted, enrolled_authors)


def lane_advisory(pull, repo, enrolled_authors):
    """The notes the review lane owes this pull's AUTHOR, as a list of `(code, message)`.

    EMPTY IS THE COMMON AND CORRECT ANSWER — for every pull outside the orchestrator class, and for
    every orchestrator pull that is ready and declares exactly one reference. Every note here names
    a refusal that is CERTAIN offline (see the header note for the `declared ⊆ raw_refs` /
    `all_refs ⊇ raw_refs` argument); the undecidable single-reference case emits nothing.

    Messages carry no author-supplied text — only this pull's number and the issue numbers the
    grammar matched, both ints. See the header note on the annotation stream as a control channel."""
    if orchestrator_class_error(pull, repo, enrolled_authors) is not None:
        return []
    number = pull.get("number")
    notes = []
    if pull.get("draft") is True:
        # #1115 population 2, 6 of 17. NOT a defect and not a thing this file may fix: the draft
        # refusal exists because groom's stale-draft carve-out reads `is_enumerable_provenance`,
        # which deliberately has no orchestrator opt-in, so a minted draft would be age-parked
        # `needs:user` instead of reviewed. The lane is CLOSED to drafts by decision, and the only
        # thing that was ever wrong was that the decision was invisible from the pull request.
        notes.append((ADVISORY_DRAFT,
                      f"pull #{number} is a DRAFT. The orchestrator review lane refuses a draft "
                      "outright (mint-provenance.pr_mint_refusal) because groom's stale-draft "
                      "carve-out reads is_enumerable_provenance, which has no orchestrator opt-in "
                      "— a minted draft would be terminally needs:user-parked by age instead of "
                      "reviewed. Drafts are out of scope for this lane BY DECISION, not by "
                      "accident (research/657-orchestrator-provenance-minting.md). Mark the pull "
                      "ready for review to be enumerated."))
    declared = declared_closing_numbers(pull.get("title"), pull.get("body"))
    if not declared:
        # #1115 population 1, 8 of 17.
        notes.append((ADVISORY_NO_REFERENCE,
                      f"pull #{number} declares no closing reference to a source issue, so "
                      "auto-mint-provenance will refuse it as `no-issue-reference`, no provenance "
                      "record will be minted, and the cross-provider review lane will never "
                      "enumerate it. Declare the issue you were DISPATCHED against — never the "
                      "branch name, never a number the body happens to mention — as one closing "
                      "keyword, one or more spaces or tabs, then the number (AGENTS.md item 13), "
                      "or run: python3 scripts/pr-body-ref.py compose --issue <n> --repo "
                      f"{repo} --body-file <f>"))
    elif len(declared) > 1:
        named = ", ".join(f"#{n}" for n in declared)
        notes.append((ADVISORY_AMBIGUOUS,
                      f"pull #{number} declares {len(declared)} distinct closing references "
                      f"({named}), so auto-mint-provenance will refuse it as "
                      "`ambiguous-issue-reference`; exactly one is needed, because the source "
                      "issue decides which lease partition the review reserves and which object a "
                      "human hold can park. A closing pair inside a fenced block still counts — "
                      "the raw side strips nothing."))
    return notes


def enrolled_authors_of(repo, policy_path):
    """This repo's master-protected `review_enrolment_authors`, or an empty frozenset.

    An unreadable or malformed policy yields EMPTY, which makes `pr_mint_refusal` refuse every pull
    and so silences the advisory entirely. That is the right direction for a read-only note: a
    policy this file cannot parse is not a licence to guess who is enrolled and start annotating
    strangers' pull requests. The authoritative fail-closed read of the same field is
    policy-resolve's, exercised on every dispatch; this one only decides whether to speak."""
    import tomllib
    try:
        with open(policy_path, "rb") as handle:
            return _policy.review_enrolment_authors(repo, tomllib.load(handle))
    except Exception:                                  # noqa: BLE001 — unreadable policy = silent
        return frozenset()


def _annotate(level, message):
    """One GitHub workflow annotation on ONE line.

    Newlines are stripped rather than `%0A`-escaped: every message in this file is already a single
    paragraph, so a newline reaching here means something unexpected got into the string, and
    flattening it is strictly safer than encoding it into a multi-line annotation."""
    print(f"::{level}::{' '.join(str(message).split())}")


def _cmd_check(args, *, enrolled=None):
    """Advise on the pull request in the workflow event payload. ALWAYS returns 0.

    TOTAL BY CONSTRUCTION — see the header note. This runs as a step of the REQUIRED `gate` job, so
    an unreadable payload, an unparseable policy or an outright bug must produce a notice and a zero
    exit, never a red gate on a pull request that has nothing to do with this lane.

    It also always says what it DECIDED, including when it decided to say nothing. An advisory that
    is silent on both "nothing to report" and "I could not run" is indistinguishable from a step
    that was accidentally disabled, which is how this class of check rots.

    `enrolled` is injectable ONLY so the self-test can drive this entry point without a policy file
    on disk; the default is the live read."""
    try:
        payload = json.loads(Path(args.event_path).read_text(encoding="utf-8"))
        pull = payload.get("pull_request") if isinstance(payload, dict) else None
        if not isinstance(pull, dict):
            _annotate("notice", "pr-body-ref check: the event carries no pull_request; nothing to "
                                "advise on")
            return 0
        authors = enrolled_authors_of(args.repo, args.policy) if enrolled is None else enrolled
        notes = lane_advisory(pull, args.repo, authors)
        if not notes:
            _annotate("notice", "pr-body-ref check: nothing to advise — this pull is either "
                                "outside the orchestrator review lane, or ready and declaring "
                                "exactly one closing reference")
            return 0
        for code, message in notes:
            _annotate("warning", f"review lane [{code}]: {message}")
    except Exception as exc:                           # noqa: BLE001 — an advisory never reds a gate
        _annotate("notice", f"pr-body-ref check did not run ({type(exc).__name__}); it is advisory "
                            "and auto-mint-provenance remains the authority")
    return 0


# ---- THE DELIVERY SEAM (pr-gate.yml), PyYAML-parsed ---------------------------------------------
# A `check` that is perfect and never invoked delivers NOTHING, and every assertion above it stays
# green while it delivers nothing: deleting the workflow step, disabling it with `if: false`,
# repointing it at `compose`, dropping `--event-path`, or dropping either of the two activity types
# the advisory needs to stay true are all invisible to a test that calls `_cmd_check` directly.
# So the workflow is read as a PARSED DOCUMENT — same construction, and for the same measured
# reason, as `mint-provenance.mint_workflow_seam_report`: an `if: false` is valid YAML, lints clean,
# and survives every grep. The `run:` body is COMMENT-STRIPPED before any token is read, because a
# wiring assertion that a comment can satisfy is not a wiring assertion.
def _workflow_document(name="pr-gate.yml"):
    """The parsed live workflow. RAISES if it is missing or unparseable — a seam check that cannot
    read its own workflow must fail the gate, never degrade to "nothing to assert"."""
    from yaml_dependency import require_yaml
    yaml = require_yaml("pr-body-ref delivery workflow-seam checks")

    path = SCRIPTS_DIR.parent / ".github" / "workflows" / name
    assert path.is_file(), f"{name} not found for the delivery-seam check: {path}"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _run_argv(run):
    """The `python3 …` invocation in a comment-stripped `run:` body, as SHELL TOKENS.

    Tokenised rather than substring-matched (AGENTS.md pre-flight item 6): `--event-path` dropped,
    `--repo "$GITHUB_EVENT_PATH"`, or the two flags' values transposed all satisfy a containment
    check on the same text and all change this list. Line continuations are folded first so the
    invocation is one argv regardless of how it is wrapped."""
    import shlex

    try:
        tokens = shlex.split(str(run).replace("\\\n", " "))
    except ValueError:                                 # an unbalanced quote is not an invocation
        return ()
    for i, token in enumerate(tokens):
        if token == "python3" and tokens[i + 1:i + 2] == ["scripts/pr-body-ref.py"]:
            return tuple(tokens[i:])
    return ()


def advisory_workflow_seam_report(workflow=None):
    """Structural findings about the LIVE pr-gate.yml, each asserted — and each MUTATED — by
    `--self-test`. `workflow` is injectable so the mutant table can run over a copy of the real
    document rather than over a hand-written stand-in that could agree with a broken file."""
    workflow = _workflow_document() if workflow is None else workflow
    strip = _load_sibling_module("registry_dispatch_claim",
                                 "dispatch-claim.py")._strip_script_comments
    # PyYAML parses a bare `on:` key as the boolean True.
    triggers = workflow.get("on") if "on" in workflow else workflow.get(True)
    types = (((triggers or {}).get("pull_request") or {}).get("types"))
    # From the `gate` job SPECIFICALLY — that is the job the ruleset requires and the only one that
    # runs on every pull. A step moved to some other job is not delivered and must read as absent.
    steps = [s for s in ((workflow.get("jobs") or {}).get("gate") or {}).get("steps") or []
             if isinstance(s, dict)]
    invoking = [s for s in steps if "scripts/pr-body-ref.py" in strip(str(s.get("run") or ""))]
    # ANY `if:` counts as disabled, deliberately, rather than only a literal `false`: this step is
    # unconditional by design, an expression cannot be evaluated offline, and `x && false` is the
    # measured shape (sparq #4743) that satisfies a "not literally false" reading while killing the
    # step. Adding a condition here therefore reds this seam and has to be argued for.
    enabled = [s for s in invoking if "if" not in s]
    # `enabled[0]` only when there is EXACTLY one: two enabled steps leave `step` None and empty the
    # argv findings, so "one call site" is a claim the mutant table can kill rather than an
    # assumption that silently picks the first of several.
    step = enabled[0] if len(enabled) == 1 else None
    argv = _run_argv(strip(str((step or {}).get("run") or "")))
    return {
        "trigger_types": tuple(sorted(types)) if isinstance(types, list) else None,
        # Both counts, because they fail differently: `invoking` going to 0 is a deletion, and
        # `enabled` falling below it is a step that is still in the file and no longer runs.
        "invoking_steps": len(invoking),
        "enabled_steps": len(enabled),
        "step_conditions": tuple(str(s.get("if")) for s in invoking if "if" in s),
        # The ONE `continue-on-error` in this required job. Asserted by VALUE, not presence: a
        # `false` here would let an import-time failure red the gate for every pull in the repo,
        # which is the exact failure the key exists to prevent.
        "continue_on_error": (step or {}).get("continue-on-error"),
        "argv": argv,
        "subcommand": argv[2] if len(argv) > 2 else None,
        "flags": tuple(sorted(t for t in argv if t.startswith("--"))),
        # Flag -> the token that FOLLOWS it. Adjacency, not membership: `--event-path --repo x y`
        # carries both flags and binds neither.
        "flag_values": {t: (argv[i + 1] if i + 1 < len(argv) else None)
                        for i, t in enumerate(argv) if t.startswith("--")},
    }


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

    # ---- `check`: the ADVISORY read half (#1115) ------------------------------------------------
    # The whole claim of this half is "every note names a refusal the reader is CERTAIN to make",
    # so every note below is asserted against what the READER ACTUALLY ANSWERS for the same body,
    # driven through auto-mint's production `derive_issue_number` over the frozen oracle. Asserting
    # the advisory against a hand-written expected code would restate this file's own belief and
    # would still pass if the reader's cardinality rules moved underneath it.
    def reader_verdict(pull):
        """auto-mint's own refusal reason for this pull, offline. None means it would derive."""
        return _auto_mint.derive_issue_number(
            pull, lambda n: {"number": n, "state": "open"}, frozen_render, ORACLE_REPO).reason

    ENROLLED = frozenset({"jeswr"})

    def pull_payload(**over):
        """A minimal LIVE-SHAPED payload that `pr_mint_refusal` admits, plus the overrides."""
        payload = {"number": 1115, "state": "open", "draft": False,
                   "head": {"repo": {"full_name": ORACLE_REPO}, "ref": "fix/lane", "sha": "a" * 40},
                   "user": {"login": "jeswr"}, "title": SAMPLE_TITLE, "body": SAMPLE_BODY}
        payload.update(over)
        return payload

    def advice(**over):
        return [code for code, _ in lane_advisory(pull_payload(**over), ORACLE_REPO, ENROLLED)]

    # CONTROL both ways, BEFORE any advisory row: an instrument that cannot say "this one is fine"
    # makes every agreement below vacuous, and one that answers `render-unavailable` is answering
    # about the oracle rather than about the grammar.
    chk("CONTROL the reader instrument refuses the no-reference body under its own name",
        reader_verdict(pull_payload()), ADVISORY_NO_REFERENCE)
    chk("CONTROL ...and DERIVES from the composed one — it can say yes",
        reader_verdict(pull_payload(body=composed)), None)

    chk("#1115 population 1: a body with no closing reference is advised, with the READER'S code",
        (advice(), reader_verdict(pull_payload())),
        ([ADVISORY_NO_REFERENCE], ADVISORY_NO_REFERENCE))
    chk("a ready pull declaring exactly one reference is advised about NOTHING",
        (advice(body=composed), reader_verdict(pull_payload(body=composed))), ([], None))
    chk("#1115 population 2: a DRAFT is advised, even when its reference is perfect",
        advice(body=composed, draft=True), [ADVISORY_DRAFT])
    chk("...and a drafted pull with no reference is advised about BOTH, draft first",
        advice(draft=True), [ADVISORY_DRAFT, ADVISORY_NO_REFERENCE])
    chk("two closing references are advised as ambiguous, with the READER'S code",
        (advice(body=two), reader_verdict(pull_payload(body=two))),
        ([ADVISORY_AMBIGUOUS], ADVISORY_AMBIGUOUS))

    # ONE-SIDEDNESS, stated as a test rather than as a comment. `quoted` declares #700 in the raw
    # text and NOTHING in the rendered prose, so the reader refuses it and the offline advisory
    # cannot know that. It must stay QUIET rather than guess — a false alarm is the one failure
    # mode that would make authors stop reading these notes.
    chk("the advisory is silent where it cannot be certain, and the reader still refuses",
        (advice(body=quoted), reader_verdict(pull_payload(body=quoted))), ([], ADVISORY_NO_REFERENCE))

    # SILENCE OUTSIDE THE CLASS. Each row is a pull `pr_mint_refusal` refuses for a reason that is
    # not draftness, so the lane was never open to it and there is nothing to advise. If any of
    # these ever speaks, the advisory is annotating pulls belonging to people not in this lane.
    for label, over in (
            ("a [bot] author", {"user": {"login": "sparq-agent[bot]"}}),
            ("an author this repo does not enrol", {"user": {"login": "someone-else"}}),
            ("a FORK head", {"head": {"repo": {"full_name": "attacker/agent-account-registry"},
                                      "ref": "fix/lane", "sha": "a" * 40}}),
            ("a worker-lane head namespace", {"head": {"repo": {"full_name": ORACLE_REPO},
                                                       "ref": "sparq-agent/123", "sha": "a" * 40}}),
            ("a closed pull", {"state": "closed"}),
            ("a malformed payload", None)):
        got = ([] if over is None
               else advice(**over))
        chk(f"SILENT outside the class: {label}", got, [])
    chk("SILENT outside the class: a non-dict payload is refused, not crashed on",
        lane_advisory("not a dict", ORACLE_REPO, ENROLLED), [])
    chk("SILENT when the repo enrols NOBODY — an empty allowlist is enrolment OFF",
        [code for code, _ in lane_advisory(pull_payload(), ORACLE_REPO, frozenset())], [])
    # ...and the silence is not the only thing this can produce: the same payload DOES speak once
    # its author is enrolled. Without this row every assertion above passes on a dead function.
    chk("...and the class predicate is not vacuously refusing everything", advice(),
        [ADVISORY_NO_REFERENCE])

    chk("relaxing draft does not relax anything else — the class probe reads pr_mint_refusal",
        orchestrator_class_error(pull_payload(draft=True), ORACLE_REPO, ENROLLED), None)
    chk("...and it still refuses a fork whose draft was cleared",
        orchestrator_class_error(
            pull_payload(draft=True, head={"repo": {"full_name": "attacker/x"}, "ref": "b",
                                           "sha": "a" * 40}), ORACLE_REPO, ENROLLED) is not None,
        True)

    # ---- THE `check` ENTRY POINT, driven end to end offline --------------------------------------
    import contextlib

    def run_check(pull, *, enrolled=ENROLLED, payload=None):
        """(exit_code, advisory codes annotated, whole stdout) for one real `check` invocation."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "event.json")
            path.write_text(json.dumps(payload if payload is not None
                                       else {"pull_request": pull}), encoding="utf-8")
            args = SimpleNamespace(event_path=str(path), repo=ORACLE_REPO, policy="/nonexistent")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = _cmd_check(args, enrolled=enrolled)
            text = out.getvalue()
            return code, [c for c in ADVISORY_CODES if f"[{c}]" in text], text

    code, codes, text = run_check(pull_payload())
    chk("ENTRY check exits 0 and warns with the reader's code", (code, codes),
        (0, [ADVISORY_NO_REFERENCE]))
    chk("ENTRY ...as a WARNING, never an error — it must not read as a gate failure",
        (text.count("::warning::"), "::error::" in text), (1, False))
    chk("ENTRY a clean pull still SAYS SO — silence and a disabled step must be distinguishable",
        run_check(pull_payload(body=composed))[0:2] + ("::notice::" in
                                                       run_check(pull_payload(body=composed))[2],),
        (0, [], True))
    # The TEXT is asserted, not just `(0, [])`. Both this and "nothing to advise" exit 0 and warn
    # about nothing, so a mutant that drops the payload-shape branch is invisible to the codes and
    # destroys only the diagnosis — the same class `run_cmd` above carries its own note about.
    no_pull = run_check(None, payload={"action": "opened"})
    chk("ENTRY a payload with no pull_request says SO, and is a notice rather than a failure",
        (no_pull[0], no_pull[1], "no pull_request" in no_pull[2]), (0, [], True))
    unreadable = io.StringIO()
    with contextlib.redirect_stdout(unreadable):
        unreadable_code = _cmd_check(SimpleNamespace(event_path="/nonexistent/event.json",
                                                     repo=ORACLE_REPO, policy="/nonexistent"),
                                     enrolled=ENROLLED)
    chk("ENTRY an unreadable event path exits 0 with a NOTICE — an advisory never reds the gate",
        (unreadable_code, unreadable.getvalue().startswith("::notice::")), (0, True))
    chk("ENTRY an unreadable policy silences rather than guessing who is enrolled",
        enrolled_authors_of(ORACLE_REPO, "/nonexistent/repos.toml"), frozenset())
    chk("...and the live policy really does enrol this repo's orchestrator class",
        bool(enrolled_authors_of(ORACLE_REPO, SCRIPTS_DIR.parent / "policy" / "repos.toml")), True)

    # INJECTION: the annotation stream is a control channel and the body is attacker-controlled.
    # A body carrying an annotation directive must not reach stdout — if it did, an author could
    # forge `::error::` rows on the REQUIRED gate from their own pull request body.
    forged = "> 🤖 SPARQ agent\n\n::error::forged gate failure\n::endgroup::\n"
    _, codes, text = run_check(pull_payload(body=forged, title="::error::forged title"))
    chk("INJECTION a body's own annotation directive is never echoed",
        ("forged" in text, "::endgroup::" in text, codes), (False, False, [ADVISORY_NO_REFERENCE]))
    chk("INJECTION every annotation line is exactly one line",
        all(line.count("::") == 1 or line.startswith("::")
            for line in text.splitlines() if line), True)
    # The flattener has to be driven DIRECTLY: every message this file composes is already one
    # paragraph, so a mutant that deleted the flattening would change no output anywhere above and
    # the guard would be there without ever having been measured.
    flattened = io.StringIO()
    with contextlib.redirect_stdout(flattened):
        _annotate("warning", "one\ntwo   three\n::error::four")
    chk("INJECTION a multi-line message collapses to ONE annotation line",
        flattened.getvalue(), "::warning::one two three ::error::four\n")

    # ---- THE DELIVERY SEAM: pr-gate.yml actually invokes this, on the events it needs -----------
    # Everything above drives `_cmd_check` in-process, so ALL of it stays green while the feature
    # delivers nothing — the step deleted, `if: false`d, repointed at `compose`, stripped of a flag,
    # or subscribed to events that never fire when the facts it diagnoses change. The production
    # call site is read here, from the PARSED document, with the same mutant discipline
    # `mint-provenance` applies to its own workflow (AGENTS.md pre-flight item 6: exact-match and
    # adjacency, never containment).
    import copy

    live_workflow = _workflow_document()
    seam = advisory_workflow_seam_report(live_workflow)

    # EXACT membership, as a set. Containment would pass while `edited` was missing, which is the
    # whole defect this pins; a superset would pass while some unargued third population started
    # re-running the required gate. The expected value is written HERE as a literal rather than
    # read back from the workflow (pre-flight item 2b — an expectation sourced from the code under
    # test cannot fail).
    chk("SEAM pr-gate subscribes to EXACTLY the activity types the advisory needs",
        seam["trigger_types"], ("converted_to_draft", "edited", "opened", "ready_for_review",
                                "reopened", "synchronize"))
    chk("SEAM exactly ONE enabled step in the required `gate` job invokes this script",
        (seam["invoking_steps"], seam["enabled_steps"], seam["step_conditions"]), (1, 1, ()))
    chk("SEAM ...and it is the one step that cannot red the gate (`continue-on-error: true`)",
        seam["continue_on_error"], True)
    # The whole argv, in order: this pins the subcommand, both flag names, both flag VALUES and the
    # adjacency of each name to its value in a single exact comparison. The values are the runner's
    # own environment variables, never a `${{ }}` expansion of author-controlled text.
    chk("SEAM the invocation is `check` with both flags bound to the runner's env, in order",
        seam["argv"], ("python3", "scripts/pr-body-ref.py", "check",
                       "--event-path", "$GITHUB_EVENT_PATH",
                       "--repo", "$GITHUB_REPOSITORY"))
    # ...and those spellings are ones THIS file's parser accepts. A flag renamed on one side of the
    # seam only (`--event-path` -> `--event_path`) leaves both halves individually correct and the
    # required gate red on every pull; argparse's refusal is a SystemExit, caught here so a
    # mismatch reds one row instead of aborting the suite below it (pre-flight item 4).
    # NOT a duplicate of pr-gate's repo-wide "every workflow-passed CLI flag is declared" step
    # (PR #595 finding 2): that one is an AST scan of flag NAMES and says nothing about the
    # SUBCOMMAND they sit under, so `compose --event-path …` satisfies it and exits 2 here.
    parsed_out = io.StringIO()
    try:
        with contextlib.redirect_stdout(parsed_out), contextlib.redirect_stderr(io.StringIO()):
            accepted = main(list(seam["argv"][2:]) + ["--policy", "/nonexistent"])
    except SystemExit as exc:
        accepted = f"argparse REJECTED the workflow's own argv ({exc.code})"
    chk("SEAM ...and this CLI accepts the exact argv the workflow passes", accepted, 0)

    # ---- the seam MUTANT TABLE ------------------------------------------------------------------
    # The happy path above proves the report can read a correct workflow, not that it would notice a
    # neutered one. Each row is a real way this step or these triggers could be lost; each must flip
    # a NAMED finding. DELETE and DISABLE are taken separately (pre-flight item 3), and the
    # comment-only mutant is included because it is the one an unstripped fragment check cannot see.
    def gate_steps(doc):
        return doc["jobs"]["gate"]["steps"]

    def advisory_step(doc):
        return next(s for s in gate_steps(doc)
                    if "scripts/pr-body-ref.py" in str(s.get("run") or ""))

    def seam_mutant(edit):
        """The report for one mutated copy of the LIVE document.

        A mutant that cannot be APPLIED — its anchor moved, its fragment is no longer unique — is
        not a kill and must not abort the rows below it (AGENTS.md pre-flight item 4,
        crash-after-partial-run: a mutant run's total check count has to match the pristine run's).
        So the failure is returned as a VALUE that reds its own row and leaves every later row
        running, instead of a traceback that silently deletes them."""
        doc = copy.deepcopy(live_workflow)
        try:
            edit(doc)
            return advisory_workflow_seam_report(doc)
        except Exception as exc:                       # noqa: BLE001 — see the docstring
            return dict.fromkeys(seam, f"MUTANT NOT APPLIED — {type(exc).__name__}: {exc}")

    def comment_out_line(doc, fragment):
        step = advisory_step(doc)
        lines = str(step["run"]).splitlines()
        hits = [i for i, line in enumerate(lines) if fragment in line]
        assert hits, f"seam mutant fragment not present: {fragment!r}"
        for i in hits:
            lines[i] = "# " + lines[i].lstrip()
        step["run"] = "\n".join(lines) + "\n"

    def replace_in_run(doc, old, new):
        step = advisory_step(doc)
        text = str(step["run"])
        assert text.count(old) == 1, f"seam mutant fragment not unique: {old!r}"
        step["run"] = text.replace(old, new)

    def wf_pull_request(doc):
        return (doc.get("on") if "on" in doc else doc.get(True))["pull_request"]

    def drop_type(name):
        return lambda d: wf_pull_request(d)["types"].remove(name)

    def move_out_of_gate(doc):
        """Not a deletion: the step, its flags and its `continue-on-error` all survive verbatim —
        in a job the ruleset does not require and that no pull is obliged to run."""
        step = advisory_step(doc)
        gate_steps(doc).remove(step)
        doc["jobs"]["advisory-elsewhere"] = {"runs-on": "ubuntu-latest", "steps": [step]}

    BOUND = '--event-path "$GITHUB_EVENT_PATH" --repo "$GITHUB_REPOSITORY"'
    for name, edit, key, want in (
            ("the advisory step is DELETED",
             lambda d: gate_steps(d).remove(advisory_step(d)), "enabled_steps", 0),
            ("the advisory step is neutered with if: false",
             lambda d: advisory_step(d).update(**{"if": "false"}), "enabled_steps", 0),
            ("...and the disabling condition is NAMED, not merely counted",
             lambda d: advisory_step(d).update(**{"if": "false"}), "step_conditions", ("false",)),
            ("the step is moved out of the REQUIRED `gate` job",
             move_out_of_gate, "enabled_steps", 0),
            ("a SECOND enabled advisory step appears (so `exactly one` is a real claim)",
             lambda d: gate_steps(d).append(copy.deepcopy(advisory_step(d))), "enabled_steps", 2),
            ("continue-on-error is DROPPED — an import error would then red every pull's gate",
             lambda d: advisory_step(d).pop("continue-on-error"), "continue_on_error", None),
            ("continue-on-error is flipped to false",
             lambda d: advisory_step(d).update(**{"continue-on-error": False}),
             "continue_on_error", False),
            # COMMENT-ONLY: the invocation is still in the file, byte for byte, as prose.
            ("the invocation survives only as a COMMENT",
             lambda d: comment_out_line(d, "python3 scripts/pr-body-ref.py"), "enabled_steps", 0),
            ("the step is repointed at another subcommand",
             lambda d: replace_in_run(d, "pr-body-ref.py check", "pr-body-ref.py compose"),
             "subcommand", "compose"),
            ("--event-path is dropped (the check would then read no event at all)",
             lambda d: replace_in_run(d, '--event-path "$GITHUB_EVENT_PATH" ', ""),
             "flags", ("--repo",)),
            ("the two flag VALUES are transposed — membership alone cannot see this",
             lambda d: replace_in_run(
                 d, BOUND, '--event-path "$GITHUB_REPOSITORY" --repo "$GITHUB_EVENT_PATH"'),
             "flag_values", {"--event-path": "$GITHUB_REPOSITORY",
                             "--repo": "$GITHUB_EVENT_PATH"}),
            ("flag/value ADJACENCY is broken while both flags and both values survive",
             lambda d: replace_in_run(
                 d, BOUND, '--event-path --repo "$GITHUB_EVENT_PATH" "$GITHUB_REPOSITORY"'),
             "flag_values", {"--event-path": "--repo", "--repo": "$GITHUB_EVENT_PATH"}),
            ("`edited` is dropped — the body advisory would go stale against the repairing edit",
             drop_type("edited"), "trigger_types",
             ("converted_to_draft", "opened", "ready_for_review", "reopened", "synchronize")),
            ("`converted_to_draft` is dropped — a re-drafted pull never gets the draft note",
             drop_type("converted_to_draft"), "trigger_types",
             ("edited", "opened", "ready_for_review", "reopened", "synchronize")),
            # DELETING the whole key is a different mutant from dropping a member: it silently
            # substitutes GitHub's default set, so both `edited` and `converted_to_draft` vanish
            # while the workflow still lints clean and still runs on most pulls.
            ("the `types:` key is deleted entirely (GitHub's default set silently substitutes)",
             lambda d: wf_pull_request(d).pop("types"), "trigger_types", None)):
        chk(f"SEAM MUTANT {name}", seam_mutant(edit)[key], want)
    # The adjacency mutant leaves flag MEMBERSHIP untouched, which is the point of pinning both.
    chk("SEAM MUTANT ...and that adjacency break is INVISIBLE to flag membership",
        seam_mutant(lambda d: replace_in_run(
            d, BOUND, '--event-path --repo "$GITHUB_EVENT_PATH" "$GITHUB_REPOSITORY"'))["flags"],
        seam["flags"])
    # VACUITY GUARD on the mutant harness itself: if `_strip_script_comments` ever stopped
    # stripping, the comment-only mutant above would still report 0 enabled steps for the WRONG
    # reason (the fragment moved onto a `#` line the finder never consulted). Drive the stripper on
    # the real step body and require the invocation to be gone.
    # An unbalanced quote is not an invocation. Driven directly because no mutant above produces
    # one, so without this row the tokeniser's refusal path is code that has never executed.
    chk("SEAM an unparseable `run:` body yields NO argv rather than a partial one",
        _run_argv('python3 scripts/pr-body-ref.py check --repo "unterminated'), ())
    chk("SEAM the comment-only mutant works by STRIPPING, not by luck",
        _run_argv(_load_sibling_module("registry_dispatch_claim",
                                       "dispatch-claim.py")._strip_script_comments(
            "# python3 scripts/pr-body-ref.py check --event-path x --repo y\n")), ())

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
# renders one is caught here rather than silently shrinking the corpus check. Moved 9 -> 10 when
# `check`'s reader-agreement rows started driving the two-reference body through the real reader.
EXPECTED_RENDERED_DOCUMENTS = 10


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
    check_cmd = sub.add_parser("check", help="advise on the pull request in a workflow event payload")
    check_cmd.add_argument("--event-path", required=True, help="$GITHUB_EVENT_PATH")
    check_cmd.add_argument("--repo", required=True)
    check_cmd.add_argument("--policy", default=str(SCRIPTS_DIR.parent / "policy" / "repos.toml"))
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if args.refresh_oracle:
        return _refresh_oracle()
    if args.command == "compose":
        return _cmd_compose(args)
    if args.command == "check":
        return _cmd_check(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
