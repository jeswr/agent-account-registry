#!/usr/bin/env python3
# [OPUS-5] The TRIGGER half of the #657 orchestrator-PR review admission (registry issue #929).
#
# WHAT WAS MISSING. #916 turned review-lane enrolment ON for the orchestrator class, and
# scripts/mint-provenance.py is the one supported writer of the provenance record that class needs.
# But mint-provenance.yml is `workflow_dispatch`-ONLY: no schedule, no repository_dispatch, no
# programmatic caller. Every reference to it in this repository is its own `--self-test` or
# documentation. So #916 converted "impossible" into "possible but MANUAL" — a human had to fire
# one dispatch per PR, and (measured on 2026-07-28) nobody ever had: zero orchestrator-attested
# records on `ledger` while the ledger was otherwise busy with worker verdicts every few seconds.
#
# WHAT THIS IS. The periodic sweep that fires the SAME minting decision, per enrolled-class PR,
# with no operator input at all. It is the TRIGGER, never the SCOPE:
#
#   * it imports mint-provenance.mint() rather than re-deriving any of its predicates, so every
#     trust gate (fork head, worker namespace, draft, allowlist, alias->provider catalog lookup,
#     attestation class, create-only idempotency, last-mile lane admissibility) is the SAME code
#     the manual path runs — this file can only ever REFUSE more, never admit more;
#   * `review_enrolment_authors` (master-protected) stays the sole authority on the population.
#     This file reads it; it can neither widen nor bypass it;
#   * `impl_alias` is a PINNED CONSTANT here with no input, argument or env binding that can reach
#     it. The lane picks the reviewer by INVERTING `impl_provider`, so an alias input would be a
#     way for the class to choose its own reviewer's side. There is deliberately none;
#   * `--allow-global-partition` is NEVER passed. A source issue that reduces to the serializing
#     `__global__` partition is a per-mint human acceptance of a fleet-wide cost, and an unattended
#     sweep must not be able to accept it.
#
# OUT OF SCOPE, DELIBERATELY: release-plz and dependabot PRs. They are not enrollable through this
# mechanism at all — reviewer selection INVERTS `impl_provider` and those classes have no
# implementing model, so admitting one requires FABRICATING a provider, which makes the
# cross-provider guarantee vacuous rather than merely weaker. They need a separate disposition
# (sparq #4677), not a wider allowlist. Nothing here reaches them: they are not in
# `review_enrolment_authors`, and `pr_mint_refusal` refuses a `[bot]` login outright.
"""auto-mint-provenance — sweep every enrolled-class PR and mint the records that are missing.

THE ONE HARD INPUT IS `issue_number`, and it is DERIVED, never defaulted. mint-provenance's own
input description says the source issue "decides the lease partition the review reserves and the
human-hold surface that can park it, so it must be a real open issue (not a PR) that the pull
request references". Guessing it wrong mis-partitions the lease AND points the human-hold at the
wrong object, so this file FAILS CLOSED on every ambiguity, with a NAMED reason:

  no-issue-reference            the PR declares no closing reference at all
  ambiguous-issue-reference     it declares more than one distinct closing reference
  reference-is-a-pull-request   the single reference resolves to a PR, not an issue
  reference-is-closed           the single reference resolves to a closed issue
  source-issue-unreadable       the reference could not be read, or read back as another number
  body-render-unavailable       GitHub's renderer did not answer, so "is this quoted?" is unknown
  body-shape-not-understood     the rendered body holds an element this derivation cannot classify

There is NO fallback. A wrong `issue_number` is worse than no mint.

WHERE THE DERIVATION READS FROM, and why it changed. The binding comes from GitHub's OWN RENDERING
of the title and body (`POST /markdown`, mode `gfm`), parsed, with text kept only from elements
POSITIVELY classified as prose — cross-checked against the raw source, so the two must agree. Three
earlier rounds derived it from regex-stripped markdown instead, and each was measured permissive in
the minting direction, because a blocklist of quoted contexts cannot be completed against a grammar
as open as GFM. The unknown case now REFUSES, which turns every future gap into a missed mint
(recoverable, visible, censused) rather than a spurious one (silent, permanent, and a grant of
review admission).

REFUSALS ARE VISIBLE ON THE PR, not only in a run log: an orchestrator-class PR that cannot be
minted is invisible to the review lane again, which is the exact state #916 exists to end. One
comment per PR per distinct reason, ever (marker-deduped) — never a per-tick refusal loop.

AND EVERY TICK EMITS A CENSUS, whatever happens. A silent auto-minter is worse than a manual one,
because nobody notices when it stops.
"""

import argparse
from html.parser import HTMLParser
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from typing import NamedTuple

SCRIPTS_DIR = Path(__file__).resolve().parent


class SweepError(RuntimeError):
    """A concise, credential-free operational error."""


class RenderUnavailable(RuntimeError):
    """GitHub's markdown renderer could not be reached, or did not answer.

    THE FAIL-CLOSED CONTRACT. The binding is derived from the rendered body, so a renderer this run
    cannot reach means this run cannot derive a binding. It REFUSES — it never falls back to reading
    the raw markdown, because the raw markdown IS the permissive derivation this redesign removed,
    and a fallback would restore it exactly when the safety check is unavailable.

    The renderer is `POST /markdown` on api.github.com, which is the SAME host and the SAME
    credential this sweep already needs to list the pull requests, read the source issue, probe the
    ledger and write the record. It is not a new availability surface: when it is down the tick has
    already skipped its target with `target-pulls-unreadable`. (Contrast sparq #4935 — a gating
    check that fetched a corpus from a THIRD-PARTY host at CI time and reddened the gate when that
    host was down. The rule this obeys is the same one that case violated: an unavailable oracle may
    only ever move the answer to the safe side.)"""


class UnknownRenderedElement(RuntimeError):
    """GitHub's rendered output holds an element this file does not positively classify.

    THIS IS THE UNKNOWN CASE, and it refuses. It is a fact about the pull request's body (the author
    wrote markup that renders to something new), so unlike `RenderUnavailable` it is COMMENTED: the
    author can act on it, and the operator learns that the classification needs a measured
    extension. Whichever it is, no record is written."""

    def __init__(self, tag):
        super().__init__(
            f"the rendered pull request contains a <{tag}> element this derivation does not "
            "classify as prose or as quoted context, so it cannot say whether a closing keyword "
            "in it is a declaration")
        self.tag = tag


# ---- WHAT THE SWEEP MAY ASSERT ----------------------------------------------------------------
# The implementing alias this unattended path will ever record. A PIN, not a default, and there is
# no CLI argument, workflow input or env binding on this path that can influence it — the seam
# report below asserts that of the LIVE workflow, not just of this constant. mint-provenance's
# `alias_mint_refusal` then resolves it through the TARGET's protected routing catalog and refuses
# anything that is not `ORCHESTRATOR_IMPL_PROVIDER`, so the recorded provider is a catalog lookup
# and the reviewer side (its inverse) is constant. The class cannot choose its own reviewer.
AUTO_IMPL_ALIAS = "opus5"

# How many records ONE tick may write. The trust plane drains slowly on purpose: a bounded sweep
# turns a bad change into a handful of records a human can read, not a ledger-wide rewrite. Stated
# in every census row (`mint_cap`) so the number is never folk knowledge.
DEFAULT_MAX_MINTS = 3

# How many refusal COMMENTS one tick may post. Bounds the first-run backlog (measured 2026-07-28:
# 20 open enrolled-class PRs, most of which declare no closing reference) into a few ticks instead
# of one burst, and bounds the blast radius of a reason-code change.
DEFAULT_MAX_COMMENTS = 5

# GitHub's own CLOSING-KEYWORD grammar, over the PR's title and body. This is the derivation, and
# it is deliberately NARROW.
#
# WHY NOT "every `#N` in the body": an orchestrator PR body routinely names a dozen issues it is
# merely discussing (predecessors, follow-ups, related defects). Taking any of them would be a
# guess, and taking all of them would make every PR ambiguous. A CLOSING keyword is an explicit
# authored declaration of the issue the PR is FOR.
#
# WHY NOT GitHub's `closingIssuesReferences` GraphQL field: it silently DROPS a reference that
# resolves to a pull request (its node type is Issue), so `reference-is-a-pull-request` could never
# fire and that refusal branch would be structurally vacuous. MEASURED on the live population:
# #886 declares `#826` and `#869`, #710 declares `#729`; `closingIssuesReferences` reports only
# `#869` and nothing, because #826 and #729 are both PRs. Deriving from the text SEES them, and
# refuses by name.
#
# Word-bounded on the left so `unfixed #7` is not a closing reference, and the `#` may only be
# preceded by the keyword's own separator — which is what keeps `Fixes sparq-org/sparq#4329` (a
# CROSS-REPO reference, in a different lease partition) from being read as this repo's `#4329`.
#
# THE NUMBER IS READ CANONICALLY — `[1-9][0-9]*`, so `#0929` is not a reference here. GitHub DOES
# resolve it (MEASURED: it renders an anchor to issue 929), so this is a declared false negative,
# and it is taken because the alternative broke this file's own invariant: `declared ⊆ raw_refs` is
# what makes everything derived here satisfy `mint-provenance.references_issue`, which searches for
# the LITERAL `#<n>`. With leading zeros admitted, `Closes #0929` derived 929 while the text `#929`
# was absent, and the shared writer refused it downstream as an opaque `mint-refused` instead of
# this file naming it. An invariant that is true by construction is worth more than one rare shape.
CLOSING_REF_RE = re.compile(
    r"(?<![0-9A-Za-z_-])(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\b[ \t]*:?[ \t]*"
    r"#([1-9][0-9]*)(?![0-9])",
    re.IGNORECASE)

# QUOTED CONTEXT — and why this file no longer tries to FIND it in the author's markdown source.
#
# GitHub does not resolve a closing keyword inside a code block; running the grammar over the raw
# text does, which makes it strictly MORE permissive than the grammar this file claims to
# implement. That gap is not cosmetic, because a wrong mint is the ONE outcome here with no
# recovery: it is silent (no comment is posted on a success), permanent (records are create-only
# and `existing_record_verdict` refuses to overwrite one with different identifying fields), and
# from the next tick onwards it is counted as `with_record` — so the sealed census would absorb the
# error AS A SUCCESS until a human deleted the ledger file. It also GRANTS REVIEW ADMISSION:
# `admits_orchestrator_pr` waives two gates of `enumerate_review_items` for a PR that has a record.
#
# IT WAS ALSO SELF-INFLICTED once. `REASON_HINTS[REASON_NO_REFERENCE]` is posted on up to
# DEFAULT_MAX_COMMENTS pull requests per tick, and quoting that comment back into the PR
# description — the single most likely author response to receiving it — was enough to mint a
# record bound to the number in the tool's own worked example.
#
# THREE ROUNDS OF BLOCKLIST, AND WHY THE BLOCKLIST WAS THE DEFECT. Rounds 3, 4 and 5 each stripped
# the quoted constructs someone had thought of — fences, code spans, blockquotes, HTML comments,
# CommonMark indented code — and each time an independent review found more shapes that still
# minted: 13, then 10, then SEVEN (`<pre>`, `<pre>`+indented, quoted `<pre>`+indented, a pipe-less
# GFM table+indented, inline `<code>`, `<details><pre>`, `<pre class=…>`), all driven end to end
# into the real writer. The residue was on the permissive side EVERY time, and the docstring
# asserting otherwise was measurably false three rounds running.
#
# The structural cause was that the strip was an ENUMERATION over an open grammar with an
# unknown case that FELL OPEN: `_continues_a_paragraph` listed five block constructs and read
# everything else as "paragraph → bind", and there was no strip for HTML code containers at all.
# A blocklist of quoted contexts cannot be completed against GitHub-flavoured Markdown.
#
# WHAT REPLACES IT. The binding is now derived from GitHub's OWN RENDERED HTML for the pull
# request's title and body (`POST /markdown`, mode `gfm`), parsed into a tree, with the text kept
# only from elements this file POSITIVELY CLASSIFIES as prose. The unknown case — any element in
# the rendered output that is in none of the classification sets below — REFUSES. See
# `rendered_prose` for the classification and `closing_references` for the two-derivation
# agreement rule that keeps a renderer surprise on the refusal side.
#
# What an INLINE quoted element leaves behind. Not a space (it would SPLICE: the grammar's
# `keyword[ \t]*:?[ \t]*#N` would read `` Fixes `mod` #1234 `` as a declaration the author never
# wrote) and not a newline (it would end `is_negated`'s sentence window mid-sentence, so
# ``this does not `x` close #7`` would stop being suppressed — a refusal turning into a mint). A
# control character cannot occur in the keyword grammar, in NEGATOR_RE's character classes, or in
# SENTENCE_BREAK_RE, which is exactly the set of properties required — and --self-test asserts all
# three of those rather than trusting the choice.
SPAN_SENTINEL = "\x00"

# ---- THE RENDERED-ELEMENT CLASSIFICATION -------------------------------------------------------
# Four CLOSED sets over GitHub's rendered output vocabulary, plus one conditional rule for `<a>`.
# Everything not named here raises `UnknownRenderedElement`, which is a REFUSAL. That is the whole
# inversion: the source grammar is open and cannot be enumerated, but the sanitised HTML GitHub
# emits is a bounded vocabulary, so a positive allowlist over IT can be complete — and when it is
# not, the gap is a missed mint (recoverable, visible, censused) rather than a spurious one.
#
# MEASURED against `POST /markdown` (mode `gfm`, this repository as context) over a 92-shape corpus
# and every rendered title+body of the live enrolled-class population: every element below was
# emitted by the real renderer for a real markdown shape. `svg`/`path` come from `> [!NOTE]` alert
# blocks, `markdown-accessiblity-table` from every GFM table, `themed-picture` from an image,
# `math-renderer` from `$…$`, `input` from a task-list checkbox, `section` from footnotes.
#
# PROSE_BLOCK: prose, and a container boundary that ENDS a proposition (a newline is emitted).
PROSE_BLOCK_ELEMENTS = frozenset({
    "p", "h1", "h2", "h3", "h4", "h5", "h6", "div", "section", "article", "aside", "header",
    "footer", "main", "nav", "ul", "ol", "li", "dl", "dt", "dd", "hr",
    "table", "thead", "tbody", "tfoot", "tr", "td", "th", "caption", "colgroup", "col",
    "details", "summary", "markdown-accessiblity-table",
})
# PROSE_INLINE: prose, and NOT a proposition boundary — text either side of it is one sentence.
PROSE_INLINE_ELEMENTS = frozenset({
    "em", "strong", "b", "i", "del", "s", "strike", "ins", "u", "sup", "sub", "mark", "q",
    "span", "small", "big", "cite", "dfn", "abbr", "time", "font", "ruby", "rt", "rp",
    "br", "wbr", "img", "input", "picture", "source", "themed-picture", "g-emoji",
    "math-renderer", "bdi", "bdo",
})
# QUOTED_BLOCK: the author is showing text, not asserting it. Its subtree contributes NO text, and
# it ends the proposition. `pre` is GitHub's own verdict that the content is code — it is what the
# renderer emits for a fence, an indented code block, a `<pre>` the author wrote, and every one of
# the seven shapes round 5 found. `blockquote` is a deliberate policy choice, not a rendering fact:
# GitHub DOES resolve a keyword inside one, so refusing it is a declared FALSE NEGATIVE (see
# `rendered_prose`), taken because quoting someone else's text is not declaring it.
QUOTED_BLOCK_ELEMENTS = frozenset({"pre", "blockquote"})
# QUOTED_INLINE: the HTML "computer output" family. Its subtree contributes SPAN_SENTINEL, never
# text. `code` is GitHub's verdict for a code span; the rest are the author's own markup saying the
# same thing, and refusing them is again a declared false negative rather than a rendering fact.
QUOTED_INLINE_ELEMENTS = frozenset({"code", "samp", "kbd", "tt", "var"})
# OPAQUE: a foreign vocabulary whose subtree is dropped WITHOUT classifying its descendants. Only
# SVG, which GitHub emits for alert icons and whose element names are not HTML's. Nothing escapes,
# so not classifying inside it cannot admit anything.
OPAQUE_ELEMENTS = frozenset({"svg"})
# Elements that never carry an end tag, so they must not be pushed onto the open-element stack.
VOID_ELEMENTS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
    "source", "track", "wbr",
})
# THE ONE CONDITIONAL RULE. `<a>` cannot be classified by tag alone, and getting it wrong breaks the
# feature in one direction or the trust model in the other. GitHub rewrites `Closes #929` into
# `Closes <a class="issue-link js-issue-link" …>#929</a>`, so dropping every anchor's text would
# make the derivation bind NOTHING; but an author-written `<a href=…>Closes #929</a>` (or the
# markdown `[Closes #929](url)`) is NOT resolved by GitHub — it emits no `issue-link` anchor —
# so treating every anchor as prose would bind a reference GitHub does not. The renderer tells the
# two apart itself: only a reference it RESOLVED carries this class.
ISSUE_LINK_CLASS = "issue-link"

# NEGATED PROSE — a best-effort suppressor, and honestly labelled as one.
#
# Unlike the four strips above, this is PROSE, so it cannot be a structural guarantee: an unlisted
# negator degrades to the old behaviour. What makes it safe to have anyway is HOW it composes —
# see `candidate_refusal`. A negated reference is removed from the DECLARED set but is still
# counted for AMBIGUITY, so this rule can only ever turn a mint into a refusal. It can never turn a
# refusal into a mint, and it can never change WHICH issue is bound. --self-test asserts that
# property directly rather than trusting the wording.
NEGATOR_RE = re.compile(
    r"(?<![0-9A-Za-z_])(?:not|no|never|neither|nor|without|cannot|unable|instead|rather"
    r"|[A-Za-z]+n['’]t)(?![0-9A-Za-z_])", re.IGNORECASE)
NEGATION_WINDOW = 64
# A negator only suppresses within its own PROPOSITION. `|` is here with the sentence enders because
# a markdown TABLE CELL boundary separates independent statements exactly as a full stop does —
# MEASURED on the live population: without it, PR #710's row `... the only caller not routed through
# `gh_retry` | **ALREADY FIXED** | #729 routed it; #749 fixed #729 ...` read the `not` from a
# DIFFERENT CELL and suppressed a reference that should refuse as `reference-is-a-pull-request`
# instead. Both outcomes are refusals, so nothing was at risk; the boundary just makes the refusal
# name the real defect.
SENTENCE_BREAK_RE = re.compile(r"[.!?\n|]")

# ADVISORY ONLY. Every same-repository `#N` the PR mentions, closing keyword or not. It is used in
# exactly one place — the prose of a `no-issue-reference` refusal comment, to name the numbers the
# author might have meant — and it is NEVER a candidate: a mention is a discussion, a closing
# keyword is a declaration, and binding a review lease to something the author merely discussed is
# the guess this whole derivation exists to refuse. --self-test pins that it cannot influence the
# derived number or the reason.
MENTION_RE = re.compile(r"(?<![0-9A-Za-z_/-])#([0-9]+)(?![0-9])")

# How many mentions the advisory hint names before it stops. An orchestrator PR body routinely
# names a dozen issues; a comment that lists all of them is not a hint.
MAX_ADVISORY_MENTIONS = 6

REPO_RE = re.compile(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+")

# How much of a refusal's own text the census carries, and how many DISTINCT causes per reason code.
# Bounded on both axes because the row is written to the job log every tick: a census that can grow
# with the population is a census nobody reads.
CENSUS_CAUSE_CHARS = 120
MAX_CENSUS_CAUSES = 4


def refusal_cause(message):
    """The one-line, whitespace-collapsed, truncated form of a refusal message for the census."""
    text = " ".join(str(message or "").split())
    return text[:CENSUS_CAUSE_CHARS] if text else "(no message)"

# ---- the refusal taxonomy ----------------------------------------------------------------------
REASON_NO_REFERENCE = "no-issue-reference"
REASON_AMBIGUOUS = "ambiguous-issue-reference"
REASON_REFERENCE_IS_PULL = "reference-is-a-pull-request"
REASON_REFERENCE_CLOSED = "reference-is-closed"
REASON_ISSUE_UNREADABLE = "source-issue-unreadable"
REASON_MINT_REFUSED = "mint-refused"
REASON_RECORD_PROBE_FAILED = "record-probe-failed"
REASON_MINT_FAILED = "mint-failed"
# THE TWO FAIL-CLOSED EXITS OF THE RENDERED DERIVATION. Neither can ever produce a record.
REASON_RENDER_UNAVAILABLE = "body-render-unavailable"
REASON_BODY_NOT_UNDERSTOOD = "body-shape-not-understood"
# ...and the third: the author wrote a closing keyword and a `#N`, and GitHub did not read the two
# as a reference at all. Named rather than folded into `no-issue-reference`, because the hint for
# that one says "add a closing reference" — actively misleading to an author who added one.
REASON_REFERENCE_NOT_RESOLVED = "reference-not-resolved"

PR_REFUSAL_REASONS = (
    REASON_NO_REFERENCE,
    REASON_AMBIGUOUS,
    REASON_REFERENCE_IS_PULL,
    REASON_REFERENCE_CLOSED,
    REASON_ISSUE_UNREADABLE,
    REASON_MINT_REFUSED,
    REASON_RECORD_PROBE_FAILED,
    REASON_MINT_FAILED,
    REASON_RENDER_UNAVAILABLE,
    REASON_BODY_NOT_UNDERSTOOD,
    REASON_REFERENCE_NOT_RESOLVED,
)

# The refusals that are censused but NOT commented on the PR. All three are facts about the
# REGISTRY or the platform — a probe that could not be read, a write that failed, a renderer that
# did not answer — not about the pull request. Commenting one would put a transient outage on
# someone else's PR permanently, because the comment dedupe is by reason and would never retract
# it. Every OTHER reason is a fact about the PR that its author can act on, so every other reason
# comments — including `body-shape-not-understood`, which IS a fact about the body. Asserted
# exactly, in both directions.
SILENT_REASONS = frozenset({REASON_RECORD_PROBE_FAILED, REASON_MINT_FAILED,
                            REASON_RENDER_UNAVAILABLE})

# Target-level refusals (not per-PR reasons): see target_sweep_refusal.
REASON_TARGET_NOT_ANNOTATABLE = "target-not-annotatable"
REASON_TARGET_ROUTING_UNREADABLE = "target-routing-unreadable"
REASON_TARGET_PULLS_UNREADABLE = "target-pulls-unreadable"

# The operator's next action, per reason. A refusal comment that does not say what to change is
# just a louder silence.
# WHY NO HINT HERE CONTAINS A LITERAL ISSUE NUMBER. These strings are posted verbatim onto pull
# requests, and the likeliest author response to receiving one is to quote it back into the PR
# description. A worked example reading `Closes #1234` was therefore a live payload that minted a
# record bound to 1234. The rendered derivation already neutralises the quoted form (the message is
# a blockquote and every placeholder a code span, both of which GitHub renders as quoted context);
# writing the placeholder without digits makes the text inert even when it is pasted UNQUOTED, and
# --self-test pins both properties over GitHub's own rendering of the whole comment.
REASON_HINTS = {
    REASON_NO_REFERENCE:
        "Add exactly one closing reference for the source issue — a `Closes #<issue-number>` line "
        "in the PR description, with the real number. `Refs #<issue-number>` is not a closing "
        "reference, and a cross-repository `owner/repo#<issue-number>` names a different lease "
        "partition. A keyword inside a code block, a code span, a blockquote or an HTML comment is "
        "QUOTED context and is deliberately not read as a declaration.",
    REASON_AMBIGUOUS:
        "Leave exactly ONE closing reference in the title and body. The others can stay as plain "
        "`#<issue-number>` mentions — only the closing keywords (`close/closes/closed`, "
        "`fix/fixes/fixed`, `resolve/resolves/resolved`) are read as the binding. A reference this "
        "sweep read as NEGATED still counts here, on purpose: it will not silently bind whichever "
        "one survived.",
    REASON_REFERENCE_IS_PULL:
        "Point the closing reference at the source ISSUE. A pull request cannot be the binding: "
        "the review lane's issue-label map skips pull-request rows while the resolve step reads "
        "the number directly, so the two would derive different packages forever.",
    REASON_REFERENCE_CLOSED:
        "Point the closing reference at an OPEN issue, or re-open it. The review lane's label map "
        "covers open issues only, so a closed one would reserve the serializing partition.",
    REASON_ISSUE_UNREADABLE:
        "Check the referenced number exists and is readable, then leave it as the single closing "
        "reference.",
    REASON_REFERENCE_NOT_RESOLVED:
        "GitHub did not read that as an issue reference, so neither does this sweep — the number "
        "is run together with a letter or an underscore (`#<issue-number>abc`, "
        "`#<issue-number>_x`), or it names an issue that does not exist. Leave the reference as a "
        "bare `#<issue-number>` followed by whitespace or punctuation, and check the number is "
        "real. This is deliberately NOT the `no-issue-reference` refusal: you did declare one, and "
        "it did not resolve.",
    REASON_BODY_NOT_UNDERSTOOD:
        "The binding is derived from GitHub's own rendering of this description, and the element "
        "named above is one this sweep does not classify as prose or as quoted context — so it "
        "cannot tell whether a closing keyword inside it is a declaration, and it refuses rather "
        "than guessing. Either express the closing reference in ordinary prose, or ask the "
        "maintainer to classify that element (it is a measured, reviewed change to the sweep, not "
        "a setting).",
    REASON_MINT_REFUSED:
        "The record was refused by the shared minting gate; the reason above is verbatim from it. "
        "Nothing was written, so this PR stays exactly as un-enumerated as it is now.",
}

# NOTE (round 7): `PASSTHROUGH_REASONS = frozenset({REASON_MINT_REFUSED})` used to live here with
# ONE definition and ZERO consumers — dead code that read as a control. The property it named is
# real and is asserted directly instead: `refusal_comment_body` renders EVERY message as a
# blockquote, and --self-test drives GitHub's real rendering of every generated comment, including
# `mint-refused`'s passthrough text, to prove the whole artefact binds nothing when pasted back.

COMMENT_MARKER_PREFIX = "<!-- auto-mint-provenance:refusal:"
SELF_ID = "> 🤖 **SPARQ agent** — auto-mint (registry #929)"


class DerivedIssue(NamedTuple):
    """The derivation result for ONE pull request. Exactly one of `number` / `reason` is set."""

    number: int | None
    reason: str | None
    message: str | None
    issue: dict | None


class RenderedProse(NamedTuple):
    """What one rendered document contributes: its PROSE text, and the SPANS of that text GitHub
    itself linkified into same-repository references — `(start, end, number)`, half-open over
    `text`.

    SPANS, NOT A SET OF NUMBERS, and that distinction is round 8's whole blocking finding. A set
    answers "is #N resolved SOMEWHERE in this pull request", which any unrelated bare mention makes
    true. The question the derivation has to ask is "is THIS OCCURRENCE — the one the closing-keyword
    grammar matched — the one GitHub resolved". MEASURED end to end into the real writer, one `> `
    character apart:

        "Closes #929abc\\n\\n> quoting an old comment that says #929"  -> refused
        "Closes #929abc\\n\\nquoting an old comment that says #929"    -> MINTED

    GitHub emits no anchor for `#929abc`; the anchor came entirely from the unrelated mention."""

    text: str
    anchors: tuple


class ClosingRefs(NamedTuple):
    """`declared` is what may BIND; `all_refs` is every closing reference either text derivation
    found, and is what AMBIGUITY is judged over; `unresolved` is the closing references BOTH texts
    agreed on that GitHub nonetheless did not resolve into a reference.

    Keeping the three apart is what makes every rule here a pure suppressor — see
    `closing_references` and `candidate_refusal`."""

    declared: list
    all_refs: list
    unresolved: list = ()


# ---- module loading (same idiom as mint-provenance.py / backfill-provenance.py) -----------------
_MODULE_CACHE = {}


def _load_script_module(filename, module_name):
    import importlib.util

    if module_name in _MODULE_CACHE:
        return _MODULE_CACHE[module_name]
    path = SCRIPTS_DIR / filename
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise SweepError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _MODULE_CACHE[module_name] = module
    return module


def _load_mint_provenance():
    """THE minting decision + writer — IMPORTED, never replicated. Every trust predicate this
    sweep is subject to lives there and is exercised by its own --self-test; a second copy here is
    how "what the sweep mints" and "what a human mints" drift."""
    return _load_script_module("mint-provenance.py", "registry_mint_provenance")


def _load_policy_resolve():
    return _load_script_module("policy-resolve.py", "registry_policy_resolve")


# ---- pure decisions (every one unit-tested by --self-test) -------------------------------------
class _ProseExtractor(HTMLParser):
    """Walks GitHub's rendered HTML and keeps the text that is PROSE, refusing anything unclassified.

    THE INVARIANT: text reaches the output only from inside elements every one of whose ancestors
    is in `PROSE_BLOCK_ELEMENTS`, `PROSE_INLINE_ELEMENTS`, or is an `<a>` the RENDERER marked as a
    resolved issue link. There is no path by which an unrecognised element contributes text: it
    raises before its content is read.

    Three things it is careful about, each a way the old regex strip got it wrong:

    * A QUOTED element's whole SUBTREE is dropped, not just its direct text, so `<pre><code>…` and
      `<a href><code>…` drop once and stay dropped.
    * A dropped BLOCK leaves a newline and a dropped INLINE leaves `SPAN_SENTINEL`, for exactly the
      reasons at `SPAN_SENTINEL`: neither can be crossed by the grammar's `[ \\t]*`, but only the
      newline ends `is_negated`'s proposition window.
    * ATTRIBUTES ARE NEVER TEXT. `<img alt="Closes #929">` renders no prose, and GitHub emits no
      issue link for it — a fixture pins that."""

    def __init__(self, repo):
        super().__init__(convert_charrefs=True)
        self.repo = repo
        self.parts = []
        self.length = 0
        self.stack = []
        self.anchors = []
        self.quote_depth = 0
        self.opaque_depth = 0

    def _emit(self, text):
        """Append to the prose and keep the running offset. The offset is what makes the anchor
        SPANS meaningful: an anchor is a REGION of the prose text, not a number."""
        self.parts.append(text)
        self.length += len(text)

    def _anchor_number(self, attrs):
        """The issue number GitHub itself RESOLVED for this anchor, if it is one and it is ours.

        Two filters, both load-bearing and both measured:

        * the href must point at THIS TARGET's `issues/` or `pull/`. A cross-repository reference
          renders as an `issue-link` too (`Fixes sparq-org/sparq#4329` →
          `href=".../sparq-org/sparq/issues/4329"`), and that number belongs to a different lease
          partition;
        * `pull/` is accepted as well as `issues/`, and that is not sloppiness. GitHub renders a
          reference to a PULL REQUEST as `href=".../pull/729"` (MEASURED on the live #729 — PR #710
          declares `fixed #729` and GitHub renders it as `pull/729`), and `resolved_issue_refusal`
          is what refuses it — BY NAME, with the reason an author can act on. Dropping `pull/` here
          would turn `reference-is-a-pull-request` into a nameless "not resolved" and make that
          branch, which fires on the live population today, structurally unreachable."""
        for name, value in attrs:
            if name != "href":
                continue
            match = re.fullmatch(
                rf"https://github\.com/{re.escape(self.repo)}/(?:issues|pull)/([0-9]+)",
                str(value or ""))
            if match:
                return int(match.group(1))
        return None

    def _classify(self, tag, attrs):
        if tag in OPAQUE_ELEMENTS:
            return "opaque"
        if tag == "a":
            classes = ""
            for name, value in attrs:
                if name == "class":
                    classes = value or ""
            return "prose-inline" if ISSUE_LINK_CLASS in classes.split() else "quoted-inline"
        if tag in PROSE_BLOCK_ELEMENTS:
            return "prose-block"
        if tag in PROSE_INLINE_ELEMENTS:
            return "prose-inline"
        if tag in QUOTED_BLOCK_ELEMENTS:
            return "quoted-block"
        if tag in QUOTED_INLINE_ELEMENTS:
            return "quoted-inline"
        raise UnknownRenderedElement(tag)

    def _separator(self, kind):
        if kind.endswith("block"):
            self._emit("\n")
        elif kind in ("quoted-inline", "opaque"):
            self._emit(SPAN_SENTINEL)

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if self.opaque_depth:
            if tag not in VOID_ELEMENTS:
                self.opaque_depth += 1
            return
        kind = self._classify(tag, attrs)
        number = (self._anchor_number(attrs)
                  if tag == "a" and kind == "prose-inline" and not self.quote_depth else None)
        self._separator(kind)
        if tag in VOID_ELEMENTS:
            return
        if kind == "opaque":
            self.opaque_depth = 1
            return
        if kind.startswith("quoted"):
            self.quote_depth += 1
        # The anchor's SPAN opens here, at the current offset, and closes when this element is
        # popped — so what is recorded is the REGION of prose text GitHub itself linkified.
        self.stack.append((tag, kind, number, self.length))

    def handle_startendtag(self, tag, attrs):
        tag = tag.lower()
        if self.opaque_depth:
            return
        self._separator(self._classify(tag, attrs))

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self.opaque_depth:
            self.opaque_depth -= 1
            return
        if tag in VOID_ELEMENTS:
            return
        while self.stack:
            open_tag, kind, number, start = self.stack.pop()
            if kind.startswith("quoted"):
                self.quote_depth -= 1
            if number is not None:
                self.anchors.append((start, self.length, number))
            if kind.endswith("block"):
                self._emit("\n")
            if open_tag == tag:
                return
        # An end tag closing nothing means the document is not the shape this parser believes it
        # is, so it is the unknown case too rather than a silently-ignored oddity.
        raise UnknownRenderedElement("/" + tag)

    def handle_data(self, data):
        if self.opaque_depth or self.quote_depth:
            return
        self._emit(data)

    def close(self):
        super().close()
        # AN UNCLOSED ANCHOR still spans what it holds, ending at the end of the document.
        #
        # THE HONEST REASON, which is NOT "it can only make the span longer". Longer is the
        # PERMISSIVE direction: a span extended to the end of the document does cover a trailing
        # run-on, and synthetically such a span BINDS one. That sentence was here first, and it was
        # a safety argument for something that is not a safety property — exactly the shape that
        # licenses the next widening.
        #
        # What actually holds is REACHABILITY, and it is three independent facts about the input,
        # none of them about this method: GitHub balances the anchors it emits; it strips
        # `class="issue-link"` from an author-written `<a>`, so an author cannot introduce one; and
        # `handle_endtag` pops until it matches, so an anchor left open by a mis-nested ancestor is
        # closed early rather than run on. If any of those three ever stops being true, this branch
        # is a widening and must be re-decided — a REFUSAL (drop the unclosed anchor entirely) is
        # the safe reading, and the only reason it is not the shipped one is that dropping it would
        # refuse a real declaration in a truncated rendering, which is a live failure mode with no
        # live counterpart on the other side.
        while self.stack:
            _tag, _kind, number, start = self.stack.pop()
            if number is not None:
                self.anchors.append((start, self.length, number))

    def text(self):
        return "".join(self.parts)


def rendered_prose(html, repo):
    """The PROSE text of GitHub's rendered HTML, and the references GitHub itself RESOLVED in it.
    Raises `UnknownRenderedElement` on anything else.

    This is the whole replacement for three rounds of source-level stripping, and the reason it can
    be complete where they could not: GitHub SANITISES its output to a bounded element vocabulary,
    so a positive allowlist over that vocabulary has a well-defined unknown case, and the unknown
    case here REFUSES.

    HONEST LIMITS — AND WHY THIS SECTION NO LONGER CONTAINS A LIST OR A COUNT.

    Every previous version of this paragraph enumerated the remaining divergences by hand, and every
    previous version was WRONG, in the permissive direction, for five consecutive rounds. The
    failure stopped being about any one shape and became about hand-written claims, so the claims
    are gone. What used to be asserted here is now DERIVED by `corpus_directions()` from GitHub's
    own rendering, frozen into `scripts/fixtures/auto-mint-provenance/rendered-oracle.json` under
    `directions`, and re-derived and compared by --self-test. Read the artefact; it cannot be out of
    date without a check going red. Two rows in --self-test enforce the absence: this docstring may
    contain no residue count and may restate no corpus row by label.

    WHAT IS PROVED, structurally, and therefore worth writing in prose:

      * A NEW GITHUB ELEMENT CANNOT MINT. Text reaches the derivation only from elements this file
        positively classifies; anything else raises, and a raise is a refusal.
      * A `#N` GITHUB DID NOT TOKENISE AS A REFERENCE CANNOT MINT. It carries no `issue-link`
        anchor, and an unanchored occurrence is not a candidate.
      * AN OCCURRENCE GITHUB DID NOT RESOLVE CANNOT MINT, even when the same number is resolved
        elsewhere in the same pull request. The check is span containment, not set membership.
      * ANYTHING DERIVED IS A LITERAL `#N` IN THE SOURCE, because `declared ⊆ raw_refs`, which is
        what `mint-provenance.references_issue` requires.
      * A RENDERER THIS RUN CANNOT REACH REFUSES, with no fall-back to the raw markdown.

    WHAT IS NOT PROVED: that no unmeasured shape can mint. The residue is an element already
    classified as PROSE whose content GitHub nonetheless does not resolve, for a reason that is
    neither the element, nor the token, nor the occurrence. Three members of that set have been
    found across rounds 6-8 and all three were closed the same way — by reading GitHub's own output
    instead of re-deriving its rules. There may be a fourth. If there is, the fix belongs in the
    same place and for the same reason.

    ONE POLICY THAT IS DELIBERATE AND IS NOT A DIVERGENCE. A `<blockquote>` is quoted context and
    does not declare; a GitHub ALERT (`> [!NOTE]`, `[!WARNING]`, …) is NOT a blockquote — the
    renderer emits `<div class="markdown-alert">` — and it DOES declare. That is the intended
    reading rather than an oversight: an alert is the author writing in their own voice with
    emphasis, while a blockquote is the author reproducing someone else's text. --self-test pins
    both halves so the distinction cannot drift silently."""
    parser = _ProseExtractor(repo)
    parser.feed(html or "")
    parser.close()
    return RenderedProse(parser.text(), tuple(parser.anchors))


def is_negated(text, keyword_start):
    """True when a negator appears between the start of `keyword_start`'s sentence and the keyword.

    Best effort by nature. It only ever REMOVES a declaration (see `candidate_refusal`), so a
    negator this does not know about degrades to "no suppression", never to a different binding."""
    window = text[max(0, keyword_start - NEGATION_WINDOW):keyword_start]
    breaks = list(SENTENCE_BREAK_RE.finditer(window))
    if breaks:
        window = window[breaks[-1].end():]
    return bool(NEGATOR_RE.search(window))


def raw_text(title, body):
    """The pull request's own source text — exactly what mint-provenance.references_issue reads."""
    return f"{title or ''}\n{body or ''}"


def prose_of(title, body, render_markdown, repo):
    """The rendered PROSE of the title and body, as the TWO SEPARATE DOCUMENTS GitHub renders.

    Rendering them TOGETHER was itself a measured defect: the title occupied line 0, so an indented
    FIRST body line always had a non-blank line above it and could never be the code block GitHub
    renders it as, and an unclosed ``` or `<!--` in a TITLE swallowed the whole body, which GitHub
    — rendering the two independently — never does. Two documents in, two renders out.

    A BLANK DOCUMENT IS NOT RENDERED. That is an identity, not an optimisation: the empty string
    renders to the empty string, so skipping the call cannot change any answer, and it keeps a PR
    with no body from spending a request. Anything non-blank goes to the renderer, including a
    document with no `#` in it — there is deliberately no "looks harmless, skip it" branch, because
    a branch like that is the enumeration this redesign exists to delete."""
    parts = [rendered_prose(render_markdown(document), repo) if (document or "").strip()
             else RenderedProse("", ())
             for document in (title, body)]
    # The two documents are JOINED with a newline, so the second one's spans must be SHIFTED by
    # exactly that much. Getting this wrong would silently move every body anchor off the text it
    # covers — a refusal, but one nobody could debug, so the offset is pinned by its own row.
    text, anchors, offset = [], [], 0
    for part in parts:
        text.append(part.text)
        anchors.extend((start + offset, end + offset, number)
                       for start, end, number in part.anchors)
        offset += len(part.text) + 1                  # +1 for the joining newline
    return RenderedProse("\n".join(text), tuple(anchors))


def derivation_texts(title, body, render_markdown, repo):
    """What the derivation cross-checks: `(raw, prose)` where `prose` carries GitHub's own anchors.

    ONE render per document per pull request, and the reason the derivation is built around this
    pair rather than around `(title, body)`: the grammar half and the advisory-mention half both
    read the prose, and computing it twice would double an already-network-bound step for no
    answer that can differ. --self-test asserts the count at the sweep's own call site."""
    return raw_text(title, body), prose_of(title, body, render_markdown, repo)


def _occurrence_is_anchored(prose, match):
    """True when THIS `#N` occurrence lies inside an anchor GitHub emitted for THAT number.

    `match` comes from `CLOSING_REF_RE`, whose group 1 is the digits, so the `#` sits at
    `match.start(1) - 1` and the whole reference is `[hash, end)`. The anchor's own text for a
    same-repository reference is exactly `#N`, so containment is the natural test and it is
    deliberately CONTAINMENT rather than equality: GitHub sometimes rewrites the anchor text (an
    issue URL renders as `#929`), and a span that is longer than the reference is still a span
    GitHub linkified."""
    hash_at, end = match.start(1) - 1, match.end(1)
    number = int(match.group(1))
    return any(start <= hash_at and end <= stop and anchored == number
               for start, stop, anchored in prose.anchors)


def closing_references(raw, prose):
    """Every same-repository closing reference, split into what may BIND and what counts for
    AMBIGUITY. Raises `RenderUnavailable` / `UnknownRenderedElement`; both are refusals upstream.

    TWO DERIVATIONS THAT MUST AGREE. The grammar is run over the RENDERED PROSE (what GitHub says
    is live text) and over the RAW SOURCE (what the author literally typed), and:

      * `declared`  — what may bind — is the INTERSECTION, minus anything negated;
      * `all_refs`  — what ambiguity is judged over — is the UNION.

    So a reference the two derivations disagree about can only ever produce a REFUSAL, never a
    binding and never a different binding. That is what makes each side's residual gap safe:

      * a keyword the renderer puts in `<pre>`/`<code>` is missing from the prose side, so it drops
        out of the intersection — the seven shapes of round 5, and every shape like them;
      * a keyword the RENDERER manufactures that the author did not type — `Clos**es** #7` renders
        as the text `Closes #7`, `Closes &#35;7` as `Closes #7`, and `Closes <issue URL>` as
        `Closes #929` because GitHub rewrites the anchor's text — is missing from the raw side, so
        it drops out too. MEASURED: all three of those DO render as a live GitHub reference, and
        all three refuse here.

    THE THIRD CONJUNCT, and why it is not a fourth patch. The two TEXT derivations above share one
    tokenizer — `CLOSING_REF_RE` — and therefore share its blind spots, so a `#N` boundary GitHub
    disagrees with is invisible to BOTH sides and the agreement rule cannot catch it by
    construction. MEASURED, round 7, driven end to end into the real writer with the live renderer:
    `Closes #929abc` minted, and GitHub emitted NO anchor for it — the grammar terminates the number
    with `(?![0-9])`, GitHub terminates it with a WORD boundary. Two more of the same class:
    `Closes #929_x` and `Closes #929é` also minted and are also unresolved by GitHub, while
    `#929-x`, `#929's`, `#929.`, `#929)`, `#929/` and `#929;` ARE resolved and must keep binding.

    So the third conjunct is GitHub's OWN ANCHOR — but over OCCURRENCES, not over numbers. This is
    the same move as the rest of the redesign, ask the authority instead of re-deriving its rules,
    and it closes the CLASS rather than the instance: any divergence between this file's `#N`
    tokenizer and GitHub's now lands on a refusal, whichever end of the token it is at.

    ROUND 8 CORRECTED THE SHAPE OF THAT CONJUNCT, and the correction is the interesting part. It was
    first written as set membership — `N ∈ prose.anchored` — which asks "did GitHub resolve #N
    SOMEWHERE in this pull request". Any unrelated bare mention makes that true, so the run-on
    re-minted with the anchor supplied by a mention one `> ` character away. The intersection
    argument ("a conjunct can only refuse more") was CORRECT over sets of numbers and was the wrong
    argument: the guarantee it was being asked to carry was over OCCURRENCES. The invariant this
    reaches for, stated properly, is:

        THE OCCURRENCE THE GRAMMAR MATCHED MUST BE THE OCCURRENCE GITHUB RESOLVED.

    Sets were an approximation of it. `_occurrence_is_anchored` is the thing itself.

    NOT the alternative of tightening `CLOSING_REF_RE`'s right boundary to `(?![0-9A-Za-z_])`. That
    re-derives GitHub's tokenizer a second time instead of reading it, and MEASURED it breaks a real
    binding row: inline prose elements concatenate without a separator, so `<ruby>Closes #929<rt>x`
    renders the prose text `Closes #929x` and a word-boundary guard would refuse a reference GitHub
    resolves.

    A NUMBER IS DECLARED WHEN AT LEAST ONE OF ITS MATCHED OCCURRENCES IS ANCHORED — not all of
    them. `Closes #929abc and closes #929` has two matched occurrences of 929, one unanchored and
    one anchored, and GitHub really does close 929 from the second, so it binds. `unresolved` is
    therefore the numbers with matched occurrences of which NONE was anchored.

    THE ANCHORS DELIBERATELY DO NOT FEED `all_refs`: GitHub anchors every bare mention too, so
    putting them in the ambiguity union would make almost every pull request ambiguous.

    It also keeps the shared writer's own precondition true by construction: `declared ⊆ raw_refs`,
    so anything derived here is a textual `#N` in the title or body and therefore satisfies
    `mint-provenance.references_issue`."""
    raw_refs = {int(match.group(1)) for match in CLOSING_REF_RE.finditer(raw)}
    resolved, matched, seen = set(), set(), set(raw_refs)
    for match in CLOSING_REF_RE.finditer(prose.text):
        number = int(match.group(1))
        seen.add(number)
        if is_negated(prose.text, match.start()):
            continue
        matched.add(number)
        if _occurrence_is_anchored(prose, match):
            resolved.add(number)
    return ClosingRefs(sorted(resolved & raw_refs), sorted(seen),
                       sorted((matched - resolved) & raw_refs))


def closing_issue_candidates(title, body, render_markdown, repo):
    """The DISTINCT, sorted set of same-repository issue numbers this PR DECLARES it closes."""
    return closing_references(*derivation_texts(title, body, render_markdown, repo)).declared


def mentioned_issue_numbers(prose):
    """ADVISORY: every same-repository `#N` the PR mentions, sorted, capped. Never a candidate.

    Reads the same RENDERED PROSE the grammar's binding half does, so the hint never advertises a
    number that only exists inside a code block the author pasted."""
    return sorted({int(number)
                   for number in MENTION_RE.findall(prose.text)})[:MAX_ADVISORY_MENTIONS]


def candidate_refusal(candidates, mentions=(), all_references=None):
    """(reason, message) when the candidate SET cannot name one source issue, else None.

    FAIL CLOSED at cardinality, before anything is read: zero candidates and two candidates are
    distinct defects with distinct fixes, so they are distinct named reasons. There is deliberately
    no tie-break, no "first one wins", and no default. `mentions` only ever reaches the PROSE.

    THE AMBIGUITY CHECK RUNS OVER `all_references`, NOT over `candidates`. That ordering is what
    makes the negation suppressor safe: a reference this file decided was negated is gone from
    `candidates` but still counted here, so a mis-read negation can only ever produce an AMBIGUOUS
    refusal — never a mint bound to whichever reference survived. `Closes #7. This does not close
    #8.` therefore refuses rather than quietly binding #7."""
    references = list(candidates) if all_references is None else list(all_references)
    if len(references) > 1:
        named = ", ".join(f"#{number}" for number in references)
        return (REASON_AMBIGUOUS,
                f"this pull request declares {len(references)} distinct closing references "
                f"({named}); exactly one is needed, because the source issue decides which lease "
                "partition the review reserves and which object a human hold can park")
    if not candidates:
        seen = ", ".join(f"#{number}" for number in mentions)
        aside = (f" It does mention {seen}; if one of those is the source issue, say so with a "
                 "closing keyword." if seen else "")
        return (REASON_NO_REFERENCE,
                "this pull request declares no closing reference to a source issue in its title "
                "or body, so the issue that would decide its review lease partition and its "
                f"human-hold surface cannot be derived.{aside}")
    return None


def resolved_issue_refusal(number, issue):
    """(reason, message) when the ONE candidate does not resolve to a live open issue, else None.

    A strict PRE-FILTER, never a widening: mint-provenance.issue_mint_refusal independently
    refuses both of the substantive cases below and stays the authority. Re-deriving them here
    buys the NAMED reason the PR comment needs, and --self-test pins the agreement so the two can
    never drift into this file admitting something the shared gate would refuse."""
    if not isinstance(issue, dict) or issue.get("number") != number:
        return (REASON_ISSUE_UNREADABLE,
                f"the closing reference #{number} could not be read back as itself")
    if "pull_request" in issue:
        return (REASON_REFERENCE_IS_PULL,
                f"the closing reference #{number} is a PULL REQUEST, not an issue; the source "
                "issue must be a real issue or the review lane derives two different packages "
                "for it and refuses its own claim every tick")
    if issue.get("state") != "open":
        return (REASON_REFERENCE_CLOSED,
                f"the closing reference #{number} is a CLOSED issue; the review lane's label map "
                "covers open issues only, so the PR would reserve the serializing partition")
    return None


def derive_issue_number(pull, read_issue, render_markdown, repo):
    """The whole `issue_number` derivation for ONE PR. TOTAL: never raises, never guesses.

    `read_issue(number)` is the live read of the single candidate and `render_markdown(text)` is
    GitHub's own renderer. Any failure of EITHER is a refusal, not an exception and emphatically
    not a fallback — in particular there is no path from "the renderer did not answer" to "read the
    raw markdown instead", because the raw markdown is the permissive derivation this file
    deliberately no longer has."""
    if not isinstance(pull, dict):
        return DerivedIssue(None, REASON_ISSUE_UNREADABLE,
                            "the pull request payload is malformed", None)
    try:
        raw, prose = derivation_texts(pull.get("title"), pull.get("body"), render_markdown, repo)
        references, mentions = closing_references(raw, prose), mentioned_issue_numbers(prose)
    except UnknownRenderedElement as exc:
        return DerivedIssue(None, REASON_BODY_NOT_UNDERSTOOD, str(exc), None)
    except Exception as exc:                              # noqa: BLE001 — no render, no derivation
        return DerivedIssue(None, REASON_RENDER_UNAVAILABLE,
                            "GitHub's markdown renderer could not be read, so whether a closing "
                            f"keyword is quoted context cannot be decided ({exc}); nothing was "
                            "derived and nothing was written", None)
    # THE UNRESOLVED CASE FIRST, because it is a strictly better message than the two cardinality
    # refusals for the same body: the author DID declare a closing reference and GitHub did not
    # resolve it, which `no-issue-reference` would tell them to fix by declaring one.
    if not references.declared and references.unresolved:
        named = ", ".join(f"#{number}" for number in references.unresolved)
        return DerivedIssue(
            None, REASON_REFERENCE_NOT_RESOLVED,
            f"this pull request declares a closing reference to {named}, but GitHub does not "
            "resolve it into an issue reference at all — so it cannot be the binding, and this "
            "sweep will not guess which issue was meant", None)
    refusal = candidate_refusal(references.declared, mentions, references.all_refs)
    if refusal:
        return DerivedIssue(None, refusal[0], refusal[1], None)
    number = references.declared[0]
    try:
        issue = read_issue(number)
    except Exception as exc:                          # noqa: BLE001 — any read failure refuses
        return DerivedIssue(None, REASON_ISSUE_UNREADABLE,
                            f"the closing reference #{number} could not be read ({exc})", None)
    refusal = resolved_issue_refusal(number, issue)
    if refusal:
        return DerivedIssue(None, refusal[0], refusal[1], None)
    return DerivedIssue(number, None, None, issue)


def routing_pointer_error(pointer):
    """Why a policy row's `routing` pointer must NOT be fetched, or None.

    mint-provenance.yml resolves this pointer inside a checkout and guards traversal with
    `Path.relative_to`; this sweep reads it through the contents API instead (one call per target,
    no dynamic checkout matrix), so the same guard has to be stated on the string."""
    if not isinstance(pointer, str) or not pointer:
        return "the policy row carries no routing pointer"
    if pointer.startswith("/") or "\\" in pointer or ":" in pointer:
        return f"the routing pointer {pointer!r} is not a relative repository path"
    parts = PurePosixPath(pointer).parts
    if not parts or any(part in ("..", ".", "") for part in parts):
        return f"the routing pointer {pointer!r} escapes the repository root"
    return None


def enrolled_targets(policy_doc, review_enrolment_authors):
    """Every ENABLED policy target that enrols at least one review author, as (repo, authors).

    Both halves, from their own authorities: `enabled` mirrors mint-provenance.yml's policy step
    (a syntax-only read once permitted provenance pre-seeding for arbitrary public repositories),
    and the author list comes from policy-resolve's VALIDATING reader, which raises on a
    malformed or non-canonical row rather than silently resolving it to "nobody"."""
    rows = (policy_doc.get("repos") or {}) if isinstance(policy_doc, dict) else {}
    targets = []
    for name in sorted(rows):
        row = rows[name]
        if not isinstance(row, dict) or row.get("enabled") is not True:
            continue
        authors = tuple(sorted(review_enrolment_authors(name, policy_doc)))
        if authors:
            targets.append((name, authors))
    return targets


def target_sweep_refusal(target_repo, annotate_repo):
    """Why an enrolled target must NOT be swept by THIS run, or None.

    A target may only be swept if this run can also ANNOTATE its pull requests. The whole point of
    #929's requirement 4 is that a refusal is visible on the PR; a target whose PRs this run can
    only read would get silent refusals, which re-creates exactly the invisibility #916 exists to
    end. `github.token` is write-scoped to the repository the workflow runs in, so today that is
    the registry — and the registry is, deliberately, the only enrolled target (#916 scoped the
    rollout to one repo). Enrolling a second one is therefore a LOUD refusal in the census rather
    than a half-working sweep: widening needs the target-scoped App token plumbing, which is a
    separate, separately-reviewed change."""
    if not isinstance(target_repo, str) or not REPO_RE.fullmatch(target_repo):
        return (REASON_TARGET_NOT_ANNOTATABLE, "the target repository is malformed")
    if target_repo != annotate_repo:
        return (REASON_TARGET_NOT_ANNOTATABLE,
                f"this run can only comment on {annotate_repo}, so a refusal on a "
                f"{target_repo} pull request would be invisible; that target needs the "
                "target-scoped App token plumbing before it can be swept")
    return None


def enrolled_class_pulls(pulls, authors):
    """The open PRs an enrolled author wrote, ascending by number.

    Author matching is CASEFOLDED, like policy-resolve's consumer and mint-provenance's own
    allowlist check. This narrows the population; it never widens it — mint-provenance's
    `pr_mint_refusal` re-checks the same allowlist and is the authority."""
    folded = {author.casefold() for author in authors if isinstance(author, str)}
    rows = []
    for pull in pulls if isinstance(pulls, list) else []:
        if not isinstance(pull, dict):
            continue
        number = pull.get("number")
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            continue
        login = str((pull.get("user") or {}).get("login", ""))
        if login and login.casefold() in folded:
            rows.append(pull)
    return sorted(rows, key=lambda row: row["number"])


def refusal_marker(reason):
    """The idempotence key of a refusal comment. Keyed on the REASON ALONE, deliberately: the
    reasons are facts about the PR's text or its source issue, not about its head, so re-posting
    on every push would be a per-tick refusal loop wearing a dedupe. One comment per PR per
    distinct reason, ever; a DIFFERENT reason (the author fixed one thing and hit the next) is a
    new comment, which is the only case where saying it again carries information."""
    return f"{COMMENT_MARKER_PREFIX}{reason} -->"


def already_refused(comments, reason):
    """True when this PR already carries the refusal comment for `reason`."""
    marker = refusal_marker(reason)
    for comment in comments if isinstance(comments, list) else []:
        if isinstance(comment, dict) and marker in str(comment.get("body") or ""):
            return True
    return False


def refusal_comment_body(reason, message):
    """The comment left ON the pull request. Credential-free by construction: every message it
    interpolates is either built in this file or is mint-provenance's own concise refusal text.

    THE MESSAGE IS RENDERED AS A BLOCKQUOTE. Not decoration: GitHub renders it into a
    `<blockquote>`, which `rendered_prose` drops, so a comment pasted back into a PR
    description cannot become a declaration — even for `mint-refused`, whose text comes from another
    component and is therefore not this file's to vet. The numbers in it are still counted for
    AMBIGUITY (the raw half of the union sees them), so a pasted-back comment REFUSES rather than
    quietly doing nothing, and --self-test asserts both halves over GitHub's own rendering."""
    hint = REASON_HINTS.get(reason, "")
    quoted = "\n".join(f"> {line}" for line in str(message).rstrip(".").splitlines() or [""])
    return (
        f"{SELF_ID}\n\n"
        f"**No provenance record could be minted for this PR — `{reason}`.**\n\n"
        f"{quoted}.\n\n"
        f"{hint}\n\n"
        "Until a record exists this pull request is invisible to the cross-provider review lane: "
        "registry #916 enrolled the orchestrator class, and the per-PR provenance record is the "
        "other half of its admission. Nothing was written, so nothing changed — this comment is "
        "the refusal being visible instead of silent, and it is posted once per distinct reason.\n"
        f"\n{refusal_marker(reason)}\n")


def census_row(counters):
    """The tick's census, as one JSON-able dict, with the SEALED accounting assertion.

    Every enrolled-class PR the sweep saw lands in exactly one bucket, and the row says so
    arithmetically. A census that does not add up is a sweep that cannot say what it did, so it
    STOPS the tick loudly rather than printing a number nobody can reconcile (the same posture
    curate-frontier takes on its readiness census)."""
    row = dict(counters)
    accounted = row["with_record"] + row["minted"] + row["refused"] + row["deferred_cap"]
    if accounted != row["enrolled_pulls"]:
        raise SweepError(
            f"auto-mint census does not account for the population: {row['enrolled_pulls']} "
            f"enrolled-class PR(s) but {accounted} accounted for "
            f"(with_record={row['with_record']} minted={row['minted']} "
            f"refused={row['refused']} deferred_cap={row['deferred_cap']})")
    row["lacking_record"] = row["enrolled_pulls"] - row["with_record"]
    row["refusal_causes"] = {reason: sorted(causes)
                             for reason, causes in (row.get("refusal_causes") or {}).items()}
    return row


def format_census(row):
    """The one-line human census. The machine-readable row is printed beside it, so a log scraper
    never has to parse this sentence."""
    refusals = ", ".join(f"{reason}={count}"
                         for reason, count in sorted((row.get("refusals") or {}).items())) or "none"
    return (f"auto-mint census: targets={row['targets']} enrolled_pulls={row['enrolled_pulls']} "
            f"with_record={row['with_record']} lacking_record={row['lacking_record']} "
            f"minted={row['minted']}/{row['mint_cap']} refused={row['refused']} "
            f"deferred_cap={row['deferred_cap']} commented={row['commented']}/"
            f"{row['comment_cap']} apply={row['apply']} refusals[{refusals}]")


def new_counters(*, mint_cap, comment_cap, apply_changes):
    return {
        "targets": 0,
        "enrolled_pulls": 0,
        "with_record": 0,
        "minted": 0,
        "refused": 0,
        "deferred_cap": 0,
        "commented": 0,
        "comment_deferred_cap": 0,
        "refusals": {},
        # WHY each reason fired, bounded. `refusals` counts reason CODES, and one code —
        # `mint-refused` — carries two operationally opposite situations: the shared gate
        # declining one pull request (the lane is working) and the lane unable to run at all (an
        # unreadable source issue, an alias missing from the routing catalog). Only the passthrough
        # TEXT separates them, and that text reached the log line and the PR comment but never the
        # machine-readable row — so the row could not tell an operator whether the lane was healthy
        # or dead. This carries a capped, deduplicated, truncated summary of it.
        "refusal_causes": {},
        "skipped_targets": {},
        "mint_cap": mint_cap,
        "comment_cap": comment_cap,
        "apply": bool(apply_changes),
    }


# ---- the sweep ---------------------------------------------------------------------------------
def sweep(targets, *, annotate_repo, read_routing, read_pulls, read_issue, read_record, mint_pr,
          read_comments, post_comment, render_markdown, apply_changes=False,
          max_mints=DEFAULT_MAX_MINTS, max_comments=DEFAULT_MAX_COMMENTS, log=print):
    """One tick. Returns the census row; every reader/writer is injectable so --self-test drives
    this exact orchestration — the call sites, not just the predicates."""
    mint_provenance = _load_mint_provenance()
    counters = new_counters(mint_cap=max_mints, comment_cap=max_comments,
                            apply_changes=apply_changes)

    def refuse(repo, pull, reason, message):
        counters["refused"] += 1
        counters["refusals"][reason] = counters["refusals"].get(reason, 0) + 1
        causes = counters["refusal_causes"].setdefault(reason, [])
        cause = refusal_cause(message)
        if cause not in causes and len(causes) < MAX_CENSUS_CAUSES:
            causes.append(cause)
        log(f"REFUSE {repo}#{pull['number']} [{reason}]: {message}")
        if reason in SILENT_REASONS:
            return
        if counters["commented"] >= max_comments:
            counters["comment_deferred_cap"] += 1
            return
        try:
            if already_refused(read_comments(repo, pull["number"]), reason):
                return
            if apply_changes:
                post_comment(repo, pull["number"], refusal_comment_body(reason, message))
            counters["commented"] += 1
        except Exception as exc:                      # noqa: BLE001 — annotation is best-effort
            log(f"WARN {repo}#{pull['number']}: could not annotate the refusal ({exc})")

    for target_repo, authors in targets:
        target_error = target_sweep_refusal(target_repo, annotate_repo)
        if target_error:
            counters["skipped_targets"][target_repo] = target_error[0]
            log(f"SKIP target {target_repo} [{target_error[0]}]: {target_error[1]}")
            continue
        try:
            routing = read_routing(target_repo)
        except Exception as exc:                      # noqa: BLE001 — an unreadable catalog skips
            counters["skipped_targets"][target_repo] = REASON_TARGET_ROUTING_UNREADABLE
            log(f"SKIP target {target_repo} [{REASON_TARGET_ROUTING_UNREADABLE}]: {exc}")
            continue
        # EVERY tick emits a census, so every reader that can raise is caught. `read_pulls` and
        # `mint_pr` below used to sit outside any handler: the run went red, but it produced NO
        # census row, and "the sweep stopped saying anything" is the failure this file exists to
        # make impossible. A target that cannot be listed is a skipped target with a named reason.
        try:
            listed = read_pulls(target_repo)
        except Exception as exc:                      # noqa: BLE001 — an unlistable target skips
            counters["skipped_targets"][target_repo] = REASON_TARGET_PULLS_UNREADABLE
            log(f"SKIP target {target_repo} [{REASON_TARGET_PULLS_UNREADABLE}]: {exc}")
            continue
        counters["targets"] += 1
        pulls = enrolled_class_pulls(listed, authors)
        counters["enrolled_pulls"] += len(pulls)
        for pull in pulls:
            number = pull["number"]
            try:
                existing = read_record(target_repo, number)
            except Exception as exc:                  # noqa: BLE001 — never "nothing is recorded"
                refuse(target_repo, pull, REASON_RECORD_PROBE_FAILED,
                       f"cannot establish whether a provenance record already exists ({exc})")
                continue
            if existing is not None:
                counters["with_record"] += 1
                continue
            derived = derive_issue_number(
                pull, lambda n, r=target_repo: read_issue(r, n),
                lambda text, r=target_repo: render_markdown(r, text), target_repo)
            if derived.reason:
                refuse(target_repo, pull, derived.reason, derived.message)
                continue
            if counters["minted"] >= max_mints:
                counters["deferred_cap"] += 1
                log(f"defer {target_repo}#{number}: the per-tick mint cap ({max_mints}) is spent")
                continue
            try:
                decision = mint_pr(target_repo, number, derived.number, routing, authors, pull,
                                   derived.issue)
            except Exception as exc:                  # noqa: BLE001 — a failed write is censused
                refuse(target_repo, pull, REASON_MINT_FAILED,
                       f"the provenance write failed ({exc}); nothing was recorded for this PR")
                continue
            if decision.action == mint_provenance.ACTION_MINT:
                counters["minted"] += 1
            elif decision.action == mint_provenance.ACTION_ALREADY:
                counters["with_record"] += 1
            else:
                refuse(target_repo, pull, REASON_MINT_REFUSED, decision.reason)
    row = census_row(counters)
    log(format_census(row))
    log("auto-mint census json: " + json.dumps(row, sort_keys=True, separators=(",", ":")))
    return row


# ---- I/O ---------------------------------------------------------------------------------------
def _gh_readers(mint_provenance, registry_repo):
    """The live readers/writers, built over mint-provenance's own `gh` helpers so this file adds
    no second HTTP idiom."""
    worker_pr = mint_provenance._load_worker_pr()

    def read_routing(target_repo):
        import base64
        import tomllib

        policy_doc = _read_policy()
        pointer = ((policy_doc.get("repos") or {}).get(target_repo) or {}).get("routing")
        error = routing_pointer_error(pointer)
        if error:
            raise SweepError(error)
        payload = mint_provenance._gh_json(
            ["api", f"repos/{target_repo}/contents/{pointer}"])
        if not isinstance(payload, dict) or payload.get("encoding") != "base64":
            raise SweepError(f"{target_repo}:{pointer} did not read back as a base64 file")
        return tomllib.loads(base64.b64decode(payload.get("content") or "").decode("utf-8"))

    def read_pulls(target_repo):
        pages = mint_provenance._gh_json(
            ["api", "--paginate", "--slurp",
             f"repos/{target_repo}/pulls?state=open&per_page=100"])
        return [row for page in (pages or []) for row in (page or [])]

    def read_issue(target_repo, number):
        return mint_provenance._gh_json(["api", f"repos/{target_repo}/issues/{number}"])

    def read_record(target_repo, number):
        path = worker_pr.provenance_path(target_repo, number)
        return mint_provenance.effective_record_body(
            lambda ref=None: worker_pr._probe_registry_file(registry_repo, path, ref=ref),
            worker_pr.LEDGER_REF)

    def read_comments(target_repo, number):
        pages = mint_provenance._gh_json(
            ["api", "--paginate", "--slurp",
             f"repos/{target_repo}/issues/{number}/comments?per_page=100"])
        return [row for page in (pages or []) for row in (page or [])]

    def post_comment(target_repo, number, body):
        mint_provenance._run_gh(
            ["api", "-X", "POST", f"repos/{target_repo}/issues/{number}/comments",
             "-f", f"body={body}"])

    def render_markdown(target_repo, text):
        """GitHub's own rendering of `text`, as it would render it IN `target_repo`.

        `context` is the target repository so a `#N` GitHub resolves there is marked with the
        `issue-link` class — that class is how `rendered_prose` tells the renderer's own
        resolved reference apart from an author-written `<a>` (see ISSUE_LINK_CLASS). `mode=gfm`
        because GFM is what GitHub renders a pull-request body with; tables, task lists and
        strikethrough all differ under plain `markdown`.

        FAILS CLOSED. A non-zero `gh` exit becomes `RenderUnavailable`, which `derive_issue_number`
        turns into a refusal. There is no raw-markdown fallback: the point of the renderer is that
        it is the authority on what is quoted, and an authority you ignore when it is inconvenient
        is not one. It runs against api.github.com with the same token as every other call this
        sweep makes, so it adds no host and no credential that the tick did not already depend on."""
        result = mint_provenance._run_gh(
            ["api", "-X", "POST", "/markdown", "-f", f"text={text}", "-f", "mode=gfm",
             "-f", f"context={target_repo}"], check=False)
        if result.returncode != 0:
            raise RenderUnavailable(
                f"GitHub's markdown renderer returned {result.returncode} for a "
                f"{len(text or '')}-character document")
        return result.stdout

    return (read_routing, read_pulls, read_issue, read_record, read_comments, post_comment,
            render_markdown)


def _read_policy():
    import tomllib

    with open(SCRIPTS_DIR.parent / "policy" / "repos.toml", "rb") as handle:
        return tomllib.load(handle)


def _mint_caller(mint_provenance, registry_repo, apply_changes, log, write_record=None):
    """The bound call into the SHARED minting path. `write_record` is injectable for the same
    reason every reader in mint() is: --self-test drives this exact call site, so a dropped or
    rebound argument here reds a check instead of surviving as an untested seam.

    Note what is NOT a parameter: `impl_alias` is the pinned AUTO_IMPL_ALIAS, and
    `allow_global_partition` is never passed — an unattended sweep must not be able to accept the
    serializing partition on the fleet's behalf, and must not be able to name the implementing
    side the reviewer is chosen by inverting."""
    def call(target_repo, pr_number, issue_number, routing, authors, pull, issue):
        return mint_provenance.mint(
            target_repo, pr_number, issue_number, AUTO_IMPL_ALIAS, registry_repo, routing, authors,
            apply_changes=apply_changes,
            read_pull=lambda: pull, read_issue=lambda: issue, read_record=lambda: None,
            write_record=write_record, log=log)

    return call


# ---- workflow seam (PyYAML-parsed; a `run:` predicate is not a testable predicate) -------------
def _workflow(name):
    import yaml

    path = SCRIPTS_DIR.parent / ".github" / "workflows" / name
    assert path.is_file(), f"{name} not found for the workflow-seam check: {path}"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def sweep_workflow_seam_report(workflow=None):
    """Structural findings about the LIVE auto-mint-provenance.yml, each asserted by --self-test.

    Derived from the PARSED document, never from a substring of the file, and the `run:` script is
    COMMENT-STRIPPED before any fragment check — a commented-out invocation leaves the token in the
    text and must not satisfy a wiring assertion.

    `schedule_crons` is the finding this whole issue is about: mint-provenance.yml is
    `workflow_dispatch`-only and therefore never fires, which is why zero records were ever
    minted. A workflow that loses its schedule is silently back in that state."""
    workflow = _workflow("auto-mint-provenance.yml") if workflow is None else workflow
    strip = _load_script_module("dispatch-claim.py",
                                "registry_dispatch_claim")._strip_script_comments
    # PyYAML parses a bare `on:` key as the boolean True.
    triggers = workflow.get("on") if "on" in workflow else workflow.get(True)
    triggers = triggers or {}
    inputs = ((triggers.get("workflow_dispatch") or {}).get("inputs") or {})
    schedule = triggers.get("schedule") or []
    job = workflow["jobs"]["sweep"]
    steps = job["steps"]
    step = next((s for s in steps
                 if "auto-mint-provenance.py" in strip(str(s.get("run") or ""))), None)
    run = strip(str((step or {}).get("run") or ""))
    guard = str(job.get("if") or "")
    self_at = run.find("auto-mint-provenance.py --self-test")
    invoke_at = run.find('auto-mint-provenance.py "${args[@]}"')
    step_env = {key: str(value) for key, value in ((step or {}).get("env") or {}).items()}
    permissions = job.get("permissions") or {}
    checkout = next((s for s in steps if "actions/checkout" in str(s.get("uses") or "")), None)
    return {
        # THE ARGUMENTS, not merely the invocation. `sweep_invoked` proves the call site exists;
        # these prove it says what this file's guarantees assume. Rebinding --annotate-repo widens
        # which repository the run will comment on, and a --max-mints/--max-comments override in
        # the workflow would silently retire the caps the census advertises — none of which a
        # "the script is called" assertion can see.
        "registry_repo_argument": bool(
            re.search(r'--registry-repo\s+"\$REGISTRY_REPO"', run)),
        "annotate_repo_argument": bool(
            re.search(r'--annotate-repo\s+"\$REGISTRY_REPO"', run)),
        "no_cap_override": not re.search(r"--max-mints|--max-comments", run),
        # A persisted token in the checkout would leave credentials on disk for every later step.
        "checkout_persist_credentials": (checkout or {}).get("with", {}).get(
            "persist-credentials"),
        # THE #929 FINDING: this workflow is self-starting, or it is mint-provenance.yml again.
        "schedule_crons": [str((entry or {}).get("cron")) for entry in schedule
                           if isinstance(entry, dict)],
        # The salt is a secret: a modified branch copy of this workflow must never see it. The
        # DISPATCH path carries the strict comparison...
        "job_ref_guarded": "github.ref ==" in guard and "default_branch" in guard,
        # ...and the `schedule` path is carved out ON PURPOSE, because the strict comparison reads
        # `github.event.repository` and a cron tick that silently evaluated it away would skip this
        # job forever with no census — the #929 defect, re-created by its own fix. Asserted so the
        # carve-out cannot be quietly deleted (which would re-open that risk) and cannot be
        # quietly widened to another event either: the finding is the exact event name.
        "job_schedule_carveout": "github.event_name == 'schedule'" in guard,
        "job_environment": job.get("environment"),
        "contents_write": permissions.get("contents"),
        # Requirement 4: a refusal has to be visible ON THE PR. Without this the sweep degrades to
        # a silent minter, which is the failure mode #929 says is worse than the manual one.
        "pull_requests_write": permissions.get("pull-requests"),
        # The identity source is the live API. This job must NOT read run logs — that is
        # backfill's identity source, and granting it here would blur two attestation classes.
        "no_actions_permission": "actions" not in permissions,
        "sweep_invoked": step is not None and invoke_at >= 0,
        "step_unconditional": step is not None and "if" not in step,
        "errexit": "set -euo pipefail" in run,
        "self_test_before_sweep": 0 <= self_at < invoke_at,
        # The write lever is conditional on its OWN input, and the manual dispatch defaults to the
        # no-op so an operator can preview a census before letting the cron write.
        "apply_is_conditional": bool(
            re.search(r'\[\[\s*"\$APPLY"\s*==\s*"true"\s*\]\].*args\+=\(--apply\)', run)),
        "dispatch_default_is_dry_run": inputs.get("apply", {}).get("default"),
        # THE REVIEWER-SIDE SEAM: the implementing alias decides (by inversion) which provider
        # reviews this class, so there must be NO input, env binding or argument that names it.
        # Same shape as mint-provenance's attestation-class seam, for the same reason.
        "no_alias_input": not any(re.search(r"alias|impl.?provider", name, re.I)
                                  for name in list(inputs) + list(step_env)),
        "no_alias_argument": not re.search(r"--impl-alias|--allow-global-partition", run),
        "no_run_key_input": not any(
            re.search(r"run.?key|recorded.?at.?run|attestation", name, re.I)
            for name in list(inputs) + list(step_env)),
        "no_run_key_argument": not re.search(r"--run-key|--recorded-at-run|--attestation", run),
        # THE CAPS ARE CONSTANTS, AND THE WORKFLOW OVERRIDES NEITHER — which is what makes
        # DEFAULT_MAX_MINTS the LIVE bound on ledger writes per tick rather than a default nobody
        # reaches. Round 7: raising the constant from 3 to 50 left the whole suite green, because
        # only the cap MECHANISM was pinned and never its value. Both halves are asserted now: the
        # value, and the absence of any path that could supply another one.
        "no_cap_argument": not re.search(r"--max-mints|--max-comments", run),
        "no_cap_input": not any(re.search(r"max.?mints|max.?comments", name, re.I)
                                for name in inputs),
        # EVERY env name the step declares, not a chosen subset: ADDING a binding is as red as
        # rebinding one, so a new secret or input cannot be handed to this job unnoticed.
        "step_env_bindings": step_env,
    }


# ---- THE RENDERED ORACLE: GitHub's own verdicts, frozen ---------------------------------------
# The repository whose issue numbering the oracle was captured against, and the REAL open issue it
# uses. Both matter: `POST /markdown` only emits an `issue-link` anchor for a reference that
# RESOLVES, so a corpus keyed on a number that does not exist reads as "GitHub rendered it as code"
# for EVERY row — an instrument artefact that a previous reviewer caught in their own harness before
# it produced a wrong conclusion. #929 is this change's own tracking issue and is open.
ORACLE_CONTEXT_REPO = "jeswr/agent-account-registry"
ORACLE_ISSUE = 929
RENDERED_ORACLE_PATH = SCRIPTS_DIR / "fixtures" / "auto-mint-provenance" / "rendered-oracle.json"

# (label, title, body, expect_bind)
#
# WHAT `expect_bind` IS AND IS NOT. It is what THIS FILE must do, decided by hand from the design
# rules and NOT read off the implementation. It is checked against a second, independent column the
# corpus does not author: `github_linkified`, recorded from the live renderer, true exactly when
# GitHub resolved the reference into an `issue-link` anchor. The suite then asserts the SAFETY
# DIRECTION over the whole table — `expect_bind` implies `github_linkified` — so a row can never be
# "corrected" into binding something GitHub renders as code without that assertion going red.
#
# One row's hand-written expectation WAS wrong when the corpus was first measured (`alert block`:
# `> [!NOTE]` renders as a `markdown-alert` div, not a blockquote, so GitHub resolves it and so does
# this file). It is recorded here because a corpus whose expectations never disagree with the
# implementation is a corpus that was read off the implementation.
RENDERED_ORACLE_CORPUS = (
    ('plain closes line', 'fix: thing', 'Closes #929.', True),
    ('title declaration', 'Closes #929 - thing', '', True),
    ('closes with colon', 't', 'Closes: #929', True),
    ('uppercase', 't', 'CLOSES #929', True),
    ('inside a list item', 't', '- Closes #929', True),
    ('inside a heading', 't', '## Closes #929', True),
    ('inside a table cell', 't', '| a |\n|---|\n| Closes #929 |', True),
    ('bold emphasis around the keyword', 't', '**Closes** #929', False),
    ('declaration beside a fenced block', 't', '```\nx\n```\n\nCloses #929', True),
    ('declaration beside a quoted block', 't', '> quoted stuff\n\nCloses #929', True),
    ('inside <details> body', 't', '<details>\n<summary>s</summary>\n\nCloses #929\n\n</details>', True),
    ('task list item', 't', '- [x] Closes #929', True),
    ('paragraph continuation (indented, prose)', 't', 'some prose that wraps\n    Closes #929', True),
    ('R1 <pre> block', 't', '<pre>\nCloses #929\n</pre>', False),
    ('R2 <pre> then indented', 't', '<pre>x</pre>\n    Closes #929', False),
    ('R3 quoted <pre> then indented', 't', '> <pre>\n> x\n> </pre>\n    Closes #929', False),
    ('R4 pipe-less GFM table then indented', 't', 'a | b\n--- | ---\nc | d\n    Closes #929', False),
    ('R5 inline HTML <code>', 't', 'Use <code>Closes #929</code> in the body', False),
    ('R6 <details> wrapping <pre>', 't', '<details><pre>Closes #929</pre></details>', False),
    ('R7 <pre class=...>', 't', '<pre class="highlight">Closes #929</pre>', False),
    ('fenced block', 't', '```\nCloses #929\n```', False),
    ('~~~ fence', 't', '~~~\nCloses #929\n~~~', False),
    ('unclosed fence', 't', '```\nCloses #929', False),
    ('inline code span', 't', 'write a `Closes #929` line', False),
    ('multi-backtick span', 't', 'write ``Closes #929`` here', False),
    ('blockquote', 't', 'their body reads:\n\n> Closes #929', False),
    ('html comment', 't', '<!-- template: Closes #929 -->', False),
    ('multi-line html comment', 't', '<!--\nCloses #929\n-->', False),
    ('unclosed html comment', 't', '<!-- draft\nCloses #929', False),
    ('4-space indented code', 't', 'prose\n\n    Closes #929', False),
    ('tab indented code', 't', 'prose\n\n\tCloses #929', False),
    ('ATX heading then indented', 't', '## Evidence\n    Closes #929', False),
    ('setext heading then indented', 't', 'Evidence\n========\n    Closes #929', False),
    ('*** break then indented', 't', 'prose\n\n***\n    Closes #929', False),
    ('--- underline then indented', 't', 'Evidence\n---\n    Closes #929', False),
    ('___ break then indented', 't', 'prose\n\n___\n    Closes #929', False),
    ('closed html comment then indented', 't', '<!-- c -->\n    Closes #929', False),
    ('closed fence then indented', 't', '```\nx\n```\n    Closes #929', False),
    ('~~~ fence then indented', 't', '~~~\nx\n~~~\n    Closes #929', False),
    ('GFM table then indented', 't', '| a | b |\n|---|---|\n| c | d |\n    Closes #929', False),
    ('quoted ATX heading then indented', 't', '> ## Evidence\n    Closes #929', False),
    ('quoted setext then indented', 't', '> Evidence\n> ========\n    Closes #929', False),
    ('quoted *** then indented', 't', '> ***\n    Closes #929', False),
    ('quoted fence then indented', 't', '> ```\n> x\n> ```\n    Closes #929', False),
    ('quoted table then indented', 't', '> | a | b |\n> |---|---|\n    Closes #929', False),
    ('quoted blank then indented', 't', '> quoted\n>\n    Closes #929', False),
    ('nested quote holding a heading', 't', '> > ## Evidence\n    Closes #929', False),
    ('nested quote holding a fence', 't', '> > ```\n> > x\n> > ```\n    Closes #929', False),
    ('quote marker with no space', 't', '>## Evidence\n    Closes #929', False),
    ('quoted lazy continuation', 't', '> quoted\n    Closes #929', False),
    ('blockquote lazy paragraph', 't', '> quoted para\n    Closes #929', False),
    ('indented FIRST body line', 'fix: thing', '    Closes #929', False),
    ('live #781 self-id banner', 't', '> 🤖 **SPARQ agent** - AUTHOR ONLY; no `VERDICT:` line. Closes #929.', False),
    ('inline html comment in a quoted line', 't', '> 🤖 agent <!-- marker --> Closes #929.', False),
    ('bullet item continuation', 't', '- item\n\n    Closes #929', True),
    ('numbered item continuation', 't', '1. item\n\n    Closes #929', True),
    ('code span between keyword and number', 't', 'Fixes `mod` #929', False),
    ('spliced with no spaces', 't', 'Closes`x`#929', False),
    ('span inside the keyword', 't', 'clo`x`ses #929', False),
    ('negator across a code span', 't', 'this PR does not `x` close #929', False),
    ('negated prose', 't', 'this PR does NOT close #929', False),
    ('negator in the previous sentence', 't', 'This is not a revert. Closes #929', True),
    ('markdown link text', 't', 'Closes [#929](https://x)', False),
    ('issue URL form', 't', 'Closes https://github.com/jeswr/agent-account-registry/issues/929', False),
    ('GH- form', 't', 'Closes GH-929', False),
    ('html anchor around the keyword', 't', "<a href='https://x'>Closes #929</a>", False),
    ('img alt text', 't', "<img alt='Closes #929' src='x.png'>", False),
    ('emphasis inside the keyword', 't', 'Clos**es** #929', False),
    ('numeric entity for the hash', 't', 'Closes &#35;929', False),
    ('cross-repo reference', 't', 'Fixes sparq-org/sparq#4329', False),
    ('bare mention', 't', 'see #929, related work', False),
    ('Refs is not a closing keyword', 't', 'Refs #929', False),
    ('keyword inside another word', 't', 'unfixed #929', False),
    ('conventional-commit scope', 'fix(#929): thing', '', False),
    ('keyword not adjacent', 't', 'Closes the composition defect in #929', False),
    ('kbd', 't', '<kbd>Closes #929</kbd>', False),
    ('samp', 't', '<samp>Closes #929</samp>', False),
    ('alert block', 't', '> [!NOTE]\n> Closes #929', True),
    ('footnote definition', 't', 'x[^1]\n\n[^1]: Closes #929\n', True),
    ('strikethrough', 't', '~~Closes #929~~', True),
    ('math block', 't', '$$ Closes #929 $$', True),
    ('nested code in anchor', 't', "<a href='x'><code>Closes #929</code></a>", False),
    ('suggestion fence', 't', '```suggestion\nCloses #929\n```', False),
    ('blockquote holding a fence', 't', '> ```\n> Closes #929\n> ```', False),
    ('html <p> passthrough', 't', '<p>Closes #929</p>', True),
    ('html <div> passthrough', 't', '<div>Closes #929</div>', True),
    ('html <blockquote> passthrough', 't', '<blockquote>Closes #929</blockquote>', False),
    ('definition list', 't', '<dl><dt>Closes #929</dt><dd>x</dd></dl>', True),
    ('summary text', 't', '<details><summary>Closes #929</summary>x</details>', True),
    ('ruby annotation', 't', '<ruby>Closes #929<rt>x</rt></ruby>', True),
    ('mark + q + sup', 't', '<mark>Closes #929</mark>', True),
    ('picture element', 't', "<picture><source srcset='a.png'><img src='a.png' alt='Closes #929'></picture>", False),
    # ---- THE `#N` RIGHT AND LEFT BOUNDARY ----------------------------------------------------
    # ROUND 7's BLOCKING CLASS, and the gap that let it through: the 92-row corpus had NO row on
    # the boundary of the number itself, so `SAFETY` was green while blind to the class that fails
    # it. `CLOSING_REF_RE` terminates the number with `(?![0-9])`; GitHub terminates it with a WORD
    # boundary. Every row below was rendered by the live renderer and its anchor recorded, so which
    # side each falls on is GitHub's answer, not a guess — and the ones GitHub DOES resolve are
    # here too, because a corpus of only-refusals would be satisfied by refusing everything.
    ('right boundary: letter run-on', 't', 'Closes #929abc', False),
    ('right boundary: underscore run-on', 't', 'Closes #929_x', False),
    ('right boundary: non-ASCII letter run-on', 't', 'Closes #929\u00e9', False),
    ('right boundary: hyphen', 't', 'Closes #929-x', True),
    ('right boundary: apostrophe-s', 't', "Closes #929's", True),
    ('right boundary: full stop', 't', 'Closes #929. Done', True),
    ('right boundary: comma', 't', 'Closes #929, and more', True),
    ('right boundary: closing paren', 't', 'Closes #929)', True),
    ('right boundary: semicolon', 't', 'Closes #929;', True),
    ('right boundary: slash', 't', 'Closes #929/', True),
    ('leading zeros are not a canonical reference', 't', 'Closes #0929', False),
    ('a number that does not exist is not a reference', 't', 'Closes #99999999', False),
    ('an unresolved run-on beside a real declaration still binds the real one', 't',
     'Closes #929abc and closes #929', True),
    # WHERE THE ANCHOR IS COLLECTED FROM, and why it is only from PROSE. A blockquote QUOTING a
    # reference carries a real `issue-link` anchor, so collecting anchors regardless of quote depth
    # would let quoted text SATISFY the third conjunct for a run-on the author wrote in their own
    # prose — a spurious mint out of two halves neither of which is a declaration. MEASURED on this
    # exact body: `anchored` is empty as shipped and `[929]` with the quote-depth guard removed.
    ('a quoted anchor cannot resolve a run-on written in prose', 't',
     'Closes #929abc\n\n> quoting an old comment that says #929\n', False),
    # ---- SPANS, NOT SETS: round 8's blocking class ---------------------------------------------
    # THE ONE-CHARACTER PAIR. These two rows differ by a single `> `, and at the previous head they
    # differed in OUTCOME: the quoted one refused and the unquoted one MINTED, because the conjunct
    # asked "is #929 resolved somewhere in this pull request" instead of "is THIS occurrence the one
    # GitHub resolved". Kept adjacent, because a regression in either direction shows up as the pair
    # disagreeing.
    ('an UNQUOTED unrelated mention cannot resolve a run-on either', 't',
     'Closes #929abc\n\nquoting an old comment that says #929\n', False),
    ('...nor a mention in a table cell', 't',
     'Closes #929_x\n\n| a |\n|---|\n| #929 |\n', False),
    ('...nor a mention in the TITLE resolving a run-on in the body',
     'thing (#929)', 'Closes #929abc', False),
    ('...nor a run-on in the TITLE resolved by a mention in the body',
     'Closes #929abc', 'see #929 for background', False),
    # ...and the CONTROLS. A conjunct that refused every run-on-adjacent body would satisfy all four
    # rows above, so the same shapes with a REAL declaration beside the run-on must still bind.
    ('a real declaration beside a run-on still binds', 't',
     'Closes #929abc\n\nand separately, closes #929\n', True),
    ('...and a real declaration in the TITLE beside a run-on in the body',
     'Closes #929 - thing', 'also mentions #929abc somewhere', True),
    # ---- THE TWO SHAPES A REVIEW DISAGREEMENT TURNED UP ------------------------------------------
    # Round 8 closed with the reviewer and me reporting opposite outcomes for "a quoted declaration
    # beside a run-on". Both measurements were right; we were running different bodies, and these are
    # the two that separate them. They are here because that is the only way the question stops
    # being re-litigated from memory.
    #
    # A genuinely QUOTED declaration beside a run-on refuses — but add ONE unquoted mention and the
    # set-membership conjunct bound it. That is round 8's class in a third shape, and it is the body
    # the disagreement was actually about.
    ('a quoted declaration and a run-on and an unquoted mention', 't',
     '> Closes #929\n\nand a run-on Closes #929abc, see #929\n', False),
    # ...and the shape where "I quoted it" is the WRONG intuition. `> [!NOTE]` looks like a
    # blockquote to the author who typed it and is a `<div class="markdown-alert">` to GitHub, so the
    # declaration inside it is LIVE PROSE, GitHub resolves it, and it BINDS — correctly, and both
    # before and after the span fix. A control, not a defect: it is the row that stops the alert
    # policy being "fixed" into a refusal by someone reading `>` as quotation.
    ('an ALERT declaration is live prose even beside a run-on', 't',
     '> [!NOTE]\n> Closes #929\n\nand a run-on Closes #929abc\n', True),
)


def _rendered_oracle():
    """The frozen renderings, or a loud failure. Never falls back to rendering live in a test."""
    with open(RENDERED_ORACLE_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def _frozen_renderer(oracle):
    """A `render_markdown` bound to the frozen corpus.

    A DOCUMENT WITH NO FROZEN RENDER RAISES `SweepError`, deliberately NOT `RenderUnavailable`: a
    missing fixture must red a NAMED check, never quietly satisfy a refusal assertion. That is the
    difference between "this shape refuses because the derivation understood it and said no" and
    "this shape refuses because the harness had nothing to give it"."""
    documents = oracle["documents"]

    def render(text):
        if text not in documents:
            raise SweepError(f"no frozen render for {text!r}; run --refresh-rendered-oracle")
        return documents[text]

    return render


# THE TOOL'S OWN OUTPUT, fed back in. `REASON_HINTS` is posted onto up to DEFAULT_MAX_COMMENTS
# pull requests per tick, and the likeliest author response is to quote the comment into the PR
# description — which minted a record bound to the number in the tool's own worked example once
# already. So every rendered refusal comment is a corpus document too, carrying a deliberately
# HOSTILE passthrough message, and --self-test asserts the whole artefact derives NOTHING.
#
# The comments are GENERATED, not typed, so they cannot go stale silently: change the wording and
# the frozen render no longer covers the text, `_frozen_renderer` raises `SweepError`, and the
# named check goes red rather than quietly passing on the old artefact.
# The numbers here must be REAL objects in ORACLE_CONTEXT_REPO. Since round 7 the derivation
# requires GitHub's own `issue-link` anchor, and GitHub emits none for a number that does not
# exist — so a payload built from invented numbers would be inert for a reason that has nothing to
# do with the quoting this control exists to test, i.e. vacuous. #929 and #657 are open issues,
# #916 is a merged pull request; all three linkify.
ORACLE_HOSTILE_PASSTHROUGH = "Closes #929 and fixes #916 -- resolves #657"


def _oracle_own_output_documents():
    """Every document the corpus derives from this file's OWN generated text."""
    documents = [refusal_comment_body(reason, ORACLE_HOSTILE_PASSTHROUGH)
                 for reason in PR_REFUSAL_REASONS]
    # ...and the hints with their code spans DEFEATED. Feeding the hints in verbatim would be inert
    # for the WRONG reason (every placeholder sits in a code span), so the backticks come off.
    documents.append("\n".join(REASON_HINTS.values()).replace("`", ""))
    documents.append(ORACLE_HOSTILE_PASSTHROUGH)
    return documents


def hand_written_residue_claims(doc):
    """The hand-written residue claims in `doc` — a COUNT of rows, or a corpus row restated by name.

    A NAMED PREDICATE, not an inline expression, because a guard that has never fired on a known
    positive cannot be told apart from one that cannot fire. --self-test runs it on a string that
    DOES contain both shapes before trusting it on the real docstring. That is not hypothetical: the
    inline version of this guard SURVIVED a mutant that disabled it, because the docstring it
    pointed at was already clean."""
    counts = [match.group(0) for match in re.finditer(r"\b\d+ (?:corpus )?rows?\b", doc or "")]
    labels = [label for label, _t, _b, _e in RENDERED_ORACLE_CORPUS
              if len(label) > 15 and label in (doc or "")]
    return sorted(counts) + sorted(labels)


def corpus_directions(oracle, render):
    """DERIVE, do not assert: each corpus row's actual direction, computed from the live-rendered
    oracle and this file's real derivation.

    WHY THIS FUNCTION EXISTS AT ALL. The `HONEST LIMITS` paragraph was hand-written and was FALSE
    for five consecutive rounds, always in the permissive direction. That stopped being a fact about
    any single defect and became a fact about hand-written claims. So the residue is no longer
    stated anywhere a human types: it is computed here, frozen into the fixture by
    `--refresh-rendered-oracle`, and --self-test re-derives it and compares. A divergence can then
    no longer be CLAIMED wrongly — only MEASURED wrongly, which the oracle work already guards.

    Three directions, and only one of them is a defect:

      `agree`          GitHub resolved it and this file binds, or neither does;
      `missed-mint`    GitHub emitted an anchor for the row's issue and this file refuses — the
                       recoverable direction, and the only one the residue is allowed to contain;
      `SPURIOUS-MINT`  this file binds and GitHub emitted no anchor at all. Silent, permanent, and a
                       grant of review admission. Must always be empty.
    """
    directions = {"agree": [], "missed-mint": [], "SPURIOUS-MINT": []}
    for label, title, body, _expect in RENDERED_ORACLE_CORPUS:
        try:
            binds = closing_issue_candidates(title, body, render, ORACLE_CONTEXT_REPO) == [
                ORACLE_ISSUE]
        except Exception:                             # noqa: BLE001 — a raise is a refusal
            binds = False
        linkified = bool(oracle["github_linkified"].get(label))
        if binds and not linkified:
            directions["SPURIOUS-MINT"].append(label)
        elif linkified and not binds:
            directions["missed-mint"].append(label)
        else:
            directions["agree"].append(label)
    return {key: sorted(value) for key, value in directions.items()}


def _refresh_rendered_oracle(render):
    """Re-render every corpus document against the LIVE GitHub renderer and rewrite the fixture.

    The corpus rows live in ONE place (above) and this derives the frozen artefact from them, so a
    row can never disagree with its own fixture. `github_linkified` is recorded here, from GitHub's
    output, and is never editable by hand in the checked-in file without the safety assertion in
    --self-test catching a row that binds without it."""
    anchor = re.compile(r'class="issue-link[^"]*"[^>]*/issues/%d"' % ORACLE_ISSUE)
    documents, linkified = {}, {}
    for label, title, body, _expect in RENDERED_ORACLE_CORPUS:
        seen_link = False
        for document in (title, body):
            if not (document or "").strip():
                continue
            if document not in documents:
                documents[document] = render(document)
            seen_link = seen_link or bool(anchor.search(documents[document]))
        linkified[label] = seen_link
    for document in _oracle_own_output_documents():
        if document not in documents:
            documents[document] = render(document)
    RENDERED_ORACLE_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "_comment": "Frozen `POST /markdown` (mode=gfm) output. Regenerate with "
                    "`auto-mint-provenance.py --refresh-rendered-oracle`; never hand-edit.",
        "context": ORACLE_CONTEXT_REPO,
        "issue": ORACLE_ISSUE,
        "documents": documents,
        "github_linkified": linkified,
    }
    # ...and the residue, DERIVED from the two columns above rather than written by anyone. This is
    # the artefact that replaced five rounds of a hand-written `HONEST LIMITS` paragraph.
    payload["directions"] = corpus_directions(
        payload, _frozen_renderer(payload))
    payload["directions"]["_comment"] = (
        "GENERATED by corpus_directions(). Never hand-edit: --self-test re-derives this and "
        "compares, so an edit here is a red check, and a behaviour change shows up as a diff in "
        "review rather than as a sentence somebody has to remember to update.")
    with open(RENDERED_ORACLE_PATH, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=1, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    return len(documents)


# ---- self-test ---------------------------------------------------------------------------------
def _self_test():                                                       # noqa: C901 - flat asserts
    import base64
    import inspect
    import copy
    import shutil
    import tempfile

    ok = True

    def check(name, got, want):
        nonlocal ok
        if got != want:
            ok = False
            print(f"FAIL {name}: got {got!r}, want {want!r}")
        else:
            print(f"ok   {name}")

    def total(thunk):
        """Call `thunk`, turning any exception into a comparable value. The derivation and every
        refusal predicate is documented TOTAL — "never raises, never guesses" — so a raise is a
        defect that must red a NAMED check here rather than abort the whole suite with a
        traceback that belongs to no branch."""
        try:
            return thunk()
        except Exception as exc:                      # noqa: BLE001 — a raise IS the failure
            return ("RAISED", type(exc).__name__)

    def refuses(name, reason, thunk):
        got = total(thunk)
        check(name, got[0] if isinstance(got, tuple) else got, reason)

    mint_provenance = _load_mint_provenance()

    # ---- THE SWEEP IS WIRED TO THE THIRD LAST MILE (mint_provenance.review_run_refusal) --------
    # [registry #1288] review-fix.yml's `run` job now ADMITS the self-attested class — into a job
    # that holds no target App token, which is what replaced the App-author check — so the shared
    # writer no longer refuses it and this sweep mints again.
    #
    # Both directions are asserted UNPATCHED and through the sweep's OWN composition, because the
    # thing being proved is the wiring, not the answer: a sweep that stopped consulting the run
    # gate would satisfy the live row alone. Only then is the refusal stood down for the rest of
    # the suite, where every row is about some OTHER predicate and would otherwise pass for this
    # reason and stop testing what it names.
    _amp_claim = mint_provenance._load_dispatch_claim()
    _live_run_refusal = mint_provenance.review_run_refusal(
        _amp_claim.review_fix_identity_admits_orchestrator_class,
        shell_admits=_amp_claim.worker_live_admits_orchestrator_class)
    check("the shared writer ADMITS the class on the live identity gate",
          _live_run_refusal, None)
    _refused_run_refusal = mint_provenance.review_run_refusal(
        lambda: False, shell_admits=lambda: True)
    check("...and still refuses it when the identity gate does, naming that gate",
          isinstance(_refused_run_refusal, str)
          and "target-App identity gate" in _refused_run_refusal, True)
    # [registry #1288] ...and when the FOURTH consumer refuses while the identity gate admits. The
    # sweep must carry every conjunct, not the one that happened to be live when it was written.
    _refused_by_shell = mint_provenance.review_run_refusal(
        lambda: True, shell_admits=lambda: False)
    check("...and refuses when worker-live.sh's own head-ref gate would refuse the head branch",
          isinstance(_refused_by_shell, str) and "worker-live.sh" in _refused_by_shell, True)
    mint_provenance.review_run_refusal = lambda _probe, **_kw: None

    # ---- THE RENDERED ORACLE, AND THE INSTRUMENT THAT MEASURES IT -----------------------------
    # ROUND 6 REDESIGN. Rounds 3-5 stripped quoted markdown constructs from the SOURCE and were
    # found permissive three times running, always in the minting direction, because the strip was
    # an enumeration over an open grammar whose unknown case fell OPEN. The derivation now runs over
    # GitHub's OWN RENDERING and refuses anything it does not positively classify. These rows are
    # the measurement of that, against frozen output from the live `POST /markdown`.
    oracle = total(_rendered_oracle)
    check("the frozen rendered oracle loads", isinstance(oracle, dict), True)
    oracle = oracle if isinstance(oracle, dict) else {"documents": {}, "github_linkified": {}}
    frozen = _frozen_renderer(oracle)

    def prose_text_of(html, repo="o/r"):
        """`rendered_prose(...).text`, so an extractor row reads as the one thing it asserts."""
        return rendered_prose(html, repo).text


    def cand(title, body, render=None):
        """`closing_issue_candidates` through the FROZEN renderer, total-ised."""
        return total(lambda: closing_issue_candidates(title, body, render or frozen,
                                                      ORACLE_CONTEXT_REPO))

    def anchored_html(text, repo):
        """A FAITHFUL stand-in for GitHub's rendering of one prose line.

        Faithful matters here, and it is not decoration: GitHub rewrites every `#N` it RESOLVES into
        an `issue-link` anchor, and `closing_references` now requires that anchor as its third
        conjunct. A hand-written `<p>{text}</p>` would carry no anchors, so every fixture using it
        would refuse — passing the "this refuses" rows for a reason that has nothing to do with what
        they test, and reddening every "this binds" row. Round 7's own first run did exactly that,
        which is how this helper came to exist."""
        return "<p>" + MENTION_RE.sub(
            lambda match: (f'<a class="issue-link js-issue-link" href="https://github.com/{repo}'
                           f'/issues/{match.group(1)}">#{match.group(1)}</a>'),
            text) + "</p>"

    # THE INSTRUMENT IS VALIDATED BEFORE ANYTHING IS MEASURED WITH IT. A corpus keyed on an issue
    # number that does not exist reads as "GitHub rendered it as code" for every single row, because
    # GitHub only emits an `issue-link` anchor for a reference it RESOLVES — a real artefact, caught
    # in a reviewer's own harness before it produced a wrong conclusion. A known POSITIVE and a
    # known NEGATIVE are therefore asserted first: if these two are not opposite, every oracle row
    # below is meaningless and says so by name.
    check("INSTRUMENT — the known POSITIVE resolves: GitHub linkifies a plain closing line",
          oracle["github_linkified"].get("plain closes line"), True)
    check("INSTRUMENT — the known NEGATIVE does not: GitHub renders a fenced keyword as code",
          oracle["github_linkified"].get("fenced block"), False)
    check("INSTRUMENT — every corpus document has a frozen render, so no row can refuse merely "
          "because the harness had nothing to give it",
          sorted({document for _l, title, body, _e in RENDERED_ORACLE_CORPUS
                  for document in (title, body)
                  if (document or "").strip() and document not in oracle["documents"]}), [])
    check("...and the fixture was captured against THIS repository's numbering",
          (oracle.get("context"), oracle.get("issue")), (ORACLE_CONTEXT_REPO, ORACLE_ISSUE))
    check("...and the corpus labels are distinct, so no row silently shadows another",
          len({row[0] for row in RENDERED_ORACLE_CORPUS}), len(RENDERED_ORACLE_CORPUS))
    # HARNESS INTEGRITY, asserted rather than assumed. A frozen renderer that answered "" for a
    # document it does not have would make every "this shape refuses" row below pass for the WRONG
    # reason — the derivation would be reading an empty document, not understanding the shape and
    # declining. It must RAISE, and the raise must not be `RenderUnavailable`, which the production
    # path would swallow into a refusal.
    missing = total(lambda: frozen("a document that is deliberately not in the fixture"))
    check("HARNESS — a document with no frozen render RAISES rather than answering empty",
          missing, ("RAISED", "SweepError"))

    oracle_binds = {}
    for label, title, body, expect_bind in RENDERED_ORACLE_CORPUS:
        oracle_binds[label] = cand(title, body) == [ORACLE_ISSUE]
        check(f"ORACLE — {label}: "
              + ("BINDS" if expect_bind else "REFUSES"), oracle_binds[label], expect_bind)

    # ---- THE RESIDUE IS DERIVED, NOT ASSERTED ---------------------------------------------------
    # WHY THIS BLOCK LOOKS LIKE THIS. The `HONEST LIMITS` paragraph and the residue list used to be
    # hand-written, and they were FALSE for FIVE consecutive rounds, always in the permissive
    # direction. That is not a fact about any one defect; it is a fact about hand-written claims. So
    # nothing here states the residue. `corpus_directions()` computes it from GitHub's own column
    # and this file's real derivation; `--refresh-rendered-oracle` freezes it into the fixture; and
    # these rows RE-DERIVE it and compare. A divergence can no longer be CLAIMED wrongly — only
    # MEASURED wrongly, which the oracle validation above already guards.
    directions = total(lambda: corpus_directions(oracle, frozen))
    directions = directions if isinstance(directions, dict) else {
        "agree": [], "missed-mint": [], "SPURIOUS-MINT": [("RAISED", directions)]}
    # THE ONE CLAIM THAT IS A CLAIM, and it is GitHub's, not this file's: nothing binds that GitHub
    # declined to resolve. Asserted as the LIST, so a failure names the shape.
    # THE DETECTOR IS VALIDATED BEFORE IT IS TRUSTED. `SPURIOUS-MINT == []` is the headline claim of
    # this whole file, and a detector that has never produced a non-empty answer is worth nothing —
    # MEASURED: deleting the branch that records the direction SURVIVED a green suite, because on a
    # correct corpus the list is empty either way. So it is first run against a corpus whose oracle
    # column has been forced to "GitHub resolved NOTHING", where every binding row must be reported.
    blind_oracle = dict(oracle, github_linkified={label: False
                                                  for label in oracle["github_linkified"]})
    blind = total(lambda: corpus_directions(blind_oracle, frozen))
    check("INSTRUMENT — the spurious-mint detector really fires: against an oracle that resolved "
          "NOTHING, every binding row is reported",
          len(blind["SPURIOUS-MINT"]) if isinstance(blind, dict) else blind,
          sum(1 for _l, _t, _b, expect in RENDERED_ORACLE_CORPUS if expect))
    check("...and reports nothing as agreeing-and-bound in that world",
          [label for label in (blind["missed-mint"] if isinstance(blind, dict) else [])], [])
    check("SAFETY — no shape binds a reference GitHub emitted no anchor for",
          directions["SPURIOUS-MINT"], [])
    # ...and the residue, compared against the GENERATED artefact. Both sides are machine-produced:
    # one now, one at the last refresh. A behaviour change is a diff in review, not a sentence
    # somebody has to remember to update.
    stored = (oracle.get("directions") or {})
    check("the DERIVED residue still matches the generated artefact — regenerate with "
          "--refresh-rendered-oracle and read the diff if this reds",
          directions["missed-mint"], stored.get("missed-mint"))
    check("...and so does the agreeing set, so a row cannot move between them unobserved",
          directions["agree"], stored.get("agree"))
    check("...and the artefact records no spurious mint either", stored.get("SPURIOUS-MINT"), [])
    # A ROW THAT RAISES IS A REFUSAL, NOT A BIND. `corpus_directions` swallows the raise, and which
    # way it resolves it decides whether an unclassifiable body would be reported as agreeing. Fed a
    # renderer that raises for everything, no row may be counted as binding.
    exploding = total(lambda: corpus_directions(
        oracle, lambda _text: (_ for _ in ()).throw(RenderUnavailable("down"))))
    check("...and a row whose render RAISES is counted as a refusal, never as a bind",
          (exploding["SPURIOUS-MINT"], len(exploding["agree"]) > 0)
          if isinstance(exploding, dict) else exploding, ([], True))
    # NON-VACUITY, in both directions, so the comparison above is over a table that says something.
    check("...over a corpus that really holds rows GitHub renders as CODE",
          sum(1 for label in oracle["github_linkified"]
              if not oracle["github_linkified"][label]) > 20, True)
    check("...and rows it RESOLVES that this file also binds",
          sum(1 for label, title, body, expect in RENDERED_ORACLE_CORPUS
              if expect and oracle["github_linkified"].get(label)) > 20, True)
    # AND THE DOCSTRING MAY NOT RESTATE ANY OF IT. If a sentence cannot be produced mechanically
    # from the corpus, it does not belong in prose that a reader will trust. These two rows are the
    # mechanical enforcement of that, aimed at exactly the two things that went wrong five times: a
    # hand-written COUNT, and a hand-written LIST of shapes.
    # THE GUARD IS VALIDATED ON A KNOWN POSITIVE FIRST. A guard that has never fired cannot be told
    # apart from one that cannot fire — MEASURED: the inline version of this check SURVIVED a mutant
    # that disabled it, because the docstring it pointed at was already clean, so the row was
    # vacuous. My own control, and it was the failure it exists to catch.
    planted = ("...and there are 24 rows where GitHub resolves it, including "
               + next(label for label, _t, _b, _e in RENDERED_ORACLE_CORPUS if len(label) > 15))
    check("INSTRUMENT — the hand-written-claim guard fires on a planted COUNT and a planted LABEL",
          len(hand_written_residue_claims(planted)), 2)
    check("...and stays silent on prose that states neither",
          hand_written_residue_claims("This paragraph states no counts and names no shapes."), [])
    check("the HONEST LIMITS docstring makes no hand-written residue claim",
          hand_written_residue_claims(rendered_prose.__doc__), [])

    # ---- THE SEVEN SHAPES THAT MINTED AT THE PREVIOUS HEAD ------------------------------------
    # Each was driven end to end into the real `mint_provenance.mint()` by an independent review and
    # produced `minted=1 ledger_writes=['LEDGER-PUT'] refused=0`. They are named here so a
    # regression cannot be a nameless row in a big table.
    for label in ("R1 <pre> block", "R2 <pre> then indented", "R3 quoted <pre> then indented",
                  "R4 pipe-less GFM table then indented", "R5 inline HTML <code>",
                  "R6 <details> wrapping <pre>", "R7 <pre class=...>"):
        check(f"ROUND-5 REGRESSION — {label} no longer binds", oracle_binds.get(label), False)

    # ---- THE UNKNOWN CASE: what happens to a shape nobody enumerated --------------------------
    # This is the criterion that separates a REDESIGN from a fourth patch round, so it is asserted
    # on the MECHANISM and not on a fixture: hand-written HTML holding an element that appears in no
    # classification set, in no test above, and in no corpus row.
    for label, html in (
            ("a custom element nobody classified", "<p>Closes <weird-thing>#7</weird-thing></p>"),
            ("...as the outermost element", "<x-frame>Closes #7</x-frame>"),
            ("...nested inside prose", "<div><p>Closes <q><novel>#7</novel></q></p></div>"),
            ("...a future GitHub wrapper around a table",
             "<markdown-future-table><table><tr><td>Closes #7</td></tr></table>"
             "</markdown-future-table>"),
            ("...an end tag that closes nothing", "<p>Closes #7</p></section>")):
        got = total(lambda h=html: prose_text_of(h))
        check(f"UNKNOWN CASE — {label} raises rather than being read as prose",
              got[0] if isinstance(got, tuple) else "NO RAISE — TEXT WAS READ",
              "RAISED")
    unknown_tag = None
    try:
        prose_text_of("<p>Closes <weird-thing>#7</weird-thing></p>")
    except UnknownRenderedElement as exc:
        unknown_tag = exc.tag
    check("...and the raise NAMES the element, so an operator can classify it deliberately "
          "instead of discovering it in a census count", unknown_tag, "weird-thing")
    # ...and the unknown case reaches the DERIVATION as a named refusal, not as a crash and not as
    # a mint. `derive_issue_number` is documented TOTAL, so this is asserted rather than assumed.
    unknown_render = lambda _text: "<p>Closes <weird-thing>#7</weird-thing></p>"     # noqa: E731
    check("UNKNOWN CASE — the derivation refuses it by name",
          total(lambda: derive_issue_number({"title": "t", "body": "Closes #7"},
                                            lambda n: None, unknown_render, "o/r").reason),
          REASON_BODY_NOT_UNDERSTOOD)
    check("...and derives NO number",
          total(lambda: derive_issue_number({"title": "t", "body": "Closes #7"},
                                            lambda n: None, unknown_render, "o/r").number), None)
    # THE CONTROL for the two rows above: the SAME body, the SAME derivation, with the element
    # classified — it binds. Without this, "the unknown case refuses" is satisfied by a derivation
    # that refuses everything.
    known_render = lambda _text: anchored_html("Closes #7", "o/r")                   # noqa: E731
    open_issue_7 = {"number": 7, "state": "open", "labels": [{"name": "area:ci"}]}
    check("...while the same body through a render this file DOES understand binds",
          total(lambda: derive_issue_number({"title": "", "body": "Closes #7"},
                                            lambda n: open_issue_7, known_render, "o/r").number),
          7)

    # ---- THE RENDERER ITSELF FAILING: fail closed, never fall back -----------------------------
    def exploding_render(_text):
        raise RenderUnavailable("GitHub's markdown renderer returned 22 for a 40-character document")

    check("RENDERER OUTAGE — an unreachable renderer refuses by name",
          total(lambda: derive_issue_number({"title": "t", "body": "Closes #7"},
                                            lambda n: open_issue_7, exploding_render,
                                            "o/r").reason),
          REASON_RENDER_UNAVAILABLE)
    check("...and derives NOTHING — there is no raw-markdown fallback",
          total(lambda: derive_issue_number({"title": "t", "body": "Closes #7"},
                                            lambda n: open_issue_7, exploding_render,
                                            "o/r").number),
          None)
    check("...and it is censused rather than commented, because it is a fact about the PLATFORM "
          "and the dedupe would make a transient outage permanent on someone else's PR",
          REASON_RENDER_UNAVAILABLE in SILENT_REASONS, True)
    check("...while a body this run cannot classify IS commented, because its author can act on it",
          REASON_BODY_NOT_UNDERSTOOD in SILENT_REASONS, False)

    # ---- THE PROSE EXTRACTOR, element class by element class -----------------------------------
    check("prose text is kept", prose_text_of("<p>Closes #7</p>").strip(), "Closes #7")
    check("a <pre> subtree contributes NO text",
          "#7" in prose_text_of("<pre>Closes #7</pre>"), False)
    check("...a <code> span contributes none either",
          "#7" in prose_text_of("<p>a <code>Closes #7</code> b</p>"), False)
    check("...nor a <blockquote>",
          "#7" in prose_text_of("<blockquote><p>Closes #7</p></blockquote>"), False)
    check("...nor anything nested inside one",
          "#7" in prose_text_of("<pre><code><span>Closes #7</span></code></pre>"), False)
    check("...nor an <svg> icon's own vocabulary",
          "#7" in prose_text_of("<p><svg><title>Closes #7</title><path d='M0'/></svg>x</p>"),
          False)
    check("...and the text AFTER a quoted subtree is prose again",
          "#7" in prose_text_of("<p><code>x</code> Closes #7</p>"), True)
    # ATTRIBUTES ARE NEVER TEXT. `<img alt='Closes #7'>` renders nothing an author asserted, and
    # GitHub emits no issue link for it — the `img alt text` corpus row is the live confirmation.
    # SELF-CLOSING TAGS — `handle_startendtag`, which round 7 found at ZERO coverage. The shipped
    # code raises correctly, but the frozen oracle holds no `<x/>` at all, so the branch was
    # unreachable from every row: the marquee "an unknown element raises" claim had an uncovered
    # branch on the very path an author can write by hand. All three classes are driven directly.
    check("a self-closing UNKNOWN element raises, exactly as its paired form does",
          total(lambda: prose_text_of("<p>Closes <weird-thing/> #7</p>"))[:1], ("RAISED",))
    check("...a self-closing PROSE element contributes no separator that breaks a declaration",
          bool(CLOSING_REF_RE.search(prose_text_of("<p>Closes<br/> #7</p>"))), True)
    check("...and a self-closing QUOTED element still leaves the sentinel the grammar cannot cross",
          bool(CLOSING_REF_RE.search(prose_text_of("<p>Fixes<code/>#7</p>"))), False)
    check("...while a self-closing BLOCK element still ends the proposition",
          bool(SENTENCE_BREAK_RE.search(
              prose_text_of("<p>this does not close anything<hr/>Closes #7</p>"))), True)
    # THE `<a>` CLASS MATCH IS A TOKEN MATCH, NOT A SUBSTRING. GitHub strips `class` from an
    # author-written anchor today, so this is not exploitable — but "not exploitable today" is a
    # property of GitHub's sanitiser, not of this file, and the sanitiser is not ours.
    check("an anchor whose class merely CONTAINS the token is not an issue link",
          "#7" in prose_text_of('<p><a class="issue-linkish" href="x">Closes #7</a></p>'), False)
    check("...nor one where it is a prefix of a longer word",
          "#7" in prose_text_of('<p><a class="not-issue-link-really" href="x">Closes #7</a></p>'),
          False)
    check("...while the token in a multi-class attribute IS one, in either order",
          (prose_text_of(
              '<p>Closes <a class="js-issue-link issue-link" href="x">#7</a></p>').strip(),
           prose_text_of(
               '<p>Closes <a class="issue-link js-issue-link" href="x">#7</a></p>').strip()),
          ("Closes #7", "Closes #7"))
    check("an attribute value is never prose",
          "#7" in prose_text_of("<p><img alt='Closes #7' src='x'></p>"), False)
    # THE `<a>` RULE, both halves. Getting either wrong breaks the feature or the trust model.
    check("an anchor the RENDERER marked as a resolved issue link is prose — this is how a real "
          "`Closes #7` survives at all",
          prose_text_of('<p>Closes <a class="issue-link js-issue-link" href="x">#7</a></p>')
          .strip(), "Closes #7")
    check("...while an author-written anchor is not, because GitHub does not resolve one",
          "#7" in prose_text_of('<p><a href="x">Closes #7</a></p>'), False)
    # THE ALERT / BLOCKQUOTE DISTINCTION, stated rather than left as an accident of classification.
    # `> [!NOTE]` LOOKS like a blockquote in source and is not one to GitHub: the renderer emits
    # `<div class="markdown-alert">`. So an alert DECLARES and a blockquote does not. That is the
    # intended reading — an alert is the author writing in their own voice with emphasis, a
    # blockquote is the author reproducing someone else's text — and it is a hole in the "quoting is
    # not declaring" policy only if left unstated. Both halves are pinned so neither can drift.
    check("a GitHub ALERT is the author's own voice, so it declares",
          "#7" in prose_text_of(
              '<div class="markdown-alert markdown-alert-note"><p>Closes #7</p></div>'), True)
    check("...while a BLOCKQUOTE is someone else's text, so it does not",
          "#7" in prose_text_of("<blockquote><p>Closes #7</p></blockquote>"), False)
    check("...and the corpus agrees with both, on shapes GitHub really rendered",
          (oracle_binds.get("alert block"), oracle_binds.get("blockquote")), (True, False))
    # WHAT A DROPPED CONSTRUCT LEAVES BEHIND — the two separators, and the three properties of the
    # inline one. A SPACE would SPLICE (`Fixes `mod` #7` becomes a declaration nobody wrote); a
    # NEWLINE would end the negation window mid-sentence (`this does not `x` close #7` would stop
    # being suppressed, a refusal turning into a mint).
    check("a dropped INLINE construct leaves a sentinel the grammar cannot cross",
          bool(CLOSING_REF_RE.search(prose_text_of(
              "<p>Fixes <code>mod</code> #7</p>"))), False)
    check("...which is not `[ \\t]`", bool(re.fullmatch(r"[ \t]", SPAN_SENTINEL)), False)
    check("...is not a word character, so it breaks no keyword boundary and no `#` guard",
          bool(re.fullmatch(r"[0-9A-Za-z_-]", SPAN_SENTINEL)), False)
    check("...and is deliberately NOT a sentence break, so a negator still reaches across it",
          bool(SENTENCE_BREAK_RE.search(SPAN_SENTINEL)), False)
    check("a dropped BLOCK construct DOES end the proposition, so a negator cannot reach past it",
          bool(SENTENCE_BREAK_RE.search(
              prose_text_of("<p>this does not close anything</p>"
                                  "<pre>x</pre><p>Closes #7</p>"))), True)
    # BOTH EDGES of a block boundary, and the fixture that can tell them apart. A VOID block element
    # has no end tag, so only the OPENING separator exists for it — and without that separator the
    # two sides SPLICE into a declaration nobody wrote, which is the mint direction. MEASURED: with
    # only a closing-edge separator this row is the sole one in the suite that reds.
    check("a block boundary separates on the OPENING edge too, so a void block cannot splice a "
          "keyword onto a number across it",
          bool(CLOSING_REF_RE.search(prose_text_of("Fixes<hr>#7"))), False)
    check("...and the same two halves DO bind when the author really wrote them adjacent",
          bool(CLOSING_REF_RE.search(prose_text_of("<p>Fixes #7</p>"))), True)

    # ---- THE TWO-DERIVATION AGREEMENT RULE ------------------------------------------------------
    # `declared` is the INTERSECTION of the rendered prose and the raw source; `all_refs` is their
    # UNION. Each half is asserted with a shape only that half catches.
    def refs(title, body, render):
        return total(lambda: closing_references(
            *derivation_texts(title, body, render, ORACLE_CONTEXT_REPO)))

    quoted_only = refs("t", "Closes #7", lambda _t: "<pre>Closes #7</pre>")
    check("PROSE HALF — a reference the RENDERER puts in code drops out of the binding set",
          (quoted_only.declared, quoted_only.all_refs), ([], [7]))
    manufactured = refs("t", "Clos**es** #7", lambda _t: "<p>Clos<strong>es</strong> #7</p>")
    check("RAW HALF — a reference only the RENDERER manufactures drops out too",
          (manufactured.declared, manufactured.all_refs), ([], [7]))
    # ---- THE THIRD CONJUNCT: GitHub's own anchor ------------------------------------------------
    # ROUND 7's BLOCKING CLASS. The two TEXT derivations share one tokenizer, so a `#N` boundary
    # GitHub disagrees with is invisible to BOTH and the agreement rule cannot catch it by
    # construction. `Closes #929abc` minted end to end at the previous head with the LIVE renderer
    # emitting no anchor at all.
    # ---- SPANS, NOT SETS: the occurrence-level conjunct ------------------------------------------
    # ROUND 8's BLOCKING CLASS. `N in prose.anchored` asked "is #N resolved SOMEWHERE in this pull
    # request", which any unrelated bare mention makes true. These rows ask the question the
    # derivation actually needs answered.
    def anchor_at(text, number, repo=None):
        """Prose HTML where ONLY the LAST `#N` is an anchor — the unrelated-mention shape."""
        head, _sep, tail = text.rpartition(f"#{number}")
        return (f"<p>{head}<a class=\"issue-link\" href=\"https://github.com/"
                f"{repo or ORACLE_CONTEXT_REPO}/issues/{number}\">#{number}</a>{tail}</p>")

    split = refs("t", "Closes #7abc and see #7",
                 lambda _t: anchor_at("Closes #7abc and see #7", 7))
    check("SPANS — an anchor on a DIFFERENT occurrence does not resolve the one the grammar "
          "matched, even though the number is resolved in this pull request",
          (split.declared, split.unresolved), ([], [7]))
    check("...and the prose really does contain a resolved #7, so the row is not vacuous",
          [number for _s, _e, number in
           total(lambda: rendered_prose(anchor_at("Closes #7abc and see #7", 7),
                                        ORACLE_CONTEXT_REPO)).anchors], [7])
    both = refs("t", "Closes #7abc and closes #7",
                lambda _t: anchor_at("Closes #7abc and closes #7", 7))
    check("...while a number with TWO matched occurrences binds when EITHER is resolved — GitHub "
          "really does close it from the second",
          (both.declared, both.unresolved), ([7], []))
    # THE SPAN OFFSET across the title/body join. Rendered as two documents, so the body's spans
    # must shift by exactly `len(title_text) + 1`; an off-by-one moves every body anchor off its own
    # text and turns every body declaration into a nameless refusal.
    joined = total(lambda: derivation_texts(
        "a title of some length", "Closes #7",
        lambda text: anchored_html(text, ORACLE_CONTEXT_REPO), ORACLE_CONTEXT_REPO)[1])
    check("SPANS — a body anchor's span still covers its own text after the title/body join",
          [joined.text[start:stop] for start, stop, _n in joined.anchors], ["#7"])
    unanchored = refs("t", "Closes #7", lambda _t: "<p>Closes #7</p>")
    check("ANCHOR HALF — a reference GitHub did not resolve is not a candidate, even though BOTH "
          "text derivations see it",
          (unanchored.declared, unanchored.all_refs, unanchored.unresolved), ([], [7], [7]))
    check("...and it refuses under its OWN name, not `no-issue-reference` — the author DID declare "
          "one, so telling them to add one would be wrong",
          total(lambda: derive_issue_number(
              {"title": "t", "body": "Closes #7"}, lambda n: open_issue_7,
              lambda _t: "<p>Closes #7</p>", "o/r").reason), REASON_REFERENCE_NOT_RESOLVED)
    check("...and the message NAMES the reference GitHub declined",
          total(lambda: "#7" in derive_issue_number(
              {"title": "t", "body": "Closes #7"}, lambda n: open_issue_7,
              lambda _t: "<p>Closes #7</p>", "o/r").message), True)
    # THE ANCHOR MUST BE OURS. A cross-repository reference renders as an `issue-link` too, and its
    # number belongs to a different lease partition — so an anchor pointing anywhere else must not
    # satisfy the conjunct for a same-numbered reference in our text.
    foreign = refs("t", "Closes #7", lambda _t: (
        '<p>Closes #7 (see <a class="issue-link" '
        'href="https://github.com/other/repo/issues/7">other/repo#7</a>)</p>'))
    # THE ANCHOR MUST BE FOR THIS NUMBER, not merely overlap the occurrence. GitHub's anchor text
    # and its href can disagree (`Closes #0929` links to issue 929), so containment alone is not
    # enough — the recorded number has to match the matched one.
    wrong_number = refs("t", "Closes #7", lambda _t: (
        '<p>Closes <a class="issue-link" href="https://github.com/' + ORACLE_CONTEXT_REPO
        + '/issues/8">#7</a></p>'))
    check("SPANS — a span recorded for a DIFFERENT number does not resolve this occurrence",
          (wrong_number.declared, wrong_number.unresolved), ([], [7]))
    # ...and a FOREIGN anchor covering the occurrence itself. The href filter is what stops it, and
    # until this row existed the filter's mutant survived: the only fixture had the foreign anchor
    # somewhere ELSE in the prose, where the span check refuses it for an unrelated reason.
    foreign_span = refs("t", "Closes #7", lambda _t: (
        '<p>Closes <a class="issue-link" '
        'href="https://github.com/other/repo/issues/7">#7</a></p>'))
    check("SPANS — an anchor into ANOTHER repository does not resolve an occurrence it covers",
          (foreign_span.declared, foreign_span.unresolved), ([], [7]))
    # AN UNCLOSED ANCHOR still spans what it holds — `close()` records it at the end of the
    # document. Without that, a truncated rendering would refuse a real declaration.
    unclosed = refs("t", "Closes #7", lambda _t: (
        '<p>Closes <a class="issue-link" href="https://github.com/' + ORACLE_CONTEXT_REPO
        + '/issues/7">#7'))
    check("SPANS — an UNCLOSED anchor still spans its own text", unclosed.declared, [7])
    # ...and the DIRECTION of that choice, demonstrated rather than described. Extending an unclosed
    # anchor to the end of the document is PERMISSIVE — the span then covers text after it, and a
    # trailing run-on inside that span binds. `close()` says so in as many words now; this row is
    # what makes the sentence checkable, so nobody can re-read it as a safety argument.
    runon_in_span = refs("t", "Closes #7abc", lambda _t: (
        '<p>x <a class="issue-link" href="https://github.com/' + ORACLE_CONTEXT_REPO
        + '/issues/7">y</a>'.replace("</a>", "") + ' and Closes #7abc</p>'))
    check("SPANS — an unclosed anchor's span DOES reach a later run-on, which is the permissive "
          "direction; it is unreachable on GitHub's own output, not safe by construction",
          runon_in_span.declared, [7])
    # ...and the anchor must be in PROSE. A blockquote that merely QUOTES a reference carries a real
    # `issue-link` anchor; letting it satisfy the conjunct would mint from two halves neither of
    # which is a declaration. MEASURED with the live renderer before this row existed.
    quoted_anchor = refs("t", "Closes #7abc", lambda _t: (
        '<p>Closes #7abc</p><blockquote><p>see <a class="issue-link" href="https://github.com/'
        + ORACLE_CONTEXT_REPO + '/issues/7">#7</a></p></blockquote>'))
    check("ANCHOR HALF — an anchor inside QUOTED context does not resolve a run-on in prose",
          (quoted_anchor.declared, quoted_anchor.unresolved), ([], [7]))
    # ...and WHY, stated as a property rather than left to the guard. Quoted text emits nothing, so
    # a quoted anchor's span is EMPTY, and an empty span cannot contain a non-empty reference. That
    # makes the quote-depth guard on anchor collection redundant under spans — MEASURED: with the
    # guard removed the span is recorded as zero-length and the row still refuses. The guard stays
    # (it keeps the anchor list honest about what was collected), but the safety no longer rests on
    # it, and this row is what says so.
    check("SPANS — an empty span can never contain a reference, so a quoted anchor is inert even "
          "if it is collected",
          _occurrence_is_anchored(RenderedProse("Closes #7", ((7, 7, 7),)),
                                  CLOSING_REF_RE.search("Closes #7")), False)
    check("...while the same span over the reference itself does contain it",
          _occurrence_is_anchored(RenderedProse("Closes #7", ((7, 9, 7),)),
                                  CLOSING_REF_RE.search("Closes #7")), True)
    check("ANCHOR HALF — an anchor into ANOTHER repository does not resolve OUR number",
          (foreign.declared, foreign.unresolved), ([], [7]))
    # ...and a `pull/` href DOES satisfy it, deliberately. Dropping it would make
    # `reference-is-a-pull-request` — which fires on the live population — structurally unreachable,
    # replacing a named, actionable refusal with a vague one.
    pulled = refs("t", "Closes #7", lambda _t: (
        '<p>Closes <a class="issue-link" href="https://github.com/' + ORACLE_CONTEXT_REPO
        + '/pull/7">#7</a></p>'))
    check("ANCHOR HALF — a `pull/` anchor still resolves, so the PULL-REQUEST refusal stays "
          "reachable and keeps its name",
          (pulled.declared, pulled.unresolved), ([7], []))
    check("...and the shared-gate pre-filter then names it",
          total(lambda: derive_issue_number(
              {"title": "t", "body": "Closes #7"},
              lambda n: {"number": 7, "state": "open", "pull_request": {"url": "x"}},
              lambda _t: ('<p>Closes <a class="issue-link" '
                          'href="https://github.com/o/r/pull/7">#7</a></p>'), "o/r").reason),
          REASON_REFERENCE_IS_PULL)
    # A CONJUNCT CAN ONLY REFUSE MORE — the property that makes it safe to add without re-auditing
    # the other two terms. Asserted over the whole corpus: adding it lost NO binding row.
    check("...and adding the conjunct removed no true binding: every row that binds is a row whose "
          "number GitHub resolved",
          sorted(label for label, binds in oracle_binds.items()
                 if binds and not oracle["github_linkified"].get(label)), [])
    check("...and BOTH agreeing is what binds",
          refs("t", "Closes #7",
               lambda _t: anchored_html("Closes #7", ORACLE_CONTEXT_REPO)).declared, [7])
    # AND THE PROPERTY THAT MAKES BOTH SAFE: a disagreement can only ever REFUSE. Asserted over the
    # whole corpus rather than on one shape — no row binds a number that is not the only reference
    # either derivation saw.
    check("...so nothing this file binds is ever one of several references it saw",
          sorted(label for label, binds in oracle_binds.items() if binds
                 and total(lambda ll=label: refs(
                     *[row[1:3] for row in RENDERED_ORACLE_CORPUS if row[0] == ll][0],
                     frozen).all_refs) != [ORACLE_ISSUE]), [])

    # ---- the RAW closing-keyword grammar, which the intersection's raw half runs -----------------
    # These need no renderer: they are properties of CLOSING_REF_RE over the author's own text.
    def raw_refs(text):
        return sorted({int(m.group(1)) for m in CLOSING_REF_RE.finditer(text)})

    check("every documented GitHub closing keyword is read",
          raw_refs("close #1 closes #2 closed #3 fix #4 fixes #5 fixed #6 resolve #7 "
                   "resolves #8 resolved #9"), [1, 2, 3, 4, 5, 6, 7, 8, 9])
    check("...case-insensitively", raw_refs("CLOSES #12"), [12])
    check("...with a colon", raw_refs("Closes: #12"), [12])
    check("a bare mention is not a closing reference", raw_refs("see #7, related #8"), [])
    check("`Refs #7` is not a closing reference", raw_refs("Refs #7"), [])
    check("a CROSS-REPO closing reference names another lease partition",
          raw_refs("Fixes sparq-org/sparq#4329"), [])
    check("a keyword inside another word is not a keyword", raw_refs("unfixed #7"), [])
    check("a keyword not adjacent to the number does not bind it",
          raw_refs("Closes the composition defect in #7"), [])
    check("a comment anchor is not an issue reference",
          raw_refs("fixes #issuecomment-5096919798"), [])
    check("a conventional-commit scope is not a declaration", raw_refs("fix(#869): emit"), [])

    # ---- NEGATED PROSE: a suppressor that can only ever cause a refusal ------------------------
    # Driven through the REAL derivation on a rendered paragraph, because the suppressor now reads
    # the prose text and nothing else.
    def para(text):
        return total(lambda: closing_references(
            *derivation_texts("t", text, lambda _t: anchored_html(text, "o/r"), "o/r")))

    for phrase in ("does not close", "doesn't close", "will not fix", "won't fix",
                   "never closes", "cannot close", "no longer closes", "unable to close",
                   "neither closes", "closes nothing, and does not close",
                   "supersedes rather than closes"):
        check(f"...{phrase!r} suppresses the declaration",
              para(f"this PR {phrase} #1234").declared, [])
    check("a negator in the PREVIOUS sentence does not suppress the next one",
          para("This is not a revert. Closes #7").declared, [7])
    check("...nor one in a different TABLE CELL (live shape, PR #710)",
          para("| not routed through x | ALREADY FIXED | fixed #7 |").declared, [7])
    check("...while a negator in the SAME cell still suppresses",
          para("| a | this does not fix #7 |").declared, [])
    # THE PROPERTY that makes the suppressor safe, asserted directly rather than described: a
    # negated reference is still counted for AMBIGUITY, so suppression can only turn a mint into a
    # refusal — never a refusal into a mint, and never a DIFFERENT binding.
    mixed = para("Closes #7. This does not close #8.")
    check("a negated reference is dropped from the DECLARED set", mixed.declared, [7])
    check("...but still counted for AMBIGUITY", mixed.all_refs, [7, 8])
    check("...so the pull request REFUSES rather than silently binding the survivor",
          total(lambda: (candidate_refusal(mixed.declared, (), mixed.all_refs)
                         or ("MINTED-THE-SURVIVOR",))[0]), REASON_AMBIGUOUS)

    # ---- the ADVISORY mention list (rendered prose only; never a candidate) --------------------
    def mentions_of(text):
        return total(lambda: mentioned_issue_numbers(
            derivation_texts("", text, lambda _t: anchored_html(text, "o/r"), "o/r")[1]))

    check("mentions are collected for the hint", mentions_of("see #8 and #7"), [7, 8])
    check("...cross-repository mentions are not this repo's numbers",
          mentions_of("sparq-org/sparq#4329"), [])
    check("...and the hint is capped",
          len(total(lambda: mentioned_issue_numbers(derivation_texts(
              "", "x", lambda _t: anchored_html(" ".join(f"#{n}" for n in range(1, 20)), "o/r"),
              "o/r")[1]))),
          MAX_ADVISORY_MENTIONS)
    check("...and the mention list reads the same RENDERED PROSE the grammar's binding half does",
          total(lambda: mentioned_issue_numbers(derivation_texts(
              "t", "x",
              lambda _t: "<p><code>#1234</code></p><blockquote>#999</blockquote>",
              "o/r")[1])), [])
    # THE CONTROL that keeps the hint advisory: a body full of mentions and NO closing keyword
    # still derives NOTHING, and still refuses under the SAME reason as a body with no `#` at all.
    def mentions_only(text):
        return derive_issue_number({"title": "t", "body": text}, lambda n: None,
                                   lambda _t: anchored_html(text, "o/r"), "o/r")

    check("a body full of mentions still derives nothing",
          total(lambda: mentions_only("#7 #8 #9").number), None)
    check("...under the same reason as a body with no reference at all",
          total(lambda: mentions_only("#7 #8 #9").reason),
          total(lambda: mentions_only("nothing at all").reason))
    check("...and the hint names them so the author can fix it in one edit",
          total(lambda: all(token in candidate_refusal([], [7, 8])[1]
                           for token in ("#7", "#8"))), True)
    check("...while a PR that mentions nothing gets no dangling hint",
          total(lambda: "does mention" in candidate_refusal([], [])[1]), False)

    # ---- REFUSAL BRANCH 1/4: zero references --------------------------------------------------
    refuses("ZERO closing references refuse by name", REASON_NO_REFERENCE,
            lambda: candidate_refusal([]))
    # ---- REFUSAL BRANCH 2/4: multiple candidates ----------------------------------------------
    refuses("MULTIPLE closing references refuse by name", REASON_AMBIGUOUS,
            lambda: candidate_refusal([826, 869]))
    check("...and the refusal NAMES the candidates so the author can pick one",
          total(lambda: all(token in candidate_refusal([826, 869])[1]
                           for token in ("#826", "#869"))), True)
    check("exactly one candidate is not a cardinality refusal", candidate_refusal([7]), None)

    def issue(**over):
        return {**{"number": 7, "state": "open", "labels": [{"name": "area:ci"}]}, **over}

    # ---- REFUSAL BRANCH 3/4: the reference resolves to a PULL REQUEST -------------------------
    refuses("a reference that resolves to a PULL REQUEST refuses by name",
            REASON_REFERENCE_IS_PULL,
            lambda: resolved_issue_refusal(7, issue(pull_request={"url": "x"})))
    # ---- REFUSAL BRANCH 4/4: the reference resolves to a CLOSED issue -------------------------
    refuses("a reference that resolves to a CLOSED issue refuses by name",
            REASON_REFERENCE_CLOSED, lambda: resolved_issue_refusal(7, issue(state="closed")))
    refuses("a reference that reads back as another number refuses by name",
            REASON_ISSUE_UNREADABLE, lambda: resolved_issue_refusal(7, issue(number=8)))
    for bad in (None, [], "7", {}):
        refuses(f"a malformed issue payload {bad!r} refuses by name", REASON_ISSUE_UNREADABLE,
                lambda b=bad: resolved_issue_refusal(7, b))
    check("an OPEN issue is not a resolution refusal", resolved_issue_refusal(7, issue()), None)

    # THE ANTI-DRIFT CONTROL. This file's resolution gate is a strict PRE-FILTER of the shared one:
    # everything it refuses, mint-provenance.issue_mint_refusal refuses too. Without this the two
    # derivations could drift until this file admitted something the shared gate would refuse, and
    # the sweep would mint records that stall.
    def pull(**over):
        base = {"number": 41, "state": "open", "draft": False,
                "title": "fix: something", "body": "Closes #7",
                "user": {"login": "jeswr"},
                "head": {"ref": "fix/ordinary-branch", "sha": "a" * 40,
                         "repo": {"full_name": "o/r"}}}
        head = {**base["head"], **over.pop("head", {})}
        return {**base, **over, "head": head}

    lease_schema = _load_script_module("lease_schema.py", "registry_lease_schema")
    shared_args = (lease_schema.plan_package, lease_schema.GLOBAL_PACKAGE)
    for label, payload in (("a PULL REQUEST", issue(pull_request={"url": "x"})),
                           ("a CLOSED issue", issue(state="closed"))):
        check(f"...and the SHARED gate independently refuses {label} too",
              isinstance(mint_provenance.issue_mint_refusal(7, payload, pull(), *shared_args), str),
              True)
    check("...while the case this file ACCEPTS is the case the shared gate accepts",
          mint_provenance.issue_mint_refusal(7, issue(), pull(), *shared_args), None)
    # ...and anything this file derives also satisfies the shared BINDING predicate, because a
    # closing keyword reference is a textual reference.
    check("a derived candidate always satisfies the shared reference binding",
          mint_provenance.references_issue(pull(body="Closes #7"), 7), True)

    # ---- the derivation end to end ------------------------------------------------------------
    def paragraph_render(text):
        """GitHub's rendering of a single line of ordinary prose: one `<p>`, with every `#N` it
        resolved rewritten into the `issue-link` anchor the third conjunct reads."""
        return anchored_html(text, "o/r")

    def derive(body, issue_payload=None, boom=False, render=None):
        def read(number):
            if boom:
                raise RuntimeError("HTTP 502")
            return issue_payload if issue_payload is not None else issue(number=number)

        # `total` so a derivation that RAISES reds these named checks instead of aborting the run:
        # "TOTAL: never raises, never guesses" is the property, so it is asserted, not assumed.
        got = total(lambda: derive_issue_number(pull(body=body), read,
                                                render or paragraph_render, "o/r"))
        return got if isinstance(got, DerivedIssue) else DerivedIssue(got, got, str(got), None)

    # POSITIVE CONTROL: a well-formed PR with exactly one open referenced issue derives it.
    check("POSITIVE CONTROL: one open referenced issue derives cleanly",
          (derive("Closes #7").number, derive("Closes #7").reason), (7, None))
    check("...and carries the issue payload forward so the mint does not re-read it",
          derive("Closes #7").issue["number"], 7)
    for label, body, payload, reason in (
            ("zero references", "no reference at all", None, REASON_NO_REFERENCE),
            ("multiple references", "Closes #7, fixes #8", None, REASON_AMBIGUOUS),
            ("a reference to a PR", "Closes #7", issue(pull_request={"url": "x"}),
             REASON_REFERENCE_IS_PULL),
            ("a reference to a closed issue", "Closes #7", issue(state="closed"),
             REASON_REFERENCE_CLOSED)):
        got = derive(body, payload)
        check(f"the derivation refuses {label} by name", (got.number, got.reason),
              (None, reason))
    unreadable = derive("Closes #7", boom=True)
    check("an unreadable source issue refuses rather than raising",
          (unreadable.number, unreadable.reason), (None, REASON_ISSUE_UNREADABLE))
    check("...and NEVER falls back to a default",
          [derive(b, p).number for b, p in (("nothing", None), ("Closes #7, fixes #8", None),
                                            ("Closes #7", issue(pull_request={"u": "x"})),
                                            ("Closes #7", issue(state="closed")))],
          [None, None, None, None])
    # ---- THE DERIVATION'S OWN CALL SITE, argument by argument ---------------------------------
    # WHY THIS BLOCK EXISTS. `derive_issue_number` is the ONLY production caller of
    # `candidate_refusal`, and every negation and mention fixture above it stops at
    # `closing_references` / `candidate_refusal` and hand-passes the very argument under test. That
    # asserts a property of the FUNCTION while leaving the WIRING unobserved, and the wiring is the
    # whole design: MEASURED, dropping the third argument at the one call site below turned
    # `Closes #7. This does not close #8.` from an `ambiguous-issue-reference` refusal into a silent
    # mint of the survivor — with the entire suite still green. Every argument of that call is
    # therefore pinned here THROUGH the real derivation, so a dropped or rebound one reds a check
    # named for what it costs.
    negated_two = "Closes #7. This does not close #8."
    check("ARG 3 (all_refs): a negated reference still reaches the AMBIGUITY gate through the "
          "real derivation, so the survivor is never silently bound",
          (derive(negated_two).number, derive(negated_two).reason), (None, REASON_AMBIGUOUS))
    check("ARG 1 (declared): a body whose ONLY reference is negated refuses for having no "
          "declaration — the suppressor really is applied on the production path",
          (derive("This PR does not close #7.").number,
           derive("This PR does not close #7.").reason), (None, REASON_NO_REFERENCE))
    check("ARG 2 (mentions): the advisory numbers reach the refusal MESSAGE the author reads",
          total(lambda: all(token in derive("it relates to #7 and to #8").message
                            for token in ("#7", "#8"))), True)
    # ARG 4 (render): the derivation really goes THROUGH the renderer rather than reading the raw
    # body. A render that returns an EMPTY document must therefore derive nothing, even though the
    # raw body declares a reference — if this binds, the renderer is not on the path at all.
    check("ARG 4 (render): a body whose RENDERING is empty derives nothing, so the raw source is "
          "never the binding derivation",
          (derive("Closes #7", render=lambda _t: "").number,
           derive("Closes #7", render=lambda _t: "").reason), (None, REASON_NO_REFERENCE))
    # ARG 5 (prose): the ADVISORY hint reads the rendered prose, not the raw source, THROUGH the
    # production derivation. Asserting it on `mentioned_issue_numbers` alone leaves the wiring
    # unobserved — MEASURED, pointing the call at `raw` survived the whole suite — and the cost is
    # a public comment telling an author to use a number that only exists in a code block they
    # pasted. The body mentions #1234 in the SOURCE and #8 in the RENDERING.
    quoted_hint = derive("`#1234` see #8",
                         render=lambda _t: "<p><code>#1234</code> see #8</p>")
    check("ARG 5 (prose): the advisory hint names only the numbers GitHub renders as live text",
          (quoted_hint.reason, "#8" in (quoted_hint.message or ""),
           "#1234" in (quoted_hint.message or "")),
          (REASON_NO_REFERENCE, True, False))

    check("a malformed pull payload refuses rather than raising",
          total(lambda: derive_issue_number(None, lambda n: issue(),
                                            paragraph_render, "o/r").reason),
          REASON_ISSUE_UNREADABLE)
    check("...and so does a payload with no title or body at all",
          total(lambda: derive_issue_number({}, lambda n: issue(),
                                            paragraph_render, "o/r").reason),
          REASON_NO_REFERENCE)

    # ---- the refusal taxonomy + comment --------------------------------------------------------
    check("every per-PR refusal reason is distinct", len(set(PR_REFUSAL_REASONS)),
          len(PR_REFUSAL_REASONS))
    check("exactly the three PLATFORM-side reasons are censused without a PR comment",
          sorted(SILENT_REASONS), sorted([REASON_MINT_FAILED, REASON_RECORD_PROBE_FAILED,
                                          REASON_RENDER_UNAVAILABLE]))
    check("...and every silent reason really is a registry-or-platform fact, not a PR fact",
          [r for r in SILENT_REASONS if r not in (REASON_RECORD_PROBE_FAILED,
                                                  REASON_MINT_FAILED,
                                                  REASON_RENDER_UNAVAILABLE)], [])
    check("...and every OTHER reason carries an operator hint to put in that comment",
          sorted(reason for reason in PR_REFUSAL_REASONS
                 if reason not in SILENT_REASONS and not REASON_HINTS.get(reason)), [])
    body = refusal_comment_body(REASON_AMBIGUOUS, "two candidates")
    check("the refusal comment self-identifies", body.startswith(SELF_ID), True)
    check("...names the machine-readable reason", f"`{REASON_AMBIGUOUS}`" in body, True)
    check("...carries the operator's next action", REASON_HINTS[REASON_AMBIGUOUS] in body, True)
    check("...and carries its dedupe marker", refusal_marker(REASON_AMBIGUOUS) in body, True)
    # THE TOOL'S OWN OUTPUT IS NOT A LIVE PAYLOAD. The likeliest author response to a refusal
    # comment is to quote it back into the PR description, so the WHOLE rendered comment — for
    # EVERY reason code, and with a deliberately HOSTILE passthrough message — must derive nothing.
    # Driven through GITHUB'S OWN RENDERING of the comment (frozen), not through a description of
    # it: two independent properties hold it, and each is asserted separately below.
    check("every generated refusal comment has a frozen render — so a wording change reds these "
          "checks instead of quietly passing on a stale artefact",
          [document[:60] for document in _oracle_own_output_documents()
           if document not in oracle["documents"]], [])
    hostile = ORACLE_HOSTILE_PASSTHROUGH
    for reason in PR_REFUSAL_REASONS:
        rendered = refusal_comment_body(reason, hostile)
        refs = total(lambda r=rendered: closing_references(
            *derivation_texts("", r, frozen, ORACLE_CONTEXT_REPO)))
        # `declared` is what could BIND, and it must be empty. `all_refs` is deliberately NOT
        # empty: the raw half of the intersection still SEES the hostile numbers, which is what
        # makes a pasted-back comment an AMBIGUOUS refusal rather than a quiet no-op. Asserting
        # both is the honest statement — the previous version asserted `all_refs == []`, which was
        # true only because the whole comment used to be erased by a source-level strip.
        check(f"the {reason} comment binds NOTHING when quoted back into a PR body",
              refs.declared if isinstance(refs, ClosingRefs) else refs, [])
        check(f"...and the {reason} comment's numbers still reach the AMBIGUITY gate",
              refs.all_refs if isinstance(refs, ClosingRefs) else refs, [657, 916, 929])
    # THE "UNQUOTED PASTE" TEST HAS TO DEFEAT THIS FILE'S OWN QUOTING, or it proves nothing: every
    # placeholder sits in a code span, so feeding the hints in verbatim is inert for the WRONG
    # reason. Strip the backticks first, and assert the structural property behind it.
    check("...and no hint contains a literal issue number at all",
          sorted(reason for reason, hint in REASON_HINTS.items() if re.search(r"#[0-9]", hint)),
          [])
    check("...proved with the code spans DEFEATED: backticks removed, the hints still bind nothing",
          cand("", "\n".join(REASON_HINTS.values()).replace("`", "")), [])
    check("...which the hostile control proves is not vacuous: the payload DOES bind on its own",
          cand("", hostile), [657, 916, 929])

    check("an existing comment for THIS reason dedupes",
          already_refused([{"body": body}], REASON_AMBIGUOUS), True)
    check("...and a comment for a DIFFERENT reason does not",
          already_refused([{"body": body}], REASON_NO_REFERENCE), False)
    for bad in (None, "x", [None], [{"body": None}], [{}]):
        check(f"a malformed comment list {bad!r} never dedupes",
              already_refused(bad, REASON_AMBIGUOUS), False)

    # ---- the target gate -----------------------------------------------------------------------
    check("the registry sweeps itself", target_sweep_refusal("o/r", "o/r"), None)
    refuses("a target this run cannot COMMENT on is refused, loudly",
            REASON_TARGET_NOT_ANNOTATABLE, lambda: target_sweep_refusal("other/repo", "o/r"))
    refuses("a malformed target is refused", REASON_TARGET_NOT_ANNOTATABLE,
            lambda: target_sweep_refusal("not-a-repo", "o/r"))
    check("the routing pointer of the shipped policy row is fetchable",
          routing_pointer_error("orchestration/routing.toml"), None)
    for bad in (None, "", "/etc/passwd", "../secrets.toml", "a/../../b", "C:\\x"):
        check(f"a routing pointer {bad!r} is refused",
              isinstance(routing_pointer_error(bad), str), True)

    # ---- the enrolled population ---------------------------------------------------------------
    policy_doc = _read_policy()
    policy_resolve = _load_policy_resolve()
    live_targets = enrolled_targets(policy_doc, policy_resolve.review_enrolment_authors)
    # The SAME freeze control mint-provenance carries, at the sweep's own enumeration: this names
    # the population rather than merely asserting it is small, so it reds on a SECOND repo being
    # enrolled alongside a trigger change (the blast-radius widening #916 deliberately deferred)
    # AND on the list being emptied, which would make every sweep vacuous forever.
    # [#1451] REPOINTED, not relaxed — names both enrolled repos so a THIRD still reds it.
    check("the sweep's population is EXACTLY the registry and sparq, and only `jeswr`",
          live_targets, [("jeswr/agent-account-registry", ("jeswr",)),
                         ("sparq-org/sparq", ("jeswr",))])
    check("...and a disabled row is never a target",
          enrolled_targets({"repos": {"o/r": {"enabled": False,
                                              "review_enrolment_authors": ["x"]}}},
                           lambda name, doc: doc["repos"][name]["review_enrolment_authors"]), [])
    check("...and an enabled row that enrols NOBODY is never a target",
          enrolled_targets({"repos": {"o/r": {"enabled": True}}}, lambda name, doc: []), [])
    check("...while an enabled row that enrols someone IS one",
          enrolled_targets({"repos": {"o/r": {"enabled": True}}}, lambda name, doc: ["a", "B"]),
          [("o/r", ("B", "a"))])
    # `enabled is not True` is a STRICTER test than `enabled is False`, and only an ABSENT or
    # non-boolean `enabled` can tell them apart — which no fixture did, so `is not True` could be
    # weakened to `is False` and nothing red. That is a missing fixture, not an equivalent mutant:
    # the difference is opt-OUT versus opt-IN for a row that never states the field, and this is the
    # gate deciding which repositories an unattended writer may touch.
    for label, row in (("absent", {"review_enrolment_authors": ["x"]}),
                       ("null", {"enabled": None, "review_enrolment_authors": ["x"]}),
                       ("the STRING 'true'", {"enabled": "true",
                                              "review_enrolment_authors": ["x"]}),
                       ("1", {"enabled": 1, "review_enrolment_authors": ["x"]})):
        check(f"...and a row whose `enabled` is {label} is NOT a target — enrolment is opt-IN",
              enrolled_targets({"repos": {"o/r": row}}, lambda name, doc: ["x"]), [])

    check("the pinned implementing alias resolves to the pinned provider in the LIVE catalog",
          mint_provenance.alias_mint_refusal(
              AUTO_IMPL_ALIAS, _live_routing()), None)
    check("...and the shared writer's provider pin is the one the lane inverts",
          mint_provenance.ORCHESTRATOR_IMPL_PROVIDER, "anthropic")

    check("an enrolled author's open PR is in the population",
          [row["number"] for row in enrolled_class_pulls([pull()], ("jeswr",))], [41])
    check("...case-insensitively",
          [row["number"] for row in enrolled_class_pulls([pull(user={"login": "JesWR"})],
                                                          ("jeswr",))], [41])
    check("a NON-enrolled author is not in the population",
          enrolled_class_pulls([pull(user={"login": "stranger"})], ("jeswr",)), [])
    check("a [bot] author is not in the population either (release-plz / dependabot stay out)",
          enrolled_class_pulls([pull(user={"login": "dependabot[bot]"})], ("jeswr",)), [])
    check("the population is ascending by number",
          [row["number"] for row in enrolled_class_pulls(
              [pull(number=9), pull(number=2), pull(number=5)], ("jeswr",))], [2, 5, 9])
    for bad in (None, "x", [None], [{}], [{"number": True}], [{"number": 0}]):
        check(f"a malformed pull list {bad!r} contributes nobody",
              enrolled_class_pulls(bad, ("jeswr",)), [])

    # ---- the census ----------------------------------------------------------------------------
    counters = new_counters(mint_cap=3, comment_cap=5, apply_changes=True)
    counters.update(enrolled_pulls=6, with_record=2, minted=1, refused=2, deferred_cap=1)
    row = census_row(counters)
    check("the census derives the #929 population (PRs lacking a record)", row["lacking_record"],
          4)
    check("...and states the cap it enforced", (row["mint_cap"], row["comment_cap"]), (3, 5))
    check("...and every bucket appears in the one-line form",
          all(token in format_census(row) for token in
              ("enrolled_pulls=6", "with_record=2", "lacking_record=4", "minted=1/3", "refused=2",
               "deferred_cap=1")), True)
    unaccounted = new_counters(mint_cap=3, comment_cap=5, apply_changes=True)
    unaccounted.update(enrolled_pulls=6, with_record=2, minted=1, refused=1, deferred_cap=1)
    raised = False
    try:
        census_row(unaccounted)
    except SweepError:
        raised = True
    check("a census that does not account for the population STOPS the tick", raised, True)

    # ---- the sweep ORCHESTRATION: its own call sites -------------------------------------------
    class _Recorder:
        def __init__(self, pulls, records=None, issues=None, comments=None, actions=None):
            self.pulls, self.records = pulls, records or {}
            self.issues, self.comments = issues or {}, comments or {}
            self.actions = actions or {}
            self.written, self.posted, self.rendered = [], [], []
            # WHAT THE WRITER WAS HANDED, recorded verbatim. A fixture that only looks at the
            # RESULT cannot tell a dropped argument from a kept one, which is how a call site
            # becomes an untested seam while its callee is exhaustively unit-tested.
            self.handed = []

        def run(self, *, apply_changes=True, max_mints=DEFAULT_MAX_MINTS,
                max_comments=DEFAULT_MAX_COMMENTS, annotate_repo="o/r",
                targets=(("o/r", ("jeswr",)),), record_boom=False, pulls_boom=False,
                mint_boom=False, routing_boom=False, comments_boom=False, render=None,
                render_boom=False):
            def mint_pr(repo, number, issue_number, routing, authors, pl, iss):
                self.handed.append({"repo": repo, "number": number, "issue_number": issue_number,
                                    "routing": routing, "authors": authors, "issue": iss})
                if mint_boom:
                    raise RuntimeError("registry PUT failed: HTTP 502")
                action, reason = self.actions.get(
                    number, (mint_provenance.ACTION_MINT, "no record yet"))
                if action == mint_provenance.ACTION_MINT and apply_changes:
                    self.written.append((repo, number, issue_number))
                return mint_provenance.MintDecision(action, reason, None)

            def read_record(repo, number):
                if record_boom:
                    raise RuntimeError("HTTP 502")
                return self.records.get(number)

            def read_pulls(repo):
                if pulls_boom:
                    raise RuntimeError("pull listing failed: HTTP 502")
                return self.pulls

            def read_routing(repo):
                if routing_boom:
                    raise SweepError("the routing pointer is not a relative repository path")
                return {"models": {AUTO_IMPL_ALIAS: {"provider": "anthropic"}}}

            def read_comments(repo, number):
                if comments_boom:
                    raise RuntimeError("comment listing failed: HTTP 502")
                return self.comments.get(number, [])

            def render_markdown(repo, text):
                self.rendered.append((repo, text))
                if render_boom:
                    raise RenderUnavailable("GitHub's markdown renderer returned 22")
                return (render or paragraph_render)(text)

            return sweep(
                list(targets), annotate_repo=annotate_repo,
                read_routing=read_routing,
                read_pulls=read_pulls, read_issue=lambda repo, n:
                    self.issues.get(n, issue(number=n)),
                read_record=read_record, mint_pr=mint_pr,
                read_comments=read_comments,
                post_comment=lambda repo, n, b: self.posted.append((n, b)),
                render_markdown=render_markdown,
                apply_changes=apply_changes, max_mints=max_mints, max_comments=max_comments,
                log=lambda *_a, **_k: None)

    class _NoCensus(dict):
        """A census row that was never emitted, whose every field reads back as a NAMED marker.

        Production code in this file is allowed to raise in exactly one place — `census_row`'s seal,
        which STOPS a tick whose counters do not account for the population. That is correct
        behaviour, but in the harness a raise out of `sweep()` aborted the run with a traceback
        belonging to no branch: MEASURED, an `enrolled_pulls += 0` mutant killed the suite with
        `0 FAIL` rows at check 183 of 311, and a `declared`/`all_refs` swap reded one named check
        then abandoned the remaining 106. Both are now named failures instead."""

        def __init__(self, why):
            super().__init__()
            self.why = why

        def __missing__(self, _key):
            return ("NO CENSUS EMITTED", self.why)

    def run_row(recorder, **kwargs):
        """`recorder.run(**kwargs)`'s census row, or a row whose every field names the raise."""
        row = total(lambda: recorder.run(**kwargs))
        return row if isinstance(row, dict) else _NoCensus(row)

    class _Exploding:
        """A tick that raises, to prove `run_row` above is not itself an unreached control."""

        @staticmethod
        def run(**_kwargs):
            raise SweepError("the tick could not account for its population")

    _exploded = run_row(_Exploding())
    check("the harness's OWN safety net fires: a tick that raises reports every census field as a "
          "named marker, so a counter defect reds a check instead of aborting the run",
          (_exploded["minted"], _exploded["refusals"]),
          ((("NO CENSUS EMITTED", ("RAISED", "SweepError")),) * 2))

    clean = [pull(number=41, body="Closes #7")]
    rec = _Recorder(clean)
    row = run_row(rec)
    check("POSITIVE CONTROL: the sweep mints the well-formed PR, once",
          (row["minted"], rec.written), (1, [("o/r", 41, 7)]))
    check("...and the census counts it as lacking a record beforehand", row["lacking_record"], 1)
    check("...and posts no refusal comment", rec.posted, [])
    # WHAT THE WRITER WAS HANDED. Asserting only the RESULT cannot distinguish a forwarded argument
    # from a dropped one — both produce the same census row here — so each is read back off the
    # recorded call. Dropping either is a silent TOTAL outage of the feature (the shared gate
    # refuses an unreadable issue and an alias missing from the catalog), and an outage that
    # censuses itself as `mint-refused` is exactly the shape this file exists to make impossible.
    check("...and hands the writer the issue it ALREADY read, so the mint neither re-reads nor "
          "re-derives it",
          total(lambda: (rec.handed[0]["issue"] or {}).get("number")), 7)
    check("...and the TARGET's own routing catalog, which the pinned alias resolves against",
          total(lambda: rec.handed[0]["routing"]),
          {"models": {AUTO_IMPL_ALIAS: {"provider": "anthropic"}}})
    check("...and the derived issue number, not the PR's own",
          total(lambda: (rec.handed[0]["number"], rec.handed[0]["issue_number"])), (41, 7))
    # WHAT THE RENDERER WAS HANDED. `POST /markdown`'s `context` is what makes GitHub mark a
    # reference it RESOLVED with the `issue-link` class, and that class is the ONLY thing telling a
    # resolved reference apart from an author-written `<a>`. A hard-coded repository here would
    # render a SECOND enrolled target's bodies against the wrong numbering — invisible today
    # because there is one target, which is exactly why it needs a target whose name differs.
    other = _Recorder([pull(number=41, body="Closes #7")])
    run_row(other, annotate_repo="x/y", targets=(("x/y", ("jeswr",)),))
    check("...and the sweep renders each target's documents IN THAT TARGET's context",
          sorted({repo for repo, _text in other.rendered}), ["x/y"])
    check("...rendering the TITLE and the BODY as two separate documents, never concatenated, and "
          "each EXACTLY ONCE — the grammar half and the mention half read one shared rendering",
          sorted(text for _repo, text in other.rendered), ["Closes #7", "fix: something"])
    # ...and a PR that can never bind still pays for its rendering, deliberately: the advisory hint
    # in a `no-issue-reference` comment names the numbers the author DID mention, and that list is
    # read from the rendered prose so it cannot advertise a number out of a pasted code block.
    hintless = _Recorder([pull(number=41, body="mentions #8 but declares nothing")])
    run_row(hintless)
    check("...and a PR with no closing reference at all is still rendered, so its hint is honest",
          len(hintless.rendered), 2)

    # IDEMPOTENCE: a second tick over the record the first one wrote is a NO-OP.
    rec2 = _Recorder(clean, records={41: json.dumps({"pr_number": 41})})
    row2 = run_row(rec2)
    check("IDEMPOTENCE: a PR that already has a record is never re-minted",
          (row2["minted"], row2["with_record"], rec2.written, rec2.posted), (0, 1, [], []))
    # ...and if the record appears BETWEEN the probe and the mint, the shared writer's own
    # create-only verdict still lands as a no-op rather than a write.
    rec3 = _Recorder(clean, actions={41: (mint_provenance.ACTION_ALREADY, "identical")})
    row3 = run_row(rec3)
    check("...and a race that resolves to `already-minted` writes nothing either",
          (row3["minted"], row3["with_record"], rec3.written), (0, 1, []))

    # THE CAP.
    many = [pull(number=n, body="Closes #7") for n in (41, 42, 43, 44, 45)]
    capped = _Recorder(many)
    row4 = run_row(capped, max_mints=2)
    check("CAP: at most `max_mints` records are written in one tick",
          (row4["minted"], len(capped.written)), (2, 2))
    check("...and the rest are censused as cap-deferred, not lost", row4["deferred_cap"], 3)
    check("...and the cap is stated in the census", row4["mint_cap"], 2)
    check("...and the deferred PRs are the LATER ones (the sweep is deterministic)",
          [number for _repo, number, _issue in capped.written], [41, 42])

    # THE REFUSALS, end to end, one named reason each, each visible ON the PR.
    for label, payloads, issues, reason in (
            ("zero references", [pull(number=41, body="no reference")], {}, REASON_NO_REFERENCE),
            ("multiple references", [pull(number=41, body="Closes #7, fixes #8")], {},
             REASON_AMBIGUOUS),
            ("a reference to a PR", [pull(number=41, body="Closes #7")],
             {7: issue(pull_request={"url": "x"})}, REASON_REFERENCE_IS_PULL),
            ("a reference to a closed issue", [pull(number=41, body="Closes #7")],
             {7: issue(state="closed")}, REASON_REFERENCE_CLOSED)):
        rec = _Recorder(payloads, issues=issues)
        row = run_row(rec)
        check(f"the sweep refuses {label} and writes NOTHING",
              (row["refused"], row["refusals"], rec.written),
              (1, {reason: 1}, []))
        posted = rec.posted[0] if rec.posted else (None, "")
        check(f"...and the refusal for {label} is VISIBLE on the PR",
              (len(rec.posted), posted[0], refusal_marker(reason) in posted[1]),
              (1, 41, True))

    # THE NEGATED REFERENCE, END TO END THROUGH THE REAL SWEEP. The one fixture shape the negation
    # rule never had: every other negation check stops before `derive_issue_number`, so nothing
    # observed that the ambiguity gate is fed `all_refs` on the production path. This drives a
    # negated body through the real writer and asserts the tick wrote NOTHING.
    negated = _Recorder([pull(number=41, body="Closes #7. This does not close #8.")])
    row = run_row(negated)
    check("the sweep REFUSES a negated-reference PR end to end and writes nothing",
          (row["minted"], row["refused"], row["refusals"], negated.written, negated.handed),
          (0, 1, {REASON_AMBIGUOUS: 1}, [], []))
    check("...and the refusal it posts is the AMBIGUITY one, naming both references",
          total(lambda: (refusal_marker(REASON_AMBIGUOUS) in negated.posted[0][1],
                         "#7" in negated.posted[0][1], "#8" in negated.posted[0][1])),
          (True, True, True))
    # ...and the suppressor really is applied on that path too: a body whose only reference is
    # negated refuses for having NO declaration rather than binding the one it suppressed.
    only_negated = _Recorder([pull(number=41, body="This PR does not close #7.")])
    row = run_row(only_negated)
    check("...while a body whose ONLY reference is negated refuses as un-declared, not by binding",
          (row["minted"], row["refusals"], only_negated.written),
          (0, {REASON_NO_REFERENCE: 1}, []))

    # THE ENROLLED-CLASS FILTER IS AT THE SWEEP'S OWN CALL SITE. `enrolled_class_pulls` is
    # exhaustively unit-tested above, but nothing drove a NON-enrolled author through `sweep`, so
    # dropping the filter there minted provenance for strangers and bots with the suite green — the
    # blast-radius pin #916 deliberately deferred, undone by a one-line edit.
    mixed_authors = _Recorder([pull(number=41, body="Closes #7"),
                               pull(number=42, body="Closes #7", user={"login": "stranger"}),
                               pull(number=43, body="Closes #7",
                                    user={"login": "dependabot[bot]"})])
    row = run_row(mixed_authors)
    check("the sweep counts and mints the ENROLLED class ONLY — a stranger and a bot are neither",
          (row["enrolled_pulls"], row["minted"], mixed_authors.written),
          (1, 1, [("o/r", 41, 7)]))

    # THE REFUSAL COMMENT CARRIES THE DERIVATION'S OWN MESSAGE. Without this, `refuse()` could be
    # handed a constant and every author would get an unactionable comment naming no numbers.
    messaged = _Recorder([pull(number=41, body="it relates to #7 and to #8")])
    run_row(messaged)
    check("the posted comment carries the DERIVATION's message, not a generic one",
          total(lambda: all(token in messaged.posted[0][1]
                            for token in ("#7", "#8", "declares no closing reference"))), True)

    refused_by_shared = _Recorder(
        clean, actions={41: (mint_provenance.ACTION_REFUSE, "the pull request is a DRAFT")})
    row = run_row(refused_by_shared)
    check("a refusal from the SHARED gate is censused and commented too",
          (row["refused"], row["refusals"], len(refused_by_shared.posted)),
          (1, {REASON_MINT_REFUSED: 1}, 1))
    check("...with the shared gate's own reason text, verbatim",
          total(lambda: "the pull request is a DRAFT" in refused_by_shared.posted[0][1]), True)
    # ...and the MACHINE-READABLE row says which situation it was. `mint-refused` covers both "the
    # gate declined this PR" (the lane is working) and "the lane could not run at all", and the
    # reason CODE is identical for the two — so a census carrying only the code cannot tell an
    # operator whether the sweep is healthy or dead. That distinction is the whole operational value
    # of the row, so it is asserted with the two shapes side by side.
    check("...and the census row itself names WHY, not just the reason code",
          row.get("refusal_causes"), {REASON_MINT_REFUSED: ["the pull request is a DRAFT"]})
    outage = run_row(_Recorder(
        clean, actions={41: (mint_provenance.ACTION_REFUSE,
                             "the implementer alias 'opus5' is not in the target's routing "
                             "catalog")}))
    check("...so a working lane declining ONE pr and a lane that cannot run at all are "
          "distinguishable in the JSON, under the SAME reason code",
          (outage.get("refusals"), outage.get("refusal_causes")),
          ({REASON_MINT_REFUSED: 1},
           {REASON_MINT_REFUSED: ["the implementer alias 'opus5' is not in the target's routing "
                                  "catalog"]}))
    many_causes = run_row(_Recorder(
        [pull(number=n, body="Closes #7") for n in range(41, 49)],
        actions={n: (mint_provenance.ACTION_REFUSE, f"distinct cause {n}") for n in range(41, 49)}),
        max_mints=8, max_comments=8)
    check("...and the cause list is BOUNDED, so a census cannot grow with the population",
          total(lambda: (len(many_causes.get("refusal_causes", {}).get(REASON_MINT_REFUSED, [])),
                         many_causes.get("refusals"))),
          (MAX_CENSUS_CAUSES, {REASON_MINT_REFUSED: 8}))
    check("...and each cause is one truncated line, never a multi-line message",
          (refusal_cause("a\nb   c" + "x" * 400), refusal_cause("")),
          ("a b c" + "x" * (CENSUS_CAUSE_CHARS - 5), "(no message)"))

    # The comment is deduped by reason, so a refusal is never a per-tick comment loop.
    dedupe = _Recorder([pull(number=41, body="no reference")],
                       comments={41: [{"body": refusal_comment_body(REASON_NO_REFERENCE, "x")}]})
    row = run_row(dedupe)
    check("an already-commented refusal is censused again but NOT re-commented",
          (row["refused"], row["commented"], dedupe.posted), (1, 0, []))

    comment_capped = _Recorder([pull(number=n, body="no reference") for n in (41, 42, 43)])
    row = run_row(comment_capped, max_comments=2)
    check("COMMENT CAP: refusal comments are bounded per tick too",
          (row["refused"], row["commented"], len(comment_capped.posted)), (3, 2, 2))
    check("...and the un-commented refusals are censused as cap-deferred",
          row["comment_deferred_cap"], 1)

    dry = _Recorder(clean + [pull(number=42, body="no reference")])
    row = run_row(dry, apply_changes=False)
    check("a DRY RUN decides everything and writes NOTHING — no record, no comment",
          (row["minted"], row["refused"], dry.written, dry.posted), (1, 1, [], []))
    check("...and says so in the census", row["apply"], False)

    probe_failed = _Recorder(clean)
    row = run_row(probe_failed, record_boom=True)
    check("an UNREADABLE record probe refuses (never 'nothing is recorded') and writes nothing",
          (row["minted"], row["refusals"], probe_failed.written),
          (0, {REASON_RECORD_PROBE_FAILED: 1}, []))
    check("...and does NOT put a registry-side outage on someone else's PR",
          probe_failed.posted, [])

    foreign = _Recorder(clean)
    row = run_row(foreign, targets=(("other/repo", ("jeswr",)),))
    check("a target this run cannot annotate is SKIPPED, loudly, and swept for nothing",
          (row["targets"], row["enrolled_pulls"], row["skipped_targets"], foreign.written),
          (0, 0, {"other/repo": REASON_TARGET_NOT_ANNOTATABLE}, []))

    empty = _Recorder([])
    row = run_row(empty, targets=())
    check("a tick with no targets STILL emits a census (a silent minter is the failure mode)",
          (row["targets"], row["enrolled_pulls"], row["lacking_record"]), (0, 0, 0))

    # EVERY tick emits a census, INCLUDING the ticks where a reader or the writer blows up. These
    # two paths used to raise straight out of sweep(): the run went red but said NOTHING about what
    # it had done, which is the state requirement 3 exists to prevent.
    def census_fields(thunk, *fields):
        """The named census fields, or the raise that PREVENTED a census — which is the failure
        these two checks exist to catch, so it must red them by name, not abort the run."""
        row = total(thunk)
        if not isinstance(row, dict):
            return ("NO CENSUS EMITTED", row)
        return tuple(row[field] for field in fields)

    unlistable = _Recorder(clean)
    check("a target whose pulls cannot be listed still yields a census, with a named reason",
          census_fields(lambda: unlistable.run(pulls_boom=True),
                        "targets", "enrolled_pulls", "skipped_targets"),
          (0, 0, {"o/r": REASON_TARGET_PULLS_UNREADABLE}))
    failed_write = _Recorder(clean)
    check("a FAILED provenance write still yields a census, as a named refusal",
          census_fields(lambda: failed_write.run(mint_boom=True),
                        "minted", "refused", "refusals") + (failed_write.written,),
          (0, 1, {REASON_MINT_FAILED: 1}, []))
    check("...and does not put a registry-side write failure on someone else's PR",
          failed_write.posted, [])

    # THE SHARED WRITER IS REALLY THE ONE THAT DECIDES: drive `_mint_caller` into the real
    # mint-provenance.mint over an issue that reduces to the serializing __global__ partition. The
    # sweep never passes --allow-global-partition, so this must refuse.
    written = []
    caller = _mint_caller(mint_provenance, "reg/istry", True, lambda *_a, **_k: None,
                          write_record=lambda: written.append("put"))
    env = {"GITHUB_RUN_ID": "555", "GITHUB_RUN_ATTEMPT": "1", "PROVENANCE_SALT": "s"}
    saved = {key: os.environ.get(key) for key in env}
    os.environ.update(env)
    try:
        routing = {"models": {AUTO_IMPL_ALIAS: {"provider": "anthropic"},
                              "sol": {"provider": "openai"}}}
        decision = caller("o/r", 41, 7, routing, ("jeswr",), pull(body="Closes #7"),
                          issue(labels=[]))
        check("the sweep can NEVER accept the serializing __global__ partition",
              (decision.action, "__global__" in decision.reason),
              (mint_provenance.ACTION_REFUSE, True))
        check("...and that refusal writes nothing", written, [])
        good = caller("o/r", 41, 7, routing, ("jeswr",), pull(body="Closes #7"), issue())
        check("...while the ordinary single-area case reaches a real mint decision",
              good.action, mint_provenance.ACTION_MINT)
        check("...and writes exactly one record through the SHARED writer", written, ["put"])
        check("...and the record it writes pins the constant provider and the pinned alias",
              (good.document["impl_provider"], good.document["impl_alias"]),
              (mint_provenance.ORCHESTRATOR_IMPL_PROVIDER, AUTO_IMPL_ALIAS))
        # THE CALLER'S SHAPE, not just its output. `AUTO_IMPL_ALIAS` being a pinned constant is the
        # reason this class cannot choose the provider that reviews it — but the pin lives inside a
        # closure, and nothing observed that the closure takes no alias parameter. Adding one
        # survived every check: the pin still held, and the SHAPE that guarantees it went
        # unasserted. The signature is the guarantee, so the signature is asserted.
        check("...and the bound caller exposes NO lever for the alias or the global partition",
              (sorted(inspect.signature(caller).parameters),
               sorted(inspect.signature(_mint_caller).parameters)),
              (["authors", "issue", "issue_number", "pr_number", "pull", "routing", "target_repo"],
               ["apply_changes", "log", "mint_provenance", "registry_repo", "write_record"]))
        # ...and `read_record` is pinned to None on purpose: the sweep has ALREADY probed for an
        # existing record, and letting the shared writer re-read it would be a second, unsynced
        # opinion on the one question idempotence turns on.
        check("...and the shared writer is told the record probe was already done",
              total(lambda: mint_provenance.mint.__doc__ is not None
                    and "read_record" in inspect.signature(mint_provenance.mint).parameters), True)
        dry = []
        dry_caller = _mint_caller(mint_provenance, "reg/istry", False, lambda *_a, **_k: None,
                                  write_record=lambda: dry.append("put"))
        dry_decision = dry_caller("o/r", 41, 7, routing, ("jeswr",), pull(body="Closes #7"),
                                  issue())
        check("...and `--apply` really reaches the writer: without it, nothing is written",
              (dry_decision.action, dry), (mint_provenance.ACTION_MINT, []))
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    # ---- END TO END: the production `sweep()` into the REAL `mint_provenance.mint()` -------------
    # THE PATH AN INDEPENDENT REVIEW USED TO PROVE THE PREVIOUS HEAD MINTED. At `ba1a6030d`, each of
    # the seven shapes below produced `minted=1 ledger_writes=['LEDGER-PUT'] refused=0` through this
    # exact composition: production `sweep()`, `_mint_caller` bound to the real shared writer, only
    # the ledger PUT stubbed, `apply_changes=True`. The unit rows above assert the derivation; these
    # assert that nothing between the derivation and the ledger can undo it.
    e2e_rows = {label: (title, body) for label, title, body, _e in RENDERED_ORACLE_CORPUS}

    def e2e(label, render=None, pull_over=None):
        """One corpus row, all the way to the (stubbed) ledger PUT. Returns (census, writes, posts)."""
        title, body = e2e_rows.get(label, ("t", "no reference"))
        writes, posts = [], []
        routing = {"models": {AUTO_IMPL_ALIAS: {"provider": "anthropic"},
                              "sol": {"provider": "openai"}}}
        # The TARGET is the oracle's own repository, because these rows are real GitHub renderings
        # captured in its numbering — the `issue-link` hrefs the third conjunct reads point there.
        row = total(lambda: sweep(
            [(ORACLE_CONTEXT_REPO, ("jeswr",))], annotate_repo=ORACLE_CONTEXT_REPO,
            read_routing=lambda _r: routing,
            read_pulls=lambda _r: [pull(number=41, title=title, body=body,
                                        head={"repo": {"full_name": ORACLE_CONTEXT_REPO}},
                                        **(pull_over or {}))],
            read_issue=lambda _r, n: issue(number=n),
            read_record=lambda _r, _n: None,
            mint_pr=_mint_caller(mint_provenance, "reg/istry", True, lambda *_a, **_k: None,
                                 write_record=lambda: writes.append("LEDGER-PUT")),
            read_comments=lambda _r, _n: [],
            post_comment=lambda _r, n, _b: posts.append(n),
            render_markdown=(render or (lambda _r, text: frozen(text))),
            apply_changes=True, log=lambda *_a, **_k: None))
        if not isinstance(row, dict):
            row = _NoCensus(row)
        return row, writes, posts

    e2e_env = {"GITHUB_RUN_ID": "555", "GITHUB_RUN_ATTEMPT": "1", "PROVENANCE_SALT": "s"}
    e2e_saved = {key: os.environ.get(key) for key in e2e_env}
    os.environ.update(e2e_env)
    try:
        # POSITIVE CONTROL FIRST, and it has to be a REAL WRITE. Without it "the seven refuse" is
        # satisfied by a sweep that refuses everything, which is the failure mode a fail-closed
        # redesign is most likely to have.
        row, writes, posts = e2e("plain closes line")
        check("E2E CONTROL — a genuine `Closes #929` mints ONE record through the real shared "
              "writer, and the ledger PUT really happens",
              (row["minted"], row["refused"], writes, posts),
              (1, 0, ["LEDGER-PUT"], []))
        check("...and the census says nothing was refused", row["refusals"], {})
        for label in ("R1 <pre> block", "R2 <pre> then indented",
                      "R3 quoted <pre> then indented", "R4 pipe-less GFM table then indented",
                      "R5 inline HTML <code>", "R6 <details> wrapping <pre>",
                      "R7 <pre class=...>"):
            row, writes, posts = e2e(label)
            check(f"E2E — {label}: minted 1 record at the previous head; now refuses and writes "
                  "NOTHING to the ledger",
                  (row["minted"], row["refused"], row["refusals"], writes),
                  (0, 1, {REASON_NO_REFERENCE: 1}, []))
            check(f"...and the refusal for {label} is VISIBLE on the PR", posts, [41])
        # THE UNKNOWN CASE, end to end. A rendering this file cannot classify must stop at the
        # census, not at the ledger — and it must be its OWN named reason, so an operator can tell
        # "the author quoted it" from "we do not understand this body".
        row, writes, posts = e2e(
            "plain closes line",
            render=lambda _r, _text: "<p>Closes <weird-thing>#929</weird-thing></p>")
        check("E2E UNKNOWN CASE — an unclassified rendered element refuses by its own name and "
              "writes NOTHING",
              (row["minted"], row["refusals"], writes),
              (0, {REASON_BODY_NOT_UNDERSTOOD: 1}, []))
        check("...and the census carries WHICH element, so it is actionable rather than a count",
              any("weird-thing" in cause
                  for cause in row["refusal_causes"].get(REASON_BODY_NOT_UNDERSTOOD, [])), True)
        check("...and it is commented on the PR, because its author can act on it", posts, [41])
        # THE ROUND-7 CLASS, END TO END. `Closes #929abc` minted at the previous head through this
        # exact composition with the LIVE renderer; it must now stop at the census.
        for label in ("right boundary: letter run-on", "right boundary: underscore run-on",
                      "right boundary: non-ASCII letter run-on",
                      "a number that does not exist is not a reference"):
            row, writes, posts = e2e(label)
            check(f"E2E ROUND-7 — {label}: refuses by its own name and writes NOTHING",
                  (row["minted"], row["refusals"], writes),
                  (0, {REASON_REFERENCE_NOT_RESOLVED: 1}, []))
            check(f"...and the refusal for {label} is VISIBLE on the PR", posts, [41])
        # ...and the CONTROLS, because a conjunct that refuses everything would satisfy all four.
        for label in ("right boundary: hyphen", "right boundary: full stop",
                      "an unresolved run-on beside a real declaration still binds the real one"):
            row, writes, _posts = e2e(label)
            check(f"E2E ROUND-7 CONTROL — {label}: still mints, and still writes",
                  (row["minted"], row["refused"], writes), (1, 0, ["LEDGER-PUT"]))

        # THE ROUND-8 CLASS, END TO END, AND THE ONE-CHARACTER PAIR. These two rows differ by a
        # single `> ` and differed in OUTCOME at the previous head: the quoted one refused, the
        # unquoted one MINTED. Driven together so a regression in either direction shows up as the
        # pair disagreeing rather than as one silent row.
        for label in ("a quoted anchor cannot resolve a run-on written in prose",
                      "an UNQUOTED unrelated mention cannot resolve a run-on either",
                      "...nor a mention in a table cell",
                      "...nor a mention in the TITLE resolving a run-on in the body",
                      "...nor a run-on in the TITLE resolved by a mention in the body"):
            row, writes, _posts = e2e(label)
            check(f"E2E ROUND-8 — {label}: an unrelated anchor does not resolve it, and NOTHING "
                  "reaches the ledger",
                  (row["minted"], row["refusals"], writes),
                  (0, {REASON_REFERENCE_NOT_RESOLVED: 1}, []))
        for label in ("a real declaration beside a run-on still binds",
                      "...and a real declaration in the TITLE beside a run-on in the body"):
            row, writes, _posts = e2e(label)
            check(f"E2E ROUND-8 CONTROL — {label}: still mints, and still writes",
                  (row["minted"], row["refused"], writes), (1, 0, ["LEDGER-PUT"]))

        # THE RENDERER OUTAGE, end to end. Fail closed, censused, NOT commented.
        def _down(_repo, _text):
            raise RenderUnavailable("GitHub's markdown renderer returned 22")

        row, writes, posts = e2e("plain closes line", render=_down)
        check("E2E RENDERER OUTAGE — the SAME body that mints when the renderer answers writes "
              "NOTHING when it does not; there is no raw-markdown fallback",
              (row["minted"], row["refusals"], writes),
              (0, {REASON_RENDER_UNAVAILABLE: 1}, []))
        check("...and a platform outage is not posted onto someone else's PR forever", posts, [])
    finally:
        for key, value in e2e_saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    # ---- main(): THE PRODUCTION CALL SITE, argument by argument ---------------------------------
    # WHY THIS BLOCK EXISTS. Round 2 blocked on "a value pinned through a pure helper while the call
    # site independently re-wires it"; the repair swept `sweep()`'s call sites and STOPPED THERE.
    # `main()` is the call site above those, and it was at 0% line coverage — 26 body lines that no
    # check reached. MEASURED: 13 one-line edits inside it survived the whole suite. The worst is
    # not subtle: passing `True` instead of `args.apply` makes a manual dispatch advertised as a
    # census-only preview WRITE REAL LEDGER RECORDS, and `--apply` is the entire safety story of an
    # unattended writer.
    #
    # So `main()` is driven here with a patched argv and recorders in place of the six readers, the
    # writer factory and `sweep` itself, and every argument it forwards is read back off the
    # recorded call. Coverage is the instrument that found this, and it is cheaper than mutation
    # testing: run it, list every function at 0%, and drive those first.
    def main_call(argv, policy=None, targets_authors=("jeswr",), step_summary=None):
        """Run the real `main()` with recorders installed. Returns what it forwarded.

        GITHUB_STEP_SUMMARY IS PINNED, always. In Actions that variable is set, and `main()`
        legitimately appends the census to whatever it points at — so a fixture that leaves it alone
        writes one `### auto-mint` block into the REAL job summary per call, ten per run, on a green
        gate. The env is a shared resource in the harness exactly as it is in production."""
        seen = {}

        def fake_sweep(targets, **kwargs):
            seen["targets"] = targets
            seen.update(kwargs)
            return census_row(new_counters(mint_cap=kwargs["max_mints"],
                                          comment_cap=kwargs["max_comments"],
                                          apply_changes=kwargs["apply_changes"]))

        def fake_mint_caller(mp, registry_repo, apply_changes, log, write_record=None):
            seen["mint_caller_args"] = (registry_repo, apply_changes)
            return lambda *a, **k: None

        def fake_gh_readers(mp, registry_repo):
            seen["gh_readers_repo"] = registry_repo
            return tuple(f"reader-{name}" for name in
                         ("routing", "pulls", "issue", "record", "comments", "post", "render"))

        doc = policy if policy is not None else {
            "repos": {"o/r": {"enabled": True, "review_enrolment_authors": list(targets_authors)}}}
        patches = {
            "sweep": fake_sweep, "_mint_caller": fake_mint_caller,
            "_gh_readers": fake_gh_readers, "_read_policy": lambda: doc,
            "_load_mint_provenance": lambda: mint_provenance,
            "_load_policy_resolve": lambda: type("P", (), {
                "review_enrolment_authors": staticmethod(
                    lambda name, d: (d["repos"][name].get("review_enrolment_authors") or []))})(),
        }
        saved_globals = {name: globals()[name] for name in patches}
        saved_argv, saved_stderr = sys.argv[:], sys.stderr
        saved_summary = os.environ.get("GITHUB_STEP_SUMMARY")
        globals().update(patches)
        sys.argv = ["auto-mint-provenance.py", *argv]
        if step_summary is None:
            os.environ.pop("GITHUB_STEP_SUMMARY", None)
        else:
            os.environ["GITHUB_STEP_SUMMARY"] = str(step_summary)
        # argparse prints usage to stderr on a refusal; swallow it so a PASSING run's log stays
        # readable, and assert the exit code instead of scraping the text.
        sys.stderr = io.StringIO()
        try:
            seen["returned"] = main()
        except SystemExit as exc:                     # argparse refusals are a legitimate outcome
            seen["exit"] = exc.code
        finally:
            globals().update(saved_globals)
            sys.argv, sys.stderr = saved_argv, saved_stderr
            if saved_summary is None:
                os.environ.pop("GITHUB_STEP_SUMMARY", None)
            else:
                os.environ["GITHUB_STEP_SUMMARY"] = saved_summary
        return seen

    def fwd(seen, *keys):
        """What main() forwarded, or a NAMED marker per missing key.

        A mutant that stops calling `sweep` (or drops a keyword) must red a check, not raise a
        KeyError from inside the assertion and abort every later check with it."""
        got = tuple(seen.get(key, "NOT-FORWARDED") for key in keys)
        return got[0] if len(keys) == 1 else got

    ran = main_call(["--registry-repo", "o/r", "--annotate-repo", "o/r"])
    check("main() forwards the DRY RUN by default — apply_changes is args.apply, not True",
          fwd(ran, "apply_changes"), False)
    check("...and the WRITER is built dry too, which is the whole meaning of --apply",
          fwd(ran, "mint_caller_args"), ("o/r", False))
    check("...and the caps it forwards are the parsed arguments' defaults",
          fwd(ran, "max_mints", "max_comments"), (DEFAULT_MAX_MINTS, DEFAULT_MAX_COMMENTS))
    check("...and --annotate-repo reaches the sweep as given", fwd(ran, "annotate_repo"), "o/r")
    check("...and the readers are the ones _gh_readers built for THIS registry",
          fwd(ran, "gh_readers_repo", "read_routing", "post_comment"),
          ("o/r", "reader-routing", "reader-post"))
    # ...INCLUDING the renderer. `sweep()` takes it keyword-only, so dropping it here is a
    # TypeError in production — but the harness's `sweep` stand-in takes `**kwargs`, which is
    # exactly the shape that lets a dropped keyword go unobserved. MEASURED: deleting this
    # forwarding survived the whole suite before this row existed.
    check("...and the RENDERER, without which there is no derivation at all",
          fwd(ran, "render_markdown"), "reader-render")
    check("...and the population comes from the master-protected enrolment authority",
          fwd(ran, "targets"), [("o/r", ("jeswr",))])
    check("...and a clean run returns 0", fwd(ran, "returned"), 0)

    applied = main_call(["--registry-repo", "o/r", "--annotate-repo", "o/r", "--apply"])
    check("--apply reaches BOTH the writer factory and the comment switch, together",
          fwd(applied, "mint_caller_args", "apply_changes"), (("o/r", True), True))

    capped = main_call(["--registry-repo", "o/r", "--annotate-repo", "o/r",
                        "--max-mints", "1", "--max-comments", "2"])
    check("the per-tick caps main() forwards are the OPERATOR's, not constants",
          fwd(capped, "max_mints", "max_comments"), (1, 2))

    other = main_call(["--registry-repo", "reg/istry", "--annotate-repo", "other/repo"])
    check("...and --registry-repo and --annotate-repo are DISTINCT arguments, not one value",
          total(lambda: (other["gh_readers_repo"], other["mint_caller_args"][0],
                         other["annotate_repo"])),
          ("reg/istry", "reg/istry", "other/repo"))

    check("a run enrolling NOBODY sweeps nothing rather than defaulting to an author",
          main_call(["--registry-repo", "o/r", "--annotate-repo", "o/r"],
                    policy={"repos": {"o/r": {"enabled": True}}}).get("targets",
                                                                       "NOT-FORWARDED"), [])
    for missing in (["--registry-repo", "o/r"], ["--annotate-repo", "o/r"], []):
        check(f"main() REFUSES rather than guessing when {missing or 'everything'} is all it has",
              main_call(missing).get("exit"), 2)
    check("...and a negative cap is refused rather than silently clamped",
          main_call(["--registry-repo", "o/r", "--annotate-repo", "o/r",
                     "--max-mints", "-1"]).get("exit"), 2)

    # THE OPERATOR-VISIBLE OUTPUT. The census reaches the job summary, which is where a human
    # actually reads whether the tick did anything; a run that decides correctly and reports nowhere
    # is the silent-minter failure mode in another costume.
    # The probes go to a REAL temporary directory, not into `.git`. In a `git worktree` checkout
    # `.git` is a FILE, so the old location made --self-test die with `NotADirectoryError` before it
    # reached a single check — a red baseline for any reviewer following the house instruction to
    # work in an isolated worktree, which is exactly who this suite most needs to serve.
    probe_dir = Path(tempfile.mkdtemp(prefix="auto-mint-probe-"))
    summary_path = probe_dir / "summary"
    try:
        main_call(["--registry-repo", "o/r", "--annotate-repo", "o/r"],
                  step_summary=summary_path)
        written_summary = summary_path.read_text(encoding="utf-8") if summary_path.exists() else ""
    finally:
        summary_path.unlink(missing_ok=True)
    # ...and the fixtures must not write into the job summary the ENVIRONMENT already set. In
    # Actions GITHUB_STEP_SUMMARY is always set, so an unpinned fixture appends one `### auto-mint`
    # block to the REAL summary per call — measured at 5 per green run before this was pinned.
    leak_path = probe_dir / "leak"
    leak_path.write_text("", encoding="utf-8")
    saved_env = os.environ.get("GITHUB_STEP_SUMMARY")
    os.environ["GITHUB_STEP_SUMMARY"] = str(leak_path)
    try:
        main_call(["--registry-repo", "o/r", "--annotate-repo", "o/r"])
        leaked = leak_path.read_text(encoding="utf-8")
    finally:
        if saved_env is None:
            os.environ.pop("GITHUB_STEP_SUMMARY", None)
        else:
            os.environ["GITHUB_STEP_SUMMARY"] = saved_env
        leak_path.unlink(missing_ok=True)
        shutil.rmtree(probe_dir, ignore_errors=True)
    check("...and a fixture run NEVER appends to the job summary the environment already set",
          leaked, "")

    check("main() writes the census into the job summary an operator actually reads",
          ("### auto-mint" in written_summary, "enrolled_pulls=0" in written_summary), (True, True))

    # ---- _gh_readers: the live endpoints, the pagination, the pointer guard ---------------------
    # Also 0% covered, and the survivors there are severe: reading `pulls/{n}` instead of
    # `issues/{n}` makes every reference resolve as a pull request; reading a FIXED comment thread
    # makes the dedupe miss forever, so a refusal comment is re-posted on every tick; and NOT
    # flattening the paginated list is a TOTAL OUTAGE that censuses as `enrolled_pulls=0` — a
    # fabricated healthy zero, which is the worst failure shape available to this file.
    class _FakeGH:
        """Just enough of mint-provenance to drive `_gh_readers` and record every call."""

        LEDGER_REF = "ledger"

        def __init__(self, payloads=None, render_stdout="<p>rendered</p>", render_returncode=0):
            self.calls, self.posted = [], []
            self.payloads = payloads or {}
            self.render_stdout, self.render_returncode = render_stdout, render_returncode

        def _gh_json(self, argv):
            self.calls.append(list(argv))
            for needle, value in self.payloads.items():
                if any(needle in part for part in argv):
                    return value
            return None

        def _run_gh(self, argv, *, check=True):
            self.posted.append(list(argv))
            # The REAL `_run_gh` returns a CompletedProcess; `render_markdown` reads `.returncode`
            # and `.stdout` off it, so the fake has to be that shape or the render call site is
            # untested. `render_stdout`/`render_returncode` are what a fixture steers.
            return type("R", (), {"returncode": self.render_returncode,
                                  "stdout": self.render_stdout})()

        def _load_worker_pr(self):
            gh = self

            class _WorkerPR:
                LEDGER_REF = "ledger"

                @staticmethod
                def provenance_path(repo, number):
                    return f"provenance/{repo}/{number}.json"

                @staticmethod
                def _probe_registry_file(registry_repo, path, ref=None):
                    gh.calls.append(["probe", registry_repo, path, str(ref)])
                    return None

            return _WorkerPR()

        @staticmethod
        def effective_record_body(probe, ledger_ref):
            return probe(ledger_ref)

    def readers_for(payloads=None, policy=None, call=None, gh_kwargs=None):
        """Build the real readers over a fake gh, and run `call(readers)` WHILE the policy patch is
        still installed.

        The patch has to outlive the build, and that is not a detail: `read_routing` calls
        `_read_policy()` at CALL time, so an earlier version of this helper that restored the global
        in a `finally` around the build alone left every pointer fixture refusing for the wrong
        reason — "the policy row carries no routing pointer" from the LIVE policy, which has no
        `o/r` row at all. Those checks passed, and would have passed with the traversal guard
        deleted. Asserting the guard's own reason is what makes them mean anything."""
        fake = _FakeGH(payloads, **(gh_kwargs or {}))
        saved_policy = globals()["_read_policy"]
        globals()["_read_policy"] = lambda: (
            policy if policy is not None
            else {"repos": {"o/r": {"routing": "orchestration/routing.toml"}}})
        try:
            readers = _gh_readers(fake, "reg/istry")
            if call is None:
                return fake, readers, None
            try:
                return fake, readers, call(readers)
            except Exception as exc:              # noqa: BLE001 — the raise IS the observation
                # The MESSAGE, not just the type. Asserting the type alone let a mutant that
                # refused for an unrelated reason (without fetching) satisfy the row, because the
                # reason was being read from a SEPARATE call to the pure predicate rather than
                # from the raise the call site actually produced.
                return fake, readers, ("RAISED", type(exc).__name__, str(exc))
        finally:
            globals()["_read_policy"] = saved_policy

    fake, _built, _ = readers_for(
        payloads={"pulls?state=open": [[{"number": 41}, {"number": 42}], [{"number": 43}]],
                  "/comments": [[{"body": "a"}], [{"body": "b"}]]})
    check("_gh_readers returns exactly the seven readers the sweep's signature needs",
          total(lambda: len(_built)), 7)
    r_routing, r_pulls, r_issue, r_record, r_comments, r_post, r_render = (
        list(_built) + [lambda *a, **k: "MISSING-READER"] * 7)[:7]
    check("read_pulls FLATTENS the paginated slurp — an unflattened page list would make the "
          "population silently EMPTY while the census reported enrolled_pulls=0",
          total(lambda: [row["number"] for row in r_pulls("o/r")]), [41, 42, 43])
    check("...and it asks for OPEN pulls, paginated, from the target",
          total(lambda: any("--paginate" in c
                            and any("repos/o/r/pulls?state=open&per_page=100" in p for p in c)
                            for c in fake.calls)), True)
    check("read_comments flattens its pages too",
          total(lambda: [row["body"] for row in r_comments("o/r", 41)]), ["a", "b"])
    check("...and reads the comments of THE PR IT WAS ASKED ABOUT, not a fixed thread",
          total(lambda: any(any("repos/o/r/issues/41/comments" in p for p in c)
                            for c in fake.calls)), True)
    fake.calls.clear()
    r_issue("o/r", 7)
    check("read_issue reads the ISSUES endpoint — a `pulls/{n}` edit would make every reference "
          "resolve as a pull request",
          total(lambda: fake.calls), [["api", "repos/o/r/issues/7"]])
    fake.calls.clear()
    r_record("o/r", 41)
    check("read_record probes the REGISTRY's own provenance path on the ledger ref",
          total(lambda: fake.calls), [["probe", "reg/istry", "provenance/o/r/41.json", "ledger"]])
    r_post("o/r", 41, "the refusal body")
    check("post_comment posts the body it was GIVEN, to that PR",
          total(lambda: (fake.posted[0][:5], "-f" in fake.posted[0],
                         "body=the refusal body" in fake.posted[0])),
          (["api", "-X", "POST", "repos/o/r/issues/41/comments", "-f"], True, True))

    # THE PATH-TRAVERSAL GUARD, at its ONLY call site. The predicate has an exhaustive fixture table
    # above; nothing observed that `read_routing` actually consults it.
    #
    # THE DISCRIMINATOR IS THE RAISE'S OWN MESSAGE, read off the call site. An earlier one paired
    # "it refused without fetching" with a reason taken from a SEPARATE call to the pure predicate —
    # so a mutant that refused for an unrelated reason, and still did not fetch, satisfied the row.
    # The reason now has to come out of the exception `read_routing` itself raised.
    for pointer, because in (("../secrets.toml", "escapes the repository root"),
                             ("a/../../b", "escapes the repository root"),
                             ("/etc/passwd", "not a relative repository path"),
                             ("C:\\x", "not a relative repository path"),
                             (None, "carries no routing pointer"),
                             ("", "carries no routing pointer")):
        fake, _readers, outcome = readers_for(policy={"repos": {"o/r": {"routing": pointer}}},
                                             call=lambda rs: rs[0]("o/r"))
        raised_kind = outcome[:2] if isinstance(outcome, tuple) else outcome
        raised_says = (because in outcome[2]) if (isinstance(outcome, tuple)
                                                 and len(outcome) > 2) else outcome
        check(f"read_routing REFUSES the routing pointer {pointer!r} instead of fetching it, "
              f"and ITS OWN raise says why: {because!r}",
              (raised_kind, fake.calls, raised_says),
              (("RAISED", "SweepError"), [], True))
    _fake, _readers, parsed = readers_for(
        payloads={"contents/": {"encoding": "base64",
                                "content": base64.b64encode(
                                    b'[models.opus5]\nprovider="anthropic"\n').decode()}},
        call=lambda rs: rs[0]("o/r"))
    check("...while the SHIPPED pointer is fetched and parsed",
          parsed, {"models": {"opus5": {"provider": "anthropic"}}})
    _fake, _readers, refused = readers_for(
        payloads={"contents/": {"encoding": "utf-8", "content": "x"}},
        call=lambda rs: rs[0]("o/r"))
    check("...and a payload that is not a base64 file refuses rather than being trusted, saying so",
          (refused[:2], "did not read back as a base64 file" in refused[2]),
          (("RAISED", "SweepError"), True))

    # ---- render_markdown: the live renderer's own call site --------------------------------------
    # This is the ONE new network dependency the redesign adds, and the whole safety argument rests
    # on two properties of THIS function: what it asks for, and what it does when it does not get it.
    fake, _built, _ = readers_for()
    r_render = list(_built)[6]
    rendered_html = total(lambda: r_render("o/r", "Closes #7"))
    check("render_markdown returns GitHub's rendering verbatim", rendered_html, "<p>rendered</p>")
    posted = fake.posted[0] if fake.posted else []
    check("...asking GitHub's own /markdown endpoint",
          posted[:4], ["api", "-X", "POST", "/markdown"])
    check("...in GFM mode, because a pull-request body is GFM and plain `markdown` renders "
          "tables, task lists and strikethrough differently",
          "mode=gfm" in posted, True)
    check("...with the TARGET repository as the context, which is what makes GitHub mark a "
          "reference it RESOLVED with the `issue-link` class the prose extractor reads",
          "context=o/r" in posted, True)
    check("...and it sends the document it was given", "text=Closes #7" in posted, True)
    # FAIL CLOSED. A non-zero exit must become `RenderUnavailable` — never an empty string (which
    # would derive nothing for the WRONG reason) and never a fall back to the raw markdown (which
    # is the permissive derivation this redesign deleted).
    fake_down, built_down, _ = readers_for(gh_kwargs={"render_returncode": 22,
                                                      "render_stdout": ""})
    check("RENDERER OUTAGE — a non-zero `gh` exit raises RenderUnavailable rather than returning "
          "an empty rendering",
          total(lambda: list(built_down)[6]("o/r", "Closes #7"))[:2],
          ("RAISED", "RenderUnavailable"))

    # ---- sweep()'s two remaining uncovered branches ---------------------------------------------
    routing_boom = _Recorder(clean)
    check("an UNREADABLE routing catalog SKIPS the target with a named reason and still "
          "emits a census — it must never raise out of the tick",
          census_fields(lambda: routing_boom.run(routing_boom=True),
                        "targets", "enrolled_pulls", "skipped_targets") + (routing_boom.written,),
          (0, 0, {"o/r": REASON_TARGET_ROUTING_UNREADABLE}, []))
    annotate_boom = _Recorder([pull(number=41, body="no reference")])
    row = run_row(annotate_boom, comments_boom=True)
    check("a refusal whose ANNOTATION fails is still censused, and the tick continues",
          (row["refused"], row["refusals"], annotate_boom.written),
          (1, {REASON_NO_REFERENCE: 1}, []))

    # ---- THE CAPS: the VALUES, not only the mechanism -------------------------------------------
    # `M13`/`M26` taught this the hard way twice over: deleting each cap CHECK reds by name, but
    # raising DEFAULT_MAX_MINTS from 3 to 50 left the suite green with 0 FAILs. The workflow passes
    # no override, so that constant IS the live bound on how many records one unattended tick may
    # write to the ledger — an unpinned number deciding a write budget is worth a red test on its
    # own terms, independently of whether any adversary can reach it.
    check("the per-tick MINT cap is 3 — the live bound on ledger writes per tick, not a default",
          DEFAULT_MAX_MINTS, 3)
    check("...and the per-tick COMMENT cap is 5", DEFAULT_MAX_COMMENTS, 5)
    check("...and both are small enough that one bad tick is a handful of records a human can read",
          (DEFAULT_MAX_MINTS <= 5, DEFAULT_MAX_COMMENTS <= 10), (True, True))
    check("...and main() defaults to exactly those constants, so the CLI cannot drift from them",
          (inspect.signature(sweep).parameters["max_mints"].default,
           inspect.signature(sweep).parameters["max_comments"].default),
          (DEFAULT_MAX_MINTS, DEFAULT_MAX_COMMENTS))
    # SELF-IDENTIFICATION is a standing repository rule and this file posts to PUBLIC pull
    # requests. `M31` (replacing SELF_ID with a bare string) survived a green suite.
    check("every refusal comment self-identifies as a SPARQ agent, with the bot glyph and the "
          "issue it answers to",
          (SELF_ID.startswith("> "), "🤖" in SELF_ID, "SPARQ agent" in SELF_ID,
           "auto-mint" in SELF_ID, "#929" in SELF_ID), (True,) * 5)

    # ---- the workflow seam ----------------------------------------------------------------------
    seam = sweep_workflow_seam_report()
    check("the workflow passes NO cap override, so DEFAULT_MAX_MINTS is the live write budget",
          (seam["no_cap_argument"], seam["no_cap_input"]), (True, True))
    check("THE #929 FIX: the sweep is SELF-STARTING (mint-provenance.yml is dispatch-only)",
          bool(seam["schedule_crons"]), True)
    check("...on the explicit-minute cadence this repo uses", seam["schedule_crons"],
          ["13,43 * * * *"])
    check("the sweep job refuses to run off the default ref on a DISPATCH",
          seam["job_ref_guarded"], True)
    check("...while the cron tick is carved out, so the guard can never silently skip it",
          seam["job_schedule_carveout"], True)
    check("the sweep job takes the secret-scoped environment", seam["job_environment"],
          "dispatch-secrets")
    check("the sweep job may write ledger contents", seam["contents_write"], "write")
    check("the sweep job may comment the refusal ON the PR", seam["pull_requests_write"], "write")
    check("the sweep job may NOT read run logs (that is backfill's identity source)",
          seam["no_actions_permission"], True)
    check("the sweep is actually invoked", seam["sweep_invoked"], True)
    check("...against THIS registry, and commenting only on THIS repository",
          (seam["registry_repo_argument"], seam["annotate_repo_argument"]), (True, True))
    check("...and the workflow cannot override the per-tick caps", seam["no_cap_override"], True)
    check("the checkout persists no credentials", seam["checkout_persist_credentials"], False)
    check("the sweep step is unconditional", seam["step_unconditional"], True)
    check("the sweep step is errexit", seam["errexit"], True)
    check("the self-test runs BEFORE the sweep", seam["self_test_before_sweep"], True)
    check("--apply is conditional on its own input", seam["apply_is_conditional"], True)
    check("a MANUAL dispatch defaults to a dry run", seam["dispatch_default_is_dry_run"], False)
    check("no input or env names the implementing alias (the reviewer side is not choosable)",
          seam["no_alias_input"], True)
    check("no argument names it either — nor the global-partition override",
          seam["no_alias_argument"], True)
    check("no input or env names a run key / attestation class", seam["no_run_key_input"], True)
    check("no argument names one either", seam["no_run_key_argument"], True)
    check("every env name is bound to its OWN expression, and there are no others",
          seam["step_env_bindings"], {
              "GH_TOKEN": "${{ github.token }}",
              "PROVENANCE_SALT": "${{ secrets.PROVENANCE_SALT }}",
              "REGISTRY_REPO": "${{ github.repository }}",
              "APPLY": "${{ github.event_name != 'workflow_dispatch' || inputs.apply }}",
          })

    # ---- the YAML-seam MUTANT TABLE -------------------------------------------------------------
    # Asserting the happy path proves the report can read a correct workflow, not that it would
    # catch a broken one. Every mutant is a real way this workflow could be neutered — the `if:`,
    # the STEP, the CALL SITE and the TRIGGER — and each must flip a NAMED finding. Three survive
    # only as a COMMENT, the exact shape a raw-text grep passes.
    def mutated(edit):
        doc = copy.deepcopy(_workflow("auto-mint-provenance.yml"))
        edit(doc)
        return sweep_workflow_seam_report(doc)

    def sweep_step(doc):
        return next(s for s in doc["jobs"]["sweep"]["steps"]
                    if "auto-mint-provenance.py" in str(s.get("run") or ""))

    def comment_out_line(doc, fragment):
        step = sweep_step(doc)
        lines = str(step["run"]).splitlines()
        hits = [i for i, line in enumerate(lines) if fragment in line]
        assert hits, f"seam mutant fragment not present: {fragment!r}"
        for i in hits:
            lines[i] = "# " + lines[i].lstrip()
        step["run"] = "\n".join(lines) + "\n"

    def triggers_of(doc):
        return doc.get("on") if "on" in doc else doc.get(True)

    for name, edit, key, want in (
            # THE CALL-SITE/TRIGGER MUTANT this issue exists for.
            ("the schedule is deleted (back to dispatch-only, the #929 defect)",
             lambda d: triggers_of(d).pop("schedule"), "schedule_crons", []),
            ("the job is neutered with if: false",
             lambda d: d["jobs"]["sweep"].update(**{"if": "false"}), "job_ref_guarded", False),
            ("the default-ref guard is deleted",
             lambda d: d["jobs"]["sweep"].pop("if"), "job_ref_guarded", False),
            ("the schedule carve-out is deleted (the cron can then silently skip)",
             lambda d: d["jobs"]["sweep"].update(**{
                 "if": "${{ github.ref == format('refs/heads/{0}', "
                       "github.event.repository.default_branch) }}"}),
             "job_schedule_carveout", False),
            ("...or widened to another event",
             lambda d: d["jobs"]["sweep"].update(**{
                 "if": str(d["jobs"]["sweep"]["if"]).replace("github.event_name == 'schedule'",
                                                             "github.event_name != ''")}),
             "job_schedule_carveout", False),
            ("the secret-scoped environment is dropped",
             lambda d: d["jobs"]["sweep"].pop("environment"), "job_environment", None),
            ("pull-requests: write is dropped (refusals go silent again)",
             lambda d: d["jobs"]["sweep"]["permissions"].pop("pull-requests"),
             "pull_requests_write", None),
            ("actions: read is granted (backfill's identity source)",
             lambda d: d["jobs"]["sweep"]["permissions"].update(actions="read"),
             "no_actions_permission", False),
            ("the sweep step is made conditional",
             lambda d: sweep_step(d).update(**{"if": "false"}), "step_unconditional", False),
            ("an operator-supplied impl_alias input appears",
             lambda d: triggers_of(d)["workflow_dispatch"]["inputs"].update(
                 impl_alias={"type": "string"}), "no_alias_input", False),
            ("an --impl-alias argument appears",
             lambda d: sweep_step(d).update(run=str(sweep_step(d)["run"]) + "  --impl-alias sol\n"),
             "no_alias_argument", False),
            ("an --allow-global-partition argument appears",
             lambda d: sweep_step(d).update(
                 run=str(sweep_step(d)["run"]) + "  --allow-global-partition\n"),
             "no_alias_argument", False),
            ("an operator-supplied run key input appears",
             lambda d: triggers_of(d)["workflow_dispatch"]["inputs"].update(
                 run_key={"type": "string"}), "no_run_key_input", False),
            ("an --attestation argument appears",
             lambda d: sweep_step(d).update(
                 run=str(sweep_step(d)["run"]) + "  --attestation x\n"),
             "no_run_key_argument", False),
            ("--annotate-repo is rebound to another repository",
             lambda d: sweep_step(d).update(run=str(sweep_step(d)["run"]).replace(
                 '--annotate-repo "$REGISTRY_REPO"', '--annotate-repo "sparq-org/sparq"')),
             "annotate_repo_argument", False),
            ("--registry-repo is rebound",
             lambda d: sweep_step(d).update(run=str(sweep_step(d)["run"]).replace(
                 '--registry-repo "$REGISTRY_REPO"', '--registry-repo "other/reg"')),
             "registry_repo_argument", False),
            ("the mint cap is raised at the call site",
             lambda d: sweep_step(d).update(
                 run=str(sweep_step(d)["run"]) + "  --max-mints 100\n"),
             "no_cap_override", False),
            ("the comment cap is raised at the call site",
             lambda d: sweep_step(d).update(
                 run=str(sweep_step(d)["run"]) + "  --max-comments 100\n"),
             "no_cap_override", False),
            ("the checkout persists its token",
             lambda d: next(s for s in d["jobs"]["sweep"]["steps"]
                            if "actions/checkout" in str(s.get("uses") or ""))["with"].update(
                                **{"persist-credentials": True}),
             "checkout_persist_credentials", True),
            ("the manual-dispatch default flips to apply=true",
             lambda d: triggers_of(d)["workflow_dispatch"]["inputs"]["apply"].update(default=True),
             "dispatch_default_is_dry_run", True),
            # COMMENT-ONLY mutants: the token stays in the text, the CODE is gone.
            ("the sweep INVOCATION survives only as a comment",
             lambda d: comment_out_line(d, 'auto-mint-provenance.py "${args[@]}"'),
             "sweep_invoked", False),
            ("the self-test invocation survives only as a comment",
             lambda d: comment_out_line(d, "auto-mint-provenance.py --self-test"),
             "self_test_before_sweep", False),
            ("the --apply conditional survives only as a comment",
             lambda d: comment_out_line(d, "args+=(--apply)"), "apply_is_conditional", False),
            ("set -euo pipefail survives only as a comment",
             lambda d: comment_out_line(d, "set -euo pipefail"), "errexit", False)):
        check(f"YAML-seam mutant reds: {name}", mutated(edit)[key], want)
    # The wrong-input seam needs a value comparison rather than a boolean: rebinding APPLY to a
    # constant is valid YAML, lints clean, and silently turns every manual dry run into a write.
    check("YAML-seam mutant reds: APPLY is rebound to an unconditional true",
          mutated(lambda d: sweep_step(d)["env"].update(APPLY="true"))["step_env_bindings"]["APPLY"],
          "true")
    check("YAML-seam mutant reds: a NEW env binding is as red as a rebound one",
          "IMPL_ALIAS" in mutated(
              lambda d: sweep_step(d)["env"].update(IMPL_ALIAS="sol"))["step_env_bindings"], True)
    # ...and the control: a RAW-TEXT search WOULD have passed the comment-only mutants, which is
    # why the comment stripper is load-bearing rather than tidy.

    def raw_run(edit):
        doc = copy.deepcopy(_workflow("auto-mint-provenance.yml"))
        edit(doc)
        return str(sweep_step(doc)["run"])

    check("...and a raw-text grep WOULD have passed the commented-out invocation",
          'auto-mint-provenance.py "${args[@]}"' in raw_run(
              lambda d: comment_out_line(d, 'auto-mint-provenance.py "${args[@]}"')), True)

    print("auto-mint-provenance self-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def _live_routing():
    """This repository's OWN routing catalog, read from the checkout. Used only by --self-test, to
    prove the pinned alias still resolves to the pinned provider."""
    import tomllib

    with open(SCRIPTS_DIR.parent / "orchestration" / "routing.toml", "rb") as handle:
        return tomllib.load(handle)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--refresh-rendered-oracle", action="store_true",
                        help="re-render every --self-test corpus document against the LIVE GitHub "
                             "renderer and rewrite scripts/fixtures/auto-mint-provenance/"
                             "rendered-oracle.json. Never run on the sweep path; it writes a "
                             "checked-in fixture and needs a token that can POST /markdown")
    parser.add_argument("--registry-repo", help="owner/name of THIS registry repository")
    parser.add_argument("--annotate-repo",
                        help="the ONLY repository whose pull requests this run may comment on; a "
                             "target it cannot annotate is skipped rather than swept silently")
    parser.add_argument("--max-mints", type=int, default=DEFAULT_MAX_MINTS,
                        help=f"records this tick may write (default {DEFAULT_MAX_MINTS})")
    parser.add_argument("--max-comments", type=int, default=DEFAULT_MAX_COMMENTS,
                        help=f"refusal comments this tick may post "
                             f"(default {DEFAULT_MAX_COMMENTS})")
    parser.add_argument("--apply", action="store_true",
                        help="write the records and post the refusal comments (default: dry run)")
    args = parser.parse_args()
    if args.refresh_rendered_oracle:
        mint_provenance = _load_mint_provenance()

        def _render(text):
            result = mint_provenance._run_gh(
                ["api", "-X", "POST", "/markdown", "-f", f"text={text}", "-f", "mode=gfm",
                 "-f", f"context={ORACLE_CONTEXT_REPO}"], check=False)
            if result.returncode != 0:
                raise SweepError(f"the renderer returned {result.returncode}")
            return result.stdout

        print(f"frozen documents: {_refresh_rendered_oracle(_render)}")
        return 0
    if args.self_test:
        return _self_test()
    missing = [name for name in ("registry_repo", "annotate_repo") if not getattr(args, name)]
    if missing:
        parser.error("missing required argument(s): "
                     + ", ".join("--" + name.replace("_", "-") for name in missing))
    if args.max_mints < 0 or args.max_comments < 0:
        parser.error("--max-mints and --max-comments must be non-negative")
    mint_provenance = _load_mint_provenance()
    policy_resolve = _load_policy_resolve()
    targets = enrolled_targets(_read_policy(), policy_resolve.review_enrolment_authors)
    readers = _gh_readers(mint_provenance, args.registry_repo)
    (read_routing, read_pulls, read_issue, read_record, read_comments, post_comment,
     render_markdown) = readers
    row = sweep(targets, annotate_repo=args.annotate_repo, read_routing=read_routing,
                read_pulls=read_pulls, read_issue=read_issue, read_record=read_record,
                mint_pr=_mint_caller(mint_provenance, args.registry_repo, args.apply,
                                     lambda line: print(f"  mint: {line}")),
                read_comments=read_comments, post_comment=post_comment,
                render_markdown=render_markdown,
                apply_changes=args.apply, max_mints=args.max_mints,
                max_comments=args.max_comments)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(f"### auto-mint\n\n```\n{format_census(row)}\n```\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SweepError as exc:
        print(f"::error::{exc}")
        sys.exit(1)
