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

There is NO fallback. A wrong `issue_number` is worse than no mint.

REFUSALS ARE VISIBLE ON THE PR, not only in a run log: an orchestrator-class PR that cannot be
minted is invisible to the review lane again, which is the exact state #916 exists to end. One
comment per PR per distinct reason, ever (marker-deduped) — never a per-tick refusal loop.

AND EVERY TICK EMITS A CENSUS, whatever happens. A silent auto-minter is worse than a manual one,
because nobody notices when it stops.
"""

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from typing import NamedTuple

SCRIPTS_DIR = Path(__file__).resolve().parent


class SweepError(RuntimeError):
    """A concise, credential-free operational error."""


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
CLOSING_REF_RE = re.compile(
    r"(?<![0-9A-Za-z_-])(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\b[ \t]*:?[ \t]*"
    r"#([0-9]+)(?![0-9])",
    re.IGNORECASE)

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

# ---- the refusal taxonomy ----------------------------------------------------------------------
REASON_NO_REFERENCE = "no-issue-reference"
REASON_AMBIGUOUS = "ambiguous-issue-reference"
REASON_REFERENCE_IS_PULL = "reference-is-a-pull-request"
REASON_REFERENCE_CLOSED = "reference-is-closed"
REASON_ISSUE_UNREADABLE = "source-issue-unreadable"
REASON_MINT_REFUSED = "mint-refused"
REASON_RECORD_PROBE_FAILED = "record-probe-failed"

PR_REFUSAL_REASONS = (
    REASON_NO_REFERENCE,
    REASON_AMBIGUOUS,
    REASON_REFERENCE_IS_PULL,
    REASON_REFERENCE_CLOSED,
    REASON_ISSUE_UNREADABLE,
    REASON_MINT_REFUSED,
    REASON_RECORD_PROBE_FAILED,
)

# The ONE refusal that is censused but NOT commented on the PR. A registry-side probe failure is a
# fact about the REGISTRY, not about the pull request: commenting it would put a transient outage
# on someone else's PR, permanently (the comment dedupe is by reason, so it would never be
# retracted). Every OTHER reason is a fact about the PR that its author can act on, so every other
# reason comments. Asserted exactly, in both directions, by --self-test.
SILENT_REASONS = frozenset({REASON_RECORD_PROBE_FAILED})

# Target-level refusal (not a per-PR reason): see target_sweep_refusal.
REASON_TARGET_NOT_ANNOTATABLE = "target-not-annotatable"
REASON_TARGET_ROUTING_UNREADABLE = "target-routing-unreadable"

# The operator's next action, per reason. A refusal comment that does not say what to change is
# just a louder silence.
REASON_HINTS = {
    REASON_NO_REFERENCE:
        "Add exactly one closing reference for the source issue — e.g. a `Closes #1234` line in "
        "the PR description. `Refs #1234` is not a closing reference, and a cross-repository "
        "`owner/repo#1234` names a different lease partition.",
    REASON_AMBIGUOUS:
        "Leave exactly ONE closing reference in the title and body. The others can stay as plain "
        "`#1234` mentions — only the closing keywords (`close/closes/closed`, `fix/fixes/fixed`, "
        "`resolve/resolves/resolved`) are read as the binding.",
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
    REASON_MINT_REFUSED:
        "The record was refused by the shared minting gate; the reason above is verbatim from it. "
        "Nothing was written, so this PR stays exactly as un-enumerated as it is now.",
}

COMMENT_MARKER_PREFIX = "<!-- auto-mint-provenance:refusal:"
SELF_ID = "> 🤖 **SPARQ agent** — auto-mint (registry #929)"


class DerivedIssue(NamedTuple):
    """The derivation result for ONE pull request. Exactly one of `number` / `reason` is set."""

    number: int | None
    reason: str | None
    message: str | None
    issue: dict | None


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
def closing_issue_candidates(title, body):
    """The DISTINCT, sorted set of same-repository issue numbers this PR declares it closes.

    Reads the title and the body, exactly like mint-provenance.references_issue reads them, so
    anything this function accepts also satisfies that function's binding requirement."""
    text = f"{title or ''}\n{body or ''}"
    return sorted({int(number) for number in CLOSING_REF_RE.findall(text)})


def mentioned_issue_numbers(title, body):
    """ADVISORY: every same-repository `#N` the PR mentions, sorted, capped. Never a candidate."""
    text = f"{title or ''}\n{body or ''}"
    return sorted({int(number) for number in MENTION_RE.findall(text)})[:MAX_ADVISORY_MENTIONS]


def candidate_refusal(candidates, mentions=()):
    """(reason, message) when the candidate SET cannot name one source issue, else None.

    FAIL CLOSED at cardinality, before anything is read: zero candidates and two candidates are
    distinct defects with distinct fixes, so they are distinct named reasons. There is deliberately
    no tie-break, no "first one wins", and no default. `mentions` only ever reaches the PROSE."""
    if not candidates:
        seen = ", ".join(f"#{number}" for number in mentions)
        aside = (f" It does mention {seen}; if one of those is the source issue, say so with a "
                 "closing keyword." if seen else "")
        return (REASON_NO_REFERENCE,
                "this pull request declares no closing reference to a source issue in its title "
                "or body, so the issue that would decide its review lease partition and its "
                f"human-hold surface cannot be derived.{aside}")
    if len(candidates) > 1:
        named = ", ".join(f"#{number}" for number in candidates)
        return (REASON_AMBIGUOUS,
                f"this pull request declares {len(candidates)} distinct closing references "
                f"({named}); exactly one is needed, because the source issue decides which lease "
                "partition the review reserves and which object a human hold can park")
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


def derive_issue_number(pull, read_issue):
    """The whole `issue_number` derivation for ONE PR. TOTAL: never raises, never guesses.

    `read_issue(number)` is the live read of the single candidate. Any failure of it is a refusal,
    not an exception and emphatically not a fallback."""
    if not isinstance(pull, dict):
        return DerivedIssue(None, REASON_ISSUE_UNREADABLE,
                            "the pull request payload is malformed", None)
    candidates = closing_issue_candidates(pull.get("title"), pull.get("body"))
    refusal = candidate_refusal(
        candidates, mentioned_issue_numbers(pull.get("title"), pull.get("body")))
    if refusal:
        return DerivedIssue(None, refusal[0], refusal[1], None)
    number = candidates[0]
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
    interpolates is either built in this file or is mint-provenance's own concise refusal text."""
    hint = REASON_HINTS.get(reason, "")
    return (
        f"{SELF_ID}\n\n"
        f"**No provenance record could be minted for this PR — `{reason}`.**\n\n"
        f"{str(message).rstrip('.')}.\n\n"
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
        "skipped_targets": {},
        "mint_cap": mint_cap,
        "comment_cap": comment_cap,
        "apply": bool(apply_changes),
    }


# ---- the sweep ---------------------------------------------------------------------------------
def sweep(targets, *, annotate_repo, read_routing, read_pulls, read_issue, read_record, mint_pr,
          read_comments, post_comment, apply_changes=False, max_mints=DEFAULT_MAX_MINTS,
          max_comments=DEFAULT_MAX_COMMENTS, log=print):
    """One tick. Returns the census row; every reader/writer is injectable so --self-test drives
    this exact orchestration — the call sites, not just the predicates."""
    mint_provenance = _load_mint_provenance()
    counters = new_counters(mint_cap=max_mints, comment_cap=max_comments,
                            apply_changes=apply_changes)

    def refuse(repo, pull, reason, message):
        counters["refused"] += 1
        counters["refusals"][reason] = counters["refusals"].get(reason, 0) + 1
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
        counters["targets"] += 1
        pulls = enrolled_class_pulls(read_pulls(target_repo), authors)
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
            derived = derive_issue_number(pull, lambda n, r=target_repo: read_issue(r, n))
            if derived.reason:
                refuse(target_repo, pull, derived.reason, derived.message)
                continue
            if counters["minted"] >= max_mints:
                counters["deferred_cap"] += 1
                log(f"defer {target_repo}#{number}: the per-tick mint cap ({max_mints}) is spent")
                continue
            decision = mint_pr(target_repo, number, derived.number, routing, authors, pull,
                               derived.issue)
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

    return read_routing, read_pulls, read_issue, read_record, read_comments, post_comment


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
    return {
        # THE #929 FINDING: this workflow is self-starting, or it is mint-provenance.yml again.
        "schedule_crons": [str((entry or {}).get("cron")) for entry in schedule
                           if isinstance(entry, dict)],
        # The salt is a secret: a modified branch copy of this workflow must never see it.
        "job_ref_guarded": "github.ref ==" in guard and "default_branch" in guard,
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
        # EVERY env name the step declares, not a chosen subset: ADDING a binding is as red as
        # rebinding one, so a new secret or input cannot be handed to this job unnoticed.
        "step_env_bindings": step_env,
    }


# ---- self-test ---------------------------------------------------------------------------------
def _self_test():                                                       # noqa: C901 - flat asserts
    import copy

    ok = True

    def check(name, got, want):
        nonlocal ok
        if got != want:
            ok = False
            print(f"FAIL {name}: got {got!r}, want {want!r}")
        else:
            print(f"ok   {name}")

    def refuses(name, reason, thunk):
        got = thunk()
        check(name, got[0] if isinstance(got, tuple) else got, reason)

    mint_provenance = _load_mint_provenance()

    # ---- the closing-reference grammar --------------------------------------------------------
    check("a plain Closes line is the candidate",
          closing_issue_candidates("fix: thing", "Closes #869."), [869])
    check("...and the title counts too", closing_issue_candidates("Closes #869 — thing", ""),
          [869])
    # A conventional-commit SCOPE is not a declaration: `fix(#869):` names the area the commit
    # touches. MEASURED — PR #886's title is exactly this shape, and GitHub's own linked-issue
    # resolution takes #869 from its `Closes #869` body line, not from the title scope.
    check("a conventional-commit scope is not a closing reference",
          closing_issue_candidates("fix(#869): emit the marker", ""), [])
    check("...and every documented GitHub closing keyword is read", closing_issue_candidates(
        "", "close #1 closes #2 closed #3 fix #4 fixes #5 fixed #6 resolve #7 resolves #8 "
            "resolved #9"), [1, 2, 3, 4, 5, 6, 7, 8, 9])
    check("...case-insensitively", closing_issue_candidates("", "CLOSES #12"), [12])
    check("...with a colon", closing_issue_candidates("", "Closes: #12"), [12])
    check("the same issue named twice is ONE candidate",
          closing_issue_candidates("fix (#7)", "Closes #7 and fixes #7"), [7])
    # NON-CANDIDATES. Each is a way a body mentions an issue WITHOUT declaring it as the binding.
    check("a bare mention is not a closing reference",
          closing_issue_candidates("", "see #7, related #8"), [])
    check("`Refs #7` is not a closing reference", closing_issue_candidates("", "Refs #7"), [])
    check("a CROSS-REPO closing reference names another lease partition and is not a candidate",
          closing_issue_candidates("", "Fixes sparq-org/sparq#4329"), [])
    check("a keyword inside another word is not a keyword",
          closing_issue_candidates("", "unfixed #7"), [])
    check("`Closes the ... in #7` does not bind #7",
          closing_issue_candidates("", "Closes the composition defect in #7"), [])
    check("a comment anchor is not an issue reference",
          closing_issue_candidates("", "fixes #issuecomment-5096919798"), [])

    # ---- the ADVISORY mention list (prose only; never a candidate) -----------------------------
    check("mentions are collected for the hint", mentioned_issue_numbers("", "see #8 and #7"),
          [7, 8])
    check("...cross-repository mentions are not this repo's numbers",
          mentioned_issue_numbers("", "sparq-org/sparq#4329"), [])
    check("...and the hint is capped",
          len(mentioned_issue_numbers("", " ".join(f"#{n}" for n in range(1, 20)))),
          MAX_ADVISORY_MENTIONS)
    # THE CONTROL that keeps the hint advisory: a body full of mentions and NO closing keyword
    # still derives NOTHING, and still refuses under the SAME reason as a body with no `#` at all.
    check("a body full of mentions still derives nothing",
          derive_issue_number({"title": "t", "body": "#7 #8 #9"}, lambda n: None).number, None)
    check("...under the same reason as a body with no reference at all",
          derive_issue_number({"title": "t", "body": "#7 #8 #9"}, lambda n: None).reason,
          derive_issue_number({"title": "t", "body": "nothing"}, lambda n: None).reason)
    check("...and the hint names them so the author can fix it in one edit",
          all(token in candidate_refusal([], [7, 8])[1] for token in ("#7", "#8")), True)
    check("...while a PR that mentions nothing gets no dangling hint",
          "does mention" in candidate_refusal([], [])[1], False)

    # ---- REFUSAL BRANCH 1/4: zero references --------------------------------------------------
    refuses("ZERO closing references refuse by name", REASON_NO_REFERENCE,
            lambda: candidate_refusal([]))
    # ---- REFUSAL BRANCH 2/4: multiple candidates ----------------------------------------------
    refuses("MULTIPLE closing references refuse by name", REASON_AMBIGUOUS,
            lambda: candidate_refusal([826, 869]))
    check("...and the refusal NAMES the candidates so the author can pick one",
          all(token in candidate_refusal([826, 869])[1] for token in ("#826", "#869")), True)
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
    def derive(body, issue_payload=None, boom=False):
        def read(number):
            if boom:
                raise RuntimeError("HTTP 502")
            return issue_payload if issue_payload is not None else issue(number=number)

        return derive_issue_number(pull(body=body), read)

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
    check("a malformed pull payload refuses rather than raising",
          derive_issue_number(None, lambda n: issue()).reason, REASON_ISSUE_UNREADABLE)

    # ---- the refusal taxonomy + comment --------------------------------------------------------
    check("every per-PR refusal reason is distinct", len(set(PR_REFUSAL_REASONS)),
          len(PR_REFUSAL_REASONS))
    check("exactly ONE reason is censused without a PR comment, and it is the registry-side one",
          sorted(SILENT_REASONS), [REASON_RECORD_PROBE_FAILED])
    check("...and every OTHER reason carries an operator hint to put in that comment",
          sorted(reason for reason in PR_REFUSAL_REASONS
                 if reason not in SILENT_REASONS and not REASON_HINTS.get(reason)), [])
    body = refusal_comment_body(REASON_AMBIGUOUS, "two candidates")
    check("the refusal comment self-identifies", body.startswith(SELF_ID), True)
    check("...names the machine-readable reason", f"`{REASON_AMBIGUOUS}`" in body, True)
    check("...carries the operator's next action", REASON_HINTS[REASON_AMBIGUOUS] in body, True)
    check("...and carries its dedupe marker", refusal_marker(REASON_AMBIGUOUS) in body, True)
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
    check("the sweep's population is EXACTLY the registry, and only `jeswr`",
          live_targets, [("jeswr/agent-account-registry", ("jeswr",))])
    check("...and a disabled row is never a target",
          enrolled_targets({"repos": {"o/r": {"enabled": False,
                                              "review_enrolment_authors": ["x"]}}},
                           lambda name, doc: doc["repos"][name]["review_enrolment_authors"]), [])
    check("...and an enabled row that enrols NOBODY is never a target",
          enrolled_targets({"repos": {"o/r": {"enabled": True}}}, lambda name, doc: []), [])
    check("...while an enabled row that enrols someone IS one",
          enrolled_targets({"repos": {"o/r": {"enabled": True}}}, lambda name, doc: ["a", "B"]),
          [("o/r", ("B", "a"))])

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
            self.written, self.posted = [], []

        def run(self, *, apply_changes=True, max_mints=DEFAULT_MAX_MINTS,
                max_comments=DEFAULT_MAX_COMMENTS, annotate_repo="o/r",
                targets=(("o/r", ("jeswr",)),), record_boom=False):
            def mint_pr(repo, number, issue_number, routing, authors, pl, iss):
                action, reason = self.actions.get(
                    number, (mint_provenance.ACTION_MINT, "no record yet"))
                if action == mint_provenance.ACTION_MINT and apply_changes:
                    self.written.append((repo, number, issue_number))
                return mint_provenance.MintDecision(action, reason, None)

            def read_record(repo, number):
                if record_boom:
                    raise RuntimeError("HTTP 502")
                return self.records.get(number)

            return sweep(
                list(targets), annotate_repo=annotate_repo,
                read_routing=lambda repo: {"models": {AUTO_IMPL_ALIAS:
                                                      {"provider": "anthropic"}}},
                read_pulls=lambda repo: self.pulls, read_issue=lambda repo, n:
                    self.issues.get(n, issue(number=n)),
                read_record=read_record, mint_pr=mint_pr,
                read_comments=lambda repo, n: self.comments.get(n, []),
                post_comment=lambda repo, n, b: self.posted.append((n, b)),
                apply_changes=apply_changes, max_mints=max_mints, max_comments=max_comments,
                log=lambda *_a, **_k: None)

    clean = [pull(number=41, body="Closes #7")]
    rec = _Recorder(clean)
    row = rec.run()
    check("POSITIVE CONTROL: the sweep mints the well-formed PR, once",
          (row["minted"], rec.written), (1, [("o/r", 41, 7)]))
    check("...and the census counts it as lacking a record beforehand", row["lacking_record"], 1)
    check("...and posts no refusal comment", rec.posted, [])

    # IDEMPOTENCE: a second tick over the record the first one wrote is a NO-OP.
    rec2 = _Recorder(clean, records={41: json.dumps({"pr_number": 41})})
    row2 = rec2.run()
    check("IDEMPOTENCE: a PR that already has a record is never re-minted",
          (row2["minted"], row2["with_record"], rec2.written, rec2.posted), (0, 1, [], []))
    # ...and if the record appears BETWEEN the probe and the mint, the shared writer's own
    # create-only verdict still lands as a no-op rather than a write.
    rec3 = _Recorder(clean, actions={41: (mint_provenance.ACTION_ALREADY, "identical")})
    row3 = rec3.run()
    check("...and a race that resolves to `already-minted` writes nothing either",
          (row3["minted"], row3["with_record"], rec3.written), (0, 1, []))

    # THE CAP.
    many = [pull(number=n, body="Closes #7") for n in (41, 42, 43, 44, 45)]
    capped = _Recorder(many)
    row4 = capped.run(max_mints=2)
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
        row = rec.run()
        check(f"the sweep refuses {label} and writes NOTHING",
              (row["refused"], row["refusals"], rec.written),
              (1, {reason: 1}, []))
        check(f"...and the refusal for {label} is VISIBLE on the PR",
              (len(rec.posted), rec.posted[0][0], refusal_marker(reason) in rec.posted[0][1]),
              (1, 41, True))

    refused_by_shared = _Recorder(
        clean, actions={41: (mint_provenance.ACTION_REFUSE, "the pull request is a DRAFT")})
    row = refused_by_shared.run()
    check("a refusal from the SHARED gate is censused and commented too",
          (row["refused"], row["refusals"], len(refused_by_shared.posted)),
          (1, {REASON_MINT_REFUSED: 1}, 1))
    check("...with the shared gate's own reason text, verbatim",
          "the pull request is a DRAFT" in refused_by_shared.posted[0][1], True)

    # The comment is deduped by reason, so a refusal is never a per-tick comment loop.
    dedupe = _Recorder([pull(number=41, body="no reference")],
                       comments={41: [{"body": refusal_comment_body(REASON_NO_REFERENCE, "x")}]})
    row = dedupe.run()
    check("an already-commented refusal is censused again but NOT re-commented",
          (row["refused"], row["commented"], dedupe.posted), (1, 0, []))

    comment_capped = _Recorder([pull(number=n, body="no reference") for n in (41, 42, 43)])
    row = comment_capped.run(max_comments=2)
    check("COMMENT CAP: refusal comments are bounded per tick too",
          (row["refused"], row["commented"], len(comment_capped.posted)), (3, 2, 2))
    check("...and the un-commented refusals are censused as cap-deferred",
          row["comment_deferred_cap"], 1)

    dry = _Recorder(clean + [pull(number=42, body="no reference")])
    row = dry.run(apply_changes=False)
    check("a DRY RUN decides everything and writes NOTHING — no record, no comment",
          (row["minted"], row["refused"], dry.written, dry.posted), (1, 1, [], []))
    check("...and says so in the census", row["apply"], False)

    probe_failed = _Recorder(clean)
    row = probe_failed.run(record_boom=True)
    check("an UNREADABLE record probe refuses (never 'nothing is recorded') and writes nothing",
          (row["minted"], row["refusals"], probe_failed.written),
          (0, {REASON_RECORD_PROBE_FAILED: 1}, []))
    check("...and does NOT put a registry-side outage on someone else's PR",
          probe_failed.posted, [])

    foreign = _Recorder(clean)
    row = foreign.run(targets=(("other/repo", ("jeswr",)),))
    check("a target this run cannot annotate is SKIPPED, loudly, and swept for nothing",
          (row["targets"], row["enrolled_pulls"], row["skipped_targets"], foreign.written),
          (0, 0, {"other/repo": REASON_TARGET_NOT_ANNOTATABLE}, []))

    empty = _Recorder([])
    row = empty.run(targets=())
    check("a tick with no targets STILL emits a census (a silent minter is the failure mode)",
          (row["targets"], row["enrolled_pulls"], row["lacking_record"]), (0, 0, 0))

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

    # ---- the workflow seam ----------------------------------------------------------------------
    seam = sweep_workflow_seam_report()
    check("THE #929 FIX: the sweep is SELF-STARTING (mint-provenance.yml is dispatch-only)",
          bool(seam["schedule_crons"]), True)
    check("...on the explicit-minute cadence this repo uses", seam["schedule_crons"],
          ["13,43 * * * *"])
    check("the sweep job refuses to run off the default ref", seam["job_ref_guarded"], True)
    check("the sweep job takes the secret-scoped environment", seam["job_environment"],
          "dispatch-secrets")
    check("the sweep job may write ledger contents", seam["contents_write"], "write")
    check("the sweep job may comment the refusal ON the PR", seam["pull_requests_write"], "write")
    check("the sweep job may NOT read run logs (that is backfill's identity source)",
          seam["no_actions_permission"], True)
    check("the sweep is actually invoked", seam["sweep_invoked"], True)
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
    read_routing, read_pulls, read_issue, read_record, read_comments, post_comment = readers
    row = sweep(targets, annotate_repo=args.annotate_repo, read_routing=read_routing,
                read_pulls=read_pulls, read_issue=read_issue, read_record=read_record,
                mint_pr=_mint_caller(mint_provenance, args.registry_repo, args.apply,
                                     lambda line: print(f"  mint: {line}")),
                read_comments=read_comments, post_comment=post_comment,
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
