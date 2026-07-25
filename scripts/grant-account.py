#!/usr/bin/env python3
# Per-repository account_pool GRANT SCOPING for the set-up-account broker (issue #579, re-filed
# from #190; the closed PR #260 preserves the prior six cross-provider review rounds).
#
# THE DEFECT THIS MODULE EXISTS TO PREVENT. Enrollment used to append the newly brokered handle to
# EVERY `account_pool` row in policy/repos.toml with ONE unanchored, global regex substitution
# (`(?m)^(account_pool\s*=\s*\[)([^\]]*)(\])` + `pattern.subn`), and then "proved" the write with an
# EXISTENTIAL check — "SOME row now contains the handle". `account_pool` is the credential-
# authorization boundary: it is the allow-list policy-resolve.py validates, select-and-claim.claim()
# filters on, and worker.yml independently re-checks. So one web sign-in silently granted the new
# credential to every enabled target (disabled and future rows included), and a partial or
# wrong-row edit satisfied the postcondition.
#
# THE INVARIANTS (all enforced here, all exercised by --self-test):
#  1. AUTHORIZATION IS EXPLICIT. The request must name its targets (`grant:<owner>/<repo>` labels on
#     the request issue). No target set => no enrollment. An unparseable `grant:` label is a
#     REFUSAL, never a silently ignored label — an authorization token we cannot read cannot be
#     honoured.
#  2. TARGETS MUST BE ENABLED ROWS. A target that is not an `enabled = true` row of the policy
#     document being edited is refused (fail closed): never created, never defaulted, never coerced.
#  3. THE EDIT IS ROW-SCOPED. render_grant rewrites ONLY the requested rows' `account_pool` lines,
#     located by their own `[repos."owner/name"]` table header, and is idempotent per row.
#  4. THE POSTCONDITION IS EXACT AND PER-TARGET, PROVED BY PARSING — never by regex bookkeeping
#     (`count` from a substitution proves nothing about WHICH rows moved). verify_grant requires,
#     for every requested target, `account_pool.count(handle) == 1`; every OTHER row's pool
#     byte-identical to the base document's; every row's remaining fields untouched; and every
#     changed LINE inside a requested row and an `account_pool` assignment.
#     verify_membership is the single-document form: it proves the same per-target exactness (plus
#     "the handle leaked into no other row") where no before/after pair exists — the "already
#     present" no-op path and the post-merge `activate` job — so a duplicate or a pre-existing
#     entry can never be reported as a successful grant.
#  5. THE AUTHORIZATION IS RE-PROVED LIVE. The target set is captured BEFORE a multi-minute
#     interactive login. require_same_targets makes the pre-login snapshot and the LIVE label set
#     EXACTLY equal immediately before the policy write, so a target removed during that window
#     fails closed instead of being granted anyway.
#
# Untrusted text (issue labels, issue bodies) reaches this module as DATA: the workflow hands it
# over through env/JSON and never interpolates it into a `run:` script — .github/workflows/
# set-up-account.yml holds contents:write, and PR #260 round 4 was a shell-injection blocker on
# exactly that interpolation.
#
# SURVIVES SEAM(#325): the account-pool list is slated to move to a private location. Nothing here
# knows where the document lives — callers pass its TEXT — so a relocation re-points the reader
# while every scoping invariant above travels with it.
"""Row-scoped account_pool grants + their exact, per-target postconditions (one shared helper)."""

import argparse
import importlib.util
import os
import pathlib
import re
import sys
import tomllib

# The authorization carrier on the request issue. Labels (not body prose) because a label change is
# timeline-audited, requires write access, and is cheap to RE-READ live immediately before the
# policy write (invariant 5).
GRANT_LABEL_PREFIX = "grant:"
# The line the broker stamps into the account issue body so the post-merge `activate` job (a
# separate job, on a separate event, with no access to the request's labels) can re-prove the SAME
# per-target postcondition. select-and-claim._parse_account ignores unknown keys, so adding it to
# the account record is safe.
RECORD_KEY = "grant_targets"
# owner/repo shape guard. Belt-and-braces only — every target is additionally required to be a KEY
# of the parsed policy — but it keeps unreviewed text out of a TOML string and out of any comment.
TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
# The broker's own handle shape (`acct%02d`), matching the workflow's `^acct[0-9a-z]{2,}$` guard.
HANDLE_RE = re.compile(r"^acct[0-9a-z]{2,}$")
# A TOML table header line, e.g. `[repos."o/r"]` or `[repos."o/r".throughput]`.
_HEADER_RE = re.compile(r"^[ \t]*\[([^\[\]]*)\][ \t]*$")
# A SINGLE-LINE `account_pool = [...]` assignment. A multi-line array is deliberately unsupported:
# it yields zero matches inside the row span and render_grant then refuses (fail closed) rather
# than editing a shape it cannot bound.
_POOL_LINE_RE = re.compile(r"^([ \t]*account_pool[ \t]*=[ \t]*\[)([^\[\]]*)(\][ \t]*)$")


class GrantError(RuntimeError):
    """An account_pool grant that cannot be PROVEN correct: an absent/unreadable authorization, a
    target that is not an enabled policy row, an edit that reached beyond the requested rows, or a
    postcondition that does not hold exactly. Every caller treats it as a refusal — the credential
    capture is irreversible, but a policy write that cannot be proven must never land."""


def _policy_repos(policy_text):
    """The `[repos]` table of a policy document, or GrantError. A document that does not parse, or
    carries no repository rows, can never authorize a grant."""
    if not isinstance(policy_text, str) or not policy_text.strip():
        raise GrantError("policy document is empty — refusing to reason about a grant")
    try:
        document = tomllib.loads(policy_text)
    except tomllib.TOMLDecodeError as exc:
        raise GrantError(f"policy document does not parse as TOML: {exc}") from exc
    repos = document.get("repos")
    if not isinstance(repos, dict) or not repos:
        raise GrantError("policy document carries no [repos] rows — refusing")
    return repos


def _require_handle(handle):
    if not isinstance(handle, str) or not HANDLE_RE.match(handle):
        raise GrantError(f"unsafe account handle {handle!r} — refusing")
    return handle


def targets_from_labels(label_names):
    """The requested target set carried by `grant:<owner>/<repo>` labels (invariant 1).

    Raises GrantError when the label list is unreadable, when NO grant label is present (an
    enrollment with no authorization choice must never proceed), or when a `grant:` label does not
    name an owner/repo target — an authorization token we cannot parse is a refusal, never an
    ignored label."""
    if not isinstance(label_names, (list, tuple)):
        raise GrantError("the request's label list is unavailable — cannot prove which "
                         "repositories this enrollment is authorized for (fail closed)")
    targets = []
    for name in label_names:
        if not isinstance(name, str):
            raise GrantError(f"unreadable label entry {name!r} — refusing")
        if not name.startswith(GRANT_LABEL_PREFIX):
            continue
        value = name[len(GRANT_LABEL_PREFIX):].strip()
        if not TARGET_RE.match(value):
            raise GrantError(
                f"label {name!r} does not name an <owner>/<repo> target — refusing to guess "
                "which repository it authorizes (fail closed)")
        targets.append(value)
    if not targets:
        raise GrantError(
            f"the request carries no `{GRANT_LABEL_PREFIX}<owner>/<repo>` label, so it names no "
            "target repository — an account is granted only to the repositories the request "
            "explicitly authorizes (fail closed)")
    return sorted(set(targets))


def enabled_targets(policy_text):
    """Every `enabled = true` repository row of `policy_text` (the only grantable targets)."""
    repos = _policy_repos(policy_text)
    return sorted(name for name, row in repos.items()
                  if isinstance(row, dict) and row.get("enabled") is True)


def validate_targets(requested, policy_text):
    """The requested targets, proven grantable against `policy_text` (invariant 2), sorted.

    Raises GrantError on an empty set, a malformed name, a target that is not a row of this policy,
    a row that is not `enabled = true`, or a row with no `account_pool` list. Nothing is created and
    nothing is defaulted: an unlisted or disabled repository is a refusal."""
    if not requested:
        raise GrantError("no target repository was requested — refusing to grant an account "
                         "(fail closed)")
    repos = _policy_repos(policy_text)
    resolved = []
    for target in requested:
        if not isinstance(target, str) or not TARGET_RE.match(target):
            raise GrantError(f"target {target!r} is not an <owner>/<repo> name — refusing")
        row = repos.get(target)
        if not isinstance(row, dict):
            raise GrantError(
                f"target {target!r} is not a repository row in the policy — refusing to grant an "
                "account to a repository the policy does not describe (fail closed)")
        if row.get("enabled") is not True:
            raise GrantError(
                f"target {target!r} is not an `enabled = true` policy row — refusing to grant an "
                "account to a disabled repository (fail closed)")
        if not isinstance(row.get("account_pool"), list):
            raise GrantError(f"target {target!r} has no account_pool list — refusing")
        resolved.append(target)
    return sorted(set(resolved))


def require_same_targets(snapshot, live):
    """The pre-login snapshot re-proved against LIVE authorization (invariant 5), sorted.

    The target set is captured before an interactive login that can take ~13 minutes; the policy
    write happens after. Anything but EXACT equality — a target removed, a target added, an empty
    live set — is a refusal: the authorization that was reviewed is no longer the authorization in
    force, and a machine must not pick the intersection on a maintainer's behalf."""
    before = sorted(set(snapshot or []))
    now = sorted(set(live or []))
    if not before:
        raise GrantError("no authorized target set was captured for this request — refusing")
    if not now:
        raise GrantError("the request no longer carries any grant label, so its authorization is "
                         "gone — refusing to write policy (fail closed)")
    if before != now:
        raise GrantError(
            f"the request's LIVE grant labels {now} no longer match the authorized target set "
            f"{before} — the authorization changed during enrollment; refusing to write policy "
            "(fail closed)")
    return now


def authorize(live_labels, policy_text, snapshot=None):
    """The whole authorization decision in one call: the live `grant:` labels, proven grantable
    against `policy_text`, and (when `snapshot` is given) proven EXACTLY equal to the pre-login
    snapshot. Returns the sorted target set; raises GrantError on any doubt."""
    live = validate_targets(targets_from_labels(live_labels), policy_text)
    if snapshot is None:
        return live
    return require_same_targets(snapshot, live)


def _row_header_target(line):
    """The target named by a `[repos."owner/name"]` ROW header, or None for any other line —
    including a sub-table header such as `[repos."owner/name".throughput]`, which is a different
    table and never carries an account_pool."""
    match = _HEADER_RE.match(line)
    if not match:
        return None
    key = match.group(1).strip()
    for quote in ('"', "'"):
        prefix = f"repos.{quote}"
        if key.startswith(prefix) and key.endswith(quote) and len(key) > len(prefix) + 1:
            return key[len(prefix):-1]
    return None


def _row_spans(policy_text):
    """{target: (first_line_after_header, end_line_exclusive)} for every `[repos."..."]` row, so an
    edit can be confined to ONE row's lines. Sections end at the next table header of any kind."""
    lines = policy_text.split("\n")
    headers = [(index, _row_header_target(line)) for index, line in enumerate(lines)
               if _HEADER_RE.match(line)]
    spans = {}
    for position, (index, target) in enumerate(headers):
        if target is None:
            continue
        end = headers[position + 1][0] if position + 1 < len(headers) else len(lines)
        if target in spans:
            raise GrantError(f'policy carries two [repos."{target}"] headers — refusing')
        spans[target] = (index + 1, end)
    return spans


def _pool_line(lines, target, span):
    """The (index, match) of the ONE single-line account_pool assignment inside `target`'s row.

    Zero matches (a multi-line array, a renamed key) or several is a refusal: an edit whose shape
    cannot be bounded to one assignment must not be attempted."""
    hits = []
    for index in range(span[0], span[1]):
        match = _POOL_LINE_RE.match(lines[index])
        if match:
            hits.append((index, match))
    if len(hits) != 1:
        raise GrantError(
            f'expected exactly one single-line `account_pool = [...]` assignment in '
            f'[repos."{target}"], found {len(hits)} — refusing to edit a shape this grant cannot '
            "bound (fail closed)")
    return hits[0]


def render_grant(policy_text, handle, targets):
    """`policy_text` with `handle` appended to ONLY the requested rows' account_pool (invariant 3).

    Idempotent per row: a row that already lists the handle is left byte-identical. The result is
    re-proved with verify_grant before it is returned, so no caller can skip the postcondition."""
    _require_handle(handle)
    resolved = validate_targets(targets, policy_text)
    lines = policy_text.split("\n")
    spans = _row_spans(policy_text)
    for target in resolved:
        span = spans.get(target)
        if span is None:
            raise GrantError(
                f'no [repos."{target}"] row header found in the policy text even though it parses '
                "as a row — refusing to edit a row this grant cannot locate (fail closed)")
        index, match = _pool_line(lines, target, span)
        items = match.group(2)
        entries = [entry.strip() for entry in items.split(",") if entry.strip()]
        quoted = f'"{handle}"'
        if quoted in entries:
            continue
        separator = ", " if items.strip() else ""
        lines[index] = f"{match.group(1)}{items}{separator}{quoted}{match.group(3)}"
    new_text = "\n".join(lines)
    verify_grant(policy_text, new_text, handle, resolved)
    return new_text


def _changed_line_indexes(before_text, after_text):
    before = before_text.split("\n")
    after = after_text.split("\n")
    if len(before) != len(after):
        raise GrantError(
            f"the proposed policy adds or removes lines ({len(before)} -> {len(after)}) — a grant "
            "only rewrites account_pool assignments (fail closed)")
    return [index for index in range(len(before)) if before[index] != after[index]]


def verify_grant(before_text, after_text, handle, targets):
    """The EXACT, per-target postcondition on a proposed grant (invariant 4). Returns the sorted
    target set; raises GrantError otherwise.

    Proved by PARSING both documents (never from a substitution count):
      * every requested target row lists `handle` EXACTLY once,
      * no requested row's OTHER pool members were added, removed or reordered,
      * every NON-TARGET row's account_pool is unchanged,
      * no row's remaining fields (or sub-tables) moved, and no row appeared or vanished,
      * and at the TEXT level, every changed line sits inside a requested row AND is an
        account_pool assignment on both sides — so a global substitution, a comment rewrite, or a
        stray edit anywhere else in the document is caught even if it happened to parse equal."""
    _require_handle(handle)
    if not targets:
        raise GrantError("cannot verify a grant with no target repositories — refusing")
    resolved = sorted(set(targets))
    before = _policy_repos(before_text)
    after = _policy_repos(after_text)
    if sorted(before) != sorted(after):
        raise GrantError("the proposed policy adds or removes repository rows — refusing")
    missing = [target for target in resolved if target not in after]
    if missing:
        raise GrantError(f"requested targets {missing} are not rows of the policy — refusing")
    for name in sorted(after):
        base_row, new_row = before[name], after[name]
        if not isinstance(base_row, dict) or not isinstance(new_row, dict):
            raise GrantError(f"row {name!r} is not a table — refusing")
        base_pool, new_pool = base_row.get("account_pool"), new_row.get("account_pool")
        if not isinstance(base_pool, list) or not isinstance(new_pool, list):
            raise GrantError(f"row {name!r} has no account_pool list — refusing")
        if ({key: value for key, value in base_row.items() if key != "account_pool"}
                != {key: value for key, value in new_row.items() if key != "account_pool"}):
            raise GrantError(
                f"the proposed policy changes fields other than account_pool on row {name!r} — "
                "an account grant must touch nothing else (fail closed)")
        if name in resolved:
            count = new_pool.count(handle)
            if count != 1:
                raise GrantError(
                    f"target {name!r} account_pool contains {handle} {count} time(s); the grant "
                    "postcondition is EXACTLY once (fail closed)")
            if ([entry for entry in new_pool if entry != handle]
                    != [entry for entry in base_pool if entry != handle]):
                raise GrantError(
                    f"target {name!r} account_pool members other than {handle} changed — refusing")
        elif new_pool != base_pool:
            raise GrantError(
                f"NON-TARGET row {name!r} account_pool was mutated (was {base_pool}, now "
                f"{new_pool}) — the grant is scoped to {resolved} (fail closed)")
    spans = _row_spans(before_text)
    after_lines = after_text.split("\n")
    before_lines = before_text.split("\n")
    for index in _changed_line_indexes(before_text, after_text):
        owner = next((target for target in resolved
                      if target in spans and spans[target][0] <= index < spans[target][1]), None)
        if owner is None:
            raise GrantError(
                f"line {index + 1} changed outside every requested target row — every other line "
                "must stay byte-identical (fail closed)")
        if not (_POOL_LINE_RE.match(before_lines[index])
                and _POOL_LINE_RE.match(after_lines[index])):
            raise GrantError(
                f'line {index + 1} in [repos."{owner}"] is not an account_pool assignment on both '
                "sides — refusing")
    return resolved


def verify_membership(policy_text, handle, targets):
    """The single-document form of the exact postcondition, for the paths with no before/after pair:
    the "already present in master" no-op path and the post-merge `activate` job.

    Requires, in ONE parsed document: every target is an `enabled = true` row whose account_pool
    lists `handle` EXACTLY once, and NO other row lists it at all. An existential "some row has the
    handle" check passes on a wrong-row or partial edit and on a pre-existing duplicate; this does
    not — which is why the no-op path must call it before reporting a successful grant."""
    _require_handle(handle)
    if not targets:
        raise GrantError(f"cannot prove {handle} is granted with no target repositories — refusing")
    resolved = validate_targets(targets, policy_text)
    repos = _policy_repos(policy_text)
    for target in resolved:
        pool = repos[target].get("account_pool")
        count = pool.count(handle)
        if count != 1:
            raise GrantError(
                f"target {target!r} account_pool contains {handle} {count} time(s); exactly once "
                "is required before this grant can be reported as landed (fail closed)")
    strays = sorted(name for name, row in repos.items()
                    if name not in resolved and isinstance(row, dict)
                    and handle in (row.get("account_pool") or []))
    if strays:
        raise GrantError(
            f"{handle} is present in NON-TARGET rows {strays}; the grant is scoped to {resolved} "
            "(fail closed)")
    return resolved


# The ONE head-branch namespace a brokered account_pool grant may travel on. `activate` keys off it
# (`startsWith(head.ref, 'account-pool/')`), and merged_grant_prs below uses it as the PROVENANCE
# carrier: a grant that never travelled on this branch was never reviewed as a grant.
GRANT_BRANCH_PREFIX = "account-pool/"


def grant_branch(handle):
    """The one head-branch name a brokered grant for `handle` may travel on."""
    return f"{GRANT_BRANCH_PREFIX}{_require_handle(handle)}"


def merged_grant_prs(pulls, handle, base="master"):
    """The MERGED grant pull requests for `handle`, sorted — the PROVENANCE of an ALREADY-PRESENT
    account_pool membership (#616 cross-provider review finding 1).

    verify_membership proves the SHAPE of a policy document: the handle occurs exactly once in each
    authorized row and in no other row. It cannot prove HOW or WHY the handle got there. So on the
    "already present in master, no PR needed" no-op path, membership alone would let a handle that
    was pre-seeded into the policy by ANY other means — a hand edit, a leftover row from a retired
    account, an unrelated merged PR — skip the CHECKED `account-pool/<handle>` PR entirely and
    activate a freshly captured credential inline, with no review of the grant at all. That is the
    two-phase design (#185) silently bypassed, and it contradicts this module's own claim that a
    pre-existing entry can never be reported as a successful grant.

    So the no-op path must additionally prove the membership came from a merged grant PR: at least
    one entry of `pulls` that is MERGED, whose base is `base`, and whose head ref is EXACTLY this
    handle's grant branch. No such PR, an unreadable listing, only an open or closed-unmerged one, a
    different handle's branch, or a different base are all refusals — the safe direction is to leave
    the account `status:pending` for a human rather than activate an unproven grant."""
    branch = grant_branch(handle)
    if not isinstance(pulls, (list, tuple)):
        raise GrantError(
            f"the pull-request listing for {branch} is unavailable, so it cannot be proven that "
            f"{handle} was granted by a merged, checked account_pool PR — refusing (fail closed)")
    numbers = []
    for pull in pulls:
        if not isinstance(pull, dict):
            raise GrantError(f"unreadable pull-request entry {pull!r} — refusing")
        head, into = pull.get("head"), pull.get("base")
        head_ref = head.get("ref") if isinstance(head, dict) else None
        base_ref = into.get("ref") if isinstance(into, dict) else None
        if head_ref != branch or base_ref != base:
            continue
        if not pull.get("merged_at"):
            continue
        number = pull.get("number")
        if not isinstance(number, int):
            raise GrantError(f"a merged pull request on {branch} carries no readable number "
                             "— refusing")
        numbers.append(number)
    if not numbers:
        raise GrantError(
            f"{handle} is already listed in the policy account_pool, but NO merged pull request "
            f"from `{branch}` into `{base}` accounts for it — the membership was not established by "
            "a checked grant PR, so this enrollment cannot report it as its own successful grant "
            "(fail closed)")
    return sorted(set(numbers))


def require_grant_pr_scope(number, files, path):
    """The merged grant PR `number` proven to have changed the policy document `path` AND NOTHING
    ELSE (the file-level companion of merged_grant_prs).

    Without it the provenance check degrades to "some merged PR used that branch name": a branch
    named `account-pool/<handle>` whose merged diff never touched the policy — or touched a workflow
    as well — would stand in for a reviewed grant. A brokered grant PR is a single contents PUT to
    exactly this one path, and the documented manual-recovery PR edits only the granted rows, so
    anything else is a refusal."""
    if not isinstance(files, (list, tuple)) or not files:
        raise GrantError(
            f"the changed-file listing for merged PR #{number} is unavailable or empty, so it "
            f"cannot be proven that the grant it carries edited {path} — refusing (fail closed)")
    names = []
    for entry in files:
        if not isinstance(entry, dict) or not isinstance(entry.get("filename"), str):
            raise GrantError(f"unreadable changed-file entry {entry!r} on PR #{number} — refusing")
        names.append(entry["filename"])
    if sorted(set(names)) != [path]:
        raise GrantError(
            f"merged PR #{number} changed {sorted(set(names))}, not exactly [{path!r}] — a grant "
            "PR edits the policy document and nothing else, so this PR does not prove the "
            "account_pool membership is a reviewed grant (fail closed)")
    return number


def format_record_line(targets):
    """The `grant_targets: ...` line stamped into the account issue body (the record the `activate`
    job re-proves against the merged policy). Every entry is shape-validated first, so the line can
    never carry unreviewed text into the record."""
    resolved = sorted(set(targets or []))
    if not resolved:
        raise GrantError("refusing to record an empty target set on an account issue")
    for target in resolved:
        if not isinstance(target, str) or not TARGET_RE.match(target):
            raise GrantError(f"target {target!r} is not an <owner>/<repo> name — refusing")
    return f"{RECORD_KEY}: " + ", ".join(resolved)


def parse_record_line(body):
    """The target set recorded on an account issue body, sorted. Raises GrantError when the line is
    absent, empty, or malformed: an account whose authorized targets cannot be read must never be
    activated (its grant cannot be proven), so the failure direction is a refusal."""
    match = re.search(rf"(?m)^{RECORD_KEY}:[ \t]*(.*)$", body or "")
    if not match:
        raise GrantError(
            f"the account record carries no `{RECORD_KEY}:` line, so the repositories this account "
            "was authorized for cannot be read — refusing to prove or activate its grant "
            "(fail closed)")
    values = [value.strip() for value in match.group(1).replace("\r", "").split(",")
              if value.strip()]
    if not values:
        raise GrantError(f"the account record's `{RECORD_KEY}:` line is empty — refusing")
    for value in values:
        if not TARGET_RE.match(value):
            raise GrantError(
                f"the account record's `{RECORD_KEY}:` line entry {value!r} is not an "
                "<owner>/<repo> name — refusing")
    return sorted(set(values))


# The exact global substitution this module replaces (issue #579 evidence, quoted so the self-test
# can REPLAY it and prove the guard still catches it).
_LEGACY_GLOBAL_PATTERN = re.compile(r"(?m)^(account_pool\s*=\s*\[)([^\]]*)(\])")


def _legacy_global_append(policy_text, handle):
    """The retired every-row append, reproduced verbatim for the regression test below."""
    def append(match):
        entries = match.group(2)
        if f'"{handle}"' in entries:
            return match.group(0)
        separator = ", " if entries.strip() else ""
        return f'{match.group(1)}{entries}{separator}"{handle}"{match.group(3)}'
    return _LEGACY_GLOBAL_PATTERN.subn(append, policy_text)[0]


# ---------------------------------------------------------------------------------------------
# WIRING ASSERTIONS: reading the workflow as TEXT without letting a comment stand in for a call.
#
# #616 cross-provider review findings 3 + 4 (the TEST-VACUITY class). The self-test below asserts
# that the privileged workflow actually CALLS these guards, and it used to do that with whole-file
# substring checks — `"authorize(" in workflow`, `"format_record_line(" in workflow`. Every one of
# those is satisfiable by a PROSE COMMENT or by an unrelated call site in a different step, so
# deleting the guard from the privileged step left the assertion green: the live-authorization
# re-proof (invariant 5) had NO mutation-effective coverage at all. These two helpers make a wiring
# assertion mean what it says — the comment lines are removed, and the assertion is scoped to the
# ONE step that must make the call. Both fail LOUDLY (GrantError) when they cannot resolve their
# target, so a renamed step id can never silently turn an assertion vacuous.
def strip_yaml_comments(text):
    """`text` with every whole-line `#` comment removed (YAML comments and, inside `run:` blocks,
    shell/python comments alike). A claim in prose must never satisfy an assertion about code."""
    if not isinstance(text, str):
        raise GrantError("cannot strip comments from a non-text document — refusing")
    return "\n".join(line for line in text.split("\n") if not line.lstrip().startswith("#"))


def workflow_step(text, step_id):
    """The full YAML text of the ONE workflow step whose `id:` is `step_id`, comments stripped.

    Located by the step's `id:` and bounded by the surrounding sequence indentation, so a call in a
    NEIGHBOURING step (or in a header comment) cannot satisfy an assertion about this one. Raises
    GrantError when no such step exists or the extracted body is empty — a wiring assertion that
    cannot find its step must fail, never pass vacuously."""
    if not isinstance(text, str):
        raise GrantError("cannot extract a step from a non-text workflow — refusing")
    lines = text.split("\n")
    marks = [index for index, line in enumerate(lines) if line.strip() == f"id: {step_id}"]
    if len(marks) != 1:
        raise GrantError(
            f"expected exactly one workflow step with `id: {step_id}`, found {len(marks)} — "
            "refusing to assert against a step that cannot be located (fail closed)")
    starts = [index for index in range(marks[0], -1, -1) if lines[index].lstrip().startswith("- ")]
    if not starts:
        raise GrantError(f"step `id: {step_id}` has no enclosing `- ` sequence entry — refusing")
    start = starts[0]
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if not line.strip():
            continue
        here = len(line) - len(line.lstrip())
        if here < indent or (here == indent and line.lstrip().startswith("- ")):
            end = index
            break
    body = strip_yaml_comments("\n".join(lines[start:end]))
    if not body.strip():
        raise GrantError(f"step `id: {step_id}` extracted to an empty body — refusing")
    return body


FIXTURE = '''# a policy comment that must survive every grant byte-identical
[repos."o/target"]
enabled = true
routing = "r.toml"
account_pool = ["acct01", "acct02"]
max_concurrent = 2

[repos."o/target".throughput]
target_ready = 5

[repos."o/second"]
enabled = true
routing = "r.toml"
account_pool = ["acct01"]
max_concurrent = 1

[repos."o/disabled"]
enabled = false
routing = "r.toml"
account_pool = ["acct09"]
'''


def _self_test():
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    def refuses(fn, *args, needle="", **kwargs):
        """True iff `fn` raises GrantError whose message contains `needle` — so a check can never
        pass on an unrelated crash."""
        try:
            fn(*args, **kwargs)
        except GrantError as exc:
            return needle in str(exc)
        return False

    pool = lambda text, row: tomllib.loads(text)["repos"][row]["account_pool"]  # noqa: E731

    # ---- invariant 1: the request must NAME its targets, and an unreadable grant label refuses --
    check("grant labels yield the target set",
          targets_from_labels(["set-up-account", "provider:anthropic", "grant:o/target"]),
          ["o/target"])
    check("several grant labels are all honoured (sorted, deduped)",
          targets_from_labels(["grant:o/second", "grant:o/target", "grant:o/second"]),
          ["o/second", "o/target"])
    check("NO grant label => refusal (no silent every-repo default)",
          refuses(targets_from_labels, ["set-up-account", "provider:openai"],
                  needle="no target repository"), True)
    check("a malformed grant label refuses instead of being ignored",
          refuses(targets_from_labels, ["grant:not-a-repo"], needle="does not name"), True)
    check("a grant label with shell metacharacters refuses",
          refuses(targets_from_labels, ['grant:o/r"; rm -rf /'], needle="does not name"), True)
    check("an unreadable label list refuses",
          refuses(targets_from_labels, None, needle="label list is unavailable"), True)
    check("a non-string label entry refuses",
          refuses(targets_from_labels, ["grant:o/target", 7], needle="unreadable label"), True)

    # ---- invariant 2: only ENABLED rows of THIS policy are grantable --------------------------
    check("enabled_targets lists exactly the enabled rows",
          enabled_targets(FIXTURE), ["o/second", "o/target"])
    check("validate_targets accepts an enabled row", validate_targets(["o/target"], FIXTURE),
          ["o/target"])
    check("an UNLISTED repository refuses",
          refuses(validate_targets, ["o/nope"], FIXTURE, needle="not a repository row"), True)
    check("a DISABLED row refuses",
          refuses(validate_targets, ["o/disabled"], FIXTURE, needle="not an `enabled = true`"),
          True)
    check("an empty target set refuses",
          refuses(validate_targets, [], FIXTURE, needle="no target repository"), True)
    check("an unparseable policy refuses",
          refuses(validate_targets, ["o/target"], "not = = toml", needle="does not parse"), True)
    check("a policy with no [repos] rows refuses",
          refuses(validate_targets, ["o/target"], "[other]\nx = 1\n", needle="no [repos] rows"),
          True)

    # ---- invariant 3: the edit is ROW-SCOPED and idempotent -----------------------------------
    granted = render_grant(FIXTURE, "acct07", ["o/target"])
    check("the requested row gains the handle exactly once",
          pool(granted, "o/target"), ["acct01", "acct02", "acct07"])
    check("the OTHER enabled row is untouched", pool(granted, "o/second"), ["acct01"])
    check("the DISABLED row is untouched", pool(granted, "o/disabled"), ["acct09"])
    unchanged = [line for line in FIXTURE.split("\n") if line not in granted.split("\n")]
    check("exactly ONE line of the document changed", unchanged,
          ['account_pool = ["acct01", "acct02"]'])
    check("the leading comment survives byte-identical",
          granted.startswith("# a policy comment that must survive every grant byte-identical"),
          True)
    check("a grant to TWO targets edits both and nothing else",
          [pool(render_grant(FIXTURE, "acct07", ["o/target", "o/second"]), row)
           for row in ("o/target", "o/second", "o/disabled")],
          [["acct01", "acct02", "acct07"], ["acct01", "acct07"], ["acct09"]])
    check("re-granting is a byte-identical no-op (idempotent)",
          render_grant(granted, "acct07", ["o/target"]), granted)
    check("an unsafe handle refuses",
          refuses(render_grant, FIXTURE, "acct01; rm -rf /", ["o/target"],
                  needle="unsafe account handle"), True)
    check("a multi-line account_pool array refuses (a shape the grant cannot bound)",
          refuses(render_grant,
                  '[repos."o/target"]\nenabled = true\naccount_pool = [\n  "acct01",\n]\n',
                  "acct07", ["o/target"], needle="exactly one single-line"), True)

    # ---- invariant 4: the postcondition is EXACT and PER-TARGET -------------------------------
    check("verify_grant accepts the scoped edit",
          verify_grant(FIXTURE, granted, "acct07", ["o/target"]), ["o/target"])
    # THE #579 REGRESSION, replayed through the retired substitution itself: if the append ever
    # goes global again, verify_grant MUST refuse.
    global_text = _legacy_global_append(FIXTURE, "acct07")
    check("the replayed legacy substitution really did hit every row (the test is not vacuous)",
          [pool(global_text, row) for row in ("o/target", "o/second", "o/disabled")],
          [["acct01", "acct02", "acct07"], ["acct01", "acct07"], ["acct09", "acct07"]])
    check("[#579] a GLOBAL substitution is refused (non-target rows mutated)",
          refuses(verify_grant, FIXTURE, global_text, "acct07", ["o/target"],
                  needle="NON-TARGET row"), True)
    check("[#579] the old EXISTENTIAL check would have accepted that same global edit "
          "(so the exact check is what catches it)",
          any("acct07" in (row.get("account_pool") or [])
              for row in tomllib.loads(global_text).get("repos", {}).values()), True)
    check("a WRONG-row edit is refused (the handle landed on a row nobody requested)",
          refuses(verify_grant, FIXTURE, render_grant(FIXTURE, "acct07", ["o/second"]),
                  "acct07", ["o/target"], needle="NON-TARGET row"), True)
    check("a NO-OP proposal is refused (the requested row never gained the handle)",
          refuses(verify_grant, FIXTURE, FIXTURE, "acct07", ["o/target"],
                  needle="contains acct07 0 time(s)"), True)
    check("a PARTIAL edit is refused (only one of two requested rows moved)",
          refuses(verify_grant, FIXTURE, granted, "acct07", ["o/target", "o/second"],
                  needle="contains acct07 0 time(s)"), True)
    doubled = FIXTURE.replace('account_pool = ["acct01", "acct02"]',
                              'account_pool = ["acct01", "acct02", "acct07", "acct07"]')
    check("a DUPLICATE entry is refused (exactly once, never 'at least once')",
          refuses(verify_grant, FIXTURE, doubled, "acct07", ["o/target"],
                  needle="2 time(s)"), True)
    dropped = granted.replace('account_pool = ["acct01"]', 'account_pool = ["acct02"]')
    check("a silent membership swap on a non-target row is refused",
          refuses(verify_grant, FIXTURE, dropped, "acct07", ["o/target"],
                  needle="NON-TARGET row"), True)
    reordered = FIXTURE.replace('account_pool = ["acct01", "acct02"]',
                                'account_pool = ["acct07", "acct01"]')
    check("dropping an existing member of the target row is refused",
          refuses(verify_grant, FIXTURE, reordered, "acct07", ["o/target"],
                  needle="members other than acct07 changed"), True)
    other_field = granted.replace("max_concurrent = 2", "max_concurrent = 40")
    check("a change to any OTHER policy field is refused",
          refuses(verify_grant, FIXTURE, other_field, "acct07", ["o/target"],
                  needle="fields other than account_pool"), True)
    sub_table = granted.replace("target_ready = 5", "target_ready = 99")
    check("a change to a row's SUB-TABLE is refused",
          refuses(verify_grant, FIXTURE, sub_table, "acct07", ["o/target"],
                  needle="fields other than account_pool"), True)
    comment_edit = granted.replace("# a policy comment", "# an edited comment")
    check("a comment/formatting edit outside the row is refused (byte-identical elsewhere)",
          refuses(verify_grant, FIXTURE, comment_edit, "acct07", ["o/target"],
                  needle="changed outside every requested target row"), True)
    check("an added line is refused",
          refuses(verify_grant, FIXTURE, granted + '\n[repos."o/new"]\nenabled = true\n'
                  'account_pool = ["acct07"]\n', "acct07", ["o/target"],
                  needle="adds or removes"), True)
    check("verifying with NO targets is refused (never a vacuous pass)",
          refuses(verify_grant, FIXTURE, granted, "acct07", [], needle="no target repositories"),
          True)

    # ---- the NO-OP / post-merge path must run the SAME exact proof ----------------------------
    check("verify_membership accepts a landed, scoped grant",
          verify_membership(granted, "acct07", ["o/target"]), ["o/target"])
    check("[#579] verify_membership refuses when the target row does NOT carry the handle",
          refuses(verify_membership, FIXTURE, "acct07", ["o/target"],
                  needle="0 time(s)"), True)
    check("[#579] verify_membership refuses a PRE-EXISTING duplicate on the no-op path",
          refuses(verify_membership, doubled, "acct07", ["o/target"], needle="2 time(s)"), True)
    check("[#579] verify_membership refuses when the handle LEAKED into other rows",
          refuses(verify_membership, global_text, "acct07", ["o/target"],
                  needle="NON-TARGET rows"), True)
    check("verify_membership refuses a disabled target",
          refuses(verify_membership, granted, "acct07", ["o/disabled"],
                  needle="not an `enabled = true`"), True)
    check("verify_membership refuses an empty target set",
          refuses(verify_membership, granted, "acct07", [], needle="no target repositories"), True)
    check("verify_membership refuses a wrong handle shape",
          refuses(verify_membership, granted, "sudo", ["o/target"],
                  needle="unsafe account handle"), True)

    # ---- invariant 5: a STALE pre-login authorization snapshot is never accepted --------------
    check("snapshot == live authorization is accepted",
          require_same_targets(["o/target"], ["o/target"]), ["o/target"])
    check("[#579] a target REMOVED during the login window refuses",
          refuses(require_same_targets, ["o/target", "o/second"], ["o/target"],
                  needle="no longer match"), True)
    check("[#579] a target ADDED during the login window refuses",
          refuses(require_same_targets, ["o/target"], ["o/target", "o/second"],
                  needle="no longer match"), True)
    check("[#579] every grant label removed during the window refuses",
          refuses(require_same_targets, ["o/target"], [], needle="authorization is gone"), True)
    check("an absent snapshot refuses",
          refuses(require_same_targets, [], ["o/target"], needle="no authorized target set"), True)
    check("authorize() accepts live labels matching the snapshot",
          authorize(["grant:o/target", "provider:openai"], FIXTURE, ["o/target"]), ["o/target"])
    check("authorize() refuses a stale snapshot",
          refuses(authorize, ["grant:o/target"], FIXTURE, ["o/target", "o/second"],
                  needle="no longer match"), True)
    check("authorize() refuses live labels naming a disabled row",
          refuses(authorize, ["grant:o/disabled"], FIXTURE, ["o/disabled"],
                  needle="not an `enabled = true`"), True)
    check("authorize() with no snapshot still validates the live set",
          authorize(["grant:o/second"], FIXTURE), ["o/second"])

    # ---- the account-issue record the `activate` job re-proves --------------------------------
    line = format_record_line(["o/target", "o/second"])
    check("the record line is stable and sorted", line, "grant_targets: o/second, o/target")
    body = f"provider: openai\n{line}\nrequest_issue: 7\n"
    check("the record line round-trips", parse_record_line(body), ["o/second", "o/target"])
    check("a CRLF body still parses", parse_record_line(body.replace("\n", "\r\n")),
          ["o/second", "o/target"])
    check("a MISSING record line refuses (never activate an unprovable grant)",
          refuses(parse_record_line, "provider: openai\nrequest_issue: 7\n",
                  needle="no `grant_targets:` line"), True)
    check("an EMPTY record line refuses",
          refuses(parse_record_line, "grant_targets:\n", needle="is empty"), True)
    check("a malformed record entry refuses",
          refuses(parse_record_line, "grant_targets: o/target, nonsense\n",
                  needle="line entry 'nonsense'"), True)
    check("recording an empty target set refuses",
          refuses(format_record_line, [], needle="empty target set"), True)

    # ---- #616 finding 1: SHAPE IS NOT PROVENANCE (the no-op path's merged-grant-PR proof) ------
    check("the grant branch namespace has ONE spelling", grant_branch("acct07"),
          "account-pool/acct07")
    check("an unsafe handle cannot even name a grant branch",
          refuses(grant_branch, "acct01; rm -rf /", needle="unsafe account handle"), True)
    merged_pr = {"number": 41, "merged_at": "2026-07-25T00:00:00Z",
                 "head": {"ref": "account-pool/acct07"}, "base": {"ref": "master"}}
    check("a merged account-pool PR accounts for the membership",
          merged_grant_prs([merged_pr], "acct07"), [41])
    check("several merged grant PRs are all reported, sorted and deduped",
          merged_grant_prs([{**merged_pr, "number": 55}, merged_pr, merged_pr], "acct07"),
          [41, 55])
    check("[#616] NO account-pool PR at all refuses (a pre-seeded pool entry is NOT a grant)",
          refuses(merged_grant_prs, [], "acct07", needle="NO merged pull request"), True)
    check("[#616] an OPEN / closed-unmerged account-pool PR refuses",
          refuses(merged_grant_prs, [{**merged_pr, "merged_at": None}], "acct07",
                  needle="NO merged pull request"), True)
    check("[#616] a merged PR on ANOTHER handle's grant branch refuses",
          refuses(merged_grant_prs, [{**merged_pr, "head": {"ref": "account-pool/acct08"}}],
                  "acct07", needle="NO merged pull request"), True)
    check("[#616] a merged PR into a base other than master refuses",
          refuses(merged_grant_prs, [{**merged_pr, "base": {"ref": "ledger"}}], "acct07",
                  needle="NO merged pull request"), True)
    check("[#616] an unreadable PR listing refuses (a failed read is never a proven negative)",
          refuses(merged_grant_prs, None, "acct07",
                  needle="listing for account-pool/acct07 is unavailable"), True)
    check("[#616] an unreadable PR entry refuses",
          refuses(merged_grant_prs, ["not-a-pull"], "acct07",
                  needle="unreadable pull-request entry"), True)
    check("the provenance PR must have changed the policy document",
          require_grant_pr_scope(41, [{"filename": "policy/repos.toml"}], "policy/repos.toml"), 41)
    check("[#616] a merged grant-branch PR that never touched the policy refuses",
          refuses(require_grant_pr_scope, 41, [{"filename": "README.md"}], "policy/repos.toml",
                  needle="not exactly"), True)
    check("[#616] a merged grant PR that ALSO changed another file refuses",
          refuses(require_grant_pr_scope, 41,
                  [{"filename": "policy/repos.toml"},
                   {"filename": ".github/workflows/worker.yml"}],
                  "policy/repos.toml", needle="not exactly"), True)
    check("[#616] an empty/unreadable changed-file listing refuses",
          (refuses(require_grant_pr_scope, 41, [], "policy/repos.toml",
                   needle="unavailable or empty"),
           refuses(require_grant_pr_scope, 41, None, "policy/repos.toml",
                   needle="unavailable or empty")), (True, True))

    # ---- the LIVE documents: this repo's real policy + the wiring in the real workflow --------
    root = pathlib.Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    # #616 finding 4: the schema-compatibility claim is proved by the REAL parser, not against a
    # key set the test wrote itself. The register step validates the exact bytes it is about to
    # persist through select-and-claim's guard, and the credential is captured and stored BEFORE
    # that write — so a record the allocator rejects strands an irreversible capture. Import the
    # actual module and prove (a) a body carrying the grant_targets line still validates, and
    # (b) the key is genuinely IGNORED rather than mis-parsed into a schema field.
    claim_spec = importlib.util.spec_from_file_location(
        "registry_select_and_claim", str(root / "scripts/select-and-claim.py"))
    claim = importlib.util.module_from_spec(claim_spec)
    claim_spec.loader.exec_module(claim)
    record_body = (
        "provider: openai\nharness: codex\nmodels: [sol, luna, terra]\n"
        "credential_format: codex-auth-json\nmax_concurrent_workers: 1\n"
        "secret_ref: ACCT07_TOKEN\nrequest_issue: 7\n"
        f"{format_record_line(['o/target', 'o/second'])}\n"
        "notes: registered via set-up-account broker; pending account_pool PR merge\n")
    def real_parser(fn, *args):
        """One real-parser verdict, with any REJECTION turned into a legible failing VALUE.

        A rejection is exactly the outcome this pair of checks exists to catch, so it must show up
        as a red assertion with the reason in it — never as a traceback that takes the whole suite
        down without naming the record key at fault. (Broad on purpose: the exception becomes a
        loud failure, never an empty-data pass.)"""
        try:
            return fn(*args)
        except Exception as exc:  # noqa: BLE001 - any rejection IS the failure signal
            return f"REJECTED by the real parser: {type(exc).__name__}: {exc}"

    check("[#616] the REAL allocator schema guard accepts a record carrying the grant record line",
          real_parser(claim.account_record_schema_errors, "acct07", record_body), [])
    parsed = real_parser(claim.validate_account_record, "acct07", record_body)
    check("[#616] the REAL parser IGNORES the grant record key (it collides with no schema field)",
          parsed if isinstance(parsed, str) else
          (RECORD_KEY in parsed, parsed["models"], parsed["secret_ref"], parsed["provider"],
           parsed["credential_format"], parsed["max_concurrent_workers"]),
          (False, ["sol", "luna", "terra"], "ACCT07_TOKEN", "openai", "codex-auth-json", 1))
    check("[#616] and the stamped line is still readable back out of that same record body",
          parse_record_line(record_body), ["o/second", "o/target"])
    live_policy = (root / "policy/repos.toml").read_text(encoding="utf-8")
    live_enabled = enabled_targets(live_policy)
    check("the REAL policy/repos.toml parses and has enabled rows", bool(live_enabled), True)
    if len(live_enabled) >= 2:
        first, second = live_enabled[0], live_enabled[1]
        live_granted = render_grant(live_policy, "acct99", [first])
        check(f"a real-policy grant to {first} leaves {second} byte-identical",
              pool(live_granted, second), pool(live_policy, second))
        check("a real-policy grant is verifiable end to end",
              verify_membership(live_granted, "acct99", [first]), [first])
        check("[#579] the retired global append on the REAL policy is refused",
              refuses(verify_grant, live_policy, _legacy_global_append(live_policy, "acct99"),
                      "acct99", [first], needle="NON-TARGET row"), True)

    # #616 findings 3 + 4 (TEST VACUITY on the wiring). Every assertion below used to be a
    # WHOLE-FILE substring check, and every one of those was satisfiable by a prose comment or by
    # the same call in a DIFFERENT step: deleting the post-login `grant.authorize(...)` from the
    # privileged write step left "the login job re-proves authorization live" green, because the
    # pre-login step calls it too — so invariant 5, the entire point of the ~13-minute sign-in
    # window, had no mutation-effective coverage. The workflow is therefore read comment-stripped
    # and PER STEP from here down: each guard is asserted against the one step that must call it.
    workflow = (root / ".github/workflows/set-up-account.yml").read_text(encoding="utf-8")
    executable = strip_yaml_comments(workflow)
    preflight = workflow_step(workflow, "grant")            # pre-login authorization preflight
    write = workflow_step(workflow, "policy_pr")            # the privileged policy write
    register = workflow_step(workflow, "register")          # the account record stamp
    activated = workflow_step(workflow, "activate_merged")  # the post-merge activation proof
    check("the step extractor bounds exactly ONE step (it is not returning the whole file)",
          ("Authorize the target repositories" in preflight,
           "Open a checked account_pool PR" in preflight,
           "Open a checked account_pool PR" in write,
           "Authorize the target repositories" in write),
          (True, False, True, False))
    check("the extracted step body is comment-stripped, so prose cannot satisfy a wiring check",
          [line for line in write.split("\n") if line.lstrip().startswith("#")], [])
    check("an absent/renamed step id fails LOUDLY instead of asserting vacuously",
          refuses(workflow_step, workflow, "no_such_step", needle="found 0"), True)
    check("set-up-account.yml loads this helper",
          "scripts/grant-account.py" in executable, True)
    check("[#579] the pre-login preflight authorizes from the request's own grant labels",
          "grant.authorize" in preflight, True)
    check("[#579/#616] the PRIVILEGED WRITE STEP re-proves authorization live against the snapshot",
          ("grant.authorize" in write, "snapshot" in write), (True, True))
    check("the write step renders the row-scoped edit and verifies it exactly",
          ("grant.render_grant" in write, "grant.verify_grant" in write), (True, True))
    check("[#616] the no-op path proves membership AND merged-grant-PR provenance",
          ("grant.verify_membership" in write, "grant.merged_grant_prs" in write,
           "grant.require_grant_pr_scope" in write), (True, True, True))
    check("[#616] the ACTIVATE step re-proves the record, membership AND the two-document scope",
          ("grant.parse_record_line" in activated, "grant.verify_membership" in activated,
           "grant.verify_grant" in activated), (True, True, True))
    check("[#579] the account record stamp happens in the REGISTER step",
          "grant.format_record_line" in register, True)
    check("[#579] the policy write never substitutes over the document",
          bool(_LEGACY_GLOBAL_PATTERN.search(write)) or ".subn(" in write or "re.sub(" in write,
          False)
    check("[#579] set-up-account.yml no longer carries an existential pool check",
          "any(handle in" in executable, False)
    check("untrusted issue labels cross into the shell as JSON data, not interpolation",
          "${{ toJSON(github.event.issue.labels.*.name) }}" in executable
          and "${{ join(github.event.issue.labels" not in executable, True)
    template = (root / ".github/ISSUE_TEMPLATE/set-up-account.yml").read_text(encoding="utf-8")
    check("the request form documents the grant label (in the form itself, not a comment)",
          GRANT_LABEL_PREFIX in strip_yaml_comments(template), True)

    print("grant-account self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    parser.error("grant-account.py is a shared helper module; only --self-test runs standalone")
    return 2


if __name__ == "__main__":
    sys.exit(main())
