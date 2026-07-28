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
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
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
    # The ONE opt-out from the grant-delta requirement, and the reason it is safe: this function is
    # idempotent per row BY CONTRACT, so a handle already present in every requested row must return
    # a byte-identical document for the caller's no-op path to recognize. That path then proves
    # provenance separately (verify_membership + merged_grant_prs + require_grant_pr_scope +
    # verify_grant_patch) rather than treating no-change as a grant.
    verify_grant(policy_text, new_text, handle, resolved, require_delta=False)
    return new_text


def _changed_line_indexes(before_text, after_text):
    before = before_text.split("\n")
    after = after_text.split("\n")
    if len(before) != len(after):
        raise GrantError(
            f"the proposed policy adds or removes lines ({len(before)} -> {len(after)}) — a grant "
            "only rewrites account_pool assignments (fail closed)")
    return [index for index in range(len(before)) if before[index] != after[index]]


def verify_grant(before_text, after_text, handle, targets, require_delta=True):
    """The EXACT, per-target postcondition on a proposed grant (invariant 4). Returns the sorted
    target set; raises GrantError otherwise.

    `require_delta=True` (the DEFAULT, and the fail-closed posture) additionally requires that this
    pair actually ESTABLISHED part of the grant: at least one requested target row must have gone
    from not-listing `handle` to listing it. #616 review round 2 (MAJOR): without it an empty
    changed-line set was a SUCCESS, so a byte-identical (or formatting-only, or
    different-file-only) pair passed both this check and verify_membership — pre-seeded membership
    plus a non-grant `account-pool/<handle>` PR could flip status:pending -> status:available. The
    partial case still passes: a handle already present in target A and added to target B has one
    added row, which is exactly "this diff established part of the grant".

    The ONE legitimate opt-out is render_grant's idempotent per-row contract, where a byte-identical
    result is a meaningful outcome the CALLER then handles as the no-op path (and which carries its
    own merged-grant-PR provenance proof). Callers must opt out explicitly; nothing defaults to it.

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
    established = []
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
            if handle not in base_pool:
                established.append(name)
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
    if require_delta and not established:
        raise GrantError(
            f"this policy pair does not ADD {handle} to any requested target row — every requested "
            f"row of {resolved} already listed it, so nothing here established the grant. A "
            "byte-identical or formatting-only change is not a grant, and a PR that did not "
            "establish the membership must never license activating a credential (fail closed)")
    return resolved


def _pool_entries(pool_line):
    """The quoted entries of a single-line `account_pool = [...]` assignment, or None."""
    match = _POOL_LINE_RE.match(pool_line)
    if not match:
        return None
    return [entry.strip() for entry in match.group(2).split(",") if entry.strip()]


def patch_changed_lines(record):
    """`additions + deletions` from ONE `pulls/N/files` record, as the completeness oracle for its
    `patch` string. GrantError when the record does not carry both as non-negative integers.

    #616 review round 4 (MAJOR): `--paginate --slurp` proves every file RECORD was listed; it proves
    nothing about whether each record's `patch` STRING is that file's whole diff. GitHub truncates
    (and for very large diffs omits) `patch`, and a returned PREFIX that happens to contain a
    complete legitimate grant hunk while omitting a later hunk used to be accepted as a complete
    proof. The API reports the file's real changed-line counts in the same record, so the patch can
    be checked for completeness against them instead of being trusted."""
    if not isinstance(record, dict):
        raise GrantError("the changed-file record is not an object — refusing to judge the "
                         "completeness of its diff (fail closed)")
    counts = []
    for key in ("additions", "deletions"):
        value = record.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise GrantError(
                f"the changed-file record carries no usable `{key}` count ({value!r}), so a "
                "TRUNCATED patch cannot be ruled out — refusing (fail closed)")
        counts.append(value)
    return counts[0] + counts[1]


def verify_grant_patch(patch, handle, changed_lines):
    """Prove from a PULL REQUEST'S OWN unified diff of the policy document that the PR ADDED
    `handle` to one or more `account_pool` assignments and changed nothing else there.

    WHY THIS EXISTS AND WHAT IT REPLACES — #616 review round 2, both MAJORs.

    (1) The post-merge two-document proof reads the pre-merge policy from the merge commit's FIRST
    PARENT. That is master-immediately-before for a merge commit, a squash and a SINGLE-commit
    rebase — but this repository reports `allow_rebase_merge: true`, and for a MULTI-COMMIT rebase
    the final commit's first parent is an earlier commit OF THE SAME PR, so earlier unrelated policy
    edits carried by that PR are INVISIBLE to the comparison. A PR's `files[].patch` is computed
    against the MERGE BASE, so it covers every commit of the PR whatever strategy merged it: this
    check is strategy-independent and closes that hole. Re-reading the whole document at the merge
    base instead would have reintroduced false refusals — a concurrent enrollment landing between
    the merge base and the merge legitimately adds ANOTHER handle to the same rows — which is why
    the fix is a diff-level proof rather than a different base for the document-level one.

    (2) It is also the grant-DELTA proof at the PR level: an absent or empty patch (a
    byte-identical, formatting-only or other-file-only PR) is a REFUSAL, so a non-grant PR on the
    `account-pool/<handle>` branch can no longer stand in for a reviewed grant.

    Requirements, all of them refusals otherwise: the patch is readable, non-empty and COMPLETE
    (see `changed_lines`); every removed and added line is a single-line `account_pool` assignment;
    no removed line already lists `handle`; every added line lists `handle` exactly once; and
    stripping `handle` from each added line's entries reproduces the removed lines' entry lists
    EXACTLY, POSITION BY POSITION. Any other policy edit — a different handle added or removed, a
    reordered pool, a non-pool field, a comment rewrite — therefore fails. Pure; unit-tested by
    --self-test.

    POSITIONAL, NOT A MULTISET — #616 review round 4 (MAJOR), reproduced. The comparison used to be
    `sorted(stripped) != sorted(removed)`, i.e. a GLOBAL multiset that is order-insensitive ACROSS
    ROWS, while the row scoping it deferred to (verify_grant) runs against the merge commit's first
    parent — which under a MULTI-COMMIT REBASE is a commit of the same PR. So a PR whose commit 1
    SWAPPED two other accounts' pools and whose commit 2 added this handle passed all four proofs:
    the swap was already in `before`, and `removed [[aa],[bb]]` vs `stripped [[bb],[aa]]` sorted
    equal. Other accounts' repository authorizations moved silently, inside a PR whose review surface
    read "add acct99 to the pool". Within one file's patch, hunks and their changed groups are
    emitted in FILE ORDER on both sides, so `removed[i]` pairs with `added[i]` and the multiset was
    buying nothing that order did not already give: legitimate 1-row and 2-row grants still accept,
    while a cross-row swap and a 3-row rotation now refuse.

    ROW SCOPING IS STILL NOT THIS FUNCTION'S JOB: the diff carries no row NAMES. verify_grant (line
    spans, against the merged document) and verify_membership (handle in no non-target row) own that.
    What the positional form adds is that the pool CONTENTS cannot migrate between the lines this
    diff touches."""
    _require_handle(handle)
    quoted = f'"{handle}"'
    if not isinstance(patch, str) or not patch.strip():
        raise GrantError(
            f"the merged pull request carries no readable diff of the policy document, so it cannot "
            f"be proven that it ADDED {handle} to any account_pool — refusing (fail closed)")
    removed, added = [], []
    for line in patch.split("\n"):
        if line.startswith(("+++", "---", "@@", "\\")) or not line[:1] in {"+", "-"}:
            continue
        body = line[1:]
        entries = _pool_entries(body)
        if entries is None:
            raise GrantError(
                f"the grant diff changes {body.strip()!r}, which is not a single-line account_pool "
                "assignment — a grant PR rewrites account_pool lines and nothing else (fail closed)")
        (added if line.startswith("+") else removed).append(entries)
    # COMPLETENESS (#616 review round 4, MAJOR). Every changed line reaching this point is a pool
    # assignment (anything else raised above), so the patch's changed-line count must equal the count
    # the API reports for this file. A truncated patch — a prefix carrying a valid grant hunk while a
    # later hunk is cut off — is therefore a refusal instead of a proof. REQUIRED, positionally: a
    # default would be the fail-open shape (a caller that forgot it would still get a "proof"), so a
    # caller that omits it gets a TypeError and every production call site passes
    # patch_changed_lines(record).
    if not isinstance(changed_lines, int) or isinstance(changed_lines, bool) or changed_lines < 0:
        raise GrantError(
            f"the changed-line count for this patch is {changed_lines!r}, so a TRUNCATED patch "
            "cannot be ruled out — refusing (fail closed)")
    if len(added) + len(removed) != changed_lines:
        raise GrantError(
            f"the diff of the policy document carries {len(added) + len(removed)} changed "
            f"line(s) but the API reports {changed_lines} for that file — the patch is "
            "TRUNCATED or otherwise incomplete, so it cannot prove what this PR changed "
            "(fail closed)")
    if not added:
        raise GrantError(
            f"the grant diff adds no account_pool line, so it did not establish {handle}'s "
            "membership — refusing (fail closed)")
    if len(added) != len(removed):
        raise GrantError(
            f"the grant diff rewrites {len(removed)} account_pool line(s) into {len(added)}; a grant "
            "replaces each pool line it touches one-for-one — refusing (fail closed)")
    for entries in removed:
        if quoted in entries:
            raise GrantError(
                f"the grant diff REMOVES an account_pool line that already listed {handle}; a grant "
                "adds the handle, it never rewrites a row that already had it (fail closed)")
    stripped = []
    for entries in added:
        if entries.count(quoted) != 1:
            raise GrantError(
                f"an added account_pool line lists {handle} {entries.count(quoted)} time(s); the "
                "grant postcondition is EXACTLY once (fail closed)")
        stripped.append([entry for entry in entries if entry != quoted])
    if stripped != removed:
        raise GrantError(
            f"the grant diff changes account_pool members other than {handle} (before {removed}, "
            f"after {stripped} once {handle} is set aside, compared POSITION BY POSITION) — a grant "
            "adds ONE handle and moves nothing else, so this PR carries an edit outside its grant, "
            "or it MOVED pool members between rows (fail closed)")
    return len(added)


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


def evidence_grant_rows(before_text, after_text, handle):
    """The policy rows a merged pull request PROVABLY granted `handle` to, from its own pre/post
    documents (its merge commit and that commit's first parent). Sorted; GrantError otherwise.

    This is the ROW IDENTITY the diff-level proof cannot carry, and the reason the no-op path needed
    it is #616 review round 4 (MAJOR 3), reproduced: `verify_grant_patch` proves "some checked PR
    added this handle to SOME pool line", so a historical checked PR that granted row C validated a
    later, UNCHECKED membership in rows A and B once C was cleaned up — ZERO current targets traced
    to a checked PR. Here the rows the PR established are derived by parsing both of ITS OWN
    documents, and `verify_grant` then proves that PR's edit was scoped to exactly those rows, so
    the row names are as trustworthy as the two-document proof itself."""
    _require_handle(handle)
    before = _policy_repos(before_text)
    after = _policy_repos(after_text)
    gained = []
    for name in sorted(after):
        row, base_row = after[name], before.get(name)
        if not isinstance(row, dict) or not isinstance(base_row, dict):
            continue
        pool, base_pool = row.get("account_pool"), base_row.get("account_pool")
        if not isinstance(pool, list) or not isinstance(base_pool, list):
            continue
        if handle in pool and handle not in base_pool:
            gained.append(name)
    if not gained:
        raise GrantError(
            f"added {handle} to no account_pool row between its merge commit and that commit's "
            "first parent, so it did not establish this membership (fail closed)")
    # The same exact, row-scoped postcondition the live path uses: this PR added the handle to
    # exactly `gained` and moved nothing else in the document.
    verify_grant(before_text, after_text, handle, gained)
    return gained


def trace_membership_provenance(handle, targets, candidates, path):
    """Map EVERY requested target to a merged pull request that provably granted `handle` to THAT
    row. Returns {target: pr number}; GrantError when any target is untraced.

    #616 review round 4 (MAJOR 3). The previous no-op-path bound — "the enrollment's own PR must be
    a provable grant" — cannot hold on a path that by construction has no own PR, and what the code
    actually proved was only that SOME merged `account-pool/<handle>` PR added the handle to SOME
    pool line. Each candidate must now clear all four of: the file-level scope (only `path`
    changed), a COMPLETE (non-truncated) diff of that file, that diff being a positional
    handle-only grant, and the row-scoped two-document proof that names the rows it established.

    WHAT THIS DOES AND DOES NOT BOUND, stated exactly. It does establish that every target row of
    THIS enrollment was, at some point, granted this handle by a merged, checked, row-scoped PR — so
    the zero-traced-target path above is closed. It does NOT prove the CURRENT bytes of those rows
    are the ones that PR wrote: an unchecked later edit could have removed the handle from a row and
    re-added it. `verify_membership` proves today's shape, and the two together are the honest
    bound. Closing that last gap needs per-row history (a commit walk of the policy document), which
    is deliberately not attempted here."""
    _require_handle(handle)
    resolved = sorted(set(targets or []))
    if not resolved:
        raise GrantError("cannot trace the provenance of an empty target set — refusing")
    if not isinstance(candidates, (list, tuple)) or not candidates:
        raise GrantError(
            f"no merged grant pull request is available to account for {handle}'s membership — "
            "refusing (fail closed)")
    traced, refusals = {}, []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise GrantError(f"unreadable grant-PR evidence entry {candidate!r} — refusing")
        number = candidate.get("number")
        try:
            require_grant_pr_scope(number, candidate.get("changed") or [], path)
            records = [entry for entry in candidate["changed"]
                       if isinstance(entry, dict) and entry.get("filename") == path]
            if len(records) != 1:
                raise GrantError(f"carries {len(records)} diffs of {path}, expected exactly 1")
            verify_grant_patch(records[0].get("patch"), handle, patch_changed_lines(records[0]))
            rows = evidence_grant_rows(candidate.get("before"), candidate.get("after"), handle)
        except GrantError as exc:
            refusals.append(f"#{number}: {exc}")
            continue
        for row in rows:
            traced.setdefault(row, number)
    missing = [target for target in resolved if target not in traced]
    if missing:
        raise GrantError(
            f"no merged, row-scoped grant pull request accounts for {handle}'s membership in "
            f"{missing} — the membership of those rows was not established by a checked grant PR, "
            f"so this enrollment cannot activate on it — {'; '.join(refusals) or 'no candidates'} "
            "(fail closed)")
    return {target: traced[target] for target in resolved}


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


def workflow_step_raw(text, step_id):
    """The ONE workflow step whose `id:` is `step_id`, WITH its comments — for the paths that must
    execute a delimited region of the step (the sentinels are comments, so they must survive)."""
    return _workflow_step_slice(text, step_id)


def workflow_step(text, step_id):
    """The full YAML text of the ONE workflow step whose `id:` is `step_id`, comments stripped.

    Located by the step's `id:` and bounded by the surrounding sequence indentation, so a call in a
    NEIGHBOURING step (or in a header comment) cannot satisfy an assertion about this one. Raises
    GrantError when no such step exists or the extracted body is empty — a wiring assertion that
    cannot find its step must fail, never pass vacuously."""
    body = strip_yaml_comments(_workflow_step_slice(text, step_id))
    if not body.strip():
        raise GrantError(f"step `id: {step_id}` extracted to an empty body — refusing")
    return body


def _workflow_step_slice(text, step_id):
    """The raw lines of the ONE step whose `id:` is `step_id` (shared by both extractors above)."""
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
    slice_text = "\n".join(lines[start:end])
    if not slice_text.strip():
        raise GrantError(f"step `id: {step_id}` extracted to an empty body — refusing")
    return slice_text


def workflow_step_script(text, step_id):
    """The EXECUTABLE `run:` script of the ONE step whose `id:` is `step_id`, dedented.

    #616 review round 4 (MAJOR 2): every step except `meta`'s provider fragment was asserted by
    per-step substring PRESENCE, and presence is not outcome — turning `activate_merged`'s own
    `except grant.GrantError: sys.exit(1)` into a `::warning::` left the full 34-script suite green,
    a one-token fail-open on the credential boundary. The privileged body is EXECUTED instead, the
    way #612 / #605 / #597 execute theirs. Comments are preserved: this text goes to bash, and the
    step's own `# >>>` sentinels must survive for workflow_block."""
    lines = workflow_step_raw(text, step_id).split("\n")
    heads = [index for index, line in enumerate(lines) if line.strip() in {"run: |", "run: |-"}]
    if len(heads) != 1:
        raise GrantError(
            f"step `id: {step_id}` has {len(heads)} block `run:` scripts, expected exactly 1 — "
            "refusing to execute a body that cannot be located (fail closed)")
    head = heads[0]
    indent = len(lines[head]) - len(lines[head].lstrip())
    body = []
    for line in lines[head + 1:]:
        if line.strip() and (len(line) - len(line.lstrip())) <= indent:
            break
        body.append(line[indent + 2:] if line.strip() else "")
    script = "\n".join(body)
    if not script.strip():
        raise GrantError(f"step `id: {step_id}` extracted to an empty `run:` script — refusing")
    return script


def workflow_block(text, step_id, marker):
    """The dedented fragment between `# >>> <marker>` and `# <<< <marker>` inside the ONE step whose
    `id:` is `step_id` — a region meant to be EXECUTED, so its comments are preserved.

    #616 review round 2 (MAJOR): the provider-label predicate had no test at all. Executing it needs
    a delimited fragment; the sentinels are part of the workflow, and removing either makes this
    raise rather than silently extracting something else."""
    body = workflow_step_raw(text, step_id).split("\n")
    opens = [index for index, line in enumerate(body)
             if line.strip().startswith(f"# >>> {marker}")]
    closes = [index for index, line in enumerate(body) if line.strip() == f"# <<< {marker}"]
    if len(opens) != 1 or len(closes) != 1 or closes[0] <= opens[0]:
        raise GrantError(
            f"step `id: {step_id}` must carry exactly one `# >>> {marker}` ... `# <<< {marker}` "
            f"pair, found {len(opens)}/{len(closes)} — refusing to assert vacuously")
    kept = [line for line in body[opens[0] + 1:closes[0]]
            if line.strip() and not line.lstrip().startswith("#")]
    if not kept:
        raise GrantError(f"the `{marker}` block extracted to nothing — refusing")
    pad = min(len(line) - len(line.lstrip()) for line in kept)
    return "\n".join(line[pad:] for line in kept)


def workflow_step_env(text, step_id):
    """The `env:` mapping declared by the ONE step whose `id:` is `step_id` (comments stripped).

    #263: the TRANSPORT of untrusted label names is the `env:` block, not the script, so a test
    that executes a step's fragment must take the fragment's environment FROM THE WORKFLOW rather
    than supplying it. Deleting or renaming `LABELS_JSON:` then leaves the variable unset and the
    fragment dies under `set -u`, instead of passing against a value the test kindly provided.
    A step with no `env:` block, or an unparseable entry, raises — never an empty environment."""
    lines = workflow_step(text, step_id).split("\n")
    heads = [index for index, line in enumerate(lines) if line.strip() == "env:"]
    if len(heads) != 1:
        raise GrantError(
            f"expected exactly one `env:` block in step `id: {step_id}`, found {len(heads)} — "
            "refusing to execute a fragment whose environment cannot be located (fail closed)")
    indent = len(lines[heads[0]]) - len(lines[heads[0]].lstrip())
    mapping = {}
    for line in lines[heads[0] + 1:]:
        if not line.strip():
            continue
        if (len(line) - len(line.lstrip())) <= indent:
            break
        key, sep, value = line.strip().partition(":")
        if not sep or not key.strip():
            raise GrantError(
                f"step `id: {step_id}` carries an unparseable `env:` entry {line.strip()!r} — "
                "refusing to guess its environment (fail closed)")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        mapping[key.strip()] = value
    if not mapping:
        raise GrantError(f"step `id: {step_id}` declares an empty `env:` block — refusing")
    return mapping


_GHA_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
# `join(<array>, '<sep>')` — the array argument of interest carries no comma of its own.
_GHA_JOIN_SEPARATOR = re.compile(r"^join\(\s*[^,]*,\s*(['\"])(.*?)\1\s*\)$", re.S)


def render_gha_expressions(text, labels):
    """`text` with every `${{ ... }}` expression substituted the way the Actions runner substitutes
    it: TEXTUALLY, before anything — a shell, a YAML value — parses the result.

    #263, THE HAZARD THIS MODELS. `${{ join(github.event.issue.labels.*.name, ' ') }}` written
    inline in a `run:` block is not an argument the shell receives; it is source code the label
    name BECOMES. Labels can be applied by anyone with TRIAGE permission while set-up-account's
    trust gate only vets the triggering actor and the issue author for admin/maintain, so a
    pre-applied label named `$(...)` was code execution inside a job holding issues:write +
    contents:write that gates the REGISTRY_SECRETS_PAT steps. Rendering here lets --self-test run
    the REAL fragment exactly as the runner would, with a hostile label, and observe whether that
    label is data or code — an assertion that no amount of prose about `env:` can stand in for.

    Only label-reading expressions are modelled (`toJSON` -> the JSON document, `join` -> its
    separator, a bare `.*.name` array -> space-separated, matching the runner); every other
    expression renders to an inert placeholder, because this is a label-injection harness and not
    a general Actions evaluator. Pure; unit-tested by --self-test, including the proof that it
    DOES inject through the old inline form (a renderer that quietly neutralized everything would
    make the regression below vacuous)."""
    if not isinstance(text, str):
        raise GrantError("cannot render expressions in a non-text fragment — refusing")
    if not isinstance(labels, list) or any(not isinstance(name, str) for name in labels):
        raise GrantError("label names must render from a list of strings — refusing")

    def one(match):
        expr = match.group(1).strip()
        if "github.event.issue.labels" not in expr:
            return "<gha>"
        if expr.startswith("toJSON("):
            return json.dumps(labels)
        separator = _GHA_JOIN_SEPARATOR.match(expr)
        if separator:
            return separator.group(2).join(labels)
        if expr.startswith("join("):
            return ",".join(labels)   # join()'s documented default separator
        return " ".join(labels)       # a bare `.*.name` array renders space-separated

    return _GHA_EXPRESSION.sub(one, text)


def _condition_at(lines, start, end, indent):
    """The single-space-normalized `if:` expression declared at `indent` between `start` and `end`.

    #616 review round 2 (MAJOR): workflow_step validates step BODIES only, never the enclosing
    job/event/workflow `if:` — so flipping the condition that restricts activation to a MERGED
    `account-pool/*` pull request left every test green. Folded (`>-`) and inline forms are both
    handled; a missing or duplicated `if:` raises, so a control condition that cannot be located
    can never be asserted vacuously."""
    marks = [index for index in range(start, end)
             if (len(lines[index]) - len(lines[index].lstrip())) == indent
             and lines[index].lstrip().startswith("if:")]
    if len(marks) != 1:
        raise GrantError(f"expected exactly one `if:` at indent {indent}, found {len(marks)}")
    head = lines[marks[0]].lstrip()[len("if:"):].strip()
    collected = [] if head in {">-", ">", "|", "|-"} else [head]
    for index in range(marks[0] + 1, end):
        if not lines[index].strip():
            continue
        if (len(lines[index]) - len(lines[index].lstrip())) <= indent:
            break
        collected.append(lines[index].strip())
    condition = " ".join(" ".join(collected).split())
    if not condition:
        raise GrantError(f"the `if:` at indent {indent} extracted to an empty expression")
    return condition


def job_condition(text, job_id):
    """The `if:` expression guarding the WORKFLOW JOB `job_id`, whitespace-normalized."""
    lines = text.split("\n")
    marks = [index for index, line in enumerate(lines) if line == f"  {job_id}:"]
    if len(marks) != 1:
        raise GrantError(
            f"expected exactly one job `{job_id}:` at the jobs indent, found {len(marks)}")
    end = len(lines)
    for index in range(marks[0] + 1, len(lines)):
        line = lines[index]
        if line.strip() and (len(line) - len(line.lstrip())) <= 2:
            end = index
            break
    return _condition_at(lines, marks[0] + 1, end, 4)


def step_condition(text, step_id):
    """The `if:` expression guarding the STEP whose `id:` is `step_id`, whitespace-normalized."""
    body = workflow_step(text, step_id).split("\n")
    return _condition_at(body, 0, len(body), len(body[0]) - len(body[0].lstrip()) + 2)


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

    # ------------------------------------------------------------------------------------------
    # [#616 review ROUND 4, MAJOR 3] THE NO-OP PATH'S TARGET-SET RESIDUAL WAS BROADER THAN DISCLOSED.
    # `verify_grant_patch` carries no row identity, so a historical checked PR that added the handle
    # to row C validated later UNCHECKED membership in rows A and B once C was cleaned up — ZERO
    # current targets traced to a checked PR, while the notice claimed the membership WAS traced. Row
    # identity now comes from each candidate PR's own pre/post documents, and every requested target
    # must be traced. The row below is that exact reproduction, and it must REFUSE.
    # ------------------------------------------------------------------------------------------
    policy_path = "policy/repos.toml"
    three_rows = FIXTURE.replace('[repos."o/disabled"]\nenabled = false',
                                 '[repos."o/third"]\nenabled = true')

    def evidence(number, before_text, after_text, patch, additions=1, deletions=1, files=None):
        record = {"filename": policy_path, "additions": additions, "deletions": deletions,
                  "patch": patch}
        return {"number": number, "before": before_text, "after": after_text,
                "changed": [record] if files is None else files}

    granted_third = render_grant(three_rows, "acct07", ["o/third"])
    third_patch = ('@@ -18,1 +18,1 @@\n-account_pool = ["acct09"]\n'
                   '+account_pool = ["acct09", "acct07"]\n')
    # ...and the CURRENT membership: acct07 seeded into o/target + o/second by an unchecked edit,
    # removed from o/third. The only checked PR on the branch is the o/third grant above.
    seeded_now = render_grant(three_rows, "acct07", ["o/second", "o/target"])
    check("[#616 r4] a checked PR that granted a DIFFERENT row cannot validate today's targets",
          refuses(trace_membership_provenance, "acct07", ["o/second", "o/target"],
                  [evidence(41, three_rows, granted_third, third_patch)], policy_path,
                  needle="no merged, row-scoped grant pull request accounts for"), True)
    check("[#616 r4] ...and verify_membership alone was happy with that seeded document (why it hid)",
          verify_membership(seeded_now, "acct07", ["o/second", "o/target"]),
          ["o/second", "o/target"])
    # The positive control: the SAME rows, granted by a real row-scoped PR, trace.
    real_grant = render_grant(three_rows, "acct07", ["o/second", "o/target"])
    real_patch = ('@@ -5,1 +5,1 @@\n-account_pool = ["acct01", "acct02"]\n'
                  '+account_pool = ["acct01", "acct02", "acct07"]\n'
                  '@@ -16,1 +16,1 @@\n-account_pool = ["acct01"]\n'
                  '+account_pool = ["acct01", "acct07"]\n')
    check("[#616 r4] a row-scoped grant PR traces every requested target to itself",
          trace_membership_provenance("acct07", ["o/second", "o/target"],
                                      [evidence(41, three_rows, real_grant, real_patch,
                                                additions=2, deletions=2)], policy_path),
          {"o/second": 41, "o/target": 41})
    # A UNION of two checked PRs is accepted (a two-request history is legitimate); a partial union
    # is not, so no target can ride in on another's provenance.
    first_only = render_grant(three_rows, "acct07", ["o/target"])
    first_patch = ('@@ -5,1 +5,1 @@\n-account_pool = ["acct01", "acct02"]\n'
                   '+account_pool = ["acct01", "acct02", "acct07"]\n')
    second_patch = ('@@ -16,1 +16,1 @@\n-account_pool = ["acct01"]\n'
                    '+account_pool = ["acct01", "acct07"]\n')
    check("[#616 r4] two checked PRs, one row each, together trace both targets",
          trace_membership_provenance(
              "acct07", ["o/second", "o/target"],
              [evidence(41, three_rows, first_only, first_patch),
               evidence(42, first_only, real_grant, second_patch)], policy_path),
          {"o/second": 42, "o/target": 41})
    check("[#616 r4] ...but a PARTIAL union still refuses the untraced row",
          refuses(trace_membership_provenance, "acct07", ["o/second", "o/target"],
                  [evidence(41, three_rows, first_only, first_patch)], policy_path,
                  needle="['o/second']"), True)
    check("[#616 r4] a candidate whose own pre/post documents show NO grant is not evidence",
          refuses(trace_membership_provenance, "acct07", ["o/target"],
                  [evidence(41, first_only, first_only, first_patch)], policy_path,
                  needle="added acct07 to no account_pool row"), True)
    check("[#616 r4] a candidate whose edit reached another row is not evidence either",
          refuses(trace_membership_provenance, "acct07", ["o/target"],
                  [evidence(41, three_rows,
                            first_only.replace('account_pool = ["acct09"]',
                                               'account_pool = ["acct09", "acct42"]'),
                            first_patch)], policy_path,
                  needle="NON-TARGET row"), True)
    check("[#616 r4] an empty candidate list and an empty target set both refuse",
          (refuses(trace_membership_provenance, "acct07", ["o/target"], [], policy_path,
                   needle="no merged grant pull request is available"),
           refuses(trace_membership_provenance, "acct07", [],
                   [evidence(41, three_rows, first_only, first_patch)], policy_path,
                   needle="empty target set")), (True, True))
    check("[#616 r4] evidence_grant_rows names exactly the rows the PR established",
          evidence_grant_rows(three_rows, real_grant, "acct07"), ["o/second", "o/target"])

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

    # ------------------------------------------------------------------------------------------
    # [#616 review ROUND 2, MAJOR 1] AUTHORIZATION: A NO-DELTA PAIR IS NOT A GRANT. verify_grant
    # returned SUCCESS on a byte-identical (or formatting-only, or other-file-only) pair, because
    # _changed_line_indexes returns [] and nothing required the pair to have ADDED the handle. With
    # membership pre-seeded by any other means, a non-grant `account-pool/<handle>` PR therefore
    # passed BOTH verify_membership and verify_grant and could flip status:pending ->
    # status:available. These rows assert the REFUSAL, so a mutant that drops the requirement is
    # caught ADMITTING the non-grant pair, not merely missing a call.
    # ------------------------------------------------------------------------------------------
    seeded = render_grant(FIXTURE, "acct07", ["o/target"])
    check("[#616 r2] a byte-identical policy pair is REFUSED as a grant (no delta established)",
          refuses(verify_grant, seeded, seeded, "acct07", ["o/target"],
                  needle="does not ADD acct07"), True)
    check("[#616 r2] ...and so is a pair whose every requested row already listed the handle",
          refuses(verify_grant, seeded, seeded, "acct07", ["o/target"],
                  needle="already listed it"), True)
    check("[#616 r2] a PARTIAL pre-existing grant still passes (one row added is a real delta)",
          verify_grant(seeded, render_grant(seeded, "acct07", ["o/target", "o/second"]),
                       "acct07", ["o/target", "o/second"]),
          ["o/second", "o/target"])
    check("[#616 r2] render_grant keeps its idempotent per-row contract (the ONE opt-out)",
          render_grant(seeded, "acct07", ["o/target"]), seeded)

    # ------------------------------------------------------------------------------------------
    # [#616 review ROUND 2, MAJOR 2] THE REBASE-MERGE BASE HOLE. The post-merge proof reads the
    # pre-merge policy from the merge commit's FIRST PARENT; this repository reports
    # `allow_rebase_merge: true`, so for a MULTI-COMMIT rebase that parent is an earlier commit OF
    # THE SAME PR and the PR's earlier policy edits are invisible to the comparison. The PR's own
    # `files[].patch` is computed against the MERGE BASE, so it sees every commit of the PR whatever
    # strategy merged it: verify_grant_patch is the strategy-independent proof. Each row asserts a
    # REFUSAL of a diff a rebase could otherwise have hidden.
    # ------------------------------------------------------------------------------------------
    good_patch = ('@@ -3,3 +3,3 @@\n'
                  ' routing = "r.toml"\n'
                  '-account_pool = ["acct01", "acct02"]\n'
                  '+account_pool = ["acct01", "acct02", "acct07"]\n')
    check("[#616 r2] a real grant diff is accepted and counts the rows it granted",
          verify_grant_patch(good_patch, "acct07", 2), 1)
    # Split into separate rows on purpose: each must be able to go red and PRINT independently, so a
    # mutant that removes the readability guard reports a legible refusal-became-acceptance rather
    # than taking the suite down on the `None` row before the string row is shown.
    check("[#616 r2] an EMPTY diff is refused — a no-delta PR never licenses activation",
          refuses(verify_grant_patch, "", "acct07", 2, needle="no readable diff"), True)
    check("[#616 r2] an ABSENT diff (patch omitted by the API) is refused the same way",
          refuses(verify_grant_patch, None, "acct07", 2, needle="no readable diff"), True)
    check("[#616 r2] a context-only diff is refused (it establishes nothing)",
          refuses(verify_grant_patch, "@@ -1,1 +1,1 @@\n context only\n", "acct07", 0,
                  needle="adds no account_pool line"), True)
    check("[#616 r2] a diff that ALSO edits a non-pool policy line is refused (the rebase payload)",
          refuses(verify_grant_patch,
                  good_patch + '-max_concurrent = 2\n+max_concurrent = 9\n', "acct07", 4,
                  needle="not a single-line account_pool assignment"), True)
    check("[#616 r2] a diff that ALSO adds a DIFFERENT handle elsewhere is refused",
          (refuses(verify_grant_patch,
                   good_patch
                   + '-account_pool = ["acct01"]\n+account_pool = ["acct01", "acct99", "acct07"]\n',
                   "acct07", 4, needle="members other than acct07"),
           # ...and a second changed pool line that does not carry the handle at all is refused too
           refuses(verify_grant_patch,
                   good_patch + '-account_pool = ["acct01"]\n+account_pool = ["acct01", "acct99"]\n',
                   "acct07", 4, needle="EXACTLY once")),
          (True, True))
    check("[#616 r2] a diff that REMOVES another handle while adding this one is refused",
          refuses(verify_grant_patch,
                  '-account_pool = ["acct01", "acct02"]\n+account_pool = ["acct01", "acct07"]\n',
                  "acct07", 2, needle="members other than acct07"), True)
    check("[#616 r2] a diff that rewrites a row ALREADY listing the handle is refused",
          refuses(verify_grant_patch,
                  '-account_pool = ["acct07"]\n+account_pool = ["acct07", "acct07"]\n',
                  "acct07", 2, needle="already listed"), True)
    check("[#616 r2] a diff adding the handle TWICE is refused (exactly once, at diff level too)",
          refuses(verify_grant_patch,
                  '-account_pool = ["acct01"]\n+account_pool = ["acct01", "acct07", "acct07"]\n',
                  "acct07", 2, needle="EXACTLY once"), True)
    check("[#616 r2] a pure DELETION of a pool line is refused (nothing was established)",
          refuses(verify_grant_patch, '-account_pool = ["acct01", "acct07"]\n', "acct07", 1,
                  needle="adds no account_pool line"), True)
    # Two granted rows in two hunks. The comparison is POSITIONAL (#616 review round 4), and
    # permuting whole hunks permutes BOTH streams together, so hunk ordering still cannot make a
    # correct grant false-refuse — which is exactly why the multiset was buying nothing.
    two_rows = ('@@ -5,1 +5,1 @@\n-account_pool = ["acct01", "acct02"]\n'
                '+account_pool = ["acct01", "acct02", "acct07"]\n'
                '@@ -14,1 +14,1 @@\n-account_pool = ["acct01"]\n'
                '+account_pool = ["acct01", "acct07"]\n')
    check("[#616 r2] a two-row grant is accepted in either hunk order",
          (verify_grant_patch(two_rows, "acct07", 4),
           verify_grant_patch("\n".join(reversed(two_rows.strip().split("\n"))), "acct07", 4)),
          (2, 2))
    # ------------------------------------------------------------------------------------------
    # [#616 review ROUND 4, MAJOR 1] THE CROSS-ROW SWAP. `sorted(stripped) != sorted(removed)` is a
    # GLOBAL multiset — order-insensitive ACROSS rows — while the row scoping it deferred to runs
    # against the merge commit's first parent, which under a multi-commit rebase is a commit of the
    # SAME PR. So commit 1 could swap two other accounts' pools, commit 2 add the handle, and all
    # four proofs passed while other accounts' repository authorizations moved. Every row below
    # ACCEPTS under the multiset comparison and refuses under the positional one.
    # ------------------------------------------------------------------------------------------
    swap_patch = ('@@ -5,1 +5,1 @@\n-account_pool = ["acctaa"]\n+account_pool = ["acctbb", "acct07"]\n'
                  '@@ -14,1 +14,1 @@\n-account_pool = ["acctbb"]\n'
                  '+account_pool = ["acctaa", "acct07"]\n')
    rotation_patch = (
        '-account_pool = ["acctaa"]\n+account_pool = ["acctbb", "acct07"]\n'
        '-account_pool = ["acctbb"]\n+account_pool = ["acctcc", "acct07"]\n'
        '-account_pool = ["acctcc"]\n+account_pool = ["acctaa", "acct07"]\n')
    check("[#616 r4] a CROSS-ROW pool swap carried by a grant diff is refused",
          refuses(verify_grant_patch, swap_patch, "acct07", 4,
                  needle="POSITION BY POSITION"), True)
    check("[#616 r4] ...and so is a three-row rotation (the same defect, one row wider)",
          refuses(verify_grant_patch, rotation_patch, "acct07", 6,
                  needle="POSITION BY POSITION"), True)
    check("[#616 r4] the multiset form of that swap really was order-equal (why it passed)",
          sorted([["acctbb"], ["acctaa"]]) == sorted([["acctaa"], ["acctbb"]]), True)
    # ------------------------------------------------------------------------------------------
    # [#616 review ROUND 4, MAJOR 4] A TRUNCATED PATCH IS NOT A PROOF. `--paginate --slurp` proves
    # every file RECORD was listed; GitHub truncates (and for very large diffs omits) each record's
    # `patch` string, so a PREFIX carrying a complete legitimate grant hunk while a later hunk is cut
    # off used to be accepted. The API reports the file's own changed-line counts in the same record.
    # ------------------------------------------------------------------------------------------
    check("[#616 r4] a patch shorter than the API's own changed-line count is refused",
          refuses(verify_grant_patch, good_patch, "acct07", 4, needle="TRUNCATED"), True)
    check("[#616 r4] ...and a caller that cannot supply the count is refused too (no fail-open)",
          (refuses(verify_grant_patch, good_patch, "acct07", None, needle="TRUNCATED"),
           refuses(verify_grant_patch, good_patch, "acct07", -1, needle="TRUNCATED")),
          (True, True))
    check("[#616 r4] patch_changed_lines reads additions+deletions, and refuses a record without",
          (patch_changed_lines({"additions": 2, "deletions": 2}),
           refuses(patch_changed_lines, {"additions": 2}, needle="no usable `deletions`"),
           refuses(patch_changed_lines, {"additions": "2", "deletions": 2},
                   needle="no usable `additions`"),
           refuses(patch_changed_lines, {"additions": True, "deletions": 2},
                   needle="no usable `additions`"),
           refuses(patch_changed_lines, None, needle="not an object")),
          (4, True, True, True, True))

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
    # #616 review round 2: `"scripts/grant-account.py" in executable` was a WHOLE-FILE grep and the
    # path appears 7 times, so deleting the import from any single step left it green. Assert it
    # PER STEP, on each step that must load the helper to make a decision.
    check("[#616 r2] every DECIDING step loads this helper (per step, not whole-file)",
          {name: "scripts/grant-account.py" in body
           for name, body in (("grant", preflight), ("policy_pr", write),
                              ("register", register), ("activate_merged", activated))},
          {"grant": True, "policy_pr": True, "register": True, "activate_merged": True})
    check("[#579] the pre-login preflight authorizes from the request's own grant labels",
          "grant.authorize" in preflight, True)
    check("[#579/#616] the PRIVILEGED WRITE STEP re-proves authorization live against the snapshot",
          ("grant.authorize" in write, "snapshot" in write), (True, True))
    check("the write step renders the row-scoped edit and verifies it exactly",
          ("grant.render_grant" in write, "grant.verify_grant" in write), (True, True))
    check("[#616] the no-op path proves membership AND merged-grant-PR provenance",
          ("grant.verify_membership" in write, "grant.merged_grant_prs" in write,
           "grant.trace_membership_provenance" in write), (True, True, True))
    # #616 review round 2: branch name + filename prove the SHAPE of the provenance, not that the PR
    # ADDED THIS HANDLE. The no-op path must prove that from the candidate PR's own diff, and must
    # not just take the newest merged PR on the branch on trust.
    # #616 review round 4 (MAJOR 3): and the diff carries no ROW identity, so every requested target
    # must be traced to a candidate whose OWN pre/post documents (merge commit + first parent) show
    # it granted THAT row. The scope + completeness + positional-diff + row-scoping proofs all live
    # inside trace_membership_provenance, which is unit-tested above; what these rows pin is that the
    # privileged step calls it, with the two documents, over EVERY candidate. This step body is NOT
    # executed (only `activate_merged` and `meta` are) — stated plainly rather than implied.
    check("[#616 r4] the no-op path traces every target row to a checked PR, from two documents",
          ("grant.trace_membership_provenance" in write, "merged[-1]" in write,
           "for candidate in merged" in write, "merge_commit_sha" in write,
           '"before": policy_at(' in write, '"after": policy_at(' in write),
          (True, False, True, True, True, True))
    check("[#616] the ACTIVATE step re-proves the record, membership AND the two-document scope",
          ("grant.parse_record_line" in activated, "grant.verify_membership" in activated,
           "grant.verify_grant" in activated), (True, True, True))
    # #616 review round 2: activation omitted require_grant_pr_scope entirely (additional files in
    # the merged PR sat outside the final proof) and had no strategy-independent delta proof, so the
    # multi-commit-rebase first-parent hole was load-bearing. Both calls are asserted IN that step.
    check("[#616 r2] the ACTIVATE step also scopes the merged PR's FILES and proves its own diff",
          ("grant.require_grant_pr_scope" in activated,
           "grant.verify_grant_patch" in activated,
           "--paginate" in activated), (True, True, True))
    check("[#616 r2] the ACTIVATE step POST-READS the labels it flipped (the header's own claim)",
          ("did NOT land" in activated,
           # ...and the read comes AFTER the write, not before it. `find` (not `index`) so a deleted
           # post-read reports a legible False instead of taking the suite down on a ValueError.
           0 <= activated.find("gh issue edit") < activated.find("did NOT land")),
          (True, True))
    check("[#579] the account record stamp happens in the REGISTER step",
          "grant.format_record_line" in register, True)
    check("[#579] the policy write never substitutes over the document",
          bool(_LEGACY_GLOBAL_PATTERN.search(write)) or ".subn(" in write or "re.sub(" in write,
          False)
    check("[#579] set-up-account.yml no longer carries an existential pool check",
          "any(handle in" in executable, False)
    # #616 review round 2: the transport assertion was whole-file and `toJSON(...labels...)` appears
    # twice, so deleting one left it green. Scope it to the TWO steps that consume label names.
    meta = workflow_step(workflow, "meta")                  # the provider-label predicate
    check("[#616 r2] untrusted labels cross as JSON DATA in each consuming step, never interpolated",
          {name: ("${{ toJSON(github.event.issue.labels.*.name) }}" in body,
                  "${{ join(github.event.issue.labels" in body)
           for name, body in (("meta", meta), ("grant", preflight))},
          {"meta": (True, False), "grant": (True, False)})
    check("untrusted issue labels cross into the shell as JSON data, not interpolation",
          "${{ join(github.event.issue.labels" not in executable, True)

    # ------------------------------------------------------------------------------------------
    # [#616 review ROUND 2, MAJOR] WORKFLOW CONTROL CONDITIONS. workflow_step validates step BODIES
    # only, so flipping the condition that restricts activation to a MERGED `account-pool/*` pull
    # request left every test green — that condition IS the trust boundary of the activate job. Both
    # the job `if:` and the resume-gated step `if:` are now pinned EXACTLY, whitespace-normalized.
    # ------------------------------------------------------------------------------------------
    check("[#616 r2] the activate job fires ONLY for a MERGED account-pool/* pull request",
          job_condition(workflow, "activate"),
          "github.event_name == 'pull_request' && github.event.pull_request.merged == true && "
          "startsWith(github.event.pull_request.head.ref, 'account-pool/')")
    check("[#616 r2] the enrollment job fires only on the set-up-account label event",
          job_condition(workflow, "login"),
          "github.event_name == 'issues' && github.event.label.name == 'set-up-account'")
    check("[#616 r2] the provider-label step's resume condition is pinned",
          step_condition(workflow, "meta"), "steps.reconcile.outputs.resume != 'true'")
    check("[#616 r2] the privileged policy write runs only after a real login or a resume",
          step_condition(workflow, "policy_pr"),
          "steps.login.outputs.status == 'ok' || steps.reconcile.outputs.resume == 'true'")
    # #616 review round 4 (MINOR): the round-3 form of the row below was TAUTOLOGICAL —
    # `refuses(...) or step_condition(workflow, "register") != ""` has a second disjunct that is
    # unconditionally True, so it passed whether `register` carried no `if:` or any non-empty one.
    # Pin the condition EXACTLY (like every other one), and prove the loud-refusal behaviour on a
    # step that genuinely has no `if:` of its own — `activate_merged` is gated by its JOB.
    check("[#616 r4] the register step's condition is pinned exactly",
          step_condition(workflow, "register"), "steps.login.outputs.status == 'ok'")
    check("an absent/renamed job — and a step with no `if:` — fail LOUDLY, never vacuously",
          (refuses(job_condition, workflow, "no_such_job", needle="found 0"),
           refuses(step_condition, workflow, "no_such_step", needle="found 0"),
           refuses(step_condition, workflow, "activate_merged", needle="found 0")),
          (True, True, True))

    # ------------------------------------------------------------------------------------------
    # [#616 review ROUND 2, MAJOR] THE PROVIDER-LABEL PREDICATE IS EXECUTED. It had no test at all,
    # so `run:` -> `true`, restoring last-label-wins, or dropping `unique` all passed. The fragment
    # between its sentinels is extracted and RUN against label fixtures. `${{ }}` expressions are
    # rendered the way the runner renders them (#263) — label-reading ones carry the fixture's own
    # label names, every other one becomes an inert placeholder.
    #
    # #263: the fragment's environment is READ FROM THE STEP (workflow_step_env) instead of being
    # supplied by the test. The old form hardcoded `LABELS_JSON=json.dumps(labels)`, so it proved
    # the predicate's logic while saying nothing about the transport: deleting the `LABELS_JSON:`
    # env entry — or replacing it with an inline `join(...)` interpolation — left every row below
    # green. Now the transport IS the fixture, and the hostile-label regression at the end of this
    # block observes whether a metacharacter label name is data or code.
    # ------------------------------------------------------------------------------------------
    meta_env = workflow_step_env(workflow, "meta")
    provider_fragment = workflow_block(workflow, "meta", "provider-label")

    def provider_of(labels):
        """(exit code, resolved provider) from the REAL predicate fragment, run under the step's
        OWN `env:` block, both rendered exactly as the Actions runner would render them."""
        script = ("set -euo pipefail\n" + render_gha_expressions(provider_fragment, labels)
                  + '\nprintf "PROV=%s\\n" "$prov"\n')
        rendered = {key: render_gha_expressions(value, labels)
                    for key, value in meta_env.items()}
        done = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                              env={**os.environ, **rendered}, timeout=120, check=False)
        match = re.search(r"^PROV=(.*)$", done.stdout, re.M)
        return done.returncode, (match.group(1) if match else None)

    check("[#616 r2] exactly one provider label resolves that provider",
          [provider_of(["provider:openai", "status:pending"]),
           provider_of(["area:ci", "provider:anthropic"])],
          [(0, "openai"), (0, "anthropic")])
    check("[#616 r2] BOTH provider labels are REFUSED — last-label-wins must never come back",
          [provider_of(["provider:openai", "provider:anthropic"])[0],
           provider_of(["provider:anthropic", "provider:openai"])[0]],
          [1, 1])
    check("[#616 r2] NO provider label is refused (there is no silent default)",
          (provider_of([])[0], provider_of(["area:ci"])[0]), (1, 1))
    check("[#616 r2] a REPEATED single provider label still resolves (unique, not count)",
          provider_of(["provider:openai", "provider:openai"]), (0, "openai"))

    # ------------------------------------------------------------------------------------------
    # [#278] THE PER-PROVIDER MINT DEFAULTS ARE EXECUTED, AND THE RECORD STEP CONSUMES THEM.
    #
    # The broker derived `models` here and then hard-coded `max_concurrent_workers: 1` in the
    # register step, so every account it minted was capped at ONE concurrent worker whatever the
    # provider (#278: openai plans run 12, anthropic 4) — and the sibling defect in the same issue,
    # an openai `models: [terra]` that no sol/luna claim could ever match, is what an UNEXECUTED
    # derivation drifting silently looks like. Both values now come out of one fragment, which is
    # RUN per provider below with the alias lists and the numbers pinned exactly: reverting either
    # default, or splitting them back apart, flips these rows red.
    # ------------------------------------------------------------------------------------------
    defaults_fragment = workflow_block(workflow, "meta", "provider-defaults")

    def defaults_for(provider):
        """(exit code, models, workers) from the REAL derivation fragment, for one provider.

        `$prov` — the fragment's only input — arrives through the environment, exactly as its only
        producer (the provider-label predicate above) leaves it in the step's shell."""
        script = ('set -euo pipefail\nprov="$SELFTEST_PROV"\n' + defaults_fragment
                  + '\nprintf "M=%s\\nW=%s\\n" "$models" "$workers"\n')
        done = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                              env={**os.environ, "SELFTEST_PROV": provider},
                              timeout=120, check=False)

        def field(name):
            match = re.search(rf"^{name}=(.*)$", done.stdout, re.M)
            return match.group(1) if match else None
        return done.returncode, field("M"), field("W")

    check("[#278] openai mints the FULL codex alias set at the openai parallelism",
          defaults_for("openai"), (0, "[sol, luna, terra]", "12"))
    check("[#278] anthropic mints the opus5-led chain at the anthropic parallelism",
          defaults_for("anthropic"), (0, "[opus5, fable, opus, sonnet, haiku]", "4"))
    check("[#278] the derivation evaluates NO Actions expression (no untrusted text reaches it)",
          "${{" in defaults_fragment, False)
    # END TO END through the REAL allocator: the values the fragment just produced, in a record of
    # the shape the register step writes, must be ACCEPTED and must read back as the intended
    # routing. A default that parses to something else (or is rejected) strands a captured
    # credential in an unallocatable record, which is the failure mode this whole path guards.
    minted = {}
    for provider, harness_name, credential in (("openai", "codex", "codex-auth-json"),
                                               ("anthropic", "claude", "claude-oauth-token")):
        _, models_line, workers = defaults_for(provider)
        minted_body = (f"provider: {provider}\nharness: {harness_name}\n"
                       f"models: {models_line}\ncredential_format: {credential}\n"
                       f"max_concurrent_workers: {workers}\n"
                       "secret_ref: ACCT42_TOKEN\nrequest_issue: 42\n")
        parsed_record = real_parser(claim.validate_account_record, "acct42", minted_body)
        minted[provider] = (parsed_record if isinstance(parsed_record, str) else
                            (parsed_record["models"], parsed_record["max_concurrent_workers"]))
    check("[#278] a record minted from those defaults is accepted, and routes as intended",
          minted, {"openai": (["sol", "luna", "terra"], 12),
                   "anthropic": (["opus5", "fable", "opus", "sonnet", "haiku"], 4)})
    # ...and the register step takes the cap FROM that derivation. A literal here is the defect.
    register_env = workflow_step_env(workflow, "register")
    check("[#278] the register step stamps the DERIVED cap, never a literal",
          (register_env.get("WORKERS"),
           "max_concurrent_workers: %s" in register,
           "max_concurrent_workers: 1" in register),
          ("${{ steps.meta.outputs.workers }}", True, False))
    # WHY that step guards the value rather than trusting it: an EMPTY cap field is not a schema
    # error — the real parser maps a non-numeric value to 1 SILENTLY, which is precisely the defect
    # #278 removed, and the credential is already captured and stored by then. So a lost `meta`
    # output would quietly re-mint a cap-1 account, and this guard is the only thing preventing it.
    empty_cap = real_parser(claim.validate_account_record, "acct42",
                            "provider: openai\nharness: codex\nmodels: [sol, luna, terra]\n"
                            "credential_format: codex-auth-json\nmax_concurrent_workers:\n"
                            "secret_ref: ACCT42_TOKEN\n")
    check("[#278] an EMPTY cap parses to 1 instead of failing, so the register step guards it",
          (empty_cap if isinstance(empty_cap, str) else empty_cap["max_concurrent_workers"],
           '"${WORKERS:?' in register),
          (1, True))

    # ------------------------------------------------------------------------------------------
    # [#263] A LABEL NAME IS DATA, NEVER SHELL — EXECUTED, not asserted in prose.
    #
    # The pre-login `meta` step used to expand `${{ join(github.event.issue.labels.*.name, ' ') }}`
    # straight into a shell `for` loop. Labels can be applied by anyone with TRIAGE permission,
    # while the trust gate above only vets the triggering actor and the issue author for
    # admin/maintain — so a triage-level user who pre-applied a label named `$(...)` got code
    # execution in the broker job, which holds issues:write + contents:write and gates the
    # REGISTRY_SECRETS_PAT-bearing steps. The transport is now `toJSON(...)` into `LABELS_JSON`,
    # and these rows are the REGRESSION: the real fragment, the step's real `env:` block, hostile
    # label names, and a CANARY FILE that only a shell-PARSED label could ever create.
    #
    # The renderer is proved non-vacuous in the same breath: the identical hostile labels are put
    # through the OLD inline form and the canary MUST fire. Without that row, a renderer that
    # quietly neutralized every expression would make the regression above green forever.
    # ------------------------------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as directory:
        # Each shape gets its OWN canary, and is exercised ALONE: a single `for` list mixing
        # unbalanced quotes makes bash fail to PARSE, which would hide the injection behind a
        # syntax error and quietly make the non-vacuity row below unprovable.
        injections = {"command-substitution": "$(touch {canary})",
                      "backtick-substitution": "`touch {canary}`"}
        # The pre-#579 form this issue is about: the label names interpolated into the `run:`
        # script itself, where the runner substitutes them BEFORE bash parses a single word.
        inline_form = ("for lbl in ${{ join(github.event.issue.labels.*.name, ' ') }}; do\n"
                       "  case \"$lbl\" in provider:*) prov=\"${lbl#provider:}\";; esac\n"
                       "done\n")

        def inject(tag, shape):
            """(canary path, hostile label name) for one injection shape."""
            path = os.path.join(directory, tag)
            return path, shape.format(canary=path)

        executed_by_real = {}
        executed_by_inline = {}
        for tag, shape in injections.items():
            path, label = inject(f"real-{tag}", shape)
            executed_by_real[tag] = (provider_of(["provider:anthropic", label]),
                                     os.path.exists(path))
            path, label = inject(f"inline-{tag}", shape)
            subprocess.run(["bash", "-c", render_gha_expressions(inline_form, [label])],
                           capture_output=True, text=True, timeout=120, check=False)
            executed_by_inline[tag] = os.path.exists(path)

        check("[#263] every injection shape is DATA to the real pre-login fragment",
              executed_by_real,
              {tag: ((0, "anthropic"), False) for tag in injections})
        # NON-VACUITY: the SAME shapes through the pre-#579 inline form MUST execute. Without
        # this row a renderer (or a harness) that quietly neutralized everything would leave the
        # row above green forever while proving nothing.
        check("[#263] NON-VACUOUS: the old inline `join(...)` form DOES execute those shapes",
              executed_by_inline, {tag: True for tag in injections})
        # Quoting/whitespace metacharacters stay inert on the REFUSAL path too — the branch that
        # interpolates issue coordinates into a `gh issue comment` right beside the label data.
        soup = os.path.join(directory, "quote-soup")
        check("[#263] quote/whitespace metacharacter labels are data on the REFUSAL path too",
              (provider_of([f'x"; touch {soup}; #', f"'; touch {soup}; '", f"; touch {soup}",
                            "a label with spaces", "provider:openai extra"])[0],
               os.path.exists(soup)),
              (1, False))

    check("[#263] render_gha_expressions models the runner, and refuses non-text input",
          (render_gha_expressions("${{ toJSON(github.event.issue.labels.*.name) }}", ["a", "b"]),
           render_gha_expressions("${{ join(github.event.issue.labels.*.name, ' ') }}", ["a", "b"]),
           render_gha_expressions("${{ join(github.event.issue.labels.*.name) }}", ["a", "b"]),
           render_gha_expressions("${{ github.event.issue.labels.*.name }}", ["a", "b"]),
           render_gha_expressions("${{ github.repository }}", ["a"]),
           refuses(render_gha_expressions, None, [], needle="non-text fragment"),
           refuses(render_gha_expressions, "x", "not-a-list", needle="list of strings")),
          ('["a", "b"]', "a b", "a,b", "a b", "<gha>", True, True))
    # The `env:` reader must fail LOUDLY rather than hand back an empty environment, or the
    # transport fixture above degrades into "LABELS_JSON happened to be unset".
    check("[#263] the step `env:` reader resolves the transport, and refuses what it cannot locate",
          (meta_env.get("LABELS_JSON"),
           refuses(workflow_step_env, workflow, "no_such_step", needle="found 0"),
           refuses(workflow_step_env, workflow, "app-token-pool", needle="found 0")),
          ("${{ toJSON(github.event.issue.labels.*.name) }}", True, True))
    # And the label context must reach these steps ONLY through `env:` — never named inside the
    # script the shell parses. This is the textual half of the #263 regression; the executed half
    # is above. Comment-stripped, so a prose mention cannot trip it.
    check("[#263] no label-consuming step names the label context inside its `run:` script",
          {name: "github.event.issue.labels" in strip_yaml_comments(
              workflow_step_script(workflow, name)) for name in ("meta", "grant")},
          {"meta": False, "grant": False})

    # ------------------------------------------------------------------------------------------
    # [#616 review ROUND 4, MAJOR 2] THE PRIVILEGED `activate_merged` BODY IS EXECUTED. Round 3
    # asserted it by per-step substring PRESENCE, and presence is not outcome: converting its own
    # `except grant.GrantError -> sys.exit(1)` into a `::warning::` and continuing left the entire
    # 34-script suite green — a one-token fail-open on the credential boundary, on the step that
    # performs the four-way proof and flips status:pending -> status:available. Seven more mutants of
    # the same class survived (a self-comparison `verify_grant(policy, policy, require_delta=False)`,
    # a neutered `verify_membership`, a synthetic literal patch, `base.sha` for the first parent, and
    # three post-read mutations).
    #
    # So the real step body is run under bash against a FAKE `gh` (a dispatching script on PATH that
    # serves a scenario document and RECORDS every call) with the REAL helper module on disk. Nothing
    # about the proof is stubbed: each scenario differs only in what GitHub returns, and the
    # assertions are the step's EXIT CODE and whether the account issue was actually relabelled.
    # An unexpected `gh` invocation makes the fake exit nonzero, so a mutation that reads a different
    # endpoint or a different issue fails closed instead of passing quietly.
    # ------------------------------------------------------------------------------------------
    activate_script = workflow_step_script(workflow, "activate_merged")
    fake_gh = r'''#!/usr/bin/env python3
import json, os, re, sys
argv = sys.argv[1:]
with open(os.environ["FAKE_GH_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(argv) + "\n")
path = os.environ["FAKE_GH_STATE"]
with open(path, encoding="utf-8") as fh:
    state = json.load(fh)


def save():
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(state, fh)


def die(message, code=1):
    sys.stderr.write("fake-gh: " + message + "\n")
    sys.exit(code)


def flag(name):
    return argv[argv.index(name) + 1] if name in argv else ""


if argv[:2] == ["issue", "list"]:
    for number in state["issue_numbers"]:
        print(number)
elif argv[:2] == ["issue", "view"]:
    number = argv[2]
    fields = flag("--json")
    if number not in state["labels"]:
        die("no such issue " + number, 4)
    if fields == "body":
        print(state["bodies"].get(number, ""))
    elif fields == "labels":
        print(" ".join(state["labels"][number]))
    else:
        die("unexpected --json " + fields, 4)
elif argv[:2] == ["issue", "edit"]:
    number = argv[2]
    if "edit" in state.get("fail", []):
        die("issue edit rejected")
    if not state.get("lose_edit"):
        labels = list(state["labels"][number])
        if not state.get("partial_edit"):
            labels = [x for x in labels if x != flag("--remove-label")]
        labels.append(flag("--add-label"))
        state["labels"][number] = labels
        save()
elif argv[:2] in (["issue", "comment"], ["issue", "close"]):
    pass
elif argv[:1] == ["api"]:
    url = argv[1]
    if "/commits/" in url:
        if "commits" in state.get("fail", []):
            die("commits read rejected")
        print(state["parent_sha"])
    elif "/contents/policy/repos.toml" in url:
        ref = re.search(r"ref=([0-9a-zA-Z]+)", url).group(1)
        document = state["policy_at"].get(ref)
        if document is None:
            die("404 no policy at " + ref)
        sys.stdout.write(document)
    elif re.search(r"/pulls/\d+/files", url):
        if "files" in state.get("fail", []):
            die("files read rejected")
        print(json.dumps(state["pr_files"]))
    elif re.search(r"/pulls/\d+$", url):
        print(state["base_sha"])
    else:
        die("unexpected api call " + url, 4)
else:
    die("unexpected gh invocation " + " ".join(argv), 4)
'''
    handle = "acct07"
    activate_targets = ["o/second", "o/target"]
    merged_policy = render_grant(FIXTURE, handle, activate_targets)
    account_body = (f"secret_ref: X\nrequest_issue: 9\n{format_record_line(activate_targets)}\n")
    grant_patch = ('@@ -5,1 +5,1 @@\n'
                   '-account_pool = ["acct01", "acct02"]\n'
                   '+account_pool = ["acct01", "acct02", "acct07"]\n'
                   '@@ -16,1 +16,1 @@\n'
                   '-account_pool = ["acct01"]\n'
                   '+account_pool = ["acct01", "acct07"]\n')
    parent_sha, base_sha = "a" * 40, "b" * 40

    def pr_files(patch=grant_patch, additions=2, deletions=2, extra=()):
        record = {"filename": "policy/repos.toml", "status": "modified",
                  "additions": additions, "deletions": deletions}
        if patch is not None:
            record["patch"] = patch
        return [[record, *extra]]

    def run_activate(policy=None, before=None, body=None, labels=None, head_ref=None, **scenario):
        """Execute the REAL activate_merged body against a fake GitHub.

        Returns (exit code, final labels of the account issue, the gh calls, combined output)."""
        with tempfile.TemporaryDirectory() as directory:
            work = pathlib.Path(directory)
            (work / "scripts").mkdir()
            (work / "scripts" / "grant-account.py").write_text(
                pathlib.Path(__file__).read_text(encoding="utf-8"), encoding="utf-8")
            (work / "policy").mkdir()
            (work / "policy" / "repos.toml").write_text(
                merged_policy if policy is None else policy, encoding="utf-8")
            (work / "bin").mkdir()
            (work / "bin" / "gh").write_text(fake_gh, encoding="utf-8")
            (work / "bin" / "gh").chmod(0o755)
            (work / "runner-temp").mkdir()
            state = {"issue_numbers": ["5"],
                     "bodies": {"5": account_body if body is None else body},
                     "labels": {"5": ["status:pending"] if labels is None else labels},
                     "parent_sha": parent_sha, "base_sha": base_sha,
                     "policy_at": {parent_sha: FIXTURE if before is None else before,
                                   base_sha: FIXTURE},
                     "pr_files": pr_files()}
            state.update(scenario)
            state_file, log_file = work / "state.json", work / "calls.jsonl"
            state_file.write_text(json.dumps(state), encoding="utf-8")
            log_file.write_text("", encoding="utf-8")
            done = subprocess.run(
                ["bash", "-c", activate_script], cwd=str(work), capture_output=True, text=True,
                timeout=300, check=False,
                env={**os.environ, "PATH": f"{work / 'bin'}:{os.environ['PATH']}",
                     "REPO": "o/registry",
                     "HEAD_REF": head_ref or f"account-pool/{handle}",
                     "PR_NUMBER": "42", "MERGE_SHA": "c" * 40, "GH_TOKEN": "t",
                     "RUNNER_TEMP": str(work / "runner-temp"),
                     "FAKE_GH_STATE": str(state_file), "FAKE_GH_LOG": str(log_file)})
            final = json.loads(state_file.read_text(encoding="utf-8"))["labels"]["5"]
            calls = [json.loads(line) for line in
                     log_file.read_text(encoding="utf-8").split("\n") if line.strip()]
            return done.returncode, final, calls, done.stdout + done.stderr

    def activated_view(**scenario):
        """(exit code, final labels, did it relabel?, did it comment on the account issue?)"""
        code, final, calls, _output = run_activate(**scenario)
        return (code, final,
                any(call[:2] == ["issue", "edit"] for call in calls),
                any(call[:3] == ["issue", "comment", "5"] for call in calls))

    check("[#616 r4] EXECUTED activate: a fully proven merge flips pending -> available",
          activated_view(),
          (0, ["status:available"], True, True))
    code, _final, calls, output = run_activate()
    check("[#616 r4] EXECUTED activate: ...and it closes the linked request issue",
          (any(call[:3] == ["issue", "close", "9"] for call in calls),
           "confirmed granted to exactly ['o/second', 'o/target']" in output),
          (True, True))
    # THE fail-open mutant: with `except grant.GrantError` turned into a ::warning:: every row below
    # reads (0, ["status:available"], True, True) — the credential is authorized on an unproven grant.
    partial = render_grant(FIXTURE, handle, ["o/target"])
    check("[#616 r4] EXECUTED activate: a PARTIAL grant (one target missing) activates nothing",
          activated_view(policy=partial),
          (1, ["status:pending"], False, False))
    # verify_grant(policy, policy, ..., require_delta=False) — a self-comparison — passes here, and
    # so does reading `pulls/N` `.base.sha` instead of the merge commit's FIRST PARENT: the parent
    # carries an unrelated non-target edit, exactly the multi-commit-rebase shape.
    tampered_parent = FIXTURE.replace('account_pool = ["acct09"]',
                                      'account_pool = ["acct09", "acct42"]')
    check("[#616 r4] EXECUTED activate: a non-target row that moved since the FIRST PARENT refuses",
          activated_view(before=tampered_parent),
          (1, ["status:pending"], False, False))
    # THE cross-row swap (#616 review round 4, MAJOR 1), driven through the privileged step. The
    # swap is already in the first parent (a multi-commit rebase), so verify_grant sees nothing;
    # verify_membership and require_grant_pr_scope pass; ONLY the PR's own diff, compared
    # POSITIONALLY, refuses. Under the multiset comparison — and under a synthetic literal patch
    # fed to verify_grant_patch — this row reads (0, ["status:available"], True, True).
    swapped_parent = (FIXTURE.replace('account_pool = ["acct01", "acct02"]',
                                      'account_pool = ["acct02", "acct01"]'))
    swapped_merged = render_grant(swapped_parent, handle, activate_targets)
    swap_patch = ('@@ -5,1 +5,1 @@\n'
                  '-account_pool = ["acct01", "acct02"]\n'
                  '+account_pool = ["acct02", "acct01", "acct07"]\n'
                  '@@ -16,1 +16,1 @@\n'
                  '-account_pool = ["acct02"]\n'
                  '+account_pool = ["acct01", "acct07"]\n')
    check("[#616 r4] EXECUTED activate: a CROSS-ROW pool swap carried by the PR refuses",
          activated_view(policy=swapped_merged, before=swapped_parent,
                         pr_files=pr_files(patch=swap_patch)),
          (1, ["status:pending"], False, False))
    # A TRUNCATED patch (#616 review round 4, MAJOR 4): the API's own counts say six changed lines,
    # the patch carries four. Without the completeness check this activates on a prefix.
    check("[#616 r4] EXECUTED activate: a TRUNCATED policy patch refuses",
          activated_view(pr_files=pr_files(additions=3, deletions=3)),
          (1, ["status:pending"], False, False))
    check("[#616 r4] EXECUTED activate: an ABSENT patch refuses (no proof of what merged)",
          activated_view(pr_files=pr_files(patch=None, additions=0, deletions=0)),
          (1, ["status:pending"], False, False))
    # A neutered verify_membership: the handle ALSO sits in a non-target row, and it was there
    # before the merge, so the two-document proof and the diff proof both pass.
    leaked_parent = FIXTURE.replace('account_pool = ["acct09"]',
                                    'account_pool = ["acct09", "acct07"]')
    check("[#616 r4] EXECUTED activate: the handle leaked into a NON-TARGET row refuses",
          activated_view(policy=render_grant(leaked_parent, handle, activate_targets),
                         before=leaked_parent),
          (1, ["status:pending"], False, False))
    check("[#616 r4] EXECUTED activate: an extra file in the merged PR refuses (scope)",
          activated_view(pr_files=pr_files(extra=({"filename": ".github/workflows/x.yml",
                                                   "status": "modified", "additions": 1,
                                                   "deletions": 0, "patch": "@@ -1 +1 @@\n+x\n"},))),
          (1, ["status:pending"], False, False))
    check("[#616 r4] EXECUTED activate: an unreadable record line refuses (no grant_targets)",
          activated_view(body="secret_ref: X\nrequest_issue: 9\n"),
          (1, ["status:pending"], False, False))
    check("[#616 r4] EXECUTED activate: an unresolvable first parent refuses",
          activated_view(fail=["commits"]), (1, ["status:pending"], False, False))
    check("[#616 r4] EXECUTED activate: an unreadable changed-file listing refuses",
          activated_view(fail=["files"]), (1, ["status:pending"], False, False))
    check("[#616 r4] EXECUTED activate: two account issues with that title refuse (ambiguity)",
          activated_view(issue_numbers=["5", "6"]), (1, ["status:pending"], False, False))
    # THE POST-READ (#616 review round 4, MINOR): the round-3 assertion was a substring plus an
    # ordering test, so a constant `post`, a post-read of a DIFFERENT issue, and a flipped case
    # polarity all survived. Here the label write reports success and does NOT land: the step must
    # refuse and must NOT post an activation notice.
    check("[#616 r4] EXECUTED activate: a label write that did not LAND refuses, and never notices",
          activated_view(lose_edit=True),
          (1, ["status:pending"], True, False))
    # ...and the SECOND post-read case: a partially-applied edit that ADDED status:available while
    # leaving status:pending in place. The first case is satisfied by the available label, so only the
    # ambiguous-state guard refuses — deleting it left the suite green until this row existed.
    check("[#616 r4] EXECUTED activate: a flip that left status:pending behind refuses, no notice",
          activated_view(partial_edit=True),
          (1, ["status:pending", "status:available"], True, False))
    check("[#616 r4] EXECUTED activate: an already-available account is an idempotent no-op",
          activated_view(labels=["status:available"]),
          (0, ["status:available"], False, False))
    check("[#616 r4] EXECUTED activate: an account in neither state refuses",
          activated_view(labels=["status:parked"]), (1, ["status:parked"], False, False))
    check("[#616 r4] EXECUTED activate: NO account issue with that title refuses",
          activated_view(issue_numbers=[]), (1, ["status:pending"], False, False))
    check("[#616 r4] EXECUTED activate: a head ref that is not a handle refuses before any read",
          run_activate(head_ref="account-pool/not-a-handle!")[:2] + (
              [call for call in run_activate(head_ref="account-pool/x")[2]], ),
          (1, ["status:pending"], []))

    # ------------------------------------------------------------------------------------------
    # [#394] REGISTRATION IS CREATE-ONCE — EXECUTED. Round 2 of #383 made both activation paths
    # refuse unless EXACTLY ONE exact-title account issue exists, so a duplicate `acctNN` record
    # WEDGES the account permanently: no automated path can tell two records apart, and the slot's
    # claim ref is never released. That defence sits downstream of the defect — the register step
    # created the record without proving the title was free, and GitHub permits duplicate titles.
    # The new proof is therefore RUN, not asserted in prose: the REAL fragment, against a fake `gh`
    # that serves an issue listing and RECORDS every call, with the fragment's exit code and the
    # `gh issue create` it did (or did not) reach as the observations. A deleted guard, a listing
    # narrowed to open issues, a swallowed listing failure, and a comparison against the wrong
    # title all flip a row below red. The fake refuses any unexpected invocation, so a mutation that
    # reads some other endpoint fails closed instead of passing quietly.
    #
    # What the fake MODELS rather than executes: `--jq` projects each issue to `<number> <title>`
    # and drops pull requests, so the fake serves lines already in that shape. The EXACT-title
    # decision — the part that can fail OPEN — is the fragment's own, and rows 5/6 below drive it.
    # ------------------------------------------------------------------------------------------
    register_fragment = workflow_block(workflow, "register", "register-uniqueness")
    register_gh = r'''#!/usr/bin/env python3
import json, os, sys
argv = sys.argv[1:]
with open(os.environ["FAKE_GH_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(argv) + "\n")
with open(os.environ["FAKE_GH_STATE"], encoding="utf-8") as fh:
    state = json.load(fh)
if argv[:1] == ["api"]:
    # The listing must be the FULLY PAGINATED, ALL-STATE issues read: a closed duplicate wedges
    # activation exactly like an open one, and an unpaginated read proves nothing past page 1.
    endpoints = [word for word in argv[1:] if word.startswith("repos/")]
    if (len(endpoints) != 1 or not endpoints[0].endswith("/issues?state=all&per_page=100")
            or "--paginate" not in argv):
        sys.stderr.write("fake-gh: unexpected listing " + " ".join(argv) + "\n"); sys.exit(4)
    if state.get("listing_fails"):
        sys.stderr.write("fake-gh: issue listing rejected\n"); sys.exit(1)
    for number, title in state["issues"]:
        print(str(number) + " " + title)
elif argv[:2] == ["label", "create"]:
    sys.exit(1)                      # the normal case: the label already exists
elif argv[:2] == ["issue", "create"]:
    pass
else:
    sys.stderr.write("fake-gh: unexpected invocation " + " ".join(argv) + "\n"); sys.exit(4)
'''

    def run_register(issues, script=None, handle="acct07", **scenario):
        """Execute the REAL register-uniqueness fragment against a fake GitHub whose issue listing
        is `issues` (a list of [number, title] pairs). Returns (exit code, the gh calls)."""
        with tempfile.TemporaryDirectory() as directory:
            work = pathlib.Path(directory)
            (work / "bin").mkdir()
            (work / "bin" / "gh").write_text(register_gh, encoding="utf-8")
            (work / "bin" / "gh").chmod(0o755)
            state = {"issues": issues}
            state.update(scenario)
            state_file, log_file = work / "state.json", work / "calls.jsonl"
            state_file.write_text(json.dumps(state), encoding="utf-8")
            log_file.write_text("", encoding="utf-8")
            body = "set -euo pipefail\n" + render_gha_expressions(
                register_fragment if script is None else script, [])
            done = subprocess.run(
                ["bash", "-c", body], cwd=str(work), capture_output=True, text=True,
                timeout=300, check=False,
                env={**os.environ, "PATH": f"{work / 'bin'}:{os.environ['PATH']}",
                     "HANDLE": handle, "PROVIDER": "openai",
                     "body": "provider: openai\nmodels: [sol, luna, terra]\n",
                     "FAKE_GH_STATE": str(state_file), "FAKE_GH_LOG": str(log_file)})
            calls = [json.loads(line) for line in
                     log_file.read_text(encoding="utf-8").split("\n") if line.strip()]
            return done.returncode, calls

    def register_view(issues, **scenario):
        """(exit code, [(title, labels)] of every account issue the fragment actually created)."""
        code, calls = run_register(issues, **scenario)
        return code, [(call[call.index("--title") + 1],
                       [call[index + 1] for index, word in enumerate(call) if word == "--label"])
                      for call in calls if call[:2] == ["issue", "create"]]

    minted_record = ("acct07", ["account", "provider:openai", "status:pending"])
    check("[#394] EXECUTED register: a FREE title is registered — status:pending, never available",
          register_view([[9, "acct08"], [10, "some unrelated issue"]]), (0, [minted_record]))
    check("[#394] EXECUTED register: an existing issue with that exact title creates NOTHING",
          register_view([[5, "acct07"]]), (1, []))
    check("[#394] EXECUTED register: ...and two of them refuse too (the wedged state)",
          register_view([[5, "acct07"], [6, "acct07"]]), (1, []))
    check("[#394] EXECUTED register: an unreadable issue listing refuses (freeness unprovable)",
          register_view([[9, "acct08"]], listing_fails=True), (1, []))
    # Both directions of the EXACT comparison, in one fixture: near-miss titles must NOT block the
    # registration (a substring/prefix test would false-refuse every enrollment past acct07)...
    check("[#394] EXECUTED register: near-miss titles are not this handle",
          register_view([[5, "acct7"], [6, "acct070"], [7, "Acct07"], [8, "acct07 spare"]]),
          (0, [minted_record]))
    # ...and the same fixture with the exact title added back must refuse, so a comparison against
    # the wrong variable (which matches nothing at all) cannot pass the two rows above.
    check("[#394] EXECUTED register: the exact title among near-misses still refuses",
          register_view([[5, "acct7"], [6, "acct070"], [7, "acct07"], [8, "acct07 spare"]]),
          (1, []))
    # NON-VACUITY: the pre-#394 form — create with no proof — MUST create the duplicate against the
    # very fixture the real fragment refuses. Without this row a harness that never reached
    # `gh issue create` at all would leave every refusal row above green while proving nothing.
    legacy_register = ('gh issue create -R "${{ github.repository }}" --title "$HANDLE" '
                       '--label account --label "provider:$PROVIDER" --label status:pending '
                       '--body "$body"\n')
    check("[#394] NON-VACUOUS: the pre-#394 form DOES create a duplicate on that same fixture",
          register_view([[5, "acct07"]], script=legacy_register), (0, [minted_record]))
    # The guard must sit BEFORE the create in the step the runner executes (the fragment is a
    # region of it), and the handle it proves free must be the CLAIMED slot from the store step —
    # not `meta`'s pre-login hint, which is the stale snapshot #186 removed.
    check("[#394] the register step proves the title free BEFORE it creates, on the CLAIMED slot",
          (0 <= register.find("issues?state=all&per_page=100") < register.find("gh issue create"),
           register_env.get("HANDLE")),
          (True, "${{ steps.store.outputs.handle }}"))
    # ...and the always() alarm OWNS the recovery for that refusal (the issue asked for it
    # explicitly): a human must not answer a duplicate-title refusal by hand-creating the second
    # record. Comment-stripped, so the guidance has to be in the comment the alarm POSTS.
    alarm = workflow_step(workflow, "alarm")
    check("[#394] the always() alarm's recovery guidance covers the duplicate-title refusal",
          ("#394" in alarm, "do **not** hand-create a second" in alarm,
           "allocates a FRESH slot" in alarm),
          (True, True, True))

    template = (root / ".github/ISSUE_TEMPLATE/set-up-account.yml").read_text(encoding="utf-8")
    form = strip_yaml_comments(template)
    check("the request form documents the grant label (in the form itself, not a comment)",
          GRANT_LABEL_PREFIX in form, True)
    # ------------------------------------------------------------------------------------------
    # [#261] THE FORM COLLECTS NO REQUEST DATA. It used to open with a REQUIRED `provider` dropdown
    # whose value landed in the issue BODY, which the broker never reads — the `meta` step above
    # resolves the provider from the `provider:*` LABELS (asserted, and EXECUTED, further up). So a
    # request could be filed "with a provider" and still be refused for having no provider label,
    # and the field advertised a second source of truth that can disagree with the labels the broker
    # enforces. Both rows below fail closed on an empty/renamed form rather than passing vacuously.
    # ------------------------------------------------------------------------------------------
    element_types = [line.strip()[len("- type: "):].strip()
                     for line in form.split("\n") if line.strip().startswith("- type: ")]
    check("[#261] the form declares elements, and NONE of them collects request data",
          (bool(element_types), sorted(set(element_types) - {"markdown", "checkboxes"})),
          (True, []))
    check("[#261] the form documents the provider LABELS (in the form itself, not a comment)",
          ("provider:openai" in form, "provider:anthropic" in form), (True, True))

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
