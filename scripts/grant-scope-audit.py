#!/usr/bin/env python3
# [OPUS-5 #608] READ-ONLY grant-scope AUDIT for the set-up-account broker.
#
# WHY THIS EXISTS. Issue #579 made every NEW enrollment carry an explicit `target:<owner>/<repo>`
# authorization, but it deliberately left the grants that predate it alone: the rows already in
# policy/repos.toml were produced by the retired DOCUMENT-WIDE append, so both enabled targets
# still list the IDENTICAL `account_pool`. Every pre-#579 account is therefore still usable by
# every enabled target. #608 asks the audit question that must be answered before that can be
# narrowed: which accounts does each target actually NEED?
#
# WHAT THIS IS NOT. It is not a fix and it cannot become one. Narrowing an existing row REVOKES a
# live capability, so it is a maintainer POLICY decision, not a worker edit — this module holds no
# write path at all (grant-account.render_grant is the only sanctioned policy writer, and it only
# ADDS). Everything here is advisory evidence for a human, and the exit status is 0 whether or not
# revocation candidates are found: an audit that gated CI would turn an unmade decision into an
# outage.
#
# THE EVIDENCE, AND WHAT IT CAN HONESTLY PROVE. The durable per-(target, account) record is the
# implementer provenance corpus, `orchestration/provenance/<owner>--<name>--pr<N>.json`: the
# filename names the TARGET and `impl_account_h` is sha256(handle + ':' + PROVENANCE_SALT)[:16] —
# the account that did the work. Two other sources look usable and are not:
#   * `data/leases.json` is LIVE state, not history. groom.py's release path REMOVES a lease from
#     the array when it expires and keeps no ring, so it can only ever sample the present.
#   * `scripts/account-usage.py` probes LIVE rate-limit headroom per account and carries NO target
#     attribution whatsoever.
# So the provenance corpus is the only source that answers #608, and it answers it only for PRs
# that have a record. That bounds the audit, and the bound is enforced rather than narrated:
#
# FAIL-CLOSED, IN THE DIRECTION THAT MATTERS. The dangerous error here is proposing a revocation
# that is really just missing evidence. Absence of evidence is never reported as evidence of
# disuse:
#   1. A target with ZERO records yields `insufficient-evidence` and an EMPTY candidate list.
#   2. A NONEMPTY corpus is not a COMPLETE one, and only a complete one can prove disuse. The
#      corpus on `master` is demonstrably partial (its PR numbers have gaps; records have been
#      written to the `ledger` branch since #96), and on a partial corpus "this handle appears in
#      no record" is indistinguishable from "the record that named it is not in this checkout" —
#      so counting records is NOT a completeness signal and must never be used as one. Completeness
#      is therefore never inferred: it must be ASSERTED by a durable expected-record manifest
#      (`--expected-records`, {target: {window, records: [PR numbers]}}) that the maintainer
#      derives from the authoritative enumeration of that target's worker PRs in an observation
#      window, and VERIFIED here — every expected record must actually be present, and the stated
#      `window` must be a PR-number range that CONTAINS every record listed under it (a window the
#      audit cannot check is a scope the reader is asked to take on trust). Verification is
#      by FILENAME, so a filename must be worth trusting: each record's name is parsed exactly and
#      must agree with the `pr_number` INSIDE it, or the audit refuses. Otherwise a record parked
#      under another PR's name would witness a record that is really missing, and an incomplete
#      corpus would be declared complete — the false revocation this whole module exists to
#      prevent. Without a verified manifest a row is `partial-evidence`: observed handles are
#      reported (positive evidence of USE is sound on any corpus) and the candidate list stays
#      EMPTY.
#   3. Without a salt the fingerprints cannot be mapped back to handles, so NO target ever yields
#      a candidate — the pool is "unknown", not "unused". Mapping is opt-in (`--salt-env`).
#   4. A fingerprint that no granted handle explains (a RETIRED account like acct03/acct06, or an
#      account granted to another row) is counted and surfaced, never silently dropped: it means
#      the corpus is describing accounts this row's pool does not, and the reader must know.
#
# PRIVACY. This registry is PUBLIC and the provenance README's rule is that records never carry a
# raw handle. A mapped report is exactly the join that rule avoids publishing, so NO report — text
# or JSON, mapped or not — ever emits a fingerprint; only handles the policy already lists in the
# clear, and counts. The report is therefore safe to paste into an issue. (--self-test proves it.)
"""Read-only per-target account_pool grant-scope evidence for a maintainer (issue #608)."""

import argparse
import collections
import hashlib
import importlib.util
import json
import os
import pathlib
import sys

FINGERPRINT_LENGTH = 16
# The `impl_account_h` shape asserted by worker-pr.record_document and mint-provenance.
_FINGERPRINT_ALPHABET = frozenset("0123456789abcdef")
# One record per worker PR; worker-pr.provenance_path builds exactly this name.
RECORD_SUFFIX = ".json"
RECORD_INFIX = "--pr"
_DIGITS = frozenset("0123456789")
# A manifest `window` is an INCLUSIVE PR-number range, `#<low>..#<high>` — see `window_bounds`.
WINDOW_SEPARATOR = ".."
WINDOW_NUMBER_PREFIX = "#"
DEFAULT_POLICY = "policy/repos.toml"
DEFAULT_PROVENANCE_DIR = "orchestration/provenance"
# The env var holding the salt, when the operator opts in to mapping. Never read unless asked for,
# never printed.
DEFAULT_SALT_ENV = "PROVENANCE_SALT"

STATUS_INSUFFICIENT = "insufficient-evidence"   # no records: say nothing about this row's pool
STATUS_UNMAPPED = "unmapped-evidence"           # records, but no salt: counts only, no candidates
STATUS_PARTIAL = "partial-evidence"             # mapped, but completeness unproven: use only
STATUS_SCOPED = "scoped"                        # complete + mapped: candidates are meaningful


class AuditError(RuntimeError):
    """The evidence cannot be read safely, so no scope conclusion may be drawn from it."""


def _script_dir():
    return os.path.dirname(os.path.abspath(__file__))


def _load_sibling(filename, module_name):
    """Load a hyphen-named sibling script as a module (the account-usage._load_sibling pattern)."""
    spec = importlib.util.spec_from_file_location(
        module_name, os.path.join(_script_dir(), filename))
    if spec is None or spec.loader is None:
        raise AuditError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fingerprint(handle, salt):
    """The canonical public account identity. IDENTICAL to select-and-claim.account_fingerprint and
    worker-pr.account_hash — a drift here would map every handle to a fingerprint no record carries
    and report the whole pool as unused, so --self-test pins it against the real sibling."""
    if not isinstance(handle, str) or not handle or not isinstance(salt, str) or not salt:
        raise AuditError("a handle and a non-empty salt are required to map an account identity")
    return hashlib.sha256(f"{handle}:{salt}".encode()).hexdigest()[:FINGERPRINT_LENGTH]


def is_fingerprint(value):
    return (isinstance(value, str) and len(value) == FINGERPRINT_LENGTH
            and set(value) <= _FINGERPRINT_ALPHABET)


def pools_by_target(policy_text, grant_account):
    """{enabled target: sorted granted handles} from a policy document.

    Reuses grant-account's own parser so the audit reads the authorization boundary through the
    SAME lens the broker writes it with. A pool entry that is not a broker handle is a refusal: the
    audit must not reason about a row whose shape it does not recognise."""
    repos = grant_account._policy_repos(policy_text)
    pools = {}
    for target in grant_account.enabled_targets(policy_text):
        pool = repos[target].get("account_pool")
        if not isinstance(pool, list) or not pool:
            raise AuditError(f"enabled target {target!r} has no non-empty account_pool — refusing")
        for entry in pool:
            if not isinstance(entry, str) or not grant_account.HANDLE_RE.match(entry):
                raise AuditError(
                    f"target {target!r} lists account_pool entry {entry!r}, which is not a broker "
                    "handle — refusing to audit a pool shape this module cannot bound")
        if len(set(pool)) != len(pool):
            raise AuditError(f"target {target!r} lists a duplicate account_pool entry — refusing")
        pools[target] = sorted(pool)
    if not pools:
        raise AuditError("policy carries no `enabled = true` rows — nothing to audit")
    return pools


def record_prefix(target):
    """The provenance filename prefix worker-pr.provenance_path builds for `target`."""
    owner, _, name = target.partition("/")
    if not owner or not name:
        raise AuditError(f"target {target!r} is not an <owner>/<repo> name — refusing")
    return f"{owner}--{name}{RECORD_INFIX}"


def record_target(filename, targets):
    """The one audited target a record filename belongs to, or None when it belongs to none.

    Attribution is by the target's OWN prefix rather than by splitting the filename, because a
    repository name may itself contain `--` and a split would silently mis-attribute it. Two
    targets matching the same file is a refusal, not a first-wins guess."""
    if not filename.endswith(RECORD_SUFFIX):
        return None
    matched = [target for target in targets if filename.startswith(record_prefix(target))]
    if len(matched) > 1:
        raise AuditError(
            f"provenance record {filename!r} is attributable to more than one audited target "
            f"({', '.join(sorted(matched))}) — refusing to guess which row it is evidence for")
    return matched[0] if matched else None


def record_number(filename, target):
    """The PR number named by a record filename attributed to `target`.

    EXACT, never a loose prefix read: the name must be precisely what worker-pr.provenance_path
    builds for some positive PR number (`<owner>--<name>--pr<N>.json`, no zero padding), because
    this number is what binds a record's NAME to its CONTENT in `record_fingerprint` below.

    A file this module has attributed to a target but cannot number REFUSES the whole audit rather
    than being demoted to `foreign` and ignored: dropping it would remove positive evidence of USE
    from that row, and a handle whose only record was dropped becomes a revocation candidate —
    absence manufactured by a parse we gave up on, in the one direction that must never fail
    open."""
    prefix = record_prefix(target)
    number = (filename[len(prefix):-len(RECORD_SUFFIX)]
              if filename.startswith(prefix) and filename.endswith(RECORD_SUFFIX) else "")
    if not number or set(number) - _DIGITS or number.startswith("0"):
        raise AuditError(
            f"provenance record {filename!r} is attributed to target {target!r} but is not named "
            f"{prefix}<PR number>{RECORD_SUFFIX} — refusing to audit a corpus holding a record "
            "whose name this module cannot read exactly (fail closed)")
    return int(number)


def record_fingerprint(text, filename, number):
    """`impl_account_h` from one record's TEXT, bound to the PR its FILENAME names. Any unreadable
    record refuses the whole audit: a record we cannot parse is a PR whose account we do not know,
    and skipping it would quietly shrink the evidence for exactly the rows the audit is about to
    propose narrowing.

    The document's own `pr_number` must EQUAL `number`, the PR the filename claims. Completeness
    downstream is verified against the set of observed FILENAMES, so a filename witnesses that a
    PR's record is present only if the document under it really is that PR's record: a record
    copied or renamed onto another PR's name would otherwise satisfy the manifest entry for a
    record that is genuinely ABSENT, marking an incomplete corpus `scoped` and turning the missing
    evidence into revocation candidates. One writer produces both halves (provenance_record puts
    `pr_number` in the document and the same number in provenance_path), so a disagreement is
    corruption, not a variant shape — it refuses."""
    try:
        document = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise AuditError(f"provenance record {filename!r} does not parse as JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise AuditError(f"provenance record {filename!r} is not a JSON object — refusing")
    value = document.get("impl_account_h")
    if not is_fingerprint(value):
        raise AuditError(
            f"provenance record {filename!r} carries impl_account_h={value!r}, which is not a "
            f"{FINGERPRINT_LENGTH}-hex account fingerprint — refusing to audit a corpus with an "
            "unreadable record (fail closed)")
    recorded = document.get("pr_number")
    if isinstance(recorded, bool) or not isinstance(recorded, int) or recorded <= 0:
        raise AuditError(
            f"provenance record {filename!r} carries pr_number={recorded!r}, which is not a "
            "positive PR number — refusing a record whose filename cannot be bound to its content")
    if recorded != number:
        raise AuditError(
            f"provenance record {filename!r} is the record of PR #{recorded}: its name and its "
            f"content name different PRs, so this file cannot witness that PR #{number}'s record "
            "is present — refusing (fail closed)")
    return value


def _window_number(text):
    """One `#<N>` bound of a window, or None when `text` is not EXACTLY that — including when it is
    the empty string, which is what a window carrying no `..` partitions into.

    The same number grammar `record_number` reads out of a filename (positive, digits only, no zero
    padding), because the two are compared to each other."""
    if not text.startswith(WINDOW_NUMBER_PREFIX):
        return None
    digits = text[len(WINDOW_NUMBER_PREFIX):]
    if not digits or set(digits) - _DIGITS or digits.startswith("0"):
        return None
    return int(digits)


def window_bounds(window, target):
    """The INCLUSIVE (low, high) PR numbers a manifest entry's `window` states.

    A completeness claim is only as good as the scope it is made over, and `window` USED to be any
    non-blank string: the report told the reader "all N expected record(s) present for window W"
    while nothing had ever related W to the records beside it, so a manifest whose window said one
    thing and whose records enumerated another was indistinguishable from a correct one (#1887).

    A PR-NUMBER range is the one window shape this module can actually check. Dates cannot be: a
    provenance record's filename carries only a PR number, so neither the corpus nor the manifest
    holds a timestamp to check an instant against, and validating an ISO-8601 shape would only make
    the unverified text better formatted. PR numbers are monotonic per repository, so `records` and
    `window` are expressed in the SAME units and the containment below is a real check
    (`research/1027-expected-record-manifest-generation.md` §5.3).

    Exactly `#<low>..#<high>`, with no trailing prose: a window that carried free text would be
    partly checked and partly not, which is the property this refuses to keep."""
    if not isinstance(window, str):
        raise AuditError(
            f"expected-records entry for {target!r} states no observation `window` string (got "
            f"{window!r}) — refusing to accept an unbounded completeness claim")
    # A window carrying no `..` partitions into an empty high bound, which `_window_number` already
    # rejects — so the separator is NOT tested a second time here. A duplicated guard makes each
    # copy individually unkillable (AGENTS.md pre-flight 4), and one refusal is what a reader has to
    # be able to trust.
    low_text, _, high_text = window.partition(WINDOW_SEPARATOR)
    low, high = _window_number(low_text), _window_number(high_text)
    if low is None or high is None:
        raise AuditError(
            f"expected-records entry for {target!r} states window {window!r}, which is not a PR "
            f"number range {WINDOW_NUMBER_PREFIX}<low>{WINDOW_SEPARATOR}{WINDOW_NUMBER_PREFIX}"
            "<high> — refusing a completeness claim whose scope cannot be checked against the "
            "records it is made over")
    if low > high:
        raise AuditError(
            f"expected-records entry for {target!r} states window {window!r}, whose low bound is "
            "above its high bound — refusing a window that contains nothing")
    return low, high


def expected_records(manifest_text, targets):
    """{target: {"window": str, "records": frozenset(filenames)}} from a completeness manifest.

    THE MANIFEST IS THE COMPLETENESS SIGNAL, and nothing else is. It is the maintainer's durable,
    authoritative enumeration of the worker PRs a target ran inside a stated observation window
    (from the `ledger` branch / the PR list — neither of which a worker can reach), so that
    "no record names this handle" can mean "unused" instead of "not in this checkout". Every part
    of it is validated, because a manifest this module misreads is a manifest that would license
    exactly the false revocation the audit exists to prevent.

    Record numbers, not filenames: a number is turned into a filename through `record_prefix` for
    the target it is declared under, so a manifest entry can never assert completeness using
    another row's evidence.

    The `window` is checked against the `records` declared under it (`window_bounds`): every listed
    PR number must lie inside the range the entry claims to be enumerating, so the scope the report
    quotes is the scope the record list actually describes. This does not prove the enumeration is
    COMPLETE for that window — nothing here can, since a manifest is exactly the assertion this
    module cannot derive — but a manifest whose two halves describe different populations no longer
    verifies as if they agreed."""
    try:
        document = json.loads(manifest_text)
    except (ValueError, TypeError) as exc:
        raise AuditError(f"expected-records manifest does not parse as JSON: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("targets"), dict):
        raise AuditError("expected-records manifest must be a JSON object with a `targets` object")
    claims = {}
    for target, entry in document["targets"].items():
        if target not in targets:
            raise AuditError(
                f"expected-records manifest declares target {target!r}, which is not an audited "
                "enabled target — refusing to reason from a manifest that does not describe this "
                "policy")
        if not isinstance(entry, dict):
            raise AuditError(f"expected-records entry for {target!r} is not an object — refusing")
        window = entry.get("window")
        low, high = window_bounds(window, target)
        numbers = entry.get("records")
        if not isinstance(numbers, list) or not numbers:
            raise AuditError(
                f"expected-records entry for {target!r} lists no `records` — an empty expectation "
                "asserts nothing and would license a revocation on no evidence at all")
        for number in numbers:
            if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
                raise AuditError(
                    f"expected-records entry for {target!r} lists record {number!r}, which is not "
                    "a positive PR number — refusing")
            if not low <= number <= high:
                raise AuditError(
                    f"expected-records entry for {target!r} lists record #{number}, which lies "
                    f"outside its own window {window!r} — refusing a manifest whose stated scope "
                    "and whose record list describe different populations")
        if len(set(numbers)) != len(numbers):
            raise AuditError(
                f"expected-records entry for {target!r} lists a duplicate PR number — refusing a "
                "manifest whose record count does not mean what it says")
        prefix = record_prefix(target)
        claims[target] = {"window": window,
                          "records": frozenset(f"{prefix}{n}{RECORD_SUFFIX}" for n in numbers)}
    if not claims:
        raise AuditError("expected-records manifest declares no target — nothing is bounded by it")
    return claims


def collect_evidence(corpus, targets):
    """({target: {fingerprint: count}}, {target: {record filename}}, records belonging to no
    audited target).

    The filenames are what a completeness manifest is verified against, so they are collected on
    the same pass that reads the evidence — the audit must never check completeness against a
    different view of the corpus than the one it draws its conclusions from. A filename reaches
    `observed` only out of a corpus in which EVERY record's name and content name the same PR —
    one disagreement refuses this whole pass, so no report is ever built on a name that does not
    hold the record it claims.

    `corpus` is an iterable of (filename, text) so the reader stays pure and the caller owns I/O."""
    evidence = {target: collections.Counter() for target in targets}
    observed = {target: set() for target in targets}
    foreign = 0
    for filename, text in corpus:
        target = record_target(filename, targets)
        if target is None:
            foreign += 1
            continue
        number = record_number(filename, target)
        evidence[target][record_fingerprint(text, filename, number)] += 1
        observed[target].add(filename)
    return evidence, observed, foreign


def read_corpus(directory):
    """Every `*--pr<N>.json` record under `directory`, as (filename, text). READ-ONLY."""
    root = pathlib.Path(directory)
    if not root.is_dir():
        raise AuditError(f"provenance directory {directory!r} is not a directory — refusing")
    corpus = []
    for path in sorted(root.iterdir()):
        if not path.is_file() or RECORD_INFIX not in path.name:
            continue
        if not path.name.endswith(RECORD_SUFFIX):
            continue
        corpus.append((path.name, path.read_text(encoding="utf-8")))
    return corpus


def shared_pool_groups(pools):
    """Sorted groups of 2+ enabled targets whose granted pools are EXACTLY equal — the #608
    condition itself. Two rows with an identical pool are provably unscoped relative to each
    other, whatever the usage evidence turns out to say."""
    by_pool = collections.defaultdict(list)
    for target, pool in pools.items():
        by_pool[tuple(pool)].append(target)
    return sorted([sorted(group) for group in by_pool.values() if len(group) > 1])


def audit(pools, evidence, foreign=0, salt=None, observed=None, expected=None):
    """The advisory report. A row yields revocation candidates ONLY when both opt-ins hold: a salt
    maps fingerprints to handles, AND a manifest bounds the corpus and every record it expects is
    present. Either one missing => an EMPTY candidate list."""
    observed = observed or {}
    expected = expected or {}
    targets = {}
    for target, pool in sorted(pools.items()):
        counts = evidence.get(target, collections.Counter())
        records = sum(counts.values())
        # Completeness is a VERIFIED CLAIM, never an inference from `records`. Records present
        # beyond the manifest are not a failure: extra evidence can only ever move a handle from
        # candidate to evidenced, which is the safe direction.
        claim = expected.get(target)
        missing = sorted(claim["records"] - set(observed.get(target, ()))) if claim else []
        complete = bool(claim) and not missing
        row = {
            "granted": list(pool),
            "records": records,
            "distinct_accounts": len(counts),
            "evidenced": [],
            "revocation_candidates": [],
            "unexplained_accounts": 0,
            "evidence_bounds": {
                "window": claim["window"] if claim else None,
                "expected_records": len(claim["records"]) if claim else 0,
                "missing_records": len(missing),
                "complete": complete,
            },
        }
        if records == 0:
            # No record is not "no use" — it is no evidence. Say so and propose nothing.
            row["status"] = STATUS_INSUFFICIENT
        elif salt is None:
            # Records exist but nothing maps a fingerprint to a handle, so every granted handle is
            # UNKNOWN rather than unused. Counts only.
            row["status"] = STATUS_UNMAPPED
        else:
            seen = {fingerprint(handle, salt): handle for handle in pool}
            row["evidenced"] = sorted(seen[f] for f in counts if f in seen)
            # A fingerprint no granted handle explains: a RETIRED handle (acct03/acct06 were
            # removed from both pools on 2026-07-25) or an account granted elsewhere. Surfaced,
            # because it means this row's pool does not describe everything that served this row.
            row["unexplained_accounts"] = sum(1 for f in counts if f not in seen)
            if complete:
                row["status"] = STATUS_SCOPED
                row["revocation_candidates"] = sorted(set(pool) - set(row["evidenced"]))
            else:
                # A handle IS evidenced by a record naming it — that holds on any corpus. A handle
                # is NOT disproved by a corpus that is not known to hold every record, so the
                # candidate list stays empty until completeness is asserted and verified.
                row["status"] = STATUS_PARTIAL
        targets[target] = row
    return {
        "mapped": salt is not None,
        "foreign_records": foreign,
        "shared_pool_groups": shared_pool_groups(pools),
        "targets": targets,
        # Restated in the artifact so a reader who only ever sees the JSON cannot mistake it for a
        # decision, or for something that already happened.
        "decision": "maintainer",
        "revocation_applied": False,
    }


def render(report):
    """The human report. Emits handles and counts only — never a fingerprint (see PRIVACY)."""
    lines = ["grant-scope audit (issue #608) — ADVISORY EVIDENCE, no policy is changed",
             f"  account identity mapping: {'ON' if report['mapped'] else 'OFF (no salt)'}"]
    for group in report["shared_pool_groups"]:
        lines.append("  UNSCOPED: identical account_pool shared by " + ", ".join(group))
    if report["foreign_records"]:
        lines.append(f"  {report['foreign_records']} record(s) belong to no enabled target "
                     "(ignored)")
    for target, row in report["targets"].items():
        lines.append(f"  {target} [{row['status']}]")
        lines.append(f"    granted  ({len(row['granted'])}): {', '.join(row['granted'])}")
        lines.append(f"    records: {row['records']} across {row['distinct_accounts']} distinct "
                     "account(s)")
        bounds = row["evidence_bounds"]
        if row["status"] in (STATUS_SCOPED, STATUS_PARTIAL):
            lines.append(f"    evidenced ({len(row['evidenced'])}): "
                         f"{', '.join(row['evidenced']) or '(none)'}")
            if row["unexplained_accounts"]:
                lines.append(f"    {row['unexplained_accounts']} evidenced account(s) match NO "
                             "granted handle (retired, or granted to another row)")
        if row["status"] == STATUS_SCOPED:
            lines.append(f"    completeness: VERIFIED — all {bounds['expected_records']} expected "
                         f"record(s) present for window {bounds['window']}")
            lines.append(f"    revocation CANDIDATES ({len(row['revocation_candidates'])}): "
                         f"{', '.join(row['revocation_candidates']) or '(none)'}")
        elif row["status"] == STATUS_PARTIAL:
            if bounds["expected_records"]:
                lines.append(f"    completeness: NOT verified — {bounds['missing_records']} of "
                             f"{bounds['expected_records']} record(s) expected for window "
                             f"{bounds['window']} are absent from this corpus")
            else:
                lines.append("    completeness: NOT verified — no expected-record manifest bounds "
                             "this target's corpus")
            lines.append("    proposing nothing: an absent handle in a corpus not known to be "
                         "complete is unknown, not unused")
        elif row["status"] == STATUS_INSUFFICIENT:
            lines.append("    no provenance record names this target — proposing nothing "
                         "(absence of evidence is not evidence of disuse)")
        else:
            lines.append("    no salt, so no fingerprint maps to a handle — proposing nothing")
    lines.append("  A revocation is a reviewed policy/repos.toml edit by the maintainer; this "
                 "tool never writes one.")
    return "\n".join(lines)


def _read(path, what):
    """A document the audit cannot read is a conclusion it must not draw (AuditError => exit 2)."""
    try:
        return pathlib.Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise AuditError(f"cannot read {what} {str(path)!r}: {exc}") from exc


def run(policy_path, provenance_dir, salt=None, expected_path=None):
    grant_account = _load_sibling("grant-account.py", "registry_grant_account")
    pools = pools_by_target(_read(policy_path, "policy"), grant_account)
    evidence, observed, foreign = collect_evidence(read_corpus(provenance_dir), sorted(pools))
    expected = (expected_records(_read(expected_path, "expected-records manifest"), sorted(pools))
                if expected_path else None)
    return audit(pools, evidence, foreign=foreign, salt=salt, observed=observed, expected=expected)


# ---------------------------------------------------------------------------------------------
# SELF-TEST
# ---------------------------------------------------------------------------------------------
SALT = "test-salt"
_H = {handle: hashlib.sha256(f"{handle}:{SALT}".encode()).hexdigest()[:16]
      for handle in ("acct01", "acct02", "acct03", "acctzz")}


def _policy(rows):
    text = ""
    for target, (enabled, pool) in rows.items():
        listing = ", ".join(f'"{handle}"' for handle in pool)
        text += (f'[repos."{target}"]\nenabled = {str(enabled).lower()}\n'
                 f"account_pool = [{listing}]\n\n")
    return text


def _record(handle, number):
    """One provenance record, shaped like worker-pr.provenance_record's document. `number` is
    REQUIRED and has no default: every fixture must state which PR it is the record of, so a
    fixture whose filename and content disagree cannot be written by accident — that mismatch is
    the fail-open this module now refuses, and it must only ever appear where a check means it."""
    return json.dumps({"pr_number": number, "head_sha_at_open": "a" * 40,
                       "impl_provider": "anthropic", "impl_alias": "opus5",
                       "impl_account_h": _H[handle], "issue": 1, "recorded_at_run": "1.1"})


def _manifest(rows, window="#1..#9"):
    """A completeness manifest naming, per target, the PR numbers that MUST be present. The default
    window is the inclusive PR-number range every fixture record below falls inside."""
    return json.dumps({"targets": {target: {"window": window, "records": list(numbers)}
                                   for target, numbers in rows.items()}})


# The env var the CLI checks exercise. Deliberately NOT the production PROVENANCE_SALT: a self-test
# must never read, and must never depend on, a real credential.
_SELFTEST_SALT_ENV = "GRANT_SCOPE_AUDIT_SELFTEST_SALT"


def _cli(argv, env=None):
    """Run `main()` at its REAL seam — argparse over a constructed argv, the process environment,
    and the process's stdout/stderr — so the CLI controls (`--salt-env` and its env lookup,
    `--expected-records`, `--json`, the exit statuses) are covered by execution rather than by
    assumption. argv, env, stdout and stderr are all restored afterwards.

    Returns (exit status, stdout, stderr)."""
    import contextlib
    import io
    out, err = io.StringIO(), io.StringIO()
    saved_argv, saved_env = sys.argv, dict(os.environ)
    sys.argv = ["grant-scope-audit.py"] + list(argv)
    try:
        for name, value in (env or {}).items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = main()
    finally:
        sys.argv = saved_argv
        os.environ.clear()
        os.environ.update(saved_env)
    return status, out.getvalue(), err.getvalue()


def _self_test():
    ok = True

    def check(label, got, want):
        nonlocal ok
        if got != want:
            ok = False
            print(f"FAIL {label}\n  got  {got!r}\n  want {want!r}")
        else:
            print(f"ok   {label}")

    def refuses(label, thunk):
        """A refusal is an AuditError and nothing else. Any OTHER exception reds THIS row and lets
        the suite continue: a traceback is not a refusal (it is an unhandled input reaching
        production code), and letting it propagate would abort the run and leave every check below
        unrun — a mutant that crashes here would otherwise be scored on a partial suite."""
        nonlocal ok
        try:
            thunk()
        except AuditError:
            print(f"ok   {label}")
            return
        except Exception as exc:               # noqa: BLE001 — a crash is a failure, not a refusal
            ok = False
            print(f"FAIL {label}: raised {type(exc).__name__} ({exc}) instead of refusing")
            return
        ok = False
        print(f"FAIL {label}: no refusal")

    def fixture(label, thunk):
        """Build an input the checks BELOW depend on. A refusal here is a failure of this suite's
        own premise, so it reds a named row and yields None rather than aborting: with None the
        dependent rows go red too (an absent manifest proposes nothing), and every remaining check
        is still measured."""
        nonlocal ok
        try:
            built = thunk()
        except AuditError as exc:
            ok = False
            print(f"FAIL {label}: the fixture itself refused ({exc})")
            return None
        print(f"ok   {label}")
        return built

    grant_account = _load_sibling("grant-account.py", "registry_grant_account")

    # -- IDENTITY PARITY. A drift here maps every handle to a fingerprint no record carries, so the
    # audit would report every pool entry unused: the exact false revocation this tool must not
    # produce. Pinned against the REAL sibling, with a wrong-salt positive control.
    sac = _load_sibling("select-and-claim.py", "registry_select_and_claim")
    check("fingerprint IS select-and-claim.account_fingerprint",
          fingerprint("acct01", SALT), sac.account_fingerprint("acct01", SALT))
    check("a different salt derives a DIFFERENT fingerprint (the check above is not vacuous)",
          fingerprint("acct01", SALT) == sac.account_fingerprint("acct01", "other"), False)
    refuses("an empty salt refuses rather than deriving an identity",
            lambda: fingerprint("acct01", ""))

    # -- POLICY READING
    both = _policy({"o/a": (True, ["acct01", "acct02", "acct03"]),
                    "o/b": (True, ["acct01", "acct02", "acct03"]),
                    "o/off": (False, ["acct01"])})
    pools = pools_by_target(both, grant_account)
    check("only ENABLED rows are audited", sorted(pools), ["o/a", "o/b"])
    check("the granted pool is read verbatim", pools["o/a"], ["acct01", "acct02", "acct03"])
    check("identical pools are reported as the #608 unscoped condition",
          shared_pool_groups(pools), [["o/a", "o/b"]])
    check("differing pools are NOT reported as unscoped (the check above is not vacuous)",
          shared_pool_groups({"o/a": ["acct01"], "o/b": ["acct02"]}), [])
    refuses("a pool entry that is not a broker handle refuses",
            lambda: pools_by_target(_policy({"o/a": (True, ["not a handle"])}), grant_account))
    refuses("an empty pool refuses",
            lambda: pools_by_target(_policy({"o/a": (True, [])}), grant_account))
    refuses("a pool listing the same handle twice refuses (its count would not mean what it says)",
            lambda: pools_by_target(_policy({"o/a": (True, ["acct01", "acct01"])}), grant_account))
    refuses("a policy with no enabled row refuses",
            lambda: pools_by_target(_policy({"o/a": (False, ["acct01"])}), grant_account))

    # -- RECORD ATTRIBUTION
    check("a record is attributed to its own target",
          record_target("o--a--pr7.json", ["o/a", "o/b"]), "o/a")
    check("a record for an unaudited target is attributed to NO target",
          record_target("x--y--pr7.json", ["o/a", "o/b"]), None)
    check("a repository name containing `--` is attributed by prefix, not by splitting",
          record_target("o--a--b--pr7.json", ["o/a--b", "o/a"]), "o/a--b")
    check("a file that is not a .json record is attributed to no target",
          record_target("o--a--pr7.txt", ["o/a", "o/b"]), None)
    refuses("a record attributable to two targets refuses instead of guessing",
            lambda: record_target("o--a--pr1--pr7.json", ["o/a", "o/a--pr1"]))
    refuses("a target that is not <owner>/<repo> has no record prefix and refuses",
            lambda: record_prefix("not-a-target"))
    check("a well-formed record yields its fingerprint",
          record_fingerprint(_record("acct01", 1), "o--a--pr1.json", 1), _H["acct01"])
    refuses("a record with a non-fingerprint impl_account_h refuses the audit",
            lambda: record_fingerprint('{"impl_account_h": "zz"}', "o--a--pr1.json", 1))
    refuses("a record with NO impl_account_h refuses the audit",
            lambda: record_fingerprint('{"pr_number": 1}', "o--a--pr1.json", 1))
    refuses("an unparseable record refuses the audit (never skipped)",
            lambda: record_fingerprint("{not json", "o--a--pr1.json", 1))
    refuses("a record that parses but is not a JSON object refuses the audit",
            lambda: record_fingerprint("[]", "o--a--pr1.json", 1))

    # -- FILENAME <-> CONTENT. Completeness is verified against filenames, so a filename that does
    # not hold the record it names would witness a record that is absent. The number is read
    # EXACTLY from the name, and the document must agree with it.
    check("a canonical record filename yields the PR number it names",
          record_number("o--a--pr7.json", "o/a"), 7)
    check("...for a repository name containing `--` too",
          record_number("o--a--b--pr7.json", "o/a--b"), 7)
    refuses("a record name whose PR number is not digits refuses (never silently ignored)",
            lambda: record_number("o--a--prX.json", "o/a"))
    refuses("...nor is a zero-padded number, which is not the name the writer builds",
            lambda: record_number("o--a--pr07.json", "o/a"))
    refuses("...nor a name carrying no number at all", lambda: record_number("o--a--pr.json", "o/a"))
    refuses("a name that is not this target's record at all refuses",
            lambda: record_number("x--y--pr7.json", "o/a"))
    refuses("a record whose document names a DIFFERENT PR than its filename refuses",
            lambda: record_fingerprint(_record("acct01", 1), "o--a--pr2.json", 2))
    refuses("a record with NO pr_number refuses (its name would witness nothing)",
            lambda: record_fingerprint(json.dumps({"impl_account_h": _H["acct01"]}),
                                       "o--a--pr1.json", 1))
    # Each shape below would COMPARE EQUAL to the filename's number (`True == 1`, `1.0 == 1`), so
    # the equality check alone accepts them: only the shape guard refuses, and these are what make
    # it independently killable rather than a second copy of the check above.
    refuses("a record whose pr_number is a string refuses",
            lambda: record_fingerprint(json.dumps({"impl_account_h": _H["acct01"],
                                                   "pr_number": "1"}), "o--a--pr1.json", 1))
    refuses("a record whose pr_number is a bool refuses (JSON true equals 1 in Python)",
            lambda: record_fingerprint(json.dumps({"impl_account_h": _H["acct01"],
                                                   "pr_number": True}), "o--a--pr1.json", 1))
    refuses("a record whose pr_number is a float refuses (1.0 equals 1 too)",
            lambda: record_fingerprint(json.dumps({"impl_account_h": _H["acct01"],
                                                   "pr_number": 1.0}), "o--a--pr1.json", 1))
    refuses("a record whose pr_number is not positive refuses even when the caller agrees with it",
            lambda: record_fingerprint(json.dumps({"impl_account_h": _H["acct01"],
                                                   "pr_number": -5}), "o--a--pr5.json", -5))
    refuses("a sibling that cannot be loaded refuses rather than auditing without it",
            lambda: _load_sibling("no-such-sibling.txt", "registry_no_such_sibling"))

    # -- THE CORE #608 QUESTION: usage is attributed PER TARGET, and does not leak across rows.
    # Every fixture below names, in its filename AND in its document, the SAME PR — the corpus a
    # correct writer produces. It is the positive control for the binding checks that follow.
    corpus = [("o--a--pr1.json", _record("acct01", 1)), ("o--a--pr2.json", _record("acct02", 2)),
              ("o--b--pr3.json", _record("acct03", 3)), ("x--y--pr4.json", _record("acct01", 4))]
    evidence, observed, foreign = collect_evidence(corpus, ["o/a", "o/b"])
    check("records belonging to no audited target are counted, not attributed", foreign, 1)
    check("each audited target's own record filenames are collected for the completeness check",
          (sorted(observed["o/a"]), sorted(observed["o/b"])),
          (["o--a--pr1.json", "o--a--pr2.json"], ["o--b--pr3.json"]))
    # The binding AT THE SEAM THAT USES IT. `o--a--pr2.json` holding PR 1's record would otherwise
    # be observed as PR 2's record and satisfy the manifest entry for a record that is genuinely
    # missing — declaring an incomplete corpus complete and turning the absence into candidates.
    refuses("a corpus record whose document names another PR refuses the whole audit",
            lambda: collect_evidence([("o--a--pr1.json", _record("acct01", 1)),
                                      ("o--a--pr2.json", _record("acct02", 1))], ["o/a", "o/b"]))
    refuses("...and a corpus record with an unreadable PR number is refused, never made foreign",
            lambda: collect_evidence([("o--a--pr0x2.json", _record("acct01", 2))], ["o/a", "o/b"]))
    # The manifest states the corpus is EXACTLY these PRs for these windows, so — and only so —
    # absence becomes disuse. Every candidate-producing check below runs under this claim.
    complete = fixture("a correct manifest is ACCEPTED (every refusal below is a real distinction)",
                       lambda: expected_records(_manifest({"o/a": [1, 2], "o/b": [3]}),
                                                ["o/a", "o/b"]))
    scoped = audit(pools, evidence, foreign=foreign, salt=SALT, observed=observed,
                   expected=complete)
    check("a target's evidenced set is its OWN records only",
          scoped["targets"]["o/a"]["evidenced"], ["acct01", "acct02"])
    check("a handle used only by the OTHER target is a revocation candidate here",
          scoped["targets"]["o/a"]["revocation_candidates"], ["acct03"])
    check("and symmetrically for the other row",
          (scoped["targets"]["o/b"]["evidenced"],
           scoped["targets"]["o/b"]["revocation_candidates"]),
          (["acct03"], ["acct01", "acct02"]))
    check("the report never claims a revocation happened",
          (scoped["decision"], scoped["revocation_applied"]), ("maintainer", False))

    check("a complete corpus reports its verified bounds",
          scoped["targets"]["o/a"]["evidence_bounds"],
          {"window": "#1..#9", "expected_records": 2, "missing_records": 0, "complete": True})
    check("...and the window is surfaced to the reader of the text report",
          "completeness: VERIFIED — all 2 expected record(s) present for window #1..#9"
          in render(scoped), True)

    # -- FAIL CLOSED 1: no evidence for a row proposes NOTHING (not "revoke the whole pool").
    empty = audit(pools, {"o/a": collections.Counter(), "o/b": evidence["o/b"]}, salt=SALT,
                  observed=observed, expected=complete)
    check("a target with zero records is insufficient-evidence",
          empty["targets"]["o/a"]["status"], STATUS_INSUFFICIENT)
    check("...and proposes NO revocation despite an entirely unevidenced pool",
          empty["targets"]["o/a"]["revocation_candidates"], [])
    check("...while the row that DOES have COMPLETE evidence still proposes (not vacuous)",
          empty["targets"]["o/b"]["revocation_candidates"], ["acct01", "acct02"])

    # -- FAIL CLOSED 2: a NONEMPTY corpus is not a COMPLETE one. This is the inference the whole
    # tool turns on: the same corpus, the same salt, the same pools — only the completeness claim
    # differs, and a claim that is not verified must propose nothing.
    unbounded = audit(pools, evidence, foreign=foreign, salt=SALT, observed=observed)
    check("with NO manifest a nonempty corpus is partial-evidence, not scoped",
          unbounded["targets"]["o/a"]["status"], STATUS_PARTIAL)
    check("...and proposes NO revocation, though the same inputs WITH a manifest do",
          (unbounded["targets"]["o/a"]["revocation_candidates"],
           scoped["targets"]["o/a"]["revocation_candidates"]), ([], ["acct03"]))
    check("...while the handles actually observed are still reported (use is sound either way)",
          unbounded["targets"]["o/a"]["evidenced"], ["acct01", "acct02"])
    check("...and the report says why it is proposing nothing",
          "completeness: NOT verified — no expected-record manifest bounds this target's corpus"
          in render(unbounded), True)
    # A manifest that expects a record the corpus does not hold is the partial-corpus case itself:
    # pr9 was written to the ledger branch and is not in this checkout.
    gapped = fixture("a manifest expecting a record this corpus lacks is still a VALID manifest",
                     lambda: expected_records(_manifest({"o/a": [1, 2, 9], "o/b": [3]}),
                                              ["o/a", "o/b"]))
    holey = audit(pools, evidence, foreign=foreign, salt=SALT, observed=observed, expected=gapped)
    check("a manifest with ONE expected record missing makes that row partial-evidence",
          holey["targets"]["o/a"]["status"], STATUS_PARTIAL)
    check("...and proposes nothing for it, while the row whose records are ALL present still does",
          (holey["targets"]["o/a"]["revocation_candidates"],
           holey["targets"]["o/b"]["revocation_candidates"]), ([], ["acct01", "acct02"]))
    check("...and the missing count and window are surfaced, not swallowed",
          holey["targets"]["o/a"]["evidence_bounds"],
          {"window": "#1..#9", "expected_records": 3, "missing_records": 1, "complete": False})
    check("...in the text report too",
          "completeness: NOT verified — 1 of 3 record(s) expected for window #1..#9 are absent"
          in render(holey), True)
    # A manifest is only a completeness signal if it is read exactly; every way of getting one
    # wrong refuses rather than licensing a revocation.
    refuses("a manifest that does not parse refuses",
            lambda: expected_records("{not json", ["o/a"]))
    refuses("a manifest with no `targets` object refuses",
            lambda: expected_records(json.dumps({"records": [1]}), ["o/a"]))
    refuses("a manifest naming an unaudited target refuses (a stale manifest bounds nothing)",
            lambda: expected_records(_manifest({"o/zz": [1]}), ["o/a"]))
    refuses("a manifest entry that is not an object refuses",
            lambda: expected_records(json.dumps({"targets": {"o/a": [1, 2]}}), ["o/a"]))
    refuses("a manifest entry with no observation window refuses",
            lambda: expected_records(json.dumps({"targets": {"o/a": {"records": [1]}}}), ["o/a"]))
    refuses("a manifest entry with an empty window refuses",
            lambda: expected_records(_manifest({"o/a": [1]}, window="  "), ["o/a"]))
    # -- THE WINDOW IS CHECKED AGAINST THE RECORDS IT IS MADE OVER (#1887). It used to be any
    # non-blank string, while the report quoted it as the scope the completeness claim was made
    # over: a manifest whose window said one thing and whose records enumerated another was
    # indistinguishable from a correct one. Bounds and records are now in the SAME units.
    check("a window is read as an INCLUSIVE PR-number range",
          window_bounds("#3..#7", "o/a"), (3, 7))
    inclusive = fixture("records ON both bounds and between them are ACCEPTED (the refusals below "
                        "are real distinctions, not a window that rejects everything)",
                        lambda: expected_records(_manifest({"o/a": [1, 4, 9]}, window="#1..#9"),
                                                 ["o/a"]))
    check("...and all three become expected records (the bounds are inclusive, not off by one)",
          sorted(inclusive["o/a"]["records"]) if inclusive else None,
          ["o--a--pr1.json", "o--a--pr4.json", "o--a--pr9.json"])
    refuses("a manifest listing a record ABOVE its own window refuses",
            lambda: expected_records(_manifest({"o/a": [1, 12]}, window="#1..#9"), ["o/a"]))
    refuses("...and one BELOW its own window refuses too",
            lambda: expected_records(_manifest({"o/a": [2, 5]}, window="#4..#9"), ["o/a"]))
    refuses("a DATE window refuses: no record carries a timestamp, so it bounds nothing this "
            "module can check",
            lambda: expected_records(_manifest({"o/a": [1]}, window="2026-07-01..2026-07-28"),
                                     ["o/a"]))
    refuses("a window whose bounds carry no `#` refuses",
            lambda: expected_records(_manifest({"o/a": [1]}, window="1..9"), ["o/a"]))
    # MULTI-DIGIT on purpose. With a single-digit bound the `#` requirement and the slice that
    # strips it mask each other — `"1"[1:]` is empty and refuses anyway — so dropping the prefix
    # check alone survives the row above. `"12..99"` is where the two come apart: without the
    # check it reads as the window #2..#9, silently narrowing the scope by ten PRs.
    refuses("...including a multi-digit one, which without the `#` check would read as #2..#9",
            lambda: window_bounds("12..99", "o/a"))
    refuses("a window carrying trailing prose refuses (a partly-checked scope is unchecked)",
            lambda: expected_records(_manifest({"o/a": [1]}, window="#1..#9 (July)"), ["o/a"]))
    refuses("a window that names one bound and no range refuses",
            lambda: window_bounds("#7", "o/a"))
    refuses("a window with a third bound refuses rather than reading the first two",
            lambda: window_bounds("#1..#4..#9", "o/a"))
    refuses("a zero-padded window bound refuses, exactly as in a record name",
            lambda: window_bounds("#01..#09", "o/a"))
    refuses("a window bound that is not a positive PR number refuses",
            lambda: window_bounds("#0..#9", "o/a"))
    refuses("a window whose low bound is above its high bound refuses (it contains nothing)",
            lambda: window_bounds("#9..#1", "o/a"))
    refuses("a window that is not a string at all refuses",
            lambda: window_bounds(20260701, "o/a"))
    refuses("a manifest entry expecting NO record refuses (it asserts nothing)",
            lambda: expected_records(_manifest({"o/a": []}), ["o/a"]))
    refuses("a manifest entry with a non-PR-number record refuses",
            lambda: expected_records(_manifest({"o/a": ["pr1"]}), ["o/a"]))
    refuses("a manifest entry with a duplicate PR number refuses",
            lambda: expected_records(_manifest({"o/a": [1, 1]}), ["o/a"]))
    refuses("an empty manifest refuses", lambda: expected_records(_manifest({}), ["o/a"]))
    filed = fixture("a two-target manifest is accepted",
                    lambda: expected_records(_manifest({"o/a": [1, 2]}), ["o/a", "o/b"]))
    check("a manifest number becomes THIS target's record filename, never another row's",
          sorted(filed["o/a"]["records"]) if filed else None,
          ["o--a--pr1.json", "o--a--pr2.json"])

    # -- FAIL CLOSED 3: no salt => no candidate anywhere, on the SAME corpus that produces them.
    # Called through a catcher: without the no-salt gate `fingerprint()` refuses (the second
    # fail-closed layer), and a suite that ABORTS there would report a kill while leaving every
    # row below it unrun. Catching turns that into a red row with the rest still measured.
    try:
        unmapped = audit(pools, evidence, foreign=foreign, salt=None, observed=observed,
                         expected=complete)
    except AuditError:
        unmapped = None
    check("without a salt the audit REPORTS rather than refusing to run at all",
          unmapped is not None, True)
    unmapped = unmapped if unmapped is not None else audit(pools, {}, salt=None)
    check("without a salt every row is unmapped-evidence",
          sorted({row["status"] for row in unmapped["targets"].values()}), [STATUS_UNMAPPED])
    check("...and no row proposes a revocation",
          [row["revocation_candidates"] for row in unmapped["targets"].values()], [[], []])
    check("...though the distinct-account count is still reported honestly",
          unmapped["targets"]["o/a"]["distinct_accounts"], 2)

    # -- FAIL CLOSED 4: an evidenced account that no granted handle explains is surfaced.
    retired = {"o/a": collections.Counter({_H["acct01"]: 1, _H["acctzz"]: 3}),
               "o/b": collections.Counter()}
    retired_report = audit(
        pools, retired, salt=SALT, observed={"o/a": {"o--a--pr1.json", "o--a--pr5.json"}},
        expected=fixture("a manifest whose records straddle its window bounds is ACCEPTED",
                         lambda: expected_records(_manifest({"o/a": [1, 5]}), ["o/a", "o/b"])))
    row = retired_report["targets"]["o/a"]
    check("an unexplained (retired/foreign) account is counted", row["unexplained_accounts"], 1)
    check("...and does NOT mark any granted handle evidenced", row["evidenced"], ["acct01"])
    check("...so the remaining pool is still proposed for review",
          row["revocation_candidates"], ["acct02", "acct03"])
    check("...and the reader is TOLD the corpus names an account this pool does not",
          "    1 evidenced account(s) match NO granted handle (retired, or granted to another row)"
          in render(retired_report), True)

    # -- PRIVACY: no report ever emits a fingerprint, in either mode.
    check("the corpus really does carry the fingerprint (the checks below are not vacuous)",
          _H["acct01"] in corpus[0][1], True)
    for name, report in (("mapped", scoped), ("unmapped", unmapped)):
        blob = render(report) + json.dumps(report)
        leaked = sorted(value for value in _H.values() if value in blob)
        check(f"the {name} report emits no account fingerprint", leaked, [])
    check("...while still naming the handles the policy already lists in the clear",
          "acct03" in render(scoped), True)

    # -- END TO END over real files, and READ-ONLY: the inputs are byte-identical afterwards.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        policy_path = root / "repos.toml"
        policy_path.write_text(both, encoding="utf-8")
        prov = root / "provenance"
        prov.mkdir()
        for name, text in corpus:
            (prov / name).write_text(text, encoding="utf-8")
        (prov / "README.md").write_text("not a record", encoding="utf-8")
        # Named like a record but not one: the corpus reader must skip it rather than read it.
        (prov / "o--a--pr8.txt").write_text("not a record either", encoding="utf-8")
        manifest_path = root / "expected.json"
        manifest_path.write_text(_manifest({"o/a": [1, 2], "o/b": [3]}), encoding="utf-8")
        before = {path.name: path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file()}
        end_to_end = fixture("the end-to-end run over real files completes",
                             lambda: run(str(policy_path), str(prov), salt=SALT,
                                         expected_path=str(manifest_path)))
        check("the end-to-end run reproduces the per-target scoping",
              end_to_end["targets"]["o/a"]["revocation_candidates"] if end_to_end else None,
              ["acct03"])
        check("a non-record file in the corpus directory is ignored",
              end_to_end["foreign_records"] if end_to_end else None, 1)
        check("the same end-to-end run WITHOUT a manifest proposes nothing (not vacuous)",
              [row["revocation_candidates"]
               for row in run(str(policy_path), str(prov), salt=SALT)["targets"].values()],
              [[], []])
        after = {path.name: path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file()}
        check("the audit is READ-ONLY (policy + corpus byte-identical after a full run)",
              after, before)

        # END TO END through read_corpus: PR 5's record parked under PR 6's name. The manifest does
        # not even expect pr6 — an EXTRA record is allowed — but a file whose name does not hold
        # the record it claims makes every filename in this corpus untrustworthy as a completeness
        # witness, so the whole run refuses rather than reporting from it.
        misnamed = prov / "o--a--pr6.json"
        misnamed.write_text(_record("acct01", 5), encoding="utf-8")
        refuses("end to end, a corpus file whose name and content name different PRs refuses",
                lambda: run(str(policy_path), str(prov), salt=SALT,
                            expected_path=str(manifest_path)))
        misnamed.unlink()
        rerun = fixture("...and the SAME corpus without that one file is readable again",
                        lambda: run(str(policy_path), str(prov), salt=SALT,
                                    expected_path=str(manifest_path)))
        check("...and it scopes normally (the refusal above is not vacuous)",
              rerun["targets"]["o/a"]["revocation_candidates"] if rerun else None, ["acct03"])

        refuses("a missing provenance directory refuses",
                lambda: run(str(policy_path), str(root / "nope"), salt=SALT))
        refuses("an unreadable policy refuses (rather than a traceback)",
                lambda: run(str(root / "nope.toml"), str(prov), salt=SALT))
        refuses("an unreadable expected-records manifest refuses",
                lambda: run(str(policy_path), str(prov), salt=SALT,
                            expected_path=str(root / "nope.json")))

        # -- THE CLI SEAM. Everything above calls run()/audit() directly; the production controls
        # live in main(), so they are exercised HERE, through argparse and the real environment.
        # Each check pins a VALUE the flag controls, not merely that the flag is accepted.
        base = ["--policy", str(policy_path), "--provenance-dir", str(prov),
                "--expected-records", str(manifest_path)]
        status, out, err = _cli(base, env={_SELFTEST_SALT_ENV: SALT})
        check("the CLI default is UNMAPPED even with a salt sitting in the environment",
              (status, "account identity mapping: OFF (no salt)" in out,
               "revocation CANDIDATES" in out), (0, True, False))
        status, mapped_out, err = _cli(base + ["--salt-env", _SELFTEST_SALT_ENV],
                                       env={_SELFTEST_SALT_ENV: SALT})
        check("--salt-env <VAR> reads THAT variable and maps, exit 0, nothing on stderr",
              (status, "account identity mapping: ON" in mapped_out, err), (0, True, ""))
        check("...and the mapped CLI report names the candidates exactly",
              "    revocation CANDIDATES (1): acct03" in mapped_out, True)
        status, out, err = _cli(base + ["--salt-env", _SELFTEST_SALT_ENV],
                                env={_SELFTEST_SALT_ENV: None})
        check("a MISSING salt variable cannot map: unmapped, warned, still exit 0",
              (status, "account identity mapping: OFF (no salt)" in out,
               "revocation CANDIDATES" in out, _SELFTEST_SALT_ENV in err), (0, True, False, True))
        status, out, _ = _cli(base + ["--salt-env", _SELFTEST_SALT_ENV],
                              env={_SELFTEST_SALT_ENV: ""})
        check("an EMPTY salt variable cannot map either",
              (status, "revocation CANDIDATES" in out), (0, False))
        # Bare --salt-env falls back to the production variable name; PROVENANCE_SALT is unset for
        # this call so the check cannot depend on (or read) a real credential.
        status, out, err = _cli(base + ["--salt-env"],
                                env={DEFAULT_SALT_ENV: None, _SELFTEST_SALT_ENV: SALT})
        check("bare --salt-env falls back to the PROVENANCE_SALT variable, not to some other one",
              (status, DEFAULT_SALT_ENV in err, "revocation CANDIDATES" in out), (0, True, False))
        # The blocker case at the seam: mapped, nonempty corpus, no completeness claim.
        status, out, _ = _cli(["--policy", str(policy_path), "--provenance-dir", str(prov),
                               "--salt-env", _SELFTEST_SALT_ENV], env={_SELFTEST_SALT_ENV: SALT})
        check("a mapped CLI run with NO --expected-records is partial-evidence and proposes nothing",
              (status, f"[{STATUS_PARTIAL}]" in out, "revocation CANDIDATES" in out),
              (0, True, False))
        status, json_out, _ = _cli(base + ["--salt-env", _SELFTEST_SALT_ENV, "--json"],
                                   env={_SELFTEST_SALT_ENV: SALT})
        try:                        # a FAILING parse must red this row, not abort the suite
            document = json.loads(json_out)
        except ValueError:
            document = None
        check("--json emits a parseable report carrying the same candidates",
              (status, document and document["mapped"],
               document and document["targets"]["o/a"]["revocation_candidates"]),
              (0, True, ["acct03"]))
        check("...and the JSON the CLI actually printed carries no account fingerprint",
              sorted(value for value in _H.values() if value in json_out), [])
        status, out, err = _cli(["--policy", str(policy_path),
                                 "--provenance-dir", str(root / "nope")])
        check("a read failure at the CLI exits 2, explains itself on stderr, prints no report",
              (status, err.startswith("grant-scope-audit: "), out), (2, True, ""))

    # -- THE LIVE DOCUMENTS. Runs against this repo's real policy + provenance corpus, in the
    # DEFAULT (unmapped) mode, which is the mode CI would ever use. The assertion is the one that
    # stays true after the maintainer eventually narrows a row: the default mode is advisory-safe.
    repo = pathlib.Path(_script_dir()).parent
    live = run(str(repo / DEFAULT_POLICY), str(repo / DEFAULT_PROVENANCE_DIR))
    check("the real policy + corpus audit cleanly",
          all(row["granted"] for row in live["targets"].values()), True)
    check("the default (no-salt) mode proposes NO revocation on the real documents",
          [row["revocation_candidates"] for row in live["targets"].values()],
          [[] for _ in live["targets"]])
    print(render(live))
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default=DEFAULT_POLICY)
    parser.add_argument("--provenance-dir", default=DEFAULT_PROVENANCE_DIR)
    parser.add_argument(
        "--salt-env", nargs="?", const=DEFAULT_SALT_ENV, default=None,
        help=("opt in to mapping fingerprints back to handles by naming the env var holding "
              f"PROVENANCE_SALT (default {DEFAULT_SALT_ENV}). Without it no revocation candidate "
              "is ever proposed. The salt is never printed."))
    parser.add_argument(
        "--expected-records", default=None,
        help=('path to the durable expected-record manifest that bounds the corpus ({"targets": '
              '{"<owner>/<repo>": {"window": "#<low>..#<high>", "records": [<PR number>, ...]}}}). '
              "The window is an INCLUSIVE PR-number range and every listed record must lie inside "
              "it: a window this tool cannot check would be a scope the reader takes on trust."
              " Without it, or with any expected record absent, the row is partial-evidence and no "
              "revocation candidate is proposed — a corpus not known to be complete cannot show "
              "disuse."))
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    salt = None
    if args.salt_env:
        salt = os.environ.get(args.salt_env) or None
        if salt is None:
            sys.stderr.write(
                f"{args.salt_env} is empty; continuing UNMAPPED (no revocation candidate will be "
                "proposed)\n")
    try:
        report = run(args.policy, args.provenance_dir, salt=salt,
                     expected_path=args.expected_records)
    except AuditError as exc:
        sys.stderr.write(f"grant-scope-audit: {exc}\n")
        return 2
    print(json.dumps(report, indent=1, sort_keys=True) if args.json else render(report))
    # Always 0 on a successful read: this is advisory evidence for a human, never a gate. A
    # revocation is a maintainer decision, and an undecided decision must not fail anyone's CI.
    return 0


if __name__ == "__main__":
    sys.exit(main())
