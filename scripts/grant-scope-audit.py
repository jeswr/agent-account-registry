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
#      window. That manifest must be DERIVED by `--generate-manifest` and never typed (see MANIFEST
#      GENERATION below, issue #1027): the reader REFUSES a manifest carrying no generation
#      provenance, because a claim that can be typed can be typed SHORT, and a short claim is
#      satisfied by the very partial corpus it was meant to bound — strictly more dangerous than no
#      claim at all. What is derived is then VERIFIED here: every expected record must be present.
#      Verification is by FILENAME, so a filename must be worth trusting: each record's name is
#      parsed exactly and must agree with the `pr_number` INSIDE it, or the audit refuses.
#      Otherwise a record parked under another PR's name would witness a record that is really
#      missing, and an incomplete corpus would be declared complete — the false revocation this
#      whole module exists to prevent. Without a verified manifest a row is `partial-evidence`:
#      observed handles are reported (positive evidence of USE is sound on any corpus) and the
#      candidate list stays EMPTY.
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
DEFAULT_POLICY = "policy/repos.toml"
DEFAULT_PROVENANCE_DIR = "orchestration/provenance"
# The env var holding the salt, when the operator opts in to mapping. Never read unless asked for,
# never printed.
DEFAULT_SALT_ENV = "PROVENANCE_SALT"
# The `generated.basis` an expected-record manifest must carry to be READ AT ALL. Written by the
# generator (MANIFEST GENERATION below) and required by the reader (`generation_provenance`): a
# completeness claim that can be typed can be typed SHORT, and short is the false-revocation case
# this module exists to prevent.
MANIFEST_BASIS = "ledger-provenance-records"

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


def generation_provenance(document):
    """(stamped window, source record count) from a manifest's `generated` block. Refuses without.

    THE READER IS THE ARM SIDE, so derivation is ENFORCED here rather than recommended in the help
    text. A manifest this function accepts is what turns `partial-evidence` into `scoped` and a
    live account into a revocation candidate, so shipping a generator while still accepting a
    hand-typed `{"targets": ...}` document would leave the exact hole the generator exists to
    close: a transcription short of a PR is invisible, is satisfied by the very partial corpus it
    was meant to bound, and arms. A document without this block is therefore REFUSED, not read as
    advisory — a manifest that is read at all is a manifest that can arm.

    WHAT THIS DOES AND DOES NOT PROVE, stated because "refuses hand-written manifests" would be an
    overclaim. There is no secret to sign a manifest with: the audit runs offline and its only
    credential is the provenance salt, which anyone who can type a manifest can also read, so this
    is a STRUCTURAL bind and not a cryptographic one. Its force is that the block must AGREE with
    the entries it describes — same basis, same window, same record COUNT — so the realistic
    failure, an operator editing or retyping a generated artifact and dropping a PR from it, breaks
    the count and refuses. It cannot stop a deliberate, self-consistent forgery; only an
    authoritative enumeration the auditor fetches itself could, and that needs the network and a
    token this module deliberately does not have. What it removes is the SLIP."""
    block = document.get("generated")
    if not isinstance(block, dict):
        raise AuditError(
            "expected-records manifest carries no `generated` block: only a manifest DERIVED by "
            "--generate-manifest may assert completeness, because a hand-written one that is short "
            "of a PR is satisfied by the partial corpus it was meant to bound and would license a "
            "revocation on missing evidence — regenerate it with `--generate-manifest "
            "--from-records <authoritative tree> --window <window>`")
    basis = block.get("basis")
    if basis != MANIFEST_BASIS:
        raise AuditError(
            f"expected-records manifest states generated.basis={basis!r}, not {MANIFEST_BASIS!r} — "
            "refusing a completeness claim that was not derived from an authoritative record tree")
    window = block.get("window")
    if not isinstance(window, str) or not window.strip():
        raise AuditError(
            "expected-records manifest's `generated` block states no observation `window` — "
            "refusing an unbounded completeness claim")
    count = block.get("source_records")
    # No lower bound: a negative or otherwise absurd count cannot equal the number of records the
    # entries list, so the comparison in `expected_records` refuses it anyway. What that comparison
    # canNOT see is a non-int that compares EQUAL to it (2.0 == 2), which is what this guard is for.
    if isinstance(count, bool) or not isinstance(count, int):
        raise AuditError(
            f"expected-records manifest states generated.source_records={count!r}, which is not a "
            "record count — refusing a claim whose entries are bound to nothing")
    return window, count


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
    another row's evidence."""
    try:
        document = json.loads(manifest_text)
    except (ValueError, TypeError) as exc:
        raise AuditError(f"expected-records manifest does not parse as JSON: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("targets"), dict):
        raise AuditError("expected-records manifest must be a JSON object with a `targets` object")
    derived_window, source_records = generation_provenance(document)
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
        if not isinstance(window, str) or not window.strip():
            raise AuditError(
                f"expected-records entry for {target!r} states no observation `window` — refusing "
                "to accept an unbounded completeness claim")
        if window != derived_window:
            raise AuditError(
                f"expected-records entry for {target!r} states window {window!r}, but the manifest "
                f"was derived over {derived_window!r} — refusing an entry that does not belong to "
                "the generation that produced it")
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
        if len(set(numbers)) != len(numbers):
            raise AuditError(
                f"expected-records entry for {target!r} lists a duplicate PR number — refusing a "
                "manifest whose record count does not mean what it says")
        prefix = record_prefix(target)
        claims[target] = {"window": window,
                          "records": frozenset(f"{prefix}{n}{RECORD_SUFFIX}" for n in numbers)}
    if not claims:
        raise AuditError("expected-records manifest declares no target — nothing is bounded by it")
    listed = sum(len(claim["records"]) for claim in claims.values())
    if listed != source_records:
        raise AuditError(
            f"expected-records manifest lists {listed} record(s) across its entries, but its "
            f"`generated` block was derived from {source_records} — refusing a manifest whose "
            "entries were edited after generation: a claim short of a PR is satisfied by the very "
            "corpus it was meant to bound")
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


# ---------------------------------------------------------------------------------------------
# MANIFEST GENERATION (issue #1027)
#
# The manifest above is the ONLY completeness signal, and until now the maintainer TYPED it. A
# transcription slip that OMITS a PR number is invisible and fails OPEN in the one direction this
# module exists to close: the audit checks that every expected record is PRESENT, so a manifest
# short of a few PRs is trivially satisfied by the partial corpus it was supposed to bound, the row
# is marked `scoped`, and every handle whose only records were the omitted ones becomes a
# revocation candidate. A short manifest is therefore strictly more dangerous than no manifest.
#
# So the manifest is DERIVED here from an authoritative record tree the maintainer points at — a
# `ledger`-branch checkout of orchestration/provenance, the branch records have been written to
# since #96 — and the derived document is validated through `expected_records` (the audit's OWN
# reader) before it is printed. Still READ-ONLY, and still no policy write path: it prints to
# stdout, and the maintainer redirects it and REVIEWS a generated artifact instead of typing one.
#
# And derivation is REQUIRED, not merely offered: the generator stamps `generated` and the reader
# refuses any manifest that does not carry it, consistent with its entries (`generation_provenance`
# states exactly how far that binding goes). A generator the arm side treats as optional would have
# left the typed short manifest above arming exactly as before.
#
# TWO THINGS A GENERATED MANIFEST DOES NOT PROVE, stated because a generated artifact reads as more
# authoritative than a typed one:
#   * It bounds the corpus against the ledger's RECORD SET, not against the set of worker PRs that
#     RAN. A PR whose record was never minted is absent from both trees, so it is absent from the
#     manifest too and the audit would still call that corpus complete. Only an enumeration of the
#     target's merged worker PRs can see that, and that needs the network and a token — neither of
#     which this module has. The stamped `window` is what lets a human check the two by eye, which
#     is why it is required and cannot be defaulted.
#   * It cannot bound a corpus it was DERIVED FROM. Generating from the very tree the audit reads
#     yields a manifest that is complete by construction and asserts nothing, so pointing
#     `--from-records` at the audited corpus REFUSES rather than emitting that tautology.


def is_same_directory(left, right):
    """True when two paths name the SAME directory, with symlinks, mounts and `..` resolved.

    `samefile` is the strong form — it compares the underlying inode, so a second mount or bind
    mount of the audited corpus cannot present itself as an independent source. The resolved-path
    comparison is the fallback for a path that does not exist, which `read_corpus` refuses a moment
    later anyway.

    DECLARED EQUIVALENT SURVIVOR (AGENTS.md 4): forcing the `samefile` branch to raise, so only the
    fallback runs, survives this module's self-test — `Path.resolve()` canonicalises symlinks too,
    so the two forms agree on every input an offline test can construct. `samefile` is kept because
    it ALSO sees the inode-level aliases a path comparison cannot (a bind mount, a second mount of
    one tree), and those are precisely what no self-test here can create."""
    left, right = pathlib.Path(left), pathlib.Path(right)
    try:
        return left.samefile(right)
    except OSError:
        return left.resolve() == right.resolve()


def manifest_from_corpus(corpus, targets, window):
    """The expected-record manifest that an AUTHORITATIVE `corpus` supports, stamped with `window`.

    Four properties, each of which is what makes a generated manifest worth more than a typed one:

      * Every record is read through `collect_evidence` — the SAME pass, with the same name/content
        binding, that the audit draws its conclusions from. A source file whose filename and
        `pr_number` name different PRs refuses the generation outright rather than putting a number
        into the manifest that nothing in the source actually witnesses.
      * A target the source holds NO record for is OMITTED, and named in
        `generated.targets_without_records` so the omission is visible rather than inferred from a
        gap. It cannot be emitted with an empty `records` list: `expected_records` refuses that,
        because an entry expecting nothing is satisfied by any corpus at all.
      * Records belonging to no audited target are counted, never attributed — the same treatment
        the audit gives them.
      * The document is round-tripped through `expected_records` before it is returned, so the
        generator can never emit an artifact the audit would refuse, and the manifest grammar keeps
        exactly ONE definition: the reader's. That round trip is what validates `window`, and — now
        that the reader REQUIRES a `generated` block — what proves this generator is a path through
        that gate rather than something the gate would lock out."""
    _evidence, observed, foreign = collect_evidence(corpus, targets)
    entries, unbounded = {}, []
    for target in sorted(targets):
        numbers = sorted(record_number(name, target) for name in observed.get(target, ()))
        if numbers:
            entries[target] = {"window": window, "records": numbers}
        else:
            unbounded.append(target)
    document = {
        # The block the READER requires (`generation_provenance`): `basis`, `window` and
        # `source_records` are what an accepted manifest is bound to, so an artifact edited after
        # generation no longer agrees with it. `foreign_records` and `targets_without_records` are
        # advisory, for the human reviewing the artifact — they say what the source held that this
        # document does NOT claim, so a manifest cannot be mistaken for an enumeration of merged PRs.
        "generated": {
            "basis": MANIFEST_BASIS,
            "window": window,
            "source_records": sum(len(entry["records"]) for entry in entries.values()),
            "foreign_records": foreign,
            "targets_without_records": unbounded,
        },
        "targets": entries,
    }
    expected_records(json.dumps(document), targets)
    return document


def generate(policy_path, source_dir, window, audited_dir):
    """Derive the manifest for `policy_path`'s enabled targets from `source_dir`. READ-ONLY."""
    if is_same_directory(source_dir, audited_dir):
        raise AuditError(
            f"--from-records {str(source_dir)!r} is the corpus this audit reads "
            f"({str(audited_dir)!r}): a manifest derived from the corpus it bounds is complete by "
            "construction and asserts nothing — point it at an authoritative tree, such as a "
            "`ledger`-branch checkout of the provenance directory")
    grant_account = _load_sibling("grant-account.py", "registry_grant_account")
    pools = pools_by_target(_read(policy_path, "policy"), grant_account)
    return manifest_from_corpus(read_corpus(source_dir), sorted(pools), window)


def manifest_mode_error(generating, from_records, window, expected_path):
    """The refusal for an incoherent invocation, or None when the flags cohere.

    Generation and audit are separate runs over separate trees. A flag belonging to the other mode
    is REFUSED rather than ignored: an accepted-but-inert flag reads to its operator as though it
    took effect, and here that operator is deciding whether to revoke a live capability."""
    if generating:
        if expected_path:
            return ("--generate-manifest DERIVES a manifest and reads none, so --expected-records "
                    "cannot apply to it — run the audit separately against the generated file")
        missing = [flag for flag, value in (("--from-records", from_records), ("--window", window))
                   if not value]
        if missing:
            return (f"--generate-manifest requires {' and '.join(missing)}: a manifest with no "
                    "authoritative source, or with no stated observation window, bounds nothing")
        return None
    stray = [flag for flag, value in (("--from-records", from_records), ("--window", window))
             if value]
    if stray:
        return f"{' and '.join(stray)} only apply to --generate-manifest"
    return None


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


# The self-test's OWN copy of the generator's basis string, and of the window `_manifest` stamps.
# GEN_BASIS is deliberately a LITERAL rather than MANIFEST_BASIS: a fixture that reads the constant
# the reader compares against agrees with whatever value the module carries, so it could not see a
# basis drift at all (AGENTS.md 2c).
GEN_BASIS = "ledger-provenance-records"
WINDOW = "2026-07-01..2026-07-28"


def _block(source_records, window=WINDOW, basis=GEN_BASIS):
    """The generation-provenance block a manifest must carry to be READ at all."""
    return {"basis": basis, "window": window, "source_records": source_records}


def _manifest(rows, window=WINDOW, basis=GEN_BASIS, source_records=None, derived=True):
    """A completeness manifest naming, per target, the PR numbers that MUST be present.

    It carries the generation-provenance block by default because the reader accepts nothing else
    (#1027 review round 1). `derived=False` produces the LEGACY hand-typed shape — the document an
    operator transcribes — which every check below expects to be refused, never read."""
    document = {"targets": {target: {"window": window, "records": list(numbers)}
                            for target, numbers in rows.items()}}
    if derived:
        listed = sum(len(list(numbers)) for numbers in rows.values())
        document["generated"] = _block(listed if source_records is None else source_records,
                                       window=window, basis=basis)
    return json.dumps(document)


# The window the GENERATOR is asked to stamp. Deliberately not `_manifest`'s default: a check that
# the stated window is stamped verbatim proves nothing if the two literals collide.
GEN_WINDOW = "2026-07-29..2026-08-01"


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
        try:
            thunk()
        except AuditError as exc:
            print(f"ok   {label}")
            return str(exc)             # so a caller can pin WHICH guard refused, not merely that
        nonlocal ok                     # one did — layered guards mask each other otherwise
        ok = False
        print(f"FAIL {label}: no refusal")
        return ""

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
    complete = expected_records(_manifest({"o/a": [1, 2], "o/b": [3]}), ["o/a", "o/b"])
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
          {"window": "2026-07-01..2026-07-28", "expected_records": 2, "missing_records": 0,
           "complete": True})
    check("...and the window is surfaced to the reader of the text report",
          "completeness: VERIFIED — all 2 expected record(s) present for window "
          "2026-07-01..2026-07-28" in render(scoped), True)

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
    gapped = expected_records(_manifest({"o/a": [1, 2, 9], "o/b": [3]}), ["o/a", "o/b"])
    holey = audit(pools, evidence, foreign=foreign, salt=SALT, observed=observed, expected=gapped)
    check("a manifest with ONE expected record missing makes that row partial-evidence",
          holey["targets"]["o/a"]["status"], STATUS_PARTIAL)
    check("...and proposes nothing for it, while the row whose records are ALL present still does",
          (holey["targets"]["o/a"]["revocation_candidates"],
           holey["targets"]["o/b"]["revocation_candidates"]), ([], ["acct01", "acct02"]))
    check("...and the missing count and window are surfaced, not swallowed",
          holey["targets"]["o/a"]["evidence_bounds"],
          {"window": "2026-07-01..2026-07-28", "expected_records": 3, "missing_records": 1,
           "complete": False})
    check("...in the text report too",
          "completeness: NOT verified — 1 of 3 record(s) expected for window "
          "2026-07-01..2026-07-28 are absent" in render(holey), True)
    # A manifest is only a completeness signal if it is read exactly; every way of getting one
    # wrong refuses rather than licensing a revocation.
    refuses("a manifest that does not parse refuses",
            lambda: expected_records("{not json", ["o/a"]))
    refuses("a manifest with no `targets` object refuses",
            lambda: expected_records(json.dumps({"records": [1]}), ["o/a"]))
    refuses("a manifest naming an unaudited target refuses (a stale manifest bounds nothing)",
            lambda: expected_records(_manifest({"o/zz": [1]}), ["o/a"]))
    # These two carry a well-formed `generated` block on purpose: without one they would refuse at
    # the derivation gate above, and the entry grammar they exist to test would never be reached.
    refuses("a manifest entry that is not an object refuses",
            lambda: expected_records(json.dumps({"generated": _block(2),
                                                 "targets": {"o/a": [1, 2]}}), ["o/a"]))
    refuses("a manifest entry with no observation window refuses",
            lambda: expected_records(json.dumps({"generated": _block(1),
                                                 "targets": {"o/a": {"records": [1]}}}), ["o/a"]))
    refuses("a manifest entry with an empty window refuses",
            lambda: expected_records(json.dumps({"generated": _block(1),
                                                 "targets": {"o/a": {"window": "  ",
                                                                     "records": [1]}}}), ["o/a"]))
    refuses("a manifest entry expecting NO record refuses (it asserts nothing)",
            lambda: expected_records(_manifest({"o/a": []}), ["o/a"]))
    refuses("a manifest entry with a non-PR-number record refuses",
            lambda: expected_records(_manifest({"o/a": ["pr1"]}), ["o/a"]))
    refuses("a manifest entry with a duplicate PR number refuses",
            lambda: expected_records(_manifest({"o/a": [1, 1]}), ["o/a"]))
    refuses("an empty manifest refuses", lambda: expected_records(_manifest({}), ["o/a"]))
    check("a manifest number becomes THIS target's record filename, never another row's",
          sorted(expected_records(_manifest({"o/a": [1, 2]}), ["o/a", "o/b"])["o/a"]["records"]),
          ["o--a--pr1.json", "o--a--pr2.json"])

    # -- THE DERIVATION GATE (#1027 review round 1). The READER is the arm side: a generator the
    # reader treats as optional closes nothing, because the dangerous document is precisely the one
    # a human produced by hand. Every refusal below is a document that, if READ, would mark this
    # corpus `scoped` and name a live account for revocation.
    refuses("[#1027] a LEGACY hand-typed manifest — no `generated` block at all — is REFUSED, "
            "never read as advisory",
            lambda: expected_records(_manifest({"o/a": [1, 2], "o/b": [3]}, derived=False),
                                     ["o/a", "o/b"]))
    refuses("...and one asserting some other basis is refused: the block must be THIS generator's",
            lambda: expected_records(_manifest({"o/a": [1, 2]}, basis="transcribed-from-the-board"),
                                     ["o/a"]))
    refuses("...and one whose block asserts NO basis at all is refused: a block must say what "
            "derived it, not merely be present",
            lambda: expected_records(json.dumps(
                {"generated": {"window": WINDOW, "source_records": 2},
                 "targets": {"o/a": {"window": WINDOW, "records": [1, 2]}}}), ["o/a"]))
    # Pinned by MESSAGE, not merely by refusal: the entry/block window bind below would refuse this
    # document too (no entry can equal an absent window), so a refusal alone leaves this guard
    # individually unkillable — the masked-duplicate case AGENTS.md 4 names.
    windowless = refuses("...and one whose block states no derivation window is refused",
                         lambda: expected_records(json.dumps(
                             {"generated": {"basis": GEN_BASIS, "source_records": 2},
                              "targets": {"o/a": {"window": WINDOW, "records": [1, 2]}}}), ["o/a"]))
    check("...and it is the BLOCK's missing window that is named, not an entry mismatch",
          "`generated` block states no observation `window`" in (windowless or ""), True)
    refuses("...and one whose block states no source record count is refused",
            lambda: expected_records(json.dumps(
                {"generated": {"basis": GEN_BASIS, "window": WINDOW},
                 "targets": {"o/a": {"window": WINDOW, "records": [1, 2]}}}), ["o/a"]))
    refuses("...and a non-numeric count is refused rather than compared as a string",
            lambda: expected_records(_manifest({"o/a": [1, 2]}, source_records="2"), ["o/a"]))
    # A FLOAT count is the one non-int the comparison below CANNOT catch — `2 != 2.0` is False — so
    # it is what makes the type guard load-bearing rather than a duplicate of the count bind.
    refuses("...including a float count, which the count comparison alone would accept as equal",
            lambda: expected_records(_manifest({"o/a": [1, 2]}, source_records=2.0), ["o/a"]))
    refuses("...and an entry stating a window the manifest was NOT derived over refuses — the "
            "block is BOUND to the entries it describes, not merely present alongside them",
            lambda: expected_records(json.dumps(
                {"generated": _block(2, window=GEN_WINDOW),
                 "targets": {"o/a": {"window": WINDOW, "records": [1, 2]}}}), ["o/a"]))
    # THE TRANSCRIPTION SLIP ITSELF, now against a GENERATED artifact: delete one PR from an entry
    # and the count the block was derived from no longer covers what the document lists. This is
    # the realistic #1027 failure — an operator hand-editing an artifact — and it is what the
    # structural bind is for; `generation_provenance` states what it cannot do.
    refuses("[#1027] a generated manifest with a PR DELETED from an entry refuses: it lists 3 "
            "record(s) where the block it carries was derived from 4",
            lambda: expected_records(_manifest({"o/a": [1, 2], "o/b": [3]}, source_records=4),
                                     ["o/a", "o/b"]))
    refuses("...and one with a PR ADDED refuses on the same comparison — the count is matched "
            "EXACTLY, in both directions, never as a floor",
            lambda: expected_records(_manifest({"o/a": [1, 2, 9], "o/b": [3]}, source_records=3),
                                     ["o/a", "o/b"]))
    check("...while BOTH of those documents are accepted once their counts agree — the refusals "
          "above are about the BIND, not about the records they list",
          (sorted(expected_records(_manifest({"o/a": [1, 2], "o/b": [3]}, source_records=3),
                                   ["o/a", "o/b"])),
           sorted(expected_records(_manifest({"o/a": [1, 2, 9], "o/b": [3]}, source_records=4),
                                   ["o/a", "o/b"])["o/a"]["records"])),
          (["o/a", "o/b"], ["o--a--pr1.json", "o--a--pr2.json", "o--a--pr9.json"]))

    # -- MANIFEST GENERATION (#1027). The manifest was TYPED until now, and a typed manifest that
    # omits a PR fails OPEN: the short claim is satisfied by the very partial corpus it was meant
    # to bound. The reader now refuses a typed manifest outright (THE DERIVATION GATE above); this
    # is the path it leaves open. `ledger` is the authoritative tree — the audited `corpus` above,
    # plus PR 9, which is exactly the master/ledger split this module was written for (records have
    # gone to the `ledger` branch since #96).
    ledger = corpus + [("o--a--pr9.json", _record("acct03", 9))]
    generated = manifest_from_corpus(ledger, ["o/a", "o/b"], GEN_WINDOW)
    check("the manifest is DERIVED per target, as PR numbers, from the authoritative tree",
          generated["targets"],
          {"o/a": {"window": GEN_WINDOW, "records": [1, 2, 9]},
           "o/b": {"window": GEN_WINDOW, "records": [3]}})
    check("the stated window is stamped verbatim on every entry",
          sorted({entry["window"] for entry in generated["targets"].values()}), [GEN_WINDOW])
    # The basis is asserted against a LITERAL, never against MANIFEST_BASIS: comparing what the
    # module wrote to the constant it writes from is a tautology that cannot fail (AGENTS.md 2b).
    check("...and on the artifact's provenance block, with the basis it was derived from",
          (generated["generated"]["window"], generated["generated"]["basis"]),
          (GEN_WINDOW, "ledger-provenance-records"))
    check("a source record belonging to no audited target is counted, never listed as expected",
          (generated["generated"]["foreign_records"], generated["generated"]["source_records"]),
          (1, 4))
    check("the generated document is accepted by the audit's OWN reader, unchanged",
          sorted(expected_records(json.dumps(generated), ["o/a", "o/b"])["o/a"]["records"]),
          ["o--a--pr1.json", "o--a--pr2.json", "o--a--pr9.json"])
    # THE #1027 CLAIM ITSELF, both directions, over the SAME audited corpus, salt and pools —
    # only the manifest differs. `scoped` above is a manifest SHORT of PR 9: the gate refuses the
    # hand-typed and the edited forms of it (above), but a claim that is internally consistent is
    # still believed, and this is what believing a short one costs. That residue is why the source
    # of the claim — a derivation from an authoritative tree — is the actual fix, not the gate.
    from_generated = audit(pools, evidence, foreign=foreign, salt=SALT, observed=observed,
                           expected=expected_records(json.dumps(generated), ["o/a", "o/b"]))
    check("[#1027] a manifest SHORT of PR 9 declares this partial corpus complete and proposes "
          "acct03 — whose only record is the one it omits",
          (scoped["targets"]["o/a"]["status"], scoped["targets"]["o/a"]["revocation_candidates"]),
          (STATUS_SCOPED, ["acct03"]))
    check("[#1027] ...while the GENERATED manifest sees PR 9 absent from that corpus and proposes "
          "nothing",
          (from_generated["targets"]["o/a"]["status"],
           from_generated["targets"]["o/a"]["revocation_candidates"]), (STATUS_PARTIAL, []))
    check("...and the row the generated manifest DOES bound still proposes (not vacuous)",
          from_generated["targets"]["o/b"]["revocation_candidates"], ["acct01", "acct02"])
    # A target the source cannot bound is omitted and NAMED, never given an empty expectation:
    # an entry expecting no record is satisfied by any corpus at all.
    one_sided = manifest_from_corpus([("o--a--pr1.json", _record("acct01", 1))], ["o/a", "o/b"],
                                     GEN_WINDOW)
    # The foreign count is asserted here as well as above, on a source that has NONE: a single
    # fixture whose foreign count happens to be 1 is satisfied by a hard-coded 1 (AGENTS.md 4,
    # value-identical survivor — measured, not hypothetical).
    check("a target the source holds no record for is omitted, and the omission is stated",
          (sorted(one_sided["targets"]), one_sided["generated"]["targets_without_records"],
           one_sided["generated"]["foreign_records"], one_sided["generated"]["source_records"]),
          (["o/a"], ["o/b"], 0, 1))
    refuses("a source holding no record for ANY audited target generates nothing",
            lambda: manifest_from_corpus([("x--y--pr4.json", _record("acct01", 4))],
                                         ["o/a", "o/b"], GEN_WINDOW))
    refuses("a blank window refuses at generation (the round trip through the reader is live)",
            lambda: manifest_from_corpus(ledger, ["o/a", "o/b"], "   "))
    refuses("a source record whose name and content name different PRs refuses the generation, "
            "rather than expecting a number nothing in the source witnesses",
            lambda: manifest_from_corpus(corpus + [("o--a--pr9.json", _record("acct03", 8))],
                                         ["o/a", "o/b"], GEN_WINDOW))
    # The mode check refuses a flag belonging to the other mode instead of accepting it inert.
    check("a coherent generate invocation is not refused (the refusals below are not vacuous)",
          manifest_mode_error(True, "src", GEN_WINDOW, None), None)
    check("...nor is a coherent audit invocation carrying an --expected-records path",
          manifest_mode_error(False, None, None, "manifest.json"), None)

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
    retired_report = audit(pools, retired, salt=SALT,
                           observed={"o/a": {"o--a--pr1.json", "o--a--pr5.json"}},
                           expected=expected_records(_manifest({"o/a": [1, 5]}), ["o/a", "o/b"]))
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
        end_to_end = run(str(policy_path), str(prov), salt=SALT,
                         expected_path=str(manifest_path))
        check("the end-to-end run reproduces the per-target scoping",
              end_to_end["targets"]["o/a"]["revocation_candidates"], ["acct03"])
        check("a non-record file in the corpus directory is ignored",
              end_to_end["foreign_records"], 1)
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
        check("...and the SAME run without that one file scopes normally (the refusal is not "
              "vacuous)",
              run(str(policy_path), str(prov), salt=SALT,
                  expected_path=str(manifest_path))["targets"]["o/a"]["revocation_candidates"],
              ["acct03"])

        refuses("a missing provenance directory refuses",
                lambda: run(str(policy_path), str(root / "nope"), salt=SALT))
        refuses("an unreadable policy refuses (rather than a traceback)",
                lambda: run(str(root / "nope.toml"), str(prov), salt=SALT))
        refuses("an unreadable expected-records manifest refuses",
                lambda: run(str(policy_path), str(prov), salt=SALT,
                            expected_path=str(root / "nope.json")))

        # -- #1027 OVER REAL DIRECTORIES. A manifest bounds a corpus only when it was derived from
        # a DIFFERENT tree, so the source/corpus identity check is exercised against real paths.
        ledger_dir = root / "ledger-provenance"
        ledger_dir.mkdir()
        for name, text in ledger:
            (ledger_dir / name).write_text(text, encoding="utf-8")
        ledger_before = {path.name: path.read_bytes() for path in sorted(ledger_dir.iterdir())}
        check("two independent trees are not the same directory",
              is_same_directory(str(ledger_dir), str(prov)), False)
        corpus_link = root / "corpus-link"
        corpus_link.symlink_to(prov, target_is_directory=True)
        check("...but a symlink to the audited corpus IS it, however it is spelled",
              is_same_directory(str(corpus_link), str(prov)), True)
        refuses("generating FROM the audited corpus refuses rather than emitting a tautology",
                lambda: generate(str(policy_path), str(prov), GEN_WINDOW, str(prov)))
        refuses("...and a symlink to it does not launder that",
                lambda: generate(str(policy_path), str(corpus_link), GEN_WINDOW, str(prov)))
        check("...while an independent tree generates normally (the refusals are not vacuous)",
              generate(str(policy_path), str(ledger_dir), GEN_WINDOW,
                       str(prov))["targets"]["o/a"]["records"], [1, 2, 9])
        refuses("a missing source tree refuses instead of generating an empty manifest",
                lambda: generate(str(policy_path), str(root / "no-ledger"), GEN_WINDOW, str(prov)))
        check("generation is READ-ONLY (the authoritative tree is byte-identical afterwards)",
              {path.name: path.read_bytes() for path in sorted(ledger_dir.iterdir())},
              ledger_before)

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

        # -- #1027 AT THE CLI SEAM, end to end: generate the artifact, then AUDIT with the exact
        # bytes that were generated. The salt sits in the environment throughout, and generation
        # must neither need it nor leak through it.
        gen_base = ["--policy", str(policy_path), "--provenance-dir", str(prov)]
        status, gen_out, err = _cli(
            gen_base + ["--generate-manifest", "--from-records", str(ledger_dir),
                        "--window", GEN_WINDOW], env={_SELFTEST_SALT_ENV: SALT})
        try:                        # a FAILING parse must red this row, not abort the suite
            gen_doc = json.loads(gen_out)
        except ValueError:
            gen_doc = None
        check("--generate-manifest prints a parseable manifest, exit 0, nothing on stderr",
              (status, gen_doc and gen_doc["targets"]["o/a"]["records"], err), (0, [1, 2, 9], ""))
        check("...and the generated artifact carries no account fingerprint",
              sorted(value for value in _H.values() if value in gen_out), [])
        generated_path = root / "generated.json"
        generated_path.write_text(gen_out, encoding="utf-8")
        status, out, _ = _cli(gen_base + ["--expected-records", str(generated_path),
                                          "--salt-env", _SELFTEST_SALT_ENV],
                              env={_SELFTEST_SALT_ENV: SALT})
        check("the generated file drives a REAL audit: o/a is partial (PR 9 is absent here) and "
              "proposes nothing, while the bounded row still does",
              (status, f"o/a [{STATUS_PARTIAL}]" in out,
               "    revocation CANDIDATES (2): acct01, acct02" in out,
               "revocation CANDIDATES (1): acct03" in out), (0, True, True, False))
        # THE ARM-SIDE NEGATIVE (#1027 review round 1), end to end. The short HAND-TYPED manifest —
        # the shape an operator transcribes, and the shape `--expected-records` accepted before
        # derivation was required — must reach no conclusion at all. The positive control is three
        # checks up: the DERIVED manifest at `manifest_path`, over this same corpus and salt, prints
        # "revocation CANDIDATES (1): acct03", so this refusal is about provenance, not about a
        # document the audit could not have used.
        legacy_path = root / "hand-typed.json"
        legacy_path.write_text(_manifest({"o/a": [1, 2], "o/b": [3]}, derived=False),
                               encoding="utf-8")
        status, out, err = _cli(gen_base + ["--expected-records", str(legacy_path),
                                            "--salt-env", _SELFTEST_SALT_ENV],
                                env={_SELFTEST_SALT_ENV: SALT})
        check("[#1027] a hand-typed manifest exits 2 at the CLI and prints NO report: no scoped "
              "row, no revocation candidate, no handle named",
              (status, out, STATUS_SCOPED in out, "revocation CANDIDATES" in out,
               "acct03" in out, "`generated` block" in err),
              (2, "", False, False, False, True))
        status, out, err = _cli(gen_base + ["--generate-manifest", "--from-records", str(prov),
                                            "--window", GEN_WINDOW])
        check("at the CLI, generating from the audited corpus exits 2 and emits no manifest",
              (status, "asserts nothing" in err, out), (2, True, ""))
        # Every branch of manifest_mode_error, at the seam. An accepted-but-inert flag reads to its
        # operator as though it took effect, and the operator here is deciding a revocation.
        for named, flags in (
                ("--from-records", ["--generate-manifest", "--window", GEN_WINDOW]),
                ("--window", ["--generate-manifest", "--from-records", str(ledger_dir)]),
                ("--expected-records", ["--generate-manifest", "--from-records", str(ledger_dir),
                                        "--window", GEN_WINDOW,
                                        "--expected-records", str(manifest_path)]),
                ("--from-records", ["--from-records", str(ledger_dir)]),
                ("--window", ["--window", GEN_WINDOW])):
            try:
                status, out, err = _cli(gen_base + flags)
            except Exception as exc:    # noqa: BLE001 — ANY escape from main() is the defect here
                # Without the mode check these argv reach `generate` with a None path and raise a
                # TypeError that ABORTS the suite: a mutant would then record as a crash with 7
                # checks never run, instead of as a red row (AGENTS.md 4, crash-after-partial-run).
                status, out, err = repr(exc), "", ""
            check(f"an incoherent invocation is refused by name ({named}, {len(flags)} flag words),"
                  " exits 2, prints no document",
                  (status, named in err, out), (2, True, ""))

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
        help=("path to the durable expected-record manifest that bounds the corpus. It must be a "
              "--generate-manifest artifact: a manifest carrying no `generated` provenance block, "
              "or one whose entries no longer agree with it, is REFUSED rather than believed. "
              "Without it, or with any expected record absent, the row is partial-evidence and no "
              "revocation candidate is proposed — a corpus not known to be complete cannot show "
              "disuse."))
    parser.add_argument(
        "--generate-manifest", action="store_true",
        help=("derive an --expected-records manifest from an authoritative record tree and print "
              "it to stdout for the maintainer to review; changes nothing. Requires "
              "--from-records and --window."))
    parser.add_argument(
        "--from-records", default=None,
        help=("with --generate-manifest: the authoritative provenance tree to derive from, e.g. a "
              "`ledger`-branch checkout of " + DEFAULT_PROVENANCE_DIR + ". It must NOT be the "
              "corpus the audit reads, which a manifest cannot bound."))
    parser.add_argument(
        "--window", default=None,
        help=("with --generate-manifest: the observation window the source tree covers, stamped "
              "verbatim into every entry. Required — an unbounded completeness claim is refused."))
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    # Generation runs BEFORE the salt is looked at: it derives PR numbers and target names only, so
    # it has no use for an account salt and must never be a reason to put one in the environment.
    mode_error = manifest_mode_error(args.generate_manifest, args.from_records, args.window,
                                     args.expected_records)
    if mode_error:
        sys.stderr.write(f"grant-scope-audit: {mode_error}\n")
        return 2
    if args.generate_manifest:
        try:
            document = generate(args.policy, args.from_records, args.window, args.provenance_dir)
        except AuditError as exc:
            sys.stderr.write(f"grant-scope-audit: {exc}\n")
            return 2
        print(json.dumps(document, indent=1, sort_keys=True))
        return 0
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
