#!/usr/bin/env python3
"""ledger-history-purge — verify, and locally rewrite, published ledger history that still
carries RAW account handles (issue #536; the code-side stop-the-bleeding fix was #212).

Locked decision 22 says no raw account handle appears on this repo's public surface. #212 made
every FUTURE ledger write conform: `select-and-claim.py` stores the salted 16-hex fingerprint in
each lease's ``account`` and its commit subject is `claim <cid8> <package>/<role>`. It could not
touch what is ALREADY published — the `ledger` branch's commit graph still contains, verbatim:

  * legacy claim subjects of the shape `claim <cid8> <handle> <package>/<role>`, and
  * `data/leases.json` snapshots whose lease rows carry the handle where the fingerprint belongs.

Purging those requires a force-update of a published ref, which is a MAINTAINER action inside a
maintenance window. This module is the part that can be automated safely, and it is deliberately
INERT with respect to the remote:

  * it needs no GitHub token and never invokes `gh` — every subcommand is local git plumbing;
  * `rewrite` writes ONE local ref (and git's own `refs/original/` backup) and refuses any ref
    that does not RESOLVE to a `refs/heads/` branch, so it cannot be pointed at anything it
    could publish;
  * pushing the rewritten ref stays a human step. See README § "Purging raw handles from
    published ledger history" for the ordered runbook (quiesce writers → rewrite → verify →
    force-with-lease → resume writers).

FAIL-CLOSED POSTURE. `scan` is the verification gate the operator runs before AND after the
force-update, so every ambiguity is an exposure or an error, never a pass: a snapshot that does
not parse as `{"leases": [...]}`, a ref that resolves to no commits, or any git failure exits
non-zero. `rewrite` re-scans the ref it just wrote and fails if anything survived. And a lease row
whose ``account`` is not EXACTLY 16 lowercase hex characters is treated as an exposed identity —
the same shape `groom.validate_ledger` and `select-and-claim.validate_lease_account_identities`
drop at read time, so the three agree on what "already fingerprinted" means.

PRIVACY OF THE TOOL'S OWN OUTPUT. A verifier that printed the handle it found would republish it
into a public Actions log. Every report here is counts plus commit/blob SHAs; handles are never
echoed, including the ones read from `--handles-file`.
"""

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

LEDGER_PATH = "data/leases.json"

# The canonical public account identity: sha256(handle:PROVENANCE_SALT)[:16], lowercase hex.
# Kept deliberately identical to `groom.SAFE_ACCOUNT_HASH` and
# `select-and-claim.ACCOUNT_FINGERPRINT_RE` — anything else in an `account` field is a legacy raw
# identity. Matched with fullmatch(): a 17-hex or mixed-case value is NOT canonical.
ACCOUNT_FINGERPRINT_RE = re.compile(r"[0-9a-f]{16}")

# The pre-#212 claim subject: `claim <cid8> <handle> <package>/<role>`. The third token is
# constrained to carry NO slash and the fourth to carry one, which is what distinguishes this from
# the canonical `claim <cid8> <package>/<role>` (three tokens, no handle) without having to guess
# whether a token is a handle or a package.
LEGACY_CLAIM_SUBJECT_RE = re.compile(
    r"^claim (?P<claim>[0-9a-f]{8}) (?P<handle>[^ /]+) (?P<target>[^ ]+/[^ ]+)$")

# A commit SHA as `git log --format=%H` prints it: 40 hex (SHA-1) or 64 (SHA-256). The bulk read
# below validates every record against this rather than trusting its own framing.
COMMIT_SHA_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


class PurgeError(Exception):
    """Any condition under which this tool refuses to report success."""


# ---- pure transforms -----------------------------------------------------------------------


def sanitize_subject(subject):
    """Rewrite ONE legacy claim subject to the canonical handle-free form.

    Every other message line — including an already-canonical `claim`, a `release`, an `adopt`,
    or a `model-health record` subject — is returned unchanged. Returning the input verbatim is
    the safe default here: this filter's job is to remove a handle, not to normalize history.
    """
    match = LEGACY_CLAIM_SUBJECT_RE.match(subject)
    if match is None:
        return subject
    return f"claim {match.group('claim')} {match.group('target')}"


def sanitize_message(message):
    """Apply `sanitize_subject` to every line of a commit message."""
    return "".join(sanitize_subject(line.rstrip("\n")) + line[len(line.rstrip("\n")):]
                   for line in message.splitlines(keepends=True))


def raw_identity_rows(document):
    """Return the lease rows of a parsed snapshot whose ``account`` is not the canonical
    fingerprint. Raises PurgeError when the snapshot is not a ledger document at all — an
    unreadable snapshot is never silently treated as clean (or as empty)."""
    if not isinstance(document, dict):
        raise PurgeError("ledger snapshot is not a JSON object")
    leases = document.get("leases")
    if not isinstance(leases, list) or any(not isinstance(row, dict) for row in leases):
        raise PurgeError("ledger snapshot has no `leases` list of objects")
    return [row for row in leases
            if not isinstance(row.get("account"), str)
            or ACCOUNT_FINGERPRINT_RE.fullmatch(row["account"]) is None]


def sanitize_snapshot(blob):
    """Rewrite one `data/leases.json` blob to a hash-only snapshot.

    Rows carrying a raw identity are DROPPED — a snapshot whose rows were all raw becomes the
    empty snapshot — and every other key of the document is preserved. Returns
    ``(new_bytes, dropped_count)``; ``dropped_count == 0`` means the caller must leave the blob
    byte-for-byte alone rather than re-serialize a clean snapshot into a gratuitously new object.

    Serialization matches `select-and-claim._write_ledger` (``json.dumps(..., indent=1)``, no
    trailing newline) so a rewritten snapshot is byte-identical to what the live writer would have
    produced for the same rows.
    """
    try:
        document = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise PurgeError(f"ledger snapshot does not parse as JSON: {exc}") from exc
    exposed = raw_identity_rows(document)
    if not exposed:
        return blob, 0
    document["leases"] = [row for row in document["leases"] if row not in exposed]
    return json.dumps(document, indent=1).encode("utf-8"), len(exposed)


# ---- git plumbing --------------------------------------------------------------------------


def _git(args, repo=None, stdin=None, check=True):
    """Run one git command and return its stdout as bytes. No `gh`, no network."""
    argv = ["git"] + (["-C", str(repo)] if repo is not None else []) + list(args)
    try:
        result = subprocess.run(argv, input=stdin, capture_output=True)
    except OSError as exc:
        raise PurgeError(f"cannot run git: {exc}") from exc
    if check and result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise PurgeError(f"`git {' '.join(args[:2])}` failed: {detail or 'unknown error'}")
    return result.stdout


def _commit_messages(repo, ref):
    """Return ``[(commit_sha, message), ...]`` for every commit reachable from `ref`.

    Framed with NUL (`git log -z`), which is the ONE byte a commit message cannot contain. Control
    characters are ordinary DATA in a message: framing records on, say, \\x01 lets a crafted
    message split itself into a second pseudo-record whose text lands in the `sha` field — and
    neither the legacy-subject walk nor the literal handle count ever reads that field, so the ref
    reports clean while the handle is still published. Inside a record the SHA is newline-
    terminated, and a SHA contains no newline. Every record is validated against
    `COMMIT_SHA_RE`, so a framing surprise REFUSES instead of being parsed into a false clean.
    """
    raw = _git(["log", "-z", "--format=%H%n%B", ref], repo=repo)
    records = []
    for chunk in raw.split(b"\x00"):
        if not chunk:
            continue
        sha, newline, message = chunk.partition(b"\n")
        sha = sha.decode("utf-8", "replace")
        if not newline or COMMIT_SHA_RE.fullmatch(sha) is None:
            raise PurgeError(f"`git log` record does not begin with a commit SHA ({sha[:16]!r}) — "
                             "refusing to parse it")
        records.append((sha, message.decode("utf-8", "replace")))
    if not records:
        raise PurgeError(f"ref {ref!r} resolves to no commits — refusing to report it clean")
    return records


def _snapshot_blobs(repo, commits):
    """Map each commit to the blob SHA of its `data/leases.json`, then read each DISTINCT blob
    once. Returns ``(blob_bytes_by_sha, example_commit_by_sha)``."""
    probe = "".join(f"{sha}:{LEDGER_PATH}\n" for sha in commits).encode("utf-8")
    listing = _git(["cat-file", "--batch-check"], repo=repo, stdin=probe).decode("utf-8", "replace")
    lines = listing.splitlines()
    # One answer per probe, or the zip below would silently truncate and report the commits it
    # never looked at as clean.
    if len(lines) != len(commits):
        raise PurgeError(f"cat-file answered {len(lines)} of {len(commits)} ledger snapshot "
                         "probes — refusing to report a partial walk")
    example = {}
    for line, commit in zip(lines, commits):
        fields = line.split()
        if len(fields) == 3 and fields[1] == "blob":
            example.setdefault(fields[0], commit)
        elif not line.endswith(" missing"):
            raise PurgeError(f"unreadable ledger snapshot at {commit}: {line}")
    if not example:
        return {}, {}
    contents = {}
    stream = _git(["cat-file", "--batch"], repo=repo,
                  stdin="".join(f"{sha}\n" for sha in example).encode("utf-8"))
    offset = 0
    while offset < len(stream):
        end = stream.index(b"\n", offset)
        header = stream[offset:end].decode("utf-8", "replace").split()
        offset = end + 1
        if len(header) != 3:
            raise PurgeError(f"unreadable ledger blob: {' '.join(header)}")
        size = int(header[2])
        contents[header[0]] = stream[offset:offset + size]
        offset += size + 1
    return contents, example


# ---- scan (the verification gate) ------------------------------------------------------------


def scan(repo, ref, handles=()):
    """Walk every commit reachable from `ref` and report the raw identities still published.

    Returns a report dict. Handles are counted, never named: `handle_hits` aggregates literal
    occurrences of the operator-supplied handles across ALL of them, so the report is safe to
    paste anywhere the branch itself is visible.
    """
    messages = _commit_messages(repo, ref)
    commits = [sha for sha, _ in messages]
    blobs, example = _snapshot_blobs(repo, commits)

    legacy_subjects = [sha for sha, message in messages
                       if any(LEGACY_CLAIM_SUBJECT_RE.match(line)
                              for line in message.splitlines())]
    exposed_rows = 0
    exposed_blobs = []
    for blob_sha, blob in blobs.items():
        try:
            document = json.loads(blob.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise PurgeError(
                f"ledger snapshot {blob_sha} (e.g. commit {example[blob_sha]}) does not parse: "
                f"{exc}") from exc
        rows = raw_identity_rows(document)
        if rows:
            exposed_rows += len(rows)
            exposed_blobs.append(blob_sha)

    needles = [handle.encode("utf-8") for handle in handles]
    handle_hits = 0
    if needles:
        for _sha, message in messages:
            encoded = message.encode("utf-8")
            handle_hits += sum(encoded.count(needle) for needle in needles)
        for blob in blobs.values():
            handle_hits += sum(blob.count(needle) for needle in needles)

    return {
        "ref": ref,
        "commits": len(commits),
        "snapshots": len(blobs),
        "legacy_subjects": legacy_subjects,
        "exposed_blobs": exposed_blobs,
        "exposed_rows": exposed_rows,
        "handle_hits": handle_hits,
        "handles_checked": len(needles),
    }


def report_exposures(report):
    """Total exposures. Zero — and only zero — means the ref is publishable."""
    return (len(report["legacy_subjects"]) + report["exposed_rows"] + report["handle_hits"])


def print_report(report, stream=None):
    # Resolved at CALL time, never bound as a default: a `sys.stdout` default argument is fixed at
    # definition and would escape any redirection the caller installs.
    stream = sys.stdout if stream is None else stream
    print(f"ledger-history-purge scan: ref {report['ref']}", file=stream)
    print(f"  commits examined:              {report['commits']}", file=stream)
    print(f"  distinct leases.json snapshots: {report['snapshots']}", file=stream)
    print(f"  legacy claim subjects:         {len(report['legacy_subjects'])}", file=stream)
    print(f"  raw-identity lease rows:       {report['exposed_rows']} "
          f"in {len(report['exposed_blobs'])} snapshots", file=stream)
    if report["handles_checked"]:
        print(f"  literal handle occurrences:    {report['handle_hits']} "
              f"({report['handles_checked']} handles checked)", file=stream)
    for sha in report["legacy_subjects"][:10]:
        print(f"    exposed commit subject: {sha}", file=stream)
    for sha in report["exposed_blobs"][:10]:
        print(f"    exposed snapshot blob:  {sha}", file=stream)


def _read_handles(path):
    """One handle per line; blanks and `#` comments ignored. Never echoed back."""
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise PurgeError(f"cannot read handles file: {exc}") from exc
    handles = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
    if not handles:
        raise PurgeError("handles file is empty — refusing to run a vacuous literal check")
    return handles


# ---- filters (invoked BY git filter-branch, once per commit) ---------------------------------


def cmd_index_filter():
    """`--index-filter` body: sanitize `data/leases.json` in the temporary index in place.

    Reads GIT_DIR/GIT_INDEX_FILE from the environment git filter-branch sets, so it must not
    depend on the working directory (filter-branch runs filters from an empty scratch tree).
    """
    listing = _git(["ls-files", "-s", "--", LEDGER_PATH]).decode("utf-8", "replace").strip()
    if not listing:
        return 0  # this commit has no ledger snapshot; nothing to purge
    meta, _, path = listing.partition("\t")
    mode, blob_sha, _stage = meta.split()
    if path != LEDGER_PATH:
        raise PurgeError(f"unexpected index entry {path!r}")
    blob = _git(["cat-file", "blob", blob_sha])
    new_blob, _dropped = sanitize_snapshot(blob)
    # No "skip when nothing was dropped" branch here. `sanitize_snapshot` already owns that rule
    # and returns a clean snapshot byte-identical, so re-hashing one yields the SAME object id and
    # this re-stage is a no-op. A second copy of the rule would only make each copy individually
    # unkillable (AGENTS.md § AUTHOR pre-flight, item 4) — one definition, no duplicate.
    new_sha = _git(["hash-object", "-w", "--stdin"], stdin=new_blob).decode().strip()
    _git(["update-index", "--cacheinfo", f"{mode},{new_sha},{LEDGER_PATH}"])
    return 0


def cmd_msg_filter():
    """`--msg-filter` body: stdin message → sanitized message on stdout."""
    message = sys.stdin.buffer.read().decode("utf-8", "surrogateescape")
    sys.stdout.buffer.write(sanitize_message(message).encode("utf-8", "surrogateescape"))
    return 0


# ---- rewrite (LOCAL refs only) ---------------------------------------------------------------


def resolve_local_branch(repo, ref):
    """Resolve `ref` to the ONE full ref name, and refuse anything outside `refs/heads/`.

    Resolution comes FIRST because `git filter-branch` acts on the RESOLVED ref, not on the
    spelling the operator typed: `origin/ledger` — the very spelling the README uses for scans —
    resolves to `refs/remotes/origin/ledger`, and filter-branch rewrites it happily. A guard that
    only pattern-matched the argument would therefore wave through exactly the ref it promises to
    refuse. An argument that names no ref at all (a bare SHA, `HEAD@{1}`) resolves to nothing and
    is refused too; an unknown revision makes `rev-parse` exit non-zero, which `_git` raises.
    """
    names = _git(["rev-parse", "--symbolic-full-name", ref], repo=repo).decode(
        "utf-8", "replace").split()
    if len(names) != 1 or not names[0].startswith("refs/"):
        raise PurgeError(f"{ref!r} does not name exactly one ref (git resolved {len(names)}) — "
                         "rewrite needs an unambiguous local branch")
    if not names[0].startswith("refs/heads/"):
        raise PurgeError(f"refusing to rewrite {ref!r}: it resolves to {names[0]}, which is "
                         "not a local branch under refs/heads/ — rewrite a local branch and let "
                         "a human force-update the remote")
    return names[0]


def rewrite(repo, ref, stream=None, verify=None):
    """Rewrite `ref` in place with git filter-branch, then VERIFY the result.

    `verify` is the post-rewrite scanner and is injectable for the self-test ONLY; production
    callers leave it None and get `scan`.

    Local only, and fail-closed at three points: the ref is resolved and refused unless it is a
    local branch, before anything runs (this tool must never be aimable at a ref that could be
    pushed by rewriting it); an existing `refs/original/` is refused rather than silently
    clobbering the one backup of the pre-purge history; and the post-rewrite scan must come back
    with zero exposures.
    """
    stream = sys.stdout if stream is None else stream
    # Every operation below uses the RESOLVED name, so what was guarded is what git acts on.
    ref = resolve_local_branch(repo, ref)
    existing = _git(["for-each-ref", "--format=%(refname)", "refs/original/"], repo=repo)
    if existing.strip():
        raise PurgeError("refs/original/ already exists — a previous rewrite's backup is still "
                         "there; inspect it and remove it deliberately before rewriting again")
    before = scan(repo, ref)
    print(f"ledger-history-purge rewrite: {before['commits']} commits, "
          f"{report_exposures(before)} exposures to purge", file=stream)

    script = str(Path(__file__).resolve())
    filter_cmd = f"{shlex.quote(sys.executable)} {shlex.quote(script)}"
    env = dict(os.environ, FILTER_BRANCH_SQUELCH_WARNING="1")
    # No --prune-empty: a claim commit whose only row was a raw identity sanitizes to a no-op
    # tree change, and keeping that commit preserves the timeline (the handle is gone; the fact
    # that a claim happened is not a secret) instead of silently shortening published history.
    argv = ["git", "-C", str(repo), "filter-branch",
            "--index-filter", f"{filter_cmd} index-filter",
            "--msg-filter", f"{filter_cmd} msg-filter",
            "--", ref]
    result = subprocess.run(argv, capture_output=True, env=env)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise PurgeError(f"git filter-branch failed (history left untouched at "
                         f"refs/original/): {detail or 'unknown error'}")

    after = (verify or scan)(repo, ref)
    if report_exposures(after) != 0:
        raise PurgeError(f"rewrite completed but {report_exposures(after)} exposures REMAIN on "
                         f"{ref} — do NOT force-update the remote")
    print_report(after, stream=stream)
    print(f"ledger-history-purge rewrite: {ref} is clean "
          f"({after['commits']} commits); original preserved under refs/original/", file=stream)
    return after


# ---- CLI ---------------------------------------------------------------------------------------


def _build_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    sub = parser.add_subparsers(dest="command")
    for name in ("scan", "rewrite"):
        child = sub.add_parser(name)
        child.add_argument("--repo", default=".", help="path to a LOCAL ledger clone")
        child.add_argument("--ref", default="ledger", help="the ledger ref to inspect/rewrite")
        if name == "scan":
            child.add_argument("--handles-file",
                               help="optional file of known handles, one per line, for a literal "
                                    "belt-and-braces check; contents are never printed")
    sub.add_parser("index-filter")
    sub.add_parser("msg-filter")
    return parser


def main(argv=None):
    args = _build_parser().parse_args(argv)
    if args.self_test:
        return _self_test()
    try:
        if args.command == "scan":
            handles = _read_handles(args.handles_file) if args.handles_file else ()
            report = scan(args.repo, args.ref, handles)
            print_report(report)
            exposures = report_exposures(report)
            if exposures:
                print(f"ledger-history-purge: {exposures} exposures remain on {args.ref}",
                      file=sys.stderr)
                return 1
            print(f"ledger-history-purge: {args.ref} carries no raw account identity")
            return 0
        if args.command == "rewrite":
            rewrite(args.repo, args.ref)
            return 0
        if args.command == "index-filter":
            return cmd_index_filter()
        if args.command == "msg-filter":
            return cmd_msg_filter()
    except PurgeError as exc:
        print(f"ledger-history-purge: {exc}", file=sys.stderr)
        return 2
    _build_parser().print_usage(sys.stderr)
    return 2


# ---- self-test ---------------------------------------------------------------------------------


def _fixture_repo(root, snapshots):
    """Build a real single-branch git repo whose commits are `(message, snapshot_or_None)`."""
    repo = Path(root)
    _git(["init", "-q", str(repo)])
    _git(["symbolic-ref", "HEAD", "refs/heads/ledger"], repo=repo)
    (repo / "data").mkdir(exist_ok=True)
    for message, snapshot in snapshots:
        if snapshot is not None:
            (repo / LEDGER_PATH).write_bytes(snapshot)
        _git(["add", "-A"], repo=repo)
        _git(["-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
              "commit", "-q", "--allow-empty", "-m", message], repo=repo)
    return repo


def _subjects(repo, ref):
    return _git(["log", "--format=%s", ref], repo=repo).decode().splitlines()


def _self_test():
    """Offline suite. No `gh`, no network, no token: real git repos in a temp dir, driven through
    the same entry points an operator types.

    DECLARED UNEXECUTED LINES (measured with `python3 -m trace --count --missing`, whose marker
    was validated against a function known not to run — the default `--count` output marks nothing
    and would have reported a clean sheet). Five lines are contract assertions on git's own output
    and cannot be reached while git honours it: the empty-`git log` refusal (a bad ref exits
    non-zero first), the `git log -z` record that does not begin with a SHA, the malformed
    `cat-file --batch` header, the truncated `--batch-check` answer, and the ls-files entry naming
    a path other than the pathspec it was given. Plus the `__main__` non-self-test dispatch,
    unreachable from inside a self-test by construction. Every other line executes here.
    """
    import io
    import contextlib

    checks = []

    def check(name, got, want):
        checks.append((name, got, want))

    FP_A = "0123456789abcdef"          # canonical fingerprints, chosen to appear nowhere else
    FP_B = "fedcba9876543210"
    raw_row = {"account": "acct01", "claim_id": "a" * 32, "package": "bench", "role": "impl"}
    good_row = {"account": FP_A, "claim_id": "b" * 32, "package": "bench", "role": "impl"}
    other_row = {"account": FP_B, "claim_id": "c" * 32, "package": "ci", "role": "fix"}

    # ---- sanitize_subject: expected values written LITERALLY here, never re-derived from the
    # regex under test, so a widened/narrowed pattern cannot make its own assertion true. -------
    check("legacy claim subject loses exactly the handle token",
          sanitize_subject("claim 0123abcd acct01 bench/impl"), "claim 0123abcd bench/impl")
    check("legacy subject with a dotted handle is rewritten",
          sanitize_subject("claim 89abcdef acct2.css set-up-account/review"),
          "claim 89abcdef set-up-account/review")
    check("already-canonical claim subject is untouched",
          sanitize_subject("claim 0123abcd bench/impl"), "claim 0123abcd bench/impl")
    check("release subject is untouched", sanitize_subject("release 47f4b2e0"), "release 47f4b2e0")
    check("adopt subject is untouched",
          sanitize_subject("adopt a89de32a -> worker run"), "adopt a89de32a -> worker run")
    check("model-health subject is untouched",
          sanitize_subject("model-health record (openai/no_change)"),
          "model-health record (openai/no_change)")
    # Over-match guards: a slashed third token is a package, not a handle, and a trailing token
    # means this is not the legacy shape at all. Dropping either constraint mangles real history.
    check("a slashed third token is not treated as a handle",
          sanitize_subject("claim 0123abcd a/b c/d"), "claim 0123abcd a/b c/d")
    check("a five-token claim subject is untouched",
          sanitize_subject("claim 0123abcd acct01 bench/impl extra"),
          "claim 0123abcd acct01 bench/impl extra")
    check("a non-hex claim id is not the legacy shape",
          sanitize_subject("claim zzzzzzzz acct01 bench/impl"),
          "claim zzzzzzzz acct01 bench/impl")
    check("multi-line message sanitizes the subject and preserves the body",
          sanitize_message("claim 0123abcd acct01 bench/impl\n\nbody line\n"),
          "claim 0123abcd bench/impl\n\nbody line\n")

    # ---- sanitize_snapshot ------------------------------------------------------------------
    mixed = json.dumps({"leases": [raw_row, good_row]}, indent=1).encode()
    purged, dropped = sanitize_snapshot(mixed)
    check("raw row dropped, canonical row survives",
          (json.loads(purged.decode()), dropped), ({"leases": [good_row]}, 1))
    check("purged snapshot matches the live writer's serialization",
          purged, json.dumps({"leases": [good_row]}, indent=1).encode())
    all_raw = json.dumps({"leases": [raw_row, dict(raw_row, account="acct2css")]}, indent=1)
    check("an all-raw snapshot becomes the EMPTY snapshot",
          sanitize_snapshot(all_raw.encode()), (b'{\n "leases": []\n}', 2))
    clean = json.dumps({"leases": [good_row, other_row]}, indent=1).encode()
    check("a clean snapshot is returned byte-identical with zero drops",
          sanitize_snapshot(clean), (clean, 0))
    # Deliberately NOT this module's own serialization: a fixture written with `indent=1` is
    # byte-identical to what a re-serializing implementation would emit, so it cannot tell "left
    # alone" from "rewritten to the same bytes". A clean snapshot must be left ALONE, whatever
    # formatting the historical writer used.
    clean_other_format = (json.dumps({"leases": [good_row, other_row]}) + "\n").encode()
    check("a differently-formatted clean snapshot is not re-serialized",
          sanitize_snapshot(clean_other_format), (clean_other_format, 0))
    check("unrelated top-level keys are preserved through a purge",
          json.loads(sanitize_snapshot(
              json.dumps({"leases": [raw_row], "note": "keep"}).encode())[0].decode()),
          {"leases": [], "note": "keep"})
    # Fingerprint shape is EXACT: fullmatch, lowercase, exactly 16. Each of these is a distinct
    # one-character weakening of ACCOUNT_FINGERPRINT_RE.
    for label, account in (("uppercase", FP_A.upper()), ("17 hex", FP_A + "0"),
                           ("15 hex", FP_A[:-1]), ("hex with a suffix", FP_A + "-acct01"),
                           ("non-hex", "g" * 16)):
        check(f"an account of {label} is treated as a raw identity",
              sanitize_snapshot(json.dumps({"leases": [dict(raw_row, account=account)]})
                                .encode())[1], 1)
    check("a non-string account is treated as a raw identity",
          sanitize_snapshot(json.dumps({"leases": [dict(raw_row, account=None)]}).encode())[1], 1)

    def _refusal(thunk):
        """The refusal MESSAGE, or None if the call returned. Which guard fired matters: several
        of the refusals below are also produced — for a different reason, at a different point —
        by git itself, so a bare did-it-raise probe cannot tell the guard from its backstop."""
        try:
            thunk()
        except PurgeError as exc:
            return str(exc)
        return None

    def _raises(thunk):
        return _refusal(thunk) is not None

    # Positive control for the probe itself: a probe that reports True unconditionally would make
    # every fail-closed assertion below pass without the guard existing.
    check("the _raises probe reports a non-raising thunk", _raises(lambda: None), False)

    check("an unparseable snapshot fails closed (never 'clean', never 'empty')",
          _raises(lambda: sanitize_snapshot(b"not json")), True)
    check("a snapshot that is not an object fails closed",
          _raises(lambda: sanitize_snapshot(b"[]")), True)
    check("a snapshot with no leases list fails closed",
          _raises(lambda: sanitize_snapshot(b'{"leases": {}}')), True)
    check("a snapshot with a non-object lease fails closed",
          _raises(lambda: sanitize_snapshot(b'{"leases": ["x"]}')), True)

    with tempfile.TemporaryDirectory(prefix="ledger-history-purge-") as tmp:
        root = Path(tmp)

        # ---- end-to-end: a real repo, git's real filter-branch driver -----------------------
        dirty_a = json.dumps({"leases": [raw_row, good_row]}, indent=1).encode()
        dirty_b = json.dumps({"leases": [dict(raw_row, claim_id="d" * 32), other_row]},
                             indent=1).encode()
        repo = _fixture_repo(root / "ledger", [
            ("release 47f4b2e0", b'{\n "leases": []\n}'),
            ("claim 0123abcd acct01 bench/impl", dirty_a),
            ("claim 89abcdef bench/impl", json.dumps({"leases": [good_row]}, indent=1).encode()),
            ("adopt a89de32a -> worker run", dirty_b),
        ])

        before = scan(repo, "ledger")
        check("scan counts every commit on the ref", before["commits"], 4)
        check("scan finds the one legacy subject", len(before["legacy_subjects"]), 1)
        check("scan finds both exposed snapshots", len(before["exposed_blobs"]), 2)
        check("scan counts each exposed row", before["exposed_rows"], 2)
        check("a dirty ref is not publishable", report_exposures(before), 3)

        handles_file = root / "handles.txt"
        handles_file.write_text("# fleet\nacct01\nacct2css\n\n", encoding="utf-8")
        literal = scan(repo, "ledger", _read_handles(str(handles_file)))
        check("the literal handle check finds occurrences the structural check also saw",
              literal["handle_hits"] > 0, True)
        check("the rendered report never names a handle it counted",
              _rendered(literal), False)

        # The literal check exists to catch what the STRUCTURAL check cannot: a handle that is
        # not in an `account` field and not in a claim subject. Such a ref scans clean
        # structurally, so the literal hits must reach the exposure total on their own — a count
        # that is reported but not totalled is a verification that passes over a live leak.
        residual = _fixture_repo(root / "residual", [
            ("release 47f4b2e0\n\nrecovered by hand for acct01\n",
             json.dumps({"leases": [dict(good_row, package="acct01-bench")]}, indent=1).encode()),
        ])
        check("a handle outside account/subject is structurally invisible",
              report_exposures(scan(residual, "ledger")), 0)
        check("the literal check sees it in BOTH the message and the snapshot, and totals it",
              [scan(residual, "ledger", ["acct01"])["handle_hits"],
               report_exposures(scan(residual, "ledger", ["acct01"]))], [2, 2])
        residual_out = io.StringIO()
        with contextlib.redirect_stdout(residual_out):
            residual_code = main(["scan", "--repo", str(residual), "--ref", "ledger",
                                  "--handles-file", str(handles_file)])
        check("the CLI literal check EXITS NON-ZERO on a structurally-clean ref", residual_code, 1)
        check("the literal-check report still names no handle",
              "acct01" in residual_out.getvalue(), False)

        # CONTROL BYTES ARE DATA. A commit message may contain any byte but NUL, so a bulk read
        # framed on \x01/\x02 lets ONE message split itself into pseudo-records whose text lands
        # in the parsed `sha` field — which neither the subject walk nor the literal count reads.
        # Handles sit AFTER each control byte, so a framing regression reports this ref clean.
        control = _fixture_repo(root / "control-bytes", [
            ("release 47f4b2e0\n\nrestored \x01 for acct01 and \x02 for acct2css\n", None)])
        control_records = _commit_messages(control, "ledger")
        # Expected SHA read from git, not from the parser under test.
        check("a control-byte message parses as ONE record, keyed by the real commit SHA",
              [len(control_records), control_records[0][0]],
              [1, _git(["rev-parse", "refs/heads/ledger"], repo=control).decode().strip()])
        check("both control bytes survive INSIDE the message rather than framing it",
              ["\x01" in control_records[0][1], "\x02" in control_records[0][1]], [True, True])
        control_report = scan(control, "ledger", ["acct01", "acct2css"])
        check("the control-byte ref is still counted as one commit",
              control_report["commits"], 1)
        check("the handles after \\x01 and \\x02 are counted and reach the exposure total",
              [control_report["handle_hits"], report_exposures(control_report)], [2, 2])
        check("the control-byte report still names no handle", _rendered(control_report), False)

        # `main` is the entry point the operator actually runs; drive it (report rendering
        # included) rather than only its helpers, with stdout captured so the suite's own rows
        # stay the only thing on stdout.
        cli_out = io.StringIO()
        with contextlib.redirect_stdout(cli_out):
            exit_code = main(["scan", "--repo", str(repo), "--ref", "ledger"])
        check("scan EXITS NON-ZERO on a dirty ref", exit_code, 1)
        check("the dirty CLI report renders both exposure counts",
              [line for line in cli_out.getvalue().splitlines()
               if "claim subjects" in line or "lease rows" in line],
              ["  legacy claim subjects:         1",
               "  raw-identity lease rows:       2 in 2 snapshots"])

        # Recorded as a CHECK, not left to propagate: a filter regression makes the post-rewrite
        # verification refuse, and an escaping exception here would abort the run before any row
        # printed — recording a kill while every check below it silently never ran.
        buffer = io.StringIO()
        check("the end-to-end rewrite completes without a refusal",
              _refusal(lambda: rewrite(repo, "ledger", stream=buffer)), None)
        check("rewrite preserves the commit count", len(_subjects(repo, "ledger")), 4)
        check("rewrite purges the handle from the subject and nothing else",
              _subjects(repo, "ledger"),
              ["adopt a89de32a -> worker run", "claim 89abcdef bench/impl",
               "claim 0123abcd bench/impl", "release 47f4b2e0"])
        after = scan(repo, "ledger")
        check("the rewritten ref is clean", report_exposures(after), 0)
        clean_out = io.StringIO()
        with contextlib.redirect_stdout(clean_out):
            clean_code = main(["scan", "--repo", str(repo), "--ref", "ledger"])
        check("scan EXITS ZERO on the rewritten ref", clean_code, 0)
        check("the clean CLI run says so on stdout",
              "carries no raw account identity" in clean_out.getvalue(), True)
        # The rewrite must PURGE, not empty: the canonical rows are the ledger's whole value.
        tip = _git(["cat-file", "blob", f"ledger:{LEDGER_PATH}"], repo=repo)
        check("the canonical row survives the rewrite at the tip",
              json.loads(tip.decode()), {"leases": [other_row]})
        mid = _git(["cat-file", "blob", f"ledger~2:{LEDGER_PATH}"], repo=repo)
        check("the canonical row survives the rewrite mid-history",
              json.loads(mid.decode()), {"leases": [good_row]})
        check("the pre-purge history is preserved under refs/original/",
              _git(["for-each-ref", "--format=%(refname)", "refs/original/"],
                   repo=repo).decode().strip(),
              "refs/original/refs/heads/ledger")
        check("the original ref still carries the exposures (nothing was destroyed)",
              report_exposures(scan(repo, "refs/original/refs/heads/ledger")), 3)

        # ---- fail-closed guards ------------------------------------------------------------
        # Assert on WHICH refusal fired: filter-branch also declines a second run ("a previous
        # backup already exists"), so a did-it-raise probe alone passes with this guard deleted.
        check("a second rewrite refuses on the backup, before filter-branch is reached",
              "refs/original/ already exists" in
              (_refusal(lambda: rewrite(repo, "ledger", stream=io.StringIO())) or ""), True)
        # A REAL remote-tracking ref, so the refusal cannot be an unknown-ref error standing in
        # for the guard. Rewriting one would rewrite what the next `git push` compares against.
        # `repo` already carries a refs/original/, so this also pins the ORDER: the ref guard runs
        # before the backup guard, and the message says which one fired.
        remote_head = _git(["rev-parse", "refs/original/refs/heads/ledger"],
                           repo=repo).decode().strip()
        _git(["update-ref", "refs/remotes/origin/ledger", remote_head], repo=repo)
        check("rewrite refuses a remote-tracking ref before the backup guard is reached",
              "not a local branch under refs/heads/" in
              (_refusal(lambda: rewrite(repo, "refs/remotes/origin/ledger",
                                        stream=io.StringIO())) or ""), True)
        check("the refused remote-tracking ref was not moved",
              _git(["rev-parse", "refs/remotes/origin/ledger"], repo=repo).decode().strip(),
              remote_head)

        # SHORTHAND. `git filter-branch` acts on the RESOLVED ref, so `origin/ledger` — the exact
        # spelling the README uses for scans — rewrites `refs/remotes/origin/ledger`. A guard that
        # matched the typed spelling let this through. Fixture has NO refs/original/, so the
        # backup guard cannot stand in for the one under test, and the accept case below is in the
        # SAME repo: a guard that simply refused everything would red it.
        shorthand = _fixture_repo(root / "shorthand", [
            ("claim 0123abcd acct01 bench/impl", dirty_a)])
        shorthand_head = _git(["rev-parse", "refs/heads/ledger"], repo=shorthand).decode().strip()
        _git(["update-ref", "refs/remotes/origin/ledger", shorthand_head], repo=shorthand)
        for spelling in ("origin/ledger", "remotes/origin/ledger", "refs/remotes/origin/ledger"):
            check(f"rewrite refuses {spelling!r}, which RESOLVES outside refs/heads/",
                  "not a local branch under refs/heads/" in
                  (_refusal(lambda: rewrite(shorthand, spelling, stream=io.StringIO())) or ""),
                  True)
        # A bare SHA names no ref; filter-branch would rewrite whatever ref happened to point at
        # it. Different branch of the guard, different message.
        check("rewrite refuses a bare commit SHA, which names no ref at all",
              "does not name exactly one ref" in
              (_refusal(lambda: rewrite(shorthand, shorthand_head, stream=io.StringIO())) or ""),
              True)
        check("no refused spelling moved the remote-tracking ref",
              _git(["rev-parse", "refs/remotes/origin/ledger"], repo=shorthand).decode().strip(),
              shorthand_head)
        check("no refused spelling created a backup namespace at all",
              _git(["for-each-ref", "--format=%(refname)", "refs/original/"],
                   repo=shorthand).decode().strip(), "")
        # ACCEPT side, same repo: the local branch's own shorthand still rewrites, and the backup
        # git then writes is the LOCAL one — proving resolution routed to refs/heads/, not to the
        # remote-tracking ref that shares the name.
        check("the same repo's LOCAL branch shorthand is still accepted",
              _refusal(lambda: rewrite(shorthand, "ledger", stream=io.StringIO())), None)
        check("the accepted rewrite backed up the LOCAL branch, and left the remote-tracking ref",
              [_git(["for-each-ref", "--format=%(refname)", "refs/original/"],
                    repo=shorthand).decode().strip(),
               _git(["rev-parse", "refs/remotes/origin/ledger"], repo=shorthand).decode().strip()],
              ["refs/original/refs/heads/ledger", shorthand_head])
        check("scan of an unknown ref fails closed",
              _raises(lambda: scan(repo, "refs/heads/does-not-exist")), True)
        check("scan of an unknown ref EXITS NON-ZERO",
              main(["scan", "--repo", str(repo), "--ref", "refs/heads/does-not-exist"]), 2)
        check("a missing handles file fails closed",
              _raises(lambda: _read_handles(str(root / "missing-handles.txt"))), True)
        # A file of only blanks and comments reaches a DIFFERENT guard than a missing one, and
        # would otherwise leave `handle_hits` structurally pinned at 0 — a check that cannot fail.
        (root / "blank-handles.txt").write_text("# nothing\n\n  \n", encoding="utf-8")
        check("a handles file with no handles is refused rather than checked vacuously",
              _raises(lambda: _read_handles(str(root / "blank-handles.txt"))), True)

        # A snapshot git can read but this tool cannot parse must stop the rewrite in the PRE-scan,
        # before filter-branch runs at all — so nothing is rewritten and no backup is consumed.
        broken = _fixture_repo(root / "broken", [
            ("release 47f4b2e0", b'{\n "leases": []\n}'),
            ("claim 0123abcd acct01 bench/impl", b"{ this is not json"),
        ])
        broken_tip = _git(["rev-parse", "ledger"], repo=broken).decode().strip()
        check("an unparseable snapshot refuses the rewrite",
              _raises(lambda: rewrite(broken, "ledger", stream=io.StringIO())), True)
        check("the refused rewrite left the ref where it was",
              _git(["rev-parse", "ledger"], repo=broken).decode().strip(), broken_tip)
        check("the refused rewrite never reached filter-branch (no backup was written)",
              _git(["for-each-ref", "--format=%(refname)", "refs/original/"],
                   repo=broken).decode().strip(), "")

        # A filter-branch that exits non-zero for git's OWN reasons (here: unstaged changes) must
        # surface as a refusal too — this is a different branch from the pre-scan refusal above.
        unstaged = _fixture_repo(root / "unstaged", [
            ("release 47f4b2e0", json.dumps({"leases": [good_row]}, indent=1).encode())])
        (unstaged / LEDGER_PATH).write_bytes(b'{\n "leases": []\n}')
        check("a filter-branch that git itself refuses is reported as a failure",
              _raises(lambda: rewrite(unstaged, "ledger", stream=io.StringIO())), True)

        # The post-rewrite verification is the backstop for a FILTER regression, so it must refuse
        # even when filter-branch itself reported success. Drive it with a scanner that reports a
        # leftover exposure; the real `scan` is what every other path here uses.
        leftover = _fixture_repo(root / "leftover", [
            ("claim 0123abcd acct01 bench/impl", dirty_a)])
        still_dirty = dict(scan(leftover, "ledger"), legacy_subjects=["deadbeef"],
                           exposed_rows=0, exposed_blobs=[], handle_hits=0)
        check("a rewrite whose verification still sees an exposure refuses to report success",
              _raises(lambda: rewrite(leftover, "ledger", stream=io.StringIO(),
                                      verify=lambda *_: still_dirty)), True)

        # ---- the two filter entry points, driven IN PROCESS ---------------------------------
        # filter-branch runs these as subprocesses, so the end-to-end run above executes them
        # where no in-process instrument can see them — which is exactly the region a fabricating
        # edit survives in. Drive each one directly against a real index / real streams.
        # The clean snapshot here is deliberately NOT written with this module's own `indent=1`
        # serialization: an implementation that re-serialized every snapshot would produce
        # byte-identical output for an `indent=1` fixture and stage a new blob undetectably.
        filtered = _fixture_repo(root / "filters", [
            ("release 47f4b2e0", dirty_a),
            ("release 47f4b2e1", (json.dumps({"leases": [other_row]}) + "\n").encode()),
        ])
        no_snapshot = _fixture_repo(root / "no-snapshot", [("release 47f4b2e2", None)])

        def _staged(repo_path, rev, index_name):
            """Load `rev` into a scratch index and run `index-filter` over it, as git would."""
            index = root / index_name
            saved = {key: os.environ.get(key) for key in ("GIT_DIR", "GIT_INDEX_FILE")}
            os.environ["GIT_DIR"] = str(Path(repo_path) / ".git")
            os.environ["GIT_INDEX_FILE"] = str(index)
            try:
                _git(["read-tree", rev])
                before_entry = _git(["ls-files", "-s", "--", LEDGER_PATH]).decode().strip()
                code = main(["index-filter"])
                after_entry = _git(["ls-files", "-s", "--", LEDGER_PATH]).decode().strip()
                content = (_git(["cat-file", "blob", after_entry.split()[1]])
                           if after_entry else b"")
            finally:
                for key, value in saved.items():
                    os.environ.pop(key, None) if value is None else os.environ.update({key: value})
            return code, before_entry, after_entry, content

        code, was, now, content = _staged(filtered, "ledger~1", "idx-dirty")
        check("index-filter returns 0 on a snapshot it purged", code, 0)
        check("index-filter replaced the staged blob",
              was.split()[1] != now.split()[1], True)
        check("index-filter staged exactly the purged snapshot",
              content, json.dumps({"leases": [good_row]}, indent=1).encode())
        check("index-filter preserved the file mode", now.split()[0], "100644")
        code, was, now, _content = _staged(filtered, "ledger", "idx-clean")
        check("index-filter leaves a clean snapshot's blob untouched", (code, now), (0, was))
        code, was, now, _content = _staged(no_snapshot, "ledger", "idx-absent")
        check("index-filter is a no-op when the commit has no ledger snapshot",
              (code, was, now), (0, "", ""))

        class _Stream:
            def __init__(self, data=b""):
                self.buffer = io.BytesIO(data)

        saved_stdin, saved_stdout = sys.stdin, sys.stdout
        sys.stdin, sys.stdout = _Stream(b"claim 0123abcd acct01 bench/impl\n"), _Stream()
        try:
            msg_code, msg_out = main(["msg-filter"]), sys.stdout.buffer.getvalue()
        finally:
            sys.stdin, sys.stdout = saved_stdin, saved_stdout
        check("msg-filter rewrites the message it is handed on stdin",
              (msg_code, msg_out), (0, b"claim 0123abcd bench/impl\n"))

        # `rewrite` and the no-subcommand usage path, through the CLI the operator types.
        cli_repo = _fixture_repo(root / "cli", [
            ("claim 0123abcd acct01 bench/impl", dirty_a)])
        rewrite_out = io.StringIO()
        with contextlib.redirect_stdout(rewrite_out):
            rewrite_code = main(["rewrite", "--repo", str(cli_repo), "--ref", "ledger"])
        check("the rewrite CLI exits zero and leaves a clean ref",
              (rewrite_code, _subjects(cli_repo, "ledger"),
               report_exposures(scan(cli_repo, "ledger"))),
              (0, ["claim 0123abcd bench/impl"], 0))
        with contextlib.redirect_stderr(io.StringIO()):
            check("no subcommand is a usage error, never a silent success", main([]), 2)

        # ---- the remaining refusals in the git seam -----------------------------------------
        # A ref with no ledger snapshot at all scans clean without touching cat-file's batch.
        empty_report = scan(no_snapshot, "ledger")
        check("a ref carrying no ledger snapshot scans clean, with the commit still counted",
              (empty_report["snapshots"], empty_report["commits"],
               report_exposures(empty_report)), (0, 1, 0))
        # `data/leases.json` as a TREE is neither a readable snapshot nor absent: refuse, rather
        # than skip it as if the path were missing.
        shadowed = Path(root / "shadowed")
        _git(["init", "-q", str(shadowed)])
        _git(["symbolic-ref", "HEAD", "refs/heads/ledger"], repo=shadowed)
        (shadowed / LEDGER_PATH / "nested").mkdir(parents=True)
        (shadowed / LEDGER_PATH / "nested" / "x.json").write_text("{}", encoding="utf-8")
        _git(["add", "-A"], repo=shadowed)
        _git(["-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
              "commit", "-q", "-m", "release 47f4b2e3"], repo=shadowed)
        check("a ledger path that is not a blob fails closed",
              _raises(lambda: scan(shadowed, "ledger")), True)
        # git missing from PATH is a refusal, not an empty (therefore "clean") walk.
        saved_path = os.environ.get("PATH", "")
        os.environ["PATH"] = str(root / "no-bin")
        try:
            check("an unrunnable git fails closed", _raises(lambda: _git(["--version"])), True)
        finally:
            os.environ["PATH"] = saved_path

    ok = True
    for name, got, want in checks:
        passed = got == want
        ok = ok and passed
        print(f"  {'ok  ' if passed else 'FAIL'} {name}: {got!r} (want {want!r})")
    print(f"  {len(checks)} checks")
    print("ledger-history-purge self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def _rendered(report):
    """True iff rendering a report would emit a handle. Used only by the self-test."""
    import io
    buffer = io.StringIO()
    print_report(report, stream=buffer)
    text = buffer.getvalue()
    return any(handle in text for handle in ("acct01", "acct2css"))


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(main(sys.argv[1:]))
    raise SystemExit(main())
