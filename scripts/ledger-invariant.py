#!/usr/bin/env python3
"""Fail-closed validator for the ledger branch's data-only Git tree."""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path


ALLOWED_ENTRIES = (
    ("100644", "blob", re.compile(r"README\.md")),
    ("040000", "tree", re.compile(r"data")),
    ("100644", "blob", re.compile(r"data/[^/]+\.json")),
    ("040000", "tree", re.compile(r"orchestration")),
    ("040000", "tree", re.compile(r"orchestration/(?:provenance|review-verdicts)")),
    ("100644", "blob",
     re.compile(r"orchestration/(?:provenance|review-verdicts)/[^/]+\.json")),
)


# Issue #891: the allowlist above constrains the ledger's SHAPE — paths, object types, modes — and
# an observability snapshot is a legitimately-shaped flat `data/*.json` blob, so the tree check
# cannot see what it CARRIES. What it may not carry is a per-account lease row array: a
# `flow.leases[]` of `{label, provider, utilization_1h}` reads out the fleet's size directly and its
# salted labels are stable across builds (issue #374), and this branch is PUBLIC. Issue #841 stopped
# dashboard-gen REQUIRING those rows — a collector sends the pre-aggregated
# `flow.lease_utilization_1h` and writes no rows anywhere — but nothing REFUSED them, so a collector
# authored against the older prose would park the array here with every check green. This is that
# refusal, at the ledger ref itself: it fires for every consumer of this branch (dashboard, groom,
# dispatch, review-fix), not only the builds that go on to read the file, because the disclosure is
# the file EXISTING on a public branch rather than anything a build publishes from it.
OBSERVABILITY_PATH = "data/observability.json"

# Regular-file blob modes. A `120000` blob at the observability path is a symlink whose "content"
# is a link target, which the tree allowlist already refuses; reading it as a snapshot would only
# parse the target string as JSON.
REGULAR_BLOB_MODES = ("100644", "100755")


class _DuplicateMember(ValueError):
    """A JSON object repeating a member name — `json.loads` keeps only the last one."""


def entry_allowed(mode, kind, path):
    return any(mode == allowed_mode and kind == allowed_kind and pattern.fullmatch(path)
               for allowed_mode, allowed_kind, pattern in ALLOWED_ENTRIES)


def _reject_duplicate_members(pairs):
    seen = set()
    for key, _value in pairs:
        if key in seen:
            raise _DuplicateMember(key)
        seen.add(key)
    return dict(pairs)


def _snapshot_violations(source, raw):
    """Content invariants for one observability snapshot's raw BYTES (`source` names where from).

    Keyed on the PRESENCE of the `leases` key, never on whether a row parses: a malformed or empty
    row array discloses the same fleet as a well-formed one. A non-object document is refused for
    the same reason — the declared schema is an object, so anything else is a shape no consumer
    validates and an obvious place to hide the array this refuses. An undecodable or unparseable
    snapshot is refused rather than waved through, since nothing downstream can vouch for bytes
    this could not read.

    A REPEATED member name is refused before any lookup (#1506 review round 1): `json.loads` is
    last-key-wins, so `{"flow": {"leases": [...]}, "flow": {}}` would present an empty `flow` to
    `document.get` while the published bytes still literally carry the row array — and the bytes
    existing on the public branch IS the disclosure. Refusing every duplicate, at every object
    level, is the fail-closed reading: this validator cannot certify a document whose meaning
    depends on which parser reads it.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{source} is not decodable UTF-8: {exc}") from exc
    try:
        document = json.loads(text, object_pairs_hook=_reject_duplicate_members)
    except _DuplicateMember as exc:                # must precede ValueError: it IS a ValueError
        return [f"{source}: duplicate JSON member {exc.args[0]!r} — last-key-wins parsing would "
                "hide an earlier flow.leases from this check (issue #891)"]
    except ValueError as exc:                      # JSONDecodeError
        raise ValueError(f"{source} is not parseable JSON: {exc}") from exc
    if not isinstance(document, dict):
        return [f"{source}: snapshot is not a JSON object"]
    flow = document.get("flow")
    if isinstance(flow, dict) and "leases" in flow:
        return [f"{source}: flow.leases per-account rows on a public branch "
                "(send the pre-aggregated flow.lease_utilization_1h instead; issue #891)"]
    return []


def _head_snapshot(root, entries):
    """The ATTESTED snapshot bytes: the blob `entries` enumerated at `OBSERVABILITY_PATH` in HEAD.

    None when HEAD carries no regular blob there. Gated on the same `entries` the tree check ran
    over so the content check and the shape check certify ONE Git object, and a `git cat-file` that
    then fails on a blob this enumeration just listed is refused rather than read as absent.
    """
    if not any(mode in REGULAR_BLOB_MODES and kind == "blob" and path == OBSERVABILITY_PATH
               for mode, kind, path in entries):
        return None
    result = subprocess.run(
        ["git", "-C", str(root), "cat-file", "blob", f"HEAD:{OBSERVABILITY_PATH}"],
        check=False, capture_output=True)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise ValueError(f"cannot read the attested {OBSERVABILITY_PATH}: "
                         f"{detail or 'git cat-file failed'}")
    return result.stdout


def _worktree_snapshot(root):
    """The snapshot bytes consumers actually read, or None when the file is absent.

    An ABSENT file is the documented pre-collector state and is not a violation; an unreadable one
    is refused, since nothing downstream can vouch for a file this could not read.
    """
    try:
        return (Path(root) / OBSERVABILITY_PATH).read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError(f"cannot read {OBSERVABILITY_PATH}: {exc}") from exc


def observability_violations(root, entries):
    """Content invariants for `data/observability.json` that the tree allowlist cannot express.

    Checks BOTH bytes this checkout can disclose, because they are two different objects and each
    is load-bearing on its own (#1506 review round 1). The HEAD blob is what `ledger_entries`
    attested and what the PUBLIC branch publishes — validating only the worktree let a commit
    carrying rows pass once its worktree copy was deleted or overwritten, certifying one Git object
    while reading different bytes. The worktree copy is what every consumer of this checkout goes
    on to read (`dashboard-gen.py --observability ledger/data/observability.json`), including when
    it is untracked and so invisible to the tree enumeration. Identical bytes are checked once.
    """
    violations = []
    head = _head_snapshot(root, entries)
    if head is not None:
        violations.extend(_snapshot_violations(f"{OBSERVABILITY_PATH}@HEAD", head))
    worktree = _worktree_snapshot(root)
    if worktree is not None and worktree != head:
        violations.extend(_snapshot_violations(f"{OBSERVABILITY_PATH} (worktree)", worktree))
    return violations


def ledger_entries(root):
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-tree", "-r", "-t", "-z", "HEAD"],
            check=False, capture_output=True)
    except OSError as exc:
        raise ValueError(f"cannot inspect ledger Git tree: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise ValueError(f"cannot inspect ledger Git tree: {detail or 'git ls-tree failed'}")

    entries = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            metadata, path_raw = raw.split(b"\t", 1)
            mode_raw, kind_raw, _object_id = metadata.split(b" ", 2)
            mode = mode_raw.decode("ascii")
            kind = kind_raw.decode("ascii")
            path = path_raw.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("ledger Git tree contains an unparseable entry") from exc
        entries.append((mode, kind, path))
    return entries


def validate(root):
    """Every reason to refuse this ledger checkout: Git tree entries outside the allowlist, plus
    the content invariants the tree shape alone cannot express (issue #891)."""
    entries = ledger_entries(root)
    if not entries:
        return ["ledger Git tree is empty"]
    violations = [f"{mode} {kind} {path}" for mode, kind, path in entries
                  if not entry_allowed(mode, kind, path)]
    violations.extend(observability_violations(root, entries))
    return violations


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _commit(repo):
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=ledger-test", "-c", "user.email=ledger@example.invalid",
         "commit", "-m", "fixture")


def _observability_fixture(tmp, snapshot):
    """A minimal, tree-clean ledger checkout carrying `snapshot` (raw text; None => no file).

    The snapshot is written to a LITERAL `data/observability.json`, never to `OBSERVABILITY_PATH`:
    an input derived from the constant the code reads follows a repoint and cannot fail (AGENTS.md
    AUTHOR pre-flight item 2c). The tree here is deliberately allowlist-clean, so every violation
    these rows assert came from the content check rather than from the tree check.
    """
    repo = Path(tmp)
    _git(repo, "init")
    (repo / "data").mkdir()
    (repo / "README.md").write_text("ledger\n", encoding="utf-8")
    (repo / "data" / "leases.json").write_text("{}\n", encoding="utf-8")
    if snapshot is not None:
        (repo / "data" / "observability.json").write_text(snapshot, encoding="utf-8")
    _commit(repo)
    return repo


def _observability_self_test():
    """Issue #891: a `flow.leases[]` row array in the observability snapshot is REFUSED here, and
    the row-free contract issue #841 made the collector's job is still accepted."""
    row_free = json.dumps({"schema": "registry-observability/v1",
                           "flow": {"queue": [{"class": "2a", "depth": 1}],
                                    "lease_utilization_1h": {"mean": 0.3, "max": 0.7}}})
    with tempfile.TemporaryDirectory(prefix="ledger-obs-rowfree-") as tmp:
        assert validate(_observability_fixture(tmp, row_free)) == [], \
            "the row-free collector contract (#841) must stay acceptable on the ledger"
    with tempfile.TemporaryDirectory(prefix="ledger-obs-absent-") as tmp:
        assert validate(_observability_fixture(tmp, None)) == [], \
            "an absent snapshot is the documented pre-collector state, not a violation"

    # Presence-keyed, so an empty/null/mis-typed `leases` is refused exactly like a populated one:
    # make this conditional on the rows being a non-empty list and the last three rows go green.
    for case, rows in (
            ("a populated row array", [{"label": "ab12cd340a5f9e71", "provider": "anthropic",
                                        "utilization_1h": 0.5}]),
            ("an EMPTY row array", []),
            ("a null leases key", None),
            ("a non-list leases key", {"ab12cd340a5f9e71": 0.5}),
    ):
        snapshot = json.dumps({"schema": "registry-observability/v1",
                               "flow": {"lease_utilization_1h": {"mean": 0.3, "max": 0.7},
                                        "leases": rows}})
        with tempfile.TemporaryDirectory(prefix="ledger-obs-rows-") as tmp:
            refusals = validate(_observability_fixture(tmp, snapshot))
        assert any("data/observability.json" in item and "flow.leases" in item
                   for item in refusals), \
            f"{case} must be refused on the public ledger branch, got {refusals!r}"

    # ...and the refusal is bound to the OBJECT the tree enumeration attested, not to whatever the
    # worktree happens to hold when the validator runs (#1506 review round 1). Both mutations below
    # leave a HEAD blob carrying the rows — which is the disclosure — while the worktree copy this
    # used to read alone says nothing.
    rows = json.dumps({"schema": "registry-observability/v1",
                       "flow": {"leases": [{"label": "ab12cd340a5f9e71",
                                            "utilization_1h": 0.5}]}})
    for case, mutate in (
            ("deleted from the worktree", lambda snapshot: snapshot.unlink()),
            ("overwritten with a row-free copy in the worktree",
             lambda snapshot: snapshot.write_text(row_free, encoding="utf-8")),
    ):
        with tempfile.TemporaryDirectory(prefix="ledger-obs-head-") as tmp:
            repo = _observability_fixture(tmp, rows)
            mutate(repo / "data" / "observability.json")
            refusals = validate(repo)
        assert any("data/observability.json" in item and "flow.leases" in item
                   for item in refusals), \
            f"a COMMITTED row array must still be refused with the file {case}, got {refusals!r}"

    # ...and the converse direction: the worktree copy consumers actually read stays load-bearing
    # when HEAD never saw it, since an untracked snapshot is invisible to the tree enumeration.
    with tempfile.TemporaryDirectory(prefix="ledger-obs-untracked-") as tmp:
        repo = _observability_fixture(tmp, None)
        (repo / "data" / "observability.json").write_text(rows, encoding="utf-8")
        refusals = validate(repo)
    assert any("data/observability.json" in item and "flow.leases" in item
               for item in refusals), \
        f"an UNTRACKED row array must be refused from the worktree, got {refusals!r}"

    # ...and the mirror image of the two rows above: an attested blob that is clean while the
    # worktree copy consumers read carries the rows. Neither source subsumes the other, so a check
    # that consults the worktree only when HEAD has no blob would read past exactly this one.
    with tempfile.TemporaryDirectory(prefix="ledger-obs-divergent-") as tmp:
        repo = _observability_fixture(tmp, row_free)
        (repo / "data" / "observability.json").write_text(rows, encoding="utf-8")
        refusals = validate(repo)
    assert any("data/observability.json" in item and "flow.leases" in item
               for item in refusals), \
        f"a row array in the worktree copy must be refused beside a clean HEAD, got {refusals!r}"

    # A repeated member is refused before any lookup: `json.loads` is last-key-wins, so the later
    # empty `flow` presents no rows to `document.get` while the published bytes still literally
    # carry the array (#1506 review round 1). Raw text, because `json.dumps` cannot emit a
    # duplicate member.
    for case, snapshot in (
            ("a later empty flow member shadowing the row array",
             '{"flow": {"leases": [{"label": "ab12cd340a5f9e71"}]}, "flow": {}}'),
            ("a duplicate nested inside flow",
             '{"flow": {"leases": [{"label": "ab12cd340a5f9e71"}], "leases": []}}'),
    ):
        with tempfile.TemporaryDirectory(prefix="ledger-obs-dup-") as tmp:
            refusals = validate(_observability_fixture(tmp, snapshot))
        assert any("data/observability.json" in item and "duplicate JSON member" in item
                   for item in refusals), \
            f"{case} must be refused, got {refusals!r}"

    # A symlink at the observability path is reported as the TREE violation it is, rather than as
    # an unparseable snapshot: `cat-file` on a `120000` blob hands back a link TARGET, so reading
    # one as content refuses for a reason that misnames what is wrong with the ledger.
    with tempfile.TemporaryDirectory(prefix="ledger-obs-symlink-") as tmp:
        repo = Path(tmp)
        _git(repo, "init")
        (repo / "data").mkdir()
        (repo / "README.md").write_text("ledger\n", encoding="utf-8")
        (repo / "data" / "leases.json").write_text("{}\n", encoding="utf-8")
        (repo / "data" / "observability.json").symlink_to("leases.json")
        _commit(repo)
        assert any(item.startswith("120000 blob") for item in validate(repo)), \
            "a symlinked observability snapshot must be refused as the tree violation it is"

    # ...and a HEAD blob the tree enumeration listed but Git then cannot hand over is REFUSED, not
    # read as an absent snapshot. Driven with an enumeration that names a blob the repository does
    # not carry, which is the only way to make `cat-file` fail on a listed path without corrupting
    # an object store.
    with tempfile.TemporaryDirectory(prefix="ledger-obs-unreadable-") as tmp:
        repo = _observability_fixture(tmp, None)
        try:
            _head_snapshot(repo, [("100644", "blob", "data/observability.json")])
        except ValueError:
            pass
        else:
            raise AssertionError("an unreadable attested snapshot must fail closed, not read empty")

    # A non-object document is the bypass this closes: `[{"flow": {"leases": [...]}}]` carries the
    # same array while `document.get("flow")` sees nothing.
    with tempfile.TemporaryDirectory(prefix="ledger-obs-alien-") as tmp:
        alien = json.dumps([{"flow": {"leases": [{"label": "ab12cd340a5f9e71"}]}}])
        assert validate(_observability_fixture(tmp, alien)), \
            "a non-object observability snapshot must be refused, not read past"

    # ...and the whole point is the EXIT CODE: every workflow that runs this validator sees only
    # that, so a refusal `validate` computes but `main` does not report is no refusal at all. This
    # is the one row that executes main's CLI path (`--self-test` returns before it), which is
    # otherwise never run — `if bad:` -> `if False:` exits 0 on a violating ledger with the whole
    # suite above still green.
    for case, snapshot, expected_code in (
            ("a row array", json.dumps(
                {"schema": "registry-observability/v1",
                 "flow": {"leases": [{"label": "ab12cd340a5f9e71", "utilization_1h": 0.5}]}}), 1),
            ("a row array shadowed by a later empty flow member",
             '{"flow": {"leases": [{"label": "ab12cd340a5f9e71"}]}, "flow": {}}', 1),
            ("the row-free contract", row_free, 0),
    ):
        with tempfile.TemporaryDirectory(prefix="ledger-obs-cli-") as tmp:
            repo = _observability_fixture(tmp, snapshot)
            run = subprocess.run([sys.executable, str(Path(__file__).resolve()), str(repo)],
                                 check=False, capture_output=True, text=True)
        assert run.returncode == expected_code, \
            f"a ledger carrying {case} must exit {expected_code}, got {run.returncode}"
        if expected_code:
            assert "data/observability.json" in run.stderr and "flow.leases" in run.stderr, \
                f"the refusal must NAME the offending file and key, got {run.stderr!r}"

    # ...and an unparseable snapshot fails CLOSED rather than being read as carrying no rows.
    for case, snapshot in (("unparseable JSON", "{not json"),
                           ("undecodable bytes", '{"flow": "\udcff"}')):
        with tempfile.TemporaryDirectory(prefix="ledger-obs-bad-") as tmp:
            repo = Path(tmp)
            _git(repo, "init")
            (repo / "data").mkdir()
            (repo / "README.md").write_text("ledger\n", encoding="utf-8")
            (repo / "data" / "observability.json").write_text(
                snapshot, encoding="utf-8", errors="surrogateescape")
            _commit(repo)
            try:
                validate(repo)
            except ValueError:
                continue
            raise AssertionError(f"an observability snapshot with {case} must fail closed")


def self_test():
    _observability_self_test()
    with tempfile.TemporaryDirectory(prefix="ledger-invariant-") as tmp:
        repo = Path(tmp)
        _git(repo, "init")
        (repo / "data").mkdir()
        (repo / "orchestration" / "provenance").mkdir(parents=True)
        (repo / "orchestration" / "review-verdicts").mkdir()
        (repo / "README.md").write_text("ledger\n", encoding="utf-8")
        (repo / "data" / "leases.json").write_text("{}\n", encoding="utf-8")
        (repo / "orchestration" / "provenance" / "1.json").write_text(
            "{}\n", encoding="utf-8")
        (repo / "orchestration" / "review-verdicts" / "1.json").write_text(
            "{}\n", encoding="utf-8")
        _commit(repo)
        assert validate(repo) == [], "documented data and record stores must be accepted"

        (repo / "data" / "payload.bin").write_bytes(b"arbitrary")
        _commit(repo)
        assert any("data/payload.bin" in item for item in validate(repo)), \
            "arbitrary blobs must be rejected"

        (repo / "data" / "payload.bin").unlink()
        executable = repo / "data" / "executable.json"
        executable.write_text("{}\n", encoding="utf-8")
        executable.chmod(0o755)
        _commit(repo)
        assert any(item.startswith("100755 blob") for item in validate(repo)), \
            "executable JSON blobs must be rejected"

        executable.unlink()
        (repo / "data" / "link.json").symlink_to("leases.json")
        _commit(repo)
        assert any(item.startswith("120000 blob") for item in validate(repo)), \
            "symlinks with allowed-looking names must be rejected"

        head = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True,
            capture_output=True, text=True).stdout.strip()
        _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{head},data/submodule.json")
        _git(repo, "-c", "user.name=ledger-test", "-c", "user.email=ledger@example.invalid",
             "commit", "-m", "submodule fixture")
        assert any(item.startswith("160000 commit") for item in validate(repo)), \
            "submodules must be rejected regardless of allowed-looking paths"
        assert not entry_allowed("100644", "blob", "data/nested/extra.json"), \
            "nested data files must be rejected"

    try:
        validate(Path("/definitely/not/a/ledger/checkout"))
    except ValueError:
        pass
    else:
        raise AssertionError("a missing checkout must fail closed")
    print("ledger-invariant self-test PASSED")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", help="ledger checkout root")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.root:
        parser.error("root is required unless --self-test is used")
    try:
        bad = validate(Path(args.root))
    except ValueError as exc:
        print(f"ledger-invariant: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    if bad:
        print("ledger-invariant: ledger violates the data-only invariant:", file=sys.stderr)
        for entry in bad:
            print(f"  {entry}", file=sys.stderr)
        raise SystemExit(1)
    print("ledger-invariant: data-only ledger checkout verified")


if __name__ == "__main__":
    main()
