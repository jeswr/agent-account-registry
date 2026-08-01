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


def entry_allowed(mode, kind, path):
    return any(mode == allowed_mode and kind == allowed_kind and pattern.fullmatch(path)
               for allowed_mode, allowed_kind, pattern in ALLOWED_ENTRIES)


def observability_violations(root):
    """Content invariants for `data/observability.json` that the tree allowlist cannot express.

    Reads the WORKTREE, not the HEAD tree: the worktree is what every consumer of this checkout
    goes on to read (`dashboard-gen.py --observability ledger/data/observability.json`), so it is
    the artifact the refusal has to cover. An ABSENT file is the documented pre-collector state and
    is not a violation; an unreadable, undecodable or unparseable one is refused rather than waved
    through, since nothing downstream can vouch for a file this could not read.

    Keyed on the PRESENCE of the `leases` key, never on whether a row parses: a malformed or empty
    row array discloses the same fleet as a well-formed one. A non-object document is refused for
    the same reason — the declared schema is an object, so anything else is a shape no consumer
    validates and an obvious place to hide the array this refuses.
    """
    path = Path(root) / OBSERVABILITY_PATH
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise ValueError(f"cannot read {OBSERVABILITY_PATH}: {exc}") from exc
    except ValueError as exc:                     # JSONDecodeError + UnicodeDecodeError
        raise ValueError(f"{OBSERVABILITY_PATH} is not parseable JSON: {exc}") from exc
    if not isinstance(document, dict):
        return [f"{OBSERVABILITY_PATH}: snapshot is not a JSON object"]
    flow = document.get("flow")
    if isinstance(flow, dict) and "leases" in flow:
        return [f"{OBSERVABILITY_PATH}: flow.leases per-account rows on a public branch "
                "(send the pre-aggregated flow.lease_utilization_1h instead; issue #891)"]
    return []


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
    violations.extend(observability_violations(root))
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
