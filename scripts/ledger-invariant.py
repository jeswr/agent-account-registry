#!/usr/bin/env python3
"""Fail-closed validator for the ledger branch's data-only Git tree."""

import argparse
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


def entry_allowed(mode, kind, path):
    return any(mode == allowed_mode and kind == allowed_kind and pattern.fullmatch(path)
               for allowed_mode, allowed_kind, pattern in ALLOWED_ENTRIES)


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
    entries = ledger_entries(root)
    if not entries:
        return ["ledger Git tree is empty"]
    return [f"{mode} {kind} {path}" for mode, kind, path in entries
            if not entry_allowed(mode, kind, path)]


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _commit(repo):
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=ledger-test", "-c", "user.email=ledger@example.invalid",
         "commit", "-m", "fixture")


def self_test():
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
        print("ledger-invariant: ledger carries non-whitelisted Git tree entries:",
              file=sys.stderr)
        for entry in bad:
            print(f"  {entry}", file=sys.stderr)
        raise SystemExit(1)
    print("ledger-invariant: data-only Git tree verified")


if __name__ == "__main__":
    main()
