#!/usr/bin/env python3
# [SPARQ agent] Resolve the policy-backed repository matrix for backfill-provenance.yml.
"""Resolve enabled provenance-backfill targets, refusing every empty or unknown selection."""

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import tomllib


class TargetResolutionError(ValueError):
    """The policy cannot produce the requested non-empty target matrix."""


def resolve_targets(policy, requested=""):
    """Return the sorted enabled targets, optionally narrowed to one requested target."""
    repos = policy.get("repos") if isinstance(policy, dict) else None
    if not isinstance(repos, dict):
        raise TargetResolutionError("policy has no `repos` table")
    enabled = sorted(name for name, row in repos.items()
                     if isinstance(name, str) and isinstance(row, dict)
                     and row.get("enabled") is True)
    requested = (requested or "").strip()
    if requested:
        if requested not in enabled:
            raise TargetResolutionError(
                f"target_repo {requested!r} is not an ENABLED policy row: {enabled}")
        return [requested]
    if not enabled:
        raise TargetResolutionError("policy enables no repos — refusing an empty matrix")
    return enabled


def resolve_file(path, requested=""):
    with open(path, "rb") as handle:
        return resolve_targets(tomllib.load(handle), requested)


def _self_test():
    failures = []

    def check(name, got, want):
        good = got == want
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")
        if not good:
            failures.append(name)

    def refusal(policy, requested=""):
        try:
            resolve_targets(policy, requested)
        except TargetResolutionError:
            return True
        return False

    fixture = {"repos": {
        "fixture/beta": {"enabled": True},
        "fixture/alpha": {"enabled": True},
        "fixture/off": {"enabled": False},
        "stray": "not-a-row",
    }}
    check("empty request sweeps every enabled row in stable order",
          resolve_targets(fixture), ["fixture/alpha", "fixture/beta"])
    check("whitespace request is the scheduled full-sweep case",
          resolve_targets(fixture, "  \t"), ["fixture/alpha", "fixture/beta"])
    check("enabled manual request narrows to exactly one target",
          resolve_targets(fixture, " fixture/beta "), ["fixture/beta"])
    check("unknown manual request refuses instead of widening to all",
          refusal(fixture, "fixture/unknown"), True)
    check("disabled manual request refuses", refusal(fixture, "fixture/off"), True)
    check("empty enabled population refuses instead of emitting []",
          refusal({"repos": {"fixture/off": {"enabled": False}}}), True)
    check("missing repos table refuses", refusal({}), True)
    check("truthy non-boolean enabled does not grant admission",
          refusal({"repos": {"fixture/wrong": {"enabled": 1}}}), True)

    with tempfile.TemporaryDirectory() as directory:
        policy_path = Path(directory) / "repos.toml"
        policy_path.write_text('[repos."fixture/one"]\nenabled = true\n', encoding="utf-8")
        check("file boundary loads TOML and resolves it",
              resolve_file(policy_path), ["fixture/one"])
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main(["--policy", str(policy_path), "--requested", "fixture/one"])
        check("CLI emits the GitHub-output assignment on success",
              (status, stdout.getvalue().strip()), (0, 'repos=["fixture/one"]'))
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = main(["--policy", str(policy_path), "--requested", "fixture/unknown"])
        check("CLI returns nonzero and names an unknown target refusal",
              (status, "not an ENABLED policy row" in stderr.getvalue()), (1, True))

    if failures:
        for name in failures:
            print(f"FAIL: {name}")
        print(f"::error::backfill-targets self-test: {len(failures)} failure(s)")
        return 1
    print("backfill-targets self-test: all checks passed")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--policy", default="policy/repos.toml")
    parser.add_argument("--requested", default=None)
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    requested = os.environ.get("REQUESTED", "") if args.requested is None else args.requested
    try:
        targets = resolve_file(args.policy, requested)
    except (OSError, tomllib.TOMLDecodeError, TargetResolutionError) as exc:
        print(f"backfill-targets: {exc}", file=sys.stderr)
        return 1
    print("repos=" + json.dumps(targets))
    return 0


if __name__ == "__main__":
    sys.exit(main())
