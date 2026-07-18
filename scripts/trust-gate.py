#!/usr/bin/env python3
# [OPUS-4.8] Issue-native orchestration: the untrusted-input safeguard.
"""trust-gate — decide whether the automation may act on an issue/PR/comment's CONTENT.

Fails CLOSED. Trust is derived from the author's REPO PERMISSION (no hard-coded logins): anyone with
write / maintain / admin (a collaborator or maintainer who could already push code) is trusted;
everyone else (read / triage / none = third-party) is untrusted UNTIL the maintainer promotes it with
a 👍 reaction. See research/issue-native-orchestration.md.

Verdicts:
  trusted    — author can push to the repo (write+), or is an automation identity → act normally.
  promoted   — third-party author, but the maintainer 👍-approved it → act (maintainer opted in).
  untrusted  — third-party, unapproved → take NO model action on its content; quarantine + notify.

Exit code: 0 if actionable (trusted|promoted), 3 if untrusted — so a workflow step can gate on it.

Usage:
  trust-gate.py --author <login> --permission <admin|maintain|write|triage|read|none> \
                [--bot a,b] [--maintainer-approved]
  trust-gate.py --author <login> --repo <owner/name> --fetch [--bot a,b] [--maintainer-approved]
  trust-gate.py --self-test
"""
import argparse
import subprocess
import sys

WRITE_PLUS = ("admin", "maintain", "write")   # can push -> already trusted with code


def verdict(author, permission, maintainer_approved, bot_logins=()):
    """Pure decision. `permission` is the author's repo permission string; `bot_logins` are
    automation identities (e.g. the GitHub App / bot). Comparison is case-insensitive."""
    a = (author or "").strip().lower()
    if a and a in {str(b).strip().lower() for b in bot_logins if str(b).strip()}:
        return "trusted"
    if str(permission or "").strip().lower() in WRITE_PLUS:
        return "trusted"
    if maintainer_approved:
        return "promoted"
    return "untrusted"


def actionable(v):
    return v in ("trusted", "promoted")


def fetch_permission(repo, author):
    """Effective repo permission for `author` (covers direct + org/team). 'none' on error/absence."""
    try:
        out = subprocess.run(
            ["gh", "api", f"repos/{repo}/collaborators/{author}/permission", "--jq", ".permission"],
            capture_output=True, text=True, check=True).stdout.strip()
        return out or "none"
    except Exception:
        return "none"


def _cli_exit_tests():
    """CLI-contract checks (sol r1 on registry #227): the 0/3 exit codes and the fail-closed
    fetch-failure path are what worker-issue.reverify consumes — cover them end-to-end."""
    import os
    me = os.path.abspath(__file__)
    ok = True

    def run_cli(*args):
        return subprocess.run([sys.executable, me, *args],
                              capture_output=True, text=True).returncode

    checks = [
        ("trusted author exits 0",
         run_cli("--author", "a", "--permission", "admin"), 0),
        ("bot author exits 0 regardless of permission",
         run_cli("--author", "b[bot]", "--permission", "none", "--bot", "b[bot]"), 0),
        ("third-party exits 3",
         run_cli("--author", "x", "--permission", "read"), 3),
        ("promoted third-party exits 0",
         run_cli("--author", "x", "--permission", "read", "--maintainer-approved"), 0),
        # --fetch against an unreachable repo: fetch_permission degrades to "none" ->
        # untrusted -> exit 3 (fail closed, NEVER a crash exit).
        ("fetch failure fails closed to 3",
         run_cli("--author", "x", "--repo", "invalid/definitely-not-a-repo-000", "--fetch"), 3),
        # Malformed invocations are hard errors (exit 2), never actionable verdicts.
        ("missing author is a hard error",
         run_cli("--permission", "write"), 2),
        ("approval without author is a hard error",
         run_cli("--maintainer-approved"), 2),
        ("--fetch without --repo is a hard error",
         run_cli("--author", "x", "--fetch"), 2),
        ("--fetch with --permission is a hard error",
         run_cli("--author", "x", "--repo", "o/r", "--fetch", "--permission", "write"), 2),
    ]
    for name, got, want in checks:
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: exit {got} (want {want})")
    # Hermetic SUCCESSFUL fetch (sol r2): a fake `gh` on PATH returns admin — --fetch must
    # print trusted and exit 0. Without this, a broken endpoint (fetch always "none") passes
    # every self-test while recreating the defer-all outage.
    import tempfile
    with tempfile.TemporaryDirectory() as fake_bin:
        fake_gh = os.path.join(fake_bin, "gh")
        with open(fake_gh, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\necho admin\n")
        os.chmod(fake_gh, 0o755)
        env = dict(os.environ, PATH=fake_bin + os.pathsep + os.environ.get("PATH", ""))
        r = subprocess.run([sys.executable, os.path.abspath(__file__),
                            "--author", "x", "--repo", "o/r", "--fetch"],
                           capture_output=True, text=True, env=env)
        good = r.returncode == 0 and r.stdout.strip() == "trusted"
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} hermetic successful fetch -> trusted/0: "
              f"exit {r.returncode} out {r.stdout.strip()!r} (want 0 'trusted')")
    return ok


def _self_test():
    BOT = ["sparq-bot[bot]"]
    cases = [
        # (author, permission, approved) -> expected
        ("alice", "admin", False, "trusted"),
        ("alice", "maintain", False, "trusted"),
        ("alice", "write", False, "trusted"),
        ("ext", "triage", False, "untrusted"),      # triage can't push -> not trusted
        ("ext", "read", False, "untrusted"),
        ("ext", "none", False, "untrusted"),
        ("ext", "read", True, "promoted"),           # maintainer 👍
        ("sparq-bot[bot]", "none", False, "trusted"),  # automation identity
        ("", "none", False, "untrusted"),            # missing author fails closed
    ]
    ok = True
    for author, perm, approved, want in cases:
        got = verdict(author, perm, approved, BOT)
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} author={author!r:16} perm={perm:9} approved={approved!s:5} -> {got} (want {want})")
    assert actionable("trusted") and actionable("promoted") and not actionable("untrusted")
    ok = _cli_exit_tests() and ok
    print("trust-gate self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="Untrusted-input safeguard (repo-permission based)")
    ap.add_argument("--author", default="")
    ap.add_argument("--permission", default="")
    ap.add_argument("--repo", default="")
    ap.add_argument("--fetch", action="store_true", help="fetch the author's repo permission via gh")
    ap.add_argument("--bot", default="", help="comma-separated automation identities")
    ap.add_argument("--maintainer-approved", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()
    # Fail closed on malformed invocations (sol r2 on registry #227): an absent author must
    # never combine with a supplied permission/approval into an actionable verdict, and the
    # permission source must be EXPLICIT — exactly one of --fetch (with --repo) or
    # --permission. An incomplete --fetch silently falling back to --permission recreated the
    # trusted-by-accident shape this gate exists to prevent.
    if not args.author.strip():
        print("error: --author is required and must be nonempty", file=sys.stderr)
        return 2
    if args.fetch:
        if not args.repo.strip():
            print("error: --fetch requires --repo", file=sys.stderr)
            return 2
        if args.permission:
            print("error: --fetch and --permission are mutually exclusive", file=sys.stderr)
            return 2
        perm = fetch_permission(args.repo, args.author)
    else:
        perm = args.permission
    bots = [b for b in args.bot.split(",") if b.strip()]
    v = verdict(args.author, perm, args.maintainer_approved, bots)
    print(v)
    return 0 if actionable(v) else 3


if __name__ == "__main__":
    sys.exit(main())
