#!/usr/bin/env python3
# [SPARQ agent] registry #1429: ONE owner for "the commit this pr-gate run graded is the FIRST
# PARENT of the checked-out refs/pull/N/merge".
"""graded_base.py — which base tip did this pr-gate run actually grade?

WHY THIS EXISTS (registry #1429 — the AGENTS.md §#958 shape). `pr-gate` checks out
`refs/pull/N/merge`, a synthetic commit GitHub composes as *merge <the pull request head> into
<the base tip>*. Its FIRST parent is therefore the base tip the run was graded against and its
SECOND is the pull request head — a fact observable ONLY from inside the run, which is why two
independent consumers re-derive it:

  * `gate-staleness.freshness` (#920) — is that tip still the live tip?
  * `compose-gate.compose` (#1304) — does `PR ⊕ the live tip` still pass?

Each carried its own `git rev-list --parents -n 1 HEAD`, its own `parents[1]`, its own
parent-count refusal and its own wording for it. One literal fact, two definitions, no owner: a
REPOINT (a different rev, a different flag, a different parent, a stricter refusal) would have to
be made in both at once, and #945 measured what that shape costs directly — two copies of one
guard make each copy INDIVIDUALLY UNKILLABLE, because removing either alone leaves the suite
green. The consumers' FAIL-CLOSED SHAPES still differ on purpose (`gate-staleness` reports
`unprovable` and exits 0; `compose-gate` blocks), and that divergence is per-consumer policy. The
DERIVATION underneath it is not, and it lives here.

WHAT THIS MODULE OWNS

  * `GRADED_BASE_ARGV` — the exact read-only git argv both consumers run. Sharing the parser
    while each consumer kept its own argv would leave the repoint half-done: `rev-list --parents`
    and, say, `rev-parse HEAD^1` answer the same question with different failure modes.
  * `graded_base(line)` — `(base_tip, composed_head, refusal)` for that command's output, with
    the parent-count rule written ONCE. It is PURE: the subprocess, the error type and the
    per-consumer verdict stay with the consumer, so this module runs no command and decides no
    gate.

FAIL-CLOSED, IN ONE DIRECTION ONLY. Anything that is not exactly a two-parent merge commit
yields a REFUSAL and no shas — never a base tip picked out of a shorter line. A single-parent
HEAD is what a `ref:` override on the checkout produces (both consumers pin against that at the
YAML seam), and reading `parents[1]` off a non-merge commit would silently hand back the pull
request's own head as though it were a base tip: `gate-staleness` would report FRESH on a tree it
never compared, and `compose-gate` would compose a PR with itself and call it CLEAN. Both are
fail-OPEN readings that let an arm proceed, which is why the count is checked before any index is
taken, and why the tokens are required to be 40-hex commit ids rather than merely three words.

THE RESIDUAL, NAMED. One sentence is still written twice — each consumer's "the checked-out commit
is unreadable (<git error>)". That is a fact about the SUBPROCESS, not about the derivation: the two
consumers run git through different helpers with different error types and fold the failure into
different verdicts, so owning it here would mean owning the subprocess, and this module would stop
being pure. The rule that has a REPOINT hazard — which command, which parent, and when to refuse —
is the one that lives here.

IT DOES NOT RAISE. A malformed or absent line comes back as a refusal string, because a helper
that raises aborts its caller's `--self-test` mid-run — and a crash records as a kill while every
check below it never runs (AGENTS.md pre-flight item 4).

NOT THE SAME FACT as `pr-gate.yml`'s `git merge-base "$base" HEAD`. That step derives the newest
BASE-BRANCH COMMIT THE GRADED TREE CONTAINS, to decide which self-test manifest is the protected
baseline (#1777, #1834). On a merge ref the two coincide, but they answer different questions —
one is "what tree was graded", the other is "what baseline may this branch be held to" — so it is
deliberately NOT routed through here.
"""
import re
import sys

# THE ONE QUESTION, asked ONE way. `git rev-list --parents -n 1 HEAD` prints a single line —
# `<commit> <parent>...`, every id full 40-hex — for the checked-out commit.
GRADED_BASE_ARGV = ("rev-list", "--parents", "-n", "1", "HEAD")

# GitHub composes the merge ref as `Merge <head> into <base>`, so parent 1 is the base tip and
# parent 2 is the pull request head. Token 0 is the merge commit itself.
_MERGE_TOKENS = 3
_BASE_PARENT = 1
_HEAD_PARENT = 2

_SHA_RE = re.compile(r"[0-9a-f]{40}")


def graded_base(rev_list_output):
    """PURE: `(base_tip, composed_head, refusal)` for one `GRADED_BASE_ARGV` output line.

    On success `refusal` is `""`. On ANY refusal both shas are `""` — a caller that reports a sha
    it was also given a reason to distrust is the fail-open this function exists to prevent — and
    `refusal` is the sentence the consumer puts in its own verdict. The parent COUNT is stated in
    it because that is the operator's whole diagnosis: `1 parent(s)` means the checkout is not the
    merge ref at all."""
    tokens = str(rev_list_output or "").split()
    if len(tokens) != _MERGE_TOKENS:
        return ("", "", f"the checked-out commit has {max(len(tokens) - 1, 0)} parent(s), so it is "
                        "not the two-parent refs/pull/N/merge commit this gate grades — no base "
                        "tip can be attributed to it")
    if not all(_SHA_RE.fullmatch(token) for token in tokens):
        return ("", "", "the checked-out commit's parent line is not three 40-hex commit ids "
                        f"({' '.join(tokens)[:96]!r}), so no base tip can be attributed to it")
    return (tokens[_BASE_PARENT], tokens[_HEAD_PARENT], "")


def _fixture_repo(root, git):
    """A real repository shaped exactly like a pr-gate checkout: HEAD detached at the two-parent
    merge of a feature head INTO a base tip, in GitHub's own orientation.

    The point of building it with git rather than hand-writing a line is AGENTS.md pre-flight 2b:
    an expected value read back out of the string under test proves only that `split()` works. Here
    the INPUT is real `git rev-list --parents` output and every EXPECTED sha is read independently
    through `git rev-parse` on a named ref, so the claim "parent 1 is the BASE" is measured rather
    than assumed."""
    shas = {}

    def commit(message, path, body):
        with open(f"{root}/{path}", "w", encoding="utf-8") as handle:
            handle.write(body)
        git(["add", "--", path])
        git(["commit", "-m", message])

    git(["init", "--initial-branch=master", "--quiet"])
    commit("base 0", "base.txt", "0\n")
    shas["base"] = git(["rev-parse", "master"])
    git(["checkout", "--quiet", "-b", "feature"])
    commit("pull request head", "head.txt", "head\n")
    shas["head"] = git(["rev-parse", "feature"])
    git(["checkout", "--quiet", "--detach", "master"])
    git(["merge", "--no-ff", "--no-edit", "-m", "Merge feature into master", shas["head"]])
    shas["merge"] = git(["rev-parse", "HEAD"])
    return shas


def _self_test():
    import os
    import subprocess
    import tempfile

    ok = True
    checks = 0

    def chk(name, got, want):
        nonlocal ok, checks
        checks += 1
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    def reports(name, line, want, reader=None):
        """A RAISE is a named FAIL row, never an abort — this module's callers run whole self-test
        suites underneath it (AGENTS.md pre-flight item 4)."""
        nonlocal ok, checks
        checks += 1
        try:
            got = (reader or graded_base)(line)
        except Exception as exc:                     # noqa: BLE001 — a raise IS the finding here
            got = f"RAISED {type(exc).__name__}"
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    # ---- the argv is PINNED against a hand-written literal ---------------------------------------
    # Transcribed by hand, NOT built from the constant: both consumers hand this to `git`, so a
    # silent repoint here changes what two gates measure. `rev-parse HEAD^1` would be a different
    # command with a different failure mode, and `-n 1` is what keeps the output ONE line.
    chk("the shared argv is exactly the documented read-only git command",
        list(GRADED_BASE_ARGV), ["rev-list", "--parents", "-n", "1", "HEAD"])

    # ---- REAL GIT, in a real pr-gate-shaped repository -------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        repo = os.path.join(tmp, "repo")
        os.mkdir(repo)
        env = dict(os.environ, HOME=tmp,
                   GIT_CONFIG_GLOBAL=os.path.join(tmp, "no-such-gitconfig"),
                   GIT_CONFIG_SYSTEM=os.path.join(tmp, "no-such-gitconfig"),
                   GIT_AUTHOR_NAME="selftest", GIT_AUTHOR_EMAIL="selftest@example.invalid",
                   GIT_COMMITTER_NAME="selftest", GIT_COMMITTER_EMAIL="selftest@example.invalid",
                   GIT_AUTHOR_DATE="2026-09-02T00:00:00+00:00",
                   GIT_COMMITTER_DATE="2026-09-02T00:00:00+00:00")

        def git(args):
            proc = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True,
                                  env=env)
            if proc.returncode != 0:
                raise RuntimeError(f"git {args[0]} failed: {(proc.stderr or '').strip()[:200]}")
            return proc.stdout.strip()

        def rev_list():
            """The module's OWN argv, run in the fixture — with a git failure turned into a VALUE.

            A mutant that repoints `GRADED_BASE_ARGV` at a rev that does not always resolve (say
            `HEAD^2`) makes git exit non-zero, and an exception here would ABORT this suite with
            the rows below never run and no roll-up printed — which records as a kill while
            measuring nothing (AGENTS.md pre-flight item 4). Returned as text, it refuses through
            the ordinary path and reds NAMED rows with the check count intact."""
            try:
                return git(list(GRADED_BASE_ARGV))
            except RuntimeError as exc:
                return f"GIT-FAILED {exc}"

        sha = _fixture_repo(repo, git)
        chk("CONTROL: the fixture's base tip and head are DIFFERENT commits, so reading the wrong "
            "parent cannot pass the rows below by coincidence",
            sha["base"] == sha["head"], False)

        # THE LOAD-BEARING ROW. Input: real `git rev-list --parents` output, produced by running
        # the module's OWN argv. Expected: the two shas read independently off named refs.
        chk("the module's own argv, run against a pr-gate-shaped checkout, yields the BASE tip as "
            "parent 1 and the pull request HEAD as parent 2",
            graded_base(rev_list()), (sha["base"], sha["head"], ""))
        chk("...and the merge commit itself is NOT reported as either operand",
            sha["merge"] in graded_base(rev_list())[:2], False)

        # The two REACHABLE non-merge checkouts, driven through real git rather than a hand-written
        # short line: a `ref:` override on the gate's checkout produces the first, and an
        # (unreachable here, but stated) root commit the second. Each must name its OWN count, so a
        # constant in place of `len(tokens) - 1` reds.
        git(["checkout", "--quiet", "--detach", sha["head"]])
        chk("a single-parent HEAD — what a `ref:` override checks out — refuses, names 1 parent, "
            "and hands back NO shas",
            graded_base(rev_list())[:2] + ("1 parent(s)" in graded_base(rev_list())[2],),
            ("", "", True))
        git(["checkout", "--quiet", "--detach", sha["base"]])
        chk("a root-commit HEAD refuses, and names 0 parents (not 1 — the count is the real one)",
            ("0 parent(s)" in graded_base(rev_list())[2],
             "1 parent(s)" in graded_base(rev_list())[2]), (True, False))

    # ---- the PURE reject direction, on shapes real git cannot cheaply be made to emit -------------
    A, B, C = "a" * 40, "b" * 40, "c" * 40
    reports("an octopus merge (3 parents) is NOT the merge ref, and says 3",
            f"{A} {B} {C} {'d' * 40}",
            ("", "", "the checked-out commit has 3 parent(s), so it is not the two-parent "
                     "refs/pull/N/merge commit this gate grades — no base tip can be attributed "
                     "to it"))
    for label, line in (("an empty line", ""), ("whitespace only", "   \n  "),
                        ("None", None), ("a non-string", 1429), ("a bare commit id", A)):
        got = graded_base(line)
        reports(f"{label} refuses with no shas", line, ("", "", got[2]))
        chk(f"...and {label}'s refusal is non-empty and names a parent count", bool(got[2]), True)
    # A THREE-WORD line that is not three commit ids. Every one of these satisfies a count-only
    # check, so this is the row that keeps the hex requirement load-bearing.
    for label, line in (("abbreviated ids", "abc123 def456 789abc"),
                        ("a 39-hex parent", f"{A} {'b' * 39} {C}"),
                        ("an UPPERCASE parent", f"{A} {'B' * 40} {C}"),
                        ("a git error line", "fatal: bad revision")):
        got = graded_base(line)
        chk(f"a three-word line with {label} refuses, with no shas and a reason of its own",
            (got[0], got[1], got[2] != "" and "parent(s)" not in got[2]), ("", "", True))

    def _raising_reader(_line):
        raise RuntimeError("this reader is broken")

    # POSITIVE CONTROL for every `reports` row above: they are the only rows here asserting an
    # ABSENCE of raising, so a harness that silently swallowed a raise would pass them while
    # measuring nothing. Drive the same harness with a reader that DOES raise and require the raise
    # to come back as a VALUE — i.e. those rows read `graded_base`'s behaviour, not the harness's.
    reports("CONTROL: a reader that RAISES becomes a named row, it does not abort this suite",
            f"{A} {B} {C}", "RAISED RuntimeError", reader=_raising_reader)

    # ---- the ORIENTATION is asymmetric, so swapping the two indices cannot pass -------------------
    chk("parent 1 is the base and parent 2 is the head, never the other way round",
        graded_base(f"{C} {A} {B}"), (A, B, ""))
    chk("...and the accept path reports NO refusal (the row above would also hold with one)",
        graded_base(f"{C} {A} {B}")[2], "")

    # ---- the ENTRY POINT, which nothing above reaches (AGENTS.md pre-flight item 1) ---------------
    _argv = sys.argv
    try:
        sys.argv = ["graded_base.py"]
        chk("`main` without --self-test summarises the module and exits 0 (it runs no command and "
            "decides no gate)", main(), 0)
    finally:
        sys.argv = _argv

    print("graded_base self-test", "PASSED" if ok else "FAILED", f"({checks} checks)")
    return 0 if ok else 1


def main():
    if "--self-test" in sys.argv:
        return _self_test()
    print(__doc__.strip().splitlines()[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
