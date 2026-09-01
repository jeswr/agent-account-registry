#!/usr/bin/env python3
# [SPARQ agent] A STANDING detector that the published `ledger` branch has not re-acquired a raw
# account identity (registry #1092).
#
# #212 stopped the writers emitting raw handles and #536 added `scripts/ledger-history-purge.py`,
# whose `scan` subcommand walks every reachable ledger commit in about a second with no token and
# no `gh`. Nothing ran it on a schedule. A one-shot purge is a POINT measurement: after it, a new
# writer that skips `account_fingerprint`, a hand-edited snapshot, or a restored old branch would
# sit PUBLISHED until somebody thought to look. This is the standing form of that measurement.
#
# ⚠️ DEPLOYMENT ORDER. The scanner is not on the default branch yet, so the workflow ships with
# `workflow_dispatch` and NO `schedule:`, and `_test_workflow_seam` reds if a cron appears while
# the scanner is absent. `unverified` is the correct answer for a tick that cannot measure; it is
# not a correct thing to schedule daily forever, because an alert nothing can clear is a false
# alarm on the channel real exposures arrive on. Runtime polarity and deployment readiness are
# separate questions and this module answers both.
#
# ⚠️ THIS SCRIPT OWNS NO DETECTION RULE. The definition of "raw account identity" lives in exactly
# one place — `ledger-history-purge.py` — and is invoked as a SUBPROCESS, never re-derived here.
# A second copy of that rule is the #958 shape (four independent definitions of one literal, two
# consumers blind to a repoint); every gap between the copies would be a FALSE GREEN on a trust
# surface. What this script owns is the TRANSPORT and the FAIL-CLOSED POLARITY.
#
# THE POLARITY IS THE WHOLE POINT. There are three verdicts, not two:
#
#   clean       the scanner ran, over a full history, and found nothing            -> may close
#   exposed     the scanner ran and found raw identity                             -> alert
#   unverified  the scanner did not run, or did not complete, or cannot be trusted -> alert
#
# `unverified` exists because the absence of evidence of exposure is NOT evidence of cleanliness.
# A detector that treats "could not measure" as "healthy" closes its own alert on exactly the tick
# its subject broke — the silent-disarm failure plan-alert.py's close-only-on-explicit-health rule
# was written for. Three concrete false-green vectors are refused BY NAME in `preflight`:
#
#   1. the scanner is absent from the checkout (it is a sibling script, not a vendored copy);
#   2. the ledger clone is SHALLOW — a scan of a truncated history calls every commit it cannot
#      reach clean, so an `actions/checkout` that lost `fetch-depth: 0` would report a green
#      ledger forever. This is the single most likely way this lane goes quietly useless;
#   3. the ref does not resolve to a commit.
#
# ...plus a fourth in `classify`: the scanner must pass its OWN `--self-test` before its verdict is
# believed. A scanner that cannot prove itself may not certify the ledger.
#
# WHAT CROSSES THE PUBLIC SINK. The alert issue and the Actions log are public. The scanner's
# STDOUT is the report and is safe by its own construction — counts plus object SHAs, with handles
# counted and never named — so it is published verbatim (bounded). The scanner's STDERR is the
# error channel and carries no such contract, so it is NEVER read: `_capture` does not touch it,
# and the self-test enforces that structurally, off the AST, rather than by convention.
#
# SCOPE + AUTHORITY. This script may create/edit/comment/close exactly ONE `ops-alert` issue and
# nothing else. It writes no ledger, applies no orchestration label, touches no PR, and arms
# nothing — all three enforced structurally by the self-test.
"""ledger-identity-watch — standing detector for raw account identity on the `ledger` branch."""

import argparse
import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
SCANNER_NAME = "ledger-history-purge.py"
WORKFLOW_PATH = ".github/workflows/ledger-identity-watch.yml"

# The scanner's documented exit codes. Only `0` is believed; the DECISION never depends on telling
# 1 from 2 (both alert) — the code selects the WORDING, not the polarity.
SCAN_CLEAN_RC = 0
SCAN_EXPOSED_RC = 1

CLEAN = "clean"
EXPOSED = "exposed"
UNVERIFIED = "unverified"

ALERT_LABEL = "ops-alert"
ALERT_TITLE = "⚠️ The ledger branch is not proven free of raw account identity"
# Stable marker: it is the dedupe key, so renaming it orphans every open alert.
ALERT_MARKER = "<!-- ledger-identity-watch:v1 key=ledger-raw-identity -->"

# The report is bounded before it is published: the scanner caps its SHA lists at ten each, but a
# future widening must not be able to paste an unbounded blob into an issue body.
REPORT_MAX_LINES = 40
REPORT_MAX_CHARS = 4000


class LedgerWatchError(Exception):
    """A self-test input or invariant that must abort loudly rather than stop asserting."""


def _repo_root():
    return SCRIPTS_DIR.parent


def _require(path):
    """Read a file the self-test asserts against. FAIL CLOSED: a missing input aborts the self-test
    loudly rather than making its assertions quietly unreachable."""
    full = _repo_root() / path
    if not full.is_file():
        raise LedgerWatchError(
            f"self-test input {path} is missing from the working copy at {_repo_root()} — the "
            "YAML-seam assertions cannot run, and a self-test that silently stops asserting is "
            "worse than no self-test")
    return full.read_text(encoding="utf-8")


def scanner_path(scripts_dir=None):
    return str(Path(scripts_dir or SCRIPTS_DIR) / SCANNER_NAME)


def _capture(cmd, runner=None):
    """-> (returncode, stdout). `stderr` is deliberately NOT read; see the module header.

    `subprocess.run` is resolved at CALL time, never bound as a default argument: a default binds
    the function OBJECT at definition and would escape any patching a harness installs — the exact
    shape that let a "faked" suite issue real writes twice in one night.
    """
    run = subprocess.run if runner is None else runner
    result = run(cmd, capture_output=True, text=True)
    return result.returncode, (result.stdout or "")


def preflight(repo, ref, scanner, runner=None):
    """The reason this tick CANNOT be measured, or None when it can.

    Every branch here is a way a scan reports `clean` while measuring nothing.
    """
    if not os.path.isfile(scanner):
        return (f"the scanner `scripts/{SCANNER_NAME}` is not present in this checkout, so nothing "
                "measured the ledger branch this tick")
    rc, shallow = _capture(["git", "-C", repo, "rev-parse", "--is-shallow-repository"], runner)
    if rc != 0:
        return f"`{repo}` is not a readable git clone of the ledger branch (git rc={rc})"
    if shallow.strip() != "false":
        return (f"the clone at `{repo}` is SHALLOW — a scan of a truncated history calls every "
                "commit it cannot reach clean, so this tick proves nothing")
    rc, _ = _capture(
        ["git", "-C", repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"], runner)
    if rc != 0:
        return f"ref `{ref}` does not resolve to a commit in `{repo}`"
    return None


def run_scan(scanner, repo, ref, runner=None):
    """-> (selftest_rc, scan_rc|None, report). The scanner certifies ITSELF before it certifies the
    ledger; when it cannot, the scan is not run at all and `scan_rc` is None."""
    selftest_rc, _ = _capture(["python3", scanner, "--self-test"], runner)
    if selftest_rc != 0:
        return selftest_rc, None, ""
    scan_rc, report = _capture(
        ["python3", scanner, "scan", "--repo", repo, "--ref", ref], runner)
    return selftest_rc, scan_rc, report


def classify(preflight_reason, selftest_rc, scan_rc):
    """-> (verdict, reasons). `clean` requires a POSITIVE result from a scanner that proved itself
    over a full history; everything else is `unverified`, never silence."""
    if preflight_reason:
        return UNVERIFIED, [preflight_reason]
    if selftest_rc != SCAN_CLEAN_RC:
        return UNVERIFIED, [f"`{SCANNER_NAME} --self-test` failed (rc={selftest_rc}) — a scanner "
                            "that cannot prove itself may not certify the ledger"]
    if scan_rc == SCAN_CLEAN_RC:
        return CLEAN, []
    if scan_rc == SCAN_EXPOSED_RC:
        return EXPOSED, [f"`{SCANNER_NAME} scan` reports raw account identity still reachable from "
                         "the ledger branch"]
    return UNVERIFIED, [f"`{SCANNER_NAME} scan` exited rc={scan_rc} — the walk did not complete, "
                        "so the branch is unmeasured this tick"]


def decide(verdict, has_open_alert):
    """Pure: 'upsert' | 'close' | 'noop'.

    Close ONLY on an explicit `clean`. `unverified` deliberately shares the `exposed` path: an
    alert that closes when its detector broke is worse than no alert, because a reader who trusts
    a closed alert stops looking.
    """
    if verdict != CLEAN:
        return "upsert"
    if has_open_alert:
        return "close"
    return "noop"


def excerpt(text, max_lines=REPORT_MAX_LINES, max_chars=REPORT_MAX_CHARS):
    """The scanner's report, bounded for a public sink. Truncation is ANNOUNCED, never silent."""
    lines = (text or "").strip().splitlines()
    trimmed = lines[:max_lines]
    body = "\n".join(trimmed)[:max_chars]
    if len(lines) > len(trimmed) or len(body) < len("\n".join(trimmed)):
        body += f"\n… truncated ({len(lines)} lines total)"
    return body


def render_body(repo_slug, ref, verdict, reasons, report, run_url, maintainer):
    listed = "\n".join(f"- {reason}" for reason in reasons) or "- (none)"
    shown = excerpt(report)
    return "\n".join([
        ALERT_MARKER,
        "> 🤖 SPARQ agent — automated ops-alert (ledger raw-account-identity watch)",
        "",
        f"**The `{ref}` branch of `{repo_slug}` is NOT proven free of raw account identity.** "
        f"Verdict: **`{verdict}`**.",
        "",
        "Why:",
        listed,
        "",
        "⚠️ **`unverified` is an alert, not a pass.** This detector reports `clean` only when "
        f"`scripts/{SCANNER_NAME} scan` completed over a FULL (non-shallow) history after passing "
        "its own `--self-test`. If it could not measure, it says so here rather than closing — the "
        "absence of evidence of exposure is not evidence of cleanliness.",
        "",
        "**What is needed:** re-run the scan locally against a full clone "
        f"(`python3 scripts/{SCANNER_NAME} scan --repo <clone> --ref {ref}`). If it reports "
        "exposures, the maintainer-run purge runbook (`rewrite`) is the remedy and the writer that "
        "re-introduced the raw identity is the root cause; if it reports none, this lane's own "
        "wiring is what broke.",
        "",
        "Scanner report (counts and object SHAs only — handles are counted, never named):",
        "",
        "```",
        shown or "(the scanner produced no report)",
        "```",
        "",
        f"Run: {run_url}" if run_url else "",
        f"cc @{maintainer}",
    ])


def _gh(args, capture=False, token=None, check=False):
    # Sanitized fail-loud wrapper: op + returncode only — never stderr (GH_DEBUG=api can echo
    # request bodies) and never argument content beyond the gh subcommand words.
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    result = subprocess.run(["gh"] + args, capture_output=capture, text=True, env=env)
    if check and result.returncode != 0:
        print(f"::warning::ledger-identity-watch: gh {args[0]} "
              f"{args[1] if len(args) > 1 else ''} failed (rc={result.returncode})")
    return result


def _alert_route(alert_repo, alert_token, registry_repo):
    """(repo, token) — identical semantics to groom-alert/usage-alert/park-stock-alert: the private
    ALERT_REPO only when ALERT_TOKEN is present; otherwise the registry repo under the ambient
    token."""
    if alert_repo and alert_token:
        return alert_repo, alert_token
    return registry_repo, None


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    # The workflow-seam self-test scans for exactly this declaration, so it must stay an argparse
    # option and not a hand-rolled sys.argv check.
    parser.add_argument("--self-test", action="store_true",
                        help="run the hermetic self-test and exit")
    parser.add_argument("--repo", default="ledger",
                        help="path to a LOCAL, FULL clone of the ledger branch")
    parser.add_argument("--ref", default="ledger", help="the ledger ref to scan")
    return parser


def main(argv=None):
    args = build_parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    if args.self_test:
        return _self_test()

    scanner = scanner_path()
    reason = preflight(args.repo, args.ref, scanner)
    selftest_rc, scan_rc, report = SCAN_CLEAN_RC, None, ""
    if reason is None:
        selftest_rc, scan_rc, report = run_scan(scanner, args.repo, args.ref)
    verdict, reasons = classify(reason, selftest_rc, scan_rc)

    print(f"ledger-identity-watch: verdict={verdict} ref={args.ref}")
    for line in excerpt(report).splitlines():
        print(f"  | {line}")

    registry_repo = os.environ["REGISTRY_REPO"]
    repo, token = _alert_route(
        os.environ.get("ALERT_REPO"), os.environ.get("ALERT_TOKEN"), registry_repo)
    run_url = os.environ.get("RUN_URL", "")
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")

    listed = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", "open",
                  "--json", "number,title,body", "--limit", "100"],
                 capture=True, token=token, check=True)
    if listed.returncode != 0:
        return 1
    try:
        found = json.loads(listed.stdout or "[]")
        if not isinstance(found, list):
            raise ValueError("expected a JSON array")
    except ValueError:
        # FAIL CLOSED. `gh` exited 0 but the alert board is unreadable, so this tick has no dedupe
        # or recovery state. Returning 0 here would record the detector as HEALTHY on a tick that
        # delivered no alert at all — and on a first `exposed`/`unverified` tick there is no
        # pre-existing issue left visible to carry the signal, so the whole measurement would
        # evaporate behind a green run. A failed run is retried and is visible; a green silent one
        # is neither. The payload itself is never echoed: it is `gh` output bound for a public log.
        print("::error::ledger-identity-watch: gh issue list succeeded but returned unparseable "
              "JSON — refusing to decide on an alert board we could not read (no mutation)")
        return 1
    num = next((row["number"] for row in found
                if isinstance(row, dict) and ALERT_MARKER in (row.get("body") or "")), None)
    if num is None:
        num = next((row["number"] for row in found
                    if isinstance(row, dict) and row.get("title") == ALERT_TITLE), None)

    action = decide(verdict, num is not None)
    if action == "upsert":
        _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", "d73a4a",
             "--description", "Autonomous ops alert (maintainer action)"],
            capture=True, token=token)  # idempotent
        body = render_body(registry_repo, args.ref, verdict, reasons, report, run_url, maintainer)
        if num:
            wrote = _gh(["issue", "edit", str(num), "-R", repo, "--body", body],
                        capture=True, token=token, check=True)
        else:
            wrote = _gh(["issue", "create", "-R", repo, "--title", ALERT_TITLE,
                         "--label", ALERT_LABEL, "--body", body],
                        capture=True, token=token, check=True)
        if wrote.returncode != 0:
            return 1
        print(f"::warning::ledger-identity-watch: {'; '.join(reasons)} — maintainer alerted")
        return 0
    if action == "close":
        commented = _gh(["issue", "comment", str(num), "-R", repo, "--body",
                         f"✅ Recovered — `{args.ref}` scanned clean over a full history. "
                         "Auto-closing."], capture=True, token=token, check=True)
        closed = _gh(["issue", "close", str(num), "-R", repo], capture=True, token=token,
                     check=True)
        if commented.returncode != 0 or closed.returncode != 0:
            return 1
        print("ledger-identity-watch: ledger scanned clean — closed the alert")
        return 0
    print("ledger-identity-watch: ledger scanned clean, no open alert — nothing to do")
    return 0


# ------------------------------------------------------------------------------------------------
# HERMETIC SELF-TEST — no network, no `gh`, no real scanner invocation.
def _self_test():
    failures = []

    def chk(name, got, want=True):
        ok = got == want
        print(f"  {'ok  ' if ok else 'FAIL'} {name}: {got!r}" + ("" if ok else f" (want {want!r})"))
        if not ok:
            failures.append(name)

    _test_preflight(chk)
    _test_classify(chk)
    _test_decide(chk)
    _test_body(chk)
    _test_main_flows(chk)
    _test_structural_authority(chk)
    _test_workflow_seam(chk)

    print(("ledger-identity-watch self-test: FAIL " + ", ".join(failures)) if failures
          else "ledger-identity-watch self-test: PASS")
    return 1 if failures else 0


class _FakeResult:
    def __init__(self, rc=0, stdout=""):
        self.returncode = rc
        self.stdout = stdout
        # Every fake carries a sentinel on the channel this module must never read. If any reason,
        # log line, or issue body ever contains it, something started reading stderr.
        self.stderr = "SENTINEL-STDERR-must-never-be-published"


def _fake_git(shallow="false", rev_parse_rc=0, is_shallow_rc=0):
    """A runner that answers only the two git probes `preflight` makes."""
    def runner(cmd, capture_output=False, text=False, env=None):
        if "--is-shallow-repository" in cmd:
            return _FakeResult(is_shallow_rc, shallow + "\n")
        if "--verify" in cmd:
            return _FakeResult(rev_parse_rc, "")
        raise LedgerWatchError(f"unexpected command in the preflight fake: {cmd!r}")
    return runner


def _test_preflight(chk):
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ledger-identity-watch-") as tmp:
        present = os.path.join(tmp, SCANNER_NAME)
        with open(present, "w", encoding="utf-8") as handle:
            handle.write("# a stand-in for the scanner; preflight only checks that it EXISTS\n")
        absent = os.path.join(tmp, "no-such-scanner.py")

        # ---- THE CONTROL: a full clone with a resolvable ref is measurable -----------------------
        # Without this row every assertion below is satisfied by a preflight that refuses
        # unconditionally — which would alert forever and teach an operator to ignore the lane.
        chk("[CONTROL] scanner present + non-shallow clone + resolvable ref -> measurable (None)",
            preflight("ledger", "ledger", present, _fake_git()), None)

        # ---- THE RED ROWS: each is a distinct way a scan reports clean having measured nothing ---
        chk("[RED] a MISSING scanner is unmeasurable, not clean",
            "is not present in this checkout" in (preflight("ledger", "ledger", absent,
                                                            _fake_git()) or ""))
        chk("[RED] a SHALLOW clone is unmeasurable (this is what a lost `fetch-depth: 0` looks "
            "like, and it is the vector that would make this lane green forever)",
            "SHALLOW" in (preflight("ledger", "ledger", present, _fake_git(shallow="true")) or ""))
        chk("[RED] an unreadable clone is unmeasurable",
            "not a readable git clone" in (preflight("ledger", "ledger", present,
                                                     _fake_git(is_shallow_rc=128)) or ""))
        chk("[RED] an unresolvable ref is unmeasurable",
            "does not resolve to a commit" in (preflight("ledger", "nope", present,
                                                         _fake_git(rev_parse_rc=1)) or ""))
        # `--is-shallow-repository` printing anything OTHER than the two documented words must fail
        # closed too: a future git (or a wrapper) that answers "unknown" may not be read as full.
        chk("an UNRECOGNISED shallowness answer fails closed, it is not treated as full",
            "SHALLOW" in (preflight("ledger", "ledger", present,
                                    _fake_git(shallow="unknown")) or ""))

        # The probes are asserted by SHAPE, not assumed: a preflight that stopped passing `-C repo`
        # would silently probe the CONTROL-PLANE checkout (which is never shallow) and pass.
        seen = []

        def recording(cmd, capture_output=False, text=False, env=None):
            seen.append(list(cmd))
            return _FakeResult(0, "false\n")

        preflight("some/clone", "some-ref", present, recording)
        chk("both git probes are scoped to the clone under test with `-C <repo>`",
            [cmd[:3] for cmd in seen],
            [["git", "-C", "some/clone"], ["git", "-C", "some/clone"]])
        chk("...and the ref probe asks for the REF ARGUMENT, peeled to a commit",
            seen[1][-1], "some-ref^{commit}")


def _test_classify(chk):
    # A scanner-absent preflight reason dominates every other input.
    chk("preflight reason -> unverified, carrying that reason",
        classify("a stated reason", 0, 0), (UNVERIFIED, ["a stated reason"]))
    chk("[RED] a scanner that fails its OWN self-test cannot certify the ledger",
        classify(None, 3, 0)[0], UNVERIFIED)
    chk("a completed scan with no exposures is the ONLY clean verdict",
        classify(None, 0, 0), (CLEAN, []))
    chk("[RED] exposures -> exposed", classify(None, 0, 1)[0], EXPOSED)
    chk("a scan that DIED (rc=2) is unverified, never clean", classify(None, 0, 2)[0], UNVERIFIED)
    chk("an unrun scan (scan_rc None) is unverified, never clean",
        classify(None, 0, None)[0], UNVERIFIED)
    # The decision must not depend on telling 1 from 2: only rc 0 is believed. A future scanner
    # that renumbered its exit codes must still alert on every one of them.
    chk("EVERY non-zero scan rc alerts — the exit code selects the wording, not the polarity",
        sorted({classify(None, 0, rc)[0] for rc in (1, 2, 3, 127, -9)}), [EXPOSED, UNVERIFIED])
    chk("every non-clean verdict states at least one reason (a silent alert body is not an alert)",
        [classify(*row)[1] for row in (("r", 0, 0), (None, 1, None), (None, 0, 1), (None, 0, 9))
         if not classify(*row)[1]], [])


def _test_decide(chk):
    chk("exposed -> upsert", decide(EXPOSED, False), "upsert")
    chk("exposed with an open alert -> upsert (edit in place, never a duplicate)",
        decide(EXPOSED, True), "upsert")
    chk("[RED] unverified with an open alert -> upsert, NOT close — a detector that closes its own "
        "alert when it could not measure disarms on exactly the tick that matters",
        decide(UNVERIFIED, True), "upsert")
    chk("unverified with no alert -> upsert", decide(UNVERIFIED, False), "upsert")
    chk("clean with an open alert -> close", decide(CLEAN, True), "close")
    chk("clean with no alert -> noop", decide(CLEAN, False), "noop")
    # An unknown verdict string must alert, not fall through to `close`. `decide` is written as
    # `!= CLEAN` rather than `in (EXPOSED, UNVERIFIED)` precisely so a new verdict fails closed.
    chk("an UNKNOWN verdict fails closed to upsert", decide("something-new", True), "upsert")
    chk("...and `clean` is the exact literal that opens the close path (a typo'd verdict alerts)",
        (decide("Clean", True), decide("clean ", True)), ("upsert", "upsert"))


def _test_body(chk):
    report = "ledger-history-purge scan: ref ledger\n  commits examined: 20460"
    body = render_body("o/r", "ledger", UNVERIFIED, ["a stated reason"], report, "http://run", "me")
    # The marker is asserted as a LITERAL, not against the constant it is built from: comparing a
    # module's output to the constant it writes from is a tautology that cannot fail.
    chk("the body carries the stable dedupe marker, verbatim",
        "<!-- ledger-identity-watch:v1 key=ledger-raw-identity -->" in body)
    chk("...and that literal IS the module's marker (one definition, asserted from outside)",
        ALERT_MARKER, "<!-- ledger-identity-watch:v1 key=ledger-raw-identity -->")
    chk("the body names the verdict", "`unverified`" in body)
    chk("the body names the ref and the repo", "`ledger`" in body and "`o/r`" in body)
    chk("the body states every reason", "a stated reason" in body)
    chk("the body carries the scanner's report", "commits examined: 20460" in body)
    chk("the body says plainly that `unverified` is not a pass",
        "is an alert, not a pass" in body)
    chk("the body carries the model-agnostic SPARQ self-ID", "> 🤖 SPARQ agent" in body)
    chk("the run URL and the maintainer mention are present",
        "http://run" in body and "@me" in body)

    # Bounding, and the ANNOUNCEMENT of it: a silently truncated report reads as a complete one.
    long_report = "\n".join(f"line {n}" for n in range(200))
    trimmed = excerpt(long_report)
    chk("a long report is bounded to REPORT_MAX_LINES", len(trimmed.splitlines()),
        REPORT_MAX_LINES + 1)
    chk("...and the truncation is ANNOUNCED with the real total", "(200 lines total)" in trimmed)
    chk("a short report is passed through whole, with nothing appended",
        excerpt("a\nb"), "a\nb")
    chk("a report longer than REPORT_MAX_CHARS is cut by characters too, and announced",
        len(excerpt("x" * 9000)) < 9000 and "truncated" in excerpt("x" * 9000))
    chk("an EMPTY report renders a stated placeholder rather than an empty fence",
        "(the scanner produced no report)" in
        render_body("o/r", "ledger", UNVERIFIED, ["r"], "", "", "me"))


def _test_main_flows(chk):
    """Full `main()` paths under a fake `subprocess.run` that records every command. Entry points
    are where fabricating bugs survive, so the flows are driven end-to-end rather than asserted
    about."""
    import contextlib
    import io
    import tempfile

    calls = []
    envs = []
    plan = {}

    def fake_run(cmd, capture_output=False, text=False, env=None):
        calls.append(list(cmd))
        envs.append(dict(env or {}))
        if cmd[0] == "git":
            if "--is-shallow-repository" in cmd:
                return _FakeResult(0, plan.get("shallow", "false") + "\n")
            return _FakeResult(plan.get("rev_parse_rc", 0), "")
        if cmd[0] == "python3":
            if "--self-test" in cmd:
                return _FakeResult(plan.get("scanner_selftest_rc", 0), "")
            return _FakeResult(plan.get("scan_rc", 0), plan.get("report", "report line"))
        if cmd[0] == "gh":
            key = tuple(cmd[1:3])
            if key == ("issue", "list"):
                return _FakeResult(plan.get("list_rc", 0), plan.get("list_json", "[]"))
            return _FakeResult(1 if key in plan.get("fail", ()) else 0, "")
        raise LedgerWatchError(f"unexpected command in the main() fake: {cmd!r}")

    def gh_subs():
        return [tuple(cmd[1:3]) for cmd in calls if cmd[0] == "gh"]

    def gh_args():
        return [" ".join(str(word) for word in cmd) for cmd in calls if cmd[0] == "gh"]

    def gh_env(sub):
        return next((env for cmd, env in zip(calls, envs)
                     if cmd[0] == "gh" and tuple(cmd[1:3]) == sub), {})

    def run_main(scanner_present=True, alert_repo="", alert_token="", **kwargs):
        calls.clear()
        envs.clear()
        plan.clear()
        os.environ["ALERT_REPO"] = alert_repo
        os.environ["ALERT_TOKEN"] = alert_token
        plan.update(kwargs)
        with tempfile.TemporaryDirectory(prefix="ledger-identity-watch-main-") as tmp:
            if scanner_present:
                with open(os.path.join(tmp, SCANNER_NAME), "w", encoding="utf-8") as handle:
                    handle.write("# stand-in\n")
            saved_dir, saved_argv = globals()["SCRIPTS_DIR"], sys.argv
            globals()["SCRIPTS_DIR"] = Path(tmp)
            sys.argv = ["ledger-identity-watch.py", "--repo", "ledger", "--ref", "ledger"]
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    rc = main()
            finally:
                globals()["SCRIPTS_DIR"] = saved_dir
                sys.argv = saved_argv
        return rc, buf.getvalue()

    real_run = subprocess.run
    saved_env = {key: os.environ.get(key) for key in
                 ("REGISTRY_REPO", "ALERT_REPO", "ALERT_TOKEN", "RUN_URL", "MAINTAINER_HANDLE")}
    open_alert = json.dumps([{"number": 7, "title": ALERT_TITLE, "body": ALERT_MARKER}])
    subprocess.run = fake_run
    os.environ.update({"REGISTRY_REPO": "o/registry", "ALERT_REPO": "", "ALERT_TOKEN": "",
                       "RUN_URL": "http://run", "MAINTAINER_HANDLE": "jeswr"})
    try:
        # ---- the scanner is invoked EXACTLY as documented, self-test first --------------------
        run_main()
        chk("main runs the scanner's own --self-test BEFORE the scan, and passes the CLI's --repo "
            "and --ref straight through to `scan`",
            [cmd[2:] for cmd in calls if cmd[0] == "python3"],
            [["--self-test"], ["scan", "--repo", "ledger", "--ref", "ledger"]])

        # ---- clean ---------------------------------------------------------------------------
        rc, out = run_main(list_json=open_alert)
        chk("clean + open alert -> comment + close",
            (rc, ("issue", "comment") in gh_subs(), ("issue", "close") in gh_subs()),
            (0, True, True))
        rc, _ = run_main()
        chk("clean + no alert -> NO mutation at all",
            (rc, [sub for sub in gh_subs() if sub != ("issue", "list")]), (0, []))

        # ---- exposed -------------------------------------------------------------------------
        rc, out = run_main(scan_rc=1)
        chk("exposed + no alert -> create", (rc, ("issue", "create") in gh_subs()), (0, True))
        rc, _ = run_main(scan_rc=1, list_json=open_alert)
        chk("exposed + open alert -> edit, never a second issue",
            (rc, ("issue", "edit") in gh_subs(), ("issue", "create") in gh_subs()),
            (0, True, False))
        # DEDUPE is a PAIR of independent matchers, and the fixture above satisfies BOTH — so each
        # is asserted alone, with the other made unable to rescue it. Two copies of one guard make
        # each copy individually unkillable; that is what these two rows exist to prevent.
        marker_only = json.dumps([{"number": 7, "title": "a hand-edited title", "body":
                                   "<!-- ledger-identity-watch:v1 key=ledger-raw-identity -->"}])
        title_only = json.dumps([{"number": 7, "title": ALERT_TITLE, "body": "no marker here"}])
        rc, _ = run_main(scan_rc=1, list_json=marker_only)
        chk("dedupe by MARKER alone — a retitled alert is still found, so a renamed title cannot "
            "orphan it into a duplicate",
            (rc, ("issue", "edit") in gh_subs(), ("issue", "create") in gh_subs()),
            (0, True, False))
        rc, _ = run_main(scan_rc=1, list_json=title_only)
        chk("dedupe by TITLE alone — a pre-marker alert is still found",
            (rc, ("issue", "edit") in gh_subs(), ("issue", "create") in gh_subs()),
            (0, True, False))
        rc, _ = run_main(scan_rc=1, list_json=json.dumps(
            [{"number": 7, "title": "some other ops-alert", "body": "unrelated"}]))
        chk("...and an UNRELATED ops-alert matches neither — it is not hijacked",
            (rc, ("issue", "create") in gh_subs(), ("issue", "edit") in gh_subs()),
            (0, True, False))

        # ---- THE FAIL-CLOSED ROWS: an unmeasurable tick may never close ------------------------
        for label, kwargs in (
                ("the scanner is absent", {"scanner_present": False}),
                ("the clone is shallow", {"shallow": "true"}),
                ("the ref does not resolve", {"rev_parse_rc": 1}),
                ("the scanner fails its own self-test", {"scanner_selftest_rc": 1}),
                ("the scan dies (rc=2)", {"scan_rc": 2})):
            rc, _ = run_main(list_json=open_alert, **kwargs)
            chk(f"[RED] {label} -> the OPEN alert is EDITED, never closed",
                (rc, ("issue", "edit") in gh_subs(), ("issue", "close") in gh_subs()),
                (0, True, False))

        # A shallow clone must not even reach the scanner: measuring a truncated history and then
        # discarding the answer is one refactor away from believing it.
        run_main(shallow="true")
        chk("a shallow clone short-circuits BEFORE the scanner runs",
            [cmd for cmd in calls if cmd[0] == "python3"], [])
        # Same property one layer in: a scanner that fails its OWN self-test is not then asked to
        # scan. Believing its verdict is refused in `classify`; RUNNING it is refused here, and the
        # two are separate edits, so neither assertion covers the other.
        run_main(scanner_selftest_rc=1)
        chk("a scanner that fails its own self-test is never asked to scan",
            [cmd[2:] for cmd in calls if cmd[0] == "python3"], [["--self-test"]])

        # ---- transport faults ------------------------------------------------------------------
        rc, out = run_main(scan_rc=1, list_rc=1)
        chk("an unreadable issue list -> rc=1 and NO mutation (never decide on a board we could "
            "not read)",
            (rc, [sub for sub in gh_subs() if sub != ("issue", "list")]), (1, []))
        # An unreadable board is a FAILED tick, not a quiet one: a `return 0` here would report the
        # detector healthy on a tick that filed no alert and, with no pre-existing issue to stay
        # visible, produced no evidence anywhere. rc=1 AND no mutation are both required — passing
        # either alone (fail loudly but create a duplicate; or stay silent) is the defect.
        rc, out = run_main(scan_rc=1, list_json="SENTINEL-MALFORMED {not json")
        chk("[RED] a malformed issue list -> rc=1 (a failed, retryable tick), no mutation, payload "
            "never echoed",
            (rc, "SENTINEL-MALFORMED" in out,
             [sub for sub in gh_subs() if sub != ("issue", "list")]), (1, False, []))
        rc, out = run_main(scan_rc=1, list_json='{"message": "sentinel-error-object"}')
        chk("[RED] a NON-ARRAY issue list (gh renders an API error as an object) -> rc=1, no "
            "mutation, payload never echoed",
            (rc, "sentinel-error-object" in out,
             [sub for sub in gh_subs() if sub != ("issue", "list")]), (1, False, []))
        # Both rows above are ALERTING ticks, so a fail-closed narrowed to `if verdict != CLEAN`
        # would pass them both. The CLEAN tick is the other half: an unreadable board means the
        # RECOVERY path (close the stale alert) could not run either, and that is a failed tick too.
        rc, _ = run_main(list_json="SENTINEL-MALFORMED {not json")
        chk("[RED] ...and a CLEAN tick over an unreadable board fails the same way — the recovery "
            "path could not run, so the tick did not succeed, it went unmeasured",
            (rc, [sub for sub in gh_subs() if sub != ("issue", "list")]), (1, []))
        rc, _ = run_main(scan_rc=1, fail=(("issue", "create"),))
        chk("a failed create -> rc=1 (delivery failure is loud, not swallowed)", rc, 1)
        rc, _ = run_main(list_json=open_alert, fail=(("issue", "close"),))
        chk("a failed close -> rc=1", rc, 1)
        # A row that is not a mapping must not crash the matcher.
        rc, _ = run_main(list_json='[42, {"number": 7, "body": "' + ALERT_MARKER + '"}]')
        chk("a malformed row is skipped, never crashes", rc, 0)

        # ---- THE PUBLIC-SINK GUARD ------------------------------------------------------------
        # Every fake result carries a stderr sentinel. If it ever reaches a gh argument or the log,
        # this module started reading a channel with no safety contract.
        rc, out = run_main(scan_rc=2, list_json=open_alert)
        chk("[RED] the scanner's stderr reaches NEITHER the issue body NOR the run log",
            ("SENTINEL-STDERR" in " ".join(gh_args()), "SENTINEL-STDERR" in out), (False, False))
        chk("...while the scanner's STDOUT report does reach the issue body (the guard above is "
            "not vacuously satisfied by publishing nothing)",
            any("report line" in arg for arg in gh_args()), True)
        # ---- the ALERT ROUTE is wired end-to-end, not merely computed --------------------------
        # `_alert_route` returning a token proves nothing on its own: the token still has to reach
        # `gh` as GH_TOKEN, and the issue still has to be filed against the PRIVATE repo. Dropping
        # either half sends the alert to the wrong place under the wrong identity.
        rc, _ = run_main(scan_rc=1, alert_repo="o/private", alert_token="SENTINEL-ALERT-TOKEN")
        chk("a configured private alert route files against THAT repo, with THAT token in the "
            "child env",
            (rc, "o/private" in gh_args()[-1].split(),
             gh_env(("issue", "create")).get("GH_TOKEN")),
            (0, True, "SENTINEL-ALERT-TOKEN"))
        rc, _ = run_main(scan_rc=1)
        chk("...and with no route configured the alert lands on the registry under the ambient "
            "token (the fallback is not a silent drop)",
            (rc, "o/registry" in gh_args()[-1].split()), (0, True))
    finally:
        subprocess.run = real_run
        for key, value in saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    # Routing matrix (mirrors the audited groom-alert/usage-alert/park-stock-alert one).
    chk("route: repo+token -> private + token",
        _alert_route("o/private", "tok", "o/registry"), ("o/private", "tok"))
    chk("route: repo but NO token -> registry fallback",
        _alert_route("o/private", "", "o/registry"), ("o/registry", None))
    chk("route: no repo -> registry", _alert_route("", "tok", "o/registry"), ("o/registry", None))


def _test_structural_authority(chk):
    """AST facts about this module, not conventions a later edit can erode."""
    # `_require` is what keeps every assertion below reachable, so prove it FAILS CLOSED first: a
    # `_require` that returned "" on a missing file would turn this whole section into a no-op.
    missing = False
    try:
        _require("no/such/self-test-input.yml")
    except LedgerWatchError:
        missing = True
    chk("a missing self-test input RAISES rather than silently emptying these assertions", missing)

    tree = ast.parse(_require("scripts/ledger-identity-watch.py"))

    literals = [node.value for node in ast.walk(tree)
                if isinstance(node, ast.Constant) and isinstance(node.value, str)]
    chk("STRUCTURAL: no code path can write a needs:/status:/role:/area:/review: label — there is "
        "no such string literal in the module at all",
        sorted({text for text in literals if re.match(r"^(needs|status|role|area|review):", text)}),
        [])

    nouns, verbs = set(), set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and getattr(node.func, "id", getattr(node.func, "attr", "")) == "_gh"):
            continue
        argv = node.args[0] if node.args else None
        if not isinstance(argv, ast.List):
            raise LedgerWatchError(
                "a _gh() call passes a non-literal argv — the authority surface would stop being "
                "statically readable, which is how this guard fails open")
        words = [element.value for element in argv.elts if isinstance(element, ast.Constant)]
        if words:
            nouns.add(words[0])
        if len(words) > 1:
            verbs.add(words[1])
    chk("STRUCTURAL: the COMPLETE set of gh commands this module can construct — no `pr`, no "
        "merge, no arming, no label mutation beyond creating the ops-alert label itself",
        (sorted(nouns), sorted(verbs)),
        (["issue", "label"], ["close", "comment", "create", "edit", "list"]))

    # The scanner's stderr has no safety contract and this module is public-sinking. Enforce the
    # "never read it" rule where a refactor cannot quietly undo it.
    chk("STRUCTURAL: no expression in this module reads a `.stderr` attribute (the only writes of "
        "that name are the FAKE results the self-test hands back)",
        sorted({node.attr for node in ast.walk(tree)
                if isinstance(node, ast.Attribute) and node.attr == "stderr"
                and isinstance(node.ctx, ast.Load)}), [])


def _test_workflow_seam(chk):
    """THE YAML SEAM. Every uncaught mutant measured in this estate sat one level above the shell
    body — in an `if:`, a `with:` value, or a call site — never in the Python. So each is pinned by
    EXACT match, never containment."""
    from yaml_dependency import require_yaml
    yaml = require_yaml("ledger-identity-watch workflow-seam checks")

    def crons(document):
        """How many `schedule:` entries a workflow document declares.

        ONE definition, used by the deployment-gate row below AND by its control. Written twice it
        would be #945's shape exactly: a misspelled trigger key in the guard's copy would make the
        guard permanently permissive while the control's copy still passed, so each copy would be
        individually unkillable.
        """
        # `on:` is parsed by PyYAML as the boolean True (the Norway problem), not the string "on".
        return len(((document.get("on", document.get(True)) or {}).get("schedule")) or [])

    document = yaml.safe_load(_require(WORKFLOW_PATH))
    triggers = document.get("on", document.get(True)) or {}
    jobs = document.get("jobs") or {}
    chk("the workflow declares exactly one job", sorted(jobs), ["watch"])
    job = jobs["watch"]
    steps = job.get("steps") or []

    # ⚠️ THE DEPLOYMENT GATE. The detection rule lives in `ledger-history-purge.py` (#536), which is
    # not on the default branch yet. `unverified` is the right RUNTIME answer when it is missing —
    # but a cron enabled before it lands can only ever produce that answer, i.e. one permanently
    # open alert no maintainer action can clear, on the channel real exposures arrive on. So the
    # schedule is COUPLED to the scanner's presence rather than left to a comment nobody re-reads.
    # DIRECTIONALITY IS DELIBERATE: declaring a cron while the scanner is absent REDS here, but the
    # row goes permissive the moment the scanner lands, so merging #536 can never red this required
    # gate for every unrelated pull in the repository. Enabling the cron then is the follow-up.
    chk("[RED] no `schedule:` while the scanner that drives it is absent from this checkout — a "
        "cron that can only ever report `unverified` is a permanently alarming detector, not the "
        "standing measurement #1092 asks for",
        crons(document) > 0 and not Path(scanner_path()).is_file(), False)
    # CONTROL for the row above: it reads a key that is ABSENT from the file today, so on its own
    # it would be satisfied just as well by a `crons` that can never see a cron at all —
    # permanently permissive, and permanently silent about it. Drive the SAME function over a
    # document that does declare one.
    chk("[CONTROL] the same `crons` read finds a cron when one IS declared, so the row above is a "
        "live guard rather than a lookup that can never match",
        crons(yaml.safe_load('on:\n  schedule:\n    - cron: "23 5 * * *"\n')), 1)
    chk("...and the lane stays manually kickable, so a maintainer can take the measurement — or "
        "read the honest `unverified` — on demand while the cron is withheld",
        "workflow_dispatch" in triggers)
    chk("the job carries no `if:` and no `needs:` — there is no upstream whose failure may "
        "suppress the detector",
        ("if" in job, job.get("needs")), (False, None))
    chk("authority is EXACTLY contents:read + issues:write — no pull-requests, no actions, no "
        "arming or merge surface", document.get("permissions"),
        {"contents": "read", "issues": "write"})
    chk("overlapping fires are serialised, and a live run is never cancelled mid-upsert",
        ((job.get("concurrency") or document.get("concurrency") or {}).get("cancel-in-progress")),
        False)

    checkouts = [step for step in steps if str(step.get("uses", "")).startswith("actions/checkout@")]
    chk("every action is SHA-pinned (actionlint does not check pinning)",
        [step["uses"] for step in steps
         if step.get("uses") and not re.fullmatch(r"[^@]+@[0-9a-f]{40}", str(step["uses"]))], [])
    ledger_checkouts = [(step.get("with") or {}) for step in checkouts
                        if (step.get("with") or {}).get("ref")]
    chk("exactly one checkout materialises a ref other than the default", len(ledger_checkouts), 1)
    ledger = ledger_checkouts[0]
    # `fetch-depth: 0` is THE load-bearing value here and it is FALSY, so a truthiness check would
    # accept its deletion. Pin the integer.
    chk("[RED] the ledger checkout takes the FULL history — `fetch-depth: 0`, pinned as the "
        "integer, because losing it makes every scan report a one-commit history as clean",
        ledger.get("fetch-depth"), 0)
    chk("...and it checks out the ledger branch, into its own path, with no persisted token",
        (ledger.get("ref"), ledger.get("path"), ledger.get("persist-credentials")),
        ("ledger", "ledger", False))

    invocations = []
    for step in steps:
        body = (step.get("run") or "").replace("\\\n", " ")
        live = "\n".join(line for line in body.splitlines() if not line.strip().startswith("#"))
        pattern = re.compile(r"^\s*python3\s+(?:\S*/)?ledger-identity-watch\.py([^\n]*)$", re.M)
        for match in pattern.finditer(live):
            invocations.append((step, match.group(1).split()))
    chk("[RED] the call sites are EXACTLY the hermetic self-test then the live scan, tokenised — a "
        "substring check accepts `--repo-DROPPED` and a dropped `--ref` silently rescans the "
        "default", [args for _step, args in invocations],
        [["--self-test"], ["--repo", "ledger", "--ref", "ledger"]])
    chk("neither call site is step-conditional — an `if:` here would leave this harness exercising "
        "a body production can skip", [step.get("if") for step, _args in invocations], [None, None])
    chk("no call site is continue-on-error — a detector whose failure is swallowed is not a gate",
        [step.get("continue-on-error") for step, _args in invocations], [None, None])

    # CROSS-CHECK the two halves of the seam against each other: the path the scan is pointed at
    # must be the path the ledger checkout materialises. Asserting each against a literal leaves a
    # repoint of ONE of them invisible.
    def flag_value(args, flag):
        # Returns a MISSING sentinel rather than raising: a mutant that drops the flag must land
        # on a named FAIL row with the suite's full check count intact, not abort the run part-way
        # and record as a kill while every check below it never ran.
        index = args.index(flag) if flag in args else -1
        return args[index + 1] if 0 <= index < len(args) - 1 else "<flag-missing>"

    scan_args = invocations[-1][1] if invocations else []
    chk("the `--repo` the scan is given IS the checkout's `path:`, and the `--ref` IS its `ref:`",
        (flag_value(scan_args, "--repo"), flag_value(scan_args, "--ref")),
        (ledger.get("path"), ledger.get("ref")))

    # The alert transport needs these three; a missing REGISTRY_REPO raises KeyError in main().
    env = {**(document.get("env") or {}), **(job.get("env") or {})}
    chk("the job supplies the alert transport's environment",
        sorted(key for key in ("GH_TOKEN", "REGISTRY_REPO", "RUN_URL", "MAINTAINER_HANDLE")
               if key in env),
        ["GH_TOKEN", "MAINTAINER_HANDLE", "REGISTRY_REPO", "RUN_URL"])


if __name__ == "__main__":
    sys.exit(main())
