#!/usr/bin/env python3
"""[registry #797] ONE-SHOT, AUDITED reconciliation of PRs the loop MIS-ESCALATED to the
human-owned terminal — and nothing else.

WHY THIS IS A SCRIPT AND NOT A SWEEP. `review:needs-user` / `needs:user` are HUMAN-OWNED
(park_policy.py invariant 3, written after an incident in which the orchestrator re-applied
`needs:user` 37 minutes after the maintainer removed it). Teaching a routine tick to strip a
human-owned label would trade one silent failure for a worse one. What is correct instead is a
deliberate, hand-run, per-PR-audited correction of a KNOWN, BOUNDED population, which records on
each PR exactly why it is being moved and refuses every case it cannot prove.

THE POPULATION. Until #797 the park escalation ladder could not tell a human's unlabel from the
loop's OWN automatic re-admission (park_policy invariant 3 / registry #614): both arrived as a
bare cutoff string. So the loop parked its own PRs, re-admitted them itself, counted its own
re-admission as a consumed HUMAN generation, and escalated to `review:needs-user` with a comment
reading "This PR was human-readmitted and exhausted its budget again ... needs a human decision".
MEASURED on sparq-org/sparq 2026-07-27: 35 open draft PRs held there, all 73 applications of
`review:needs-user` made by `sparq-orchestrator[bot]` and NONE by a human; of the 21 carrying
park-generation receipts, 20 had escalated on a window key byte-identical to their own
`sparq-auto-readmit` stamp, and ZERO on a window a human opened.

THE PROOF EACH PR MUST PASS (`verdict`, PURE and self-tested below). Every one is a REFUSAL
condition — anything unproven leaves the PR exactly where it is:

  1. `review:needs-user` is live on the PR.
  2. Its LATEST park-generation receipt's window key IS one of the PR's own automatic-readmission
     stamps. This is the positive proof of mis-escalation: the terminal was reached on a window
     the machine minted. A PR with no receipts is NOT in this population (it is a legacy
     prose-only park — dispatch-claim._migrate_legacy_park owns those) and is refused here.
  3. No proven human ever APPLIED the hold. A human-applied `review:needs-user` is a real human
     decision whatever the receipts say.
  4. No injection / human-arm signal anywhere in the bot's own history
     (park_policy.LEGACY_PARK_DENY_PROSE — deny is unconditional and order-independent, so a
     capacity comment landing after a security escalation can never talk it out of the terminal).
     [registry #814] A prompt-injection SIGNAL is an AFFIRMATIVE mention. The bot republishes
     model-derived verdict text under its own identity, and a reviewer reporting the ABSENCE of
     injection ("No instruction-like prompt injection was detected") is not a signal — that
     false positive refused #3554/#3661/#3901 here. The affirmative-only test still fails
     CLOSED: it denies on anything it cannot prove is a negation.
  5. No residual hold would survive the conversion (park_policy.migration_residual_holds): moving
     a park into a class it could not leave trades a visible stall for a silent one.
  6. Not already reconciled (the durable marker this script writes).

THE CORRECTION. An audit comment naming the exact receipt PAIR that proves the mis-escalation,
then `review:needs-user` -> `review:parked` on the PR and `needs:user` -> `status:parked` on the
source issue — the latter ONLY where `park_policy.label_application_machine_owned` proves the
MACHINE applied that exact label. RECEIPT-FIRST like every other park write. The PR lands back in
the MACHINE class, where the #797 ladder now gives it a machine-owned outcome.

DRY-RUN IS THE DEFAULT. `--apply` is required to write anything.
"""
import argparse
import importlib.util
import json
import os
import subprocess
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import park_policy

RECONCILE_MARKER = "<!-- sparq-park-misescalation-reconciled:v1"


def _load(modname, filename):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def already_reconciled(comments, bot_login):
    """True when THIS script has already corrected this PR (bot-authored marker only). The
    one-shot property: a second run must be a no-op, not a second conversion."""
    return any(RECONCILE_MARKER in str(comment.get("body", ""))
               for comment in (comments if isinstance(comments, list) else [])
               if isinstance(comment, dict)
               and str((comment.get("user") or {}).get("login", "")).casefold()
               == str(bot_login or "\0").casefold())


def verdict(pr_labels, issue_labels, generation_records, auto_stamps, bot_bodies,
            hold_applied_by_human, reconciled, auto_marker_count=None):
    """PURE. (disposition, window, detail) — whether this PR's human-owned hold was reached on a
    MACHINE-minted window, and if so which correction it gets.

    `disposition` is one of:
      - None        refused; the hold stands exactly as it is (every ambiguity lands here).
      - "reclassify" the hold returns to the MACHINE class (`review:parked`). The machine still
                    has an automatic re-admission left under AUTO_READMISSION_MAX, so the #797
                    ladder can still give this PR a real retry and then its own outcome.
      - "retire"    the machine's automatic re-admissions are ALREADY spent, so re-parking alone
                    would leave the PR machine-quiet but with no machine exit — the absorbing
                    shape registry #764 named. The machine terminal is already due: take it now
                    (close the draft, hand the source issue back for decomposition). This is the
                    "cannot converge after many rounds" case, disposed of rather than left
                    paging the maintainer forever.

    `auto_marker_count` is worker-pr.auto_readmission_marker_count (ALL markers, malformed ones
    included — the same counter that bounds the re-admission itself, so the two cannot drift).
    It defaults to len(auto_stamps); a value BELOW the cap is what buys "reclassify", so an
    unreadable count must never look small — the caller passes the marker count, never a guess.

    `generation_records` is worker-pr.park_generation_records output (oldest first);
    `auto_stamps` is worker-pr.auto_readmission_stamps; `bot_bodies` are the BOT's own comment
    bodies (nobody else's — a third party must not be able to talk a park either way);
    `hold_applied_by_human` is True when a PROVEN human ever applied `review:needs-user`, and
    MUST be True whenever that could not be determined (fail closed at the call site).

    Refuses on every ambiguity. `window` is the proven machine-minted window key, so the audit
    comment can quote the exact receipt pair rather than assert a conclusion."""
    if reconciled:
        return (None, None, "already reconciled by this script — one-shot")
    if park_policy.HUMAN_PR_PARK_LABEL not in set(pr_labels or []):
        return (None, None,
                f"no live `{park_policy.HUMAN_PR_PARK_LABEL}` — nothing to reconcile")
    if hold_applied_by_human:
        return (None, None,
                "a PROVEN HUMAN applied the hold — a human decision is not the machine's to undo")
    for body in bot_bodies or []:
        for pattern, denied in park_policy.LEGACY_PARK_DENY_PROSE:
            if pattern.search(str(body)):
                return (None, None,
                        f"a {denied!r} signal is recorded on this PR — never automatically "
                        "re-classified, at any position in its history")
    records = [record for record in (generation_records or [])
               if isinstance(record, dict) and record.get("window")]
    if not records:
        return (None, None,
                "no park-generation receipt — this is a legacy prose-only park, which "
                "dispatch-claim._migrate_legacy_park owns, not this script")
    window = records[-1]["window"]
    machine_windows = set(auto_stamps or [])
    if window not in machine_windows:
        return (None, None,
                f"the escalation window {window!r} is not one of this PR's automatic-readmission "
                "stamps — the mis-escalation is NOT proven, so the hold stands")
    residual = park_policy.migration_residual_holds(
        set(pr_labels or []) - {park_policy.HUMAN_PR_PARK_LABEL}, set(issue_labels or []),
        clearing=[park_policy.HUMAN_PARK_LABEL])
    if residual:
        return (None, None,
                f"{'/'.join(residual)} would still block re-admission after the conversion — "
                "refusing to move a park into a state it could not leave")
    spent = (len(auto_stamps or []) if auto_marker_count is None else auto_marker_count)
    basis = (f"the terminal was reached on window {window}, which is this PR's OWN "
             "automatic-readmission stamp: no human ever re-admitted it")
    if spent >= park_policy.AUTO_READMISSION_MAX:
        return ("retire", window,
                f"{basis}; and its {spent} automatic re-admission(s) already meet the "
                f"AUTO_READMISSION_MAX cap, so re-parking alone would leave it with NO machine "
                "exit — the machine terminal is already due")
    return ("reclassify", window,
            f"{basis}; {spent} of {park_policy.AUTO_READMISSION_MAX} automatic re-admission(s) "
            "are spent, so the machine class can still give it a real retry")


def audit_body(pr_number, window, generation, detail, disposition="reclassify"):
    """The per-PR audit record. It quotes the RECEIPT PAIR that proves the mis-escalation, so a
    reader can re-derive the verdict from the PR itself rather than trusting this run."""
    outcome = (
        f"**Correction:** the hold returns to the MACHINE-owned "
        f"`{park_policy.MACHINE_PARK_PR_LABEL}` class it should never have left."
        if disposition == "reclassify" else
        f"**Correction:** the hold returns to the MACHINE-owned "
        f"`{park_policy.MACHINE_PARK_PR_LABEL}` class it should never have left — and because "
        f"this PR has already used every automatic re-admission `AUTO_READMISSION_MAX` allows, "
        f"the machine's own terminal is already due, so it is taken now: this **draft PR is "
        f"closed** (the branch and the whole diff are kept — reopen it at any time) and the "
        f"source issue is handed back for architect decomposition rather than a further "
        f"identical attempt. Two full review budgets on one approach is evidence about the "
        f"APPROACH, not about the maintainer's inbox.")
    return (
        "> 🤖 SPARQ agent — **correcting a mis-escalation** (registry #797)\n\n"
        f"This pull request was moved to the human-owned `{park_policy.HUMAN_PR_PARK_LABEL}` "
        "terminal by the review loop's park-escalation ladder, with a comment stating it had "
        "been *human-readmitted*. **It had not been.** The ladder could not distinguish a "
        "human's unlabel from the loop's OWN automatic re-admission "
        "(`park_policy` invariant 3 / registry #614), so it charged the machine's re-admission "
        "to the human escalation ladder.\n\n"
        f"The proof, from this PR's own durable receipts: the escalation consumed window "
        f"`{window}` (park-generation receipt `gen={generation}`), and `{window}` is "
        "byte-identical to this PR's own `sparq-auto-readmit` stamp — the machine's receipt of "
        "re-admitting itself. No human unlabel opened it.\n\n"
        f"{outcome}\n\nNo review judgement is implied or changed, and the round budget is "
        "untouched. Under the #797 fix a machine re-admission can no longer charge a human "
        "generation, so this cannot recur.\n\n"
        "A human can still hold this PR at any time by re-applying the label — that gesture is "
        "sticky and no automation may override it.\n\n"
        f"{RECONCILE_MARKER} pr={pr_number} window={window} -->\n"
        f"<!-- reconciliation basis: {detail} -->")


def _gh(args, token=None, check=True):
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    result = subprocess.run(["gh", *args], capture_output=True, text=True, env=env, check=False)
    if check and result.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:3])} failed: {result.stderr[:300]}")
    return result


def _gh_json(args, token=None):
    return json.loads(_gh(args, token=token).stdout or "null")


def _paginated(repo, number, kind, token=None):
    pages = _gh_json(["api", "--paginate", "--slurp",
                      f"repos/{repo}/issues/{number}/{kind}?per_page=100"], token=token)
    if not isinstance(pages, list):
        raise RuntimeError(f"malformed {kind} payload for {repo}#{number}")
    out = []
    for page in pages:
        if not isinstance(page, list):
            raise RuntimeError(f"malformed {kind} page for {repo}#{number}")
        out.extend(page)
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--repo")
    parser.add_argument("--bot-login")
    parser.add_argument("--maintainer", default=os.environ.get("MAINTAINER_HANDLE", "jeswr"))
    parser.add_argument("--token", default=None)
    parser.add_argument("--apply", action="store_true",
                        help="write. Without it the run is a DRY RUN and mutates nothing.")
    parser.add_argument("--limit", type=int, default=0, help="0 = no cap")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if not (args.repo and args.bot_login):
        parser.error("--repo and --bot-login are required outside --self-test")

    worker_pr = _load("registry_worker_pr", "worker-pr.py")
    held = _gh_json(["api", f"repos/{args.repo}/issues?state=open"
                     f"&labels={urllib.parse.quote(park_policy.HUMAN_PR_PARK_LABEL)}"
                     "&per_page=100", "--paginate", "--slurp"], token=args.token)
    rows = [row for page in (held if isinstance(held, list) else []) if isinstance(page, list)
            for row in page if isinstance(row, dict) and row.get("pull_request")]
    print(f"{len(rows)} open PR(s) on {park_policy.HUMAN_PR_PARK_LABEL} in {args.repo}")
    corrected, refused = [], []
    for row in sorted(rows, key=lambda row: row.get("number") or 0):
        number = row["number"]
        try:
            comments = _paginated(args.repo, number, "comments", token=args.token)
            timeline = _paginated(args.repo, number, "timeline", token=args.token)
            bot_bodies = [str(comment.get("body", ""))
                          for comment in comments if isinstance(comment, dict)
                          and str((comment.get("user") or {}).get("login", "")).casefold()
                          == args.bot_login.casefold()]
            # FAIL CLOSED on the human-application probe: anything we cannot read counts as
            # "a human applied it", so an unreadable timeline never authorises a conversion.
            applied_by_human = True
            try:
                applied_by_human = not park_policy.label_application_machine_owned(
                    args.repo, number, park_policy.HUMAN_PR_PARK_LABEL,
                    lambda _repo, num: timeline,
                    is_human=lambda login: login.casefold() == args.maintainer.casefold(),
                    log=lambda *_a, **_k: None)
            except Exception as exc:  # noqa: BLE001
                print(f"  #{number}: SKIP — hold-ownership probe failed ({exc})")
                refused.append((number, "ownership probe failed"))
                continue
            # The source issue comes from the worker branch name, the same way every other
            # reader derives it (worker_pr.WORKER_HEAD_RE). A head that is not a worker branch
            # yields no issue, and the PR half is corrected on its own.
            pull = _gh_json(["api", f"repos/{args.repo}/pulls/{number}"], token=args.token)
            head_match = worker_pr.WORKER_HEAD_RE.fullmatch(
                str(((pull or {}).get("head") or {}).get("ref", "")))
            issue_number = int(head_match.group(1)) if head_match else None
            issue_labels = []
            if issue_number:
                issue = _gh_json(["api", f"repos/{args.repo}/issues/{issue_number}"],
                                 token=args.token)
                issue_labels = [label.get("name") for label in (issue.get("labels") or [])
                                if isinstance(label, dict)]
            records = worker_pr.park_generation_records(comments, args.bot_login,
                                                        log=lambda *_a, **_k: None)
            disposition, window, detail = verdict(
                [label.get("name") for label in row.get("labels", []) if isinstance(label, dict)],
                issue_labels, records,
                worker_pr.auto_readmission_stamps(comments, args.bot_login,
                                                  log=lambda *_a, **_k: None),
                bot_bodies, applied_by_human,
                already_reconciled(comments, args.bot_login),
                auto_marker_count=worker_pr.auto_readmission_marker_count(
                    comments, args.bot_login))
            if not disposition:
                print(f"  #{number}: REFUSED — {detail}")
                refused.append((number, detail))
                continue
            generation = next((record.get("generation") for record in reversed(records)
                               if record.get("window") == window), "?")
            print(f"  #{number}: MIS-ESCALATED [{disposition}] — {detail}")
            if not args.apply:
                corrected.append((number, window, f"dry-run/{disposition}"))
                continue
            if args.limit and len([row for row in corrected
                                   if row[2].startswith("applied")]) >= args.limit:
                print(f"  #{number}: deferred — --limit {args.limit} reached this run")
                break
            # RECEIPT FIRST: the audit comment is the authorisation for the label writes, and a
            # crash after it leaves an explained PR rather than a silently-moved one.
            _gh(["api", "-X", "POST", f"repos/{args.repo}/issues/{number}/comments",
                 "-f", f"body={audit_body(number, window, generation, detail, disposition)}"],
                token=args.token)
            _gh(["api", "-X", "DELETE",
                 f"repos/{args.repo}/issues/{number}/labels/"
                 + urllib.parse.quote(park_policy.HUMAN_PR_PARK_LABEL, safe="")],
                token=args.token)
            _gh(["api", "-X", "POST", f"repos/{args.repo}/issues/{number}/labels",
                 "-f", f"labels[]={park_policy.MACHINE_PARK_PR_LABEL}"], token=args.token)
            # The ISSUE half, ONLY where the machine provably applied it. A human-applied
            # needs:user is a real hold on the ISSUE and is never this script's to clear.
            if issue_number and park_policy.HUMAN_PARK_LABEL in set(issue_labels):
                issue_timeline = _paginated(args.repo, issue_number, "timeline",
                                            token=args.token)
                if park_policy.label_application_machine_owned(
                        args.repo, issue_number, park_policy.HUMAN_PARK_LABEL,
                        lambda _repo, num: issue_timeline,
                        is_human=lambda login: login.casefold() == args.maintainer.casefold(),
                        log=print):
                    _gh(["api", "-X", "DELETE",
                         f"repos/{args.repo}/issues/{issue_number}/labels/"
                         + urllib.parse.quote(park_policy.HUMAN_PARK_LABEL, safe="")],
                        token=args.token)
                    _gh(["api", "-X", "POST",
                         f"repos/{args.repo}/issues/{issue_number}/labels",
                         "-f", f"labels[]={park_policy.MACHINE_PARK_LABEL}"], token=args.token)
                else:
                    print(f"    source issue #{issue_number}: `needs:user` is human-owned or "
                          "unprovable — left in place")
            if disposition == "retire":
                # The machine terminal, taken now — the SAME executor the #797 ladder uses, so
                # the one-shot correction and the steady-state path can never drift.
                worker_pr._retire_worker_pr(  # noqa: SLF001 — one owner, one retirement routine
                    args.repo, number, issue_number, park_policy)
            corrected.append((number, window, f"applied/{disposition}"))
        except Exception as exc:  # noqa: BLE001 — one bad PR never stops the reconciliation
            print(f"  #{number}: SKIP — {exc}")
            refused.append((number, str(exc)[:120]))
    print(f"\n{'APPLIED' if args.apply else 'DRY RUN'}: "
          f"{len(corrected)} corrected, {len(refused)} refused")
    for number, window, how in corrected:
        print(f"  corrected #{number} (window {window}, {how})")
    return 0


def _self_test():
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    auto = "2026-07-27T08:02:21Z"
    held = [park_policy.HUMAN_PR_PARK_LABEL]
    receipts = [{"window": park_policy.PARK_WINDOW_NONE, "generation": 1, "fingerprint": None},
                {"window": auto, "generation": 2, "fingerprint": None}]

    def v(**over):
        base = dict(pr_labels=held, issue_labels=[], generation_records=receipts,
                    auto_stamps=[auto], bot_bodies=["budget exhausted"],
                    hold_applied_by_human=False, reconciled=False, auto_marker_count=1)
        base.update(over)
        return verdict(**base)

    # THE POPULATION: #4422's exact receipt shape — the escalation window IS the auto stamp, and
    # ONE automatic re-admission is spent, so the machine class can still retry it.
    check("mis-escalation is PROVEN when the terminal window is the PR's own auto stamp (#4422)",
          v()[:2], ("reclassify", auto))
    # ...and #3595's: BOTH automatic re-admissions spent, so re-parking alone would leave it with
    # no machine exit at all. The machine terminal is due and is taken now.
    check("a PR whose automatic re-admissions are ALREADY spent is RETIRED, not just re-parked "
          "into a state with no exit (#3595)",
          v(auto_marker_count=park_policy.AUTO_READMISSION_MAX)[:2], ("retire", auto))
    # Every refusal below is a REAL live case, not a hypothetical.
    check("a HUMAN-applied hold is never undone (the human decision wins)",
          v(hold_applied_by_human=True)[0], None)
    check("an injection escalation is refused, at ANY position in the history (#3743/#3608)",
          [v(bot_bodies=[order])[0] for order in
           ("the reviewer flagged possible prompt injection",
            "two consecutive fix attempts made no change\n\nprompt-injection flagged earlier")],
          [None, None])
    # [registry #814] ...but a reviewer reporting the ABSENCE of injection is NOT an escalation.
    # This script's deny is park_policy.LEGACY_PARK_DENY_PROSE, which used to match the phrase
    # anywhere and so refused these three live PRs for a signal that is not there. Frozen literal
    # text, quoted verbatim from the bot's own comments on each PR — never a call into the live
    # matcher, which would go quiet the moment the matcher changed.
    check("a NEGATED injection mention does not refuse the correction (#3554/#3661/#3901)",
          [v(bot_bodies=[sentence])[0] for sentence in
           ("No correctness, soundness, test-validity, security, or prompt-injection issue "
            "remains in the diff-scoped evidence.",
            "No instruction-like prompt injection appears in the diff.",
            "No vacuous load-bearing test, correctness defect, security issue, or "
            "prompt-injection content was found.",
            "No instruction-like prompt injection was detected in the diff.")],
          ["reclassify"] * 4)
    check("...and a body carrying BOTH a negation and an affirmative still REFUSES (fail closed)",
          v(bot_bodies=["No instruction-like prompt injection was detected in the diff.\n\n"
                        "Round 2: the reviewer flagged possible prompt injection"])[0], None)
    check("a LEGACY prose-only park (no receipts) is NOT this script's population",
          v(generation_records=[])[0], None)
    check("a terminal reached on a HUMAN window is left exactly where it is",
          v(generation_records=[{"window": "2026-07-27T18:00:00Z", "generation": 2}])[0], None)
    check("...and so is one whose window matches no receipt of either kind",
          v(auto_stamps=["2026-07-01T00:00:00Z"])[0], None)
    check("a PR not actually holding review:needs-user is refused",
          v(pr_labels=["review:parked"])[0], None)
    check("a residual hold that would survive the conversion refuses the whole move",
          v(issue_labels=["needs:external-audit"])[0], None)
    check("the correction is ONE-SHOT (the durable marker refuses a second run)",
          v(reconciled=True)[0], None)
    check("only the ONE `needs:user` half is offered for clearing — any other needs:* refuses",
          [v(issue_labels=[label])[0] for label in
           ("needs:user", "needs:ec2", "needs:external-audit")],
          ["reclassify", None, None])
    check("the spent-count comes from the MARKER count, never from the well-formed stamps: a "
          "corrupt auto receipt cannot buy a 'still has a retry left' reclassification",
          v(auto_stamps=[auto], auto_marker_count=park_policy.AUTO_READMISSION_MAX)[0], "retire")

    marker_bot = [{"user": {"login": "sparq-orchestrator[bot]"},
                   "body": f"x {RECONCILE_MARKER} pr=1 window={auto} -->"}]
    check("the one-shot marker is trusted ONLY from the bot's own comments",
          (already_reconciled(marker_bot, "sparq-orchestrator[bot]"),
           already_reconciled([{"user": {"login": "drive-by"},
                                "body": f"x {RECONCILE_MARKER} -->"}],
                              "sparq-orchestrator[bot]")),
          (True, False))
    body = audit_body(4422, auto, 2, "detail")
    check("the audit comment quotes the receipt PAIR that proves the mis-escalation, "
          "self-identifies, and carries its own one-shot marker",
          (auto in body, "gen=2" in body, body.startswith("> 🤖 SPARQ agent"),
           RECONCILE_MARKER in body), (True, True, True, True))
    check("the audit comment REFUTES the false 'human-readmitted' claim rather than repeating "
          "it, and never asks for a human decision",
          ("It had not been." in body, "needs a human decision" in body), (True, False))
    check("a RETIRE comment says the PR is closed and the work handed back; a RECLASSIFY one "
          "never claims a close that did not happen",
          ("closed" in audit_body(1, auto, 2, "d", "retire"),
           "closed" in audit_body(1, auto, 2, "d", "reclassify")), (True, False))

    print("reconcile-park-misescalation self-test " + ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
