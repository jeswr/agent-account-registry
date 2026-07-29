#!/usr/bin/env python3
"""[registry #446] THE STUCK-ESCALATION AUTO-ADJUDICATOR — a steady-state sweep that gives every
PR parked on the human-owned `review:needs-user` terminal ONE machine-readable disposition, and
returns to the review loop the ones whose park was never a human question in the first place.

THE STALL. Measured 2026-07-19: 36 draft PRs terminally parked on `review:needs-user` (19 sparq,
17 registry) with NOTHING that resolves them. The active review set drains, merges stop, and the
maintainer is paged by a queue rather than by a question. Two mechanisms already exist and
neither closes this: `reconcile-park-misescalation.py` is a deliberately ONE-SHOT, hand-run
correction of the #797 mis-escalation population, and the #797 ladder only keeps FUTURE capacity
parks machine-owned. Nothing sweeps the terminal itself, so every park that reaches it — for any
reason, including no stated reason at all — stays there forever.

THE TWO DISPOSITIONS, AND WHY THERE IS NO THIRD. Issue #446 specified three, the third being
`override-arm` ("the finding was spurious -> arm"). Design record
`research/967-adjudicator-override-arm-authority.md` (merged as #1005) decided against it, and
this module implements that decision: `DISPOSITIONS` is a CLOSED set of two, asserted in
`--self-test` so it cannot grow silently.

  - `return-to-loop`   the park was reached over a CAPACITY episode (a budget/starvation/gate
                       stop — something that can come out differently on the next attempt). The
                       PR goes back to the FIX lane with a real, capped budget window.
  - `genuinely-human`  a policy / security / trust decision, or a stop a retry cannot change.
                       The PR STAYS EXACTLY WHERE IT IS and gains a machine-readable reason
                       marker, so the terminal stops being silent.

Everything else is REFUSED and the park stands untouched. This module never arms, never writes
`review:pass`, never merges, never edits a verdict, and never relaxes a test or a gate — the
correctness question is handed back to the cross-provider review round `return-to-loop` buys,
which is the only party that reads the diff under gate (#967 §3).

TRUST SURFACES. #446's guardrail — "ZK/MPC/security/trust surfaces default to genuinely-human
unless clearly spurious" — was written for the disposition that ARMS. With no arming disposition
the guardrail's subject is gone, and re-entry is not an exception to it: a returned PR must still
pass a full cross-provider review round, whose approve path re-derives the touched trust surfaces
from the LIVE diff over the fail-closed `DEFAULT_TRUST_SURFACE_PATHS` floor and applies the
SHA-bound post-merge audit trail (`worker-pr.resolve_trust_surface_paths` /
`_apply_trust_surface_audit`). A path-based refusal here would instead make the sweep vacuous on
this repository, where essentially every PR touches `scripts/`. What DOES bind unconditionally is
the CAUSE: `park_policy.PARK_HUMAN_ONLY_CAUSES` (`injection`, `human-arm`) and every
`LEGACY_PARK_DENY_PROSE` signal anywhere in the bot's history are `genuinely-human`, always, and
so is every question-class cause and every cause that cannot be read at all.

THE BUDGET IS REAL, AND CAPPED. `return-to-loop` mints its window with the ONE marker writer the
whole park-receipt family reads (`worker-pr.auto_readmission_marker`), so the re-entry:
  - is charged against `park_policy.AUTO_READMISSION_MAX` (2 per PR, counted over MARKERS, so a
    corrupt receipt still spends cap) — the sweep can never become a treadmill;
  - opens a genuine round budget (`worker-pr.budget_round_charge`), instead of handing the PR
    back past the hard cap where it would re-park before one round ran; and
  - lands on the #797 MACHINE ladder if it exhausts that budget, which RETIRES it rather than
    returning it to the human terminal. The backlog drains in one direction only.

DRY-RUN IS THE DEFAULT. `--apply` is required to write anything. Every write is RECEIPT-FIRST:
the audit comment is the authorisation for the label writes, so a crash after it leaves an
explained PR rather than a silently-moved one.
"""
import argparse
import datetime
import importlib.util
import json
import os
import re
import subprocess
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import park_policy

# The CLOSED disposition set (#967 §5). `--self-test` asserts both its membership and its LENGTH,
# so an `override-arm` (or any other arming authority under a different name) cannot be added
# here without turning the suite red and forcing the design record's §6 conversation.
RETURN_TO_LOOP = "return-to-loop"
GENUINELY_HUMAN = "genuinely-human"
DISPOSITIONS = (RETURN_TO_LOOP, GENUINELY_HUMAN)

# The durable per-EPISODE adjudication record. Bot-authored + reserved-namespace like every other
# marker in this family. It is the one-shot key for BOTH dispositions: a park that has been
# adjudicated is never adjudicated again on the same episode, so a 15-minute cron neither
# re-comments on a standing human question nor re-spends a re-admission.
ADJUDICATION_MARKER = "<!-- sparq-stuck-adjudication:v1"
_ADJUDICATION_RE = re.compile(
    re.escape(ADJUDICATION_MARKER) + r" episode=(\S+) disposition=(\S+) cause=(\S+) -->")

# The evidence-key namespace this sweep mints its re-admission windows in. It is deliberately
# DISTINCT from model-health's `fleet-health/` namespace (worker-pr.AUTO_READMIT_HEURISTIC_PREFIX)
# so a reader can tell an adjudicated re-entry from a cause-recovery one, and so neither can post
# the other's finding sentence by omission.
EVIDENCE_PREFIX = "adjudication/"


def _load(modname, filename):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def episode_key(generation_records, head_sha):
    """The consume-exactly-once evidence key for THIS park episode, or None when no
    representable key exists (which refuses the whole adjudication).

    Keyed on the LATEST park-generation window when the PR has receipts — that window IS the
    episode the ladder escalated on — and on the head SHA otherwise, so a legacy prose-only park
    still gets a stable key and a park that is re-reached on a NEW head is a new episode rather
    than a permanently-consumed one. Validated against park_policy.safe_receipt_part here, at the
    writer, rather than left to blow up mid-transaction."""
    records = [record for record in (generation_records or [])
               if isinstance(record, dict) and record.get("window")]
    if records:
        suffix = str(records[-1]["window"])
    elif head_sha and re.fullmatch(r"[0-9a-f]{40}", str(head_sha)):
        suffix = f"head-{str(head_sha)[:12]}"
    else:
        return None
    key = EVIDENCE_PREFIX + suffix
    return key if park_policy.safe_receipt_part(key) else None


def adjudicated_episodes(comments, bot_login):
    """Every episode key this sweep has already adjudicated, from the BOT's OWN comments only —
    a third party must not be able to pin a PR out of the population, nor to fake a disposition
    it never made."""
    episodes = set()
    for comment in comments if isinstance(comments, list) else []:
        if not isinstance(comment, dict):
            continue
        login = str((comment.get("user") or {}).get("login", ""))
        if login.casefold() != str(bot_login or "\0").casefold():
            continue
        for match in _ADJUDICATION_RE.finditer(str(comment.get("body", ""))):
            episodes.add(match.group(1))
    return episodes


def adjudicate(pr_labels, issue_labels, reason_records, legacy, bot_bodies,
               hold_applied_by_human, auto_marker_count, consumed_keys, adjudicated,
               evidence_key, is_worker_draft, review_labels=(),
               issue_hold_machine_owned=False):
    """PURE. (disposition, cause, detail) for ONE parked PR.

    `disposition` is None (REFUSED — the park stands exactly as it is, which is where every
    ambiguity lands) or a member of the CLOSED `DISPOSITIONS` set. `cause` is the
    park_policy.PARK_CAUSES entry the disposition rests on, or None on a refusal; it is what the
    `genuinely-human` path records as a machine-readable reason marker.

    Inputs, and the fail-closed contract each carries:
      `reason_records`        park_policy.park_reason_records (bot-authored, oldest first). The
                              NEWEST record decides when one exists.
      `legacy`                park_policy.reclassify_legacy_park's (cause, class, detail) — the
                              prose fallback for a park written before the marker existed. It
                              denies on injection/human-arm prose on its own account.
      `bot_bodies`            the BOT's own comment bodies, nobody else's. Scanned for
                              LEGACY_PARK_DENY_PROSE INDEPENDENTLY of `legacy`, because a park
                              that carries a reason MARKER never reaches the legacy path at all
                              and a `class=capacity` marker must not be able to out-vote an
                              injection signal recorded elsewhere in the same history.
      `hold_applied_by_human` True whenever a PROVEN human applied `review:needs-user`, and MUST
                              be True whenever that could not be determined (fail closed at the
                              call site).
      `auto_marker_count`     worker-pr.auto_readmission_marker_count — ALL markers, malformed
                              ones included, so an unreadable receipt can never look small enough
                              to buy an extra re-admission.
      `consumed_keys`         evidence keys already consumed by a re-admission receipt.
      `adjudicated`           episode keys this sweep already disposed of (one-shot, both ways).
      `review_labels`         the closed `review:*` namespace (worker-pr.REVIEW_LABELS). Any
                              OTHER live member of it means the PR is in a split state no valid
                              flow produces, and this sweep is not the thing to resolve it.
      `issue_hold_machine_owned`
                              True only when the MACHINE provably applied the source issue's
                              `needs:user`, so this sweep may lift it. It DEFAULTS TO FALSE and
                              must be False whenever that could not be proven: clearing the PR
                              half while a human-owned `needs:user` still holds the issue would
                              swap a visible stall for a silent one.
    """
    if evidence_key is None:
        return (None, None,
                "no representable episode key (no park-generation receipt and no readable head) "
                "— an unkeyable adjudication could not be made once-only")
    if park_policy.HUMAN_PR_PARK_LABEL not in set(pr_labels or []):
        return (None, None,
                f"no live `{park_policy.HUMAN_PR_PARK_LABEL}` — not this sweep's population")
    if not is_worker_draft:
        return (None, None,
                "not an open worker DRAFT PR — a ready or foreign PR is not the review loop's "
                "to move")
    if evidence_key in set(adjudicated or ()):
        return (None, None,
                f"episode {evidence_key} was already adjudicated — one disposition per episode")
    if evidence_key in set(consumed_keys or ()):
        return (None, None,
                f"the re-admission evidence {evidence_key} is already consumed — the same "
                "episode can never buy a second window")
    if hold_applied_by_human:
        return (None, None,
                "a PROVEN HUMAN applied the hold — a human decision is not the machine's to undo")
    # DENY FIRST, unconditionally and order-independently (park_policy.LEGACY_PARK_DENY_PROSE):
    # a raised injection / human-arm signal is a property of the PR's WHOLE history, and the two
    # causes it names are park_policy.PARK_HUMAN_ONLY_CAUSES — no automatic path may convert them
    # out of the terminal, at any position, behind any newer marker.
    for body in bot_bodies or []:
        for pattern, denied in park_policy.LEGACY_PARK_DENY_PROSE:
            if pattern.search(str(body)):
                return (GENUINELY_HUMAN, denied,
                        f"a {denied!r} signal is recorded on this PR — this park exists BECAUSE "
                        "a judgement was made, and no automation may re-admit it at any position "
                        "in its history")
    records = [record for record in (reason_records or []) if isinstance(record, dict)]
    if records:
        cause, park_class = records[-1].get("cause"), records[-1].get("class")
        basis = f"the park's own machine-readable reason marker says cause={cause!r}"
    else:
        cause, park_class, legacy_detail = (legacy or (None, None, "no legacy classification"))
        basis = f"no reason marker; {legacy_detail}"
    if cause is None or park_class is None:
        return (None, None,
                f"{basis} — an unclassifiable park is a human question, and there is no taxonomy "
                "entry that would let this sweep say anything truthful about it")
    if cause in park_policy.PARK_HUMAN_ONLY_CAUSES:
        return (GENUINELY_HUMAN, cause,
                f"{basis}, which is one of PARK_HUMAN_ONLY_CAUSES — never re-classified, "
                "re-admitted, or converted out of the human terminal by any machine path")
    if park_class == park_policy.PARK_CLASS_QUESTION:
        return (GENUINELY_HUMAN, cause,
                f"{basis} ({park_class}): a re-dispatch changes none of its inputs, so returning "
                "it to the loop would be a treadmill, not a retry")
    if park_class != park_policy.PARK_CLASS_CAPACITY:
        return (None, None, f"{basis} carries the unknown class {park_class!r} — the park stands")
    foreign = sorted(set(pr_labels or []) & set(review_labels or ())
                     - {park_policy.HUMAN_PR_PARK_LABEL})
    if foreign:
        return (None, cause,
                f"{'/'.join(foreign)} is live beside the terminal — a split review state is not "
                "this sweep's to resolve")
    residual = park_policy.migration_residual_holds(
        set(pr_labels or []) - {park_policy.HUMAN_PR_PARK_LABEL}, set(issue_labels or []),
        clearing=[park_policy.HUMAN_PARK_LABEL])
    if residual:
        return (None, cause,
                f"{'/'.join(residual)} would still hold this PR after the re-admission — "
                "refusing to move a park into a state it could not leave")
    if (park_policy.HUMAN_PARK_LABEL in set(issue_labels or [])
            and not issue_hold_machine_owned):
        return (None, cause,
                f"the source issue's `{park_policy.HUMAN_PARK_LABEL}` is human-applied or "
                "unprovable — re-admitting the PR half would leave it running behind a hold "
                "this sweep may not lift, which is a silent stall rather than a visible one")
    spent = (auto_marker_count if isinstance(auto_marker_count, int)
             and not isinstance(auto_marker_count, bool)
             else park_policy.AUTO_READMISSION_MAX)
    if spent >= park_policy.AUTO_READMISSION_MAX:
        return (None, cause,
                f"{spent} of {park_policy.AUTO_READMISSION_MAX} automatic re-admission(s) are "
                "already spent — the machine has had every chance the cap allows, so what is "
                "left really is a human's call")
    return (RETURN_TO_LOOP, cause,
            f"{basis} ({park_class}): a capacity stop is not a human question, and {spent} of "
            f"{park_policy.AUTO_READMISSION_MAX} automatic re-admission(s) are spent, so the "
            "loop can still give it a real budget window")


def write_plan(disposition):
    """PURE. The CLOSED set of writes a disposition authorises, in the order they are made.

    This exists so the WRITE half is assertable without a GitHub round-trip: `_sweep_one` reads
    its branches from here rather than re-deciding them, so "a park that stays parked never mints
    a budget window and never touches a label" is a checked property of the module rather than a
    claim about a code path no test reaches. A refusal authorises NOTHING."""
    if disposition == RETURN_TO_LOOP:
        return ("comment", "readmit-window", "drop-human-hold", "add-fix-lane",
                "clear-machine-issue-hold")
    if disposition == GENUINELY_HUMAN:
        return ("comment", "reason-marker")
    return ()


def adjudication_marker(episode, disposition, cause):
    """The durable per-episode disposition record. Raises ValueError on anything unrepresentable
    or on a disposition outside the CLOSED set — an arming disposition cannot be smuggled in as
    an unvalidated string."""
    if disposition not in DISPOSITIONS:
        raise ValueError(f"disposition {disposition!r} is not one of {DISPOSITIONS}")
    if park_policy.park_cause_class(cause) is None:
        raise ValueError(f"unknown park cause {cause!r} (not in PARK_CAUSES)")
    for part in (episode, disposition, cause):
        if not park_policy.safe_receipt_part(str(part)):
            raise ValueError(f"unsafe adjudication marker part {part!r}")
    return (f"{ADJUDICATION_MARKER} episode={episode} disposition={disposition} "
            f"cause={cause} -->")


def audit_body(disposition, cause, detail, episode, readmit_marker=None, reason_marker=None,
               lane=None):
    """The per-PR audit record. It states the disposition, the cause it rests on, and — for a
    re-entry — exactly what the re-entry is NOT, so a reader never has to infer that an
    automatic unpark implied a review judgement."""
    if disposition == RETURN_TO_LOOP:
        head = (
            "> 🤖 SPARQ agent — **stuck-escalation adjudication: returning this PR to the review "
            "loop** (registry #446)\n\n"
            f"This pull request has been sitting on the human-owned "
            f"`{park_policy.HUMAN_PR_PARK_LABEL}` terminal, but its own durable receipts classify "
            f"the stop as **`{cause}` ({park_policy.PARK_CLASS_CAPACITY})** — a capacity stop, "
            "not a question. A capacity stop caps something that can come out differently on the "
            "next attempt, so there is nothing here for a human to decide that the loop has not "
            "already been asked.\n\n"
            f"**Basis:** {detail}\n\n"
            f"**What happens now.** The hold is removed and the PR re-enters the FIX lane "
            f"(`{lane}`) with a real, capped "
            "round-budget window opened by the re-admission receipt below. The findings it is "
            "re-dispatched against are the ones already recorded in the registry — no finding is "
            "dismissed, edited, or re-graded here.\n\n"
            "**What this is NOT.** This adjudication does not arm, approve, merge, or mark this "
            "PR passed; it does not overrule the reviewer; and it weakens no test and no gate. "
            "Whether the diff is correct is decided where it has always been decided — by a full "
            "cross-provider review round on the live diff, which this PR must still pass "
            "(design record `research/967-adjudicator-override-arm-authority.md`).\n\n"
            f"**The bound.** At most {park_policy.AUTO_READMISSION_MAX} automatic re-admissions "
            "are ever granted to one PR. If this budget is exhausted again the PR lands on the "
            "machine ladder, which retires it — it does not come back here.\n\n"
            "A human can hold this PR at any time by re-applying the label; that gesture is "
            "sticky and no automation may override it.\n\n")
    else:
        head = (
            "> 🤖 SPARQ agent — **stuck-escalation adjudication: this one really is yours** "
            "(registry #446)\n\n"
            f"This pull request stays exactly where it is. Its stop reason is **`{cause}` "
            f"({park_policy.park_cause_class(cause)})** — a decision the machine has no standing "
            "to make, or one a re-dispatch could not change.\n\n"
            f"**Basis:** {detail}\n\n"
            "Nothing about this PR's labels, budget, findings, or verdict has been touched. The "
            "marker below records the reason in machine-readable form so this park is no longer "
            "silent: the sweep that drains the terminal can tell it apart from a park that was "
            "merely given up on, and will not ask about it again.\n\n")
    tail = "\n".join(part for part in (reason_marker, readmit_marker,
                                       adjudication_marker(episode, disposition, cause)) if part)
    return head + tail


def _gh(args, check=True):
    result = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:3])} failed: {result.stderr[:300]}")
    return result


def _gh_json(args):
    return json.loads(_gh(args).stdout or "null")


def _paginated(repo, number, kind):
    pages = _gh_json(["api", "--paginate", "--slurp",
                      f"repos/{repo}/issues/{number}/{kind}?per_page=100"])
    if not isinstance(pages, list):
        raise RuntimeError(f"malformed {kind} payload for {repo}#{number}")
    out = []
    for page in pages:
        if not isinstance(page, list):
            raise RuntimeError(f"malformed {kind} page for {repo}#{number}")
        out.extend(page)
    return out


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sweep_one(args, worker_pr, row, applied):
    """Adjudicate ONE parked PR. Returns (disposition, cause, detail); writes only under
    --apply, and only after the audit comment that authorises the writes."""
    number = row["number"]
    comments = _paginated(args.repo, number, "comments")
    timeline = _paginated(args.repo, number, "timeline")
    bot_bodies = [str(comment.get("body", "")) for comment in comments
                  if isinstance(comment, dict)
                  and str((comment.get("user") or {}).get("login", "")).casefold()
                  == args.bot_login.casefold()]
    # FAIL CLOSED on the hold-ownership probe: anything unreadable counts as "a human applied
    # it", so an unreadable timeline never authorises a re-admission.
    try:
        applied_by_human = not park_policy.label_application_machine_owned(
            args.repo, number, park_policy.HUMAN_PR_PARK_LABEL,
            lambda _repo, _num: timeline,
            is_human=lambda login: login.casefold() == args.maintainer.casefold(),
            log=lambda *_a, **_k: None)
    except Exception as exc:  # noqa: BLE001
        return (None, None, f"hold-ownership probe failed ({exc})")

    pull = _gh_json(["api", f"repos/{args.repo}/pulls/{number}"])
    head = (pull or {}).get("head") or {}
    head_sha = str(head.get("sha", ""))
    head_match = worker_pr.WORKER_HEAD_RE.fullmatch(str(head.get("ref", "")))
    is_worker_draft = bool(head_match) and bool((pull or {}).get("draft"))
    issue_number = int(head_match.group(1)) if head_match else None
    issue_labels = []
    if issue_number:
        issue = _gh_json(["api", f"repos/{args.repo}/issues/{issue_number}"])
        issue_labels = [label.get("name") for label in (issue.get("labels") or [])
                        if isinstance(label, dict)]
    # FAIL CLOSED again on the ISSUE half: a `needs:user` this sweep cannot prove the machine
    # applied is a real hold on the work, and re-admitting the PR behind it would trade a
    # visible stall for a silent one. Unreadable => human-owned => the whole move is refused.
    issue_hold_machine_owned = False
    if issue_number and park_policy.HUMAN_PARK_LABEL in set(issue_labels):
        try:
            issue_hold_machine_owned = park_policy.label_application_machine_owned(
                args.repo, issue_number, park_policy.HUMAN_PARK_LABEL,
                lambda _repo, _num: _paginated(args.repo, issue_number, "timeline"),
                is_human=lambda login: login.casefold() == args.maintainer.casefold(),
                log=print)
        except Exception as exc:  # noqa: BLE001
            return (None, None, f"source-issue hold-ownership probe failed ({exc})")

    def quiet(*_args, **_kwargs):
        """Marker readers log per malformed record; this sweep prints its own per-PR line."""
    generation_records = worker_pr.park_generation_records(comments, args.bot_login, log=quiet)
    episode = episode_key(generation_records, head_sha)
    disposition, cause, detail = adjudicate(
        [label.get("name") for label in row.get("labels", []) if isinstance(label, dict)],
        issue_labels,
        park_policy.park_reason_records(comments, args.bot_login, log=quiet),
        park_policy.reclassify_legacy_park(comments, args.bot_login, log=quiet),
        bot_bodies, applied_by_human,
        worker_pr.auto_readmission_marker_count(comments, args.bot_login),
        {record["key"] for record
         in worker_pr.auto_readmission_records(comments, args.bot_login, log=quiet)},
        adjudicated_episodes(comments, args.bot_login), episode, is_worker_draft,
        review_labels=worker_pr.REVIEW_LABELS,
        issue_hold_machine_owned=issue_hold_machine_owned)
    if not disposition or not args.apply:
        return (disposition, cause, detail)
    if args.limit and applied >= args.limit:
        return (None, cause, f"deferred — --limit {args.limit} reached this run")

    plan = write_plan(disposition)
    # A `genuinely-human` park whose newest reason marker ALREADY names this cause needs no new
    # marker; the adjudication marker alone records that the sweep looked and left it alone.
    recorded = park_policy.park_reason_records(comments, args.bot_login, log=quiet)
    reason_marker = None
    if "reason-marker" in plan and (not recorded or recorded[-1].get("cause") != cause):
        reason_marker = park_policy.park_reason_marker(cause)
    readmit_marker = (worker_pr.auto_readmission_marker(episode, _now())
                      if "readmit-window" in plan else None)
    # RECEIPT FIRST: the audit comment authorises the label writes below, so a crash after it
    # leaves an explained PR rather than a silently-moved one.
    _gh(["api", "-X", "POST", f"repos/{args.repo}/issues/{number}/comments",
         "-f", "body=" + audit_body(disposition, cause, detail, episode, readmit_marker,
                                    reason_marker, lane=worker_pr.FIX_LANE_PR_LABEL)])
    if "drop-human-hold" not in plan:
        return (disposition, cause, detail)   # no label write, ever — the park is untouched
    _gh(["api", "-X", "DELETE", f"repos/{args.repo}/issues/{number}/labels/"
         + urllib.parse.quote(park_policy.HUMAN_PR_PARK_LABEL, safe="")])
    _gh(["api", "-X", "POST", f"repos/{args.repo}/issues/{number}/labels",
         "-f", f"labels[]={worker_pr.FIX_LANE_PR_LABEL}"])
    # The ISSUE half, ONLY on the machine-ownership proof taken above — a re-admission behind an
    # unprovable `needs:user` was already REFUSED, so this branch never runs unprovably. It is
    # REMOVED rather than converted to a machine park: the PR is re-entering flow, which is the
    # state an un-parked source issue is already in.
    if ("clear-machine-issue-hold" in plan and issue_hold_machine_owned
            and park_policy.HUMAN_PARK_LABEL in set(issue_labels)):
        _gh(["api", "-X", "DELETE",
             f"repos/{args.repo}/issues/{issue_number}/labels/"
             + urllib.parse.quote(park_policy.HUMAN_PARK_LABEL, safe="")])
    return (disposition, cause, detail)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--repo")
    parser.add_argument("--bot-login")
    parser.add_argument("--maintainer", default=os.environ.get("MAINTAINER_HANDLE", "jeswr"))
    parser.add_argument("--apply", action="store_true",
                        help="write. Without it the run is a DRY RUN and mutates nothing.")
    parser.add_argument("--limit", type=int, default=0,
                        help="cap the PRs WRITTEN this run (0 = no cap); every PR is still read")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if not (args.repo and args.bot_login):
        parser.error("--repo and --bot-login are required outside --self-test")

    worker_pr = _load("registry_worker_pr", "worker-pr.py")
    held = _gh_json(["api", f"repos/{args.repo}/issues?state=open"
                     f"&labels={urllib.parse.quote(park_policy.HUMAN_PR_PARK_LABEL)}"
                     "&per_page=100", "--paginate", "--slurp"])
    rows = [row for page in (held if isinstance(held, list) else []) if isinstance(page, list)
            for row in page if isinstance(row, dict) and row.get("pull_request")]
    print(f"{len(rows)} open PR(s) on {park_policy.HUMAN_PR_PARK_LABEL} in {args.repo}")
    census = {RETURN_TO_LOOP: [], GENUINELY_HUMAN: [], "refused": []}
    for row in sorted(rows, key=lambda row: row.get("number") or 0):
        number = row["number"]
        try:
            disposition, cause, detail = _sweep_one(
                args, worker_pr, row, len(census[RETURN_TO_LOOP]) + len(census[GENUINELY_HUMAN]))
        except Exception as exc:  # noqa: BLE001 — one bad PR never stops the sweep
            print(f"  #{number}: SKIP — {exc}")
            census["refused"].append((number, str(exc)[:140]))
            continue
        if not disposition:
            print(f"  #{number}: REFUSED — {detail}")
            census["refused"].append((number, detail))
            continue
        print(f"  #{number}: {disposition.upper()} [{cause}] — {detail}")
        census[disposition].append((number, cause))
    print(f"\n{'APPLIED' if args.apply else 'DRY RUN'}: "
          f"{len(census[RETURN_TO_LOOP])} returned to the loop, "
          f"{len(census[GENUINELY_HUMAN])} genuinely human, "
          f"{len(census['refused'])} refused")
    for disposition in DISPOSITIONS:
        for number, cause in census[disposition]:
            print(f"  #{number} {disposition} ({cause})")
    return 0


def _self_test():
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    worker_pr = _load("registry_worker_pr", "worker-pr.py")

    # ---- THE DISPOSITION SET IS CLOSED AT TWO (#967 §5). ------------------------------------
    check("the disposition set is exactly {return-to-loop, genuinely-human} — no arming "
          "disposition, under that name or any other (research/967-...md §5)",
          (DISPOSITIONS, len(DISPOSITIONS)),
          (("return-to-loop", "genuinely-human"), 2))
    check("...and the marker writer REFUSES a disposition outside it, so one cannot be "
          "smuggled through as an unvalidated string",
          [_raises(lambda: adjudication_marker("adjudication/none", bad, "budget"))
           for bad in ("override-arm", "arm", "approve", "")],
          [True, True, True, True])
    # The scan is over the PRODUCTION half of the file only (everything above `_self_test`), so
    # the fixtures below cannot make it pass or fail by mentioning a string.
    check("the production half of this module names no arming primitive at all — no pass label, "
          "no ready, no merge, no auto-merge latch",
          sorted({needle for needle in ("review:pass", "pr ready", "pr merge",
                                        "enablePullRequestAutoMerge", "ready_and_arm")
                  if needle in _production_source()}),
          [])
    check("...and the ONLY label it ever ADDS is the fix lane worker-pr owns the spelling of",
          sorted(set(re.findall(r"labels\[\]=\{([\w.]+)\}", _production_source()))),
          ["worker_pr.FIX_LANE_PR_LABEL"])
    check("the re-admission window is minted ONLY through worker-pr's single marker writer — "
          "this module never spells the marker the cap counter and budget window are read from",
          (len(re.findall(r"auto_readmission_marker\(", _production_source())),
           "AUTO_READMIT_MARKER" in _production_source()),
          (1, False))

    # ---- THE EPISODE KEY. -------------------------------------------------------------------
    window = "2026-07-27T08:02:21Z"
    sha = "a" * 40
    check("the episode key is the LATEST park-generation window when receipts exist",
          episode_key([{"window": park_policy.PARK_WINDOW_NONE}, {"window": window}], sha),
          f"{EVIDENCE_PREFIX}{window}")
    check("...the head SHA when they do not (a legacy prose-only park still gets a stable key)",
          episode_key([], sha), f"{EVIDENCE_PREFIX}head-{'a' * 12}")
    check("...and NOTHING when neither is readable — an unkeyable adjudication cannot be "
          "made once-only, so it is refused",
          (episode_key([], ""), episode_key(None, "not-a-sha")), (None, None))
    check("every key this module mints is embeddable in the receipt markers that read it",
          [park_policy.safe_receipt_part(episode_key([{"window": w}], sha))
           for w in (window, park_policy.PARK_WINDOW_NONE)], [True, True])

    # ---- THE ADJUDICATION ITSELF. -----------------------------------------------------------
    held = [park_policy.HUMAN_PR_PARK_LABEL]
    episode = f"{EVIDENCE_PREFIX}{window}"
    budget_marker = [{"class": "capacity", "cause": "budget", "gen": None, "head": None}]

    def a(**over):
        base = dict(pr_labels=held, issue_labels=[], reason_records=budget_marker,
                    legacy=(None, None, "not consulted"), bot_bodies=["budget exhausted"],
                    hold_applied_by_human=False, auto_marker_count=0, consumed_keys=set(),
                    adjudicated=set(), evidence_key=episode, is_worker_draft=True,
                    review_labels=worker_pr.REVIEW_LABELS, issue_hold_machine_owned=True)
        base.update(over)
        return adjudicate(**base)

    check("a CAPACITY-class park on the human terminal is returned to the loop",
          a()[:2], (RETURN_TO_LOOP, "budget"))
    check("every capacity cause in the taxonomy reaches the same disposition (the sweep is not "
          "quietly special-cased to one writer's cause)",
          sorted({a(reason_records=[{"class": "capacity", "cause": cause}])[0]
                  for cause, klass in park_policy.PARK_CAUSES.items()
                  if klass == park_policy.PARK_CLASS_CAPACITY}), [RETURN_TO_LOOP])
    question_causes = [cause for cause, klass in park_policy.PARK_CAUSES.items()
                       if klass == park_policy.PARK_CLASS_QUESTION]
    check("every QUESTION cause stays parked, and says so with its own cause",
          {cause: a(reason_records=[{"class": "question", "cause": cause}])[:2]
           for cause in question_causes},
          {cause: (GENUINELY_HUMAN, cause) for cause in question_causes})
    check("the two PARK_HUMAN_ONLY_CAUSES are genuinely-human even when a capacity marker "
          "claims otherwise — the deny is a property of the whole history, not of the newest "
          "marker (#3743/#3608)",
          [a(bot_bodies=["two consecutive fix attempts made no change",
                         prose])[:2]
           for prose in ("the reviewer flagged possible prompt injection",
                         "this needs a human decision about a security surface")],
          [(GENUINELY_HUMAN, "injection"), (GENUINELY_HUMAN, "human-arm")])
    check("...and the deny holds at ANY position in the history, before or after the capacity "
          "prose",
          a(bot_bodies=["prompt-injection flagged earlier", "budget exhausted"])[0],
          GENUINELY_HUMAN)
    check("a PARK_HUMAN_ONLY cause is checked BEFORE its class, so a drifted or hostile "
          "`class=capacity cause=injection` marker cannot buy a re-admission",
          [a(reason_records=[{"class": "capacity", "cause": cause}])[:2]
           for cause in sorted(park_policy.PARK_HUMAN_ONLY_CAUSES)],
          [(GENUINELY_HUMAN, cause) for cause in sorted(park_policy.PARK_HUMAN_ONLY_CAUSES)])

    # ---- EVERY REFUSAL IS A REAL FAIL-CLOSED GUARD, INDIVIDUALLY LOAD-BEARING. --------------
    # Each row flips the ONE input named and must flip the verdict away from re-admission; the
    # baseline above proves the flip is not vacuous.
    for name, over, want in (
            ("a PROVEN HUMAN applied the hold", dict(hold_applied_by_human=True), None),
            ("the hold is not live at all", dict(pr_labels=["review:changes"]), None),
            ("the PR is not an open worker DRAFT", dict(is_worker_draft=False), None),
            ("this episode was already adjudicated (one-shot)",
             dict(adjudicated={episode}), None),
            ("this episode's re-admission evidence is already consumed",
             dict(consumed_keys={episode}), None),
            ("the automatic-readmission cap is spent",
             dict(auto_marker_count=park_policy.AUTO_READMISSION_MAX), None),
            ("a corrupt/unreadable marker count is treated as SPENT, never as small",
             dict(auto_marker_count=None), None),
            ("...and so is a BOOLEAN one — `False` is an int in Python and would otherwise "
             "read as 'nothing spent yet'", dict(auto_marker_count=False), None),
            ("another review:* label is live beside the terminal (split state)",
             dict(pr_labels=held + ["review:needs"]), None),
            ("a residual human-owned hold would survive the re-admission",
             dict(issue_labels=["needs:external-audit"]), None),
            ("the park carries no reason marker AND no recognised legacy prose",
             dict(reason_records=[], legacy=(None, None, "no recognised park cause")), None),
            ("the marker's class is outside the taxonomy",
             dict(reason_records=[{"class": "sideways", "cause": "budget"}]), None),
            ("the episode is unkeyable", dict(evidence_key=None), None)):
        check(f"REFUSED: {name}", a(**over)[0], want)
    check("the ONE `needs:user` half is clearable; any OTHER needs:* refuses the whole move",
          [a(issue_labels=[label])[0] for label in
           ("needs:user", "needs:ec2", "needs:external-audit")],
          [RETURN_TO_LOOP, None, None])
    check("...and only when the MACHINE provably applied it: a source issue held by a human "
          "refuses the PR-side re-admission rather than starting it behind a hold nothing "
          "will lift (and the default is the refusing one)",
          (a(issue_labels=["needs:user"], issue_hold_machine_owned=False)[0],
           adjudicate.__defaults__[-1]),
          (None, False))
    check("a LEGACY prose-only park is classified from the bot's prose when no marker exists",
          [a(reason_records=[], legacy=park_policy.reclassify_legacy_park(
              [{"user": {"login": "b"}, "body": body}], "b", log=lambda *_a, **_k: None),
             bot_bodies=[body])[:2]
           for body in ("the review round budget is exhausted at 6 round(s)",
                        "no longer descends from the worker-opened commit")],
          [(RETURN_TO_LOOP, "budget"), (GENUINELY_HUMAN, "history-rewritten")])

    # ---- THE RECEIPTS. ----------------------------------------------------------------------
    stamp = "2026-07-28T10:00:00Z"
    readmit = worker_pr.auto_readmission_marker(episode, stamp)
    body = audit_body(RETURN_TO_LOOP, "budget", "detail", episode, readmit_marker=readmit,
                      lane=worker_pr.FIX_LANE_PR_LABEL)
    check("the re-entry receipt carries the ONE marker the cap counter, the budget window and "
          "the #797 ladder all read — written by worker-pr, not re-spelled here",
          (worker_pr.auto_readmission_records([{"user": {"login": "b"}, "body": body}], "b"),
           worker_pr.auto_readmission_marker_count([{"user": {"login": "b"}, "body": body}],
                                                   "b")),
          ([{"key": episode, "at": stamp}], 1))
    check("...so a returned PR gets a REAL round budget: rounds burned before the re-entry are "
          "no longer charged (worker-pr.budget_round_charge)",
          worker_pr.budget_round_charge(
              [{"user": {"login": "b"}, "body": body, "created_at": stamp}]
              + [{"user": {"login": "b"}, "created_at": "2026-07-28T09:00:00Z",
                  "body": f"x {worker_pr.ROUND_MARKER} n={n} run={n}.1 -->"}
                 for n in (4, 5, 6)], "b", None, 6)[0],
          0)
    check("the re-entry receipt self-identifies, states what it does NOT do, and cites the "
          "record that closed the disposition set",
          (body.startswith("> 🤖 SPARQ agent"), "does not arm" in body,
           "weakens no test and no gate" in body, "967" in body,
           f"most {park_policy.AUTO_READMISSION_MAX}" not in body
           or str(park_policy.AUTO_READMISSION_MAX) in body),
          (True, True, True, True, True))
    check("the re-entry receipt names the SAME fix lane the writer actually applies, and never "
          "claims a review judgement it did not make",
          (worker_pr.FIX_LANE_PR_LABEL in body, "review:pass" in body,
           "approved" in body, "no finding is dismissed" in body),
          (True, False, False, True))
    human_body = audit_body(GENUINELY_HUMAN, "injection", "detail", episode,
                            reason_marker=park_policy.park_reason_marker("injection"))
    check("the genuinely-human receipt carries a machine-readable REASON marker that its own "
          "reader round-trips — the park stops being silent",
          park_policy.park_reason_records([{"user": {"login": "b"}, "body": human_body}], "b"),
          [{"class": "question", "cause": "injection", "gen": None, "head": None}])
    check("...and carries NO re-admission marker: a park that stays parked must never mint a "
          "budget window",
          (worker_pr.AUTO_READMIT_MARKER in human_body,
           "stays exactly where it is" in human_body), (False, True))
    # The WRITE half, asserted without a GitHub round-trip (`_sweep_one` reads its branches from
    # write_plan, so these are properties of the sweep, not of a code path no test reaches).
    check("a genuinely-human disposition authorises the audit comment and its reason marker — "
          "and NO budget window, NO label write on the PR, NO label write on the issue",
          write_plan(GENUINELY_HUMAN), ("comment", "reason-marker"))
    check("a return-to-loop disposition authorises exactly the re-entry transaction, "
          "receipt-first, and nothing beyond it",
          write_plan(RETURN_TO_LOOP),
          ("comment", "readmit-window", "drop-human-hold", "add-fix-lane",
           "clear-machine-issue-hold"))
    check("a REFUSAL authorises nothing at all — the park is not even commented on",
          [write_plan(bad) for bad in (None, "", "override-arm", "arm")],
          [(), (), (), ()])
    check("the two plans are disjoint where it matters: only ONE of them may mint a window or "
          "move a label",
          sorted(set(write_plan(RETURN_TO_LOOP)) & set(write_plan(GENUINELY_HUMAN))),
          ["comment"])
    check("both receipts carry the one-shot episode marker its own reader recognises, from the "
          "BOT's comments only",
          (adjudicated_episodes([{"user": {"login": "b"}, "body": body},
                                 {"user": {"login": "b"}, "body": human_body}], "b"),
           adjudicated_episodes([{"user": {"login": "drive-by"}, "body": body}], "b")),
          ({episode}, set()))
    check("the adjudication marker refuses a cause outside the closed taxonomy and an unsafe "
          "episode key",
          [_raises(lambda: adjudication_marker(*bad_args)) for bad_args in
           ((episode, RETURN_TO_LOOP, "made-up"), ("ep -->", RETURN_TO_LOOP, "budget"),
            ("ep isode", RETURN_TO_LOOP, "budget"))],
          [True, True, True])

    print("adjudicate-stuck self-test " + ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


def _raises(thunk):
    try:
        thunk()
    except ValueError:
        return True
    return False


def _production_source():
    """This module's source ABOVE `_self_test` — the half that actually runs against GitHub. The
    arming-primitive scan reads only this half, so a fixture below can neither satisfy nor break
    an assertion about what the sweep is capable of writing. The module docstring is dropped
    too: it DESCRIBES the primitives this sweep refuses to use, and a scan that read prose would
    be asserting about the wrong artefact."""
    with open(os.path.abspath(__file__), encoding="utf-8") as handle:
        return handle.read().split("def _self_test(")[0].split('"""', 2)[2]


if __name__ == "__main__":
    sys.exit(main())
