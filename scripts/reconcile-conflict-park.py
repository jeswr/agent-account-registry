#!/usr/bin/env python3
"""[registry #953] THE MACHINE EXIT from a conflict-resolver-manufactured `needs:user` on a PR.

THE DEADLOCK THIS EXITS. `resolve-conflicts.py` carries `needs:user` in `HARD_EXCLUDE_LABELS`, so
a PR wearing it is `_skip`ped ("hard exclusion label(s)") BEFORE the rebase, before the escalation,
and — the part that made this invisible — before `_no_exit`, so `--no-exit-threshold 0` cannot see
the population at all. The SAME program is the only writer of that label on these PRs. So a
conflicting PR that the resolver escalates can never again be touched by the resolver, never gets
rebased, never converges on the moving default branch, and (registry #853) gets NO `pr-gate` run at
all while it is `CONFLICTING`. It decays in a state only a human can exit.

MEASURED on jeswr/agent-account-registry 2026-07-28, over ALL 34 open PRs (drafts included): 14
carry `needs:user`. TWO of them (#348, #359) were parked by `jeswr`, type=User — genuine human
decisions. The other TWELVE (#565 #624 #656 #681 #683 #685 #689 #702 #710 #722 #756 #781) were
applied by `sparq-orchestrator[bot]`, ZERO by a human, and every one carries the resolver's own
`<!-- conflict-resolver escalated -->` receipt. Counting durable `attempt=` markers, ELEVEN of the
twelve have exactly ONE — they came through the `stuck-attempt-escalation` grace-window branch
(#753), i.e. a TIMEOUT took the human terminal. Only #685 has the two the message claims.

THE SECOND LOCK, WHICH THIS PROGRAM DOES NOT REPAIR AND MUST NOT BE CONFUSED WITH. Of those twelve,
ZERO are visible to the review/fix lane (no `sparq-agent/issue-N-` head ref). A park exit cannot
make an unenrollable PR reviewable; that repair is #657/#681. This program reports the axis so the
two are counted apart, and refuses to gate on it — see LANE_HEAD_RE.

RELATIONSHIP TO #941. #941 fixes the SOURCE, forward: the grace-window exit stops taking the human
class. It states its own boundary out loud — "No existing `needs:user` is cleared. This is the
source fix, applied forward." The population already parked by the old path is therefore covered by
neither program, and it is what this one owns. Nothing here writes `needs:user`; this program can
only ever REMOVE one, and only on proof.

WHY A SCHEDULED SWEEP AND NOT A HAND-RUN SCRIPT. `reconcile-park-misescalation.py` argues — for its
own population — that teaching a routine tick to strip a human-owned label trades one silent
failure for a worse one. That argument binds a sweep whose proof is "no human is visible". It does
not bind this one, because the exit here is not "nobody objected": it is POSITIVE proof that the
machine applied the label, plus positive proof that the label's own stated cause has RECOVERED. A
human-only unpark is what turns a transient into a permanent stall, and 7 PRs is that stall.

WHAT "CAUSE-RECOVERED" MEANS HERE, AND WHY IT IS NOT A CLOCK. The park's stated cause is "a
mechanical rebase of head H onto the default branch conflicted". Exactly two facts retire it, each
independently sufficient, and each chosen because it hands the NEXT resolver tick an action it has
never taken:

  * `head-moved`      the live head is not any head this resolver recorded an attempt against, so
                      the next sweep's `head_sha in heads` short-circuit does not fire and it
                      performs a FRESH mechanical rebase.
  * `conflict-resolved`  the PR is no longer `mergeable is False`. The stated cause is simply gone.

No branch of this program reads a clock. "It has been N hours" is not a reason and is not
available: the identical park evaluated 1000 h later returns the identical answer.

DELIVERY, NOT MERELY EXIT (registry memo "a 6-hour park buys ONE round on an UNCHANGED tree"). An
exit that re-admits a PR into the state it just left has produced nothing. That is why
`cause-unrecovered` is a REFUSAL rather than a timed release: for a PR whose head has not moved and
which still conflicts, clearing the label would re-derive the identical escalation with no new
attempt in between. Such a PR stays parked and is REPORTED every run, armed on its cause.

WHY THE TWO-DISTINCT-HEAD CLASS IS NEVER CLEARED, executably rather than by deference. Clearing it
delivers nothing: `resolve-conflicts._process_pr` reaches `if len(heads) >= 2: self._escalate(...)`
BEFORE any rebase budget, so the very next sweep re-applies the label without attempting anything.
It is also the one exit #941 keeps in the human class on the merits.

BOUNDED. Every clear is receipted durably and bot-authored; the receipt names `(cause, head)` and
is the consume-exactly-once key, so the same recovery can never be spent twice; and at most
`RECONCILE_MAX` clears may ever be granted to one PR — past the cap the program stops trying and
says so. Receipt COUNT includes malformed receipts, so a corrupt receipt can never buy a clear.

DRY-RUN IS THE DEFAULT. `--apply` is required to write anything. A census row is printed for EVERY
considered PR on EVERY run — including a run that clears nothing and a run whose population is
empty — split into the HUMAN-TERMINAL (genuine) and EXIT-REACHABLE (machine, waiting on its cause)
classes. A silent sweeper turns a visible backlog into an invisible one.

PR content is untrusted: this program never clones a PR, never runs target code, tests or hooks,
and reads only the GitHub API.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import park_policy


def _load(modname, filename):
    path = Path(__file__).resolve().parent / filename
    spec = importlib.util.spec_from_file_location(modname, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load registry helper {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The on-PR wire protocol this program reads is OWNED by resolve-conflicts.py, so it is IMPORTED
# from there rather than re-declared. A second private copy of `attempt=`/`escalated` is exactly
# how two readers of one durable format drift apart in silence; an import turns a rename in the
# owning program into a LOUD self-test failure here instead.
_resolver = _load("registry_resolve_conflicts", "resolve-conflicts.py")
ATTEMPT_RE = _resolver.ATTEMPT_RE
ESCALATION_MARKER = _resolver.ESCALATION_MARKER
# [#941 INTERACTION — the merge-composition hazard, closed by IMPORTING the other program's own
# predicate rather than restating it.] #941's `_escalate_stuck` writes the HUMAN terminal once a
# grace-window park goes past `STUCK_UNPARK_MAX` (`stuck_park_label`), and that over-cap write
# ALSO emits `ESCALATION_MARKER` beside its receipt — so a PR #941 handed to a human PRECISELY FOR
# EXHAUSTING ITS AUTOMATIC BUDGET is byte-indistinguishable, on the two facts this program
# originally read, from a pre-#941 timeout park. It is single-attempt too, because the grace-window
# branch only fires when `head_sha in heads and len(heads) == 1`. Left alone, this program would
# grant it `RECONCILE_MAX` more releases: an EFFECTIVE CAP OF FOUR, assembled from two mechanisms
# each correct alone. Each of the three names below is asserted against the owning module in
# `_self_test`, so a rename or a semantic change there fails LOUDLY here rather than silently
# re-opening the compose hole.
STUCK_PARK_MARKER = _resolver.STUCK_PARK_MARKER
STUCK_UNPARK_MAX = _resolver.STUCK_UNPARK_MAX
stuck_receipts = _resolver.stuck_receipts

RECONCILE_MARKER = "<!-- sparq-conflict-park-reconciled:v1"
RECEIPT_RE = re.compile(
    re.escape(RECONCILE_MARKER) + r" pr=(\d+) cause=([a-z-]+) head=([0-9a-f]{40}) gen=(\d+) -->"
)
# At most this many automatic clears may EVER be granted to one PR. Past it the loop stops trying:
# a PR that keeps re-acquiring this park after two real, distinct recoveries is a genuine human
# question about the change, not about the pipeline.
RECONCILE_MAX = 2
# Live REVIEW decisions. `park_policy.human_owned_holds` covers `review:needs-user` and the
# `needs:*` family, but NOT `review:changes` — a reviewer's substantive "changes requested", which
# on the measured population is human-applied (#781, `jeswr`, type=User) and is precisely the kind
# of standing judgement a false clear would discard. Named here because the residual-hold rule
# this program must apply is strictly WIDER than the shared one, never narrower.
REVIEW_DECISION_HOLDS = ("review:changes", "review:needs-user")
# THE SECOND AXIS, REPORTED AND NEVER CONSULTED. A park is one lock; LANE ADMISSIBILITY is a
# different one, and the two need different exits. The review/fix lane selects PRs by head-ref
# shape, so a PR on any other branch is invisible to it no matter what its labels say — no amount
# of cause-recovery re-admits it, because it was never admissible. MEASURED on
# jeswr/agent-account-registry 2026-07-28: of the 12 machine-parked conflict PRs, ZERO are
# lane-visible; #681 (`feat/self-declared-dual-review`, the fix for lane invisibility) is itself
# lane-invisible, draft, CONFLICTING and `needs:user` — four independent locks on one PR.
#
# This axis annotates the census so the two populations are countable apart. It is deliberately
# NOT an input to `verdict`: gating the conflict park on lane shape would be wrong (the
# conflict-resolver handles non-lane PRs directly — `owned_by_review_rebase_lane` CEDES lane
# branches, it does not claim them), and a reported axis that quietly became a decision is how a
# census turns into an unreviewed policy. `_self_test` asserts it stays inert.
LANE_HEAD_RE = re.compile(r"^sparq-agent/issue-([1-9][0-9]*)-")

# --- the closed refusal taxonomy ------------------------------------------------------------
# HUMAN-TERMINAL: nothing this program will ever do clears it; only a human gesture can.
# EXIT-REACHABLE: machine-owned and self-healing; a later tick clears it once its cause recovers.
# A code outside this taxonomy is a defect, not a quiet default — `census_summary` counts it as
# `unclassified` and the run says so.
ADMIT_CODES = {
    "head-moved": "cleared-head-moved",
    "conflict-resolved": "cleared-conflict-resolved",
}
REFUSAL_HUMAN_TERMINAL = (
    "human-applied",        # a PROVEN human applied `needs:user` at some point in this history
    "budget-exhausted",     # #941 wrote this terminal for exhausting ITS automatic budget
    "human-review-hold",    # a live review decision (review:changes / review:needs-user)
    "residual-hold",        # a needs:* hold would survive the clear on the PR or its issue
    "deny-prose",           # an injection / human-arm signal is recorded by the bot
    "two-head-exhaustion",  # the class the resolver reaches on >= 2 distinct attempted heads
    "cap-reached",          # RECONCILE_MAX automatic clears already granted
    "not-population",       # no conflict-resolver escalation receipt: not this program's park
)
REFUSAL_EXIT_REACHABLE = (
    "cause-unrecovered",    # head unmoved AND still conflicting: clearing delivers no new action
    "already-cleared",      # this exact (cause, head) recovery is already spent
    "no-live-park",         # no `needs:user` on the PR at all
    "read-failed",          # the PR could not be read this tick; the next one retries
)


def refusal_exit_class(code):
    """"human-terminal" / "exit-reachable" for a refusal `code`, None for anything outside the
    closed taxonomy. An unrecognised code is never silently filed as self-healing: None forces the
    caller to surface it, because a refusal nobody classified is what this exists to stop."""
    if code in REFUSAL_HUMAN_TERMINAL:
        return "human-terminal"
    if code in REFUSAL_EXIT_REACHABLE:
        return "exit-reachable"
    return None


def census_record(census, repo, number, code, detail, lane_visible=None):
    """Append EXACTLY ONE census row. The ONLY writer of a row: a second hand-built append is how
    the `exit` class drifts from `refusal_exit_class`, and that class is the whole machine/genuine
    split this program exists to publish. `lane_visible` is the second axis (annotation only)."""
    if not isinstance(census, list):
        return
    census.append({
        "repo": repo, "number": number, "code": code,
        "exit": (None if code in set(ADMIT_CODES.values()) else refusal_exit_class(code)),
        "lane_visible": lane_visible, "detail": detail,
    })


def census_summary(records):
    """PURE. (counts_by_code, cleared, human_terminal, exit_reachable, unclassified, lane_split).

    Malformed rows are counted under the reserved `malformed` code rather than dropped — a census
    that silently discards what it cannot parse is how a population goes missing in the first
    place. The number lists are ascending and de-duplicated.

    `lane_split` is the SECOND AXIS: {"lane_visible": [...], "lane_invisible": [...],
    "lane_unknown": [...]}. A park exit and a lane enrolment are different repairs, and a census
    that reports only the park axis cannot tell an operator which one a PR is actually waiting
    on."""
    counts, cleared, terminal, reachable, unclassified = {}, set(), set(), set(), set()
    lanes = {"lane_visible": set(), "lane_invisible": set(), "lane_unknown": set()}
    admits = set(ADMIT_CODES.values())
    for record in records if isinstance(records, (list, tuple)) else []:
        if not isinstance(record, dict):
            counts["malformed"] = counts.get("malformed", 0) + 1
            continue
        code, number = record.get("code"), record.get("number")
        if not isinstance(code, str) or not code:
            counts["malformed"] = counts.get("malformed", 0) + 1
            continue
        counts[code] = counts.get(code, 0) + 1
        if not isinstance(number, int) or isinstance(number, bool):
            continue
        lane = record.get("lane_visible")
        lanes["lane_visible" if lane is True
              else "lane_invisible" if lane is False else "lane_unknown"].add(number)
        if code in admits:
            cleared.add(number)
            continue
        klass = refusal_exit_class(code)
        if klass == "human-terminal":
            terminal.add(number)
        elif klass == "exit-reachable":
            reachable.add(number)
        else:
            unclassified.add(number)
    ordered = {code: counts[code] for code in sorted(counts)}
    lane_split = {key: sorted(value) for key, value in sorted(lanes.items())}
    return (ordered, sorted(cleared), sorted(terminal), sorted(reachable), sorted(unclassified),
            lane_split)


def attempt_heads(bot_bodies):
    """The distinct heads this resolver recorded a conflict attempt against, oldest first. Read
    ONLY from the BOT's own comment bodies (the caller filters): a third party must not be able to
    manufacture — or erase — an attempt history and so decide this park either way."""
    heads = []
    for body in bot_bodies or []:
        for match in ATTEMPT_RE.finditer(str(body)):
            head = match.group(2)
            if head not in heads:
                heads.append(head)
    return heads


def escalation_recorded(bot_bodies):
    """Whether the resolver's own terminal receipt is present. Positive proof that THIS program's
    population is what we are looking at, rather than a `needs:user` some other writer applied."""
    return any(ESCALATION_MARKER in str(body) for body in (bot_bodies or []))


def clear_receipts(comments, bot_login):
    """(receipts, count) from the BOT's own comments.

    `receipts` are the well-formed `(cause, head)` pairs — the consume-exactly-once keys.
    `count` is EVERY marker occurrence including malformed ones, and it is what the cap reads: a
    corrupt receipt must never look like a clear that did not happen, so it can never buy an extra
    grant. (The same discipline as worker-pr.auto_readmission_marker_count.)"""
    receipts, count = [], 0
    want = str(bot_login or "\0").casefold()
    for comment in comments if isinstance(comments, list) else []:
        if not isinstance(comment, dict):
            continue
        if str((comment.get("user") or {}).get("login", "")).casefold() != want:
            continue
        body = str(comment.get("body", ""))
        count += body.count(RECONCILE_MARKER)
        for match in RECEIPT_RE.finditer(body):
            receipts.append({"cause": match.group(2), "head": match.group(3),
                             "generation": int(match.group(4))})
    return receipts, count


def human_ever_applied(timeline, label, is_human):
    """Whether a PROVEN human EVER applied `label` — not merely whether the NEWEST application was
    human, which is what `park_policy.label_application_machine_owned` answers.

    Deliberately STRICTER than the shared newest-wins rule, in the only direction that is safe
    here: a human who parks a PR and a bot that re-parks it later reads as machine-owned under
    newest-wins, and this program would then delete the human's decision. Both rules are applied
    (the caller ANDs them); this one is the one that can only ever refuse more.

    Raises on an unreadable/malformed timeline. The caller fails closed on the exception — an
    unreadable history is never permission."""
    probe = park_policy._human_probe(is_human)      # noqa: SLF001 — the shared probe, one owner
    for created, kind, login, via_app in park_policy._event_rows(timeline, label):  # noqa: SLF001
        if kind != "labeled":
            continue
        park_policy.parse_ts(created)               # a malformed instant raises: never ignored
        if park_policy._is_proven_human(login, via_app, probe):   # noqa: SLF001
            return True
    return False


def machine_applied(timeline, label, is_human=None):
    """POSITIVE proof that the newest application of `label` was made by an automation identity:
    an App-driven event, or an actor login ending in `[bot]`.

    THE DEFINITION IS NO LONGER HERE (registry #1849). This program kept a private walk because
    `label_application_machine_owned` answered only "the newest applier was not a PROVEN human",
    so an actor nobody could classify read as permission to delete — and every consumer of that
    answer had to remember to compensate locally, which is the #958 shape. park_policy owns the
    quantifier now: MACHINE is a positive proof and an unattributable actor answers
    LABEL_OWNER_UNATTRIBUTABLE, so this is a THIN projection of the shared walk rather than a
    second definition of it (AGENTS.md pre-flight 4 — a guard written twice is unkillable in
    either copy).

    It stays a named function for ONE reason the shared BOOLEAN cannot serve: it RAISES on an
    unreadable/malformed timeline instead of absorbing it into False, and `reconcile_repo` needs
    that to file a broken read as `read-failed` rather than as a human-terminal verdict."""
    return park_policy.label_owner_from_events(
        timeline, label, is_human=is_human) == park_policy.LABEL_OWNER_MACHINE


def verdict(*, pr_labels, issue_labels, live_head, live_mergeable, heads, escalated,
            hold_applied_by_human, bot_bodies, receipts, receipt_count, stuck_park_gen=None,
            reconcile_max=RECONCILE_MAX, stuck_unpark_max=STUCK_UNPARK_MAX):
    """PURE. (cause, code, detail). `cause is None` means REFUSED and the park stands exactly as
    it is — every ambiguity lands there.

    `heads` is `attempt_heads(...)`; `receipts`/`receipt_count` are `clear_receipts(...)`;
    `hold_applied_by_human` MUST be True whenever it could not be determined (fail closed at the
    call site); `bot_bodies` are the BOT's own comment bodies and nobody else's."""
    labels = {label for label in (pr_labels or []) if isinstance(label, str)}
    if park_policy.HUMAN_PARK_LABEL not in labels:
        return (None, "no-live-park",
                f"no live `{park_policy.HUMAN_PARK_LABEL}` — nothing to reconcile")
    # UNCONDITIONAL and order-independent: a security signal anywhere in the bot's own history
    # denies the clear outright, so a later ordinary conflict comment can never talk it out of the
    # terminal. Read through park_policy.legacy_deny_signal and never over the prose table
    # directly (#814 round 2): the bot's history includes REPUBLISHED model verdict text, and a
    # sentence in one is evidence about the model, not about the loop.
    for body in bot_bodies or []:
        denied = park_policy.legacy_deny_signal(body)
        if denied:
            return (None, "deny-prose",
                    f"a {denied!r} signal is recorded on this PR — never automatically "
                    "cleared, at any position in its history")
    if hold_applied_by_human:
        return (None, "human-applied",
                "a PROVEN HUMAN applied the hold (or its ownership could not be proven "
                "machine-made) — a human decision is not the machine's to undo")
    # [#941 INTERACTION] Positive proof, from #941's OWN durable receipt, that this terminal was
    # written for exhausting THAT program's automatic re-admission budget. Releasing it would hand
    # a further `reconcile_max` grants to a PR whose whole reason for being here is that its grants
    # ran out — the two caps would COMPOSE into one of four. A flap is a genuine question.
    if stuck_park_gen is not None and stuck_park_gen > stuck_unpark_max:
        return (None, "budget-exhausted",
                f"#941's grace-window park reached generation {stuck_park_gen}, past its "
                f"STUCK_UNPARK_MAX of {stuck_unpark_max}: this terminal IS the exhaustion of the "
                "conflict lane's own automatic budget, and a second mechanism must not re-grant "
                "what the first deliberately stopped granting")
    live_review = sorted(labels & set(REVIEW_DECISION_HOLDS))
    if live_review:
        return (None, "human-review-hold",
                f"{', '.join(live_review)} is a live review decision — clearing the conflict park "
                "would re-admit a PR a reviewer is holding")
    residual = park_policy.migration_residual_holds(
        labels - {park_policy.HUMAN_PARK_LABEL}, set(issue_labels or []),
        clearing=[park_policy.HUMAN_PARK_LABEL])
    if residual:
        return (None, "residual-hold",
                f"{'/'.join(residual)} would still hold this work after the clear — refusing to "
                "release a park into a state it could not leave")
    if not escalated or not heads:
        return (None, "not-population",
                "no conflict-resolver escalation receipt — this `needs:user` was not written by "
                "the conflict lane, so it is not this program's to clear")
    if len(heads) >= 2:
        return (None, "two-head-exhaustion",
                f"{len(heads)} distinct attempted heads: this is the two-distinct-head exhaustion "
                "class, and clearing it delivers nothing — the next sweep re-escalates at "
                "`len(heads) >= 2` before it reaches any rebase budget")
    if receipt_count >= reconcile_max:
        return (None, "cap-reached",
                f"{receipt_count} automatic clear(s) already granted, meeting RECONCILE_MAX "
                f"({reconcile_max}) — a park re-acquired after that many real recoveries is a "
                "genuine question about the change")
    # THE CAUSE. Two facts, each independently sufficient, each handing the next resolver tick an
    # action it has never taken. Nothing below reads a clock.
    if live_mergeable is True:
        cause = "conflict-resolved"
        basis = "the PR is no longer `mergeable is False`: the park's stated cause is gone"
    elif live_head and live_head not in heads:
        cause = "head-moved"
        # `heads` is non-empty here because the not-population guard above requires it. The
        # fallback exists so that BYPASSING that guard yields a WRONG ANSWER a named check catches,
        # rather than an IndexError that aborts the suite before any `FAIL:` row prints — a mutant
        # killed only by a traceback tells you the code crashed, not that the guard was load-bearing.
        attempted = heads[-1][:8] if heads else "(no attempt on record)"
        basis = (f"the live head {live_head[:8]} is not the attempted head {attempted}, so the "
                 "next sweep's duplicate-attempt short-circuit does not fire and it performs a "
                 "FRESH mechanical rebase")
    else:
        return (None, "cause-unrecovered",
                "the head has not moved since the recorded attempt and the PR still conflicts — "
                "clearing the hold would re-derive the identical escalation with no new attempt "
                "in between, which is not an exit")
    if any(receipt.get("cause") == cause and receipt.get("head") == live_head
           for receipt in receipts or []):
        return (None, "already-cleared",
                f"this exact recovery (cause={cause} head={live_head[:8]}) is already spent — a "
                "new clear needs a NEW recovery, never the same one twice")
    return (cause, ADMIT_CODES[cause], basis)


def audit_body(number, cause, head, generation, detail, reconcile_max=RECONCILE_MAX):
    """The per-PR record. It quotes the evidence a reader can re-derive from the PR itself, and it
    carries its own consume-once receipt, so this run does not have to be trusted."""
    return (
        "> 🤖 SPARQ agent — **releasing a machine-applied conflict park** (registry #953)\n\n"
        f"The `{park_policy.HUMAN_PARK_LABEL}` on this pull request was applied by the "
        "conflict-resolver, not by a human: its own "
        f"`{ESCALATION_MARKER}` receipt is on this thread, and every `labeled` event for that "
        "label was made by an automation identity. While it was live, "
        "`resolve-conflicts.py` hard-excluded this PR from the rebase lane entirely — so it could "
        "not converge on the moving default branch, and a `CONFLICTING` PR gets no `pr-gate` run "
        "at all (registry #853).\n\n"
        f"**The park's cause has recovered: `{cause}`.** {detail}\n\n"
        "So the hold is released and the conflict lane owns this PR again. No review judgement is "
        "implied or changed, no label other than "
        f"`{park_policy.HUMAN_PARK_LABEL}` is touched, and nothing here arms, merges or rebases "
        "anything.\n\n"
        f"This release is receipted below and **consumed exactly once**: the same "
        f"`(cause, head)` recovery can never grant a second one, and at most {reconcile_max} "
        "automatic releases are ever granted to one pull request.\n\n"
        "A human can hold this PR again at any time by re-applying the label — that gesture is "
        "sticky and no automation may override it.\n\n"
        f"{RECONCILE_MARKER} pr={number} cause={cause} head={head} gen={generation} -->\n"
        f"<!-- release basis: {detail} -->")


def render_summary(counts, cleared, terminal, reachable, unclassified, lane_split, considered):
    """The operator table. Written on EVERY run, including one that clears nothing and one whose
    population is empty — the empty run is the one an operator most needs to see, because it is
    indistinguishable from a run that never happened."""
    lines = ["### conflict-park reconciliation census\n",
             f"\n{considered} PR(s) considered; {len(cleared)} released, "
             f"{len(terminal)} human-terminal (genuine), "
             f"{len(reachable)} exit-reachable (machine, awaiting cause).\n",
             "\n| code | count | class |\n| --- | --- | --- |\n"]
    admits = set(ADMIT_CODES.values())
    for code in sorted(counts):
        klass = ("released" if code in admits else (refusal_exit_class(code) or "UNCLASSIFIED"))
        lines.append(f"| {code} | {counts[code]} | {klass} |\n")
    if terminal:
        lines.append(f"\nHuman-terminal: {', '.join('#' + str(n) for n in terminal)}\n")
    if reachable:
        lines.append(f"\nExit-reachable: {', '.join('#' + str(n) for n in reachable)}\n")
    # The SECOND AXIS. A lane-invisible PR is waiting on ENROLMENT, not on this exit, and an
    # operator reading only the park axis would keep waiting for a release that cannot help it.
    invisible = (lane_split or {}).get("lane_invisible") or []
    if invisible:
        lines.append(f"\nLane-INVISIBLE (no head-ref the review/fix lane selects — a park release "
                     f"cannot make these reviewable): "
                     f"{', '.join('#' + str(n) for n in invisible)}\n")
    if unclassified:
        lines.append(f"\n**UNCLASSIFIED refusal codes on: "
                     f"{', '.join('#' + str(n) for n in unclassified)}**\n")
    return "".join(lines)


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


class GhClient:
    """Every GitHub read and write this program performs, in one injectable seam.

    It exists so `reconcile_repo` — the CALL SITE, where the verdict is turned into a label
    deletion — is executable in `--self-test` against a fake. A pure `verdict` pinned by tests
    while the call site independently decides what to write is the exact shape that has shipped
    silent defects in this repo: the guard is proven and the thing it is supposed to guard is not.

    The write surface is deliberately TWO methods. This program can post a comment and remove one
    label. It cannot add a label, push, arm, merge, close, or run anything."""

    def __init__(self, token=None):
        self.token = token

    def _paginated(self, path):
        pages = _gh_json(["api", "--paginate", "--slurp", path], token=self.token)
        if not isinstance(pages, list):
            raise RuntimeError(f"malformed paginated payload for {path}")
        rows = []
        for page in pages:
            if not isinstance(page, list):
                raise RuntimeError(f"malformed page for {path}")
            rows.extend(page)
        return rows

    def parked_pulls(self, repo, label):
        rows = self._paginated(f"repos/{repo}/issues?state=open&per_page=100"
                               f"&labels={urllib.parse.quote(label)}")
        return [row for row in rows if isinstance(row, dict) and row.get("pull_request")]

    def comments(self, repo, number):
        return self._paginated(f"repos/{repo}/issues/{number}/comments?per_page=100")

    def timeline(self, repo, number):
        return self._paginated(f"repos/{repo}/issues/{number}/timeline?per_page=100")

    def pull(self, repo, number):
        return _gh_json(["api", f"repos/{repo}/pulls/{number}"], token=self.token)

    def issue_labels(self, repo, number):
        issue = _gh_json(["api", f"repos/{repo}/issues/{number}"], token=self.token)
        return [label.get("name") for label in ((issue or {}).get("labels") or [])
                if isinstance(label, dict)]

    def post_comment(self, repo, number, body):
        _gh(["api", "-X", "POST", f"repos/{repo}/issues/{number}/comments", "-f", f"body={body}"],
            token=self.token)

    def remove_label(self, repo, number, label):
        _gh(["api", "-X", "DELETE", f"repos/{repo}/issues/{number}/labels/"
             + urllib.parse.quote(label, safe="")], token=self.token)


def reconcile_repo(client, repo, bot_login, maintainer, apply, max_clears, reconcile_max, census):
    """Sweep ONE repository. Returns the number of PRs considered. Every PR appends exactly one
    census row, whatever happens to it — including a read failure."""
    rows = client.parked_pulls(repo, park_policy.HUMAN_PARK_LABEL)
    print(f"SCAN {repo}: {len(rows)} open PR(s) on {park_policy.HUMAN_PARK_LABEL}")
    granted = 0
    for row in sorted(rows, key=lambda row: row.get("number") or 0):
        number = row.get("number")
        lane_visible = None
        try:
            comments = client.comments(repo, number)
            timeline = client.timeline(repo, number)
            bot_bodies = [str(comment.get("body", ""))
                          for comment in comments if isinstance(comment, dict)
                          and str((comment.get("user") or {}).get("login", "")).casefold()
                          == str(bot_login).casefold()]
            pull = client.pull(repo, number)
            # The second axis, plus the source issue it makes derivable. A non-lane head has no
            # derivable source issue, so its residual-hold check covers the PR's labels alone —
            # said out loud because a silently narrower check is the drift this program guards.
            lane_match = LANE_HEAD_RE.match(str(((pull or {}).get("head") or {}).get("ref", "")))
            lane_visible = bool(lane_match)
            issue_labels = client.issue_labels(repo, lane_match.group(1)) if lane_match else []
            # FAIL CLOSED on ownership: BOTH the shared newest-wins rule — which since registry
            # #1849 must POSITIVELY prove a machine applied the park, so an actor nobody can
            # attribute is not permission — and the stricter ever-applied rule must clear it.
            # Anything unreadable raises and lands in `read-failed`, never in permission.
            # ONE walk per rule: the positive-machine proof used to be a second, local definition
            # here (`machine_applied`'s own walk) ANDed onto the shared answer, and once park_policy
            # owns the quantifier a second copy would only make each copy unkillable (AGENTS.md
            # pre-flight 4).
            def _is_human(login, _m=maintainer):
                return str(login or "").casefold() == str(_m).casefold()
            applied_by_human = (
                not machine_applied(timeline, park_policy.HUMAN_PARK_LABEL, is_human=_is_human)
                or human_ever_applied(timeline, park_policy.HUMAN_PARK_LABEL, _is_human))
            receipts, receipt_count = clear_receipts(comments, bot_login)
            # [#941 INTERACTION] The generation of the NEWEST grace-window park #941 recorded, read
            # through ITS OWN trust-filtered reader so the two programs cannot disagree about what
            # counts as a receipt. None when #941 never parked this PR (the pre-#941 population).
            stuck_parks = stuck_receipts(comments, bot_login, STUCK_PARK_MARKER)
            stuck_park_gen = stuck_parks[-1]["gen"] if stuck_parks else None
            cause, code, detail = verdict(
                pr_labels=[label.get("name") for label in (row.get("labels") or [])
                           if isinstance(label, dict)],
                issue_labels=issue_labels,
                live_head=str(((pull or {}).get("head") or {}).get("sha", "")),
                live_mergeable=(pull or {}).get("mergeable"),
                heads=attempt_heads(bot_bodies),
                escalated=escalation_recorded(bot_bodies),
                hold_applied_by_human=applied_by_human,
                bot_bodies=bot_bodies, receipts=receipts, receipt_count=receipt_count,
                stuck_park_gen=stuck_park_gen, reconcile_max=reconcile_max)
        except Exception as exc:      # noqa: BLE001 — one bad PR never stops the sweep
            census_record(census, repo, number, "read-failed", str(exc)[:160], lane_visible)
            print(f"  {repo}#{number}: READ-FAILED — {str(exc)[:160]}")
            continue
        if cause is None:
            census_record(census, repo, number, code, detail, lane_visible)
            print(f"  {repo}#{number}: REFUSED [{code}/{refusal_exit_class(code)}"
                  f"{'' if lane_visible else '/lane-invisible'}] — {detail}")
            continue
        if granted >= max_clears:
            census_record(census, repo, number, "read-failed",
                          f"deferred: per-run clear cap ({max_clears}) reached", lane_visible)
            print(f"  {repo}#{number}: deferred — per-run clear cap ({max_clears}) reached")
            continue
        generation = receipt_count + 1
        head = str(((pull or {}).get("head") or {}).get("sha", ""))
        print(f"  {repo}#{number}: RELEASE [{code}] — {detail}")
        if apply:
            # RECEIPT FIRST: the audit comment is the authorisation for the label delete, and a
            # crash after it leaves an EXPLAINED park rather than a silently released one. It is
            # also the consume-once key, so writing it first can only ever refuse a future clear.
            client.post_comment(
                repo, number,
                audit_body(number, cause, head, generation, detail, reconcile_max))
            client.remove_label(repo, number, park_policy.HUMAN_PARK_LABEL)
        granted += 1
        census_record(census, repo, number, code, detail, lane_visible)
    return len(rows)


def publish(census, considered, errors, apply, summary_path):
    """Emit the census and return the process exit code.

    UNCONDITIONAL. Not `if census`, not `if counts`: a run whose population is EMPTY must still
    publish that fact, or a drained backlog and a broken sweep read identically. It is a separate
    function so `--self-test` can execute the emission itself rather than only the table it
    renders — the emission is what an operator actually consumes."""
    counts, cleared, terminal, reachable, unclassified, lane_split = census_summary(census)
    print("CONFLICT-PARK-CENSUS " + json.dumps(
        {"considered": considered, "released": cleared, "human_terminal": terminal,
         "exit_reachable": reachable, "unclassified": unclassified, "codes": counts,
         "lane": lane_split, "apply": bool(apply), "errors": errors},
        separators=(",", ":"), sort_keys=True))
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as handle:
                handle.write(render_summary(counts, cleared, terminal, reachable, unclassified,
                                            lane_split, considered))
        except OSError as exc:
            print(f"::warning::could not write the step summary: {exc}", file=sys.stderr)
    if unclassified:
        print(f"::error::refusal codes outside the closed taxonomy on {unclassified}",
              file=sys.stderr)
    return 1 if (errors or unclassified) else 0


def build_parser():
    """The CLI, extracted so `--self-test` can read the DEFAULTS it ships with. The two caps are
    the headline claim of this program, and a cap whose only assertion derives from the constant
    under test cannot disagree with it — so the test reads these and compares them to literals."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--repos", default="", help="comma-separated owner/name targets")
    parser.add_argument("--bot-login", default="")
    parser.add_argument("--maintainer", default=os.environ.get("MAINTAINER_HANDLE", "jeswr"))
    parser.add_argument("--token", default=None)
    parser.add_argument("--apply", action="store_true",
                        help="write. Without it the run is a DRY RUN and mutates nothing.")
    parser.add_argument("--max-clears", type=int, default=5,
                        help="per-run cap on automatic releases across all repositories")
    parser.add_argument("--reconcile-max", type=int, default=RECONCILE_MAX,
                        help="lifetime cap on automatic releases for ONE pull request")
    parser.add_argument("--summary-path", default=os.environ.get("GITHUB_STEP_SUMMARY"))
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    repos = [repo.strip() for repo in args.repos.split(",") if repo.strip()]
    if not repos or not args.bot_login:
        parser.error("--repos and --bot-login are required outside --self-test")

    client = GhClient(args.token)
    census, considered, errors = [], 0, []
    for repo in repos:
        try:
            considered += reconcile_repo(client, repo, args.bot_login, args.maintainer,
                                         args.apply, args.max_clears, args.reconcile_max, census)
        except Exception as exc:      # noqa: BLE001 — one bad repo never hides the census
            errors.append(f"{repo}: {str(exc)[:160]}")
            print(f"::error::conflict-park reconcile {repo}: {str(exc)[:160]}", file=sys.stderr)
    return publish(census, considered, errors, bool(args.apply), args.summary_path)


def _self_test():
    ok = True

    def check(name, actual, expected):
        nonlocal ok
        passed = actual == expected
        ok = ok and passed
        print(f"{'PASS' if passed else 'FAIL'}: {name}")
        if not passed:
            print(f"  expected: {expected!r}\n  actual:   {actual!r}")

    head_a = "a" * 40
    head_b = "b" * 40
    esc = f"blah {ESCALATION_MARKER} blah"
    one_attempt = [f"<!-- conflict-resolver attempt=1 head={head_a} -->", esc]

    def v(**over):
        base = dict(pr_labels=[park_policy.HUMAN_PARK_LABEL], issue_labels=[],
                    live_head=head_b, live_mergeable=False, heads=[head_a], escalated=True,
                    hold_applied_by_human=False, bot_bodies=one_attempt, receipts=[],
                    receipt_count=0)
        base.update(over)
        return verdict(**base)

    # --- (a) the wire protocol is IMPORTED from its owner, not re-declared here ---------------
    check("the attempt/escalation wire protocol is the resolver's own, and still matches the "
          "bytes observed on the live population",
          (ATTEMPT_RE is _resolver.ATTEMPT_RE, ESCALATION_MARKER is _resolver.ESCALATION_MARKER,
           ESCALATION_MARKER, bool(ATTEMPT_RE.search(
               f"<!-- conflict-resolver attempt=1 head={head_a} -->"))),
          (True, True, "<!-- conflict-resolver escalated -->", True))

    # --- (b) THE TWO CAUSES, and that neither reads a clock ----------------------------------
    check("head-moved is a recovery: the live head is not the attempted one",
          v()[:2], ("head-moved", "cleared-head-moved"))
    check("conflict-resolved is a recovery on its OWN, even with the head unmoved",
          v(live_head=head_a, live_mergeable=True)[:2],
          ("conflict-resolved", "cleared-conflict-resolved"))
    # THE ANTI-TIMER CONTROL. The first version asserted only that `verdict`'s SIGNATURE had no
    # time-shaped parameter — a PRESENCE test, which a behaviour-neutral
    # `and __import__("time").time() > 0` inside the function satisfied and SURVIVED. The property
    # that actually matters is that this module cannot READ THE CURRENT TIME AT ALL, so it is
    # asserted structurally over the whole module: no time module is imported by any spelling
    # (including `__import__` / `import_module`), and no current-time attribute is ever reached.
    #
    # Parsing and ORDERING timestamps is deliberately still allowed — `machine_applied` compares
    # `labeled` instants to find the newest, which is a comparison between two recorded events and
    # never a comparison against now.
    import ast as clock_ast
    import inspect

    TIME_MODULES = {"time", "datetime", "calendar", "zoneinfo", "dateutil", "sched", "timeit"}
    NOW_ATTRS = {"time", "time_ns", "monotonic", "monotonic_ns", "perf_counter", "perf_counter_ns",
                 "process_time", "thread_time", "clock", "clock_gettime", "times", "now",
                 "utcnow", "today", "fromtimestamp"}
    module_source = Path(__file__).resolve().read_text(encoding="utf-8")
    module_ast = clock_ast.parse(module_source)
    imported, dynamic, reached = set(), [], set()
    for node in clock_ast.walk(module_ast):
        if isinstance(node, clock_ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, clock_ast.ImportFrom):
            imported.add(str(node.module or "").split(".")[0])
        elif isinstance(node, clock_ast.Call):
            name = getattr(node.func, "id", "") or getattr(node.func, "attr", "")
            if name in {"__import__", "import_module"}:
                dynamic.append(name)
        elif isinstance(node, clock_ast.Attribute) and node.attr in NOW_ATTRS:
            reached.add(node.attr)
    # SCOPE, stated honestly rather than in a title that outruns it. This catches every IN-PROCESS
    # clock — `import time`, `from time import time`, `datetime.utcnow()`, `__import__("time")`,
    # `importlib.import_module`. It does NOT catch an OUT-OF-PROCESS one: `subprocess.run(["date"])`
    # or reading `/proc/uptime` would evade it. Those survive, and the honest mitigation is that
    # this module's ONLY subprocess call is `gh` (asserted separately) — not that the scan is total.
    check("no IN-PROCESS clock is reachable: no time module is imported by any spelling, no "
          "dynamic import exists, and no current-time attribute is reached",
          (sorted(imported & TIME_MODULES), dynamic, sorted(reached)), ([], [], []))
    argv0 = [node for node in clock_ast.walk(module_ast)
             if isinstance(node, clock_ast.Call)
             and getattr(node.func, "attr", "") == "run"
             and getattr(getattr(node.func, "value", None), "id", "") == "subprocess"]
    check("...and the ONLY subprocess this module can spawn is `gh`, which is what bounds the "
          "out-of-process clocks the scan above cannot see",
          (len(argv0), [getattr(call.args[0].elts[0], "value", None) for call in argv0]),
          (1, ["gh"]))
    check("...and `verdict` additionally takes no time-shaped parameter, so a timed branch cannot "
          "be wired in from a caller either",
          sorted(name for name in inspect.signature(verdict).parameters
                 if any(token in name for token in ("time", "now", "clock", "hour", "age",
                                                    "grace", "elapsed"))),
          [])

    # --- (c) THE CRITICAL RED TEST: a GENUINE escalation is never cleared ---------------------
    # Each of these is a real live shape, and each is asserted with a cause that HAS recovered —
    # so the row can only pass because the refusal fired, never because there was nothing to do.
    check("a PR not actually holding `needs:user` is refused — this program only ever removes a "
          "park that is live, never acts on one it did not read",
          [v(pr_labels=labels)[1] for labels in
           ([], ["review:parked"], ["needs:ec2"], [park_policy.HUMAN_PARK_LABEL])],
          ["no-live-park", "no-live-park", "no-live-park", "cleared-head-moved"])
    check("[GENUINE] a PROVEN-HUMAN-applied park is NEVER cleared, even with the cause recovered",
          v(hold_applied_by_human=True)[:2], (None, "human-applied"))
    # --- (c2) [#941 INTERACTION] the merge-composition hazard ---------------------------------
    check("[#941] the imported exhaustion predicate is the OWNING module's, so a rename or a "
          "semantic change there fails here rather than silently re-opening the compose hole",
          (STUCK_PARK_MARKER is _resolver.STUCK_PARK_MARKER,
           STUCK_UNPARK_MAX is _resolver.STUCK_UNPARK_MAX,
           stuck_receipts is _resolver.stuck_receipts,
           STUCK_UNPARK_MAX, _resolver.stuck_park_label(STUCK_UNPARK_MAX + 1),
           _resolver.stuck_park_label(STUCK_UNPARK_MAX)),
          (True, True, True, 2, park_policy.HUMAN_PARK_LABEL,
           park_policy.MACHINE_PARK_PR_LABEL))
    check("[#941][GENUINE] a park #941 wrote for EXHAUSTING ITS OWN BUDGET is never released — "
          "otherwise the two caps compose into an effective cap of four",
          [v(stuck_park_gen=gen)[1] for gen in (None, 1, 2, 3, 4)],
          ["cleared-head-moved", "cleared-head-moved", "cleared-head-moved",
           "budget-exhausted", "budget-exhausted"])
    check("[#941] the exhaustion refusal outranks a FULLY RECOVERED cause, and is HUMAN-terminal",
          (v(stuck_park_gen=3, live_mergeable=True)[1],
           refusal_exit_class("budget-exhausted")),
          ("budget-exhausted", "human-terminal"))
    check("[GENUINE] a live `review:changes` review decision blocks the release (#781's shape)",
          v(pr_labels=[park_policy.HUMAN_PARK_LABEL, "review:changes"])[:2],
          (None, "human-review-hold"))
    check("[GENUINE] a live `review:needs-user` blocks it too",
          v(pr_labels=[park_policy.HUMAN_PARK_LABEL, "review:needs-user"])[:2],
          (None, "human-review-hold"))
    # The LIVE escalation prose (sparq #3743/#3608), not a paraphrase: since #814 the deny keys on
    # the sentence the loop itself WRITES, so a fixture that merely contains the phrase would test
    # a rule this table no longer has.
    reviewer_flag = ("> 🤖 SPARQ agent — the autonomous review loop stopped: the reviewer flagged "
                     "possible prompt injection")
    check("[GENUINE] an injection / human-arm signal denies the release at ANY position in the "
          "bot's history",
          [v(bot_bodies=order)[1] for order in
           ([*one_attempt, reviewer_flag], [reviewer_flag, *one_attempt])],
          ["deny-prose", "deny-prose"])
    # [registry #814] ...and it does NOT deny on the bot REPUBLISHING a model verdict that reports
    # the ABSENCE of injection (worker-pr.post_findings echoes model text under the bot identity).
    # Verbatim live text from sparq #3901. Without this the release is refused `deny-prose` on a
    # sentence asserting the opposite of the signal, and the park has no machine exit at all.
    check("[#814] a republished verdict NEGATING injection is not a deny signal",
          v(bot_bodies=[*one_attempt,
                        "> 🤖 SPARQ agent — cross-provider review round 2: **approve**.\n\n"
                        "No instruction-like prompt injection was detected in the diff."])[:2],
          ("head-moved", "cleared-head-moved"))
    # [registry #814 round 2] ...nor on a model FORGING the escalation sentence into that same
    # republished body, which any reviewer can do at will. The first half asserts the sentence
    # really does match the raw prose table, so the second cannot pass by the fixture having gone
    # inert: what makes it safe is that the LOOP did not write it, not how it is worded.
    forged_republish = ("> 🤖 SPARQ agent — cross-provider review round 2: **request_changes**."
                        "\n\nThe reviewer flagged the fixture as possible prompt-injection bait, "
                        "quoted verbatim from the diff.")
    check("[#814 r2] a FORGED escalation sentence in a republished verdict is not a deny signal",
          (bool([cause for pattern, cause in park_policy.LEGACY_PARK_DENY_PROSE
                 if pattern.search(forged_republish)]),
           v(bot_bodies=[*one_attempt, forged_republish])[:2]),
          (True, ("head-moved", "cleared-head-moved")))
    # ...while the machine-authored receipt post_findings appends beside its own escalation still
    # denies: it is the only injection evidence a republishing comment can carry.
    check("[#814 r2] ...but the machine RECEIPT in one still denies the release",
          v(bot_bodies=[*one_attempt, forged_republish + "\n\n"
                        + park_policy.review_injection_marker(2)])[1],
          "deny-prose")
    check("[GENUINE] a needs:* hold that would survive the clear refuses the whole release",
          [v(pr_labels=[park_policy.HUMAN_PARK_LABEL, "needs:external-audit"])[1],
           v(issue_labels=["needs:ec2"])[1]],
          ["residual-hold", "residual-hold"])
    check("[GENUINE] the two-distinct-head exhaustion class is never cleared",
          v(heads=[head_a, "c" * 40])[:2], (None, "two-head-exhaustion"))
    check("[GENUINE] a `needs:user` with no conflict-resolver escalation receipt is not this "
          "program's park",
          [v(escalated=False)[1], v(heads=[], bot_bodies=[esc])[1]],
          ["not-population", "not-population"])

    # --- (d) DELIVERY: an exit that re-admits into the same state is refused, not granted ------
    check("[DELIVERY] head unmoved AND still conflicting is a REFUSAL, not a timed release — "
          "clearing it would re-derive the identical escalation with no new attempt",
          v(live_head=head_a)[:2], (None, "cause-unrecovered"))
    check("...and `mergeable` unknown (None) fails CLOSED rather than reading as resolved",
          v(live_head=head_a, live_mergeable=None)[1], "cause-unrecovered")

    # --- (e) CONSUMED ONCE, and CAPPED --------------------------------------------------------
    spent = [{"cause": "head-moved", "head": head_b, "generation": 1}]
    check("the SAME (cause, head) recovery can never be spent twice",
          v(receipts=spent, receipt_count=1)[:2], (None, "already-cleared"))
    check("...but a NEW head is a NEW recovery",
          v(live_head="d" * 40, receipts=spent, receipt_count=1)[:2],
          ("head-moved", "cleared-head-moved"))
    # PINNED TO LITERALS, not to the constant under test. The first version of this row read
    # `v(receipt_count=RECONCILE_MAX)`, whose input derives from the very constant it is meant to
    # guard — so `RECONCILE_MAX = 1000000` passed it. A cap must be asserted against a number the
    # code cannot supply.
    check("the lifetime cap is the LITERAL 2: one release is still allowed, a second is refused",
          (RECONCILE_MAX, v(receipt_count=0)[1], v(receipt_count=1)[1], v(receipt_count=2)[1],
           v(receipt_count=3)[1]),
          (2, "cleared-head-moved", "cleared-head-moved", "cap-reached", "cap-reached"))
    cli = build_parser().parse_args(["--repos", "o/r", "--bot-login", "b"])
    check("the shipped CLI DEFAULTS are the literals 5 (per run) and 2 (per PR), so neither cap "
          "can be widened by changing a constant alone",
          (cli.max_clears, cli.reconcile_max), (5, 2))
    check("a MALFORMED receipt still counts toward the cap: a corrupt receipt can never buy an "
          "extra release",
          clear_receipts(
              [{"user": {"login": "bot"},
                "body": f"{RECONCILE_MARKER} pr=1 cause=head-moved head={head_a} gen=1 -->"},
               {"user": {"login": "bot"}, "body": f"{RECONCILE_MARKER} corrupted -->"}], "bot"),
          ([{"cause": "head-moved", "head": head_a, "generation": 1}], 2))
    check("receipts and attempt markers are trusted ONLY from the bot's own comments",
          (clear_receipts([{"user": {"login": "drive-by"},
                            "body": f"{RECONCILE_MARKER} pr=1 cause=head-moved "
                                    f"head={head_a} gen=1 -->"}], "bot"),
           attempt_heads([f"<!-- conflict-resolver attempt=1 head={head_a} -->"])),
          (([], 0), [head_a]))

    # --- (f) LABEL-OWNERSHIP: positive machine proof, and the stricter ever-applied rule -------
    def event(kind, label, when, login, via_app=None):
        return {"event": kind, "label": {"name": label}, "created_at": when,
                "actor": {"login": login}, "performed_via_github_app": via_app}

    bot_park = event("labeled", "needs:user", "2026-07-28T01:29:27Z", "sparq-orchestrator[bot]")
    human_park = event("labeled", "needs:user", "2026-07-27T10:00:00Z", "jeswr")
    stranger = event("labeled", "needs:user", "2026-07-28T02:00:00Z", "some-service")
    is_jeswr = (lambda login: str(login).casefold() == "jeswr")
    check("a positively-identified BOT application is machine-applied; an unidentifiable actor "
          "is NOT (absence of a proven human is not proof of a machine)",
          (machine_applied([bot_park], "needs:user"),
           machine_applied([stranger], "needs:user"),
           machine_applied([], "needs:user")),
          (True, False, False))
    # [#1849] THE SEAM, stated as a state and not merely as this program's boolean: the positive
    # machine proof is park_policy's now, so if that answer ever goes back to "not proven human"
    # this row reds HERE — in the consumer that would silently start deleting human parks — rather
    # than only in the owning module's own suite.
    check("the shared ownership answer names the unattributable applier as such, so the boolean "
          "projection this program deletes on cannot read it as permission",
          (park_policy.label_owner_from_events([stranger], "needs:user", is_human=is_jeswr),
           park_policy.label_owner_from_events([bot_park], "needs:user", is_human=is_jeswr),
           park_policy.label_owner_from_events([human_park], "needs:user", is_human=is_jeswr),
           park_policy.label_application_machine_owned(
               "o/r", 1, "needs:user", lambda *_a: [stranger],
               is_human=is_jeswr, log=lambda *_a, **_k: None)),
          (park_policy.LABEL_OWNER_UNATTRIBUTABLE, park_policy.LABEL_OWNER_MACHINE,
           park_policy.LABEL_OWNER_HUMAN, False))
    check("a human application ANYWHERE in the history refuses, even when a LATER bot "
          "re-application would make newest-wins read machine-owned",
          (human_ever_applied([human_park, bot_park], "needs:user", is_jeswr),
           park_policy.label_application_machine_owned(
               "o/r", 1, "needs:user", lambda *_a: [human_park, bot_park],
               is_human=is_jeswr, log=lambda *_a, **_k: None)),
          (True, True))
    check("an app-performed unlabel/label is machine-owned via performed_via_github_app, not the "
          "login suffix alone",
          machine_applied([event("labeled", "needs:user", "2026-07-28T01:00:00Z", "jeswr",
                                 {"slug": "sparq-orchestrator"})], "needs:user"),
          True)

    # --- (g) THE CENSUS, including the empty run ----------------------------------------------
    rows = []
    census_record(rows, "o/r", 1, "cleared-head-moved", "d", True)
    census_record(rows, "o/r", 2, "human-applied", "d", False)
    census_record(rows, "o/r", 3, "cause-unrecovered", "d", False)
    census_record(rows, "o/r", 4, "invented-code", "d", None)
    census_record(rows, "o/r", 5, None, "d", False)
    counts, cleared, terminal, reachable, unclassified, lane_split = census_summary(rows)
    check("the census splits MACHINE (exit-reachable) from GENUINE (human-terminal), and a code "
          "outside the closed taxonomy is surfaced rather than filed as self-healing",
          (cleared, terminal, reachable, unclassified, counts.get("malformed")),
          ([1], [2], [3], [4], 1))
    check("every code this program can emit is inside the closed taxonomy",
          sorted(code for code in
                 (*ADMIT_CODES.values(), *REFUSAL_HUMAN_TERMINAL, *REFUSAL_EXIT_REACHABLE)
                 if code not in set(ADMIT_CODES.values())
                 and refusal_exit_class(code) is None),
          [])
    empty_counts, *empty_rest = census_summary([])
    empty_summary = render_summary(empty_counts, [], [], [], [], {}, 0)
    check("the census renders on an EMPTY population — a drained backlog and a broken sweep must "
          "not read identically",
          ("conflict-park reconciliation census" in empty_summary,
           "0 PR(s) considered" in empty_summary, empty_rest),
          (True, True, [[], [], [], [],
                        {"lane_invisible": [], "lane_unknown": [], "lane_visible": []}]))

    # --- (g2) THE SECOND AXIS: reported, and provably NOT consulted ---------------------------
    # Row 5 is MALFORMED (no code). It is counted under `malformed` and lands in NO lane bucket:
    # a row this program could not parse must not be attributed to an axis it never read. That is
    # asserted here rather than left implicit, because the first draft of this row expected the
    # opposite and the test found it.
    check("the census reports lane admissibility as its own axis; an unknown lane is not silently "
          "filed as either answer, and a MALFORMED row is attributed to no lane at all",
          (lane_split, counts.get("malformed")),
          ({"lane_invisible": [2, 3], "lane_unknown": [4], "lane_visible": [1]}, 1))
    check("the lane-invisible population is named in the operator table, because a park release "
          "cannot make an unenrollable PR reviewable",
          "Lane-INVISIBLE" in render_summary(counts, cleared, terminal, reachable, unclassified,
                                             lane_split, 5),
          True)
    # PRECISELY WHAT THIS PROVES, and no more. The lane BOOLEAN never reaches `verdict` — asserted
    # on the signature below. But lane SHAPE is not inert: a lane head ref makes the source issue
    # derivable, and those issue labels DO feed the residual-hold rule (L532-534, and the lane row
    # in block (h2) demonstrates exactly that). The first version of this row was titled "lane
    # admissibility can never change a verdict", which its own sibling row disproves. The direction
    # is one-way — deriving the issue can only ever add a refusal, never authorise a release — and
    # that is the property worth naming.
    check("the lane BOOLEAN is not a verdict input (no lane parameter exists); lane SHAPE reaches "
          "the verdict only through issue_labels, which can only ever ADD a refusal",
          (sorted(name for name in inspect.signature(verdict).parameters
                  if any(token in name for token in ("lane", "branch", "head_ref", "author",
                                                     "draft", "enrol", "enroll"))),
           # A lane head with a clean source issue releases exactly as a non-lane head does, so the
           # derivation adds refusals and nothing else.
           v(issue_labels=[])[1], v(issue_labels=["needs:ec2"])[1]),
          ([], "cleared-head-moved", "residual-hold"))
    check("the head-ref axis matches the lane's own shape and nothing else",
          [bool(LANE_HEAD_RE.match(ref)) for ref in
           ("sparq-agent/issue-394-30316285331-1", "feat/self-declared-dual-review",
            "sparq-agent/issue-0-1-1", "fix/launch-path-708")],
          [True, False, False, False])

    # --- (g3) THE EMISSION ITSELF, executed — not merely the table it renders ------------------
    import ast as census_ast
    import contextlib
    import io

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        empty_code = publish([], 0, [], False, None)
    emitted = buffer.getvalue()
    check("the census is EMITTED on a run whose population is empty, and such a run is not an "
          "error",
          ("CONFLICT-PARK-CENSUS " in emitted, empty_code,
           json.loads(emitted.split("CONFLICT-PARK-CENSUS ", 1)[1])["considered"]),
          (True, 0, 0))
    buffer, errbuf = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(errbuf):
        bad_code = publish([{"repo": "o/r", "number": 9, "code": "invented", "detail": ""}],
                           1, [], False, None)
    check("an UNCLASSIFIED refusal code reds the run AND is announced, rather than passing "
          "quietly",
          (bad_code, "::error::" in errbuf.getvalue(),
           json.loads(buffer.getvalue().split("CONFLICT-PARK-CENSUS ", 1)[1])["unclassified"]),
          (1, True, [9]))
    # THE CONDITIONALLY-INERT MUTANT, killed STRUCTURALLY: wrapping the emission call in any `if`
    # (`if census:`, `if counts.get("total")`) or deleting it reds this row. A source-text search
    # would pass on a commented-out call; the AST is what actually runs.
    main_ast = census_ast.parse(inspect.getsource(main)).body[0]
    guarded = [node for statement in census_ast.walk(main_ast)
               if isinstance(statement, census_ast.If)
               for node in census_ast.walk(statement)
               if isinstance(node, census_ast.Call)
               and getattr(node.func, "id", "") == "publish"]
    top_level = [statement for statement in main_ast.body
                 for node in census_ast.walk(statement)
                 if isinstance(node, census_ast.Call)
                 and getattr(node.func, "id", "") == "publish"]
    check("the census emission is reached UNCONDITIONALLY from main — never deleted, and never "
          "guarded by a population test",
          (len(top_level), guarded), (1, []))

    # --- (g4) MALFORMED SHAPES. Every one of these is a fail-closed path that a hostile or merely
    # degraded API response reaches, and each was unexecuted until a line-granular coverage run
    # named it. A defensive branch nobody has run is a guess, not a defence.
    malformed_census = []
    census_record(malformed_census, "o/r", 1, "cleared-head-moved", "d", True)
    census_record("not-a-list", "o/r", 2, "cleared-head-moved", "d", True)   # must not raise
    malformed_census.extend(["not-a-dict", {"code": "human-applied", "number": "seven"}])
    counts_m, cleared_m, terminal_m, reachable_m, unclassified_m, lanes_m = census_summary(
        malformed_census)
    check("a non-list census sink is a silent no-op, a non-dict row and a non-integer PR number "
          "are counted rather than dropped, and neither can enter a population list",
          (len(malformed_census), counts_m.get("malformed"), counts_m.get("human-applied"),
           cleared_m, terminal_m, reachable_m, unclassified_m,
           lanes_m["lane_visible"]),
          (3, 1, 1, [1], [], [], [], [1]))
    check("a non-dict comment cannot contribute a receipt, and a non-`labeled` timeline event is "
          "ignored by BOTH ownership rules rather than counted as an application",
          (clear_receipts(["not-a-dict", None], "bot"),
           human_ever_applied([event("unlabeled", "needs:user", "2026-07-28T01:00:00Z", "jeswr")],
                              "needs:user", is_jeswr),
           machine_applied([event("unlabeled", "needs:user", "2026-07-28T01:00:00Z",
                                  "sparq-orchestrator[bot]")], "needs:user")),
          (([], 0), False, False))
    load_failures = []
    try:
        _load("registry_missing_helper", "no-such-helper-file.py")
    except Exception as exc:      # noqa: BLE001 — the point is that it raises at all
        load_failures.append(type(exc).__name__)
    check("a missing registry helper fails LOUDLY at import rather than degrading to a module "
          "with no predicates",
          bool(load_failures), True)

    # --- (h) the audit comment ----------------------------------------------------------------
    body = audit_body(710, "head-moved", head_b, 1, "the live head is not the attempted head")
    check("the release comment self-identifies, names the cause, and carries its own "
          "consume-once receipt keyed on (cause, head)",
          (body.startswith("> 🤖 SPARQ agent"), "head-moved" in body,
           bool(RECEIPT_RE.search(body)),
           [(m.group(2), m.group(3)) for m in RECEIPT_RE.finditer(body)]),
          (True, True, True, [("head-moved", head_b)]))
    check("the release comment states that a human re-application is sticky, and never claims a "
          "review judgement",
          ("sticky" in body, "review judgement is implied or changed" in body), (True, True))

    # --- (h2) THE CALL SITE, executed against a fake client ------------------------------------
    # `verdict` being right proves nothing about what `reconcile_repo` WRITES. This block runs the
    # real sweep over a fake GitHub and asserts the writes themselves, because a pure helper pinned
    # by tests while the call site independently decides what to do is a measured failure shape in
    # this repo.
    class FakeGh:
        def __init__(self, pulls):
            self.pulls_by_number = pulls
            self.comments_posted = []
            self.labels_removed = []
            self.calls = []

        def parked_pulls(self, repo, label):
            return [row["issue"] for row in self.pulls_by_number.values()
                    if label in {lab["name"] for lab in row["issue"]["labels"]}]

        def comments(self, repo, number):
            row = self.pulls_by_number[number]
            if row.get("read_fails"):
                raise RuntimeError("timeline unreadable")
            return row["comments"]

        def timeline(self, repo, number):
            return self.pulls_by_number[number]["timeline"]

        def pull(self, repo, number):
            return self.pulls_by_number[number]["pull"]

        def issue_labels(self, repo, number):
            return self.pulls_by_number.get(int(number), {}).get("issue_labels", [])

        def post_comment(self, repo, number, body):
            self.calls.append(("comment", number))
            self.comments_posted.append((number, body))

        def remove_label(self, repo, number, label):
            self.calls.append(("remove-label", number))
            self.labels_removed.append((number, label))

    def fake_row(number, *, labels=("needs:user",), head=head_b, mergeable=False,
                 attempted=head_a, ref="fix/some-branch", read_fails=False, bot="bot",
                 timeline=None):
        bodies = ([{"user": {"login": bot},
                    "body": f"<!-- conflict-resolver attempt=1 head={attempted} -->"},
                   {"user": {"login": bot}, "body": esc}] if attempted else [])
        return {
            "issue": {"number": number, "labels": [{"name": name} for name in labels],
                      "pull_request": {}},
            "comments": bodies,
            "timeline": timeline if timeline is not None else [
                event("labeled", "needs:user", "2026-07-28T01:00:00Z", "sparq-orchestrator[bot]")],
            "pull": {"head": {"sha": head, "ref": ref}, "mergeable": mergeable},
            "read_fails": read_fails,
        }

    # THE TWO OWNERSHIP RULES DISAGREE HERE, and each fixture exists to make exactly ONE of the
    # call site's two rules load-bearing. Without them both rules agree on every row and either
    # could be deleted with the suite still green — the 1/N call-site shape.
    #
    # [#1849] The first row is now a CROSS-MODULE pin. The positive-machine proof was a local
    # conjunct here and is park_policy's answer since #1849, so this fixture reds if that answer
    # regresses to "not proven human" — in the program that would then delete a park nobody can
    # attribute, which is the only place the harm is visible.
    unknown_actor = FakeGh({20: fake_row(20, timeline=[
        event("labeled", "needs:user", "2026-07-28T01:00:00Z", "some-service")])})
    reconcile_repo(unknown_actor, "o/r", "bot", "jeswr", True, 5, RECONCILE_MAX, [])
    check("[CALL SITE][GENUINE] an UNIDENTIFIABLE applier is not a machine: `not proven human` "
          "alone must not authorise the delete (the positive-machine proof)",
          unknown_actor.labels_removed, [])
    # [#1849] ...and the ownership read must still RAISE on a malformed timeline rather than
    # absorbing it into "not machine". Both answers refuse the release, so only the CENSUS can
    # tell them apart: swapping this call for park_policy's absorbing wrapper would file a broken
    # read as a genuine human decision — a permanently mis-classified terminal, silently.
    broken_timeline = FakeGh({24: fake_row(24, timeline=[
        {"event": "labeled", "label": 7, "created_at": "2026-07-28T01:00:00Z"}])})
    rows_broken = []
    reconcile_repo(broken_timeline, "o/r", "bot", "jeswr", True, 5, RECONCILE_MAX, rows_broken)
    check("[CALL SITE] a MALFORMED park timeline is a read failure, not a human-terminal verdict",
          (broken_timeline.labels_removed,
           [(row["number"], row["code"]) for row in rows_broken]),
          ([], [(24, "read-failed")]))
    # [#941 INTERACTION] The call-site fixture is built by #941's OWN `stuck_receipt`, so it is the
    # real wire bytes rather than my restatement of them. Over-cap generation => refused.
    over_cap = FakeGh({22: fake_row(22)})
    over_cap.pulls_by_number[22]["comments"].append(
        {"user": {"login": "bot"},
         "body": "> 🤖 SPARQ agent\n" + _resolver.stuck_receipt(
             STUCK_PARK_MARKER, head_a, STUCK_UNPARK_MAX + 1)})
    rows_cap = []
    reconcile_repo(over_cap, "o/r", "bot", "jeswr", True, 5, RECONCILE_MAX, rows_cap)
    check("[CALL SITE][#941] an over-cap grace-window park, in #941's real receipt bytes, is "
          "refused at the call site — the effective-cap-of-four hazard",
          (over_cap.labels_removed, [(row["number"], row["code"]) for row in rows_cap]),
          ([], [(22, "budget-exhausted")]))
    under_cap = FakeGh({23: fake_row(23)})
    under_cap.pulls_by_number[23]["comments"].append(
        {"user": {"login": "bot"},
         "body": _resolver.stuck_receipt(STUCK_PARK_MARKER, head_a, STUCK_UNPARK_MAX)})
    reconcile_repo(under_cap, "o/r", "bot", "jeswr", True, 5, RECONCILE_MAX, [])
    check("[CALL SITE][#941] an UNDER-cap grace-window receipt does not block the release — the "
          "refusal is the exhaustion, not the mere presence of #941",
          under_cap.labels_removed, [(23, "needs:user")])
    human_then_bot = FakeGh({21: fake_row(21, timeline=[
        event("labeled", "needs:user", "2026-07-27T10:00:00Z", "jeswr"),
        event("labeled", "needs:user", "2026-07-28T01:00:00Z", "sparq-orchestrator[bot]")])})
    reconcile_repo(human_then_bot, "o/r", "bot", "jeswr", True, 5, RECONCILE_MAX, [])
    check("[CALL SITE][GENUINE] a human application followed by a LATER bot re-application is "
          "still a human decision — newest-wins alone must not authorise the delete "
          "(the ever-applied conjunct)",
          human_then_bot.labels_removed, [])

    # One released PR, one GENUINE human hold whose cause HAS recovered, and one unreadable PR.
    fake = FakeGh({
        10: fake_row(10),
        11: fake_row(11, labels=("needs:user", "review:changes")),
        12: fake_row(12, read_fails=True),
    })
    rows2 = []
    considered = reconcile_repo(fake, "o/r", "bot", "jeswr", True, 5, RECONCILE_MAX, rows2)
    check("[CALL SITE] the release writes the receipt comment BEFORE the label delete, and "
          "touches ONLY `needs:user` on ONLY the released PR",
          (fake.calls, fake.labels_removed, considered),
          ([("comment", 10), ("remove-label", 10)], [(10, "needs:user")], 3))
    check("[CALL SITE][GENUINE] a PR held by a human review decision has its cause RECOVERED and "
          "is still not written to — no comment, no label removal",
          ([number for number, _ in fake.comments_posted],
           [number for number, _ in fake.labels_removed]),
          ([10], [10]))
    check("[CALL SITE] every PR yields exactly one census row, including the unreadable one, and "
          "the RELEASE row carries the lane axis",
          ([(row["number"], row["code"], row["lane_visible"]) for row in rows2], len(rows2)),
          ([(10, "cleared-head-moved", False), (11, "human-review-hold", False),
            (12, "read-failed", None)], 3))
    # The READ-FAILED census site gets its own distinguishing fixture: here the read fails AFTER
    # the lane is known, so the row must still carry it. In the #12 fixture above the failure
    # precedes lane detection, so that row alone cannot tell the argument from its default.
    class LateFailGh(FakeGh):
        def issue_labels(self, repo, number):
            raise RuntimeError("issue unreadable")

    late = LateFailGh({14: fake_row(14, ref="sparq-agent/issue-14-99-1")})
    rows_late = []
    reconcile_repo(late, "o/r", "bot", "jeswr", True, 5, RECONCILE_MAX, rows_late)
    check("[CALL SITE] a read that fails AFTER lane detection still records the lane axis",
          [(row["number"], row["code"], row["lane_visible"]) for row in rows_late],
          [(14, "read-failed", True)])
    dry = FakeGh({10: fake_row(10)})
    reconcile_repo(dry, "o/r", "bot", "jeswr", False, 5, RECONCILE_MAX, [])
    check("[CALL SITE] a DRY RUN mutates nothing at all", (dry.calls, dry.labels_removed),
          ([], []))
    capped = FakeGh({10: fake_row(10), 13: fake_row(13)})
    rows3 = []
    reconcile_repo(capped, "o/r", "bot", "jeswr", True, 1, RECONCILE_MAX, rows3)
    check("[CALL SITE] the per-run cap stops the SECOND release and says so in the census, "
          "carrying the lane axis on the deferred row too",
          ([number for number, _ in capped.labels_removed],
           [(row["number"], row["code"], row["lane_visible"]) for row in rows3]),
          ([10], [(10, "cleared-head-moved", False), (13, "read-failed", False)]))
    # The fake keys issues by the SAME number, so `issue-10-` is the source issue of PR 10.
    lane = FakeGh({10: fake_row(10, ref="sparq-agent/issue-10-30316285331-1")})
    lane.pulls_by_number[10]["issue_labels"] = ["needs:external-audit"]
    rows4 = []
    reconcile_repo(lane, "o/r", "bot", "jeswr", True, 5, RECONCILE_MAX, rows4)
    check("[CALL SITE] a LANE head derives its source issue, and a hold there refuses the "
          "release the PR's own labels would have allowed",
          ([(row["number"], row["code"], row["lane_visible"]) for row in rows4],
           lane.labels_removed),
          ([(10, "residual-hold", True)], []))

    # --- (h3) THE REAL WRITE PATH, executed ---------------------------------------------------
    # `GhClient.post_comment` and `GhClient.remove_label` are the ONLY two writes this program can
    # perform, and neither had ever executed — not in the self-test, not in a live dry run (a dry
    # run by definition skips them). A write path proven only by the fake that stands in for it is
    # not proven at all, so the real methods run here against a recorded `_gh`.
    global _gh
    real_gh = _gh
    issued = []

    def recording_gh(args, token=None, check=True):      # noqa: ARG001 — signature must match
        issued.append((tuple(args), token))

        class _Result:
            stdout = "null"
            returncode = 0
        return _Result()

    try:
        _gh = recording_gh
        client = GhClient("tok-123")
        client.post_comment("o/r", 7, "body-text")
        client.remove_label("o/r", 7, "needs:user")
        client.remove_label("o/r", 7, "needs:external audit/x")
    finally:
        _gh = real_gh
    check("[WRITE PATH] the real GhClient issues exactly one comment POST and one label DELETE, "
          "on the right endpoints, carrying the token",
          (len(issued), issued[0][0][:4], issued[0][1],
           issued[1][0], issued[1][1]),
          (3,
           ("api", "-X", "POST", "repos/o/r/issues/7/comments"), "tok-123",
           ("api", "-X", "DELETE", "repos/o/r/issues/7/labels/needs%3Auser"), "tok-123"))
    check("[WRITE PATH] the label name is URL-quoted with NO safe characters, so a label "
          "containing `/` or a space cannot traverse to another endpoint",
          issued[2][0][3], "repos/o/r/issues/7/labels/needs%3Aexternal%20audit%2Fx")
    check("[WRITE PATH] this program's whole write surface is two methods — it cannot add a "
          "label, push, arm, merge or close",
          sorted(name for name in vars(GhClient)
                 if not name.startswith("_") and name not in
                 ("parked_pulls", "comments", "timeline", "pull", "issue_labels")),
          ["post_comment", "remove_label"])

    # The read-error paths, which the reviewer confirmed correct but untested.
    def failing_gh(args, token=None, check=True):         # noqa: ARG001
        class _Result:
            stdout = ""
            returncode = 1
            stderr = "boom"
        if check:
            raise RuntimeError("gh api failed: boom")
        return _Result()

    try:
        _gh = failing_gh
        raised = []
        try:
            GhClient(None).pull("o/r", 1)
        except RuntimeError as exc:
            raised.append(str(exc)[:20])

        def shaped_gh(payload):
            def inner(args, token=None, check=True):      # noqa: ARG001
                class _Result:
                    stdout = json.dumps(payload)
                    returncode = 0
                return _Result()
            return inner

        malformed = []
        for payload in (None, {"not": "a list"}, ["page-is-not-a-list"]):
            _gh = shaped_gh(payload)
            try:
                GhClient(None).comments("o/r", 1)
            except RuntimeError as exc:
                malformed.append("malformed" in str(exc))
    finally:
        _gh = real_gh
    check("[READ PATH] a failing `gh` raises rather than returning an empty read, and a malformed "
          "or non-list page raises instead of silently reading as 'no comments'",
          (raised, malformed), (["gh api failed: boom"], [True, True, True]))
    check("[READ PATH] an unwritable step summary WARNS and never changes the verdict",
          publish([], 0, [], False, "/proc/self/nonexistent-dir/summary.md"), 0)
    parser_errors = []
    with contextlib.redirect_stderr(io.StringIO()):
        try:
            main(["--repos", ""])
        except SystemExit as exc:
            parser_errors.append(exc.code)
    check("[CLI] a run with no target repo or no bot login EXITS rather than sweeping nothing "
          "quietly",
          parser_errors, [2])

    check("machine_applied resolves an EXACT-INSTANT human/bot tie toward HUMAN ownership, across "
          "both `Z` and `+00:00` spellings of the same instant",
          [machine_applied([event("labeled", "needs:user", bot_when, "sparq-orchestrator[bot]"),
                            event("labeled", "needs:user", human_when, "jeswr")], "needs:user")
           for bot_when, human_when in (("2026-07-28T01:00:00Z", "2026-07-28T01:00:00Z"),
                                        ("2026-07-28T01:00:00Z", "2026-07-28T01:00:00+00:00"),
                                        ("2026-07-28T01:00:00+00:00", "2026-07-28T01:00:00Z"))],
          [False, False, False])

    # --- (h4) THE WHOLE STACK, DRIVEN THROUGH `main()` ----------------------------------------
    # Everything above stops at `reconcile_repo` and substitutes a fake CLIENT, which leaves the
    # four real entry points — `_gh`, `_paginated`, `parked_pulls`, `issue_labels`, `timeline` —
    # and `main`'s own sweep loop unexecuted. A canary-gated line-coverage run measured 40
    # uncovered lines concentrated exactly there, and ten mutants inside that gap survived the
    # whole suite. So this block stubs ONE thing — the `subprocess` module global — and drives the
    # REAL stack from `main(argv)` down to the real HTTP argv.
    #
    # Stubbing at the BOTTOM is deliberate. Faking reads while leaving writes real is how a sibling
    # agent posted 567 comments to a live PR; here the single seam is below both, so a write that
    # escaped the fake would have to spawn a real `gh` process, and the recorded argv proves it did
    # not. `subprocess` is resolved as a module global at call time, so no default-argument binding
    # captures the real one at definition time.
    class FakeApi:
        def __init__(self, issues, fail_repo=None):
            self.issues, self.fail_repo = issues, fail_repo
            self.reads, self.writes = [], []

        @staticmethod
        def _result(stdout="null", returncode=0, stderr=""):
            return types.SimpleNamespace(stdout=stdout, returncode=returncode, stderr=stderr)

        def run(self, argv, capture_output=None, text=None, env=None, check=None):
            args = list(argv)[1:]
            if self.fail_repo and any(self.fail_repo in str(part) for part in args):
                return self._result("", 1, "server exploded")
            if "-X" in args:
                self.writes.append(tuple(args))
                return self._result()
            path = args[-1]
            self.reads.append(path)
            if "--paginate" in args:
                if "/comments" in path:
                    rows = self.issues[int(path.split("/issues/")[1].split("/")[0])]["comments"]
                elif "/timeline" in path:
                    rows = self.issues[int(path.split("/issues/")[1].split("/")[0])]["timeline"]
                else:
                    rows = [row["issue"] for row in self.issues.values()]
                return self._result(json.dumps([rows]))
            if "/pulls/" in path:
                return self._result(json.dumps(
                    self.issues[int(path.rsplit("/", 1)[1])]["pull"]))
            number = int(path.rsplit("/", 1)[1])
            return self._result(json.dumps(
                {"labels": [{"name": name}
                            for name in self.issues.get(number, {}).get("source_labels", [])]}))

    def stack_row(number, *, is_pr=True, labels=("needs:user",), ref="fix/x", head=head_b,
                  mergeable=False, attempted=head_a, author="bot", source_labels=(),
                  escalated=True):
        issue = {"number": number, "labels": [{"name": name} for name in labels]}
        if is_pr:
            issue["pull_request"] = {"url": f"https://api.github.com/pulls/{number}"}
        comments = ([{"user": {"login": author},
                      "body": f"<!-- conflict-resolver attempt=1 head={attempted} -->"}]
                    + ([{"user": {"login": author}, "body": esc}] if escalated else [])
                    if attempted else [])
        return {"issue": issue, "comments": comments,
                "timeline": [event("labeled", "needs:user", "2026-07-28T01:00:00Z",
                                   "sparq-orchestrator[bot]")],
                "pull": {"head": {"sha": head, "ref": ref}, "mergeable": mergeable},
                "source_labels": list(source_labels)}

    import tempfile
    import types

    def drive(api, argv):
        """Run the REAL main() over the REAL GhClient with only `subprocess` faked."""
        global subprocess
        saved, out, err = subprocess, io.StringIO(), io.StringIO()
        try:
            subprocess = types.SimpleNamespace(run=api.run)
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(argv)
        finally:
            subprocess = saved
        payload = out.getvalue().split("CONFLICT-PARK-CENSUS ", 1)
        return code, (json.loads(payload[1]) if len(payload) > 1 else None), out.getvalue()

    summary_file = os.path.join(tempfile.mkdtemp(), "summary.md")
    stack = FakeApi({
        # An ISSUE — not a pull request — carrying `needs:user`. It must never be touched.
        100: stack_row(100, is_pr=False),
        # A LANE head whose SOURCE ISSUE holds a needs:* the release would strand.
        101: stack_row(101, ref="sparq-agent/issue-101-9-1", source_labels=["needs:external-audit"]),
        # Releasable.
        102: stack_row(102),
        # Attempt + escalation markers authored by a THIRD PARTY, not the bot.
        103: stack_row(103, author="drive-by"),
        # A bot ATTEMPT marker with NO escalation receipt: the resolver tried and is still trying,
        # so no terminal was ever written and this is not a park to release. This row is what makes
        # `escalation_recorded` load-bearing — with `heads` empty (as on #103) a hard-coded True
        # still refuses, so only a case with a real attempt and no receipt can catch it.
        104: stack_row(104, escalated=False),
    })
    code, census_json, transcript = drive(stack, [
        "--repos", "o/r", "--bot-login", "bot", "--apply", "--token", "tok",
        "--summary-path", summary_file])
    def stack_code(number):
        """The refusal/admit code the run recorded for ONE pr, read from the run's own per-PR
        line. Asserting a COUNT cannot tell two PRs sharing a code apart, which is exactly the
        confusion that would let a third-party-manufactured park pass as a bot attempt."""
        for line in transcript.splitlines():
            if f"#{number}: " in line:
                return line.split("[", 1)[1].split("/", 1)[0] if "[" in line else line.strip()
        return None

    released = [int(w[3].split("/issues/")[1].split("/")[0]) for w in stack.writes
                if "DELETE" in w]
    check("[STACK] driving the REAL main() over the REAL client: only the releasable PR is "
          "written to, and exactly one comment plus one label delete are issued",
          (code, released, sorted({w[2] for w in stack.writes}), len(stack.writes)),
          (0, [102], ["DELETE", "POST"], 2))
    check("[STACK] an ISSUE carrying `needs:user` is never swept — this program acts on pull "
          "requests only, and dropping that filter would let it edit issues",
          (100 in (census_json or {}).get("released", []),
           any("/issues/100/" in str(w) for w in stack.writes),
           sorted(census_json["codes"])),
          (False, False, ["cleared-head-moved", "not-population", "residual-hold"]))
    check("[STACK] a bot ATTEMPT with NO escalation receipt is not a park — the resolver is still "
          "working on it, and no terminal was ever written",
          (stack_code(104), 104 in census_json["released"]), ("not-population", False))
    check("`escalation_recorded` reads the receipt rather than assuming it: an attempt comment "
          "alone, or any other prose, is not an escalation",
          [escalation_recorded(bodies) for bodies in
           ([], ["nothing here"], [f"<!-- conflict-resolver attempt=1 head={head_a} -->"],
            [esc])],
          [False, False, False, True])
    check("[STACK] the LANE head's SOURCE ISSUE is really fetched, and its hold refuses the "
          "release — through the live `issue_labels`, not a fake",
          (stack_code(101), any(read.endswith("/issues/101") for read in stack.reads)),
          ("residual-hold", True))
    check("[STACK] attempt and escalation markers authored by a THIRD PARTY do not make a "
          "population — a drive-by comment cannot manufacture a park for this program to clear",
          (stack_code(103), 103 in census_json["released"]), ("not-population", False))
    check("[STACK] the census reaches the STEP SUMMARY file, and records that this run applied",
          ("conflict-park reconciliation census" in open(summary_file, encoding="utf-8").read(),
           census_json["apply"], census_json["considered"]),
          (True, True, 4))

    dry_stack = FakeApi({102: stack_row(102)})
    dry_code, dry_census, _ = drive(dry_stack, ["--repos", "o/r", "--bot-login", "bot"])
    check("[STACK] WITHOUT --apply the very same population is reported as released but NOTHING "
          "is written — a silent no-op that still printed RELEASE would otherwise pass",
          (dry_code, dry_stack.writes, dry_census["released"], dry_census["apply"]),
          (0, [], [102], False))

    boom = FakeApi({102: stack_row(102)}, fail_repo="o/r")
    boom_code, boom_census, _ = drive(boom, ["--repos", "o/r", "--bot-login", "bot", "--apply"])
    # Indexing `errors[0]` here would make the swallow-the-error mutant die by IndexError instead
    # of by name, which shows the code crashed rather than that the handler was load-bearing.
    check("[STACK] an unreadable REPOSITORY reds the run through main's own handler and is named "
          "in the census — never swallowed into a clean exit zero",
          (boom_code, len(boom_census["errors"]),
           any("o/r" in message for message in boom_census["errors"]),
           boom_census["considered"]),
          (1, 1, True, 0))

    # A non-zero `gh` exit whose payload nevertheless PARSES. Without the returncode check in
    # `_gh`, every read looks like a success and the sweep releases on data it never really got —
    # the shape a secondary rate-limit or a revoked token produces.
    class RcFailApi(FakeApi):
        def run(self, argv, **kwargs):
            result = super().run(argv, **kwargs)
            return types.SimpleNamespace(stdout=result.stdout, returncode=1,
                                         stderr="You have exceeded a secondary rate limit")

    rc_fail = RcFailApi({102: stack_row(102)})
    rc_code, rc_census, _ = drive(rc_fail, ["--repos", "o/r", "--bot-login", "bot", "--apply"])
    check("[STACK] a NON-ZERO `gh` exit is a failure even when its payload parses — the sweep "
          "reds and writes nothing, rather than acting on data it never really received",
          (rc_code, rc_fail.writes, rc_census["released"], len(rc_census["errors"])),
          (1, [], [], 1))

    # --- (i) THE YAML SEAM. Pin the CALL SITE, not only the Python ----------------------------
    # Every uncaught mutant in this repo's measured mutation runs lived at a workflow `if:`, a
    # step, or a call site. Deleting the invocation, dropping --apply or either cap, adding
    # continue-on-error, or appending `|| true` reds one of these three checks.
    import yaml as workflow_yaml

    workflow_path = (Path(__file__).resolve().parent.parent
                     / ".github/workflows/reconcile-conflict-park.yml")
    document = workflow_yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    steps = document["jobs"]["reconcile"]["steps"]
    call_steps = [step for step in steps
                  if "reconcile-conflict-park.py" in str(step.get("run", ""))]
    # Shell COMMENTS are stripped before the assertion: a guard a comment can satisfy is not a
    # guard (the measured failure that made resolve-conflicts.py block (o) strip them too).
    call_body = "\n".join(line for line in str(call_steps[0].get("run", "")).splitlines()
                          if not line.strip().startswith("#")) if call_steps else ""
    call_run = " ".join(call_body.replace("\\\n", " ").split())
    # EXACT TOKENS, NOT SUBSTRING CONTAINMENT. `"--apply" in call_run` is satisfied by
    # `--apply-DROPPED`, and `"--reconcile-max" in call_run` by `--reconcile-max-DROPPED`; both
    # mutants survived the first version of this row. Tokenising and using list membership makes
    # the match exact, and reading the VALUE that follows each flag pins the number as well as the
    # name.
    tokens = call_run.split()

    def has_sequence(want):
        parts = want.split()
        return any(tokens[i:i + len(parts)] == parts
                   for i in range(len(tokens) - len(parts) + 1))

    def flag_value(flag):
        index = tokens.index(flag) if flag in tokens else -1
        return tokens[index + 1] if 0 <= index < len(tokens) - 1 else None

    check("the workflow call site invokes this program by EXACT token sequence — self-test first, "
          "then the applying run",
          (len(call_steps),
           has_sequence("python3 scripts/reconcile-conflict-park.py --self-test"),
           has_sequence("python3 scripts/reconcile-conflict-park.py --apply"),
           "--apply" in tokens, "--repos" in tokens, "--bot-login" in tokens),
          (1, True, True, True, True, True))
    check("the workflow passes the SAME cap literals the CLI defaults to, so a widening in either "
          "place disagrees with the other",
          (flag_value("--max-clears"), flag_value("--reconcile-max"),
           str(cli.max_clears), str(cli.reconcile_max)),
          ("5", "2", "5", "2"))
    check("the reconcile step can neither continue-on-error nor swallow its exit code",
          (call_steps[0].get("continue-on-error") if call_steps else "no step",
           "|| true" in call_run, "set +e" in call_run, "set -euo pipefail" in call_run),
          (None, False, False, True))
    # PyYAML resolves the `on:` key to the BOOLEAN True, so read both spellings rather than
    # asserting against a key that silently does not exist.
    triggers = document.get(True) if document.get(True) is not None else document.get("on") or {}
    check("the job runs on a schedule with least privilege and the default-branch-restricted "
          "secrets environment",
          (bool(triggers.get("schedule")),
           document["jobs"]["reconcile"].get("environment"),
           document.get("permissions"),
           document["jobs"]["reconcile"].get("permissions")),
          (True, "dispatch-secrets", {}, {"contents": "read"}))

    print("reconcile-conflict-park self-test " + ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
