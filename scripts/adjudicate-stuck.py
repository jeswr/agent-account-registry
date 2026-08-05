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

THE SWEEP'S OWN FAILURE IS NEVER A QUIET TICK. A control whose only failure signal is a census
it prints itself must not be able to print a HEALTHY census when it did nothing, so the exit
status carries three distinct facts and `main()` is driven by `--self-test` end to end:
  - a malformed/unreadable POPULATION payload is not an empty backlog. The `--paginate --slurp`
    shape is validated in full (`_flatten_pages`) and a `null`/non-list/non-object anywhere in it
    EXITS NONZERO after emitting the census, instead of flattening to `rows = []` and reporting a
    zero backlog that is indistinguishable from a drained one;
  - a failed WRITE exits nonzero, always. Every mutation goes through `_gh_write`, so a write
    failure is a distinct exception class rather than one more read-side deferral: the audit
    comment has already authorised the transaction, so a write that does not land leaves an
    explained-but-unmoved PR that the next tick REFUSES as already adjudicated. That state must
    page a human, not report `APPLIED: 0 returned`;
  - operational ERRORS are counted apart from policy REFUSALS in the census, and a tick in which
    EVERY eligible PR errored exits nonzero — the sweep was inoperative, not quiet.
One bad PR still never stops the sweep: a single row's read failure defers that row to the next
tick and the rest of the population is still adjudicated.
"""
import argparse
import contextlib
import datetime
import importlib.util
import io
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


class WriteFailed(RuntimeError):
    """A MUTATION did not land. Distinct from every read failure because the audit comment has
    already authorised the transaction by the time any label moves: a write that fails leaves an
    explained-but-unmoved PR which the NEXT tick refuses as already-adjudicated, so it is the one
    outcome that must never be filed as a per-PR deferral and reported in a green run."""


def _gh(args, check=True):
    result = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:3])} failed: {result.stderr[:300]}")
    return result


def _gh_write(args):
    """EVERY mutation goes through here, so the sweep's exit status can tell a failed write from a
    failed read. `--self-test` asserts that no `-X` call in the production half bypasses it."""
    try:
        return _gh(args)
    except Exception as exc:  # noqa: BLE001 — re-raised, classified
        raise WriteFailed(str(exc)) from exc


def _gh_json(args):
    return json.loads(_gh(args).stdout or "null")


def _flatten_pages(pages, what):
    """The rows of a `gh api --paginate --slurp` response — a LIST of page LISTS of OBJECTS —
    validated in full, raising on anything that is not exactly that.

    This is the one shape reader for every paginated read in the module, population included,
    because the failure it prevents is the sweep's worst: a `null` (empty stdout), an error
    object, or a page of scalars silently flattening to zero rows, which a caller cannot tell
    apart from a drained backlog. A malformed payload is NOT evidence of an empty result set.

    A zero-PAGE response is passed through as zero rows and is not an error: `--slurp` collects
    one array per HTTP response and an empty collection still returns one empty page, so `[]`
    only appears where gh itself returned nothing to slurp — and the callers that matter
    (population, and `main`'s all-rows-errored guard) already treat "no rows" as a fact they must
    report rather than a success they may assume."""
    if not isinstance(pages, list):
        raise RuntimeError(
            f"malformed {what} payload: {type(pages).__name__}, not a --slurp list of pages")
    out = []
    for page in pages:
        if not isinstance(page, list):
            raise RuntimeError(f"malformed {what} page: {type(page).__name__}, not a list of rows")
        for row in page:
            if not isinstance(row, dict):
                raise RuntimeError(f"malformed {what} row: {type(row).__name__}, not an object")
            out.append(row)
    return out


def _paginated(repo, number, kind):
    return _flatten_pages(_gh_json(["api", "--paginate", "--slurp",
                                    f"repos/{repo}/issues/{number}/{kind}?per_page=100"]),
                          f"{kind} for {repo}#{number}")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _maintainer_probe(repo):
    """(is_human, unverifiable) — the strict collaborator-PERMISSION probe this sweep reads hold
    OWNERSHIP through, plus the list that makes an unreadable lookup fail CLOSED.

    REVIEW FINDING (round 2). Ownership used to be asked as `login == --maintainer`, i.e. login
    EQUALITY against one configured handle. `label_application_machine_owned` defines every
    non-App actor that fails the probe as machine-owned, so that spelling made a direct
    `review:needs-user` (or source `needs:user`) by EVERY human maintainer or collaborator except
    that single login machine-owned — and this sweep would clear their hold, contradicting the
    receipt's own promise that re-applying the label is sticky. Ownership is a PERMISSION
    question, so it is answered by the same shared strict probe every other park consumer uses:
    `park_policy.probe_maintainer` over `HUMAN_MAINTAINER_PERMISSIONS`, exactly as
    `dispatch-claim._target_is_human_maintainer` and `curate-frontier._is_human_maintainer` do.

    THE FAIL DIRECTION IS INVERTED HERE, so it is handled here. probe_maintainer answers an
    unverifiable actor with "not human", which is the safe direction for a park VETO (no veto)
    and the UNSAFE one for this consumer, where "not human" is precisely what authorises deleting
    the hold. So every permission read that does not produce a payload — transport blip, expired
    or wrong-owner mint, a not-a-collaborator 404, a malformed body — is RECORDED in
    `unverifiable`, and `_sweep_one` turns any recorded entry into human-owned/NOT clearable. The
    label writes require a PROOF that a machine applied the hold, never the absence of one."""
    unverifiable = []

    def read_permission(login):
        try:
            payload = _gh_json(["api", f"repos/{repo}/collaborators/"
                                + urllib.parse.quote(str(login), safe="") + "/permission"])
        except Exception as exc:  # noqa: BLE001 — recorded, re-raised to the shared classifier
            unverifiable.append(f"{login} ({str(exc)[:80]})")
            raise
        if not isinstance(payload, dict):
            unverifiable.append(f"{login} (malformed collaborator permission payload)")
            raise RuntimeError(f"malformed collaborator permission payload for {login}")
        return payload.get("permission")

    def is_human(login):
        return park_policy.probe_maintainer(repo, login, read_permission)

    return is_human, unverifiable


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
    is_human, unverifiable = _maintainer_probe(args.repo)
    try:
        applied_by_human = not park_policy.label_application_machine_owned(
            args.repo, number, park_policy.HUMAN_PR_PARK_LABEL,
            lambda _repo, _num: timeline, is_human=is_human, log=lambda *_a, **_k: None)
    except Exception as exc:  # noqa: BLE001
        return (None, None, f"hold-ownership probe failed ({exc})")
    # ...and fail closed on the PERMISSION half of that probe too: probe_maintainer answers an
    # unreadable lookup with "not human", which here would read as "a machine applied it".
    if unverifiable:
        return (None, None,
                "hold ownership is UNPROVABLE — no collaborator permission could be read for "
                f"{'; '.join(unverifiable)[:200]}, and an unverifiable actor never authorises "
                "clearing a human terminal")

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
        issue_is_human, issue_unverifiable = _maintainer_probe(args.repo)
        try:
            issue_hold_machine_owned = park_policy.label_application_machine_owned(
                args.repo, issue_number, park_policy.HUMAN_PARK_LABEL,
                lambda _repo, _num: _paginated(args.repo, issue_number, "timeline"),
                is_human=issue_is_human, log=print)
        except Exception as exc:  # noqa: BLE001
            return (None, None, f"source-issue hold-ownership probe failed ({exc})")
        # A permission lookup this sweep could not read proves nothing about who applied the
        # issue hold, and adjudicate() refuses a live `needs:user` it cannot prove machine-owned.
        if issue_unverifiable:
            print(f"  #{number}: source-issue hold ownership unprovable — no collaborator "
                  f"permission for {'; '.join(issue_unverifiable)[:200]}")
            issue_hold_machine_owned = False

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
    _gh_write(["api", "-X", "POST", f"repos/{args.repo}/issues/{number}/comments",
               "-f", "body=" + audit_body(disposition, cause, detail, episode, readmit_marker,
                                          reason_marker, lane=worker_pr.FIX_LANE_PR_LABEL)])
    if "drop-human-hold" not in plan:
        return (disposition, cause, detail)   # no label write, ever — the park is untouched
    _gh_write(["api", "-X", "DELETE", f"repos/{args.repo}/issues/{number}/labels/"
               + urllib.parse.quote(park_policy.HUMAN_PR_PARK_LABEL, safe="")])
    _gh_write(["api", "-X", "POST", f"repos/{args.repo}/issues/{number}/labels",
               "-f", f"labels[]={worker_pr.FIX_LANE_PR_LABEL}"])
    # The ISSUE half, ONLY on the machine-ownership proof taken above — a re-admission behind an
    # unprovable `needs:user` was already REFUSED, so this branch never runs unprovably. It is
    # REMOVED rather than converted to a machine park: the PR is re-entering flow, which is the
    # state an un-parked source issue is already in.
    if ("clear-machine-issue-hold" in plan and issue_hold_machine_owned
            and park_policy.HUMAN_PARK_LABEL in set(issue_labels)):
        _gh_write(["api", "-X", "DELETE",
                   f"repos/{args.repo}/issues/{issue_number}/labels/"
                   + urllib.parse.quote(park_policy.HUMAN_PARK_LABEL, safe="")])
    return (disposition, cause, detail)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--repo")
    parser.add_argument("--bot-login")
    # NO `--maintainer`: who counts as human is NOT configuration. It is the target repo's
    # collaborator permission, read per actor (`_maintainer_probe`) — a single configured handle
    # made every OTHER maintainer's hold machine-owned and therefore clearable.
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
    census = {RETURN_TO_LOOP: [], GENUINELY_HUMAN: [], "refused": [], "errors": []}
    try:
        rows = _population(args)
    except Exception as exc:  # noqa: BLE001 — a population read that failed is not an empty one
        print(f"POPULATION READ FAILED for {args.repo}: {exc}")
        census["errors"].append((0, str(exc)[:140]))
        _emit_census(census, args.apply)
        print("::error::the park population could not be read, so this tick knows NOTHING about "
              "the backlog — a malformed payload is not a drained terminal")
        return 1
    print(f"{len(rows)} open PR(s) on {park_policy.HUMAN_PR_PARK_LABEL} in {args.repo}")
    write_failed = []
    for row in sorted(rows, key=lambda row: row.get("number") or 0):
        number = row.get("number")
        try:
            disposition, cause, detail = _sweep_one(
                args, worker_pr, row, len(census[RETURN_TO_LOOP]) + len(census[GENUINELY_HUMAN]))
        except WriteFailed as exc:
            # NOT a deferral: the audit comment above it already authorised this transaction.
            print(f"  #{number}: WRITE FAILED — {exc}")
            census["errors"].append((number, f"write failed: {str(exc)[:120]}"))
            write_failed.append(number)
            continue
        except Exception as exc:  # noqa: BLE001 — one bad PR never stops the sweep
            print(f"  #{number}: ERROR — {exc}")
            census["errors"].append((number, str(exc)[:140]))
            continue
        if not disposition:
            print(f"  #{number}: REFUSED — {detail}")
            census["refused"].append((number, detail))
            continue
        print(f"  #{number}: {disposition.upper()} [{cause}] — {detail}")
        census[disposition].append((number, cause))
    _emit_census(census, args.apply)
    # THE EXIT STATUS. A census this process prints itself is not a signal unless the process can
    # also fail, so the two conditions under which the sweep DELIVERED NOTHING are nonzero.
    if write_failed:
        print(f"::error::{len(write_failed)} PR(s) {write_failed} carry an audit comment whose "
              "transaction did not complete — the next tick will refuse them as already "
              "adjudicated, so this needs a human, not a green run")
        return 1
    if rows and len(census["errors"]) == len(rows):
        print(f"::error::all {len(rows)} eligible PR(s) errored — this sweep was inoperative, "
              "which is not the same as a quiet tick")
        return 1
    return 0


def _population(args):
    """Every open PR on the human terminal, from a STRICTLY validated page shape (`_flatten_pages`
    raises rather than letting a malformed payload read as a drained backlog). Rows that are not
    pull requests are the label's issue half and are not this sweep's population."""
    held = _gh_json(["api", f"repos/{args.repo}/issues?state=open"
                     f"&labels={urllib.parse.quote(park_policy.HUMAN_PR_PARK_LABEL)}"
                     "&per_page=100", "--paginate", "--slurp"])
    return [row for row in _flatten_pages(held, f"{args.repo} park population")
            if row.get("pull_request")]


def _emit_census(census, apply):
    """ALWAYS emit, including the all-zero row and the ERROR row — the quiet tick is exactly the
    one an operator interrogates, and an operational error is reported apart from a policy refusal
    so "nothing was eligible" can never be read off a run that could not read anything."""
    print(f"\n{'APPLIED' if apply else 'DRY RUN'}: "
          f"{len(census[RETURN_TO_LOOP])} returned to the loop, "
          f"{len(census[GENUINELY_HUMAN])} genuinely human, "
          f"{len(census['refused'])} refused, "
          f"{len(census['errors'])} errored")
    for disposition in DISPOSITIONS:
        for number, cause in census[disposition]:
            print(f"  #{number} {disposition} ({cause})")
    for number, detail in census["errors"]:
        print(f"  #{number} ERROR ({detail})")


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

    # ---- THE PAGE-SHAPE READER: A MALFORMED PAYLOAD IS NOT AN EMPTY RESULT SET. --------------
    check("the ONE --slurp shape reader flattens a well-formed response, and REFUSES every "
          "malformed one rather than yielding the zero rows a caller reads as 'nothing to do'",
          [_flatten_pages([[{"a": 1}], [{"b": 2}]], "t"), _flatten_pages([[]], "t")]
          + [_raises(lambda payload=payload: _flatten_pages(payload, "t"), RuntimeError)
             for payload in (None, "[]", {"message": "Bad credentials"}, 7,
                             [None], [{"a": 1}], [[1]], [[{"a": 1}], "page"])],
          [[{"a": 1}, {"b": 2}], []] + [True] * 8)
    check("every MUTATION in the production half goes through the write wrapper, so a write that "
          "did not land can never be filed as a read-side per-PR deferral",
          sorted(set(re.findall(r'(_gh\w*)\(\["api", "-X"', _production_source()))),
          ["_gh_write"])

    # ---- THE ENTRY POINT. main()'s EXIT STATUS IS THE SWEEP'S ONLY ENFORCED SIGNAL. ----------
    # These drive the REAL main() — and with it _population, _sweep_one's write half, _gh_write
    # and _emit_census — with `gh` stubbed at the process boundary. Before them, every line of
    # that half had NEVER executed under test (AGENTS.md pre-flight §1), which is precisely where
    # a fabricating bug survives: a census this module prints about itself is not an alarm unless
    # the process can also fail.
    bot = "adjudicator[bot]"
    # LITERAL, not park_policy.HUMAN_PR_PARK_LABEL: a repoint of the terminal must surface here as
    # a red row rather than follow the fixture silently (AGENTS.md pre-flight §2c).
    terminal = "review:needs-user"
    argv = ["--repo", "o/r", "--bot-login", bot]

    quiet = _run_main(argv, {"issues?state=open": [[]]})
    check("an EMPTY population is a REAL quiet tick: exit 0, with the all-zero census still "
          "emitted (the row an operator interrogates)",
          (quiet[0], "0 returned to the loop, 0 genuinely human, 0 refused, 0 errored"
           in quiet[1]),
          (0, True))
    malformed = {"null (gh printed nothing at all)": None,
                 "an error object instead of pages": {"message": "Bad credentials"},
                 "a JSON string": "[]",
                 "a page that is not a list": [{"number": 1}],
                 "a null page": [None],
                 "a row that is not an object": [[7]]}
    broken = {name: _run_main(argv, {"issues?state=open": payload})
              for name, payload in malformed.items()}
    check("a MALFORMED population payload EXITS NONZERO instead of flattening to an empty "
          "backlog — every shape a failing API/schema can hand back",
          {name: run[0] for name, run in broken.items()},
          {name: 1 for name in malformed})
    check("...and still emits the census and a named error, so the failure is legible in the run "
          "log rather than only in the status",
          sorted({("POPULATION READ FAILED" in run[1], "0 refused, 1 errored" in run[1],
                   "::error::" in run[1], run[2] == []) for run in broken.values()}),
          [(True, True, True, True)])

    pr_row = {"url": "https://api.github.com/repos/o/r/pulls/12"}
    two = [[{"number": 11, "labels": [{"name": terminal}], "pull_request": pr_row},
            {"number": 12, "labels": [{"name": terminal}], "pull_request": pr_row}]]
    boom = RuntimeError("gh api failed: 502 Bad Gateway")
    unreadable = {"issues/11/comments": boom, "issues/12/comments": boom}
    check("a tick in which EVERY eligible PR errored EXITS NONZERO — a sweep that delivered "
          "nothing is not a quiet tick, and the workflow's per-invocation counter cannot see it",
          _run_main(argv, {"issues?state=open": two, **unreadable})[0], 1)
    partial = _run_main(argv, {"issues?state=open": two, "issues/11/comments": boom,
                               "issues/12/comments": [[]], "issues/12/timeline": [[]],
                               "pulls/12": {"head": {"sha": "", "ref": "x"}, "draft": False}})
    check("...but ONE bad PR still never stops the sweep: a PARTIAL failure stays exit 0, and "
          "the operational error is counted APART from the policy refusal it is not",
          (partial[0], "0 genuinely human, 1 refused, 1 errored" in partial[1]), (0, True))

    def parked(number, issue, body, sha):
        """The four reads one parked worker draft answers, as `gh api` would print them."""
        return {f"issues/{number}/comments": [[{"user": {"login": bot}, "body": body}]],
                f"issues/{number}/timeline": [[{"event": "labeled", "label": {"name": terminal},
                                                "created_at": "2026-07-20T00:00:00Z",
                                                "actor": {"login": bot},
                                                "performed_via_github_app": {"slug": "app"}}]],
                f"pulls/{number}": {"head": {"sha": sha, "ref": f"sparq-agent/issue-{issue}-3"},
                                    "draft": True},
                f"issues/{issue}": {"labels": []}}

    # BOTH write halves in ONE tick: #12 is a capacity park (the full re-entry transaction) and
    # #13 a legacy prose-only question park (the audit comment ALONE). Two rows is also what makes
    # the lost-write exit measurable AT ALL — with a single row `errors == rows`, so the
    # all-errored guard would return 1 for an unrelated reason and mask it (AGENTS.md §4's
    # mutually-masking pair; measured: three write-side mutants survived on a one-row fixture).
    # ...plus #14, the label's ISSUE half: the same query returns it, and it is not a pull request
    # to adjudicate. It carries no stubbed reads, so a population that stopped filtering it would
    # surface as an ERROR row in the census below rather than as silence.
    both = {"issues?state=open": [[{"number": n, "labels": [{"name": terminal}],
                                    "pull_request": pr_row} for n in (12, 13)]
                                  + [{"number": 14, "labels": [{"name": terminal}]}]],
            **parked(12, 77, "the round budget ran out "
                     + park_policy.park_reason_marker("budget"), "b" * 40),
            **parked(13, 78, "this branch no longer descends from the worker-opened commit",
                     "c" * 40)}
    applied = _run_main(argv + ["--apply"], both)
    check("both write halves, RECEIPT-FIRST and nothing beyond: the capacity park gets its audit "
          "comment, THEN the hold drop, THEN the fix lane — and the question park gets its audit "
          "comment and NO label write, on either half",
          (applied[0], _endpoints(applied[2]),
           "1 returned to the loop, 1 genuinely human, 0 refused, 0 errored" in applied[1]),
          (0, [("POST", "issues/12/comments"),
               ("DELETE", "issues/12/labels/review%3Aneeds-user"),
               ("POST", "issues/12/labels"),
               ("POST", "issues/13/comments")], True))
    dry = _run_main(argv, both)
    check("...and WITHOUT --apply the same population writes NOTHING AT ALL (the flag's value, "
          "not its presence), while still reporting both dispositions",
          (dry[0], dry[2], "1 returned to the loop, 1 genuinely human" in dry[1]), (0, [], True))
    failed = {target: _run_main(argv + ["--apply"], both, write_fails=(target,))
              for target in ("12/comments", "DELETE", "13/comments")}
    check("a write that does NOT land EXITS NONZERO and stops that PR's transaction where it "
          "failed — while the OTHER PR of the same tick is adjudicated normally, so the status "
          "can come from nothing but the lost write",
          {target: (run[0], len(run[2])) for target, run in failed.items()},
          {"12/comments": (1, 2), "DELETE": (1, 3), "13/comments": (1, 4)})
    check("...and the half-written transaction is filed as an ERROR — NAMED, with the PR number, "
          "never as the disposition it did not complete, while the PR that DID complete counts",
          {target: ("WRITE FAILED" in run[1], "1 errored" in run[1], "::error::" in run[1],
                    "1 returned to the loop" in run[1], "1 genuinely human" in run[1],
                    sorted(re.findall(r"#(\d+) ERROR \(", run[1])))
           for target, run in failed.items()},
          {"12/comments": (True, True, True, False, True, ["12"]),
           "DELETE": (True, True, True, False, True, ["12"]),
           "13/comments": (True, True, True, True, False, ["13"])})

    # ---- WHO OWNS THE HOLD IS A PERMISSION QUESTION (round-2 review finding). ----------------
    # The probe used to be `login == --maintainer`, and label_application_machine_owned calls
    # every non-App actor that FAILS the probe machine-owned — so a hold applied directly by any
    # human maintainer other than that ONE configured login authorised this sweep to delete it.
    # These rows vary NOTHING but the actor (and the permission the target repo reports for it)
    # across one otherwise re-admissible capacity park, so the disposition can come from nothing
    # else. Permission strings are LITERALS, never derived from HUMAN_MAINTAINER_PERMISSIONS
    # (AGENTS.md pre-flight §2c), and the unreadable cases pin the FAIL-CLOSED direction.
    def probe_answer(payload):
        """(answer, unverifiable rows, endpoints read) for one actor, with `gh api` answering
        `payload` — an Exception INSTANCE is raised in its place."""
        calls = []

        def fake_gh_json(call):
            calls.append(next((arg for arg in call if arg.startswith("repos/")), ""))
            if isinstance(payload, Exception):
                raise payload
            return payload

        saved = globals()["_gh_json"]
        try:
            globals()["_gh_json"] = fake_gh_json
            is_human, unverifiable = _maintainer_probe("o/r")
            with contextlib.redirect_stdout(io.StringIO()):
                answer = is_human("second-maintainer")
        finally:
            globals()["_gh_json"] = saved
        return answer, len(unverifiable), calls

    graded = {permission: probe_answer({"permission": permission})
              for permission in ("admin", "maintain", "write", "triage", "read", "none")}
    check("EVERY collaborator holding a write-class permission is human — not one hard-coded "
          "login — and a below-write permission is not",
          {permission: run[0] for permission, run in graded.items()},
          {"admin": True, "maintain": True, "write": True,
           "triage": False, "read": False, "none": False})
    check("...read per ACTOR from the TARGET repo's own collaborator-permission endpoint",
          graded["admin"][2], ["repos/o/r/collaborators/second-maintainer/permission"])
    check("...and a DEFINITIVE not-a-maintainer answer is a result, not an outage (nothing "
          "recorded), while every unreadable one is recorded so the caller can fail CLOSED",
          [graded["admin"][1], graded["read"][1]]
          + [probe_answer(payload)[:2] for payload in
             (RuntimeError("gh api failed: 502 Bad Gateway"), None, ["admin"], "admin")],
          [0, 0] + [(False, 1)] * 4)

    app_driven = {"slug": "app"}

    def held(pr_actor=bot, pr_via_app=app_driven, issue_held=False,
             pr_permission="maintain", issue_actor=bot, issue_via_app=app_driven,
             issue_permission="maintain"):
        """ONE capacity-parked worker draft (#12, source issue #77) that is re-admissible in
        every respect except who applied its holds. `*_permission` of None makes that actor's
        collaborator lookup FAIL, which is the unprovable-ownership case."""
        def label_event(label, actor, via_app):
            return {"event": "labeled", "label": {"name": label},
                    "created_at": "2026-07-20T00:00:00Z", "actor": {"login": actor},
                    "performed_via_github_app": via_app}

        def permission(value):
            return ({"permission": value} if value
                    else RuntimeError("gh api failed: 502 Bad Gateway"))

        # `source` is the LITERAL park_policy.HUMAN_PARK_LABEL, so a repoint reds these rows.
        source = "needs:user"
        return {"issues?state=open": [[{"number": 12, "labels": [{"name": terminal}],
                                        "pull_request": pr_row}]],
                "issues/12/comments": [[{"user": {"login": bot},
                                         "body": "the round budget ran out "
                                         + park_policy.park_reason_marker("budget")}]],
                "issues/12/timeline": [[label_event(terminal, pr_actor, pr_via_app)]],
                f"collaborators/{pr_actor}": permission(pr_permission),
                f"collaborators/{issue_actor}": permission(issue_permission),
                "pulls/12": {"head": {"sha": "d" * 40, "ref": "sparq-agent/issue-77-3"},
                             "draft": True},
                # BEFORE the bare issue key: the stub matches endpoint SUBSTRINGS in insertion
                # order, and "issues/77" is a prefix of "issues/77/timeline".
                "issues/77/timeline": [[label_event(source, issue_actor, issue_via_app)]],
                "issues/77": {"labels": [{"name": source}] if issue_held else []}}

    machine = _run_main(argv + ["--apply"], held())
    check("CONTROL: the machine-owned path stays REACHABLE — an App-driven hold is returned to "
          "the loop with the full re-entry transaction",
          (machine[0], _endpoints(machine[2]), "1 returned to the loop" in machine[1]),
          (0, [("POST", "issues/12/comments"),
               ("DELETE", "issues/12/labels/review%3Aneeds-user"),
               ("POST", "issues/12/labels")], True))
    human_pr = _run_main(argv + ["--apply"], held(pr_actor="second-maintainer", pr_via_app=None))
    check("a `review:needs-user` applied DIRECTLY by an authorized human who is NOT the one login "
          "this sweep used to hard-code is HUMAN-owned: refused, with no comment and no label "
          "write of any kind",
          (human_pr[0], human_pr[2],
           "0 returned to the loop, 0 genuinely human, 1 refused, 0 errored" in human_pr[1]),
          (0, [], True))
    read_only = _run_main(argv + ["--apply"], held(pr_actor="drive-by", pr_via_app=None,
                                                   pr_permission="read"))
    check("...and it is the permission VALUE that decided that, not merely the actor being "
          "non-App: a read-permission actor proves no human ownership",
          (read_only[0], _endpoints(read_only[2])[:1], "1 returned to the loop" in read_only[1]),
          (0, [("POST", "issues/12/comments")], True))
    blind_pr = _run_main(argv + ["--apply"], held(pr_actor="second-maintainer", pr_via_app=None,
                                                  pr_permission=None))
    check("...while a permission lookup that cannot be READ fails CLOSED — the hold stands, "
          "nothing is written, and the refusal says UNPROVABLE rather than claiming a proof",
          (blind_pr[0], blind_pr[2], "UNPROVABLE" in blind_pr[1], "1 refused" in blind_pr[1]),
          (0, [], True, True))
    human_issue = _run_main(argv + ["--apply"],
                            held(issue_held=True, issue_actor="second-maintainer",
                                 issue_via_app=None))
    check("the SOURCE-ISSUE hold is probed the same way: a `needs:user` applied by any authorized "
          "human holds the work, so the PR behind it is refused and NEITHER half is written",
          (human_issue[0], human_issue[2], "1 refused" in human_issue[1]), (0, [], True))
    machine_issue = _run_main(argv + ["--apply"], held(issue_held=True))
    check("...CONTROL: the same issue hold applied by the App IS lifted, so the issue-half write "
          "is reachable and only the ACTOR separates these two rows",
          (machine_issue[0], _endpoints(machine_issue[2])),
          (0, [("POST", "issues/12/comments"),
               ("DELETE", "issues/12/labels/review%3Aneeds-user"),
               ("POST", "issues/12/labels"),
               ("DELETE", "issues/77/labels/needs%3Auser")]))
    blind_issue = _run_main(argv + ["--apply"],
                            held(issue_held=True, issue_actor="second-maintainer",
                                 issue_via_app=None, issue_permission=None))
    check("...and an unreadable permission on the ISSUE half fails closed too: the PR is never "
          "re-admitted behind a hold this sweep could not prove a machine applied",
          (blind_issue[0], blind_issue[2], "unprovable" in blind_issue[1]), (0, [], True))
    with contextlib.redirect_stderr(io.StringIO()):
        no_knob = _raises(lambda: main(["--repo", "o/r", "--bot-login", bot,
                                        "--maintainer", "x"]), SystemExit)
    check("and there is NO configured-human knob to re-narrow this with: a `--maintainer`-style "
          "flag is refused by the parser rather than silently accepted",
          no_knob, True)

    # ---- THE YAML SEAM. The exit status above is only a signal if the CRON reads it. -----------
    workflow = _workflow_source()
    increments = [n for n, line in enumerate(workflow) if line.strip() == "swept=$((swept + 1))"]
    check("the cron counts a repo as SWEPT only inside the SUCCESS branch of the invocation — an "
          "increment that merely records that python3 ran cannot tell a failed sweep, an "
          "unreadable population or a lost write from a drained backlog",
          (len(increments), [workflow[n - 1].strip() for n in increments]), (1, ["then"]))
    check("...and both final guards are live: the run fails when NO repo was swept and when ANY "
          "repo's sweep failed",
          sorted(var for var in ("$failed", "$swept")
                 if any(var in line and "exit 1" in line for line in workflow)),
          ["$failed", "$swept"])

    print("adjudicate-stuck self-test " + ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


def _raises(thunk, kind=ValueError):
    """True only when `thunk` raises EXACTLY `kind`. A DIFFERENT exception is malformedness, not
    the guard firing, so it returns False — which reds THIS row and lets the rest of the suite
    run, instead of aborting it and recording the 15 checks below as neither passed nor failed
    (measured: an inert shape guard scored 43 of 58 checks, AGENTS.md pre-flight §4)."""
    try:
        thunk()
    except kind:
        return True
    except Exception:  # noqa: BLE001 — a different failure is a RED row, never a kill
        return False
    return False


def _workflow_source():
    """The cron that runs this sweep, as lines — or NO lines when it cannot be read, so a missing
    workflow fails the seam checks closed instead of vacuously satisfying them. Read as text, not
    parsed: the worker container has no YAML module, and the seam under test is the shell step."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        ".github", "workflows", "adjudicate-stuck.yml")
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().splitlines()
    except OSError:
        return []


def _endpoints(writes):
    """(method, path-below-the-repo) for each write a stubbed run attempted, in order."""
    return [(method, path.split("/", 3)[-1]) for method, path in writes]


def _run_main(argv, reads, write_fails=()):
    """Drive the REAL `main()` offline — no gh process, no network, no token.

    `reads` maps a distinctive endpoint substring to the payload `gh api` would print, or to an
    Exception INSTANCE to raise in its place; `write_fails` names substrings of the endpoint (or
    the HTTP method) whose mutation must fail. Returns (exit status, stdout, writes attempted),
    so one check can pin the status, the census text and the receipt-first write ORDER together.

    The stub replaces `_gh`/`_gh_json` at the PROCESS boundary rather than the functions under
    test, so `_gh_write`, `_flatten_pages`, `_population`, `_sweep_one` and `_emit_census` are the
    shipped ones."""
    writes = []

    def endpoint(call):
        return next((arg for arg in call if arg.startswith("repos/")), "")

    def fake_gh_json(call):
        path = endpoint(call)
        for key, payload in reads.items():
            if key in path:
                if isinstance(payload, Exception):
                    raise payload
                return payload
        raise AssertionError(f"unstubbed read {path!r}")

    def fake_gh(call, check=True):
        method, path = (call[2] if len(call) > 2 else ""), endpoint(call)
        writes.append((method, path))
        if any(fail in path or fail == method for fail in write_fails):
            raise RuntimeError(f"gh api failed: 502 Bad Gateway on {path}")
        return None

    saved = {name: globals()[name] for name in ("_gh", "_gh_json")}
    out = io.StringIO()
    try:
        globals()["_gh"], globals()["_gh_json"] = fake_gh, fake_gh_json
        with contextlib.redirect_stdout(out):
            status = main(argv)
    finally:
        globals().update(saved)
    return status, out.getvalue(), writes


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
