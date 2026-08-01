#!/usr/bin/env python3
"""Plan AND apply one safe, idempotent retriage mutation from an issue JSON document.

TWO DIRECTIONS, ONE CLASSIFIER (issue #586). The sweep that shipped for #415 was one-directional
— it only promoted `status:untriaged` — so an issue that LOST a required triage label while
KEEPING its `status:ready` attestation was recoverable by nothing on master: retriage never listed
it, curate-frontier skips anything already carrying a `status:` label, groom only repairs
claim-backed state, and triage-issue.yml did not fire on label events. It simply left the
readiness frontier forever. `plan()` therefore recomputes `triage.triage()` drift in BOTH
directions:

  * PROMOTE — a `status:untriaged` issue whose label set is now triage-complete re-enters dispatch.
  * REPARK  — a `status:ready` issue whose label set the READINESS ENGINE provably cannot enumerate
              (`ready-issues.exclusion_reason`) goes back to `status:untriaged`, so the promotion
              lane above re-admits it the moment the missing label is restored.
  * REPAIR  — a `status:ready` issue the engine cannot enumerate today but WHICH the classifier's
              own drift makes enumerable (the lost-`role:*` case: `triage()` re-derives the role)
              is repaired in place. Strictly better than a re-park — it needs no human — and it is
              the SAME classifier verdict, not a second notion of completeness.

WHO MAY BE RETRIAGED (registry #487). The author trust gate is the FIRST thing `plan()` checks,
and until now it recognised exactly two automation identities: the maintainer and the orchestrator
App bot. `github-actions[bot]` — the login every one of THIS repo's own workflows authors issues as
— is neither, and reads a repo permission of `none`, so a lane-labelled issue our own automation
opened would return `untrusted-author` and be neither promotable out of `status:untriaged` nor
demotable on a label regression. #487 already shipped the per-repo `allow_actions_bot_issues`
opt-in and wired it into dispatch CLAIM (`dispatch-claim._issue_is_trusted`) and the curator
(`curate-frontier.trusted_author`); this sweep was the residual consumer. It now reads the SAME
policy row, so triage trust cannot drift from admission trust. This is a LATENT-CONSISTENCY fix
and is INERT on this repo today: the sweep's board is exactly the `status:untriaged` and
`status:ready` lane queries, and nothing labels a `github-actions[bot]` issue onto either lane
(see the "[registry #487] THE ACTIONS-BOT TRIAGE OPT-IN" block in the self-test for the executed
board-membership assertion and the upstream unit this waits on). The opt-in admits the EXACT login
`github-actions[bot]` and nothing else — never a `<x>[bot]` suffix match, which is the defect #487
closed on the dispatch side, since a suffix would admit any unrelated or compromised GitHub App.
It widens TRIAGE only: it grants no admission, no arming and no merge, and every park below is
still evaluated afterwards, unchanged.

FAIL CLOSED. `triage.triage()` is the only completeness classifier and `ready-issues` is the only
enumerability predicate; if the drift does not PROVE one of the three transitions the plan is a
no-op skip. Park policy is load-bearing and checked BEFORE any classification: an untrusted author,
any `needs:*` / `trust:untrusted` gate, an `<!-- orchestration:hold -->` marker, the
dispatcher-owned `status:deferred`, the machine-owned `status:parked`, a claim-owned
`status:in-progress[-review]`, and `kind:epic` are all skipped, never re-parked.

ONE APPLIER FOR ALL THREE ACTIONS (PR #595 finding 3). `--apply` owns the whole
read -> plan -> mutate -> verify sequence for every accepted action above, through the SAME
fail-closed applier `triage.py --apply` uses (triage.apply_triage). retriage.yml previously
sent the additions AND removals through one opaque `gh issue edit` in the workflow shell:
  * nothing verified that the replacement `role:*` label EXISTS or LANDED before the strip;
  * on a partial failure `set -e` exited the step, SKIPPING the post-read entirely;
  * when the post-read did fire and saw zero roles it merely `exit 1`-ed — leaving the issue
    `status:ready` with no role, the terminal #582 state retriage itself cannot revisit;
  * its check ACCEPTED multiple roles, which route-resolve rejects (AmbiguousRoleError).
The applier now adds + verifies the replacement first, keeps the incumbent role on any failure,
asserts EXACTLY ONE role in a revision-bound post-read, and repairs — or demotes `status:ready` to
`status:untriaged` so the next retriage tick owns the issue — instead of stranding it. The re-park
and repair lanes ride the very same sequence: a repair ADDS the re-derived `role:*`, which is
exactly the add-must-land-first shape #582 is about.

EVERY SUGGESTED LABEL IS VALIDATED, NOT JUST THE ROLE (registry #510). #582 taught the classifier
to check its target `role:*` against the target repo's LIVE label set; every OTHER label a decision
writes — the derived `priority:P4` floor, the `status:*` lane attestations — still went to the API
unchecked. GitHub fails the WHOLE `gh issue edit` when any one `--add-label` names a label the repo
does not have, so a single unknown suggestion cost the entire mutation, exited the applier 1 and
turned the sweep red — and, because nothing about the issue changed, it re-tripped on every
subsequent tick (measured: run 29883925637, `'role:soundness' not found`, cleared only by a manual
relabel). `validate_labels` now reduces the decision to labels that provably exist BEFORE any write
and names each dropped label on its own log line; `drop_is_safe` then refuses to apply a REDUCED
write that would no longer be the transition it claims to be. A dropped label is never an error
exit: the tick is a no-op with a log, so the recurrence is a quiet, attributable no-op rather than a
red run. Genuine write failures are unchanged — still recorded per issue, still red after the loop.
"""
import argparse
import importlib.util
import json
import os
import sys
import tomllib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import park_policy
import triage as static_triage


def _load(modname, filename):
    """Import a sibling script whose filename is not a valid module name (dashed)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_ready = _load("ready_issues", "ready-issues.py")

HOLD_MARKER = "<!-- orchestration:hold -->"
TRUSTED_PERMISSIONS = {"admin", "maintain", "write"}
# registry #487. The EXACT login every workflow in one of our own repositories authors issues as.
# Compared with `==`, never a suffix/prefix/case-folded test: a `<x>[bot]` suffix match is what
# admitted arbitrary GitHub Apps into dispatch before #487, and `curate-frontier.ACTIONS_BOT_LOGIN`
# / `dispatch-claim._issue_is_trusted` spell the same string for the same reason. The self-test
# asserts this constant is still IDENTICAL to the curator's, so the three cannot drift apart.
ACTIONS_BOT_LOGIN = "github-actions[bot]"
# Claim-owned states: groom's orphan/lease repair owns these, never this sweep (a re-park here
# would race a live worker and strip the claim its PR is bound to).
CLAIM_OWNED = {"status:in-progress", "status:in-progress-review"}
# The actions that WRITE. `--apply` mutates for each of them through the one shared applier; every
# other verdict is a no-op skip (fail-closed: an unknown action never becomes a write).
WRITING_ACTIONS = ("promote", "repark", "repair")
# The two lane attestations this sweep moves an issue between, and the verdict a decision is
# downgraded to when its unknown-label reduction cannot be applied safely. Both are POINTERS, not
# copies (registry #1490): the reduction they belong to now lives in `triage.py` and is shared with
# `triage.py --apply`, so a second spelling here is the #958 shape waiting to happen.
LANE_LABELS = static_triage.LANE_LABELS
UNSAFE_DROP_REASON = static_triage.UNSAFE_DROP_REASON
NON_DISPATCHABLE = _ready.NON_DISPATCHABLE            # kind:epic
# Bounded, rate-limit-safe sweep: an explicit per-run cap and a runaway ceiling on the paginated
# snapshot. A partial page must never be mistaken for the whole board.
SWEEP_CAP = 40
SWEEP_CEILING = 5000
# The REQUEST bound on the board fetch, enforced where the pagination happens (retriage.yml) —
# #605 review finding 2: `--paginate --slurp` pulled EVERY page into a file before SWEEP_CEILING
# could look at anything, so the ceiling bounded neither requests nor memory and could only refuse
# to mutate after the fact. 100 issues per page.
SWEEP_MAX_PAGES = 20


class SweepError(RuntimeError):
    """A snapshot this sweep refuses to act on (runaway size, or a partial/malformed page)."""


def actions_bot_trust(policy_file, repo):
    """Is `github-actions[bot]` a trusted TRIAGE author for `repo`? (registry #487)

    policy/repos.toml's per-repo `allow_actions_bot_issues` is the ONE source of truth — the same
    row `dispatch-claim._issue_is_trusted` and `curate-frontier.trusted_author` already read — so
    this sweep cannot grant (or withhold) triage trust that admission does not.

    Three outcomes, and the difference between them is load-bearing:

      * NO policy requested (an empty `--policy-file`) -> False. Nothing was declared, so nothing
        is widened; this is the pre-#487 behaviour and remains the default for every caller that
        does not opt in.
      * A policy that names `repo` -> that row's boolean, defaulting False when the key is absent
        (`_allow_actions_bot_issues_of`'s contract, mirrored). A repo the policy does not mention
        at all is likewise False — unmentioned is not opted in.
      * A policy we were TOLD to read and could NOT (missing file, undecodable TOML, no `[repos]`
        table, a non-table row, a non-boolean flag) -> SweepError, which the caller turns into a
        red step. Silently returning False there would rebuild the exact invisible starvation #487
        is about: an unreadable policy would be indistinguishable from "not allowed" and nobody
        would ever be told which one happened.

    `enabled` is deliberately NOT consulted. It declares whether a repo is a DISPATCH target;
    this flag declares who may author an issue in it. Coupling them would silently switch triage
    trust off as a side effect of pausing dispatch — a second invisible-starvation shape.
    """
    if not policy_file:
        return False
    try:
        with open(policy_file, "rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise SweepError(f"repository policy {policy_file!r} could not be read, so the "
                         f"actions-bot triage opt-in cannot be resolved: {exc}") from exc
    rows = document.get("repos") if isinstance(document, dict) else None
    if not isinstance(rows, dict) or not rows:
        raise SweepError(f"repository policy {policy_file!r} has no [repos] target rows")
    row = rows.get(repo)
    if row is None:
        return False
    if not isinstance(row, dict):
        raise SweepError(f"repository policy row for {repo!r} is not a table")
    value = row.get("allow_actions_bot_issues", False)
    if not isinstance(value, bool):
        raise SweepError(f"allow_actions_bot_issues for {repo!r} must be boolean")
    return value


def plan(issue, maintainer, app_bot, permission, classify=static_triage.triage,
         known_labels=None, allow_actions_bot_issues=False):
    """`known_labels` (optional): the target repo's ACTUAL label set. Supplying it makes the role
    transition fail-closed (registry #582) — the classifier never plans an add of a label the repo
    does not have, and never plans a strip of the last role label for one. Without a role the
    classifier reports not-ready, so this path skips the issue as `classifier-incomplete` rather
    than promoting it to a role-less `status:ready` (silently undispatchable, unrecoverable)."""
    labels = {item["name"] if isinstance(item, dict) else item
              for item in issue.get("labels", [])}
    author = (issue.get("author") or {}).get("login", "")
    trusted = (author in {maintainer, app_bot} or permission in TRUSTED_PERMISSIONS
               # registry #487: the ONE narrow per-repo opt-in. Fork-PR workflows get read-only
               # tokens and cannot create issues, so this login can only author an issue in one of
               # our own repositories through a workflow that repository already controls. EXACT
               # equality — `my-github-actions[bot]` and `evil[bot]` must both still be refused.
               or (allow_actions_bot_issues and author == ACTIONS_BOT_LOGIN))
    if not trusted:
        return {"action": "skip", "reason": "untrusted-author"}
    # Everything below this line is UNCHANGED by the opt-in. It widens who may be CLASSIFIED, not
    # what a classification may do: every `needs:*` / `trust:untrusted` gate, the hold marker, the
    # dispatcher-owned `status:deferred`, the machine-owned `status:parked`, the claim-owned
    # in-progress states and `kind:epic` are all still evaluated, in the same order, for an
    # actions-bot author exactly as for the maintainer.
    gates = sorted(label for label in labels
                   if label.startswith("needs:") or label == "trust:untrusted")
    if gates:
        return {"action": "skip", "reason": "gated:" + ",".join(gates)}
    if HOLD_MARKER in (issue.get("body") or ""):
        return {"action": "skip", "reason": "explicit-hold"}
    # status:deferred is owned exclusively by the dispatcher's bounded retry path. Retriage must
    # not consume it or it would reset that path's retry/escalation state.
    if "status:deferred" in labels:
        return {"action": "skip", "reason": "not-retriageable"}
    # status:parked is the MACHINE-owned capacity park (park_policy.py): the deferred-retry lane
    # is its readmission hook, so this sweep never touches it either.
    if park_policy.MACHINE_PARK_LABEL in labels:
        return {"action": "skip", "reason": "machine-parked"}
    if labels & CLAIM_OWNED:
        return {"action": "skip", "reason": "claim-owned"}
    # An epic is DELIBERATELY unenumerable, not stranded — re-parking it would be a spurious write.
    if NON_DISPATCHABLE in labels:
        return {"action": "skip", "reason": "epic"}
    untriaged = "status:untriaged" in labels
    if not untriaged and "status:ready" not in labels:
        return {"action": "skip", "reason": "not-retriageable"}
    try:
        # #598: the issue's REAL type, not the literal `"task"` this used to pass. With the literal,
        # `ROLE_BY_TYPE["task"]` always resolved, so this sweep could never reach the area-derived
        # default (#225) that triage-issue.yml now reaches — and the two classifiers would have
        # disagreed about any custom-typed issue, the promotion lane writing `role:impl` over the
        # role the event-driven classifier derived. `_apply_cli` puts the LIVE type on the document;
        # a document with no `type` key — every direct/self-test caller, and only those, since
        # `snapshot()` deliberately carries none — is UNTYPED, which derives the role from the
        # `area:*` exactly as triage-issue.yml now does for the same issue.
        # PASSED RAW, on purpose: `triage()` normalizes, and a SECOND `normalize_issue_type()` call
        # here would be a mutually-masking duplicate (AGENTS.md pre-flight 4) — idempotent, so
        # deleting either copy alone would leave every row green and neither could be killed.
        result = classify(labels, issue.get("type"), trusted=True, known_labels=known_labels)
    except Exception:
        return {"action": "skip", "reason": "classifier-failure"}
    add, remove = set(result["add"]), set(result["remove"])
    # `role` is the INTENDED single role and rides EVERY accepted action: `--apply` needs it to add
    # and VERIFY the replacement before any strip (PR #595 findings 3 + 4). It is load-bearing on
    # the #586 lanes too — the repair lane's whole job is writing back the `role:*` the issue lost,
    # and the re-park lane may re-route an incumbent role on its way out of `status:ready`.
    role = result["role"]
    if untriaged:
        if not result["ready"]:
            # A CONTRADICTORY dual-status issue (`status:untriaged` alongside a stale
            # `status:ready` — the same partial label edit that strands the pure `status:ready`
            # case below) would otherwise keep its positive attestation forever, since the
            # promotion lane only ever writes when the classifier says complete. Strip it, from
            # the SAME classifier verdict the re-park lane uses.
            if "status:ready" in remove:
                return {"action": "repark", "add": [], "remove": sorted(remove), "role": role}
            return {"action": "skip", "reason": "classifier-incomplete"}
        remove.update(labels.intersection({"status:untriaged"}))
        # registry #582 belt-and-braces: never emit a promotion whose post-state has no role:*
        # label — that state is silently undispatchable and, once `status:untriaged` is gone,
        # unreachable by the promotion lane that would repair it.
        post = (labels | add) - remove
        if not any(label.startswith("role:") for label in post):
            return {"action": "skip", "reason": "role-invariant"}
        return {"action": "promote", "add": sorted(add), "remove": sorted(remove), "role": role}

    # ---- the #586 lane: a `status:ready` issue the readiness engine cannot enumerate ----
    if _ready.exclusion_reason(labels) is None and result["ready"]:
        # BOTH authorities agree the issue is healthy — the readiness engine can enumerate it AND
        # the classifier calls its label set triage-complete — so this sweep leaves it completely
        # alone: no mutation, no comment, whatever OTHER drift the classifier may see (collapsing
        # an ambiguous role set is triage-issue.yml's job, not a stranding).
        #
        # Both halves are load-bearing. An issue that lost its `area:*` is still *enumerable* (a
        # package-less issue reserves the serializing `__global__` partition), yet a GLOBAL in the
        # busy set drops EVERY plan item — an area regression degrades the whole frontier, not just
        # its own row — and only the classifier sees it. An issue that lost its `role:*` is the
        # mirror image: the classifier re-derives the role and calls it complete, while the engine
        # (which needs the LABEL) cannot enumerate it.
        return {"action": "skip", "reason": "ready-consistent"}
    projected = (labels | add) - remove
    if _ready.exclusion_reason(projected) is None:
        # The classifier's OWN output restores enumerability (the lost-`role:*` case: triage()
        # re-derives the role). Repair in place — strictly better than a re-park, which would need
        # a human to do what the classifier already proved. Non-empty by construction: an empty
        # drift would leave `projected == labels`, which the branch above already returned on.
        return {"action": "repair", "add": sorted(add), "remove": sorted(remove), "role": role}
    if not result["ready"]:
        # `needs:area` is deliberately NOT minted here even though triage() parks a no-area issue
        # with it: this sweep SKIPS every gated issue, so writing that gate would strand the issue
        # behind a door the sweep itself refuses to open — re-creating the exact hole #586 closes.
        # `status:untriaged` alone is sufficient; the promotion lane re-admits on label restore.
        add -= {"needs:area"}
        if "status:untriaged" not in add or "status:ready" not in remove:
            # triage() always parks a not-ready issue this way; a drifted classifier that does not
            # is unproven input, so do nothing.
            return {"action": "skip", "reason": "classifier-inconsistent"}
        return {"action": "repark", "add": sorted(add), "remove": sorted(remove), "role": role}
    # The classifier calls the label set complete yet the engine still cannot enumerate it (e.g.
    # `status:blocked`, or an open blocker). Nothing is PROVEN about triage, so do nothing.
    return {"action": "skip", "reason": "unprovable"}


def snapshot(pages, cap=SWEEP_CAP, ceiling=SWEEP_CEILING, rotation=0):
    """Normalize a paginated issue-page list into (this run's board, count outside the window).

    FAIL CLOSED on any malformed view: a page that is not a list, an entry that is not an object, a
    missing issue number or a malformed label RAISES rather than yielding a short board. What that
    validates is SHAPE, not COMPLETENESS — a well-formed board missing its last page is
    indistinguishable here, which is why the caller (retriage.yml) is the one that proves it read
    every page and fails closed on a board larger than SWEEP_MAX_PAGES (#605 review finding 2).
    `ceiling` stays as defence in depth against a runaway board reaching the planner at all.

    SELECTION IS A ROTATING PARTITION OF A STABLE ORDERING (#605 review finding 1, a BLOCKER). The
    first form sorted the whole board by `(updatedAt, number)` and took the oldest `cap` — but the
    overwhelming majority of selected issues are NO-OP skips (healthy `status:ready`, `needs:*`-gated,
    machine-parked, claim-owned, untrusted-author, incomplete-untriaged), and a no-op does not change
    `updated_at`. So the oldest-`cap` window filled with permanent no-ops and the SAME issues were
    selected on every scheduled run, forever, while everything behind them was reported as "deferred
    to the next run" and in fact deferred for good. The ordering was inverted for exactly the case
    #586 exists to rescue: an issue that JUST lost a label has a RECENT `updated_at`, so it sorted to
    the very back. Measured on the live board when this was written: 178 `status:untriaged` + 24
    `status:ready` = 202 open issues against a cap of 80, i.e. 122 permanently unreachable.

    So the window now rotates: the board is ordered by ISSUE NUMBER — immutable, so the ordering is
    stable across runs — and the start offset advances by `cap` per `rotation` (the workflow passes
    its run number), with NO persistent cursor state to keep. NOT a partition: the offsets advance
    modulo `total`, so consecutive windows are disjoint only while `cap` divides `total`; otherwise
    the wrapping window re-visits the head (#605 review round 4 — the suite's own 7/3 fixture wraps
    and overlaps issues 1 and 2, so "disjoint"/"partition" was the wrong word). What IS guaranteed
    is COVERAGE: any ceil(total/cap) consecutive rotations visit every issue on an unchanged board,
    which is the property the starvation fix needs. Within the run the board is handed over
    oldest-updated first, which is a fairness ORDER
    only, never a decision input.

    WHAT THE ROTATION DOES AND DOES NOT GUARANTEE (#605 review round 2). For a board of UNCHANGED
    MEMBERSHIP every issue is visited within ceil(total/cap) runs. Issue numbers are immutable, but
    board membership is not: closing, reopening or relabelling a LOWER-numbered issue between runs
    shifts every later offset, so an untouched issue can be revisited later than that bound — the
    guarantee is progress and no permanent head-of-line starvation, not a hard per-issue deadline.
    """
    if not isinstance(pages, list):
        raise SweepError("snapshot payload is not a list of pages")
    raw = []
    for page in pages:
        if not isinstance(page, list):
            raise SweepError("a page of the paginated snapshot is not a list — refusing to act "
                             "on a partial view")
        for item in page:
            if not isinstance(item, dict):
                raise SweepError("a snapshot entry is not an object")
            if "pull_request" in item:       # /issues returns PRs too
                continue
            raw.append(item)
    if len(raw) >= ceiling:
        raise SweepError(f"fetched {len(raw)} >= ceiling {ceiling} — the snapshot looks runaway "
                         "(fail-closed)")
    seen, issues = set(), []
    for item in raw:
        number = item.get("number")
        if not isinstance(number, int):
            raise SweepError("a snapshot entry has no integer issue number")
        if number in seen:                   # the two label queries may overlap
            continue
        seen.add(number)
        user = item.get("user")
        login = user.get("login") if isinstance(user, dict) else ""
        # #605 review round 4 (MINOR): `item.get("labels") or []` was inside the "every malformed
        # snapshot fails closed" claim while itself normalizing a missing key, `null`, `""` and
        # several malformed containers to "no labels". The REST issue payload always carries a
        # `labels` array, so the tolerance bought nothing and softened the claim; the container is
        # now validated like every other decision-shaped field.
        raw_labels = item.get("labels")
        if not isinstance(raw_labels, list):
            raise SweepError(f"issue #{number} carries a malformed `labels` container "
                             f"({type(raw_labels).__name__}) — refusing to act on a partial view")
        names = []
        for label in raw_labels:
            name = label.get("name") if isinstance(label, dict) else label
            if not isinstance(name, str) or not name:
                raise SweepError(f"issue #{number} carries a malformed label")
            names.append({"name": name})
        issues.append({"number": number,
                       # TRANSPORT ONLY, and deliberately tolerant: a missing body normalizes to
                       # "" rather than raising. That is honest now (#605 review round 2) BECAUSE
                       # `_apply_cli` re-reads the body LIVE before it decides anything — the
                       # snapshot's copy is never a decision input, so this tolerance cannot become
                       # a fail-open hold bypass. The "every malformed snapshot fails closed" claim
                       # is scoped to what IS a decision input: pages, entries, numbers, labels.
                       "body": item.get("body") or "",
                       "author": {"login": login if isinstance(login, str) else ""},
                       "labels": names,
                       "updatedAt": str(item.get("updated_at") or "")})
    # Stable ordering for the rotation: the issue NUMBER never changes, so consecutive rotations
    # advance over the SAME ordering and cover the board (an `updatedAt` ordering re-shuffles
    # between runs and can skip past an issue entirely). Windows are not disjoint in general — see
    # the docstring: the wrap re-visits the head whenever `cap` does not divide `total`.
    issues.sort(key=lambda issue: issue["number"])
    total = len(issues)
    if total <= cap:
        window, dropped = issues, 0
    else:
        start = (max(0, int(rotation)) * cap) % total
        window = (issues + issues)[start:start + cap]   # wraps past the end of the board
        dropped = total - cap
    # Oldest-updated first WITHIN the run: a fairness order only, never a decision input.
    window.sort(key=lambda issue: (issue["updatedAt"], issue["number"]))
    return window, dropped


def apply_decision(current, decision, edit, view, read_state=None, warn=None):
    """Apply an ACCEPTED decision through the SHARED fail-closed applier (triage.apply_triage).

    Every writing action goes through here — `promote`, and the #586 `repark`/`repair` lanes — so
    the two directions of the sweep cannot drift into two mutation paths. `ready` is the projected
    attestation (a re-park is on its way OUT of `status:ready`); `role` is the intended single role,
    which the applier adds and VERIFIES before it strips any incumbent.

    Returns {"ok": bool, "warnings": [...]}. ok=False must turn the workflow step RED — never
    swallow it, and never let the shell short-circuit past the post-condition (PR #595 finding 3).
    """
    result = {"add": set(decision.get("add", ())), "remove": set(decision.get("remove", ())),
              "ready": decision.get("action") != "repark", "role": decision.get("role"),
              "warnings": []}
    return static_triage.apply_triage(current, result, edit, view, warn, read_state=read_state)


def validate_labels(decision, known_labels):
    """Reduce a decision to the labels the target repo ACTUALLY has. Returns (decision, dropped).

    registry #510, and since #1490 the reduction itself is ONE implementation,
    `triage.validate_plan`, shared with `triage.py --apply` — which had the same hole for every
    non-`role:*` family. The contract (what is validated, why `remove` is NOT, what
    `known_labels is None` means) is stated there, once; this wrapper adds only the part that is
    retriage's own: WHICH decisions are writes.

    A non-writing decision is returned untouched — a skip has nothing to validate.
    """
    if decision.get("action") not in WRITING_ACTIONS:
        return decision, []
    return static_triage.validate_plan(decision, known_labels)


def drop_is_safe(decision, live_labels, issue_type, known_labels):
    """Is a decision REDUCED by `validate_labels` still the transition it claims to be?

    registry #510; the LANE and PREMISE invariants and their measured oscillation argument live
    with the shared implementation, `triage.reduced_write_is_safe` (#1490). This wrapper supplies
    the one retriage-shaped input it takes: what the decision ATTESTS. A promote/repair attests
    `status:ready`; a re-park attests nothing — the SAME action->ready conversion
    `_decision_to_result` already makes when it hands a decision to the shared applier.
    """
    return static_triage.reduced_write_is_safe(
        decision, live_labels, issue_type, known_labels,
        attests_ready=decision.get("action") != "repark")


def workflow_step_script(text, step_id):
    """The EXECUTABLE `run:` script of the ONE workflow step whose `id:` is `step_id`, dedented.

    #605 review round 2, finding 2: the sweep's pagination ceiling, completeness proof, page-shape
    guard and truncation break are all SHELL guards, and the assertions on them were whole-file
    substring searches — `"--paginate" not in executable`, `re.search(r"exit\\s+1", executable)`,
    `-lt 100`. None of those protect the behaviour they name: another `exit 1` later in the file
    satisfies the ceiling check, `if false` satisfies it too, and `got=0` keeps the `-lt 100`
    substring while stopping after page 1 and applying a TRUNCATED board. `bash -n` and actionlint
    cannot see any of it. So the body is extracted and RUN. Raises SweepError when it cannot resolve
    its target or the recovered script is empty — an assertion that cannot find its step must fail,
    never pass vacuously."""
    lines = text.split("\n")
    marks = [index for index, line in enumerate(lines) if line.strip() == f"id: {step_id}"]
    if len(marks) != 1:
        raise SweepError(f"expected exactly one workflow step with `id: {step_id}`, "
                         f"found {len(marks)} — refusing to assert vacuously")
    starts = [index for index in range(marks[0], -1, -1) if lines[index].lstrip().startswith("- ")]
    if not starts:
        raise SweepError(f"step `id: {step_id}` has no enclosing `- ` sequence entry")
    indent = len(lines[starts[0]]) - len(lines[starts[0]].lstrip())
    end = len(lines)
    for index in range(starts[0] + 1, len(lines)):
        line = lines[index]
        if not line.strip():
            continue
        here = len(line) - len(line.lstrip())
        if here < indent or (here == indent and line.lstrip().startswith("- ")):
            end = index
            break
    block = lines[starts[0]:end]
    heads = [index for index, line in enumerate(block) if line.strip() in {"run: |", "run: |-"}]
    if len(heads) != 1:
        raise SweepError(f"step `id: {step_id}` has {len(heads)} block `run:` scripts, expected 1")
    head = heads[0]
    script_indent = len(block[head]) - len(block[head].lstrip())
    body = []
    for line in block[head + 1:]:
        if line.strip() and (len(line) - len(line.lstrip())) <= script_indent:
            break
        body.append(line[script_indent + 2:] if line.strip() else "")
    script = "\n".join(body)
    if not script.strip():
        raise SweepError(f"step `id: {step_id}` extracted to an empty `run:` script")
    return script


def read_live_body(repo, number):
    """The issue's LIVE `{"body": str, "state": "OPEN"|"CLOSED", "type": str}`, through the shared
    bounded-retry READ layer. RAISES on anything it cannot positively interpret.

    #605 review round 2 (a fail-OPEN race): `_apply_cli` refreshed only `labels` from the live
    read, while the `body` that decides the `<!-- orchestration:hold -->` park still came from the
    board snapshot taken BEFORE pagination. A hold added between the list read and the apply was
    therefore ignored and the issue could still be promoted or repaired — on a deliberately
    load-bearing park policy, and against a docstring claiming planning happened against the live
    read.

    #605 review round 4 (MAJOR): the first fix RAISED only for a transport failure. A SUCCESSFUL
    read whose document was malformed still fell open to "no hold" — measured with `{}` (key
    missing), a non-string body, and schema drift (`{"data": {"body": ...}}`), each of which
    returned `""` and let the write proceed. So the unsafe side is now unreachable BY SHAPE: only a
    document that positively carries a string `body` (or an explicit JSON `null`, which is how
    GitHub renders an empty body — the one tolerated shape, tolerated deliberately and named here)
    yields a value at all. Every other shape raises, and `_apply_cli` treats a raise as
    "the hold could not be verified, so assume it is there".

    The `state` half closes round 4's stale-eligibility MINOR at zero extra cost — open/closed was
    the last decision input still coming from the pre-pagination board query, so a concurrently
    CLOSED issue could still receive promote/repair/repark label mutations. It rides the same read.

    THE ISSUE TYPE RIDES IT TOO (#598), and for the SAME reason: `plan()` used to hand the
    classifier the LITERAL `"task"`, so `ROLE_BY_TYPE["task"]` always resolved and this sweep could
    never reach the area-derived role default (#225) that triage-issue.yml now can. Two classifiers
    deriving different roles for the same issue is the failure this closes — the sweep's promotion
    lane would have written `role:impl` over the `role:docs` the event-driven classifier derived.
    It is read LIVE rather than taken from the board snapshot because the type is MUTABLE, and the
    docstring below (`_apply_cli`) states as an invariant that no mutable snapshot field reaches a
    decision. `issueType` is `null` for an issue with NO type — a real GitHub state, not drift, and
    the one tolerated shape here; it yields `""`, which the classifier reads as untyped and derives
    the role from the area (#225). An ABSENT key is schema drift and raises, exactly like `body`.

    A module-level function on purpose — the self-test substitutes the READ under it
    (`triage._gh_read`) so this function's own parsing and validation are the code under test, not
    a stub that replaces them (round-4 MAJOR: stubbing this function left `return ""` and a read of
    issue `1` both green)."""
    raw = static_triage._gh_read(                          # noqa: SLF001 — the one shared read layer
        ["issue", "view", str(number), "-R", repo, "--json", "body,state,issueType"])
    try:
        document = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise SweepError(f"issue #{number}: the live read is not JSON ({exc})") from exc
    if not isinstance(document, dict):
        raise SweepError(f"issue #{number}: the live read is not a JSON object")
    if "body" not in document:
        raise SweepError(f"issue #{number}: the live read carries no `body` key (schema drift) — "
                         "an orchestration hold cannot be ruled out from this document")
    body = document["body"]
    if body is None:
        body = ""                    # GitHub renders an empty body as JSON null
    if not isinstance(body, str):
        raise SweepError(f"issue #{number}: the live `body` is {type(body).__name__}, not a string")
    state = document.get("state")
    if not isinstance(state, str) or state.strip().upper() not in {"OPEN", "CLOSED"}:
        raise SweepError(f"issue #{number}: the live read carries no usable `state` ({state!r})")
    # #598: `issueType` is `{"id":…, "name":"Bug", …}` for a typed issue and `null` for an untyped
    # one. Same posture as `body`: an ABSENT key is schema drift and refuses, because a document
    # that says nothing about the type cannot be read as "untyped" — that would silently re-derive
    # the role from a value this run never actually observed.
    if "issueType" not in document:
        raise SweepError(f"issue #{number}: the live read carries no `issueType` key (schema "
                         "drift) — the role derivation cannot be trusted from this document")
    issue_type = document["issueType"]
    if issue_type is None:
        name = ""                    # GitHub renders an issue with NO type as JSON null
    elif isinstance(issue_type, dict) and isinstance(issue_type.get("name"), str):
        name = issue_type["name"]
    else:
        # A typed issue whose type we cannot NAME is drift, not "untyped": only the top-level
        # `null` above is GitHub's untyped answer, and reading anything else as untyped would
        # re-derive the role from a value this run never observed.
        raise SweepError(f"issue #{number}: the live `issueType` is neither null nor an object "
                         f"with a string `name` ({issue_type!r})")
    return {"body": body, "state": state.strip().upper(), "type": name}


def _apply_cli(repo, number, issue, maintainer, app_bot, permission, known_labels,
               allow_actions_bot_issues=False):
    """`--apply`: re-read the LIVE labels AND the LIVE body, plan against them, mutate fail-closed.

    Planning against the live read (not the possibly-stale board snapshot the sweep passed on
    stdin) means a gate added since the list read — needs:design, trust:untrusted, a concurrent
    promotion, an `<!-- orchestration:hold -->` marker added to the BODY, a close — is honoured.
    Reads go through gh_retry; the mutation is single-attempt + fail-loud.

    WHICH INPUTS ARE LIVE, stated exactly (#605 review round 4 corrected two words here). Labels,
    body, open/closed state and — since #598 — the issue TYPE are re-read LIVE. The snapshot supplies
    the issue NUMBER (immutable) and the AUTHOR login — the author DOES reach a decision (it is
    compared against the maintainer/app-bot for trust) but is immutable on GitHub, and a missing
    author reads as untrusted, so a stale copy cannot widen trust. Permission is read fresh per
    issue by the shell and a failed read collapses to `none`. So no MUTABLE snapshot field reaches
    a decision — which is a narrower claim than the earlier "nothing from the snapshot reaches a
    decision", and it is the true one.
    """
    read_state, view, edit, warn = static_triage.live_gh(repo, number, title="retriage")
    live, _revision = read_state()
    fresh = dict(issue)
    fresh["labels"] = sorted(live)
    # The hold marker lives in the BODY, so the body is refreshed too or the hold is checked
    # against pre-pagination state (#605 review round 2). Fail CLOSED on a body that cannot be
    # read OR cannot be interpreted (#605 review round 4): a park we cannot verify must stop the
    # write, not be assumed absent.
    try:
        document = read_live_body(repo, number)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"::error title=retriage #{number}::cannot read the live issue body, so the "
              f"orchestration hold cannot be honoured — refusing to act (fail closed): {exc}")
        return 1
    fresh["body"] = document["body"]
    # #598: the ROLE derivation's other input. `snapshot()` deliberately does not carry a type, so
    # this key exists only because the live read produced it — a stale board copy must never decide
    # a role (see the invariant in this docstring).
    fresh["type"] = document["type"]
    if document["state"] != "OPEN":
        # #605 review round 4 (MINOR): open/closed was the last eligibility input still taken from
        # the pre-pagination board query, so an issue closed during the sweep could still be
        # promoted/repaired/re-parked. Not an error — the board was simply right when it was read.
        print(json.dumps({"action": "skip", "reason": "closed-since-snapshot"}, sort_keys=True))
        return 0
    known = list(known_labels) if known_labels else static_triage.repo_label_set(repo)
    decision = plan(fresh, maintainer, app_bot, permission, known_labels=known,
                    allow_actions_bot_issues=allow_actions_bot_issues)
    # registry #510: the LAST gate before the API. `known` is the label list this run fetched ONCE
    # (retriage.yml's `gh_read label list`, or the live fallback above) — the same oracle #582 gave
    # the classifier, now applied to EVERY label the decision would write rather than to the role
    # alone. Validated BEFORE the decision is printed, so the audit line on the run log is the write
    # that was actually attempted and not the one the classifier wished for.
    decision, dropped = validate_labels(decision, known)
    for label in dropped:
        print(f"::warning title=retriage #{number}::classifier suggested unknown label {label} — "
              f"dropped (it does not exist in {repo}'s label set, and GitHub fails the WHOLE label "
              f"edit on one unknown name; registry #510)")
    if dropped and decision["action"] in WRITING_ACTIONS and not drop_is_safe(
            decision, live, fresh["type"], known):
        # Applying what survives would strand or oscillate the issue (see drop_is_safe): write
        # NOTHING this tick. Deliberately NOT an error exit — a repository missing one of its own
        # taxonomy labels is a config defect to fix, not a reason to fail every sweep forever, and
        # a red run is exactly the state registry #510 exists to end.
        print(f"::warning title=retriage #{number}::{decision['action']} depended on "
              f"{', '.join(dropped)}; applying only the labels that survive would leave the issue "
              f"worse, so this tick writes NOTHING (registry #510 — a no-op with a log, not a red "
              f"run). Create the missing label(s) to unblock it")
        decision = {"action": "skip", "reason": UNSAFE_DROP_REASON, "dropped": dropped}
    print(json.dumps(decision, sort_keys=True))
    if decision["action"] not in WRITING_ACTIONS:
        return 0
    outcome = apply_decision(live, decision, edit, view, read_state, warn)
    if not outcome["ok"]:
        print(f"::error title=retriage #{number}::{decision['action']} did not satisfy the "
              f"single-role post-condition (registry #582): {'; '.join(outcome['warnings'])}")
        return 1
    return 0


def _self_test():
    base = {"author": {"login": "owner"}, "body": "",
            "labels": [{"name": "priority:P2"}, {"name": "area:workflows"}]}

    def issue(status, *extra, body=""):
        value = dict(base)
        value["body"] = body
        value["labels"] = base["labels"] + [{"name": status}] + [
            {"name": label} for label in extra]
        return value

    def labelled(*names, body="", author="owner"):
        return {"author": {"login": author}, "body": body,
                "labels": [{"name": name} for name in names]}

    def label_set(doc):
        return {item["name"] for item in doc["labels"]}

    def applied(doc, decision):
        """The post-mutation issue the workflow would leave behind."""
        labels = ((label_set(doc) | set(decision.get("add", [])))
                  - set(decision.get("remove", [])))
        out = dict(doc)
        out["labels"] = [{"name": name} for name in sorted(labels)]
        return out

    checks = []

    def chk(name, got, want=True):
        checks.append((f"{name}: {got!r} (want {want!r})", got == want))

    got = plan(issue("status:untriaged"), "owner", "app[bot]", "none")
    chk("status:untriaged promotion",
        got["action"] == "promote" and "status:ready" in got["add"]
        and "status:untriaged" in got["remove"])
    chk("dispatcher-owned deferred rejected",
        plan(issue("status:deferred"), "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "not-retriageable"})
    chk("mixed untriaged and deferred rejected",
        plan(issue("status:untriaged", "status:deferred"), "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "not-retriageable"})
    chk("needs gate rejected",
        plan(issue("status:untriaged", "needs:design"), "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "gated:needs:design"})
    chk("hold marker rejected",
        plan(issue("status:untriaged", body=HOLD_MARKER), "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "explicit-hold"})

    # [registry #582] the base fixture (priority:P2 + area:workflows) derives role:ci. If the target
    # repo does NOT have that label, promoting would strip/skip the role and land a role-less
    # status:ready — silently undispatchable and unrecoverable (retriage only revisits
    # status:untriaged). Fail-closed: skip, leaving the issue retriageable next tick.
    real = {"role:ci", "role:impl", "status:ready", "status:untriaged", "priority:P2",
            "area:workflows"}
    checks.append(("known label set present -> still promotes",
                   plan(issue("status:untriaged"), "owner", "app[bot]", "none",
                        known_labels=real)["action"] == "promote"))
    checks.append(("[#582] missing role label -> fail-closed skip, never role-less ready",
                   plan(issue("status:untriaged"), "owner", "app[bot]", "none",
                        known_labels=real - {"role:ci"})
                   == {"action": "skip", "reason": "classifier-incomplete"}))

    def roleless(*_args, **_kwargs):
        """A classifier that promotes while stripping the only role — the #582 shape."""
        return {"add": {"status:ready"}, "remove": {"role:ci"}, "ready": True, "role": None,
                "warnings": []}

    checks.append(("[#582] role-invariant guard rejects a role-less promotion",
                   plan(issue("status:untriaged", "role:ci"), "owner", "app[bot]", "none", roleless)
                   == {"action": "skip", "reason": "role-invariant"}))

    def broken(*_args, **_kwargs):
        raise RuntimeError("fixture")

    chk("classifier failure is idempotent",
        plan(issue("status:untriaged"), "owner", "app[bot]", "none", broken),
        {"action": "skip", "reason": "classifier-failure"})
    foreign = issue("status:untriaged")
    foreign["author"] = {"login": "outsider"}
    chk("trust rejection", plan(foreign, "owner", "app[bot]", "read"),
        {"action": "skip", "reason": "untrusted-author"})
    chk("write collaborator accepted", plan(foreign, "owner", "app[bot]", "write")["action"],
        "promote")
    chk("a promotion carries the INTENDED single role for the applier",
        plan(issue("status:untriaged"), "owner", "app[bot]", "none",
             known_labels=real).get("role"), "ci")

    # -------------------------------------------------------------------------------------------
    # [registry #487] THE ACTIONS-BOT TRIAGE OPT-IN — a LATENT-CONSISTENCY fix, not a live one.
    # `github-actions[bot]` is neither the maintainer nor the App bot and reads a repo permission
    # of `none`, so this sweep's trust gate returns `untrusted-author` for it while
    # `dispatch-claim._issue_is_trusted` and `curate-frontier.trusted_author` — reading the SAME
    # per-repo policy row — admit it. What #487 closes here is that DISAGREEMENT: triage trust can
    # no longer refuse what admission trust already grants for the same repo.
    #
    # It changes no decision on this repo today, and the honest reason is worth writing down
    # because a green sweep will otherwise be misread as coverage. The sweep's board is EXACTLY
    # the two lane queries (`labels=status:untriaged` and `labels=status:ready` — asserted by
    # EXECUTION in the "[#487] the sweep board is EXACTLY the two lane queries" row below), and
    # nothing puts a `github-actions[bot]` issue on either lane: `triage-issue.yml` is the only
    # thing that applies a lane label and it fires on `issues: [opened, edited, reopened, labeled,
    # unlabeled]` (#607), while events written with the repository's own `GITHUB_TOKEN` do not start
    # workflow runs — so the alert issues `metrics.py` opens on `github.token`, and every label our
    # own workflows then write on them, are never triaged at all. `plan()` is
    # therefore never called on them and this gate is never reached. Making the alert-responder
    # class actually triageable needs the UPSTREAM unit (open those issues as the App bot, for
    # which `triage-issue.yml` does fire, or have `metrics.py` apply the triage labels itself);
    # this diff is the consumer that will be correct when that lands, and inert until it does.
    # -------------------------------------------------------------------------------------------
    def authored(login, *names, body=""):
        doc = issue(*names, body=body) if names else issue("status:untriaged", body=body)
        doc["author"] = {"login": login}
        return doc

    chk("[#487] actions-bot is UNTRUSTED with no opt-in (the shipped default)",
        plan(authored(ACTIONS_BOT_LOGIN), "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "untrusted-author"})
    chk("[#487] ...and TRIAGEABLE with it — the whole point of the unit",
        plan(authored(ACTIONS_BOT_LOGIN), "owner", "app[bot]", "none",
             allow_actions_bot_issues=True)["action"], "promote")
    # NEGATIVE CONTROLS. Each impostor kills a DIFFERENT sloppy implementation of the same test:
    # `endswith`, `startswith`, a case-folded compare, an `in` containment, and the bare "<x>[bot]"
    # suffix match that #487 removed from dispatch. Only `==` passes all five.
    for impostor in ("my-github-actions[bot]",      # dies on .endswith(ACTIONS_BOT_LOGIN)
                     "github-actions[bot]-evil",    # dies on .startswith(ACTIONS_BOT_LOGIN)
                     "GitHub-Actions[bot]",         # dies on a .lower() compare
                     "github-actions",              # dies on `login in ACTIONS_BOT_LOGIN`
                     "evil-app[bot]"):              # dies on the pre-#487 "[bot]" suffix match
        chk(f"[#487] NEGATIVE: {impostor!r} is refused even WITH the opt-in",
            plan(authored(impostor), "owner", "app[bot]", "none", allow_actions_bot_issues=True),
            {"action": "skip", "reason": "untrusted-author"})
    # SCOPE. The opt-in widens who may be CLASSIFIED and nothing else: every park check runs after
    # it, unchanged, for an actions-bot author exactly as for the maintainer. `needs:user` is the
    # terminal HUMAN hold (park_policy invariant 3) and must never be re-admitted by this widening.
    for reason, names, body in (
            ("gated:needs:user", ("status:untriaged", "needs:user"), ""),
            ("gated:trust:untrusted", ("status:untriaged", "trust:untrusted"), ""),
            ("explicit-hold", ("status:untriaged",), HOLD_MARKER),
            ("not-retriageable", ("status:deferred",), ""),
            ("machine-parked", ("status:untriaged", park_policy.MACHINE_PARK_LABEL), ""),
            ("claim-owned", ("status:untriaged", "status:in-progress"), ""),
            ("epic", ("status:untriaged", NON_DISPATCHABLE), "")):
        chk(f"[#487] the opt-in widens TRIAGE only — {reason} still stands for the bot author",
            plan(authored(ACTIONS_BOT_LOGIN, *names, body=body), "owner", "app[bot]", "none",
                 allow_actions_bot_issues=True),
            {"action": "skip", "reason": reason})
    # ...and the same park set is refused identically for the MAINTAINER, so the rows above are
    # asserting the park checks' reach and not merely re-asserting the trust gate they sit behind.
    chk("[#487] POSITIVE CONTROL: those parks are the SHARED path, not a bot-only branch",
        [plan(authored("owner", *names, body=body), "owner", "app[bot]", "none")["reason"]
         for reason, names, body in (
             ("gated:needs:user", ("status:untriaged", "needs:user"), ""),
             ("explicit-hold", ("status:untriaged",), HOLD_MARKER),
             ("machine-parked", ("status:untriaged", park_policy.MACHINE_PARK_LABEL), ""))],
        ["gated:needs:user", "explicit-hold", "machine-parked"])
    # The login string is duplicated across three trust surfaces (this sweep, the curator, CLAIM).
    # Pin it to the curator's copy so a one-sided edit cannot silently split triage from admission.
    _curator = _load("curate_frontier_for_test", "curate-frontier.py")
    chk("[#487] the trusted login is IDENTICAL to the curator's — no per-file drift",
        (ACTIONS_BOT_LOGIN, _curator.ACTIONS_BOT_LOGIN),
        ("github-actions[bot]", "github-actions[bot]"))


    # ---- #586: the label-lost half. A `status:ready` issue the readiness engine cannot
    # enumerate is re-parked; a healthy one is left completely untouched. ----
    # `area:groom` is a TRUST-SURFACE keyword, so triage() derives the trust-plane role for it
    # (triage.TRUST_PLANE_ROLE, ahead of any explicit `role:*`). The fixtures below therefore carry
    # that same role: the lane under test is the LOST-LABEL drift, not an incidental re-route.
    ROLE = static_triage.TRUST_PLANE_ROLE
    ROLE_LABEL = f"role:{ROLE}"
    HEALTHY = ("status:ready", "priority:P2", ROLE_LABEL, "area:groom")
    healthy = labelled(*HEALTHY)
    chk("POSITIVE CONTROL: a fully-labelled status:ready issue is untouched",
        plan(healthy, "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "ready-consistent"})
    # #605 review finding 5: "carries NO label writes" alone was satisfied by the PRE-FIX code too,
    # which rejected every `status:ready` issue as `not-retriageable` and so also wrote nothing. The
    # assertion only means something PAIRED with its opposite, so assert the discrimination: the
    # healthy issue carries no writes AND a drifted twin (same labels minus the role) carries them.
    chk("POSITIVE CONTROL: 'no label writes' DISCRIMINATES — the drifted twin does write",
        (sorted(set(plan(healthy, "owner", "app[bot]", "none")) & {"add", "remove"}),
         sorted(set(plan(labelled("status:ready", "priority:P2", "area:groom"),
                         "owner", "app[bot]", "none")) & {"add", "remove"})),
        ([], ["add", "remove"]))
    # Criterion 4 scope: an ENUMERABLE status:ready issue is never rewritten by this sweep, even
    # when the classifier sees other drift (here: an ambiguous role set it would collapse).
    chk("an enumerable status:ready issue is left alone despite unrelated classifier drift",
        plan(labelled("status:ready", "priority:P2", "role:soundness", "role:impl", "area:docs"),
             "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "ready-consistent"})

    lost_priority = labelled("status:ready", ROLE_LABEL, "area:groom")
    # Every WRITING decision carries the intended `role` (the applier's add-before-strip input),
    # so an accidental drop of it — which would disarm the #582 verification on these lanes —
    # fails this suite rather than shipping silently.
    chk("lost priority is re-parked", plan(lost_priority, "owner", "app[bot]", "none"),
        {"action": "repark", "add": ["status:untriaged"], "remove": ["status:ready"],
         "role": ROLE})
    ambiguous = labelled("status:ready", "priority:P1", "priority:P2", ROLE_LABEL, "area:groom")
    chk("ambiguous priority is re-parked", plan(ambiguous, "owner", "app[bot]", "none"),
        {"action": "repark", "add": ["status:untriaged"], "remove": ["status:ready"],
         "role": ROLE})
    lost_area = labelled("status:ready", "priority:P2", ROLE_LABEL)
    chk("lost area is re-parked", plan(lost_area, "owner", "app[bot]", "none"),
        {"action": "repark", "add": ["status:untriaged"], "remove": ["status:ready"],
         "role": ROLE})
    chk("the re-park never MINTS a needs:* gate it would then refuse to cross",
        "needs:area" in plan(lost_area, "owner", "app[bot]", "none").get("add", []), False)
    lost_role = labelled("status:ready", "priority:P2", "area:groom")
    chk("lost role is repaired in place (the classifier re-derives it)",
        plan(lost_role, "owner", "app[bot]", "none"),
        {"action": "repair", "add": [ROLE_LABEL], "remove": [], "role": ROLE})

    # Park policy stays load-bearing on the NEW lane too — none of these is re-parked.
    for park, reason in ((park_policy.MACHINE_PARK_LABEL, "machine-parked"),
                         ("status:in-progress", "claim-owned"),
                         ("status:in-progress-review", "claim-owned"),
                         ("kind:epic", "epic"),
                         ("status:deferred", "not-retriageable")):
        chk(f"status:ready + {park} is not re-parked",
            plan(labelled("status:ready", ROLE_LABEL, "area:groom", park),
                 "owner", "app[bot]", "none"),
            {"action": "skip", "reason": reason})
    chk("status:ready + needs:user is not re-parked (human-owned park)",
        plan(labelled("status:ready", ROLE_LABEL, "area:groom", "needs:user"),
             "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "gated:needs:user"})
    chk("an untrusted author is never inspected on the re-park lane",
        plan(labelled("status:ready", ROLE_LABEL, "area:groom", author="outsider"),
             "owner", "app[bot]", "read"),
        {"action": "skip", "reason": "untrusted-author"})
    chk("an orchestration hold is honoured on the re-park lane",
        plan(labelled("status:ready", ROLE_LABEL, "area:groom", body=HOLD_MARKER),
             "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "explicit-hold"})
    chk("classifier failure never re-parks",
        plan(lost_priority, "owner", "app[bot]", "none", broken),
        {"action": "skip", "reason": "classifier-failure"})
    # #605 review round 4 (MINOR): the re-park lane's classifier-CONSISTENCY guard had no fixture —
    # every real classifier verdict happens to carry both halves of the park, so deleting
    # `if "status:untriaged" not in add or "status:ready" not in remove` stayed green while a drifted
    # classifier could drive a re-park that strips `status:ready` WITHOUT adding `status:untriaged`
    # (terminally unenumerable) or adds the park without leaving the ready lane (a contradiction).
    # Both halves, from a stub whose verdict is otherwise well-formed.
    def drifted(add, remove):
        def classify(labels, kind, trusted=True, known_labels=None):
            return {"ready": False, "add": list(add), "remove": list(remove), "role": None,
                    "warnings": []}
        return classify

    chk("[#605 r4] a re-park verdict missing status:untriaged is refused, never applied",
        plan(lost_priority, "owner", "app[bot]", "none", drifted([], ["status:ready"])),
        {"action": "skip", "reason": "classifier-inconsistent"})
    chk("[#605 r4] a re-park verdict that never leaves the ready lane is refused too",
        plan(lost_priority, "owner", "app[bot]", "none", drifted(["status:untriaged"], [])),
        {"action": "skip", "reason": "classifier-inconsistent"})
    chk("[#605 r4] ...while a well-formed park verdict still re-parks (not over-refusing)",
        plan(lost_priority, "owner", "app[bot]", "none",
             drifted(["status:untriaged"], ["status:ready"]))["action"],
        "repark")
    # FAIL CLOSED: the classifier calls it complete but the engine still cannot enumerate it
    # (`status:blocked` is a busy status triage() knows nothing about) -> no write.
    chk("an unprovable exclusion is left alone",
        plan(labelled("status:ready", "status:blocked", "priority:P2", ROLE_LABEL,
                      "area:groom"), "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "unprovable"})

    dual = labelled("status:untriaged", "status:ready", ROLE_LABEL, "area:groom")
    chk("a contradictory dual-status issue loses its stale status:ready",
        plan(dual, "owner", "app[bot]", "none"),
        {"action": "repark", "add": [], "remove": ["status:ready"], "role": ROLE})
    # [sparq#4809] The de-contradicted board no longer STOPS here: the stale `status:ready` is gone,
    # so the issue is a never-prioritised one and the floor applies. What still has to hold is
    # CONVERGENCE — the sweep must reach a fixed point, in a BOUNDED number of ticks, with no
    # oscillation. It now takes two writes (strip the stale attestation, then promote) instead of
    # stalling forever, so the third sweep is asserted stable rather than the second.
    _dedup = applied(dual, plan(dual, "owner", "app[bot]", "none"))
    _dedup_plan = plan(_dedup, "owner", "app[bot]", "none")
    chk("[sparq#4809] the de-contradicted board PROMOTES at the floor (it used to stall forever)",
        (_dedup_plan["action"], static_triage.DERIVED_PRIORITY in _dedup_plan.get("add", [])),
        ("promote", True))
    chk("[sparq#4809] ...and the sweep reaches a FIXED POINT on the third tick — no oscillation",
        plan(applied(_dedup, _dedup_plan), "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "ready-consistent"})
    # [sparq#4809] THE HEADLINE, END TO END, THROUGH THE SWEEP'S OWN CALL SITE. This is the exact
    # population that was terminal: untriaged, role + area present, no priority, nothing gated.
    # `plan()` — not `triage()` — is what the workflow invokes, so a call-site filter that dropped
    # `priority:*` from the action's `add` (the applier writes `sorted(add)` verbatim) would leave
    # triage.py's own assertions green while nothing reached the API. Assert the LABEL is in the
    # planned write, not merely that the action is a promotion.
    _stuck = plan(labelled("status:untriaged", ROLE_LABEL, "area:groom"),
                  "owner", "app[bot]", "none")
    chk("[sparq#4809] HEADLINE: the terminal untriaged-no-priority issue is PROMOTED, and the "
        "derived priority is in the write the applier will send",
        (_stuck["action"], sorted(_stuck.get("add", [])), _stuck.get("remove", [])),
        ("promote", [static_triage.DERIVED_PRIORITY, "status:ready"], ["status:untriaged"]))

    # ---- IDEMPOTENCE + the round trip (re-park -> restore the label -> promote lands back on
    # the ORIGINAL label set, with no oscillation and no second write) ----
    reparked = applied(lost_priority, plan(lost_priority, "owner", "app[bot]", "none"))
    # [sparq#4809] THE TRADE, PINNED — read this before widening or narrowing the derivation.
    # While the issue still carried its stale `status:ready`, `derive_priority` DECLINED it
    # (`ready-attested-regression`): a ready-attested issue with no readable priority LOST one, and
    # flooring it would overwrite a human's P0..P3. That decline is what makes the re-park above
    # happen at all. Once re-parked the attestation is gone, so the next sweep can no longer tell
    # this issue from one that was never prioritised, and it floors it.
    #
    # That is deliberate and it is the lesser harm: the alternative is the starvation this change
    # exists to fix — the old behaviour left the issue untriaged indefinitely, waiting on a human
    # who, measured across two weeks of green retriage runs, did not come.
    _floored = plan(reparked, "owner", "app[bot]", "none")
    chk("[sparq#4809] a re-parked lost-priority issue is floored by the NEXT sweep, not stalled",
        (_floored["action"], static_triage.DERIVED_PRIORITY in _floored.get("add", [])), ("promote", True))
    # ...and a LATE restore — the human's real priority arriving AFTER that floor landed — is now
    # RESOLVED rather than declined. An earlier revision of this fixture asserted the pair stayed
    # declined-and-visible and called that the acceptable failure mode of the trade; PR #1053's
    # review showed that is the majority path, not an edge case, so the retract rung decides it.
    # The floor is withdrawn and the restored value governs.
    _late = applied(applied(reparked, _floored), {"add": ["priority:P2"]})
    _late_plan = plan(_late, "owner", "app[bot]", "none")
    chk("[sparq#4809] a LATE restore RETRACTS the floor and keeps the human's value",
        (static_triage.derive_priority(label_set(_late))[1],
         static_triage.DERIVED_PRIORITY in _late_plan.get("remove", []),
         any(lb.startswith("priority:") for lb in _late_plan.get("add", []))),
        ("floor-retracted", True, False))
    chk("[sparq#4809] ...landing on the human's priority, with the floor gone",
        {lb for lb in label_set(applied(_late, _late_plan)) if lb.startswith("priority:")},
        {"priority:P2"})
    restored = dict(reparked)
    restored["labels"] = reparked["labels"] + [{"name": "priority:P2"}]
    promotion = plan(restored, "owner", "app[bot]", "none")
    chk("the restored label is promoted back by the EXISTING lane", promotion["action"], "promote")
    chk("ROUND TRIP: re-park -> restore -> promote lands on the original label set",
        label_set(applied(restored, promotion)), set(HEALTHY))
    chk("ROUND TRIP: the round-tripped issue is then left untouched",
        plan(applied(restored, promotion), "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "ready-consistent"})
    repaired = applied(lost_role, plan(lost_role, "owner", "app[bot]", "none"))
    chk("a second sweep over the repaired board plans ZERO writes",
        plan(repaired, "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "ready-consistent"})

    # ---- the bounded, fail-closed snapshot ----
    def api(number, *names, login="owner", updated="2026-07-01T00:00:00Z"):
        return {"number": number, "user": {"login": login}, "body": "",
                "labels": [{"name": name} for name in names], "updated_at": updated}

    issues, dropped = snapshot([[api(3, "status:ready", updated="2026-07-03T00:00:00Z"),
                                 {"number": 99, "pull_request": {"url": "x"}}],
                                [api(1, "status:untriaged", updated="2026-07-01T00:00:00Z")]])
    chk("snapshot drops pull requests and normalizes the gh-issue-list shape",
        [i["number"] for i in issues], [1, 3])
    chk("snapshot normalizes user.login to author.login", issues[0]["author"], {"login": "owner"})
    # #605 review finding 4: the old label check fed `{"name": ...}` dicts, the exact output shape,
    # so the normalization step was an IDENTITY there and deleting it left the check green. Feed the
    # OTHER accepted input shape — the bare string the REST payload uses for a label-name list — and
    # a missing/absent author, so the normalization has real work to do.
    bare, _ = snapshot([[{"number": 5, "labels": ["status:ready", "priority:P2"],
                         "updated_at": "2026-07-05T00:00:00Z"}]])
    chk("[#605] snapshot normalizes BARE string labels and a missing author",
        (bare[0]["labels"], bare[0]["author"], bare[0]["body"]),
        ([{"name": "status:ready"}, {"name": "priority:P2"}], {"login": ""}, ""))
    chk("snapshot dedupes an issue matched by BOTH label queries",
        [i["number"] for i in snapshot([[api(4, "status:ready")], [api(4, "status:ready")]])[0]],
        [4])

    # ---- #605 review finding 1 (BLOCKER): the per-run window must ROTATE, or a capped board
    # starves its tail FOREVER. The old window was the oldest-`cap` by `updatedAt`, and a no-op skip
    # does not change `updated_at`, so the same head was re-selected on every run while the warning
    # claimed the rest were "deferred to the next run". These checks are the coverage proof.
    board = [[api(n, "status:ready", updated=f"2026-07-{n:02d}T00:00:00Z") for n in range(1, 8)]]
    windows = [[i["number"] for i in snapshot(board, cap=3, rotation=r)[0]] for r in range(4)]
    # (each window is then re-sorted oldest-updated-first for hand-over, so #7 leads its window by
    # NUMBER but trails it by updatedAt — the selection is what rotates, not the hand-over order.)
    chk("[#605] consecutive rotations ADVANCE the window — there is no fixed head any more",
        windows, [[1, 2, 3], [4, 5, 6], [1, 2, 7], [3, 4, 5]])
    chk("[#605] every issue on the board is covered within ceil(total/cap) runs",
        sorted({number for window in windows[:3] for number in window}), [1, 2, 3, 4, 5, 6, 7])
    # #605 review round 4 (MINOR, an F-class wording defect): the docstring and the workflow comment
    # called consecutive windows "disjoint"/"a partition". They are not, whenever `cap` does not
    # divide `total` — this very fixture wraps and re-visits 1 and 2. The claim is now COVERAGE, and
    # the overlap is asserted so nobody re-derives the stronger wording from a passing suite.
    chk("[#605 r4] the wrapping window OVERLAPS the head when the cap does not divide the board",
        (sorted(set(windows[0]) & set(windows[2])), len(board[0]) % 3), ([1, 2], 1))
    divides = [{i["number"] for i in snapshot([board[0][:6]], cap=3, rotation=r)[0]}
               for r in range(2)]
    chk("[#605 r4] ...and it IS a partition exactly when the cap divides the board",
        (sorted(divides[0] & divides[1]), sorted(divides[0] | divides[1])),
        ([], [1, 2, 3, 4, 5, 6]))
    chk("[#605] the cap and the outside-the-window count are exact at every rotation",
        {(len(window), snapshot(board, cap=3, rotation=r)[1])
         for r, window in enumerate(windows)}, {(3, 4)})
    # the old fixed-window behaviour, stated as the thing that must NOT come back: rotation 0 and
    # rotation 1 must not be the same window.
    chk("[#605] rotation actually MOVES the window (a fixed window is the starvation bug)",
        windows[0] == windows[1], False)
    chk("[#605] within a run the window is handed over oldest-updated first",
        [i["updatedAt"] for i in snapshot(
            [[api(3, "status:ready", updated="2026-07-09T00:00:00Z"),
              api(1, "status:ready", updated="2026-07-02T00:00:00Z"),
              api(2, "status:ready", updated="2026-07-05T00:00:00Z")]], cap=3)[0]],
        ["2026-07-02T00:00:00Z", "2026-07-05T00:00:00Z", "2026-07-09T00:00:00Z"])
    # #605 review finding 4: a cap ABOVE the board size proved nothing (dropped was 0 either way).
    # Assert the boundary in both directions.
    chk("[#605] a board that fits is whole and drops nothing; one over the cap drops exactly one",
        (snapshot(board, cap=7, rotation=9)[1], snapshot(board, cap=6, rotation=0)[1],
         len(snapshot(board, cap=7, rotation=9)[0])),
        (0, 1, 7))
    huge = [i["number"] for i in snapshot(board, cap=3, rotation=10 ** 9)[0]]
    chk("a negative/absurd rotation cannot escape the board",
        ([i["number"] for i in snapshot(board, cap=3, rotation=-5)[0]],
         len(huge), sorted(set(huge) - set(range(1, 8)))),
        ([1, 2, 3], 3, []))

    # #605 review finding 4: each refusal now asserts the MESSAGE, not merely that SOMETHING raised
    # — the payloads reach several different guards, and a bare "did it raise" check cannot tell
    # which one fired, so deleting one guard could leave the check green on a neighbour's raise.
    for label, payload, needle in (
            ("a runaway board", [[api(n, "status:ready") for n in range(12)]], "looks runaway"),
            ("a partial page", [[api(1, "status:ready")], "truncated"], "is not a list — refusing"),
            ("a non-object entry", [[api(1, "status:ready"), 7]], "entry is not an object"),
            ("a numberless entry", [[{"user": {"login": "o"}, "labels": []}]],
             "no integer issue number"),
            ("a malformed label", [[{"number": 1, "labels": [{"colour": "red"}]}]],
             "malformed label"),
            # #605 review round 4 (MINOR): `item.get("labels") or []` normalized every one of these
            # to "no labels" while sitting inside the fail-closed claim.
            ("an ABSENT labels container", [[{"number": 1, "user": {"login": "o"}}]],
             "malformed `labels` container"),
            ("a null labels container", [[{"number": 1, "labels": None}]],
             "malformed `labels` container"),
            ("a string labels container", [[{"number": 1, "labels": "status:ready"}]],
             "malformed `labels` container"),
            ("an object labels container", [[{"number": 1, "labels": {"name": "x"}}]],
             "malformed `labels` container"),
            ("a non-list payload", {"pages": []}, "payload is not a list of pages")):
        try:
            snapshot(payload, ceiling=10)
            chk(f"snapshot refuses {label}", "no error", f"SweepError({needle!r})")
        except SweepError as exc:
            chk(f"snapshot refuses {label}", needle in str(exc), True)

    # -------------------------------------------------------------------------------------------
    # [PR #595 finding 3] THE LIVE TRANSITION IS FAIL-CLOSED — verified against a fake GitHub, not
    # against the shell. The workflow used to issue ONE `gh issue edit` carrying the adds AND the
    # removals, with no add-first verification: when the add failed (the #582 shape — a role label
    # the repo does not have) the strip still landed and the issue went ready-and-role-less.
    class FakeGh:
        """Drops adds of labels outside `known` (the live #582 failure mode) + tracks a revision."""

        def __init__(self, labels, known):
            self.labels, self.known, self.rev, self.calls = set(labels), set(known), 0, []

        def edit(self, add, remove):
            self.calls.append((sorted(add), sorted(remove)))
            before = set(self.labels)
            for label in add:
                if label not in self.known:
                    raise RuntimeError(f"'{label}' not found")
                self.labels.add(label)
            self.labels -= set(remove)
            if self.labels != before:
                self.rev += 1

        def view(self):
            return set(self.labels)

        def read_state(self):
            return set(self.labels), self.rev

    def roles_of(labels):
        return {label for label in labels if label.startswith("role:")}

    def live_plan(gh, known):
        doc = {"author": {"login": "owner"}, "body": "",
               "labels": [{"name": name} for name in sorted(gh.labels)]}
        return plan(doc, "owner", "app[bot]", "none", known_labels=known)

    # A trust-surface area is the one input that RE-ROUTES an incumbent role (an explicit role:*
    # otherwise wins), so it is the fixture that exercises the add-then-strip transition.
    start = {"priority:P2", "area:dispatch", "role:docs", "status:untriaged"}
    known = real | {"role:docs", "area:dispatch"}
    gh = FakeGh(start, known)
    outcome = apply_decision(set(gh.labels), live_plan(gh, known), gh.edit, gh.view, gh.read_state)
    checks.append(("[#595 f3] happy path: exactly one role, promoted, ok",
                   (outcome["ok"], roles_of(gh.labels), "status:ready" in gh.labels,
                    "status:untriaged" in gh.labels) == (True, {"role:impl"}, True, False)))
    # The target role label does NOT exist in the repo: the ADD fails, so NOTHING may be stripped.
    # plan() already fails closed on that input, so the applier is driven with the PRE-FIX plan
    # shape — the blind add-role/strip-role mutation the workflow shell used to send in one edit.
    gh = FakeGh(start, known - {"role:impl"})
    outcome = apply_decision(set(gh.labels),
                              {"action": "promote", "add": ["role:impl", "status:ready"],
                               "remove": ["role:docs", "status:untriaged"], "role": "impl"},
                              gh.edit, gh.view, gh.read_state)
    checks.append(("[#595 f3] a non-existent replacement role NEVER strips the incumbent",
                   (outcome["ok"], roles_of(gh.labels)) == (False, {"role:docs"})))
    checks.append(("[#595 f3] the refusal names the label and #582",
                   any("role:impl" in w and "#582" in w for w in outcome["warnings"])))
    # a post-read that finds ZERO roles on a status:ready issue RESTORES the incumbent — the old
    # workflow check merely `exit 1`-ed here, leaving the terminal state live.
    class RoleEatingGh(FakeGh):
        def edit(self, add, remove):
            super().edit(add, remove)
            if not any(label.startswith("role:") for label in add):
                self.labels -= roles_of(self.labels)
                self.rev += 1

    gh = RoleEatingGh(start, known)
    outcome = apply_decision(set(gh.labels), live_plan(gh, known), gh.edit, gh.view, gh.read_state)
    checks.append(("[#595 f3] a zero-role post-state is RESTORED, not merely reported",
                   (outcome["ok"], roles_of(gh.labels), "status:ready" in gh.labels)
                   == (False, {"role:docs"}, True)))
    # MULTIPLE roles are rejected by route-resolve (AmbiguousRoleError), so the post-read must not
    # accept them: the old workflow check (`,$post,` != *",role:"*) PASSED an ambiguous set, leaving
    # a terminal undispatchable issue. Repair down to the single intended role instead.
    class InjectingGh(FakeGh):
        """A concurrent actor injects a THIRD role label once, mid-transition."""

        def __init__(self, labels, known, persistent=False):
            super().__init__(labels, known)
            self.persistent, self.injected = persistent, False

        def edit(self, add, remove):
            super().edit(add, remove)
            if (self.persistent or not self.injected) and "role:ci" not in self.labels:
                self.injected = True
                self.labels.add("role:ci")
                self.rev += 1

    gh = InjectingGh(start, known)
    outcome = apply_decision(set(gh.labels), live_plan(gh, known), gh.edit, gh.view, gh.read_state)
    checks.append(("[#595 f3] an ambiguous post-state is repaired to ONE role, never accepted",
                   (outcome["ok"], roles_of(gh.labels), "status:ready" in gh.labels)
                   == (False, {"role:impl"}, True)))
    # ... and when the repair CANNOT hold (a persistent concurrent writer), status:ready is DEMOTED
    # to status:untriaged so the next retriage tick owns the issue — never left ready-and-ambiguous,
    # which route-resolve rejects and nothing else revisits.
    gh = InjectingGh(start, known, persistent=True)
    outcome = apply_decision(set(gh.labels), live_plan(gh, known), gh.edit, gh.view, gh.read_state)
    checks.append(("[#595 f3] an unrepairable ambiguity DEMOTES to status:untriaged, never terminal",
                   (outcome["ok"], "status:ready" in gh.labels, "status:untriaged" in gh.labels)
                   == (False, False, True)))

    # -------------------------------------------------------------------------------------------
    # [PR #595 finding 2] THE ARGV ENTRYPOINT, PINNED TO THE WORKFLOW'S OWN ARGUMENT LIST.
    # Every check above calls plan()/apply_decision() DIRECTLY, which is precisely why
    # `--known-labels` could ship undeclared: the workflow-shaped invocation exited 2 with
    # "unrecognized arguments" on every scheduled sweep while this suite reported PASSED. The
    # argument list below is READ OUT OF THE WORKFLOW FILE and driven through the REAL entrypoint
    # (main -> _apply_cli -> plan -> apply_decision) against a fake GitHub, so a workflow/CLI drift
    # turns the enrolled suite red instead of hiding behind a direct call.
    import io
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    workflow = os.path.join(root, ".github/workflows/retriage.yml")
    argvs = static_triage.workflow_argvs(
        workflow, "retriage.py",
        {"MAINTAINER_LOGIN": "owner", "APP_BOT_LOGIN": "app[bot]", "permission": "write",
         "known": ",".join(sorted(known)), "REPO": "o/r", "number": "7"})
    options = static_triage.declared_options(build_parser())
    passed = sorted({token for argv in argvs for token in argv if token.startswith("--")})
    checks.append(("[#595 f2] retriage.yml invokes scripts/retriage.py (self-test + apply)",
                   len(argvs) >= 2))
    checks.append((f"[#595 f2] every flag retriage.yml passes is DECLARED by the parser: {passed}",
                   not set(passed) - options))
    checks.append(("[#595 f2] the workflow still passes --known-labels", "--known-labels" in passed))

    apply_argv = next((argv for argv in argvs if "--apply" in argv), [])
    stale = {"author": {"login": "owner"}, "body": "", "labels": [{"name": "stale:snapshot"}]}

    def run_apply_argv(gh, stdin_doc=None, live_body="", body_error=None, live_document=None,
                       live_state="OPEN", argv=None, live_type=None):
        """Drive main(apply_argv) end-to-end against a fake GitHub. Returns (exit code, spied).

        THE STUB BOUNDARY IS `triage._gh_read`, NOT `read_live_body` (#605 review round 4, MAJOR).
        The round-3 form substituted `read_live_body` itself, which proved only that `_apply_cli`
        consults that name: replacing the function's whole body with `return ""`, or pointing it at
        issue `1`, left every row green. Stubbing the READ under it puts the production call site —
        the argv it builds, the JSON parse, and the fail-closed shape validation — inside the test.

        `live_body` is what the LIVE issue body read returns — distinct from the stdin snapshot's
        body, which is how the #605 round-2 fail-open hold race is exercised. `live_document`
        overrides the whole RAW response text (a malformed success). `body_error` makes the read
        fail like the real `_gh_read` does, which must stop the write. `live_type` is the LIVE
        issue-type name (#598); `None` renders GitHub's untyped answer, a JSON `null` `issueType`."""
        seen = {}
        saved_plan = globals()["plan"]
        saved_read = static_triage._gh_read                # noqa: SLF001 — the seam under test
        saved_live_gh, saved_labels = static_triage.live_gh, static_triage.repo_label_set
        saved_stdin, saved_stdout = sys.stdin, sys.stdout

        def spy_plan(issue_doc, maintainer, app_bot, permission,
                     classify=static_triage.triage, known_labels=None,
                     allow_actions_bot_issues=False):
            seen.update(known_labels=known_labels, maintainer=maintainer, permission=permission,
                        labels=list(issue_doc.get("labels", ())), body=issue_doc.get("body"),
                        type=issue_doc.get("type"),
                        allow_actions_bot_issues=allow_actions_bot_issues)
            return saved_plan(issue_doc, maintainer, app_bot, permission, classify, known_labels,
                              allow_actions_bot_issues)

        def fake_read(args):
            """The one shared read layer, faked at the boundary the production code really calls."""
            seen.setdefault("reads", []).append(list(args))
            if body_error is not None:
                # Exactly how the real _gh_read reports a failed read.
                raise RuntimeError(f"gh {' '.join(args)} failed: {body_error}")
            if live_document is not None:
                return live_document
            return json.dumps({"body": live_body, "state": live_state,
                               # GitHub renders an issue with no type as a JSON null `issueType`,
                               # and a typed one as the object below (#598).
                               "issueType": {"name": live_type} if live_type else None})

        try:
            globals()["plan"] = spy_plan
            static_triage._gh_read = fake_read             # noqa: SLF001 — the seam under test
            static_triage.live_gh = lambda repo, number, title="triage": (
                gh.read_state, gh.view, gh.edit, lambda _message: None)
            static_triage.repo_label_set = lambda repo: (_ for _ in ()).throw(
                AssertionError("--known-labels must be used; the live label read is a fallback"))
            sys.stdin = io.StringIO(json.dumps(stdin_doc if stdin_doc is not None else stale))
            sys.stdout = io.StringIO()
            try:
                code = main(apply_argv if argv is None else argv)
            except SystemExit as exc:  # argparse exits 2 on an undeclared flag — that is the defect
                code = exc.code
            finally:
                seen["stdout"] = sys.stdout.getvalue()
        finally:
            globals()["plan"] = saved_plan
            static_triage._gh_read = saved_read            # noqa: SLF001 — the seam under test
            static_triage.live_gh, static_triage.repo_label_set = saved_live_gh, saved_labels
            sys.stdin, sys.stdout = saved_stdin, saved_stdout
        return code, seen

    gh = FakeGh(start, known)
    code, seen = run_apply_argv(gh)
    checks.append(("[#595 f2] the workflow-shaped ARGV exits 0 (it exited 2: unrecognized args)",
                   code == 0))
    checks.append(("[#595 f2] --known-labels reaches plan() as a parsed label list",
                   seen.get("known_labels") == sorted(known)))
    checks.append(("[#595 f2] the other workflow-passed values reach plan() too",
                   (seen.get("maintainer"), seen.get("permission")) == ("owner", "write")))
    checks.append(("[#595 f2] --apply plans against the LIVE labels, not the stdin snapshot",
                   "stale:snapshot" not in (seen.get("labels") or [])))
    checks.append(("[#595 f2] the workflow-shaped invocation actually applied the promotion",
                   (roles_of(gh.labels), "status:ready" in gh.labels) == ({"role:impl"}, True)))

    # -------------------------------------------------------------------------------------------
    # [registry #487] THE OPT-IN IS WIRED, END TO END, FROM THE YAML. Everything above this point
    # passes `allow_actions_bot_issues` to plan() DIRECTLY — which is exactly how a policy flag can
    # be "consumed" by a script that production never hands it to (the shape #487's own dispatch
    # half and PR #595 finding 2 both hit). So the argument list is READ OUT OF retriage.yml and
    # driven through the REAL entrypoint (main -> actions_bot_trust -> _apply_cli -> plan ->
    # apply_decision) against fixture policies, and the ISSUE IS ACTUALLY PROMOTED OR NOT.
    #
    # The mutations these rows die on:
    #   * delete `--policy-file policy/repos.toml` from retriage.yml       -> SweepError below
    #   * typo the path                                                    -> the EXISTS row
    #   * drop `allow_actions_bot_issues=...` from _apply_cli's plan() call -> the grant rows
    #   * hardcode the flag True                                           -> the deny rows
    #   * hardcode it False                                                -> the grant rows
    # -------------------------------------------------------------------------------------------
    import tempfile

    def workflow_policy_path(argv):
        """The policy path retriage.yml ACTUALLY passes — or a legible refusal.

        Raised, not returned-False, and deliberately BEFORE anything indexes the argv: a bare
        `ValueError: '--policy-file' is not in list` from a later index() is a kill with no name
        on it. Same idiom as run_snapshot_argv's missing-`--snapshot` refusal below."""
        if "--policy-file" not in argv:
            raise SweepError(
                "retriage.yml no longer passes `--policy-file` to `retriage.py --apply` — the "
                "registry #487 actions-bot triage opt-in would silently revert to DENY and every "
                "issue this repo's own workflows open would go back to `untrusted-author` with a "
                "perfectly green sweep; refusing")
        return argv[argv.index("--policy-file") + 1]

    def apply_argv_for(policy_path, permission="none"):
        """retriage.yml's OWN apply argv with the two values production computes PER RUN: the
        collaborator permission (the shell probes it per issue) and the policy file. The policy
        path is a repo-relative literal rather than a `$VAR`, so it is swapped here instead of
        env-substituted; every other token is exactly what the workflow writes."""
        argv = next((candidate for candidate in static_triage.workflow_argvs(
            workflow, "retriage.py",
            {"MAINTAINER_LOGIN": "owner", "APP_BOT_LOGIN": "app[bot]", "permission": permission,
             "known": ",".join(sorted(known)), "REPO": "o/r", "number": "7"})
            if "--apply" in candidate), None)
        if argv is None:
            raise SweepError("retriage.yml no longer invokes `retriage.py --apply` — refusing")
        argv = list(argv)
        workflow_policy_path(argv)              # refuse legibly before indexing
        argv[argv.index("--policy-file") + 1] = policy_path
        return argv

    # The path retriage.yml ACTUALLY names must exist and be a usable policy. `root` is the repo
    # root; production resolves the same relative path against the step's cwd, which actions/
    # checkout makes that same directory.
    declared_policy = workflow_policy_path(apply_argv)
    live_policy = (declared_policy if os.path.isabs(declared_policy)
                   else os.path.join(root, declared_policy))
    live_rows = {}
    try:
        with open(live_policy, "rb") as handle:
            live_rows = tomllib.load(handle).get("repos") or {}
    except (OSError, tomllib.TOMLDecodeError, AttributeError):
        live_rows = {}
    checks.append((f"[#487] retriage.yml names a policy file that EXISTS and parses: "
                   f"{declared_policy}", isinstance(live_rows, dict) and bool(live_rows)))
    # ...and EVERY row in the live policy resolves to a boolean rather than raising, so a malformed
    # row in the file production actually reads is caught here and not at 07:07 on a Sunday.
    checks.append(("[#487] every live policy row resolves to a boolean opt-in (no malformed row)",
                   isinstance(live_rows, dict)
                   and all(isinstance(actions_bot_trust(live_policy, name), bool)
                           for name in live_rows)))

    with tempfile.TemporaryDirectory() as policy_dir:
        def policy(text, name):
            path = os.path.join(policy_dir, name)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
            return path

        grant = policy('[repos."o/r"]\nenabled = true\nallow_actions_bot_issues = true\n',
                       "grant.toml")
        deny = policy('[repos."o/r"]\nenabled = true\n', "deny.toml")
        bot_doc = {"author": {"login": ACTIONS_BOT_LOGIN}, "body": "",
                   "labels": [{"name": "stale:snapshot"}]}

        granted = FakeGh(start, known)
        code, seen = run_apply_argv(granted, stdin_doc=bot_doc, argv=apply_argv_for(grant))
        checks.append(("[#487] the workflow's OWN argv carries the opt-in into plan()",
                       (code, seen.get("allow_actions_bot_issues")) == (0, True)))
        checks.append(("[#487] ...and an own-workflow issue is ACTUALLY PROMOTED (permission=none, "
                       "author=github-actions[bot])",
                       (roles_of(granted.labels), "status:ready" in granted.labels,
                        "status:untriaged" in granted.labels)
                       == ({"role:impl"}, True, False)))

        denied = FakeGh(start, known)
        code, seen = run_apply_argv(denied, stdin_doc=bot_doc, argv=apply_argv_for(deny))
        checks.append(("[#487] a policy WITHOUT the opt-in refuses the same issue and writes "
                       "nothing",
                       (code, seen.get("allow_actions_bot_issues"), denied.calls,
                        denied.labels == set(start),
                        "untrusted-author" in seen.get("stdout", ""))
                       == (0, False, [], True, True)))
        # The maintainer's own issue is unaffected by either policy — the widening is additive.
        for label, path in (("granting", grant), ("denying", deny)):
            control = FakeGh(start, known)
            code, _seen = run_apply_argv(control, argv=apply_argv_for(path))
            checks.append((f"[#487] CONTROL: a maintainer-authored issue still promotes under a "
                           f"{label} policy", (code, "status:ready" in control.labels) == (0, True)))
        # An unreadable policy is a RED RUN, not a silent deny: main() must exit non-zero and write
        # nothing. A silent False here is indistinguishable from "not opted in" — the invisible
        # starvation #487 exists to close.
        unreadable = FakeGh(start, known)
        code, seen = run_apply_argv(
            unreadable, stdin_doc=bot_doc,
            argv=apply_argv_for(os.path.join(policy_dir, "does-not-exist.toml")))
        checks.append(("[#487] a policy production cannot READ fails the run, never denies quietly",
                       (code, unreadable.calls, unreadable.labels == set(start))
                       == (1, [], True)))

    # ---- the policy resolver itself: where that opt-in comes FROM (registry #487) ----
    with tempfile.TemporaryDirectory() as policy_dir:
        def policy(text, name):
            path = os.path.join(policy_dir, name)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
            return path

        grant = policy('[repos."o/r"]\nenabled = true\nallow_actions_bot_issues = true\n',
                       "grant.toml")
        chk("[#487] the policy row grants the opt-in", actions_bot_trust(grant, "o/r"), True)
        chk("[#487] an absent key defaults to DENY",
            actions_bot_trust(policy('[repos."o/r"]\nenabled = true\n', "deny.toml"), "o/r"), False)
        chk("[#487] an explicit false denies",
            actions_bot_trust(policy(
                '[repos."o/r"]\nallow_actions_bot_issues = false\n', "explicit.toml"), "o/r"),
            False)
        chk("[#487] a repo the policy does not mention is NOT opted in",
            actions_bot_trust(grant, "other/repo"), False)
        chk("[#487] no policy file requested means no widening", actions_bot_trust("", "o/r"), False)
        # `enabled` is deliberately NOT consulted: pausing DISPATCH must not silently switch TRIAGE
        # trust off as a side effect (that would be a second invisible-starvation shape).
        chk("[#487] the opt-in does not silently depend on `enabled`",
            actions_bot_trust(policy(
                '[repos."o/r"]\nenabled = false\nallow_actions_bot_issues = true\n', "off.toml"),
                "o/r"), True)
        for label, path in (
                ("a missing file", os.path.join(policy_dir, "nope.toml")),
                ("undecodable TOML", policy("[repos.\n", "broken.toml")),
                ("no [repos] table", policy("other = 1\n", "norows.toml")),
                ("an EMPTY [repos] table", policy("[repos]\n", "empty.toml")),
                ("a non-table row", policy('[repos]\n"o/r" = 7\n', "notable.toml")),
                ("a non-boolean flag",
                 policy('[repos."o/r"]\nallow_actions_bot_issues = "yes"\n', "nonbool.toml"))):
            try:
                actions_bot_trust(path, "o/r")
                raised = False
            except SweepError:
                raised = True
            chk(f"[#487] {label} RAISES rather than silently denying", raised)

    # -------------------------------------------------------------------------------------------
    # [issue #586 x PR #595 finding 3] BOTH DIRECTIONS OF THE SWEEP GO THROUGH THAT SAME APPLIER.
    # The promotion lane above is only half the sweep; a re-park/repair applied by any other path
    # would re-open exactly the #582 hole the applier closes, so the two remaining lanes are driven
    # through the REAL entrypoint too (a `--apply` that silently no-op'ed on them would leave the
    # stranded `status:ready` issues #586 is about untouched, and this check red).
    stranded = FakeGh({"status:ready", "role:docs", "area:dispatch"}, known)   # lost its priority
    code, _seen = run_apply_argv(stranded)
    checks.append(("[#586] the workflow-shaped ARGV RE-PARKS a stranded status:ready issue",
                   (code, "status:ready" in stranded.labels, "status:untriaged" in stranded.labels)
                   == (0, False, True)))
    checks.append(("[#586] the re-park ADDS + verifies the replacement role before any strip",
                   (stranded.calls[:1], roles_of(stranded.labels))
                   == ([(["role:impl"], [])], {"role:impl"})))

    # The REPAIR lane is the purest #582 shape: its whole mutation is writing back the `role:*` the
    # issue lost while KEEPING `status:ready`. When that label does not exist in the repo the add
    # fails, and the issue must be demoted rather than left ready-and-role-less (terminal).
    repair = plan(labelled("status:ready", "priority:P2", "area:dispatch"),
                  "owner", "app[bot]", "none")
    checks.append(("[#586] a lost role is planned as a repair carrying the intended role",
                   (repair["action"], repair["add"], repair["role"])
                   == ("repair", ["role:impl"], "impl")))
    gh = FakeGh({"status:ready", "priority:P2", "area:dispatch"}, known)
    outcome = apply_decision(set(gh.labels), repair, gh.edit, gh.view, gh.read_state)
    checks.append(("[#586] a repair restores the role and KEEPS the issue enumerable",
                   (outcome["ok"], roles_of(gh.labels), "status:ready" in gh.labels)
                   == (True, {"role:impl"}, True)))
    gh = FakeGh({"status:ready", "priority:P2", "area:dispatch"}, known - {"role:impl"})
    outcome = apply_decision(set(gh.labels), repair, gh.edit, gh.view, gh.read_state)
    checks.append(("[#586] a repair whose role label does not exist DEMOTES, never stays role-less",
                   (outcome["ok"], roles_of(gh.labels), "status:ready" in gh.labels,
                    "status:untriaged" in gh.labels) == (False, set(), False, True)))
    # The one lane that is BOTH: a role-less issue whose target role label the repo does not have.
    # triage() keeps it role-less (#582), so the sweep can only re-park it — and it must still do
    # so LOUDLY: the park lands (the issue leaves the frontier it cannot be dispatched from) while
    # the step turns red, because a repo missing its own routed role label is a config defect.
    roleless_known = known - {ROLE_LABEL}
    repark = plan(labelled("status:ready", "priority:P2", "area:dispatch"), "owner", "app[bot]",
                  "none", known_labels=roleless_known)
    checks.append(("[#582 x #586] a missing role label downgrades the repair to a re-park",
                   (repark["action"], repark["role"]) == ("repark", None)))
    gh = FakeGh({"status:ready", "priority:P2", "area:dispatch"}, roleless_known)
    outcome = apply_decision(set(gh.labels), repark, gh.edit, gh.view, gh.read_state)
    checks.append(("[#582 x #586] that re-park still LANDS, and still fails the step LOUDLY",
                   (outcome["ok"], "status:ready" in gh.labels, "status:untriaged" in gh.labels,
                    roles_of(gh.labels)) == (False, False, True, set())))

    # -------------------------------------------------------------------------------------------
    # [#605 review ROUND 2, finding 1(ii)] THE REPAIR LANE, THROUGH THE REAL ENTRYPOINT. Every
    # repair check above calls plan()/apply_decision() DIRECTLY — so removing `"repair"` from
    # WRITING_ACTIONS made `_apply_cli` `return 0` WITHOUT WRITING and the entire suite stayed
    # green, silently stranding exactly the role-less `status:ready` issues #586 exists to rescue.
    # (The comment above claimed "the two remaining lanes are driven through the REAL entrypoint";
    # only repark was. It is true as of this check.)
    repaired = FakeGh({"status:ready", "priority:P2", "area:dispatch"}, known)
    code, _seen = run_apply_argv(repaired)
    checks.append(("[#605 r2 f1] the workflow-shaped ARGV REPAIRS a role-less status:ready issue",
                   (code, roles_of(repaired.labels), "status:ready" in repaired.labels,
                    repaired.calls[:1]) == (0, {"role:impl"}, True, [(["role:impl"], [])])))

    # [#605 review ROUND 2, finding 3] THE ORCHESTRATION HOLD IS READ LIVE, NOT FROM THE SNAPSHOT.
    # `_apply_cli` refreshed only `labels`; the `body` that decides the hold still came from the
    # board snapshot taken BEFORE pagination, so a `<!-- orchestration:hold -->` added between the
    # list read and the apply was ignored and the issue was promoted or repaired anyway — a
    # fail-OPEN race on a deliberately load-bearing park, against a docstring claiming the opposite.
    # The `--apply` fixture pinned the permissive shape (`"body": ""`), so nothing exercised it.
    # Three rows, because only the SET pins the source of the body rather than its value.
    held = FakeGh(start, known)
    code, seen = run_apply_argv(held, live_body=f"prose\n{HOLD_MARKER}\n")
    checks.append(("[#605 r2 f3] a hold added AFTER the board snapshot stops the write (no mutation)",
                   (code, held.calls, held.labels == set(start), seen.get("body"))
                   == (0, [], True, f"prose\n{HOLD_MARKER}\n")))
    lifted = FakeGh(start, known)
    code, _seen = run_apply_argv(
        lifted, stdin_doc={"author": {"login": "owner"}, "body": f"stale\n{HOLD_MARKER}\n",
                           "labels": [{"name": "stale:snapshot"}]}, live_body="")
    checks.append(("[#605 r2 f3] ...and a hold LIFTED since the snapshot no longer blocks the write",
                   (code, roles_of(lifted.labels), "status:ready" in lifted.labels)
                   == (0, {"role:impl"}, True)))
    unreadable = FakeGh(start, known)
    code, _seen = run_apply_argv(unreadable, body_error="HTTP 503")
    checks.append(("[#605 r2 f3] an UNREADABLE live body REFUSES to act; it never assumes 'no hold'",
                   (code, unreadable.calls, unreadable.labels == set(start)) == (1, [], True)))

    # -------------------------------------------------------------------------------------------
    # [#605 review ROUND 4, MAJOR 1] THE PRODUCTION READ ITSELF. The rows above stub
    # `triage._gh_read`, so `read_live_body`'s own argv construction, JSON parse and validation are
    # under test rather than replaced. These two rows are what make the round-4 survivors die:
    # `read_live_body() -> return ""` never reaches the read layer at all, and a read pointed at
    # issue `1` (or at the wrong fields) records different argv.
    probe = FakeGh(start, known)
    code, seen = run_apply_argv(probe, live_body=f"prose\n{HOLD_MARKER}\n")
    body_reads = [args for args in seen.get("reads", []) if args[:2] == ["issue", "view"]]
    checks.append(("[#605 r4 M1] the live body read really goes through the shared read layer, "
                   "for THIS issue, asking for body+state+issueType",
                   (code, probe.calls, body_reads)
                   == (0, [], [["issue", "view", "7", "-R", "o/r",
                                "--json", "body,state,issueType"]])))
    checks.append(("[#605 r4 M1] ...and its RESULT is what planning saw (not a constant)",
                   seen.get("body") == f"prose\n{HOLD_MARKER}\n"))

    # [#605 review ROUND 4, MAJOR 2] A MALFORMED *SUCCESSFUL* READ FAILS CLOSED. Measured on the
    # round-3 head: `{}` (key missing), `{"body": 123}` and `{"data": {"body": ...}}` each returned
    # `""` from `read_live_body`, so "no orchestration hold" was inferred from a document that said
    # nothing about the body at all and the write proceeded. Every shape below must now refuse; the
    # ONE tolerated shape (`"body": null`, how GitHub renders an empty body) is pinned separately so
    # the tolerance is a decision rather than a leftover.
    # The three `[#598]` rows at the END ride the SAME posture for the TYPE half: a document that
    # says nothing usable about the type cannot be read as "untyped", because that silently
    # re-derives the role from a value this run never observed. Each of those three carries a
    # WELL-FORMED body and state, so only the type half can refuse it — that is what stops them
    # passing vacuously for the body/state reason the rows above them test. The body/state rows in
    # turn gain a valid `issueType` so THEY keep failing for their own original reason.
    for shape_name, shape in (
            ("key MISSING", '{"state": "OPEN", "issueType": null}'),
            ("non-string body", '{"body": 123, "state": "OPEN", "issueType": null}'),
            ("schema drift", '{"data": {"body": "' + HOLD_MARKER
             + '"}, "state": "OPEN", "issueType": null}'),
            ("not an object", '["' + HOLD_MARKER + '"]'),
            ("not JSON at all", 'Not Found'),
            ("state MISSING", '{"body": "", "issueType": null}'),
            ("alien state", '{"body": "", "state": "MERGED", "issueType": null}'),
            ("[#598] issueType key MISSING", '{"body": "", "state": "OPEN"}'),
            ("[#598] scalar issueType", '{"body": "", "state": "OPEN", "issueType": "Bug"}'),
            ("[#598] non-string issueType.name",
             '{"body": "", "state": "OPEN", "issueType": {"name": 7}}'),
            ("[#598] issueType object with NO name",
             '{"body": "", "state": "OPEN", "issueType": {"id": 3}}')):
        malformed = FakeGh(start, known)
        code, seen = run_apply_argv(malformed, live_document=shape)
        checks.append((f"[#605 r4 M2] a malformed live read ({shape_name}) refuses to act, "
                       "it never reads as 'no hold'",
                       (code, malformed.calls, malformed.labels == set(start))
                       == (1, [], True)))
    nulled = FakeGh(start, known)
    code, seen = run_apply_argv(
        nulled, live_document='{"body": null, "state": "OPEN", "issueType": null}')
    checks.append(("[#605 r4 M2] an explicit JSON null body IS an empty body (the one tolerance)",
                   (code, seen.get("body"), roles_of(nulled.labels),
                    "status:ready" in nulled.labels) == (0, "", {"role:impl"}, True)))
    # [#598] the mirror tolerance on the type half: `issueType: null` is GitHub's answer for an
    # issue with NO type, so it must be accepted and read as untyped — not refused, and not
    # rewritten into a type. Pinned separately so the tolerance stays a decision.
    untyped = FakeGh(start, known)
    code, seen = run_apply_argv(
        untyped, live_document='{"body": "", "state": "OPEN", "issueType": null}')
    checks.append(("[#598] a null issueType IS 'untyped' (the mirror tolerance), and it plans",
                   (code, seen.get("type"), roles_of(untyped.labels)) == (0, "", {"role:impl"})))
    typed = FakeGh(start, known)
    code, seen = run_apply_argv(typed, live_type="Bug")
    checks.append(("[#598] a TYPED issue's live type name reaches plan() verbatim (display case, "
                   "un-normalized — the normalizer is triage.py's single definition)",
                   (code, seen.get("type")) == (0, "Bug")))
    # [#598] HEADLINE, end to end through main() -> _apply_cli -> read -> plan -> apply_decision:
    # the live type CHANGES THE LABEL THIS SWEEP WRITES. `area:docs` is the fixture that can tell
    # the lanes apart — its area default (`docs`) differs from `ROLE_BY_TYPE["bug"]` (`impl`) — and
    # `area:dispatch` cannot, because SEC_KEYWORDS forces the trust-plane role whatever the type is.
    # Both directions on the SAME start labels: with the pre-#598 hard-coded `"task"` the second row
    # is what BOTH rows produced, so a revert turns the first RED, and a stub that ignores the read
    # turns the second RED. This is also the row that pins the two classifiers into agreement —
    # triage-issue.yml derives `role:docs` for exactly this untyped issue.
    docs_start = {"priority:P2", "area:docs", "status:untriaged"}
    docs_untyped = FakeGh(docs_start, known)
    code, seen = run_apply_argv(docs_untyped)
    checks.append(("[#598] an UNTYPED area:docs issue is promoted with the AREA-derived role:docs "
                   "(pre-#598 this lane hard-coded `task` and wrote role:impl)",
                   (code, roles_of(docs_untyped.labels), "status:ready" in docs_untyped.labels)
                   == (0, {"role:docs"}, True)))
    docs_typed = FakeGh(docs_start, known)
    code, seen = run_apply_argv(docs_typed, live_type="Bug")
    checks.append(("[#598] ...while a MAPPED live type still wins over the area default, so the "
                   "area map widened the derivation rather than replacing it",
                   (code, roles_of(docs_typed.labels), "status:ready" in docs_typed.labels)
                   == (0, {"role:impl"}, True)))

    # -------------------------------------------------------------------------------------------
    # [registry #510] EVERY SUGGESTED LABEL IS VALIDATED AGAINST THE TARGET REPO'S LIVE LABEL SET.
    # #582 pinned the ROLE family only; the derived `priority:P4` floor and the `status:*` lane
    # attestations still went to the API unchecked, and GitHub fails the WHOLE `gh issue edit` on
    # one unknown `--add-label`. So a single missing taxonomy label cost the entire mutation, exited
    # the applier 1, and — nothing about the issue having changed — re-tripped on every following
    # tick (run 29883925637: `'role:soundness' not found`, cleared only by a manual relabel).
    #
    # The unit rows below pin the validator's contract; the end-to-end rows after them drive the
    # REAL entrypoint (main -> _apply_cli -> validate_labels -> drop_is_safe -> apply_decision)
    # against a fake GitHub that raises on an unknown add exactly as the API does.
    # -------------------------------------------------------------------------------------------
    _known510 = {"role:impl", "role:docs", "status:ready", "status:untriaged", "priority:P2"}
    _promote510 = {"action": "promote", "add": ["priority:P4", "role:impl", "status:ready"],
                   "remove": ["role:docs", "status:untriaged"], "role": "impl"}
    chk("[#510] an unknown suggested label is DROPPED and every valid one is KEPT",
        validate_labels(_promote510, _known510),
        ({"action": "promote", "add": ["role:impl", "status:ready"],
          "remove": ["role:docs", "status:untriaged"], "role": "impl"}, ["priority:P4"]))
    # NEGATIVE CONTROL, and the row that keeps the one above from being satisfied by a validator
    # that simply drops things: a fully-known write must pass through byte-identical, with NO
    # reported drop. Without it, `return {"add": [], ...}, sorted(add)` would pass the whole block.
    chk("[#510] NEGATIVE CONTROL: a fully-known write passes through UNCHANGED, dropping nothing",
        validate_labels({"action": "promote", "add": ["role:impl", "status:ready"],
                         "remove": ["status:untriaged"], "role": "impl"}, _known510),
        ({"action": "promote", "add": ["role:impl", "status:ready"],
          "remove": ["status:untriaged"], "role": "impl"}, []))
    # The role half is #582's rule read from the other side. `apply_triage` writes the target
    # INDEPENDENTLY of `add` (its add-before-strip phase fires whenever the target is not already on
    # the issue), so an unknown role must also clear `role` — and clearing it MUST withdraw every
    # `role:*` strip, or the sweep would strip the incumbent for a replacement it refuses to write.
    chk("[#510] an unknown ROLE clears the role AND withdraws every role:* strip (never strip an "
        "incumbent for a replacement this run will not write)",
        validate_labels({"action": "promote", "add": ["role:ci", "status:ready"],
                         "remove": ["role:docs", "status:untriaged"], "role": "ci"}, _known510),
        ({"action": "promote", "add": ["status:ready"], "remove": ["status:untriaged"],
          "role": None}, ["role:ci"]))
    chk("[#510] the role is validated even when it is NOT in `add` (apply_triage writes it anyway)",
        validate_labels({"action": "repair", "add": [], "remove": [], "role": "ci"}, _known510),
        ({"action": "repair", "add": [], "remove": [], "role": None}, ["role:ci"]))
    chk("[#510] no label set means no validation (the documented `None` contract)",
        validate_labels(_promote510, None), (_promote510, []))
    # The one thing the wrapper owns since #1490: WHICH decisions are writes. Carrying labels on the
    # skip is what makes the gate OBSERVABLE — measured, a `{"action": "skip", "reason": "epic"}`
    # fixture has nothing to reduce, so removing the gate returned the identical value and the row
    # could not fail. Fail-closed: an unknown or future action is a NO-WRITE, never something the
    # reducer quietly turns into a smaller write.
    chk("[#510] a non-writing decision is never touched, even one carrying labels",
        validate_labels({"action": "skip", "reason": "epic", "add": ["role:soundness"],
                         "remove": [], "role": "soundness"}, set()),
        ({"action": "skip", "reason": "epic", "add": ["role:soundness"], "remove": [],
          "role": "soundness"}, []))
    # [#1490] ...and the reduction itself is the SHARED object, not a second spelling of it. The
    # literal is written out here on purpose: comparing the constant against itself cannot fail.
    chk("[#1490] the lane labels and the unsafe-drop reason are triage.py's, by identity — the "
        "reduction has ONE definition and this module points at it (AGENTS.md: #958)",
        (LANE_LABELS is static_triage.LANE_LABELS,
         UNSAFE_DROP_REASON is static_triage.UNSAFE_DROP_REASON,
         UNSAFE_DROP_REASON, sorted(LANE_LABELS)),
        (True, True, "unknown-label-unsafe-drop", ["status:ready", "status:untriaged"]))

    # drop_is_safe: the two named invariants that decide whether the REDUCED write may be applied.
    chk("[#510] LANE INVARIANT: a reduction that leaves the issue on NEITHER lane is refused "
        "(it would be invisible to the readiness engine AND to this sweep's own board queries)",
        drop_is_safe({"action": "promote", "add": [], "remove": ["status:untriaged"]},
                     {"status:untriaged", "role:impl", "area:dispatch", "priority:P2"}, "", known),
        False)
    chk("[#510] PREMISE INVARIANT: a promotion whose readiness DEPENDED on the dropped priority is "
        "refused — applying it oscillates promote<->repark, two writes per two ticks, forever",
        drop_is_safe({"action": "promote", "add": ["role:impl", "status:ready"],
                      "remove": ["role:docs", "status:untriaged"]},
                     {"status:untriaged", "role:docs", "area:dispatch"}, "", known),
        False)
    chk("[#510] ...and the SAME reduction IS applied when the post-state still classifies READY "
        "without the dropped label (the invariant refuses a write, not every write)",
        drop_is_safe({"action": "promote", "add": ["role:impl", "status:ready"],
                      "remove": ["role:docs", "status:untriaged"]},
                     {"status:untriaged", "role:docs", "area:dispatch", "priority:P2"}, "", known),
        True)
    chk("[#510] a re-park attests nothing, so it needs only to LAND on the park lane",
        (drop_is_safe({"action": "repark", "add": ["status:untriaged"],
                       "remove": ["status:ready"]},
                      {"status:ready", "role:impl", "area:dispatch"}, "", known),
         drop_is_safe({"action": "repark", "add": [], "remove": ["status:ready"]},
                      {"status:ready", "role:impl", "area:dispatch"}, "", known)),
        (True, False))

    # THE LIVE FAILURE, END TO END. `known` (the fixture label set retriage.yml's own argv carries)
    # has no `priority:P4`, so this unprioritised issue's promotion suggests a label the repo does
    # not have — the #487-class shape. MUTATION TRIPWIRE: delete the `validate_labels` call from
    # `_apply_cli` and FakeGh raises on that add exactly as the API does, so the applier reports
    # ok=False and this row goes red on `code == 0` AND on `calls == []`.
    unprioritised_start = {"area:dispatch", "role:docs", "status:untriaged"}
    unprioritised = FakeGh(set(unprioritised_start), known)
    code, seen = run_apply_argv(unprioritised)
    checks.append(("[#510] an unknown suggested label is dropped with a loud per-issue log line, "
                   "the tick writes NOTHING, and the run stays GREEN (it used to exit 1 forever)",
                   (code, unprioritised.calls, unprioritised.labels == unprioritised_start,
                    "classifier suggested unknown label priority:P4 — dropped"
                    in seen.get("stdout", ""),
                    UNSAFE_DROP_REASON in seen.get("stdout", ""))
                   == (0, [], True, True, True)))
    # ...and the acceptance criterion the live failure is about: RE-RUNNING is a no-op with the same
    # log, not a second red run. The board is unchanged, so this is exactly what the next scheduled
    # tick does to the same issue.
    code, seen = run_apply_argv(unprioritised)
    checks.append(("[#510] re-running on the SAME issue is a no-op-with-log — the #487-class "
                   "failure cannot recur",
                   (code, unprioritised.calls, unprioritised.labels == unprioritised_start,
                    "classifier suggested unknown label priority:P4 — dropped"
                    in seen.get("stdout", "")) == (0, [], True, True)))
    # POSITIVE CONTROL: the same issue with a priority the repo DOES have still promotes in full,
    # writing every valid label. Without it, `return skip` in `_apply_cli` would satisfy both rows
    # above while disabling the entire sweep.
    prioritised = FakeGh(unprioritised_start | {"priority:P2"}, known)
    code, seen = run_apply_argv(prioritised)
    checks.append(("[#510] POSITIVE CONTROL: a fully-known promotion still applies EVERY valid "
                   "label, with no drop reported",
                   (code, roles_of(prioritised.labels), "status:ready" in prioritised.labels,
                    "status:untriaged" in prioritised.labels,
                    "classifier suggested unknown label" in seen.get("stdout", ""))
                   == (0, {"role:impl"}, True, False, False)))

    # [#605 review ROUND 4, MINOR] open/closed is no longer a stale input: it rides the same read.
    closed = FakeGh(start, known)
    code, seen = run_apply_argv(closed, live_state="CLOSED")
    checks.append(("[#605 r4] an issue CLOSED since the board snapshot is skipped, never mutated",
                   (code, closed.calls, closed.labels == set(start),
                    "closed-since-snapshot" in seen.get("stdout", ""))
                   == (0, [], True, True)))

    # [#605 review ROUND 4, MAJOR 3] THE LIVE LANE-MEMBERSHIP REFUSAL. Deleting
    # `if not untriaged and "status:ready" not in labels: return skip` from plan() left the whole
    # suite green. In production the board selects an issue that carries a lane label and the label
    # can be REMOVED before the apply's live read; without that guard the repair lane happily writes
    # `status:ready` back, overriding a concurrent removal nobody asked it to undo. Stdin still says
    # `status:ready`; the LIVE labels carry neither lane.
    departed = FakeGh({"priority:P2", "area:dispatch"}, known)
    code, seen = run_apply_argv(
        departed, stdin_doc={"author": {"login": "owner"}, "body": "",
                             "labels": [{"name": "status:ready"}, {"name": "priority:P2"}]})
    checks.append(("[#605 r4 M3] an issue that left BOTH lanes before the live read is not "
                   "retriageable, and nothing is written",
                   (code, departed.calls, departed.labels == {"priority:P2", "area:dispatch"},
                    "not-retriageable" in seen.get("stdout", ""))
                   == (0, [], True, True)))
    checks.append(("[#605 r4 M3] ...planned against the LIVE labels, which carry neither lane",
                   ({"status:ready", "status:untriaged"} & set(seen.get("labels") or []), )
                   == (set(), )))
    # The same predicate, directly: the guard's own truth table, so a deletion is caught even if the
    # entrypoint row above were ever weakened.
    checks.append(("[#605 r4 M3] plan() refuses a lane-less issue and admits each lane",
                   [plan(labelled(*names, author="owner"), "owner", "app[bot]", "write",
                         known_labels=known)["action"]
                    for names in (("priority:P2", "area:dispatch", "role:impl"),
                                  ("status:ready", "priority:P2", "area:dispatch"),
                                  ("status:untriaged", "priority:P2", "area:dispatch"))]
                   == ["skip", "repair", "promote"]))

    # -------------------------------------------------------------------------------------------
    # [PR #595 findings 3 + 6] STATIC WORKFLOW CONTRACT. The sweep must mutate ONLY through the
    # fail-closed applier, route every READ through the shared bounded-retry layer (gh_retry —
    # mutations stay single-attempt/fail-loud per its hard scope rule), and never short-circuit out
    # of the loop before the post-condition. Comment lines are stripped first so these assertions
    # read the executable text only.
    body = "\n".join(line for line in open(workflow, encoding="utf-8").read().splitlines()
                     if not line.strip().startswith("#"))
    checks.append(("[#595 f3] the sweep mutates only via `retriage.py --apply`",
                   "scripts/retriage.py --apply" in body.replace("\\\n", " ")))
    checks.append(("[#595 f3] no raw `gh issue edit` label mutation remains in the workflow",
                   "gh issue edit" not in body))
    import re
    checks.append(("[#595 f6] every workflow `gh` READ goes through the gh_retry wrapper",
                   not re.findall(r"(?<![\w./-])gh\s+(?:api|issue|label|pr|run|search)\b", body)))
    checks.append(("[#595 f6] the wrapper is the shared layer, not a hand-rolled retry loop",
                   "scripts/gh_retry.py read" in body))
    loop = re.search(r"while IFS=.*?done <", body, re.S)
    checks.append(("[#595 f3] the sweep loop cannot short-circuit past the post-read",
                   loop is not None and not re.search(r"\bexit\b", loop.group(0))))
    checks.append(("[#595 f3] a failed apply still fails the STEP after the sweep completes",
                   loop is not None and re.search(r"exit\s+1", body[loop.end():]) is not None))
    # [#586] ...and the board the sweep feeds that applier is BOTH lanes, bounded by the fail-closed
    # snapshot. A workflow that lists only `status:untriaged` re-opens the label-lost half of #178:
    # nothing else recovers a `status:ready` issue that dropped a required label. The step's `name:`
    # is excluded so a DESCRIPTION of the ready lane can never stand in for querying it.
    # (`body` is ALREADY comment-stripped above, so a prose mention cannot satisfy these; #605
    # review finding 3 read this as comment-inclusive and is answered in the PR thread with the
    # mutation. The `- name:` strip is what keeps the step TITLE from standing in for the query,
    # and the assertion is now on the LOOP itself rather than on two loose substrings.)
    executable = "\n".join(line for line in body.splitlines()
                           if not line.strip().startswith("- name:"))
    checks.append(("[#586] the sweep board is QUERIED from BOTH the untriaged AND ready lanes",
                   re.search(r"for\s+label\s+in\s+status:untriaged\s+status:ready\s*;",
                             executable) is not None))
    # [#605 review finding 2] the fetch itself must be bounded, and must PROVE it read the whole
    # board: `--paginate --slurp` pulled every page before any ceiling applied, and a board missing
    # its last page was indistinguishable from a short one.
    #
    # THESE THREE ARE STATIC SHAPE CHECKS ONLY, and #605 review round 2 was right that on their own
    # they are vacuous: another `exit 1` later in the file satisfies the ceiling check, `if false`
    # or an enormous `max_pages` satisfies it too, and `got=0` keeps the `-lt 100` substring while
    # truncating the board after page 1. They are kept as cheap drift detection; the guards they
    # NAME are covered by the EXECUTED step body further down ("[#605 r2 f2] ...").
    checks.append(("[#605 f2] the board fetch is page-bounded — no unbounded --paginate remains",
                   "--paginate" not in executable and "max_pages=" in executable))
    checks.append(("[#605 f2] a board too large for that ceiling fails the step CLOSED",
                   "could not read completely" in executable
                   and re.search(r"exit\s+1", executable) is not None))
    checks.append(("[#605 f2] completeness is proved by reading until a page comes back short",
                   re.search(r"-lt\s+100", executable) is not None))
    snapshot_argv = next((argv for argv in argvs if "--snapshot" in argv), [])
    cap = (snapshot_argv[snapshot_argv.index("--cap") + 1] if "--cap" in snapshot_argv else "")
    checks.append(("[#586] the board goes through the fail-closed, per-run-capped snapshot",
                   bool(snapshot_argv) and cap.isdigit() and 0 < int(cap) <= SWEEP_CEILING))
    # [#605 review finding 1] and that cap must come with a ROTATION, or its window starves the
    # rest of the board forever (no-op skips never move `updated_at`, so a fixed oldest-first
    # window re-selects the same head on every run).
    checks.append(("[#605 f1] the capped window ROTATES per run (never a fixed head)",
                   "--rotation" in snapshot_argv
                   and "GITHUB_RUN_NUMBER" in executable))

    # -------------------------------------------------------------------------------------------
    # [#605 review ROUND 2, finding 1(i)] --rotation IS FORWARDED — proved through main().
    # Deleting `rotation=args.rotation` from main()'s snapshot() call left every direct rotation
    # check AND every workflow-text check above green while production silently reverted to
    # rotation=0, reinstating the head-of-line BLOCKER. So the workflow's OWN `--snapshot` argv is
    # replayed through the real entrypoint for two different run numbers: the windows must differ
    # from each other and must equal what snapshot() returns for that rotation.
    # -------------------------------------------------------------------------------------------
    def run_snapshot_argv(pages, run_number):
        argv = next((candidate for candidate in static_triage.workflow_argvs(
            workflow, "retriage.py",
            {"GITHUB_RUN_NUMBER": str(run_number), "REPO": "o/r", "tmp": "/nonexistent"})
            if "--snapshot" in candidate), None)
        if argv is None:
            # Fail CLOSED and legibly: a workflow that no longer invokes `--snapshot` at all (a step
            # body replaced by `true`) must turn this check red, not raise StopIteration.
            raise SweepError("retriage.yml no longer invokes `retriage.py --snapshot` — refusing")
        saved = (sys.stdin, sys.stdout, sys.stderr)
        sys.stdin, sys.stdout, sys.stderr = (io.StringIO(json.dumps(pages)), io.StringIO(),
                                             io.StringIO())
        try:
            code = main(argv)
            emitted = [json.loads(line) for line in sys.stdout.getvalue().splitlines() if line]
            noise = sys.stderr.getvalue()
        finally:
            sys.stdin, sys.stdout, sys.stderr = saved
        return code, argv, [issue["number"] for issue in emitted], noise

    rot_board = [[api(number, "status:untriaged") for number in range(1, 201)]]
    code_a, rot_argv, window_a, warning = run_snapshot_argv(rot_board, 0)
    code_b, _argv, window_b, _noise = run_snapshot_argv(rot_board, 1)
    rot_cap = int(rot_argv[rot_argv.index("--cap") + 1])
    checks.append(("[#605 r2 f1] the workflow's own --snapshot argv is replayable (no shell tokens)",
                   (code_a, code_b, [token for token in rot_argv if token in {"<", ">"}])
                   == (0, 0, [])))
    checks.append((f"[#605 r2 f1] main() FORWARDS --rotation: run 0 and run 1 walk different "
                   f"windows of {rot_cap}",
                   (len(window_a), len(window_b), window_a != window_b) == (rot_cap, rot_cap, True)))
    checks.append(("[#605 r2 f1] ...and each replayed window equals snapshot(rotation=n) exactly",
                   (window_a, window_b)
                   == (sorted(issue["number"] for issue in
                              snapshot(rot_board, cap=rot_cap, rotation=0)[0]),
                       sorted(issue["number"] for issue in
                              snapshot(rot_board, cap=rot_cap, rotation=1)[0]))))
    checks.append(("[#605 r2 f1] the cap warning states the bound's UNCHANGED-BOARD condition",
                   "UNCHANGED board" in warning and "not a per-issue deadline" in warning))

    # -------------------------------------------------------------------------------------------
    # [#605 review ROUND 2, finding 2] THE SHELL PAGINATION GUARDS ARE EXECUTED. The step body is
    # extracted from the workflow and run against a stubbed `gh_retry` (canned board pages) and a
    # stubbed applier, so the REQUEST ceiling, the page-shape guard and the short-page completeness
    # break are asserted by OUTCOME. Every row below dies on the mutations round 2 named: deleting
    # the ceiling's own `exit 1`, `if false`, an enormous `max_pages`, `got=0`, and reverting the
    # page-type guard to the bare `jq 'length'` that scored 2 on `{"message":"Not Found"}`.
    # -------------------------------------------------------------------------------------------
    import subprocess
    import tempfile
    sweep_script = workflow_step_script(open(workflow, encoding="utf-8").read(), "sweep")
    GH_RETRY_STUB = '''import json, os, sys
args = sys.argv[1:]
if not args or args[0] != "read":
    sys.exit(f"stub gh_retry refuses a non-read call: {args}")
rest = args[1:]
if rest[:1] == ["label"]:
    print("role:impl,role:docs,status:ready,status:untriaged,priority:P2,area:dispatch")
    sys.exit(0)
if rest[:1] != ["api"]:
    sys.exit(f"stub gh_retry saw an unexpected call: {args}")
target = rest[1]
with open(os.environ["STUB_TARGET_LOG"], "a", encoding="utf-8") as handle:
    handle.write(target + "\\n")
if "/collaborators/" in target:
    print("write")
    sys.exit(0)
if os.environ["STUB_PAYLOAD"] == "object":
    print(json.dumps({"message": "Not Found"}))
    sys.exit(0)
# A lane-LESS board query is SERVED, not refused: the stub must not be the thing that catches an
# unfiltered sweep, or the "[#487] the sweep board is EXACTLY the two lane queries" row below would
# be asserting the stub's strictness instead of the workflow's. It answers with a short page so the
# page accounting the #605 rows check is undisturbed and that row is the ONLY thing that goes red.
label = target.split("labels=")[1].split("&")[0] if "labels=" in target else ""
page = int(target.split("&page=")[1])   # NOT "page=" — `per_page=100` matches that first
base = 1000000 if label.endswith("ready") else (2000000 if not label else 0)
count = 7 if not label else (100 if page <= int(os.environ["STUB_FULL_PAGES"]) else 7)
print(json.dumps([{"number": base + page * 1000 + index, "user": {"login": "owner"},
                   "body": "", "labels": [{"name": label}],
                   "updated_at": "2026-07-01T00:00:00Z"} for index in range(count)]))
'''
    # STUB_FAIL_APPLIES (registry #510) names the 1-based applier invocations that must FAIL, so the
    # sweep loop's error isolation is asserted by OUTCOME: the log line is written BEFORE the exit,
    # so a failing issue is still counted and "did the loop keep going" is answerable.
    RETRIAGE_STUB = '''import os, subprocess, sys
if "--snapshot" in sys.argv:
    sys.exit(subprocess.run([sys.executable, os.environ["STUB_REAL_RETRIAGE"], *sys.argv[1:]],
                            check=False).returncode)
log = os.environ["STUB_APPLY_LOG"]
with open(log, "a", encoding="utf-8") as handle:
    handle.write("apply\\n")
with open(log, encoding="utf-8") as handle:
    nth = sum(1 for line in handle if line.strip())
if str(nth) in {token for token in os.environ.get("STUB_FAIL_APPLIES", "").split(",") if token}:
    print("simulated gh label write failure", file=sys.stderr)
    sys.exit(1)
'''

    def run_sweep_step(full_pages=2, payload="array", run_number=3, fail_applies=""):
        """Execute the REAL sweep step body. Returns (exit code, log text, page-file names,
        window line count, applier invocation count, API targets the step actually requested)."""
        with tempfile.TemporaryDirectory() as directory:
            root = os.path.join(directory, "repo")
            os.makedirs(os.path.join(root, "scripts"))
            for name, source in (("gh_retry.py", GH_RETRY_STUB), ("retriage.py", RETRIAGE_STUB)):
                with open(os.path.join(root, "scripts", name), "w", encoding="utf-8") as handle:
                    handle.write(source)
            temp = os.path.join(directory, "runner-temp")
            os.makedirs(temp)
            log = os.path.join(directory, "apply.log")
            targets_path = os.path.join(directory, "targets.log")
            environment = dict(os.environ, RUNNER_TEMP=temp, REPO="o/r",
                               MAINTAINER_LOGIN="owner", APP_BOT_LOGIN="app[bot]",
                               GITHUB_RUN_NUMBER=str(run_number),
                               STUB_FULL_PAGES=str(full_pages), STUB_PAYLOAD=payload,
                               STUB_APPLY_LOG=log, STUB_TARGET_LOG=targets_path,
                               STUB_FAIL_APPLIES=fail_applies,
                               STUB_REAL_RETRIAGE=os.path.abspath(__file__))
            completed = subprocess.run(["bash", "-c", sweep_script], cwd=root, env=environment,
                                       capture_output=True, text=True, timeout=600, check=False)
            sweep_temp = os.path.join(temp, "retriage")
            pages = sorted(name for name in (os.listdir(sweep_temp)
                                             if os.path.isdir(sweep_temp) else [])
                           if name.startswith("page-"))
            window_path = os.path.join(sweep_temp, "issues.jsonl")
            window = 0
            if os.path.isfile(window_path):
                with open(window_path, encoding="utf-8") as handle:
                    window = sum(1 for line in handle if line.strip())
            applies = 0
            if os.path.isfile(log):
                with open(log, encoding="utf-8") as handle:
                    applies = sum(1 for line in handle if line.strip())
            targets = []
            if os.path.isfile(targets_path):
                with open(targets_path, encoding="utf-8") as handle:
                    targets = [line.strip() for line in handle if line.strip()]
            return (completed.returncode, completed.stdout + completed.stderr, pages, window,
                    applies, targets)

    # 2 full pages + a short third page per lane = 207 issues per lane, 414 in all, cap 80.
    # `got=0` (the truncation mutation) fetches ONE page per lane and applies a truncated board:
    # the page-file list and the reported board total both change, so this row dies on it.
    code, log, pages, window, applies, targets = run_sweep_step(full_pages=2)
    checks.append(("[#605 r2 f2] the step reads until a SHORT page arrives, on BOTH lanes",
                   (code, pages) == (0, ["page-ready-1.json", "page-ready-2.json",
                                         "page-ready-3.json", "page-untriaged-1.json",
                                         "page-untriaged-2.json", "page-untriaged-3.json"])))
    checks.append(("[#605 r2 f2] ...and the COMPLETE board reaches the snapshot (414 = 2x(200+7))",
                   "414 board issue(s)" in log))
    checks.append(("[#605 r2 f2] ...and the capped window is what the applier is actually fed",
                   (window, applies) == (80, 80)))
    # [registry #487] BOARD MEMBERSHIP — the honest scope of the opt-in, asserted by EXECUTION.
    # The rows above prove the widening WORKS on a document handed to plan(); this one proves WHICH
    # documents production can ever hand it. Every board request the real step body issues carries
    # a `labels=` filter, and the filter values are exactly the two lanes — so an issue carrying
    # NEITHER lane label is never fetched, never snapshotted, never passed to `--apply`, and
    # `plan()` (hence the #487 trust gate) is never reached for it. That is why this unit is inert
    # on this repo today rather than "covering" the alert-responder class, and it is what a reader
    # must not be allowed to forget. Dies on: dropping `labels=$label` from the board query
    # (an unfiltered board would sweep every open issue), and on adding/renaming/removing a lane.
    board = [target for target in targets if "/issues?" in target]
    lanes = {target.split("labels=")[1].split("&")[0] for target in board if "labels=" in target}
    checks.append(("[#487] the sweep board is EXACTLY the two lane queries — an issue on no lane "
                   "is never fetched, so plan() and its trust gate are never reached for it",
                   (bool(board), all("labels=" in target for target in board), lanes)
                   == (True, True, {"status:untriaged", "status:ready"})))
    # The REQUEST ceiling: 25 full pages against max_pages=20. Deleting the ceiling's own `exit 1`,
    # or `if false`, or a raised max_pages all let the loop run to the short page and exit 0.
    code, log, pages, _window, applies, _targets = run_sweep_step(full_pages=25)
    checks.append(("[#605 r2 f2] a board past the REQUEST ceiling fails the step CLOSED at page 20",
                   (code != 0, "larger than 20 pages" in log,
                    len([name for name in pages if name.startswith("page-untriaged-")]), applies)
                   == (True, True, 20, 0)))
    # The page-SHAPE guard: `jq 'length'` alone returns 2 for {"message": "Not Found"}, which is
    # `-lt 100`, so an error document used to break the loop and be swept as a complete board.
    code, log, _pages, _window, applies, _targets = run_sweep_step(payload="object")
    checks.append(("[#605 r2 f2] a non-array page payload fails the step CLOSED, never sweeps",
                   (code != 0, "not a JSON array" in log, applies) == (True, True, 0)))

    # [registry #510] PER-ISSUE ERROR ISOLATION, EXECUTED. A GENUINE write failure — the class that
    # is still an error, as opposed to a dropped unknown label — must be RECORDED per issue, must
    # NOT abort the remaining issues, and must turn the step red exactly ONCE, after the loop. This
    # was asserted only textually before (`\\bexit\\b` absent from the loop body), which cannot see
    # `set -e` aborting the sweep at the first non-zero applier. Dies on: moving the `exit 1` inside
    # the loop, dropping the `failed=1` bookkeeping (code would be 0), and on a sweep that stops at
    # the first failure (applies would be 1, not 80). The green control is the very first
    # `run_sweep_step` row above — same board, no injected failure, exit 0 with the same 80 applies.
    code, log, _pages, _window, applies, _targets = run_sweep_step(fail_applies="1,2")
    checks.append(("[#510] a genuine per-issue write failure is recorded, the OTHER 78 issues are "
                   "still processed, and the step exits non-zero once AFTER the loop",
                   (code != 0, applies, log.count("fail-closed retriage FAILED"),
                    "one or more issues failed" in log) == (True, 80, 2, True)))

    ok = all(result for _, result in checks)
    for name, result in checks:
        print(f"  {'ok  ' if result else 'FAIL'} {name}")
    print("retriage self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def build_parser():
    """The CLI contract. A named builder so the self-test can assert that every flag
    .github/workflows/retriage.yml passes is actually DECLARED (PR #595 finding 2: `--known-labels`
    was passed by the workflow and declared NOWHERE — a workflow-shaped invocation exited 2 with
    "unrecognized arguments" on every sweep, while the enrolled suite stayed green because every
    self-test called plan() directly)."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--snapshot", action="store_true",
                        help="read a list of issue pages on stdin and emit THIS run's rotating "
                             "sweep window as JSON lines")
    parser.add_argument("--cap", type=int, default=SWEEP_CAP)
    parser.add_argument("--ceiling", type=int, default=SWEEP_CEILING)
    parser.add_argument("--rotation", type=int, default=0,
                        help="rotates the per-run window by --cap (the workflow passes its run "
                             "number) so a capped board cannot starve its tail — #605 review "
                             "finding 1")
    parser.add_argument("--maintainer", default="")
    parser.add_argument("--app-bot", default="")
    parser.add_argument("--permission", default="none")
    parser.add_argument("--known-labels", default="",
                        help="comma-separated target-repo label set; enables the registry #582 "
                             "existence check so a non-existent role:* label is never planned")
    parser.add_argument("--policy-file", default="",
                        help="policy/repos.toml — the ONE source of the per-repo "
                             "`allow_actions_bot_issues` triage opt-in (registry #487). Empty "
                             "means no opt-in; an unreadable/malformed one is a hard error, never "
                             "a silent deny")
    parser.add_argument("--apply", action="store_true",
                        help="plan AND apply the promotion FAIL-CLOSED (needs --repo/--number)")
    parser.add_argument("--repo", default="")
    parser.add_argument("--number", default="")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if args.snapshot:
        try:
            issues, dropped = snapshot(json.load(sys.stdin), cap=args.cap, ceiling=args.ceiling,
                                       rotation=args.rotation)
        except (SweepError, ValueError) as exc:
            print(f"::error::retriage sweep refused its snapshot: {exc}", file=sys.stderr)
            return 1
        if dropped:
            # #605 review finding 1: the old wording — "deferred to the next run (oldest-updated
            # first)" — was materially FALSE under a fixed oldest-first window: the tail was
            # deferred forever. State what the rotation actually guarantees, in runs.
            total = len(issues) + dropped
            runs = -(-total // args.cap)
            # ...and #605 review ROUND 2: "covered within N runs" was still unqualified. Issue
            # numbers are immutable but board MEMBERSHIP is not, so a lower-numbered issue that
            # closes/reopens/gains a swept label between runs shifts every later offset. State the
            # bound with the condition it actually holds under.
            print(f"::warning::retriage sweep cap {args.cap} reached — {dropped} of {total} board "
                  f"issue(s) are outside THIS run's window; the window rotates by {args.cap} per "
                  f"run (--rotation {args.rotation}), so for an UNCHANGED board the whole of it is "
                  f"covered within {runs} runs (membership changes shift the offsets, so that is a "
                  "no-starvation bound, not a per-issue deadline)", file=sys.stderr)
        for issue in issues:
            print(json.dumps(issue, sort_keys=True))
        return 0
    known = [item for item in args.known_labels.split(",") if item.strip()] or None
    # registry #487. Resolved ONCE, here, for both the plan-only and the --apply paths, so the two
    # cannot disagree about who is trusted. A policy we were asked to read and could not is a hard
    # exit, not a silent deny (see actions_bot_trust) — the silent deny is the starvation bug.
    try:
        allow_actions_bot = actions_bot_trust(args.policy_file, args.repo)
    except SweepError as exc:
        print(f"::error title=retriage::refusing to retriage against an unusable repository "
              f"policy: {exc}", file=sys.stderr)
        return 1
    issue = json.load(sys.stdin)
    if args.apply:
        if not args.repo or not args.number:
            parser.error("--apply requires --repo and --number")
        return _apply_cli(args.repo, args.number, issue, args.maintainer, args.app_bot,
                          args.permission, known, allow_actions_bot)
    print(json.dumps(plan(issue, args.maintainer, args.app_bot, args.permission,
                          known_labels=known, allow_actions_bot_issues=allow_actions_bot),
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
