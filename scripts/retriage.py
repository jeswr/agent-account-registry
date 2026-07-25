#!/usr/bin/env python3
"""Plan AND apply one safe, idempotent retriage mutation from an issue JSON document.

TWO DIRECTIONS, ONE CLASSIFIER (issue #586). The sweep that shipped for #415 was one-directional
— it only promoted `status:untriaged` — so an issue that LOST a required triage label while
KEEPING its `status:ready` attestation was recoverable by nothing on master: retriage never listed
it, curate-frontier skips anything already carrying a `status:` label, groom only repairs
claim-backed state, and triage-issue.yml does not fire on label events. It simply left the
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
"""
import argparse
import importlib.util
import json
import os
import sys

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
# Claim-owned states: groom's orphan/lease repair owns these, never this sweep (a re-park here
# would race a live worker and strip the claim its PR is bound to).
CLAIM_OWNED = {"status:in-progress", "status:in-progress-review"}
# The actions that WRITE. `--apply` mutates for each of them through the one shared applier; every
# other verdict is a no-op skip (fail-closed: an unknown action never becomes a write).
WRITING_ACTIONS = ("promote", "repark", "repair")
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


def plan(issue, maintainer, app_bot, permission, classify=static_triage.triage,
         known_labels=None):
    """`known_labels` (optional): the target repo's ACTUAL label set. Supplying it makes the role
    transition fail-closed (registry #582) — the classifier never plans an add of a label the repo
    does not have, and never plans a strip of the last role label for one. Without a role the
    classifier reports not-ready, so this path skips the issue as `classifier-incomplete` rather
    than promoting it to a role-less `status:ready` (silently undispatchable, unrecoverable)."""
    labels = {item["name"] if isinstance(item, dict) else item
              for item in issue.get("labels", [])}
    author = (issue.get("author") or {}).get("login", "")
    trusted = (author in {maintainer, app_bot} or permission in TRUSTED_PERMISSIONS)
    if not trusted:
        return {"action": "skip", "reason": "untrusted-author"}
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
        result = classify(labels, "task", trusted=True, known_labels=known_labels)
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
    stable across runs and the windows really do partition it — and the start offset advances by
    `cap` per `rotation` (the workflow passes its run number). Every issue is therefore visited
    within ceil(total/cap) runs with NO persistent cursor state to keep. Within the run the board is
    handed over oldest-updated first, which is a fairness ORDER only, never a decision input.
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
        names = []
        for label in item.get("labels") or []:
            name = label.get("name") if isinstance(label, dict) else label
            if not isinstance(name, str) or not name:
                raise SweepError(f"issue #{number} carries a malformed label")
            names.append({"name": name})
        issues.append({"number": number,
                       "author": {"login": login if isinstance(login, str) else ""},
                       "body": item.get("body") or "",
                       "labels": names,
                       "updatedAt": str(item.get("updated_at") or "")})
    # Stable ordering for the partition: the issue NUMBER never changes, so consecutive rotations
    # really do walk disjoint windows (an `updatedAt` ordering re-shuffles between runs and can
    # skip past an issue entirely).
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


def _apply_cli(repo, number, issue, maintainer, app_bot, permission, known_labels):
    """`--apply`: re-read the LIVE labels, plan against them, and mutate fail-closed.

    Planning against the live read (not the possibly-stale board snapshot the sweep passed on
    stdin) means a gate added since the list read — needs:design, trust:untrusted, a concurrent
    promotion — is honoured. Reads go through gh_retry; the mutation is single-attempt + fail-loud.
    """
    read_state, view, edit, warn = static_triage.live_gh(repo, number, title="retriage")
    live, _revision = read_state()
    fresh = dict(issue)
    fresh["labels"] = sorted(live)
    known = list(known_labels) if known_labels else static_triage.repo_label_set(repo)
    decision = plan(fresh, maintainer, app_bot, permission, known_labels=known)
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
    chk("a second sweep over the de-contradicted board plans ZERO writes",
        plan(applied(dual, plan(dual, "owner", "app[bot]", "none")), "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "classifier-incomplete"})
    chk("an incomplete untriaged issue with NO stale attestation is still left alone",
        plan(labelled("status:untriaged", ROLE_LABEL, "area:groom"),
             "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "classifier-incomplete"})

    # ---- IDEMPOTENCE + the round trip (re-park -> restore the label -> promote lands back on
    # the ORIGINAL label set, with no oscillation and no second write) ----
    reparked = applied(lost_priority, plan(lost_priority, "owner", "app[bot]", "none"))
    chk("a second sweep over the re-parked board plans ZERO writes",
        plan(reparked, "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "classifier-incomplete"})
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

    def run_apply_argv(gh, stdin_doc=None):
        """Drive main(apply_argv) end-to-end against a fake GitHub. Returns (exit code, spied)."""
        seen = {}
        saved_plan = globals()["plan"]
        saved_live_gh, saved_labels = static_triage.live_gh, static_triage.repo_label_set
        saved_stdin, saved_stdout = sys.stdin, sys.stdout

        def spy_plan(issue_doc, maintainer, app_bot, permission,
                     classify=static_triage.triage, known_labels=None):
            seen.update(known_labels=known_labels, maintainer=maintainer, permission=permission,
                        labels=list(issue_doc.get("labels", ())))
            return saved_plan(issue_doc, maintainer, app_bot, permission, classify, known_labels)

        try:
            globals()["plan"] = spy_plan
            static_triage.live_gh = lambda repo, number, title="triage": (
                gh.read_state, gh.view, gh.edit, lambda _message: None)
            static_triage.repo_label_set = lambda repo: (_ for _ in ()).throw(
                AssertionError("--known-labels must be used; the live label read is a fallback"))
            sys.stdin = io.StringIO(json.dumps(stdin_doc if stdin_doc is not None else stale))
            sys.stdout = io.StringIO()
            try:
                code = main(apply_argv)
            except SystemExit as exc:  # argparse exits 2 on an undeclared flag — that is the defect
                code = exc.code
        finally:
            globals()["plan"] = saved_plan
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
            print(f"::warning::retriage sweep cap {args.cap} reached — {dropped} of {total} board "
                  f"issue(s) are outside THIS run's window; the window rotates by {args.cap} per "
                  f"run (--rotation {args.rotation}), so the whole board is covered within {runs} "
                  "runs", file=sys.stderr)
        for issue in issues:
            print(json.dumps(issue, sort_keys=True))
        return 0
    known = [item for item in args.known_labels.split(",") if item.strip()] or None
    issue = json.load(sys.stdin)
    if args.apply:
        if not args.repo or not args.number:
            parser.error("--apply requires --repo and --number")
        return _apply_cli(args.repo, args.number, issue, args.maintainer, args.app_bot,
                          args.permission, known)
    print(json.dumps(plan(issue, args.maintainer, args.app_bot, args.permission,
                          known_labels=known), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
