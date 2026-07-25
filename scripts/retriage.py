#!/usr/bin/env python3
"""Plan one safe, idempotent retriage mutation from an issue JSON document.

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
NON_DISPATCHABLE = _ready.NON_DISPATCHABLE            # kind:epic
# Bounded, rate-limit-safe sweep: an explicit per-run write cap and a runaway ceiling on the
# paginated snapshot. A partial page must never be mistaken for the whole board.
SWEEP_CAP = 40
SWEEP_CEILING = 5000


class SweepError(RuntimeError):
    """A snapshot this sweep refuses to act on (runaway size, or a partial/malformed page)."""


def plan(issue, maintainer, app_bot, permission, classify=static_triage.triage):
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
        result = classify(labels, "task", trusted=True)
    except Exception:
        return {"action": "skip", "reason": "classifier-failure"}
    add, remove = set(result["add"]), set(result["remove"])
    if untriaged:
        if not result["ready"]:
            # A CONTRADICTORY dual-status issue (`status:untriaged` alongside a stale
            # `status:ready` — the same partial label edit that strands the pure `status:ready`
            # case below) would otherwise keep its positive attestation forever, since the
            # promotion lane only ever writes when the classifier says complete. Strip it, from
            # the SAME classifier verdict the re-park lane uses.
            if "status:ready" in remove:
                return {"action": "repark", "add": [], "remove": sorted(remove)}
            return {"action": "skip", "reason": "classifier-incomplete"}
        remove.update(labels.intersection({"status:untriaged"}))
        return {"action": "promote", "add": sorted(add), "remove": sorted(remove)}

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
        return {"action": "repair", "add": sorted(add), "remove": sorted(remove)}
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
        return {"action": "repark", "add": sorted(add), "remove": sorted(remove)}
    # The classifier calls the label set complete yet the engine still cannot enumerate it (e.g.
    # `status:blocked`, or an open blocker). Nothing is PROVEN about triage, so do nothing.
    return {"action": "skip", "reason": "unprovable"}


def snapshot(pages, cap=SWEEP_CAP, ceiling=SWEEP_CEILING):
    """Normalize a `gh api --paginate --slurp` page list into (issues, dropped).

    FAIL CLOSED on any partial view: a page that is not a list, an entry that is not an object, a
    missing issue number or a malformed label RAISES rather than yielding a short board — acting on
    a truncated snapshot would look exactly like "nothing to do". `ceiling` is the runaway guard
    (mirrors ready-issues._fetch); `cap` bounds the writes one run may plan, oldest-updated first,
    with the remainder reported by the caller (never silently truncated).
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
    # Oldest-updated first: a FAIRNESS ordering only (never a decision input), so a stranded issue
    # is at the head of every run until it is repaired. Number breaks ties deterministically.
    issues.sort(key=lambda i: (i["updatedAt"], i["number"]))
    return issues[:cap], max(0, len(issues) - cap)


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

    # ---- #586: the label-lost half. A `status:ready` issue the readiness engine cannot
    # enumerate is re-parked; a healthy one is left completely untouched. ----
    HEALTHY = ("status:ready", "priority:P2", "role:soundness", "area:groom")
    healthy = labelled(*HEALTHY)
    chk("POSITIVE CONTROL: a fully-labelled status:ready issue is untouched",
        plan(healthy, "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "ready-consistent"})
    chk("POSITIVE CONTROL: the untouched decision carries NO label writes",
        set(plan(healthy, "owner", "app[bot]", "none")) & {"add", "remove"}, set())
    # Criterion 4 scope: an ENUMERABLE status:ready issue is never rewritten by this sweep, even
    # when the classifier sees other drift (here: an ambiguous role set it would collapse).
    chk("an enumerable status:ready issue is left alone despite unrelated classifier drift",
        plan(labelled("status:ready", "priority:P2", "role:soundness", "role:impl", "area:docs"),
             "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "ready-consistent"})

    lost_priority = labelled("status:ready", "role:soundness", "area:groom")
    chk("lost priority is re-parked", plan(lost_priority, "owner", "app[bot]", "none"),
        {"action": "repark", "add": ["status:untriaged"], "remove": ["status:ready"]})
    ambiguous = labelled("status:ready", "priority:P1", "priority:P2", "role:soundness",
                         "area:groom")
    chk("ambiguous priority is re-parked", plan(ambiguous, "owner", "app[bot]", "none"),
        {"action": "repark", "add": ["status:untriaged"], "remove": ["status:ready"]})
    lost_area = labelled("status:ready", "priority:P2", "role:soundness")
    chk("lost area is re-parked", plan(lost_area, "owner", "app[bot]", "none"),
        {"action": "repark", "add": ["status:untriaged"], "remove": ["status:ready"]})
    chk("the re-park never MINTS a needs:* gate it would then refuse to cross",
        "needs:area" in plan(lost_area, "owner", "app[bot]", "none").get("add", []), False)
    lost_role = labelled("status:ready", "priority:P2", "area:groom")
    chk("lost role is repaired in place (the classifier re-derives it)",
        plan(lost_role, "owner", "app[bot]", "none"),
        {"action": "repair", "add": ["role:soundness"], "remove": []})

    # Park policy stays load-bearing on the NEW lane too — none of these is re-parked.
    for park, reason in ((park_policy.MACHINE_PARK_LABEL, "machine-parked"),
                         ("status:in-progress", "claim-owned"),
                         ("status:in-progress-review", "claim-owned"),
                         ("kind:epic", "epic"),
                         ("status:deferred", "not-retriageable")):
        chk(f"status:ready + {park} is not re-parked",
            plan(labelled("status:ready", "role:soundness", "area:groom", park),
                 "owner", "app[bot]", "none"),
            {"action": "skip", "reason": reason})
    chk("status:ready + needs:user is not re-parked (human-owned park)",
        plan(labelled("status:ready", "role:soundness", "area:groom", "needs:user"),
             "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "gated:needs:user"})
    chk("an untrusted author is never inspected on the re-park lane",
        plan(labelled("status:ready", "role:soundness", "area:groom", author="outsider"),
             "owner", "app[bot]", "read"),
        {"action": "skip", "reason": "untrusted-author"})
    chk("an orchestration hold is honoured on the re-park lane",
        plan(labelled("status:ready", "role:soundness", "area:groom", body=HOLD_MARKER),
             "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "explicit-hold"})
    chk("classifier failure never re-parks",
        plan(lost_priority, "owner", "app[bot]", "none", broken),
        {"action": "skip", "reason": "classifier-failure"})
    # FAIL CLOSED: the classifier calls it complete but the engine still cannot enumerate it
    # (`status:blocked` is a busy status triage() knows nothing about) -> no write.
    chk("an unprovable exclusion is left alone",
        plan(labelled("status:ready", "status:blocked", "priority:P2", "role:soundness",
                      "area:groom"), "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "unprovable"})

    dual = labelled("status:untriaged", "status:ready", "role:soundness", "area:groom")
    chk("a contradictory dual-status issue loses its stale status:ready",
        plan(dual, "owner", "app[bot]", "none"),
        {"action": "repark", "add": [], "remove": ["status:ready"]})
    chk("a second sweep over the de-contradicted board plans ZERO writes",
        plan(applied(dual, plan(dual, "owner", "app[bot]", "none")), "owner", "app[bot]", "none"),
        {"action": "skip", "reason": "classifier-incomplete"})
    chk("an incomplete untriaged issue with NO stale attestation is still left alone",
        plan(labelled("status:untriaged", "role:soundness", "area:groom"),
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
    chk("snapshot normalizes labels", issues[1]["labels"], [{"name": "status:ready"}])
    chk("snapshot plans nothing beyond the board", dropped, 0)
    chk("snapshot dedupes an issue matched by BOTH label queries",
        [i["number"] for i in snapshot([[api(4, "status:ready")], [api(4, "status:ready")]])[0]],
        [4])
    capped, dropped = snapshot([[api(n, "status:ready", updated=f"2026-07-0{n}T00:00:00Z")
                                 for n in (1, 2, 3)]], cap=2)
    chk("the per-run cap is explicit and oldest-updated first",
        ([i["number"] for i in capped], dropped), ([1, 2], 1))
    for label, payload in (("a runaway board", [[api(n, "status:ready") for n in range(12)]]),
                           ("a partial page", [[api(1, "status:ready")], "truncated"]),
                           ("a non-object entry", [[api(1, "status:ready"), 7]]),
                           ("a numberless entry", [[{"user": {"login": "o"}, "labels": []}]]),
                           ("a malformed label", [[{"number": 1, "labels": [{"colour": "red"}]}]]),
                           ("a non-list payload", {"pages": []})):
        try:
            snapshot(payload, ceiling=10)
            chk(f"snapshot refuses {label}", "no error", "SweepError")
        except SweepError:
            chk(f"snapshot refuses {label}", "raised", "raised")

    ok = all(result for _, result in checks)
    for name, result in checks:
        print(f"  {'ok  ' if result else 'FAIL'} {name}")
    print("retriage self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--snapshot", action="store_true",
                        help="read a `gh api --paginate --slurp` page list on stdin and emit the "
                             "bounded, oldest-updated-first sweep board as JSON lines")
    parser.add_argument("--cap", type=int, default=SWEEP_CAP)
    parser.add_argument("--ceiling", type=int, default=SWEEP_CEILING)
    parser.add_argument("--maintainer", default="")
    parser.add_argument("--app-bot", default="")
    parser.add_argument("--permission", default="none")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    if args.snapshot:
        try:
            issues, dropped = snapshot(json.load(sys.stdin), cap=args.cap, ceiling=args.ceiling)
        except (SweepError, ValueError) as exc:
            print(f"::error::retriage sweep refused its snapshot: {exc}", file=sys.stderr)
            return 1
        if dropped:
            print(f"::warning::retriage sweep cap {args.cap} reached — {dropped} issue(s) deferred "
                  "to the next run (oldest-updated first)", file=sys.stderr)
        for issue in issues:
            print(json.dumps(issue, sort_keys=True))
        return 0
    issue = json.load(sys.stdin)
    print(json.dumps(plan(issue, args.maintainer, args.app_bot, args.permission), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
