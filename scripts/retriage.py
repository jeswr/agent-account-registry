#!/usr/bin/env python3
"""Plan AND apply one safe, idempotent retriage mutation from an issue JSON document.

`--apply` (PR #595 finding 3) owns the whole read -> plan -> mutate -> verify sequence, through the
SAME fail-closed applier `triage.py --apply` uses (triage.apply_triage). retriage.yml previously
sent the additions AND removals through one opaque `gh issue edit` in the workflow shell:
  * nothing verified that the replacement `role:*` label EXISTS or LANDED before the strip;
  * on a partial failure `set -e` exited the step, SKIPPING the post-read entirely;
  * when the post-read did fire and saw zero roles it merely `exit 1`-ed — leaving the issue
    `status:ready` with no role, the terminal #582 state retriage itself cannot revisit;
  * its check ACCEPTED multiple roles, which route-resolve rejects (AmbiguousRoleError).
The applier now adds + verifies the replacement first, keeps the incumbent role on any failure,
asserts EXACTLY ONE role in a revision-bound post-read, and repairs — or demotes `status:ready` to
`status:untriaged` so the next retriage tick owns the issue — instead of stranding it.
"""
import argparse
import json
import sys

import triage as static_triage


HOLD_MARKER = "<!-- orchestration:hold -->"
TRUSTED_PERMISSIONS = {"admin", "maintain", "write"}


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
    if "status:untriaged" not in labels or "status:deferred" in labels:
        return {"action": "skip", "reason": "not-retriageable"}
    try:
        result = classify(labels, "task", trusted=True, known_labels=known_labels)
    except Exception:
        return {"action": "skip", "reason": "classifier-failure"}
    if not result["ready"]:
        return {"action": "skip", "reason": "classifier-incomplete"}
    remove = set(result["remove"])
    remove.update(labels.intersection({"status:untriaged"}))
    # registry #582 belt-and-braces: never emit a promotion whose post-state has no role:* label.
    post = (labels | set(result["add"])) - remove
    if not any(label.startswith("role:") for label in post):
        return {"action": "skip", "reason": "role-invariant"}
    # `role` is the INTENDED single role. --apply needs it to add + verify the replacement BEFORE
    # any strip, and to repair an ambiguous post-state down to one role (PR #595 findings 3 + 4).
    return {"action": "promote", "add": sorted(result["add"]), "remove": sorted(remove),
            "role": result["role"]}


def apply_promotion(current, decision, edit, view, read_state=None, warn=None):
    """Apply a `promote` decision through the SHARED fail-closed applier (triage.apply_triage).

    Returns {"ok": bool, "warnings": [...]}. ok=False must turn the workflow step RED — never
    swallow it, and never let the shell short-circuit past the post-condition (PR #595 finding 3).
    """
    result = {"add": set(decision.get("add", ())), "remove": set(decision.get("remove", ())),
              "ready": True, "role": decision.get("role"), "warnings": []}
    return static_triage.apply_triage(current, result, edit, view, warn, read_state=read_state)


def _apply_cli(repo, number, issue, maintainer, app_bot, permission, known_labels):
    """`--apply`: re-read the LIVE labels, plan against them, and mutate fail-closed.

    Planning against the live read (not the possibly-stale `gh issue list` snapshot the sweep passed
    on stdin) means a gate added since the list read — needs:design, trust:untrusted, a concurrent
    promotion — is honoured. Reads go through gh_retry; the mutation is single-attempt + fail-loud.
    """
    read_state, view, edit, warn = static_triage.live_gh(repo, number, title="retriage")
    live, _revision = read_state()
    fresh = dict(issue)
    fresh["labels"] = sorted(live)
    known = list(known_labels) if known_labels else static_triage.repo_label_set(repo)
    decision = plan(fresh, maintainer, app_bot, permission, known_labels=known)
    print(json.dumps(decision, sort_keys=True))
    if decision["action"] != "promote":
        return 0
    outcome = apply_promotion(live, decision, edit, view, read_state, warn)
    if not outcome["ok"]:
        print(f"::error title=retriage #{number}::promotion did not satisfy the single-role "
              f"post-condition (registry #582): {'; '.join(outcome['warnings'])}")
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

    checks = []
    got = plan(issue("status:untriaged"), "owner", "app[bot]", "none")
    checks.append(("status:untriaged promotion",
                   got["action"] == "promote" and "status:ready" in got["add"]
                   and "status:untriaged" in got["remove"]))
    checks.append(("dispatcher-owned deferred rejected",
                   plan(issue("status:deferred"), "owner", "app[bot]", "none")
                   == {"action": "skip", "reason": "not-retriageable"}))
    checks.append(("mixed untriaged and deferred rejected",
                   plan(issue("status:untriaged", "status:deferred"),
                        "owner", "app[bot]", "none")
                   == {"action": "skip", "reason": "not-retriageable"}))
    checks.append(("needs gate rejected",
                   plan(issue("status:untriaged", "needs:design"), "owner", "app[bot]", "none")
                   == {"action": "skip", "reason": "gated:needs:design"}))
    checks.append(("hold marker rejected",
                   plan(issue("status:untriaged", body=HOLD_MARKER), "owner", "app[bot]", "none")
                   == {"action": "skip", "reason": "explicit-hold"}))

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

    checks.append(("classifier failure is idempotent",
                   plan(issue("status:untriaged"), "owner", "app[bot]", "none", broken)
                   == {"action": "skip", "reason": "classifier-failure"}))
    foreign = issue("status:untriaged")
    foreign["author"] = {"login": "outsider"}
    checks.append(("trust rejection",
                   plan(foreign, "owner", "app[bot]", "read")
                   == {"action": "skip", "reason": "untrusted-author"}))
    checks.append(("write collaborator accepted",
                   plan(foreign, "owner", "app[bot]", "write")["action"] == "promote"))
    checks.append(("a promotion carries the INTENDED single role for the applier",
                   plan(issue("status:untriaged"), "owner", "app[bot]", "none",
                        known_labels=real).get("role") == "ci"))

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
    outcome = apply_promotion(set(gh.labels), live_plan(gh, known), gh.edit, gh.view, gh.read_state)
    checks.append(("[#595 f3] happy path: exactly one role, promoted, ok",
                   (outcome["ok"], roles_of(gh.labels), "status:ready" in gh.labels,
                    "status:untriaged" in gh.labels) == (True, {"role:impl"}, True, False)))
    # The target role label does NOT exist in the repo: the ADD fails, so NOTHING may be stripped.
    # plan() already fails closed on that input, so the applier is driven with the PRE-FIX plan
    # shape — the blind add-role/strip-role mutation the workflow shell used to send in one edit.
    gh = FakeGh(start, known - {"role:impl"})
    outcome = apply_promotion(set(gh.labels),
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
    outcome = apply_promotion(set(gh.labels), live_plan(gh, known), gh.edit, gh.view, gh.read_state)
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
    outcome = apply_promotion(set(gh.labels), live_plan(gh, known), gh.edit, gh.view, gh.read_state)
    checks.append(("[#595 f3] an ambiguous post-state is repaired to ONE role, never accepted",
                   (outcome["ok"], roles_of(gh.labels), "status:ready" in gh.labels)
                   == (False, {"role:impl"}, True)))
    # ... and when the repair CANNOT hold (a persistent concurrent writer), status:ready is DEMOTED
    # to status:untriaged so the next retriage tick owns the issue — never left ready-and-ambiguous,
    # which route-resolve rejects and nothing else revisits.
    gh = InjectingGh(start, known, persistent=True)
    outcome = apply_promotion(set(gh.labels), live_plan(gh, known), gh.edit, gh.view, gh.read_state)
    checks.append(("[#595 f3] an unrepairable ambiguity DEMOTES to status:untriaged, never terminal",
                   (outcome["ok"], "status:ready" in gh.labels, "status:untriaged" in gh.labels)
                   == (False, False, True)))

    # -------------------------------------------------------------------------------------------
    # [PR #595 finding 2] THE ARGV ENTRYPOINT, PINNED TO THE WORKFLOW'S OWN ARGUMENT LIST.
    # Every check above calls plan()/apply_promotion() DIRECTLY, which is precisely why
    # `--known-labels` could ship undeclared: the workflow-shaped invocation exited 2 with
    # "unrecognized arguments" on every scheduled sweep while this suite reported PASSED. The
    # argument list below is READ OUT OF THE WORKFLOW FILE and driven through the REAL entrypoint
    # (main -> _apply_cli -> plan -> apply_promotion) against a fake GitHub, so a workflow/CLI drift
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
    gh = FakeGh(start, known)
    seen = {}
    saved_plan, saved_live_gh, saved_labels = plan, static_triage.live_gh, static_triage.repo_label_set
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
        sys.stdin = io.StringIO(json.dumps({"author": {"login": "owner"}, "body": "",
                                            "labels": [{"name": "stale:snapshot"}]}))
        sys.stdout = io.StringIO()
        try:
            code = main(apply_argv)
        except SystemExit as exc:      # argparse exits 2 on an undeclared flag — that is the defect
            code = exc.code
    finally:
        globals()["plan"] = saved_plan
        static_triage.live_gh, static_triage.repo_label_set = saved_live_gh, saved_labels
        sys.stdin, sys.stdout = saved_stdin, saved_stdout
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
