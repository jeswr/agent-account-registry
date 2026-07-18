#!/usr/bin/env python3
# [FABLE-5] Registry self-management: the RETRIAGE sweep for jeswr/agent-account-registry.
# Modeled on the sparq target's scripts/retriage.py, adjusted for the registry's stricter
# fail-closed posture (no default priority — this repo IS the orchestration trust plane).
# Applied by .github/workflows/retriage.yml.
"""retriage.py — re-run static triage over parked/label-lost issues, fail-closed.

`triage-issue.yml` only fires on opened/edited/reopened, and GitHub's `edited` activity does NOT
cover label changes — so `status:untriaged` was TERMINAL (a human later adding `priority:P2`
never re-ran triage), and an issue whose `status:*` labels vanished entirely was invisible to
dispatch forever (observed 2026-07-18: 7 untriaged + 9 label-lost of 39 open). This cron sweep
closes the loop by recomputing labels with the SAME static pass triage-issue.yml runs
(scripts/triage.py — imported, never duplicated). Static derivation has no LLM dependency; an
issue whose label-set is still incomplete simply keeps `status:untriaged` and the cron retries
after the next human/label change.

Scope — an OPEN issue is retriaged iff ALL hold:
  * NOT an account record (no `provider:*` label — those are data rows, not work items);
  * NOT gated `needs:user` / `needs:design` (human-owned holds; retriage never edits them);
  * NOT `trust:untrusted` (quarantine is owned by the maintainer-approval flow, #31/#63);
  * NO `status:ready` (already visible to dispatch — nothing to do);
  * NOT in a dispatch/groom-owned busy state (`status:in-progress`,
    `status:in-progress-review`, `status:blocked`, `status:deferred`). In particular
    `status:in-progress` recovery — orphaned or otherwise — belongs to groom's lease-driven
    repair (attempt accounting, worker-run inspection); retriage racing the ledger from a
    stale read at :13/:43 could strip a LIVE worker's status, so it never touches the state
    and never reads the ledger at all;
  * the AUTHOR re-passes the exact triage-issue.yml trust gate (maintainer / App bot slug /
    admin-maintain-write collaborator). Bot trust is TYPE-verified: only a GraphQL `Bot`
    actor may match the App slug, and a Bot actor can ONLY be trusted as that exact App —
    a human account merely named like the App falls through to the permission probe, and a
    foreign bot matches nothing. An untrusted author is never triaged here — and never
    re-quarantined either (that could undo a maintainer approval).

Unlike the sparq retriage, NO default priority is applied: auto-P3 would auto-dispatch
trust-plane work no human ever prioritised. Missing priority stays parked, fail-closed.

Idempotent (an empty label delta is not an action; re-planning the post-state yields nothing).
Bounded API usage: one issue list, <=1 cached permission probe per unique
author, exactly one `gh issue edit` per acted-on issue, hard-capped at MAX_EDITS per run.
Pure `plan_retriage()` is unit-tested (--self-test); the CLI wraps it over `gh`. Default is a
dry-run print; the cron passes --apply.
"""
import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import triage  # noqa: E402  (same-directory static-triage module — the single source of truth)

# States owned by the dispatch/groom/review state machines — retriage never touches them.
# status:in-progress is machine-owned too: ALL its recovery (orphan rows included) is groom's
# lease-driven repair; a second reader racing live dispatch here could strip a live worker.
MACHINE_OWNED_STATUS = {"status:in-progress", "status:in-progress-review",
                        "status:blocked", "status:deferred"}
MAX_EDITS = 100  # hard per-run write cap; anything beyond is logged LOUDLY, never silent


def _labels_of(issue):
    return {lb["name"] if isinstance(lb, dict) else lb for lb in issue.get("labels", [])}


def plan_retriage(issues, trusted):
    """[(number, add:sortedlist, remove:sortedlist)] — the exact label mutations to apply.

    Empty deltas are dropped, so re-running over the post-apply state plans nothing
    (idempotence). `trusted(login, is_bot)` is the author trust gate."""
    actions = []
    for it in issues:
        labels = _labels_of(it)
        if any(lb.startswith("provider:") for lb in labels):
            continue  # account record, not a work item
        if labels & {"needs:user", "needs:design"}:
            continue  # human-owned gates
        if "trust:untrusted" in labels:
            continue  # quarantine owned by the approval flow (#31/#63)
        if "status:ready" in labels:
            continue  # already dispatchable
        if labels & MACHINE_OWNED_STATUS:
            continue  # in-progress included: groom owns ALL lease/status repair
        if not trusted(str(it.get("author", "")), bool(it.get("author_is_bot"))):
            continue
        result = triage.triage(labels, "task")
        add = set(result["add"])
        remove = set(result["remove"])
        if not add and not remove:
            continue  # already converged — no churn
        actions.append((it.get("number"), sorted(add), sorted(remove)))
    return actions


def _gh(args):
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=False)


def _norm_bot(login):
    return login[: -len("[bot]")] if login.endswith("[bot]") else login


def _exact_trust(login, is_bot, maintainer, app_bot):
    """Type-verified exact-match trust: True/False is a decision, None means the caller must
    fall through to the collaborator-permission probe (human actors only).

    A Bot actor (GraphQL `Bot` / REST `user.type == "Bot"`) can ONLY be trusted as the exact
    registry App identity — never via the maintainer match or the permission probe. A human
    actor can NEVER match the App slug, so an account merely NAMED like the App gains nothing.
    The slug is compared [bot]-suffix-insensitively only because GraphQL (`gh issue list`)
    reports bot logins without the suffix while REST events carry it — same identity, two
    spellings; the actor-type requirement is what prevents this from widening trust."""
    if not login:
        return False
    if is_bot:
        return bool(app_bot) and _norm_bot(login) == _norm_bot(app_bot)
    if login.endswith("[bot]"):
        return False  # brackets are impossible in real user logins — spoofed, never probed
    if login == maintainer:
        return True
    return None


def _trusted_factory(repo, maintainer, app_bot):
    """Exact-match maintainer/App-bot trust (type-verified, see _exact_trust), else a CACHED
    collaborator-permission probe — the same gate triage-issue.yml applies, never a blanket
    [bot] trust."""
    cache = {}

    def trusted(login, is_bot=False):
        exact = _exact_trust(login, is_bot, maintainer, app_bot)
        if exact is not None:
            return exact
        if login not in cache:
            r = _gh(["api", f"repos/{repo}/collaborators/{login}/permission",
                     "--jq", ".permission"])
            cache[login] = (r.stdout or "").strip() if r.returncode == 0 else "none"
        return cache[login] in {"admin", "maintain", "write"}

    return trusted


def _fetch_open_issues(repo):
    # author.is_bot is GraphQL's actor-type discriminator (`__typename == "Bot"`) — the
    # type half of the _exact_trust gate, not inferable from the login string.
    r = _gh(["issue", "list", "-R", repo, "--state", "open", "--limit", "500",
             "--json", "number,labels,author"])
    if r.returncode != 0:
        raise SystemExit(f"retriage: could not list open issues for {repo}: {r.stderr.strip()}")
    issues = []
    for it in json.loads(r.stdout or "[]"):
        author = it.get("author") or {}
        issues.append({"number": it.get("number"), "labels": it.get("labels") or [],
                       "author": (author.get("login") or ""),
                       "author_is_bot": bool(author.get("is_bot"))})
    return issues


def _self_test():
    import copy
    global _gh
    ok = True

    def chk(n, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {n}: {got} (want {want})")

    def iss(n, labels, author="jeswr", is_bot=False):
        return {"number": n, "labels": labels, "author": author, "author_is_bot": is_bot}

    # The REAL trust gate, with the network probe stubbed to "no permission" so every
    # fall-through is fail-closed and observable (`probes` records who got probed). The
    # stub is not restored: --self-test returns straight to exit, nothing else runs.
    probes = []

    class _Denied:
        returncode = 1
        stdout = ""
        stderr = "stubbed: no collaborator permission"

    def _stub_gh(args):
        probes.append(args)
        return _Denied()

    _gh = _stub_gh
    trusted = _trusted_factory("jeswr/agent-account-registry", "jeswr",
                               "agent-account-registry[bot]")
    fixture = [
        # 1: human later added the priority by LABEL (the exact terminal case) -> promotes
        iss(1, ["status:untriaged", "priority:P2", "kind:docs", "area:docs"]),
        # 2: account record -> skipped (data row, not a work item)
        iss(2, ["provider:anthropic", "status:available", "priority:P1"]),
        # 3: needs:design (B2 hold) -> skipped, even with a full label-set
        iss(3, ["status:untriaged", "priority:P2", "role:impl", "area:review-loop",
                "needs:design"]),
        # 4: label-LOST but complete -> status:ready restored
        iss(4, ["priority:P1", "role:impl", "area:usage"]),
        # 5: label-LOST and incomplete -> status:untriaged (+role) restored, visible again
        iss(5, ["kind:docs"]),
        # 6: needs:user gate -> skipped
        iss(6, ["status:untriaged", "priority:P1", "role:impl", "area:docs", "needs:user"]),
        # 7: already ready -> out of scope
        iss(7, ["status:ready", "priority:P1", "role:impl", "area:docs"]),
        # 8: quarantined -> owned by the approval flow, skipped
        iss(8, ["status:untriaged", "trust:untrusted", "priority:P1"]),
        # 9: untrusted author -> never triaged here (and never re-quarantined)
        iss(9, ["priority:P1", "role:impl", "area:usage"], author="rando"),
        # 10/11: status:in-progress is machine-owned — groom owns ALL its repair (orphan
        # rows included); retriage must NEVER touch it, ledger or no ledger
        iss(10, ["status:in-progress", "priority:P1", "role:impl", "area:docs"]),
        iss(11, ["status:in-progress", "priority:P2", "role:impl", "area:usage"]),
        # 12: review/deferred/blocked machine states -> skipped
        iss(12, ["status:in-progress-review", "priority:P1", "role:impl", "area:docs"]),
        iss(13, ["status:deferred", "priority:P1", "role:impl", "area:docs"]),
        iss(14, ["status:blocked", "priority:P1", "role:impl", "area:docs"]),
        # 15: untriaged, still incomplete (no priority) -> parked untouched, cron retries
        iss(15, ["status:untriaged", "role:impl", "area:usage"]),
        # 16: epic label-lost -> untriaged restored (umbrellas are untriaged-by-design)
        iss(16, ["kind:epic", "priority:P1", "role:impl", "area:usage"]),
        # 17: untriaged, no area -> parks needs:area (same as triage-issue would)
        iss(17, ["status:untriaged", "priority:P2", "role:impl"]),
        # 18: label-lost, authored by the registry App — a TYPE-verified Bot actor is
        # trusted under the exact slug (GraphQL spells it without the [bot] suffix)
        iss(18, ["priority:P1", "role:impl", "area:usage"],
            author="agent-account-registry", is_bot=True),
        # 19: an actor NAMED like the App but NOT a Bot -> impersonator, never trusted
        # (falls through to the permission probe, which the stub denies)
        iss(19, ["priority:P1", "role:impl", "area:usage"],
            author="agent-account-registry", is_bot=False),
    ]
    snapshot = copy.deepcopy(fixture)
    actions = {n: (a, r) for n, a, r in plan_retriage(fixture, trusted)}

    chk("acted-on set", sorted(actions), [1, 4, 5, 16, 17, 18])
    chk("untriaged->ready promotes", actions[1],
        (["role:docs", "status:ready"], ["status:untriaged"]))
    chk("account record skipped", 2 in actions, False)
    chk("needs:design skipped (B2)", 3 in actions, False)
    chk("label-lost complete -> ready restored", actions[4], (["status:ready"], []))
    chk("label-lost incomplete -> untriaged restored", actions[5],
        (["role:docs", "status:untriaged"], []))
    chk("needs:user skipped", 6 in actions, False)
    chk("status:ready out of scope", 7 in actions, False)
    chk("quarantine skipped", 8 in actions, False)
    chk("untrusted author skipped", 9 in actions, False)
    chk("status:in-progress NEVER touched (groom owns all repair)",
        any(n in actions for n in (10, 11)), False)
    chk("machine-owned states skipped", any(n in actions for n in (12, 13, 14)), False)
    chk("incomplete untriaged untouched (no churn)", 15 in actions, False)
    chk("epic label-lost -> untriaged restored", actions[16], (["status:untriaged"], []))
    chk("no-area parks needs:area", actions[17], (["needs:area"], []))
    chk("type-verified App bot trusted -> swept", actions[18], (["status:ready"], []))
    chk("non-Bot actor with the App's name NOT trusted", 19 in actions, False)

    # trust gate directly: actor TYPE + exact identity, both required
    chk("bot + exact slug (GraphQL spelling) trusted",
        trusted("agent-account-registry", True), True)
    chk("bot + exact slug (REST spelling) trusted",
        trusted("agent-account-registry[bot]", True), True)
    chk("non-bot with App name not exact-trusted",
        trusted("agent-account-registry", False), False)
    chk("non-bot with [bot]-suffixed name not trusted",
        trusted("agent-account-registry[bot]", False), False)
    chk("foreign bot not trusted", trusted("some-other-app", True), False)
    chk("maintainer (human) trusted", trusted("jeswr", False), True)
    chk("bot impersonating the maintainer slug not trusted", trusted("jeswr", True), False)
    chk("empty login not trusted", trusted("", False), False)
    # Bot actors must NEVER reach the collaborator probe — no probe carries a bot login
    chk("no permission probe ever ran for a bot actor",
        any("some-other-app" in " ".join(p) or "[bot]" in " ".join(p) for p in probes),
        False)

    # MUTATION check 1: planning never mutates its input
    chk("input not mutated", fixture == snapshot, True)

    # MUTATION check 2 (idempotence): applying the planned deltas and re-planning yields nothing
    applied = []
    for it in fixture:
        labels = _labels_of(it)
        if it["number"] in actions:
            add, remove = actions[it["number"]]
            labels = (labels | set(add)) - set(remove)
        applied.append({"number": it["number"], "labels": sorted(labels),
                        "author": it["author"], "author_is_bot": it["author_is_bot"]})
    chk("idempotent (re-plan of post-state is empty)",
        plan_retriage(applied, trusted), [])

    # the promoted post-state is genuinely dispatch-visible per the readiness invariants
    ready_labels = set(applied[0]["labels"])
    chk("promoted issue satisfies readiness shape",
        ("status:ready" in ready_labels, "status:untriaged" in ready_labels), (True, False))

    print("retriage self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="jeswr/agent-account-registry")
    ap.add_argument("--apply", action="store_true", help="apply the label deltas (cron mode)")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()

    maintainer = os.environ.get("MAINTAINER_LOGIN", "jeswr")
    app_bot = os.environ.get("APP_BOT_LOGIN", "agent-account-registry[bot]")
    actions = plan_retriage(_fetch_open_issues(args.repo),
                            _trusted_factory(args.repo, maintainer, app_bot))
    if len(actions) > MAX_EDITS:
        print(f"::warning::retriage: {len(actions)} deltas exceed the per-run cap of "
              f"{MAX_EDITS}; the remainder is deferred to the next tick (NOT silent)")
        actions = actions[:MAX_EDITS]
    failures = 0
    for number, add, remove in actions:
        print(f"#{number}: +{','.join(add) or '-'} -{','.join(remove) or '-'}")
        if not args.apply:
            continue
        edit = ["issue", "edit", str(number), "-R", args.repo]
        if add:
            edit += ["--add-label", ",".join(add)]
        if remove:
            edit += ["--remove-label", ",".join(remove)]
        r = _gh(edit)  # one write per issue — bounded
        if r.returncode != 0:
            failures += 1
            print(f"::error::retriage: label edit failed for #{number}: {r.stderr.strip()}")
    print(f"retriage: {len(actions)} issue(s) "
          f"{'updated' if args.apply else 'actionable (dry-run)'}"
          + (f", {failures} FAILED" if failures else ""))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
