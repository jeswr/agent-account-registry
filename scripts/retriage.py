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
  * NOT in a dispatch/groom-owned busy state (`status:in-progress-review`, `status:blocked`,
    `status:deferred` — flipping those would break the deferral/review state machines);
  * `status:in-progress` only when the lease LEDGER IS READABLE and NO lease row (live or
    expired) references the issue: groom's lease-driven repair owns every row-backed case
    (it runs 2x as often and does attempt accounting); a row that VANISHED entirely is the
    LOST state only this sweep can see. An unreadable ledger fail-closed skips all
    in-progress issues;
  * the AUTHOR re-passes the exact triage-issue.yml trust gate (maintainer / App bot slug /
    admin-maintain-write collaborator). An untrusted author is never triaged here — and never
    re-quarantined either (that could undo a maintainer approval).

Unlike the sparq retriage, NO default priority is applied: auto-P3 would auto-dispatch
trust-plane work no human ever prioritised. Missing priority stays parked, fail-closed.

Idempotent (an empty label delta is not an action; re-planning the post-state yields nothing).
Bounded API usage: one issue list, one ledger read, <=1 cached permission probe per unique
author, exactly one `gh issue edit` per acted-on issue, hard-capped at MAX_EDITS per run.
Pure `plan_retriage()` is unit-tested (--self-test); the CLI wraps it over `gh`. Default is a
dry-run print; the cron passes --apply.
"""
import argparse
import base64
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import triage  # noqa: E402  (same-directory static-triage module — the single source of truth)

LEDGER_PATH = "data/leases.json"
LEDGER_REF = os.environ.get("REGISTRY_LEDGER_REF", "ledger")
# review:/fix: repair leases are PR-scoped (dispatch-claim prefixes) — never issue-mapped here.
REPAIR_HOLDER_PREFIXES = ("review:", "fix:")
# States owned by the dispatch/groom/review state machines — retriage never touches them.
MACHINE_OWNED_STATUS = {"status:in-progress-review", "status:blocked", "status:deferred"}
MAX_EDITS = 100  # hard per-run write cap; anything beyond is logged LOUDLY, never silent


def _labels_of(issue):
    return {lb["name"] if isinstance(lb, dict) else lb for lb in issue.get("labels", [])}


def plan_retriage(issues, trusted, leased_numbers=frozenset(), ledger_ok=True):
    """[(number, add:sortedlist, remove:sortedlist)] — the exact label mutations to apply.

    `leased_numbers` is the set of issue numbers referenced by ANY lease-ledger row (live or
    expired); `ledger_ok=False` means the ledger could not be read, which fail-closed skips
    every `status:in-progress` issue. Empty deltas are dropped, so re-running over the
    post-apply state plans nothing (idempotence)."""
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
            continue
        extra_remove = set()
        if "status:in-progress" in labels:
            if not ledger_ok or it.get("number") in leased_numbers:
                continue  # a lease row exists (or is unknowable) — groom owns the repair
            extra_remove = {"status:in-progress"}  # lease row VANISHED — the LOST state
        if not trusted(str(it.get("author", ""))):
            continue
        result = triage.triage(labels, "task")
        add = set(result["add"])
        remove = set(result["remove"]) | extra_remove
        if not add and not remove:
            continue  # already converged — no churn
        actions.append((it.get("number"), sorted(add), sorted(remove)))
    return actions


def _gh(args):
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=False)


def _norm_bot(login):
    return login[: -len("[bot]")] if login.endswith("[bot]") else login


def _trusted_factory(repo, maintainer, app_bot):
    """Exact-match maintainer/App-bot trust, else a CACHED collaborator-permission probe —
    the same gate triage-issue.yml applies, never a blanket [bot] trust. The App slug is
    compared [bot]-suffix-insensitively because GraphQL (`gh issue list`) reports bot authors
    without the suffix while the REST issue event carries it."""
    cache = {}

    def trusted(login):
        if not login:
            return False
        if login == maintainer:
            return True
        if app_bot and _norm_bot(login) == _norm_bot(app_bot):
            return True
        if login not in cache:
            r = _gh(["api", f"repos/{repo}/collaborators/{login}/permission",
                     "--jq", ".permission"])
            cache[login] = (r.stdout or "").strip() if r.returncode == 0 else "none"
        return cache[login] in {"admin", "maintain", "write"}

    return trusted


def _fetch_open_issues(repo):
    r = _gh(["issue", "list", "-R", repo, "--state", "open", "--limit", "500",
             "--json", "number,labels,author"])
    if r.returncode != 0:
        raise SystemExit(f"retriage: could not list open issues for {repo}: {r.stderr.strip()}")
    issues = []
    for it in json.loads(r.stdout or "[]"):
        issues.append({"number": it.get("number"), "labels": it.get("labels") or [],
                       "author": ((it.get("author") or {}).get("login") or "")})
    return issues


def _fetch_leased_numbers(repo, ref=LEDGER_REF):
    """Issue numbers referenced by ANY ledger lease row for `repo`, or None if the ledger is
    unreadable (fail-closed: the caller then skips every status:in-progress issue)."""
    r = _gh(["api", f"repos/{repo}/contents/{LEDGER_PATH}?ref={ref}", "--jq", ".content"])
    if r.returncode != 0:
        return None
    try:
        rows = json.loads(base64.b64decode(r.stdout)).get("leases", [])
    except (ValueError, TypeError, AttributeError):
        return None
    numbers = set()
    prefix = f"{repo}#"
    for lease in rows:
        holder = lease.get("holder", "") if isinstance(lease, dict) else ""
        if not isinstance(holder, str) or holder.startswith(REPAIR_HOLDER_PREFIXES):
            continue
        key = holder.split("@", 1)[0]  # holder shape: repo#issue@run (groom.py HOLDER)
        if key.startswith(prefix):
            try:
                numbers.add(int(key[len(prefix):]))
            except ValueError:
                continue
    return numbers


def _self_test():
    import copy
    ok = True

    def chk(n, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {n}: {got} (want {want})")

    def iss(n, labels, author="jeswr"):
        return {"number": n, "labels": labels, "author": author}

    trusted = lambda login: login in {"jeswr", "agent-account-registry[bot]"}  # noqa: E731
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
        # 10: in-progress with a lease row -> groom owns it, skipped
        iss(10, ["status:in-progress", "priority:P1", "role:impl", "area:docs"]),
        # 11: in-progress ORPHAN (lease row vanished) -> re-derived, in-progress stripped
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
    ]
    snapshot = copy.deepcopy(fixture)
    actions = {n: (a, r) for n, a, r in plan_retriage(fixture, trusted, leased_numbers={10})}

    chk("acted-on set", sorted(actions), [1, 4, 5, 11, 16, 17])
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
    chk("leased in-progress skipped", 10 in actions, False)
    chk("orphaned in-progress re-derived", actions[11],
        (["status:ready"], ["status:in-progress"]))
    chk("machine-owned states skipped", any(n in actions for n in (12, 13, 14)), False)
    chk("incomplete untriaged untouched (no churn)", 15 in actions, False)
    chk("epic label-lost -> untriaged restored", actions[16], (["status:untriaged"], []))
    chk("no-area parks needs:area", actions[17], (["needs:area"], []))

    # unreadable ledger fail-closed skips EVERY in-progress issue, orphan included
    closed = {n for n, _, _ in plan_retriage(fixture, trusted, set(), ledger_ok=False)}
    chk("ledger unreadable -> in-progress skipped", 11 in closed, False)
    chk("ledger unreadable -> others still swept", 1 in closed, True)

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
                        "author": it["author"]})
    chk("idempotent (re-plan of post-state is empty)",
        plan_retriage(applied, trusted, leased_numbers={10}), [])

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
    leased = _fetch_leased_numbers(args.repo)
    ledger_ok = leased is not None
    if not ledger_ok:
        print("::warning::retriage: lease ledger unreadable — "
              "all status:in-progress issues skipped (fail-closed)")
    actions = plan_retriage(_fetch_open_issues(args.repo),
                            _trusted_factory(args.repo, maintainer, app_bot),
                            leased or set(), ledger_ok)
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
