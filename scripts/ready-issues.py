#!/usr/bin/env python3
# [OPUS-4.8] Registry self-management: the readiness engine for jeswr/agent-account-registry.
# A copy of the sparq target's scripts/ready-issues.py — the dispatch PLAN clones this repo and
# runs `scripts/ready-issues.py --self-test` + imports compute_ready(), exactly as it does for
# sparq. Kept behaviourally identical so the shared dispatcher treats both targets the same.
"""ready-issues.py — compute the dispatchable frontier from GitHub issues, FAIL-CLOSED.

Readiness requires POSITIVE, bot-attested state — never mere absence of a quarantine label. An
issue is READY iff, in priority order, ALL hold:
  * OPEN, and
  * carries `status:ready` (positive attestation the triage/trust pipeline set), and
  * carries exactly ONE valid `priority:P0..P4` (ambiguous/invalid priority -> excluded), and
  * carries a `role:*` label, and
  * carries NO gate label (`needs:*` — INCLUDING `needs:design` and `needs:user` —, or
    `trust:untrusted`) and is NOT busy
    (`status:in-progress|in-progress-review|blocked|deferred|untriaged`), and
  * has zero open blockers, and
  * none of its PACKAGES (`area:<section>`) is already taken by an in-progress issue or an
    earlier-selected ready issue. A no-package / cross-cutting issue reserves a **global
    partition** that serializes it against ALL other work.

`needs:design` (B2) is a DESIGN-HOLD gate: a `needs:*` label so an issue that still needs an
architect pass is NEVER ready while it is present, exactly like `needs:user`. The gate is the
prefix rule below — no design-heavy issue can be dispatched until a human clears the label.
"""
import argparse
import json
import re
import subprocess
import sys

# Any `needs:*` (needs:user, needs:design, needs:area, ...) is a hard gate; `trust:untrusted` too.
GATE_LABELS = ("needs:", "trust:untrusted")
BUSY_STATUS = {"status:in-progress", "status:in-progress-review", "status:blocked",
               "status:deferred", "status:untriaged"}
# an epic is a tracking umbrella (its children are the work) — never dispatchable.
NON_DISPATCHABLE = "kind:epic"
GLOBAL = "__global__"  # the cross-cutting partition (serializes against everything)
_PRIO = re.compile(r"^priority:P([0-4])$")   # only P0..P4 are valid
_PKG = re.compile(r"^area:(.+)$")
_ROLE = re.compile(r"^role:.+$")


def labels_of(issue):
    return {lb["name"] if isinstance(lb, dict) else lb for lb in issue.get("labels", [])}


def valid_priority(labels):
    """Exactly one valid priority:P0..P4 -> its int; zero or multiple or out-of-range -> None."""
    ps = {int(m.group(1)) for lb in labels for m in [_PRIO.match(lb)] if m}
    return next(iter(ps)) if len(ps) == 1 else None


def packages_of(labels):
    """The SET of all area:<section> packages; empty -> the serializing global partition."""
    pkgs = {m.group(1) for lb in labels for m in [_PKG.match(lb)] if m}
    return pkgs or {GLOBAL}


def has_role(labels):
    return any(_ROLE.match(lb) for lb in labels)


def is_gated(labels):
    return any(lb == g or lb.startswith(g) for lb in labels for g in GATE_LABELS)


def is_busy(labels):
    return bool(labels & BUSY_STATUS)


def compute_ready(issues, in_progress_packages=None):
    """Conflict-free, priority-ordered, FAIL-CLOSED ready frontier."""
    taken = set(in_progress_packages or ())
    for it in issues:
        if str(it.get("state", "OPEN")).upper() != "OPEN":
            continue
        L = labels_of(it)
        if "status:in-progress" in L or "status:in-progress-review" in L:
            taken |= packages_of(L)
    cands = []
    for it in issues:
        if str(it.get("state", "OPEN")).upper() != "OPEN":
            continue
        L = labels_of(it)
        if "status:ready" not in L:          # positive attestation required
            continue
        if NON_DISPATCHABLE in L:            # epics are tracking umbrellas, not work items
            continue
        if is_gated(L) or is_busy(L):
            continue
        p = valid_priority(L)
        if p is None:                        # need exactly one valid priority
            continue
        if not has_role(L):                  # need a role
            continue
        if int(it.get("open_blockers", 0)) > 0:
            continue
        cands.append((p, it.get("number", 0), it, packages_of(L)))
    cands.sort(key=lambda c: (c[0], c[1]))   # priority then number (deterministic)
    ready = []
    for _p, _n, it, pkgs in cands:
        if GLOBAL in taken:                  # cross-cutting work in flight -> nothing else co-runs
            break
        if pkgs & taken:                     # package conflict
            continue
        if GLOBAL in pkgs and taken:         # cross-cutting can't co-run with any package in flight
            continue
        taken |= pkgs
        ready.append(it)
    return ready


def _self_test():
    def iss(n, labels, blk=0, state="OPEN"):
        return {"number": n, "state": state, "labels": labels, "open_blockers": blk}

    R = ["status:ready", "role:impl"]
    F = [
        iss(1, R + ["priority:P2", "area:worker"]),
        iss(2, R + ["priority:P0", "area:worker"]),
        iss(3, R + ["priority:P1", "area:dispatch"]),
        iss(4, R + ["priority:P1", "area:dispatch", "needs:user"]),          # gated
        iss(40, R + ["priority:P1", "area:review-loop", "needs:design"]),    # DESIGN-HOLD gate (B2)
        iss(5, R + ["priority:P1", "area:usage"], blk=2),                    # blocked
        iss(6, R + ["priority:P0", "area:groom"], state="CLOSED"),           # closed
        iss(7, R + ["priority:P1", "trust:untrusted", "area:docs"]),         # untrusted
        iss(8, ["priority:P3", "role:impl", "area:worker"]),                 # not status:ready
        iss(9, R + ["priority:P1", "priority:P2", "area:usage"]),            # ambiguous priority
        iss(10, R + ["priority:P1", "area:set-up-account", "status:in-progress-review"]),  # busy
        iss(11, R + ["priority:P4"]),                                        # no package -> global
        iss(12, R + ["priority:P1", "area:groom"]),                          # groom (free)
        iss(13, R + ["priority:P0", "area:docs", "kind:epic"]),              # epic -> excluded
    ]
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got} (want {want})")

    ready = compute_ready(F)
    # eligible: 2(P0 worker),3(P1 dispatch),12(P1 groom) then 11(P4 global blocked — board taken).
    check("ready order", [i["number"] for i in ready], [2, 3, 12])
    # B2: a needs:design issue with an otherwise-perfect ready label-set is NEVER ready.
    check("needs:design gated (B2)", 40 in [i["number"] for i in ready], False)
    check("is_gated needs:design (B2)", is_gated({"needs:design", "status:ready"}), True)
    check("is_gated needs:user", is_gated({"needs:user"}), True)
    check("in-progress-review is busy", is_busy({"status:in-progress-review"}), True)
    check("epic excluded", 13 in [i["number"] for i in ready], False)
    check("lone global", [i["number"] for i in compute_ready([iss(11, R + ["priority:P4"])])], [11])
    g = compute_ready([iss(11, R + ["priority:P0"]), iss(12, R + ["priority:P1", "area:groom"])])
    check("global serializes", [i["number"] for i in g], [11])
    check("valid_priority single", valid_priority({"priority:P0"}), 0)
    check("valid_priority ambiguous", valid_priority({"priority:P1", "priority:P2"}), None)
    check("packages none->global", packages_of({"role:impl"}), {GLOBAL})
    check("flatten pages drops PRs", _flatten_pages(
        [[{"number": 1}, {"number": 2, "pull_request": {}}], [{"number": 3}], "junk", [None]]),
        [{"number": 1}, {"number": 3}])
    print("ready-issues self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def _flatten_pages(pages):
    """Flatten `gh api --paginate --slurp` output (a list of pages) into issues, dropping PRs."""
    return [i for page in pages for i in (page if isinstance(page, list) else [])
            if isinstance(i, dict) and "pull_request" not in i]


def _fetch(repo, ceiling=10000):
    """Open-issue snapshot via REAL cursor pagination; the explicit ceiling fails closed."""
    out = subprocess.run(
        ["gh", "api", "--paginate", "--slurp",
         f"repos/{repo}/issues?state=open&per_page=100"],
        capture_output=True, text=True, check=True).stdout
    pages = json.loads(out or "[]")
    raw = _flatten_pages(pages)
    if len(raw) >= ceiling:
        raise SystemExit(f"refusing: fetched {len(raw)} >= ceiling {ceiling} — snapshot looks "
                         "runaway (fail-closed).")
    open_numbers = {i["number"] for i in raw}
    issues = []
    for i in raw:
        blockers = re.findall(r"[Bb]locked-by:\s*#(\d+)", i.get("body") or "")
        open_blk = sum(1 for b in blockers if int(b) in open_numbers)
        issues.append({"number": i["number"], "state": i["state"],
                       "labels": i["labels"], "open_blockers": open_blk})
    return issues


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="jeswr/agent-account-registry")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()
    for it in compute_ready(_fetch(args.repo)):
        L = labels_of(it)
        print(f"P{valid_priority(L)}  #{it['number']:5}  {sorted(packages_of(L))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
