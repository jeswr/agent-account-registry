#!/usr/bin/env python3
# [OPUS-5] ALERT ON THE STOCK, NOT THE RUN — applied to the HUMAN-TERMINAL park population.
#
# The principle is `triage-stock-alert.py`'s and it is quoted here because this file exists only
# because it was not applied widely enough:
#
#   "A per-run success signal STRUCTURALLY CANNOT express a missing state exit, because the
#    missing exit is a property of the POPULATION over time, not of any run."
#
# `dispatch-claim` ALREADY diagnoses this population perfectly, every executed tick:
#
#   ::warning::park census jeswr/agent-account-registry: 6 parked PR(s) are in a HUMAN-TERMINAL
#   state that no automatic re-admission can clear - #590, #601, #895, #1116, #1224, #1461.
#   These are declining CORRECTLY (a human-owned hold is live, a proven human applied the park,
#   or the automatic cap is spent); they need a HUMAN gesture, and they will stay parked until
#   one arrives.
#
# That message names every PR, states the cause, and says plainly that only a human clears it.
# It is also a `::warning::` inside a dispatch log, emitted only on an EXECUTED tick - and most
# ticks are floor-held, so it is usually not produced at all. Measured 2026-08-01: the population
# had been waiting with no issue, label, or dashboard reflecting it (registry #1573).
#
# THIS SCRIPT CHANGES NO GATE. Every refusal it reports is CORRECT and stays exactly as it is -
# including the fresh-gesture rule, which is what stops a consumed unpark granting unlimited
# budget windows. The defect is transport, not policy: the estate knows, and never says so
# anywhere a human looks.
#
# SCOPE + AUTHORITY. This script may create/edit/comment/close ONE `ops-alert` issue and nothing
# else. It never labels, closes, or comments on a target PR, and it never writes the ledger.
#
# THE POPULATION, and its DELIBERATE LIMIT. This reports parked PRs carrying a live HUMAN-OWNED
# HOLD. `park_policy.human_owned_holds` is THE shared rule and is imported, never re-derived - its
# own docstring: "A guard scoped to one symptom does not generalise; one shared rule does."
#
# ⚠️ THIS IS A SUBSET OF `dispatch-claim`'s HUMAN-TERMINAL SET, and the difference is measured, not
# assumed. dispatch-claim counts a park terminal when ANY of three hold: a live human-owned hold,
# a PROVEN HUMAN applied the park, or the automatic cap is spent. Only the first is decidable from
# labels alone; the other two need per-PR timeline and receipt reads. Measured 2026-08-01 on the
# registry: dispatch-claim reported 6 terminal (#590, #601, #895, #1116, #1224, #1461); this
# label-only census finds 2 (#1116, #1461).
#
# So the title and body say "a live human-owned hold", NOT "human-terminal". Naming the wider
# population while measuring the narrower one would let this alert CLOSE as healthy while four PRs
# are still stuck - the silent-disarm failure the close-only-on-explicit-health rule exists to
# prevent. Covering the other two causes is follow-up work (registry #1573), not a rename.
"""Alert on the HUMAN-TERMINAL parked-PR stock (registry #1573)."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ALERT_LABEL = "ops-alert"
ALERT_TITLE = "⚠️ Parked PRs carry a live human-owned hold — only a human gesture can clear them"
# Stable marker: it is the dedupe key, so renaming it orphans every open alert.
ALERT_MARKER = "<!-- park-stock-alert:v1 key=park-human-hold -->"
SCRIPTS_DIR = Path(__file__).resolve().parent


def _load_park_policy():
    spec = importlib.util.spec_from_file_location(
        "registry_park_policy_stock", SCRIPTS_DIR / "park_policy.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _labels(pull):
    raw = pull.get("labels") if isinstance(pull, dict) else None
    out = []
    for label in raw or []:
        name = label.get("name") if isinstance(label, dict) else label
        if isinstance(name, str):
            out.append(name)
    return out


def census(pulls, park_policy):
    """PURE. -> {"terminal": [numbers], "parked": n, "considered": n, "holds": {label: n}}.

    A PR counts as HUMAN-TERMINAL iff the machine park label is live AND `human_owned_holds`
    returns a non-empty set for its labels. Both halves are required: a machine park alone is
    re-admissible by a machine, and a human hold alone is not a park.
    """
    terminal, parked, holds = [], 0, {}
    for pull in pulls or []:
        if not isinstance(pull, dict):
            continue
        names = _labels(pull)
        if park_policy.MACHINE_PARK_PR_LABEL not in names:
            continue
        parked += 1
        owned = park_policy.human_owned_holds(names)
        if not owned:
            continue
        number = pull.get("number")
        if isinstance(number, int) and not isinstance(number, bool):
            terminal.append(number)
        for label in owned:
            holds[label] = holds.get(label, 0) + 1
    return {"terminal": sorted(terminal), "parked": parked,
            "considered": len(pulls or []), "holds": dict(sorted(holds.items()))}


def breached(counts):
    """The reasons this stock is unhealthy, sorted ([] == healthy).

    ANY human-terminal PR is a breach. There is no threshold: one PR that no machine can ever
    re-admit is already a population the maintainer has not been told about, and a threshold
    would simply choose how many to hide.
    """
    n = len(counts.get("terminal") or [])
    if not n:
        return []
    return [f"{n} parked PR(s) need a human re-admission gesture and no machine can supply one"]


def decide(reasons, has_open_alert):
    """Pure: 'upsert' | 'close' | 'noop'.

    Close ONLY on an explicitly healthy census computed from a board actually read. `main()`
    never calls this on a failed read — the ABSENCE of evidence of a breach is not evidence of
    recovery, and closing on it is how an alert silently disarms itself (plan-alert.py's rule).
    """
    if reasons:
        return "upsert"
    if has_open_alert:
        return "close"
    return "noop"


def render_body(repo, counts, reasons, run_url, maintainer):
    listed = ", ".join(f"#{n}" for n in counts["terminal"]) or "(none)"
    holds = ", ".join(f"`{k}`={v}" for k, v in counts["holds"].items()) or "(none)"
    return "\n".join([
        ALERT_MARKER,
        "> 🤖 SPARQ agent — automated ops-alert (parked-PR stock)",
        "",
        f"**{len(counts['terminal'])} parked PR(s) in `{repo}` carry a live HUMAN-OWNED HOLD**: a "
        "machine capacity park is live AND `park_policy.human_owned_holds` is non-empty, so no "
        "automatic re-admission can clear them. They are declining **correctly** — this is not a "
        "bug report against the park policy.",
        "",
        "⚠️ **This is a SUBSET.** `dispatch-claim` also treats a park as terminal when a proven "
        "human applied it, or the automatic cap is spent — both need per-PR timeline/receipt "
        "reads and are NOT covered here. Measured 2026-08-01: dispatch-claim saw 6 terminal on "
        "the registry where this label-only census sees 2. Do not read a closed alert as "
        "\"no parked PR needs a human\" (registry #1573).",
        "",
        f"- PRs: {listed}",
        f"- live holds: {holds}",
        f"- parked PRs considered: {counts['parked']} of {counts['considered']} open",
        "",
        "**What is needed:** a human re-admission gesture (remove the live human-owned hold, or "
        "close the PR if it is obsolete). Until one arrives these stay parked indefinitely.",
        "",
        "This alert exists because the estate already computed this list every executed dispatch "
        "tick and reported it only to a workflow log (registry #1573). No gate changed.",
        "",
        f"Run: {run_url}" if run_url else "",
        f"cc @{maintainer}",
    ])


def _gh(args, capture=False, token=None, check=False):
    # Sanitized fail-loud wrapper: op + returncode only — never stderr (GH_DEBUG=api can echo
    # request bodies) and never argument content beyond the gh subcommand words.
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    result = subprocess.run(["gh"] + args, capture_output=capture, text=True, env=env)
    if check and result.returncode != 0:
        print(f"::warning::park-stock-alert: gh {args[0]} "
              f"{args[1] if len(args) > 1 else ''} failed (rc={result.returncode})")
    return result


def _alert_route(alert_repo, alert_token, registry_repo):
    """(repo, token) — identical semantics to groom-alert/usage-alert/triage-stock-alert: the
    private ALERT_REPO only when ALERT_TOKEN is present; otherwise the registry repo under the
    ambient token."""
    if alert_repo and alert_token:
        return alert_repo, alert_token
    return registry_repo, None


def read_pulls(repo, max_pages=20):
    """Every open PR, paged EXPLICITLY with a request ceiling. Raises on an unreadable page so
    main() can skip the tick rather than decide on a partial board."""
    out = []
    for page in range(1, max_pages + 1):
        result = _gh(["api", f"repos/{repo}/pulls?state=open&per_page=100&page={page}"],
                     capture=True, check=True)
        if result.returncode != 0:
            raise RuntimeError(f"could not read open PRs for {repo} (page {page})")
        try:
            batch = json.loads(result.stdout or "[]")
        except ValueError as exc:
            raise ValueError(f"unparseable PR listing for {repo} (page {page})") from exc
        if not isinstance(batch, list):
            raise ValueError(f"PR listing for {repo} is not a JSON array")
        out.extend(batch)
        if len(batch) < 100:
            return out
    raise RuntimeError(f"open-PR listing for {repo} exceeded {max_pages} pages")


def enabled_targets(policy_path):
    import tomllib
    with open(policy_path, "rb") as handle:
        policy = tomllib.load(handle)
    return sorted(name for name, row in (policy.get("repos") or {}).items()
                  if isinstance(row, dict) and row.get("enabled"))


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    # The workflow-seam self-test scans for exactly this declaration, so it must stay an argparse
    # option and not a hand-rolled sys.argv check.
    parser.add_argument("--self-test", action="store_true",
                        help="run the hermetic self-test and exit")
    parser.add_argument("--policy-file", default=str(SCRIPTS_DIR.parent / "policy" / "repos.toml"))
    return parser


def main(argv=None):
    args = build_parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    if args.self_test:
        return _self_test()

    park_policy = _load_park_policy()
    registry_repo = os.environ["REGISTRY_REPO"]
    repo, token = _alert_route(
        os.environ.get("ALERT_REPO"), os.environ.get("ALERT_TOKEN"), registry_repo)
    run_url = os.environ.get("RUN_URL", "")
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")

    # Targets come from POLICY, never a second hardcoded list — the duplication that took dispatch
    # fully down on 2026-08-01 (#1537/#1540).
    targets = enabled_targets(args.policy_file)
    merged = {"terminal": [], "parked": 0, "considered": 0, "holds": {}}
    per_repo = {}
    for target in targets:
        try:
            pulls = read_pulls(target)
        except (RuntimeError, ValueError) as exc:
            # Never decide() on a board we could not read: an unread board has no census and the
            # 'close' branch would read it as recovery.
            print(f"::warning::park-stock-alert: {exc} — skipping this tick")
            return 1
        counts = census(pulls, park_policy)
        per_repo[target] = counts
        merged["terminal"] += [f"{target}#{n}" for n in counts["terminal"]]
        merged["parked"] += counts["parked"]
        merged["considered"] += counts["considered"]
        for label, n in counts["holds"].items():
            merged["holds"][label] = merged["holds"].get(label, 0) + n
    merged["holds"] = dict(sorted(merged["holds"].items()))
    reasons = breached(merged)
    print(f"park-stock-alert: {json.dumps(per_repo, default=str)}")

    listed = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", "open",
                  "--json", "number,title,body", "--limit", "100"],
                 capture=True, token=token, check=True)
    if listed.returncode != 0:
        return 1
    try:
        found = json.loads(listed.stdout or "[]")
        if not isinstance(found, list):
            raise ValueError("expected a JSON array")
    except ValueError:
        print("::warning::park-stock-alert: gh issue list succeeded but returned unparseable "
              "JSON — skipping this tick (no dedupe/recovery data; next tick retries)")
        return 0
    num = next((i["number"] for i in found if ALERT_MARKER in (i.get("body") or "")), None)
    if num is None:
        num = next((i["number"] for i in found if i.get("title") == ALERT_TITLE), None)

    action = decide(reasons, num is not None)
    if action == "upsert":
        _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", "d73a4a",
             "--description", "Autonomous ops alert (maintainer action)"],
            capture=True, token=token)  # idempotent
        body = render_body(", ".join(targets), merged, reasons, run_url, maintainer)
        if num:
            wrote = _gh(["issue", "edit", str(num), "-R", repo, "--body", body],
                        capture=True, token=token, check=True)
        else:
            wrote = _gh(["issue", "create", "-R", repo, "--title", ALERT_TITLE,
                         "--label", ALERT_LABEL, "--body", body],
                        capture=True, token=token, check=True)
        if wrote.returncode != 0:
            return 1
        print(f"::warning::park-stock-alert: {'; '.join(reasons)} — maintainer alerted")
        return 0
    if action == "close":
        commented = _gh(["issue", "comment", str(num), "-R", repo, "--body",
                         "✅ Recovered — no parked PR is in a human-terminal state. Auto-closing."],
                        capture=True, token=token, check=True)
        closed = _gh(["issue", "close", str(num), "-R", repo], capture=True, token=token,
                     check=True)
        if commented.returncode != 0 or closed.returncode != 0:
            return 1
        print("park-stock-alert: stock healthy — closed the alert")
        return 0
    print("park-stock-alert: stock healthy, no open alert — nothing to do")
    return 0


# ------------------------------------------------------------------------------------------------
# HERMETIC SELF-TEST — no network, no gh.
def _self_test():
    failures = []

    def chk(name, got, want=True):
        ok = got == want
        print(f"  {'ok  ' if ok else 'FAIL'} {name}: {got!r}" + ("" if ok else f" (want {want!r})"))
        if not ok:
            failures.append(name)

    pp = _load_park_policy()
    PARK, HUMAN = pp.MACHINE_PARK_PR_LABEL, pp.HUMAN_PR_PARK_LABEL

    def pull(number, *labels):
        return {"number": number, "labels": [{"name": n} for n in labels]}

    # ---- THE RED TEST: both halves live -> terminal --------------------------------------------
    board = [pull(1, PARK, HUMAN), pull(2, PARK, "needs:user"), pull(3, PARK, "needs:design")]
    chk("[RED] park + a human-owned hold is HUMAN-TERMINAL",
        census(board, pp)["terminal"], [1, 2, 3])

    # ---- CONTROLS: each half alone is NOT terminal ----------------------------------------------
    # Without these, a census that simply returned "every parked PR" (or "every held PR") would
    # pass the red test and alert on a population machines CAN clear.
    chk("[CONTROL] a machine park ALONE is not terminal (a machine can re-admit it)",
        census([pull(4, PARK), pull(5, PARK, "area:ci")], pp)["terminal"], [])
    chk("[CONTROL] a human hold ALONE is not terminal (it is not a park)",
        census([pull(6, HUMAN), pull(7, "needs:user"), pull(8, "needs:design")], pp)["terminal"], [])
    chk("[CONTROL] an unrelated label is neither", census([pull(9, "area:ci")], pp)["terminal"], [])

    # ---- DELEGATION, not a second copy of the rule ----------------------------------------------
    # The hold predicate MUST come from park_policy.human_owned_holds. A local re-implementation is
    # the drift this codebase has paid for; prove the call is real by inverting it.
    seen = {"n": 0}
    real = pp.human_owned_holds
    try:
        pp.human_owned_holds = lambda labels: (seen.__setitem__("n", seen["n"] + 1), [])[1]
        inverted = census([pull(10, PARK, HUMAN)], pp)["terminal"]
    finally:
        pp.human_owned_holds = real
    chk("census CALLS park_policy.human_owned_holds (delegation, not a local copy)",
        seen["n"] >= 1)
    chk("...and honours its answer — a stubbed-empty predicate yields NO terminal rows",
        inverted, [])

    # ---- census bookkeeping --------------------------------------------------------------------
    c = census([pull(1, PARK, HUMAN), pull(2, PARK), pull(3, "area:ci")], pp)
    chk("parked counts every machine-parked PR, terminal or not", c["parked"], 2)
    chk("considered counts the whole board", c["considered"], 3)
    chk("holds are tallied by label", c["holds"], {HUMAN: 1})
    chk("a malformed row is skipped, never crashes", census([None, 42, pull(1, PARK, HUMAN)], pp)["terminal"], [1])

    # ---- breach: NO threshold; one terminal PR is already a breach ------------------------------
    chk("one terminal PR breaches (a threshold would only choose how many to hide)",
        len(breached({"terminal": [1]})), 1)
    chk("an empty terminal set is healthy", breached({"terminal": []}), [])

    # ---- transport decision --------------------------------------------------------------------
    chk("breach -> upsert", decide(["r"], False), "upsert")
    chk("breach with an open alert -> upsert (edit in place, never a duplicate)",
        decide(["r"], True), "upsert")
    chk("healthy with an open alert -> close", decide([], True), "close")
    chk("healthy with no alert -> noop", decide([], False), "noop")

    # ---- the body must NAME the PRs; a count alone is what the log already gave us --------------
    body = render_body("o/r", {"terminal": ["o/r#590", "o/r#601"], "parked": 5, "considered": 40,
                               "holds": {HUMAN: 2}}, ["r"], "http://run", "jeswr")
    chk("the alert body NAMES the PRs", "#590" in body and "#601" in body)
    chk("the alert body carries the stable dedupe marker", ALERT_MARKER in body)
    chk("the alert body states a human gesture is required", "human re-admission gesture" in body)

    print(("park-stock-alert self-test: FAIL " + ", ".join(failures)) if failures
          else "park-stock-alert self-test: PASS")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
