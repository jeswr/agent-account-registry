#!/usr/bin/env python3
# [SPARQ agent] ALERT ON THE STOCK, NOT THE RUN — applied to the HUMAN-TERMINAL park population.
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
    # `terminal` rows are already `owner/repo#N` (main() qualifies them per target). GitHub
    # linkifies THAT form; prefixing another "#" yields `#owner/repo#N`, which resolves to
    # nothing — 13 dead links in the first live alert. Bare ints keep their "#".
    listed = ", ".join(str(n) if isinstance(n, str) and "#" in n else f"#{n}"
                       for n in counts["terminal"]) or "(none)"
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
        "⚠️ **This is a SUBSET — measured 13 of 24.** `dispatch-claim`'s own park census names "
        "24 human-terminal PRs across both targets where this census finds 13. Three known "
        "reasons, from reading its code rather than guessing:",
        "",
        "1. it censuses only BOT-AUTHORED parked PRs and classifies by the ADMISSION REFUSAL "
        "code, not by labels;",
        "2. a park is a PAIR — `review:needs-user` on the PR AND `needs:user` on the SOURCE "
        "ISSUE — and this census reads PR labels ONLY, so a PR held via its source issue is "
        "invisible here;",
        "3. `proven-human park` and `spent automatic cap` are terminal for dispatch-claim and "
        "need per-PR timeline/receipt reads.",
        "",
        "⚠️ **Do not read a closed alert as \"no parked PR needs a human\".** The complete list "
        "is emitted by dispatch-claim every executed tick; giving THAT census a durable output "
        "is the right fix, not widening this one (registry #1573).",
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


def _repo_confirmed_private(repo, token):
    proc = _gh(["api", f"repos/{repo}"], capture=True, token=token)
    if proc.returncode != 0:
        return False
    try:
        payload = json.loads(proc.stdout or "")
    except ValueError:
        return False
    return isinstance(payload, dict) and payload.get("private") is True


def _alert_route(alert_repo, alert_token, registry_repo, confirmed_private=None):
    """(repo, token) for the alert issue. ALERT_REPO is selected ONLY when its token is present,
    it differs from the registry case-insensitively, and a live GET /repos/{ALERT_REPO} under that
    token confirms a literal `private: true`. Presence is configuration, not verification; every
    other shape falls back to the registry. This body contains public issue and pull state."""
    if alert_repo and alert_token:
        same_repo = alert_repo.strip().lower() == (registry_repo or "").strip().lower()
        check = confirmed_private if confirmed_private is not None else _repo_confirmed_private
        if not same_repo and check(alert_repo, alert_token):
            return alert_repo, alert_token
    return registry_repo, None


def _private_probe_rows():
    global _gh
    original, calls = _gh, []
    def response(rc, body):
        def fake(args, **kwargs):
            calls.append((args, kwargs)); return type("Result", (), {"returncode": rc, "stdout": body})()
        return fake
    try:
        values = []
        for rc, body in ((0, '{"private": true}'), (0, '{"private": false}'), (9, '{"private": true}'),
                         (0, ""), (0, '{"private": "yes"}')):
            _gh = response(rc, body); values.append(_repo_confirmed_private("org/private", "route-token"))
    finally: _gh = original
    return values, calls[0]


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

    probe_values, probe_call = _private_probe_rows()
    for name, got, want in zip(("private true", "public", "failed lookup", "unparseable",
                                "non-boolean private"), probe_values,
                               (True, False, False, False, False)):
        chk(f"visibility probe: {name}", got, want)
    chk("visibility probe GETs repos/{repo} under route token", probe_call,
        (["api", "repos/org/private"], {"capture": True, "token": "route-token"}))

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
    # ...and renders a CROSS-REPO ref GitHub can actually resolve. `owner/repo#N` linkifies;
    # `#owner/repo#N` does not — the first live alert shipped 13 dead links exactly that way.
    chk("a qualified ref renders as owner/repo#N, never #owner/repo#N",
        "#o/r#590" in body, False)
    chk("...and the qualified ref IS present in linkable form", "o/r#590" in body)
    # A BARE int must still get its "#": the two forms are rendered by one expression, so a fix
    # for one that breaks the other is the shape this pins.
    chk("a bare number still renders as #N",
        "#42" in render_body("o/r", {"terminal": [42], "parked": 1, "considered": 1, "holds": {}},
                             ["r"], "", "jeswr"))
    chk("the alert body carries the stable dedupe marker", ALERT_MARKER in body)
    chk("the alert body states a human gesture is required", "human re-admission gesture" in body)
    # The subset caveat must name the MEASURED shortfall and the ACTUAL reasons. An alert that
    # under-reports while implying completeness is worse than one that reports nothing: a reader
    # who trusts a closed alert stops looking. Pinned on the numbers so a future widening that
    # changes coverage must update the claim with it.
    chk("the caveat states the measured coverage, not a vague 'subset'", "13 of 24" in body)
    chk("...and names the source-issue half of the park pair as a cause", "SOURCE" in body)

    # ---- the alert-route contract (#1667, extending #1021) --------------------------------------
    _test_alert_route_contract(chk)
    # ---- and the route's END-TO-END wiring into the gh calls (#1773) ----------------------------
    _test_route_wiring(chk)

    print(("park-stock-alert self-test: FAIL " + ", ".join(failures)) if failures
          else "park-stock-alert self-test: PASS")
    return 1 if failures else 0


def _test_alert_route_contract(chk):
    """#1667 (extending #1021): the router's PROSE must not promise more than the router ENFORCES,
    and this module must carry exactly ONE copy of the router.

    `_alert_route` branches on the TRUTHINESS of ALERT_TOKEN. Nothing is requested under that token
    before the route is chosen, so a docstring saying the private destination is selected only once
    the token has been shown able to write there states a strictly stronger contract than the code
    enforces. #1021 found exactly that sentence copied verbatim across seven alert scripts, where
    any single copy could drift back while the suite stayed green on the others — the #945
    mutually-masking-duplicate shape applied to prose. THIS copy's prose was already accurate when
    #1021 landed, which is the whole reason it was left uncensused, and the whole reason nothing
    stops the same drift reappearing here (#1667).

      1. CANONICAL PROSE, pinned CLOSED (phrasing-independent, load-bearing). The router's ENTIRE
         docstring is pinned by EQUALITY against the verbatim copy below (whitespace-flattened, so
         re-wrapping is free). Adding a sentence, dropping one, or rewording one reds this file
         whatever words it chooses — no list of banned phrasings is consulted, so no unanticipated
         phrasing escapes. CONTAINMENT would not do: #1021's review round 2 measured that pinning
         the approved sentences proves only that they are PRESENT, so a contradictory claim worded
         outside every enumerated phrasing could simply be added beside them and stay green.
      2. ENUMERATED TRIPWIRE (phrasing-dependent, defence in depth). The whole module outside this
         function — which is everything guard 1 pins PLUS the prose it does not reach, including
         the header and the rendered body — is scanned for a fixed list of write-capability
         phrasings, scoped to ALERT_TOKEN on EITHER side of the phrase, catching a stronger claim
         that lands in an UNPINNED comment or a rendered body. It is a tripwire, not a proof, and
         the row that reports it says so rather than promising the semantic property.

    The tripwire census scans this module with THIS FUNCTION'S OWN LINES REMOVED, so the banned
    phrases and the detector fixtures can be written literally below without the census matching
    itself; that exclusion is derived from the parsed AST, and its own row reds if it cannot find
    this function. Every row below is independently killable: edit the pinned docstring on one side
    only, weaken the pin back to containment, blunt the claim detector so it cannot fire, drop a
    phrasing or one scoping direction from it, widen its scope so it fires on unrelated prose,
    paste a second router into this file, reintroduce a listed claim anywhere outside this
    function, or drop either half of the router's guard."""
    import ast  # noqa: PLC0415 — self-test only; the census needs the module's own parsed source

    # GUARD 1 — the router's docstring, copied here VERBATIM and compared by EQUALITY (both sides
    # whitespace-flattened, so re-wrapping the source is free and every other edit is not).
    canonical_route_doc = """
    (repo, token) for the alert issue. ALERT_REPO is selected ONLY when its token is present,
    it differs from the registry case-insensitively, and a live GET /repos/{ALERT_REPO} under that
    token confirms a literal `private: true`. Presence is configuration, not verification; every
    other shape falls back to the registry. This body contains public issue and pull state.
    """

    def flat(text):
        """One whitespace-collapsed line — the normal form both sides of the guard-1 pin are
        compared in, so re-wrapping or re-indenting the governed prose is free and rewording it is
        not."""
        return " ".join((text or "").split())

    def matches_canonical(doc):
        """THE comparison guard 1 makes — named, so the non-vacuity rows below drive the SAME
        predicate the live pin uses. Re-typing `==` beside those rows instead would leave them
        green while the live pin degraded to containment; that mutant survived the first version
        of this census (AGENTS.md AUTHOR pre-flight #2b — an expected value must come from the
        same place the code reads it)."""
        return flat(doc) == flat(canonical_route_doc)

    # GUARD 2 — ENUMERATED, and kept inside this function so the census's own exclusion covers
    # these literals. The list is deliberately identical in every alert script carrying this guard.
    # `capable of writing` is NOT on it: honest prose in these routers may quote that phrase in
    # order to DISCLAIM it, and a lexical scan cannot tell a quotation from an assertion — guard 1
    # is what covers the pinned sentences.
    phrasings = ("can write there", "can write to", "write access", "able to write",
                 "may write there", "permission to write", "write permission",
                 "authorized to write", "authorised to write", "authorized to create",
                 "authorised to create", "able to create", "can create issues",
                 "allowed to write", "rights to write", "writable by")

    def claims_about_the_route(text):
        """Every ENUMERATED write-capability phrasing `text` uses ABOUT THE ALERT ROUTE, deduped
        and sorted. A tripwire over the list above — NOT a decision procedure for "does this text
        claim write capability", which is why the canonical-contract row is the load-bearing guard.

        `text` is flattened to one whitespace-collapsed lowercase string first, so a claim broken
        across a wrapped comment or docstring line is still found; a hit then counts only when
        ALERT_TOKEN is named within 160 characters (~two wrapped lines) on EITHER side, since the
        capability can be stated before the token names it as easily as after. BOTH directions of
        that scoping are exercised below, and so is the unscoped false positive the window exists
        to suppress."""
        blob = flat(text).lower()
        found = []
        for claim in phrasings:
            cursor = blob.find(claim)
            while cursor != -1:
                if "alert_token" in blob[max(0, cursor - 160):cursor + len(claim) + 160]:
                    found.append(claim)
                cursor = blob.find(claim, cursor + 1)
        return sorted(set(found))

    # VALIDATE THE DETECTOR BEFORE TRUSTING ITS SILENCE. On a clean tree every `find` returns -1,
    # so without these fixtures the whole scoping loop above never executes even once and the
    # census below reports `[]` whatever it is pointed at — an instrument that cannot fire has said
    # nothing (AGENTS.md AUTHOR pre-flight #1, which is how this hole was found in #1021).
    chk("#1667: the claim detector FIRES on route prose that makes the claim, including when the "
        "claim wraps onto the line after ALERT_TOKEN",
        claims_about_the_route("the private ALERT_REPO is the destination\n"
                               "ONLY when ALERT_TOKEN\ncan write there; otherwise the registry"),
        ["can write there"])
    chk("#1667: ... and on the SYNONYMS of that claim, not just the one wording #1021 removed",
        (claims_about_the_route("ALERT_TOKEN has permission to write there"),
         claims_about_the_route("the route needs an ALERT_TOKEN authorized to create issues in "
                                "the private repo")),
        (["permission to write"], ["authorized to create"]))
    chk("#1667: ... and when the capability is stated BEFORE ALERT_TOKEN names it (the scope "
        "window reaches both ways)",
        claims_about_the_route("the destination is private, so a credential able to write there "
                               "is required; that credential is ALERT_TOKEN"),
        ["able to write"])
    chk("#1667: ... and stays SILENT on a write-capability sentence about something that is not "
        "the route",
        claims_about_the_route("workflow_dispatch can be run from any ref by anyone with write "
                               "access, so it is excluded from the tick allowlist"), [])
    chk("#1667: ... and on one where ALERT_TOKEN appears but is far out of scope (a widened "
        "window would swallow this and make the census fire on unrelated prose)",
        claims_about_the_route("ALERT_TOKEN names the private route. " + "Unrelated prose. " * 12
                               + "The runner needs write access to the checkout."), [])

    chk("#1667: ... and every phrasing in the enumerated list is LIVE — each one, dropped into "
        "route prose, is reported — with the list still at its full #1021 reach, so shrinking it "
        "to make a red row green is a diff-visible act and never a silent one",
        (len(phrasings),
         [claims_about_the_route(f"the route needs an ALERT_TOKEN {claim} it")
          for claim in phrasings]),
        (16, [[claim] for claim in phrasings]))

    source = Path(__file__).read_text(encoding="utf-8")
    definitions = [node for node in ast.walk(ast.parse(source))
                   if isinstance(node, ast.FunctionDef)]
    routers = [node for node in definitions if node.name == "_alert_route"]
    chk("#1667: exactly ONE _alert_route definition in this module (a second copy makes each copy "
        "individually unkillable)", len(routers), 1)
    live_route_doc = ast.get_docstring(routers[0]) or ""
    chk("#1667: the router's docstring is EXACTLY the canonical contract — pinned by EQUALITY, so "
        "the governed prose is CLOSED: nothing can be added beside the approved sentences",
        (matches_canonical(live_route_doc), flat(live_route_doc)),
        (True, flat(canonical_route_doc)))
    # NON-VACUITY of that equality, and of its CLOSEDNESS specifically. `flat(x) == flat(y)` would
    # also hold with both sides empty, and a containment form would pass every input here except
    # the appended one — which is worded OUTSIDE `phrasings` on purpose, so the tripwire cannot be
    # what catches it. The dropped-clause input asserts its anchor occurs exactly ONCE first: a
    # `.replace()` that matched nothing would leave that row comparing the text with itself
    # (AGENTS.md mutation-run hygiene).
    anchor = "Presence is configuration, not verification"
    dropped = canonical_route_doc.replace(anchor, "")
    appended = canonical_route_doc + (
        "\n    ALERT_TOKEN has issue-creation privileges at ALERT_REPO.\n")
    chk("#1667: ... and that equality REJECTS an appended capability claim no phrasing list "
        "anticipates, a dropped clause, and an empty docstring — while ACCEPTING a re-wrapped "
        "copy, so it pins the WORDS and not the line breaks",
        (canonical_route_doc.count(anchor),
         matches_canonical(appended),
         matches_canonical(dropped),
         matches_canonical(""),
         matches_canonical("\n\n  ".join(canonical_route_doc.split()))),
        (1, False, False, False, True))
    census = [node for node in definitions if node.name == "_test_alert_route_contract"]
    chk("#1667: the prose census can locate its own body to exclude it from the scan",
        len(census), 1)
    # The scan excludes THIS function's own lines — derived from the parsed AST, not hard-coded —
    # so the banned phrases and the fixtures above can be written literally without self-matching.
    lines = source.splitlines()
    scanned = "\n".join(lines[:census[0].lineno - 1] + lines[census[0].end_lineno:])
    # The verdict is pinned TOGETHER WITH two properties of the text it was measured on, because
    # `[]` is also what an empty input returns: a census pointed at nothing would otherwise read
    # exactly like a clean module (AGENTS.md pre-flight #3's conditionally-inert mutant).
    # `def _alert_route(` proves the scan covered the module; the ABSENCE of this function's own
    # nested helper name proves the exclusion removed THIS function and not some other span.
    chk("#1667: none of the ENUMERATED write-capability phrasings survives in this module's "
        "alert-route prose — a tripwire over a fixed list, not a proof that no stronger claim can "
        "be worded (the canonical-contract row above is that guard) — measured over a scan that "
        "demonstrably covers the router and excludes only this function",
        (claims_about_the_route(scanned), "def _alert_route(" in scanned,
         "claims_about_the_route" in scanned),
        ([], True, False))
    # Behavioural statement of the contract the prose is now allowed to make. These literals appear
    # nowhere else in this harness, so a substituted value cannot collide with a fixture's.
    chk("#1775: a positively verified private destination is selected",
        _alert_route("org/priv-1667", "not-a-credential-1667", "org/reg-1667",
                     lambda r, t: True),
        ("org/priv-1667", "not-a-credential-1667"))
    chk("#1775: an unverified or public destination fails closed to the registry",
        _alert_route("org/public-1775", "token-1775", "org/reg-1667", lambda r, t: False),
        ("org/reg-1667", None))
    calls = []
    chk("#1775: same-repo is rejected case-insensitively without a lookup",
        (_alert_route("ORG/REG-1667", "token-1775", "org/reg-1667",
                      lambda r, t: calls.append(r) or True), calls),
        (("org/reg-1667", None), []))
    chk("#1667: ... and an EMPTY ALERT_TOKEN never does (the half-configured fallback, which must "
        "not silently lose the alert)",
        _alert_route("org/priv-1667", "", "org/reg-1667"), ("org/reg-1667", None))
    chk("#1667: ... and neither does an absent ALERT_REPO with a token beside it",
        _alert_route("", "not-a-credential-1667", "org/reg-1667"), ("org/reg-1667", None))


def _test_route_wiring(chk):
    """#1773: the (repo, token) the router returns must REACH the `gh` calls — asserted END TO END.

    The matrix rows above exercise the FUNCTION; they structurally cannot see the CALL SITE.
    `main()` resolves the route ONCE and then threads `repo` through `-R` and `token` through
    `_gh`'s env on SIX separate commands (issue list, label create, issue create, issue edit, issue
    comment, issue close). Dropping `token=token` from any one of them, or pointing one `-R` at a
    census target instead of the routed repo, leaves every matrix row green while the alert lands
    somewhere the maintainer is not looking — the call-site vacuity AGENTS.md pre-flight #2a and #6
    name, and the reason this file's router had NO coverage at all while five sibling alert scripts
    pinned theirs.

    `subprocess.run` is stubbed, so this is hermetic: no network, no `gh`, no real token. Every
    command `main()` issues is recorded with its FULL argv and env, and the rows below read the
    routed repo and `GH_TOKEN` back off those recordings. The fallback rows compare against the
    ambient token OBSERVED on the one command the route never tokenises (the PR census read) rather
    than against a constant restated here, so the expected value comes from the same place the code
    reads it (pre-flight #2b).

    Independently killable, one mutant each: return the registry on the private branch; return the
    alert token on either fallback branch; drop `token=token` from any single `_gh` call; drop
    `-R repo` from one; point one command at the census target; or drop a command entirely."""
    import contextlib  # noqa: PLC0415 — self-test only
    import io  # noqa: PLC0415
    import tempfile  # noqa: PLC0415

    # Literals that appear NOWHERE else in this harness, so a substituted value cannot collide with
    # a fixture's and read as a pass (pre-flight #4, value-identical survivor).
    PRIVATE, REGISTRY, TARGET = "org/priv-1773", "org/reg-1773", "org/target-1773"
    ALERT_TOK = "sentinel-park-tok-1773"

    pp = _load_park_policy()
    # One HUMAN-TERMINAL PR, so the default run reaches `upsert` and actually ISSUES the commands
    # whose wiring is under test. A healthy board (`[]`) plus an open alert reaches `close`.
    terminal_board = json.dumps([{"number": 1773,
                                  "labels": [{"name": pp.MACHINE_PARK_PR_LABEL},
                                             {"name": pp.HUMAN_PR_PARK_LABEL}]}])
    open_alert = json.dumps([{"number": 42, "title": ALERT_TITLE, "body": ALERT_MARKER}])

    class _Result:
        def __init__(self, rc=0, stdout=""):
            self.returncode, self.stdout = rc, stdout
            self.stderr = "SENTINEL-STDERR-1773"

    calls = []                                       # [(argv, env)] for the LAST run only
    state = {"board": terminal_board, "listing": "[]"}

    def fake_run(cmd, capture_output=False, text=False, env=None):
        calls.append((list(cmd), dict(env or {})))
        if cmd[1:3] == ["api", f"repos/{PRIVATE}"]:
            return _Result(0, json.dumps({"private": True}))
        if cmd[1] == "api":
            return _Result(0, state["board"])
        if cmd[1:3] == ["issue", "list"]:
            return _Result(0, state["listing"])
        return _Result(0, "")

    def routed(*sub):
        """(the `-R` argument, the GH_TOKEN) of the recorded `gh <sub…>` command.

        (None, None) when that command was never issued — so a row whose command vanishes REDS
        instead of quietly comparing two absences."""
        for cmd, env in calls:
            if cmd[1:1 + len(sub)] == list(sub):
                return (cmd[cmd.index("-R") + 1] if "-R" in cmd else None), env.get("GH_TOKEN")
        return None, None

    def ambient():
        """The GH_TOKEN seen on the PR census read — the ONE call `main()` makes with `token=None`,
        whatever the harness ambient happens to be (unset locally, set in CI)."""
        for cmd, env in calls:
            if cmd[1] == "api" and "/pulls?" in cmd[2]:
                return env.get("GH_TOKEN")
        return None

    def run_once(alert_repo, alert_token, board=terminal_board, listing="[]"):
        calls.clear()
        state["board"], state["listing"] = board, listing
        os.environ["ALERT_REPO"], os.environ["ALERT_TOKEN"] = alert_repo, alert_token
        with contextlib.redirect_stdout(io.StringIO()):
            return main([f"--policy-file={policy_path}"])

    saved_run = subprocess.run
    saved_env = {k: os.environ.get(k) for k in ("REGISTRY_REPO", "ALERT_REPO", "ALERT_TOKEN")}
    with tempfile.TemporaryDirectory() as tmp:
        policy_path = str(Path(tmp) / "repos.toml")
        Path(policy_path).write_text(f'[repos."{TARGET}"]\nenabled = true\n', encoding="utf-8")
        try:
            subprocess.run = fake_run
            os.environ["REGISTRY_REPO"] = REGISTRY

            rc = run_once(PRIVATE, ALERT_TOK)
            chk("#1773 wiring: the PRIVATE route reaches EVERY command of the alert upsert — the "
                "dedupe listing, the label ensure and the issue create all carry -R ALERT_REPO and "
                "run under ALERT_TOKEN",
                (rc, routed("issue", "list"), routed("label", "create"),
                 routed("issue", "create")),
                (0, (PRIVATE, ALERT_TOK), (PRIVATE, ALERT_TOK), (PRIVATE, ALERT_TOK)))
            # The route governs where the alert LANDS; it must not follow the census read, which is
            # a different repo under a different credential. Pinning both halves is what stops a
            # "just use `repo` everywhere" simplification from silently re-pointing the census.
            api_cmd, api_env = next(((c, e) for c, e in calls
                                     if c[1] == "api" and "/pulls?" in c[2]), (None, {}))
            chk("#1773 wiring: ...while the PR census still reads the POLICY target, and never "
                "borrows the routed credential to do it",
                (api_cmd is not None and TARGET in api_cmd[2],
                 api_env.get("GH_TOKEN") == ALERT_TOK), (True, False))

            rc_edit = run_once(PRIVATE, ALERT_TOK, listing=open_alert)
            chk("#1773 wiring: ...and the EDIT-in-place branch is routed identically (a repoint "
                "that lands only on `issue create` refreshes nothing)",
                (rc_edit, routed("issue", "edit"), routed("issue", "create")),
                (0, (PRIVATE, ALERT_TOK), (None, None)))

            rc_close = run_once(PRIVATE, ALERT_TOK, board="[]", listing=open_alert)
            chk("#1773 wiring: ...and so is the RECOVERY branch — comment and close both target "
                "ALERT_REPO under ALERT_TOKEN, or the alert is closed in the wrong repository",
                (rc_close, routed("issue", "comment"), routed("issue", "close")),
                (0, (PRIVATE, ALERT_TOK), (PRIVATE, ALERT_TOK)))

            rc_half = run_once(PRIVATE, "")
            chk("#1773 wiring: a HALF-CONFIGURED route falls back to the REGISTRY under the "
                "UNCHANGED ambient token — the alert still lands, and never under ALERT_TOKEN",
                (rc_half, routed("issue", "create") == (REGISTRY, ambient()),
                 routed("issue", "create")[1] == ALERT_TOK),
                (0, True, False))

            rc_norepo = run_once("", ALERT_TOK)
            chk("#1773 wiring: ...and so does a token with NO ALERT_REPO beside it",
                (rc_norepo, routed("issue", "create") == (REGISTRY, ambient()),
                 routed("issue", "create")[1] == ALERT_TOK),
                (0, True, False))
        finally:
            subprocess.run = saved_run
            for key, value in saved_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


if __name__ == "__main__":
    sys.exit(main())
