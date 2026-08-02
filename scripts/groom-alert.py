#!/usr/bin/env python3
# Hard-GROOM-failure ops alert (issue #176): the model-access health decision is the LAST step of
# the `groom` job and runs under the default success() guard, so ANY earlier failure — the ledger
# data-only invariant sweep, a target-token mint, the main sweep (dead-lease CAS exhaustion,
# target-repo errors), or the 15-minute timeout — SKIPS it. groom is the ONLY crash-recovery path
# and the ONLY health-alert evaluator, so a persistent groom failure means recovery has stopped AND
# health alerts are no longer evaluated, yet it presents only as a skipped step on a cron nobody
# watches. The standalone groom-alert job calls this script, which keys on needs.groom.result and
# upserts/auto-closes a rolling `ops-alert` issue.
#
# Mirrors plan-alert.py (issue #38) / usage-alert.py (issue #39) hardening exactly:
#  - _alert_route: the private ALERT_REPO is the destination ONLY when ALERT_TOKEN is PRESENT
#    AND that destination is POSITIVELY VERIFIED private (issue #436, matching the #432 round-1
#    hardening of usage-alert/model-health/pat-validity); a half-configured deployment (repo set,
#    token missing), a same-repo misconfiguration, or an unverifiable destination falls back to the
#    registry repo under the ambient token instead of silently failing the private write or
#    silently degrading the private channel to the public registry. The groom-alert body carries
#    NO account handles (it reports only the job RESULT + run link), so the fallback needs no
#    redaction variant — the verification exists so that a misconfigured ALERT_REPO is not read as
#    "private" here, and so a future body change cannot start leaking under a weaker route.
#  - decide(): close ONLY on an explicit `success` — needs.<job>.result also permits `skipped`,
#    which proves nothing about recovery, so an open alert must survive a skipped GROOM.
#  - _gh(check=True): a non-zero gh returncode is surfaced as a sanitized ::warning:: (op +
#    returncode only — never stderr, which can echo request bodies under GH_DEBUG=api) and main()
#    returns non-zero so the step outcome goes red (continue-on-error isolates the groomer).
#  - a SUCCESSFUL `gh issue list` returning MALFORMED JSON (truncation, HTML error page) fails
#    SOFT — sanitized ::warning:: (payload never echoed) and a graceful no-mutation skip, never an
#    uncaught JSONDecodeError crashing the alert; the next scheduled tick retries.
#
# Pure decide()/_alert_route() + a stubbed-gh flow test run under --self-test (registry-selftest).
import ast
import json
import os
import subprocess
import sys

ALERT_LABEL = "ops-alert"
ALERT_TITLE = "⚠️ Scheduled GROOM job is failing — crash-recovery and health alerts are stalled"
# Dedupe keyed on the TITLE alone breaks the moment anyone (human or a later wording tweak) renames
# the open alert — the next failing tick files a duplicate and recovery can't find the issue to
# close. The body carries this stable machine marker; dedupe matches the marker first and falls
# back to the exact title only for pre-marker legacy alerts.
ALERT_MARKER = "<!-- groom-alert:v1 key=groom-job-failure -->"


def _repo_confirmed_private(repo, token):
    """True ONLY on a definitive `"private": true` from GET /repos/{repo} read under the route
    token (issue #436, mirroring usage-alert.py's #432 round-1 helper). FAIL-CLOSED: a failed
    lookup, an unparseable payload, or anything but a literal boolean true reads as NOT private
    and the caller falls back to the registry. The response body is parsed, never echoed."""
    proc = _gh(["api", f"repos/{repo}"], capture=True, token=token)
    if proc.returncode != 0:
        return False
    try:
        payload = json.loads(proc.stdout or "")
    except ValueError:  # json.JSONDecodeError is a ValueError
        return False
    return isinstance(payload, dict) and payload.get("private") is True


def _alert_route(alert_repo, alert_token, registry_repo, confirmed_private=None):
    """(repo, token) for the alert issue — same semantics as usage-alert.py's router (privacy
    d22c + issue #39, hardened for issue #436): the ALERT_REPO destination is selected ONLY when
    ALERT_TOKEN is present, ALERT_REPO is distinct from the public registry repo (case-insensitive
    — a "private route" naming the registry IS the public repo), AND the destination is CONFIRMED
    private by a live GET /repos/{ALERT_REPO} under ALERT_TOKEN. Every other shape falls back to
    the registry repo under the ambient token (token=None means "use the ambient GH_TOKEN").

    Presence of both env vars is CONFIGURATION, not verification (#432 round 1): the pair can name
    the public registry itself or any other public repository, and token presence proves nothing
    about destination visibility. This body carries no account handles, so the fallback is a
    delivery choice rather than a redaction one — but a misconfigured ALERT_REPO must not be
    reported or relied on as a private channel, and a future body change must not inherit a route
    that was never verified.

    `confirmed_private` is injectable for the self-test; the default performs the live lookup,
    consulted only once both halves of the route are set and the same-repo case is excluded."""
    if alert_repo and alert_token:
        same_repo = alert_repo.strip().lower() == (registry_repo or "").strip().lower()
        check = confirmed_private if confirmed_private is not None else _repo_confirmed_private
        if not same_repo and check(alert_repo, alert_token):
            return alert_repo, alert_token
    return registry_repo, None


def decide(groom_result, has_open_alert):
    """Pure decision: 'upsert' | 'close' | 'noop'. Upsert on failure/cancelled; close ONLY on an
    explicit success with an alert open (`skipped` must NOT close — a skipped GROOM is not a
    recovery); anything else is a no-op."""
    if groom_result in ("failure", "cancelled"):
        return "upsert"
    if groom_result == "success" and has_open_alert:
        return "close"
    return "noop"


def _render_body(result, run_url, maintainer):
    return (
        f"{ALERT_MARKER}\n"
        "> 🤖 SPARQ agent — automated ops-alert (issue #176)\n\n"
        f"@{maintainer} the scheduled **GROOM** job ended `{result}`. groom is the ONLY "
        "crash-recovery path (dead-lease release, orphaned-PR/exhausted-attempt repair) AND it "
        "hosts the ONLY model-access health-alert evaluator as its final step — the default "
        "`success()` guard means that evaluator was **skipped** by this failure, so health "
        "alerts are not being raised or closed either.\n\n"
        "Likely cause: the ledger data-only invariant sweep, a target-token mint, the main sweep "
        "(dead-lease CAS exhaustion / target-repo errors), or the 15-minute timeout. Check the "
        "run below; the next scheduled tick retries automatically and this alert auto-closes once "
        "a GROOM succeeds.\n\n"
        f"- Failing run: {run_url}\n"
    )


def _gh(args, capture=False, token=None, check=False):
    # Sanitized fail-loud wrapper: op + returncode only — never stderr (GH_DEBUG=api can echo
    # request bodies) and never argument content beyond the gh subcommand words.
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    result = subprocess.run(["gh"] + args, capture_output=capture, text=True, env=env)
    if check and result.returncode != 0:
        print(f"::warning::groom-alert: gh {args[0]} {args[1] if len(args) > 1 else ''} "
              f"failed (rc={result.returncode})")
    return result


def main():
    registry_repo = os.environ["REGISTRY_REPO"]
    repo, token = _alert_route(
        os.environ.get("ALERT_REPO"), os.environ.get("ALERT_TOKEN"), registry_repo)
    result = os.environ.get("GROOM_RESULT", "")
    run_url = os.environ.get("RUN_URL", "")
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")

    # --limit 100: the `ops-alert` label is SHARED with the plan-failure alert, the
    # account-availability alert, and anything else ops-flavoured; a 20-issue window could push
    # this alert out of the dedupe scan (duplicate on failure, uncloseable on recovery). 100
    # comfortably exceeds any plausible open ops-alert count; the marker/title match below still
    # scans every returned row.
    listed = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", "open",
                  "--json", "number,title,body", "--limit", "100"],
                 capture=True, token=token, check=True)
    if listed.returncode != 0:
        # Fail loud: without the list we can neither dedupe an upsert nor prove recovery — go red
        # (the job's continue-on-error keeps the groomer isolated).
        return 1
    # A SUCCESSFUL gh call can still hand back malformed JSON (truncated output, an HTML error
    # page, a proxy interposing). That must degrade, not crash the whole alert: without a parseable
    # list we can neither dedupe nor prove recovery, so warn (sanitized — never echo the payload,
    # which is remote/user-controlled) and skip this tick; the next tick retries.
    try:
        found = json.loads(listed.stdout or "[]")
        if not isinstance(found, list):
            raise ValueError("expected a JSON array")
    except ValueError:  # json.JSONDecodeError is a ValueError
        print("::warning::groom-alert: gh issue list succeeded but returned unparseable "
              "JSON — skipping this tick (no dedupe/recovery data; next tick retries)")
        return 0
    # Match the stable body MARKER first (survives a retitled alert), exact title second (legacy
    # alerts filed before the marker existed).
    num = next((i["number"] for i in found if ALERT_MARKER in (i.get("body") or "")), None)
    if num is None:
        num = next((i["number"] for i in found if i.get("title") == ALERT_TITLE), None)

    action = decide(result, num is not None)
    if action == "upsert":
        _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", "d73a4a",
             "--description", "Autonomous ops alert (maintainer action)"],
            capture=True, token=token)  # idempotent; pre-existing label is fine
        body = _render_body(result, run_url, maintainer)
        if num:
            wrote = _gh(["issue", "edit", str(num), "-R", repo, "--body", body],
                        capture=True, token=token, check=True)
        else:
            wrote = _gh(["issue", "create", "-R", repo, "--title", ALERT_TITLE,
                         "--label", ALERT_LABEL, "--body", body],
                        capture=True, token=token, check=True)
        if wrote.returncode != 0:
            return 1
        print("::warning::groom-alert: GROOM job {} — maintainer alerted".format(result))
        return 0
    if action == "close":
        commented = _gh(["issue", "comment", str(num), "-R", repo, "--body",
                         "✅ Recovered — the scheduled GROOM job succeeded again. Auto-closing."],
                        capture=True, token=token, check=True)
        closed = _gh(["issue", "close", str(num), "-R", repo],
                     capture=True, token=token, check=True)
        if commented.returncode != 0 or closed.returncode != 0:
            return 1
        print("groom-alert: GROOM recovered — closed the alert")
        return 0
    print("groom-alert: GROOM result={} — nothing to do".format(result or "unknown"))
    return 0


def _test_alert_route_contract(chk):
    """#1021: the router's PROSE must not promise more than the router ENFORCES, and this module
    must carry exactly ONE copy of the router.

    What `_alert_route` tests of ALERT_TOKEN is its TRUTHINESS. The token is then used to READ
    `GET /repos/{ALERT_REPO}` — which establishes the destination's VISIBILITY (#432 r1 / #436),
    not the token's ability to write an issue there. So a comment saying the private destination is
    selected only once the token has been shown able to write there states a strictly stronger
    contract than the code enforces. #1021 found that one sentence copied verbatim across six alert
    scripts, where any single copy could drift back while the suite stayed green on the others —
    the #945 mutually-masking-duplicate shape applied to prose.

    Guard 1 was CONTAINMENT in review round 1 and that was unsound, which round 2 measured: pinning
    the approved sentences proves only that they are PRESENT, so a contradictory claim could simply
    be added beside them — `ALERT_TOKEN has issue-creation privileges at ALERT_REPO` is outside
    every enumerated phrasing, so the tripwire returned `[]` too and the whole suite stayed green
    with the false contract restored. A guard that only forbids what it can enumerate cannot be the
    load-bearing one. So guard 1 is now CLOSED — exact equality over the whole governed text:

      1. CANONICAL PROSE, pinned CLOSED (phrasing-independent, load-bearing). The router's ENTIRE
         docstring, and the ENTIRE route comment on this script's step in groom.yml, are pinned by
         EQUALITY against the verbatim copies below (whitespace-flattened, re-wrapping is free).
         Adding a sentence, dropping one, or rewording one reds this file whatever words it
         chooses — no list of banned phrasings is consulted, so no unanticipated phrasing escapes.
      2. ENUMERATED TRIPWIRE (phrasing-dependent, defence in depth). The whole module outside this
         function — which is everything guard 1 pins PLUS the prose it does not reach — is scanned
         for a fixed list of write-capability phrasings, scoped to ALERT_TOKEN on EITHER side of
         the phrase, catching a stronger claim that lands in an UNPINNED comment or a rendered
         body. It is a tripwire, not a proof, and the row that reports it says so rather than
         promising the semantic property.

    The tripwire census scans this module with THIS FUNCTION'S OWN LINES REMOVED, so the banned
    phrases and the detector fixtures can be written literally below without the census matching
    itself; that exclusion is derived from the parsed AST, and its own row reds if it cannot find
    this function. Every row below is independently killable: edit a pinned block on one side only,
    weaken the pin back to containment, blunt the claim detector so it cannot fire, drop a phrasing
    or one scoping direction from it, widen its scope so it fires on unrelated prose, paste a
    second router into this file, reintroduce a listed claim anywhere outside this function,
    rename or move the workflow step the comment sits on, add a real capability probe to the
    router, or drop the token half of the router's guard."""
    # GUARD 1 — the router's docstring, copied here VERBATIM and compared by EQUALITY (both sides
    # whitespace-flattened, so re-wrapping the source is free and every other edit is not).
    canonical_route_doc = """
    (repo, token) for the alert issue — same semantics as usage-alert.py's router (privacy
    d22c + issue #39, hardened for issue #436): the ALERT_REPO destination is selected ONLY when
    ALERT_TOKEN is present, ALERT_REPO is distinct from the public registry repo (case-insensitive
    — a "private route" naming the registry IS the public repo), AND the destination is CONFIRMED
    private by a live GET /repos/{ALERT_REPO} under ALERT_TOKEN. Every other shape falls back to
    the registry repo under the ambient token (token=None means "use the ambient GH_TOKEN").

    Presence of both env vars is CONFIGURATION, not verification (#432 round 1): the pair can name
    the public registry itself or any other public repository, and token presence proves nothing
    about destination visibility. This body carries no account handles, so the fallback is a
    delivery choice rather than a redaction one — but a misconfigured ALERT_REPO must not be
    reported or relied on as a private channel, and a future body change must not inherit a route
    that was never verified.

    `confirmed_private` is injectable for the self-test; the default performs the live lookup,
    consulted only once both halves of the route are set and the same-repo case is excluded.
    """
    # GUARD 1, second governed consumer — groom.yml's route comment, which no module scan can
    # reach. Copied here VERBATIM (leading `#` and indentation stripped) and pinned by EQUALITY.
    canonical_workflow_comment = """
    Privacy routing (locked decision 22c, issue #39): scripts/groom-alert.py routes to a
    maintainer-set PRIVATE ALERT_REPO only when ALERT_TOKEN is PRESENT, ALERT_REPO differs
    from this registry, and that destination is CONFIRMED private by a live GET /repos read
    (#432 r1 / #436); otherwise the registry repo under the ambient token. The body carries
    NO account handles (it reports only the groom job RESULT + run link), so that fallback
    is safe.
    #1021: presence and VISIBILITY are what is checked. The token's write capability at
    ALERT_REPO is never probed, so this comment must not say that it is.
    """

    def flat(text):
        """One whitespace-collapsed line — the normal form both sides of a guard-1 pin are compared
        in, so re-wrapping or re-indenting the governed prose is free and rewording it is not."""
        return " ".join((text or "").split())

    def route_comment(text, script):
        """The `#` comment block immediately above the ALERT_REPO env line of the ONE step in
        workflow `text` that RUNS `script` — a `python3 ... <script>` line, not a mere mention of
        it, because dispatch.yml's checkout-step comment names the script in prose and the first
        version of this locator bound the WRONG step through it. FAIL CLOSED: raises unless exactly
        one such step exists, so renaming the step, moving the call site or deleting the env line
        reds this file instead of quietly pinning nothing. A step with no comment block yields ""
        — which is not the canonical text either, so deleting the comment reds too."""
        rows = text.splitlines()
        step_starts = [i for i, row in enumerate(rows) if row.strip().startswith("- name:")]
        hits = []
        for index, row in enumerate(rows):
            if not row.strip().startswith("ALERT_REPO:"):
                continue
            end = next((start for start in step_starts if start > index), len(rows))
            if any("python3 " in below and script in below for below in rows[index:end]):
                hits.append(index)
        if len(hits) != 1:
            raise ValueError(
                f"expected exactly ONE workflow step running {script} beside an ALERT_REPO env "
                f"line, found {len(hits)} — the route comment cannot be pinned (fail closed)")
        block, cursor = [], hits[0] - 1
        while cursor >= 0 and rows[cursor].strip().startswith("#"):
            block.insert(0, rows[cursor].strip().lstrip("#"))
            cursor -= 1
        return flat(" ".join(block))

    # GUARD 2 — ENUMERATED, and kept inside this function so the census's own exclusion covers
    # these literals. The list is deliberately identical in every alert script carrying this guard.
    # `capable of writing` is NOT on it: the honest prose in these routers quotes that phrase in
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
        that scoping were measured while writing this. Unscoped, the detector flagged
        groom-mint-alert.py's unrelated "anyone with write access" note about workflow_dispatch
        triggers — a false positive. Scoped, it still caught usage-alert.py's rendered maintainer
        hint, which told the operator the private route needs a token that could write to the
        destination — a true one, fixed in the same change."""
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
    # census below reports `[]` whatever it is pointed at — an instrument that cannot fire has
    # said nothing (AGENTS.md AUTHOR pre-flight #1, which is how this hole was found).
    chk("#1021: the claim detector FIRES on route prose that makes the claim, including when the "
        "claim wraps onto the line after ALERT_TOKEN",
        claims_about_the_route("the private ALERT_REPO is the destination\n"
                               "ONLY when ALERT_TOKEN\ncan write there; otherwise "
                               "the registry"),
        ["can write there"])
    chk("#1021: ... and on the SYNONYMS of that claim, not just the one wording #1021 removed",
        (claims_about_the_route("ALERT_TOKEN has permission to write there"),
         claims_about_the_route("the route needs an ALERT_TOKEN authorized to create issues in "
                                "the private repo")),
        (["permission to write"], ["authorized to create"]))
    chk("#1021: ... and when the capability is stated BEFORE ALERT_TOKEN names it (the scope "
        "window reaches both ways)",
        claims_about_the_route("the destination is private, so a credential able to write there "
                               "is required; that credential is ALERT_TOKEN"),
        ["able to write"])
    chk("#1021: ... and stays SILENT on a write-capability sentence about something that is not "
        "the route",
        claims_about_the_route("workflow_dispatch can be run from any ref by anyone with write "
                               "access, so it is excluded from the tick allowlist"), [])
    chk("#1021: ... and on one where ALERT_TOKEN appears but is far out of scope (a widened "
        "window would swallow this and make the census fire on unrelated prose)",
        claims_about_the_route("ALERT_TOKEN names the private route. " + "Unrelated prose. " * 12
                               + "The runner needs write access to the checkout."), [])
    source = open(__file__, encoding="utf-8").read()
    definitions = [node for node in ast.walk(ast.parse(source))
                   if isinstance(node, ast.FunctionDef)]
    routers = [node for node in definitions if node.name == "_alert_route"]
    chk("#1021: exactly ONE _alert_route definition in this module (a second copy makes each "
        "copy individually unkillable)", len(routers), 1)
    chk("#1021: the router's docstring is EXACTLY the canonical contract — pinned by EQUALITY, so "
        "the governed prose is CLOSED: nothing can be added beside the approved sentences",
        flat(ast.get_docstring(routers[0]) or ""), flat(canonical_route_doc))
    # NON-VACUITY of that equality, and of its CLOSEDNESS specifically. `flat(x) == flat(y)`
    # would also hold with both sides empty, and round 1's containment form passed every input
    # here except the appended one — which is the exact sentence review round 2 showed surviving,
    # worded OUTSIDE `phrasings` on purpose so the tripwire cannot be what catches it. The
    # dropped-clause input asserts its anchor occurs exactly ONCE first: a `.replace()` that
    # matched nothing would leave that row comparing the text with itself (mutation-run hygiene).
    anchor = (
        "Presence of both env vars is CONFIGURATION, not verification (#432 round 1): the pair")
    dropped = canonical_route_doc.replace(anchor, "")
    appended = canonical_route_doc + (
        "\n    ALERT_TOKEN has issue-creation privileges at ALERT_REPO.\n")
    chk("#1021: ... and that equality REJECTS an appended capability claim no phrasing list "
        "anticipates, a dropped clause, and an empty docstring — while ACCEPTING a re-wrapped "
        "copy, so it pins the WORDS and not the line breaks",
        (canonical_route_doc.count(anchor),
         flat(appended) == flat(canonical_route_doc),
         flat(dropped) == flat(canonical_route_doc),
         flat("") == flat(canonical_route_doc),
         flat("\n\n  ".join(canonical_route_doc.split())) == flat(canonical_route_doc)),
        (1, False, False, False, True))
    # The WORKFLOW consumer. groom.yml's route comment restates this contract to whoever reads
    # the step, and no scan of this module can reach it — round 2 named that as the remaining
    # ungoverned prose. It is pinned the same CLOSED way, through the same normal form.
    # VALIDATE THE EXTRACTOR FIRST: a wrong locator returns "" or the wrong block, which would make
    # the live pin below red for the wrong reason and, once "fixed" by re-pinning, green forever.
    # The synthetic step proves it finds the block, that ONE extra comment line CHANGES what it
    # returns, and that a missing or duplicated step REFUSES instead of pinning nothing.
    step_1021 = ("      - name: alert step\n"
                 "        env:\n"
                 "          # first comment line\n"
                 "          # second comment line\n"
                 "          ALERT_REPO: x\n"
                 "        run: python3 registry/scripts/zzz-1021.py --self-test\n")

    def refused_1021(text, script):
        try:
            route_comment(text, script)
        except ValueError:
            return "refused"
        return "returned"

    chk("#1021: the workflow-comment extractor FIRES on the block above the route's env line, "
        "and an extra capability line there CHANGES what it returns (which is what makes pinning "
        "it by equality forbid one)",
        (route_comment(step_1021, "scripts/zzz-1021.py"),
         route_comment(step_1021.replace(
             "          # second comment line\n",
             "          # second comment line\n"
             "          # ALERT_TOKEN has issue-creation privileges at ALERT_REPO\n"),
             "scripts/zzz-1021.py") == "first comment line second comment line",
         route_comment(step_1021.replace("          # first comment line\n", "")
                       .replace("          # second comment line\n", ""),
                       "scripts/zzz-1021.py")),
        ("first comment line second comment line", False, ""))
    chk("#1021: ... and REFUSES rather than pinning nothing when the step that runs the script is "
        "renamed away, duplicated, or only MENTIONS the script in prose — a skip here would disarm "
        "the workflow pin silently, and prose-matching bound the wrong step when this was written",
        (refused_1021(step_1021, "scripts/not-a-step-1021.py"),
         refused_1021(step_1021 + step_1021, "scripts/zzz-1021.py"),
         refused_1021(step_1021.replace(
             "        run: python3 registry/scripts/zzz-1021.py --self-test\n",
             "        # the alert logic lives in scripts/zzz-1021.py, checked out above\n"),
             "scripts/zzz-1021.py"),
         refused_1021(step_1021, "scripts/zzz-1021.py")),
        ("refused", "refused", "refused", "returned"))
    # The live pin. The alert JOB sparse-checks-out only this script, so on a tick there is no
    # workflow tree to read and this must not red every run; pr-gate's full checkout is where it is
    # enforced, and a PR is the only way this comment can change. Discriminate on the DIRECTORY,
    # not on the file: a renamed or deleted groom.yml with the directory present raises out of the
    # `open` below, which is the fail-closed outcome, not a skipped pin.
    workflows_1021 = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".github", "workflows")
    sparse_1021 = "not applicable: this checkout carries no .github/workflows tree"

    def workflow_pin_verdict(tree_present):
        """The pinned route comment when a workflow tree is present, else an explicit
        not-applicable verdict. Split out so the sparse arm is EXERCISED below: pr-gate runs a FULL
        checkout, so that arm is otherwise never executed anywhere this suite runs, and an
        unexecuted arm is where a mutant survives (AGENTS.md AUTHOR pre-flight #1)."""
        if not tree_present:
            return sparse_1021
        with open(os.path.join(workflows_1021, "groom.yml"), encoding="utf-8") as handle:
            return route_comment(handle.read(), "scripts/groom-alert.py")

    chk("#1021: the not-applicable arm returns an explicit verdict and NEVER the pinned text, so "
        "a sparse tick cannot be mistaken for a satisfied pin",
        (workflow_pin_verdict(False),
         workflow_pin_verdict(False) == flat(canonical_workflow_comment)),
        (sparse_1021, False))
    # The verdict is reported TOGETHER WITH a second, INDEPENDENT read of the filesystem, and the
    # row emits on BOTH paths. Without that pairing the skip is fail-open: forcing the branch to
    # skip while the tree IS present just dropped the pin and left the suite green — a measured
    # survivor of the first version of this row (AGENTS.md pre-flight #3, conditionally inert).
    chk("#1021: groom.yml's route comment on the step that runs THIS script is EXACTLY the "
        "canonical text — the workflow prose is closed by the same pin as the docstring, so a "
        "capability claim added there reds this file too; and the pin is never SILENTLY "
        "skipped, only explicitly not-applicable on a checkout with no workflow tree at all",
        (workflow_pin_verdict(os.path.isdir(workflows_1021)), os.path.isdir(workflows_1021)),
        (flat(canonical_workflow_comment), True) if os.path.isdir(workflows_1021)
        else (sparse_1021, False))
    census = [node for node in definitions if node.name == "_test_alert_route_contract"]
    chk("#1021: the prose census can locate its own body to exclude it from the scan",
        len(census), 1)
    # The scan excludes THIS function's own lines — derived from the parsed AST, not hard-coded —
    # so the banned phrases and the fixtures above can be written literally without self-matching.
    lines = source.splitlines()
    scanned = "\n".join(lines[:census[0].lineno - 1] + lines[census[0].end_lineno:])
    # The verdict is pinned TOGETHER WITH two properties of the text it was measured on, because
    # `[]` is also what an empty input returns: a census pointed at nothing would otherwise read
    # exactly like a clean module (AGENTS.md pre-flight #3's conditionally-inert mutant, which
    # survived the first version of this row). `def _alert_route(` proves the scan covered the
    # module; the ABSENCE of this function's own nested helper name proves the exclusion really
    # removed this function and not some other span.
    chk("#1021: none of the ENUMERATED write-capability phrasings survives in this module's "
        "alert-route prose — a tripwire over a fixed list, not a proof that no stronger claim can "
        "be worded (the canonical-contract row above is that guard) — measured over a scan that "
        "demonstrably covers the router and excludes only this function",
        (claims_about_the_route(scanned), "def _alert_route(" in scanned,
         "claims_about_the_route" in scanned),
        ([], True, False))
    # Behavioural statement of the contract the prose is now allowed to make. These literals appear
    # nowhere else in this harness, so a substituted value cannot collide with a fixture's.
    chk("#1021: PRESENCE + CONFIRMED-private, not capability — a credential that obviously "
        "cannot write anything still selects ALERT_REPO, exactly as a good one does",
        _alert_route("org/priv-1021", "not-a-credential-1021", "org/reg-1021",
                     confirmed_private=lambda r, t: True),
        ("org/priv-1021", "not-a-credential-1021"))
    probe_1021 = []
    chk("#1021: ... and an EMPTY ALERT_TOKEN never does, with the visibility check left uncalled",
        (_alert_route("org/priv-1021", "", "org/reg-1021",
                      confirmed_private=lambda r, t: probe_1021.append(r) or True),
         probe_1021),
        (("org/reg-1021", None), []))


def _self_test():
    ok = True

    def chk(n, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {n}: {got} (want {want})")

    # Routing (mirrors usage-alert.py's audited matrix, incl. the #432 round-1 / issue #436
    # positive private-destination verification: configuration alone never selects ALERT_REPO).
    vis_calls = []
    chk("route: repo+token+CONFIRMED private -> private + token",
        _alert_route("org/private", "tok", "org/registry",
                     confirmed_private=lambda r, t: vis_calls.append((r, t)) or True),
        ("org/private", "tok"))
    chk("route: the visibility check runs against the ALERT repo under the ALERT token",
        vis_calls, [("org/private", "tok")])
    chk("route: ALERT_REPO == REGISTRY_REPO -> registry fallback (the registry is never private)",
        _alert_route("org/registry", "tok", "org/registry",
                     confirmed_private=lambda r, t: True), ("org/registry", None))
    chk("route: same-repo rejection is case-insensitive (GitHub repo names are)",
        _alert_route("Org/Registry", "tok", "org/registry",
                     confirmed_private=lambda r, t: True), ("org/registry", None))
    chk("route: UNCONFIRMED visibility (public repo or failed lookup) -> registry, fail closed",
        _alert_route("org/other-public", "tok", "org/registry",
                     confirmed_private=lambda r, t: False), ("org/registry", None))
    half_calls = []
    chk("route: repo but NO token -> registry fallback, and NO visibility call (#39)",
        (_alert_route("org/private", "", "org/registry",
                      confirmed_private=lambda r, t: half_calls.append(r) or True),
         half_calls),
        (("org/registry", None), []))
    chk("route: repo but None token -> registry fallback",
        _alert_route("org/private", None, "org/registry",
                     confirmed_private=lambda r, t: True), ("org/registry", None))
    chk("route: no repo -> registry",
        _alert_route("", "tok", "org/registry",
                     confirmed_private=lambda r, t: True), ("org/registry", None))
    # The router's PROSE must not outrun what the router ENFORCES (#1021).
    _test_alert_route_contract(chk)
    # decide(): success-only closure (`skipped` must not close), upsert on hard fail
    chk("decide: failure -> upsert", decide("failure", False), "upsert")
    chk("decide: failure w/ open -> upsert", decide("failure", True), "upsert")
    chk("decide: cancelled -> upsert", decide("cancelled", True), "upsert")
    chk("decide: success + open -> close", decide("success", True), "close")
    chk("decide: success + none -> noop", decide("success", False), "noop")
    chk("decide: SKIPPED + open -> noop (not a recovery)", decide("skipped", True), "noop")
    chk("decide: empty result + open -> noop", decide("", True), "noop")
    # body: run link + maintainer mention, no secrets/handles by construction
    body = _render_body("failure", "https://example.test/run/1", "jeswr")
    chk("body carries run url + mention",
        ("https://example.test/run/1" in body, "@jeswr" in body), (True, True))
    # every rendered body must carry the stable dedupe marker.
    chk("body carries the stable dedupe marker", ALERT_MARKER in body, True)
    # Stubbed-gh flow: full main() paths with a fake subprocess.run that records the COMPLETE
    # command and env per call, and can inject a failure for any individual gh subcommand — so
    # repo/token wiring and every mutation return-code check are asserted, not assumed.
    import contextlib
    import io

    class _Result:
        def __init__(self, rc=0, stdout=""):
            self.returncode = rc
            self.stdout = stdout
            self.stderr = "SENTINEL-STDERR"

    calls = []          # [(cmd_list, env_dict)]
    responses = {}      # (sub, sub2) -> _Result

    def fake_run(cmd, capture_output=False, text=False, env=None):
        calls.append((list(cmd), dict(env or {})))
        return responses.get(tuple(cmd[1:3]), _Result())

    def find(sub):
        return next(((c, e) for c, e in calls if tuple(c[1:3]) == sub), (None, None))

    def subs():
        return [tuple(c[1:3]) for c, _e in calls]

    real_run = subprocess.run
    base_env = {"REGISTRY_REPO": "org/registry", "GROOM_RESULT": "", "RUN_URL": "u",
                "MAINTAINER_HANDLE": "m", "ALERT_REPO": "", "ALERT_TOKEN": ""}

    def run_main(groom_result, list_json="[]", fail=(), alert_repo="", alert_token="",
                 visibility='{"private": true}'):
        calls.clear()
        responses.clear()
        responses[("issue", "list")] = _Result(1 if ("issue", "list") in fail else 0, list_json)
        # The route's live GET /repos/{ALERT_REPO}: private by default so the pre-#436 flow
        # assertions keep exercising the private route; `visibility` injects the other shapes.
        if alert_repo:
            responses[("api", f"repos/{alert_repo}")] = _Result(0, visibility)
        for key in fail:
            if key != ("issue", "list"):
                responses[key] = _Result(1)
        os.environ.update(base_env)
        os.environ["GROOM_RESULT"] = groom_result
        os.environ["ALERT_REPO"] = alert_repo
        os.environ["ALERT_TOKEN"] = alert_token
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main()
        return rc, buf.getvalue()

    subprocess.run = fake_run
    try:
        rc_a, _ = run_main("failure")
        chk("flow: failure + no open -> create", (rc_a, ("issue", "create") in subs()), (0, True))
        open_json = json.dumps([{"number": 7, "title": ALERT_TITLE}])
        rc_b, _ = run_main("failure", open_json)
        chk("flow: failure + open -> edit not create",
            (rc_b, ("issue", "edit") in subs(), ("issue", "create") in subs()), (0, True, False))
        rc_c, _ = run_main("success", open_json)
        chk("flow: success + open -> comment+close",
            (rc_c, ("issue", "comment") in subs(), ("issue", "close") in subs()), (0, True, True))
        rc_d, _ = run_main("skipped", open_json)
        chk("flow: skipped + open -> NO mutation",
            (rc_d, [s for s in subs() if s != ("issue", "list")]), (0, []))
        rc_e, out_e = run_main("failure", fail=(("issue", "list"),))
        chk("flow: list failure -> rc=1 + sanitized warning",
            (rc_e, "::warning::" in out_e, "SENTINEL-STDERR" in out_e), (1, True, False))
        # A SUCCESSFUL list handing back malformed JSON must fail SOFT — warning + graceful
        # no-mutation skip (rc=0, no exception), and the payload is never echoed.
        rc_m, out_m = run_main("failure", "SENTINEL-MALFORMED-PAYLOAD {not json")
        chk("flow: malformed list JSON -> warning + graceful skip, payload not echoed",
            (rc_m, "::warning::" in out_m, "SENTINEL-MALFORMED-PAYLOAD" in out_m,
             [s for s in subs() if s != ("issue", "list")]),
            (0, True, False, []))
        # ...and valid-JSON-but-not-a-list (e.g. a gh/API error OBJECT) takes the same soft path.
        rc_n, out_n = run_main("success", '{"message": "sentinel-error-object"}')
        chk("flow: non-array list JSON -> warning + graceful skip, payload not echoed",
            (rc_n, "::warning::" in out_n, "sentinel-error-object" in out_n,
             [s for s in subs() if s != ("issue", "list")]),
            (0, True, False, []))
        # EVERY mutation's returncode must fail the run (not just the list's).
        for failing in (("issue", "create"), ("issue", "edit")):
            rc_f, out_f = run_main("failure", open_json if failing == ("issue", "edit") else "[]",
                                   fail=(failing,))
            chk(f"flow: {failing[0]} {failing[1]} failure -> rc=1 + warning",
                (rc_f, "::warning::" in out_f), (1, True))
        for failing in (("issue", "comment"), ("issue", "close")):
            rc_g, out_g = run_main("success", open_json, fail=(failing,))
            chk(f"flow: {failing[0]} {failing[1]} failure -> rc=1 + warning",
                (rc_g, "::warning::" in out_g), (1, True))
        # repo/token WIRING. Private route: every command targets ALERT_REPO and runs under
        # ALERT_TOKEN; fallback route: registry repo under the ambient token.
        run_main("failure", alert_repo="org/private", alert_token="sentinel-alert-tok")
        create_cmd, create_env = find(("issue", "create"))
        chk("wiring: private route -> -R org/private under ALERT_TOKEN",
            (create_cmd is not None and create_cmd[create_cmd.index("-R") + 1],
             (create_env or {}).get("GH_TOKEN")),
            ("org/private", "sentinel-alert-tok"))
        ambient = os.environ.get("GH_TOKEN")  # whatever the harness ambient is (None locally, set in CI)
        run_main("failure", alert_repo="org/private", alert_token="")
        create_cmd2, create_env2 = find(("issue", "create"))
        chk("wiring: half-config -> -R org/registry under UNCHANGED ambient token",
            (create_cmd2 is not None and create_cmd2[create_cmd2.index("-R") + 1],
             (create_env2 or {}).get("GH_TOKEN") == ambient,
             (create_env2 or {}).get("GH_TOKEN") == "sentinel-alert-tok"),
            ("org/registry", True, False))
        # #436 END-TO-END: a fully-configured but UNVERIFIABLE destination must not become the
        # alert repo — the alert still lands (fail closed on privacy, not on delivery), on the
        # registry, and never under the alert token.
        run_main("failure", alert_repo="org/public", alert_token="sentinel-alert-tok",
                 visibility='{"private": false}')
        create_pub, env_pub = find(("issue", "create"))
        chk("wiring: PUBLIC ALERT_REPO -> registry fallback, alert still lands, no ALERT_TOKEN",
            (create_pub is not None and create_pub[create_pub.index("-R") + 1],
             (env_pub or {}).get("GH_TOKEN") == "sentinel-alert-tok",
             ("api", "repos/org/public") in subs()),
            ("org/registry", False, True))
        # ...and a same-repo ALERT_REPO is rejected WITHOUT spending a visibility probe.
        run_main("failure", alert_repo="ORG/Registry", alert_token="sentinel-alert-tok")
        create_same, env_same = find(("issue", "create"))
        chk("wiring: ALERT_REPO == REGISTRY_REPO -> registry fallback, NO visibility probe",
            (create_same is not None and create_same[create_same.index("-R") + 1],
             (env_same or {}).get("GH_TOKEN") == "sentinel-alert-tok",
             [s for s in subs() if s[0] == "api"]),
            ("org/registry", False, []))
        # _repo_confirmed_private itself: True ONLY on a definitive `"private": true`; every
        # failure shape is False (fail closed), and the lookup runs under the ROUTE token.
        vis_seen = []

        def vis_gh(rc, stdout):
            def run(cmd, capture_output=False, text=False, env=None):
                vis_seen.append((list(cmd), (env or {}).get("GH_TOKEN")))
                return _Result(rc, stdout)
            return run

        subprocess.run = vis_gh(0, json.dumps({"private": True, "full_name": "org/private"}))
        chk("visibility: definitive private=true -> True, GET repos/{repo} under the route token",
            (_repo_confirmed_private("org/private", "route-tok"), vis_seen[0]),
            (True, (["gh", "api", "repos/org/private"], "route-tok")))
        subprocess.run = vis_gh(0, json.dumps({"private": False}))
        chk("visibility: a PUBLIC destination -> False (fail closed)",
            _repo_confirmed_private("org/pub", "t"), False)
        subprocess.run = vis_gh(1, "")
        chk("visibility: failed lookup -> False (fail closed, never assumed private)",
            _repo_confirmed_private("org/private", "t"), False)
        subprocess.run = vis_gh(0, "SENTINEL-NOT-JSON")
        chk("visibility: unparseable payload -> False (fail closed)",
            _repo_confirmed_private("org/private", "t"), False)
        subprocess.run = vis_gh(0, json.dumps({"private": "true"}))
        chk("visibility: anything but a literal private=true bool -> False",
            _repo_confirmed_private("org/private", "t"), False)
        subprocess.run = fake_run
        # the dedupe scan uses --limit 100 and matches a title past position 20.
        crowd = [{"number": i, "title": f"unrelated ops alert {i}"} for i in range(25)]
        rc_h, _ = run_main("failure", json.dumps(crowd + [{"number": 99, "title": ALERT_TITLE}]))
        list_cmd, _list_env = find(("issue", "list"))
        edit_cmd, _ = find(("issue", "edit"))
        chk("dedupe: --limit 100 + title found past position 20 -> edit #99, no create",
            (rc_h, "100" in (list_cmd or []), ("issue", "create") in subs(),
             edit_cmd is not None and "99" in edit_cmd),
            (0, True, False, True))
        # a RENAMED alert (same underlying failure, retitled by a human or a wording tweak) must
        # still dedupe via the body marker — edit the open issue, never file a twin.
        renamed = json.dumps([{"number": 55, "title": "GROOM broke again (renamed by maintainer)",
                               "body": "legacy prose\n" + ALERT_MARKER + "\nmore prose"}])
        rc_i, _ = run_main("failure", renamed)
        edit_i, _ = find(("issue", "edit"))
        chk("dedupe: RENAMED alert -> marker match edits #55, no create",
            (rc_i, ("issue", "create") in subs(), edit_i is not None and "55" in edit_i),
            (0, False, True))
        # ...and recovery must find the renamed alert too (close via marker, not title).
        rc_j, _ = run_main("success", renamed)
        close_j, _ = find(("issue", "close"))
        chk("close: RENAMED alert -> marker match closes #55",
            (rc_j, close_j is not None and "55" in close_j), (0, True))
        # Legacy fallback: a pre-marker alert (exact title, marker-less body) still dedupes.
        legacy = json.dumps([{"number": 8, "title": ALERT_TITLE, "body": "old body, no marker"}])
        rc_k, _ = run_main("failure", legacy)
        edit_k, _ = find(("issue", "edit"))
        chk("dedupe: legacy title-only alert -> fallback edits #8, no create",
            (rc_k, ("issue", "create") in subs(), edit_k is not None and "8" in edit_k),
            (0, False, True))
        # The list request must fetch `body` or the marker match is silently vacuous.
        list_cmd_k, _ = find(("issue", "list"))
        chk("dedupe: list fetches number,title,body",
            "number,title,body" in (list_cmd_k or []), True)
    finally:
        subprocess.run = real_run
        for key in base_env:
            os.environ.pop(key, None)
    print("groom-alert self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
