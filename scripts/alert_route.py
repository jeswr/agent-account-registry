#!/usr/bin/env python3
# Shared ops-alert DESTINATION ROUTER — the single home for locked decision 22c / issue #39.
#
# Issue #591: this decision was written out by hand in every ops-alert emitter. Five copies of one
# locked decision drift apart silently, and #958 measured the shape directly — a literal with four
# independent definitions had two consumers blind to a repoint, one of them fail-open. This module
# is the one definition; emitters load it by path and bind their private `_alert_route` name to it.
#
# THE DECISION (22c / #39). The maintainer-set PRIVATE `ALERT_REPO` is the destination ONLY when an
# `ALERT_TOKEN` that can write there is also set. A half-configured deployment (repo set, token
# missing) falls back to the PUBLIC registry repo under the ambient workflow token rather than
# silently losing the alert to a write that cannot succeed. `token=None` means "use the ambient
# GH_TOKEN" — it is NOT "no token".
#
# TWO ENTRYPOINTS, deliberately not one. They are different decisions, not one decision with a
# flag, and collapsing them would silently change semantics in one direction or the other:
#
#   alert_route()          -> (repo, token)          for bodies that carry NO account handles and
#                                                    no compositional fleet disclosure (a job
#                                                    RESULT + a run link). The public fallback is
#                                                    safe, so configuration is the whole test.
#   alert_route_verified() -> (repo, token, redact)  for bodies that DO enumerate accounts or
#                                                    credential validity (issues #107/#204). Here
#                                                    configuration is NOT verification: the route
#                                                    must also be a DIFFERENT repo from the public
#                                                    registry and CONFIRMED private by a live
#                                                    lookup. Every other shape falls back public
#                                                    with redact=True.
#
# Consumers load this by PATH (`importlib.util.spec_from_file_location`), because the alert jobs
# sparse-check-out an explicit file list rather than the whole tree. That makes the sparse-checkout
# list part of this module's contract, so `sparse_checkout_verdict` below asserts it against the
# LIVE workflows — an emitter migrated here without its `scripts/alert_route.py` line would
# otherwise die at import time inside a `continue-on-error: true` step, i.e. silently.
#
# Pure routing matrices + the workflow-seam census run under `--self-test` (registry-selftest).
import os
import re
import sys

# Emitters that load this module. Adding one means adding `scripts/alert_route.py` to every
# sparse-checkout list that names it — LIVE_SPARSE_SITES below pins that, so this tuple and the
# workflows cannot drift apart quietly.
CONSUMERS = (
    "scripts/groom-alert.py",
    "scripts/pat-validity.py",
    "scripts/plan-alert.py",
    "scripts/usage-alert.py",
)

MODULE_PATH = "scripts/alert_route.py"

# The COMPLETE set of (workflow file, consumer) pairs that appear inside a `sparse-checkout:` value
# in this repo. Asserted as an exact set, not as a floor: a census that only checks the pairs it
# already knows about cannot see a NEW sparse job that omits `scripts/alert_route.py`, and that
# omission is precisely the failure this exists to catch. `scripts/usage-alert.py` and
# `scripts/pat-validity.py` are absent on purpose — their jobs take a FULL checkout.
LIVE_SPARSE_SITES = (
    ("dispatch.yml", "scripts/plan-alert.py"),
    ("groom.yml", "scripts/groom-alert.py"),
)


def alert_route(alert_repo, alert_token, registry_repo):
    """(repo, token) for an ops-alert whose body carries no account handles.

    Locked decision 22c / issue #39: the private ALERT_REPO is the destination ONLY when
    ALERT_TOKEN can write there; a half-configured deployment (repo set, token missing) falls back
    to the registry repo under the ambient token (token=None means "use the ambient GH_TOKEN")
    instead of silently losing the alert."""
    if alert_repo and alert_token:
        return alert_repo, alert_token
    return registry_repo, None


def alert_route_verified(alert_repo, alert_token, registry_repo, confirmed_private):
    """(repo, token, redact) for an ops-alert whose DETAILED body must never reach a public repo.

    Locked decision 22c hardened by issues #107/#204 and review round 1 of #432. The detailed body
    is emitted ONLY over a POSITIVELY VERIFIED private route: ALERT_REPO and ALERT_TOKEN both set,
    ALERT_REPO distinct from the public registry repo (case-insensitive — a "private route" naming
    the registry itself IS the public repo), AND the destination CONFIRMED private by
    `confirmed_private(alert_repo, alert_token)`. Configuration alone (two non-empty strings) is
    NOT verification: it fails OPEN on a same-repo or public ALERT_REPO. EVERY other shape —
    unconfigured, half-configured, same-repo, public, or a failed/indeterminate visibility lookup —
    falls back to the public registry with redact=True.

    `confirmed_private` is REQUIRED and is called at most once, and only once both halves of the
    route are set and the route is not the registry itself: a half-configured or same-repo route
    needs no API call to be rejected."""
    if alert_repo and alert_token:
        same_repo = alert_repo.strip().lower() == (registry_repo or "").strip().lower()
        if not same_repo and confirmed_private(alert_repo, alert_token):
            return alert_repo, alert_token, False
    return registry_repo, None, True


# --- the sparse-checkout seam ------------------------------------------------------------------
# TEXTUAL on purpose, unlike dispatch-secrets-guard.py's PyYAML-backed `sparse_checkout_paths`.
# The question here is not a semantic job-shape question (which is where regex-over-YAML let five
# permissive misparses into the secrets guard, #621) — it is "enumerate the entries of one block
# scalar". Keeping it dependency-free is what lets this assertion run in the worker container,
# where PyYAML is absent and a third of the suite is already ENV-BLOCKED.
#
# Both error directions land RED, which is what makes a textual reader acceptable here. A false
# POSITIVE (a `sparse-checkout:` line matched somewhere it is not a checkout key) adds a site the
# declared population does not contain; a false NEGATIVE (a reflowed step the matcher stops seeing)
# removes one. `LIVE_SPARSE_SITES` is asserted as an exact SET, so either direction fails the
# self-test rather than quietly shrinking the census to nothing.
_SPARSE_KEY = re.compile(r"^(?P<indent>[ \t]*)sparse-checkout:(?P<rest>.*)$")
_BLOCK_SCALAR = ("|", "|-", "|+", ">", ">-", ">+")


def _indent_width(text):
    return len(text.expandtabs(8))


def sparse_checkout_entries(workflow_text):
    """[(line_number, [entry, ...]), ...] — one record per `sparse-checkout:` key.

    Handles both forms actions/checkout accepts: a plain scalar (`sparse-checkout: scripts/x.py`)
    and a block scalar (`sparse-checkout: |` + indented lines). A block ends at the first non-blank
    line indented no further than the key."""
    records = []
    lines = (workflow_text or "").splitlines()
    for index, line in enumerate(lines):
        match = _SPARSE_KEY.match(line)
        if not match:
            continue
        rest = match.group("rest").strip()
        if rest and rest not in _BLOCK_SCALAR:
            # Plain scalar. A YAML comment starts at ` #`; strip it so a documented entry is read
            # as the path it names rather than as an unrecognised one.
            records.append((index + 1, [rest.split(" #")[0].strip()]))
            continue
        key_indent = _indent_width(match.group("indent"))
        entries = []
        for follow in lines[index + 1:]:
            if not follow.strip():
                continue
            lead = follow[:len(follow) - len(follow.lstrip(" \t"))]
            if _indent_width(lead) <= key_indent:
                break
            entries.append(follow.strip())
        records.append((index + 1, entries))
    return records


def sparse_checkout_verdict(workflow_text):
    """(violations, covered) for ONE workflow's text.

    `violations` is [(line_number, consumer), ...] for every sparse-checkout value that names a
    CONSUMER but not scripts/alert_route.py — such a job checks out an emitter without the module
    it imports, so the emitter dies at import time. `covered` is [(line_number, consumer), ...] for
    the compliant ones, returned so a caller can assert the census is non-empty: a scan that finds
    nothing is indistinguishable from a scan that finds nothing wrong."""
    violations, covered = [], []
    for line_number, entries in sparse_checkout_entries(workflow_text):
        has_module = MODULE_PATH in entries
        for consumer in CONSUMERS:
            if consumer not in entries:
                continue
            (covered if has_module else violations).append((line_number, consumer))
    return violations, covered


def sparse_checkout_census(workflows_dir):
    """(violations, covered) over a whole workflows DIRECTORY, each entry (workflow file, consumer).

    Lifted out of the self-test so the census itself is testable against a fixture directory — the
    directory walk is where a census silently empties out (a renamed workflow, a suffix filter that
    stops matching), and an empty census makes the violation assertion trivially green."""
    violations, covered = [], []
    for name in sorted(os.listdir(workflows_dir)):
        if not name.endswith((".yml", ".yaml")):
            continue
        with open(os.path.join(workflows_dir, name), encoding="utf-8") as handle:
            bad, good = sparse_checkout_verdict(handle.read())
        violations += [(name, consumer) for _, consumer in bad]
        covered += [(name, consumer) for _, consumer in good]
    return violations, covered


def _self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got} (want {want})")

    # ---- alert_route: the 2-tuple router (locked decision 22c / #39) ---------------------------
    chk("route: repo+token -> the private route",
        alert_route("org/private", "tok", "org/registry"), ("org/private", "tok"))
    chk("route: repo but EMPTY token -> registry under the ambient token",
        alert_route("org/private", "", "org/registry"), ("org/registry", None))
    chk("route: repo but None token -> registry under the ambient token",
        alert_route("org/private", None, "org/registry"), ("org/registry", None))
    chk("route: token but no repo -> registry",
        alert_route("", "tok", "org/registry"), ("org/registry", None))
    chk("route: nothing configured -> registry",
        alert_route(None, None, "org/registry"), ("org/registry", None))
    # The fallback must hand back None, never the ALERT_TOKEN: the registry write runs under the
    # ambient GH_TOKEN, and passing a private-repo token there would authenticate as the wrong
    # identity. Asserted separately from the tuple rows because it is the half that a "just return
    # the inputs" regression keeps.
    chk("route: the fallback token is None, never the unusable ALERT_TOKEN",
        alert_route("org/private", "", "org/registry")[1], None)
    # The token guard must not weaken when REGISTRY_REPO itself is missing. Found by mutation: with
    # every row above passing a truthy registry_repo, `alert_repo and (alert_token or not
    # registry_repo)` survived the whole matrix — and that shape sends a HALF-CONFIGURED route to
    # the private repo under the ambient token, i.e. a write that cannot succeed and an alert that
    # silently vanishes, which is the entirety of issue #39. An unset REGISTRY_REPO is a broken
    # deployment either way; it must not become a reason to take the private route.
    chk("route: repo but NO token, and NO registry either -> still refuses the private route",
        alert_route("org/private", "", None), (None, None))
    chk("route: repo but NO token, EMPTY registry -> still refuses the private route",
        alert_route("org/private", None, ""), ("", None))

    # ---- alert_route_verified: the 3-tuple router (#107/#204, #432 r1) -------------------------
    calls = []

    def probe(repo, token):
        calls.append((repo, token))
        return True

    def refusing_probe(repo, token):
        calls.append((repo, token))
        return False

    del calls[:]
    chk("verified: configured + distinct + CONFIRMED private -> detailed private route",
        alert_route_verified("org/private", "tok", "org/registry", probe),
        ("org/private", "tok", False))
    chk("verified: the probe is called with the ALERT route, exactly once",
        calls, [("org/private", "tok")])

    del calls[:]
    chk("verified: configured but probe says NOT private -> public + redact",
        alert_route_verified("org/other-public", "tok", "org/registry", refusing_probe),
        ("org/registry", None, True))
    chk("verified: an unconfirmed route still consumed the probe (no silent skip)",
        len(calls), 1)

    del calls[:]
    chk("verified: ALERT_REPO IS the registry -> public + redact (a private route it is not)",
        alert_route_verified("org/registry", "tok", "org/registry", probe),
        ("org/registry", None, True))
    chk("verified: same-repo is rejected WITHOUT an API call",
        calls, [])

    del calls[:]
    chk("verified: same-repo differing only in CASE -> public + redact",
        alert_route_verified("Org/Registry", "tok", "org/registry", probe),
        ("org/registry", None, True))
    chk("verified: the case-folded same-repo rejection makes no API call either", calls, [])

    del calls[:]
    chk("verified: half-configured (no token) -> public + redact",
        alert_route_verified("org/private", "", "org/registry", probe),
        ("org/registry", None, True))
    chk("verified: unconfigured -> public + redact",
        alert_route_verified(None, None, "org/registry", probe),
        ("org/registry", None, True))
    chk("verified: no route configured at all makes no API call", calls, [])
    # A registry_repo of None must still fold to a comparable string rather than raising — the
    # same-repo test is the only place a missing REGISTRY_REPO could crash the router.
    chk("verified: registry_repo=None -> public + redact, no crash",
        alert_route_verified("org/private", "tok", None, refusing_probe),
        (None, None, True))

    # The two entrypoints must NOT be each other. A refactor that routes alert_route() through
    # alert_route_verified() (or vice versa) changes semantics silently in one direction: the
    # 2-tuple router deliberately has NO same-repo rejection and NO probe.
    chk("the two routers are distinct decisions: 2-tuple keeps a same-repo private route",
        alert_route("org/registry", "tok", "org/registry"), ("org/registry", "tok"))

    # ---- the sparse-checkout parser -------------------------------------------------------------
    block = "\n".join([
        "      - uses: actions/checkout@sha",
        "        with:",
        "          sparse-checkout: |",
        "            scripts/groom-alert.py",
        "            scripts/alert_route.py",
        "          sparse-checkout-cone-mode: false",
        "      - run: true",
    ])
    chk("parser: block scalar -> its entries, stopping at the next key",
        sparse_checkout_entries(block),
        [(3, ["scripts/groom-alert.py", "scripts/alert_route.py"])])
    chk("parser: plain scalar -> the single entry",
        sparse_checkout_entries("          sparse-checkout: scripts/plan-alert.py"),
        [(1, ["scripts/plan-alert.py"])])
    chk("parser: plain scalar with a trailing YAML comment -> the path alone",
        sparse_checkout_entries("          sparse-checkout: scripts/plan-alert.py # only this"),
        [(1, ["scripts/plan-alert.py"])])
    chk("parser: a blank line inside a block does not end it",
        sparse_checkout_entries("  sparse-checkout: |\n    a.py\n\n    b.py\n  next: 1"),
        [(1, ["a.py", "b.py"])])
    chk("parser: no sparse-checkout key -> no records",
        sparse_checkout_entries("jobs:\n  x:\n    steps: []"), [])
    chk("parser: two blocks in one file -> two records",
        len(sparse_checkout_entries(block + "\n" + block)), 2)

    # ---- the verdict, BOTH directions ----------------------------------------------------------
    chk("verdict: consumer + module in the same block -> covered, no violation",
        sparse_checkout_verdict(block), ([], [(3, "scripts/groom-alert.py")]))
    stripped = "\n".join(l for l in block.splitlines() if "alert_route.py" not in l)
    chk("verdict: module DROPPED from the block -> violation (the emitter would die on import)",
        sparse_checkout_verdict(stripped), ([(3, "scripts/groom-alert.py")], []))
    chk("verdict: single-file plain scalar naming a consumer -> violation",
        sparse_checkout_verdict("          sparse-checkout: scripts/plan-alert.py"),
        ([(1, "scripts/plan-alert.py")], []))
    chk("verdict: a block naming NO consumer is not this module's business",
        sparse_checkout_verdict("  sparse-checkout: |\n    scripts/metrics.py"), ([], []))
    # The module line must be in the SAME block as the consumer — a sibling job's list does not
    # check the file out for this job.
    two_jobs = ("  sparse-checkout: |\n    scripts/plan-alert.py\n  x: 1\n"
                "  sparse-checkout: |\n    scripts/alert_route.py\n")
    chk("verdict: module in a DIFFERENT block does not cover the consumer",
        sparse_checkout_verdict(two_jobs), ([(1, "scripts/plan-alert.py")], []))

    # ---- the directory census, over a fixture tree (BOTH directions) ---------------------------
    import tempfile

    with tempfile.TemporaryDirectory() as fixture:
        def _write(name, text):
            with open(os.path.join(fixture, name), "w", encoding="utf-8") as handle:
                handle.write(text)

        _write("good.yml", block)
        _write("bad.yaml", stripped)
        # Not a workflow: must be skipped, not parsed. A census that reads every file in the tree
        # would pick up documentation that merely QUOTES a sparse-checkout list.
        _write("README.md", stripped)
        census_bad, census_good = sparse_checkout_census(fixture)
        chk("census: a .yaml violation is reported with its FILE name",
            census_bad, [("bad.yaml", "scripts/groom-alert.py")])
        chk("census: a .yml compliant site is counted, and non-workflow files are skipped",
            census_good, [("good.yml", "scripts/groom-alert.py")])
        os.unlink(os.path.join(fixture, "bad.yaml"))
        chk("census: removing the offending workflow removes the violation (not a constant)",
            sparse_checkout_census(fixture), ([], [("good.yml", "scripts/groom-alert.py")]))

    # ---- LIVE: every sparse job that checks out a consumer also checks out this module ----------
    # Discriminate on the WORKFLOWS DIRECTORY, not on any one file: no directory => a sparse
    # checkout that cannot answer the question (skip with a notice, pr-gate's full checkout
    # enforces it); directory present but a workflow renamed away => the census below reds on the
    # population mismatch rather than silently shrinking.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    workflows_dir = os.path.join(root, ".github", "workflows")
    if not os.path.isdir(workflows_dir):
        print(f"  note .github/workflows absent at {root} — sparse checkout, the live "
              "sparse-checkout census is not applicable (pr-gate's full checkout enforces it)")
    else:
        live_violations, live_covered = sparse_checkout_census(workflows_dir)
        chk("LIVE: no sparse job checks out a consumer without scripts/alert_route.py",
            sorted(live_violations), [])
        # The census must state its population, including which sites it found. An empty scan is
        # what a renamed workflow, a reflowed step, or a parser that stopped matching all look
        # like — and every one of those would leave the assertion above trivially green.
        chk("LIVE: the covered sites are EXACTLY the declared population",
            sorted(live_covered), sorted(LIVE_SPARSE_SITES))

    # ---- the CLI entrypoint, in a subprocess ---------------------------------------------------
    # Item 1 of the AUTHOR pre-flight: entry points get skipped because the test has to construct
    # the real world. Without this row the `raise SystemExit(...)` guard below is never executed by
    # anything, so replacing it with a silent `pass` — which would make `python3 alert_route.py`
    # exit 0 and look like a successful run of nothing — would survive the whole suite.
    import subprocess

    bare = subprocess.run([sys.executable, "-B", os.path.abspath(__file__)],
                          capture_output=True, text=True)
    chk("cli: run with no --self-test -> nonzero exit naming the library contract",
        (bare.returncode != 0, "is a library" in (bare.stderr or "")), (True, True))

    print("alert_route self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(_self_test())
    raise SystemExit(
        "scripts/alert_route.py is a library (the shared ops-alert destination router, issue "
        "#591) — import it; there is nothing to run but --self-test")
