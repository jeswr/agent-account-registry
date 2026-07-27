#!/usr/bin/env python3
# [OPUS-5] registry #466: the measurement-RUN classifier, as ONE pure module.
"""measurement_gate.py — decide whether an issue's deliverable is a MEASUREMENT RUN a
standard GitHub-Actions runner structurally cannot perform, and therefore must never enter the
dispatchable frontier.

WHY THIS EXISTS (registry #466, measured 2026-07-19 ~23:00Z). Post-recovery worker success was
~25% (2 success / 6 failure over the last 8 runs) and EVERY failure was the same class:
`worker-live: model produced no repository changes`. The routed model read ~97k input tokens and
emitted ~800 output tokens with zero edits — because the target's deliverable was an EC2
quiet-box MEASUREMENT RUN on a dedicated instance with multi-GB real datasets (sparq #3067
"same-box MEASURED PyKEEN run FB15k-237/WN18RR", #3068 "canonical quiet-box GSP gather run").
A standard runner has no dedicated quiet box, no orphan-proof EC2 provisioning and no datasets, so
the model correctly produced nothing, the worker exited 1, and the dispatcher's retriage lane
re-promoted `status:deferred` -> ready and dispatched the SAME impossible issue again, forever.

BLANKET-GATING `area:bench` IS WRONG, which is the whole reason this is a classifier and not a
label check. The ready pool is MIXED: "write a wasm micro-bench", "wire the gather harness",
"fix the bench dashboard" are code-only deliverables a runner CAN complete, and gating them would
convert a waste problem into a starvation problem. The classifier separates the two.

TWO PREDICATES, DELIBERATELY DIFFERENT SCOPES — do not collapse them:

  * `is_ec2_measurement(title, body)` — the UNSCOPED, conservative predicate curate-frontier.py has
    used since #500 to fence a brand-new, status-less issue. It sees issues BEFORE any `area:*`
    label exists, so it cannot require a bench surface; that is why its keyword list
    (`EC2_KEYWORDS`) is narrow. Its list is pinned here verbatim — widening it would make curate
    write `needs:ec2` onto ordinary issues that merely MENTION a measurement. The bare `ec2`
    entry matches as a FREE WORD, never as a substring of a label / path / branch / identifier,
    for the measured reason set out on `ec2_signal`.
  * `is_measurement_run(labels, title, body)` — the BENCH-SCOPED predicate the triage/readiness
    path uses. It fires only on an issue already attributed to the bench surface
    (`BENCH_SURFACE_LABELS`), so it can afford a WIDER signal list (`MEASUREMENT_KEYWORDS`) and a
    WIDER code-only exemption (`CODE_ONLY_EXTRA`) without touching any non-bench issue.

  INVARIANTS (self-test enforced, both directions):
    MEASUREMENT_KEYWORDS  is a strict SUPERSET of EC2_KEYWORDS   — the scoped gate is never
                                                                   BLINDER than the unscoped one.
    code_only_deliverable is a strict SUPERSET of code_only_curate — the scoped gate never gates a
                                                                   title curate would have exempted.
  Those two run in opposite directions on purpose: inside the bench surface the gate sees more
  signals AND honours more exemptions, which is exactly the "classify, do not blanket-gate" rule.

FAIL-CLOSED, THE DIRECTIONS THAT MATTER:

  * A malformed title/body is not "no signal" — `issue_text` RAISES. A gate that silently reads an
    unreadable issue as clean is a gate that admits the exact class it exists to exclude.
  * The gate label is a HOLD, never a grant. Every caller writes `needs:ec2`, which is a
    `needs:*` prefix and therefore already a hard gate in ready-issues.GATE_LABELS /
    curate-frontier.GATE_LABELS — so this module can only ever REMOVE an issue from the frontier.
    It has no path that makes anything dispatchable, which is why a false positive costs a human
    label removal while a false negative costs the fleet an unbounded dispatch loop.
  * `is_measurement_run` requires the bench surface FIRST. An issue about the dispatcher itself
    that merely quotes "quiet-box"/"MEASURED" (this very issue's body does) carries `area:dispatch`,
    not `area:bench`, and is never gated by it.
"""
import re
import sys

# The gate this module asks for. `needs:*` is a hard gate in BOTH readiness engines
# (ready-issues.GATE_LABELS, curate-frontier.GATE_LABELS), and `needs:ec2` specifically is the
# label park_policy.py already recognises as a human-owned foreign hold — so a gated issue leaves
# the frontier and stays out until a human (or an EC2-capable lane) clears it. Nothing here ever
# REMOVES a label.
GATE_LABEL = "needs:ec2"

# The labels that attribute an issue to the BENCHMARK surface. EXACT matches, never substrings:
# substring semantics on `area:*` would drag `area:benchmarks-dashboard`-shaped surfaces in, and
# the whole point of this module is that the bench surface is mixed.
BENCH_SURFACE_LABELS = frozenset({"area:bench", "kind:bench", "type:bench"})

# --- the UNSCOPED signal (curate-frontier's, pinned verbatim) ----------------------------------
# Copied from curate-frontier.py's EC2_KEYWORDS at the time this module was extracted. curate now
# imports it from here so there is ONE list; the self-test pins the exact tuple so a future edit to
# the scoped list cannot silently widen the unscoped fence curate applies to every new issue.
EC2_KEYWORDS = (
    "quiet-box", "ec2", "canonical gather", "same-box", "full-scale",
    "nightly gather", "gather run",
)
# `ec2` is the ONE entry in EC2_KEYWORDS that is a BARE TOKEN rather than a phrase, so it is the
# only one a label (`needs:ec2`, `blocked:ec2`), a path (`research/ci-ec2-design.md`,
# `.github/workflows/bench-ec2.yml`, `scripts/ec2-buildfarm.sh`), a branch name
# (`chore/sq-uhqah-formalize-codex-ec2`) or an identifier (`AWSServiceRoleForEC2Spot`) can
# swallow. Every one of those is the issue TALKING ABOUT the fence, not announcing work that has
# to run on dedicated hardware. It therefore matches as a FREE WORD, never as a substring — see
# `ec2_signal` for the measured false-positive census that forced the repair.
EC2_BARE_KEYWORD = "ec2"
EC2_PHRASE_KEYWORDS = tuple(k for k in EC2_KEYWORDS if k != EC2_BARE_KEYWORD)
# Free-word `ec2`: not glued into a label (`:` before), a path segment (`/` before), a compound
# (`-`/`_` either side), an identifier (alnum either side), or a filename extension (`.yml`).
# `/` is deliberately NOT excluded AFTER the token, so prose like `EC2/nightly tier` and
# `CANONICAL/EC2 measurement` still match; and a trailing `.` only blocks when an extension
# follows, so a sentence ending "…runs on EC2." still matches.
_EC2_FREE_WORD = re.compile(
    rf"(?<![A-Za-z0-9_:/-]){re.escape(EC2_BARE_KEYWORD)}(?![A-Za-z0-9_-]|\.[A-Za-z0-9])",
    re.IGNORECASE,
)

# --- the BENCH-SCOPED signal ---------------------------------------------------------------------
# Additional phrases that denote a measurement RUN, safe ONLY because `is_measurement_run` has
# already required a bench-surface label. "measured" is the clearest example of why the scoping is
# load-bearing: this repository's own scripts are full of "MEASURED 2026-07-26" provenance notes,
# so an unscoped "measured" keyword would fence half the registry's backlog behind `needs:ec2`.
MEASUREMENT_KEYWORDS = EC2_KEYWORDS + (
    "measured", "measurement run", "benchmark run", "bench run",
    "real-dataset", "real dataset run", "nightly tier", "competitor column",
    "dedicated instance", "quiet box",
)
# The scoped list inherits the bare-token partition from the unscoped one: `ec2` is scanned by the
# free-word rule in BOTH signals, so the containment invariant below stays true of the BEHAVIOUR
# and not merely of the tuples — a scoped scan that still substring-matched `ec2` would gate bench
# issues on the very `needs:ec2`/`bench-ec2.yml` mentions the unscoped scan now refuses to.
_MEASUREMENT_PHRASE_KEYWORDS = tuple(k for k in MEASUREMENT_KEYWORDS if k != EC2_BARE_KEYWORD)

# --- the code-only exemptions --------------------------------------------------------------------
# curate-frontier's exemption, pinned verbatim: an imperative verb within 80 characters of
# `script`/`scripts`/`harness` in the TITLE means the deliverable is code, not a run.
CODE_ONLY_BENCH = re.compile(
    r"\b(?:fix|wire|repair|refactor|update|change|implement|add|modify)\b"
    r".{0,80}\b(?:scripts?|harness)\b"
    r"|\b(?:scripts?|harness)\b.{0,80}"
    r"\b(?:fix|wire|repair|refactor|update|change|implement|add|modify)\b",
    re.IGNORECASE | re.DOTALL,
)
# The bench-scoped-only additions (#466: "write a micro-bench, wire a harness, dashboard/site"
# stays dispatchable). `write`/`author`/`port` are added as verbs, and micro-bench / dashboard /
# site / CI-workflow authoring are added as objects, so a title like
# "write a micro-bench for the full-scale loader" — which DOES carry a measurement keyword — is
# still recognised as code work. Applied ONLY by `code_only_deliverable`, so curate's fence keeps
# its exact previous width.
CODE_ONLY_EXTRA = re.compile(
    r"\bmicro-?bench(?:mark)?s?\b"
    r"|\b(?:dashboard|site|README|docs?)\b"
    r"|\b(?:write|author|port|plumb|scaffold|stub|parameteris|parameteriz)\w*\b"
    r".{0,80}\b(?:bench(?:mark)?s?|harness|workflow|runner|suite|crate|module)\b"
    r"|\b(?:bench(?:mark)?s?|harness|workflow|runner|suite|crate|module)\b.{0,80}"
    r"\b(?:write|author|port|plumb|scaffold|stub|parameteris|parameteriz)\w*\b",
    re.IGNORECASE | re.DOTALL,
)


class MeasurementGateError(ValueError):
    """A malformed title/body reached the classifier. Raised rather than folded to "no signal":
    an unreadable issue must fail the READ, never quietly pass the gate."""


def issue_text(title, body):
    """`title\\nbody`, FAIL-LOUD on a malformed pair.

    A `None` body is the ordinary GitHub shape for an empty body and normalises to "". Anything
    else — a non-string title, a non-string non-None body — RAISES, because the alternative is a
    gate that reads an unparseable issue as clean.
    """
    if not isinstance(title, str) or not isinstance(body, (str, type(None))):
        raise MeasurementGateError("issue title/body are malformed")
    return f"{title}\n{body or ''}"


def ec2_signal(text):
    """The UNSCOPED keyword test (curate-frontier's). Case-insensitive substring match for the
    PHRASE keywords, free-word match for the bare `ec2` token.

    WHY THE BARE TOKEN IS NOT A SUBSTRING, AND WHY THAT IS A BLOCKING DEFECT RATHER THAN A
    PRECISION NICETY. `needs:ec2` is a ONE-WAY hold: no lane in this estate removes it, and
    `triage-stock-alert.census()` excludes every `needs:*` row from `machine_owed`, because a
    `needs:` gate normally means a HUMAN owes the issue its next move. So a false fence does not
    merely delay an issue, it moves the issue OUT of the population the starvation alarm keys on.

    MEASURED, frozen snapshots of BOTH enabled targets, 2026-07-27 (1501 + 350 open issues). The
    three live registry false positives are code issues that match a plain substring scan ONLY
    because the literal label `needs:ec2` appears in a body discussing this very fence:

        #803  "…with only #3314 correctly carrying `needs:ec2`…"
        #802  "…asks the worker to auto-gate `needs:ec2` when…"
        #471  "…auto-gate EC2-measurement bench issues with needs:ec2…"

    Predicate population, base -> this rule: registry 4 -> 1, sparq 102 -> 84. All 18 sparq drops
    are the same class — `bench-ec2.yml`, `scripts/ec2-buildfarm.sh`, `research/ci-ec2-design.md`,
    `chore/sq-uhqah-formalize-codex-ec2`, `blocked:ec2`, `AWSServiceRoleForEC2Spot`,
    `work-box/EC2 timings are NON-canonical`. NOTHING that says it must run on a box is dropped:
    #4040/#4056/#4352/#4370/#3314/#2764/#2810/#2822/#3163/#3164 all still fence.

    REJECTED ALTERNATIVE, on the measurement. Title-scoping the keyword scan (so match and escape
    share a scope) removes all three registry false positives too, but on sparq it drops SIXTY
    rows including every one of those genuine run-on-hardware issues — their titles say "bench",
    "microbench", "re-gather", "canonical host", not "ec2". Trading a false hold for a fleet loop
    on the larger target is not a repair, so the asymmetry is fixed by making the MATCH precise
    rather than by making it narrow.

    KNOWN RESIDUAL, stated not hidden: sparq #4328 (an IAM-config audit of the bench role) still
    fences, because its body free-mentions "the EC2 benchmark role". Over a BODY, `ec2` is a topic
    word, and no keyword predicate can separate "audits the EC2 role" from "must run on EC2". The
    durable exit for that class is a machine exit for `needs:ec2` itself, not a wider regex —
    tracked in `triage-stock-alert`'s `machine_gated` census, which makes such rows countable
    instead of invisible.
    """
    folded = text.casefold()
    return (any(keyword in folded for keyword in EC2_PHRASE_KEYWORDS)
            or bool(_EC2_FREE_WORD.search(text)))


def measurement_signal(text):
    """The BENCH-SCOPED keyword test. A strict superset of `ec2_signal` (self-test pinned).

    The bare `ec2` token is scanned by the same free-word rule `ec2_signal` uses; every other
    scoped keyword is a phrase and stays a substring match.
    """
    folded = text.casefold()
    return (any(keyword in folded for keyword in _MEASUREMENT_PHRASE_KEYWORDS)
            or bool(_EC2_FREE_WORD.search(text)))


def code_only_curate(title):
    """curate-frontier's code-only exemption, unchanged."""
    return bool(CODE_ONLY_BENCH.search(title))


def code_only_deliverable(title):
    """The BENCH-SCOPED code-only exemption. A strict superset of `code_only_curate`."""
    return bool(CODE_ONLY_BENCH.search(title) or CODE_ONLY_EXTRA.search(title))


def is_ec2_measurement(title, body):
    """curate-frontier.py's predicate, moved here unchanged so there is ONE keyword list.

    UNSCOPED — it runs on issues that have no `area:*` label yet, which is why its signal list is
    the narrow one. Do not widen it; widen `MEASUREMENT_KEYWORDS` instead.
    """
    return ec2_signal(issue_text(title, body)) and not code_only_curate(title)


def is_bench_surface(labels):
    """True iff the issue is attributed to the benchmark surface. EXACT label match."""
    return bool({label for label in labels if isinstance(label, str)} & BENCH_SURFACE_LABELS)


def is_measurement_run(labels, title, body):
    """THE TRIAGE-PATH PREDICATE (#466): a bench-surface issue whose deliverable is a RUN.

    All three conditions are required, and each one is a separate way for the issue to stay
    dispatchable:
      1. the issue is on the bench surface — a dispatcher/CI issue that merely QUOTES a
         measurement is never gated;
      2. the title+body carries a measurement-run signal — a bench issue with no run language is
         ordinary bench code work;
      3. the TITLE is not a code-only deliverable — "write a wasm micro-bench", "wire the gather
         harness", "fix the bench dashboard" stay dispatchable even when the body discusses the
         run they serve.
    """
    if not is_bench_surface(labels):
        return False
    text = issue_text(title, body)                     # validates title/body, or raises
    return measurement_signal(text) and not code_only_deliverable(title)


def _self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    BENCH = {"area:bench", "priority:P2", "role:impl"}

    # ---- THE WIRE CONTRACT: curate-frontier's unscoped list is pinned to an INDEPENDENT literal.
    # Without this, widening MEASUREMENT_KEYWORDS by editing EC2_KEYWORDS would silently widen the
    # fence curate applies to EVERY brand-new issue in the target repo.
    chk("EC2_KEYWORDS is exactly curate-frontier's pinned list", list(EC2_KEYWORDS),
        ["quiet-box", "ec2", "canonical gather", "same-box", "full-scale",
         "nightly gather", "gather run"])
    chk("MEASUREMENT_KEYWORDS is a STRICT superset of EC2_KEYWORDS",
        (set(EC2_KEYWORDS) < set(MEASUREMENT_KEYWORDS)), True)
    chk("`measured` is scoped-only — it is NOT an unscoped keyword",
        "measured" in EC2_KEYWORDS, False)
    # The bare token is scanned ONLY by the free-word rule, in BOTH signals. If a future edit
    # renames or drops the `ec2` entry, the phrase tuples silently regain a plain-substring `ec2`
    # and every free-word check below goes green again while the defect is back — the
    # decaying-control shape. Pin the partition itself rather than trusting the derivation.
    chk("the bare ec2 keyword is scanned ONLY by the free-word rule (unscoped)",
        (EC2_BARE_KEYWORD in EC2_KEYWORDS,
         EC2_BARE_KEYWORD in EC2_PHRASE_KEYWORDS,
         set(EC2_PHRASE_KEYWORDS) | {EC2_BARE_KEYWORD} == set(EC2_KEYWORDS),
         len(EC2_PHRASE_KEYWORDS) == len(EC2_KEYWORDS) - 1), (True, False, True, True))
    chk("...and by the free-word rule in the SCOPED signal too",
        (EC2_BARE_KEYWORD in _MEASUREMENT_PHRASE_KEYWORDS,
         set(_MEASUREMENT_PHRASE_KEYWORDS) | {EC2_BARE_KEYWORD} == set(MEASUREMENT_KEYWORDS)),
        (False, True))
    chk("the gate label is a needs:* hold (the only shape both engines treat as a gate)",
        GATE_LABEL.startswith("needs:"), True)

    # ---- THE #466 ACCEPTANCE FIXTURES ------------------------------------------------------------
    looper_title = "same-box MEASURED PyKEEN run FB15k-237/WN18RR"
    looper_body = ("**Deliverable:** a canonical quiet-box gather run on a dedicated EC2 instance "
                   "with the real datasets. Results are non-canonical anywhere else.")
    chk("the #3067 looper (MEASURED quiet-box run) IS gated",
        is_measurement_run(BENCH, looper_title, looper_body), True)
    chk("the #3068 looper (canonical gather run) IS gated",
        is_measurement_run(BENCH, "canonical quiet-box GSP gather run — Fuseki/Oxigraph/CSS "
                                  "columns live", "competitor column gather, nightly tier."), True)
    chk("a code-only bench issue (`write a wasm micro-bench`) stays dispatchable",
        is_measurement_run(BENCH, "write a wasm micro-bench", "add a criterion micro-bench"), False)
    # ...and stays dispatchable EVEN when its body discusses the run it will serve. This is the
    # assertion that flips red if the code-only exemption is dropped from `is_measurement_run`.
    chk("a micro-bench issue whose BODY mentions the quiet-box run stays dispatchable",
        is_measurement_run(BENCH, "write a wasm micro-bench",
                           "it will eventually feed the quiet-box EC2 gather run"), False)
    chk("`wire the gather harness` stays dispatchable (curate's own exemption)",
        is_measurement_run(BENCH, "wire the gather harness for the full-scale run", ""), False)
    chk("`fix the bench dashboard` stays dispatchable",
        is_measurement_run(BENCH, "fix the bench dashboard for the nightly tier", ""), False)

    # ---- GUARD: the SCOPE is load-bearing. A non-bench issue is NEVER gated, however loudly its
    # text talks about measurement. Deleting the `is_bench_surface` check turns these red — and
    # registry #466 ITSELF is the fixture, because its own body quotes every keyword.
    dispatch_labels = {"area:dispatch", "priority:P1", "role:impl"}
    chk("a DISPATCH issue quoting quiet-box/MEASURED/EC2 is NOT gated",
        is_measurement_run(dispatch_labels,
                           "dispatch waste: EC2 benchmark-RUN issues leak into the frontier",
                           "MEASURED 2026-07-19: the quiet-box gather run loopers #3067/#3068."),
        False)
    chk("...and neither is an unlabelled issue with the same text",
        is_measurement_run(set(), looper_title, looper_body), False)
    for surface in sorted(BENCH_SURFACE_LABELS):
        chk(f"{surface} alone is enough to reach the gate",
            is_measurement_run({surface}, looper_title, looper_body), True)
    chk("a near-miss area label is NOT the bench surface (exact match, never prefix)",
        is_measurement_run({"area:benchmarks-dashboard"}, looper_title, looper_body), False)

    # ---- GUARD: the SIGNAL is load-bearing. A bench issue with no run language is ordinary work.
    # Deleting the `measurement_signal` check turns this red (it would gate ALL of area:bench,
    # which #466 names explicitly as the wrong fix).
    chk("a bench issue with NO measurement signal stays dispatchable",
        is_measurement_run(BENCH, "add a bench for the triple parser",
                           "the parser is slow; add coverage."), False)
    chk("...so the classifier is not a blanket area:bench gate",
        [is_measurement_run(BENCH, t, "") for t in
         ("add a bench for the triple parser", "MEASURED quiet-box run")], [False, True])

    # ---- GUARD: curate's UNSCOPED predicate is unchanged by any of the above.
    chk("curate's predicate still fences a status-less quiet-box run",
        is_ec2_measurement("Run canonical gather on same-box EC2", ""), True)
    chk("curate's predicate still exempts its scripts/harness titles",
        is_ec2_measurement("Fix scripts/gather.py for canonical gather", ""), False)
    chk("curate's predicate is NOT widened by the scoped keywords (`measured` alone)",
        is_ec2_measurement("MEASURED parser regression", "a measurement run would help"), False)
    chk("curate's predicate ignores labels entirely (it runs before area:* exists)",
        is_ec2_measurement("quiet-box gather run", ""), True)

    # ---- GUARD: THE FREE-WORD RULE, BOTH DIRECTIONS. The fence is a ONE-WAY hold with no machine
    # exit, so a false positive removes the issue from the population triage-stock-alert's
    # `machine_owed` census keys on. Reverting `ec2_signal` to `"ec2" in folded` reds every row in
    # the first block; narrowing the scan to the TITLE (the alternative rejected on the
    # measurement) reds every row in the second.
    mention_title = "Repair the alpha snapshot writer"
    for label, mention in (
        ("the needs:ec2 LABEL named in a body",
         "Layer 2 asks the worker to auto-gate `needs:ec2` when the model reports a blocker, "
         "and only #3314 correctly carries `needs:ec2` today."),
        ("a research path", "The `research/ci-ec2-design.md` OIDC pattern is the one to reuse."),
        ("a workflow filename", "Wire the HEAVY tiers into `.github/workflows/bench-ec2.yml`."),
        ("a script path", "Flip `scripts/ec2-buildfarm.sh` fmt from ADVISORY to gating."),
        ("a branch name", "Stale branch `chore/sq-uhqah-formalize-codex-ec2` is unreachable."),
        ("an identifier", "The scoped role cannot create the `AWSServiceRoleForEC2Spot` SLR."),
        ("a sibling gate label", "It is held by `blocked:ec2`, which nothing removes."),
    ):
        chk(f"NOT fenced: {label}", is_ec2_measurement(mention_title, mention), False)
    # ...and naming the label in the TITLE does not make it fence-able either.
    chk("NOT fenced: the needs:ec2 label named in a TITLE",
        is_ec2_measurement("Auto-gate bench issues with needs:ec2", ""), False)

    # THE FIX MUST NOT BECOME A FAIL-OPEN: the repair narrows WHICH mentions count, never WHERE
    # they may appear. A body that says the work runs on a box still fences.
    for label, run in (
        ("free-word ec2 mid-sentence", "Gathered on the quiet EC2 reference box with CANONICAL=1."),
        ("ec2 before a slash", "This needs the DBPSB EC2/nightly tier, not the work box."),
        ("ec2 ending a sentence", "Work-box numbers are non-canonical; run it on EC2."),
        ("a phrase keyword, untouched by the repair",
         "Requires the dedicated quiet-box protocol on the perf host."),
    ):
        chk(f"STILL fenced: {label}",
            is_ec2_measurement("Measure the alpha loader at 100M triples", run), True)

    # The SCOPED predicate inherits the repair, so a bench issue that merely NAMES the gate label
    # is not gated either. This reds if `measurement_signal` keeps a substring scan for `ec2`.
    chk("the scoped gate also refuses a bare needs:ec2 mention",
        is_measurement_run(BENCH, mention_title,
                           "auto-gate `needs:ec2` when the model reports a blocker."), False)
    # BEHAVIOURAL containment, not just tuple containment: everything the unscoped signal fires on,
    # the scoped signal fires on too.
    corpus = ("Gathered on the quiet EC2 reference box", "canonical gather run", "nightly gather",
              "full-scale replay", "same-box timings", "`needs:ec2` is named here",
              "scripts/ec2-buildfarm.sh", "an ordinary parser fix")
    chk("ec2_signal implies measurement_signal on every corpus row",
        [t for t in corpus if ec2_signal(t) and not measurement_signal(t)], [])
    # The exemption containment, both directions, on a title that only the SCOPED exemption knows.
    chk("code_only_deliverable is a STRICT superset of code_only_curate",
        (code_only_curate("write a wasm micro-bench"),
         code_only_deliverable("write a wasm micro-bench")), (False, True))
    chk("...and agrees with it on curate's own shape",
        (code_only_curate("fix scripts/gather.py"),
         code_only_deliverable("fix scripts/gather.py")), (True, True))

    # ---- GUARD: a malformed title/body FAILS THE READ rather than passing the gate.
    for bad_title, bad_body in ((None, ""), (7, ""), (["t"], ""), ("t", 5), ("t", {})):
        for predicate, label in ((lambda: is_measurement_run(BENCH, bad_title, bad_body), "scoped"),
                                 (lambda: is_ec2_measurement(bad_title, bad_body), "unscoped")):
            try:
                predicate()
            except MeasurementGateError:
                chk(f"{label} gate REFUSES title={bad_title!r} body={bad_body!r}", True, True)
            else:
                chk(f"{label} gate REFUSES title={bad_title!r} body={bad_body!r}",
                    "passed", "refused")
    chk("a None body is the ordinary empty shape, not malformed",
        is_measurement_run(BENCH, looper_title, None), True)
    # A malformed LABEL entry must not crash the surface test (labels come from validated readers,
    # but the predicate is total on them so a junk entry cannot mask a real bench label).
    chk("a junk label entry does not hide the bench surface",
        is_measurement_run({"area:bench", None, 7}, looper_title, ""), True)

    # ---- GUARD: case folding, so a SHOUTED or lowercased body reads the same.
    chk("the signal is case-insensitive",
        [is_measurement_run(BENCH, t, "") for t in
         ("QUIET-BOX GATHER RUN", "quiet-box gather run", "Quiet-Box Gather Run")],
        [True, True, True])

    print("measurement_gate self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    if "--self-test" in sys.argv:
        return _self_test()
    print(__doc__.strip().splitlines()[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
