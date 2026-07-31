#!/usr/bin/env python3
# PRIVATE DIAGNOSTIC SINK BOOTSTRAP (issue #370, the follow-up #183 left behind).
#
# WHAT #183 DID. `account-whoami.yml` (identity probe) and `fingerprint-accounts.yml` (per-account
# 7d-reset fingerprint) identify the Anthropic accounts behind the `ACCTNN_TOKEN` secrets. Even
# logging only salted hashes, a run writes a STABLE per-account identifier into an Actions log —
# and this registry's logs are world-readable, so a few runs enumerate the fleet. #183 therefore
# put a job-level
#
#     if: ${{ github.event.repository.private == true }}
#
# on both. On THIS repo that condition is false forever: the jobs skip, touch no secret, emit
# nothing. The diagnostics did not stop being useful — they stopped having anywhere to run.
#
# WHAT THIS SCRIPT IS. The bootstrap for that somewhere. `emit` materialises the two probes —
# BYTE-FOR-BYTE, guard included — as a bundle to drop into the sink repo, and `plan` prints the
# ordered runbook that stands the sink's Actions surface up around them. Nothing here talks to
# GitHub: the whole program is a verified copy plus a printed runbook a maintainer executes.
#
# THE SINK IS NOT A NEW CONCEPT. `jeswr/agent-account-data` is already this registry's private
# destination for account-enumerating output — `ALERT_REPO`, the route `model-health.py` /
# `usage-alert.py` file fleet alerts through, whose detailed body is emitted only after
# `model-health._repo_confirmed_private` reads a literal `"private": true` back (#432). The
# probes belong on that same repo, not on a second one invented here.
#
# WHY THE COPY IS VERBATIM, AND WHY THE GUARD TRAVELS WITH IT. The guard is not scaffolding to be
# stripped once the file reaches a private repo — it is the whole reason the bundle is safe to
# hand over at all. Carried across, it is re-evaluated by GitHub on every single run against the
# DESTINATION's visibility, so:
#
#   * a bundle dropped into a repo that is not private is inert, and
#   * a sink that is later flipped public goes inert by itself, with no edit and no human noticing.
#
# That is a stronger property than anything this offline script could check about the destination,
# and it is why `emit` refuses to rewrite so much as a line. The verification below is the other
# half: a probe whose guard has regressed IN THIS TREE must never be packaged for a repo whose
# visibility we cannot see. Both `emit` and `plan` refuse — before writing anything — unless every
# job of every probe is PROVABLY unreachable while the guard atom is false.
#
# FAIL-CLOSED, everywhere the answer is not a proof:
#   * a probe file missing from the tree                       -> refusal (rc 2), nothing written
#   * a workflow with no parsable `jobs:` block, or no jobs     -> refusal
#   * a job whose `if:` can be true while the guard is false    -> refusal naming the job
#   * a job whose `if:` this grammar cannot DECIDE              -> refusal (an unreadable guard is
#     not a proven guard — the polarity rule `guard_gate_verdict` runs on dispatch.yml)
#   * a secret-consuming job with no `environment:` binding     -> refusal (the sink would read it
#     from repo scope, at any ref)
#   * a scan that derives NO secret-consuming job at all        -> refusal (it proves nothing:
#     either the parser or the probe shape drifted)
#   * a whole-context reader whose own NAME allowlist cannot be derived (absent, ambiguous, not a
#     portable ERE) -> refusal. The environment these probes bind to is a TRUST BOUNDARY, not an
#     account-token inventory: `dispatch-secrets` also holds REGISTRY_SECRETS_PAT and ALERT_TOKEN.
#     A runbook that enumerated it unfiltered would be telling the maintainer to copy the
#     registry's admin credentials into a second repository.
#   * an output path that already exists                        -> refusal, the existing file is
#     never overwritten, and the bundle is written ALL-OR-NOTHING
#
# ONE DEFINITION, NOT A COPY (#958). Every fact about the probes is DERIVED from the probes:
# the guard polarity through `dispatch-secrets-guard.if_condition_admits` (the same decision
# procedure that proves dispatch.yml's exfil gate), and the secrets + environment the sink must
# provision through `dispatch-secrets-guard.secret_consuming_jobs` (the same scan that derives the
# binding map). Nothing about the probes is restated here, so nothing about them can drift here.
# The emitted sink README says the same thing to the sink: the registry is the source, and the
# copy is regenerated, never hand-edited.
#
# WHAT THIS SCRIPT DELIBERATELY DOES NOT DO. It does not create the repo, set a secret, push, or
# dispatch — this container holds no GitHub token by design, and every step of the runbook is an
# irreversible repository-settings change a human must own. It also does not delete the public
# copies: they are the SOURCE the bundle is derived from, and they are already inert. Retiring
# them is a separate change, once a sink run has been observed green.

import argparse
import collections
import importlib.util
import os
import re
import shlex
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# The probes #183 made inert here. Both, always: a bundle that ships one of them and silently
# drops the other would move "the probe cadence" only half-way.
PROBE_WORKFLOWS = ("account-whoami.yml", "fingerprint-accounts.yml")
WORKFLOW_DIR = os.path.join(".github", "workflows")

# The registry's EXISTING private destination for account-enumerating output (ALERT_REPO).
DEFAULT_SINK_REPO = "jeswr/agent-account-data"
# THIS registry — the repo the runbook is executed from, and the AUTHORITATIVE holder of the
# concrete per-account secret names. `ACCTNN_TOKEN` is the family notation used throughout this
# repo's prose; no secret is called that, so the runbook enumerates the real names from here rather
# than printing a name-shaped literal for a human to expand.
REGISTRY_REPO = "jeswr/agent-account-registry"
DEFAULT_SINK_DEFAULT_BRANCH = "master"

# The guard atom, in the canonical (space-free) form `_if_atom_map` reduces a parsed comparison to
# — the same shape as dispatch-secrets-guard's WRITEBACK_ROTATION_POSSIBLE_WORLD patterns. Only a
# genuinely parsed COMPARISON against `true` is recognised: `if: ${{ ...private }}` used bare is
# semantically equivalent to a human and is REFUSED here, because it is not a comparison this
# procedure can pin, and refusing an unrecognised spelling is the safe direction.
#
# ANCHORED WHOLE-CANONICAL (\A..\Z), because `if_condition_admits` matches this with `re.search`
# against the canonical text and PINS EVERY MATCH FALSE. Unanchored, the accepted text is a
# SUBSTRING test, and a substring match pins an atom that is not this guard: `...private ==
# truefoo` contains `...private==true`, so it would be pinned false and the job reported provably
# unreachable — while at runtime `truefoo` is an undefined path (null -> 0) and `false == null` is
# TRUE, so the probe runs and enumerates the fleet on a PUBLIC repo. The same shape on the left
# (`needs.x.outputs.github.event.repository.private == true`) pins a comparison against a
# different, unrelated path. An atom that is not character-for-character the guard is not the
# guard: it stays FREE, the expression comes back reachable, and the bundle is refused.
PRIVATE_GUARD_RE = re.compile(r"\Agithub\.event\.repository\.private==(?:true|['\"]true['\"])\Z")
PRIVATE_GUARD_TEXT = "github.event.repository.private == true"

# The whole-context probe's own account-token NAME allowlist, lifted out of its `jq ... test("...")`
# filter. THREE separate properties, checked separately and on purpose: the scanner below finds
# candidates and says nothing about their shape, and each rule that can refuse one has an input the
# other two ACCEPT. Folding them together (an anchored-only scanner AND an anchored-only validator,
# say) is the #945 shape — two copies of one rule leave each copy individually unkillable.
_ALLOWLIST_PATTERN_RE = re.compile(r'test\(\s*"([^"\n]*)"\s*\)')
# (1) ANCHORED. An unanchored filter is a substring test, and the runbook renders whatever it finds
# straight into `grep -E`, where `ACCT[A-Z0-9]+_TOKEN` selects `XACCT01_TOKENX` too.
_ALLOWLIST_ANCHORED_RE = re.compile(r"\A\^.*\$\Z", re.DOTALL)
# (2) PORTABLE — it must mean the SAME THING in POSIX ERE as it does in the probe. jq's regex engine
# is Oniguruma; `grep -E` is POSIX ERE, and the two diverge precisely at the BACKSLASH (`\d`, `\w`,
# `\b` are Oniguruma shorthands ERE has no notion of). A pattern carrying one would silently select
# a different set of names in the runbook than the probe fingerprints, so the accepted alphabet
# excludes backslash outright and anything unrecognised is REFUSED, never translated.
_ALLOWLIST_PORTABLE_RE = re.compile(r"\A[A-Za-z0-9_\[\]|()*+.?{},^$-]*\Z")
# (3) A VALID REGEX AT ALL — `re.compile`, below.


class SinkRefusal(Exception):
    """A fail-closed refusal. Carries the reason; `main` prints it and exits 2."""


_READER = None


def _reader():
    """The shared workflow reader: `dispatch-secrets-guard.py`, loaded as a module (the
    `_load_sibling` pattern used across this scripts/ directory for hyphen-named siblings).

    Loaded rather than re-implemented on purpose. Its `if_condition_admits` is the decision
    procedure that proves dispatch.yml's exfil gate, and its `secret_consuming_jobs` is the scan
    that derives the binding map; a second copy of either here would be a copy that drifts, and
    a hand-rolled workflow parser is exactly what let the five #621 misparses through."""
    global _READER
    if _READER is None:
        path = os.path.join(SCRIPT_DIR, "dispatch-secrets-guard.py")
        spec = importlib.util.spec_from_file_location("registry_dispatch_secrets_guard", path)
        if spec is None or spec.loader is None:                   # pragma: no cover - env fault
            raise SinkRefusal("cannot load the shared workflow reader "
                              "(scripts/dispatch-secrets-guard.py)")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _READER = module
    return _READER


# ---- reading the probes -------------------------------------------------------------------------
def probe_sources(repo_root, workflows=PROBE_WORKFLOWS):
    """{filename: text} for every probe. Raises SinkRefusal naming the first missing one — a
    bundle assembled out of whatever happened to be on disk is not a bundle."""
    sources = {}
    for filename in workflows:
        path = os.path.join(repo_root, WORKFLOW_DIR, filename)
        if not os.path.isfile(path):
            raise SinkRefusal(f"probe workflow {WORKFLOW_DIR}/{filename} is not in the tree at "
                              f"{repo_root} — refusing to emit a partial diagnostic bundle")
        with open(path, encoding="utf-8") as handle:
            sources[filename] = handle.read()
    return sources


def parse_probes(sources):
    """{filename: {job name: parsed job}} — the ONE yaml seam in this file. `workflow_job_docs`
    returns None for a document with no parsable `jobs:` block; that None is carried through so
    `guard_verdict` refuses it by name rather than crashing."""
    reader = _reader()
    return {filename: reader.workflow_job_docs(text) for filename, text in sources.items()}


# ---- the guard verdict (pure) --------------------------------------------------------------------
def guard_verdict(filename, job_docs):
    """Pure: (ok, reason) — is EVERY job of this probe provably unable to run while
    `github.event.repository.private == true` is false?

    Decided by `if_condition_admits`, which pins the guard atom FALSE and asks whether any
    assignment of the remaining atoms still makes the condition true. `admits=False` is a proof
    over all worlds; `admits=True` exhibits a reaching one. UNDECIDED is treated as admitting: a
    guard this grammar cannot read is not a guard it has verified.

    EVERY job, not the first one: a probe that grows a second, unguarded job (a setup step, a
    summary step) leaks exactly as hard as an unguarded first one."""
    if not job_docs:
        return False, (f"{filename}: no parsable `jobs:` block, or no mapping-shaped job — the "
                       "guard cannot be verified, so the probe is not packaged (fail closed)")
    reader = _reader()
    for job_name in sorted(job_docs):
        condition = reader.job_if_expression(job_docs[job_name])
        admits, decided, detail = reader.if_condition_admits(condition, PRIVATE_GUARD_RE)
        if not decided:
            return False, (f"{filename}: job `{job_name}` carries an `if:` this decision procedure "
                           f"cannot decide ({detail}), so `{PRIVATE_GUARD_TEXT}` is NOT a proven "
                           "guard on it (fail closed)")
        if admits:
            return False, (f"{filename}: job `{job_name}` can run while `{PRIVATE_GUARD_TEXT}` is "
                           f"FALSE ({detail}) — on a repo that is not private this probe would "
                           "write per-account identifiers to a readable log. Restore the guard "
                           "before packaging it.")
    return True, "ok"


def bundle_verdict(parsed):
    """Pure: (ok, reason) over {filename: job docs}. Refuses unless the probe set is exactly the
    one this bundle is defined as, and every probe passes `guard_verdict`."""
    if sorted(parsed) != sorted(PROBE_WORKFLOWS):
        return False, ("the bundle must carry exactly " + ", ".join(sorted(PROBE_WORKFLOWS))
                       + " — got " + (", ".join(sorted(parsed)) or "nothing"))
    for filename in sorted(parsed):
        ok, reason = guard_verdict(filename, parsed[filename])
        if not ok:
            return False, reason
    return True, "ok"


# ---- what the sink must provision, DERIVED from the bundle ---------------------------------------
# What the sink repo must hold before the bundle can run: the named secrets, the jobs that read the
# WHOLE secrets context (whose coverage is the environment's contents, so it cannot be enumerated
# here), and the environments the bindings name. A namedtuple rather than a class: equality and
# repr come from the stdlib, so there is no hand-written comparison for an assertion to be
# tautologically compared against.
Requirements = collections.namedtuple("Requirements",
                                      "secrets context_readers environments allowlist")


def context_allowlist(sources, context_readers):
    """The account-token NAME allowlist the whole-context probe filters `toJSON(secrets)` with,
    DERIVED from that probe's own text (#958 — one definition, never a restatement here).

    This is a trust boundary, not a convenience. `toJSON(secrets)` covers the WHOLE environment,
    and `dispatch-secrets` is not an account-token inventory — it also holds REGISTRY_SECRETS_PAT
    and ALERT_TOKEN, which is exactly why the probe filters at all. The runbook has to name the
    same set the probe fingerprints; an unfiltered enumeration would read as "copy each of these
    into the sink", which is the registry's admin credentials landing in a second repository.

    Fail-closed five ways, because every one of them ends in the runbook printing a name the
    maintainer would then copy. Each has an input the other four accept, so none can hide behind
    another (#945):
      * NO name filter in the reader's text — either the probe stopped filtering (it now
        fingerprints every secret in the environment) or the filter moved somewhere this cannot
        see. Neither is a set this script may guess.
      * MORE THAN ONE distinct filter across the readers — the readers disagree about their own
        coverage, so there is no single set to print.
      * an UNANCHORED filter — see `_ALLOWLIST_ANCHORED_RE`.
      * a pattern outside the portable-ERE alphabet — see `_ALLOWLIST_PORTABLE_RE`.
      * a pattern that is not a valid regex at all.
    """
    found = set()
    for filename, _job, _read in context_readers:
        found.update(_ALLOWLIST_PATTERN_RE.findall(sources.get(filename, "")))
    readers = ", ".join(sorted({filename for filename, _job, _read in context_readers}))
    if not found:
        raise SinkRefusal(
            f"{readers}: reads the WHOLE secrets context but no name allowlist (`test(\"...\")`) "
            "can be derived from it — the runbook cannot say which secrets belong in the sink "
            "without restating a filter that would then drift, and an unfiltered enumeration "
            "would name every credential in the environment (fail closed)")
    if len(found) > 1:
        raise SinkRefusal(
            f"{readers}: the whole-context readers carry DIFFERENT name allowlists ("
            + ", ".join(sorted(found)) + ") — they disagree about their own coverage, so there is "
            "no single set of names the runbook may print (fail closed)")
    pattern = found.pop()
    if not _ALLOWLIST_ANCHORED_RE.match(pattern):
        raise SinkRefusal(
            f"{readers}: the derived allowlist `{pattern}` is UNANCHORED — rendered into the "
            "runbook's `grep -E` it would select every name that merely CONTAINS an account-token "
            "name, so the enumeration would be wider than the probe's own coverage (fail closed)")
    if not _ALLOWLIST_PORTABLE_RE.match(pattern):
        raise SinkRefusal(
            f"{readers}: the derived allowlist `{pattern}` is outside the POSIX-ERE alphabet this "
            "runbook can hand to `grep -E` unchanged — in jq's Oniguruma it may select a set the "
            "shell command would not. Refusing to translate it (fail closed)")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise SinkRefusal(f"{readers}: the derived allowlist `{pattern}` is not a valid regular "
                          f"expression ({exc}) — refusing to render it into a command")
    return pattern


def sink_expected_name_pattern(requirements):
    """The POSIX ERE that EVERY secret name in the sink's environment must match: the probe's own
    account-token allowlist, plus each separately derived NAMED requirement (PROVENANCE_SALT and
    friends) the allowlist does not already cover.

    It exists so the runbook's read-back can REJECT a name rather than merely print it. A read-back
    a human eyeballs is not a check; this one is the difference between "the sink holds the fleet"
    and "the sink holds the fleet plus whatever else got pasted in"."""
    alternatives = [requirements.allowlist] if requirements.allowlist else []
    alternatives += ["^" + re.escape(name) + "$" for name in requirements.secrets
                     if not (requirements.allowlist
                             and re.search(requirements.allowlist, name))]
    return "|".join(alternatives)


def sink_requirements(sources):
    """Requirements, DERIVED from the probe text by the same scan that builds the registry's
    binding map (`secret_consuming_jobs`). Raises SinkRefusal rather than guessing.

    Three refusals, all of them the "a default here grants access" shape:
      * an unparsable jobs block — nothing can be derived from it;
      * a secret-consuming job with NO `environment:` binding — the sink would serve that secret
        from repo scope, readable by a modified workflow copy at any ref (#101), and a runbook
        that silently omitted the environment would provision exactly that;
      * a scan deriving NO secret-consuming job — that is not "the probes need nothing", it is the
        parser or the probe shape having drifted, and a runbook built from it would stand up an
        empty sink whose probes report `token_present=no` forever.

    The emptiness floor is checked on `consuming` and NOWHERE ELSE, deliberately. A second floor on
    the derived secrets/environments would be a DUPLICATE of this one — `secret_consuming_jobs`
    reports only jobs that read a secret, and a reading job with no binding already refused above,
    so "no secret derived" and "no environment derived" and "no consuming job" are the same
    condition. Two copies of one guard make each copy individually unkillable (#945), which is
    exactly how it measured: a mutant weakening `or not environments` to `and not environments`
    survived the whole suite because no input can separate the two halves."""
    consuming = _reader().secret_consuming_jobs(sources)
    if consuming is None:
        raise SinkRefusal("cannot locate a `jobs:` block in every probe workflow, so the sink's "
                          "secret/environment requirements cannot be derived (fail closed)")
    if not consuming:
        raise SinkRefusal("the secret scan derived NO secret-consuming job from the probes — the "
                          "probes read secrets, so this is parser or probe-shape drift, not an "
                          "empty requirement (fail closed)")
    secrets, context_readers, environments = set(), set(), set()
    for (filename, job_name), (reads, environment) in sorted(consuming.items()):
        if not environment:
            raise SinkRefusal(
                f"{filename}: job `{job_name}` reads {', '.join(reads)} with NO job-level "
                "`environment:` binding — in the sink that secret would come from repo scope and "
                "be readable at any ref. Refusing to emit a bundle whose runbook cannot say where "
                "the secret belongs.")
        environments.add(environment)
        for read in reads:
            if read.startswith("secrets."):
                secrets.add(read.split(".", 1)[1])
            else:
                context_readers.add((filename, job_name, read))
    readers = tuple(sorted(context_readers))
    # No whole-context reader means no unenumerable coverage, so there is nothing to filter and
    # nothing to derive — `None`, not an empty pattern that would render as `grep -E ''` and match
    # every line. Derived ONLY when a reader exists, and a refusal when one exists without it.
    return Requirements(tuple(sorted(secrets)), readers, tuple(sorted(environments)),
                        context_allowlist(sources, readers) if readers else None)


# ---- the bundle ----------------------------------------------------------------------------------
SINK_README_NAME = "README.md"


def sink_readme(sources, requirements, sink_repo):
    """The one file this bundle AUTHORS. Everything else is a byte-for-byte copy."""
    probes = "\n".join(f"- `{WORKFLOW_DIR}/{name}`" for name in sorted(sources))
    secrets = "\n".join(f"- `{name}`" for name in requirements.secrets)
    # Stated separately because it CANNOT be enumerated: a job that reads the whole secrets context
    # covers whatever the environment happens to hold, filtered by the probe's own allowlist. The
    # allowlist is named because it is the boundary — "add each one" without it reads as an
    # instruction to copy every credential the source environment happens to hold.
    contextual = "\n".join(
        f"- `{filename}` job `{job}` reads `{read}` and filters it by NAME with\n"
        f"  `{requirements.allowlist}`, so its coverage is exactly the secrets in this\n"
        "  environment whose name matches that pattern. Add the account tokens you want\n"
        "  fingerprinted and NOTHING else — this environment is a trust boundary, not an\n"
        "  account-token inventory."
        for filename, job, read in requirements.context_readers)
    environments = "\n".join(f"- `{name}`" for name in requirements.environments)
    return f"""# account diagnostics (private sink)

The maintainer-only account diagnostics for `jeswr/agent-account-registry`. They live here, and
not on the registry, because they write a STABLE per-account identifier into an Actions log and
the registry's logs are public (registry issues #183 and #370).

{probes}

## Do not edit these workflows here

The registry is the source. Regenerate the copy instead:

    python3 scripts/diagnostic-sink.py emit --outdir <dir> --sink-repo {sink_repo}

run from a `jeswr/agent-account-registry` checkout. The emitted workflows are byte-for-byte the
registry's, refused outright if their guard has regressed there.

## The guard is load-bearing HERE too

Every job carries `if: ${{{{ {PRIVATE_GUARD_TEXT} }}}}`. GitHub re-evaluates that
against THIS repository on every run, so if this repo is ever made public the probes go inert by
themselves — no edit, no human noticing in time. Never remove it, and never move these workflows
to a repo without it.

A run whose job reports as **skipped** is telling you this repository is not private.

## What this repo must provide

Secrets, in the environment(s) below:

{secrets}
{contextual}

Environments (each needs a custom deployment-branch policy naming only this repo's default
branch — an environment GitHub auto-creates has NO policy and admits every ref):

{environments}

Whatever triggers these workflows declare on the registry are the triggers here: the copy is
byte-for-byte, so this repo never adds a cadence the registry has not reviewed.
"""


def bundle(sources, requirements, sink_repo):
    """{relative path: content} — the probes VERBATIM plus the generated sink README.

    Verbatim is the contract, not an implementation detail: the guard verified above is only
    verified for the text that was verified, so anything that rewrote a line would be shipping
    text no one checked."""
    files = {os.path.join(WORKFLOW_DIR, name): text for name, text in sources.items()}
    files[SINK_README_NAME] = sink_readme(sources, requirements, sink_repo)
    return files


def write_bundle(files, outdir):
    """Write the bundle ALL-OR-NOTHING. Every target path is checked for existence FIRST, so a
    collision refuses before the first byte is written and never overwrites a file that was
    already there. Returns the written paths, sorted."""
    targets = {relpath: os.path.join(outdir, relpath) for relpath in sorted(files)}
    clashes = sorted(relpath for relpath, path in targets.items() if os.path.exists(path))
    if clashes:
        raise SinkRefusal(f"refusing to overwrite existing file(s) under {outdir}: "
                          + ", ".join(clashes))
    for relpath in sorted(targets):
        path = targets[relpath]
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(files[relpath])
    return sorted(targets.values())


# ---- the runbook ---------------------------------------------------------------------------------
class Step:
    """One runbook step: a title, prose, and the commands a maintainer runs."""

    def __init__(self, title, note, commands=()):
        self.title = title
        self.note = note
        self.commands = tuple(commands)

    def tokens(self):
        """Every command, tokenised. The self-test asserts EXACT flag membership over these —
        a substring check over the rendered text would accept `--private` inside `--privateX`
        and would read a flag out of the prose."""
        return tuple(tuple(shlex.split(command)) for command in self.commands)


def runbook(requirements, sink_repo, sink_default_branch, outdir="<dir>"):
    """The ordered steps that stand the sink up. Derived from `requirements`, so a probe that
    starts reading a new secret changes the runbook without anyone remembering to.

    ORDER IS LOAD-BEARING: the deployment-branch policy goes on BEFORE any secret value is
    written. Between the value and the policy the environment admits EVERY branch, so each secret
    would be readable by an env-bound job at an arbitrary ref — the #101 hole in a new shape.
    `research/271-coordinated-secret-migration-runbook.md` §S3 makes the same argument for the
    registry's own migration; this is the same ordering for the same reason."""
    steps = [
        Step("0. The sink must exist and be PRIVATE — create only if absent, then PROVE it",
             "Every probe here is guarded on the repository being private, so a public sink is "
             "not a leak — it is a permanent no-op that looks like a working probe. Confirm "
             "before spending the rest of this runbook. If the repo does not exist yet, create "
             "it private; never create it public and flip it afterwards.\n\n"
             "Both lines are RUNNABLE AS WRITTEN in either state, which an unconditional "
             "`view` then `create` pair is not: for a sink that already exists the create fails, "
             "and for one that does not the view fails first. The first line therefore creates "
             "ONLY when the view says the repo is absent. The second is an ASSERTION, not a "
             "display: `gh api repos/<sink> --jq .private` prints `true` or `false`, and `test` "
             "exits NONZERO on `false` — the same literal `\"private\": true` that "
             "`model-health._repo_confirmed_private` requires before it will route detail to this "
             "repo (#432). Do not go on to step 1 until it exits 0.",
             [f"gh repo view {sink_repo} >/dev/null 2>&1 || gh repo create {sink_repo} --private",
              f'test "$(gh api repos/{sink_repo} --jq .private)" = true']),
    ]
    for environment in requirements.environments:
        steps.append(Step(
            f"1. Environment `{environment}`, with a default-branch-only deployment policy",
            "GitHub AUTO-CREATES an environment referenced by a workflow, with NO deployment "
            "policy — a default-allow shape. Set the policy explicitly and read it back: it must "
            f"be one `branch`-typed entry naming exactly `{sink_default_branch}`.",
            [f"gh api -X PUT repos/{sink_repo}/environments/{environment} "
             "-F deployment_branch_policy[protected_branches]=false "
             "-F deployment_branch_policy[custom_branch_policies]=true",
             f"gh api -X POST repos/{sink_repo}/environments/{environment}"
             f"/deployment-branch-policies -f name={sink_default_branch} -f type=branch",
             f"gh api repos/{sink_repo}/environments/{environment}/deployment-branch-policies"]))
    for environment in requirements.environments:
        steps.append(Step(
            f"2. Secrets, into `{environment}` (never repo scope) — AFTER the policy above",
            "Paste each value at the prompt; never pass it as an argument (it would land in the "
            "shell history and in `ps`). These are the accounts the probes will identify, so put "
            "in exactly the ones you want identified.",
            [f"gh secret set {name} -R {sink_repo} --env {environment}"
             for name in requirements.secrets]))
    if requirements.context_readers:
        expected = sink_expected_name_pattern(requirements)
        steps.append(Step(
            "3. The account tokens the fleet fingerprint covers — enumerate them, then read back",
            "One probe reads the WHOLE secrets context and filters it by NAME with its own "
            f"allowlist `{requirements.allowlist}`, so its coverage is exactly the secrets in the "
            "environment above whose name matches that pattern.\n"
            + "\n".join(f"  - {filename} job `{job}` reads `{read}`"
                        for filename, job, read in requirements.context_readers)
            + "\n\nNo `gh secret set` line is printed for these, deliberately. This repo's prose "
            "writes the family as `ACCTNN_TOKEN`, but that is NOTATION — no secret is called "
            "that, `gh secret set` would take it literally, and the probe's allowlist ACCEPTS the "
            "literal name, so a pasted placeholder installs one empty slot and the sweep then "
            "runs GREEN having fingerprinted nothing. Instead: read the concrete names out of the "
            "registry environment that already holds them (first command), add each one with the "
            "step-2 command under ITS OWN name, then read the sink environment back (second "
            "command). Every account you meant to cover must appear in that read-back — it is the "
            "only thing that distinguishes a provisioned fleet from an empty one, and step 5 "
            "cannot tell them apart.\n\n"
            "THE ENUMERATION IS FILTERED, AND THAT FILTER IS THE POINT. The registry environment "
            "it reads is a TRUST BOUNDARY, not an account-token inventory — it also holds the "
            "registry's admin PAT and alert token, which the probe never touches and the sink "
            "must never hold. The first command therefore prints only the names the probe itself "
            "would fingerprint; copy those, plus the named secrets of step 2, and nothing else. "
            "The third command is the ENFORCEMENT of that: it exits NONZERO if the sink's "
            "environment holds ANY name outside "
            f"`{expected}`. A read-back that only prints names cannot catch a credential that was "
            "pasted in by mistake; this one refuses.",
            [f"gh api repos/{REGISTRY_REPO}/environments/{environment}/secrets "
             f"--jq '.secrets[].name' | grep -E '{requirements.allowlist}'"
             for environment in requirements.environments]
            + [f"gh api repos/{sink_repo}/environments/{environment}/secrets "
               "--jq '.secrets[].name' | sort" for environment in requirements.environments]
            + [f"! gh api repos/{sink_repo}/environments/{environment}/secrets "
               f"--jq '.secrets[].name' | grep -vE '{expected}'"
               for environment in requirements.environments]))
    steps.append(Step(
        "4. The workflows themselves",
        "Emitted byte-for-byte from the registry, guard included. Commit them to the sink's "
        "default branch — the deployment policy above admits no other ref.",
        [f"python3 scripts/diagnostic-sink.py emit --outdir {outdir} --sink-repo {sink_repo}"]))
    steps.append(Step(
        "5. Prove the guard evaluates TRUE there",
        "A run that reports the job as skipped means the sink is not private (or the guard did "
        "not travel). That is the whole acceptance test for this move: the same file that is a "
        "permanent no-op on the registry must produce output here.",
        [f"gh workflow run {name} -R {sink_repo}" for name in sorted(PROBE_WORKFLOWS)]))
    steps.append(Step(
        "6. Only then, retire the registry copies",
        "The public copies are the SOURCE this bundle is derived from and they are already "
        "inert, so there is no hurry and no risk in leaving them until a sink run has been seen "
        "green. Retire them in their own PR.",
        []))
    return tuple(steps)


def render_runbook(steps):
    lines = []
    for step in steps:
        lines.append(f"## {step.title}")
        lines.append("")
        lines.append(step.note)
        if step.commands:
            lines.append("")
            lines.extend(f"    {command}" for command in step.commands)
        lines.append("")
    return "\n".join(lines)


# ---- CLI -----------------------------------------------------------------------------------------
def _prepare(repo_root, sink_repo):
    """The verification every command runs first: read the probes, prove the guard, derive the
    requirements. Raises SinkRefusal; no command proceeds past it."""
    sources = probe_sources(repo_root)
    ok, reason = bundle_verdict(parse_probes(sources))
    if not ok:
        raise SinkRefusal(reason)
    requirements = sink_requirements(sources)
    return sources, requirements, bundle(sources, requirements, sink_repo)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Bootstrap the private diagnostic sink for the account probes (issue #370).")
    parser.add_argument("command", choices=("verify", "plan", "emit"),
                        help="verify: prove the probes are still guarded. plan: print the runbook. "
                             "emit: write the sink bundle.")
    parser.add_argument("--outdir", help="where `emit` writes the bundle (must not already hold "
                                         "any of its files)")
    parser.add_argument("--repo-root", default=os.path.dirname(SCRIPT_DIR),
                        help="registry checkout to read the probes from")
    parser.add_argument("--sink-repo", default=DEFAULT_SINK_REPO)
    parser.add_argument("--sink-default-branch", default=DEFAULT_SINK_DEFAULT_BRANCH)
    parser.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    try:
        sources, requirements, files = _prepare(args.repo_root, args.sink_repo)
        if args.command == "verify":
            print(f"diagnostic-sink: {len(sources)} probe workflow(s) verified — every job is "
                  f"provably unreachable unless `{PRIVATE_GUARD_TEXT}`.")
            print("diagnostic-sink: the sink must provide secrets "
                  + ", ".join(requirements.secrets) + " in environment(s) "
                  + ", ".join(requirements.environments) + ".")
            return 0
        if args.command == "plan":
            print(render_runbook(runbook(requirements, args.sink_repo, args.sink_default_branch,
                                         args.outdir or "<dir>")))
            return 0
        if not args.outdir:
            raise SinkRefusal("emit requires --outdir")
        for path in write_bundle(files, args.outdir):
            print(f"diagnostic-sink: wrote {path}")
        return 0
    except SinkRefusal as refusal:
        print(f"diagnostic-sink: REFUSED — {refusal}", file=sys.stderr)
        return 2


# =============================================================================================
# self-test
# =============================================================================================
def _self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got} (want {want})")

    _test_guard_polarity(chk)
    _test_guard_covers_every_job(chk)
    _test_bundle_set(chk)
    _test_requirements_are_derived(chk)
    _test_allowlist_is_derived(chk)
    _test_bundle_is_verbatim(chk)
    _test_runbook_is_derived(chk)
    _test_step0_runs_in_every_repo_state(chk)
    _test_fleet_step_never_copies_unrelated_credentials(chk)
    _test_write_is_all_or_nothing(chk)
    _test_cli(chk)
    _test_live_tree(chk)

    print("diagnostic-sink self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def _verdict(job_docs, filename="probe.yml"):
    """`guard_verdict`'s ok bit, with any exception folded into a distinguishable value.

    MUTATION HYGIENE, not politeness. A mutant that deletes a guard and lets the next line raise
    would otherwise ABORT the suite part-way: the rows above it go red, the run records as a kill,
    and every check below it never executed (#945). Folding the raise into a value keeps the check
    COUNT constant, so a kill is a kill. It is also an assertion in its own right — `guard_verdict`
    must ANSWER a malformed workflow, not explode on it."""
    try:
        return guard_verdict(filename, job_docs)[0]
    except Exception as exc:                                       # noqa: BLE001 - see docstring
        return f"raised {type(exc).__name__}"


def _reason(job_docs, filename="probe.yml"):
    """`guard_verdict`'s reason string, with the same exception folding as `_verdict`."""
    try:
        return guard_verdict(filename, job_docs)[1]
    except Exception as exc:                                       # noqa: BLE001 - see _verdict
        return f"raised {type(exc).__name__}"


def _job(condition):
    """A parsed job doc carrying (or not carrying) an `if:`. Built as a dict, not parsed from
    YAML, so the polarity rows below run with no third-party dependency at all."""
    doc = {"runs-on": "ubuntu-latest", "steps": [{"run": "echo probe"}]}
    if condition is not None:
        doc["if"] = condition
    return doc


GUARD = "${{ " + PRIVATE_GUARD_TEXT + " }}"


def _test_guard_polarity(chk):
    """The accept AND the reject direction of the one property this script exists to prove.

    The mutant values here (`vars.SINK_DEBUG`, `github.actor == 'octocat'`) appear NOWHERE else in
    this harness on purpose: a substituted value that collides with one the fixture already uses
    produces a value-identical survivor that reads as a kill."""
    accepted = [
        ("the exact #183 guard", GUARD),
        # Spelled out, NOT composed from PRIVATE_GUARD_TEXT: an input derived from the same
        # constant the code reads cannot fail when that constant moves (question (c)).
        ("the guard spelled literally", "${{ github.event.repository.private == true }}"),
        ("the guard ANDed with an unrelated condition (still unreachable when it is false)",
         "${{ " + PRIVATE_GUARD_TEXT + " && github.actor == 'octocat' }}"),
        ("the quoted-true spelling", "${{ github.event.repository.private == 'true' }}"),
    ]
    for label, condition in accepted:
        chk(f"guard: ACCEPTS {label}", _verdict({"probe": _job(condition)}), True)

    refused = [
        ("no `if:` at all", None),
        ("an empty `if:`", ""),
        ("the guard ORed away — the classic gate bypass",
         "${{ always() || " + PRIVATE_GUARD_TEXT + " }}"),
        ("a second OR arm that reaches on its own",
         "${{ " + PRIVATE_GUARD_TEXT + " || vars.SINK_DEBUG == 'on' }}"),
        ("the INVERTED guard", "${{ github.event.repository.private == false }}"),
        ("the NEGATED guard", "${{ !(" + PRIVATE_GUARD_TEXT + ") }}"),
        ("a bare truthiness test — equivalent to a human, not a comparison this can pin",
         "${{ github.event.repository.private }}"),
        ("the guard as a STRING ARGUMENT to a function (the #621-class defeat)",
         "${{ contains('" + PRIVATE_GUARD_TEXT + "', 'private') }}"),
        ("an unconditional `true`", "${{ true }}"),
        ("an `if:` interleaving literal text with an expression (undecidable)",
         "probe-${{ " + PRIVATE_GUARD_TEXT + " }}"),
        ("an unbalanced expression (unparseable)", "${{ " + PRIVATE_GUARD_TEXT + " && ( }}"),
        # The two SUBSTRING collisions around the recognised atom. Both are spelled literally (not
        # composed from PRIVATE_GUARD_TEXT) so they keep colliding with whatever the constant says.
        # The first is the dangerous one and is why the pattern is anchored: `truefoo` is an
        # undefined path, so it is null, and GitHub compares `false == null` as `0 == 0` — the
        # condition is TRUE exactly when the repository is PUBLIC. An unanchored pattern pinned it
        # false and reported the job provably unreachable.
        ("a SUFFIX on the right operand — reaches on a PUBLIC repo, so it is the opposite of the "
         "guard", "${{ github.event.repository.private == truefoo }}"),
        ("a PREFIX on the left operand — a comparison against an entirely different path",
         "${{ needs.x.outputs.github.event.repository.private == true }}"),
    ]
    for label, condition in refused:
        chk(f"guard: REFUSES {label}", _verdict({"probe": _job(condition)}), False)

    # The refusal must NAME the job — a bare False sends the reader looking through both files.
    chk("guard: the refusal names the offending job and the guard it lost",
        [token in _reason({"leaky": _job(None)})
         for token in ("probe.yml", "leaky", PRIVATE_GUARD_TEXT)], [True, True, True])
    # And an undecidable `if:` must refuse for the UNDECIDED reason, not be silently lumped in
    # with "can run": the operator's fix differs (rewrite the condition vs restore the guard).
    chk("guard: an undecidable `if:` refuses as undecidable, not as reachable",
        "cannot decide" in _reason({"probe": _job("probe-${{ true }}")}), True)


def _test_guard_covers_every_job(chk):
    """EVERY job, not the first, not any. Kills a `break`-on-first-ok loop and an `any(...)`.
    Both orderings, because a loop that returns on the first job passes one of them by luck."""
    guarded, leaky = _job(GUARD), _job(None)
    chk("guard: both jobs guarded -> ok", _verdict({"aaa": guarded, "zzz": guarded}), True)
    chk("guard: the SECOND job unguarded -> refused (a loop that stops at the first pass is blind)",
        _verdict({"aaa": guarded, "zzz": leaky}), False)
    chk("guard: the FIRST job unguarded -> refused",
        _verdict({"aaa": leaky, "zzz": guarded}), False)
    chk("guard: a workflow with NO jobs is a refusal ANSWERED, not a vacuous pass and not a "
        "crash", (_verdict({}), _verdict(None)), (False, False))


def _test_bundle_set(chk):
    """The bundle is BOTH probes or it is a refusal."""
    guarded = {"probe": _job(GUARD)}
    both = {name: guarded for name in PROBE_WORKFLOWS}
    chk("bundle: both probes, both guarded -> ok", bundle_verdict(both)[0], True)
    chk("bundle: one probe missing -> refused",
        bundle_verdict({PROBE_WORKFLOWS[0]: guarded})[0], False)
    chk("bundle: an extra workflow smuggled in -> refused",
        bundle_verdict(dict(both, **{"dispatch.yml": guarded}))[0], False)
    for name in PROBE_WORKFLOWS:
        chk(f"bundle: {name} unguarded -> the WHOLE bundle is refused",
            bundle_verdict(dict(both, **{name: {"probe": _job(None)}}))[0], False)


def _fixture_probe(condition_line, secret_line, environment_line="    environment: sink-env",
                   filter_line=""):
    lines = ["name: probe", "on:", "  workflow_dispatch: {}", "permissions: {}", "jobs:",
             "  probe:", "    runs-on: ubuntu-latest"]
    if condition_line:
        lines.append(condition_line)
    if environment_line:
        lines.append(environment_line)
    lines += ["    steps:", "      - name: probe", "        env:"]
    if secret_line:
        lines.append(secret_line)
    lines += ["        run: |", "          echo probe"]
    if filter_line:
        lines.append("          " + filter_line)
    lines.append("")
    return "\n".join(lines)


FIXTURE_GUARD_LINE = "    if: ${{ " + PRIVATE_GUARD_TEXT + " }}"
FIXTURE_SECRET_LINE = "          TOK: ${{ secrets.SINK_FIXTURE_TOKEN }}"
FIXTURE_CONTEXT_LINE = "          ALL: ${{ toJSON(secrets) }}"
# The fixture's OWN allowlist, in the fixture's OWN namespace. Spelled here and embedded in the
# fixture text below; the code under test never reads this constant, it reads the text — so this is
# an independent input, not the tautology of question (c). `SINKACCT` collides with nothing in this
# repo, so a hardcoded `^ACCT...` in the code cannot produce this answer.
FIXTURE_ALLOWLIST = "^SINKACCT[0-9]+_TOKEN$"


def _fixture_filter_line(allowlist=FIXTURE_ALLOWLIST):
    return "jq -r 'keys[] | select(test(\"" + allowlist + "\"))' \"$SECRETS_FILE\""


def _fixture_sources(condition_line=FIXTURE_GUARD_LINE, secret_line=FIXTURE_SECRET_LINE,
                     environment_line="    environment: sink-env", filter_line=""):
    return {name: _fixture_probe(condition_line, secret_line, environment_line, filter_line)
            for name in PROBE_WORKFLOWS}


def _fixture_contextual(filter_line=None):
    """The fixture shape that exercises the whole-context path: a probe reading `toJSON(secrets)`
    and (by default) carrying its own anchored allowlist."""
    return _fixture_sources(
        secret_line=FIXTURE_CONTEXT_LINE,
        filter_line=_fixture_filter_line() if filter_line is None else filter_line)


def _test_requirements_are_derived(chk):
    """Derived from the probe text, never restated. The fixture names a secret and an environment
    that exist nowhere else in this repo, so a hardcoded list cannot produce this answer."""
    chk("requirements: the whole requirement is DERIVED from the probe text — a secret name and "
        "an environment that appear nowhere else in this repo",
        sink_requirements(_fixture_sources()),
        Requirements(("SINK_FIXTURE_TOKEN",), (), ("sink-env",), None))

    contextual = _fixture_contextual()
    chk("requirements: a toJSON(secrets) job is recorded as a context reader, not as a secret",
        (sink_requirements(contextual).secrets,
         [read for _f, _j, read in sink_requirements(contextual).context_readers]),
        ((), ["toJSON(secrets)", "toJSON(secrets)"]))

    def refusal(sources):
        # Any exception, not just SinkRefusal: a mutant that drops a fail-closed branch and lets
        # the next line raise must land as a red ROW here, not as an aborted suite (#945).
        try:
            sink_requirements(sources)
        except Exception as exc:                                   # noqa: BLE001 - see comment
            return f"{type(exc).__name__}: {exc}"
        return None

    # The refusal probe must not be refusing everything: without this row, a `sink_requirements`
    # that raised unconditionally would leave every "is not None" row below green (question (d) —
    # does the control ever take the OTHER branch).
    chk("requirements: the well-formed fixture raises NOTHING (the refusals below are decisions, "
        "not a function that always refuses)", refusal(_fixture_sources()), None)

    unbound = refusal(_fixture_sources(environment_line=""))
    chk("requirements: a secret-consuming job with NO environment binding is REFUSED "
        "(the sink would serve it from repo scope, at any ref)",
        unbound is not None and "environment" in unbound, True)
    chk("requirements: ... and the refusal names the job",
        unbound is not None and "probe" in unbound, True)
    # These two refusals overlap on their INPUT — an unparsable document also derives no consuming
    # job — so `not consuming` alone would answer both and the `is None` branch would be
    # individually unkillable (#945). They are separated on their DIAGNOSIS instead, which is the
    # thing that actually differs for the operator: a broken document is fixed by repairing YAML,
    # an empty scan by looking at why the probes stopped reading secrets.
    chk("requirements: a scan deriving NO secret-consuming job is REFUSED, not accepted as "
        "'the probes need nothing', and says THAT",
        "NO secret-consuming job" in (refusal(_fixture_sources(secret_line="")) or ""), True)
    chk("requirements: an unparsable jobs block is REFUSED as a PARSE failure, not folded into "
        "the empty-scan diagnosis",
        "cannot locate a `jobs:` block"
        in (refusal({name: "name: broken\n" for name in PROBE_WORKFLOWS}) or ""), True)


def _test_allowlist_is_derived(chk):
    """The account-token allowlist is read OUT OF the probe, and a probe that cannot supply one is
    a refusal — never an unfiltered enumeration of a trust boundary."""
    def refusal(sources):
        # Folded, per #945: a mutant that drops a branch and lets the next line raise must be a red
        # ROW, not an aborted suite with a shortened check count.
        try:
            return None, sink_requirements(sources)
        except Exception as exc:                                   # noqa: BLE001 - see comment
            return f"{type(exc).__name__}: {exc}", None

    # ACCEPT direction, and the control for question (d): the well-formed contextual fixture
    # derives the fixture's OWN pattern and raises nothing.
    reason, derived = refusal(_fixture_contextual())
    chk("allowlist: DERIVED verbatim from the whole-context probe's own `test(\"^...$\")` filter",
        (reason, derived.allowlist if derived else None), (None, FIXTURE_ALLOWLIST))
    # And it is derived ONLY where there is something unenumerable to filter: a probe reading a
    # NAMED secret needs no allowlist, and `None` here is what keeps `grep -E ''` (which matches
    # every line) out of the runbook.
    named_reason, named = refusal(_fixture_sources(filter_line=_fixture_filter_line()))
    chk("allowlist: a probe with no whole-context read carries NO allowlist, and that is not a "
        "refusal", (named_reason, named.allowlist if named else "no requirements"), (None, None))

    # REJECT direction, one input per branch so no branch is masked by another (#945).
    missing = refusal(_fixture_contextual(filter_line=""))[0]
    chk("allowlist: a whole-context reader with NO name filter at all is REFUSED — an unfiltered "
        "enumeration would name every credential in the environment",
        (missing is not None, "no name allowlist" in (missing or ""),
         PROBE_WORKFLOWS[0] in (missing or "")), (True, True, True))
    # Anchoring, portability and validity are three DIFFERENT rules with three different fixes, and
    # each input below is ACCEPTED by the other two rules — so removing any one rule alone shows up
    # as a red row rather than being masked by its neighbour (#945's mutually-masking shape).
    unanchored = refusal(_fixture_contextual(
        filter_line=_fixture_filter_line("SINKACCT[0-9]+_TOKEN")))[0]
    chk("allowlist: an UNANCHORED filter is REFUSED — in `grep -E` it would also select every "
        "name that merely contains an account-token name",
        (unanchored is not None, "UNANCHORED" in (unanchored or "")), (True, True))

    # The two probes disagree: one filters on the fixture allowlist, the other on a different one.
    split = _fixture_contextual()
    split[PROBE_WORKFLOWS[1]] = _fixture_probe(
        FIXTURE_GUARD_LINE, FIXTURE_CONTEXT_LINE,
        filter_line=_fixture_filter_line("^SINKOTHER[0-9]+_TOKEN$"))
    disagree = refusal(split)[0]
    chk("allowlist: readers carrying DIFFERENT allowlists are REFUSED, not silently unioned or "
        "first-wins", (disagree is not None, "DIFFERENT name allowlists" in (disagree or "")),
        (True, True))

    backslash = refusal(_fixture_contextual(
        filter_line=_fixture_filter_line(r"^SINKACCT\d+_TOKEN$")))[0]
    chk("allowlist: an Oniguruma-only escape (`\\d`) is REFUSED rather than handed to `grep -E`, "
        "where it would select a different set of names",
        (backslash is not None, "POSIX-ERE" in (backslash or "")), (True, True))
    invalid = refusal(_fixture_contextual(
        filter_line=_fixture_filter_line("^SINKACCT[0-9+_TOKEN$")))[0]
    chk("allowlist: a pattern that is not a valid regex at all is REFUSED as INVALID, a different "
        "diagnosis from the portability one",
        (invalid is not None, "not a valid regular expression" in (invalid or "")), (True, True))

    # The expected-name pattern the read-back enforces: the allowlist, PLUS every named secret the
    # allowlist does not already cover, and NOTHING else. Built from a Requirements whose names
    # appear nowhere else, so a hardcoded answer cannot produce it.
    chk("allowlist: the sink's expected-name pattern is the allowlist plus each named requirement "
        "the allowlist does not already cover — and the covered one is not restated",
        sink_expected_name_pattern(Requirements(
            ("SINKACCT07_TOKEN", "SINK_ODD_SALT"), (("f.yml", "j", "toJSON(secrets)"),),
            ("sink-odd-env",), FIXTURE_ALLOWLIST)),
        FIXTURE_ALLOWLIST + "|^SINK_ODD_SALT$")


def _test_bundle_is_verbatim(chk):
    """Byte-for-byte. The guard was verified for the text that was verified."""
    sources = _fixture_sources()
    requirements = sink_requirements(sources)
    files = bundle(sources, requirements, "owner/sink")
    chk("bundle: exactly the two probes plus the one authored README",
        sorted(files), sorted([os.path.join(WORKFLOW_DIR, name) for name in PROBE_WORKFLOWS]
                              + [SINK_README_NAME]))
    chk("bundle: every probe is copied BYTE-FOR-BYTE (a rewrite would ship unverified text)",
        [files[os.path.join(WORKFLOW_DIR, name)] == sources[name] for name in PROBE_WORKFLOWS],
        [True, True])
    readme = files[SINK_README_NAME]
    chk("bundle: the sink README names both probes, the guard, and the regeneration source",
        [name in readme for name in PROBE_WORKFLOWS]
        + [PRIVATE_GUARD_TEXT in readme, "diagnostic-sink.py emit" in readme,
           "SINK_FIXTURE_TOKEN" in readme, "sink-env" in readme, "owner/sink" in readme],
        [True, True, True, True, True, True, True])

    # The whole-context bullet is the one the sink's maintainer acts on, and it is the one that
    # used to say "add each one you want fingerprinted" with no boundary stated at all.
    ctx_sources = _fixture_contextual()
    ctx_readme = bundle(ctx_sources, sink_requirements(ctx_sources),
                        "owner/sink")[SINK_README_NAME]
    chk("bundle: the sink README states the whole-context probe's NAME allowlist AND that the "
        "environment is a boundary — without both, 'add each one' reads as an instruction to copy "
        "every credential the source environment happens to hold",
        (FIXTURE_ALLOWLIST in ctx_readme, "trust boundary" in ctx_readme), (True, True))


# The requirements that exercise the whole-context (fleet) path. Every name in it appears nowhere
# else in this repo, so no hardcoded answer in the code can reproduce the runbook it renders.
CTX_REQUIREMENTS = Requirements(("SINK_ODD_SECRET",), (("f.yml", "j", "toJSON(secrets)"),),
                                ("sink-odd-env",), FIXTURE_ALLOWLIST)


def _test_runbook_is_derived(chk):
    """The runbook is a function of the requirements. Feeding it names that appear nowhere else
    proves it, and tokenised flag membership is what makes `--private` an assertion rather than a
    substring that `--privately` would also satisfy."""
    requirements = Requirements(("SINK_ODD_SECRET",), (), ("sink-odd-env",), None)
    steps = runbook(requirements, "owner/sink", "trunk")
    commands = [command for step in steps for command in step.commands]
    tokens = [token for step in steps for command in step.tokens() for token in command]

    chk("runbook: the derived secret name reaches a `gh secret set` line",
        any(shlex.split(c)[:2] == ["gh", "secret"] and "SINK_ODD_SECRET" in shlex.split(c)
            for c in commands), True)
    chk("runbook: the derived environment reaches the --env argument",
        any("--env" in shlex.split(c) and
            shlex.split(c)[shlex.split(c).index("--env") + 1] == "sink-odd-env"
            for c in commands), True)
    chk("runbook: the derived default branch reaches the deployment-branch policy",
        any("-f" in shlex.split(c) and "name=trunk" in shlex.split(c) for c in commands), True)
    chk("runbook: EVERY `/environments/` path names the derived environment — a hardcoded one "
        "would set the policy on an environment the workflows never bind to",
        sorted({token.split("/environments/", 1)[1].split("/")[0]
                for command in commands for token in shlex.split(command)
                if "/environments/" in token}), ["sink-odd-env"])
    chk("runbook: the sink is created PRIVATE — exact token, and `--public` appears NOWHERE",
        ("--private" in tokens, "--public" in tokens), (True, False))

    policy = next(i for i, c in enumerate(commands) if "deployment-branch-policies" in c)
    first_secret = next(i for i, c in enumerate(commands) if shlex.split(c)[:2] == ["gh", "secret"])
    chk("runbook: the deployment-branch policy is set BEFORE the first secret value is written "
        "(between them the environment admits every branch)", policy < first_secret, True)

    contextual = CTX_REQUIREMENTS
    ctx_steps = runbook(contextual, "owner/sink", "trunk")
    titles = [step.title for step in ctx_steps]
    chk("runbook: a whole-context reader adds the account-token step; no reader, no step",
        (any("fleet fingerprint" in title for title in titles),
         any("fleet fingerprint" in step.title for step in steps)), (True, False))

    # The fleet step is the one whose subject CANNOT be enumerated offline, so it is the one that
    # invites a name-shaped placeholder — and `gh secret set` has no placeholder syntax: whatever
    # is written there is the secret that gets created. These two rows are what stop that.
    ctx_argv = [shlex.split(command) for step in ctx_steps for command in step.commands]
    chk("runbook: EVERY `gh secret set` names a DERIVED secret — a name-shaped placeholder would "
        "be run verbatim and install a slot with no account behind it",
        sorted({argv[3] for argv in ctx_argv if argv[:3] == ["gh", "secret", "set"]}),
        ["SINK_ODD_SECRET"])
    fleet_reads = [(index, token) for index, argv in enumerate(ctx_argv) for token in argv
                   if token.endswith("/environments/sink-odd-env/secrets")]
    fleet_repos = sorted({token.split("/environments/", 1)[0] for _index, token in fleet_reads})
    dispatch = next(index for index, argv in enumerate(ctx_argv) if argv[:2] == ["gh", "workflow"])
    chk("runbook: the secret NAMES are read from TWO repos — the one that already holds them (the "
        "sink is empty at that point, so it cannot be their source) and the sink itself, read "
        "BACK before the probes are dispatched: a fleet that was never provisioned must be "
        "visible, not a green run over one slot",
        (len(fleet_repos), "repos/owner/sink" in fleet_repos,
         max([index for index, _token in fleet_reads] or [dispatch + 1]) < dispatch),
        (2, True, True))
    chk("runbook: every command tokenises (a step whose command cannot be run is not a runbook)",
        all(step.tokens() is not None for step in steps), True)
    chk("runbook: the rendered text carries every command verbatim",
        all(command in render_runbook(steps) for command in commands), True)


# ---- the runbook, EXECUTED ------------------------------------------------------------------
# The rows above prove the commands are DERIVED. These prove they RUN — and that they run to the
# right answer in each state the sink can be in. Nothing here reaches the network: `gh` is a stub
# on PATH whose whole job is to be the seam. `--jq '.secrets[].name'` is what the real CLI applies
# server-side, so the stub prints one name per line and the assertion under test is the part this
# script actually authors: the FILTER and the read-back's exit code.
#
# The filter lives in `grep -E`, not inside `--jq`, precisely so it is this testable offline. A
# filter buried in the jq program would be executed by a binary this container cannot stand in for,
# and the reviewer's blocker would have been re-checkable only by eye.
GH_STUB = r"""#!/bin/sh
# `gh` stand-in. State lives in $STUB_DIR, so a create in one command is visible to the read-back
# in the next: the runbook's step-0 lines are only correct TOGETHER.
printf '%s\n' "$*" >> "$STUB_DIR/calls"
case "$1 $2" in
  "repo view")
    [ -f "$STUB_DIR/private" ] || exit 1
    ;;
  "repo create")
    if [ -f "$STUB_DIR/private" ]; then
      echo "gh: repository already exists" >&2
      exit 1
    fi
    case "$*" in
      *--private*) echo true > "$STUB_DIR/private" ;;
      *) echo false > "$STUB_DIR/private" ;;
    esac
    ;;
  "api repos"*)
    [ -f "$STUB_DIR/names" ] && { cat "$STUB_DIR/names"; exit 0; }
    [ -f "$STUB_DIR/private" ] || exit 1
    cat "$STUB_DIR/private"
    ;;
esac
exit 0
"""


def _stubbed_shell(chk_dir, commands, state):
    """Run `commands` under bash with the `gh` stub on PATH. Returns (returncode, stdout, calls).

    The child environment is built from scratch — PATH and STUB_DIR only — so the result cannot
    depend on anything this process inherited."""
    import shutil
    import subprocess
    stub_bin = os.path.join(chk_dir, "bin")
    stub_state = os.path.join(chk_dir, "state")
    os.makedirs(stub_bin, exist_ok=True)
    os.makedirs(stub_state, exist_ok=True)
    gh_path = os.path.join(stub_bin, "gh")
    with open(gh_path, "w", encoding="utf-8") as handle:
        handle.write(GH_STUB)
    os.chmod(gh_path, 0o755)
    for name, content in state.items():
        with open(os.path.join(stub_state, name), "w", encoding="utf-8") as handle:
            handle.write(content)
    bash = shutil.which("bash")
    if bash is None or any(command is None for command in commands):   # pragma: no cover
        # Never silently pass: an unrunnable harness must land as a red ROW.
        return "no-harness", "", []
    proc = subprocess.run(  # noqa: S603 - fixed argv, hermetic env, stub-only PATH
        [bash, "-c", "\n".join(commands)], capture_output=True, text=True,
        env={"PATH": stub_bin + os.pathsep + "/usr/bin" + os.pathsep + "/bin",
             "STUB_DIR": stub_state})
    calls_path = os.path.join(stub_state, "calls")
    calls = []
    if os.path.isfile(calls_path):
        with open(calls_path, encoding="utf-8") as handle:
            calls = handle.read().splitlines()
    return proc.returncode, proc.stdout, calls


def _only(commands, predicate):
    """The single command matching `predicate`, or None when the step's shape has drifted. None
    rather than an exception so a drifted shape reds a row instead of aborting the suite (#945)."""
    matches = [command for command in commands if predicate(command)]
    return matches[0] if len(matches) == 1 else None


def _test_step0_runs_in_every_repo_state(chk):
    """Step 0, EXECUTED, in each of the three states the sink can be in. The previous shape (an
    unconditional `gh repo view` followed by an unconditional `gh repo create`) fails one command
    in EVERY state, and its `--jq .visibility` only PRINTED — a PUBLIC sink read back clean.

    Non-vacuity, by construction: deleting the read-back leaves state (c) green; making the create
    unconditional leaves state (b) green; flipping the expected literal reds (a) and (b)."""
    import tempfile
    step0 = runbook(CTX_REQUIREMENTS, "owner/sink", "trunk")[0]
    commands = list(step0.commands)

    with tempfile.TemporaryDirectory() as tmp:
        code, _out, calls = _stubbed_shell(os.path.join(tmp, "absent"), commands, {})
        chk("step 0: an ABSENT sink is CREATED (private) and then passes the read-back — the "
            "runbook is runnable as written, not only for a repo that already exists",
            (code, any(call.startswith("repo create") for call in calls)), (0, True))

    with tempfile.TemporaryDirectory() as tmp:
        code, _out, calls = _stubbed_shell(os.path.join(tmp, "private"), commands,
                                           {"private": "true\n"})
        chk("step 0: an EXISTING private sink passes WITHOUT a create being attempted — the create "
            "is conditional, so the documented already-exists state does not fail a command",
            (code, [call for call in calls if call.startswith("repo create")]), (0, []))

    with tempfile.TemporaryDirectory() as tmp:
        code, out, _calls = _stubbed_shell(os.path.join(tmp, "public"), commands,
                                           {"private": "false\n"})
        chk("step 0: an EXISTING PUBLIC sink FAILS — the visibility read-back is an assertion that "
            "exits nonzero, not a value printed for a human to notice",
            (code != 0, code != "no-harness", out.strip()), (True, True, ""))


# The registry environment as it really is: account tokens the probe fingerprints, ALONGSIDE the
# unrelated trust credentials `dispatch-secrets` also holds (the registry's admin PAT and its alert
# token, here under fixture names that appear nowhere else). Plus the two near-misses an UNANCHORED
# filter would wrongly select. If any of these reaches the sink, the runbook has told a maintainer
# to copy a credential the probes never touch into a second repository.
FLEET_FIXTURE_NAMES = "\n".join([
    "SINKACCT01_TOKEN",
    "SINKACCT02_TOKEN",
    "SINK_ODD_ADMIN_PAT",
    "SINK_ODD_ALERT_TOKEN",
    "SINK_ODD_SECRET",
    "XSINKACCT01_TOKEN",
    "SINKACCT01_TOKENX",
]) + "\n"


def _test_fleet_step_never_copies_unrelated_credentials(chk):
    """The blocker this step exists to close: the enumeration must name ONLY what the probe
    fingerprints, and the sink read-back must REJECT anything else rather than print it."""
    import tempfile
    fleet = next(step for step in runbook(CTX_REQUIREMENTS, "owner/sink", "trunk")
                 if "fleet fingerprint" in step.title)
    enumerate_cmd = _only(fleet.commands, lambda c: REGISTRY_REPO in c)
    assert_cmd = _only(fleet.commands, lambda c: "-vE" in shlex.split(c))
    # Named as its own row, because `_stubbed_shell` reports a missing command as the sentinel
    # "no-harness", which is != 0 — a step that rendered NO assertion at all would otherwise leave
    # every REJECT row below green. The rejection rows re-check the sentinel for the same reason.
    chk("fleet: the step renders exactly ONE filtered registry enumeration and exactly ONE "
        "rejecting sink read-back", (enumerate_cmd is not None, assert_cmd is not None),
        (True, True))

    with tempfile.TemporaryDirectory() as tmp:
        code, out, _calls = _stubbed_shell(os.path.join(tmp, "enum"), [enumerate_cmd],
                                           {"names": FLEET_FIXTURE_NAMES})
        chk("fleet: the registry enumeration names ONLY the account tokens the probe's own "
            "allowlist selects — the unrelated admin PAT and alert token in the same environment "
            "are never requested, and neither near-miss is selected",
            (code, out.split()), (0, ["SINKACCT01_TOKEN", "SINKACCT02_TOKEN"]))

    # The read-back ACCEPTS a correctly provisioned sink: allowlisted account tokens plus the
    # separately derived named requirement. Without this row an assertion that always failed would
    # leave the rejection row below green (question (d)).
    with tempfile.TemporaryDirectory() as tmp:
        code, out, _calls = _stubbed_shell(
            os.path.join(tmp, "clean"), [assert_cmd],
            {"names": "SINKACCT01_TOKEN\nSINKACCT02_TOKEN\nSINK_ODD_SECRET\n"})
        chk("fleet: the sink read-back ACCEPTS account tokens plus the derived named requirement "
            "(PROVENANCE_SALT's fixture stand-in) — it is a decision, not a blanket refusal",
            (code, out.strip()), (0, ""))

    for label, extra in (("the registry's admin PAT", "SINK_ODD_ADMIN_PAT"),
                         ("an unrelated token-shaped trust credential", "SINK_ODD_ALERT_TOKEN"),
                         ("a name the anchors exclude", "XSINKACCT01_TOKEN")):
        with tempfile.TemporaryDirectory() as tmp:
            code, _out, _calls = _stubbed_shell(
                os.path.join(tmp, "dirty"), [assert_cmd],
                {"names": "SINKACCT01_TOKEN\nSINK_ODD_SECRET\n" + extra + "\n"})
            chk(f"fleet: the sink read-back REJECTS {label} with a NONZERO exit — a read-back that "
                "only printed names would pass this",
                (code != 0, code != "no-harness"), (True, True))


def _test_write_is_all_or_nothing(chk):
    import tempfile
    files = {"a.txt": "alpha", os.path.join(WORKFLOW_DIR, "b.yml"): "beta"}
    with tempfile.TemporaryDirectory() as tmp:
        written = write_bundle(files, tmp)
        chk("write: both files land, nested path created",
            [os.path.relpath(path, tmp) for path in written],
            sorted(["a.txt", os.path.join(WORKFLOW_DIR, "b.yml")]))
        with open(os.path.join(tmp, "a.txt"), encoding="utf-8") as handle:
            chk("write: content is exact", handle.read(), "alpha")
    with tempfile.TemporaryDirectory() as tmp:
        # Only the SECOND file collides: a per-file "skip if exists" would still write the first.
        os.makedirs(os.path.join(tmp, WORKFLOW_DIR))
        with open(os.path.join(tmp, WORKFLOW_DIR, "b.yml"), "w", encoding="utf-8") as handle:
            handle.write("PRE-EXISTING")
        refused = False
        try:
            write_bundle(files, tmp)
        except SinkRefusal:
            refused = True
        with open(os.path.join(tmp, WORKFLOW_DIR, "b.yml"), encoding="utf-8") as handle:
            survived = handle.read()
        chk("write: a collision refuses, leaves the existing file untouched, and writes NEITHER "
            "file (all-or-nothing, not skip-the-clash)",
            (refused, survived, os.path.exists(os.path.join(tmp, "a.txt"))),
            (True, "PRE-EXISTING", False))


def _write_fixture_root(root, sources):
    os.makedirs(os.path.join(root, WORKFLOW_DIR), exist_ok=True)
    for name, text in sources.items():
        with open(os.path.join(root, WORKFLOW_DIR, name), "w", encoding="utf-8") as handle:
            handle.write(text)


def _test_cli(chk):
    """main() end to end — the entry point, on a real tree, through argparse. Entry points are
    where fabricating bugs survive precisely because the test has to build the world first."""
    import contextlib
    import io
    import tempfile

    def run(argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            # An escaping exception is folded into the exit code rather than allowed to abort the
            # suite: `main` must REFUSE its bad inputs, and a mutant that lets one crash instead
            # has to show up as a red row with the check count intact (#945).
            try:
                code = main(argv)
            except Exception as exc:                               # noqa: BLE001 - see comment
                code = f"raised {type(exc).__name__}"
        return code, out.getvalue(), err.getvalue()

    with tempfile.TemporaryDirectory() as tmp:
        good, bad = os.path.join(tmp, "good"), os.path.join(tmp, "bad")
        _write_fixture_root(good, _fixture_sources())
        _write_fixture_root(bad, _fixture_sources(condition_line=""))

        code, out, _ = run(["verify", "--repo-root", good])
        chk("cli: verify on a guarded tree exits 0 and reports the derived requirement",
            (code, "SINK_FIXTURE_TOKEN" in out, "sink-env" in out), (0, True, True))

        code, _, err = run(["verify", "--repo-root", bad])
        chk("cli: verify on an UNGUARDED tree exits 2 and says so",
            (code, "REFUSED" in err), (2, True))

        code, out, _ = run(["plan", "--repo-root", good, "--sink-repo", "owner/sink"])
        chk("cli: plan exits 0 and renders the runbook against the named sink",
            (code, "owner/sink" in out, "gh secret set SINK_FIXTURE_TOKEN" in out),
            (0, True, True))

        outdir = os.path.join(tmp, "emitted")
        code, _, _ = run(["emit", "--repo-root", good, "--outdir", outdir])
        emitted = sorted(os.path.relpath(os.path.join(base, name), outdir)
                         for base, _dirs, names in os.walk(outdir) for name in names)
        chk("cli: emit writes the whole bundle and exits 0",
            (code, emitted),
            (0, sorted([SINK_README_NAME]
                       + [os.path.join(WORKFLOW_DIR, n) for n in PROBE_WORKFLOWS])))
        # Read defensively: if the emit above was refused, this row must go RED, not raise and
        # abort every check below it (#945's crash-after-partial-run).
        emitted_path = os.path.join(outdir, WORKFLOW_DIR, PROBE_WORKFLOWS[0])
        emitted_text = None
        if os.path.isfile(emitted_path):
            with open(emitted_path, encoding="utf-8") as handle:
                emitted_text = handle.read()
        chk("cli: ... byte-for-byte the source",
            emitted_text == _fixture_sources()[PROBE_WORKFLOWS[0]], True)

        code, _, err = run(["emit", "--repo-root", good, "--outdir", outdir])
        chk("cli: a second emit into the same dir refuses rather than overwriting",
            (code, "REFUSED" in err), (2, True))

        blocked = os.path.join(tmp, "blocked")
        code, _, err = run(["emit", "--repo-root", bad, "--outdir", blocked])
        chk("cli: emit from an UNGUARDED tree exits 2 and writes NOTHING — the refusal is before "
            "the first byte, not after a partial bundle",
            (code, "REFUSED" in err, os.path.exists(blocked)), (2, True, False))

        code, _, err = run(["emit", "--repo-root", good])
        chk("cli: emit with no --outdir refuses", (code, "REFUSED" in err), (2, True))

        missing = os.path.join(tmp, "missing")
        _write_fixture_root(missing, {PROBE_WORKFLOWS[0]: _fixture_probe(
            FIXTURE_GUARD_LINE, FIXTURE_SECRET_LINE)})
        code, _, err = run(["verify", "--repo-root", missing])
        chk("cli: a tree holding only ONE probe refuses (no half bundles)",
            (code, PROBE_WORKFLOWS[1] in err), (2, True))
        # ... and it refuses AT THE READ, naming the absent file and its path. Without this row the
        # downstream probe-set check in `bundle_verdict` masks a `probe_sources` that silently
        # skipped the missing file: two guards for one property make each individually unkillable
        # (#945), and only the read-side one can say WHICH file is gone.
        try:
            probe_sources(missing)
            sources_reason = None
        except SinkRefusal as exc:
            sources_reason = str(exc)
        chk("cli: probe_sources itself refuses a missing probe, naming the file and the path",
            (sources_reason is not None,
             PROBE_WORKFLOWS[1] in (sources_reason or ""),
             WORKFLOW_DIR in (sources_reason or "")), (True, True, True))


def _test_live_tree(chk):
    """THE STANDING PIN. This row runs in the enrolled suite on every registry PR, so #183's guard
    cannot regress on either probe without a red gate — the diagnostics have no other continuous
    check, and their whole safety property is that one line."""
    repo_root = os.path.dirname(SCRIPT_DIR)
    sources = probe_sources(repo_root)
    chk("live: both probe workflows are still in the tree", sorted(sources), sorted(PROBE_WORKFLOWS))
    ok, reason = bundle_verdict(parse_probes(sources))
    chk(f"live: every job of every probe is PROVABLY unreachable unless `{PRIVATE_GUARD_TEXT}` "
        f"({reason})", ok, True)
    # FOLDED, not raised (#945). A live probe that drifts into one of `sink_requirements`' fail-
    # closed refusals — an unbound secret, a whole-context read whose name allowlist went away or
    # went unanchored — must red the rows BELOW with the check count intact. Left to raise, it
    # aborts the suite: the gate does go red, but every remaining assertion silently never runs and
    # the log reads as a partial pass. The sentinel is deliberately not a plausible value.
    try:
        requirements = sink_requirements(sources)
    except SinkRefusal as refusal:
        requirements = Requirements((f"REFUSED: {refusal}",), (), (), None)
    chk("live: the sink requirement derived from the live probes is the dispatch-secrets "
        "environment", requirements.environments, ("dispatch-secrets",))
    chk("live: ... and it names the account token + salt the probes actually read",
        requirements.secrets, ("ACCT02_TOKEN", "PROVENANCE_SALT"))
    chk("live: ... and records the fleet-wide whole-context read",
        [(filename, read) for filename, _job, read in requirements.context_readers],
        [("fingerprint-accounts.yml", "toJSON(secrets)")])
    # THE STANDING PIN ON THE FILTER. `dispatch-secrets` also holds REGISTRY_SECRETS_PAT and
    # ALERT_TOKEN; this pattern is the only thing separating them from the names the runbook tells
    # a maintainer to copy into the sink. If the probe's own filter is loosened, moved or dropped,
    # this row goes red (or `sink_requirements` refuses) instead of the runbook quietly widening.
    chk("live: the account-token allowlist is derived from the live probe and is still the "
        "anchored ACCT family", requirements.allowlist, "^ACCT[A-Z0-9]+_TOKEN$")
    chk("live: ... and the sink's expected-name pattern adds the salt WITHOUT widening the family",
        sink_expected_name_pattern(requirements),
        "^ACCT[A-Z0-9]+_TOKEN$|^PROVENANCE_SALT$")
    files = bundle(sources, requirements, DEFAULT_SINK_REPO)
    chk("live: the emitted bundle is byte-identical to the live probes",
        [files[os.path.join(WORKFLOW_DIR, name)] == sources[name] for name in PROBE_WORKFLOWS],
        [True, True])


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
