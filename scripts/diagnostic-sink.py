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
Requirements = collections.namedtuple("Requirements", "secrets context_readers environments")


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
    return Requirements(tuple(sorted(secrets)), tuple(sorted(context_readers)),
                        tuple(sorted(environments)))


# ---- the bundle ----------------------------------------------------------------------------------
SINK_README_NAME = "README.md"


def sink_readme(sources, requirements, sink_repo):
    """The one file this bundle AUTHORS. Everything else is a byte-for-byte copy."""
    probes = "\n".join(f"- `{WORKFLOW_DIR}/{name}`" for name in sorted(sources))
    secrets = "\n".join(f"- `{name}`" for name in requirements.secrets)
    # Stated separately because it CANNOT be enumerated: a job that reads the whole secrets context
    # covers whatever the environment happens to hold, filtered by the probe's own allowlist.
    contextual = "\n".join(
        f"- `{filename}` job `{job}` reads `{read}`, so its coverage is exactly the account\n"
        "  tokens this environment holds — add each one you want fingerprinted."
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
        Step("0. The sink must be PRIVATE — read it back, do not assume it",
             "Every probe here is guarded on the repository being private, so a public sink is "
             "not a leak — it is a permanent no-op that looks like a working probe. Confirm "
             "before spending the rest of this runbook. If the repo does not exist yet, create "
             "it private; never create it public and flip it afterwards.",
             [f"gh repo view {sink_repo} --json visibility --jq .visibility",
              f"gh repo create {sink_repo} --private"]),
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
        steps.append(Step(
            "3. The account tokens the fleet fingerprint covers — enumerate them, then read back",
            "One probe reads the WHOLE secrets context and filters it with its own allowlist, so "
            "its coverage is exactly the account tokens present in the environment above — it "
            "cannot be listed here without restating that allowlist.\n"
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
            "cannot tell them apart.",
            [f"gh api repos/{REGISTRY_REPO}/environments/{environment}/secrets "
             "--jq '.secrets[].name'" for environment in requirements.environments]
            + [f"gh api repos/{sink_repo}/environments/{environment}/secrets "
               "--jq '.secrets[].name'" for environment in requirements.environments]))
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
    _test_bundle_is_verbatim(chk)
    _test_runbook_is_derived(chk)
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


def _fixture_probe(condition_line, secret_line, environment_line="    environment: sink-env"):
    lines = ["name: probe", "on:", "  workflow_dispatch: {}", "permissions: {}", "jobs:",
             "  probe:", "    runs-on: ubuntu-latest"]
    if condition_line:
        lines.append(condition_line)
    if environment_line:
        lines.append(environment_line)
    lines += ["    steps:", "      - name: probe", "        env:"]
    if secret_line:
        lines.append(secret_line)
    lines += ["        run: echo probe", ""]
    return "\n".join(lines)


FIXTURE_GUARD_LINE = "    if: ${{ " + PRIVATE_GUARD_TEXT + " }}"
FIXTURE_SECRET_LINE = "          TOK: ${{ secrets.SINK_FIXTURE_TOKEN }}"


def _fixture_sources(condition_line=FIXTURE_GUARD_LINE, secret_line=FIXTURE_SECRET_LINE,
                     environment_line="    environment: sink-env"):
    return {name: _fixture_probe(condition_line, secret_line, environment_line)
            for name in PROBE_WORKFLOWS}


def _test_requirements_are_derived(chk):
    """Derived from the probe text, never restated. The fixture names a secret and an environment
    that exist nowhere else in this repo, so a hardcoded list cannot produce this answer."""
    chk("requirements: the whole requirement is DERIVED from the probe text — a secret name and "
        "an environment that appear nowhere else in this repo",
        sink_requirements(_fixture_sources()),
        Requirements(("SINK_FIXTURE_TOKEN",), (), ("sink-env",)))

    contextual = _fixture_sources(secret_line="          ALL: ${{ toJSON(secrets) }}")
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


def _test_runbook_is_derived(chk):
    """The runbook is a function of the requirements. Feeding it names that appear nowhere else
    proves it, and tokenised flag membership is what makes `--private` an assertion rather than a
    substring that `--privately` would also satisfy."""
    requirements = Requirements(("SINK_ODD_SECRET",), (), ("sink-odd-env",))
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

    contextual = Requirements(("SINK_ODD_SECRET",), (("f.yml", "j", "toJSON(secrets)"),),
                              ("sink-odd-env",))
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
    requirements = sink_requirements(sources)
    chk("live: the sink requirement derived from the live probes is the dispatch-secrets "
        "environment", requirements.environments, ("dispatch-secrets",))
    chk("live: ... and it names the account token + salt the probes actually read",
        requirements.secrets, ("ACCT02_TOKEN", "PROVENANCE_SALT"))
    chk("live: ... and records the fleet-wide whole-context read",
        [(filename, read) for filename, _job, read in requirements.context_readers],
        [("fingerprint-accounts.yml", "toJSON(secrets)")])
    files = bundle(sources, requirements, DEFAULT_SINK_REPO)
    chk("live: the emitted bundle is byte-identical to the live probes",
        [files[os.path.join(WORKFLOW_DIR, name)] == sources[name] for name in PROBE_WORKFLOWS],
        [True, True])


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
