#!/usr/bin/env python3
# Secret-exfiltration SETTINGS guard for dispatch.yml (issue #101, cross-provider review round 1
# on the #101 PR): the `dispatch-secrets` environment binding on the CLAIM / plan-alert jobs is
# enforced by REPOSITORY SETTINGS, not by the workflow file — GitHub silently AUTO-CREATES a
# referenced environment with NO deployment-branch policy, and repo-scope secrets stay readable
# by a modified workflow copy dispatched at an attacker-controlled ref. A binding whose settings
# are not applied is therefore a default-ALLOW no-op. This guard runs in an UNPRIVILEGED,
# environment-UNBOUND job BEFORE any secret-bearing job and fails CLOSED unless both load-bearing
# settings are verifiably in effect:
#
#   1. EMPTY REPO SCOPE — the unbound job's `secrets` context (passed in as ALL_SECRETS; key
#      NAMES only are ever inspected or printed, values never) must hold nothing beyond the
#      ephemeral `github_token`. That context is exactly what an attacker copy that STRIPS the
#      environment binding would receive, so proving it empty proves the stripped-file exfil
#      path yields nothing. CLAIM reads toJSON(secrets), so EVERY repo-scope secret is in its
#      blast radius — the assertion is total, not a name allowlist.
#   2. DEFAULT-BRANCH-ONLY ENVIRONMENT — the `dispatch-secrets` environment must exist with a
#      CUSTOM deployment-branch policy naming exactly the default branch, EXPLICITLY `branch`
#      typed (round 18: an entry with a MISSING type is refused — absence cannot prove
#      non-tag): protected-branches mode admits every protected branch (an admin-configurable
#      SET, not the default branch), and a `tag`-type policy admits a collaborator-created tag
#      of the same name pointing at arbitrary code. A kept-binding attacker copy at any other
#      ref is then refused server-side.
#
# Any API failure, malformed document, or missing setting is a hard refusal (never a warning):
# the dispatcher pauses LOUDLY (red tick every ten minutes) instead of running one more tick in
# the known default-allow state. Read-only by construction — every gh call is a bare `gh api`
# GET; the self-test asserts no mutation flag ever appears in the argv.
#
# LIVE AUTHORIZATION DEPENDENCY (review round 2 on the #101 PR): the environment and
# deployment-branch-policy GETs require `actions: read` on the guard job's fine-grained
# GITHUB_TOKEN. The job declares an explicit permissions map (unlisted permissions become none),
# so dropping that grant would make BOTH reads fail on every tick — a permanent denial, not a
# verification. The self-test statically parses .github/workflows/dispatch.yml and asserts the
# guard job's permission map stays exactly {actions: read, contents: read}.
#
# SET-UP-ACCOUNT SLOT-UNION CONTRACT (sol round 6 on the #275 PR, finding 3; STRENGTHENED in
# round 8 after sol mutation-tested it in round 7): post-#101 the ACCTNN_TOKEN secrets live in
# the dispatch-secrets ENVIRONMENT, and set-up-account.yml's store step derives its
# slot-allocation union BEFORE creating the IRREVERSIBLE acct-claims ref. That union is pure
# workflow-shell (no script seam), so this guard's self-test statically asserts — same pattern
# as the dispatch.yml permission pin — that the store step:
#   (presence)      enumerates ALL FOUR paginated listings (claim refs, acctNN issues in any
#                   state, repo-scope secrets, AND the dispatch-secrets environment secrets);
#   (ordering)      issues every one of them textually BEFORE the `git/refs` claim mutation —
#                   sol's round-7 mutation moved the env listing AFTER the claim and the old
#                   presence-only check still passed, though a post-claim listing cannot stop
#                   a burned slot;
#   (participation) captures each listing into a variable that FLOWS INTO the `taken=$(...)`
#                   union the claimed slot is computed from — sol's other round-7 mutation
#                   dropped "$env_secret_nums" from the union while the listing still ran,
#                   leaving the env scope enumerated but IGNORED (a dead listing), and the old
#                   check still passed;
#   (determination) round 16: pins the FULL dependency chain `taken -> n -> cand -> git/refs
#                   claim` — everything flowing INTO `taken` proves nothing unless `taken`
#                   also flows OUT into the claimed ref. Sol's round-16 mutation replaced the
#                   `n=$(jq ... "$taken" ...)` slot computation with `n=$reserved` and the old
#                   check still passed, though the union no longer determined the slot and a
#                   reserved-but-occupied slot would be burned. Every `n=` assignment must
#                   reference "$taken", every `cand=` must derive from "$n", and the `git/refs`
#                   creation must claim `refs/acct-claims/$cand` — replacing any link with a
#                   constant/reserved value goes red.
# Dropping the env listing (or breaking any of these properties) would make an env-only token
# invisible and permanently burn the claimed slot. set-up-account.yml ships in the guard job's
# sparse checkout so the assertion also runs live every tick.
#
# BINDING-MAP CONTRACT (sol round 17 on the #275 PR): the empty-repo-scope check above proves an
# UNBOUND job sees nothing — which also means every job that CONSUMES a secret only works while
# it carries the job-level `environment: dispatch-secrets` binding, and a job whose binding is
# dropped both breaks (reads empty secrets) and becomes an any-ref exfiltration surface the
# moment the secrets ever regress to repo scope. That map was previously maintained by hand per
# workflow; this guard now DERIVES it: every job across .github/workflows/ whose body holds a
# secrets-context read — a dotted `${{ secrets.<NAME> }}` reference (the 14 migrated names and
# every other real secret: post-#101 the repo scope is provably empty, so any non-ephemeral name
# resolves ONLY inside the environment), a dynamic `${{ secrets[...] }}` read (worker/review-fix
# resolve secrets[secret_ref]), or a whole-context `${{ toJSON(secrets) }}` read — must carry
# the binding (round 18: the scan is CASE-INSENSITIVE — GitHub resolves secret names that
# way — and folded-scalar-aware: each job body is scanned as one joined text, since GitHub
# evaluates expressions only after YAML folding has already erased the line breaks). The ONLY
# hardcoded entries are the deliberate exceptions (BINDING_EXCEPTIONS):
# dispatch.yml's secrets-guard job (its UNBOUND toJSON(secrets) read IS check 1 above) and the
# one-shot migration's quiesce/migrate jobs (env-UNBOUND by design — documented in that file's
# header). Round 19 (sol finding 1): an exception job must carry NO environment AT ALL, not
# merely "not dispatch-secrets" — environment secrets OVERRIDE same-named repository secrets,
# so an exception bound to ANY other environment would resolve that environment's copies
# instead of the repo-scope originals it exists to read (a stale-value injection into the
# migration wearing a green tick). An exception whose job stops consuming, disappears, or
# carries any binding therefore goes red so the allowlist can never silently cover a future
# job. Two env-scoped WRITES are pinned the same way: the broker's final store
# (set-up-account.yml `gh secret set "$SECRET_NAME" ... --env dispatch-secrets`) and the
# rotation write-back (worker-live.sh `... secret set "$secret_ref" ... --env
# dispatch-secrets`) — a repo-scope write would re-trip the guard AND strand the env-bound
# consumers on the pre-rotation credential. Round 19 (sol findings 3+4): EVERY shell-text
# check — both write pins and the whole slot-union dataflow chain — first strips inline shell
# comments QUOTE-AWARELY (strip_shell_comments): sol planted `--env dispatch-secrets` and
# `"$env_secret_nums"` inside `# ...` comment tails and the raw-text matching counted comment
# prose as evidence. The workflows directory and scripts/worker-live.sh ship in the guard
# job's sparse checkout so both contracts also run live every tick.
#
# GATE CONTRACT (issue #618) — this guard's own exit code proves NOTHING about whether the
# privileged jobs are stopped. The job shipped with `continue-on-error: true` (a 2026-07-18
# advisory-mode line, issue #276, meant to be removed once #275's migration verified on
# 2026-07-19), which does not merely keep the RUN green: it makes this job resolve as SUCCESS for
# DEPENDENCY purposes, so CLAIM's plain `needs: secrets-guard` AND plan-alert's
# `needs.secrets-guard.result == 'success'` were BOTH satisfied by a FAILING guard. Measured on run
# 30141528651: GUARD conclusion `failure`, CLAIM ran, ALERT ran, run conclusion `success`. The
# self-test therefore asserts the WIRING in dispatch.yml (guard_gate_verdict): the guard job exists
# and carries NO truthy continue-on-error at job or step level; every secret-consuming job in the
# file — DERIVED, not listed — declares `needs: secrets-guard`; and any such job carrying a
# job-level `if:` re-states `needs.secrets-guard.result == 'success'` (an `if` containing always()
# cancels the implicit needs-must-succeed gate). Re-adding the continue-on-error line turns that
# check red.
#
# SPARSE-CHECKOUT COVERAGE (issue #618 defect 2) — this same self-test runs in TWO environments:
# the full-checkout pr-gate and the guard job's SPARSE checkout. A live input missing from the
# latter used to land in a broad `except` and silently degrade the check that needed it: #528 added
# the human-arm trust-surface assertions (which read scripts/worker-pr.py and policy/repos.toml)
# without extending dispatch.yml's sparse-checkout list, so from 2026-07-22T12:43Z the surface
# derived EMPTY and the guard reported all 22 privileged scripts — this file included — as "outside
# the human-arm trust surface", every tick, for 62 hours, hidden behind the continue-on-error.
# SELF_TEST_LIVE_INPUTS + sparse_checkout_covers_verdict now pin the two lists together, and an
# empty surface refuses by NAMING the derivation instead of emitting a script list that reads as a
# policy finding.
#
# TRANSITIVE live inputs (2026-07-25 — the class recurred, and this time it HALTED DISPATCH). Pinning
# two HAND-MAINTAINED lists to each other cannot catch a dependency that joins neither. This
# self-test EXECUTES set-up-account.yml's reconcile `run:` body, and #616 made that body load
# scripts/grant-account.py by repository-relative path; both lists stayed mutually consistent, the
# coverage assertion stayed green, and on every tick the file was simply absent from the sparse
# checkout — so the body's load raised FileNotFoundError, it took its (correct) "grant cannot be
# proven" refusal branch, and two credential-existence assertions failed for a reason that had
# nothing to do with the contract they name. #621 had (rightly) made this guard GATING, so CLAIM was
# skipped on every tick: no workers, no reviews, no fixes. executed_body_file_dependencies now
# DERIVES the executed body's file set from its own text and requires it both DECLARED (caught in
# pr-gate's full checkout) and PRESENT (named on a dispatch tick), so the next step that starts
# loading a script goes red at review time instead of halting the fleet.
#
# TRANSIENT source reads (issue #554). #618 fixed the DIAGNOSIS of an unreadable covered set; the
# COST stayed, because this guard is gating: one blipped read of worker-pr.py or policy/repos.toml
# and the tick launches nothing. derive_trust_surfaces now reads both through
# read_source_with_retry — a BOUNDED retry that re-raises rather than degrading to empty text,
# since empty text resolves to the empty surface, which is the all-22-uncovered false alarm itself.
#
# Pure verdict helpers + a stubbed-gh flow (including value-never-echoed sentinels) run under
# --self-test (registry-selftest gate).
import importlib.util
import itertools
import json
import os
import re
import subprocess
import sys
import time


def _load_gh_403():
    """Load scripts/gh_403.py (same checkout) — THE 403 taxonomy, shared with plan-snapshot
    (registry #1208). By PATH, not `import gh_403`: `scripts/` is not a package and the CWD a
    workflow step runs from is not this directory.

    FAILS LOUD AND CLOSED, by design, and NAMED. This module is a fail-closed control, so a
    missing dependency must never degrade a check into a verdict it did not earn — that is the
    2026-07-25 dispatch halt (#616's undeclared `grant-account.py` load) verbatim. The two
    protections against ever reaching this branch in production are the same two that closed that
    class: `scripts/gh_403.py` is declared in SELF_TEST_LIVE_INPUTS, and
    sparse_checkout_covers_verdict pins that list to the guard job's sparse-checkout block, so an
    omission goes red in pr-gate's full checkout instead of halting dispatch."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gh_403.py")
    spec = importlib.util.spec_from_file_location("registry_gh_403_for_guard", path)
    if spec is None or spec.loader is None or not os.path.exists(path):
        raise SystemExit(
            f"::error::secrets-guard: the shared 403 taxonomy ({path}) is unavailable, so a failed "
            "GitHub read cannot be classified — refusing to verify anything (fail closed). Add "
            "scripts/gh_403.py to the secrets-guard job's sparse-checkout list in dispatch.yml.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gh_403 = _load_gh_403()

ENVIRONMENT = "dispatch-secrets"
REPO_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")
REMEDIATION = (
    "secrets-guard: REQUIRED maintainer settings (issue #101): (1) create the "
    "`dispatch-secrets` environment; (2) restrict its deployment branches to a CUSTOM policy "
    "naming ONLY the default branch; (3) MOVE every repository-scope Actions secret into that "
    "environment (repo scope must be empty). Until all three hold, every dispatch tick refuses "
    "to run the secret-bearing jobs (fail closed).")


def repo_scope_verdict(secret_keys):
    """Pure: (ok, offending_names). The secrets context of an environment-UNBOUND job must hold
    nothing beyond the ephemeral github_token — any other key is a repo/org-scope secret an
    attacker-ref workflow copy could read."""
    offending = sorted(key for key in secret_keys if key.lower() != "github_token")
    return (not offending, offending)


def branch_policy_verdict(environment_doc, policies_doc, default_branch):
    """Pure: (ok, reason). Accepts ONLY a custom deployment-branch policy whose entries are
    exactly one EXPLICITLY `branch`-typed policy naming the default branch. Everything else —
    all-branches default, protected-branches mode, tag-type entries, entries MISSING a type
    (round 18: absence proves nothing about non-tag, so it fails closed like any other
    unproven setting), extra/wrong names, malformed docs — is a refusal with the specific
    reason."""
    if not isinstance(environment_doc, dict):
        return False, "environment document is unreadable"
    policy = environment_doc.get("deployment_branch_policy")
    if not isinstance(policy, dict):
        return False, "deployment-branch policy is 'All branches' (default-allow)"
    if not policy.get("custom_branch_policies") or policy.get("protected_branches"):
        return False, ("deployment-branch policy must be CUSTOM branch policies "
                       "(protected-branches mode admits every protected branch, "
                       "not only the default branch)")
    if (not isinstance(policies_doc, dict)
            or not isinstance(policies_doc.get("branch_policies"), list)):
        return False, "deployment-branch policy list is unreadable"
    names = []
    for entry in policies_doc["branch_policies"]:
        if not isinstance(entry, dict):
            return False, "deployment-branch policy entry is malformed"
        # Round 18 (sol, #275): the type must be EXPLICITLY "branch". The old default-to-
        # "branch" on a MISSING key meant a degraded/lenient document whose entries carry
        # only a name ({"name": "master"}) passed without ever proving the entry is not a
        # tag policy — this guard exists to verify settings, so an absent setting is an
        # unproven setting (fail closed), never a default.
        if entry.get("type") != "branch":
            return False, (f"policy type {entry.get('type')!r} is not explicitly 'branch' "
                           "(a missing type cannot prove non-tag, and a tag-type policy "
                           "admits collaborator-created tags at arbitrary commits)")
        names.append(entry.get("name"))
    if names != [default_branch]:
        return False, (f"policy names {names!r} must be exactly [{default_branch!r}] "
                       "(the default branch, nothing else)")
    return True, "ok"


def workflow_guard_permissions(workflow_text):
    """Pure: extract the secrets-guard job's `permissions:` map from dispatch.yml text, or None
    when it cannot be located unambiguously (callers treat None as a failure — fail closed).
    Deliberately dependency-free — the live runner image and the gate host need not share a
    PyYAML install — so this is a NARROW line parser over the two-space-indented block this
    repo controls, not a general YAML reader; reshaping the job that confuses it goes red in
    the self-test rather than silently passing."""
    lines = workflow_text.splitlines()
    try:
        start = lines.index("  secrets-guard:")
    except ValueError:
        return None
    permissions = None
    for line in lines[start + 1:]:
        stripped = line.split("#", 1)[0].rstrip()
        if not stripped:
            continue
        if not line.startswith("    "):
            break  # dedented out of the secrets-guard job
        if stripped == "    permissions:":
            permissions = {}
            continue
        if permissions is not None:
            if line.startswith("      ") and ":" in stripped:
                key, _, value = stripped.strip().partition(":")
                permissions[key.strip()] = value.strip()
                continue
            break  # end of the permissions mapping
    return permissions


# ---- the GATE contract (issue #618) --------------------------------------------------------------
# The guard job's own exit code is worthless on its own: `continue-on-error: true` kept every
# existing assertion green for 62 hours while the control was fail-OPEN. What must be asserted is
# that a FAILING guard PREVENTS the privileged jobs from running, so these checks are on the WIRING
# in dispatch.yml, not on the guard's behaviour.
#
# RETRO-REVIEW OF #621 (the PR that added this contract). Two mutations against the merged file left
# the whole enrolled suite GREEN, so the contract as shipped was DEFEATABLE:
#   (a) replacing BOTH `python3 registry/scripts/dispatch-secrets-guard.py` invocations in the guard
#       job's `run:` with `true` — the contract proved a job NAMED secrets-guard exists, is gated on,
#       and carries no continue-on-error, but never that it RUNS THE VERIFIER. An empty guard job
#       satisfies every dependency and verifies nothing;
#   (b) flipping `always() && needs.secrets-guard.result == 'success'` to `||` at dispatch.yml — the
#       old check was a SUBSTRING search for the success comparison, and the comparison is still
#       present in the `||` form, so "GATE (LIVE)" kept passing while the gate was inverted.
# Plus five permissive misparses from matching regexes against YAML rather than parsing it:
# `"continue-on-error": true` (quoted key), `continue-on-error : true` (space before the colon),
# `"if": ${{ always() }}` (quoted key => the polarity check was SKIPPED entirely), `needs: [plan]`
# with a TAB-prefixed `# secrets-guard` comment (` #` tail-stripping missed it, so the COMMENT
# satisfied the needs check), and `lstrip("./")` letting a `github/workflows/` sparse-checkout entry
# "cover" `.github/workflows/dispatch.yml`. Everything below therefore parses the workflow with
# PyYAML — the same precedent #619 set in dispatch-claim.py the same night — and the two gate
# properties are asserted SEMANTICALLY: the verifier is invoked, and the success condition's POLARITY
# is evaluated rather than pattern-matched.
GATE_GUARD_JOB = "secrets-guard"
# The success-conditioned dependency expression. Required only on a gated job that ALSO carries a
# job-level `if:` — an `if:` containing always() cancels the implicit needs-must-succeed gate, so
# the dependency has to be re-stated explicitly. Whitespace-tolerant; either quote style. Used as
# the FALSE atom of the polarity evaluation below, never as a bare substring test.
GATE_SUCCESS_RE = re.compile(
    r"needs\s*\.\s*" + GATE_GUARD_JOB + r"\s*\.\s*result\s*==\s*['\"]success['\"]")
# The guard job must EXECUTE the verifier. This FULLMATCHES the script word of a parsed simple
# command (see shell_script_invocations) — the live job uses the `registry/` sparse-checkout prefix,
# the synthetic fixtures none. The argument tail separates the `--self-test` (static assertions)
# invocation from the bare (live settings verification) one; BOTH are required, and both must be
# UNCONDITIONALLY REACHED. RETRO-REVIEW OF #629 (F2): the previous form was a text search whose left
# context `(?:^|[;&|]\s*|\s)` a `#` comment and a `true || …` short-circuit both satisfied, so a guard
# job whose only invocations were commented out PASSED — measured.
GATE_VERIFIER_SCRIPT_RE = re.compile(r"(?:[\w./$~{}-]*/)?scripts/dispatch-secrets-guard\.py")


def _yaml_module():
    """PyYAML, or a RuntimeError naming the fix. HARD dependency, deliberately: the workflow-shape
    checks in this file are security assertions, and a hand-rolled line parser is precisely what let
    the five #621 misparses through. Every context that runs this script installs or provides it
    (pr-gate.yml pins it version+hash-locked; dispatch.yml's guard job probes for it and falls back
    to the same pinned install) — so an ImportError here is a real misconfiguration and must be
    LOUD, never a silent downgrade to the buggy parser."""
    try:
        import yaml  # lazy: same shape as resolve-conflicts.validate_syntax_blob / #619
    except ImportError as exc:                                   # pragma: no cover - env fault
        raise RuntimeError(
            "PyYAML is required to parse the workflows for the secret-exfil gate assertions "
            "(install pyyaml==6.0.2); refusing to fall back to a line parser") from exc
    return yaml


def workflow_document(workflow_text):
    """Pure: the PARSED workflow mapping, or None when the text is not a YAML mapping (callers
    treat None as a refusal — fail closed)."""
    yaml = _yaml_module()
    try:
        document = yaml.safe_load(workflow_text or "")
    except yaml.YAMLError:
        return None
    return document if isinstance(document, dict) else None


def workflow_parse_error(workflow_text):
    """Pure: the first line of the YAMLError parsing `workflow_text` raises, or None when it parses.
    Reported separately so a REFUSAL can name the real fault: "does not parse as YAML" and "has no
    jobs: block" are different problems, and conflating them sends the reader looking in the wrong
    place. A stray TAB before a comment — one of the five #621 misparses, where the comment used to
    satisfy a `needs:` check — lands here."""
    yaml = _yaml_module()
    try:
        yaml.safe_load(workflow_text or "")
    except yaml.YAMLError as exc:
        return str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
    return None


def workflow_job_docs(workflow_text):
    """Pure: {job name: parsed job mapping} for the top-level `jobs:` block, or None when the block
    is missing/not a mapping/holds no mapping-shaped job (fail closed).

    This is the PARSED counterpart of workflow_jobs (which returns body LINES and is still used by
    the binding-map and privileged-script scans). Parsing is what makes a quoted key, an unusual
    space before a colon, a TAB-prefixed comment or a folded scalar a non-event: the value the
    assertions see is the value GitHub sees."""
    document = workflow_document(workflow_text)
    if document is None:
        return None
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        return None
    parsed = {str(name): body for name, body in jobs.items() if isinstance(body, dict)}
    return parsed or None


def _job_steps(job_doc):
    """Pure: the `steps:` list of a parsed job, or an empty tuple."""
    steps = (job_doc or {}).get("steps")
    return tuple(step for step in steps if isinstance(step, dict)) if isinstance(steps, list) \
        else ()


def _continue_on_error_escape(value):
    """Pure: the escape string for one `continue-on-error` value, or None when it is provably safe.
    `false` (bool or the string) is the ONLY safe value: a `${{ ... }}` expression cannot be
    statically proven false, so it counts as an escape (fail closed)."""
    if value is None or value is False:
        return None
    if value is True:
        return "true"
    text = str(value).strip()
    return None if text.strip("'\"").lower() == "false" else (text or "''")


def job_continue_on_error(job_doc):
    """Pure: the truthy/unprovable `continue-on-error` values in one PARSED job (job level and step
    level), as a sorted list of value strings. Because the job is parsed, prose ABOUT
    continue-on-error — a full-line comment, a ` #` tail, a TAB-prefixed comment — is gone before
    this looks, and a QUOTED key or a space before the colon is the same key it always was (the
    first two #621 misparses: both read as "no continue-on-error" to the old regex)."""
    escapes = []
    for holder in (job_doc, *_job_steps(job_doc)):
        escape = _continue_on_error_escape(holder.get("continue-on-error"))
        if escape is not None:
            escapes.append(escape)
    return sorted(escapes)


def job_needs(job_doc):
    """Pure: the job names in a PARSED job's `needs:` — the scalar (`needs: a`), flow-sequence
    (`needs: [a, b]`) and block-sequence forms all arrive here as a str or a list. Empty tuple when
    the job declares no dependencies. Parsing kills #621 misparse 4: a `# secrets-guard` COMMENT
    (TAB-prefixed, so the old ` #` tail strip missed it) is not a dependency."""
    needs = (job_doc or {}).get("needs")
    if needs is None:
        return ()
    if isinstance(needs, str):
        names = [needs]
    elif isinstance(needs, list):
        names = [item for item in needs if isinstance(item, str)]
    else:
        return ()
    return tuple(sorted(name.strip() for name in names if name.strip()))


def job_if_expression(job_doc):
    """Pure: the job-level `if:` expression of a PARSED job, or None when it carries none. Parsing
    kills #621 misparse 3: `"if": ${{ always() }}` is an `if`, and the old anchored regex read it as
    "no if at all", which SKIPPED the gate-polarity check entirely."""
    condition = (job_doc or {}).get("if")
    if condition is None:
        return None
    return str(condition).strip()


# ---- `if:` POLARITY (retro-review of #621 mutation (b)) ------------------------------------------
# A substring test cannot express "this condition GATES on the guard": `always() ||
# needs.secrets-guard.result == 'success'` contains the comparison and defeats it. So evaluate the
# expression's boolean structure under the ADVERSARIAL assignment — the atom we care about is FALSE,
# every other atom is TRUE (the most permissive world an attacker could arrange) — and ask whether it
# can still be TRUE. The same primitive expresses the opposite obligation for a compensating action
# that MUST stay reachable from a failure path (see rotation_writeback_reachable_verdict), which is
# why it takes the false-atom pattern as a parameter instead of hard-coding the guard.
_IF_OPERATORS = ("&&", "||")


def _tokenize_if(expression):
    """Pure: an `if:` expression as a token list of "&&" / "||" / "!" / "(" / ")" / ("atom", text).
    A `(` that opens a FUNCTION CALL (`always()`, `contains(a, 'b')`) is absorbed into the atom;
    only a `(` in operand position is grouping. Quoted strings are opaque. Raises ValueError on
    anything it cannot tokenize — callers treat that as unparseable."""
    tokens, index, length = [], 0, len(expression)
    while index < length:
        char = expression[index]
        if char.isspace():
            index += 1
            continue
        if expression.startswith(_IF_OPERATORS, index):
            tokens.append(expression[index:index + 2])
            index += 2
            continue
        if char == "!" and not expression.startswith("!=", index):
            tokens.append("!")
            index += 1
            continue
        if char in "()":
            tokens.append(char)
            index += 1
            continue
        start, depth, quote = index, 0, ""
        while index < length:
            current = expression[index]
            if quote:
                quote = "" if current == quote else quote
                index += 1
                continue
            if current in "'\"":
                quote = current
                index += 1
                continue
            if current == "(":
                depth += 1
                index += 1
                continue
            if current == ")":
                if depth == 0:
                    break
                depth -= 1
                index += 1
                continue
            if depth == 0 and expression.startswith(_IF_OPERATORS, index):
                break
            index += 1
        if quote or depth:
            raise ValueError("unterminated quote or parenthesis inside an operand")
        atom = expression[start:index].strip()
        if not atom:
            raise ValueError("empty operand")
        tokens.append(("atom", atom))
    if not tokens:
        raise ValueError("no tokens")
    return tokens


def _evaluate_if(tokens, value_of):
    """Pure: evaluate a tokenized `if:` expression with `value_of(atom_text) -> bool`. GitHub's `&&`
    / `||` precedence (`&&` binds tighter) and `!`. Raises ValueError on a malformed token stream."""
    position = 0

    def unary():
        nonlocal position
        if position >= len(tokens):
            raise ValueError("expression ends where an operand was expected")
        token = tokens[position]
        if token == "!":
            position += 1
            return not unary()
        if token == "(":
            position += 1
            value = disjunction()
            if position >= len(tokens) or tokens[position] != ")":
                raise ValueError("unbalanced parenthesis")
            position += 1
            return value
        if isinstance(token, tuple):
            position += 1
            return bool(value_of(token[1]))
        raise ValueError(f"unexpected token {token!r}")

    def conjunction():
        nonlocal position
        value = unary()
        while position < len(tokens) and tokens[position] == "&&":
            position += 1
            value = unary() and value
        return value

    def disjunction():
        nonlocal position
        value = conjunction()
        while position < len(tokens) and tokens[position] == "||":
            position += 1
            value = conjunction() or value
        return value

    result = disjunction()
    if position != len(tokens):
        raise ValueError("trailing tokens")
    return result


# ---- ATOM STRUCTURE (POST-MERGE retro-review of #629, finding F1) --------------------------------
# `if_condition_admits` used to answer "is this atom the obligation?" with
# `false_atom_re.search(<the atom's RAW TEXT>)`, and `_tokenize_if` absorbs a whole function call —
# INCLUDING its quoted string arguments — into a single opaque atom. So
#
#     if: ${{ always() && contains('needs.secrets-guard.result == "success"', 'success') }}
#
# pinned an ALWAYS-TRUE call to FALSE, the conjunction became unsatisfiable, and the checker reported
# `admits=False` — a proof about a formula the workflow does not have. GitHub evaluates both operands
# TRUE and runs the privileged job on a FAILED guard. MEASURED end to end through `guard_gate_verdict`
# on the merged tree: `-> True`, i.e. #621's mutation (b) re-expressed in one line, and the gate
# contract still defeatable.
#
# Pinning an atom FALSE is the ONLY unsound direction (an atom pinned FALSE that is really TRUE
# shrinks the satisfying set and can turn a reachable world into a "proof" of unreachability; leaving
# an atom FREE only ever adds worlds, which is the conservative direction for the gate). So an atom
# may be pinned only when its STRUCTURE has been parsed and is a COMPARISON — string literals then
# live inside the operand they belong to and are never re-scanned as condition text. Everything else
# is a known constant, a free boolean, or — when the atom cannot be FULLY parsed — an UNDECIDED
# verdict each caller fails closed on. There is no "search the raw atom text" path left anywhere.
_IF_STRING_TERM_RE = re.compile(r"'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"")
_IF_NUMBER_TERM_RE = re.compile(r"-?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?")
_IF_PATH_TERM_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_-]*(?:\s*\.\s*(?:[A-Za-z_][A-Za-z0-9_-]*|\*))*")
_IF_CALL_TERM_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_IF_COMPARISON_OP_RE = re.compile(r"==|!=|<=|>=|<|>")


def _skip_if_space(text, position):
    while position < len(text) and text[position].isspace():
        position += 1
    return position


def _parse_if_term(text, position):
    """Pure: (kind, canonical, next_position) for ONE operand term of a GitHub expression.

    kinds: "string" / "number" / "bool" / "null" / "path" / "call". `canonical` is the term with all
    whitespace OUTSIDE string literals removed, so `needs . secrets-guard . result` and
    `needs.secrets-guard.result` canonicalise identically while a string argument keeps its content
    sealed inside its own quotes. Raises ValueError on anything this grammar does not cover — the
    caller turns that into an UNDECIDED verdict rather than a guess."""
    position = _skip_if_space(text, position)
    if position >= len(text):
        raise ValueError("an operand was expected")
    match = _IF_STRING_TERM_RE.match(text, position)
    if match:
        return "string", match.group(0), match.end()
    if not (text[position].isalpha() or text[position] == "_"):
        match = _IF_NUMBER_TERM_RE.match(text, position)
        if match:
            return "number", match.group(0), match.end()
        raise ValueError(f"unrecognised operand at offset {position}")
    match = _IF_CALL_TERM_RE.match(text, position)
    if match:
        name, arguments, cursor = match.group(1), [], match.end()
        cursor = _skip_if_space(text, cursor)
        if cursor < len(text) and text[cursor] == ")":
            cursor += 1
        else:
            while True:
                _, argument, cursor = _parse_if_term(text, cursor)
                arguments.append(argument)
                cursor = _skip_if_space(text, cursor)
                if cursor < len(text) and text[cursor] == ",":
                    cursor += 1
                    continue
                if cursor < len(text) and text[cursor] == ")":
                    cursor += 1
                    break
                raise ValueError(f"unterminated argument list of {name}(")
        return "call", f"{name}({','.join(arguments)})", cursor
    match = _IF_PATH_TERM_RE.match(text, position)
    if match:
        canonical = re.sub(r"\s+", "", match.group(0))
        lowered = canonical.lower()
        if lowered in ("true", "false"):
            return "bool", lowered, match.end()
        if lowered == "null":
            return "null", lowered, match.end()
        return "path", canonical, match.end()
    raise ValueError(f"unrecognised operand at offset {position}")


def _parse_if_atom(atom):
    """Pure: ("cmp"|"opaque", canonical) for one absorbed operand of an `if:` expression.

    "cmp" is a comparison of two parsed terms — the ONLY shape a caller's false-atom / world pattern
    is ever matched against, and the fix for F1. "opaque" is a call or a context path whose truth
    value is not derivable here. Raises ValueError when the atom is not fully covered by this grammar
    (indexing, arithmetic, a comparison chain, a bare string/number used as a condition): the caller
    reports the whole expression UNDECIDED and applies its own fail direction."""
    kind, left, position = _parse_if_term(atom, 0)
    position = _skip_if_space(atom, position)
    if position == len(atom):
        if kind in ("bool", "call", "path"):
            return "opaque", left
        raise ValueError(f"a bare {kind} literal is not a condition")
    operator = _IF_COMPARISON_OP_RE.match(atom, position)
    if not operator:
        raise ValueError(f"unrecognised operator at offset {position} of {atom!r}")
    _, right, position = _parse_if_term(atom, operator.end())
    position = _skip_if_space(atom, position)
    if position != len(atom):
        raise ValueError(f"trailing text after the comparison in {atom!r}")
    return "cmp", f"{left}{operator.group(0)}{right}"


def _if_atom_map(tokens):
    """Pure: {raw atom text: ("cmp"|"opaque", canonical)} for a tokenized `if:` expression.

    Also rejects `!` applied DIRECTLY to a comparison: GitHub binds `!` tighter than `==`, so
    `!needs.x.result == 'success'` is `(!needs.x.result) == 'success'` there and `!(needs.x.result ==
    'success')` here. Rather than guess which reading the runtime takes, refuse the expression (the
    parenthesised spelling is decided normally). Raises ValueError, which every caller surfaces as
    UNDECIDED."""
    atoms = {}
    for index, token in enumerate(tokens):
        if not isinstance(token, tuple):
            continue
        kind, canonical = _parse_if_atom(token[1])
        atoms[token[1]] = (kind, canonical)
        if index and tokens[index - 1] == "!" and kind == "cmp":
            raise ValueError(
                f"`!` is applied directly to the comparison {canonical} — GitHub binds `!` TIGHTER "
                "than `==`, so this reading and the runtime's disagree; parenthesise it")
    return atoms


# Atoms with a KNOWN constant truth value, keyed by CANONICAL form. Everything else is a FREE variable
# (see if_condition_admits): `always()` genuinely is always true, and a bare `true`/`false` literal is
# what it says. Deliberately short — assuming a value for anything else is how a substring test gets
# the answer wrong (`!cancelled()` runs on a FAILED dependency, so pinning `cancelled()` to either
# constant would mis-decide it).
_IF_CONSTANT_ATOMS = {"always()": True, "true": True, "false": False}
# Free-atom ceiling for the exhaustive decision. Real workflow conditions carry a handful of atoms;
# beyond this the expression is reported UNDECIDED and each caller applies its own fail direction,
# rather than this returning a guess.
_IF_MAX_FREE_ATOMS = 12


def if_condition_admits(condition, false_atom_re):
    """Pure: (admits, decided, detail) for a job/step-level `if:` expression.

    `admits` — is there ANY world in which this expression is TRUE while every atom matching
               `false_atom_re` is FALSE? (For the gate: can the job run while the guard did not
               succeed. For a compensating action: can it still run when the thing it compensates
               for failed.)
    `decided` — whether the question was actually answered (the expression parsed and its free-atom
               count was inside the ceiling).

    DECIDED BY EXHAUSTIVE SATISFIABILITY, not by a fixed adversarial assignment: every atom that is
    neither a known constant nor a `false_atom_re` match is a FREE boolean, and all assignments are
    tried. A fixed "everything else is TRUE" valuation is wrong under negation — it makes
    `!cancelled()` evaluate FALSE and so reads a condition that DOES run on a failed dependency as
    though it gated. `admits=False` is therefore a proof of unreachability over all worlds, and
    `admits=True` exhibits at least one reaching world.

    `false_atom_re` is matched against a PARSED COMPARISON's canonical text and nothing else (F1): an
    opaque function call's string ARGUMENTS are not conditions, and an atom whose structure this
    grammar does not cover is not silently abstracted — the whole expression comes back UNDECIDED.

    Callers pick their fail direction from `decided`: a gate that must NOT admit treats undecided as
    admitting (an unreadable gate is not a proven gate); a compensating action that MUST admit treats
    undecided as a refusal (an unprovable reachability is not reachability). Neither ever guesses."""
    text = str(condition if condition is not None else "").strip()
    if not text:
        return True, False, "empty `if:` expression"
    inner = text
    if inner.startswith("${{") and inner.endswith("}}"):
        inner = inner[3:-2].strip()
    elif "${{" in inner:
        return True, False, ("the `if:` value interleaves literal text with `${{ }}` expressions "
                             "and cannot be evaluated statically")
    try:
        tokens = _tokenize_if(inner)
    except ValueError as exc:
        return True, False, f"the `if:` expression could not be parsed ({exc})"
    try:
        atoms = _if_atom_map(tokens)
    except ValueError as exc:
        return True, False, (f"the `if:` expression carries an atom this decision procedure cannot "
                             f"fully parse, so no satisfiability claim about it is sound ({exc})")
    fixed, free = {}, []
    for atom, (kind, canonical) in atoms.items():
        if canonical in _IF_CONSTANT_ATOMS:
            fixed[atom] = _IF_CONSTANT_ATOMS[canonical]
        elif kind == "cmp" and false_atom_re.search(canonical):
            fixed[atom] = False
        else:
            free.append(atom)
    if len(free) > _IF_MAX_FREE_ATOMS:
        return True, False, (f"the `if:` expression carries {len(free)} independent atoms, over the "
                             f"{_IF_MAX_FREE_ATOMS} this decision procedure will enumerate")
    try:
        for combination in itertools.product((False, True), repeat=len(free)):
            values = dict(fixed, **dict(zip(free, combination)))
            if _evaluate_if(tokens, values.__getitem__):
                return True, True, ("reachable when "
                                    + ", ".join(f"{atom}={value}"
                                                for atom, value in sorted(values.items())))
    except ValueError as exc:
        return True, False, f"the `if:` expression could not be evaluated ({exc})"
    return False, True, "ok"


def if_condition_requires(condition, world):
    """Pure: (holds, decided, detail) — does this `if:` expression evaluate TRUE in the ONE world
    `world` pins, referencing nothing outside it?

    THE UNIVERSAL COUNTERPART OF if_condition_admits, and the fix for POST-MERGE retro-review finding
    F4. For a must-NOT-run gate, existential satisfiability is the right question. For a
    must-BE-REACHABLE compensating action it is the wrong one: `if_condition_admits` pins only the one
    atom the caller names and treats every OTHER atom as a freely satisfiable boolean — but on a
    must-be-reachable obligation the other atoms are exactly the ones CAUSALLY CORRELATED with the
    failure being compensated for, so "there exists a world where the write-back runs" was being
    accepted as "the write-back runs on every path where a rotation may have happened". MEASURED on
    the LIVE worker.yml: adding `&& steps.model.outcome == 'success'` — #596's ORIGINAL defect, the one
    the step's own comment says must never come back — left `rotation_writeback_reachable_verdict`
    returning `(True, 'ok')` and the whole enrolled suite GREEN. So did `steps.prepare.outcome !=
    'failure'`, a prepare-OUTPUT atom, and `${{ success() }}`.

    `world` is a tuple of (canonical-atom pattern, truth value) pairs describing the state of the
    system on a path where the compensated-for event MAY ALREADY HAVE HAPPENED. Each atom of the
    condition must FULLMATCH exactly one pattern; an atom outside the allowlist returns
    decided=False NAMING it, because its value on that path is not knowable here. That allowlist —
    rather than "enumerate the correlated atoms" — is what makes the obligation decidable: the
    condition may only be keyed to facts settled BEFORE the compensated-for event."""
    text = str(condition if condition is not None else "").strip()
    if not text:
        return False, False, "empty `if:` expression"
    inner = text
    if inner.startswith("${{") and inner.endswith("}}"):
        inner = inner[3:-2].strip()
    elif "${{" in inner:
        return False, False, ("the `if:` value interleaves literal text with `${{ }}` expressions "
                              "and cannot be evaluated statically")
    try:
        tokens = _tokenize_if(inner)
        atoms = _if_atom_map(tokens)
    except ValueError as exc:
        return False, False, f"the `if:` expression could not be parsed ({exc})"
    values = {}
    for atom, (_kind, canonical) in atoms.items():
        for pattern, value in world:
            if pattern.fullmatch(canonical):
                values[atom] = value
                break
        else:
            return False, False, (
                f"the condition references `{canonical}`, which is NOT one of the facts settled "
                "before the compensated-for event; its value on a path where that event may already "
                "have happened is unknowable here, so the obligation is unprovable")
    try:
        holds = _evaluate_if(tokens, values.__getitem__)
    except ValueError as exc:
        return False, False, f"the `if:` expression could not be evaluated ({exc})"
    if not holds:
        return False, True, ("the condition evaluates FALSE with "
                             + ", ".join(f"{atom}={value}"
                                         for atom, value in sorted(values.items())))
    return True, True, "ok"


# ---- SHELL REACHABILITY: a command's TEXT is not its EXECUTION (retro-review of #629, F2 + F3) ----
# `GATE_VERIFIER_RE` and `WRITEBACK_STEP_RE` were text searches over a step's `run:` body whose left
# context `(?:^|[;&|]\s*|\s)` is satisfied by a `#` COMMENT, a `true || …` short-circuit and a
# here-doc body alike. MEASURED on the merged tree: a guard job whose only verifier invocations were
# `# python3 …` returned `guard_gate_verdict ok=True` (F2), and commenting out
# `run: bash registry/scripts/worker-live.sh write-back` in BOTH live lanes left the entire enrolled
# suite GREEN (F3) — i.e. defect 3's production call site had no test at all. This is the same "a
# comment satisfies the check" class #629 fixed for `needs:` by parsing, reintroduced in the same PR
# for shell text, so the fix is the same: PARSE the left context instead of matching it.
_SHELL_CONDITIONAL_OPENERS = frozenset({"if", "elif", "while", "until", "for", "case", "select"})
_SHELL_CONDITIONAL_CLOSERS = frozenset({"fi", "done", "esac"})
_SHELL_STRUCTURAL_WORDS = frozenset({"then", "else", "do", "in", "!", "time"})
_SHELL_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _shell_heredoc_delimiters(line):
    """Pure: the here-document delimiter words one physical shell line opens, in order. Quote-aware,
    so a `<<` inside quotes is ordinary text and a `<<<` here-STRING (which has no body) is skipped."""
    delimiters, quote, escaped, index = [], None, False, 0
    while index < len(line):
        char = line[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if quote:
            if char == "\\" and quote == '"':
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char == "\\":
            escaped = True
            index += 1
            continue
        if char in "'\"":
            quote = char
            index += 1
            continue
        if char == "#" and (index == 0 or line[index - 1] in " \t"):
            break                                    # comment: nothing after it opens a here-doc
        if line.startswith("<<<", index):
            index += 3
            continue
        if line.startswith("<<", index):
            cursor = index + 2
            if cursor < len(line) and line[cursor] == "-":
                cursor += 1
            while cursor < len(line) and line[cursor] in " \t":
                cursor += 1
            opener = ""
            if cursor < len(line) and line[cursor] in "'\"":
                opener = line[cursor]
                cursor += 1
            start = cursor
            while cursor < len(line) and (
                    line[cursor].isalnum() or line[cursor] in "_-."
                    or (opener and line[cursor] != opener)):
                cursor += 1
            word = line[start:cursor]
            if opener and cursor < len(line) and line[cursor] == opener:
                cursor += 1
            if word:
                delimiters.append(word)
            index = cursor
            continue
        index += 1
    return delimiters


def strip_shell_heredocs(text):
    """Pure: `text` with every here-document BODY (and its terminator line) removed; the `<<WORD`
    redirection itself is kept so the command it belongs to still parses.

    A here-doc body is DATA, not commands. `cat <<'PY' … python3 scripts/x.py … PY` contains the TEXT
    of an invocation and executes none of it, and the retro-review measured exactly that counting as
    the guard job "running the verifier"."""
    lines = str(text or "").split("\n")
    kept, index = [], 0
    while index < len(lines):
        line = lines[index]
        kept.append(line)
        pending = _shell_heredoc_delimiters(line)
        index += 1
        while pending and index < len(lines):
            if lines[index].strip() == pending[0]:
                pending.pop(0)
            index += 1
    return "\n".join(kept)


def _shell_tokens(text):
    """Pure: [("word", raw) | ("op", operator)] for a shell body. Quote-aware; backslash-newline
    continuations are joined. `(`/`)` are operators only in command position, so `$(...)` and
    `${...}` stay inside their word."""
    tokens, buffer, quote, escaped, index = [], "", None, False, 0
    length = len(text)

    def flush():
        nonlocal buffer
        if buffer:
            tokens.append(("word", buffer))
            buffer = ""

    while index < length:
        char = text[index]
        if escaped:
            buffer += char
            escaped = False
            index += 1
            continue
        if quote:
            buffer += char
            if char == "\\" and quote == '"':
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char == "\\":
            if index + 1 < length and text[index + 1] == "\n":
                index += 2                                   # line continuation
                continue
            buffer += char
            escaped = True
            index += 1
            continue
        if char in "'\"":
            buffer += char
            quote = char
            index += 1
            continue
        if char == "\n":
            flush()
            tokens.append(("op", "\n"))
            index += 1
            continue
        if char in " \t":
            flush()
            index += 1
            continue
        if text.startswith(("||", "&&", ";;"), index):
            flush()
            tokens.append(("op", text[index:index + 2]))
            index += 2
            continue
        if char in ";|&":
            flush()
            tokens.append(("op", char))
            index += 1
            continue
        if char in "()" and not buffer:
            tokens.append(("op", char))
            index += 1
            continue
        buffer += char
        index += 1
    flush()
    return tokens


def unquote_shell_word(word):
    """Pure: one shell word with its outer quoting removed (`'x'`, `"x"`, `x` -> `x`)."""
    text = str(word or "")
    out, quote, escaped = [], None, False
    for char in text:
        if escaped:
            out.append(char)
            escaped = False
            continue
        if quote:
            if char == "\\" and quote == '"':
                escaped = True
            elif char == quote:
                quote = None
            else:
                out.append(char)
            continue
        if char == "\\":
            escaped = True
            continue
        if char in "'\"":
            quote = char
            continue
        out.append(char)
    return "".join(out)


def shell_simple_commands(run_text):
    """Pure: ((reachable, words), ...) — every simple command in a shell `run:` body, with
    `reachable` False when the command is only CONDITIONALLY reached.

    Comments (quote-awarely, via the one shared stripper) and here-document BODIES are removed first,
    so neither can supply a command. A command is UNREACHABLE when it is the right-hand side of an
    `&&`/`||` short-circuit or lies inside an `if`/`elif`/`while`/`until`/`for`/`case` construct.
    Everything else — a plain line, a `;`-separated command, a pipeline stage, a subshell — runs
    whenever the step runs. Leading `VAR=value` env prefixes and the structural keywords are skipped
    so the COMMAND NAME is words[0]. Deliberately conservative: an unrecognised construct biases
    toward UNREACHABLE, and every caller treats "textually present but not reachable" as a refusal."""
    tokens = _shell_tokens(strip_shell_comments(strip_shell_heredocs(run_text)))
    commands, words = [], []
    guard_depth, short_circuited = 0, False

    def finish():
        nonlocal words
        if words:
            commands.append((guard_depth == 0 and not short_circuited, tuple(words)))
        words = []

    for kind, value in tokens:
        if kind == "op":
            finish()
            if value in ("&&", "||"):
                short_circuited = True
            elif value in (";", "\n", "&", ";;"):
                short_circuited = False
            continue
        if not words:
            if value in _SHELL_CONDITIONAL_OPENERS:
                guard_depth += 1
                continue
            if value in _SHELL_CONDITIONAL_CLOSERS:
                guard_depth = max(0, guard_depth - 1)
                continue
            if value in _SHELL_STRUCTURAL_WORDS or _SHELL_ASSIGNMENT_RE.match(value):
                continue
        words.append(value)
    finish()
    return tuple(commands)


def shell_script_invocations(run_text, interpreter, script_re, required_args=()):
    """Pure: (reachable, unreachable) — the argument tails of every `<interpreter> <script> …` simple
    command in a shell body, split by whether that command is UNCONDITIONALLY reached.

    `script_re` must FULLMATCH the script word (so a quoted fixture string, a substring, or a mention
    inside another argument is not an invocation), and every entry of `required_args` must appear as
    its own argument word. This is what makes "the guard RUNS the verifier" and "the lane RUNS the
    rotation write-back" assertions about execution rather than about text."""
    reachable, unreachable = [], []
    for is_reachable, words in shell_simple_commands(run_text):
        if len(words) < 2 or unquote_shell_word(words[0]) != interpreter:
            continue
        if not script_re.fullmatch(unquote_shell_word(words[1])):
            continue
        arguments = [unquote_shell_word(word) for word in words[2:]]
        if any(required not in arguments for required in required_args):
            continue
        (reachable if is_reachable else unreachable).append(" ".join(arguments))
    return tuple(reachable), tuple(unreachable)


def guard_verifier_invocations(guard_doc):
    """Pure: (self_test_steps, verify_steps, guarded_steps, unreachable_steps) over a PARSED guard
    job — the step indices whose `run:` REALLY RUNS this script with `--self-test`, without it, the
    indices of any invoking step that carries a step-level `if:`, and the indices of steps that
    merely CONTAIN the text of an invocation which never executes.

    A step-level `if:` is reported because it is the same bypass as #621 mutation (a) wearing a
    different hat: `if: false` (or any condition) on the invoking step leaves the job green, the
    dependency satisfied, and the verifier unrun. The fourth element is the retro-review's F2: a
    commented-out, `||`-short-circuited or here-doc'd invocation used to satisfy the same check."""
    self_tests, verifies, conditional, unreachable = [], [], [], []
    for index, step in enumerate(_job_steps(guard_doc)):
        run = step.get("run")
        if not isinstance(run, str):
            continue
        reached, blocked = shell_script_invocations(run, "python3", GATE_VERIFIER_SCRIPT_RE)
        if not reached and (blocked or GATE_VERIFIER_SCRIPT_RE.search(run)):
            # The step MENTIONS the verifier and does not run it: commented out, short-circuited,
            # here-doc'd, quoted, or inside a conditional. Reported so the refusal can say so.
            unreachable.append(index)
        if not reached:
            continue
        for tail in reached:
            (self_tests if "--self-test" in tail.split() else verifies).append(index)
        if step.get("if") is not None:
            conditional.append(index)
    return tuple(self_tests), tuple(verifies), tuple(conditional), tuple(unreachable)


def guard_gate_verdict(workflow_text):
    """Pure: (ok, reason). Prove the secret-exfil guard actually GATES the privileged jobs in
    dispatch.yml — the assertion issue #618 was opened for, and the one no pre-existing check
    made. Five properties, each fail-closed:

      (1) the guard job EXISTS and carries NO truthy `continue-on-error` at the job or step
          level. This is the whole defect: job-level continue-on-error does not merely keep the
          RUN green, it makes the job resolve as SUCCESS for dependency purposes, so a plain
          `needs: secrets-guard` AND a `needs.secrets-guard.result == 'success'` expression are
          BOTH satisfied by a guard that failed. Measured on run 30141528651 — GUARD conclusion
          `failure`, CLAIM ran, ALERT ran (its `if` is the result-conditioned form), run
          conclusion `success`. So no downstream expression can substitute for this property;
      (1b) the guard job actually RUNS THE VERIFIER — both `dispatch-secrets-guard.py --self-test`
          (the static workflow-shape assertions) and the bare invocation (the live settings
          verification), in a step that is not itself `if:`-conditional. RETRO-REVIEW OF #621:
          replacing both `run:` invocations with `true` left the ENTIRE enrolled suite green,
          because every other property here is satisfied by an EMPTY job of the right name. A gate
          whose verifier can be deleted without a red tick is not a gate;
      (2) EVERY secret-consuming job in the file (derived by secret_consuming_jobs, not a
          hand-maintained list, so a newly added secret-bearing job cannot land ungated) other
          than the guard itself declares `needs: secrets-guard`;
      (3) a gated job that ALSO carries a job-level `if:` must not be able to run while the guard
          did NOT succeed — an `if` containing always() cancels the implicit needs-must-succeed
          gate, which is exactly why plan-alert re-states the dependency while claim needs no `if`.
          This is a POLARITY evaluation (if_condition_admits), not a substring search: RETRO-REVIEW
          OF #621 flipped that `&&` to `||` and the old substring test still found the comparison,
          so "GATE (LIVE)" passed while the gate was inverted;
      (4) the PARSED job set and the line-parsed job set (workflow_jobs, still used by the binding
          map) must AGREE. They are two readers of the same file, and a shape only one of them
          understands — a quoted job key, say — is a job that escapes whichever check uses the other
          reader. Divergence is a refusal rather than a silent half-check.

    Zero derived consumers, an unparseable jobs block, or a missing guard job is a refusal: a
    check that proves nothing must not read as a pass."""
    parse_error = workflow_parse_error(workflow_text)
    if parse_error is not None:
        return False, (f"dispatch.yml does not parse as YAML ({parse_error}) — the gate contract "
                       "cannot be derived (fail closed)")
    jobs = workflow_job_docs(workflow_text)
    if jobs is None:
        return False, "cannot locate a `jobs:` block in dispatch.yml (fail closed)"
    line_jobs = workflow_jobs(workflow_text)
    if line_jobs is None or set(line_jobs) != set(jobs):
        only_parsed = sorted(set(jobs) - set(line_jobs or {}))
        only_lines = sorted(set(line_jobs or {}) - set(jobs))
        return False, (
            "the PARSED and line-parsed job sets of dispatch.yml disagree (parsed-only: "
            f"{only_parsed}; line-only: {only_lines}) — the binding-map scan and the gate contract "
            "read the same file with two readers, so a job only one of them sees escapes the other's "
            "assertions entirely (fail closed)")
    guard_doc = jobs.get(GATE_GUARD_JOB)
    if guard_doc is None:
        return False, (f"dispatch.yml has no `{GATE_GUARD_JOB}` job — the secret-exfil settings "
                       "check is GONE, not merely ungated (fail closed)")
    escapes = job_continue_on_error(guard_doc)
    if escapes:
        return False, (
            f"`{GATE_GUARD_JOB}` carries continue-on-error: {', '.join(escapes)} — a failed guard "
            "then resolves as SUCCESS for dependency purposes, so every downstream `needs:` and "
            "`needs." + GATE_GUARD_JOB + ".result == 'success'` gate passes while the secret-exfil "
            "settings are UNVERIFIED (issue #618: the control is fail-OPEN). Put any non-blocking "
            "diagnostic in a separate advisory job instead")
    self_tests, verifies, conditional, unreachable = guard_verifier_invocations(guard_doc)
    if not verifies or not self_tests:
        missing = " and ".join(
            part for part, present in (("`dispatch-secrets-guard.py` (the live settings "
                                        "verification)", verifies),
                                       ("`dispatch-secrets-guard.py --self-test` (the static "
                                        "workflow-shape assertions)", self_tests)) if not present)
        return False, (
            f"`{GATE_GUARD_JOB}` never RUNS {missing} in any step's `run:` — the job exists, is "
            "gated on, and is green, and it VERIFIES NOTHING. Every other property of this contract "
            "is satisfied by an empty job of the right name, which is why replacing these "
            "invocations with `true` had to become a red tick"
            + (f". Step(s) {list(unreachable)} CONTAIN the text of an invocation that never "
               "executes — commented out, short-circuited behind `||`/`&&`, or inside a here-doc or "
               "conditional construct (retro-review of #629: textual presence is not execution)"
               if unreachable else ""))
    if conditional:
        return False, (
            f"`{GATE_GUARD_JOB}` invokes the verifier from `if:`-conditional step(s) "
            f"{list(conditional)} — a step-level condition can skip the verification while the job "
            "still resolves as SUCCESS for every dependent, the same fail-open shape as "
            "continue-on-error. Put any conditional diagnostic in a separate advisory job")
    consuming = secret_consuming_jobs({"dispatch.yml": workflow_text})
    if consuming is None:
        return False, "cannot derive dispatch.yml's secret-consuming jobs (fail closed)"
    gated = sorted(job for (_, job) in consuming if job != GATE_GUARD_JOB)
    if not gated:
        return False, ("derived ZERO secret-consuming jobs to gate in dispatch.yml — the scan "
                       "proves nothing (fail closed: the parser or the file shape has drifted)")
    for job_name in gated:
        job_doc = jobs.get(job_name)
        if job_doc is None:
            return False, f"derived job {job_name} is not in the parsed jobs map (fail closed)"
        if GATE_GUARD_JOB not in job_needs(job_doc):
            return False, (f"privileged job `{job_name}` consumes secrets but does not declare "
                           f"`needs: {GATE_GUARD_JOB}` — it would launch with the secret-exfil "
                           "settings unverified")
        condition = job_if_expression(job_doc)
        if condition is None:
            continue
        admits, parsed, detail = if_condition_admits(condition, GATE_SUCCESS_RE)
        if admits:
            return False, (
                f"privileged job `{job_name}` carries a job-level `if:` ({condition!r}) that can "
                f"evaluate TRUE while `needs.{GATE_GUARD_JOB}.result` is not 'success'"
                + (f" — {detail}" if not parsed else "")
                + ". An `if` expression containing always() overrides the implicit "
                "needs-must-succeed gate, and merely MENTIONING the success comparison is not "
                "requiring it (an `||` satisfies a substring test and inverts the gate), so the "
                "condition must be a conjunction the guard's failure makes false")
    return True, "ok"


# Every repository file the --self-test path READS from the live checkout. The guard job in
# dispatch.yml runs this same self-test under a SPARSE checkout, so a live input missing from that
# job's sparse-checkout list does not fail loudly — it lands in an except branch and degrades the
# check that needed it. That is issue #618 defect 2 verbatim: #528 added the trust-surface
# assertions (reading scripts/worker-pr.py + policy/repos.toml) without extending the list, the
# surface derivation resolved EMPTY, and the guard reported all 22 privileged scripts — itself
# included — as outside the trust surface, on every tick, for 62 hours, invisibly. This constant
# plus sparse_checkout_covers_verdict close that class: add a live input here and the guard goes
# red until dispatch.yml's sparse-checkout list covers it.
SELF_TEST_LIVE_INPUTS = (
    "scripts/dispatch-secrets-guard.py",
    # THE 403 TAXONOMY (registry #1208). Loaded at MODULE IMPORT by _load_gh_403, so it is a live
    # input of `--self-test` and of the live verification alike — and its absence is not a
    # degraded check but a dead module. Declared here so sparse_checkout_covers_verdict pins it to
    # the guard job's sparse-checkout block and pr-gate's full checkout catches an omission at
    # review time, which is the control that exists because #616's undeclared by-path script load
    # halted dispatch for a day.
    "scripts/gh_403.py",
    "scripts/worker-live.sh",
    "scripts/worker-pr.py",
    "policy/repos.toml",
    ".github/workflows/dispatch.yml",
    ".github/workflows/set-up-account.yml",
    # rotation_writeback_reachable_verdict reads both worker lanes (retro-review of #614). Already
    # covered by the `.github/workflows/` directory entry; listed explicitly so the dependency is
    # visible where the coverage assertion is, per this constant's whole reason for existing.
    ".github/workflows/worker.yml",
    ".github/workflows/review-fix.yml",
    # TRANSITIVE input (the 2026-07-25 dispatch halt): the reconcile harness below EXECUTES the real
    # reconcile `run:` body, and #616 made that body load scripts/grant-account.py by repository
    # -relative path to derive the resumed grant's authorized target set. A file the executed body
    # opens is a live input of --self-test exactly as much as a document this module reads directly.
    # DERIVED as well as listed: executed_body_inputs_declared_verdict re-derives this entry from
    # the body's own text, so the next step that starts loading a script cannot repeat the omission.
    "scripts/grant-account.py",
)


def normalize_repo_path(value):
    """Pure: a repository-relative path in one comparable form — backslashes to `/`, and a leading
    `./` (only that, however many times) removed.

    NOT `lstrip("./")`. RETRO-REVIEW OF #621: `lstrip` takes a SET OF CHARACTERS, so
    `".github/workflows/dispatch.yml".lstrip("./")` is `"github/workflows/dispatch.yml"` — it eats the
    leading dot of a DOTFILE directory. A sparse-checkout entry of `github/workflows/` (which checks
    out nothing at all) therefore normalized to the same prefix and read as COVERING
    `.github/workflows/dispatch.yml`, i.e. the sparse-checkout coverage assertion — the one that
    exists so no self-test input can silently degrade to vacuous on a dispatch tick — passed on a
    typo that guaranteed the file was absent."""
    path = str(value).strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def sparse_checkout_paths(workflow_text, job_name):
    """Pure: the `sparse-checkout:` block-scalar entries inside one job of `workflow_text`, or None
    when the job or the block cannot be located (callers treat None as a failure — fail closed).

    PARSED (retro-review of #621): the old reader required the literal line
    `          sparse-checkout: |` at exactly ten spaces of indent, so any reflow of the step made
    this whole coverage assertion refuse — and it hand-stripped `#` comment tails from a YAML
    LITERAL scalar, where `#` is ordinary content. PyYAML hands back the scalar already de-indented,
    whatever the style (`|`, `|-`, `>` or a flow sequence)."""
    jobs = workflow_job_docs(workflow_text)
    if jobs is None:
        return None
    job_doc = jobs.get(job_name)
    if job_doc is None:
        return None
    for step in _job_steps(job_doc):
        with_block = step.get("with")
        if not isinstance(with_block, dict) or "sparse-checkout" not in with_block:
            continue
        value = with_block["sparse-checkout"]
        raw = value if isinstance(value, list) else str(value).splitlines()
        entries = tuple(str(entry).strip() for entry in raw
                        if str(entry).strip() and not str(entry).strip().startswith("#"))
        return entries or None
    return None


def sparse_checkout_covers_verdict(workflow_text, job_name, required_paths):
    """Pure: (ok, reason). Every path in `required_paths` must be checked out by `job_name`'s
    sparse-checkout list — matched exactly or by a directory-prefix entry. An unlocatable block is
    a refusal (fail closed): the self-test's live checks silently degrade without those files."""
    entries = sparse_checkout_paths(workflow_text, job_name)
    if entries is None:
        return False, (f"cannot locate {job_name}'s `sparse-checkout:` block in dispatch.yml "
                       "(fail closed — the self-test's live inputs cannot be proven present)")
    normalized = tuple(normalize_repo_path(entry) for entry in entries)
    missing = []
    for path in required_paths:
        target = normalize_repo_path(path)
        if not any(target.startswith(entry) if entry.endswith("/") else target == entry
                   for entry in normalized):
            missing.append(path)
    if missing:
        return False, (
            "self-test live input(s) absent from " + job_name + "'s sparse checkout: "
            + ", ".join(sorted(missing)) + " — the check that reads each one would degrade to "
            "vacuous (or to a MISLEADING verdict) on every dispatch tick while passing in the "
            "full-checkout pr-gate; add them to the sparse-checkout list")
    return True, "ok"


# TRANSITIVE LIVE INPUTS OF AN *EXECUTED* WORKFLOW BODY (the 2026-07-25 dispatch halt).
#
# SELF_TEST_LIVE_INPUTS above is a HAND-MAINTAINED list, and that is exactly how issue #618
# defect 2 came back. This self-test does not merely READ set-up-account.yml — it EXTRACTS the
# reconcile step's `run:` body and RUNS it (that executability is the whole point: eight mutants of
# the credential-existence contract are killed by executing the body rather than pattern-matching
# it). So every file that body opens is a live input of `--self-test` just as much as a document
# this module opens itself, and the guard job runs under a SPARSE checkout.
#
# #616 added `spec_from_file_location(..., "scripts/grant-account.py")` to that body — the derivation
# of a resumed enrollment's authorized target set — without extending SELF_TEST_LIVE_INPUTS or
# dispatch.yml's sparse-checkout list. Both hand-maintained lists therefore stayed mutually
# consistent and sparse_checkout_covers_verdict stayed GREEN, while on every dispatch tick the file
# was simply absent: the body's load raised FileNotFoundError, the body took its `grant cannot be
# proven` refusal branch and exited 1 — the CORRECT production direction, but a FALSE self-test
# failure — and #621's (correct) removal of `continue-on-error` turned that into a full dispatch
# halt with CLAIM skipped on every tick.
#
# The fix is to stop trusting a list where a derivation is available: the two verdicts below read
# the dependency set out of the executed body's own text and require it to be (a) DECLARED in
# SELF_TEST_LIVE_INPUTS — which sparse_checkout_covers_verdict then pins to the sparse-checkout
# list, so the pr-gate full checkout catches the omission at review time — and (b) actually PRESENT
# in whatever checkout the self-test is running in, which NAMES the absent file on a dispatch tick
# instead of letting a security-contract assertion report a refusal it did not cause.
REPO_FILE_ROOTS = (
    "scripts/", "policy/", "data/", "orchestration/", "containers/", "dashboard/", "research/",
    ".github/",
)

# A repository-relative file reference in EXECUTED body text: an optional `./`, one of the roots
# above, then a path ending in an extension. The left boundary rejects an API path or a ref that
# merely CONTAINS a root name (`repos/$REPO/scripts/x.py`, `git/refs/data/y.json`) and a
# parent-relative escape (`../scripts/x.py` addresses nothing inside this checkout) — neither is a
# checked-out file. `./scripts/x.py` IS one, and normalize_repo_path folds it to the bare path.
_BODY_FILE_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])((?:\./)*(?:"
    + "|".join(re.escape(root) for root in REPO_FILE_ROOTS)
    + r")[A-Za-z0-9._/-]*\.[A-Za-z0-9]+)")


def executed_body_file_dependencies(body_text):
    """Pure: the sorted repository-relative files an EXECUTED workflow `run:` body loads.

    Comments are stripped first, through the same quote-aware stripper every other shell-text check
    here runs (round 19). That cuts both ways deliberately: a path named only in PROSE is not a
    dependency and must not be able to force an unrelated file into the checkout list, and — the
    direction that matters — a real load cannot hide behind a comment tail either."""
    if not isinstance(body_text, str):
        return ()
    # Python heredocs embedded in the body comment with `#` too, and the stripper's word-start rule
    # removes those identically, so one pass covers the whole executed text.
    stripped = strip_shell_comments(body_text)
    return tuple(sorted({normalize_repo_path(match.group(1))
                         for match in _BODY_FILE_RE.finditer(stripped)}))


def _declared_covers(path, declared):
    """Pure: is `path` covered by a declared entry, exactly or by a directory-prefix entry."""
    return any(path.startswith(entry) if entry.endswith("/") else path == entry
               for entry in declared)


def executed_body_inputs_declared_verdict(body_text, declared_inputs):
    """Pure: (ok, reason). Every file the executed body loads must be DECLARED as a self-test live
    input. An unextractable body is a refusal (fail closed): a dependency set that cannot be derived
    is precisely the state that halted dispatch."""
    if not isinstance(body_text, str) or not body_text.strip():
        return False, ("the executed reconcile body could not be extracted, so the files it loads "
                       "cannot be derived — refusing (an underived transitive dependency is the "
                       "exact gap that halted dispatch on 2026-07-25)")
    declared = tuple(normalize_repo_path(entry) for entry in declared_inputs)
    missing = [path for path in executed_body_file_dependencies(body_text)
               if not _declared_covers(path, declared)]
    if missing:
        return False, (
            "the reconcile body this self-test EXECUTES loads " + ", ".join(missing)
            + ", which is NOT declared in SELF_TEST_LIVE_INPUTS. Under the guard job's SPARSE "
            "checkout that file is absent, the body's load fails, and the credential-existence "
            "assertions report a refusal they did not cause — a FALSE guard failure that skips "
            "CLAIM on every tick (the 2026-07-25 halt). Add each path to SELF_TEST_LIVE_INPUTS "
            "and to the guard job's sparse-checkout list in dispatch.yml")
    return True, "ok"


def executed_body_inputs_present_verdict(body_text, repo_root):
    """(ok, reason). The same derived set, resolved against the checkout this self-test is ACTUALLY
    running in — the assertion that NAMES the defect on a dispatch tick. The executed body loads by
    repository-relative path from the repository root, so a derived dependency that is not on disk
    makes the body refuse for a reason unrelated to the contract under test, and the reader of the
    failing run sees a security-contract assertion fail instead of a missing file."""
    if not isinstance(body_text, str) or not body_text.strip():
        return False, ("the executed reconcile body could not be extracted, so the presence of the "
                       "files it loads cannot be proven — refusing")
    absent = [path for path in executed_body_file_dependencies(body_text)
              if not os.path.exists(os.path.join(repo_root, path))]
    if absent:
        return False, (
            "the reconcile body this self-test EXECUTES loads " + ", ".join(absent)
            + ", which is ABSENT from this checkout — every assertion that runs the body will "
            "refuse for that reason and NOT for the credential/grant contract it names. This is "
            "the 2026-07-25 dispatch halt verbatim: add the path to the guard job's "
            "sparse-checkout list in dispatch.yml (and to SELF_TEST_LIVE_INPUTS)")
    return True, "ok"


def trust_surface_from_worker_pr(source_text):
    """Pure: worker-pr.py's DEFAULT_TRUST_SURFACE_PATHS as a tuple, via `ast` — the module is
    PARSED, never imported, so the guard job never executes 7.6k lines of privileged script to
    read one constant. Raises ValueError when the constant is absent or is not a literal
    sequence of strings (callers surface that as a refusal — a surface that cannot be read must
    never resolve to the empty tuple, which would mark every privileged script uncovered)."""
    import ast

    tree = ast.parse(source_text)
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "DEFAULT_TRUST_SURFACE_PATHS":
                value = ast.literal_eval(node.value)
                if not isinstance(value, (tuple, list)) or not value:
                    raise ValueError("DEFAULT_TRUST_SURFACE_PATHS is empty or not a sequence")
                if not all(isinstance(item, str) and item.strip() for item in value):
                    raise ValueError("DEFAULT_TRUST_SURFACE_PATHS holds a non-string entry")
                return tuple(value)
    raise ValueError("DEFAULT_TRUST_SURFACE_PATHS not found in worker-pr.py")


# ---- the covered-set SOURCE read is retried, bounded, and never swallowed (issue #554) ----------
# The human-arm covered set is derived from two files read off a freshly-materialized sparse
# checkout. #618 fixed the diagnosis — an empty surface now refuses by naming the DERIVATION instead
# of emitting "22 privileged scripts outside the human-arm trust surface", a security-policy verdict
# about the whole script inventory. What it did not fix is the COST: a single transient read fault
# (a half-materialized checkout, a filesystem blip) still fails a GATING guard job, so that tick
# launches nothing. A read that can blip gets a bounded retry FIRST.
#
# Bounded and non-swallowing are both load-bearing. Unbounded would hang the tick; swallowing to ""
# would hand `trust_surface_from_worker_pr` an empty module and resolve the surface to the empty
# tuple — the exact all-uncovered false alarm this issue exists to kill. The last OSError is
# re-raised instead, so a genuinely-absent source still fails closed with the distinct derivation
# message.
SOURCE_READ_ATTEMPTS = 3
SOURCE_READ_BACKOFF_SECONDS = 0.25


def read_source_with_retry(path, attempts=SOURCE_READ_ATTEMPTS, opener=open, sleeper=time.sleep,
                           backoff=SOURCE_READ_BACKOFF_SECONDS):
    """Read `path` whole as text, retrying an OSError up to `attempts` reads TOTAL.

    Returns the file's text, or re-raises the last OSError once the budget is spent — it never
    degrades a failed read into empty text. `attempts` < 1 is a programming error and raises, since
    a zero budget would read nothing and return None, which is the silent-empty failure mode again.
    `opener`/`sleeper` are injected so the self-test can prove the retry without a real fault or a
    real delay."""
    if attempts < 1:
        raise ValueError("read_source_with_retry needs at least one attempt "
                         "(a zero budget reads nothing and cannot fail closed)")
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            with opener(path, "r", encoding="utf-8") as handle:
                return handle.read()
        except OSError as error:
            last_error = error
            if attempt < attempts:
                sleeper(backoff * attempt)
    raise last_error


def derive_trust_surfaces(repo_root, reader=read_source_with_retry):
    """(default_surfaces, policy_surfaces, error_or_None): the human-arm covered set, from the TWO
    live sources (issue #166: policy/repos.toml's per-target list EXTENDS worker-pr.py's mandatory
    floor). A read/parse fault returns EMPTY surfaces AND names itself, so the caller reports the
    DERIVATION and refuses to evaluate coverage rather than grading 22 scripts against nothing."""
    import tomllib

    try:
        default_surfaces = trust_surface_from_worker_pr(
            reader(os.path.join(repo_root, "scripts", "worker-pr.py")))
        policy_doc = tomllib.loads(reader(os.path.join(repo_root, "policy", "repos.toml")))
        policy_surfaces = tuple(
            policy_doc["repos"]["jeswr/agent-account-registry"]["readiness"]["security_paths"])
        if not policy_surfaces:
            raise ValueError("policy/repos.toml readiness.security_paths is empty")
    except (OSError, KeyError, TypeError, AttributeError, ValueError,
            SyntaxError, tomllib.TOMLDecodeError) as error:
        return (), (), f"{type(error).__name__}: {error}"
    return default_surfaces, policy_surfaces, None


# The slot-allocation listings set-up-account.yml's store step MUST union BEFORE creating the
# IRREVERSIBLE acct-claims ref (claims are never deleted — a claim on an occupied slot burns it
# permanently). Post-#101 the ACCTNN_TOKEN secrets live in the dispatch-secrets ENVIRONMENT, so
# BOTH secret scopes are load-bearing (sol round 6 on the #275 PR, finding 3: an environment-only
# token with no claim ref or issue yet was invisible to a repo-scope-only union — the broker
# claimed the slot, then failed at the env absence-probe, slot burned). Each listing must be
# `gh api --paginate` — a capped page silently treats every unseen slot as free.
SETUP_ACCOUNT_UNION_REQUIRED = (
    "git/matching-refs/acct-claims/",
    "issues?state=all&per_page=100",
    "actions/secrets?per_page=100",
    f"environments/{ENVIRONMENT}/secrets?per_page=100",
)

# A paginated listing captured into a shell variable: `[if !] VAR=$([GH_TOKEN=...] gh api
# --paginate "repos/${{ github.repository }}/<path>"...`. Group 1 = the variable, group 2 = the
# API path. Narrow on purpose (see setup_account_store_step_lines).
SETUP_ACCOUNT_LISTING_RE = re.compile(
    r'(?:if\s+!\s+)?([A-Za-z_][A-Za-z0-9_]*)=\$\(\s*(?:GH_TOKEN="\$REGISTRY_PAT"\s+)?'
    r'gh api --paginate "repos/\$\{\{ github\.repository \}\}/([^"]+)"')
# The irreversible claim mutation: the `git/refs` ref-creation POST (distinct from the
# read-only `git/matching-refs/acct-claims/` listing, whose path never equals `git/refs`).
SETUP_ACCOUNT_CLAIM_RE = re.compile(
    r'gh api\s+"repos/\$\{\{ github\.repository \}\}/git/refs"')
# The union the claimed slot is computed from.
SETUP_ACCOUNT_UNION_RE = re.compile(r'\btaken=\$\(')
# The slot computation and candidate construction the union must DETERMINE (sol round 16 on
# the #275 PR): listings flowing into `taken` prove nothing if `n` is not computed FROM it —
# `n=$reserved` reintroduces the burned-slot regression with every listing still green.
# Statement-anchored (start-of-line or whitespace) so `taken=$(`, `claim_nums=$(`, `GH_TOKEN=`
# and other names merely CONTAINING the letter never match.
SETUP_ACCOUNT_SLOT_RE = re.compile(r"(?:^|\s)n=")
SETUP_ACCOUNT_CAND_RE = re.compile(r"(?:^|\s)cand=")


def strip_shell_comments(text):
    """Pure: `text` with inline shell comments removed, line by line, QUOTE-AWARELY — the ONE
    shared stripper every shell-text check in this guard runs BEFORE matching (round 19, sol
    findings 3+4: `... < file # --env dispatch-secrets` and `"" # "$env_secret_nums"` planted
    the load-bearing evidence inside comments, and raw-text matching counted it). Rules,
    following shell tokenization: an unquoted `#` at the START OF A WORD (line start or
    preceded by whitespace) begins a comment cut to end of line; a `#` inside single or
    double quotes, backslash-escaped, or mid-word (`${VAR#pat}`, `$((10#$n))` — never
    comments in shell) is literal and preserved. Backslashes escape outside quotes and
    inside double quotes, and are literal inside single quotes. Line-at-a-time (quote state
    deliberately does not span physical lines): the checked texts join their own backslash
    continuations AFTER stripping, and a `#` comment consumes any trailing backslash exactly
    as a real shell would (a commented-out continuation does not continue)."""
    stripped_lines = []
    for line in text.split("\n"):
        out = []
        quote = None  # None | "'" | '"'
        escaped = False
        for char in line:
            if escaped:  # only ever set outside single quotes
                out.append(char)
                escaped = False
                continue
            if quote == "'":
                if char == "'":
                    quote = None
                out.append(char)
                continue
            if char == "\\":
                out.append(char)
                escaped = True
                continue
            if quote == '"':
                if char == '"':
                    quote = None
                out.append(char)
                continue
            if char in "'\"":
                quote = char
                out.append(char)
                continue
            if char == "#" and (not out or out[-1] in " \t"):
                break  # word-start unquoted `#`: comment to end of line
            out.append(char)
        stripped_lines.append("".join(out))
    return "\n".join(stripped_lines)


def setup_account_store_step_lines(workflow_text):
    """Pure: the lines of the set-up-account store step (`id: store`), or None when the step
    cannot be located (callers treat None as a failure — fail closed). The union is pure
    workflow-shell — there is no script seam to unit-test — so, exactly like
    `workflow_guard_permissions` above, this is a deliberately NARROW, dependency-free line
    parser over the one step this repo controls, not a general YAML reader; reshaping the step
    out of recognition goes red in the self-test rather than silently passing."""
    lines = workflow_text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip() == "id: store":
            start = index
            break
    if start is None:
        return None
    step = []
    for line in lines[start + 1:]:
        if line.startswith("      - name:"):
            break  # dedented into the next step
        step.append(line)
    return step


def setup_account_reconcile_run_script(workflow_text):
    """Pure: the DEDENTED shell body of the set-up-account reconcile step's `run: |` block
    (`id: reconcile`), or None when it cannot be located (callers treat None as a failure —
    fail closed). Like `setup_account_store_step_lines` above, this is a deliberately NARROW,
    dependency-free line parser over the one step this repo controls, not a general YAML
    reader. The body is returned executable so the self-test can RUN the real reconcile shell
    under stubbed `gh`/`jq` and assert its fail-closed behaviour (the #533 round-1
    credential-existence contract), instead of pattern-matching what the shell hopefully does."""
    lines = workflow_text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip() == "id: reconcile":
            start = index
            break
    if start is None:
        return None
    run_index = None
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("      - name:"):
            break  # dedented into the next step without finding a run block
        if lines[index].strip() == "run: |":
            run_index = index
            break
    if run_index is None:
        return None
    body = []
    indent = None
    for line in lines[run_index + 1:]:
        if not line.strip():
            body.append("")
            continue
        current = len(line) - len(line.lstrip())
        if indent is None:
            indent = current
        if current < indent:
            break  # dedented out of the literal block
        body.append(line[indent:])
    if not body:
        return None
    return "\n".join(body) + "\n"


def setup_account_union_verdict(step_lines):
    """Pure: (ok, reason). The store step's pre-claim union must (a) enumerate EVERY required
    listing (claim refs, acctNN issues in any state, and ACCTNN_TOKEN secret names at BOTH the
    repository scope and the dispatch-secrets environment), each via `gh api --paginate`;
    (b) ORDERING (round 8): issue each listing textually BEFORE the irreversible `git/refs`
    claim mutation — a post-claim listing cannot stop a burned slot; (c) PARTICIPATION
    (round 8): capture each listing into a variable that appears in the `taken=$(...)` union
    the claimed slot is computed from — a listing whose variable never reaches the union is
    DEAD and its slots invisible; and (d) DETERMINATION (round 16): the claimed ref must be
    COMPUTED FROM that union through the full chain `taken -> n -> cand -> git/refs claim` —
    every `n=` assignment references "$taken", every `cand=` derives from "$n", and the
    `git/refs` creation claims `refs/acct-claims/$cand` — otherwise the union is a dead
    computation and e.g. `n=$reserved` burns a reserved-but-occupied slot with every listing
    green. A missing store step, claim mutation, union, slot, or candidate construction is a
    refusal (fail closed); every refusal names what is missing. Round 19 (sol finding 4):
    every line passes through strip_shell_comments BEFORE any matching — dataflow and
    argument checks alike (listings, the union, the whole taken -> n -> cand -> claim
    chain) — so comment prose (`"" # "$env_secret_nums"`, `n=$reserved # "$taken"`) can
    never stand in for a real argument or a real dependency edge."""
    if step_lines is None:
        return False, "store step (`id: store`) not found in set-up-account.yml (fail closed)"
    step_lines = [strip_shell_comments(line) for line in step_lines]

    def joined(index):
        # Join shell continuation lines so a check sees the whole command.
        parts = [step_lines[index].rstrip()]
        follow = index
        while parts[-1].endswith("\\") and follow + 1 < len(step_lines):
            follow += 1
            parts.append(step_lines[follow].rstrip())
        return " ".join(part.rstrip("\\").strip() for part in parts)

    listings = {}  # path -> (variable, first line index)
    claim_index = None
    claim_text = None
    union_index = None
    union_text = None
    slot_texts = []  # every `n=` assignment (joined) — ALL must reference the union
    cand_texts = []  # every `cand=` assignment (joined) — ALL must derive from $n
    for index, line in enumerate(step_lines):
        for match in SETUP_ACCOUNT_LISTING_RE.finditer(line):
            listings.setdefault(match.group(2), (match.group(1), index))
        if claim_index is None and SETUP_ACCOUNT_CLAIM_RE.search(line):
            claim_index = index
            claim_text = joined(index)
        if union_index is None and SETUP_ACCOUNT_UNION_RE.search(line):
            union_index = index
            union_text = joined(index)
        if SETUP_ACCOUNT_SLOT_RE.search(line):
            slot_texts.append(joined(index))
        if SETUP_ACCOUNT_CAND_RE.search(line):
            cand_texts.append(joined(index))
    if claim_index is None:
        return False, ("irreversible claim mutation (the `git/refs` creation) not found in "
                       "the store step — cannot prove the union precedes it (fail closed)")
    if union_text is None:
        return False, ("slot-union construction (`taken=$(`) not found in the store step — "
                       "cannot prove the listings flow into the claimed slot (fail closed)")
    missing = sorted(set(SETUP_ACCOUNT_UNION_REQUIRED) - set(listings))
    if missing:
        return False, ("pre-claim slot union is missing paginated listing(s): "
                       + ", ".join(missing)
                       + " — an unseen slot is silently treated as free and the irreversible "
                       "acct-claims ref burns it")
    if union_index >= claim_index:
        return False, ("the `taken` union is computed AFTER the irreversible `git/refs` claim "
                       "creation — the claimed slot cannot have depended on it (fail closed)")
    for path in SETUP_ACCOUNT_UNION_REQUIRED:
        variable, index = listings[path]
        if index >= claim_index:
            return False, (f"listing `{path}` (captured into ${variable}) appears AFTER the "
                           "irreversible `git/refs` claim creation — a post-claim listing "
                           "cannot stop a burned slot; every listing must run BEFORE the claim")
        if (f'"${variable}"' not in union_text
                and f'"${{{variable}}}"' not in union_text):
            return False, (f"listing `{path}` is captured into ${variable} but ${variable} "
                           "does not flow into the `taken` union construction — the listing "
                           "is DEAD and every slot it sees stays invisible to the claim")
    # DETERMINATION (sol round 16): everything above proves the listings flow INTO `taken`,
    # which is vacuous unless `taken` also flows OUT into the claimed ref — mutating the slot
    # computation to `n=$reserved` bypasses the union entirely (every listing still green,
    # still pre-claim, still participating) and burns a reserved-but-occupied slot exactly as
    # the contract exists to prevent. Pin each edge of `taken -> n -> cand -> git/refs claim`
    # so replacing any link with a constant/reserved value goes red.
    if not slot_texts:
        return False, ("slot computation (`n=`) not found in the store step — cannot prove "
                       "the `taken` union determines the claimed slot (fail closed)")
    for text in slot_texts:
        if '"$taken"' not in text and '"${taken}"' not in text:
            return False, ("a slot assignment `n=` does not reference the `taken` union "
                           "(e.g. `n=$reserved`) — the union is computed but IGNORED, and "
                           "the irreversible claim burns whatever slot `n` names regardless "
                           "of the listings")
    if not cand_texts:
        return False, ("candidate construction (`cand=`) not found in the store step — "
                       "cannot prove the claimed ref derives from the computed slot "
                       "(fail closed)")
    for text in cand_texts:
        if '"$n"' not in text and '"${n}"' not in text:
            return False, ("a candidate assignment `cand=` does not derive from \"$n\" (the "
                           "union-determined slot) — a hardcoded candidate burns a slot the "
                           "union never blessed")
    if ("refs/acct-claims/$cand" not in claim_text
            and "refs/acct-claims/${cand}" not in claim_text):
        return False, ("the `git/refs` claim creation does not create `refs/acct-claims/$cand` "
                       "— the claimed ref is severed from the union-derived candidate, so the "
                       "union cannot have determined the claimed slot")
    return True, "ok"


# BINDING-MAP CONTRACT (sol round 17 on the #275 PR; scan hardened round 18) — secrets-context
# reads that make a job a secret CONSUMER. All three require the `${{` expression opener: a jq
# `.secrets[].name` filter over an API listing, or prose quoting a reference, is not a context
# read (comment lines/tails are stripped besides — and the opener-to-read span is the negated
# class `[^}]*`, which can never cross an earlier expression's `}}` closer, so a jq filter
# appearing after some unrelated expression still never matches). Round 18 (sol finding 2):
# GitHub resolves secret NAMES case-insensitively (`secrets.acct02_token` reads ACCT02_TOKEN)
# and evaluates expressions AFTER YAML folds a `>-`/`>` scalar into one string — so a
# lowercase reference, or an opener and its `secrets.` reference split across folded-scalar
# continuation lines, is a REAL secret read the old uppercase-only line-at-a-time scan let
# escape the derived map. The patterns are therefore IGNORECASE and matched over the JOB BODY
# JOINED into one text (job_secret_reads): `[^}]*` is a negated class, so it spans newlines
# WITHOUT re.DOTALL, exactly as YAML folding erases them before GitHub ever parses the
# expression — robust to any scalar style (folded, literal, quoted-flow) with no YAML
# re-implementation. The dotted form accepts ANY name in any case except the ephemeral
# GITHUB_TOKEN (compared case-insensitively: GitHub resolves `secrets.github_token` to the
# same ephemeral token) — post-#101 the repo scope is provably empty (check 1), so every real
# secret, the 14 migrated names included, resolves ONLY inside the environment and any dotted
# reference demands the binding. This scope is asserted by the self-test's accept AND reject
# directions over synthetic and LIVE workflow texts, not assumed.
BINDING_SECRET_REF_RE = re.compile(
    r"\$\{\{[^}]*\bsecrets\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)
BINDING_DYNAMIC_READ_RE = re.compile(r"\$\{\{[^}]*\bsecrets\s*\[", re.IGNORECASE)
BINDING_CONTEXT_READ_RE = re.compile(r"\$\{\{[^}]*toJSON\s*\(\s*secrets\s*\)", re.IGNORECASE)
BINDING_JOB_HEADER_RE = re.compile(r"^  ([A-Za-z_][A-Za-z0-9_-]*):\s*(?:#.*)?$")

# The ONLY jobs allowed to consume secrets UNBOUND — each deliberate, each documented at the
# job. Any other consumer without the binding is a refusal; an entry here whose job no longer
# exists, no longer consumes, or now carries the binding is a STALE-exception refusal (an
# allowlist entry nobody needs is a future bypass wearing that job's name). Round 19 (sol
# finding 1): "unbound" means NO environment WHATSOEVER (`environment is None`), not merely
# "not dispatch-secrets" — environment secrets OVERRIDE same-named repository secrets, so an
# exception job bound to any other environment would read that environment's stale copies
# instead of the repo-scope originals the exception exists to consume.
BINDING_EXCEPTIONS = {
    ("dispatch.yml", "secrets-guard"):
        "the guard's UNBOUND toJSON(secrets) read IS the empty-repo-scope assertion (check 1)",
    ("migrate-secrets-to-env.yml", "quiesce"):
        "one-shot migration writer-disable phase: mints from the repo-scope bootstrap App "
        "credentials BEFORE any cutover (env-UNBOUND by design, see that file's header)",
    ("migrate-secrets-to-env.yml", "migrate"):
        "one-shot migration main phase: MUST read the repo-scope originals to copy them into "
        "the environment — bound, it would read back the env copies and the originals could "
        "never be verified or drained (env-UNBOUND by design, see that file's header)",
}

# The env-scoped secret WRITE sites the map depends on: `gh secret set <ARG> ...` invocations
# (the `gh` token may arrive via an expansion like "${WORKER_GH_BIN:-/usr/bin/gh}", hence the
# `[}"]*` tail). Group 1 = the first argument (the secret-name word), used to select the pinned
# invocation; a quoted self-test fixture string carries no leading `gh` and never matches.
SECRET_WRITE_RE = re.compile(r'gh[}"]*\s+secret\s+set\s+("?\$?[A-Za-z_][A-Za-z0-9_]*"?)')


def workflow_jobs(workflow_text):
    """Pure: {job name: [body lines]} for the top-level `jobs:` block, or None when the block
    cannot be located or holds no jobs (callers treat None as a failure — fail closed). Same
    deliberately NARROW, dependency-free line-parser discipline as workflow_guard_permissions
    above: a column-0 `jobs:` line, two-space job keys, body = every following line until the
    next job key; a column-0 non-comment line ends the block. Reshaping a workflow out of this
    shape goes red in the self-test rather than silently passing."""
    lines = workflow_text.splitlines()
    try:
        start = lines.index("jobs:")
    except ValueError:
        return None
    jobs = {}
    current = None
    for line in lines[start + 1:]:
        if line and not line.startswith(" ") and not line.startswith("#"):
            break  # dedented out of the jobs block
        header = BINDING_JOB_HEADER_RE.match(line)
        if header:
            current = header.group(1)
            jobs[current] = []
        elif current is not None:
            jobs[current].append(line)
    return jobs or None


def job_environment(body_lines):
    """Pure: the job-level `environment:` name — the inline scalar form (`environment: x`) or
    the mapping form's `name:` key — or None when the job carries no binding."""
    for index, line in enumerate(body_lines):
        code = line.split("#", 1)[0].rstrip()
        if code == "    environment:":
            for follow in body_lines[index + 1:]:
                if not follow.startswith("      "):
                    break
                follow_code = follow.split("#", 1)[0].strip()
                if follow_code.startswith("name:"):
                    return follow_code.partition(":")[2].strip()
            return None
        if code.startswith("    environment:"):
            return code.partition(":")[2].strip()
    return None


def job_secret_reads(body_lines):
    """Pure: sorted secret-consuming expressions in one job's body (see the BINDING_* regexes
    above). Full-line comments and ` #` comment tails are stripped first, so prose ABOUT a
    secret never demands a binding; the surviving code lines are then scanned as ONE joined
    text (round 18) so an expression split across YAML folded-scalar continuation lines —
    one string by the time GitHub evaluates it — still registers as a read. Names are
    reported UPPERCASED: GitHub resolves them case-insensitively, so `secrets.acct02_token`
    and `secrets.ACCT02_TOKEN` are the same secret (and the ephemeral-token exemption must be
    case-insensitive for the same reason)."""
    code_lines = []
    for line in body_lines:
        if line.lstrip().startswith("#"):
            continue
        code_lines.append(line.split(" #", 1)[0])
    body = "\n".join(code_lines)
    reads = set()
    for name in BINDING_SECRET_REF_RE.findall(body):
        if name.upper() != "GITHUB_TOKEN":
            reads.add(f"secrets.{name.upper()}")
    if BINDING_DYNAMIC_READ_RE.search(body):
        reads.add("secrets[...]")
    if BINDING_CONTEXT_READ_RE.search(body):
        reads.add("toJSON(secrets)")
    return sorted(reads)


def secret_consuming_jobs(workflow_docs):
    """Pure: {(filename, job): (reads, environment)} over {filename: workflow text} — the
    DERIVED binding map binding_map_verdict checks. None when any document's jobs block cannot
    be parsed (fail closed). Exposed separately so the self-test can anchor the LIVE derivation
    to known consumers: a scan that stops seeing worker.yml's secrets[secret_ref] job is parser
    rot, not safety."""
    consuming = {}
    for filename in sorted(workflow_docs):
        jobs = workflow_jobs(workflow_docs[filename])
        if jobs is None:
            return None
        for job_name, body in jobs.items():
            reads = job_secret_reads(body)
            if reads:
                consuming[(filename, job_name)] = (reads, job_environment(body))
    return consuming


def binding_map_verdict(workflow_docs):
    """Pure: (ok, reason). EVERY secret-consuming job across the given workflow documents must
    carry the job-level `environment: dispatch-secrets` binding, except the documented
    BINDING_EXCEPTIONS. Fail closed on: no documents, an unparseable jobs block, a scan that
    derives ZERO consumers (it proves nothing — parser or repo shape drifted), and stale
    exceptions (scoped to filenames present in the documents so synthetic fixtures compose;
    the live self-test separately anchors every exception file's presence)."""
    if not workflow_docs:
        return False, "no workflow documents to scan (fail closed)"
    consuming = secret_consuming_jobs(workflow_docs)
    if consuming is None:
        broken = sorted(name for name in workflow_docs
                        if workflow_jobs(workflow_docs[name]) is None)
        return False, ("cannot locate a `jobs:` block in: " + ", ".join(broken)
                       + " (fail closed)")
    if not consuming:
        return False, ("derived ZERO secret-consuming jobs — the scan proves nothing "
                       "(fail closed: the parser or the repository shape has drifted)")
    stale = sorted(f"{filename}::{job}" for (filename, job) in BINDING_EXCEPTIONS
                   if filename in workflow_docs and (filename, job) not in consuming)
    if stale:
        return False, ("STALE binding exception(s): " + ", ".join(stale) + " — the job no "
                       "longer exists or no longer consumes secrets; remove the exception so "
                       "the allowlist cannot silently cover a future job of the same name")
    for (filename, job_name), (reads, environment) in sorted(consuming.items()):
        if (filename, job_name) in BINDING_EXCEPTIONS:
            if environment == ENVIRONMENT:
                return False, (f"STALE binding exception: {filename}::{job_name} is on the "
                               f"deliberately-UNBOUND list but now carries `environment: "
                               f"{ENVIRONMENT}` — remove the exception")
            if environment is not None:
                return False, (
                    f"{filename}::{job_name} is a deliberately-UNBOUND binding exception but "
                    f"is bound to environment {environment!r} — environment secrets OVERRIDE "
                    "same-named repository secrets, so ANY binding lets that environment's "
                    "copies shadow the repo-scope originals this exception exists to read "
                    "(round 19: a stale-value injection wearing a green tick); exceptions "
                    "must carry NO `environment:` at all")
            continue
        if environment != ENVIRONMENT:
            bound = f" (bound to {environment!r} instead)" if environment else ""
            return False, (
                f"{filename}::{job_name} reads {', '.join(reads)} but has no job-level "
                f"`environment: {ENVIRONMENT}` binding{bound} — post-#101 every real secret "
                "lives ONLY in that environment, so this job either reads EMPTY secrets "
                "(broken) or, should the secrets ever regress to repo scope, becomes an "
                "any-ref exfiltration surface")
    return True, "ok"


PRIVILEGED_SCRIPT_RE = re.compile(
    r"(?:^|[;&|]\s*|\s)(?:python3|bash)\s+(?:registry/)?(scripts/[A-Za-z0-9_.-]+(?:\.py|\.sh))"
)


def privileged_script_coverage_verdict(workflow_docs, surface_paths):
    """Pure: prove every script executed by a secret-consuming or write-permission job is inside
    the human-arm trust surface. The inventory is derived from workflow job bodies; zero matches,
    an unreadable jobs block, or one uncovered script fails closed."""
    # normalize_repo_path, NOT lstrip("./") — see its docstring: the character-set semantics of
    # lstrip ate the leading dot of every dotfile surface (`.github/...`), so a surface entry could
    # match a path it does not actually cover.
    surfaces = tuple(normalize_repo_path(path)
                     for path in surface_paths if isinstance(path, str) and path.strip())
    # An EMPTY surface must refuse HERE, naming the derivation (issue #618 defect 2). Falling
    # through with no surfaces marks every derived script uncovered, which reads as "22 privileged
    # scripts escaped the human-arm policy" — a security-policy verdict — when the real fault is
    # that the surface could not be READ at all. The misdiagnosis cost is the whole point: the
    # emitted list even contained this guard script itself.
    if not surfaces:
        return False, ("the human-arm trust surface derived EMPTY — this is a DERIVATION failure "
                       "(unreadable worker-pr.py / policy/repos.toml, or a moved key), NOT a "
                       "finding about the scripts; fix the derivation (fail closed)")
    privileged = set()
    for filename, document in sorted(workflow_docs.items()):
        jobs = workflow_jobs(document)
        if jobs is None:
            return False, f"cannot parse jobs in {filename} (fail closed)"
        for job_name, body_lines in jobs.items():
            body = "\n".join(body_lines)
            has_write = bool(re.search(r"(?m)^\s{6,}[a-z-]+:\s*write(?:\s*#.*)?$", body))
            if job_secret_reads(body_lines) or has_write:
                privileged.update(PRIVILEGED_SCRIPT_RE.findall(body))
    if not privileged:
        return False, "derived ZERO privileged scripts (fail closed)"

    def covered(path):
        return any(path.startswith(surface) if surface.endswith("/")
                   else path == surface or path.startswith(surface + "/")
                   for surface in surfaces)

    uncovered = sorted(path for path in privileged if not covered(path))
    if uncovered:
        return False, "privileged scripts outside human-arm trust surface: " + ", ".join(uncovered)
    return True, "ok"


# ---- NO CREDENTIAL ON A COMMAND LINE (issue #417; #195 fixed the same class in Python) ----------
# A bearer credential handed to a subprocess as an ARGUMENT is readable by every process on the
# runner through /proc/<pid>/cmdline, is captured verbatim by any diagnostic that snapshots running
# commands, and survives in `ps` output long enough to be scraped. #195 moved the probe credential
# in scripts/account-usage.py onto curl's STDIN header stream (`-H @-`); #417 is the same leak in
# the workflow SHELL — the fleet-wide account probes and the App-JWT verifier. The Python side had a
# self-test to hold it; the shell side had nothing, which is why the class survived a fix.
#
# THE INVARIANT, asserted repo-wide over every workflow job body: a command-line HEADER FLAG
# (`-H`/`--header`, including the joined `-H<value>` and `--header=<value>` forms) must never carry
# an `Authorization:`/`Proxy-Authorization:` value. The credential must arrive over stdin (`-H @-`)
# or from a mode-0600 file (`-H @path`) instead.
#
# Keyed on the FLAG, not on the command name, deliberately: shell_simple_commands drops a leading
# `VAR=$(...)` as an assignment prefix, so the curl inside `code=$(curl … )` — the exact shape of
# three of the five #417 sites — is NOT the command word and a command-name-keyed scan would be
# blind to it. Keying on the flag also leaves `printf 'Authorization: …' | curl -H @-` (the fix)
# clean: printf is a shell BUILTIN, forks no process, and its words are not a header flag's value.
#
# DECLARED LIMITATION: a header assembled into a variable first (`AUTH="Authorization: Bearer $T";
# curl -H "$AUTH"`) reads as `-H $AUTH` and is NOT caught. The check is a floor against the shape
# that has actually shipped twice, not a taint tracker.
CREDENTIAL_HEADER_RE = re.compile(r"^\s*(proxy-authorization|authorization)\s*:", re.IGNORECASE)
HEADER_FLAGS = ("-H", "--header")


def command_line_header_values(run_text):
    """Pure: every header value passed as a COMMAND-LINE argument in one shell body, in order.

    Comments and here-document BODIES are stripped by the shared shell readers first (a header
    inside a here-doc is data, not argv). A flag and its value cannot span an operator, so a
    trailing `-H` before a `|`/`;`/newline yields nothing rather than swallowing the next command."""
    values = []
    pending = False
    for kind, token in _shell_tokens(strip_shell_comments(strip_shell_heredocs(run_text))):
        if kind == "op":
            pending = False
            continue
        word = unquote_shell_word(token)
        if pending:
            values.append(word)
            pending = False
            continue
        if word in HEADER_FLAGS:
            pending = True                       # `-H <value>` / `--header <value>`
        elif word.startswith("--header="):
            values.append(word[len("--header="):])
        elif word.startswith("-H") and len(word) > 2:
            values.append(word[2:])              # the joined short form `-H<value>`
    return tuple(values)


def credential_argv_verdict(workflow_docs):
    """Pure: (ok, reason) over {filename: workflow text}. Refuses when any workflow job passes an
    Authorization header as a command-line argument, and refuses when the scan finds NO header
    arguments at all — a scan that observed nothing proves nothing (fail closed: the reader or the
    repository shape has drifted). Only the header NAME is ever reported: a refusal message is
    printed into a PUBLIC Actions log, so the value — which is the credential — is never echoed."""
    leaks, observed = [], 0
    for filename in sorted(workflow_docs):
        jobs = workflow_jobs(workflow_docs[filename])
        if jobs is None:
            return False, (f"cannot parse jobs in {filename} — refusing to certify that its "
                           "command lines carry no credential (fail closed)")
        for job_name, body_lines in sorted(jobs.items()):
            for value in command_line_header_values("\n".join(body_lines)):
                observed += 1
                match = CREDENTIAL_HEADER_RE.match(value)
                if match:
                    leaks.append(f"{filename}::{job_name} (`{match.group(1)}:`)")
    if not observed:
        return False, ("scanned ZERO command-line header arguments repo-wide — the scan proves "
                       "nothing (fail closed: the shell reader or the repository shape has "
                       "drifted, and a silent zero would certify a leak as clean)")
    if leaks:
        return False, (
            "credential header(s) passed on a COMMAND LINE: " + ", ".join(sorted(set(leaks)))
            + " — argv is readable by every process on the runner (/proc/<pid>/cmdline) and is "
            "captured by diagnostic command capture; feed the header through curl's stdin "
            "(`-H @-`) or a mode-0600 `-H @file` instead (issue #417, issue #195)")
    return True, "ok"


# ---- the ROTATION WRITE-BACK must be reachable from the FAILURE path (retro-review of #614) ------
# #614 moved the credential refresh HOST-SIDE, into worker-prep.sh, and made the rotation write-back
# key on "the pre-flight produced new durable material". It also gated the write-back step on
# `steps.prepare.outcome == 'success'`. Those two facts are incompatible: the provider commits the
# rotation EARLY inside prepare, and prepare then keeps going (materialize the minimal mount, assert
# no refresh material leaked, copy the tamper baseline, npm-install the pinned CLI, export
# $GITHUB_ENV). Any failure in that window skips the write-back, so the OLD grant is spent, the NEW
# grant is discarded with the runner, and — provider refresh tokens being ONE-TIME-USE — the account
# is permanently dead until an interactive re-mint.
#
# That is the SAME CLASS as #604's root cause: a compensating action reachable only from the success
# path. #604's void job was gated on a validated verdict, so the credential outage it existed to
# compensate for skipped it. Here the compensation for a consumed grant is gated on the success of
# the very step that consumes it. So the invariant is asserted structurally, in the workflow YAML —
# the seam the retro-review found vacuity concentrated in — and in BOTH lanes.
WRITEBACK_SCRIPT_RE = re.compile(r"(?:[\w./$~{}-]*/)?scripts/worker-live\.sh")
WRITEBACK_SUBCOMMAND = "write-back"
# Textual presence of the call site, used ONLY to tell "the step mentions the write-back and does not
# run it" (a refusal that names the fact) apart from "this step has nothing to do with the write-back".
WRITEBACK_TEXT_RE = re.compile(r"scripts/worker-live\.sh\s+" + WRITEBACK_SUBCOMMAND + r"\b")
# Every lane that MUST carry the production write-back call site. RETRO-REVIEW OF #629 (F3): defect
# 3's production call site had NO test — commenting out `run: bash registry/scripts/worker-live.sh
# write-back` in BOTH live lanes (keeping the text, so `WRITEBACK_STEP_RE` still matched and the
# "zero write-back steps => refuse" non-vacuity guard stayed satisfied) left the entire enrolled suite
# GREEN while every rotated grant would be silently discarded. Presence is now required PER LANE and
# proven through shell_script_invocations, so a comment-out in EITHER lane is a red tick on its own.
WRITEBACK_REQUIRED_LANES = ("worker.yml", "review-fix.yml")
# The atom whose falsity must NOT make the write-back unreachable: "the credential-prepare step
# succeeded". Matches `steps.<id>.outcome == 'success'` / `.conclusion == 'success'` for the prepare
# step under either quote style, with or without spaces. Retained to NAME #614's original defect in
# the refusal; the obligation itself is now decided by the allowlist below, not by this pattern.
PREPARE_SUCCESS_RE = re.compile(
    r"steps\s*\.\s*prepare\s*\.\s*(?:outcome|conclusion)\s*==\s*['\"]success['\"]")
# The ONLY atoms the rotation write-back's `if:` may reference, each paired with the value it takes on
# a path where A ROTATION MAY ALREADY HAVE HAPPENED. Every one of them is settled BEFORE the
# credential pre-flight runs, which is exactly what makes it legitimate to gate on:
#   * `always()` is a constant;
#   * `inputs.dry_run` is a workflow INPUT (and a dry run never exchanges the grant at all —
#     worker.yml passes WORKER_PREFLIGHT_REFRESH=skip — so a rotation cannot have happened);
#   * `needs.claim.outputs.acquired` is an UPSTREAM JOB output (no account claimed, no grant used);
#   * `steps.selected.*` is the account-SELECTION step, which precedes prepare.
# Anything else — the prepare step's own outcome, the MODEL step's outcome, a prepare OUTPUT,
# `success()` — is correlated with or downstream of the very failure the write-back compensates for,
# so referencing it is a REFUSAL naming the atom rather than a freely-satisfiable boolean (F4).
WRITEBACK_ROTATION_POSSIBLE_WORLD = (
    (re.compile(r"always\(\)"), True),
    (re.compile(r"(?:github\.event\.)?inputs\.dry_run"), False),
    (re.compile(r"(?:github\.event\.)?inputs\.dry_run==(?:['\"]true['\"]|true)"), False),
    (re.compile(r"(?:github\.event\.)?inputs\.dry_run==(?:['\"]false['\"]|false)"), True),
    (re.compile(r"needs\.claim\.outputs\.acquired==['\"]true['\"]"), True),
    (re.compile(r"steps\.selected\.(?:outcome|conclusion)==['\"]success['\"]"), True),
)


def rotation_writeback_reachable_verdict(workflow_docs, required_lanes=()):
    """Pure: (ok, reason). Every workflow that runs `worker-live.sh write-back` must run it on EVERY
    path where a credential rotation may already have happened — and each lane in `required_lanes`
    must actually carry the call site.

    THE OBLIGATION IS UNIVERSAL, NOT EXISTENTIAL (retro-review of #629, F4). #629 asked
    `if_condition_admits` whether there EXISTS a world in which the write-back runs while
    `steps.prepare.outcome == 'success'` is false, leaving every other atom free. That is the right
    question for a must-not-run gate and the WRONG one here, because the free atoms are precisely the
    ones correlated with prepare failing. MEASURED on the LIVE worker.yml, whole suite green:
    `&& steps.model.outcome == 'success'` (#596's original defect, which the step's own comment says
    must never come back), `&& steps.prepare.outcome != 'failure'` (defect 3 one token differently
    spelled), a prepare-output atom and `${{ success() }}` all passed. The obligation is now
    `if_condition_requires` over WRITEBACK_ROTATION_POSSIBLE_WORLD: the condition must evaluate TRUE
    on the rotation-possible path, and may reference NOTHING whose value that path leaves open.

    Fail directions, all deliberate:
      * an `if:` that cannot be decided, or that references an atom outside the allowlist, is a
        refusal (unlike the gate, where undecided means "cannot prove it gates"; here it means
        "cannot prove the compensation is reachable", and an unpersisted rotation is unrecoverable);
      * a step whose `run:` CONTAINS the write-back command but never executes it — commented out,
        short-circuited, inside a here-doc — is a refusal naming that fact (F3);
      * a required lane with no reachable call site is a refusal naming the lane (F3);
      * finding ZERO write-back steps across the documents is a refusal — the step was renamed or
        removed and this assertion would otherwise pass vacuously, which is exactly how #614's gap
        survived its own review."""
    if not workflow_docs:
        return False, "no workflow documents to scan (fail closed)"
    found = {}
    for filename in sorted(workflow_docs):
        jobs = workflow_job_docs(workflow_docs[filename])
        if jobs is None:
            continue     # not every workflow has a parseable jobs block worth scanning here
        for job_name, job_doc in sorted(jobs.items()):
            for index, step in enumerate(_job_steps(job_doc)):
                run = step.get("run")
                if not isinstance(run, str):
                    continue
                reached, blocked = shell_script_invocations(
                    run, "bash", WRITEBACK_SCRIPT_RE, (WRITEBACK_SUBCOMMAND,))
                where = f"{filename}::{job_name} step {index}"
                if not reached and (blocked or WRITEBACK_TEXT_RE.search(run)):
                    return False, (
                        f"{where}: the step CONTAINS the text of `worker-live.sh "
                        f"{WRITEBACK_SUBCOMMAND}` but never RUNS it (commented out, short-circuited "
                        "behind `||`/`&&`, or inside a here-doc or conditional construct). Every "
                        "host-side-rotated grant would be silently discarded while this assertion "
                        "passed on the text alone (retro-review of #629: the production call site "
                        "must be deletable ONLY at the cost of a red tick)")
                if not reached:
                    continue
                found.setdefault(filename, []).append(where)
                condition = step.get("if")
                if condition is None:
                    continue        # unconditional: maximally reachable
                holds, decided, detail = if_condition_requires(
                    condition, WRITEBACK_ROTATION_POSSIBLE_WORLD)
                if not decided:
                    return False, (
                        f"{where}: the rotation write-back's `if:` ({condition!r}) cannot be proven "
                        f"to hold on every path where a rotation may already have happened "
                        f"({detail})"
                        + (" — this is #596's ORIGINAL defect, a guard on the very step whose "
                           "pre-flight CONSUMES the one-time-use grant"
                           if PREPARE_SUCCESS_RE.search(str(condition)) else "")
                        + ". The condition may only be keyed to facts settled BEFORE the pre-flight "
                        "(always(), the dry-run input, the claim outputs, the account SELECTION "
                        "step); let worker-live.sh's rotation MARKER decide whether there is "
                        "anything to persist (fail closed)")
                if not holds:
                    return False, (
                        f"{where}: the rotation write-back does NOT run on a path where the "
                        f"credential pre-flight may already have rotated the grant (`if:` = "
                        f"{condition!r}; {detail}). The host-side pre-flight consumes the stored "
                        "ONE-TIME-USE refresh token EARLY inside the prepare step, so every later "
                        "failure in it (the no-leak assertion, the tamper baseline, the pinned CLI "
                        "install, the $GITHUB_ENV export) discards a grant the provider has already "
                        "rotated — old one spent, new one thrown away, account permanently dead "
                        "until an interactive re-mint (#614; same class as #604's root cause)")
    missing_lanes = [lane for lane in required_lanes if lane not in found]
    if missing_lanes:
        return False, (
            "lane(s) " + ", ".join(missing_lanes) + " carry NO reachable `worker-live.sh "
            f"{WRITEBACK_SUBCOMMAND}` step — the production call site of the rotation write-back is "
            "gone from a lane that runs the host-side credential pre-flight, so every grant that "
            "lane rotates is discarded with the runner (fail closed)")
    if not found:
        return False, ("found ZERO `worker-live.sh write-back` steps in any workflow — the rotation "
                       "write-back was renamed or removed, and this reachability assertion would "
                       "pass vacuously (fail closed)")
    return True, "ok"


def secret_env_write_verdict(text, secret_arg, where):
    """Pure: (ok, reason). Locates every `gh secret set <secret_arg> ...` invocation in `where`
    (comments stripped, backslash continuations joined) and requires each to carry
    `--env dispatch-secrets`: a repo-scope write would re-trip the empty-repo-scope check on
    the next tick AND strand the env-bound consumers on the pre-rotation credential (they
    resolve secrets from the environment, never repo scope). A write site that cannot be
    located is a refusal — reshaping it out of recognition must surface here (fail closed).
    Round 19 (sol finding 3): inline comments are stripped QUOTE-AWARELY (strip_shell_comments)
    BEFORE matching — `... < file # --env dispatch-secrets` used to pass on comment prose while
    the real invocation wrote to repo scope; stripping happens before continuation-joining, so
    a commented-out trailing backslash also stops continuing, exactly as in a real shell."""
    lines = [strip_shell_comments(line) for line in text.splitlines()]
    found = False
    for index, line in enumerate(lines):
        joined = line.rstrip()
        follow = index
        while joined.endswith("\\") and follow + 1 < len(lines):
            follow += 1
            joined = joined.rstrip("\\").rstrip() + " " + lines[follow].strip()
        for match in SECRET_WRITE_RE.finditer(joined):
            if match.group(1) != secret_arg:
                continue
            found = True
            if f"--env {ENVIRONMENT}" not in joined:
                return False, (f"{where}: `gh secret set {secret_arg}` does not carry "
                               f"`--env {ENVIRONMENT}` — a repo-scope write re-trips the "
                               "empty-repo-scope guard AND leaves the environment copy stale "
                               "while every env-bound consumer keeps resolving it")
    if not found:
        return False, (f"{where}: the `gh secret set {secret_arg}` write site was not found "
                       "(fail closed — reshaping the write must not silently pass)")
    return True, "ok"


# TRANSIENT-READ MARKERS. A read that fails for one of these reasons tells us NOTHING about the
# repository's settings — it means the guard could not look. Deliberately POSITIVE EVIDENCE ONLY:
# anything not matched here keeps the historical verdict (a settings finding), so this can only
# ever demote a failure the guard has proof was an availability problem. That polarity matters
# because the residual class is the one that prints a maintainer action item, and inferring
# "transient" from the ABSENCE of a marker would start suppressing real settings gaps.
#
# A 404 is deliberately NOT here: `environment dispatch-secrets is missing` IS the #101 condition.
_TRANSIENT_READ_MARKERS = (
    "rate limit",             # primary (installation budget) AND secondary — both clear by waiting
    "abuse detection",
    "temporarily blocked",
    "retry-after",
    "retry later",
    "502 bad gateway", "503 service", "504 gateway", "bad gateway", "service unavailable",
    "timed out", "timeout", "i/o timeout", "connection reset", "unexpected eof",
    "connection refused", "no such host", "tls handshake",
    "unexpected end of json input",
)
_TRANSIENT_STATUS = ("403", "429", "500", "502", "503", "504")
_STATUS_RE = re.compile(r"HTTP[ :]*([1-5]\d\d)\b|\(HTTP ([1-5]\d\d)\)")
# The statuses on which the 403 taxonomy is consulted. 403 is the real one; None is here because
# `gh`'s message is TRUNCATED by some callers and by its own wrapping, and the measured primary
# wording ("API rate limit exceeded for installation. For more information about rate limiting,
# see https://docs.github.com/...") is long enough that the trailing `(HTTP 403)` is the first
# thing to go — registry #710 measured exactly that excerpt on the live sink. A budget message
# whose status was cut off is still a budget message.
_BUDGET_CANDIDATE_STATUS = (None, "403")


def classify_read_failure(stderr):
    """-> 'budget' | 'transient' | 'refusal'. Which class a failed `gh api` GET belongs to.

    `transient` requires BOTH a throttle/availability marker AND a status that can carry one, so a
    404 body that happens to contain the word "timeout" is still a refusal. Everything else is
    `refusal`, which is what preserves today's behaviour for genuine settings gaps.

    `budget` (registry #1208) IS CARVED OUT OF `transient`, NEVER OUT OF `refusal`, and the
    structure below is written so that is checkable by reading rather than by trusting a comment:
    both `refusal` returns come FIRST and are byte-identical to the pre-#1208 conditions, and the
    new branch sits strictly inside what used to be the single `return "transient"`. So every
    input that refused before still refuses, and the only inputs that change answer are ones that
    were already being treated as "the guard could not look" — a class that fails closed either
    way. That is the whole safety argument for this change.

    WHY THE DISTINCTION IS WORTH DRAWING. Both classes fail closed, so the DECISION is identical;
    what differs is what the guard TELLS THE OPERATOR, and those two things imply opposite
    responses. An availability blip clears on its own in seconds and re-running is free. A primary
    budget exhaustion carries NO `Retry-After`, resets on a clock up to an hour away, and every
    retry spends a request from a bucket that has none — so "transient, recovers on its own" is
    both false and actively harmful advice. MEASURED 2026-07-29 06:00-09:00Z: GUARD failed on 16 of
    51 started dispatch runs (31%) calling this "an availability reason", and on the 4 of those
    where the FLOOR admitted the tick, PLAN reached the same 403 and printed the truth —
    `x-ratelimit-remaining=0/5000`.

    THE EVIDENCE HERE IS WEAKER THAN PLAN'S, AND THE WORDING SAYS SO. `gh api` surfaces an error as
    a message on stderr; the response headers are gone by then, so unlike plan-snapshot this cannot
    read `x-ratelimit-remaining` and never claims to. It classifies from GitHub's own wording via
    the shared taxonomy's TEXT entry point."""
    text = (stderr or "").lower()
    if not any(marker in text for marker in _TRANSIENT_READ_MARKERS):
        return "refusal"
    match = _STATUS_RE.search(stderr or "")
    status = (match.group(1) or match.group(2)) if match else None
    # A statusless failure carrying an availability marker (a dropped connection never gets a
    # status line) is transient; a status we CAN read must be one of the throttle/5xx classes.
    if status is not None and status not in _TRANSIENT_STATUS:
        return "refusal"
    # Everything from here down was `return "transient"` before #1208.
    if status in _BUDGET_CANDIDATE_STATUS and gh_403.is_budget_exhaustion_text(stderr):
        return "budget"
    return "transient"


def _api(path, transient_reads=None, budget_reads=None):
    """Read-only `gh api` GET. Returns the parsed JSON document, or None on any failure —
    sanitized: neither stderr nor the payload is ever echoed (GH_DEBUG=api can echo request
    bodies; an error page is remote-controlled content).

    When `transient_reads` is given, a failure this function can PROVE was an availability problem
    (a 403 throttle, a 429, a 5xx, a dropped connection) appends the endpoint to it. `main` uses
    that to tell "the settings are wrong" apart from "I could not check the settings" — the two
    were indistinguishable, so a budget outage printed a maintainer action item no human could act
    on (issue #819's 06:19-06:32Z runs printed the #101 remediation having verified nothing).

    `budget_reads` is the SAME "I could not look" class, split out (#1208) for the one sub-case
    whose honest remedy is different: the request budget is spent, so the wait is a machine clock
    and re-running costs a request nobody has. Both lists drive the identical FAIL-CLOSED decision;
    they select only the wording. A caller that passes `transient_reads` but not `budget_reads`
    gets the pre-#1208 behaviour with budget failures folded back into the transient list, so no
    proven-unverified read is ever LOST by this split — that would be the one way this change could
    turn an unverified failure back into a settings accusation."""
    result = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    if result.returncode != 0:
        kind = classify_read_failure(getattr(result, "stderr", ""))
        # The PATH only. stderr is never surfaced: it can carry request bodies under
        # GH_DEBUG=api, and an error page is remote-controlled content.
        if kind == "budget" and budget_reads is not None:
            budget_reads.append(path)
        elif kind in ("transient", "budget") and transient_reads is not None:
            transient_reads.append(path)
        return None
    try:
        document = json.loads(result.stdout)
    except ValueError:
        return None
    return document


def main():
    repo = os.environ.get("REGISTRY_REPO", "")
    if not REPO_RE.fullmatch(repo):
        print("::error::secrets-guard: REGISTRY_REPO is unsafe or unset (fail closed)")
        return 1
    failures = []
    try:
        secrets_map = json.loads(os.environ.get("ALL_SECRETS") or "")
    except ValueError:
        secrets_map = None
    if not isinstance(secrets_map, dict):
        failures.append("ALL_SECRETS (the unbound-job secrets context) is unreadable")
        secrets_map = {}
    scope_ok, offending = repo_scope_verdict(secrets_map)
    if not scope_ok:
        failures.append(
            "secrets are reachable OUTSIDE the `dispatch-secrets` environment (names only): "
            f"{', '.join(offending)} — a modified workflow copy dispatched at ANY ref can read "
            "these; move them into the environment")

    # Failures whose CAUSE was a read this guard could prove was an availability problem. They are
    # still fail-closed failures — an unverified setting must never admit the secret-bearing jobs —
    # but they are NOT evidence that any setting is wrong, so they must not print the maintainer
    # action item. See classify_read_failure.
    transient_reads = []
    # The same "could not look" class, split for WORDING ONLY (#1208): a spent request budget is a
    # machine-cleared wait, not an availability blip, and telling an operator otherwise invites the
    # one response that makes it worse. Same fail-closed decision. See classify_read_failure.
    budget_reads = []
    unverified = []

    def _unverified(message):
        """Record a failure caused by a read that did not complete. Attributed to the unverified
        class only when the read that produced it was PROVEN not to be a settings finding —
        transient OR budget-exhausted. Both are "the guard could not look"; neither is evidence
        about any setting."""
        failures.append(message)
        if transient_reads or budget_reads:
            unverified.append(message)

    repo_doc = _api(f"repos/{repo}", transient_reads, budget_reads)
    default_branch = repo_doc.get("default_branch") if isinstance(repo_doc, dict) else None
    if not isinstance(default_branch, str) or not default_branch:
        _unverified("cannot resolve the repository default branch (fail closed)")
    else:
        environment_doc = _api(f"repos/{repo}/environments/{ENVIRONMENT}",
                               transient_reads, budget_reads)
        if environment_doc is None:
            _unverified(f"environment `{ENVIRONMENT}` is missing or unreadable")
        else:
            policies_doc = _api(
                f"repos/{repo}/environments/{ENVIRONMENT}/deployment-branch-policies",
                transient_reads, budget_reads)
            policy_ok, reason = branch_policy_verdict(
                environment_doc, policies_doc, default_branch)
            if not policy_ok:
                _unverified(f"environment `{ENVIRONMENT}`: {reason}")

    if failures:
        for failure in failures:
            print(f"::error::secrets-guard: {failure}")
        # THE REMEDIATION IS A CLAIM ABOUT THE SETTINGS, so it may only be printed when at least
        # one failure is a claim about the settings. When EVERY failure traces to a read that did
        # not complete, the guard has verified nothing and has no business generating a maintainer
        # action item — an API outage that manufactures one costs a human a trip to a settings page
        # that is already correct, and buries the real signal (#819).
        if unverified and len(unverified) == len(failures):
            # WHICH unverified wording. Budget wins whenever ANY read proved exhaustion, because
            # the two messages differ in the advice they imply and only one of them is true then:
            # "recovers on its own when a tick completes the reads" invites the retry that a bucket
            # at zero cannot pay for. Availability is the residual — the class with no positive
            # budget evidence — which is the same polarity rule the marker table above uses.
            if budget_reads:
                print(f"::error::secrets-guard: BUDGET — {len(budget_reads)} GitHub read(s) were "
                      f"refused ({', '.join(sorted(set(budget_reads)))}) because the shared "
                      "`github.token` REQUEST BUDGET IS SPENT (GitHub's primary rate-limit "
                      "wording is the evidence — this job reads through `gh`, so unlike PLAN it "
                      "cannot see `x-ratelimit-remaining` and does not claim to). The settings "
                      "above are UNVERIFIED, not known-wrong: this is "
                      "NOT a settings finding, NO maintainer action is implied, and it is NOT an "
                      "availability problem. DO NOT RE-RUN THE TICK TO CLEAR IT — this 403 carries "
                      "no `Retry-After`, it clears only when `x-ratelimit-reset` arrives (up to an "
                      "hour away), and every retry spends a request from a bucket that has none. "
                      "THE WAIT IS MACHINE-CLEARED: scripts/dispatch-tick-floor.py defers on the "
                      "same condition and writes no anchor (#1190), so the first doorbell ring "
                      "after the reset executes immediately and this guard verifies then. If PLAN "
                      "is failing too, it is this same exhaustion — see #819, #1208.")
            else:
                print(f"::error::secrets-guard: TRANSIENT — {len(transient_reads)} GitHub read(s) "
                      f"failed for an availability reason "
                      f"({', '.join(sorted(set(transient_reads)))}), "
                      "so the settings above are UNVERIFIED, not known-wrong. This is NOT a "
                      "settings finding and NO maintainer action is implied: the guard fails "
                      "closed until a tick completes the reads, and recovers on its own when they "
                      "do. If the dispatcher is also failing in PLAN, this is the same "
                      "request-budget exhaustion — see scripts/dispatch-tick-floor.py (#819).")
        else:
            print(f"::error::{REMEDIATION}")
        return 1
    print("secrets-guard: repo scope holds no secrets and the "
          f"`{ENVIRONMENT}` environment admits only `{default_branch}` — "
          "exfil protections verified")
    return 0


def _self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        # repr(), NOT str(): a `got`/`want` holding an embedded newline (the comment-stripper
        # checks do) used to print across several lines, and the orphan fragments
        # (`tail  (want keep "a # b"`) were read as a THIRD failing assertion when issue #618 was
        # triaged from the run log — a phantom, since the check passed. One line per check keeps
        # log-scraped failure counts honest.
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    # Pure workflow-permission extraction — accept AND reject directions on synthetic text.
    sample = "\n".join([
        "jobs:",
        "  plan:",
        "    permissions:",
        "      contents: read",
        "  secrets-guard:",
        "    permissions:",
        "      # actions:read is load-bearing",
        "      actions: read",
        "      contents: read  # sparse checkout",
        "    steps:",
        "      - run: true",
        "  claim:",
        "    permissions:",
        "      actions: write",
    ])
    chk("workflow parse: extracts the guard job's map (comments stripped, other jobs ignored)",
        workflow_guard_permissions(sample), {"actions": "read", "contents": "read"})
    chk("workflow parse: missing guard job -> None (fail closed)",
        workflow_guard_permissions("jobs:\n  plan:\n    permissions:\n      contents: read"),
        None)
    chk("workflow parse: guard job without a permissions map -> None (fail closed)",
        workflow_guard_permissions("jobs:\n  secrets-guard:\n    steps:\n      - run: true"),
        None)

    # Static workflow-permission assertion (review round 2 on the #101 PR): the environment +
    # deployment-branch-policy GETs need `actions: read` on the job token, and the guard job's
    # explicit permissions map zeroes everything unlisted — a silent drop (or widening) of its
    # grants must go red HERE. Any read/parse failure yields None and fails the check (fail
    # closed); the workflow file ships in the guard job's sparse checkout so this also runs
    # live every tick.
    workflow_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 os.pardir, ".github", "workflows", "dispatch.yml")
    try:
        with open(workflow_path, encoding="utf-8") as handle:
            live_permissions = workflow_guard_permissions(handle.read())
    except OSError:
        live_permissions = None
    chk("workflow: guard job grants exactly {actions: read, contents: read}",
        live_permissions, {"actions": "read", "contents": "read"})

    # Static set-up-account slot-union contract (sol round 6 on the #275 PR, finding 3;
    # strengthened round 8 with the ORDERING + PARTICIPATION properties after sol
    # mutation-tested the presence-only version in round 7; strengthened round 16 with the
    # DETERMINATION chain `taken -> n -> cand -> git/refs claim` after sol mutation-tested
    # THAT version with `n=$reserved`). The broker's pre-claim union is pure workflow-shell
    # (no script seam), so — following the dispatch.yml permission pin above and
    # migrate-secrets.sh's workflow mint contract — it is asserted statically over the
    # workflow text: dropping ANY of the four paginated listings, moving one AFTER the
    # `git/refs` claim creation, severing one's variable from the `taken` union, or severing
    # any link of the `taken -> n -> cand -> claim` chain goes red here. set-up-account.yml
    # ships in the guard job's sparse checkout so this also runs live every tick.
    store_step_sample = [
        "      - name: Claim slot atomically",
        "        id: store",
        "        run: |",
        '          if ! claim_nums=$(gh api --paginate "repos/${{ github.repository }}/git/matching-refs/acct-claims/" \\',
        "                 --jq '.[].ref'); then exit 1; fi",
        '          issue_nums=$(gh api --paginate "repos/${{ github.repository }}/issues?state=all&per_page=100" --jq .)',
        '          secret_nums=$(GH_TOKEN="$REGISTRY_PAT" gh api --paginate "repos/${{ github.repository }}/actions/secrets?per_page=100" --jq .)',
        '          env_secret_nums=$(gh api --paginate "repos/${{ github.repository }}/environments/dispatch-secrets/secrets?per_page=100" --jq .)',
        "          taken=$(printf '%s\\n%s\\n%s\\n%s\\n' \"$claim_nums\" \"$issue_nums\" \"$secret_nums\" \"$env_secret_nums\" \\",
        "                    | jq -Rn '[inputs | tonumber]')",
        '          n=$(jq -n --argjson t "$taken" --argjson r "$reserved" \\',
        "                'if ($t | index($r)) then (([$t[], 0] | max) + 1) else $r end')",
        "          cand=$(printf 'acct%02d' \"$n\")",
        '          out=$(gh api "repos/${{ github.repository }}/git/refs" \\',
        '                  -f ref="refs/acct-claims/$cand" -f sha="$GITHUB_SHA")',
        "      - name: Validate the registration",
        '        run: gh api --paginate "repos/${{ github.repository }}/not/part/of/the/store/step"',
    ]
    union_sample = "\n".join(store_step_sample)
    chk("setup-account union: four listings before the claim, all flowing into taken -> ok",
        setup_account_union_verdict(setup_account_store_step_lines(union_sample)),
        (True, "ok"))
    dropped_env = "\n".join(line for line in store_step_sample
                            if "environments/dispatch-secrets/secrets?" not in line)
    verdict_dropped = setup_account_union_verdict(setup_account_store_step_lines(dropped_env))
    chk("setup-account union: env-secret listing dropped -> refuse, missing path NAMED",
        (verdict_dropped[0],
         "environments/dispatch-secrets/secrets?per_page=100" in verdict_dropped[1]),
        (False, True))
    # sol round-7 mutation A (PARTICIPATION): the env listing still RUNS but its variable is
    # severed from the union — a dead listing whose slots stay invisible to the claim.
    dead_env = union_sample.replace(' "$env_secret_nums"', "", 1)
    verdict_dead = setup_account_union_verdict(setup_account_store_step_lines(dead_env))
    chk("setup-account union: sol mutation A ($env_secret_nums dropped from taken) -> refuse, DEAD listing named",
        (verdict_dead[0], "$env_secret_nums" in verdict_dead[1],
         "does not flow into" in verdict_dead[1]),
        (False, True, True))
    # sol round-7 mutation B (ORDERING): the env listing is moved AFTER the claim creation —
    # too late to stop a burned slot.
    reordered = list(store_step_sample)
    env_listing_line = reordered.pop(7)
    reordered.insert(14, env_listing_line)  # after the two claim-creation lines
    verdict_reordered = setup_account_union_verdict(
        setup_account_store_step_lines("\n".join(reordered)))
    chk("setup-account union: sol mutation B (env listing AFTER the claim) -> refuse, ordering named",
        (verdict_reordered[0], "AFTER the irreversible `git/refs` claim" in verdict_reordered[1]),
        (False, True))
    # sol round-16 mutation C (DETERMINATION, edge taken->n): the jq slot computation is
    # replaced by `n=$reserved` — every listing still runs pre-claim and flows into `taken`,
    # but `taken` never determines the claimed slot, burning a reserved-but-occupied slot.
    slot_bypass = list(store_step_sample)
    slot_bypass[10:12] = ["          n=$reserved"]
    verdict_slot = setup_account_union_verdict(
        setup_account_store_step_lines("\n".join(slot_bypass)))
    chk("setup-account union: sol mutation C (n=$reserved bypasses taken) -> refuse, ignored union named",
        (verdict_slot[0], "does not reference the `taken` union" in verdict_slot[1]),
        (False, True))
    # round-16 edge n->cand: the candidate is hardcoded instead of derived from $n.
    cand_hardcoded = list(store_step_sample)
    cand_hardcoded[12] = "          cand=acct99"
    verdict_cand = setup_account_union_verdict(
        setup_account_store_step_lines("\n".join(cand_hardcoded)))
    chk("setup-account union: candidate hardcoded (cand=acct99) -> refuse, severed derivation named",
        (verdict_cand[0], "does not derive from" in verdict_cand[1]), (False, True))
    # round-16 edge cand->claim: the git/refs creation claims a ref that ignores $cand.
    unbound_claim = union_sample.replace(
        'ref="refs/acct-claims/$cand"', 'ref="refs/acct-claims/$RESERVED_HANDLE"', 1)
    verdict_unbound = setup_account_union_verdict(
        setup_account_store_step_lines(unbound_claim))
    chk("setup-account union: claim ref ignores cand -> refuse, severed claim named",
        (verdict_unbound[0], "severed from the union-derived candidate" in verdict_unbound[1]),
        (False, True))
    # sol round-19 mutation (finding 4, COMMENT-AS-EVIDENCE): the real "$env_secret_nums"
    # argument is replaced by "" with the variable name parked in an inline comment — the raw
    # text still CONTAINS the string, but the union no longer receives the listing. The
    # quote-aware comment strip must run before the participation match.
    comment_arg = union_sample.replace(
        ' "$env_secret_nums" \\', ' "" # "$env_secret_nums"', 1)
    verdict_comment = setup_account_union_verdict(
        setup_account_store_step_lines(comment_arg))
    chk("setup-account union: sol round-19 mutation (arg -> \"\" + comment) -> refuse, DEAD "
        "listing named (comments are stripped before matching)",
        (verdict_comment[0], "$env_secret_nums" in verdict_comment[1],
         "does not flow into" in verdict_comment[1]),
        (False, True, True))
    # Same stripping on the DETERMINATION chain: `n=$reserved # "$taken"` must not let comment
    # prose stand in for the taken -> n dependency edge.
    slot_comment = list(store_step_sample)
    slot_comment[10:12] = ['          n=$reserved # "$taken"']
    verdict_slot_comment = setup_account_union_verdict(
        setup_account_store_step_lines("\n".join(slot_comment)))
    chk("setup-account union: n=$reserved with \"$taken\" only in a comment -> refuse "
        "(the chain match also strips comments first)",
        (verdict_slot_comment[0],
         "does not reference the `taken` union" in verdict_slot_comment[1]),
        (False, True))
    chk("setup-account union: missing store step -> refuse (fail closed)",
        setup_account_union_verdict(setup_account_store_step_lines("jobs:\n  login:\n"))[0],
        False)
    no_claim = "\n".join(line for line in store_step_sample if "/git/refs\"" not in line)
    chk("setup-account union: missing claim mutation -> refuse (cannot prove ordering, fail closed)",
        setup_account_union_verdict(setup_account_store_step_lines(no_claim))[0], False)
    no_union = "\n".join(line for line in store_step_sample if "taken=$(" not in line)
    chk("setup-account union: missing taken construction -> refuse (cannot prove participation, fail closed)",
        setup_account_union_verdict(setup_account_store_step_lines(no_union))[0], False)
    no_slot = list(store_step_sample)
    del no_slot[10:12]  # both lines of the n= computation
    chk("setup-account union: missing slot computation -> refuse (cannot prove determination, fail closed)",
        setup_account_union_verdict(setup_account_store_step_lines("\n".join(no_slot)))[0],
        False)
    no_cand = "\n".join(line for line in store_step_sample
                        if not line.lstrip().startswith("cand="))
    chk("setup-account union: missing candidate construction -> refuse (cannot prove determination, fail closed)",
        setup_account_union_verdict(setup_account_store_step_lines(no_cand))[0], False)
    setup_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              os.pardir, ".github", "workflows", "set-up-account.yml")
    try:
        with open(setup_path, encoding="utf-8") as handle:
            live_union_verdict = setup_account_union_verdict(
                setup_account_store_step_lines(handle.read()))
    except OSError:
        live_union_verdict = (False, "set-up-account.yml unreadable (fail closed)")
    chk("workflow: set-up-account pre-claim union enumerates BOTH secret scopes + claims + issues, "
        "all paginated, all BEFORE the claim, all flowing into taken, taken determining the "
        "claimed ref (taken -> n -> cand -> claim)",
        live_union_verdict, (True, "ok"))

    # BINDING-MAP CONTRACT (sol round 17 on the #275 PR): synthetic accept + every reject
    # direction, then the LIVE derivation over the real .github/workflows/ tree. The map is
    # DERIVED (any job whose body holds a secrets-context read must be dispatch-secrets-bound),
    # never hand-listed — only BINDING_EXCEPTIONS is hardcoded, and staleness there is itself
    # a refusal.
    bound_doc = "\n".join([
        "on: workflow_dispatch",
        "jobs:",
        "  worker:",
        "    runs-on: ubuntu-latest",
        "    environment: dispatch-secrets",
        "    steps:",
        "      - run: true",
        "        env:",
        "          CRED: ${{ secrets[steps.pick.outputs.secret_ref] }}",
        "          SALT: ${{ secrets.PROVENANCE_SALT }}",
        "  deploy:",
        "    environment:",
        "      name: dispatch-secrets",
        "    steps:",
        "      - run: echo ${{ secrets.ACCT01_TOKEN != '' }}",
        "  lint:",  # consumes nothing: comment mentions + jq API listings demand no binding
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      # a comment quoting ${{ secrets.ACCT01_TOKEN }} demands nothing",
        "      - run: gh api repos/o/r/actions/secrets --jq '.secrets[].name'",
    ])
    chk("binding map: bound consumers (inline + mapping-form env) + non-consuming job -> ok",
        binding_map_verdict({"worker.yml": bound_doc}), (True, "ok"))
    unbound = binding_map_verdict(
        {"worker.yml": bound_doc.replace("    environment: dispatch-secrets\n", "")})
    chk("binding map: environment stripped from the worker job -> refuse, file::job NAMED",
        (unbound[0], "worker.yml::worker" in unbound[1],
         "no job-level `environment: dispatch-secrets`" in unbound[1]),
        (False, True, True))
    rebound = binding_map_verdict(
        {"worker.yml": bound_doc.replace(
            "    environment: dispatch-secrets", "    environment: github-pages")})
    chk("binding map: consumer bound to the WRONG environment -> refuse, binding named",
        (rebound[0], "'github-pages'" in rebound[1]), (False, True))
    # Round 18 (sol finding 2): GitHub resolves secret names CASE-INSENSITIVELY and evaluates
    # expressions only AFTER YAML folding — a lowercase reference and a folded multiline
    # expression are both REAL reads that must demand the binding exactly like the canonical
    # single-line uppercase spelling.
    lowercase_doc = "\n".join([
        "on: workflow_dispatch",
        "jobs:",
        "  drift:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - run: deploy",
        "        env:",
        "          CRED: ${{ secrets.acct02_token }}",
    ])
    lowercase = binding_map_verdict({"worker.yml": bound_doc, "drift.yml": lowercase_doc})
    chk("binding map: LOWERCASE secret reference in an unbound job -> refuse, file::job and "
        "canonical NAME surfaced (GitHub resolves names case-insensitively)",
        (lowercase[0], "drift.yml::drift" in lowercase[1],
         "secrets.ACCT02_TOKEN" in lowercase[1]),
        (False, True, True))
    folded_doc = "\n".join([
        "on: workflow_dispatch",
        "jobs:",
        "  folded:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - run: >-",
        '          echo "${{',
        '          secrets.ACCT03_TOKEN }}" > /tmp/out',
    ])
    folded = binding_map_verdict({"worker.yml": bound_doc, "folded.yml": folded_doc})
    chk("binding map: FOLDED multiline expression in an unbound job -> refuse (YAML folds the "
        "scalar into one line before GitHub evaluates it; the scan must too)",
        (folded[0], "folded.yml::folded" in folded[1],
         "secrets.ACCT03_TOKEN" in folded[1]),
        (False, True, True))
    folded_bound = binding_map_verdict(
        {"worker.yml": bound_doc,
         "folded.yml": folded_doc.replace(
             "    runs-on: ubuntu-latest",
             "    runs-on: ubuntu-latest\n    environment: dispatch-secrets")})
    chk("binding map: the same folded read WITH the binding -> ok (accept direction)",
        folded_bound, (True, "ok"))
    guard_doc = "\n".join([
        "jobs:",
        "  secrets-guard:",
        "    steps:",
        "      - run: true",
        "        env:",
        "          ALL_SECRETS: ${{ toJSON(secrets) }}",
    ])
    chk("binding map: dispatch.yml secrets-guard consumes toJSON(secrets) UNBOUND -> exception "
        "honored (its unbound read IS the empty-scope check)",
        binding_map_verdict({"dispatch.yml": guard_doc, "worker.yml": bound_doc}),
        (True, "ok"))
    ghost = binding_map_verdict(
        {"other.yml": guard_doc, "worker.yml": bound_doc})
    chk("binding map: same UNBOUND toJSON(secrets) job in a NON-excepted file -> refuse",
        (ghost[0], "other.yml::secrets-guard" in ghost[1]), (False, True))
    bound_guard = binding_map_verdict(
        {"dispatch.yml": guard_doc.replace(
            "    steps:", "    environment: dispatch-secrets\n    steps:"),
         "worker.yml": bound_doc})
    chk("binding map: exception job now BOUND -> refuse as STALE (remove the dead allowlist entry)",
        (bound_guard[0], "STALE" in bound_guard[1]), (False, True))
    # Round 19 (sol finding 1): an exception bound to ANY OTHER environment must refuse too —
    # environment secrets OVERRIDE same-named repo secrets, so `environment: other-secret-env`
    # on a migration job injects that environment's stale copies while the old
    # only-reject-dispatch-secrets check stayed green.
    otherenv = binding_map_verdict(
        {"dispatch.yml": guard_doc.replace(
            "    steps:", "    environment: other-secret-env\n    steps:"),
         "worker.yml": bound_doc})
    chk("binding map: exception job bound to ANY OTHER environment -> refuse (round 19: env "
        "secrets override same-named repo secrets — stale-value injection)",
        (otherenv[0], "'other-secret-env'" in otherenv[1], "OVERRIDE" in otherenv[1]),
        (False, True, True))
    stale_exc = binding_map_verdict(
        {"dispatch.yml": "jobs:\n  plan:\n    steps:\n      - run: true",
         "worker.yml": bound_doc})
    chk("binding map: exception file present but its job consumes nothing -> refuse as STALE",
        (stale_exc[0], "STALE" in stale_exc[1],
         "dispatch.yml::secrets-guard" in stale_exc[1]), (False, True, True))
    chk("binding map: no documents -> refuse (fail closed)",
        binding_map_verdict({})[0], False)
    chk("binding map: zero derived consumers -> refuse (a scan that proves nothing fails closed)",
        binding_map_verdict(
            {"a.yml": "jobs:\n  lint:\n    steps:\n      - run: true"})[0], False)
    chk("binding map: unparseable jobs block -> refuse, file named",
        (binding_map_verdict({"a.yml": "name: no jobs key here"})[0],
         "a.yml" in binding_map_verdict({"a.yml": "name: no jobs key here"})[1]),
        (False, True))
    workflows_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 os.pardir, ".github", "workflows")
    try:
        live_docs = {}
        for name in sorted(os.listdir(workflows_dir)):
            if name.endswith((".yml", ".yaml")):
                with open(os.path.join(workflows_dir, name), encoding="utf-8") as handle:
                    live_docs[name] = handle.read()
    except OSError:
        live_docs = {}
    chk("workflow: EVERY secret-consuming job repo-wide carries `environment: dispatch-secrets` "
        "(exceptions: dispatch's guard job + the two unbound one-shot migration phases)",
        binding_map_verdict(live_docs), (True, "ok"))
    live_consumers = secret_consuming_jobs(live_docs) or {}
    chk("workflow: the LIVE derivation still sees the known consumers + every exception "
        "(parser-rot anchor: a scan that finds fewer jobs is rot, not safety)",
        (("worker.yml", "worker") in live_consumers,
         ("review-fix.yml", "run") in live_consumers,
         ("dispatch.yml", "claim") in live_consumers,
         all(key in live_consumers for key in BINDING_EXCEPTIONS)),
        (True, True, True, True))

    privileged_fixture = {
        "privileged.yml": "\n".join([
            "jobs:",
            "  writer:",
            "    permissions:",
            "      contents: write",
            "    steps:",
            "      - run: python3 scripts/ledger-writer.py",
            "  probe:",
            "    steps:",
            "      - run: bash scripts/probe.sh",
            "        env:",
            "          TOKEN: ${{ secrets.ACCT01_TOKEN }}",
        ])
    }
    chk("privileged-script coverage: scripts/ prefix covers secret readers and writers",
        privileged_script_coverage_verdict(privileged_fixture, ("scripts/",)), (True, "ok"))
    uncovered = privileged_script_coverage_verdict(privileged_fixture,
                                                    ("scripts/ledger-writer.py",))
    chk("privileged-script coverage: uncovered secret probe fails closed",
        (uncovered[0], "scripts/probe.sh" in uncovered[1]), (False, True))
    chk("privileged-script coverage: zero derived inventory fails closed",
        privileged_script_coverage_verdict(
            {"plain.yml": "jobs:\n  lint:\n    steps:\n      - run: python3 scripts/lint.py"},
            ("scripts/",))[0], False)
    # Issue #618 defect 2: an EMPTY surface is a DERIVATION failure, and it must say so instead of
    # emitting a list of "uncovered" scripts that reads as a policy finding.
    empty_surface = privileged_script_coverage_verdict(privileged_fixture, ())
    chk("privileged-script coverage: an EMPTY surface names the DERIVATION, not the scripts",
        (empty_surface[0], "DERIVATION failure" in empty_surface[1],
         "scripts/probe.sh" in empty_surface[1]),
        (False, True, False))

    # ---- issue #554: a TRANSIENT source read is retried, never mistaken for a coverage gap ------
    # The run at 05:27 emitted all 22 privileged scripts as "outside the human-arm trust surface"
    # one tick after the identical guard passed, on identical code — a covered-set READ that came
    # back unusable, graded as an exfil finding about every script in the repo. The refusal above
    # fixes the DIAGNOSIS; these fix the recurrence: the read gets a bounded retry before anything
    # is graded, and a spent budget re-raises rather than degrading to empty text.
    class _StubHandle:
        def __init__(self, text):
            self._text = text

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def read(self):
            return self._text

    def _stub_opener(failures, text="payload"):
        """An opener that raises OSError for its first `failures` calls, then serves `text`.
        `.calls` counts opens, `.naps` the backoffs — a retry that does not happen is countable."""
        state = {"calls": 0, "naps": []}

        def opener(_path, _mode, encoding=None):
            state["calls"] += 1
            if state["calls"] <= failures:
                raise OSError(5, "transient read blip")
            return _StubHandle(text)

        opener.state = state
        return opener

    flaky = _stub_opener(failures=1, text="recovered")
    try:
        recovered = read_source_with_retry("scripts/worker-pr.py", opener=flaky,
                                           sleeper=flaky.state["naps"].append)
    except OSError as error:
        # A budget that stopped retrying reports as ONE failing line, not a traceback that
        # log-scraped failure counts have to guess at (see chk's repr() note).
        recovered = f"gave up: {error}"
    chk("source read: ONE transient fault is retried and the read SUCCEEDS (the #554 tick)",
        (recovered, flaky.state["calls"], len(flaky.state["naps"])),
        ("recovered", 2, 1))
    doomed = _stub_opener(failures=99)
    try:
        read_source_with_retry("scripts/worker-pr.py", opener=doomed,
                               sleeper=doomed.state["naps"].append)
        raised = "no-raise"
    except OSError as error:
        raised = str(error.errno)
    chk("source read: the retry is BOUNDED and re-raises — it never degrades to empty text, "
        "which is what marks every privileged script uncovered",
        (raised, doomed.state["calls"], len(doomed.state["naps"])),
        ("5", SOURCE_READ_ATTEMPTS, SOURCE_READ_ATTEMPTS - 1))
    chk("source read: the live budget is a RETRY budget (>1 attempt) with a real backoff",
        (SOURCE_READ_ATTEMPTS > 1, SOURCE_READ_BACKOFF_SECONDS > 0), (True, True))
    try:
        read_source_with_retry("x", attempts=0, opener=_stub_opener(0))
        zero_budget = "no-raise"
    except ValueError:
        zero_budget = "raised"
    except OSError:
        zero_budget = "os-error"
    chk("source read: a ZERO attempt budget is refused, not silently read-nothing",
        zero_budget, "raised")

    # The WIRE: the derivation must go through the retrying reader, and a source that stays
    # unreadable must come back as EMPTY surfaces PLUS a named error — the input the refusal above
    # consumes. A reader swapped back to a bare single-shot `open` flips the first of these red.
    chk("trust surface: the derivation reads its sources through the RETRYING reader",
        derive_trust_surfaces.__defaults__, (read_source_with_retry,))

    def _dead_reader(_path):
        # errno 5 (EIO), not 2: a read that stays broken past the retry budget, which is the shape
        # the guard job saw. (ENOENT would arrive as FileNotFoundError and hide the class.)
        raise OSError(5, "transient read blip")

    dead = derive_trust_surfaces("/nonexistent-repo-root", reader=_dead_reader)
    dead_verdict = privileged_script_coverage_verdict(privileged_fixture, dead[0])
    chk("trust surface: an unreadable source yields EMPTY surfaces + a NAMED read error, and the "
        "coverage verdict then names the DERIVATION instead of listing every script (#554)",
        (dead[0], dead[1], dead[2] is not None, "OSError" in (dead[2] or ""),
         dead_verdict[0], "DERIVATION failure" in dead_verdict[1],
         "scripts/probe.sh" in dead_verdict[1]),
        ((), (), True, True, False, True, False))

    def _blank_reader(path):
        # An empty-but-successful read: the transient blip's other shape. It must NOT resolve to a
        # usable surface — `ast.parse("")` finds no constant, so the derivation refuses.
        return "" if path.endswith("worker-pr.py") else "unused"

    blank = derive_trust_surfaces("/nonexistent-repo-root", reader=_blank_reader)
    chk("trust surface: an EMPTY-but-successful source read refuses too (an empty covered set is "
        "a read failure, never a coverage verdict)",
        (blank[0], blank[1], blank[2] is not None), ((), (), True))

    # The human-arm trust surface, derived from the TWO live sources (issue #166: the policy list
    # is a per-target EXTENSION unioned onto worker-pr.py's mandatory floor). #528 wrapped this in
    # a broad `except (OSError, KeyError, TypeError, AttributeError, ImportError)` that fell back
    # to EMPTY tuples — so on the guard job's sparse checkout, where neither file is present, both
    # assertions below turned into a 22-script "outside the trust surface" verdict rather than a
    # readable "these inputs are missing". The failure reason is now CAPTURED and asserted on its
    # own, so a derivation fault can never again be mistaken for a policy gap.
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    default_surfaces, policy_surfaces, derivation_error = derive_trust_surfaces(repo_root)
    chk("trust surface: BOTH live sources (worker-pr.py DEFAULT_TRUST_SURFACE_PATHS + "
        "policy/repos.toml security_paths) are readable here — a derivation fault must name "
        "ITSELF, never surface as a 22-script policy finding (issue #618)",
        derivation_error, None)
    chk("workflow: every script run with secrets or write permission is covered by the "
        "worker-pr mandatory human-arm floor",
        privileged_script_coverage_verdict(live_docs, default_surfaces), (True, "ok"))
    chk("workflow: every script run with secrets or write permission is covered by the registry "
        "policy human-arm surface",
        privileged_script_coverage_verdict(live_docs, policy_surfaces), (True, "ok"))

    # ---- NO CREDENTIAL ON A COMMAND LINE (issue #417) ------------------------------------------
    # The pre-#417 shape is written out BY HAND here, never derived from CREDENTIAL_HEADER_RE: an
    # input built from the same constant the code reads cannot fail (AGENTS.md pre-flight 2c). It
    # reproduces the real fingerprint-accounts.yml/account-whoami.yml shape — the curl lives inside
    # a `VAR=$(…)` command substitution, which is exactly the shape a command-name-keyed scan
    # cannot see, so this fixture is also the reject direction for that design choice.
    argv_leak_run = 'code=$(curl -s -H "Authorization: Bearer $TOK" https://api.example/x)'
    argv_clean_run = ("code=$(printf 'Authorization: Bearer %s\\n' \"$TOK\" "
                      "| curl -s -H @- https://api.example/x)")

    def argv_doc(run_line):
        return "\n".join([
            "jobs:",
            "  probe:",
            "    steps:",
            "      - run: |",
            "          " + run_line,
            "        env:",
            "          TOK: ${{ secrets.ACCT02_TOKEN }}",
        ])

    chk("argv credential: the STDIN header form (`-H @-`) is accepted",
        credential_argv_verdict({"probe.yml": argv_doc(argv_clean_run)}), (True, "ok"))
    leak = credential_argv_verdict({"probe.yml": argv_doc(argv_leak_run)})
    chk("argv credential: `-H \"Authorization: …\"` inside a `VAR=$(curl …)` substitution is "
        "REFUSED, naming the job and the header — and NEVER echoing the value (the reason is "
        "printed into a PUBLIC Actions log)",
        (leak[0], "probe.yml::probe" in leak[1], "authorization:" in leak[1].lower(),
         "TOK" in leak[1], "Bearer" in leak[1]),
        (False, True, True, False, False))
    # Each alternate-form fixture also carries a HARMLESS header argument, so the scan observes
    # something even when the form under test stops being read. Without it, deleting that form's
    # branch merely empties the scan, the zero-observation refusal returns False anyway, and a
    # `[0] == False` row passes for the wrong reason — both of these mutants SURVIVED until the
    # REASON was asserted too (AGENTS.md pre-flight 2b).
    joined = credential_argv_verdict({"probe.yml": argv_doc(
        'curl -s -H "Accept: application/json" -H"Authorization: Bearer $TOK" https://x/y')})
    chk("argv credential: the JOINED short form `-H<value>` is refused AS A LEAK (a reader that "
        "only understands `-H <value>` is bypassed by deleting one space)",
        (joined[0], "probe.yml::probe" in joined[1], "authorization:" in joined[1].lower()),
        (False, True, True))
    long_form = credential_argv_verdict({"probe.yml": argv_doc(
        'curl -s -H "Accept: application/json" --header="Authorization: Bearer $TOK" https://x/y')})
    chk("argv credential: the long `--header=<value>` form is refused AS A LEAK too",
        (long_form[0], "probe.yml::probe" in long_form[1], "authorization:" in long_form[1].lower()),
        (False, True, True))
    # HTTP header names are case-insensitive, and `Proxy-Authorization` carries a credential just as
    # `Authorization` does. Both spellings must land as leaks, or the rule is one lowercase letter
    # away from being bypassed by a workflow that never intended to bypass anything.
    lower = credential_argv_verdict({"probe.yml": argv_doc(
        'curl -s -H "authorization: Bearer $TOK" https://x/y')})
    proxy = credential_argv_verdict({"probe.yml": argv_doc(
        'curl -s -H "Proxy-Authorization: Basic $TOK" https://x/y')})
    chk("argv credential: the lowercase `authorization:` spelling and `Proxy-Authorization:` are "
        "leaks too",
        (lower[0], "probe.yml::probe" in lower[1],
         proxy[0], "proxy-authorization" in proxy[1].lower()),
        (False, True, False, True))
    # The READER itself, exact-match on the extracted values — a reader that silently returns ()
    # would make every accept above pass for the wrong reason.
    chk("argv credential reader: the fix's own shape yields ONLY the stdin marker; the printf "
        "words (a shell BUILTIN, no argv) are not header arguments",
        command_line_header_values(argv_clean_run), ("@-",))
    chk("argv credential reader: a header flag never spans an operator, and a bare header word "
        "with no flag is not an argument",
        command_line_header_values("curl -H\ncurl 'Authorization: Bearer x'"), ())
    chk("argv credential reader: the leak shape extracts the header VALUE (so the refusal above "
        "is about this value, not about the word `curl`)",
        command_line_header_values(argv_leak_run), ("Authorization: Bearer $TOK",))
    chk("argv credential: ZERO header arguments repo-wide -> refuse (a scan that observed "
        "nothing proves nothing)",
        credential_argv_verdict({"probe.yml": argv_doc("curl -s https://api.example/x")})[0],
        False)
    chk("argv credential: an unparseable jobs block -> refuse, file named",
        (credential_argv_verdict({"a.yml": "name: no jobs key here"})[0],
         "a.yml" in credential_argv_verdict({"a.yml": "name: no jobs key here"})[1]),
        (False, True))
    # LIVE. This row is what goes RED if any workflow reverts to a credential on the command line.
    chk("workflow: NO job in ANY workflow passes an Authorization header as a command-line "
        "argument (issue #417; #195 fixed the same class in scripts/account-usage.py)",
        credential_argv_verdict(live_docs), (True, "ok"))
    # …and the parser-rot anchor: the live scan must still SEE each of the three #417 credential
    # probes handing curl its bearer header OUT-OF-BAND — `@-` (stdin) or `@path` (a mode-0600
    # file), the two remediations #417 allows. Without this, the row above would also pass on a
    # scan that had stopped finding these files' header arguments at all.
    live_indirect_headers = {}
    for name in ("account-whoami.yml", "fingerprint-accounts.yml", "verify-app.yml"):
        jobs = workflow_jobs(live_docs.get(name, "")) or {}
        live_indirect_headers[name] = sorted(
            value for body in jobs.values()
            for value in command_line_header_values("\n".join(body)) if value.startswith("@"))
    chk("workflow: each #417 credential probe still hands curl its bearer header out-of-band "
        "(`-H @-` / `-H @file`), so the repo-wide row above is not passing on an empty scan",
        {name: bool(values) for name, values in sorted(live_indirect_headers.items())},
        {"account-whoami.yml": True, "fingerprint-accounts.yml": True, "verify-app.yml": True})

    # ---- the GATE: a FAILING guard must PREVENT the privileged jobs from running (issue #618) --
    # The pre-existing suite passed in full while the control was fail-OPEN, so every assertion
    # here is on dispatch.yml's WIRING. Synthetic accept + reject directions first, then LIVE.
    guard_run_block = "\n".join([
        "      - run: |",
        "          python3 scripts/dispatch-secrets-guard.py --self-test",
        "          python3 scripts/dispatch-secrets-guard.py",
    ])
    gate_ok_sample = "\n".join([
        "jobs:",
        "  plan:",
        "    runs-on: ubuntu-latest",
        "  secrets-guard:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        guard_run_block,
        "        env:",
        "          ALL_SECRETS: ${{ toJSON(secrets) }}",
        "  claim:",
        "    needs: [plan, secrets-guard]",
        "    environment: dispatch-secrets",
        "    steps:",
        "      - run: true",
        "        env:",
        "          TOKEN: ${{ secrets.ALERT_TOKEN }}",
        "  plan-alert:",
        "    needs: [plan, secrets-guard]",
        "    if: ${{ always() && needs.secrets-guard.result == 'success' }}",
        "    environment: dispatch-secrets",
        "    steps:",
        "      - run: true",
        "        env:",
        "          TOKEN: ${{ secrets.ALERT_TOKEN }}",
    ])
    chk("GATE: plain `needs` on a guard with no continue-on-error, plus an always()-job that "
        "re-states the success condition -> ok",
        guard_gate_verdict(gate_ok_sample), (True, "ok"))
    # THE defect, exactly as it shipped: the guard job is continue-on-error, so its failure
    # resolves as SUCCESS for dependents and BOTH downstream idioms pass anyway.
    gate_coe = gate_ok_sample.replace(
        "  secrets-guard:\n    runs-on:", "  secrets-guard:\n    continue-on-error: true\n"
        "    runs-on:")
    verdict_coe = guard_gate_verdict(gate_coe)
    chk("GATE: job-level `continue-on-error: true` on the guard -> REFUSE (the shipped fail-open "
        "defect; a success-conditioned downstream expression does NOT rescue it)",
        (verdict_coe[0], "continue-on-error" in verdict_coe[1]), (False, True))
    chk("GATE: `continue-on-error: ${{ ... }}` on the guard -> REFUSE (an expression cannot be "
        "statically proven false, so it counts as an escape)",
        guard_gate_verdict(gate_ok_sample.replace(
            "  secrets-guard:\n    runs-on:",
            "  secrets-guard:\n    continue-on-error: ${{ github.event_name == 'schedule' }}\n"
            "    runs-on:"))[0], False)
    chk("GATE: `continue-on-error: false` on the guard -> still ok (explicitly not an escape)",
        guard_gate_verdict(gate_ok_sample.replace(
            "  secrets-guard:\n    runs-on:",
            "  secrets-guard:\n    continue-on-error: false\n    runs-on:")), (True, "ok"))
    chk("GATE: STEP-level continue-on-error inside the guard -> REFUSE (the verification step "
        "goes red while the job reports green)",
        guard_gate_verdict(gate_ok_sample.replace(
            "        env:\n          ALL_SECRETS:",
            "        continue-on-error: true\n        env:\n          ALL_SECRETS:"))[0], False)
    chk("GATE: a comment mentioning continue-on-error is not one",
        guard_gate_verdict(gate_ok_sample.replace(
            "  secrets-guard:\n", "  secrets-guard:\n    # NO continue-on-error: true here\n")),
        (True, "ok"))
    verdict_unneeded = guard_gate_verdict(
        gate_ok_sample.replace("  claim:\n    needs: [plan, secrets-guard]", "  claim:\n"
                               "    needs: [plan]"))
    chk("GATE: privileged `claim` without `needs: secrets-guard` -> REFUSE, job NAMED",
        (verdict_unneeded[0], "claim" in verdict_unneeded[1]), (False, True))
    chk("GATE: block-sequence `needs:` form is understood (no false refusal)",
        guard_gate_verdict(gate_ok_sample.replace(
            "  claim:\n    needs: [plan, secrets-guard]",
            "  claim:\n    needs:\n      - plan\n      - secrets-guard")), (True, "ok"))
    chk("GATE: an `if: always()` job that drops the success condition -> REFUSE (always() "
        "overrides the implicit needs-must-succeed gate)",
        guard_gate_verdict(gate_ok_sample.replace(
            "    if: ${{ always() && needs.secrets-guard.result == 'success' }}",
            "    if: ${{ always() }}"))[0], False)
    chk("GATE: guard job deleted outright -> REFUSE (the check is GONE, not merely ungated)",
        guard_gate_verdict("\n".join([
            "jobs:",
            "  claim:",
            "    steps:",
            "      - run: true",
            "        env:",
            "          TOKEN: ${{ secrets.ALERT_TOKEN }}"]))[0], False)
    chk("GATE: zero derived secret consumers -> REFUSE (a gate check that proves nothing)",
        guard_gate_verdict("\n".join([
            "jobs:",
            "  secrets-guard:",
            "    steps:",
            guard_run_block,
            "        env:",
            "          ALL_SECRETS: ${{ toJSON(secrets) }}"]))[0], False)
    chk("GATE: unparseable jobs block -> REFUSE",
        guard_gate_verdict("name: no jobs key here")[0], False)

    # ---- RETRO-REVIEW OF #621, MUTATION (a): the guard job must RUN THE VERIFIER ----------------
    # Replacing both `python3 registry/scripts/dispatch-secrets-guard.py` invocations in dispatch.yml
    # with `true` left the ENTIRE enrolled suite green — every property above is satisfied by an
    # EMPTY job of the right name. These are the assertions that make that mutation a red tick.
    verdict_stub = guard_gate_verdict(gate_ok_sample.replace(
        guard_run_block, "      - run: |\n          true\n          true"))
    chk("GATE: the guard job runs `true` instead of the verifier -> REFUSE (#621 mutation (a): "
        "gated, green, and verifying NOTHING)",
        (verdict_stub[0], "VERIFIES NOTHING" in verdict_stub[1]), (False, True))
    verdict_no_selftest = guard_gate_verdict(gate_ok_sample.replace(
        "          python3 scripts/dispatch-secrets-guard.py --self-test\n", ""))
    chk("GATE: the guard drops the `--self-test` invocation -> REFUSE (the static workflow-shape "
        "assertions, this contract included, would stop running on every tick)",
        (verdict_no_selftest[0], "--self-test" in verdict_no_selftest[1]), (False, True))
    verdict_no_verify = guard_gate_verdict(gate_ok_sample.replace(
        "          python3 scripts/dispatch-secrets-guard.py\n", "\n"))
    chk("GATE: the guard drops the LIVE settings verification -> REFUSE (only the self-test would "
        "run, so the repo-settings check the job exists for is gone)",
        verdict_no_verify[0], False)
    chk("GATE: an `if:`-conditional verifier step -> REFUSE (a skipped step still resolves the job "
        "as SUCCESS for every dependent — the same fail-open shape as continue-on-error)",
        guard_gate_verdict(gate_ok_sample.replace(
            "        env:\n          ALL_SECRETS:",
            "        if: ${{ github.event_name == 'schedule' }}\n"
            "        env:\n          ALL_SECRETS:"))[0], False)
    chk("GATE: the `registry/` sparse-checkout path prefix the LIVE job uses is recognised",
        guard_gate_verdict(gate_ok_sample.replace(
            "python3 scripts/dispatch-secrets-guard.py",
            "python3 registry/scripts/dispatch-secrets-guard.py")), (True, "ok"))

    # ---- POST-MERGE RETRO-REVIEW OF #629, F2: TEXTUAL PRESENCE IS NOT EXECUTION -----------------
    # `GATE_VERIFIER_RE`'s left context `(?:^|[;&|]\s*|\s)` was satisfied by a `#` comment, a
    # `true ||` short-circuit and a here-doc body. MEASURED on the merged tree: a guard job whose ONLY
    # verifier invocations were `# python3 …` returned `guard_gate_verdict ok=True`, and so did one
    # whose only invocations were `true || python3 …`. The commented-out shape is a PLAUSIBLE ACCIDENT
    # (comment an invocation out while debugging; nothing goes red). Each mutation below is applied to
    # the SAME fixture whose honest form passes above, so these reds are the guard firing.
    for label, mutate in (
            ("COMMENTED OUT",
             lambda body: "\n".join("          # " + line.strip() if line.strip().startswith("python3")
                                    else line for line in body.split("\n"))),
            ("SHORT-CIRCUITED behind `true ||`",
             lambda body: body.replace("          python3", "          true || python3")),
            ("SHORT-CIRCUITED behind `false &&`",
             lambda body: body.replace("          python3", "          false && python3")),
            ("inside a HERE-DOC body",
             lambda body: body.replace(
                 "      - run: |\n", "      - run: |\n          cat <<'SH' > /dev/null\n")
             + "\n          SH"),
            ("inside an `if` construct",
             lambda body: body.replace(
                 "      - run: |\n", "      - run: |\n          if [ -n \"${DEBUG:-}\" ]; then\n")
             + "\n          fi"),
            ("quoted as an argument to `echo`",
             lambda body: body.replace("          python3", "          echo python3"))):
        mutant = guard_gate_verdict(gate_ok_sample.replace(guard_run_block, mutate(guard_run_block)))
        chk(f"GATE (F2): the guard's verifier invocations are {label} -> REFUSE (the job is gated, "
            "green, and VERIFIES NOTHING; the text of a command is not its execution)",
            (gate_ok_sample.replace(guard_run_block, mutate(guard_run_block)) != gate_ok_sample,
             mutant[0], "VERIFIES NOTHING" in mutant[1]),
            (True, False, True))
    commented_guard = {"steps": [{"run": "# python3 scripts/dispatch-secrets-guard.py --self-test\n"
                                        "# python3 scripts/dispatch-secrets-guard.py\n"}]}
    chk("GATE (F2): guard_verifier_invocations reports a commented-out invocation as UNREACHABLE, "
        "never as an invocation", guard_verifier_invocations(commented_guard),
        ((), (), (), (0,)))
    chk("GATE (F2): ...and the honest form is reported as reachable",
        guard_verifier_invocations(
            {"steps": [{"run": "set -euo pipefail\n"
                               "python3 registry/scripts/dispatch-secrets-guard.py --self-test\n"
                               "python3 registry/scripts/dispatch-secrets-guard.py\n"}]}),
        ((0,), (0,), (), ()))
    # The shell reachability primitive, directly — the parse that replaced the left-context regex.
    for body, expected, label in (
            ("python3 scripts/dispatch-secrets-guard.py --self-test", (("--self-test",), ()),
             "a plain line RUNS"),
            ("set -e; python3 scripts/dispatch-secrets-guard.py --self-test", (("--self-test",), ()),
             "a `;`-separated command RUNS"),
            ("# python3 scripts/dispatch-secrets-guard.py --self-test", ((), ()),
             "a full-line comment is not a command at all"),
            ("true # python3 scripts/dispatch-secrets-guard.py --self-test", ((), ()),
             "a trailing comment is not a command"),
            ("true || python3 scripts/dispatch-secrets-guard.py --self-test",
             ((), ("--self-test",)), "a `||` right-hand side is UNREACHABLE"),
            ("false && python3 scripts/dispatch-secrets-guard.py --self-test",
             ((), ("--self-test",)), "an `&&` right-hand side is UNREACHABLE"),
            ("if true; then python3 scripts/dispatch-secrets-guard.py --self-test; fi",
             ((), ("--self-test",)), "an `if` body is UNREACHABLE"),
            ("cat <<'SH'\npython3 scripts/dispatch-secrets-guard.py --self-test\nSH",
             ((), ()), "a here-doc BODY is data, not commands"),
            ("echo python3 scripts/dispatch-secrets-guard.py", ((), ()),
             "an argument to another command is not an invocation"),
            ('echo "python3 scripts/dispatch-secrets-guard.py --self-test"', ((), ()),
             "a quoted string is not an invocation"),
            ("true || python3 scripts/dispatch-secrets-guard.py --self-test\n"
             "python3 scripts/dispatch-secrets-guard.py --self-test",
             (("--self-test",), ("--self-test",)),
             "a short-circuit does not poison the NEXT line"),
            ("VAR=1 python3 scripts/dispatch-secrets-guard.py --self-test", (("--self-test",), ()),
             "a leading env assignment still leaves the command in command position")):
        chk(f"shell reachability: {label}",
            shell_script_invocations(body, "python3", GATE_VERIFIER_SCRIPT_RE), expected)

    # ---- RETRO-REVIEW OF #621, MUTATION (b): the success condition's POLARITY -------------------
    # Flipping `always() && needs.secrets-guard.result == 'success'` to `||` at dispatch.yml:1227
    # left the suite green — the old check was a SUBSTRING search, and the comparison is still
    # present in the `||` form. The gate was inverted and "GATE (LIVE)" still passed.
    verdict_or = guard_gate_verdict(gate_ok_sample.replace(
        "    if: ${{ always() && needs.secrets-guard.result == 'success' }}",
        "    if: ${{ always() || needs.secrets-guard.result == 'success' }}"))
    chk("GATE: `always() || needs.secrets-guard.result == 'success'` -> REFUSE (#621 mutation (b): "
        "the comparison is PRESENT and the gate is INVERTED)",
        (verdict_or[0], "can evaluate TRUE" in verdict_or[1]), (False, True))
    # The polarity evaluator, directly, over the shapes that matter. Accept only what a failed
    # guard makes false.
    for condition, admits in (
            ("${{ always() && needs.secrets-guard.result == 'success' }}", False),
            ("${{ needs.secrets-guard.result == 'success' && always() }}", False),
            ("${{ always() && needs.secrets-guard.result=='success' }}", False),
            ("${{ always() && needs . secrets-guard . result == \"success\" }}", False),
            # a disjunction is admitted only when EVERY branch requires the guard
            ("${{ (github.event_name == 'schedule' || github.event_name == 'push') && "
             "needs.secrets-guard.result == 'success' }}", False),
            ("${{ always() || needs.secrets-guard.result == 'success' }}", True),
            ("${{ needs.secrets-guard.result == 'success' || always() }}", True),
            ("${{ always() }}", True),
            ("${{ !cancelled() }}", True),
            ("${{ needs.secrets-guard.result != 'success' }}", True),
            ("${{ always() && needs.plan.result == 'success' }}", True),
            # negation of the requirement is not the requirement
            ("${{ always() && !(needs.secrets-guard.result == 'success') }}", True)):
        chk(f"if-polarity: {condition} admits a FAILED guard",
            if_condition_admits(condition, GATE_SUCCESS_RE)[0], admits)
    chk("if-polarity: an unparseable expression reports parsed=False and ADMITS (the gate "
        "direction fails closed — an unreadable gate is not a proven gate)",
        if_condition_admits("${{ always() && ( }}", GATE_SUCCESS_RE)[:2], (True, False))
    chk("if-polarity: a literal/expression mix cannot be evaluated statically",
        if_condition_admits("ref-${{ always() }}", GATE_SUCCESS_RE)[:2], (True, False))
    chk("if-polarity: a bare (unwrapped) expression is evaluated too",
        if_condition_admits("always() && needs.secrets-guard.result == 'success'",
                            GATE_SUCCESS_RE)[0], False)

    # ---- POST-MERGE RETRO-REVIEW OF #629, F1: THE STRING-EMBEDDED BYPASS ------------------------
    # `_tokenize_if` absorbs a whole function call INCLUDING its quoted string arguments into one
    # opaque atom, and the atom used to be pinned FALSE whenever `false_atom_re` matched ANYWHERE in
    # that raw text. So MENTIONING the guard comparison inside a string literal pinned an ALWAYS-TRUE
    # call to FALSE, the conjunction became unsatisfiable, and `admits=False` was a proof about a
    # formula the workflow does not have. MEASURED end to end on the merged tree:
    #     honest gate -> True | the `||` inversion -> False | STRING-EMBEDDED bypass -> True
    # i.e. GitHub runs the privileged job on a FAILED guard while the gate contract reports ok. The
    # atom is now PARSED: only a real comparison can be pinned, so the call is a FREE atom, the
    # expression is satisfiable with the guard failed, and the gate REFUSES.
    string_bypass = ("${{ always() && contains('needs.secrets-guard.result == \"success\"', "
                     "'success') }}")
    chk("if-polarity (F1): a call whose STRING ARGUMENT mentions the guard comparison does NOT "
        "satisfy the gate — the argument is not a condition",
        if_condition_admits(string_bypass, GATE_SUCCESS_RE)[:2], (True, True))
    bypass_sample = gate_ok_sample.replace(
        "    if: ${{ always() && needs.secrets-guard.result == 'success' }}",
        "    if: " + string_bypass)
    verdict_bypass = guard_gate_verdict(bypass_sample)
    chk("GATE (F1): the string-embedded bypass -> REFUSE (GitHub evaluates always() and contains() "
        "both TRUE and runs the privileged job on a FAILED guard)",
        (bypass_sample != gate_ok_sample, verdict_bypass[0],
         "can evaluate TRUE" in verdict_bypass[1]),
        (True, False, True))
    # The same shape in every other place a string can hide the comparison.
    for hider in (
            "contains('needs.secrets-guard.result == \"success\"', 'success')",
            # GitHub escapes a single quote inside a single-quoted string by DOUBLING it
            "startsWith('needs.secrets-guard.result == ''success''', 'needs')",
            "format('{0}', 'needs.secrets-guard.result == \"success\"')",
            "contains(github.event.head_commit.message, "
            "'needs.secrets-guard.result == ''success''')"):
        chk(f"if-polarity (F1): `{hider}` is a FREE atom, never the guard requirement",
            if_condition_admits("${{ always() && " + hider + " }}", GATE_SUCCESS_RE)[:2],
            (True, True))
    # ...and the accept direction still holds, so the fix is not "refuse every call".
    chk("if-polarity (F1): a genuine comparison alongside an unrelated call still GATES",
        if_condition_admits(
            "${{ contains(github.ref, 'main') && needs.secrets-guard.result == 'success' }}",
            GATE_SUCCESS_RE)[:2], (False, True))
    # FAIL CLOSED on anything the grammar cannot fully decide: no atom is silently abstracted.
    for undecidable, why in (
            ("${{ always() && secrets[format('ACCT{0}_TOKEN', '01')] != '' }}", "index expression"),
            ("${{ always() && 1 + 1 == 2 }}", "arithmetic"),
            ("${{ always() && 'literal' }}", "a bare string used as a condition"),
            ("${{ always() && !needs.secrets-guard.result == 'success' }}",
             "`!` binds tighter than `==` in GitHub, so the two readings disagree"),
            ("${{ always() && needs.secrets-guard.result == 'success' == true }}",
             "a comparison chain")):
        decided = if_condition_admits(undecidable, GATE_SUCCESS_RE)
        chk(f"if-polarity (F1): {why} -> UNDECIDED and ADMITS (the gate fails CLOSED rather than "
            "reasoning over an atom it cannot parse)", decided[:2], (True, False))

    # ---- RETRO-REVIEW OF #621: the five PERMISSIVE MISPARSES of regex-over-YAML -----------------
    # Each of these was verified GREEN against the merged #621 file. All five are now parse events,
    # not pattern events: the value the assertion sees is the value GitHub sees.
    chk('misparse 1: `"continue-on-error": true` (QUOTED key) -> REFUSE',
        guard_gate_verdict(gate_ok_sample.replace(
            "  secrets-guard:\n    runs-on:",
            '  secrets-guard:\n    "continue-on-error": true\n    runs-on:'))[0], False)
    chk("misparse 2: `continue-on-error : true` (space BEFORE the colon) -> REFUSE",
        guard_gate_verdict(gate_ok_sample.replace(
            "  secrets-guard:\n    runs-on:",
            "  secrets-guard:\n    continue-on-error : true\n    runs-on:"))[0], False)
    chk('misparse 3: `"if": ${{ always() }}` (QUOTED key) -> REFUSE (the old anchored regex read '
        "this as NO `if:` at all, which SKIPPED the polarity check entirely)",
        guard_gate_verdict(gate_ok_sample.replace(
            "    if: ${{ always() && needs.secrets-guard.result == 'success' }}",
            '    "if": ${{ always() }}'))[0], False)
    # misparse 4 has TWO shapes, because the exact one the retro-review used is not even valid YAML.
    # A TAB before a comment is a YAML scanner error, so it now REFUSES naming the parse fault (it
    # used to satisfy the needs check: the old ` #` tail strip required a SPACE, so the tab-prefixed
    # `# secrets-guard` survived into `re.split(r"[\[\],\s]+", ...)` and appeared as a dependency).
    misparse_tab = guard_gate_verdict(gate_ok_sample.replace(
        "  claim:\n    needs: [plan, secrets-guard]",
        "  claim:\n    needs: [plan]\t# secrets-guard"))
    chk("misparse 4a: `needs: [plan]<TAB># secrets-guard` -> REFUSE, naming the YAML parse fault "
        "(the old reader accepted the COMMENT as the dependency)",
        (misparse_tab[0], "does not parse as YAML" in misparse_tab[1]), (False, True))
    # ...and the valid-YAML sibling proves the property itself: a comment MENTIONING the guard is
    # not a dependency on it, and the refusal names the job.
    misparse_needs = guard_gate_verdict(gate_ok_sample.replace(
        "  claim:\n    needs: [plan, secrets-guard]",
        "  claim:\n    needs: [plan] # secrets-guard is deliberately not required here"))
    chk("misparse 4b: a `# secrets-guard` COMMENT does not satisfy `needs:` -> REFUSE, job NAMED",
        (misparse_needs[0], "claim" in misparse_needs[1]), (False, True))
    chk("misparse 5: a `github/workflows/` sparse-checkout entry does NOT cover "
        "`.github/workflows/dispatch.yml` -> REFUSE (lstrip('./') ate the leading dot of the "
        "dotfile directory, so a typo that checks out NOTHING read as full coverage)",
        sparse_checkout_covers_verdict(
            "\n".join(["jobs:", "  secrets-guard:", "    steps:", "      - uses: checkout",
                       "        with:", "          sparse-checkout: |",
                       "            github/workflows/", "          x: y"]),
            "secrets-guard", (".github/workflows/dispatch.yml",))[0], False)
    chk("normalize_repo_path: a leading ./ is stripped and a dotfile directory is NOT",
        (normalize_repo_path("./scripts/x.py"), normalize_repo_path(".github/workflows/d.yml"),
         normalize_repo_path("././a/b"), normalize_repo_path("a\\b"), normalize_repo_path(".env")),
        ("scripts/x.py", ".github/workflows/d.yml", "a/b", "a/b", ".env"))
    chk("normalize_repo_path is NOT lstrip('./') — the old expression on the very path that broke",
        (normalize_repo_path(".github/workflows/dispatch.yml"),
         ".github/workflows/dispatch.yml".lstrip("./")),
        (".github/workflows/dispatch.yml", "github/workflows/dispatch.yml"))
    # ...and the accept direction still holds, so the fix is not simply "refuse everything".
    chk("misparse 5 (accept): the CORRECT `.github/workflows/` entry still covers the file",
        sparse_checkout_covers_verdict(
            "\n".join(["jobs:", "  secrets-guard:", "    steps:", "      - uses: checkout",
                       "        with:", "          sparse-checkout: |",
                       "            .github/workflows/", "          x: y"]),
            "secrets-guard", (".github/workflows/dispatch.yml",)), (True, "ok"))
    # A REFLOWED-but-equivalent dispatch.yml must yield the same verdicts (#619's precedent): the
    # gate contract is now a property of the parsed document, not of the file's whitespace.
    _yaml = _yaml_module()
    reflowed_dispatch = _yaml.safe_dump(
        _yaml.safe_load(live_docs.get("dispatch.yml", "")), default_flow_style=False, width=10000)
    chk("GATE (LIVE, REFLOWED): a re-serialised dispatch.yml yields the same gate verdict — the "
        "contract is on the PARSED document, not on its indentation",
        guard_gate_verdict(reflowed_dispatch), (True, "ok"))
    chk("GATE (LIVE, REFLOWED): the reflow fixture is NON-VACUOUS — the exact 10-space "
        "`sparse-checkout: |` literal the old reader addressed by is gone from the reflow, and a "
        "single-quoted flow scalar stands where the block scalar was",
        ("          sparse-checkout: |" in reflowed_dispatch,
         "        sparse-checkout: 'scripts/dispatch-secrets-guard.py" in reflowed_dispatch),
        (False, True))
    chk("sparse checkout (LIVE, REFLOWED): the coverage assertion survives a reflow too",
        sparse_checkout_covers_verdict(reflowed_dispatch, "secrets-guard",
                                       SELF_TEST_LIVE_INPUTS), (True, "ok"))
    chk("GATE: a QUOTED job key is seen by BOTH readers or the verdict REFUSES (the parsed and "
        "line-parsed job sets must agree — a job only one reader sees escapes the other's checks)",
        guard_gate_verdict(gate_ok_sample.replace("  claim:\n", '  "claim":\n'))[0], False)
    # LIVE: dispatch.yml itself. This is the assertion that would have caught issue #618 on the
    # day the continue-on-error line landed, and it goes red the moment it comes back.
    chk("GATE (LIVE): dispatch.yml's guard carries no continue-on-error and every "
        "secret-consuming job in the file is gated on it",
        guard_gate_verdict(live_docs.get("dispatch.yml", "")), (True, "ok"))
    # LIVE [#1208]: THE GUARD JOB IS NOW ITSELF GATED on the #819 rate floor, so it no longer runs
    # on a tick the floor holds. That is admissible ONLY because a guard that does not run must not
    # admit anything, and a SKIPPED job's `result` is `skipped` — never `success`. The two consumers
    # are checked by the two mechanisms that own them:
    #   * `claim` carries no job-level `if:`, so GitHub's implicit needs-must-succeed skips it with
    #     its dependency. dispatch-tick-floor's seam test pins the absence of that `if:`.
    #   * `plan-alert` re-states the dependency because its `always()` cancels the implicit gate.
    #     if_condition_admits decides that polarity for EVERY non-success result, `skipped`
    #     included, and the row below asserts it against the LIVE expression rather than a sample.
    # If either ever became admitting, gating the guard would convert a held tick into an UNGATED
    # tick. It cannot: a held tick already skips `plan`, and `claim` needs `plan` too.
    live_alert_if = job_if_expression(
        (workflow_job_docs(live_docs.get("dispatch.yml", "")) or {}).get("plan-alert") or {})
    chk("GATE (LIVE) [#1208]: a SKIPPED guard does NOT admit plan-alert — so gating the guard on "
        "the floor can only ever skip MORE jobs, never admit one",
        (live_alert_if is not None,
         if_condition_admits(live_alert_if or "", GATE_SUCCESS_RE)[:2]),
        (True, (False, True)))
    # LIVE: the guard job's sparse checkout must carry every file this self-test reads, so no
    # check can degrade to vacuous (or misleading) on a dispatch tick while passing in pr-gate.
    chk("GATE (LIVE): the guard job's sparse checkout covers every self-test live input",
        sparse_checkout_covers_verdict(
            live_docs.get("dispatch.yml", ""), "secrets-guard", SELF_TEST_LIVE_INPUTS),
        (True, "ok"))
    missing_input = sparse_checkout_covers_verdict(
        live_docs.get("dispatch.yml", ""), "secrets-guard",
        SELF_TEST_LIVE_INPUTS + ("policy/never-checked-out.toml",))
    chk("sparse checkout: a live input absent from the list -> REFUSE, path NAMED",
        (missing_input[0], "policy/never-checked-out.toml" in missing_input[1]), (False, True))
    chk("sparse checkout: an unlocatable block -> REFUSE (fail closed)",
        sparse_checkout_covers_verdict(
            "jobs:\n  secrets-guard:\n    steps:\n      - uses: actions/checkout@v4\n",
            "secrets-guard", ("scripts/worker-pr.py",))[0], False)
    chk("sparse checkout: a directory entry covers files beneath it",
        sparse_checkout_covers_verdict(
            "\n".join(["jobs:", "  secrets-guard:", "    steps:", "      - uses: checkout",
                       "        with:", "          sparse-checkout: |",
                       "            .github/workflows/", "          x: y"]),
            "secrets-guard", (".github/workflows/dispatch.yml",)), (True, "ok"))

    # Round 19: the ONE shared quote-aware comment stripper, tested directly — every shell-text
    # check strips through it before matching.
    chk("comment strip: unquoted word-start # cuts to end of line",
        strip_shell_comments('gh secret set "$X" < f # --env dispatch-secrets'),
        'gh secret set "$X" < f ')
    chk("comment strip: # inside DOUBLE quotes preserved",
        strip_shell_comments('echo "a # b" tail'), 'echo "a # b" tail')
    chk("comment strip: # inside SINGLE quotes preserved",
        strip_shell_comments("echo 'a # b' tail"), "echo 'a # b' tail")
    chk("comment strip: mid-word # never a comment (${VAR#pat}, $((10#$n)))",
        strip_shell_comments('r=${H#acct}; r=$((10#$r))'), 'r=${H#acct}; r=$((10#$r))')
    chk("comment strip: backslash-escaped # preserved",
        strip_shell_comments('echo \\# literal'), 'echo \\# literal')
    chk("comment strip: full-line comment -> emptied",
        strip_shell_comments('  # only a comment'), '  ')
    chk("comment strip: multi-line text stripped line by line",
        strip_shell_comments('keep "a # b"\n# gone\ntail # gone too'),
        'keep "a # b"\n\ntail ')

    # Env-scoped WRITE pins (round 17): the broker's final store + the rotation write-back must
    # keep `--env dispatch-secrets` — synthetic accept/reject, then the LIVE files.
    write_sample = ('# comment: gh secret set "$SECRET_NAME" (prose, ignored)\n'
                    'GH_TOKEN="$PAT" gh secret set "$SECRET_NAME" -R "o/r" '
                    '--env dispatch-secrets < "$DIR/token"\n')
    chk("env write: store invocation carries --env dispatch-secrets -> ok",
        secret_env_write_verdict(write_sample, '"$SECRET_NAME"', "sample"), (True, "ok"))
    stripped_write = secret_env_write_verdict(
        write_sample.replace(" --env dispatch-secrets", ""), '"$SECRET_NAME"', "sample")
    chk("env write: --env dispatch-secrets stripped -> refuse, repo-scope risk named",
        (stripped_write[0], "--env dispatch-secrets" in stripped_write[1]), (False, True))
    # sol round-19 mutation (finding 3): the flag lives ONLY in an inline shell comment — the
    # raw line contains the substring, but the invocation writes to repo scope. Broker shape
    # AND rotation shape (the `"${WORKER_GH_BIN:-...}"`-expanded gh) must both refuse.
    commented_broker = ('GH_TOKEN="$PAT" gh secret set "$SECRET_NAME" -R "o/r" '
                        '< "$DIR/token" # --env dispatch-secrets\n')
    verdict_commented = secret_env_write_verdict(
        commented_broker, '"$SECRET_NAME"', "sample")
    chk("env write: --env dispatch-secrets ONLY in an inline comment -> refuse (round 19: "
        "comment prose is not evidence)",
        (verdict_commented[0], "--env dispatch-secrets" in verdict_commented[1]),
        (False, True))
    rotation_commented = ('GH_TOKEN="$pat" "${WORKER_GH_BIN:-/usr/bin/gh}" secret set '
                          '"$secret_ref" --repo "o/r" < "$current" # --env dispatch-secrets\n')
    chk("env write: rotation-shaped invocation with --env ONLY in a comment -> refuse",
        secret_env_write_verdict(rotation_commented, '"$secret_ref"', "sample")[0], False)
    continued = ('gh secret set "$SECRET_NAME" -R "o/r" \\\n'
                 '  --env dispatch-secrets < "$DIR/token"\n')
    chk("env write: backslash-continued invocation -> joined and accepted",
        secret_env_write_verdict(continued, '"$SECRET_NAME"', "sample"), (True, "ok"))
    chk("env write: write site missing entirely -> refuse (fail closed)",
        secret_env_write_verdict("echo no writes here", '"$SECRET_NAME"', "sample")[0],
        False)
    chk("env write: a quoted fixture string without a leading `gh` is NOT an invocation",
        secret_env_write_verdict(
            '"secret set ACCT05_TOKEN --repo o/r"', "ACCT05_TOKEN", "sample")[0], False)
    try:
        with open(setup_path, encoding="utf-8") as handle:
            live_broker_write = secret_env_write_verdict(
                handle.read(), '"$SECRET_NAME"', "set-up-account.yml")
    except OSError:
        live_broker_write = (False, "set-up-account.yml unreadable (fail closed)")
    chk("workflow: the broker's final store writes into the dispatch-secrets ENVIRONMENT",
        live_broker_write, (True, "ok"))
    worker_live_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "worker-live.sh")
    try:
        with open(worker_live_path, encoding="utf-8") as handle:
            live_rotation_write = secret_env_write_verdict(
                handle.read(), '"$secret_ref"', "worker-live.sh")
    except OSError:
        live_rotation_write = (False, "worker-live.sh unreadable (fail closed)")
    chk("script: the rotation write-back writes into the dispatch-secrets ENVIRONMENT",
        live_rotation_write, (True, "ok"))

    # ---- the ROTATION WRITE-BACK must be REACHABLE FROM THE FAILURE PATH (retro-review of #614) --
    # LIVE, both lanes: worker.yml and review-fix.yml each gated this step on
    # `steps.prepare.outcome == 'success'` — the success of the very step whose pre-flight CONSUMES
    # the one-time-use refresh token. This is the assertion that makes restoring that guard red.
    chk("WRITE-BACK (LIVE): the rotation write-back RUNS on every path where the credential "
        "pre-flight may already have rotated the grant, and BOTH lanes carry the call site (#614: a "
        "compensating action gated on the success of the step it compensates for is no compensation "
        "at all)",
        rotation_writeback_reachable_verdict(live_docs, WRITEBACK_REQUIRED_LANES), (True, "ok"))
    # THE MUTANT: success-only reachability, exactly as #614 shipped it. Both lanes, independently.
    for lane in WRITEBACK_REQUIRED_LANES:
        mutant_docs = dict(live_docs)
        mutant_docs[lane] = mutant_docs[lane].replace(
            "steps.selected.outcome == 'success'", "steps.prepare.outcome == 'success'")
        reverted = rotation_writeback_reachable_verdict(mutant_docs, WRITEBACK_REQUIRED_LANES)
        chk(f"WRITE-BACK: {lane} reverted to `steps.prepare.outcome == 'success'` -> REFUSE, naming "
            "the LANE and #596's original defect (one-time-use grant spent, rotated grant "
            "discarded, account permanently dead)",
            (reverted[0], lane in reverted[1], "ORIGINAL defect" in reverted[1]),
            (False, True, True))
    # ---- RETRO-REVIEW OF #629, F4: THE QUANTIFIER. Each of these mutations ADDS an atom to the LIVE
    # lane while KEEPING `steps.selected.outcome == 'success'`, so the per-lane mutant fixtures above
    # still apply and their `replace()` search string is still present. Under #629's EXISTENTIAL check
    # every one of them measured `(True, 'ok')` on the live worker.yml with the whole enrolled suite
    # green — including `&& steps.model.outcome == 'success'`, which is #596's ORIGINAL defect verbatim
    # and which the step's own comment says must never come back. These reds are the guard FIRING on
    # the defect, not a fixture string going missing. ----
    for extra_atom, why in (
            ("steps.model.outcome == 'success'",
             "#596's ORIGINAL defect: a MODEL-step guard on the write-back"),
            ("steps.prepare.outcome != 'failure'",
             "defect 3 one token differently spelled: deterministically false on a prepare failure"),
            ("steps.prepare.outputs.rotated == 'true'",
             "a prepare OUTPUT is empty when prepare aborted mid-rotation"),
            ("steps.prepare.outcome == 'skipped'",
             "a prepare outcome atom of any spelling")):
        for lane in WRITEBACK_REQUIRED_LANES:
            mutant_docs = dict(live_docs)
            mutant_docs[lane] = mutant_docs[lane].replace(
                "steps.selected.outcome == 'success' }}",
                "steps.selected.outcome == 'success' && " + extra_atom + " }}")
            chk(f"WRITE-BACK (LIVE, F4): {lane} + `&& {extra_atom}` -> REFUSE, naming the atom "
                f"({why})",
                (mutant_docs[lane] != live_docs[lane],)
                + rotation_writeback_reachable_verdict(mutant_docs, WRITEBACK_REQUIRED_LANES)[:1]
                + (extra_atom.split()[0].replace(" ", "") in rotation_writeback_reachable_verdict(
                    mutant_docs, WRITEBACK_REQUIRED_LANES)[1],),
                (True, False, True))
    # ...and the shapes the retro-review measured as passing, as a direct table on the primitive.
    for condition, reachable in (
            (None, True),
            ("${{ always() }}", True),
            ("${{ always() && steps.selected.outcome == 'success' }}", True),
            ("${{ always() && !inputs.dry_run && needs.claim.outputs.acquired == 'true' && "
             "steps.selected.outcome == 'success' }}", True),
            # F4, all four measured as GREEN under the existential check:
            ("${{ always() && steps.selected.outcome == 'success' && "
             "steps.model.outcome == 'success' }}", False),
            ("${{ always() && steps.selected.outcome == 'success' && "
             "steps.prepare.outcome != 'failure' }}", False),
            ("${{ always() && steps.selected.outcome == 'success' && "
             "steps.prepare.outputs.rotated == 'true' }}", False),
            ("${{ success() }}", False),
            # #614's shipped defect and its close spellings:
            ("${{ always() && steps.prepare.outcome == 'success' }}", False),
            ("${{ steps.prepare.conclusion == 'success' }}", False),
            # runs ONLY when prepare did NOT succeed: a rotation on the SUCCESS path is discarded
            ("${{ always() && steps.prepare.outcome != 'success' }}", False),
            ("${{ always() && (steps.prepare.outcome == 'success' || "
             "steps.preflight.outputs.rotated == 'true') }}", False),
            # a dry run cannot have rotated anything, so gating it out is legitimate
            ("${{ always() && !inputs.dry_run }}", True),
            ("${{ always() && inputs.dry_run }}", False)):
        synthetic = ["jobs:", "  run:", "    steps:"]
        if condition is not None:
            synthetic.append(f"      - if: {condition}")
            synthetic.append("        run: bash registry/scripts/worker-live.sh write-back")
        else:
            synthetic.append("      - run: bash registry/scripts/worker-live.sh write-back")
        chk(f"WRITE-BACK: `if: {condition}` runs the write-back on EVERY rotation-possible path",
            rotation_writeback_reachable_verdict({"w.yml": "\n".join(synthetic)})[0], reachable)
    chk("WRITE-BACK: zero write-back steps anywhere -> REFUSE (a renamed step must not make this "
        "assertion pass vacuously)",
        rotation_writeback_reachable_verdict(
            {"w.yml": "jobs:\n  run:\n    steps:\n      - run: true\n"})[0], False)
    chk("WRITE-BACK: an UNPARSEABLE condition on the write-back step -> REFUSE (unlike the gate, "
        "an unprovable reachability fails toward the refusal: an unpersisted rotation is "
        "unrecoverable)",
        rotation_writeback_reachable_verdict(
            {"w.yml": "\n".join(["jobs:", "  run:", "    steps:",
                                 "      - if: ${{ always() && ( }}",
                                 "        run: bash scripts/worker-live.sh write-back"])})[0],
        False)
    # ---- RETRO-REVIEW OF #629, F3: THE PRODUCTION CALL SITE, PER LANE. Commenting the `run:` out in
    # BOTH lanes (keeping the text) left the whole enrolled suite green — defect 3's call site had no
    # test at all. Each lane is now asserted INDEPENDENTLY, and the refusal names the lane. ----
    for lane in WRITEBACK_REQUIRED_LANES:
        for label, replacement in (
                ("COMMENTED OUT",
                 "        run: |\n          : # bash registry/scripts/worker-live.sh write-back"),
                ("DELETED", "        run: 'true'"),
                ("SHORT-CIRCUITED behind `true ||`",
                 "        run: true || bash registry/scripts/worker-live.sh write-back"),
                ("moved into a HERE-DOC",
                 "        run: |\n          cat <<'SH' > /dev/null\n"
                 "          bash registry/scripts/worker-live.sh write-back\n          SH")):
            mutant_docs = dict(live_docs)
            mutant_docs[lane] = mutant_docs[lane].replace(
                "        run: bash registry/scripts/worker-live.sh write-back", replacement)
            verdict = rotation_writeback_reachable_verdict(mutant_docs, WRITEBACK_REQUIRED_LANES)
            chk(f"WRITE-BACK (LIVE, F3): {lane}'s write-back call site {label} -> REFUSE, naming "
                "the lane (every rotated grant would be silently discarded)",
                (mutant_docs[lane] != live_docs[lane], verdict[0], lane in verdict[1]),
                (True, False, True))
    chk("WRITE-BACK: a required lane with no write-back step at all -> REFUSE, lane NAMED",
        (rotation_writeback_reachable_verdict(
            {"worker.yml": "jobs:\n  run:\n    steps:\n      - run: true\n"},
            ("worker.yml",))[0],
         "worker.yml" in rotation_writeback_reachable_verdict(
             {"worker.yml": "jobs:\n  run:\n    steps:\n      - run: true\n"},
             ("worker.yml",))[1]),
        (False, True))
    chk("WRITE-BACK: the required-lane list is NON-EMPTY, so the per-lane assertions above are not "
        "vacuous", len(WRITEBACK_REQUIRED_LANES) >= 2, True)

    # IDEMPOTENT-RESUME credential-existence contract (#211; review round 1 of #533): the
    # reconcile step must NEVER grant resume=true on the say-so of a secret_ref LINE — an
    # account issue can outlive its dispatch-secrets secret (deleted during manual recovery,
    # or never successfully created), and a granted resume flows straight into
    # validate -> account_pool PR -> activation around a credential no worker can use. The
    # reconcile body is pure workflow-shell (no script seam), but unlike the union contract
    # above it is cheaply EXECUTABLE: run the REAL extracted `run: |` body under stubbed
    # gh/jq on a private PATH (hermetic — no network, no real gh/jq needed on the host) and
    # assert the behaviour itself, both directions. Downstream steps gate on
    # `steps.reconcile.outputs.resume == 'true'` (or a fresh login), so "non-zero exit AND no
    # resume=true in GITHUB_OUTPUT" proves validate/policy-PR/activation are unreachable.
    import tempfile

    try:
        with open(setup_path, encoding="utf-8") as handle:
            reconcile_script = setup_account_reconcile_run_script(handle.read())
    except OSError:
        reconcile_script = None
    chk("workflow: reconcile run-block located and extracted (a reshaped step fails closed here)",
        reconcile_script is not None, True)

    # TRANSITIVE-INPUT CONTRACT (the 2026-07-25 dispatch halt). These four assertions come BEFORE the
    # harness runs, so a missing dependency is NAMED instead of surfacing as a credential-contract
    # failure the dependency did not cause. See executed_body_file_dependencies above for the full
    # #616 x #621 composition story.
    reconcile_deps = executed_body_file_dependencies(reconcile_script or "")
    chk("reconcile harness: the executed body's file dependencies are DERIVED, not assumed — the "
        "derivation is non-vacuous (an empty set would make both coverage assertions below silently "
        "pass on any omission)",
        (len(reconcile_deps) >= 1, "scripts/grant-account.py" in reconcile_deps), (True, True))
    chk("reconcile harness (LIVE): every file the executed reconcile body loads is DECLARED as a "
        "self-test live input (sparse_checkout_covers_verdict then pins it to the checkout list)",
        executed_body_inputs_declared_verdict(reconcile_script or "", SELF_TEST_LIVE_INPUTS),
        (True, "ok"))
    chk("reconcile harness (LIVE): every file the executed reconcile body loads is PRESENT in THIS "
        "checkout — the assertion that names the halt cause on a dispatch tick",
        executed_body_inputs_present_verdict(
            reconcile_script or "",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir)),
        (True, "ok"))
    undeclared = executed_body_inputs_declared_verdict(
        reconcile_script or "", tuple(entry for entry in SELF_TEST_LIVE_INPUTS
                                      if entry != "scripts/grant-account.py"))
    chk("reconcile harness: dropping the #616 dependency from the declared inputs -> REFUSE, path "
        "NAMED (this is the assertion whose absence let the halt land)",
        (undeclared[0], "scripts/grant-account.py" in undeclared[1]), (False, True))
    # Pure accept/reject directions for the derivation itself, on synthetic bodies.
    chk("executed-body derivation: a load in CODE is a dependency (`./` folded); an API path, a ref "
        "that merely contains a root name, and a parent-relative escape are NOT",
        executed_body_file_dependencies(
            'python3 -c \'open("scripts/grant-account.py")\'\n'
            'gh api "repos/$REPO/scripts/decoy.py"\n'
            'git update-ref "refs/data/decoy.json" HEAD\n'
            'cat ../scripts/outside-decoy.py\n'
            'cat ./policy/repos.toml\n'),
        ("policy/repos.toml", "scripts/grant-account.py"))
    chk("executed-body derivation: a path named only in a COMMENT is not a dependency (prose must "
        "never satisfy — nor manufacture — an assertion about code)",
        executed_body_file_dependencies('# loads scripts/never-loaded.py\ntrue\n'), ())
    chk("executed-body derivation: a real load does NOT hide behind a comment tail on the same line",
        executed_body_file_dependencies(
            'python3 scripts/really-loaded.py # scripts/decoy.py\n'),
        ("scripts/really-loaded.py",))
    chk("executed-body contract: an unextractable body -> REFUSE, both directions (fail closed)",
        (executed_body_inputs_declared_verdict(None, SELF_TEST_LIVE_INPUTS)[0],
         executed_body_inputs_present_verdict("", ".")[0]), (False, False))
    chk("executed-body presence: a derived dependency absent from the checkout -> REFUSE, path NAMED",
        (executed_body_inputs_present_verdict(
            'python3 scripts/definitely-not-in-this-repo.py\n', ".")[0],
         "scripts/definitely-not-in-this-repo.py" in executed_body_inputs_present_verdict(
             'python3 scripts/definitely-not-in-this-repo.py\n', ".")[1]),
        (False, True))

    gh_stub = r'''#!/usr/bin/env bash
# Hermetic gh stub for the reconcile harness: keyed on EXACT argv so a reshaped reconcile
# step fails LOUDLY (exit 64) instead of silently passing. STUB_MODE selects the probe fate.
args="$*"
case "$args" in
  "api --paginate repos/$REPO/issues?state=open&per_page=100")
    printf '[]\n' ;;
  "api repos/$REPO/environments/dispatch-secrets/secrets/"*)
    if [ "${GH_TOKEN:-}" != "$EXPECTED_PROBE_TOKEN" ]; then
      printf 'gh-stub: existence probe ran with the wrong token\n' >&2; exit 64
    fi
    case "$STUB_MODE" in
      secret-exists) printf '{"name":"%s"}\n' "${args##*/}" ;;
      secret-404)    printf 'gh: Not Found (HTTP 404)\n' >&2; exit 1 ;;
      *)             printf 'gh: Internal Server Error (HTTP 500)\n' >&2; exit 1 ;;
    esac ;;
  "issue view 5 -R $REPO --json title --jq .title")
    printf 'acct07\n' ;;
  "issue view 5 -R $REPO --json body --jq .body")
    cat "$STUB_BODY_FILE" ;;
  "issue comment "*)
    : ;;
  *)
    printf 'gh-stub: unexpected argv: %s\n' "$args" >&2; exit 64 ;;
esac
'''
    jq_stub = r'''#!/usr/bin/env bash
# Hermetic jq stub: the harness controls the bound-issue set directly (the binding filter's
# OUTPUT is injected), so the real jq binary is not required on the test host.
cat > /dev/null 2>/dev/null || true
if [ "$STUB_MODE" = fresh ]; then exit 0; fi
printf '5\n'
'''

    # The halted run's log showed only `(1, False, False, False)` — the harness discarded the body's
    # diagnostics, so the FileNotFoundError that actually caused the refusal never reached the log
    # and the failure read as a credential-contract regression. The body's stderr/stdout is kept and
    # printed on any UNEXPECTED refusal below, so the next such failure is triageable in one look.
    reconcile_diag = {}

    def run_reconcile(mode, secret_ref="ACCT07_TOKEN", registry_pat="sentinel-registry-pat",
                      grant_targets="jeswr/agent-account-registry"):
        """rc + GITHUB_OUTPUT text from executing the real reconcile shell hermetically."""
        if reconcile_script is None:
            return None, ""
        with tempfile.TemporaryDirectory() as tmp:
            bindir = os.path.join(tmp, "bin")
            os.mkdir(bindir)
            for name, text in (("gh", gh_stub), ("jq", jq_stub)):
                stub_path = os.path.join(bindir, name)
                with open(stub_path, "w", encoding="utf-8") as fh:
                    fh.write(text)
                os.chmod(stub_path, 0o755)
            body_file = os.path.join(tmp, "issue-body.txt")
            with open(body_file, "w", encoding="utf-8") as fh:
                fh.write("provider: anthropic\nharness: claude\n"
                         "models: [opus5, fable, opus, sonnet, haiku]\n"
                         "credential_format: claude-oauth-token\n"
                         "max_concurrent_workers: 1\n"
                         f"secret_ref: {secret_ref}\n"
                         "request_issue: 42\n"
                         # #579: the broker stamps the AUTHORIZED target repositories onto every
                         # account record, and reconcile refuses to resume a record whose grant
                         # cannot be read (an unprovable grant must never re-enter the pipeline).
                         + (f"grant_targets: {grant_targets}\n" if grant_targets else ""))
            output_path = os.path.join(tmp, "github-output")
            open(output_path, "w", encoding="utf-8").close()
            env = dict(os.environ,
                       PATH=bindir + os.pathsep + os.environ.get("PATH", ""),
                       GH_TOKEN="sentinel-github-token",
                       REGISTRY_PAT=registry_pat,
                       EXPECTED_PROBE_TOKEN="sentinel-registry-pat",
                       ISSUE="42",
                       REPO="jeswr/agent-account-registry",
                       GITHUB_OUTPUT=output_path,
                       STUB_MODE=mode,
                       STUB_BODY_FILE=body_file)
            # cwd = the repository root: the extracted reconcile body loads
            # scripts/grant-account.py by the same relative path every workflow step uses (#579),
            # so the harness must not depend on the caller's working directory.
            proc = subprocess.run(["bash", "-c", reconcile_script], cwd=os.path.abspath(
                os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir)),
                env=env, capture_output=True, text=True)
            reconcile_diag[(mode, secret_ref, bool(registry_pat), grant_targets)] = (
                proc.stderr or "") + (proc.stdout or "")
            with open(output_path, encoding="utf-8") as fh:
                return proc.returncode, fh.read()

    rc_fresh, out_fresh = run_reconcile("fresh")
    chk("reconcile: no bound account issue -> fresh enrollment (rc 0, resume=false)",
        (rc_fresh, "resume=false" in out_fresh, "resume=true" in out_fresh),
        (0, True, False))
    rc_resume, out_resume = run_reconcile("secret-exists")
    chk("reconcile: bound issue + secret PROVEN present (PAT-scoped GET) -> resume granted",
        (rc_resume, "resume=true" in out_resume, "handle=acct07" in out_resume,
         "secret=ACCT07_TOKEN" in out_resume),
        (0, True, True, True))
    rc_gone, out_gone = run_reconcile("secret-404")
    chk("reconcile: referenced secret 404s in dispatch-secrets -> refuse (rc!=0, resume NEVER "
        "granted; validate/policy-PR/activation unreachable)",
        (rc_gone != 0, "resume=true" in out_gone), (True, False))
    rc_unproven, out_unproven = run_reconcile("probe-error")
    chk("reconcile: probe fails for a non-404 reason -> refuse (existence unprovable, fail closed)",
        (rc_unproven != 0, "resume=true" in out_unproven), (True, False))
    rc_binding, out_binding = run_reconcile("secret-exists", secret_ref="ACCT99_TOKEN")
    chk("reconcile: secret_ref is not the broker-minted binding for the handle -> refuse",
        (rc_binding != 0, "resume=true" in out_binding), (True, False))
    rc_nopat, out_nopat = run_reconcile("secret-exists", registry_pat="")
    chk("reconcile: REGISTRY_SECRETS_PAT empty -> refuse (existence cannot be proven)",
        (rc_nopat != 0, "resume=true" in out_nopat), (True, False))
    # #579 GRANT-SCOPE contract, same executable harness: a resumed enrollment re-enters at
    # validate -> account_pool PR, so its AUTHORIZED target repositories must be readable from the
    # bound account record. A record with no `grant_targets:` line — or an unparseable one — can
    # never prove which rows its grant may touch, so resume is refused rather than granted with an
    # unknown (and formerly every-repository) scope.
    rc_resume_targets, out_resume_targets = run_reconcile("secret-exists")
    chk("reconcile: a readable grant_targets record publishes the resumed target set",
        (rc_resume_targets, 'targets=["jeswr/agent-account-registry"]' in out_resume_targets),
        (0, True))
    rc_nogrant, out_nogrant = run_reconcile("secret-exists", grant_targets="")
    chk("[#579] reconcile: account record with NO grant_targets line -> refuse (an unprovable "
        "grant is never resumed; validate/policy-PR/activation unreachable)",
        (rc_nogrant != 0, "resume=true" in out_nogrant), (True, False))
    rc_badgrant, out_badgrant = run_reconcile("secret-exists", grant_targets="not-a-repository")
    chk("[#579] reconcile: account record with a MALFORMED grant_targets entry -> refuse",
        (rc_badgrant != 0, "resume=true" in out_badgrant), (True, False))

    # COMPOSITION PIN (#616 x #621 — the 2026-07-25 halt, so it cannot recur silently). #616 made
    # grant verification materially stricter and #621 made this guard actually gating; neither is
    # wrong, but nothing pinned that a LEGITIMATELY PROVABLE resume is still GRANTED under the
    # stricter contract. It is, and the target set it publishes must be the LIVE
    # scripts/grant-account.py parser's own output — sorted and de-duplicated, not a pass-through of
    # the record line — which is only true if the executed body really loads and runs that parser.
    # A stubbed, bypassed, or absent parser fails here, as does a parser that stops normalizing.
    rc_multi, out_multi = run_reconcile("secret-exists",
                                       grant_targets="o/beta, o/alpha, o/alpha")
    chk("[#616 x #621 composition] reconcile: a legitimately-provable resume is GRANTED under the "
        "stricter grant contract, publishing the LIVE parser's sorted + de-duplicated target set",
        (rc_multi, "resume=true" in out_multi,
         'targets=["o/alpha", "o/beta"]' in out_multi), (0, True, True))
    # Any refusal on a path that must be GRANTED is a harness/checkout defect rather than a contract
    # finding, so surface the body's own diagnostics instead of leaving a bare tuple in the log.
    for key, expected_zero in ((("secret-exists", "ACCT07_TOKEN", True,
                                 "jeswr/agent-account-registry"), rc_resume),
                               (("secret-exists", "ACCT07_TOKEN", True,
                                 "o/beta, o/alpha, o/alpha"), rc_multi)):
        if expected_zero not in (0, None) and key in reconcile_diag:
            print("  DIAG the reconcile body refused on a MUST-GRANT path; its own output was:")
            for line in reconcile_diag[key].strip().splitlines()[-6:]:
                print(f"  DIAG   {line}")

    # Pure scope verdict — accept AND reject directions.
    chk("scope: only github_token -> ok",
        repo_scope_verdict({"github_token": "x"}), (True, []))
    chk("scope: empty -> ok", repo_scope_verdict({}), (True, []))
    chk("scope: repo secret -> offending NAME surfaced",
        repo_scope_verdict({"github_token": "x", "REGISTRY_ADMIN_APP_KEY": "v"}),
        (False, ["REGISTRY_ADMIN_APP_KEY"]))
    chk("scope: case-insensitive github_token allowance",
        repo_scope_verdict({"GITHUB_TOKEN": "x"}), (True, []))

    # Pure branch-policy verdict — every refusal direction plus the single accept shape.
    good_env = {"deployment_branch_policy":
                {"protected_branches": False, "custom_branch_policies": True}}
    good_policies = {"branch_policies": [{"name": "master", "type": "branch"}]}
    chk("policy: custom + exactly default branch -> ok",
        branch_policy_verdict(good_env, good_policies, "master"), (True, "ok"))
    chk("policy: all-branches (null) -> refuse",
        branch_policy_verdict({"deployment_branch_policy": None},
                              good_policies, "master")[0], False)
    chk("policy: protected-branches mode -> refuse",
        branch_policy_verdict({"deployment_branch_policy":
                               {"protected_branches": True,
                                "custom_branch_policies": False}},
                              good_policies, "master")[0], False)
    chk("policy: tag-type entry named like the branch -> refuse",
        branch_policy_verdict(good_env,
                              {"branch_policies": [{"name": "master", "type": "tag"}]},
                              "master")[0], False)
    # Round 18 (sol): a policy entry with NO type key must refuse — the old default-to-branch
    # let a {"name": "master"} entry pass without ever proving it is not a tag policy.
    missing_type = branch_policy_verdict(
        good_env, {"branch_policies": [{"name": "master"}]}, "master")
    chk("policy: entry MISSING an explicit type -> refuse (absence cannot prove non-tag)",
        (missing_type[0], "not explicitly 'branch'" in missing_type[1]), (False, True))
    chk("policy: wrong branch name -> refuse",
        branch_policy_verdict(good_env,
                              {"branch_policies": [{"name": "staging", "type": "branch"}]},
                              "master")[0], False)
    chk("policy: extra branch admitted -> refuse",
        branch_policy_verdict(good_env,
                              {"branch_policies": [{"name": "master", "type": "branch"},
                                                   {"name": "staging", "type": "branch"}]},
                              "master")[0], False)
    chk("policy: unreadable policy list -> refuse",
        branch_policy_verdict(good_env, None, "master")[0], False)
    chk("policy: unreadable environment doc -> refuse",
        branch_policy_verdict(None, good_policies, "master")[0], False)

    # Stubbed-gh flow: full main() paths with a fake subprocess.run keyed on the API path, so
    # the accept path, every refusal path, the read-only invariant, and the value-never-echoed
    # sentinels are asserted, not assumed.
    import contextlib
    import io

    class _Result:
        def __init__(self, rc=0, stdout="", stderr="SENTINEL-STDERR"):
            self.returncode = rc
            self.stdout = stdout
            self.stderr = stderr

    calls = []
    responses = {}

    def fake_run(cmd, capture_output=False, text=False):
        calls.append(list(cmd))
        return responses.get(cmd[2], _Result(1))

    repo = "org/registry"
    repo_path = f"repos/{repo}"
    env_path = f"{repo_path}/environments/{ENVIRONMENT}"
    policies_path = f"{env_path}/deployment-branch-policies"

    def run_main(all_secrets, docs, registry_repo=repo, stderr="SENTINEL-STDERR"):
        """`stderr` is what a FAILED `gh api` wrote — the only evidence the guard has for telling
        "the settings are wrong" apart from "I could not read the settings" (#819)."""
        calls.clear()
        responses.clear()
        for path, doc in docs.items():
            responses[path] = (_Result(0, json.dumps(doc)) if doc is not None
                               else _Result(1, stderr=stderr))
        os.environ["REGISTRY_REPO"] = registry_repo
        os.environ["ALL_SECRETS"] = all_secrets
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = main()
        return rc, buffer.getvalue()

    verified_docs = {repo_path: {"default_branch": "master"},
                     env_path: good_env, policies_path: good_policies}
    empty_scope = json.dumps({"github_token": "sentinel-ephemeral-token"})

    real_run = subprocess.run
    subprocess.run = fake_run
    try:
        rc_ok, out_ok = run_main(empty_scope, verified_docs)
        chk("flow: fully verified settings -> rc 0, token value never echoed",
            (rc_ok, "verified" in out_ok, "sentinel-ephemeral-token" in out_ok),
            (0, True, False))
        chk("flow: guard is READ-ONLY (bare `gh api` GETs, no mutation flags)",
            all(cmd[:2] == ["gh", "api"] and len(cmd) == 3
                and not any(arg.startswith("-") for arg in cmd[2:]) for cmd in calls)
            and len(calls) == 3, True)
        leaked = json.dumps({"github_token": "sentinel-ephemeral-token",
                             "REGISTRY_ADMIN_APP_KEY": "sentinel-private-key"})
        rc_leak, out_leak = run_main(leaked, verified_docs)
        chk("flow: repo-scope secret -> rc 1, NAME surfaced, VALUE never echoed",
            (rc_leak, "REGISTRY_ADMIN_APP_KEY" in out_leak,
             "sentinel-private-key" in out_leak, "::error::" in out_leak),
            (1, True, False, True))
        rc_missing, out_missing = run_main(
            empty_scope, {repo_path: {"default_branch": "master"},
                          env_path: None, policies_path: good_policies})
        chk("flow: missing environment -> rc 1 + remediation",
            (rc_missing, "missing or unreadable" in out_missing,
             "REQUIRED maintainer settings" in out_missing), (1, True, True))
        rc_all, out_all = run_main(
            empty_scope, {repo_path: {"default_branch": "master"},
                          env_path: {"deployment_branch_policy": None},
                          policies_path: good_policies})
        chk("flow: all-branches environment -> rc 1 (default-allow refused)",
            (rc_all, "All branches" in out_all), (1, True))
        rc_branch, out_branch = run_main(empty_scope, {repo_path: None})
        chk("flow: unreadable default branch -> rc 1 (fail closed)", rc_branch, 1)
        # ...and, with no PROOF the read was transient, it keeps the historical verdict. The
        # classification can only ever DEMOTE on positive evidence; it never suppresses silently.
        chk("flow: an UNCLASSIFIABLE read failure still prints the remediation (positive evidence "
            "only — absence of a throttle marker is not proof of a throttle)",
            "REQUIRED maintainer settings" in out_branch, True)

        # ---- #819: an API outage must not manufacture a maintainer action item --------------
        # The 06:19-06:32Z runs printed the #101 remediation having verified NOTHING: the first
        # read 403'd on an exhausted request budget, so the environment and branch-policy checks
        # never executed. Delete the `unverified` partition (or the `if`) and these go red.
        budget_403 = ("gh: API rate limit exceeded for installation. (HTTP 403)")
        for label, stderr in (("secondary rate limit 403",
                               "gh: You have exceeded a secondary rate limit (HTTP 403)"),
                              ("502 from the API", "gh: Bad Gateway (HTTP 502)"),
                              ("dropped connection", "error connecting: unexpected EOF")):
            rc_t, out_t = run_main(empty_scope, {repo_path: None}, stderr=stderr)
            chk(f"#819 flow: a {label} fails CLOSED but is reported as TRANSIENT, with NO "
                "maintainer action item",
                (rc_t, "TRANSIENT" in out_t, "REQUIRED maintainer settings" in out_t,
                 "UNVERIFIED, not known-wrong" in out_t), (1, True, False, True))
        chk("#819 flow: ... and the transient report never echoes the raw stderr (it can carry "
            "request bodies under GH_DEBUG=api)",
            "rate limit exceeded for installation"
            in run_main(empty_scope, {repo_path: None}, stderr=budget_403)[1], False)
        # THE OTHER DIRECTION, which is what stops this becoming a suppression bug: a GENUINE
        # settings gap found alongside a transient read must STILL print the remediation.
        rc_mixed, out_mixed = run_main(leaked, {repo_path: None}, stderr=budget_403)
        chk("#819 flow: a REAL settings finding alongside a transient read still prints the "
            "remediation (the demotion applies only when EVERY failure is unverified)",
            (rc_mixed, "REQUIRED maintainer settings" in out_mixed), (1, True))
        # And the classifier itself, in both directions.
        chk("#819 classify: a 404 is a REFUSAL, not a throttle (a missing environment IS the "
            "#101 condition and must keep its remediation)",
            classify_read_failure("gh: Not Found (HTTP 404)"), "refusal")
        chk("#819 classify: a 404 whose body merely mentions a timeout is still a refusal",
            classify_read_failure("gh: Not Found (HTTP 404) request timed out earlier"),
            "refusal")
        chk("#819 classify: a permission 403 is NOT transient",
            classify_read_failure("gh: Resource not accessible by integration (HTTP 403)"),
            "refusal")

        # ---- #1208: the BUDGET 403 is not an availability blip ------------------------------
        # Same fail-closed DECISION as #819 gave it; different, honest DIAGNOSIS. A primary budget
        # exhaustion carries no Retry-After and resets on a clock up to an hour away, so calling it
        # "an availability reason" that "recovers on its own" motivates exactly the retry that a
        # bucket at zero cannot pay for.
        chk("#1208 classify: the primary installation-budget 403 is BUDGET, not transient",
            classify_read_failure(budget_403), "budget")
        chk("#1208 classify: the user-token wording of the same limit is BUDGET too",
            classify_read_failure("gh: API rate limit exceeded for user ID 4783300. (HTTP 403)"),
            "budget")
        # A TRUNCATED budget message (registry #710 measured the trailing `(HTTP 403)` cut off by a
        # 200-char stderr excerpt) is still a budget message: a status-first reader sees nothing.
        chk("#1208 classify: a budget 403 whose STATUS was truncated away is still BUDGET",
            classify_read_failure("gh: API rate limit exceeded for installation. For more "
                                  "information about rate limiting, see https://docs.github.com/"),
            "budget")
        # THE SEPARATION THAT MATTERS. The secondary limiter clears in seconds and GitHub tells you
        # when; conflating the two would stand a tick down for an hour over a 30s wait.
        chk("#1208 classify: the SECONDARY limit stays transient (it clears in seconds — standing "
            "the tick down for an hour over it would be the opposite error)",
            classify_read_failure("gh: You have exceeded a secondary rate limit (HTTP 403)"),
            "transient")
        # FAIL-CLOSED, RESTATED AS A PARTITION. Carving `budget` out of `transient` must not have
        # moved anything out of `refusal`: every input that refused before still refuses.
        for stderr in ("gh: Not Found (HTTP 404)",
                       "gh: Not Found (HTTP 404) request timed out earlier",
                       "gh: Resource not accessible by integration (HTTP 403)",
                       "gh: Bad credentials (HTTP 401)",
                       "gh: Validation Failed (HTTP 422) rate limit exceeded",
                       "SENTINEL-STDERR"):
            chk(f"#1208 partition: {stderr[:44]!r} still REFUSES (budget was carved out of the "
                "transient class, never out of the refusal class)",
                classify_read_failure(stderr), "refusal")

        rc_b, out_b = run_main(empty_scope, {repo_path: None}, stderr=budget_403)
        chk("#1208 flow: a budget 403 fails CLOSED (rc 1) and reports BUDGET, with NO maintainer "
            "action item and NO false availability claim",
            (rc_b, "BUDGET —" in out_b, "REQUIRED maintainer settings" in out_b,
             "UNVERIFIED, not known-wrong" in out_b,
             "failed for an availability reason" in out_b, "TRANSIENT —" in out_b),
            (1, True, False, True, False, False))
        chk("#1208 flow: the budget report tells the operator NOT to retry, and says the wait is "
            "machine-cleared (this is the whole point — the old wording invited the retry)",
            ("DO NOT RE-RUN" in out_b, "MACHINE-CLEARED" in out_b.upper(),
             "no `Retry-After`" in out_b, "x-ratelimit-reset" in out_b), (True,) * 4)
        chk("#1208 flow: the budget report never echoes the raw stderr either",
            ("rate limit exceeded for installation" in out_b, "SENTINEL-STDERR" in out_b),
            (False, False))
        # KNOWN POSITIVE, on the budget path specifically. A genuine settings violation discovered
        # while the budget is gone must STILL refuse loudly with the maintainer wording — the
        # demotion is only ever "every failure is unverified", and this is the row that proves the
        # new branch did not widen it.
        rc_kp, out_kp = run_main(leaked, {repo_path: None}, stderr=budget_403)
        chk("#1208 KNOWN POSITIVE: a real repo-scope secret leak alongside a BUDGET-exhausted read "
            "still refuses LOUDLY with the maintainer remediation intact",
            (rc_kp, "REQUIRED maintainer settings" in out_kp,
             "REGISTRY_ADMIN_APP_KEY" in out_kp, "sentinel-private-key" in out_kp,
             "BUDGET —" in out_kp), (1, True, True, False, False))
        # #1190'S MESSAGE FIX, FROZEN. The transient wording was corrected once already (it used to
        # demand three repo-settings changes); it is validated in production and must not drift.
        # Pinned as a literal so a reflow, a reword, or a "helpful" merge of the two messages reds
        # THIS row and names what it broke.
        transient_out = run_main(empty_scope, {repo_path: None},
                                 stderr="gh: Bad Gateway (HTTP 502)")[1]
        chk("#1190 message fix PRESERVED byte-for-byte (the transient wording that replaced the "
            "spurious three-settings demand)",
            [line for line in transient_out.splitlines() if "TRANSIENT —" in line],
            ["::error::secrets-guard: TRANSIENT — 1 GitHub read(s) failed for an availability "
             "reason (repos/org/registry), so the settings above are UNVERIFIED, not known-wrong. "
             "This is NOT a settings finding and NO maintainer action is implied: the guard fails "
             "closed until a tick completes the reads, and recovers on its own when they do. If "
             "the dispatcher is also failing in PLAN, this is the same request-budget exhaustion "
             "— see scripts/dispatch-tick-floor.py (#819)."])
        # THE SHARED TAXONOMY — and the row that had to be DERIVED, not hand-listed.
        #
        # Every hand-written fixture above is satisfied by a private re-implementation: replacing
        # the shared call with an inline `"api rate limit" in stderr.lower()` passed the ENTIRE
        # suite (measured — mutant T7 survived a first round of this work). The hand-listed
        # examples all happen to contain that substring, so they cannot distinguish "uses the
        # shared taxonomy" from "happens to agree with it on the cases I thought of".
        #
        # So DERIVE the obligation from the shared marker set itself: every marker gh_403 knows
        # about must be recognised HERE. A private copy recognises only the markers whoever wrote
        # it happened to think of, and a marker added to gh_403 tomorrow extends this row
        # automatically instead of silently going unchecked on this side.
        assert gh_403.BUDGET_403_MARKERS, "an empty marker set would make the row below vacuous"
        chk("#1208: EVERY budget marker the shared taxonomy knows is recognised here — derived "
            "from gh_403.BUDGET_403_MARKERS, so an inline re-implementation that covers only the "
            "wordings someone remembered goes RED",
            {marker: classify_read_failure(f"gh: You have hit the {marker} limit. (HTTP 403)")
             for marker in gh_403.BUDGET_403_MARKERS},
            {marker: "budget" for marker in gh_403.BUDGET_403_MARKERS})
        chk("#1208: ...and the module those markers come from is the one plan-snapshot loads",
            (gh_403.classify_403_text is not None,
             classify_read_failure.__globals__["gh_403"].__name__),
            (True, "registry_gh_403_for_guard"))
        chk("#1208: the shared taxonomy's own self-test passes (this guard's classification now "
            "rests on it)", gh_403._self_test(), True)
        rc_garbled, _out = run_main("SENTINEL {not json", verified_docs)
        chk("flow: malformed ALL_SECRETS -> rc 1 (fail closed)", rc_garbled, 1)
        rc_repo, _out = run_main(empty_scope, verified_docs, registry_repo="bad repo$name")
        chk("flow: unsafe REGISTRY_REPO -> rc 1 before any API call",
            (rc_repo, calls), (1, []))
    finally:
        subprocess.run = real_run
        os.environ.pop("REGISTRY_REPO", None)
        os.environ.pop("ALL_SECRETS", None)

    print("dispatch-secrets-guard self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
