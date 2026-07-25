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
# Pure verdict helpers + a stubbed-gh flow (including value-never-echoed sentinels) run under
# --self-test (registry-selftest gate).
import itertools
import json
import os
import re
import subprocess
import sys

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
# The guard job must EXECUTE the verifier. Matches `python3 [<prefix>/]scripts/dispatch-secrets-guard.py`
# in a step's `run:` body — the live job uses the `registry/` sparse-checkout prefix, the synthetic
# fixtures none. Group 1 is the argument tail, which separates the `--self-test` (static assertions)
# invocation from the bare (live settings verification) one; BOTH are required.
GATE_VERIFIER_RE = re.compile(
    r"(?:^|[;&|]\s*|\s)python3\s+(?:[\w./$~{}-]*/)?scripts/dispatch-secrets-guard\.py([^\n]*)")


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


# Atoms with a KNOWN constant truth value. Everything else is a FREE variable (see
# if_condition_admits): `always()` genuinely is always true, and a bare `true`/`false` literal is
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
    fixed, free = {}, []
    for token in tokens:
        if not isinstance(token, tuple):
            continue
        atom = token[1]
        if atom in fixed or atom in free:
            continue
        if false_atom_re.search(atom):
            fixed[atom] = False
        elif atom.strip().lower() in _IF_CONSTANT_ATOMS:
            fixed[atom] = _IF_CONSTANT_ATOMS[atom.strip().lower()]
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


def guard_verifier_invocations(guard_doc):
    """Pure: (self_test_steps, verify_steps, guarded_steps) over a PARSED guard job — the step
    indices whose `run:` invokes this script with `--self-test`, without it, and (third element) the
    indices of ANY invoking step that carries a step-level `if:`.

    A step-level `if:` is reported because it is the same bypass as #621 mutation (a) wearing a
    different hat: `if: false` (or any condition) on the invoking step leaves the job green, the
    dependency satisfied, and the verifier unrun."""
    self_tests, verifies, conditional = [], [], []
    for index, step in enumerate(_job_steps(guard_doc)):
        run = step.get("run")
        if not isinstance(run, str):
            continue
        tails = GATE_VERIFIER_RE.findall(run)
        if not tails:
            continue
        for tail in tails:
            (self_tests if "--self-test" in tail else verifies).append(index)
        if step.get("if") is not None:
            conditional.append(index)
    return tuple(self_tests), tuple(verifies), tuple(conditional)


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
    self_tests, verifies, conditional = guard_verifier_invocations(guard_doc)
    if not verifies or not self_tests:
        missing = " and ".join(
            part for part, present in (("`dispatch-secrets-guard.py` (the live settings "
                                        "verification)", verifies),
                                       ("`dispatch-secrets-guard.py --self-test` (the static "
                                        "workflow-shape assertions)", self_tests)) if not present)
        return False, (
            f"`{GATE_GUARD_JOB}` never invokes {missing} in any step's `run:` — the job exists, is "
            "gated on, and is green, and it VERIFIES NOTHING. Every other property of this contract "
            "is satisfied by an empty job of the right name, which is why replacing these "
            "invocations with `true` had to become a red tick")
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
WRITEBACK_STEP_RE = re.compile(
    r"(?:^|[;&|]\s*|\s)bash\s+(?:\S*/)?scripts/worker-live\.sh\s+write-back\b")
# The atom whose falsity must NOT make the write-back unreachable: "the credential-prepare step
# succeeded". Matches `steps.<id>.outcome == 'success'` / `.conclusion == 'success'` for the prepare
# step under either quote style, with or without spaces.
PREPARE_SUCCESS_RE = re.compile(
    r"steps\s*\.\s*prepare\s*\.\s*(?:outcome|conclusion)\s*==\s*['\"]success['\"]")


def rotation_writeback_reachable_verdict(workflow_docs):
    """Pure: (ok, reason). In EVERY workflow that runs `worker-live.sh write-back`, that step's `if:`
    must still be able to run when the credential-prepare step did NOT succeed.

    Evaluated with the same polarity primitive as the secret-exfil gate, in the opposite direction:
    set `steps.prepare.outcome == 'success'` FALSE, leave every other atom TRUE, and require the
    condition to remain satisfiable. Fail directions, both deliberate:
      * a step whose condition cannot be PARSED is a refusal (unlike the gate, where unparseable
        means "cannot prove it gates"; here unparseable means "cannot prove the compensation is
        reachable", and an unpersisted rotation is unrecoverable);
      * finding ZERO write-back steps across the documents is a refusal — the step was renamed or
        removed and this assertion would otherwise pass vacuously, which is exactly how #614's gap
        survived its own review."""
    if not workflow_docs:
        return False, "no workflow documents to scan (fail closed)"
    found = []
    for filename in sorted(workflow_docs):
        jobs = workflow_job_docs(workflow_docs[filename])
        if jobs is None:
            continue     # not every workflow has a parseable jobs block worth scanning here
        for job_name, job_doc in sorted(jobs.items()):
            for index, step in enumerate(_job_steps(job_doc)):
                run = step.get("run")
                if not isinstance(run, str) or not WRITEBACK_STEP_RE.search(run):
                    continue
                where = f"{filename}::{job_name} step {index}"
                found.append(where)
                condition = step.get("if")
                if condition is None:
                    continue        # unconditional: maximally reachable
                admits, parsed, detail = if_condition_admits(condition, PREPARE_SUCCESS_RE)
                if not parsed:
                    return False, (
                        f"{where}: the rotation write-back's `if:` ({condition!r}) cannot be "
                        f"evaluated ({detail}), so its reachability from the credential-prepare "
                        "FAILURE path is unprovable (fail closed)")
                if not admits:
                    return False, (
                        f"{where}: the rotation write-back can ONLY run when the credential-prepare "
                        f"step succeeded (`if:` = {condition!r}). The host-side pre-flight consumes "
                        "the stored ONE-TIME-USE refresh token EARLY inside that step, so every "
                        "later failure in it (the no-leak assertion, the tamper baseline, the pinned "
                        "CLI install, the $GITHUB_ENV export) discards a grant the provider has "
                        "already rotated — old one spent, new one thrown away, account permanently "
                        "dead until an interactive re-mint (#614; same class as #604's root cause). "
                        "Key the condition to `always()` plus the account SELECTION, and let "
                        "worker-live.sh's rotation marker decide whether there is anything to "
                        "persist")
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


def _api(path):
    """Read-only `gh api` GET. Returns the parsed JSON document, or None on any failure —
    sanitized: neither stderr nor the payload is ever echoed (GH_DEBUG=api can echo request
    bodies; an error page is remote-controlled content)."""
    result = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    if result.returncode != 0:
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

    repo_doc = _api(f"repos/{repo}")
    default_branch = repo_doc.get("default_branch") if isinstance(repo_doc, dict) else None
    if not isinstance(default_branch, str) or not default_branch:
        failures.append("cannot resolve the repository default branch (fail closed)")
    else:
        environment_doc = _api(f"repos/{repo}/environments/{ENVIRONMENT}")
        if environment_doc is None:
            failures.append(f"environment `{ENVIRONMENT}` is missing or unreadable")
        else:
            policies_doc = _api(
                f"repos/{repo}/environments/{ENVIRONMENT}/deployment-branch-policies")
            policy_ok, reason = branch_policy_verdict(
                environment_doc, policies_doc, default_branch)
            if not policy_ok:
                failures.append(f"environment `{ENVIRONMENT}`: {reason}")

    if failures:
        for failure in failures:
            print(f"::error::secrets-guard: {failure}")
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

    # The human-arm trust surface, derived from the TWO live sources (issue #166: the policy list
    # is a per-target EXTENSION unioned onto worker-pr.py's mandatory floor). #528 wrapped this in
    # a broad `except (OSError, KeyError, TypeError, AttributeError, ImportError)` that fell back
    # to EMPTY tuples — so on the guard job's sparse checkout, where neither file is present, both
    # assertions below turned into a 22-script "outside the trust surface" verdict rather than a
    # readable "these inputs are missing". The failure reason is now CAPTURED and asserted on its
    # own, so a derivation fault can never again be mistaken for a policy gap.
    import tomllib
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    derivation_error = None
    policy_surfaces = ()
    default_surfaces = ()
    try:
        with open(os.path.join(repo_root, "scripts", "worker-pr.py"), encoding="utf-8") as handle:
            default_surfaces = trust_surface_from_worker_pr(handle.read())
        with open(os.path.join(repo_root, "policy", "repos.toml"), "rb") as handle:
            policy_doc = tomllib.load(handle)
        policy_surfaces = tuple(policy_doc["repos"]["jeswr/agent-account-registry"]["readiness"][
            "security_paths"])
        if not policy_surfaces:
            raise ValueError("policy/repos.toml readiness.security_paths is empty")
    except (OSError, KeyError, TypeError, AttributeError, ValueError,
            SyntaxError, tomllib.TOMLDecodeError) as error:
        derivation_error = f"{type(error).__name__}: {error}"
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
    chk("WRITE-BACK (LIVE): the rotation write-back is reachable when the credential-prepare step "
        "FAILED, in every lane that runs it (#614: a compensating action gated on the success of "
        "the step it compensates for is no compensation at all)",
        rotation_writeback_reachable_verdict(live_docs), (True, "ok"))
    # THE MUTANT: success-only reachability, exactly as #614 shipped it. Both lanes, independently.
    for lane in ("worker.yml", "review-fix.yml"):
        mutant_docs = dict(live_docs)
        mutant_docs[lane] = mutant_docs[lane].replace(
            "steps.selected.outcome == 'success'", "steps.prepare.outcome == 'success'")
        chk(f"WRITE-BACK: {lane} reverted to `steps.prepare.outcome == 'success'` -> REFUSE "
            "(one-time-use grant spent, rotated grant discarded, account permanently dead)",
            rotation_writeback_reachable_verdict(mutant_docs)[0], False)
    # A step-level `if:` that merely MENTIONS the prepare step is not the same as requiring it — the
    # polarity evaluation, not a substring test, decides (same primitive as the gate contract).
    for condition, reachable in (
            (None, True),
            ("${{ always() }}", True),
            ("${{ always() && steps.selected.outcome == 'success' }}", True),
            ("${{ always() && steps.prepare.outcome == 'success' }}", False),
            ("${{ steps.prepare.conclusion == 'success' }}", False),
            ("${{ always() && steps.prepare.outcome != 'success' }}", True),
            ("${{ always() && (steps.prepare.outcome == 'success' || "
             "steps.preflight.outputs.rotated == 'true') }}", True)):
        synthetic = ["jobs:", "  run:", "    steps:"]
        if condition is not None:
            synthetic.append(f"      - if: {condition}")
            synthetic.append("        run: bash registry/scripts/worker-live.sh write-back")
        else:
            synthetic.append("      - run: bash registry/scripts/worker-live.sh write-back")
        chk(f"WRITE-BACK: `if: {condition}` keeps the write-back reachable on a prepare FAILURE",
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

    def run_reconcile(mode, secret_ref="ACCT07_TOKEN", registry_pat="sentinel-registry-pat"):
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
                         "request_issue: 42\n")
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
            proc = subprocess.run(["bash", "-c", reconcile_script],
                                  env=env, capture_output=True, text=True)
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
        def __init__(self, rc=0, stdout=""):
            self.returncode = rc
            self.stdout = stdout
            self.stderr = "SENTINEL-STDERR"

    calls = []
    responses = {}

    def fake_run(cmd, capture_output=False, text=False):
        calls.append(list(cmd))
        return responses.get(cmd[2], _Result(1))

    repo = "org/registry"
    repo_path = f"repos/{repo}"
    env_path = f"{repo_path}/environments/{ENVIRONMENT}"
    policies_path = f"{env_path}/deployment-branch-policies"

    def run_main(all_secrets, docs, registry_repo=repo):
        calls.clear()
        responses.clear()
        for path, doc in docs.items():
            responses[path] = _Result(0, json.dumps(doc)) if doc is not None else _Result(1)
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
        rc_branch, _out = run_main(empty_scope, {repo_path: None})
        chk("flow: unreadable default branch -> rc 1 (fail closed)", rc_branch, 1)
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
