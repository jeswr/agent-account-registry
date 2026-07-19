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
# header); an exception whose job stops consuming, disappears, or gains the binding goes red as
# STALE so the allowlist can never silently cover a future job. Two env-scoped WRITES are pinned
# the same way: the broker's final store (set-up-account.yml `gh secret set "$SECRET_NAME" ...
# --env dispatch-secrets`) and the rotation write-back (worker-live.sh `... secret set
# "$secret_ref" ... --env dispatch-secrets`) — a repo-scope write would re-trip the guard AND
# strand the env-bound consumers on the pre-rotation credential. The workflows directory and
# scripts/worker-live.sh ship in the guard job's sparse checkout so both contracts also run live
# every tick.
#
# Pure verdict helpers + a stubbed-gh flow (including value-never-echoed sentinels) run under
# --self-test (registry-selftest gate).
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
    refusal (fail closed); every refusal names what is missing."""
    if step_lines is None:
        return False, "store step (`id: store`) not found in set-up-account.yml (fail closed)"

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
# allowlist entry nobody needs is a future bypass wearing that job's name).
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


def secret_env_write_verdict(text, secret_arg, where):
    """Pure: (ok, reason). Locates every `gh secret set <secret_arg> ...` invocation in `where`
    (comment lines ignored, backslash continuations joined) and requires each to carry
    `--env dispatch-secrets`: a repo-scope write would re-trip the empty-repo-scope check on
    the next tick AND strand the env-bound consumers on the pre-rotation credential (they
    resolve secrets from the environment, never repo scope). A write site that cannot be
    located is a refusal — reshaping it out of recognition must surface here (fail closed)."""
    lines = text.splitlines()
    found = False
    for index, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            continue
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
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got} (want {want})")

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
