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
#      CUSTOM deployment-branch policy naming exactly the default branch, `branch` type only:
#      protected-branches mode admits every protected branch (an admin-configurable SET, not
#      the default branch), and a `tag`-type policy admits a collaborator-created tag of the
#      same name pointing at arbitrary code. A kept-binding attacker copy at any other ref is
#      then refused server-side.
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
# SET-UP-ACCOUNT SLOT-UNION CONTRACT (sol round 6 on the #275 PR, finding 3): post-#101 the
# ACCTNN_TOKEN secrets live in the dispatch-secrets ENVIRONMENT, and set-up-account.yml's store
# step derives its slot-allocation union BEFORE creating the IRREVERSIBLE acct-claims ref. That
# union is pure workflow-shell (no script seam), so this guard's self-test statically asserts —
# same pattern as the dispatch.yml permission pin — that the store step enumerates ALL FOUR
# paginated listings (claim refs, acctNN issues in any state, repo-scope secrets, AND the
# dispatch-secrets environment secrets); dropping the env listing would make an env-only token
# invisible and permanently burn the claimed slot. set-up-account.yml ships in the guard job's
# sparse checkout so the assertion also runs live every tick.
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
    exactly one `branch`-type policy naming the default branch. Everything else — all-branches
    default, protected-branches mode, tag-type entries, extra/wrong names, malformed docs —
    is a refusal with the specific reason."""
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
        if entry.get("type", "branch") != "branch":
            return False, (f"policy type {entry.get('type')!r} is not 'branch' (a tag-type "
                           "policy admits collaborator-created tags at arbitrary commits)")
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


def setup_account_store_union_paths(workflow_text):
    """Pure: extract the `gh api --paginate` API paths the set-up-account store step (`id:
    store`) issues, or None when the step cannot be located (callers treat None as a failure —
    fail closed). The union is pure workflow-shell — there is no script seam to unit-test — so,
    exactly like `workflow_guard_permissions` above, this is a deliberately NARROW,
    dependency-free line parser over the one step this repo controls, not a general YAML
    reader; reshaping the step out of recognition goes red in the self-test rather than
    silently passing."""
    lines = workflow_text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip() == "id: store":
            start = index
            break
    if start is None:
        return None
    paths = []
    for line in lines[start + 1:]:
        if line.startswith("      - name:"):
            break  # dedented into the next step
        paths.extend(re.findall(
            r'gh api --paginate "repos/\$\{\{ github\.repository \}\}/([^"]+)"', line))
    return paths


def setup_account_union_verdict(paths):
    """Pure: (ok, reason). The store step's pre-claim union must enumerate EVERY required
    listing (claim refs, acctNN issues in any state, and ACCTNN_TOKEN secret names at BOTH the
    repository scope and the dispatch-secrets environment), each via `gh api --paginate`.
    A missing store step or any absent listing is a refusal naming what is missing."""
    if paths is None:
        return False, "store step (`id: store`) not found in set-up-account.yml (fail closed)"
    missing = sorted(set(SETUP_ACCOUNT_UNION_REQUIRED) - set(paths))
    if missing:
        return False, ("pre-claim slot union is missing paginated listing(s): "
                       + ", ".join(missing)
                       + " — an unseen slot is silently treated as free and the irreversible "
                       "acct-claims ref burns it")
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

    # Static set-up-account slot-union contract (sol round 6 on the #275 PR, finding 3). The
    # broker's pre-claim union is pure workflow-shell (no script seam), so — following the
    # dispatch.yml permission pin above and migrate-secrets.sh's workflow mint contract — it is
    # asserted statically over the workflow text: dropping ANY of the four paginated listings
    # (claim refs / acctNN issues / repo-scope secrets / dispatch-secrets ENV secrets) goes red
    # here. set-up-account.yml ships in the guard job's sparse checkout so this also runs live
    # every tick.
    union_sample = "\n".join([
        "      - name: Claim slot atomically",
        "        id: store",
        "        run: |",
        '          claim_nums=$(gh api --paginate "repos/${{ github.repository }}/git/matching-refs/acct-claims/" \\',
        "                 --jq '.[].ref')",
        '          issue_nums=$(gh api --paginate "repos/${{ github.repository }}/issues?state=all&per_page=100" --jq .)',
        '          secret_nums=$(gh api --paginate "repos/${{ github.repository }}/actions/secrets?per_page=100" --jq .)',
        '          env_secret_nums=$(gh api --paginate "repos/${{ github.repository }}/environments/dispatch-secrets/secrets?per_page=100" --jq .)',
        "      - name: Validate the registration",
        '        run: gh api --paginate "repos/${{ github.repository }}/not/part/of/the/store/step"',
    ])
    chk("setup-account parse: extracts exactly the store step's paginated paths (next step ignored)",
        setup_account_store_union_paths(union_sample),
        ["git/matching-refs/acct-claims/", "issues?state=all&per_page=100",
         "actions/secrets?per_page=100",
         "environments/dispatch-secrets/secrets?per_page=100"])
    chk("setup-account union: all four listings present -> ok",
        setup_account_union_verdict(setup_account_store_union_paths(union_sample)),
        (True, "ok"))
    dropped_env = "\n".join(line for line in union_sample.splitlines()
                            if "environments/dispatch-secrets/secrets" not in line)
    verdict_dropped = setup_account_union_verdict(setup_account_store_union_paths(dropped_env))
    chk("setup-account union: env-secret listing dropped -> refuse, missing path NAMED",
        (verdict_dropped[0],
         "environments/dispatch-secrets/secrets?per_page=100" in verdict_dropped[1]),
        (False, True))
    chk("setup-account union: missing store step -> refuse (fail closed)",
        setup_account_union_verdict(setup_account_store_union_paths("jobs:\n  login:\n"))[0],
        False)
    setup_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              os.pardir, ".github", "workflows", "set-up-account.yml")
    try:
        with open(setup_path, encoding="utf-8") as handle:
            live_union_verdict = setup_account_union_verdict(
                setup_account_store_union_paths(handle.read()))
    except OSError:
        live_union_verdict = (False, "set-up-account.yml unreadable (fail closed)")
    chk("workflow: set-up-account pre-claim union enumerates BOTH secret scopes + claims + issues, all paginated",
        live_union_verdict, (True, "ok"))

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
