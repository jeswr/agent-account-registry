#!/usr/bin/env python3
# [OPUS-5] The MINTING half of the #657 orchestrator-PR review admission (design record
# research/657-orchestrator-provenance-minting.md; the admission half is #759 + #821).
#
# WHAT THIS IS FOR. `enumerate_review_items` admits a PR to the autonomous review lane only when
# a REGISTRY provenance record exists for it. worker.yml's `provenance` job writes that record for
# every worker PR; nothing writes one for a PR the orchestrator authored itself, so the whole
# orchestrator-authored population is fail-closed invisible to every path that can run a model
# against a PR. #759 and #821 wired the code path that would admit such a PR; this is the ONE
# supported writer of the record it needs.
#
# WHAT IT IS NOT. It is not an enrolment mechanism. `review_enrolment_authors` — the
# master-protected, branch-protected half — is the set of logins that may ever be admitted, and
# this script REFUSES to mint for any login not already in it. So minting can never widen the
# allowlist; it can only act inside one. Both halves are still required at every consumer.
"""mint-provenance — write the `orchestrator`-class provenance record for ONE orchestrator PR.

Identity source (the ONLY one): the LIVE GitHub API read of the PR itself, performed by this
script inside a registry Actions run. There is deliberately no operator-supplied identity:

  pr_number         the PR the run was pointed at, re-read live and re-validated
  head_sha_at_open  the head sha the API reports for that PR AT MINT TIME
  impl_account_h    sha256("orchestrator:<live PR author login>" + ':' + PROVENANCE_SALT)[:16]
  impl_provider     DERIVED from the target's protected routing catalog for `--impl-alias`,
                    and REFUSED unless it is `anthropic` (see ORCHESTRATOR_IMPL_PROVIDER)
  issue             the operator-named source issue, re-read live and re-validated
  recorded_at_run   `orchestrator:<this run>.<this attempt>`, built from the runner's own
                    GITHUB_RUN_ID/GITHUB_RUN_ATTEMPT — never from an argument

HONEST SCOPE. This is not an anti-forgery guarantee against a registry-write holder: anything that
can PUT to the `ledger` branch can write any record it likes, including a machine-shaped stamp
(orchestration/provenance/README.md says so, and issue #96 is why records live on an unprotected
branch at all). What this script guarantees is narrower and still worth having:

  * it is the only SUPPORTED writer, and it can only ever write the WEAKEST attestation class —
    the escalation to a machine class is refused at `stamp_admission_error`, with no input that
    could reach it;
  * every field it writes is either read from the live API or pinned by this file, so an operator
    cannot declare an identity;
  * it refuses every case it cannot classify, and a refusal leaves the PR exactly as it is today:
    no record, therefore not enumerated, therefore no lane traffic at all.

Privacy (locked decision 22a): the registry is PUBLIC, so the record stores only the salted hash,
and this script never prints the login it hashed alongside the hash.
"""

import argparse
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import NamedTuple

SCRIPTS_DIR = Path(__file__).resolve().parent


class MintError(RuntimeError):
    """A concise, credential-free operational error."""


# ---- WHAT THE RECORD MAY ASSERT ---------------------------------------------------------------
# The one provider this path will ever record. It is a PIN, not a default, and it is the reason
# design record §7.4 step 2 ("pin a CONSTANT reviewer side for the class") needs no changes at its
# five enforcement points: the lane picks the reviewer by INVERTING `impl_provider`
# (REVIEW_CHAIN = {"anthropic": ["sol", "luna"], "openai": ["opus5"]}), so a record that can only
# ever say `anthropic` can only ever resolve to the openai review side — at the REVIEW_CHAIN
# subscript, at the `claim_provider == impl_provider` violation, at review-fix.yml's inline chain
# table and both its re-assertions. Pinning the WRITER is one enforcement point instead of five,
# and it cannot be half-applied.
#
# The pin is also why an openai-harness orchestrator must not use this path: it would be a false
# declaration, and the review would be same-provider. `alias_mint_refusal` refuses rather than
# recording it — design record §3's residual risk is an ADVISORY COMMENT, and this keeps even that
# from being manufactured by the supported writer.
ORCHESTRATOR_IMPL_PROVIDER = "anthropic"

# The account-hash preimage is domain-separated from the worker lane's `acctNN` handles. The
# reviewer != implementer assertion at CLAIM hashes a live account handle the same way and
# compares; separating the namespaces means no future account handle can ever collide with a
# login and make an orchestrator PR look like its own reviewer.
ACCOUNT_HASH_DOMAIN = "orchestrator"

# The worker lane's branch NAMESPACE, matched as a prefix (deliberately wider than
# dispatch-claim.HEAD_REF_RE, which requires the full `issue-<N>-` shape). A record minted here
# for a branch in that namespace could collide with the record worker.yml's `provenance` job will
# later try to write for the same PR — records are create-only, so the worker write would fail
# permanently and a legitimate worker PR would be stranded. This path never touches that namespace.
WORKER_NAMESPACE_RE = re.compile(r"^sparq-agent/")

# review-fix.yml's resolve step rejects any `area:*` label outside this atom shape with a
# SystemExit, on EVERY dispatch — so an unsafe area label on the bound issue is a per-tick failure
# loop, not a one-off. Refused here instead, where the refusal costs one un-enumerated PR.
SAFE_AREA = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")

REPO_RE = re.compile(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+")
SHA_RE = re.compile(r"[0-9a-f]{40}")


class MintDecision(NamedTuple):
    """The whole decision for one PR. `action` is one of ACTION_*; `document` is the record that
    would be (or was) written, and is None for every non-minting action."""

    action: str
    reason: str
    document: dict | None


ACTION_MINT = "mint"                       # nothing recorded yet; write it
ACTION_ALREADY = "already-minted"          # an identical orchestrator record is already present
ACTION_REFUSE = "refuse"                   # fail closed: leave the PR un-enumerated


# ---- module loading (same idiom as backfill-provenance.py) -------------------------------------
def _load_script_module(filename, module_name):
    import importlib.util

    path = SCRIPTS_DIR / filename
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise MintError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_worker_pr():
    return _load_script_module("worker-pr.py", "registry_worker_pr")


def _load_dispatch_claim():
    """The review loop's OWN taxonomy + admission (dispatch-claim) — IMPORTED, never replicated,
    so "what class did I write?" and "what class will be admitted?" cannot drift."""
    return _load_script_module("dispatch-claim.py", "registry_dispatch_claim")


def _load_policy_resolve():
    return _load_script_module("policy-resolve.py", "registry_policy_resolve")


def _load_lease_schema():
    """THE canonical `area:*` -> package reduction (lease_schema.plan_package). Imported for the
    same reason review-fix.yml's resolve step imports it: a second derivation is how a claim the
    dispatcher minted gets refused by its own adopt step, forever (registry issue #112)."""
    return _load_script_module("lease_schema.py", "registry_lease_schema")


# ---- pure decisions (every one unit-tested by --self-test) -------------------------------------
def mint_stamp(run_id, run_attempt, orchestrator_class):
    """The attestation stamp for THIS minting run — `<class>:<run>.<attempt>` — or None when the
    runner did not supply a usable run identity.

    Built from the runner's own environment, never from an argument: there is no CLI or workflow
    input on this path that can influence the attestation class, so an operator cannot ask for a
    machine-attested record. Fail closed: a missing or non-numeric run identity yields None, and
    the caller refuses."""
    if not isinstance(run_id, str) or not re.fullmatch(r"[0-9]+", run_id):
        return None
    if not isinstance(run_attempt, str) or not re.fullmatch(r"[0-9]+", run_attempt):
        return None
    return f"{orchestrator_class}:{run_id}.{run_attempt}"


def stamp_admission_error(stamp, attestation_class, orchestrator_class):
    """THE PRIVILEGE BOUNDARY of this script: why `stamp` may NOT be written, or None.

    A provenance record's `recorded_at_run` names the trust basis its implementer identity rests
    on, and the two MACHINE classes (`worker-run`, `backfill`) are admitted by every consumer
    INCLUDING the arm. This writer may only ever produce the weakest, self-attested class — which
    `worker-pr.ready_and_arm` refuses outright (#821). Asserted POSITIVELY, against the shared
    taxonomy (`dispatch-claim.provenance_attestation_class`): an unrecognised stamp, or a
    recognised stamp of any other class, is refused. There is no path that reaches this with a
    machine stamp today; the check exists so that adding one would go red here rather than
    silently minting a record that can authorise a merge."""
    attestation = attestation_class({"recorded_at_run": stamp})
    if attestation is None:
        return ("the minted attestation stamp is not in a recognised shape (recorded_at_run must "
                "name the host-side run that wrote the record)")
    if attestation != orchestrator_class:
        return (f"refusing to mint a {attestation!r}-attested record: this writer may only ever "
                f"produce the self-attested {orchestrator_class!r} class, which the arm refuses")
    return None


def pr_mint_refusal(repo, pull, enrolled_authors):
    """Why the live PR payload must NOT be minted for, or None.

    TOTAL and fail-closed: every malformed shape is a refusal, never a raise. The order matters
    and mirrors the consumers — the FORK GATE is first and is the one predicate no part of this
    feature may ever reach past."""
    if not isinstance(pull, dict):
        return "the pull request payload is malformed"
    number = pull.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
        return "the pull request number is malformed"
    if pull.get("state") != "open":
        return "the pull request is not open"
    head = pull.get("head")
    head = head if isinstance(head, dict) else {}
    head_repo = head.get("repo")
    if (head_repo or {}).get("full_name") != repo:
        return ("the pull request head is a fork (or is unreadable); a fork head is "
                "attacker-controlled and is never recorded, admitted or enrolled")
    ref = str(head.get("ref", ""))
    if WORKER_NAMESPACE_RE.match(ref):
        return ("the head branch is in the worker lane's `sparq-agent/` namespace; worker.yml's "
                "provenance job owns that population and records are create-only, so minting "
                "here would permanently strand the worker's own record")
    sha = str(head.get("sha", ""))
    if not SHA_RE.fullmatch(sha):
        return "the pull request head sha is missing or malformed"
    if pull.get("draft") is True:
        return ("the pull request is a DRAFT; groom's stale-draft carve-out reads "
                "is_enumerable_provenance, which has no orchestrator opt-in, so a drafted "
                "orchestrator PR would be terminally needs:user-parked by age instead of reviewed")
    login = str((pull.get("user") or {}).get("login", ""))
    if not login:
        return "the pull request author login is unreadable"
    if login.endswith("[bot]"):
        # policy-resolve already refuses a `[bot]` login in review_enrolment_authors, so this can
        # only fire if that validation were bypassed. Independent, and cheap: a bot-authored
        # record on this path would hand an App's PRs a waiver of the author gate.
        return "the pull request author is a [bot]; a [bot] login can never be enrolled"
    if not enrolled_authors:
        return (f"{repo} enrols no review authors: `review_enrolment_authors` is empty in "
                "policy/repos.toml (the master-protected half), so nothing may be minted")
    if login.casefold() not in {author.casefold() for author in enrolled_authors
                                if isinstance(author, str)}:
        return (f"the pull request author is not in {repo}'s master-protected "
                "`review_enrolment_authors`")
    return None


def references_issue(pull, issue_number):
    """True when the PR's own title or body names `#<issue_number>`.

    The record BINDS a PR to a source issue, and that issue decides the lease partition the review
    reserves and the human-hold surface that can park it. Requiring the PR to name the issue keeps
    an operator typo from binding a review to an unrelated partition, and makes the record's
    assertion checkable from the PR alone. Word-bounded on both sides so `#41` does not match
    `#412` or `x#41`."""
    if not isinstance(pull, dict) or not isinstance(issue_number, int):
        return False
    text = f"{pull.get('title') or ''}\n{pull.get('body') or ''}"
    return bool(re.search(rf"(?<![0-9A-Za-z_])#{issue_number}(?![0-9])", text))


def issue_mint_refusal(issue_number, issue, pull, plan_package, global_package,
                       allow_global_partition=False):
    """Why the named source issue must NOT be bound into a record, or None.

    Each clause below corresponds to a way the review lane would MIS-BEHAVE on this record rather
    than simply refuse it, which is exactly the class of failure the #657 enable interlock exists
    to prevent:

    * a PULL REQUEST — PLAN's `_live_issue_labels` SKIPS pull-request rows while review-fix.yml's
      resolve step reads `repos/<repo>/issues/<n>` directly (which resolves a PR). The two would
      derive different `package` values and the adopt step compares them for EQUALITY, so the
      dispatcher's own claim would be refused every tick, forever (registry issue #112);
    * a CLOSED issue — PLAN reads only `state=open`, so a closed issue is absent from its label
      map; `busy_packages_of_pulls` then reserves the serializing partition for the PR;
    * an unsafe `area:*` atom — review-fix.yml's resolve step SystemExits on it, on every
      dispatch;
    * the SERIALIZING partition — zero or multiple `area:*` labels reduce to `__global__`
      (lease_schema.plan_package), which excludes against every other area and stops the whole
      fleet for the life of the review lease. This is the incident that took the fleet to zero
      worker launches for an hour (sparq#4185). Refused by DEFAULT; `allow_global_partition` is
      the operator's explicit, per-mint acceptance of that cost.

    A live human hold or machine park is also refused — those are clean exclusions at PLAN rather
    than loops, but a record minted into one is a record that does nothing, and saying so at mint
    time is better than a silent no-op."""
    if not isinstance(issue_number, int) or isinstance(issue_number, bool) or issue_number <= 0:
        return "the source issue number is malformed"
    if not isinstance(issue, dict):
        return "the source issue could not be read"
    if issue.get("number") != issue_number:
        return "the source issue read does not identify the requested issue"
    if "pull_request" in issue:
        return (f"#{issue_number} is a PULL REQUEST, not an issue: PLAN's issue-label map skips "
                "pull-request rows while review-fix.yml's resolve step reads it directly, so the "
                "two would derive different packages and the adopt step would refuse its own "
                "claim every tick")
    if issue.get("state") != "open":
        return (f"source issue #{issue_number} is not open: PLAN's label map covers open issues "
                "only, so the PR would reserve the serializing partition")
    labels = sorted({label.get("name") for label in (issue.get("labels") or [])
                     if isinstance(label, dict) and isinstance(label.get("name"), str)})
    holds = [label for label in labels if label.startswith("needs:")]
    if holds:
        return (f"source issue #{issue_number} carries a human hold ({', '.join(holds)}); the "
                "whole PR surface is human-owned")
    if "status:parked" in labels:
        return f"source issue #{issue_number} is machine-parked (status:parked)"
    areas = [label[5:] for label in labels if label.startswith("area:")]
    unsafe = sorted(area for area in areas if not SAFE_AREA.fullmatch(area))
    if unsafe:
        return (f"source issue #{issue_number} carries an unsafe area:* label ({unsafe[0]!r}); "
                "review-fix.yml's resolve step refuses it on every dispatch")
    package = plan_package(areas)
    if package == global_package and not allow_global_partition:
        return (f"source issue #{issue_number} reduces to the serializing {global_package} "
                f"partition ({len(areas)} area:* label(s)); a review lease on it excludes every "
                "other lane. Re-run with --allow-global-partition to accept that cost, or give "
                "the issue exactly one area:* label")
    if not references_issue(pull, issue_number):
        return (f"the pull request does not reference #{issue_number} in its title or body; the "
                "record must bind a PR to the issue it actually names")
    return None


def alias_mint_refusal(impl_alias, routing):
    """Why `impl_alias` must NOT be recorded, or None — and the point at which the provider stops
    being a declaration.

    The alias must be a safe atom (it flows into workflow outputs and model prompts) AND resolve
    in the TARGET's protected routing catalog, and the provider it resolves to must be
    ORCHESTRATOR_IMPL_PROVIDER. So the recorded provider is a CATALOG LOOKUP against a file in the
    target repository, not a field the operator fills in — and the constant review side follows
    from it."""
    if not isinstance(impl_alias, str) or not SAFE_AREA.fullmatch(impl_alias):
        return "the implementer alias is not a safe atom"
    models = (routing or {}).get("models") if isinstance(routing, dict) else None
    meta = models.get(impl_alias) if isinstance(models, dict) else None
    provider = meta.get("provider") if isinstance(meta, dict) else None
    if provider is None:
        return (f"the implementer alias {impl_alias!r} is not in the target's routing catalog "
                "(a deprecated or unknown alias is never recorded)")
    if provider != ORCHESTRATOR_IMPL_PROVIDER:
        return (f"the target's routing catalog maps {impl_alias!r} to provider {provider!r}; this "
                f"writer only ever records {ORCHESTRATOR_IMPL_PROVIDER!r}, which is what pins the "
                "review side to the opposite provider")
    return None


def identifying_fields(document):
    """A record's identity, i.e. everything except the per-mint attestation stamp. Two records
    with the same identifying fields are the same claim about the same PR at the same head."""
    return {key: value for key, value in (document or {}).items() if key != "recorded_at_run"}


def existing_record_verdict(body, document, attestation_class, orchestrator_class,
                            json_type_exact):
    """(action, reason) for a record that is ALREADY on the ledger for this PR.

    Idempotency lives here rather than in `worker-pr._registry_put_file` on purpose. That
    function's `_run_key_identity` only understands `<run>.<attempt>` and `backfill:<run>.<attempt>`
    stamps, so it reads any two orchestrator stamps as unequal and rejects a re-mint as "already
    exists with different content" — a scary, wrong error for the ordinary case of re-running the
    workflow. The semantics genuinely differ: for a worker record the run id is the AUDIT LINK to
    the log the identity was read from, so a different run is a different evidence source and must
    fail closed; for an orchestrator record the run merely says "a registry Actions run minted
    this", so a second mint of an IDENTICAL claim is the same claim.

    Everything else still fails closed: a record of any other attestation class, a record that is
    not valid JSON, or one whose identifying fields differ IN ANY WAY (JSON-type-exact, so a
    type-confused stored value cannot masquerade) is a REFUSAL for a human, never an overwrite.
    This script never rewrites a record."""
    try:
        stored = json.loads(body)
    except (ValueError, TypeError):
        return ACTION_REFUSE, ("a provenance record already exists for this PR and is not valid "
                               "JSON; a human must repair or remove it")
    if not isinstance(stored, dict):
        return ACTION_REFUSE, ("a provenance record already exists for this PR and is not a JSON "
                               "object; a human must repair or remove it")
    attestation = attestation_class(stored)
    if attestation != orchestrator_class:
        return ACTION_REFUSE, (
            f"a {attestation or 'unrecognised'}-attested provenance record already exists for "
            "this PR; records are create-only and this writer never overwrites one")
    if not json_type_exact(identifying_fields(stored), identifying_fields(document)):
        return ACTION_REFUSE, (
            "an orchestrator-attested record already exists for this PR with DIFFERENT "
            "identifying fields (head sha, issue, provider, alias or account hash); records are "
            "create-only, so a human must decide")
    return ACTION_ALREADY, "an identical orchestrator-attested record is already on the ledger"


def mint_decision(repo, pr_number, issue_number, impl_alias, enrolled_authors, routing, stamp,
                  salt, pull, issue, existing_body, *, allow_global_partition,
                  attestation_class, orchestrator_class, plan_package, global_package,
                  account_hash, json_type_exact):
    """THE decision, as one pure function of everything that was read. No I/O, never raises.

    Returns a MintDecision. Every refusal degrades to today's behaviour exactly: no record is
    written, so the PR is not enumerated, so no tick does anything about it — the failure mode is
    absence, never a per-tick refusal loop."""
    if not isinstance(repo, str) or not REPO_RE.fullmatch(repo):
        return MintDecision(ACTION_REFUSE, "the target repository is malformed", None)
    if not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number <= 0:
        return MintDecision(ACTION_REFUSE, "the pull request number is malformed", None)
    if not isinstance(salt, str) or not salt:
        return MintDecision(ACTION_REFUSE,
                            "PROVENANCE_SALT is required (records store only the salted hash)",
                            None)
    stamp_error = stamp_admission_error(stamp, attestation_class, orchestrator_class)
    if stamp_error:
        return MintDecision(ACTION_REFUSE, stamp_error, None)
    alias_error = alias_mint_refusal(impl_alias, routing)
    if alias_error:
        return MintDecision(ACTION_REFUSE, alias_error, None)
    pr_error = pr_mint_refusal(repo, pull, enrolled_authors)
    if pr_error:
        return MintDecision(ACTION_REFUSE, pr_error, None)
    # The live payload is the authority on the PR's identity: the number the operator passed is
    # only ever used to FETCH it, and must match what came back. Without this a stale or
    # substituted payload could bind PR #7's head to PR #9's record path.
    if pull.get("number") != pr_number:
        return MintDecision(ACTION_REFUSE,
                            "the live pull request read does not identify the requested PR", None)
    issue_error = issue_mint_refusal(issue_number, issue, pull, plan_package, global_package,
                                     allow_global_partition=allow_global_partition)
    if issue_error:
        return MintDecision(ACTION_REFUSE, issue_error, None)
    login = str((pull.get("user") or {}).get("login", ""))
    document = {
        "pr_number": pr_number,
        "head_sha_at_open": str((pull.get("head") or {}).get("sha", "")),
        "impl_provider": ORCHESTRATOR_IMPL_PROVIDER,
        "impl_alias": impl_alias,
        "impl_account_h": account_hash(f"{ACCOUNT_HASH_DOMAIN}:{login}", salt),
        "issue": issue_number,
        "recorded_at_run": stamp,
    }
    if existing_body is not None:
        action, reason = existing_record_verdict(existing_body, document, attestation_class,
                                                 orchestrator_class, json_type_exact)
        return MintDecision(action, reason, document if action == ACTION_ALREADY else None)
    return MintDecision(ACTION_MINT, "no provenance record exists for this PR yet", document)


def admissible_by_the_review_lane(document, pr_number, admission_error):
    """Why the record this script is about to write would NOT be admitted by the review lane's own
    shared predicate (`provenance_admission_error(..., admit_orchestrator=True)`), or None.

    A LAST-MILE assertion against the consumer's definition, not this script's. Writing a record
    the lane then refuses is the exact silent-stall shape #657 is about, and it is cheap to prove
    the negative before the PUT rather than discover it a tick later."""
    return admission_error(document, pr_number, admit_orchestrator=True)


# ---- I/O ---------------------------------------------------------------------------------------
def _run_gh(args, *, check=True):
    result = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise MintError(f"GitHub request failed: {' '.join(args[:3])}")
    return result


def _gh_json(args):
    raw = _run_gh(args).stdout
    try:
        return json.loads(raw or "null")
    except json.JSONDecodeError as exc:
        raise MintError("GitHub returned malformed JSON") from exc


def effective_record_body(probe, ledger_ref):
    """The EFFECTIVE existing record for a PR — ledger-first, master as the pre-#96-outage
    fallback — or None when neither copy exists. Mirrors backfill-provenance.effective_record_body
    and groom's reader: `probe` returns (body, sha), (None, None) on a clean 404, and RAISES on
    anything else, so a transient/permission failure can never read as "nothing recorded" and let
    this script write a second, divergent record."""
    body, _sha = probe(ref=ledger_ref)
    if body is not None:
        return body
    body, _sha = probe(ref=None)
    return body


def mint(repo, pr_number, issue_number, impl_alias, registry_repo, routing, enrolled_authors,
         *, apply_changes=False, allow_global_partition=False, env=None,
         read_pull=None, read_issue=None, read_record=None, write_record=None,
         modules=None, log=print):
    """Read everything, decide once, and write at most one record. Returns the MintDecision.

    Every reader/writer is injectable so `--self-test` drives this exact orchestration — the call
    sites, not just the predicates. A dropped call here changes the returned decision."""
    env = os.environ if env is None else env
    worker_pr, dispatch_claim, lease_schema = modules or (
        _load_worker_pr(), _load_dispatch_claim(), _load_lease_schema())
    read_pull = read_pull or (lambda: _gh_json(["api", f"repos/{repo}/pulls/{pr_number}"]))
    read_issue = read_issue or (lambda: _gh_json(["api", f"repos/{repo}/issues/{issue_number}"]))
    record_path = worker_pr.provenance_path(repo, pr_number)
    if read_record is None:
        def read_record():
            return effective_record_body(
                lambda ref=None: worker_pr._probe_registry_file(registry_repo, record_path,
                                                                ref=ref),
                worker_pr.LEDGER_REF)

    stamp = mint_stamp(env.get("GITHUB_RUN_ID"), env.get("GITHUB_RUN_ATTEMPT"),
                       dispatch_claim.ORCHESTRATOR_CLASS)
    decision = mint_decision(
        repo, pr_number, issue_number, impl_alias, enrolled_authors, routing, stamp,
        env.get("PROVENANCE_SALT", ""), read_pull(), read_issue(), read_record(),
        allow_global_partition=allow_global_partition,
        attestation_class=dispatch_claim.provenance_attestation_class,
        orchestrator_class=dispatch_claim.ORCHESTRATOR_CLASS,
        plan_package=lease_schema.plan_package,
        global_package=lease_schema.GLOBAL_PACKAGE,
        account_hash=worker_pr.account_hash,
        json_type_exact=worker_pr._json_type_exact)
    if decision.action == ACTION_REFUSE:
        log(f"REFUSE {repo}#{pr_number}: {decision.reason}. Nothing is recorded, so the PR stays "
            "un-enumerated exactly as it is today.")
        return decision
    if decision.action == ACTION_ALREADY:
        log(f"skip {repo}#{pr_number}: {decision.reason}")
        return decision
    lane_error = admissible_by_the_review_lane(decision.document, pr_number,
                                               dispatch_claim.provenance_admission_error)
    if lane_error:
        reason = (f"the record this run would write is NOT admissible by the review lane "
                  f"({lane_error}); refusing to write a record that stalls")
        log(f"REFUSE {repo}#{pr_number}: {reason}")
        return MintDecision(ACTION_REFUSE, reason, None)
    document = decision.document
    if not apply_changes:
        log(f"DRY-RUN {repo}#{pr_number}: would mint {record_path} — "
            f"impl={document['impl_provider']}/{document['impl_alias']} "
            f"account_h={document['impl_account_h']} issue=#{document['issue']} "
            f"head={document['head_sha_at_open'][:8]} ({document['recorded_at_run']})")
        return decision
    writer = write_record or (lambda: worker_pr.provenance_record(
        registry_repo, repo, pr_number, document["head_sha_at_open"],
        document["impl_provider"], document["impl_alias"], document["impl_account_h"],
        document["issue"], document["recorded_at_run"]))
    writer()
    log(f"minted {record_path} for {repo}#{pr_number} ({document['recorded_at_run']}) — "
        "review-only: the arm refuses this class, a human arms it")
    return decision


# ---- workflow seam (PyYAML-parsed; a `run:` predicate is not a testable predicate) -------------
def _workflow(name):
    import yaml

    path = SCRIPTS_DIR.parent / ".github" / "workflows" / name
    assert path.is_file(), f"{name} not found for the workflow-seam check: {path}"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def mint_workflow_seam_report(workflow=None):
    """Structural findings about the LIVE mint-provenance.yml, each asserted by --self-test.

    Every finding is derived from the PARSED document, never a substring of the file: an `if:
    false`, a deleted step, a reordered command or a wrong-input binding (`APPLY: ${{
    inputs.allow_global_partition }}` is valid YAML and lints clean) all survive a grep and none
    survives this. `workflow` is injectable so the self-test can run a MUTANT TABLE over a copy of
    the real document instead of asserting the happy path only.

    The `run:` script is COMMENT-STRIPPED (dispatch-claim's audited, quote-aware stripper) before
    any fragment check. Measured on this file: without it, commenting the self-test invocation out
    left `self_test_before_mint` True — the token was still in the text. A wiring assertion may
    only ever be satisfied by CODE."""
    workflow = _workflow("mint-provenance.yml") if workflow is None else workflow
    strip = _load_dispatch_claim()._strip_script_comments
    # PyYAML parses a bare `on:` key as the boolean True.
    triggers = workflow.get("on") if "on" in workflow else workflow.get(True)
    inputs = (((triggers or {}).get("workflow_dispatch") or {}).get("inputs") or {})
    job = workflow["jobs"]["mint"]
    steps = job["steps"]
    step = next((s for s in steps
                 if "mint-provenance.py" in strip(str(s.get("run") or ""))), None)
    run = strip(str((step or {}).get("run") or ""))
    guard = str(job.get("if") or "")
    self_at = run.find("mint-provenance.py --self-test")
    invoke_at = run.find('mint-provenance.py "${args[@]}"')
    step_env = {key: str(value) for key, value in ((step or {}).get("env") or {}).items()}
    return {
        # The salt is a secret: a modified branch copy of this workflow must never see it.
        "job_ref_guarded": "github.ref ==" in guard and "default_branch" in guard,
        "job_environment": job.get("environment"),
        "contents_write": (job.get("permissions") or {}).get("contents"),
        # The identity source is the live API. This job must NOT be able to read run logs — that
        # is backfill's identity source, and granting it here would blur the two classes.
        "no_actions_permission": "actions" not in (job.get("permissions") or {}),
        "step_unconditional": step is not None and "if" not in step,
        "errexit": "set -euo pipefail" in run,
        "self_test_before_mint": 0 <= self_at < invoke_at,
        # Both write levers are conditional on their OWN input, and both default to the no-op.
        "apply_is_conditional": bool(
            re.search(r'\[\[\s*"\$APPLY"\s*==\s*"true"\s*\]\].*args\+=\(--apply\)', run)),
        "dispatch_default_is_dry_run": inputs.get("apply", {}).get("default"),
        "global_is_conditional": bool(
            re.search(r'\[\[\s*"\$ALLOW_GLOBAL"\s*==\s*"true"\s*\]\].*'
                      r'args\+=\(--allow-global-partition\)', run)),
        "global_default": inputs.get("allow_global_partition", {}).get("default"),
        # THE ATTESTATION-CLASS SEAM: the stamp is built from the runner's own run identity inside
        # the script. There must be NO workflow input, env binding or CLI argument on this path
        # that names a run key or an attestation class — that is what makes "this writer can only
        # produce the weakest class" a property of the whole path and not just of one function.
        "no_run_key_input": not any(
            re.search(r"run.?key|recorded.?at.?run|attestation", name, re.I)
            for name in list(inputs) + list(step_env)),
        "no_run_key_argument": not re.search(r"--run-key|--recorded-at-run|--attestation", run),
        "step_env_bindings": {key: step_env.get(key) for key in
                              ("TARGET_REPO", "PR_NUMBER", "ISSUE_NUMBER", "IMPL_ALIAS", "APPLY",
                               "ALLOW_GLOBAL")},
    }


# ---- self-test ---------------------------------------------------------------------------------
def _self_test():                                                       # noqa: C901 - flat asserts
    ok = True

    def check(name, got, want):
        nonlocal ok
        if got != want:
            ok = False
            print(f"FAIL {name}: got {got!r}, want {want!r}")
        else:
            print(f"ok   {name}")

    def rejects(name, needle, thunk):
        got = thunk()
        check(name, isinstance(got, str) and needle in got, True)

    dispatch_claim = _load_dispatch_claim()
    worker_pr = _load_worker_pr()
    lease_schema = _load_lease_schema()
    attestation_class = dispatch_claim.provenance_attestation_class
    orchestrator_class = dispatch_claim.ORCHESTRATOR_CLASS

    # ---- the stamp: the one thing no input may influence -------------------------------------
    # FROZEN literal, not a round-trip through the taxonomy: a rename of ORCHESTRATOR_CLASS would
    # keep a "build it then classify it" pair self-consistent and silently change what is written.
    check("the stamp is the frozen orchestrator shape",
          mint_stamp("30209757201", "2", orchestrator_class), "orchestrator:30209757201.2")
    check("...and it classifies as the orchestrator class",
          attestation_class({"recorded_at_run": mint_stamp("7", "1", orchestrator_class)}),
          orchestrator_class)
    for label, run_id, attempt in (("no run id", None, "1"), ("empty run id", "", "1"),
                                   ("non-numeric run id", "12a", "1"),
                                   ("no attempt", "12", None), ("non-numeric attempt", "12", "x"),
                                   ("injected shape", "12.1 orchestrator", "1")):
        check(f"the stamp fails closed on {label}",
              mint_stamp(run_id, attempt, orchestrator_class), None)

    # THE PRIVILEGE BOUNDARY. Every machine-shaped stamp is refused BY NAME, so a future input
    # that could reach this function cannot escalate the class it writes.
    check("an orchestrator stamp is admitted",
          stamp_admission_error("orchestrator:9.1", attestation_class, orchestrator_class), None)
    for stamp, why in (("9.1", "worker-run"), ("backfill:9.1", "backfill")):
        rejects(f"a {why}-shaped stamp is refused", "may only ever produce",
                lambda s=stamp: stamp_admission_error(s, attestation_class, orchestrator_class))
    for stamp in (None, "", "human:9.1", "orchestrator:9", "orchestrator:9.1.1", 91):
        rejects(f"an unrecognised stamp {stamp!r} is refused", "not in a recognised shape",
                lambda s=stamp: stamp_admission_error(s, attestation_class, orchestrator_class))

    # ---- the PR gates -------------------------------------------------------------------------
    repo = "o/r"
    enrolled = ("JesWR",)

    def pull(**over):
        base = {"number": 41, "state": "open", "draft": False,
                "title": "fix: something (#7)", "body": "closes #7",
                "user": {"login": "jeswr"},
                "head": {"ref": "fix/ordinary-branch", "sha": "a" * 40,
                         "repo": {"full_name": repo}}}
        head = {**base["head"], **over.pop("head", {})}
        return {**base, **over, "head": head}

    check("the enrolled orchestrator PR shape is minted for",
          pr_mint_refusal(repo, pull(), enrolled), None)
    check("...and the login match is case-insensitive (GitHub logins are)",
          pr_mint_refusal(repo, pull(user={"login": "JESWR"}), enrolled), None)
    rejects("a FORK head is refused", "fork",
            lambda: pr_mint_refusal(repo, pull(head={"repo": {"full_name": "attacker/r"}}),
                                    enrolled))
    rejects("...and an unreadable head repo is refused the same way", "fork",
            lambda: pr_mint_refusal(repo, pull(head={"repo": None}), enrolled))
    rejects("a worker-namespace head is refused", "sparq-agent/",
            lambda: pr_mint_refusal(repo, pull(head={"ref": "sparq-agent/issue-7-1-1"}), enrolled))
    rejects("...including a worker-namespace ref that HEAD_REF_RE would not match", "sparq-agent/",
            lambda: pr_mint_refusal(repo, pull(head={"ref": "sparq-agent/scratch"}), enrolled))
    rejects("a [bot] author is refused", "[bot] login can never be enrolled",
            lambda: pr_mint_refusal(repo, pull(user={"login": "some-app[bot]"}),
                                    ("some-app[bot]",)))
    rejects("a NON-enrolled author is refused", "not in o/r's master-protected",
            lambda: pr_mint_refusal(repo, pull(user={"login": "stranger"}), enrolled))
    rejects("an EMPTY allowlist refuses everything", "enrols no review authors",
            lambda: pr_mint_refusal(repo, pull(), ()))
    rejects("a closed PR is refused", "not open",
            lambda: pr_mint_refusal(repo, pull(state="closed"), enrolled))
    rejects("a DRAFT PR is refused", "DRAFT",
            lambda: pr_mint_refusal(repo, pull(draft=True), enrolled))
    rejects("a malformed head sha is refused", "head sha",
            lambda: pr_mint_refusal(repo, pull(head={"sha": "zz"}), enrolled))
    for bad in (None, [], {}, {"number": 0}, {"number": True}):
        check(f"a malformed pull payload {bad!r} is refused",
              isinstance(pr_mint_refusal(repo, bad, enrolled), str), True)

    # ---- the source issue --------------------------------------------------------------------
    def issue(**over):
        return {**{"number": 7, "state": "open", "labels": [{"name": "area:ci"}]}, **over}

    args = (lease_schema.plan_package, lease_schema.GLOBAL_PACKAGE)
    check("a single-area open issue the PR names is bound",
          issue_mint_refusal(7, issue(), pull(), *args), None)
    rejects("a PULL REQUEST as the source issue is refused", "PULL REQUEST",
            lambda: issue_mint_refusal(7, issue(pull_request={"url": "x"}), pull(), *args))
    rejects("a CLOSED source issue is refused", "not open",
            lambda: issue_mint_refusal(7, issue(state="closed"), pull(), *args))
    rejects("a needs:* held issue is refused", "human hold",
            lambda: issue_mint_refusal(
                7, issue(labels=[{"name": "area:ci"}, {"name": "needs:user"}]), pull(), *args))
    rejects("a status:parked issue is refused", "machine-parked",
            lambda: issue_mint_refusal(
                7, issue(labels=[{"name": "area:ci"}, {"name": "status:parked"}]), pull(), *args))
    rejects("an unsafe area:* atom is refused", "unsafe area",
            lambda: issue_mint_refusal(7, issue(labels=[{"name": "area:a b"}]), pull(), *args))
    rejects("ZERO area labels reduce to the serializing partition and are refused", "__global__",
            lambda: issue_mint_refusal(7, issue(labels=[]), pull(), *args))
    rejects("TWO area labels reduce to it too", "__global__",
            lambda: issue_mint_refusal(
                7, issue(labels=[{"name": "area:ci"}, {"name": "area:docs"}]), pull(), *args))
    check("...and --allow-global-partition is the explicit acceptance of that cost",
          issue_mint_refusal(7, issue(labels=[]), pull(), *args, allow_global_partition=True),
          None)
    rejects("an issue the PR does not reference is refused", "does not reference",
            lambda: issue_mint_refusal(7, issue(), pull(title="fix: x", body="no ref"), *args))
    rejects("a mismatched issue read is refused", "does not identify",
            lambda: issue_mint_refusal(7, issue(number=8), pull(), *args))
    for bad in (None, [], "7"):
        check(f"a malformed issue payload {bad!r} is refused",
              isinstance(issue_mint_refusal(7, bad, pull(), *args), str), True)
    # The reference regex is WORD-BOUNDED on both sides — the cheap version admits a prefix.
    check("#41 does not match #412", references_issue(pull(body="see #412"), 41), False)
    check("#41 does not match x#41", references_issue(pull(body="x#41"), 41), False)
    check("#41 matches (#41)", references_issue(pull(body="fixes (#41)."), 41), True)
    check("the title counts too", references_issue(pull(title="do #41", body=""), 41), True)

    # ---- the alias -> provider catalog lookup -------------------------------------------------
    routing = {"models": {"opus5": {"provider": "anthropic"}, "sol": {"provider": "openai"},
                          "weird": {"provider": None}}}
    check("an anthropic catalog alias is recorded", alias_mint_refusal("opus5", routing), None)
    rejects("an OPENAI catalog alias is refused", "only ever records 'anthropic'",
            lambda: alias_mint_refusal("sol", routing))
    rejects("an alias absent from the catalog is refused", "not in the target's routing catalog",
            lambda: alias_mint_refusal("fable", routing))
    rejects("an alias with no provider is refused", "not in the target's routing catalog",
            lambda: alias_mint_refusal("weird", routing))
    rejects("an unsafe alias is refused", "not a safe atom",
            lambda: alias_mint_refusal("a b", routing))
    for bad in (None, {}, {"models": None}, {"models": {"opus5": "anthropic"}}):
        check(f"a malformed routing document {bad!r} refuses the alias",
              isinstance(alias_mint_refusal("opus5", bad), str), True)

    # ---- the whole decision, and the record it produces ---------------------------------------
    decide_kwargs = dict(allow_global_partition=False, attestation_class=attestation_class,
                         orchestrator_class=orchestrator_class,
                         plan_package=lease_schema.plan_package,
                         global_package=lease_schema.GLOBAL_PACKAGE,
                         account_hash=worker_pr.account_hash,
                         json_type_exact=worker_pr._json_type_exact)

    def decide(**over):
        base = dict(repo=repo, pr_number=41, issue_number=7, impl_alias="opus5",
                    enrolled_authors=enrolled, routing=routing, stamp="orchestrator:9.1",
                    salt="s", pull=pull(), issue=issue(), existing_body=None)
        base.update(over)
        return mint_decision(**base, **decide_kwargs)

    minted = decide()
    check("a clean case mints", minted.action, ACTION_MINT)
    check("the record binds THIS PR at THIS head, with a pinned provider and a derived hash",
          {k: v for k, v in minted.document.items() if k != "impl_account_h"},
          {"pr_number": 41, "head_sha_at_open": "a" * 40, "impl_provider": "anthropic",
           "impl_alias": "opus5", "issue": 7, "recorded_at_run": "orchestrator:9.1"})
    check("the account hash is domain-separated from the acctNN namespace",
          minted.document["impl_account_h"], worker_pr.account_hash("orchestrator:jeswr", "s"))
    check("...and is NOT the bare-login hash a future acctNN could collide with",
          minted.document["impl_account_h"] == worker_pr.account_hash("jeswr", "s"), False)
    # THE BINDING #821 asserts at three waiver sites, proved from the other end: the record this
    # writer produces is the record for exactly one PR, and the lane's own predicate says so.
    check("the minted record is admitted by the review lane for ITS pr",
          dispatch_claim.provenance_admission_error(minted.document, 41, admit_orchestrator=True),
          None)
    check("...and is REFUSED for any other PR",
          isinstance(dispatch_claim.provenance_admission_error(minted.document, 42,
                                                               admit_orchestrator=True), str),
          True)
    check("...and the waiver decision itself refuses to waive #42's gates on #41's record",
          dispatch_claim.admits_orchestrator_pr(minted.document, 42, "jeswr", enrolled), False)
    # NON-VACUITY, and a deliberate freeze-control note. On a tree where the #657 enable interlock
    # is still armed (CLAIM unwired) `admits_orchestrator_pr` is constantly False, which would make
    # the line above prove nothing there — so state the ONLY discriminator that may make the
    # MATCHED pair False, and pin it. The two record-level assertions just above hold on either
    # tree and are the controls that never go quiet.
    check("...while the MATCHED pair is admitted exactly when the enable interlock permits it",
          dispatch_claim.admits_orchestrator_pr(minted.document, 41, "jeswr", enrolled),
          dispatch_claim.claim_admits_orchestrator_class())
    # And the class it wrote is still refused everywhere that is not the review admission.
    check("the minted record is NOT admitted without the opt-in (the default posture)",
          isinstance(dispatch_claim.provenance_admission_error(minted.document, 41), str), True)
    check("...and groom's draft carve-out still refuses it",
          dispatch_claim.is_enumerable_provenance(minted.document, 41), False)

    check("a live payload for a DIFFERENT PR is refused",
          decide(pr_number=42).action, ACTION_REFUSE)
    rejects("...by name", "does not identify the requested PR",
            lambda: decide(pr_number=42).reason)
    check("a missing salt refuses", decide(salt="").action, ACTION_REFUSE)
    check("a machine-shaped stamp refuses at the decision, not just at the helper",
          decide(stamp="9.1").action, ACTION_REFUSE)
    check("...and no document escapes a refusal", decide(stamp="9.1").document, None)
    check("an openai alias refuses at the decision", decide(impl_alias="sol").action,
          ACTION_REFUSE)
    check("a fork head refuses at the decision",
          decide(pull=pull(head={"repo": {"full_name": "attacker/r"}})).action, ACTION_REFUSE)
    check("a global-partition issue refuses at the decision",
          decide(issue=issue(labels=[])).action, ACTION_REFUSE)

    # Idempotency + create-only, at the decision.
    body = json.dumps(minted.document, indent=1, sort_keys=True) + "\n"
    check("an identical record already on the ledger is idempotent success",
          decide(existing_body=body).action, ACTION_ALREADY)
    rerun = decide(existing_body=json.dumps({**minted.document,
                                             "recorded_at_run": "orchestrator:99.1"}))
    check("...including one minted by a DIFFERENT run (the whole point of the local idempotency)",
          rerun.action, ACTION_ALREADY)
    for label, stored in (
            ("a different head", {**minted.document, "head_sha_at_open": "b" * 40}),
            ("a different issue", {**minted.document, "issue": 8}),
            ("a different provider", {**minted.document, "impl_provider": "openai"}),
            ("a type-confused pr_number", {**minted.document, "pr_number": True}),
            ("a MACHINE-attested record", {**minted.document, "recorded_at_run": "9.1"}),
            ("an unstamped record", {**minted.document, "recorded_at_run": "x"})):
        check(f"an existing record with {label} is REFUSED, never overwritten",
              decide(existing_body=json.dumps(stored)).action, ACTION_REFUSE)
    check("an existing record that is not JSON is refused",
          decide(existing_body="{").action, ACTION_REFUSE)
    check("an existing record that is not an object is refused",
          decide(existing_body="[]").action, ACTION_REFUSE)

    # ---- the ORCHESTRATION: mint()'s own call sites -------------------------------------------
    # Driving mint() end to end (not just its predicates) is what reds a DROPPED call site — the
    # failure class that left 8 survivors in #821's first mutation round.
    class _Env(dict):
        pass

    good_env = _Env({"GITHUB_RUN_ID": "555", "GITHUB_RUN_ATTEMPT": "1", "PROVENANCE_SALT": "s"})
    modules = (worker_pr, dispatch_claim, lease_schema)

    def run_mint(*, apply_changes=False, env=None, record=None, allow_global=False,
                 pull_over=None, issue_over=None):
        written = []
        decision = mint(repo, 41, 7, "opus5", "reg/istry", routing, enrolled,
                        apply_changes=apply_changes, allow_global_partition=allow_global,
                        env=env if env is not None else good_env,
                        read_pull=lambda: pull(**(pull_over or {})),
                        read_issue=lambda: issue(**(issue_over or {})),
                        read_record=lambda: record,
                        write_record=lambda: written.append("put"),
                        modules=modules, log=lambda *_a, **_k: None)
        return decision, written

    decision, written = run_mint()
    check("a DRY RUN decides to mint and writes NOTHING", (decision.action, written),
          (ACTION_MINT, []))
    check("...and the stamp came from the runner's own run identity",
          decision.document["recorded_at_run"], "orchestrator:555.1")
    decision, written = run_mint(apply_changes=True)
    check("--apply writes exactly one record", (decision.action, written), (ACTION_MINT, ["put"]))
    decision, written = run_mint(apply_changes=True, record=body)
    check("an already-minted PR writes nothing", (decision.action, written),
          (ACTION_ALREADY, []))
    decision, written = run_mint(apply_changes=True, env=_Env({"PROVENANCE_SALT": "s"}))
    check("a run with no runner run identity refuses and writes nothing",
          (decision.action, written), (ACTION_REFUSE, []))
    decision, written = run_mint(apply_changes=True,
                                 env=_Env({"GITHUB_RUN_ID": "555", "GITHUB_RUN_ATTEMPT": "1"}))
    check("a run with no salt refuses and writes nothing", (decision.action, written),
          (ACTION_REFUSE, []))
    decision, written = run_mint(apply_changes=True,
                                 pull_over={"head": {"repo": {"full_name": "attacker/r"}}})
    check("a fork head writes nothing", (decision.action, written), (ACTION_REFUSE, []))
    decision, written = run_mint(apply_changes=True, issue_over={"labels": []})
    check("a serializing-partition issue writes nothing", (decision.action, written),
          (ACTION_REFUSE, []))
    decision, written = run_mint(apply_changes=True, issue_over={"labels": []},
                                 allow_global=True)
    check("...and the override reaches the decision from mint()'s own argument",
          (decision.action, written), (ACTION_MINT, ["put"]))

    # The last-mile assertion is a REAL gate, not a comment: a document the lane would refuse
    # must not be written even if every predicate above passed.
    check("a record the lane would refuse is never written",
          admissible_by_the_review_lane({**minted.document, "impl_alias": "a b"}, 41,
                                        dispatch_claim.provenance_admission_error) is not None,
          True)

    # ---- the enrolment ordering constraint ----------------------------------------------------
    # This PR must not enable anything. Read the SHIPPED policy and assert it enrols nobody, so an
    # enabling line added alongside a minting change goes red here as well as in the two
    # interlocked self-tests.
    import tomllib

    policy_doc = tomllib.loads(
        (SCRIPTS_DIR.parent / "policy" / "repos.toml").read_text(encoding="utf-8"))
    policy_resolve = _load_policy_resolve()
    enrolled_live = sorted(
        (name, sorted(policy_resolve.review_enrolment_authors(name, policy_doc)))
        for name in (policy_doc.get("repos") or {}))
    check("the shipped policy enrols NO author (minting is inert until step 5)",
          [row for row in enrolled_live if row[1]], [])
    # NON-VACUOUS: the same reader, over the same LIVE rows, WOULD surface an enabled list — so
    # the assertion above is a fact about the shipped policy, not about a constantly-empty reader.


    probe_doc = copy.deepcopy(policy_doc)
    probe_repo = sorted(probe_doc["repos"])[0]
    probe_doc["repos"][probe_repo]["review_enrolment_authors"] = ["jeswr"]
    check("...and the same reader WOULD surface one",
          sorted(policy_resolve.review_enrolment_authors(probe_repo, probe_doc)), ["jeswr"])

    # ---- the workflow seam --------------------------------------------------------------------
    seam = mint_workflow_seam_report()
    check("the mint job refuses to run off the default ref", seam["job_ref_guarded"], True)
    check("the mint job takes the secret-scoped environment", seam["job_environment"],
          "dispatch-secrets")
    check("the mint job may write ledger contents", seam["contents_write"], "write")
    check("the mint job may NOT read run logs (that is backfill's identity source)",
          seam["no_actions_permission"], True)
    check("the mint step is unconditional", seam["step_unconditional"], True)
    check("the mint step is errexit", seam["errexit"], True)
    check("the self-test runs BEFORE the mint", seam["self_test_before_mint"], True)
    check("--apply is conditional on its own input", seam["apply_is_conditional"], True)
    check("dispatch defaults to a dry run", seam["dispatch_default_is_dry_run"], False)
    check("--allow-global-partition is conditional on its own input",
          seam["global_is_conditional"], True)
    check("...and defaults off", seam["global_default"], False)
    check("no workflow input or env names a run key / attestation class",
          seam["no_run_key_input"], True)
    check("no CLI argument names one either", seam["no_run_key_argument"], True)
    # THE WRONG-INPUT SEAM: `APPLY: ${{ inputs.allow_global_partition }}` is valid YAML, lints
    # clean, and silently turns a dry run into a write. Assert the exact expression each env name
    # is bound to, never merely that the name appears.
    check("every env name is bound to its OWN input expression", seam["step_env_bindings"], {
        "TARGET_REPO": "${{ inputs.target_repo }}",
        "PR_NUMBER": "${{ inputs.pr_number }}",
        "ISSUE_NUMBER": "${{ inputs.issue_number }}",
        "IMPL_ALIAS": "${{ inputs.impl_alias }}",
        "APPLY": "${{ inputs.apply }}",
        "ALLOW_GLOBAL": "${{ inputs.allow_global_partition }}",
    })

    # ---- the YAML-seam MUTANT TABLE ----------------------------------------------------------
    # Asserting the happy path proves the report can read a correct workflow, not that it would
    # catch a broken one. Every mutant below is a real way this workflow has been (or could be)
    # neutered; each must flip a NAMED finding. Two of them survive only as a COMMENT — the exact
    # shape that left this file's first self-test-ordering check vacuous.
    def mutated(edit):
        doc = copy.deepcopy(_workflow("mint-provenance.yml"))
        edit(doc)
        return mint_workflow_seam_report(doc)

    def mint_step(doc):
        return next(s for s in doc["jobs"]["mint"]["steps"]
                    if "mint-provenance.py" in str(s.get("run") or ""))

    def comment_out_line(doc, fragment):
        step = mint_step(doc)
        lines = str(step["run"]).splitlines()
        hits = [i for i, line in enumerate(lines) if fragment in line]
        assert hits, f"seam mutant fragment not present: {fragment!r}"
        for i in hits:
            lines[i] = "# " + lines[i].lstrip()
        step["run"] = "\n".join(lines) + "\n"

    def wf_inputs(doc):
        return (doc.get("on") if "on" in doc else doc.get(True))["workflow_dispatch"]["inputs"]

    for name, edit, key, want in (
            ("the job is neutered with if: false",
             lambda d: d["jobs"]["mint"].update(**{"if": "false"}), "job_ref_guarded", False),
            ("the default-ref guard is deleted",
             lambda d: d["jobs"]["mint"].pop("if"), "job_ref_guarded", False),
            ("the secret-scoped environment is dropped",
             lambda d: d["jobs"]["mint"].pop("environment"), "job_environment", None),
            ("actions: read is granted (backfill's identity source)",
             lambda d: d["jobs"]["mint"]["permissions"].update(actions="read"),
             "no_actions_permission", False),
            ("the mint step is made conditional",
             lambda d: mint_step(d).update(**{"if": "false"}), "step_unconditional", False),
            ("an operator-supplied run key input appears",
             lambda d: wf_inputs(d).update(run_key={"type": "string"}), "no_run_key_input", False),
            ("an --attestation argument appears",
             lambda d: mint_step(d).update(run=str(mint_step(d)["run"]) + "  --attestation x\n"),
             "no_run_key_argument", False),
            ("the dispatch default flips to apply=true",
             lambda d: wf_inputs(d)["apply"].update(default=True),
             "dispatch_default_is_dry_run", True),
            # COMMENT-ONLY mutants: the token stays in the text, the CODE is gone.
            ("the self-test invocation survives only as a comment",
             lambda d: comment_out_line(d, "mint-provenance.py --self-test"),
             "self_test_before_mint", False),
            ("the --apply conditional survives only as a comment",
             lambda d: comment_out_line(d, "args+=(--apply)"), "apply_is_conditional", False),
            ("the --allow-global-partition conditional survives only as a comment",
             lambda d: comment_out_line(d, "args+=(--allow-global-partition)"),
             "global_is_conditional", False),
            ("set -euo pipefail survives only as a comment",
             lambda d: comment_out_line(d, "set -euo pipefail"), "errexit", False)):
        check(f"YAML-seam mutant reds: {name}", mutated(edit)[key], want)
    # The wrong-input seam needs a value comparison rather than a boolean.
    check("YAML-seam mutant reds: APPLY is bound to the WRONG input",
          mutated(lambda d: mint_step(d)["env"].update(
              APPLY="${{ inputs.allow_global_partition }}"))["step_env_bindings"]["APPLY"],
          "${{ inputs.allow_global_partition }}")
    # ...and the control: a RAW-TEXT search would have passed the comment-only mutants, which is
    # why the stripper is load-bearing rather than tidy.
    def raw_run(edit):
        doc = copy.deepcopy(_workflow("mint-provenance.yml"))
        edit(doc)
        return str(mint_step(doc)["run"])

    check("...and a raw-text grep WOULD have passed the commented-out self-test",
          "mint-provenance.py --self-test" in raw_run(
              lambda d: comment_out_line(d, "mint-provenance.py --self-test")), True)

    print("mint-provenance self-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--target-repo", help="owner/name of the target repository")
    parser.add_argument("--registry-repo", help="owner/name of THIS registry repository")
    parser.add_argument("--pr", type=int, help="the orchestrator PR to mint a record for")
    parser.add_argument("--issue", type=int, help="the open source issue the PR names")
    parser.add_argument("--impl-alias", default="opus5",
                        help="the implementing model alias; must resolve to "
                             f"{ORCHESTRATOR_IMPL_PROVIDER} in the target routing catalog")
    parser.add_argument("--routing-file", help="path to the target's routing.toml")
    parser.add_argument("--apply", action="store_true", help="write the record (default: dry run)")
    parser.add_argument("--allow-global-partition", action="store_true",
                        help="accept a source issue that reduces to the serializing "
                             "__global__ partition")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    missing = [name for name in ("target_repo", "registry_repo", "pr", "issue", "routing_file")
               if not getattr(args, name)]
    if missing:
        parser.error("missing required argument(s): "
                     + ", ".join("--" + name.replace("_", "-") for name in missing))
    import tomllib

    with open(args.routing_file, "rb") as handle:
        routing = tomllib.load(handle)
    policy_resolve = _load_policy_resolve()
    with open(SCRIPTS_DIR.parent / "policy" / "repos.toml", "rb") as handle:
        policy_doc = tomllib.load(handle)
    # The MASTER-protected half. `review_enrolment_authors` validates the whole policy row, so a
    # malformed or non-canonical list raises here rather than silently resolving to "nobody".
    enrolled_authors = policy_resolve.review_enrolment_authors(args.target_repo, policy_doc)
    decision = mint(args.target_repo, args.pr, args.issue, args.impl_alias, args.registry_repo,
                    routing, enrolled_authors, apply_changes=args.apply,
                    allow_global_partition=args.allow_global_partition)
    return 1 if decision.action == ACTION_REFUSE else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except MintError as exc:
        print(f"::error::{exc}")
        sys.exit(1)
