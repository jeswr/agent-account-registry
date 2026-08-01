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
from collections import Counter
import copy
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
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

# The word boundaries a `#<n>` reference is read under, as TWO shared constants: `references_issue`
# tests ONE number against the PR text, and the census DISCOVERS every number in it. Deriving both
# from the same pair is what stops the census from proposing a candidate the binding test then
# refuses for a boundary reason alone (`#412` offering `41`, `x#41` offering `41`).
ISSUE_REF_LEFT = r"(?<![0-9A-Za-z_])"
ISSUE_REF_RIGHT = r"(?![0-9])"
ISSUE_REF_RE = re.compile(rf"{ISSUE_REF_LEFT}#([0-9]+){ISSUE_REF_RIGHT}")

# ---- census verdicts (one per PR, disjoint, and every open PR gets exactly one) ----------------
# A census that only listed the mintable PRs would be indistinguishable from a census that had
# stopped counting, so every open PR is classified and the summary names every bucket it saw.
CENSUS_MINTABLE = "MINTABLE"            # mintable AND the review lane would enumerate it
CENSUS_DEAD = "MINTABLE-BUT-DEAD"       # mintable, but the lane discards it — mints nothing
CENSUS_NO_ISSUE = "NO-BINDABLE-ISSUE"   # no `#<n>` it names survives issue_mint_refusal
CENSUS_OTHER_LANE = "NOT-THIS-LANE"     # refused on the PR's own shape (worker namespace, draft, …)
CENSUS_RECORDED = "ALREADY-RECORDED"    # a provenance record for this PR already exists
CENSUS_VERDICTS = (CENSUS_MINTABLE, CENSUS_DEAD, CENSUS_NO_ISSUE, CENSUS_RECORDED,
                   CENSUS_OTHER_LANE)

# The implementing alias both the CLI default and the census decide with. ONE literal: a census
# that judged a different alias from the one a mint would record would report a population the
# operator cannot act on.
DEFAULT_IMPL_ALIAS = "opus5"


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
# MEMOIZED. dispatch-claim.py is ~16k lines and the workflow-seam report loads it once per call;
# the self-test's mutant table calls that report a dozen times, which turned a 2 s self-test into a
# 12 s one and the mutation sweep into a coffee break. The modules are loaded for their pure
# predicates and hold no per-call state, so one exec is enough.
_MODULE_CACHE = {}


def _load_script_module(filename, module_name):
    import importlib.util

    if module_name in _MODULE_CACHE:
        return _MODULE_CACHE[module_name]
    path = SCRIPTS_DIR / filename
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise MintError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _MODULE_CACHE[module_name] = module
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
    return bool(re.search(rf"{ISSUE_REF_LEFT}#{issue_number}{ISSUE_REF_RIGHT}",
                          pull_reference_text(pull)))


def pull_reference_text(pull):
    """The PR-authored text a `#<n>` reference may be read from — title and body, nothing else."""
    if not isinstance(pull, dict):
        return ""
    return f"{pull.get('title') or ''}\n{pull.get('body') or ''}"


def referenced_issue_numbers(pull):
    """Every `#<n>` the PR's own title/body names — the census's CANDIDATE list, TITLE-FIRST.

    ORDER IS THE WHOLE POINT of the split. This repo's convention puts the source issue in the
    PR TITLE (`fix(x): … (#N)`) while a body routinely cross-references dozens of others, so a
    flat ascending walk offers whichever number happens to be lowest — measured on this PR: an
    unrelated open issue rather than the one it closes. Title references come first, then body
    references, each ascending, so the first candidate that binds is the one the PR is actually
    about.

    Discovery only. Each candidate is then put through the production `mint_decision`, which
    re-reads the live issue and applies `issue_mint_refusal`; this function decides nothing, and
    the mint proper takes an explicit `--issue` that this never supplies."""
    if not isinstance(pull, dict):
        return []
    in_title = sorted({int(m) for m in ISSUE_REF_RE.findall(str(pull.get("title") or ""))})
    in_body = sorted({int(m) for m in ISSUE_REF_RE.findall(str(pull.get("body") or ""))}
                     - set(in_title))
    return in_title + in_body


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
    # [OPUS-5] The refusal is on the SERIALIZING partition specifically, and since the reduction
    # became a SET that is exactly the ZERO-area case: a multi-area issue now reduces to a key
    # naming its own areas and excludes only against those, so there is no cross-lane cost to
    # refuse. The refusal text says "give the issue AT LEAST one area:* label" for the same
    # reason — two labels is a correct answer now, and telling an operator to delete one would
    # ask them to make the record LESS accurate to satisfy an encoding limit that no longer
    # exists. `--allow-global-partition` is unchanged and still the only way to accept the cost.
    if package == global_package and not allow_global_partition:
        return (f"source issue #{issue_number} reduces to the serializing {global_package} "
                f"partition ({len(areas)} area:* label(s)); a review lease on it excludes every "
                "other lane. Re-run with --allow-global-partition to accept that cost, or give "
                "the issue at least one area:* label")
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
    the negative before the PUT rather than discover it a tick later.

    NOT SUFFICIENT ON ITS OWN, and that is why `delivery_refusal` exists: this asks whether the
    RECORD is admissible. It asks nothing about the PR, and the PR is where every terminal
    exclusion lives."""
    return admission_error(document, pr_number, admit_orchestrator=True)


def issue_label_names(issue):
    """The `labels` of a live issue payload as a sorted list of names — the shape the review
    enumerator's `issue_labels` map holds. Malformed entries are dropped, never raised on.

    DEFENCE IN DEPTH, honestly labelled (mutation round 1): returning `[]` here changes no `mint()`
    OUTCOME, because every source-issue label state the enumerator excludes on (`needs:*`,
    `status:parked`) is already refused upstream by `issue_mint_refusal`. It is passed anyway so
    that `delivery_refusal` asks the enumerator about the REAL issue rather than a blank one — a
    property of the WIRING, and the self-test asserts it at the call site (a spy on the
    `issue_labels` argument) plus the upstream-equivalence that makes it redundant today."""
    if not isinstance(issue, dict):
        return []
    return sorted({label.get("name") for label in (issue.get("labels") or [])
                   if isinstance(label, dict) and isinstance(label.get("name"), str)})


def delivery_refusal(repo, document, pull, source_labels, enrolled_authors, *,
                     enumerate_review_items, now, hold_labels=(), park_label=None):
    """Why the record about to be written would NOT put this PR into the review lane, or None.

    THE MISSING LAST MILE. `admissible_by_the_review_lane` proves the RECORD is admissible and
    stops there — so this script could write a record the enumerator discards at its very next
    predicate, and the only symptom would be the absence of a review. Measured on the enrolled
    repo, 2026-07-28: of 36 open PRs exactly THREE passed every gate in this file, and ALL THREE
    carried `needs:user`, which `enumerate_review_items` treats as terminal. Every mint available
    on that population would have delivered nothing.

    THE DECISION IS THE CONSUMER'S OWN. This drives the PRODUCTION `enumerate_review_items` over
    the live PR payload and the exact document about to be written, and refuses unless it emits a
    review item for that PR. Nothing here re-implements an admission predicate: a widened or
    narrowed enumerator changes this answer by construction, which is the rule §9.1 of the
    admission design record established for every other consumer.

    PERMISSIVE IN EXACTLY ONE DIRECTION, deliberately. No lease store and no CI snapshot are
    passed, so a transient per-PR review lease, a conflicting base or a red gate can never make
    this refuse — the only refusals it can produce are terminal on the PR's own live state. A
    false "it would be enumerated" therefore degrades to today's behaviour (the record waits for
    the lease to clear); a false refusal would be a new way to make minting impossible, and there
    is no input here that can produce one.

    `hold_labels` / `park_label` are the consumer's own constants and feed the ADVISORY hint only.
    The refusal fires on the enumerator's answer alone — see `_delivery_hint`."""
    pr_number = document.get("pr_number") if isinstance(document, dict) else None
    exclusions = Counter()
    try:
        items = enumerate_review_items(
            repo, [pull], {pr_number: document}, [],
            {document.get("issue"): list(source_labels)}, now,
            enrolled_authors=enrolled_authors, exclusions=exclusions)
    except Exception as exc:                            # noqa: BLE001 — any refusal is a refusal
        return (f"the review lane's own enumerator could not classify this PR ({exc}); a record "
                "written now would be acted on by nothing")
    if any(isinstance(item, dict) and item.get("pr_number") == pr_number for item in items):
        return None
    named = sorted(exclusions)
    reason = named[0] if named else _delivery_hint(pull, source_labels, hold_labels, park_label)
    return f"the review lane does not enumerate it: {reason}"


def _delivery_hint(pull, source_labels, hold_labels, park_label):
    """A best-effort, ADVISORY explanation of a non-enumeration, for the operator's next action.

    NEVER a decision. `enumerate_review_items` records an exclusion reason only for PRs carrying
    an explicit review-loop signal, and the enrollable population carries none — so on exactly
    the PRs this feature exists for, the enumerator's own telemetry is silent. This reads the
    consumer's own exported CONSTANTS (never a copy of its predicates) to name the likely cause;
    if it names the wrong one the refusal is still correct, because the refusal came from the
    enumerator."""
    labels = {label.get("name") if isinstance(label, dict) else label
              for label in (pull.get("labels") or []) if isinstance(pull, dict)}
    held = sorted(label for label in labels if isinstance(label, str) and label in set(hold_labels))
    if held:
        return (f"the PR carries the human-owned hold {held[0]!r} — that is terminal for every "
                "autonomous state, so clear it (a human gesture) before minting")
    if park_label is not None and park_label in labels:
        return (f"the PR carries the machine park {park_label!r}; it is re-admitted by the "
                "pipeline's own readmission path, not by a record")
    parked = sorted(label for label in source_labels
                    if isinstance(label, str) and label == "status:parked")
    if parked:
        return "the source issue is machine-parked (status:parked)"
    return ("no exclusion was reported — re-run the census (`--census`) to see the PR's live "
            "labels and state as the enumerator reads them")


def review_run_refusal(identity_admits, *, shell_admits):
    """Why the review RUN this record would dispatch cannot reach a reviewer at all, or None.

    THE THIRD LAST MILE, and the one the first two cannot see. `admissible_by_the_review_lane`
    proves the RECORD is admissible; `delivery_refusal` proves the ENUMERATOR emits a review item.
    Both are true today for the orchestrator class, and the class still receives NO review — the
    dispatched run dies in review-fix.yml's `run` job, at a target-App identity gate that admits
    only pull requests authored by the registry App bot. MEASURED end to end on the enrolled repo:
    the first orchestrator-class mint in the registry's history reached CLAIM and resolve green and
    then failed with `pull request author is not the registry App bot`.

    ENUMERABILITY IS NOT DELIVERABILITY. That distinction is the whole content of this function,
    and it is the same lesson `delivery_refusal` learned one layer up: a predicate that stops at
    the consumer it happens to know about writes records whose only effect is a terminal park.

    THE POLARITY IS DELIBERATE, and it differs from `delivery_refusal`'s. That one is documented as
    permissive in exactly one direction so no input can make minting impossible. This one CAN
    refuse the whole class at once, on purpose: the identity gate refuses the whole class at once,
    by construction rather than by snapshot (an enrolled author is never a `[bot]` login, so it can
    never equal the App bot's), so a per-PR refusal would be the lie. Refusing costs nothing that
    is not already lost — nothing is written and the pull request stays exactly as it is — while
    minting anyway spends a runner, a claim and an account lease to reach a park.

    FAIL CLOSED on an unreadable probe, matching `delivery_refusal`'s own exception contract: a
    seam that cannot be read is not proof that a reviewer would start.

    SELF-REMOVING. Both probes re-derive their answer from the live workflow and the live shell
    script on every call, so the day a gate admits the class its refusal disappears with no code
    change here.

    [registry #1288] ``shell_admits`` IS THE FOURTH CONSUMER, and its absence was this function
    failing its own docstring. It consulted the identity gate ALONE — so once that gate was widened
    it went quiet and cheerfully authorised minting for a class that dies 29 lines later, in
    worker-live.sh's own copy of the worker head-ref gate. That is verbatim the failure this
    function is named for: "a predicate that stops at the consumer it happens to know about writes
    records whose only effect is a terminal park." Three of the four copies had been found.

    It is KEYWORD-ONLY and REQUIRED — no default — for exactly the reason `census_verdict`'s
    `identity_admits` is (mutant M17): a defaulted conjunct is the one a future caller omits, and
    the omission is invisible because the remaining conjunct still reads True. The consumer list is
    now the thing a new caller cannot forget rather than the thing a docstring asks it to
    remember."""
    for what, probe, refusal in (
            ("target-App identity gate", identity_admits,
             "review-fix.yml's target-App identity gate would refuse this run before any reviewer "
             "starts"),
            ("worker-live.sh head-ref gate", shell_admits,
             "worker-live.sh's `run_review` would refuse this pull request's head branch before "
             "the reviewer launches — it carries its own copy of the worker-namespace gate, and "
             "this class is defined by not matching it")):
        try:
            admitted = probe()
        except Exception as exc:                        # noqa: BLE001 — any probe failure refuses
            return (f"the review lane's {what} could not be read ({exc}), so it cannot be shown "
                    "that a reviewer would ever start")
        if admitted is not True:
            return (f"{refusal}. Until that is fixed, a record here buys one terminal park "
                    "instead of a review")
    return None


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
         identity_admits=None, shell_admits=None, modules=None, log=print):
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
    # An UNREADABLE existing-record probe is not "nothing is recorded" (backfill's sol #217
    # finding). effective_record_body deliberately raises on any non-404 failure, so catch it HERE
    # and turn it into a refusal with the operator's next action, rather than a traceback: a
    # transient registry failure must never let this run write a SECOND, divergent record.
    try:
        existing_body = read_record()
    except Exception as exc:                            # noqa: BLE001 — any probe failure refuses
        reason = (f"cannot establish whether a provenance record already exists ({exc}); nothing "
                  "is recorded — re-run once the registry probe succeeds")
        log(f"REFUSE {repo}#{pr_number}: {reason}")
        return MintDecision(ACTION_REFUSE, reason, None)
    # Read each payload ONCE and keep it: the delivery check below is driven by the same live PR
    # and the same live issue the decision was made from, so it cannot disagree with the decision
    # about what it is looking at.
    pull_payload = read_pull()
    issue_payload = read_issue()
    decision = mint_decision(
        repo, pr_number, issue_number, impl_alias, enrolled_authors, routing, stamp,
        env.get("PROVENANCE_SALT", ""), pull_payload, issue_payload, existing_body,
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
    # ...and the SECOND last mile: an admissible record on a PR the lane will not enumerate is a
    # write that delivers no review. Refused on the DRY RUN too, so the operator learns it from the
    # cheap gesture rather than from a record that then sits inert on the ledger forever.
    delivery_error = delivery_refusal(
        repo, decision.document, pull_payload, issue_label_names(issue_payload), enrolled_authors,
        enumerate_review_items=dispatch_claim.enumerate_review_items, now=time.time(),
        hold_labels=dispatch_claim.HUMAN_HOLD_PR_LABELS,
        park_label=dispatch_claim.MACHINE_PARK_PR_LABEL)
    if delivery_error:
        reason = (f"the record this run would write would deliver NO review ({delivery_error}); "
                  "refusing to write a record nothing acts on")
        log(f"REFUSE {repo}#{pr_number}: {reason}")
        return MintDecision(ACTION_REFUSE, reason, None)
    # ...and the THIRD last mile. The two checks above prove the record is admissible and that the
    # ENUMERATOR emits an item; neither can see the review-fix.yml `run` job, which refuses this
    # whole class at its target-App identity gate. Refused on the DRY RUN too, for the same reason
    # the delivery gate is: the operator should learn it from the cheap gesture.
    run_error = review_run_refusal(
        identity_admits or dispatch_claim.review_fix_identity_admits_orchestrator_class,
        shell_admits=(shell_admits
                      or dispatch_claim.worker_live_admits_orchestrator_class))
    if run_error:
        reason = (f"the record this run would write would deliver NO review ({run_error}); "
                  "refusing to write a record nothing acts on")
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


# ---- the census: WHICH PRs this writer can serve, answered by the production decision -----------
# WHY THIS EXISTS. Between #876 landing the writer and 2026-07-28 the mint workflow was dispatched
# ZERO times, and there were ZERO `orchestrator`-attested records among the 463 on `ledger`. The
# writer was not broken — the first dispatch of it succeeded — but nothing in the pipeline COUNTED
# this class, so the only way to learn which PR the gesture could serve was to dispatch a run per
# (PR, candidate issue) guess and read a refusal. On the live population that is ~130 dispatches to
# discover 3 candidates, all 3 of them dead. A discovery gesture nobody can afford is a gesture
# nobody performs; this makes the answer one read-only run.
def census_verdict(repo, pull, open_issues, enrolled_authors, routing, stamp, salt, *,
                   recorded=(), impl_alias=DEFAULT_IMPL_ALIAS, allow_global_partition=False,
                   attestation_class, orchestrator_class, plan_package, global_package,
                   account_hash, json_type_exact, enumerate_review_items, now, hold_labels=(),
                   park_label=None, identity_admits, shell_admits):
    """ONE disjoint census verdict for ONE open PR: `(verdict, detail)`.

    Every branch is decided by the PRODUCTION functions this file already ships — `pr_mint_refusal`
    for the shape, `mint_decision` for the binding, `delivery_refusal` for whether the lane would
    act, `review_run_refusal` for whether a reviewer would ever start. The census therefore cannot
    drift from what a real `--apply` would do: to change the census you have to change the mint.

    `identity_admits` is keyword-only and REQUIRED — no default — precisely because this is the
    conjunct a census would otherwise be able to omit and go on reporting MINTABLE for a PR that
    `mint()` refuses. That divergence is the defect this docstring's last sentence promises cannot
    happen, so the parameter is made impossible to forget rather than merely documented."""
    number = pull.get("number") if isinstance(pull, dict) else None
    shape_error = pr_mint_refusal(repo, pull, enrolled_authors)
    if shape_error:
        return CENSUS_OTHER_LANE, shape_error
    if number in set(recorded):
        return CENSUS_RECORDED, "a provenance record already exists for this PR"
    refusals = []
    dead = None
    for candidate in referenced_issue_numbers(pull):
        issue = open_issues.get(candidate)
        if issue is None:
            refusals.append(f"#{candidate}: not an OPEN issue in this repo")
            continue
        decision = mint_decision(
            repo, number, candidate, impl_alias, enrolled_authors, routing, stamp,
            salt, pull, issue, None, allow_global_partition=allow_global_partition,
            attestation_class=attestation_class, orchestrator_class=orchestrator_class,
            plan_package=plan_package, global_package=global_package, account_hash=account_hash,
            json_type_exact=json_type_exact)
        if decision.action != ACTION_MINT:
            refusals.append(f"#{candidate}: {decision.reason}")
            continue
        delivery = delivery_refusal(
            repo, decision.document, pull, issue_label_names(issue), enrolled_authors,
            enumerate_review_items=enumerate_review_items, now=now, hold_labels=hold_labels,
            park_label=park_label)
        if delivery:
            # Keep looking: a SECOND candidate issue can be live where the first is not, and
            # returning the first dead binding would under-report the population.
            dead = dead or (CENSUS_DEAD, f"issue #{candidate} binds, but {delivery}")
            continue
        # ...and the THIRD last mile, asked AFTER the binding so the row still tells the operator
        # which issue bound. A class-global refusal reported as MINTABLE would be the census
        # drifting from the mint — the one thing this function's contract forbids.
        run_error = review_run_refusal(identity_admits, shell_admits=shell_admits)
        if run_error:
            dead = dead or (CENSUS_DEAD, f"issue #{candidate} binds, but {run_error}")
            continue
        return CENSUS_MINTABLE, f"mint with --issue {candidate}"
    if dead:
        return dead
    return CENSUS_NO_ISSUE, summarise_refusals(refusals)


# A PR body on this repo routinely names 60+ issues (cross-references to the target repo's numbering
# among them), and printing every refusal made the census unreadable — a report nobody reads is the
# same as no report. The CLOSED/absent candidates are the least informative line by far, so the
# summary prefers the refusals that name a fixable condition and states how many it dropped.
CENSUS_REFUSALS_SHOWN = 3
_UNINFORMATIVE_REFUSAL = "not an OPEN issue in this repo"


def summarise_refusals(refusals, shown=CENSUS_REFUSALS_SHOWN):
    """A bounded, INFORMATIVE-FIRST rendering of why no candidate issue bound.

    Never silently truncates: the count of everything not shown is always printed, so a summary can
    never read as a complete list."""
    if not refusals:
        return "the PR's title and body name no #<n> at all"
    informative = [line for line in refusals if _UNINFORMATIVE_REFUSAL not in line]
    ordered = informative + [line for line in refusals if line not in informative]
    head = "; ".join(ordered[:shown])
    hidden = len(ordered) - len(ordered[:shown])
    closed = sum(1 for line in refusals if _UNINFORMATIVE_REFUSAL in line)
    tail = f" (+{hidden} more candidate(s), {closed} of them closed/absent)" if hidden else ""
    return head + tail


def census(repo, registry_repo, routing, enrolled_authors, *, impl_alias=DEFAULT_IMPL_ALIAS,
           env=None, read_pulls=None, read_issues=None, read_recorded=None, modules=None,
           log=print):
    """Classify every open PR in `repo` and print one row each plus a fully-seeded summary.

    READ-ONLY BY CONSTRUCTION: there is no writer here and no `--apply` reaches it. It also needs
    no secret — the account hash is the only field the salt touches and the census never prints a
    hash, so it decides with a PER-RUN EPHEMERAL salt. A census run therefore cannot disclose
    PROVENANCE_SALT even by accident, and its verdicts are provably independent of it.

    Every reader is injectable so `--self-test` drives this orchestration and not just its parts.
    A reader that FAILS raises (MintError from `_gh_json`) — an unreadable population must never
    be reported as an empty one."""
    env = os.environ if env is None else env
    worker_pr, dispatch_claim, lease_schema = modules or (
        _load_worker_pr(), _load_dispatch_claim(), _load_lease_schema())
    read_pulls = read_pulls or (lambda: _gh_json(
        ["api", "--paginate", f"repos/{repo}/pulls?state=open&per_page=100"]))
    read_issues = read_issues or (lambda: _gh_json(
        ["api", "--paginate", f"repos/{repo}/issues?state=open&per_page=100"]))
    if read_recorded is None:
        def read_recorded():
            return recorded_pr_numbers(repo, registry_repo, worker_pr)

    pulls = read_pulls() or []
    rows = read_issues() or []
    # PLAN's own issue-label map covers ISSUES, not pull-request rows (registry #112) — the same
    # exclusion `issue_mint_refusal` refuses a PR-as-source-issue for. Applied here so a candidate
    # that is really a PR is reported as "not an OPEN issue" by the same reasoning.
    #
    # DEFENCE IN DEPTH, honestly labelled (mutation round 1): removing this filter does not change
    # any VERDICT, because `issue_mint_refusal` refuses a pull-request row independently. What it
    # changes is the REASON the operator reads, and that is what the self-test pins.
    open_issues = {row.get("number"): row for row in rows
                   if isinstance(row, dict) and "pull_request" not in row}
    recorded = read_recorded()
    stamp = mint_stamp(env.get("GITHUB_RUN_ID"), env.get("GITHUB_RUN_ATTEMPT"),
                       dispatch_claim.ORCHESTRATOR_CLASS)
    # The census reports what a mint WOULD decide, so it must be told when the stamp itself is
    # unavailable rather than reporting every PR as unmintable for a reason the operator cannot see.
    if stamp is None:
        raise MintError("no runner run identity (GITHUB_RUN_ID/GITHUB_RUN_ATTEMPT): the census "
                        "reports what a mint would decide, and a mint cannot be decided without "
                        "the stamp this run would write")
    salt = os.urandom(16).hex()
    # [mutation round 1] A `Counter({v: 0 for v in CENSUS_VERDICTS})` pre-seed used to sit here and
    # was measured UNKILLABLE: the summary below enumerates CENSUS_VERDICTS and `Counter[missing]`
    # is 0, so seeding could never change an output. Two mechanisms for one property is one
    # mechanism plus a control that can never fire — the ENUMERATION at the print is the mechanism,
    # and it is the thing the self-test mutates.
    tally = Counter()
    out = []
    for pull in sorted((p for p in pulls if isinstance(p, dict)),
                       key=lambda p: p.get("number") if isinstance(p.get("number"), int) else 0):
        verdict, detail = census_verdict(
            repo, pull, open_issues, enrolled_authors, routing, stamp, salt, recorded=recorded,
            impl_alias=impl_alias,
            attestation_class=dispatch_claim.provenance_attestation_class,
            orchestrator_class=dispatch_claim.ORCHESTRATOR_CLASS,
            plan_package=lease_schema.plan_package, global_package=lease_schema.GLOBAL_PACKAGE,
            account_hash=worker_pr.account_hash, json_type_exact=worker_pr._json_type_exact,
            enumerate_review_items=dispatch_claim.enumerate_review_items, now=time.time(),
            hold_labels=dispatch_claim.HUMAN_HOLD_PR_LABELS,
            park_label=dispatch_claim.MACHINE_PARK_PR_LABEL,
            identity_admits=dispatch_claim.review_fix_identity_admits_orchestrator_class,
            shell_admits=dispatch_claim.worker_live_admits_orchestrator_class)
        tally[verdict] += 1
        out.append((pull.get("number"), verdict, detail))
        log(f"census {repo}#{pull.get('number')}: {verdict} — {detail}")
    # EVERY bucket, including the zeros: "nothing is mintable" and "this stopped being counted"
    # must not print the same way (the population-census rule this repo already applies at PLAN).
    log("census summary: " + ", ".join(f"{verdict}={tally[verdict]}" for verdict in CENSUS_VERDICTS)
        + f", open_prs={len(out)}")
    return out


def recorded_pr_numbers(repo, registry_repo, worker_pr, read_listing=None):
    """The PR numbers that ALREADY hold a provenance record, from ONE ledger directory listing.

    Both the directory and the per-repo filename prefix are derived from the PRODUCTION path
    builder (`worker_pr.provenance_path`), never spelled out here — so a record for a DIFFERENT
    target repo in the same directory can never be counted as one of this repo's PRs, and a
    renamed layout reds this rather than silently matching nothing.

    RAISES on an unreadable listing rather than returning an empty set: "no record exists" and
    "I could not tell" must never be the same answer, which is the fail-open shape backfill's
    sol #217 review found on this exact read."""
    template = worker_pr.provenance_path(repo, "")           # ".../<owner>--<name>--pr.json"
    directory, _, filename = template.rpartition("/")
    stem = filename[:-len(".json")] if filename.endswith(".json") else filename
    numbered = re.compile(rf"{re.escape(stem)}([1-9][0-9]*)\.json")
    read_listing = read_listing or (lambda: _gh_json(
        ["api", f"repos/{registry_repo}/contents/{directory}?ref={worker_pr.LEDGER_REF}"]))
    listing = read_listing()
    if not isinstance(listing, list):
        raise MintError("the ledger provenance listing was not a directory listing")
    numbers = set()
    for entry in listing:
        name = entry.get("name") if isinstance(entry, dict) else None
        match = numbered.fullmatch(name or "")
        if match:
            numbers.add(int(match.group(1)))
    return numbers


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
    census_at = run.find("mint-provenance.py --census")
    # Every OTHER invocation of the script in this step, so "the self-test runs first" is a fact
    # about the whole step and not about the one invocation that happened to be checked when the
    # step had one. A new mode added below without a self-test in front of it reds this.
    other_invocations = [match.start() for match in
                         re.finditer(r"python3 scripts/mint-provenance\.py(?! --self-test)", run)]
    guards_at = [match.start() for match in
                 re.finditer(r'\[\[\s*"\$(?:PR|ISSUE)_NUMBER"\s*=~', run)]
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
        "self_test_before_every_invocation": bool(other_invocations) and 0 <= self_at < min(
            other_invocations),
        # ---- THE MODE SEAM (#681's lesson, applied to this file) --------------------------------
        # #681's YAML battery PINNED mode="review" in its harness, which left its own dispatch-input
        # validation load-bearing and untested. So every clause of the mode branch here is a NAMED
        # finding with its own mutant: the allowlist, the census-is-read-only refusal, the `exec`
        # that stops census from reaching the write levers, and the two input guards the census
        # branch legitimately skips — which must therefore still stand between it and the mint.
        "mode_is_allowlisted": bool(re.search(r'case\s+"\$MODE"\s+in', run))
                               and bool(re.search(r"census\|mint\s*\)", run))
                               and bool(re.search(r"\*\)[^\n]*exit 1", run)),
        "mode_default": inputs.get("mode", {}).get("default"),
        "mode_options": sorted(inputs.get("mode", {}).get("options") or []),
        "census_refuses_apply": bool(re.search(
            r'if\s*\[\[\s*"\$APPLY"\s*==\s*"true"\s*\]\]\s*;\s*then[^\n]*exit 1', run)),
        # A `call` would return and fall through to the `args+=(--apply)` lines; `exec` cannot.
        "census_invocation_execs": bool(re.search(
            r"^\s*exec python3 scripts/mint-provenance\.py --census\b", run, re.M)),
        "census_before_input_guards": 0 <= census_at < min(guards_at, default=-1),
        "input_guards_before_mint": len(guards_at) == 2 and max(guards_at) < invoke_at,
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
        # EVERY env name the step declares, not a chosen subset: the self-test compares the whole
        # mapping, so ADDING a binding is as red as rebinding one. That is what keeps a new
        # secret, token or input from being handed to this job unnoticed.
        "step_env_bindings": step_env,
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
    # [OPUS-5][RED] TWO area labels used to reduce to `__global__` too, so a genuinely two-crate
    # source issue could not be recorded at all without an operator override. The reduction is a
    # SET now: the record's partition is `ci,docs`, which excludes only against `ci` and `docs`,
    # so there is nothing to refuse. The ZERO-area row above is the paired CONTROL and is still
    # refused — that is the only shape whose footprint is genuinely unknown.
    check("[RED] TWO area labels are BOUND — they reserve exactly those two areas, not the world",
          issue_mint_refusal(
              7, issue(labels=[{"name": "area:ci"}, {"name": "area:docs"}]), pull(), *args),
          None)
    check("...and the partition such a record reserves names exactly those two areas",
          lease_schema.plan_package(["docs", "ci"]), "ci,docs")
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

    # The identity gate refuses this whole class TODAY (review_run_refusal), so every row below
    # that is about some OTHER predicate injects an admitting probe — otherwise each of them would
    # pass for the new reason and stop testing what it names. The live probe, and both of its
    # failure directions, are driven by their own rows further down.
    def _identity_admits():
        return True

    def _shell_admits():
        return True

    def run_mint(*, apply_changes=False, env=None, record=None, allow_global=False,
                 pull_over=None, issue_over=None, record_reader=None,
                 identity_admits=_identity_admits, shell_admits=_shell_admits):
        written = []
        decision = mint(repo, 41, 7, "opus5", "reg/istry", routing, enrolled,
                        apply_changes=apply_changes, allow_global_partition=allow_global,
                        env=env if env is not None else good_env,
                        read_pull=lambda: pull(**(pull_over or {})),
                        read_issue=lambda: issue(**(issue_over or {})),
                        read_record=record_reader or (lambda: record),
                        write_record=lambda: written.append("put"),
                        identity_admits=identity_admits,
                        shell_admits=shell_admits,
                        modules=modules, log=lambda *_a, **_k: None)
        return decision, written

    def _exploding_probe():
        raise RuntimeError("registry file probe failed: HTTP 502")

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
    # An UNREADABLE probe is not "nothing recorded": it must refuse, never write a second record.
    decision, written = run_mint(apply_changes=True, record_reader=_exploding_probe)
    check("an unreadable existing-record probe refuses and writes nothing",
          (decision.action, written), (ACTION_REFUSE, []))
    check("...with the operator's next action, not a traceback",
          "re-run once the registry probe succeeds" in decision.reason, True)
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

    # ---- THE DELIVERY GATE: a mint that delivers no review is a defect, not a success ----------
    # THE MEASURED DEFECT (live enrolled repo, 2026-07-28): of 36 open PRs exactly THREE passed
    # every gate in this file, and ALL THREE carried `needs:user`. `admissible_by_the_review_lane`
    # said yes to all three, because it asks about the RECORD. The enumerator discards all three.
    def delivers(**over):
        payload = pull(**over.pop("pull_over", {}))
        return delivery_refusal(
            repo, over.pop("document", minted.document), payload,
            over.pop("source_labels", ["area:ci"]), over.pop("enrolled", enrolled),
            enumerate_review_items=over.pop(
                "enumerator", dispatch_claim.enumerate_review_items),
            now=1_800_000_000, hold_labels=dispatch_claim.HUMAN_HOLD_PR_LABELS,
            park_label=dispatch_claim.MACHINE_PARK_PR_LABEL, **over)

    # The POSITIVE leg first: without it every refusal below could be "this always refuses".
    check("an enrolled, unheld orchestrator PR IS delivered into the review lane", delivers(), None)
    for hold in sorted(dispatch_claim.HUMAN_HOLD_PR_LABELS):
        rejects(f"a PR carrying {hold!r} is REFUSED — the mint would deliver nothing",
                "does not enumerate it",
                lambda h=hold: delivers(pull_over={"labels": [{"name": h}]}))
    rejects("...and the hint names the label the operator has to clear", "human-owned hold",
            lambda: delivers(pull_over={"labels": [{"name": "needs:user"}]}))
    rejects("a machine-parked PR is refused too", "does not enumerate it",
            lambda: delivers(pull_over={
                "labels": [{"name": dispatch_claim.MACHINE_PARK_PR_LABEL}]}))
    # The HINT is asserted where it lives, so its coverage is not hostage to which channel happened
    # to supply the reason (the enumerator records one only for signalled PRs — and the enrollable
    # population is exactly the unsignalled one, which is why the hint exists at all).
    for labels, needle in ((["needs:user"], "human-owned hold"),
                           ([dispatch_claim.MACHINE_PARK_PR_LABEL], "machine park")):
        got = _delivery_hint(pull(labels=[{"name": name} for name in labels]), [],
                             dispatch_claim.HUMAN_HOLD_PR_LABELS,
                             dispatch_claim.MACHINE_PARK_PR_LABEL)
        check(f"the hint names {labels[0]!r} as the thing to clear", needle in got, True)
    check("the hint names a parked SOURCE ISSUE too",
          "machine-parked" in _delivery_hint(pull(), ["status:parked"],
                                            dispatch_claim.HUMAN_HOLD_PR_LABELS,
                                            dispatch_claim.MACHINE_PARK_PR_LABEL), True)
    check("...and says so honestly when it cannot tell, pointing at the census",
          "--census" in _delivery_hint(pull(), [], dispatch_claim.HUMAN_HOLD_PR_LABELS,
                                       dispatch_claim.MACHINE_PARK_PR_LABEL), True)
    rejects("a needs:* hold on the SOURCE ISSUE is refused (the enumerator's own predicate)",
            "does not enumerate it",
            lambda: delivers(source_labels=["area:ci", "needs:user"]))
    rejects("an UN-ENROLLED author is refused here too — the waiver is what makes it enumerable",
            "does not enumerate it", lambda: delivers(enrolled=()))
    # FAIL-CLOSED on the consumer itself: an enumerator that raises is not an admission.
    def _exploding_enumerator(*_a, **_k):
        raise RuntimeError("PLAN walk aborted")

    rejects("an enumerator that RAISES is a refusal, never a pass", "could not classify",
            lambda: delivers(enumerator=_exploding_enumerator))
    # ...and the decision is the ENUMERATOR's, not the hint's: an enumerator that admits everything
    # makes this pass even for a PR the hint would happily explain away, which is what pins the hint
    # as advisory. (Both directions matter — the check above pins the other one.)
    check("the verdict follows the enumerator, not the hint",
          delivers(pull_over={"labels": [{"name": "needs:user"}]},
                   enumerator=lambda *_a, **_k: [{"pr_number": 41}]), None)
    # AND IT IS WIRED. mint() must refuse a held PR end to end — a delivery predicate nothing calls
    # is the vacuity shape this repo keeps measuring.
    decision, written = run_mint(apply_changes=True,
                                 pull_over={"labels": [{"name": "needs:user"}]})
    check("mint() REFUSES a human-held PR and writes nothing", (decision.action, written),
          (ACTION_REFUSE, []))
    check("...naming the delivery, not the record", "deliver NO review" in decision.reason, True)
    check("...and the record itself was admissible, which is why the record check missed it",
          admissible_by_the_review_lane(minted.document, 41,
                                        dispatch_claim.provenance_admission_error), None)
    decision, written = run_mint(issue_over={"labels": [{"name": "area:ci"},
                                                        {"name": "status:parked"}]})
    check("a machine-parked SOURCE ISSUE is refused before the record check even needs to run",
          decision.action, ACTION_REFUSE)

    # ---- THE THIRD LAST MILE: enumerability is NOT deliverability ------------------------------
    # THE MEASURED DEFECT: the first orchestrator-class mint in the registry's history passed both
    # checks above and still delivered no review — the dispatched run died in review-fix.yml's
    # `run` job at the target-App identity gate ("pull request author is not the registry App
    # bot"). Both gates above answer about the RECORD and the ENUMERATOR; neither can see the run.
    check("the run gate PASSES when the identity probe admits the class",
          review_run_refusal(lambda: True, shell_admits=lambda: True), None)
    rejects("...and REFUSES when it does not, naming the gate that refuses",
            "target-App identity gate", lambda: review_run_refusal(lambda: False, shell_admits=lambda: True))
    rejects("...and names whose decision would unblock it, not a fake operator action",
            "terminal park", lambda: review_run_refusal(lambda: False, shell_admits=lambda: True))
    # FAIL-CLOSED, matching delivery_refusal's own exception contract: a seam that cannot be read
    # is not proof that a reviewer would start.
    def _exploding_identity():
        raise RuntimeError("review-fix.yml could not be parsed")

    rejects("an identity probe that RAISES is a refusal, never a pass", "could not be read",
            lambda: review_run_refusal(_exploding_identity, shell_admits=lambda: True))
    # ...and ONLY True admits. A probe that returns None, "" or a truthy non-True value must never
    # read as admission — `if admitted is True` is what makes that so, and this is what reds if it
    # is loosened to a bare truthiness test.
    for _label, _answer in (("None", None), ("empty string", ""), ("0", 0), ("1", 1),
                            ("'yes'", "yes"), ("[]", []), ("a truthy object", MintError("x"))):
        check(f"a non-True probe answer ({_label}) is a refusal",
              review_run_refusal(lambda v=_answer: v, shell_admits=lambda: True) is not None, True)
    # [registry #1288] THE FOURTH CONSUMER, isolated. The identity gate admits and the SHELL gate
    # does not: this must still refuse, or `review_run_refusal` authorises minting for a class that
    # dies 29 lines past the gate it does check — verbatim the failure its own name warns about,
    # and what it actually did before the shell conjunct was added.
    rejects("a refusing SHELL gate refuses the run even when the identity gate ADMITS",
            "worker-live.sh", lambda: review_run_refusal(lambda: True, shell_admits=lambda: False))
    rejects("...and names the terminal park it would otherwise buy",
            "terminal park", lambda: review_run_refusal(lambda: True, shell_admits=lambda: False))
    rejects("an exploding SHELL probe is a refusal, never a pass", "could not be read",
            lambda: review_run_refusal(lambda: True, shell_admits=_exploding_identity))
    for _label, _answer in (("None", None), ("empty string", ""), ("1", 1), ("'yes'", "yes")):
        check(f"a non-True SHELL probe answer ({_label}) is a refusal",
              review_run_refusal(lambda: True,
                                 shell_admits=lambda v=_answer: v) is not None, True)
    # ...and the CONJUNCT IS IMPOSSIBLE TO FORGET rather than merely documented. Mutant M17 was
    # exactly this shape one parameter over: the single current call site always passes the probe,
    # so a permissive DEFAULT never bites and every behavioural row stays green. The claim is a fact
    # about the SIGNATURE, so the signature is what is asserted.
    for _fn, _param in ((review_run_refusal, "shell_admits"),
                        (census_verdict, "shell_admits"),
                        (census_verdict, "identity_admits")):
        check(f"{_fn.__name__}'s {_param} is REQUIRED — a default is what lets a future caller "
              "silently drop a consumer from the interlock",
              inspect.signature(_fn).parameters[_param].default, inspect.Parameter.empty)
        check(f"...and {_fn.__name__}'s {_param} is keyword-ONLY, so it cannot be satisfied by "
              "positional accident",
              inspect.signature(_fn).parameters[_param].kind, inspect.Parameter.KEYWORD_ONLY)
    # THE LIVE SHELL GATE, by execution against the real script — the row that flips the day
    # worker-live.sh stops admitting the class.
    check("the LIVE worker-live.sh head-ref gate ADMITS the orchestrator class",
          dispatch_claim.worker_live_admits_orchestrator_class(), True)

    # THE KNOWN POSITIVE, BY EXECUTION against the REAL workflow file.
    #
    # [registry #1288] THIS ROW FLIPPED, AND THAT IS THE DESIGN WORKING, NOT AN EXEMPTION. It read
    # `False` and carried the note "this row goes RED the day the identity gate is widened — which
    # is exactly the day this whole refusal should disappear". That day is this commit: the `run`
    # job now admits the self-attested class (into a job holding no target token), so the refusal
    # self-removes and the class mints again. The predicate above is untouched — every injected-
    # probe row still proves it refuses when the gate does — and only the LIVE answer moved.
    check("the LIVE identity gate ADMITS the orchestrator class",
          dispatch_claim.review_fix_identity_admits_orchestrator_class(), True)
    # AND IT IS WIRED, driven by the LIVE probe rather than an injected one: a run-gate predicate
    # nothing calls is the vacuity shape this repo keeps measuring.
    decision, written = run_mint(apply_changes=True, identity_admits=None)
    check("mint() MINTS on the live identity gate — the class is deliverable again",
          (decision.action, written), (ACTION_MINT, ["put"]))
    # ...and the WIRING is still proved, by the direction that is now the injected one: a refusing
    # gate must still stop the write at this exact call site. Without this row the live row above
    # would be satisfied by a `mint()` that stopped consulting the run gate at all — which is
    # precisely the vacuity the flip could otherwise smuggle in.
    _refused, _refused_written = run_mint(apply_changes=True, identity_admits=lambda: False)
    check("...and a REFUSING gate still stops mint() dead, writing nothing",
          (_refused.action, _refused_written), (ACTION_REFUSE, []))
    check("...naming the run, not the record and not the enumerator",
          "target-App identity gate" in _refused.reason, True)
    # ...and BOTH upstream gates passed on this very PR, which is precisely why neither could catch
    # the run-layer refusal while it stood. They are what made "enumerability is not deliverability"
    # measurable, and they must keep passing now that delivery works.
    check("...while the record itself was admissible",
          admissible_by_the_review_lane(minted.document, 41,
                                        dispatch_claim.provenance_admission_error), None)
    check("...and the enumerator WOULD have emitted a review item for it", delivers(), None)
    # The refusal text is posted VERBATIM onto a pull request by auto-mint's `mint-refused`
    # comment, so it must carry no `#N`: a rendered reference is a live payload that a later
    # derivation can read back as a binding (the reason REASON_HINTS carries no literal numbers).
    check("the refusal text names no issue number, so pasting it back binds nothing",
          re.search(r"#\d", review_run_refusal(lambda: False, shell_admits=lambda: True)), None)

    # THE SOURCE-LABEL CHANNEL, asserted at the CALL SITE (mutation round 1: `issue_label_names`
    # returning [] killed nothing, because every label state the enumerator excludes on is already
    # refused upstream). So the property is wiring, and it is measured as wiring: a spy over the
    # production `dispatch_claim` module records what `mint()` actually handed the enumerator.
    class _SpyClaim:
        seen = {}

        def __getattr__(self, name):                     # delegate everything else, unchanged
            return getattr(dispatch_claim, name)

        def enumerate_review_items(self, *args, **kwargs):
            _SpyClaim.seen["issue_labels"] = args[4]
            _SpyClaim.seen["provenance"] = args[2]
            return dispatch_claim.enumerate_review_items(*args, **kwargs)

    _spy = _SpyClaim()
    mint(repo, 41, 7, "opus5", "reg/istry", routing, enrolled, env=good_env,
         read_pull=lambda: pull(), read_issue=lambda: issue(labels=[{"name": "area:ci"},
                                                                    {"name": "role:impl"}]),
         read_record=lambda: None, write_record=lambda: None,
         modules=(worker_pr, _spy, lease_schema), log=lambda *_a, **_k: None)
    check("mint() hands the enumerator the SOURCE ISSUE's real labels, keyed by its number",
          _SpyClaim.seen.get("issue_labels"), {7: ["area:ci", "role:impl"]})
    check("...and the document it is about to write, keyed by the PR",
          sorted((_SpyClaim.seen.get("provenance") or {})), [41])
    # ...and WHY that is belt-and-braces today, asserted rather than asserted-in-a-comment: every
    # source-issue label state the enumerator excludes on is refused upstream first.
    for label in ("needs:user", "status:parked"):
        check(f"issue_mint_refusal already refuses a source issue labelled {label!r}",
              isinstance(issue_mint_refusal(7, issue(labels=[{"name": "area:ci"},
                                                             {"name": label}]), pull(),
                                            lease_schema.plan_package,
                                            lease_schema.GLOBAL_PACKAGE), str), True)

    # ---- THE CENSUS: one disjoint verdict per open PR, decided by the production functions -----
    census_pulls = [
        pull(number=41, title="fix: a (#7)", body="closes #7"),                    # mintable
        pull(number=42, title="fix: b (#7)", body="closes #7",
             labels=[{"name": "needs:user"}]),                                    # dead
        pull(number=43, title="fix: c (#999)", body="closes #999"),                # no open issue
        pull(number=44, title="fix: d", body="no reference at all"),               # names nothing
        pull(number=45, title="fix: e (#7)", body="closes #7",
             head={"ref": "sparq-agent/issue-7-1-1"}),                             # other lane
        pull(number=46, title="fix: f (#7)", body="closes #7"),                   # recorded
    ]

    census_issues = [issue(), {"number": 8, "state": "open", "pull_request": {"url": "x"},
                               "labels": []}]

    # The census consults the SAME third last mile `mint()` does, so with the live identity gate
    # every enrollable row reads MINTABLE-BUT-DEAD. That is the truth, and it is asserted by its
    # own row below; the rows about the OTHER census branches inject an admitting gate so each
    # keeps testing the branch it names instead of passing for this one reason.
    class _AdmittingClaim:
        def __getattr__(self, name):                     # delegate everything else, unchanged
            return getattr(dispatch_claim, name)

        @staticmethod
        def review_fix_identity_admits_orchestrator_class(*_a, **_k):
            return True

    census_modules = (worker_pr, _AdmittingClaim(), lease_schema)

    def run_census(*, env=None, pulls=None, issues=None, recorded=frozenset({46}),
                   authors=None, census_mods=None):
        rows = []
        result = census(
            repo, "reg/istry", routing, enrolled if authors is None else authors,
            env=good_env if env is None else env,
            read_pulls=lambda: census_pulls if pulls is None else pulls,
            read_issues=lambda: census_issues if issues is None else issues,
            read_recorded=lambda: recorded,
            modules=census_mods or census_modules, log=rows.append)
        return result, rows

    verdicts, lines = run_census()
    check("every open PR gets exactly ONE verdict, and they are the expected disjoint set",
          [(number, verdict) for number, verdict, _ in verdicts],
          [(41, CENSUS_MINTABLE), (42, CENSUS_DEAD), (43, CENSUS_NO_ISSUE),
           (44, CENSUS_NO_ISSUE), (45, CENSUS_OTHER_LANE), (46, CENSUS_RECORDED)])
    check("...and the MINTABLE row tells the operator the exact issue to pass",
          [detail for number, _, detail in verdicts if number == 41], ["mint with --issue 7"])
    check("...and the DEAD row says the mint would deliver nothing",
          all(marker in next(d for n, _, d in verdicts if n == 42)
              for marker in ("binds", "does not enumerate")), True)
    summary = next(line for line in lines if line.startswith("census summary:"))
    check("the summary names EVERY bucket, so 'none' and 'not counted' differ",
          all(f"{verdict}=" in summary for verdict in CENSUS_VERDICTS), True)
    check("...and counts the whole population it walked", "open_prs=6" in summary, True)
    # THE ZERO-BUCKET LEG (mutation round 1: the population above filled all five buckets, so the
    # assertion above passed on a summary that printed only what it saw — the exact vacuity this
    # repo keeps measuring). Walk a population that leaves four buckets EMPTY: the summary must
    # still name all five, and `MINTABLE=0` is the reading a stalled feature actually produces.
    _, zero_lines = run_census(pulls=[pull(number=42, title="fix: b (#7)", body="closes #7",
                                           labels=[{"name": "needs:user"}])], recorded=frozenset())
    zero_summary = next(line for line in zero_lines if line.startswith("census summary:"))
    check("a census with FOUR empty buckets still names all five, and says MINTABLE=0",
          (all(f"{verdict}=" in zero_summary for verdict in CENSUS_VERDICTS),
           f"{CENSUS_MINTABLE}=0" in zero_summary, "open_prs=1" in zero_summary),
          (True, True, True))
    # The refusal summary is BOUNDED but never silently truncated, and it puts the FIXABLE reason
    # first — the closed/absent lines are the ones a PR body full of cross-references generates.
    _many = ([f"#{n}: not an OPEN issue in this repo" for n in range(20)]
             + ["#99: source issue #99 reduces to the serializing __global__ partition"])
    _rendered = summarise_refusals(_many)
    check("the refusal summary leads with the FIXABLE reason, not the closed ones",
          _rendered.startswith("#99: source issue #99 reduces"), True)
    check("...names how many candidates it did not show", "(+18 more candidate(s), 20 of them "
          "closed/absent)" in _rendered, True)
    check("...and is bounded", _rendered.count("; ") < len(_many), True)
    check("no candidates at all says so", summarise_refusals([]),
          "the PR's title and body name no #<n> at all")
    # A candidate that is really a PULL REQUEST is not an open issue for this purpose (#112) — and
    # this leg drives `census()` so the FILTER over the live issues listing is what is measured, not
    # `issue_mint_refusal`'s independent refusal one layer down. The verdict is the same either way
    # (mutation round 1), so the REASON is the observable: dropping the filter makes the census
    # report "is a PULL REQUEST" where PLAN would have reported an absent label row.
    _pr_row = {"number": 7, "state": "open", "pull_request": {"url": "x"}, "labels": []}
    _, pr_row_lines = run_census(pulls=[pull(number=48, title="fix: h (#7)", body="closes #7")],
                                 issues=[_pr_row], recorded=frozenset())
    check("a candidate resolving to a PULL REQUEST row is reported as absent from the ISSUE map",
          "not an OPEN issue in this repo" in next(
              line for line in pr_row_lines if line.startswith("census ")), True)
    check("a `#<n>` that resolves to a PULL REQUEST is not offered as a candidate",
          census_verdict(repo, pull(number=47, title="fix: g (#8)", body="closes #8"),
                         {8: {"number": 8, "state": "open", "pull_request": {"url": "x"},
                              "labels": []}},
                         enrolled, routing, "orchestrator:9.1", "s",
                         attestation_class=attestation_class,
                         orchestrator_class=orchestrator_class,
                         plan_package=lease_schema.plan_package,
                         global_package=lease_schema.GLOBAL_PACKAGE,
                         account_hash=worker_pr.account_hash,
                         json_type_exact=worker_pr._json_type_exact,
                         enumerate_review_items=dispatch_claim.enumerate_review_items,
                         now=1_800_000_000, identity_admits=lambda: True,
                         shell_admits=lambda: True)[0],
          CENSUS_NO_ISSUE)
    # THE CENSUS CANNOT DRIFT FROM THE MINT, and the contract is symmetric: it must not offer a
    # mint the writer would refuse, and it must not report DEAD a class the writer would mint.
    #
    # [registry #1288] These rows flipped with the gate. Under the LIVE gate the census now agrees
    # with the LIVE mint that row 41 is MINTABLE — and the DEAD direction is preserved directly
    # below by INJECTING a refusing gate, so the branch keeps its coverage instead of losing it to
    # the flip.
    _live_verdicts, _live_lines = run_census(census_mods=modules)
    check("with the LIVE identity gate the census reports the class MINTABLE, matching mint()",
          [row[1] for row in _live_verdicts if row[0] == 41], [CENSUS_MINTABLE])
    check("...and the row again offers the operator the exact issue to pass",
          any("mint with --issue 7" in line for line in _live_lines), True)

    class _RefusingClaim:
        def __getattr__(self, name):                     # delegate everything else, unchanged
            return getattr(dispatch_claim, name)

        @staticmethod
        def review_fix_identity_admits_orchestrator_class(*_a, **_k):
            return False

    _dead_verdicts, _dead_lines = run_census(
        census_mods=(worker_pr, _RefusingClaim(), lease_schema))
    check("...and a REFUSING identity gate still reports the class DEAD, not MINTABLE",
          [row[1] for row in _dead_verdicts if row[0] == 41], [CENSUS_DEAD])
    check("...naming the gate that refuses, and the issue that did bind",
          all(needle in next(line for line in _dead_lines if line.startswith("census o/r#41:"))
              for needle in ("target-App identity gate", "issue #7 binds")), True)
    check("...so no census line offers a mint the writer would refuse",
          any("mint with --issue" in line for line in _dead_lines), False)
    # ...and the property that keeps that true for a caller that does not exist yet. The rows above
    # all drive the ONE current call site, which passes the probe explicitly — so giving the
    # parameter a permissive default survived every one of them (measured: mutant M17). The
    # docstring claims the conjunct is impossible to forget; that claim is a fact about the
    # SIGNATURE, so the signature is what is asserted.
    check("census_verdict's identity_admits is REQUIRED — a default is what would let a future "
          "caller silently omit the run gate",
          inspect.signature(census_verdict).parameters["identity_admits"].default,
          inspect.Parameter.empty)
    check("...and it is keyword-ONLY, so it cannot be satisfied by positional accident",
          inspect.signature(census_verdict).parameters["identity_admits"].kind,
          inspect.Parameter.KEYWORD_ONLY)
    # The census must never print a hash — it is the ONE surface that walks the whole population,
    # and the record's privacy decision (22a) is that a login's hash is only ever written, never
    # reported alongside anything that identifies it.
    check("no census line prints an account hash",
          any(minted.document["impl_account_h"] in line for line in lines), False)
    # ...and it needs no secret to decide: the ephemeral salt is why that is a PROPERTY.
    _, lines_nosalt = run_census(env=_Env({"GITHUB_RUN_ID": "555", "GITHUB_RUN_ATTEMPT": "1"}))
    check("the census decides identically with NO PROVENANCE_SALT in the environment",
          [line for line in lines_nosalt if line.startswith("census ")],
          [line for line in lines if line.startswith("census ")])
    # A missing run identity is the one thing the census cannot report around: it decides what a
    # MINT would decide, and a mint has no stamp without it. Loud, never a page of false refusals.
    try:
        run_census(env=_Env({"PROVENANCE_SALT": "s"}))
    except MintError as exc:
        check("a census with no runner run identity RAISES rather than refusing every PR",
              "stamp" in str(exc), True)
    else:
        check("a census with no runner run identity RAISES rather than refusing every PR",
              "no raise", "MintError")
    # DISCOVERY may never propose a candidate the BINDING test would refuse for a boundary reason:
    # both read `#<n>` through the same two shared constants.
    _boundary = pull(title="see #412 and x#41 and (#41).", body="also #7")
    check("discovery and the binding test agree on every boundary",
          [n for n in referenced_issue_numbers(_boundary) if not references_issue(_boundary, n)],
          [])
    check("...and discovery finds exactly the word-bounded references",
          sorted(referenced_issue_numbers(_boundary)), [7, 41, 412])
    # TITLE-FIRST, and the RED test is the shape this PR itself hit: a body that cross-references a
    # LOWER-numbered open issue must not out-rank the source issue named in the title.
    check("the title's issue is offered FIRST, however low the body's cross-references run",
          referenced_issue_numbers({"title": "fix(x): thing (#959)",
                                    "body": "see #287, #112, #1 for context"}),
          [959, 287, 112, 1][:1] + [1, 112, 287])
    check("...and a body-only reference is still offered",
          referenced_issue_numbers({"title": "fix(x): thing", "body": "closes #7"}), [7])
    # The recorded-PR reader is derived from the PRODUCTION path builder, so a record for ANOTHER
    # target repo sharing the directory can never be counted as one of this repo's PRs.
    _listing = [{"name": worker_pr.provenance_path(repo, 685).rpartition("/")[2]},
                {"name": worker_pr.provenance_path("other/repo", 999).rpartition("/")[2]},
                {"name": "README.md"}, {"name": None}]
    check("the recorded-PR reader counts THIS repo's records only",
          recorded_pr_numbers(repo, "reg/istry", worker_pr, read_listing=lambda: _listing), {685})
    try:
        recorded_pr_numbers(repo, "reg/istry", worker_pr,
                            read_listing=lambda: {"message": "Not Found"})
    except MintError as exc:
        check("...and an unreadable listing RAISES rather than reading as 'nothing recorded'",
              "directory listing" in str(exc), True)
    else:
        check("...and an unreadable listing RAISES rather than reading as 'nothing recorded'",
              "no raise", "MintError")

    # ---- the enrolment ordering constraint ----------------------------------------------------
    # [#657 enable] This assertion used to read "the shipped policy enrols NOBODY" — the correct
    # statement while the minting path shipped ahead of the enable. The enable has now landed, and
    # the guard is REPOINTED rather than deleted: it pins the exact enabled SET, so it still goes
    # red on the two changes that matter — a SECOND repo enabled alongside a minting change (the
    # blast-radius widening this rollout deliberately deferred), or this repo's list emptied,
    # which would silently make every mint refusal permanent again. A guard that only ever says
    # "empty" cannot survive the feature it guards; one that names the population can.
    import tomllib

    policy_doc = tomllib.loads(
        (SCRIPTS_DIR.parent / "policy" / "repos.toml").read_text(encoding="utf-8"))
    policy_resolve = _load_policy_resolve()
    # [OPUS-5] ENABLED ROWS ONLY. `review_enrolment_authors` resolves through `_policy_row`, which
    # is fail-closed and RAISES `PolicyError: target repo ... is disabled`. Iterating every row
    # therefore crashed this self-test — and so the whole `gate` — the moment a legitimately
    # DISABLED target joined the policy (live: `jeswr/solid-sdk`, onboarded 2026-07-31 with
    # enabled=false until its routing pointer lands on its default branch). A disabled repo cannot
    # be enrolled BY CONSTRUCTION, so it contributes nothing to the enrolled set; skipping it is
    # the honest reading of the question this guard asks, not a workaround for the exception.
    # The assertion below is deliberately UNCHANGED — this fixes which rows are readable, never
    # what the guard demands of them.
    _enabled_rows = [name for name, row in (policy_doc.get("repos") or {}).items()
                     if isinstance(row, dict) and row.get("enabled")]
    enrolled_live = sorted(
        (name, sorted(policy_resolve.review_enrolment_authors(name, policy_doc)))
        for name in _enabled_rows)
    # [#1451] REPOINTED, not relaxed — exactly as the paragraph above prescribes. sparq's
    # follow-up has now landed, so the pinned population GROWS to name both enrolled repos. It
    # still reds on the two changes that matter: a THIRD repo enrolled alongside a minting change
    # (jeswr/solid-sdk is enabled and deliberately un-enrolled, so that widening is observable),
    # or either list emptied, which would silently make every mint refusal permanent again.
    check("the shipped policy enrols EXACTLY the registry and sparq, and only `jeswr` "
          "(jeswr/solid-sdk is enabled and deliberately NOT enrolled — it is the control)",
          [row for row in enrolled_live if row[1]],
          [("jeswr/agent-account-registry", ["jeswr"]), ("sparq-org/sparq", ["jeswr"])])
    # NON-VACUOUS in the other direction too: the same reader, over the same LIVE rows, surfaces an
    # EMPTY list for a repo that is not enrolled — so the assertion above is a fact about the
    # shipped policy rather than about a reader that returns whatever it is given.
    # [#1451] The un-enrolled EXAMPLE moves with the rollout: sparq is now enrolled, so asking
    # about it would assert ["jeswr"] == [] and red. jeswr/solid-sdk is the live enabled-but-
    # un-enrolled row, which is the whole reason a THIRD policy row was added before this enable —
    # without it this direction of the guard would have no subject and had to be deleted.
    check("...and the reader still reports an un-enrolled repo as empty",
          sorted(policy_resolve.review_enrolment_authors("jeswr/solid-sdk", policy_doc)), [])


    probe_doc = copy.deepcopy(policy_doc)
    # ...and the probe must pick an ENABLED row that does NOT already carry the key. Round-1
    # review: picking `sorted(_enabled_rows)[0]` selects the registry, which ALREADY resolves to
    # ["jeswr"], so setting it to ["jeswr"] is a value-identical no-op and the check below proves
    # nothing about the reader. A real transition needs a row whose CURRENT value is empty.
    # (A disabled row cannot serve either: it RAISES instead of reporting empty, testing the
    # exception rather than the reader.)
    _probe_candidates = [name for name in sorted(_enabled_rows)
                         if not policy_resolve.review_enrolment_authors(name, policy_doc)]
    assert _probe_candidates, (
        "the positive-transition probe needs an ENABLED policy row with NO review_enrolment_authors; "
        "every enabled row already carries one, so this probe can no longer prove a transition")
    probe_repo = _probe_candidates[0]
    check("...the probe row genuinely starts EMPTY, so the check below is a real transition",
          sorted(policy_resolve.review_enrolment_authors(probe_repo, policy_doc)), [])
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
    check("...and before EVERY invocation, not just the mint one",
          seam["self_test_before_every_invocation"], True)
    check("mode is an allowlist, and an unrecognised mode exits non-zero",
          seam["mode_is_allowlisted"], True)
    check("...over exactly the two modes", seam["mode_options"], ["census", "mint"])
    check("...defaulting to the READ-ONLY one", seam["mode_default"], "census")
    check("census refuses apply=true rather than ignoring it", seam["census_refuses_apply"], True)
    check("the census invocation EXECs, so it can never reach the --apply assembly",
          seam["census_invocation_execs"], True)
    check("the census branch is taken BEFORE the pr/issue guards it legitimately skips",
          seam["census_before_input_guards"], True)
    check("...and both guards still stand between that branch and the mint",
          seam["input_guards_before_mint"], True)
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
    check("every env name is bound to its OWN expression, and there are no others",
          seam["step_env_bindings"], {
              "GH_TOKEN": "${{ github.token }}",
              "PROVENANCE_SALT": "${{ secrets.PROVENANCE_SALT }}",
              "MODE": "${{ inputs.mode }}",
              "TARGET_REPO": "${{ inputs.target_repo }}",
              "PR_NUMBER": "${{ inputs.pr_number }}",
              "ISSUE_NUMBER": "${{ inputs.issue_number }}",
              "IMPL_ALIAS": "${{ inputs.impl_alias }}",
              "APPLY": "${{ inputs.apply }}",
              "ALLOW_GLOBAL": "${{ inputs.allow_global_partition }}",
              "ROUTING_FILE": "${{ steps.policy.outputs.routing_file }}",
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

    def replace_in_run(doc, old, new):
        """DISABLE-rather-than-delete: leave the line in place and make it inert. `if False`'s
        shell equivalents (a never-failing test, a `*)` that stops exiting) survive both a grep
        AND a comment-stripper, so they are the mutants a comment-only battery cannot see."""
        step = mint_step(doc)
        text = str(step["run"])
        assert text.count(old) == 1, f"seam mutant fragment not unique: {old!r}"
        step["run"] = text.replace(old, new)

    def prepend_to_run(doc, text):
        step = mint_step(doc)
        body = str(step["run"])
        head, _, tail = body.partition("set -euo pipefail\n")
        assert tail, "seam mutant anchor `set -euo pipefail` not found"
        step["run"] = head + "set -euo pipefail\n" + text + tail

    def move_guards_after_mint(doc):
        """Reordering is not a deletion, and no fragment check can see it: both guards stay in the
        script, spelled exactly as they are, but now run AFTER the mint they were guarding."""
        step = mint_step(doc)
        lines = str(step["run"]).splitlines(keepends=True)
        guards = [line for line in lines if re.search(r'\[\[ "\$(?:PR|ISSUE)_NUMBER" =~', line)]
        assert len(guards) == 2, guards
        rest = [line for line in lines if line not in guards]
        step["run"] = "".join(rest + guards)

    def swap_census_below_guards(doc):
        """The census branch (which legitimately skips the two guards) moved BELOW them, so a
        census run would be refused by a guard that does not apply to it."""
        step = mint_step(doc)
        body = str(step["run"])
        start = body.index('if [[ "$MODE" == "census" ]]; then')
        end = body.index("\n", body.index("--routing-file \"$ROUTING_FILE\"", start))
        end = body.index("\n", body.index("fi", end)) + 1
        branch, rest = body[start:end], body[:start] + body[end:]
        anchor = rest.index("args=(--target-repo")
        step["run"] = rest[:anchor] + branch + rest[anchor:]

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
             lambda d: comment_out_line(d, "set -euo pipefail"), "errexit", False),
            # ---- THE MODE SEAM: one mutant per clause, each reding a NAMED finding -------------
            # DELETE and DISABLE are different mutants and are both taken: the `case` allowlist is
            # commented out (deleted) AND widened to a never-refusing catch-all (inert).
            ("the mode allowlist survives only as a comment",
             lambda d: comment_out_line(d, 'case "$MODE" in'), "mode_is_allowlisted", False),
            ("the mode allowlist's refusal branch is made INERT (`*)` stops exiting)",
             lambda d: replace_in_run(d, "*) echo '::error::mode must be exactly census or mint'; "
                                      "exit 1 ;;", "*) ;;"), "mode_is_allowlisted", False),
            ("the census read-only refusal survives only as a comment",
             lambda d: comment_out_line(d, 'if [[ "$APPLY" == "true" ]]; then echo '
                                        "'::error::census is read-only"),
             "census_refuses_apply", False),
            ("the census invocation loses its `exec` (it would fall through to --apply)",
             lambda d: replace_in_run(d, "exec python3 scripts/mint-provenance.py --census",
                                      "python3 scripts/mint-provenance.py --census"),
             "census_invocation_execs", False),
            ("the pr_number guard survives only as a comment",
             lambda d: comment_out_line(d, '[[ "$PR_NUMBER" =~'), "input_guards_before_mint",
             False),
            ("the issue_number guard survives only as a comment",
             lambda d: comment_out_line(d, '[[ "$ISSUE_NUMBER" =~'), "input_guards_before_mint",
             False),
            ("the pr_number guard is made INERT (a never-failing pattern)",
             lambda d: replace_in_run(d, '[[ "$PR_NUMBER" =~ ^[1-9][0-9]*$ ]]',
                                      '[[ "$PR_NUMBER" == "$PR_NUMBER" ]]'),
             "input_guards_before_mint", False),
            ("the input guards are moved BELOW the mint invocation",
             lambda d: move_guards_after_mint(d), "input_guards_before_mint", False),
            ("the census branch is moved BELOW the guards it skips",
             lambda d: swap_census_below_guards(d), "census_before_input_guards", False),
            ("a second invocation appears with no self-test in front of it",
             lambda d: prepend_to_run(d, "python3 scripts/mint-provenance.py --census\n"),
             "self_test_before_every_invocation", False)):
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
    parser.add_argument("--impl-alias", default=DEFAULT_IMPL_ALIAS,
                        help="the implementing model alias; must resolve to "
                             f"{ORCHESTRATOR_IMPL_PROVIDER} in the target routing catalog")
    parser.add_argument("--routing-file", help="path to the target's routing.toml")
    parser.add_argument("--apply", action="store_true", help="write the record (default: dry run)")
    parser.add_argument("--census", action="store_true",
                        help="READ-ONLY: classify every open PR in the target — which ones this "
                             "writer can serve, and which would deliver no review. Writes "
                             "nothing, and is incompatible with --apply")
    parser.add_argument("--allow-global-partition", action="store_true",
                        help="accept a source issue that reduces to the serializing "
                             "__global__ partition")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    import tomllib

    def _require(*names):
        missing = [name for name in names if not getattr(args, name)]
        if missing:
            parser.error("missing required argument(s): "
                         + ", ".join("--" + name.replace("_", "-") for name in missing))

    def _resolve_policy():
        with open(args.routing_file, "rb") as handle:
            routing = tomllib.load(handle)
        policy_resolve = _load_policy_resolve()
        with open(SCRIPTS_DIR.parent / "policy" / "repos.toml", "rb") as handle:
            policy_doc = tomllib.load(handle)
        # The MASTER-protected half. `review_enrolment_authors` validates the whole policy row, so
        # a malformed or non-canonical list raises here rather than silently resolving to "nobody".
        return routing, policy_resolve.review_enrolment_authors(args.target_repo, policy_doc)

    if args.census:
        # READ-ONLY, refused rather than silently ignored: an operator who asked for both meant one
        # of them, and guessing which is how a "just show me" gesture writes to the ledger.
        if args.apply:
            parser.error("--census never writes: it is incompatible with --apply")
        _require("target_repo", "registry_repo", "routing_file")
        routing, enrolled_authors = _resolve_policy()
        census(args.target_repo, args.registry_repo, routing, enrolled_authors,
               impl_alias=args.impl_alias)
        # A census that finds nothing mintable is a REPORT, not a failure — the summary line is the
        # finding. Only an unreadable population fails, and that raises MintError above.
        return 0
    _require("target_repo", "registry_repo", "pr", "issue", "routing_file")
    routing, enrolled_authors = _resolve_policy()
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
