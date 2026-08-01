#!/usr/bin/env python3
# One-shot provenance backfill for worker PRs opened BEFORE registry provenance recording
# existed. Without a record those open, unarmed, bot-authored PRs are fail-closed INVISIBLE to
# the review loop forever; this writes the missing orchestration/provenance/ files AND converts
# each PR that has NOT YET BEEN THROUGH REVIEW to DRAFT (pre-migration PRs were opened non-draft,
# and both review gates hard-require draft — recording alone would leave them invisible).
# Recording and draft conversion are INDEPENDENT actions (issue #726): a PR that is queued to
# merge, auto-merge-armed or already `review:pass` is recorded but NEVER touched, because drafting
# it would evict it from the merge queue / discard a completed review. Idempotent: an existing
# record is never touched, an already-draft PR is left alone. DRY RUN unless --apply.
"""backfill-provenance — reconstruct implementer provenance for pre-existing worker PRs.

Identity source (the ONLY one): the worker RUN. The head branch embeds the registry run id
(`sparq-agent/issue-<N>-<run_id>-<attempt>`); that run's log carries the identity twice, in two
job sections that run no target/model code — the `provenance` job (REQUIRED, and PR-bound) and
the `claim` job (corroborating).

Both worker.yml invocation shapes are read (issue #712). The historical `provenance-record`
invocation passed identity as literal command arguments and bound the PR with `--pr`; the current
`reconcile-provenance` invocation passes identity through runner ENV echoes and has no `--pr` at
all, binding the PR by its deterministic `HEAD_BRANCH`. Reading only the first shape made every
current-shape recovery report AMBIGUOUS/tampered for a month.

There is deliberately NO commit-trailer fallback. Pre-existing PRs were created in the era when
the model container held the target push token, so trailers on exactly this population are
model-forgeable: a forged `[terra]`/GPT trailer on an anthropic-implemented PR would flip the
reviewer chain to the SAME provider and defeat the cross-provider inversion. A PR whose worker
run cannot be located stays fail-closed invisible and is listed for a HUMAN decision.

Privacy (locked decision 22a): the registry is public, so records store only
sha256(handle + ':' + PROVENANCE_SALT)[:16], never the raw handle — and this script never
prints a handle either.
"""

import argparse
import ast
import contextlib
import copy
import functools
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import types
from typing import NamedTuple

HEAD_RE = re.compile(r"^sparq-agent/issue-([1-9][0-9]*)-([0-9]+)-([0-9]+)$")

# The master-protected policy this script reads `review_enrolment_authors` out of (#657). A path,
# so the self-test can point the same code at a repo that actually enables enrolment — asserting
# only against the live policy, which enables it for nobody, would make every guard below
# unfalsifiable.
DEFAULT_POLICY_FILE = "policy/repos.toml"


class BackfillError(RuntimeError):
    """A concise, credential-free operational error."""


def parse_head_ref(ref):
    """(issue, run_id, attempt) from a worker head branch, or None."""
    match = HEAD_RE.fullmatch(ref or "")
    if not match:
        return None
    return int(match.group(1)), match.group(2), match.group(3)


# --- SPLIT refusal diagnostics (issue #712) ---------------------------------------------------
# One catch-all message used to say a run's "log is unavailable, has neither trusted job-anchored
# identity source, or the sources DISAGREE (tampered/ambiguous evidence)". Those are FOUR distinct
# situations with four different correct responses, and collapsing them made a PARSER-SHAPE gap
# read as tamper evidence for a month: seven worker PRs stayed fail-closed invisible, and one of
# them (sparq#4185) reserved the __global__ package partition and took the fleet to zero worker
# launches for an hour. Every code below still REFUSES — this widens what the parser can READ,
# never what it will ACCEPT.
REASON_LOG_UNAVAILABLE = "log-unavailable"      # the run log could not be fetched at all
REASON_NO_SOURCE = "no-anchored-source"         # log readable, zero anchored identity evidence
REASON_DISAGREE = "sources-disagree"            # two trusted readings name different identities
REASON_INCOMPLETE = "incomplete-anchored-evidence"   # some anchored fields present, others absent
REASON_BINDING_MISMATCH = "pr-binding-mismatch"      # evidence resolves but not to THIS PR
REASON_AUTHOR_MISMATCH = "bot-author-mismatch"       # echoed --verify-bot-login != live author

# What a human should DO about each — the whole point of splitting them.
REFUSAL_GUIDANCE = {
    REASON_LOG_UNAVAILABLE:
        "the run log could not be read (expired retention, or this job lacks `actions: read`); "
        "re-run once the log is readable — this is NOT evidence of tampering",
    REASON_NO_SOURCE:
        "the log carries no provenance-job-anchored identity evidence at all; establish the "
        "implementer identity by hand before any record is written",
    REASON_DISAGREE:
        "two trusted readings name DIFFERENT implementers — treat as tampered/ambiguous evidence "
        "and investigate before recording anything",
    REASON_INCOMPLETE:
        "the anchored evidence is PARTIAL, which usually means worker.yml changed shape and this "
        "parser has not been taught the new one; nothing here indicates tampering",
    REASON_BINDING_MISMATCH:
        "the anchored evidence resolves, but binds to a different PR/issue/repo than this one — a "
        "reused or forged run id in the head branch",
    REASON_AUTHOR_MISMATCH:
        "the run REQUIRED a different App-bot author than this PR actually has, so the provenance "
        "job failed VALIDATION rather than the registry write",
}


class Refusal(NamedTuple):
    """A fail-closed refusal with a SEPARATELY REPORTED reason. `code` is one of the REASON_*
    constants; `detail` is a concise, credential-free explanation."""

    code: str
    detail: str


# --- Job-anchored line patterns ---------------------------------------------------------------
# TRUST SCOPE: in `gh run view --log` output every line is prefixed `<job>\t<step>\t<timestamp>
# <content>`. Every pattern here ANCHORS on the job name — "provenance" for the reconcile job and
# "claim" for the lease job, NEITHER of which runs target/model code. A hostile model printing a
# lookalike line lands under the WORKER job's prefix and can never match. An UNANCHORED search
# (sol r1 on #147) let worker output forge an identity and defeat the cross-provider inversion.
# `[ \t]+` after the timestamp, never `\s+`: `\s` matches a NEWLINE, which would let a pattern
# start on one anchored line and finish on the next.
_LINE = r"(?mi)^[^\t]*{job}[^\t]*\t[^\t]*\t\S+[ \t]+"
_PROV_JOB = _LINE.format(job="provenance")
_CLAIM_JOB = _LINE.format(job="claim")

# The Actions runner wraps every `run:` SCRIPT line in cyan SGR controls, and `gh run view --log`
# emits them raw (`\x1b[36;1m ... \x1b[0m`) or caret-sanitized (`^[[36;1m ...`) rather than
# stripping (sol r6 — with a synthetic-fixture false green, the six command fields matched NOTHING
# in a real log). COMMAND-ECHO fields therefore tolerate that wrapper.
_SGR_PREFIX = r"(?:(?:\^\[|\x1b)\[[0-9;]*m)?\s*"


def _arg_echo(job, flag, value_pattern):
    """A `run:` command-echo argument (`--impl-alias "fable"`), SGR-wrapper tolerant. Only
    LITERAL values match: the current workflow echoes `--impl-alias "$IMPL_ALIAS"`, whose `$`
    fails every value pattern below — so an arg echo and its env echo can never double-count."""
    return re.compile(job + _SGR_PREFIX + re.escape(flag) + r"(?![A-Za-z0-9_-])\s*"
                      + value_pattern)


def _env_echo(job, key, value_pattern):
    """A runner-emitted `env:` block line (`  IMPL_ALIAS: fable`). Deliberately SGR-INTOLERANT:
    env echoes are emitted by the runner and never wrapped, so refusing the wrapper stops an
    SGR-wrapped SCRIPT SOURCE line that merely CONTAINS `KEY: value` from being read as a
    runtime value (the echo-vs-output trap that already caused two wrong diagnoses here)."""
    return re.compile(job + re.escape(key) + r":[ \t]*" + value_pattern + r"[ \t]*\r?$")


_ACCT_V = r"(acct[0-9a-z]{2,})"
_ALIAS_V = r'"?([A-Za-z0-9][A-Za-z0-9_.-]*)"?'
_PROVIDER_V = r'"?(anthropic|openai)"?'
_BOTLOGIN_V = r'"?([A-Za-z0-9._-]+\[bot\])"?'
_REPO_V = r'"?([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)"?'
_NUM_V = r'"?([1-9][0-9]*)"?'
_BRANCH_V = r"(sparq-agent/issue-[1-9][0-9]*-[0-9]+-[0-9]+)"

# The env-echo KEY NAMES this parser reads out of worker.yml's provenance job. Pinned to the
# workflow by _worker_yaml_shape_report() in the self-test, so renaming one there goes RED
# immediately instead of silently degrading every recovery to NEEDS-HUMAN a month later.
PROV_ENV_KEYS = ("WORKER_IMPL_ACCOUNT", "HEAD_BRANCH", "VERIFY_BOT_LOGIN",
                 "IMPL_PROVIDER", "IMPL_ALIAS")
CLAIM_ENV_KEYS = ("EXPECTED_ACCOUNT",)

# BOTH invocation shapes are read (issue #712). The historical `provenance-record` invocation
# passed identity as literal ARGUMENTS and bound the PR with `--pr`; the current
# `reconcile-provenance` invocation passes identity through runner ENV and has no `--pr` at all,
# binding the PR by its deterministic `HEAD_BRANCH`. A field resolves from whichever shape is
# present; if both are present they must agree (a per-field set, so a conflict is DISAGREE).
PROV_ACCOUNT_ENV_RE = _env_echo(_PROV_JOB, "WORKER_IMPL_ACCOUNT", _ACCT_V)
PROV_ALIAS_ARG_RE = _arg_echo(_PROV_JOB, "--impl-alias", _ALIAS_V)
PROV_ALIAS_ENV_RE = _env_echo(_PROV_JOB, "IMPL_ALIAS", _ALIAS_V)
# The PROVIDER is run-bound (sol r3): deriving it from TODAY's mutable routing lets a routing
# remap flip a historical anthropic run to openai and defeat the cross-provider gate.
PROV_PROVIDER_ARG_RE = _arg_echo(_PROV_JOB, "--impl-provider", _PROVIDER_V)
PROV_PROVIDER_ENV_RE = _env_echo(_PROV_JOB, "IMPL_PROVIDER", _PROVIDER_V)
# The exact App-bot author the job REQUIRED (sol r4): accepting any *[bot] would record a
# provenance job that failed VALIDATION (hostile worker pointed it at another bot's PR) as if it
# were the #96 write outage.
PROV_BOTLOGIN_ARG_RE = _arg_echo(_PROV_JOB, "--verify-bot-login", _BOTLOGIN_V)
PROV_BOTLOGIN_ENV_RE = _env_echo(_PROV_JOB, "VERIFY_BOT_LOGIN", _BOTLOGIN_V)
PROV_TARGET_ARG_RE = _arg_echo(_PROV_JOB, "--target-repo", _REPO_V)
PROV_ISSUE_ARG_RE = _arg_echo(_PROV_JOB, "--issue", _NUM_V)
PROV_PR_ARG_RE = _arg_echo(_PROV_JOB, "--pr", _NUM_V)
PROV_HEAD_BRANCH_ENV_RE = _env_echo(_PROV_JOB, "HEAD_BRANCH", _BRANCH_V)

PROV_JOB_FIELDS = {
    "account": (PROV_ACCOUNT_ENV_RE,),
    "alias": (PROV_ALIAS_ARG_RE, PROV_ALIAS_ENV_RE),
    "provider": (PROV_PROVIDER_ARG_RE, PROV_PROVIDER_ENV_RE),
    "bot_login": (PROV_BOTLOGIN_ARG_RE, PROV_BOTLOGIN_ENV_RE),
    "target_repo": (PROV_TARGET_ARG_RE,),
    "issue": (PROV_ISSUE_ARG_RE,),
    # --- PR binding: at least one of these two is required (see _PR_BINDING_FIELDS) ---
    "pr": (PROV_PR_ARG_RE,),
    "head_branch": (PROV_HEAD_BRANCH_ENV_RE,),
}
_REQUIRED_FIELDS = ("account", "alias", "provider", "bot_login", "target_repo", "issue")
# Either binding is sufficient and BOTH are equally strong. `--pr` names the PR number directly;
# `HEAD_BRANCH` names the exact branch the run published, and a branch name is unique within the
# target repo, so a run whose log names branch B can only be transplanted onto a PR whose head IS
# B. That is the same attack `--pr` defended against (a reused/forged run id in a head branch),
# closed the same way — and this parser only ever reaches a PR whose head ref it already parsed
# the run id out of.
_PR_BINDING_FIELDS = ("pr", "head_branch")

# --- The claim job: a SECOND, independent corroborating source --------------------------------
# Legacy shape (one line, both fields). Kept so historical runs keep parsing.
CLAIM_LEGACY_RE = re.compile(
    _CLAIM_JOB + r"(?:lease claimed|dispatcher lease adopted): account=" + _ACCT_V
    + r", model=([A-Za-z0-9][A-Za-z0-9_.-]*)")
# Current shape: privacy decision 22b removed `account=` from the printed claim line, so the
# account now comes from the step's runner-emitted env echo and the alias from the runtime print.
CLAIM_ACCOUNT_RE = _env_echo(_CLAIM_JOB, "EXPECTED_ACCOUNT", _ACCT_V)
# NO _SGR_PREFIX and no leading slack: the phrase must begin IMMEDIATELY after the timestamp, so
# the claim job's own SGR-wrapped source line `print(f"dispatcher lease adopted: model={model}…")`
# — script text, not runtime output — can never be read as a claimed model.
CLAIM_MODEL_RE = re.compile(
    _CLAIM_JOB + r"(?:lease claimed|dispatcher lease adopted): "
    r"model=([A-Za-z0-9][A-Za-z0-9_.-]*)")


def claim_from_log(log_text):
    """Tri-state: (account, model_alias) from CLAIM-job-anchored lines, None when the source is
    absent (or only half-readable — half a corroborating source is no corroboration, and this
    job runs no model code so a partial read is shape drift, never tampering), or a
    Refusal(REASON_DISAGREE) when differing repeats conflict (tamper evidence — sol r2)."""
    text = log_text or ""
    legacy = CLAIM_LEGACY_RE.findall(text)
    accounts = {acct for acct, _ in legacy} | set(CLAIM_ACCOUNT_RE.findall(text))
    aliases = {alias for _, alias in legacy} | set(CLAIM_MODEL_RE.findall(text))
    if not accounts and not aliases:
        return None
    conflicting = [name for name, values in (("account", accounts), ("model", aliases))
                   if len(values) > 1]
    if conflicting:
        return Refusal(REASON_DISAGREE,
                       "the claim job names more than one "
                       + " and ".join(conflicting) + " for this run")
    if not accounts or not aliases:
        return None
    return accounts.pop(), aliases.pop()


def provenance_job_identity_from_log(log_text):
    """A dict {account, alias, provider, bot_login, target_repo, issue, + pr and/or head_branch}
    read from the provenance job's own log section, or a Refusal.

    The refusal is SPLIT three ways (issue #712) because the responses differ:
    - REASON_DISAGREE     — a field has differing repeated matches. Tamper evidence.
    - REASON_NO_SOURCE    — not one anchored field matched. No evidence at all.
    - REASON_INCOMPLETE   — some fields matched and others did not. Shape drift, not tampering.
    Every one of them still refuses."""
    text = log_text or ""
    out = {}
    saw_any = False
    conflicting = []
    for key, patterns in PROV_JOB_FIELDS.items():
        found = set()
        for pattern in patterns:
            found |= set(pattern.findall(text))
        saw_any = saw_any or bool(found)
        if len(found) > 1:
            conflicting.append(key)
        elif found:
            out[key] = found.pop()
    if conflicting:
        # A conflicted field is tamper evidence whatever else is missing — never fall back past it.
        return Refusal(REASON_DISAGREE,
                       "the provenance job echoes conflicting values for "
                       + ", ".join(sorted(conflicting)))
    missing = [key for key in _REQUIRED_FIELDS if key not in out]
    if not any(key in out for key in _PR_BINDING_FIELDS):
        missing.append("a PR binding (--pr or HEAD_BRANCH)")
    if missing:
        if not saw_any:
            return Refusal(REASON_NO_SOURCE,
                           "no provenance-job-anchored identity evidence is present in the log")
        return Refusal(REASON_INCOMPLETE,
                       "the provenance job's anchored evidence is missing " + ", ".join(missing))
    out["issue"] = int(out["issue"])
    if "pr" in out:
        out["pr"] = int(out["pr"])
    return out


def pr_binding_error(anchored, pr_number, head_ref):
    """Why the anchored evidence does not bind to THIS PR, or None. Every binding the run echoed
    must match; presence of at least one is already enforced upstream."""
    if anchored.get("pr") is not None and anchored["pr"] != int(pr_number):
        return f"the run recorded PR #{anchored['pr']}, not #{int(pr_number)}"
    if anchored.get("head_branch") is not None and anchored["head_branch"] != head_ref:
        return "the run published a different head branch than this PR's"
    return None


def run_identity_from_log(log_text, target_repo, pr_number, issue, live_author, head_ref):
    """The PR-BOUND (account, model_alias, provider) for the run, or a Refusal (needs-human).

    Fail-closed rules, ALL unchanged by issue #712 — only the diagnostics were split and the
    readable shapes widened:
    - The provenance-job source is REQUIRED. Its own log section binds the identity to the exact
      PR being recorded (--target-repo/--issue plus --pr or HEAD_BRANCH must match the live PR);
      an unbound identity (claim line only) is NEVER sufficient.
    - AMBIGUITY in EITHER source (conflicting repeats) fails the run — never fall back past a
      conflicted source.
    - When the claim-job source is also readable it must AGREE on (account, alias)."""
    anchored = provenance_job_identity_from_log(log_text)
    if isinstance(anchored, Refusal):
        return anchored
    if anchored["target_repo"] != target_repo or anchored["issue"] != int(issue):
        return Refusal(REASON_BINDING_MISMATCH,
                       "the run echoes a different target repo/issue than this PR")
    binding = pr_binding_error(anchored, pr_number, head_ref)
    if binding is not None:
        return Refusal(REASON_BINDING_MISMATCH, binding)
    # The job hard-required this exact App author (--verify-bot-login); the live PR author must
    # still match it EXACTLY — any *[bot] is not enough (sol r4).
    if anchored["bot_login"] != live_author:
        return Refusal(REASON_AUTHOR_MISMATCH,
                       "the run required a different App-bot author than this PR has")
    claim = claim_from_log(log_text)
    if isinstance(claim, Refusal):
        return claim
    identity = (anchored["account"], anchored["alias"])
    if claim is not None and claim != identity:
        return Refusal(REASON_DISAGREE,
                       "the claim job and the provenance job name different implementers")
    return anchored["account"], anchored["alias"], anchored["provider"]


def flatten_pull_pages(pages):
    """Flatten `gh api --paginate --slurp` output (a list of per-page LISTS) into one pull
    list, or None when the shape is malformed. Every page must be a list of dicts."""
    if not isinstance(pages, list):
        return None
    pulls = []
    for page in pages:
        if not isinstance(page, list):
            return None
        for pull in page:
            if not isinstance(pull, dict):
                return None
            pulls.append(pull)
    return pulls


def provider_of(alias, routing):
    meta = (routing.get("models") or {}).get(alias)
    provider = meta.get("provider") if isinstance(meta, dict) else None
    return provider if provider in {"anthropic", "openai"} else None


def _run_gh(args, *, check=True):
    result = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise BackfillError(f"GitHub request failed: {' '.join(args[:3])}")
    return result


def _gh_json(args):
    raw = _run_gh(args).stdout
    try:
        return json.loads(raw or "null")
    except json.JSONDecodeError as exc:
        raise BackfillError("GitHub returned malformed JSON") from exc


def _load_script_module(filename, module_name):
    path = Path(__file__).resolve().parent / filename
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise BackfillError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_worker_pr():
    return _load_script_module("worker-pr.py", "registry_worker_pr")


def _load_dispatch_claim():
    """The review loop's OWN admission schema (dispatch-claim.provenance_admission_error) —
    IMPORTED, never replicated (same posture as groom), so backfill's "already recorded"
    judgement and the review loop's "will this record be admitted" judgement cannot drift."""
    return _load_script_module("dispatch-claim.py", "registry_dispatch_claim")


def _load_policy_resolve():
    """The accessor that VALIDATES the policy row before yielding `review_enrolment_authors`.

    Same posture as PLAN, CLAIM, groom and mint-provenance: a hand-rolled read of the TOML key
    would happily parse a malformed or `[bot]`-bearing list, and a `[bot]` entry is precisely
    what must never reach an author gate."""
    return _load_script_module("policy-resolve.py", "registry_policy_resolve")


def enrolled_review_authors(target_repo, policy_file):
    """The repo's MASTER-protected `review_enrolment_authors`, or an empty frozenset.

    An unreadable / unlisted policy resolves to "nobody", which is the shipped state of every
    repo and makes every orchestrator-class branch below inert — backfill then behaves
    byte-for-byte as it did before #657."""
    try:
        with open(policy_file, "rb") as handle:
            import tomllib
            document = tomllib.load(handle)
        return frozenset(_load_policy_resolve().review_enrolment_authors(target_repo, document))
    except Exception:            # noqa: BLE001 — enrolment OFF is the fail-closed answer here
        return frozenset()


def orchestrator_class_admission(claim, pull, target_repo, enrolled_authors, read_record):
    """[registry #657, design record §7.4 step 2b] Is this open PR an ADMITTED member of the
    orchestrator class? Returns the admitted record, or None.

    WHY BACKFILL NEEDS TO KNOW AT ALL. Backfill's candidate filter is the WORKER PRODUCER SHAPE
    (a `sparq-agent/issue-<N>-<run>-<attempt>` head ref plus a `[bot]` author), and #821's waiver
    exists precisely because an orchestrator PR satisfies NEITHER. Left as a bare shape test the
    class is invisible here — which is the RIGHT outcome, but for the wrong reason, and the wrong
    reason is what drifts: widen `HEAD_RE` or relax the author gate and backfill would start
    treating orchestrator PRs as un-recorded worker PRs. It would then (a) hunt a worker RUN LOG
    that does not exist for the class — `HEAD_RE`'s run id IS backfill's only identity source, and
    a self-authored PR has no worker run — reporting every one of them NEEDS-HUMAN, and (b)
    DRAFT-CONVERT them, which for a class the review lane admits *because* it stands the draft
    requirement down is a pure regression. Minting for the class is `mint-provenance.py`'s job
    (#827) and always was.

    So the class is recognised EXPLICITLY, through the SAME predicate every other consumer
    admits by (`admits_orchestrator_pr` + the shared field admission under its orchestrator
    opt-in), and skipped with an honest reason.

    ORDER IS LOAD-BEARING. The FORK GATE is first and is not waivable by anything below it —
    hoisted rather than fused into an `or`/`and` with the waivable shape tests, because inside
    a boolean list the order is irrelevant and the real hazard is CO-WAIVER.

    The allowlist half is asked with dispatch-claim's OWN probe record rather than a second
    casefold comparison written here: a valid `orchestrator`-attested record for THIS PR number
    satisfies the record half by construction, so the answer is exactly "is this login enrolled?"
    — computed by the live predicate, so it cannot drift from it, and cheap enough to gate the
    network record read behind. An EMPTY allowlist (every repo's default) answers False for every
    PR and no record is read at all.

    ``read_record`` is a ``() -> record | None`` callable; a raise propagates to the caller."""
    head = pull.get("head") or {}
    if (head.get("repo") or {}).get("full_name") != target_repo:
        return None                       # FORK GATE FIRST — never waivable, by anything
    number = pull.get("number")
    login = (pull.get("user") or {}).get("login", "")
    if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
        return None
    if not isinstance(login, str) or not login:
        return None
    if not claim.admits_orchestrator_pr(claim.orchestrator_probe_record(number), number,
                                        login, enrolled_authors):
        return None                       # not enrolled => not a candidate => no record read
    record = read_record()
    if not claim.admits_orchestrator_pr(record, number, login, enrolled_authors):
        return None
    if claim.provenance_admission_error(record, number, admit_orchestrator=True) is not None:
        return None
    return record


def effective_record_body(probe, ledger_ref):
    """The EFFECTIVE existing-record body for a PR — ledger-first — or None when neither copy
    exists. Readers consume the ledger copy FIRST (issue #96), so a present ledger record is
    judged AS-IS; the master fallback covers ONLY the clean ledger 404 (the pre-outage
    migration case — mirrors groom.worker_pr_provenance_enumerable). ``probe(ref=...)``
    returns (body, sha), (None, None) on a clean 404, and RAISES on any other failure — a
    transient/permission ledger error must never fall through to master and let a possibly
    divergent or invisible primary record count as recorded (sol #217)."""
    body, _sha = probe(ref=ledger_ref)
    if body is not None:
        return body
    body, _sha = probe(ref=None)
    return body


def _decoded_record(body):
    """The parsed record for a probe body, or None when it is absent or not valid JSON.

    Never raises: "unreadable" and "absent" both mean NOT an admitted orchestrator record, which
    is the fail-closed answer for every branch that consumes this. The WORKER path deliberately
    keeps its own decode (existing_record_admission_error) — there a malformed record is
    NEEDS-HUMAN, not a silent skip, and collapsing the two would lose that distinction."""
    if body is None:
        return None
    try:
        return json.loads(body)
    except ValueError:
        return None


def _ledger_record(worker_pr, registry_repo, target_repo, number):
    """The PARSED ledger-first provenance record for `target_repo#number`, or None.

    A named function rather than a nested lambda: ``effective_record_body`` calls its probe with
    the KEYWORD ``ref=``, so the probe's parameter name is part of the contract — and the head ref
    is called `ref` in the caller's scope too, which is exactly the shadowing a lambda invites.
    Raises ``WorkerPrError`` on a non-404 probe failure, as ``effective_record_body`` does."""
    record_path = worker_pr.provenance_path(target_repo, number)

    def probe(ref=None):
        return worker_pr._probe_registry_file(registry_repo, record_path, ref=ref)

    return _decoded_record(effective_record_body(probe, worker_pr.LEDGER_REF))


def existing_record_admission_error(body, pr_number, admission_error):
    """Why an existing record body does NOT admit target PR ``pr_number``, or None when it
    passes the review loop's full admission (sol #217: a successful Contents response used to
    short-circuit UNDECODED, so a malformed/mismatched record — which every reader rejects —
    was skipped as "already recorded" and the PR stayed fail-closed invisible forever)."""
    try:
        record = json.loads(body)
    except ValueError:
        return "the record is not valid JSON"
    return admission_error(record, pr_number)


# --- WHAT THE EXISTING RECORD MAKES THIS PR (registry #776) ------------------------------------
# Three dispositions, not two. The middle one — a record that EXISTS but which every consumer
# REFUSES — used to share the "leave it alone" branch with a healthy record and print NEEDS-HUMAN
# forever. It is a distinct state with a distinct machine action, so it gets a distinct name.
def seal_population(accounted, population):
    """Assert that every worker PR in the population left `backfill()` through exactly one
    COUNTED exit. Returns None, or RAISES BackfillError (registry #776).

    A backfill that silently skips is another state with no exit — the class this estate found
    eight times in one day. Two exits in `backfill()` printed `skip #N` and touched no counter,
    so the completion line's arithmetic had quietly stopped describing the population; both were
    unreached on live data, which is exactly why they survived review.

    IT RAISES RATHER THAN RETURNING A REASON, deliberately. A `reason = check(...)` / `if reason:
    raise` shape has a seam between deciding and acting, and a mutation run over this very change
    proved the seam is where the vacuity lives: deleting the two-line `if ... raise` while leaving
    the computation in place SURVIVED every test, because the tests exercised the predicate and
    the call site's existence but nothing forced the result to have an effect. There is no seam to
    delete when the decision and the raise are the same statement."""
    if accounted == population:
        return None
    raise BackfillError(
        f"backfill accounting is unsealed: {accounted} counted outcome(s) for a population "
        f"of {population} worker PR(s) — some PR left the loop through an uncounted exit")


RECORD_ABSENT = "absent"                 # nothing anywhere -> MINT from the run log
RECORD_ADMITS = "admits"                 # healthy -> SKIP, never rewritten, on any path
RECORD_INADMISSIBLE = "inadmissible"     # present but dead to every consumer -> REPAIR


def record_disposition(body, pr_number, admission_error):
    """PURE. What the EFFECTIVE existing record body (ledger-first, None when neither copy
    exists) makes this PR: one of the RECORD_* constants, plus the admission diagnostic.

    The whole point of naming the middle state is that its machine action DIFFERS. Measured on
    the live estate 2026-07-27: 7 master records carry the attempt-less `backfill:<run>` stamp an
    OLDER revision of THIS script wrote, which the post-#657 admission refuses. Two of them
    (sparq#2439/#2456) are open worker PRs. `backfill()` printed NEEDS-HUMAN for them on every
    run since #657 and could never do anything else, because a repair has to write a record and
    the only writer refused to touch a PR that already had one. A state whose only exit is a
    human is a state with no exit — this estate found that class eight times in one day."""
    if body is None:
        return RECORD_ABSENT, None
    error = existing_record_admission_error(body, pr_number, admission_error)
    if error is None:
        return RECORD_ADMITS, None
    return RECORD_INADMISSIBLE, error


# --- DRAFT CONVERSION: the property is "not yet through review", NOT "is not a draft" (#726) ---
# The old predicate was simply `if is_draft: return`, i.e. it drafted EVERY non-draft worker PR.
# That is right for a freshly published worker PR — publish-never-arms is what keeps an unreviewed
# PR from merging, and both review gates hard-require draft==True, so a non-draft unreviewed PR is
# invisible. It INVERTS for a PR that has already been through review: converting a PR that is in
# the merge queue EVICTS it from the queue, and converting an armed PR un-arms a merge that already
# passed. A single backfill pass would have destroyed three in-flight merges (sparq#3894/#4074/
# #4185) to fix a partition problem.
#
# THE DISCRIMINATING CASE: `autoMergeRequest` reads NULL for a PR that is already IN the queue
# (GitHub consumes the auto-merge request when it enqueues). An arm-only check therefore misses
# exactly the population at risk. Merge-queue membership is queried EXPLICITLY via GraphQL
# `mergeQueueEntry` — see `review_state`.
#
# FAILURE DIRECTION: on an unreadable/malformed review-state probe we SKIP the conversion. Not
# converting is a no-op relative to the pre-backfill state (the PR was already non-draft and is
# not armed by us, so nothing can merge that could not merge before) and the next pass converges;
# converting on unknown state is irreversible eviction of a live merge. Records are still written
# either way — the two actions are independent.
REVIEW_PASS_LABEL = "review:pass"

QUEUE_QUEUED = "queued"
QUEUE_NOT_QUEUED = "not-queued"
QUEUE_UNKNOWN = "unknown"

DRAFT_SKIP_ALREADY = "already-draft"
DRAFT_SKIP_QUEUED = "in-merge-queue"
DRAFT_SKIP_ARMED = "auto-merge-armed"
DRAFT_SKIP_REVIEW_PASS = "review-passed"
DRAFT_SKIP_QUEUE_UNKNOWN = "review-state-unknown"
DRAFT_SKIP_OPERATOR = "no-draft-convert"

DRAFT_SKIP_GUIDANCE = {
    DRAFT_SKIP_ALREADY: "already a draft",
    DRAFT_SKIP_QUEUED: "it is IN THE MERGE QUEUE; drafting would evict it from the queue",
    DRAFT_SKIP_ARMED: "auto-merge is armed; drafting would un-arm a merge that passed review",
    DRAFT_SKIP_REVIEW_PASS: f"it carries `{REVIEW_PASS_LABEL}`; drafting would discard a "
                            "completed review",
    DRAFT_SKIP_QUEUE_UNKNOWN: "its live review state could not be read, so whether drafting would "
                              "evict a queued merge is UNKNOWN — rerun once the probe succeeds",
    DRAFT_SKIP_OPERATOR: "--no-draft-convert was passed (record-only pass)",
}


class ReviewState(NamedTuple):
    """The live signals that say a PR has ALREADY been through review. `queue_state` is one of
    the QUEUE_* constants; UNKNOWN means the probe failed and nothing here may be trusted."""

    queue_state: str
    is_armed: bool
    has_review_pass: bool


# The sentinel for "not probed / not readable". UNKNOWN, never NOT_QUEUED, so that a caller which
# forgets to probe skips the conversion instead of evicting a queued PR.
UNKNOWN_REVIEW_STATE = ReviewState(QUEUE_UNKNOWN, False, False)

# `mergeQueueEntry` is the ONLY signal that reports queue membership; REST's `auto_merge` and
# GraphQL's `autoMergeRequest` are both null once a PR is enqueued. All three fields come from one
# query so there is a single failure mode to reason about.
REVIEW_STATE_QUERY = """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      mergeQueueEntry { state }
      autoMergeRequest { enabledAt }
      labels(first: 100) { nodes { name } }
    }
  }
}
"""
_REVIEW_STATE_FIELDS = ("mergeQueueEntry", "autoMergeRequest", "labels")


def query_selected_fields(query, parent):
    """The field names selected inside `parent { ... }` in a GraphQL document. The parser demands
    every _REVIEW_STATE_FIELDS key in the RESPONSE, and a response only carries what the QUERY
    asked for — so deleting `mergeQueueEntry` from the document silently turns every PR into
    "unknown" (or, with a laxer parser, "not queued"). The self-test pins document to parser."""
    opening = re.search(re.escape(parent) + r"[^{]*\{", query)
    if not opening:
        return set()
    depth, index, start = 1, opening.end(), opening.end()
    while index < len(query) and depth:
        depth += {"{": 1, "}": -1}.get(query[index], 0)
        index += 1
    if depth:
        return set()
    fields, level = set(), 0
    for line in query[start:index - 1].splitlines():
        text = line.strip()
        name = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", text)
        if level == 0 and name:
            fields.add(name.group(1))
        level += text.count("{") - text.count("}")
    return fields


def parse_review_state(payload):
    """A ReviewState from a `gh api graphql` response body, or UNKNOWN_REVIEW_STATE when the
    payload is absent, errored, or not exactly the shape asked for. Deliberately strict: a
    partially-rendered payload must not read as "not queued"."""
    if not isinstance(payload, dict) or payload.get("errors"):
        return UNKNOWN_REVIEW_STATE
    node = payload.get("data")
    for key in ("repository", "pullRequest"):
        if not isinstance(node, dict):
            return UNKNOWN_REVIEW_STATE
        node = node.get(key)
    if not isinstance(node, dict) or not set(_REVIEW_STATE_FIELDS) <= set(node):
        return UNKNOWN_REVIEW_STATE
    entry, auto, labels = (node[key] for key in _REVIEW_STATE_FIELDS)
    if entry is not None and not isinstance(entry, dict):
        return UNKNOWN_REVIEW_STATE
    if auto is not None and not isinstance(auto, dict):
        return UNKNOWN_REVIEW_STATE
    nodes = labels.get("nodes") if isinstance(labels, dict) else None
    if not isinstance(nodes, list):
        return UNKNOWN_REVIEW_STATE
    names = {label.get("name") for label in nodes if isinstance(label, dict)}
    return ReviewState(QUEUE_QUEUED if entry is not None else QUEUE_NOT_QUEUED,
                       auto is not None, REVIEW_PASS_LABEL in names)


def review_state(target_repo, number, runner=None):
    """Probe the live review state of one PR. Never raises: every failure is UNKNOWN, which the
    predicate treats as "do not touch draft state"."""
    runner = runner or _run_gh
    owner, _, name = str(target_repo).partition("/")
    if not owner or not name:
        return UNKNOWN_REVIEW_STATE
    result = runner(["api", "graphql", "-f", f"query={REVIEW_STATE_QUERY}",
                     "-F", f"owner={owner}", "-F", f"name={name}", "-F", f"number={int(number)}"],
                    check=False)
    if result.returncode != 0:
        return UNKNOWN_REVIEW_STATE
    try:
        payload = json.loads(result.stdout or "null")
    except json.JSONDecodeError:
        return UNKNOWN_REVIEW_STATE
    return parse_review_state(payload)


def draft_skip_reason(is_draft, state, no_draft_convert=False):
    """Why the draft conversion must be SKIPPED for this PR (a DRAFT_SKIP_* code), or None when
    it must happen. `state` is a ReviewState."""
    if is_draft:
        return DRAFT_SKIP_ALREADY
    if no_draft_convert:
        return DRAFT_SKIP_OPERATOR
    if state.queue_state == QUEUE_QUEUED:
        return DRAFT_SKIP_QUEUED
    if state.is_armed:
        return DRAFT_SKIP_ARMED
    if state.has_review_pass:
        return DRAFT_SKIP_REVIEW_PASS
    if state.queue_state != QUEUE_NOT_QUEUED:
        # UNKNOWN, or any value this function was never taught: fail toward the no-op.
        return DRAFT_SKIP_QUEUE_UNKNOWN
    return None


def _ensure_draft(target_repo, number, is_draft, apply_changes, *, state,
                  no_draft_convert=False, runner=None):
    """Convert a not-yet-reviewed non-draft PR to draft (both review gates require draft==True).
    Runs independently of record recording so a partially-failed earlier pass converges, and
    REFUSES on any PR that has already been through review (issue #726). `state` is REQUIRED —
    there is no default, so no call site can silently skip the merge-queue probe."""
    runner = runner or _run_gh
    reason = draft_skip_reason(is_draft, state, no_draft_convert)
    if reason is not None:
        if reason != DRAFT_SKIP_ALREADY:
            print(f"KEEP-PUBLISHED #{number}: not converting to draft — "
                  f"{DRAFT_SKIP_GUIDANCE[reason]}")
        return True
    if not apply_changes:
        print(f"DRY-RUN #{number}: would convert to draft (review gates require draft)")
        return True
    undo = runner(["pr", "ready", str(number), "-R", target_repo, "--undo"], check=False)
    if undo.returncode != 0:
        print(f"WARN #{number}: could not convert to draft — run "
              f"`gh pr ready {number} -R {target_repo} --undo` manually")
        return False
    print(f"converted #{number} to draft")
    return True


def backfill(target_repo, registry_repo, routing_file, apply_changes, no_draft_convert=False,
             policy_file=DEFAULT_POLICY_FILE):
    worker_pr = _load_worker_pr()
    claim = _load_dispatch_claim()
    admission_error = claim.provenance_admission_error
    # [registry #657] The MASTER-protected half of orchestrator-class admission. Empty for every
    # repo today, which makes every branch keyed on it inert.
    enrolled_authors = enrolled_review_authors(target_repo, policy_file)
    import tomllib
    with open(routing_file, "rb") as handle:
        routing = tomllib.load(handle)
    salt = os.environ.get("PROVENANCE_SALT", "")
    if not salt:
        raise BackfillError("PROVENANCE_SALT is required (records store only the salted hash)")

    # --slurp: without it `gh api --paginate` emits each page as a SEPARATE json array and a
    # >100-open-PR target aborts on "malformed JSON" before recovery begins (sol r5).
    pages = _gh_json(["api", "--paginate", "--slurp",
                      f"repos/{target_repo}/pulls?state=open&per_page=100"])
    pulls = flatten_pull_pages(pages)
    if pulls is None:
        raise BackfillError("pull listing is malformed")
    written = skipped = needs_human = repaired = blocked = write_failed = 0
    # [registry #776] The POPULATION this run is accountable for: every open, same-repo,
    # bot-authored worker PR. Counted at the same branch that admits the PR into the loop, so
    # the seal below compares two numbers derived from ONE walk. Without it "skipped 76" was
    # unfalsifiable — a PR that fell out of an uncounted `continue` was indistinguishable from
    # one that was never in the population, which is how two silent exits survived below.
    population = 0
    # [registry #776 x #876] THE #657 ORCHESTRATOR CLASS IS OUTSIDE THE POPULATION, and therefore
    # outside the seal. This is a decision about what "the population" MEANS, not a loosening:
    #
    #   1. The seal's whole power comes from `population` being incremented at ONE branch that is
    #      genuinely UPSTREAM of many exits — six of them below. The orchestrator branch has
    #      exactly one counted outcome, immediately adjacent, so incrementing `population` there
    #      too would be arithmetic that can never disagree with itself: zero added seal coverage,
    #      and a denominator that means no more than "whatever I happened to count". A seal that
    #      cannot fail is the thing this change exists to stop shipping.
    #   2. Substantively, backfill CANNOT ever record this class and must not try (#876/#827:
    #      there is no worker run to source an identity from, `mint-provenance.py` owns it). A
    #      population containing PRs the script is structurally forbidden to act on makes
    #      `recorded / population` a ratio of nothing.
    #
    # So it gets its OWN counter rather than riding `skipped`. #876's point — that the class must
    # be VISIBLE rather than fall out of an accidental shape test — is fully preserved: it is
    # named on the completion line, in its own bucket. What it stops doing is inflating a bucket
    # that means "already carries an admissible record".
    out_of_scope = 0
    for pull in pulls:
        if not isinstance(pull, dict):
            continue
        number = pull.get("number")
        head = pull.get("head") or {}
        ref = str(head.get("ref", ""))
        login = str((pull.get("user") or {}).get("login", ""))
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            continue
        # FORK GATE FIRST, and alone (#657). It used to sit BETWEEN the head-ref parse and the
        # author gate, which was safe only because nothing could skip either of them. Hoisted, it
        # is the one predicate here that no waiver — present or future — can be fused with.
        if (head.get("repo") or {}).get("full_name") != target_repo:
            continue                      # fork heads never get provenance
        parsed = parse_head_ref(ref)
        if parsed is None or not login.endswith("[bot]"):
            # NOT the worker producer shape. Before this reads as "nothing to do", ask the ONE
            # shared #657 predicate whether it is an ADMITTED orchestrator PR, because the two
            # populations need opposite handling and only one of them is safe to treat as
            # un-recorded. See orchestrator_class_admission for why admitting the class into the
            # loop below would be a defect rather than the fix.
            try:
                orchestrator_record = orchestrator_class_admission(
                    claim, pull, target_repo, enrolled_authors,
                    functools.partial(_ledger_record, worker_pr, registry_repo,
                                      target_repo, number))
            except worker_pr.WorkerPrError:
                # An unreadable registry probe on a PR that was invisible to this script anyway
                # is not news: it stays invisible. Nothing is written, nothing is claimed.
                continue
            if orchestrator_record is not None:
                out_of_scope += 1
                print(f"skip #{number}: #657 orchestrator class — provenance is minted by "
                      "scripts/mint-provenance.py, never backfilled (there is no worker run to "
                      "source an identity from), and the class is NON-DRAFT by design so draft "
                      "conversion must not touch it")
            continue
        population += 1
        is_draft = pull.get("draft") is True
        # Probe the LIVE review state only for an actual draft-conversion candidate (an
        # already-draft PR is never converted, so its state cannot change any outcome and the
        # query would be wasted). The unprobed value is UNKNOWN, not NOT_QUEUED, so removing the
        # `is_draft` short-circuit would skip conversions rather than evict queued PRs.
        state = UNKNOWN_REVIEW_STATE if is_draft else review_state(target_repo, number)
        issue, run_id, attempt = parsed
        record_path = worker_pr.provenance_path(target_repo, number)
        # Post-outage records live on the `ledger` data-plane branch (issue #96); pre-outage
        # ones on master. "Already recorded" is claimable ONLY when the effective ledger-first
        # record decodes and passes the review loop's admission for THIS PR (sol #217): a
        # non-404 probe failure defers the PR (worker_pr._probe_registry_file raises — unknown
        # never counts as recorded), and a present-but-inadmissible record is NEEDS-HUMAN,
        # never a skip (this script never rewrites an existing record).
        pr_probe = lambda ref=None: worker_pr._probe_registry_file(  # noqa: E731
            registry_repo, record_path, ref=ref)
        try:
            body = effective_record_body(pr_probe, worker_pr.LEDGER_REF)
        except worker_pr.WorkerPrError as exc:
            needs_human += 1
            print(f"NEEDS-HUMAN #{number}: cannot establish whether provenance is already "
                  f"recorded ({exc}); leaving untouched — rerun once the registry probe "
                  "succeeds")
            continue
        disposition, record_error = record_disposition(body, number, admission_error)
        if disposition == RECORD_ADMITS:
            skipped += 1
            print(f"skip #{number}: provenance already recorded")
            # Still reconcile the draft state (an earlier pass may have crashed between
            # the two).
            _ensure_draft(target_repo, number, is_draft, apply_changes, state=state,
                          no_draft_convert=no_draft_convert)
            continue
        if disposition == RECORD_INADMISSIBLE:
            # [registry #776] The machine exit. Fall through to the SAME run-log re-derivation
            # the mint path uses — no new trust is introduced, because a resolved identity here
            # rests on exactly the evidence a fresh record rests on, and it is strictly HIGHER
            # trust than the record being replaced (whose trust basis is what failed admission).
            # Gating the repair on agreement with the refused record would let the lower-trust
            # artifact veto its own repair, i.e. rebuild the dead end one layer down.
            print(f"REPAIR #{number}: the existing provenance record is present but NOT "
                  f"admissible by the review loop ({record_error}); re-deriving the implementer "
                  "identity from the worker run log")

        # The worker RUN LOG is the only accepted identity source (no trailer fallback: trailers
        # on this pre-migration population are model-forgeable — see the module docstring).
        # The ATTEMPT encoded in the head branch is passed explicitly (sol r1): without it a
        # rerun's log could source identity from a different attempt than the one that pushed
        # this head.
        run_key = f"backfill:{run_id}.{attempt}"
        log = _run_gh(["run", "view", run_id, "--attempt", attempt,
                       "--repo", registry_repo, "--log"], check=False)
        if log.returncode != 0:
            # SEPARATELY REPORTED (issue #712): an unreadable log is an ACCESS problem, not
            # evidence about the implementer. It used to share one message with "no source" and
            # "sources disagree", so a retention/permission failure read as tamper evidence.
            found = Refusal(REASON_LOG_UNAVAILABLE,
                            f"`gh run view` could not read run {run_id} attempt {attempt}")
        else:
            found = run_identity_from_log(log.stdout, target_repo, number, issue, login, ref)
        if isinstance(found, Refusal):
            needs_human += 1
            print(f"NEEDS-HUMAN #{number} [{found.code}]: run {run_id} attempt {attempt}: "
                  f"{found.detail}. {REFUSAL_GUIDANCE[found.code]}. Leaving fail-closed "
                  "invisible — record provenance only after a human establishes the "
                  "implementer identity.")
            continue
        account, alias, echo_provider = found
        provider = provider_of(alias, routing)
        if provider is None:
            needs_human += 1
            print(f"NEEDS-HUMAN #{number}: alias {alias!r} has no provider in routing")
            continue
        if provider != echo_provider:
            # sol r3: the run's own --impl-provider echo is authoritative for HISTORY; a
            # disagreement means today's routing was remapped since the run — recording
            # today's provider could flip the cross-provider reviewer gate.
            needs_human += 1
            print(f"NEEDS-HUMAN #{number}: the run recorded provider {echo_provider!r} but "
                  f"today's routing maps {alias!r} to {provider!r}; a human must resolve the "
                  "remap before this identity is recorded")
            continue
        commits = _gh_json(["api", f"repos/{target_repo}/pulls/{number}/commits?per_page=100"])
        # [registry #776] COUNTED. These two exits printed `skip #N` and fell out of the loop
        # touching no counter at all, so the completion line's arithmetic silently stopped
        # describing the population. They are unreached on today's data, which is exactly why
        # they survived: an uncounted exit is invisible until the day it fires.
        if not isinstance(commits, list) or not commits:
            blocked += 1
            print(f"BLOCKED #{number}: PR has no commits, so there is no head sha to bind the "
                  "record to; leaving fail-closed invisible")
            continue
        opened_sha = str((commits[0] or {}).get("sha", ""))
        if not re.fullmatch(r"[0-9a-f]{40}", opened_sha):
            blocked += 1
            print(f"BLOCKED #{number}: first commit sha is malformed, so the record cannot be "
                  "bound to a head; leaving fail-closed invisible")
            continue

        impl_account_h = worker_pr.account_hash(account, salt)
        # The replacement must itself ADMIT. A repair that writes a second refused record would
        # convert a loud dead end into a silent one — and on the mint path this is the check that
        # says the schema this script writes is the schema the review loop reads, which is
        # precisely the drift that created the population being repaired.
        candidate = {"pr_number": number, "head_sha_at_open": opened_sha,
                     "impl_provider": provider, "impl_alias": alias,
                     "impl_account_h": impl_account_h, "issue": issue,
                     "recorded_at_run": run_key}
        candidate_error = admission_error(candidate, number)
        if candidate_error is not None:
            blocked += 1
            print(f"BLOCKED #{number}: the record this run would write is itself NOT admissible "
                  f"by the review loop ({candidate_error}); refusing to write it")
            continue
        repair = disposition == RECORD_INADMISSIBLE
        verb = "repair" if repair else "record"
        if apply_changes:
            try:
                worker_pr.provenance_record(registry_repo, target_repo, number, opened_sha,
                                            provider, alias, impl_account_h, issue, run_key,
                                            supersede_legacy=repair)
            # [registry #1317] ONE PR's failed write is not the whole population's failure.
            # `WorkerPrError` is NOT a `BackfillError`, so it flew straight past main()'s handler:
            # the FIRST bad write aborted the run with a traceback, every PR after it in the walk
            # was silently dropped, and neither the completion line nor the seal ever ran.
            # Survivable for a human-watched dispatch; disqualifying for the unattended trigger
            # this class needs, where nobody reads the traceback.
            #
            # [registry #1317 r1] BUT NOT THE BASE CLASS. `provenance_record` raises WorkerPrError
            # for THREE unrelated situations, and catching all of them here reported two of them
            # as things they are not:
            #   - a DIVERGENT existing record (the write-side CAS probe found a different record
            #     already at this path) is a PERMANENT provenance conflict. "The next run retries"
            #     is false — every future run re-reads the same record and refuses again — so it
            #     is NEEDS-HUMAN, exactly like every other "a human must establish the truth
            #     before anything is recorded" exit above.
            #   - an ARGUMENT/INTEGRITY violation (impl_provider not in the pair, a non-16-hex
            #     account hash, a non-40-hex head sha) means THIS SCRIPT derived a record it must
            #     never write. That is a defect in the walk itself, not one PR's bad luck, and it
            #     stays LOUD: it propagates, aborting the run, because continuing would repeat the
            #     same malformed derivation for every remaining PR.
            # Only the narrow write-exhausted class is soft, and only it claims a retry.
            except worker_pr.RegistryRecordConflictError as exc:
                needs_human += 1
                print(f"NEEDS-HUMAN #{number}: a DIVERGENT provenance record already exists for "
                      f"this PR ({exc}); refusing to overwrite it — this is a PERMANENT conflict "
                      "that no retry can clear, so a human must reconcile the existing record "
                      "with the identity this run derived")
                continue
            except worker_pr.RegistryWriteExhaustedError as exc:
                # Its OWN bucket, not `blocked`. `blocked` means "this run refused to write a
                # record it judged unsound" and the response is to fix the evidence; this means
                # "the write itself did not land" and the response is to look at the registry
                # write path — the #712 lesson that reasons are reported apart because the
                # responses are different. It is also the one gauge that says an unattended sweep
                # is failing to write at all, which a bucket shared with routine refusals could
                # never show.
                write_failed += 1
                print(f"WRITE-FAILED #{number}: could not {verb} the provenance record "
                      f"({exc}); leaving fail-closed invisible — records are create-only and no "
                      "divergent record was found, so the next run re-derives this PR and retries "
                      "the write")
                # Nothing was recorded, so no draft conversion: drafting here would mutate the
                # target for a PR that stays invisible to the review lane either way. #726's
                # independence runs ONE way — a failed draft must never withhold a record.
                continue
        else:
            # Privacy: never print the raw handle, only the (public-anyway) salted hash.
            print(f"DRY-RUN #{number}: would {verb} impl={provider}/{alias} "
                  f"account_h={impl_account_h} issue=#{issue} opened={opened_sha[:8]} "
                  f"({run_key})")
        if repair:
            repaired += 1
        else:
            written += 1
        # Recording is DONE by this point and its count is already banked: draft conversion is an
        # INDEPENDENT action whose outcome can never withhold a provenance record (issue #726).
        _ensure_draft(target_repo, number, is_draft, apply_changes, state=state,
                      no_draft_convert=no_draft_convert)
    mode = "recorded" if apply_changes else "would record"
    # `out-of-scope` rides OUTSIDE the parenthesised population figure on purpose: the reader must
    # be able to tell "this run adjudicated N worker PRs" from "and declined M PRs that were never
    # its job", which is exactly the distinction folding the #657 class into `skipped` destroyed.
    print(f"backfill complete: {mode} {written}, repaired {repaired}, skipped {skipped}, "
          f"needs-human {needs_human}, blocked {blocked}, write-failed {write_failed} "
          f"(population {population}) out-of-scope {out_of_scope}")
    # [registry #776] THE SEAL. Every worker PR left this loop through exactly one counted exit,
    # or this raises. Bare statement on purpose — see seal_population's docstring: a
    # `reason = ...` / `if reason: raise` shape has a deletable seam, and a mutant that deleted
    # exactly that seam survived the whole suite.
    seal_population(written + repaired + skipped + needs_human + blocked + write_failed,
                    population)


def identity_from_run_log(log_readable, log_text, target_repo, pr_number, issue, live_author,
                          head_ref, run_id, attempt):
    """`run_identity_from_log` plus the ACCESS check, so "the log could not be read" is a
    separately reported (and separately testable) refusal rather than a fourth meaning stuffed
    into the identity message."""
    if not log_readable:
        return Refusal(REASON_LOG_UNAVAILABLE,
                       f"`gh run view` could not read run {run_id} attempt {attempt}")
    return run_identity_from_log(log_text, target_repo, pr_number, issue, live_author, head_ref)


# --- WORKFLOW SEAM (issue #712) ---------------------------------------------------------------
# This parser reads a log SHAPE that .github/workflows/worker.yml produces. Nothing tied the two
# together, so when worker.yml switched from `provenance-record --pr …` to `reconcile-provenance`
# with env-passed identity, the parser silently stopped resolving ANY current run and reported it
# as tamper evidence for a month. The report below re-derives the shape FROM the workflow on every
# self-test run, so the next shape change goes red in CI instead of a month later in the fleet.
# Sample renderings for the `${{ }}` expressions worker.yml interpolates. An expression that is
# NOT in this table renders to a sentinel that fails every value pattern — so a new or renamed
# expression reds the seam assertions rather than quietly rendering to nothing.
_WF_SAMPLE = {
    "inputs.target_repo": "sparq-org/sparq",
    "inputs.issue_number": "77",
    "inputs.account": "acct07",
    "github.run_id": "1234567890",
    "github.run_attempt": "1",
    "github.token": "***",
    "secrets.PROVENANCE_SALT": "***",
    "needs.claim.outputs.account": "acct07",
    "needs.claim.outputs.provider": "anthropic",
    "needs.claim.outputs.model": "fable",
    "needs.resolve.outputs.model_chain": "fable",
    "needs.resolve.outputs.account_pool": "acct07",
    "needs.resolve.outputs.packages": "",
    "needs.resolve.outputs.role": "impl",
    "needs.resolve.outputs.worker_timeout_minutes": "60",
    "steps.app-token-recon.outputs.app-slug": "sparq-orchestrator",
    # The provenance job's review-state stamp step echoes a SECOND `--pr` — the PR the reconcile
    # step itself resolved. It only runs when reconcile succeeded (so a record exists and backfill
    # skips the PR), but it is in the same job section and must never collide with the identity
    # fields, so the replay below covers EVERY step of the job, not just the reconcile one.
    "steps.provenance.outputs.pr_number": "4242",
}
_WF_UNRENDERED = "<<unrendered-expression>>"


def _render_wf(text):
    return re.sub(r"\$\{\{\s*(.*?)\s*\}\}",
                  lambda m: _WF_SAMPLE.get(m.group(1), _WF_UNRENDERED), str(text))


def _log_line(job, content):
    """One `gh run view --log` line: `<job>\\t<step>\\t<timestamp> <content>`."""
    return f"{job}\tUNKNOWN STEP\t2026-01-01T00:00:00.0000000Z {content}\n"


def _render_job_section(job_name, step):
    """The log section a runner emits for one `run:` step: the SGR-wrapped script SOURCE echo,
    then the runner-emitted (never wrapped) `env:` block."""
    out = [_log_line(job_name, f"\x1b[36;1m{_render_wf(src)}\x1b[0m")
           for src in str(step.get("run") or "").splitlines()]
    out.append(_log_line(job_name, "env:"))
    for key, value in (step.get("env") or {}).items():
        out.append(_log_line(job_name, f"  {key}: {_render_wf(value)}"))
    return "".join(out)


def _workflow(name):
    import yaml
    path = Path(__file__).resolve().parents[1] / ".github" / "workflows" / name
    assert path.is_file(), f"{name} not found for the workflow-seam check: {path}"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def worker_yaml_shape_report():
    """Findings about the LIVE worker.yml, each asserted by the self-test."""
    jobs = _workflow("worker.yml")["jobs"]
    prov, claim, worker = jobs["provenance"], jobs["claim"], jobs["worker"]
    prov_step = next(s for s in prov["steps"]
                     if "reconcile-provenance" in str(s.get("run") or ""))
    claim_run = "\n".join(str(s.get("run") or "") for s in claim["steps"])

    def anchors(job_name):
        probe = _log_line(job_name, "probe")
        return (bool(re.search(_PROV_JOB + "probe", probe)),
                bool(re.search(_CLAIM_JOB + "probe", probe)))

    # The model job's name is an `${{ }}` expression; every literal it can render to must be
    # unanchored, or hostile worker output could land under a trusted prefix.
    worker_names = re.findall(r"'([^']*)'", str(worker["name"])) or [str(worker["name"])]
    # Replay the WHOLE provenance job exactly as the runner would log it, straight from the
    # workflow — every step, so a field echoed by a NEIGHBOURING step in the same job section
    # (the review-state stamp's `--pr`) is part of what the parser is asserted against.
    replayed = "".join(_render_job_section(prov["name"], s) for s in prov["steps"])
    # Replay the claim job's env echo plus the RUNTIME line its own `print(...)` emits — the
    # format string is lifted out of the workflow, so changing the phrase reds this.
    # BOTH claim paths are live — the self-claim step prints `lease claimed: model=…` and the
    # dispatcher-adopt step prints `dispatcher lease adopted: model=…`. Each phrase must still be
    # in the workflow, or half the corroborating source dies silently.
    phrases = [p for p in ("lease claimed: model=", "dispatcher lease adopted: model=")
               if f'print(f"{p}{{model}}' in claim_run]
    claim_replay = "".join(_render_job_section(claim["name"], s) for s in claim["steps"])
    for phrase in phrases:
        claim_replay += _log_line(claim["name"], f"{phrase}fable, claim=abcd1234")
    return {
        "prov_job_anchored": anchors(prov["name"]) == (True, False),
        "claim_job_anchored": anchors(claim["name"]) == (False, True),
        "worker_job_unanchored": all(anchors(n) == (False, False) for n in worker_names),
        "prov_env_keys": set(PROV_ENV_KEYS) <= set(prov_step.get("env") or {}),
        "claim_env_keys": set(CLAIM_ENV_KEYS) <= {k for s in claim["steps"]
                                                  for k in (s.get("env") or {})},
        "claim_prints_model": phrases,
        "reconcile_has_no_pr_arg": not re.search(r"--pr(?![A-Za-z0-9_-])",
                                                 str(prov_step.get("run") or "")),
        "replayed_identity": provenance_job_identity_from_log(replayed),
        "replayed_claim": claim_from_log(claim_replay),
    }


def backfill_workflow_seam_report(workflow=None):
    """Findings about the LIVE backfill-provenance.yml invocation, each asserted by the
    self-test. Substring/count assertions do not catch YAML-seam mutations (`if: false`, a
    deleted step, a reordered command), so every finding below is structural.

    Takes an optional PARSED document so the self-test can re-derive every finding from a
    deliberately broken copy: asserting the shipped shape proves this report can read a correct
    workflow, not that it would notice a neutered one.

    The `#1544` block is what that issue exists for. This workflow was `workflow_dispatch`-only,
    so an orphaned worker PR — fail-closed INVISIBLE to the review loop until its record exists —
    stranded until a human remembered to run it, pointed at the right repo. A workflow that loses
    its schedule, or whose matrix stops deriving from policy, is silently back in that state."""
    workflow = _workflow("backfill-provenance.yml") if workflow is None else workflow
    # PyYAML parses a bare `on:` key as the boolean True.
    triggers = workflow.get("on") if "on" in workflow else workflow.get(True)
    triggers = triggers or {}
    inputs = ((triggers.get("workflow_dispatch") or {}).get("inputs") or {})
    job = workflow["jobs"]["backfill"]
    steps = job["steps"]
    # The matrix half of #1544: the sweep covers every ENABLED target, and the enabled set is read
    # from policy rather than copied into this file. `needs` is a string when there is one entry.
    needs = job.get("needs")
    needs = [needs] if isinstance(needs, str) else sorted(needs or [])
    matrix = ((job.get("strategy") or {}).get("matrix") or {})
    targets_job = workflow["jobs"].get("targets") or {}
    targets_run = "\n".join(str(s.get("run") or "") for s in (targets_job.get("steps") or []))
    step = next((s for s in steps if "backfill-provenance.py" in str(s.get("run") or "")), None)
    run = str((step or {}).get("run") or "")
    guard = str(job.get("if") or "")
    self_at = run.find("backfill-provenance.py --self-test")
    invoke_at = run.find('backfill-provenance.py "${args[@]}"')
    # The WRONG-INPUT seam: `NO_DRAFT_CONVERT: ${{ inputs.apply }}` is valid YAML, lints clean, and
    # silently turns an apply run into a record-only run (or vice versa). Assert the exact
    # expression each env name is bound to, not merely that the name appears.
    step_env = {k: str(v) for k, v in ((step or {}).get("env") or {}).items()}
    return {
        "job_ref_guarded": "github.ref ==" in guard and "default_branch" in guard,
        "job_environment": job.get("environment"),
        "actions_read": (job.get("permissions") or {}).get("actions"),
        "contents_write": (job.get("permissions") or {}).get("contents"),
        "step_unconditional": step is not None and "if" not in step,
        "errexit": "set -euo pipefail" in run,
        "self_test_before_backfill": 0 <= self_at < invoke_at,
        "apply_is_conditional": bool(
            re.search(r'\[\[\s*"\$APPLY"\s*==\s*"true"\s*\]\].*args\+=\(--apply\)', run)),
        "dispatch_default_is_dry_run": inputs.get("apply", {}).get("default"),
        # --- issue #726: the record-only lever -------------------------------------------------
        "no_draft_convert_is_conditional": bool(
            re.search(r'\[\[\s*"\$NO_DRAFT_CONVERT"\s*==\s*"true"\s*\]\].*'
                      r'args\+=\(--no-draft-convert\)', run)),
        "no_draft_convert_default": inputs.get("no_draft_convert", {}).get("default"),
        "step_env_bindings": {key: step_env.get(key)
                              for key in ("TARGET_REPO", "APPLY", "NO_DRAFT_CONVERT")},
        # --- issue #1544: this workflow must START ITSELF, across EVERY enabled target ----------
        # THE FINDING THIS ISSUE EXISTS FOR: dispatch-only meant the population only ever drained
        # when a human remembered. Reported as the cron LIST so a deletion reads as `[]`.
        "schedule_crons": [str((entry or {}).get("cron")) for entry in triggers.get("schedule")
                           or [] if isinstance(entry, dict)],
        # `default:` is materialised for workflow_dispatch ONLY, so ANY default here makes
        # "leave EMPTY to sweep every enabled target" unreachable from the UI/API — the manual
        # half silently narrows to one repo, which is the second stall #1544 measured. Reported as
        # (input present, default present) because a bare `.get("default")` reads None both when
        # there is no default AND when the whole input has been deleted.
        "target_repo_input": ("target_repo" in inputs,
                              "default" in (inputs.get("target_repo") or {})),
        # The matrix chain, link by link. Break any one and the sweep still "succeeds", over an
        # EMPTY set of repos — a green run that records nothing is indistinguishable from a
        # drained population, so each link is pinned to its exact expression.
        "matrix_needs": needs,
        "matrix_repo_expr": str(matrix.get("repo")),
        "targets_repos_output": str((targets_job.get("outputs") or {}).get("repos") or ""),
        # One source of truth. A hardcoded copy of the enabled set is the exact duplication that
        # took dispatch fully down on 2026-08-01 (#1537/#1540: policy enabled a third repo, the
        # workflow's manifest did not, CLAIM failed closed).
        "targets_policy_sourced": "policy/repos.toml" in targets_run,
    }


def _self_test():
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got} (want {want})")

    check("head ref parses", parse_head_ref("sparq-agent/issue-42-16234567890-1"),
          (42, "16234567890", "1"))
    check("non-worker ref rejected", parse_head_ref("feature/foo"), None)
    check("spoof-shaped ref without run id rejected", parse_head_ref("sparq-agent/issue-1-x"),
          None)
    claim_job = "Claim live account lease"
    prov_job = "Reconcile + record implementer provenance (no target code runs here)"
    worker_job = "Run live target worker (DRAFT, review pending)"
    HEAD = "sparq-agent/issue-3404-16234567890-1"

    def code_of(result):
        """The refusal code, or the result itself when it resolved."""
        return result.code if isinstance(result, Refusal) else result

    check("legacy claim line parses (claim-job-anchored)",
          claim_from_log(f"{claim_job}\tAdopt\t2026-07-18T09:03:04Z "
                         "lease claimed: account=acct0fx3, model=fable, claim=deadbeef\n"),
          ("acct0fx3", "fable"))
    check("legacy adopt line parses (claim-job-anchored)",
          claim_from_log(f"{claim_job}\tAdopt\t2026-07-18T09:03:04Z "
                         "dispatcher lease adopted: account=acct0fx4, model=terra, claim=ab"),
          ("acct0fx4", "terra"))
    # CURRENT claim shape (issue #712): privacy decision 22b removed `account=` from the printed
    # line, so account comes from the step env echo and alias from the runtime print. The old
    # single-line pattern returned None on EVERY live run, silently killing corroboration.
    live_claim = (_log_line(claim_job, "  EXPECTED_ACCOUNT: acct0fx1")
                  + _log_line(claim_job, "dispatcher lease adopted: model=fable, claim=3cceafe3"))
    check("CURRENT split claim shape parses (env account + runtime model line)",
          claim_from_log(live_claim), ("acct0fx1", "fable"))
    check("UNANCHORED claim line no longer matches (worker-job forgery class)",
          claim_from_log(f"{worker_job}\tmodel\t"
                         "2026-07-18T09:03:04Z lease claimed: account=acct0fx9, "
                         "model=terra, claim=ff"), None)
    # ECHO-vs-OUTPUT: the claim job's own SGR-wrapped SOURCE line CONTAINS the phrase. Reading it
    # as runtime output would mint an identity out of script text.
    claim_source_echo = _log_line(
        claim_job,
        '\x1b[36;1mprint(f"dispatcher lease adopted: model={model}, claim={claim_id[:8]}")'
        '\x1b[0m')
    check("SGR-wrapped claim SOURCE echo yields no model (echo != output)",
          CLAIM_MODEL_RE.findall(claim_source_echo), [])
    # The discriminating case: a `run:` HEREDOC BODY line whose text BEGINS with the phrase and
    # carries a LITERAL alias. The runner SGR-wraps it exactly like any other script line, so only
    # refusing the wrapper tells this script SOURCE apart from the job's runtime output.
    for wrapper, rendering in (("\x1b", "raw-ESC"), ("^[", "caret-sanitized")):
        check(f"a {rendering} SGR-wrapped heredoc line with a LITERAL alias is not runtime output",
              CLAIM_MODEL_RE.findall(_log_line(
                  claim_job,
                  f"{wrapper}[36;1m  dispatcher lease adopted: model=fable{wrapper}[0m")), [])
        check(f"...and a {rendering} SGR-wrapped `IMPL_ALIAS: fable` source line is not an env "
              "echo",
              PROV_ALIAS_ENV_RE.findall(_log_line(
                  prov_job, f"{wrapper}[36;1m  IMPL_ALIAS: fable{wrapper}[0m")), [])
    # An env echo is read as a WHOLE line or not at all. Catalog-controlled values reach this job
    # (worker.yml treats them as hostile — issue #199), so an alias of `fable junk` must refuse
    # rather than silently record the prefix `fable` as the implementer.
    check("an env echo with trailing content is refused, not truncated to its prefix",
          PROV_ALIAS_ENV_RE.findall(
              _log_line(prov_job, "  IMPL_ALIAS: fable junk")), [])
    check("...and the same value on a clean line does match",
          PROV_ALIAS_ENV_RE.findall(_log_line(prov_job, "  IMPL_ALIAS: fable")),
          ["fable"])
    check("no claim line", claim_from_log("nothing here"), None)
    check("half a claim source is no corroboration (account only)",
          claim_from_log(_log_line(claim_job, "  EXPECTED_ACCOUNT: acct0fx1")), None)
    # Trailer-derived identity is REJECTED by construction: there is no code path from a commit
    # message to a provenance record (a forged GPT trailer cannot flip the reviewer provider).
    check("no trailer-based identity source", hasattr(sys.modules[__name__],
                                                      "alias_from_trailer"), False)
    # Registry #681 rejected declaration-derived identity: no PR-body/declaration marker may be
    # load-bearing on the resolve path. There is no code path from a body marker to a record.
    check("no body-marker/declaration identity source",
          [n for n in ("alias_from_declaration", "identity_from_body", "alias_from_marker")
           if hasattr(sys.modules[__name__], n)], [])
    routing = {"models": {"terra": {"provider": "openai"}, "fable": {"provider": "anthropic"}}}
    check("provider lookup", provider_of("terra", routing), "openai")
    check("unknown alias provider", provider_of("ghost", routing), None)

    # --- SHAPE A: the historical `provenance-record` invocation (literal args, --pr) -----------
    def prov_legacy(account="acct0fx1", alias="fable", provider="anthropic",
                    target="sparq-org/sparq", pr=3459, issue=3404, wrap=True):
        # wrap=True reproduces the LITERAL `gh run view --log` shape: command echoes carry
        # caret-sanitized SGR wrappers + a trailing continuation backslash (sol r6); the env
        # echo line is runner-emitted and unwrapped.
        o, c = ("^[[36;1m  ", " \\^[[0m") if wrap else ("", " \\")
        return "".join(_log_line(prov_job, s) for s in (
            f"  WORKER_IMPL_ACCOUNT: {account}",
            f'{o}--target-repo "{target}"{c}',
            f'{o}--pr "{pr}"{c}',
            f'{o}--impl-provider "{provider}"{c}',
            f'{o}--impl-alias "{alias}"{c}',
            f'{o}--issue "{issue}"{c}',
            f'{o}--verify-bot-login "sparq-orchestrator[bot]"{c}'))

    # --- SHAPE C: the CURRENT `reconcile-provenance` invocation (env identity, no --pr) --------
    def prov_env(account="acct0fx1", alias="fable", provider="anthropic",
                 target="sparq-org/sparq", issue=3404, head=HEAD):
        return "".join(_log_line(prov_job, s) for s in (
            f'\x1b[36;1m  --target-repo "{target}" \\\x1b[0m',
            '\x1b[36;1m  --head-branch "$HEAD_BRANCH" \\\x1b[0m',
            '\x1b[36;1m  --impl-provider "$IMPL_PROVIDER" \\\x1b[0m',
            '\x1b[36;1m  --impl-alias "$IMPL_ALIAS" \\\x1b[0m',
            f'\x1b[36;1m  --issue "{issue}" \\\x1b[0m',
            '\x1b[36;1m  --verify-bot-login "$VERIFY_BOT_LOGIN"\x1b[0m',
            "env:",
            f"  WORKER_IMPL_ACCOUNT: {account}",
            f"  HEAD_BRANCH: {head}",
            "  VERIFY_BOT_LOGIN: sparq-orchestrator[bot]",
            f"  IMPL_PROVIDER: {provider}",
            f"  IMPL_ALIAS: {alias}"))

    legacy_log = prov_legacy()
    env_log = prov_env()
    legacy_bound = {"account": "acct0fx1", "alias": "fable", "provider": "anthropic",
                    "bot_login": "sparq-orchestrator[bot]",
                    "target_repo": "sparq-org/sparq", "pr": 3459, "issue": 3404}
    env_bound = {"account": "acct0fx1", "alias": "fable", "provider": "anthropic",
                 "bot_login": "sparq-orchestrator[bot]", "target_repo": "sparq-org/sparq",
                 "issue": 3404, "head_branch": HEAD}
    check("SHAPE A (provenance-record) parses ALL binding fields (caret-SGR log shape)",
          provenance_job_identity_from_log(legacy_log), legacy_bound)
    check("SHAPE A unwrapped (raw-print) still parses",
          provenance_job_identity_from_log(prov_legacy(wrap=False)), legacy_bound)
    check("SHAPE C (reconcile-provenance) parses env identity + HEAD_BRANCH binding",
          provenance_job_identity_from_log(env_log), env_bound)
    check("SHAPE C: `--impl-alias \"$IMPL_ALIAS\"` is NOT read as the literal alias $IMPL_ALIAS",
          "$IMPL_ALIAS" in str(provenance_job_identity_from_log(env_log)), False)

    ident = lambda log, pr=3459, issue=3404, author="sparq-orchestrator[bot]", head=HEAD: (
        run_identity_from_log(log, "sparq-org/sparq", pr, issue, author, head))
    check("SHAPE A bound identity resolves with the RUN's provider", ident(legacy_log),
          ("acct0fx1", "fable", "anthropic"))
    check("SHAPE C bound identity resolves with the RUN's provider", ident(env_log),
          ("acct0fx1", "fable", "anthropic"))

    # --- THE THREE SPLIT DIAGNOSTICS (issue #712) ----------------------------------------------
    # Collapsing these into one message is what made a parser-shape gap read as tamper evidence.
    # Each fixture below satisfies exactly ONE of them; the codes are then asserted pairwise
    # distinct, so a fixture that happened to satisfy two would not prove anything.
    forged = (_log_line(worker_job, "  WORKER_IMPL_ACCOUNT: acct0fx9")
              + _log_line(worker_job, '\x1b[36;1m  --impl-alias "opus"\x1b[0m'))
    partial = _log_line(prov_job, "  WORKER_IMPL_ACCOUNT: acct0fx1")
    conflicting = env_log + prov_env(account="acct0fx2")
    diagnostics = {
        REASON_LOG_UNAVAILABLE: identity_from_run_log(
            False, env_log, "sparq-org/sparq", 3459, 3404, "sparq-orchestrator[bot]", HEAD,
            "16234567890", "1"),
        REASON_NO_SOURCE: ident(forged),
        REASON_INCOMPLETE: ident(partial),
        REASON_DISAGREE: ident(conflicting),
    }
    for want, got in diagnostics.items():
        check(f"split diagnostic {want!r} is reported as ITSELF", code_of(got), want)
    check("the split diagnostics are DISTINCT codes, not one message",
          len({code_of(r) for r in diagnostics.values()}), len(diagnostics))
    check("a READABLE log with the same bytes resolves — so log-unavailable is about ACCESS only",
          identity_from_run_log(True, env_log, "sparq-org/sparq", 3459, 3404,
                                "sparq-orchestrator[bot]", HEAD, "16234567890", "1"),
          ("acct0fx1", "fable", "anthropic"))
    # The exact misdiagnosis this issue is about: PARTIAL evidence is shape drift, not tampering.
    check("PARTIAL anchored evidence is INCOMPLETE, never DISAGREE (the #712 misdiagnosis)",
          code_of(ident(partial)) == REASON_DISAGREE, False)
    check("ABSENT anchored evidence is NO-SOURCE, never INCOMPLETE",
          code_of(ident(forged)) == REASON_INCOMPLETE, False)
    check("every refusal code carries its own human guidance",
          sorted(REFUSAL_GUIDANCE) == sorted({REASON_LOG_UNAVAILABLE, REASON_NO_SOURCE,
                                              REASON_DISAGREE, REASON_INCOMPLETE,
                                              REASON_BINDING_MISMATCH, REASON_AUTHOR_MISMATCH}),
          True)

    # --- FAIL-CLOSED REFUSALS — all unchanged, only their reporting is split ------------------
    check("worker-job forgery cannot match (job-prefix anchor)",
          code_of(provenance_job_identity_from_log(forged)), REASON_NO_SOURCE)
    check("conflicting repeats are DISAGREE, not absent",
          code_of(provenance_job_identity_from_log(legacy_log + prov_legacy(account="acct0fx2"))),
          REASON_DISAGREE)
    check("provider conflicts are DISAGREE",
          code_of(provenance_job_identity_from_log(env_log + prov_env(provider="openai"))),
          REASON_DISAGREE)
    claim_ok = (f"{claim_job}\tAdopt\t2026-07-18T09:03:04Z "
                "lease claimed: account=acct0fx1, model=fable, claim=x\n")
    check("agreeing claim corroboration keeps the identity", ident(claim_ok + legacy_log),
          ("acct0fx1", "fable", "anthropic"))
    check("DISAGREEING trusted sources fail closed",
          code_of(ident(claim_ok.replace("acct0fx1", "acct0fx2") + legacy_log)), REASON_DISAGREE)
    check("conflicting claim repeats fail closed even with a clean anchored source (sol r2)",
          code_of(ident(claim_ok + claim_ok.replace("acct0fx1", "acct0fx2") + legacy_log)),
          REASON_DISAGREE)
    check("claim-only identity is NEVER sufficient (unbound to the PR)",
          code_of(ident(claim_ok)), REASON_NO_SOURCE)
    check("SHAPE A --pr binding mismatch fails closed (reused run id)",
          code_of(ident(legacy_log, pr=9999)), REASON_BINDING_MISMATCH)
    check("SHAPE C HEAD_BRANCH binding mismatch fails closed (reused run id)",
          code_of(ident(env_log, head="sparq-agent/issue-9-99-1")), REASON_BINDING_MISMATCH)
    check("issue-binding mismatch fails closed", code_of(ident(legacy_log, issue=1)),
          REASON_BINDING_MISMATCH)
    check("target-repo mismatch fails closed",
          code_of(run_identity_from_log(env_log, "attacker/repo", 3459, 3404,
                                        "sparq-orchestrator[bot]", HEAD)),
          REASON_BINDING_MISMATCH)
    check("live author must EXACTLY match the echoed --verify-bot-login (sol r4)",
          code_of(ident(legacy_log, author="different-bot[bot]")), REASON_AUTHOR_MISMATCH)
    check("an otherwise complete section with NO PR binding is INCOMPLETE, never accepted",
          code_of(provenance_job_identity_from_log(
              prov_env().replace(f"  HEAD_BRANCH: {HEAD}\n", ""))), REASON_INCOMPLETE)
    # EVERY required field is individually load-bearing: dropping any ONE of them from an
    # otherwise complete, correctly PR-bound section must still refuse. Without this, emptying
    # the required set records a HALF-BOUND identity and no test notices.
    def without_line(text, marker):
        """Drop the WHOLE log line carrying `marker`, and report how many were dropped — a
        no-op replace would make the assertion below pass for the wrong reason."""
        kept = [ln for ln in text.splitlines(keepends=True) if marker not in ln]
        return "".join(kept), len(text.splitlines()) - len(kept)

    for field, marker in (("account", "WORKER_IMPL_ACCOUNT:"), ("alias", "IMPL_ALIAS:"),
                          ("provider", "IMPL_PROVIDER:"), ("bot_login", "VERIFY_BOT_LOGIN:"),
                          ("target_repo", "--target-repo"), ("issue", "--issue")):
        without, dropped = without_line(prov_env(), marker)
        check(f"dropping the required field {field!r} refuses (never a half-bound identity)",
              (dropped, code_of(provenance_job_identity_from_log(without))),
              (1, REASON_INCOMPLETE))

    # --- REAL archived worker-run logs (issue #712 ask 4) --------------------------------------
    # Byte-exact line subsets of two REAL `gh run view --log` outputs — no line was edited, only
    # unrelated lines dropped. A synthetic fixture already produced one false green here (sol r6),
    # and then a second with a different field set, which is why these are real bytes.
    fixtures = Path(__file__).resolve().parent / "fixtures" / "backfill-provenance"
    real = {}
    for name in ("pr4185-env-shape", "pr3598-literal-shape"):
        path = fixtures / f"{name}.log"
        real[name] = path.read_text(encoding="utf-8", errors="surrogateescape") \
            if path.is_file() else ""
        check(f"real-log fixture {name} is present (fail closed, never a skipped check)",
              bool(real[name]), True)
    check("REAL current-shape log resolves (sparq#4185, registry run 30209757201)",
          run_identity_from_log(real["pr4185-env-shape"], "sparq-org/sparq", 4185, 3089,
                                "sparq-orchestrator[bot]",
                                "sparq-agent/issue-3089-30209757201-1"),
          ("acct01", "sol", "openai"))
    check("REAL literal-arg-shape log resolves (sparq#3598, registry run 29684750417)",
          run_identity_from_log(real["pr3598-literal-shape"], "sparq-org/sparq", 3598, 3235,
                                "sparq-orchestrator[bot]",
                                "sparq-agent/issue-3235-29684750417-1"),
          ("acct2css", "opus", "anthropic"))
    check("REAL log: the claim job corroborates again (it returned None on every live run)",
          claim_from_log(real["pr4185-env-shape"]), ("acct01", "sol"))
    # `gh run view --log` CARET-SANITIZES the runner's SGR controls: the real bytes are the two
    # characters `^[`, not a raw ESC. Filtering on "\x1b" here would select ZERO lines and the
    # assertion below would pass vacuously — accept either rendering.
    real_source_only = "".join(
        line for line in real["pr4185-env-shape"].splitlines(keepends=True)
        if "\x1b[" in line or "^[[" in line)
    check("REAL log: the SGR-wrapped SOURCE lines are actually PRESENT in the fixture",
          real_source_only.count("dispatcher lease adopted"), 1)
    check("REAL log: the SGR-wrapped print() SOURCE line contributes no model match",
          CLAIM_MODEL_RE.findall(real_source_only), [])
    check("  ...while the runtime output line in the same REAL log does",
          CLAIM_MODEL_RE.findall(real["pr4185-env-shape"]), ["sol"])
    check("REAL log: binding to the wrong PR's head branch still fails closed",
          code_of(run_identity_from_log(real["pr4185-env-shape"], "sparq-org/sparq", 4185, 3089,
                                        "sparq-orchestrator[bot]",
                                        "sparq-agent/issue-3089-30209757201-2")),
          REASON_BINDING_MISMATCH)

    # --- WORKFLOW SEAM: worker.yml is where the shape lives -----------------------------------
    shape = worker_yaml_shape_report()
    check("worker.yml provenance job name still matches the provenance anchor (and only it)",
          shape["prov_job_anchored"], True)
    check("worker.yml claim job name still matches the claim anchor (and only it)",
          shape["claim_job_anchored"], True)
    check("worker.yml MODEL job name matches NEITHER trusted anchor",
          shape["worker_job_unanchored"], True)
    check("worker.yml provenance step still exports every identity env key this parser reads",
          shape["prov_env_keys"], True)
    check("worker.yml claim job still exports EXPECTED_ACCOUNT", shape["claim_env_keys"], True)
    check("worker.yml claim job still PRINTS both live claim phrases",
          shape["claim_prints_model"],
          ["lease claimed: model=", "dispatcher lease adopted: model="])
    check("worker.yml reconcile invocation still has NO --pr (so HEAD_BRANCH must bind)",
          shape["reconcile_has_no_pr_arg"], True)
    check("REPLAYED straight from worker.yml, the WHOLE provenance job's log section parses",
          shape["replayed_identity"],
          {"account": "acct07", "alias": "fable", "provider": "anthropic",
           "bot_login": "sparq-orchestrator[bot]", "target_repo": "sparq-org/sparq",
           "issue": 77, "head_branch": "sparq-agent/issue-77-1234567890-1", "pr": 4242})
    # The stamp step's `--pr` is a SECOND binding in the same section. When it agrees it is extra
    # corroboration; when it disagrees the PR is refused — a binding is never outvoted.
    stamped = env_log + _log_line(prov_job, '\x1b[36;1m  --pr "3459" \\\x1b[0m')
    check("a second, AGREEING --pr binding from the stamp step still resolves", ident(stamped),
          ("acct0fx1", "fable", "anthropic"))
    check("a second, DISAGREEING --pr binding refuses (both bindings must hold)",
          code_of(ident(env_log + _log_line(prov_job, '\x1b[36;1m  --pr "9999" \\\x1b[0m'))),
          REASON_BINDING_MISMATCH)
    check("REPLAYED straight from worker.yml, the claim job corroborates",
          shape["replayed_claim"], ("acct07", "fable"))

    # --- WORKFLOW SEAM: backfill-provenance.yml is how this script is invoked ------------------
    seam = backfill_workflow_seam_report()
    check("backfill workflow refuses to run off the default branch", seam["job_ref_guarded"],
          True)
    check("backfill workflow keeps the dispatch-secrets environment guard",
          seam["job_environment"], "dispatch-secrets")
    check("backfill workflow grants actions:read (without it EVERY PR is log-unavailable)",
          seam["actions_read"], "read")
    check("backfill workflow grants contents:write for the ledger record",
          seam["contents_write"], "write")
    check("the backfill step is UNCONDITIONAL (an `if:` here disables the whole recovery)",
          seam["step_unconditional"], True)
    check("the backfill step keeps `set -euo pipefail` (else a red self-test is swallowed)",
          seam["errexit"], True)
    check("the self-test runs BEFORE the backfill invocation, in the same step",
          seam["self_test_before_backfill"], True)
    check("--apply is added only under the APPLY conditional", seam["apply_is_conditional"], True)
    check("workflow_dispatch defaults to a DRY RUN", seam["dispatch_default_is_dry_run"], False)
    check("--no-draft-convert is added only under the NO_DRAFT_CONVERT conditional",
          seam["no_draft_convert_is_conditional"], True)
    check("no_draft_convert defaults to false (the predicate, not the flag, is the fix)",
          seam["no_draft_convert_default"], False)
    # The wrong-input seam: binding NO_DRAFT_CONVERT to `inputs.apply` lints clean and silently
    # inverts an apply run. Assert the exact expression, not the mere presence of the name.
    # [#1544] TARGET_REPO now comes from the MATRIX (the schedule sweeps every enabled target and
    # a scheduled run has no `inputs.*`), and APPLY must additionally be true on a schedule.
    check("each workflow env name is bound to ITS OWN source (wrong-input seam)",
          seam["step_env_bindings"],
          {"TARGET_REPO": "${{ matrix.repo }}",
           "APPLY": "${{ inputs.apply || github.event_name == 'schedule' }}",
           "NO_DRAFT_CONVERT": "${{ inputs.no_draft_convert }}"})
    # ...and the SCHEDULED sweep must APPLY. Binding APPLY to `inputs.apply` alone lints clean,
    # keeps every check above green, and makes the cron a PERMANENT DRY RUN — it would run forever,
    # report success, and record nothing, which is indistinguishable from a drained population.
    # That is the exact "built, wired, never fired" shape this estate keeps paying for, so it is
    # asserted on the SHIPPED expression rather than trusted.
    _apply_expr = seam["step_env_bindings"]["APPLY"]
    check("a SCHEDULED run applies (the cron is not a permanent dry run)",
          "github.event_name == 'schedule'" in _apply_expr, True)
    check("...while a manual run still defaults to a DRY RUN (inputs.apply is still consulted)",
          "inputs.apply" in _apply_expr, True)

    # --- ISSUE #1544: the sweep must START ITSELF, over EVERY enabled target -------------------
    # An orphaned worker PR is fail-closed INVISIBLE to the review loop until its record exists,
    # and nothing else in the estate writes that record — so while this workflow was
    # dispatch-only, the population drained only when a human remembered to run it AND pointed it
    # at the right repo. Both stalls measured on 2026-08-01 were "nobody pointed it at this repo
    # lately", not "it never ran". The schedule and the policy-derived matrix are therefore the
    # two halves of the fix, and each is pinned to its exact shipped expression: every link below
    # can be broken in a way that still lints, still runs GREEN, and sweeps NOTHING.
    check("THE #1544 FIX: the backfill is SELF-STARTING (it was workflow_dispatch-only)",
          bool(seam["schedule_crons"]), True)
    check("...on the shipped cadence", seam["schedule_crons"], ["23 */4 * * *"])
    check("target_repo exists as a manual input and carries NO default, so 'leave EMPTY to sweep "
          "every enabled target' is reachable (a default is materialised for dispatch only)",
          seam["target_repo_input"], (True, False))
    check("the backfill job waits on the target resolver", seam["matrix_needs"], ["targets"])
    check("...and its matrix IS that resolver's output (never a hardcoded repo list)",
          seam["matrix_repo_expr"], "${{ fromJSON(needs.targets.outputs.repos) }}")
    check("...which the resolver actually publishes", seam["targets_repos_output"],
          "${{ steps.resolve.outputs.repos }}")
    check("...from policy/repos.toml — one source of truth for the enabled set (#1537/#1540)",
          seam["targets_policy_sourced"], True)

    # ---- the #1544 YAML-seam MUTANT TABLE ----------------------------------------------------
    # The checks above prove this report can read a CORRECT workflow; they do not prove it would
    # notice a neutered one. Every mutant below is a real way the recovery lane could go silently
    # dead — the TRIGGER, the INPUT, and each link of the matrix chain — and each must flip a
    # NAMED finding. None of them is a syntax error, and none would fail actionlint.
    def _mutated_seam(edit):
        doc = copy.deepcopy(_workflow("backfill-provenance.yml"))
        edit(doc)
        return backfill_workflow_seam_report(doc)

    def _triggers_of(doc):
        return doc.get("on") if "on" in doc else doc.get(True)

    def _resolve_step(doc):
        # An ANCHOR, not a search: if no step reads the policy file, the mutant is malformed and
        # must say so rather than raise a bare StopIteration from inside the table.
        hits = [s for s in doc["jobs"]["targets"]["steps"]
                if "policy/repos.toml" in str(s.get("run") or "")]
        assert len(hits) == 1, f"seam mutant anchor: {len(hits)} steps read policy/repos.toml"
        return hits[0]

    for _name, _edit, _key, _want in (
            ("the schedule is deleted (back to dispatch-only, the #1544 defect)",
             lambda d: _triggers_of(d).pop("schedule"), "schedule_crons", []),
            # Deleting a guard and making it INERT are different experiments. A cron is still
            # PRESENT here — `31 February` simply never comes — so the presence check above stays
            # green and only the exact-cadence check reds. That is the shape a "small, careful"
            # edit takes, and it is why the cadence is pinned by VALUE and not by `bool(...)`.
            ("the schedule is made inert rather than deleted (a cron that can never fire)",
             lambda d: _triggers_of(d).update(schedule=[{"cron": "0 0 31 2 *"}]),
             "schedule_crons", ["0 0 31 2 *"]),
            ("a target_repo default comes back (manual runs silently narrow to one repo)",
             lambda d: _triggers_of(d)["workflow_dispatch"]["inputs"]["target_repo"].update(
                 default="some-owner/some-name"), "target_repo_input", (True, True)),
            ("the target_repo input is deleted outright (a default-only check misses this)",
             lambda d: _triggers_of(d)["workflow_dispatch"]["inputs"].pop("target_repo"),
             "target_repo_input", (False, False)),
            ("the backfill job stops waiting on the resolver",
             lambda d: d["jobs"]["backfill"].pop("needs"), "matrix_needs", []),
            ("the matrix is hardcoded (policy enables a repo this list has never heard of)",
             lambda d: d["jobs"]["backfill"]["strategy"]["matrix"].update(
                 repo=["some-owner/some-name"]), "matrix_repo_expr", "['some-owner/some-name']"),
            ("the resolver stops publishing its list (the matrix then expands to NOTHING)",
             lambda d: d["jobs"]["targets"].pop("outputs"), "targets_repos_output", ""),
            ("the enabled set is copied into the workflow instead of read from policy",
             lambda d: _resolve_step(d).update(run=str(_resolve_step(d)["run"]).replace(
                 "policy/repos.toml", "some-owner/some-name")),
             "targets_policy_sourced", False),
    ):
        # A mutant that cannot be APPLIED (its anchor is gone — exactly what happens when the
        # schedule or `needs:` this table edits has already been deleted) must red its OWN row and
        # let the remaining rows run. Raising here instead would abort the suite mid-way: the run
        # still fails, but every check below it silently never executes, so a single seam
        # regression would also hide the #726 draft-predicate rows. Swallowing it is not an option
        # either — the handler yields a value that can never equal `_want`, so the row still FAILS.
        try:
            _got = _mutated_seam(_edit)[_key]
        except Exception as exc:   # noqa: BLE001 — reported as a failed row, never suppressed
            _got = f"MUTANT NOT APPLICABLE ({type(exc).__name__}: {exc})"
        check(f"seam mutant flips its finding: {_name}", _got, _want)
    check("two-page slurped listing flattens (sol r5)",
          flatten_pull_pages([[{"number": 1}], [{"number": 2}, {"number": 3}]]),
          [{"number": 1}, {"number": 2}, {"number": 3}])
    check("non-list page fails closed", flatten_pull_pages([[{"number": 1}], "x"]), None)
    check("non-dict pull fails closed", flatten_pull_pages([[1]]), None)
    check("empty slurp is an empty list", flatten_pull_pages([]), [])
    check("forged worker-job lines alone resolve nothing", code_of(ident(forged)),
          REASON_NO_SOURCE)

    # --- ISSUE #726: drafting must never EVICT a queued / armed / reviewed PR ------------------
    # The old predicate drafted every non-draft worker PR. Applying that pass would have converted
    # sparq#3894/#4074/#4185 while they sat in the merge queue, which EVICTS them — three live
    # merges destroyed to fix a partition problem. THE DISCRIMINATING CASE is the queued one:
    # `autoMergeRequest` is NULL for an enqueued PR, so an arm-only check reds none of its own
    # tests and still evicts. Every fixture below is either REAL captured bytes or an explicit
    # ReviewState, and each of the four obligations has its own named check.

    # REAL `gh api graphql` response bodies, captured 2026-07-26 against sparq-org/sparq. Not
    # hand-written: the null `autoMergeRequest` on a QUEUED PR is the property under test, and a
    # synthetic fixture is exactly how one would accidentally assume it away.
    REAL_QUEUED = ('{"data":{"repository":{"pullRequest":{"mergeQueueEntry":{"state":'
                   '"AWAITING_CHECKS"},"autoMergeRequest":null,"labels":{"nodes":[{"name":'
                   '"area:bench"},{"name":"review:pass"}]}}}}}')          # sparq#4185
    REAL_ARMED = ('{"data":{"repository":{"pullRequest":{"mergeQueueEntry":null,'
                  '"autoMergeRequest":{"enabledAt":"2026-07-26T02:44:31Z"},"labels":{"nodes":'
                  '[{"name":"area:deps"},{"name":"review:pass"},{"name":"area:ci"},{"name":'
                  '"area:docs"},{"name":"area:sparq-trust"},{"name":"trust-surface"}]}}}}}')
    REAL_FRESH = ('{"data":{"repository":{"pullRequest":{"mergeQueueEntry":null,'
                  '"autoMergeRequest":null,"labels":{"nodes":[{"name":"review:needs"}]}}}}}')
    check("REAL queued-PR payload parses as QUEUED — and its autoMergeRequest is NULL, which is "
          "why an arm-only check misses it",
          parse_review_state(json.loads(REAL_QUEUED)),
          ReviewState(QUEUE_QUEUED, False, True))
    check("REAL armed-but-not-queued payload parses as armed + not queued",
          parse_review_state(json.loads(REAL_ARMED)),
          ReviewState(QUEUE_NOT_QUEUED, True, True))
    check("REAL fresh worker-PR payload parses as not queued, not armed, no review:pass",
          parse_review_state(json.loads(REAL_FRESH)),
          ReviewState(QUEUE_NOT_QUEUED, False, False))

    # The four states, named exactly as the obligations. `review:pass` alone is deliberately
    # separated from the queued state: if the queued fixture also carried review:pass, a
    # review:pass-ONLY implementation would satisfy it and the queue branch would be vacuous.
    QUEUED_ONLY = ReviewState(QUEUE_QUEUED, False, False)
    ARMED_ONLY = ReviewState(QUEUE_NOT_QUEUED, True, False)
    REVIEW_PASS_ONLY = ReviewState(QUEUE_NOT_QUEUED, False, True)
    FRESH = ReviewState(QUEUE_NOT_QUEUED, False, False)
    check("a QUEUED PR is not drafted, with autoMergeRequest null AND no review:pass "
          "(an arm-only OR label-only check fails HERE)",
          draft_skip_reason(False, QUEUED_ONLY), DRAFT_SKIP_QUEUED)
    check("an ARMED-but-not-queued PR is not drafted",
          draft_skip_reason(False, ARMED_ONLY), DRAFT_SKIP_ARMED)
    check("a review:pass non-draft PR is not drafted",
          draft_skip_reason(False, REVIEW_PASS_ONLY), DRAFT_SKIP_REVIEW_PASS)
    check("a FRESH unreviewed non-draft worker PR IS still drafted (original behaviour survives)",
          draft_skip_reason(False, FRESH), None)
    check("an already-draft PR is left alone", draft_skip_reason(True, FRESH),
          DRAFT_SKIP_ALREADY)
    check("an UNREADABLE review state is not drafted (unknown != safe to evict)",
          draft_skip_reason(False, UNKNOWN_REVIEW_STATE), DRAFT_SKIP_QUEUE_UNKNOWN)
    check("a queue_state this predicate was never taught is not drafted either",
          draft_skip_reason(False, ReviewState("something-new", False, False)),
          DRAFT_SKIP_QUEUE_UNKNOWN)
    check("--no-draft-convert suppresses the conversion for a fresh PR too",
          draft_skip_reason(False, FRESH, no_draft_convert=True), DRAFT_SKIP_OPERATOR)
    check("...and --no-draft-convert is NOT what protects a queued PR (the predicate is)",
          draft_skip_reason(False, QUEUED_ONLY, no_draft_convert=False), DRAFT_SKIP_QUEUED)
    check("every draft-skip reason carries its own operator guidance",
          sorted(DRAFT_SKIP_GUIDANCE) == sorted({DRAFT_SKIP_ALREADY, DRAFT_SKIP_QUEUED,
                                                 DRAFT_SKIP_ARMED, DRAFT_SKIP_REVIEW_PASS,
                                                 DRAFT_SKIP_QUEUE_UNKNOWN, DRAFT_SKIP_OPERATOR}),
          True)

    # BEHAVIOURAL: the eviction is `gh pr ready <n> --undo`. Assert the COMMAND, not the reason —
    # a predicate that returns the right code but still shells out would pass every check above.
    issued = []

    def recording_runner(args, *, check=True):
        issued.append(list(args))
        return subprocess.CompletedProcess(list(args), 0, "", "")

    def issued_for(state, *, is_draft=False, apply_changes=True, no_draft_convert=False):
        issued.clear()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            _ensure_draft("sparq-org/sparq", 4185, is_draft, apply_changes, state=state,
                          no_draft_convert=no_draft_convert, runner=recording_runner)
        return list(issued), buffer.getvalue()

    undo_cmd = ["pr", "ready", "4185", "-R", "sparq-org/sparq", "--undo"]
    check("APPLY on a QUEUED PR issues NO `gh pr ready --undo` (the eviction command)",
          issued_for(QUEUED_ONLY)[0], [])
    check("APPLY on an ARMED PR issues no eviction command", issued_for(ARMED_ONLY)[0], [])
    check("APPLY on a review:pass PR issues no eviction command",
          issued_for(REVIEW_PASS_ONLY)[0], [])
    check("APPLY on an UNKNOWN-state PR issues no eviction command",
          issued_for(UNKNOWN_REVIEW_STATE)[0], [])
    check("APPLY on a FRESH unreviewed PR DOES issue the draft conversion (unchanged behaviour)",
          issued_for(FRESH)[0], [undo_cmd])
    check("--no-draft-convert suppresses even the fresh-PR conversion",
          issued_for(FRESH, no_draft_convert=True)[0], [])
    # The DRY-RUN line the issue was raised from: "DRY-RUN #4185: would convert to draft".
    check("DRY RUN no longer proposes converting a QUEUED PR",
          "would convert to draft" in issued_for(QUEUED_ONLY, apply_changes=False)[1], False)
    check("...and still proposes it for a FRESH unreviewed PR",
          "would convert to draft" in issued_for(FRESH, apply_changes=False)[1], True)

    # `review_state` never raises and never reports NOT_QUEUED on a bad probe — a raise would
    # abort the whole recovery, and a NOT_QUEUED would evict.
    def failing_runner(args, *, check=True):
        return subprocess.CompletedProcess(list(args), 1, "", "gh: HTTP 502")

    def replying_runner(body):
        return lambda args, *, check=True: subprocess.CompletedProcess(list(args), 0, body, "")

    check("a FAILED graphql probe is UNKNOWN, never not-queued",
          review_state("sparq-org/sparq", 4185, runner=failing_runner), UNKNOWN_REVIEW_STATE)
    check("a malformed graphql body is UNKNOWN",
          review_state("sparq-org/sparq", 4185, runner=replying_runner("{not json")),
          UNKNOWN_REVIEW_STATE)
    # A PARTIAL graphql error carries a fully-shaped `data` alongside `errors` — the discriminating
    # fixture. A `"data": null` body would be UNKNOWN via the shape walk alone, so it would not
    # prove the `errors` check does anything.
    check("a graphql body with `errors` AND a well-shaped `data` is still UNKNOWN",
          review_state("sparq-org/sparq", 4185, runner=replying_runner(
              '{"data":{"repository":{"pullRequest":{"mergeQueueEntry":null,'
              '"autoMergeRequest":null,"labels":{"nodes":[]}}}},'
              '"errors":[{"message":"Something went wrong while executing your query"}]}')),
          UNKNOWN_REVIEW_STATE)
    # The DOCUMENT must ask for exactly what the parser requires: deleting `mergeQueueEntry` from
    # the query makes every response "partial", and the merge-queue signal disappears silently.
    check("the graphql document selects exactly the fields the parser requires",
          query_selected_fields(REVIEW_STATE_QUERY, "pullRequest"), set(_REVIEW_STATE_FIELDS))
    check("  ...and the selection extractor is not vacuous (it finds the nested `state`)",
          query_selected_fields(REVIEW_STATE_QUERY, "mergeQueueEntry"), {"state"})
    check("a payload MISSING mergeQueueEntry is UNKNOWN, never not-queued",
          parse_review_state({"data": {"repository": {"pullRequest": {
              "autoMergeRequest": None, "labels": {"nodes": []}}}}}), UNKNOWN_REVIEW_STATE)
    check("a null pullRequest is UNKNOWN",
          parse_review_state({"data": {"repository": {"pullRequest": None}}}),
          UNKNOWN_REVIEW_STATE)
    check("a malformed target repo is UNKNOWN without any request",
          review_state("not-a-repo", 4185, runner=failing_runner), UNKNOWN_REVIEW_STATE)
    check("the REAL queued payload round-trips through review_state's transport too",
          review_state("sparq-org/sparq", 4185, runner=replying_runner(REAL_QUEUED)),
          ReviewState(QUEUE_QUEUED, False, True))
    # The unprobed sentinel must be UNKNOWN: `backfill` skips the probe for an already-draft PR,
    # and if the is_draft short-circuit were ever removed a NOT_QUEUED sentinel would evict.
    check("the unprobed sentinel is UNKNOWN, so a lost is_draft short-circuit cannot evict",
          UNKNOWN_REVIEW_STATE.queue_state, QUEUE_UNKNOWN)

    # RECORDING AND DRAFTING ARE INDEPENDENT: every `_ensure_draft` call in `backfill` is a bare
    # expression statement, so its result can never gate (or withhold) a provenance record. Two
    # call sites — the already-recorded reconcile and the post-write one; a third, unreviewed one
    # reds this.
    backfill_tree = ast.parse(textwrap.dedent(inspect.getsource(backfill)))
    ensure_calls = [n for n in ast.walk(backfill_tree) if isinstance(n, ast.Call)
                    and getattr(n.func, "id", "") == "_ensure_draft"]
    bare_calls = [n.value for n in ast.walk(backfill_tree) if isinstance(n, ast.Expr)
                  and isinstance(n.value, ast.Call)
                  and getattr(n.value.func, "id", "") == "_ensure_draft"]
    check("every _ensure_draft call in backfill() is a bare statement — drafting can never "
          "withhold a record",
          (len(ensure_calls), len(bare_calls)), (2, 2))
    check("every _ensure_draft call passes an explicit review `state=` (no default to forget)",
          [sorted(k.arg for k in call.keywords) for call in ensure_calls],
          [["no_draft_convert", "state"], ["no_draft_convert", "state"]])

    # --- END TO END through backfill(): the obligation is "RECORDED but NOT drafted" -----------
    # The unit checks above pin the predicate and the probe; this drives the REAL loop with the
    # registry/gh boundary stubbed, so the live wiring (does backfill actually probe? does the
    # record still get counted?) is asserted rather than assumed.
    E2E_HEAD_QUEUED = "sparq-agent/issue-3404-16234567890-1"
    E2E_HEAD_FRESH = "sparq-agent/issue-3405-16234567891-1"
    e2e_logs = {"16234567890": prov_env(issue=3404, head=E2E_HEAD_QUEUED),
                "16234567891": prov_env(issue=3405, head=E2E_HEAD_FRESH)}

    def e2e_pull(number, head):
        return {"number": number, "draft": False,
                "head": {"ref": head, "repo": {"full_name": "sparq-org/sparq"}},
                "user": {"login": "sparq-orchestrator[bot]"}}

    def e2e_gh_json(args):
        if "--slurp" in args:
            return [[e2e_pull(9001, E2E_HEAD_QUEUED), e2e_pull(9002, E2E_HEAD_FRESH)]]
        return [{"sha": "ab" * 20}]

    def e2e_run_gh(args, *, check=True):
        if list(args[:2]) == ["run", "view"]:
            return subprocess.CompletedProcess(list(args), 0, e2e_logs.get(args[2], ""), "")
        raise AssertionError(f"a DRY RUN must issue no mutating gh call, got {args}")

    def e2e_no_write(*_args, **_kwargs):
        raise AssertionError("a DRY RUN must never write a provenance record")

    e2e_state = {9001: QUEUED_ONLY, 9002: FRESH}
    routing_toml = Path(tempfile.mkdtemp()) / "routing.toml"
    routing_toml.write_text('[models.fable]\nprovider = "anthropic"\n', encoding="utf-8")
    patched = ("_gh_json", "_run_gh", "_load_worker_pr", "_load_dispatch_claim", "review_state")
    # [registry #1317 r1] The stub below carries the REAL worker-pr exception classes, never a
    # local alias. Aliasing `WorkerPrError=BackfillError` made every behavioural check blind to
    # WHICH class the write handler catches — a stub that raises one flat class cannot tell a
    # permanent divergent-record conflict from an exhausted write, which is precisely the
    # distinction the handler now has to get right.
    real_worker_pr = _load_worker_pr()

    def drive_backfill(pulls_pages, *, ledger=None, master=None, apply_changes=False,
                       admission=None, writer=None, commits=None, no_draft_convert=False):
        """Run the REAL backfill() loop over a stubbed registry/gh boundary and return its
        stdout. `ledger`/`master` are {path-suffix-number: body-or-Exception} record stores, so
        the ledger-first probe, the admission gate and the write path are all exercised as
        wired rather than as described."""
        ledger = ledger or {}
        master = master or {}

        def probe(_repo, path, ref=None):
            number = int(Path(path).stem)
            found = (ledger if ref is not None else master).get(number)
            if isinstance(found, Exception):
                raise found
            return (found, "sha") if found is not None else (None, None)

        def gh_json(args):
            if "--slurp" in args:
                return pulls_pages
            return [{"sha": "ab" * 20}] if commits is None else commits

        stub = types.SimpleNamespace(
            LEDGER_REF="ledger",
            WorkerPrError=real_worker_pr.WorkerPrError,
            RegistryRecordConflictError=real_worker_pr.RegistryRecordConflictError,
            RegistryWriteExhaustedError=real_worker_pr.RegistryWriteExhaustedError,
            provenance_path=lambda repo, number: f"orchestration/provenance/{number}.json",
            _probe_registry_file=probe,
            account_hash=lambda account, salt: "deadbeefdeadbeef",
            provenance_record=writer or e2e_no_write)
        saved_globals = {name: globals()[name] for name in patched}
        saved_salt = os.environ.get("PROVENANCE_SALT")
        buffer = io.StringIO()
        try:
            globals().update(
                _gh_json=gh_json, _run_gh=e2e_run_gh,
                _load_worker_pr=lambda: stub,
                _load_dispatch_claim=lambda: types.SimpleNamespace(
                    provenance_admission_error=admission or (lambda record, pr: None)),
                review_state=lambda repo, number, runner=None: e2e_state.get(number, FRESH))
            os.environ["PROVENANCE_SALT"] = "self-test-only"
            with contextlib.redirect_stdout(buffer):
                backfill("sparq-org/sparq", "jeswr/agent-account-registry", str(routing_toml),
                         apply_changes, no_draft_convert=no_draft_convert)
        finally:
            globals().update(saved_globals)
            if saved_salt is None:
                os.environ.pop("PROVENANCE_SALT", None)
            else:
                os.environ["PROVENANCE_SALT"] = saved_salt
        return buffer.getvalue()

    e2e_pages = [[e2e_pull(9001, E2E_HEAD_QUEUED), e2e_pull(9002, E2E_HEAD_FRESH)]]
    e2e = drive_backfill(e2e_pages)
    check("E2E: the QUEUED PR's provenance IS recorded",
          "DRY-RUN #9001: would record" in e2e, True)
    check("E2E: ...and it is NOT proposed for draft conversion (no queue eviction)",
          "DRY-RUN #9001: would convert to draft" in e2e, False)
    check("E2E: ...and the operator is told why",
          "KEEP-PUBLISHED #9001: not converting to draft — it is IN THE MERGE QUEUE" in e2e, True)
    check("E2E: the FRESH unreviewed PR is recorded AND still drafted",
          ("DRY-RUN #9002: would record" in e2e,
           "DRY-RUN #9002: would convert to draft" in e2e), (True, True))
    check("E2E: BOTH records are counted — draft policy never withholds a record",
          "backfill complete: would record 2, repaired 0, skipped 0, needs-human 0, blocked 0, "
          "write-failed 0 (population 2)" in e2e, True)

    # --- [registry #776] THE INADMISSIBLE-RECORD CLASS HAS A MACHINE EXIT ----------------------
    # Measured on the live estate 2026-07-27: 7 master records carry the attempt-less
    # `backfill:<run>` stamp an OLDER revision of THIS script wrote; the post-#657 admission
    # refuses all 7, and 2 (sparq#2439/#2456) are open worker PRs that printed NEEDS-HUMAN on
    # every run and could never do anything else.
    STALE = json.dumps({"pr_number": 9001, "impl_provider": "anthropic", "impl_alias": "fable",
                        "impl_account_h": "cd" * 8, "issue": 3404,
                        "head_sha_at_open": "cd" * 20,
                        # the exact live defect: a backfill stamp with no `.attempt`
                        "recorded_at_run": "backfill:16234567890"})
    HEALTHY = json.dumps({"pr_number": 9002, "impl_provider": "anthropic", "impl_alias": "fable",
                          "impl_account_h": "ef" * 8, "issue": 3405,
                          "head_sha_at_open": "ef" * 20,
                          "recorded_at_run": "backfill:16234567891.1"})
    real_admission = _load_dispatch_claim().provenance_admission_error
    writes = []

    def recording_writer(*args, **kwargs):
        # provenance_record(registry_repo, target_repo, pr_number, ...)
        writes.append((args[2], kwargs.get("supersede_legacy")))

    check("a stale attempt-less backfill stamp is REFUSED by the shared admission (the live "
          "defect, re-derived not assumed)",
          real_admission(json.loads(STALE), 9001) is None, False)
    check("record_disposition names the three states apart",
          (record_disposition(None, 9001, real_admission)[0],
           record_disposition(HEALTHY, 9002, real_admission)[0],
           record_disposition(STALE, 9001, real_admission)[0]),
          (RECORD_ABSENT, RECORD_ADMITS, RECORD_INADMISSIBLE))

    # [registry #776] A LEDGER 404 IS NOT "RECORDLESS". Readers are ledger-FIRST, not
    # ledger-ONLY: `effective_record_body` and both PLAN/CLAIM provenance maps fall back to the
    # legacy master copy. Enumerating the recovery population by probing `?ref=ledger` alone
    # therefore over-counts — measured 2026-07-27, it named 11 open sparq worker PRs where the
    # real not-enumerable set was 8, because sparq#2465/#2493/#2521 hold ADMISSIBLE master
    # records and are fully visible to the review loop. Pinned here because a wrong population
    # is how a backfill talks itself into writing a record over a healthy one.
    master_only = drive_backfill([[e2e_pull(9002, E2E_HEAD_FRESH)]], master={9002: HEALTHY},
                                 admission=real_admission)
    check("a PR with NO ledger record but an ADMISSIBLE master one is already recorded — a "
          "ledger 404 alone never means recordless",
          ("skip #9002: provenance already recorded" in master_only,
           "would record 0, repaired 0, skipped 1, needs-human 0, blocked 0, write-failed 0 "
           "(population 1)" in master_only), (True, True))

    repair_out = drive_backfill(e2e_pages, master={9001: STALE, 9002: HEALTHY},
                                admission=real_admission)
    check("E2E: a PR whose record is present but INADMISSIBLE is REPAIRED, not left to a human",
          ("REPAIR #9001" in repair_out, "NEEDS-HUMAN #9001" in repair_out), (True, False))
    check("E2E: ...and the repair is COUNTED in its own bucket",
          "would record 0, repaired 1, skipped 1, needs-human 0, blocked 0, write-failed 0 "
          "(population 2)" in repair_out, True)
    check("E2E: a PR whose record ALREADY ADMITS is skipped, never rewritten",
          ("skip #9002: provenance already recorded" in repair_out,
           "REPAIR #9002" in repair_out), (True, False))

    writes.clear()
    apply_out = drive_backfill(e2e_pages, master={9001: STALE, 9002: HEALTHY},
                               admission=real_admission, apply_changes=True,
                               writer=recording_writer, no_draft_convert=True)
    check("APPLY: the repair write is the ONLY one, and it is the ONLY call that supersedes "
          "the unwritable legacy master copy",
          sorted(writes), [(9001, True)])
    check("APPLY --no-draft-convert: a record-only pass issues NO merge-state gh call at all "
          "(e2e_run_gh raises on one), and still repairs",
          "repaired 1" in apply_out, True)

    # --- [registry #1317] ONE FAILED WRITE MUST NOT ABORT THE POPULATION ----------------------
    # The premise, re-derived from the REAL module rather than asserted in prose: `WorkerPrError`
    # is not a `BackfillError`, so main()'s handler never saw it and the first failed write ended
    # the run with a traceback mid-walk. If these two classes ever converge this whole block is
    # measuring nothing, so the premise is checked before the behaviour is.
    check("[#1317] worker_pr.WorkerPrError is NOT a BackfillError — main()'s handler cannot "
          "catch it, which is why the write call site must",
          issubclass(real_worker_pr.WorkerPrError, BackfillError), False)
    # [registry #1317 r1] THE TAXONOMY THIS HANDLER RESTS ON, re-derived from the real module.
    # Both narrow classes must remain WorkerPrError (every other caller catches the base and must
    # keep catching them) and must remain DISTINCT from each other — if they ever collapse, the
    # two handlers below stop discriminating and the behavioural checks silently measure nothing.
    check("[#1317 r1] the two registry-write classes are WorkerPrError subclasses, and neither "
          "is the other",
          (issubclass(real_worker_pr.RegistryWriteExhaustedError, real_worker_pr.WorkerPrError),
           issubclass(real_worker_pr.RegistryRecordConflictError, real_worker_pr.WorkerPrError),
           issubclass(real_worker_pr.RegistryWriteExhaustedError,
                      real_worker_pr.RegistryRecordConflictError),
           issubclass(real_worker_pr.RegistryRecordConflictError,
                      real_worker_pr.RegistryWriteExhaustedError)),
          (True, True, False, False))
    # A VALIDATION refusal from the REAL provenance_record — the class the write handler must NOT
    # soften. Driven through the real function (it refuses on its first argument check, before any
    # network call), so this stays true only while the taxonomy really does leave it uncaught.
    validation_exc = None
    try:
        real_worker_pr.provenance_record("reg/repo", "o/r", 7, "ab" * 20, "not-a-provider",
                                         "fable", "ab" * 8, 5, "backfill:1.1")
    except real_worker_pr.WorkerPrError as exc:
        validation_exc = exc
    check("[#1317 r1] an ARGUMENT-VALIDATION refusal is a BARE WorkerPrError — neither narrow "
          "class — so neither handler below can convert it into a soft, retryable outcome",
          (validation_exc is not None,
           isinstance(validation_exc, (real_worker_pr.RegistryWriteExhaustedError,
                                       real_worker_pr.RegistryRecordConflictError))),
          (True, False))
    # ...and the catches must be spelled through the MODULE ATTRIBUTE, narrowly. A mutant that
    # widens either handler back to `worker_pr.WorkerPrError` (or to a bare `Exception`) would
    # pass every behavioural check that raises only a narrow class, while being the exact defect
    # r1 found: a permanent conflict and a malformed-record derivation both reported as "the write
    # did not land, the next run retries". Pinned here because no runtime test can see a handler
    # that is merely WIDER than the exception it caught.
    write_handlers = [h for node in ast.walk(backfill_tree) if isinstance(node, ast.Try)
                      for h in node.handlers
                      if any(isinstance(c, ast.Call)
                             and getattr(c.func, "attr", "") == "provenance_record"
                             for c in ast.walk(node))]

    def handler_type_name(handler):
        """A TOTALLY-ORDERED string for an except clause's type expression (`worker_pr.X`, `X`,
        `<bare except>`, else the raw dump). A string ALWAYS, because the tuple-of-optionals form
        this replaced raised `TypeError: '<' not supported between NoneType and str` the moment a
        mutant installed a bare `except Name:` — an assertion that CRASHES on the very shape it
        exists to reject is AGENTS.md's false kill, and it truncated the suite at 140 of 191."""
        node = handler.type
        if node is None:
            return "<bare except>"
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        if isinstance(node, ast.Name):
            return node.id
        return ast.dump(node)

    check("[#1317 r1] the write catches EXACTLY the two narrow worker_pr classes — never the "
          "WorkerPrError base, the local BackfillError, or a bare Exception",
          # SORTED: the two handlers are siblings, so their ORDER is semantically irrelevant and
          # asserting it would kill a harmless reordering instead of a real widening.
          sorted(handler_type_name(h) for h in write_handlers),
          ["worker_pr.RegistryRecordConflictError", "worker_pr.RegistryWriteExhaustedError"])

    def failing_writer(fails_on, error=None):
        def writer(*args, **kwargs):
            if args[2] == fails_on:
                raise error or real_worker_pr.RegistryWriteExhaustedError(
                    "HTTP 409 writing the record")
            writes.append((args[2], kwargs.get("supersede_legacy")))
        return writer

    def drive_or_escape(**kwargs):
        """(stdout, the exception that ESCAPED backfill() or None).

        Every drive below goes through this because the failures under test are exactly the ones
        that escape: a widened/deleted handler lets the writer's exception out, and an uncounted
        exit trips the seal. Caught here, each becomes a NAMED, line-anchored `FAIL` row; left
        uncaught it aborts _self_test() mid-file, which scores as a kill while every check below
        it never runs — AGENTS.md's crash-after-partial-run false outcome (measured on this very
        block: four mutants took the suite from 191 checks to 140)."""
        try:
            return drive_backfill(e2e_pages, **kwargs), None
        except Exception as exc:          # noqa: BLE001 — the escape IS the observation
            return "", exc

    # No records anywhere, so BOTH PRs are RECORD_ABSENT and both would be written. Failing the
    # FIRST one in the walk is the case that used to lose #9002 entirely.
    writes.clear()
    first_fails, first_escaped = drive_or_escape(apply_changes=True,
                                                 writer=failing_writer(9001),
                                                 no_draft_convert=True)
    check("[#1317] a failed write on the FIRST PR does not abort the walk — nothing escapes "
          "backfill() and the SECOND PR is still recorded (this call raised outright before "
          "the fix)",
          (writes, first_escaped), ([(9002, False)], None))
    check("[#1317] ...the failure is reported with its own reason and the create-only retry",
          ("WRITE-FAILED #9001: could not record the provenance record "
           "(HTTP 409 writing the record)" in first_fails,
           "next run re-derives this PR and retries the write" in first_fails), (True, True))
    check("[#1317] ...it lands in its OWN bucket, and the run still SEALS (drive_backfill "
          "re-raises the unsealed BackfillError, so reaching this line is the seal passing)",
          "recorded 1, repaired 0, skipped 0, needs-human 0, blocked 0, write-failed 1 "
          "(population 2)" in first_fails, True)

    # Now fail the DRAFTABLE PR with draft conversion ENABLED: a record that did not land must not
    # be followed by a draft conversion. e2e_run_gh raises on any mutating gh call, so a lost
    # `continue` blows this run up rather than passing quietly.
    writes.clear()
    second_fails, second_escaped = drive_or_escape(apply_changes=True,
                                                   writer=failing_writer(9002))
    check("[#1317] a PR whose write FAILED is not converted to draft — nothing was recorded, so "
          "the target is left exactly as found",
          ("converted #9002 to draft" in second_fails,
           "WRITE-FAILED #9002" in second_fails, second_escaped), (False, True, None))
    check("[#1317] ...and the PR whose write SUCCEEDED is unaffected by its neighbour's failure",
          (writes, "recorded 1, repaired 0, skipped 0, needs-human 0, blocked 0, write-failed 1 "
                   "(population 2)" in second_fails), ([(9001, False)], True))

    # --- [registry #1317 r1] ...AND THE SOFT BUCKET MUST NOT SWALLOW A PERMANENT CONFLICT ------
    # `provenance_record` raises for a DIVERGENT existing record (the write-side CAS probe found a
    # different record already at this path — a concurrent writer, or a ledger record this walk's
    # read did not see). Counting that as `write_failed` told the operator two false things: that
    # nothing was written when in fact a CONFLICTING record is live, and that the next run would
    # retry when in fact every future run re-reads the same record and refuses again. It is a
    # permanent evidence conflict, so it exits through NEEDS-HUMAN like every other one.
    writes.clear()
    conflict_out, conflict_escaped = drive_or_escape(
        apply_changes=True, no_draft_convert=True,
        writer=failing_writer(9001, real_worker_pr.RegistryRecordConflictError(
            "registry file orchestration/provenance/9001.json already exists with different "
            "content on the 'ledger' branch")))
    check("[#1317 r1] a DIVERGENT-RECORD conflict is NEEDS-HUMAN, never the retryable "
          "write-failed bucket",
          ("NEEDS-HUMAN #9001: a DIVERGENT provenance record already exists" in conflict_out,
           "PERMANENT conflict that no retry can clear" in conflict_out,
           "WRITE-FAILED #9001" in conflict_out), (True, True, False))
    check("[#1317 r1] ...it is counted as needs-human, write-failed stays 0, and the walk still "
          "continues to the next PR and SEALS (an uncounted conflict exit trips seal_population, "
          "which surfaces here as an escaped exception)",
          (writes, conflict_escaped,
           "recorded 1, repaired 0, skipped 0, needs-human 1, blocked 0, write-failed 0 "
           "(population 2)" in conflict_out), ([(9002, False)], None, True))

    # The other direction: a BARE WorkerPrError (what the real function raises for a malformed
    # provider/account-hash/head-sha, i.e. a record THIS script must never have derived) is not
    # one PR's bad luck and must stay LOUD — it propagates out of backfill() exactly as it did
    # before #1317, rather than being counted as a soft per-PR outcome. `type(...) is` on purpose:
    # a handler that re-raised one of the narrow subclasses would satisfy `isinstance`.
    writes.clear()
    _loud_out, loud_escaped = drive_or_escape(
        apply_changes=True, no_draft_convert=True,
        writer=failing_writer(9001, real_worker_pr.WorkerPrError(
            "impl_provider must be anthropic or openai")))
    check("[#1317 r1] a bare WorkerPrError (validation/invariant) still ABORTS the run loudly — "
          "it is neither bucketed nor silently continued past",
          (type(loud_escaped) is real_worker_pr.WorkerPrError, str(loud_escaped), writes),
          (True, "impl_provider must be anthropic or openai", []))

    # IDEMPOTENCE — the run must converge. Second invocation over the state the first one leaves
    # behind (the repaired record now on `ledger`) must write NOTHING and skip both.
    REPAIRED = json.dumps({"pr_number": 9001, "impl_provider": "anthropic", "impl_alias": "fable",
                           "impl_account_h": "deadbeefdeadbeef", "issue": 3404,
                           "head_sha_at_open": "ab" * 20,
                           "recorded_at_run": "backfill:16234567890.1"})
    writes.clear()
    second = drive_backfill(e2e_pages, ledger={9001: REPAIRED},
                            master={9001: STALE, 9002: HEALTHY},
                            admission=real_admission, apply_changes=True,
                            writer=recording_writer, no_draft_convert=True)
    check("IDEMPOTENT: a second run over the first run's output writes nothing at all", writes, [])
    check("IDEMPOTENT: ...and reports both PRs as skipped",
          "recorded 0, repaired 0, skipped 2, needs-human 0, blocked 0, write-failed 0 "
          "(population 2)" in second, True)
    check("IDEMPOTENT: ...ledger-first — the repaired ledger copy beats the stale master one",
          "REPAIR #9001" in second, False)

    # --- [registry #776] EVERY EXIT IS COUNTED, and the seal is arithmetic that FAILS ----------
    no_commits = drive_backfill(e2e_pages, commits=[])
    check("a PR with no commits is a COUNTED terminal state, not a silent `continue`",
          ("BLOCKED #9001: PR has no commits" in no_commits,
           "would record 0, repaired 0, skipped 0, needs-human 0, blocked 2, write-failed 0 "
           "(population 2)" in no_commits), (True, True))
    bad_sha = drive_backfill(e2e_pages, commits=[{"sha": "nothex"}])
    check("a malformed first-commit sha is a COUNTED terminal state too",
          ("BLOCKED #9001: first commit sha is malformed" in bad_sha,
           "blocked 2, write-failed 0 (population 2)" in bad_sha), (True, True))
    check("a record this run would write that is ITSELF inadmissible is refused, and counted",
          "BLOCKED #9001: the record this run would write is itself NOT admissible"
          in drive_backfill(e2e_pages, admission=lambda record, pr: "synthetic refusal"), True)

    # The seal is not decoration. It is the ONE check that a future uncounted `continue` cannot
    # get past, so it is asserted as arithmetic that FAILS, on the same function backfill() calls.
    unsealed = None
    try:
        drive_backfill(e2e_pages, master={9001: real_worker_pr.WorkerPrError("HTTP 403")},
                       admission=real_admission)
    except BackfillError as exc:
        unsealed = str(exc)
    check("an unreadable registry probe is a COUNTED terminal state, so the run still seals",
          unsealed, None)
    seal_raised = None
    try:
        seal_population(1, 2)
    except BackfillError as exc:
        seal_raised = str(exc)
    check("the seal RAISES when a PR left through an uncounted exit",
          seal_raised is not None and "unsealed" in seal_raised, True)
    check("  ...and returns quietly when every PR is accounted for", seal_population(2, 2), None)
    # The seam M8 exploited: `unsealed = seal(...)` computed and then discarded. There is no
    # seam left to delete only if the call is a BARE STATEMENT of the function that itself
    # raises — assert BOTH facts, because either one alone is satisfiable by a vacuous shape.
    seal_calls = [n for n in ast.walk(backfill_tree) if isinstance(n, ast.Call)
                  and getattr(n.func, "id", "") == "seal_population"]
    seal_bare = [n.value for n in ast.walk(backfill_tree) if isinstance(n, ast.Expr)
                 and isinstance(n.value, ast.Call)
                 and getattr(n.value.func, "id", "") == "seal_population"]
    check("backfill() seals through THAT function, as a BARE statement whose result cannot be "
          "discarded by deleting an `if`",
          (len(seal_calls), len(seal_bare)), (1, 1))
    check("  ...and the sealing function is the one that RAISES (no reason-returning seam)",
          any(isinstance(n, ast.Raise) for n in ast.walk(
              ast.parse(textwrap.dedent(inspect.getsource(seal_population))))), True)

    # --- [registry #657 §7.4 step 2b] THE ORCHESTRATOR CLASS, THROUGH THE REAL LOOP -----------
    # Driven twice against the SAME tree with only `review_enrolment_authors` changing, because
    # a guard asserted only against the live policy (which enrols nobody) is unfalsifiable:
    # deleting it changes no outcome and a mutation run says so.
    real_claim = _load_dispatch_claim()
    ORCH_LOGIN = "jeswr"
    ORCH_HEAD = "fix/readiness-visibility-opus5"          # an ORDINARY branch: HEAD_RE cannot match
    POLICY_ROW = ('[repos."sparq-org/sparq"]\nenabled=true\nrouting="r.toml"\n'
                  'account_pool=["acct01"]\nmax_concurrent=1\nworker_timeout_minutes=30\n'
                  'gate_profile="lint-only"\narm_auto_merge=false\nmax_attempts=3\n'
                  'trust="collaborators"\n')

    # (0) THE PREDICATE ITSELF, called DIRECTLY. The loop below carries its own fork gate, so a
    #     loop-level fork test cannot see whether THIS function has one — and a gate whose
    #     deletion reds nothing is not a gate. Measured: deleting the fork gate inside
    #     orchestrator_class_admission survived a loop-only fork test.
    def unit_admits(pull, records, enrolled=(ORCH_LOGIN,), reads=None):
        def read():
            (reads if reads is not None else []).append(pull.get("number"))
            return records.get(pull.get("number"))
        return orchestrator_class_admission(real_claim, pull, "sparq-org/sparq", enrolled, read)

    unit_pull = {"number": 41, "draft": False, "user": {"login": ORCH_LOGIN},
                 "head": {"ref": ORCH_HEAD, "repo": {"full_name": "sparq-org/sparq"}}}
    unit_record = real_claim.orchestrator_probe_record(41)
    check("[#657] unit: an enrolled, orchestrator-attested, same-repo PR IS the class",
          unit_admits(unit_pull, {41: unit_record}), unit_record)
    check("[#657] unit: THE FORK GATE — a fork head is refused BEFORE the record is even read",
          (unit_admits({**unit_pull,
                        "head": {"ref": ORCH_HEAD, "repo": {"full_name": "mallory/sparq"}}},
                       {41: unit_record}, (ORCH_LOGIN,), reads := []), reads), (None, []))
    check("[#657] unit: an EMPTY allowlist refuses, and reads nothing",
          (unit_admits(unit_pull, {41: unit_record}, (), reads := []), reads),
          (None, []))
    check("[#657] unit: a non-enrolled author refuses, and reads nothing",
          (unit_admits({**unit_pull, "user": {"login": "mallory"}}, {41: unit_record},
                       (ORCH_LOGIN,), reads := []), reads), (None, []))
    check("[#657] unit: an ABSENT record refuses (admission requires one to exist)",
          unit_admits(unit_pull, {}), None)
    check("[#657] unit: a record bound to a DIFFERENT PR never waives this one's shape gates",
          unit_admits(unit_pull, {41: real_claim.orchestrator_probe_record(42)}), None)
    # WHERE THE `[bot]` REFUSAL ACTUALLY LIVES. `admits_orchestrator_pr` is a plain casefolded
    # membership test: hand it an allowlist containing a `[bot]` login and it WOULD admit that
    # login, widening the App-author gate to any installed App. Nothing in this file stops that
    # — the refusal is in policy-resolve's row validation, which is why enrolled_review_authors
    # goes through that accessor instead of reading the TOML key directly. Asserted where it
    # lives, honestly, rather than claimed here where it does not.
    check("[#657] unit: the waiver predicate itself does NOT refuse a `[bot]` allowlist entry",
          unit_admits({**unit_pull, "user": {"login": "mallory[bot]"}}, {41: unit_record},
                      ("mallory[bot]",)) is not None, True)
    with tempfile.TemporaryDirectory() as bot_tmp:
        bot_policy = Path(bot_tmp) / "repos.toml"
        bot_policy.write_text(POLICY_ROW + 'review_enrolment_authors=["mallory[bot]"]\n',
                              encoding="utf-8")
        check("[#657] ...and enrolled_review_authors REFUSES that policy through "
              "policy-resolve, so the widened gate can never be assembled",
              enrolled_review_authors("sparq-org/sparq", str(bot_policy)), frozenset())
        bot_policy.write_text(POLICY_ROW + f'review_enrolment_authors=["{ORCH_LOGIN}"]\n',
                              encoding="utf-8")
        check("[#657] ...while a canonical login resolves (the refusal above is not blanket)",
              enrolled_review_authors("sparq-org/sparq", str(bot_policy)),
              frozenset({ORCH_LOGIN}))

    def orch_backfill(enrolled, pull_rows, records):
        """The REAL backfill loop over `pull_rows`, with the registry/gh boundary stubbed and a
        policy that does or does not enrol ORCH_LOGIN. Returns everything it printed."""
        policy_dir = Path(tempfile.mkdtemp())
        (policy_dir / "repos.toml").write_text(
            POLICY_ROW + (f'review_enrolment_authors=["{ORCH_LOGIN}"]\n' if enrolled else ""),
            encoding="utf-8")
        probe_calls = []

        def orch_probe(_repo, path, ref=None):
            probe_calls.append((path, ref))
            body = records.get(path)
            return (json.dumps(body) if body is not None else None,
                    "ab" * 20 if body is not None else None)

        orch_worker_pr = types.SimpleNamespace(
            LEDGER_REF="ledger", WorkerPrError=real_worker_pr.WorkerPrError,
            provenance_path=lambda repo, number: f"orchestration/provenance/{number}.json",
            _probe_registry_file=orch_probe,
            account_hash=lambda account, salt: "deadbeefdeadbeef",
            provenance_record=e2e_no_write)
        state_calls = []

        def orch_review_state(_repo, number, runner=None):
            state_calls.append(number)
            return FRESH

        saved = {name: globals()[name] for name in patched}
        buffer = io.StringIO()
        try:
            globals().update(
                _gh_json=lambda args: ([pull_rows] if "--slurp" in args
                                       else [{"sha": "ab" * 20}]),
                _run_gh=e2e_run_gh, _load_worker_pr=lambda: orch_worker_pr,
                _load_dispatch_claim=lambda: real_claim,
                review_state=orch_review_state)
            os.environ["PROVENANCE_SALT"] = "self-test-only"
            with contextlib.redirect_stdout(buffer):
                backfill("sparq-org/sparq", "jeswr/agent-account-registry", str(routing_toml),
                         False, policy_file=str(policy_dir / "repos.toml"))
        finally:
            globals().update(saved)
            os.environ.pop("PROVENANCE_SALT", None)
        return buffer.getvalue(), probe_calls, state_calls

    orch_pull_row = {"number": 9003, "draft": False,
                     "head": {"ref": ORCH_HEAD, "repo": {"full_name": "sparq-org/sparq"}},
                     "user": {"login": ORCH_LOGIN}}
    worker_pull_row = e2e_pull(9002, E2E_HEAD_FRESH)
    orch_records = {"orchestration/provenance/9003.json":
                    real_claim.orchestrator_probe_record(9003)}

    # [registry #776 x #876] THE COMPOSITION, and the red test for the population decision. This
    # run carries BOTH classes at once — one worker PR and one ADMITTED #657 orchestrator PR —
    # which is exactly the pair that broke: #876's orchestrator counter sits ABOVE this change's
    # `population += 1`, so counting the class as a population OUTCOME made `accounted` exceed
    # `population` and `seal_population` raised on every real run. backfill() records the decision
    # that the class is OUTSIDE the population; this is the row that fails if it is ever folded
    # back in, and it is a NAMED row rather than an uncaught traceback so the failure says so.
    sealed = None
    try:
        on_out, on_probes, on_states = orch_backfill(
            True, [orch_pull_row, worker_pull_row], orch_records)
    except BackfillError as exc:
        on_out, on_probes, on_states, sealed = "", [], [], str(exc)
    check("[#776 x #876] a run carrying BOTH a worker PR and an admitted orchestrator PR SEALS: "
          "the orchestrator class is outside the population, so it cannot outnumber it",
          sealed, None)
    off_out, off_probes, off_states = orch_backfill(
        False, [orch_pull_row, worker_pull_row], orch_records)
    # ...and it lands in its OWN bucket. Folding it into `skipped` would conflate "not this
    # script's job" with "already carries an admissible record" — two facts a reader of the
    # completion line has to be able to tell apart, and the reason the seal broke at all.
    check("[#776 x #876] the orchestrator PR is counted OUT OF POPULATION, in its own bucket, "
          "never as a `skipped` worker PR",
          ("(population 1) out-of-scope 1" in on_out, "skipped 1" in on_out), (True, False))

    # (1) ENROLLED: the class is RECOGNISED and explicitly skipped — never minted (backfill's
    #     only identity source is a worker run log the class has no analogue for) and never
    #     draft-converted (the review lane admits the class BECAUSE it stands the draft
    #     requirement down; drafting it would be a pure regression).
    check("[#657] an enrolled orchestrator PR is recognised and skipped with an honest reason",
          "skip #9003: #657 orchestrator class" in on_out, True)
    check("[#657] ...it is never recorded",
          ("#9003: would record" in on_out, "NEEDS-HUMAN #9003" in on_out), (False, False))
    check("[#657] ...and its live review state is never even probed, so no draft conversion "
          "path can reach it", 9003 in on_states, False)
    # (2) NOT ENROLLED (every repo's shipped state): the same PR is invisible, exactly as before
    #     #657 — no skip line, no counted outcome, and NO registry read at all.
    check("[#657] with an EMPTY allowlist the same PR is invisible and costs no registry read",
          ("#9003" in off_out,
           [path for path, _ref in off_probes if "9003" in path]), (False, []))
    # (3) THE FROZEN WORKER-CLASS CONTROL. Literals on BOTH sides, in BOTH allowlist states —
    #     never a re-call of the live predicate, which is how a control goes quiet the moment
    #     the predicate it re-derives from changes. Enrolment must not move the worker lane by
    #     one character.
    WORKER_LINES = ["DRY-RUN #9002: would record impl=anthropic/fable "
                    "account_h=deadbeefdeadbeef issue=#3405 opened=abababab "
                    "(backfill:16234567891.1)",
                    "DRY-RUN #9002: would convert to draft (review gates require draft)"]
    for state, out in (("allowlist ON", on_out), ("allowlist OFF", off_out)):
        check(f"[#657] FROZEN worker-class control ({state}): the worker PR's outcome is "
              "byte-for-byte the pre-#657 one",
              [line for line in out.splitlines() if "#9002" in line], WORKER_LINES)
    # STRONGER than the pre-#776 form of this control, which asserted `skipped 1` ON and
    # `skipped 0` OFF — i.e. enrolment DID move a population counter. With the class out of the
    # population, every population counter is now byte-identical between the two runs and only the
    # out-of-scope bucket moves, which is what "enrolment must not move the worker lane" means.
    POPULATION_LINE = ("backfill complete: would record 1, repaired 0, skipped 0, "
                       "needs-human 0, blocked 0, write-failed 0 (population 1)")
    check("[#657] FROZEN worker-class control: enrolment moves ONLY the out-of-scope bucket — "
          "every population counter is identical between the two runs",
          (f"{POPULATION_LINE} out-of-scope 1" in on_out,
           f"{POPULATION_LINE} out-of-scope 0" in off_out),
          (True, True))
    # (4) THE FORK GATE, hoisted above every waivable predicate: a fork head is never admitted
    #     to the class however enrolled its author is, and is never read for.
    fork_out, fork_probes, _fork_states = orch_backfill(
        True, [{**orch_pull_row, "head": {"ref": ORCH_HEAD,
                                          "repo": {"full_name": "mallory/sparq"}}}],
        orch_records)
    check("[#657] a FORK head is never admitted to the class, enrolled author or not",
          ("#9003" in fork_out, fork_probes), (False, []))
    #     ...and the LOOP's own fork gate — the one this PR hoisted above the head-ref parse —
    #     independently refuses a fork PR that DOES have the worker producer shape. Measured:
    #     without this case, deleting that gate survived the whole suite, because the class
    #     helper's gate masked the only fork test there was.
    wfork_out, wfork_probes, wfork_states = orch_backfill(
        True, [{**e2e_pull(9004, E2E_HEAD_FRESH),
                "head": {"ref": E2E_HEAD_FRESH, "repo": {"full_name": "mallory/sparq"}}}], {})
    check("[#657] a FORK head with the WORKER producer shape gets no record, no draft "
          "conversion, and no registry read",
          ("#9004" in wfork_out, wfork_probes, wfork_states), (False, [], []))
    # (5) THE OTHER HALF OF THE CONJUNCTION: an enrolled author whose record is NOT
    #     orchestrator-attested (a machine `backfill:`-stamped record) is not the class either —
    #     the waiver needs BOTH independently-authored facts, never one.
    worker_attested = {**real_claim.orchestrator_probe_record(9003),
                       "recorded_at_run": "backfill:16234567891.1"}
    other_out, _p, _s = orch_backfill(
        True, [orch_pull_row], {"orchestration/provenance/9003.json": worker_attested})
    check("[#657] an enrolled author with a NON-orchestrator record is not the class",
          "#9003" in other_out, False)

    # --- effective ledger-first record + admission before any skip (sol #217) ------------------
    # The REAL review-loop admission function, imported — not a replica — so these red if the
    # schema and this gate ever drift apart.
    admission = _load_dispatch_claim().provenance_admission_error
    valid_record = {"pr_number": 41, "impl_provider": "anthropic", "impl_alias": "fable",
                    "impl_account_h": "ab" * 8, "issue": 7, "head_sha_at_open": "ab" * 20,
                    # Machine-attested stamp (issue #657) — this is the shape THIS script writes
                    # (`backfill:<run>.<attempt>`, see `run_key` below), and the shared admission
                    # predicate now requires a recognised host-side trust basis.
                    "recorded_at_run": "backfill:29572728300.1"}
    check("valid matching record admits (skip allowed)",
          existing_record_admission_error(json.dumps(valid_record), 41, admission), None)
    check("undecodable record body never counts as recorded",
          existing_record_admission_error("{not json", 41, admission),
          "the record is not valid JSON")
    check("record bound to a DIFFERENT PR never counts as recorded",
          existing_record_admission_error(json.dumps(valid_record), 42, admission) is None,
          False)
    check("legacy raw-handle record is surfaced, not skipped",
          existing_record_admission_error(
              json.dumps({**valid_record, "impl_account_h": "someuser"}), 41, admission)
          is None, False)

    probes = []

    def stub_probe(ledger, master):
        def probe(ref=None):
            probes.append(ref)
            result = ledger if ref is not None else master
            if isinstance(result, Exception):
                raise result
            return result, None
        return probe

    check("present ledger record is judged AS-IS",
          effective_record_body(stub_probe("L", "M"), "ledger"), "L")
    check("  ...and master is NEVER consulted past it", probes, ["ledger"])
    probes.clear()
    check("clean ledger 404 falls back to the master copy",
          effective_record_body(stub_probe(None, "M"), "ledger"), "M")
    check("  ...probed ledger first, then master", probes, ["ledger", None])
    probes.clear()
    check("no copy anywhere means no record (backfill proceeds)",
          effective_record_body(stub_probe(None, None), "ledger"), None)
    try:
        effective_record_body(stub_probe(RuntimeError("HTTP 403"), "M"), "ledger")
        probe_error_raised = False
    except RuntimeError:
        probe_error_raised = True
    check("non-404 ledger failure RAISES — never falls through to master (sol #217)",
          probe_error_raised, True)
    print("backfill-provenance self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--target-repo", default="sparq-org/sparq")
    parser.add_argument("--registry-repo", default="jeswr/agent-account-registry")
    parser.add_argument("--routing-file", default="orchestration/routing.toml",
                        help="target routing TOML (a local checkout path)")
    parser.add_argument("--apply", action="store_true",
                        help="actually write records + draft conversions (default: dry run)")
    parser.add_argument("--no-draft-convert", action="store_true",
                        help="record provenance ONLY; never touch draft state. Belt-and-braces "
                             "over the review-state predicate, which already refuses to draft a "
                             "queued/armed/review:pass PR (issue #726)")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    try:
        backfill(args.target_repo, args.registry_repo, args.routing_file, args.apply,
                 no_draft_convert=args.no_draft_convert)
    except BackfillError as exc:
        print(f"backfill-provenance: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
