#!/usr/bin/env python3
# One-shot provenance backfill for worker PRs opened BEFORE registry provenance recording
# existed. Without a record those open, unarmed, bot-authored PRs are fail-closed INVISIBLE to
# the review loop forever; this writes the missing orchestration/provenance/ files AND converts
# each PR to DRAFT (pre-migration PRs were opened non-draft, and both review gates hard-require
# draft — recording alone would leave them invisible). Idempotent: an existing record is never
# touched, an already-draft PR is left alone. Default is a DRY RUN — pass --apply to write.
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
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import NamedTuple

HEAD_RE = re.compile(r"^sparq-agent/issue-([1-9][0-9]*)-([0-9]+)-([0-9]+)$")


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


def _ensure_draft(target_repo, number, is_draft, apply_changes):
    """Convert a pre-migration non-draft PR to draft (both review gates require draft==True).
    Runs independently of record recording so a partially-failed earlier pass converges."""
    if is_draft:
        return True
    if not apply_changes:
        print(f"DRY-RUN #{number}: would convert to draft (review gates require draft)")
        return True
    undo = _run_gh(["pr", "ready", str(number), "-R", target_repo, "--undo"], check=False)
    if undo.returncode != 0:
        print(f"WARN #{number}: could not convert to draft — run "
              f"`gh pr ready {number} -R {target_repo} --undo` manually")
        return False
    print(f"converted #{number} to draft")
    return True


def backfill(target_repo, registry_repo, routing_file, apply_changes):
    worker_pr = _load_worker_pr()
    admission_error = _load_dispatch_claim().provenance_admission_error
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
    written = skipped = needs_human = 0
    for pull in pulls:
        if not isinstance(pull, dict):
            continue
        number = pull.get("number")
        head = pull.get("head") or {}
        ref = str(head.get("ref", ""))
        login = str((pull.get("user") or {}).get("login", ""))
        parsed = parse_head_ref(ref)
        if not isinstance(number, int) or parsed is None:
            continue
        if (head.get("repo") or {}).get("full_name") != target_repo:
            continue                      # fork heads never get provenance
        if not login.endswith("[bot]"):
            continue
        is_draft = pull.get("draft") is True
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
        if body is not None:
            record_error = existing_record_admission_error(body, number, admission_error)
            if record_error is None:
                skipped += 1
                print(f"skip #{number}: provenance already recorded")
                # Still reconcile the draft state (an earlier pass may have crashed between
                # the two).
                _ensure_draft(target_repo, number, is_draft, apply_changes)
                continue
            needs_human += 1
            print(f"NEEDS-HUMAN #{number}: an existing provenance record is present but NOT "
                  f"admissible by the review loop ({record_error}); a human must repair or "
                  "remove it before this PR becomes visible")
            continue

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
        if not isinstance(commits, list) or not commits:
            print(f"skip #{number}: PR has no commits")
            continue
        opened_sha = str((commits[0] or {}).get("sha", ""))
        if not re.fullmatch(r"[0-9a-f]{40}", opened_sha):
            print(f"skip #{number}: first commit sha is malformed")
            continue

        impl_account_h = worker_pr.account_hash(account, salt)
        if apply_changes:
            worker_pr.provenance_record(registry_repo, target_repo, number, opened_sha,
                                        provider, alias, impl_account_h, issue, run_key)
            written += 1
        else:
            # Privacy: never print the raw handle, only the (public-anyway) salted hash.
            print(f"DRY-RUN #{number}: would record impl={provider}/{alias} "
                  f"account_h={impl_account_h} issue=#{issue} opened={opened_sha[:8]} "
                  f"({run_key})")
            written += 1
        _ensure_draft(target_repo, number, is_draft, apply_changes)
    mode = "recorded" if apply_changes else "would record"
    print(f"backfill complete: {mode} {written}, skipped {skipped}, "
          f"needs-human {needs_human}")


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


def backfill_workflow_seam_report():
    """Findings about the LIVE backfill-provenance.yml invocation, each asserted by the
    self-test. Substring/count assertions do not catch YAML-seam mutations (`if: false`, a
    deleted step, a reordered command), so every finding below is structural."""
    workflow = _workflow("backfill-provenance.yml")
    # PyYAML parses a bare `on:` key as the boolean True.
    triggers = workflow.get("on") if "on" in workflow else workflow.get(True)
    job = workflow["jobs"]["backfill"]
    steps = job["steps"]
    step = next((s for s in steps if "backfill-provenance.py" in str(s.get("run") or "")), None)
    run = str((step or {}).get("run") or "")
    guard = str(job.get("if") or "")
    self_at = run.find("backfill-provenance.py --self-test")
    invoke_at = run.find('backfill-provenance.py "${args[@]}"')
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
        "dispatch_default_is_dry_run":
            (((triggers or {}).get("workflow_dispatch") or {}).get("inputs") or {})
            .get("apply", {}).get("default"),
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
    check("two-page slurped listing flattens (sol r5)",
          flatten_pull_pages([[{"number": 1}], [{"number": 2}, {"number": 3}]]),
          [{"number": 1}, {"number": 2}, {"number": 3}])
    check("non-list page fails closed", flatten_pull_pages([[{"number": 1}], "x"]), None)
    check("non-dict pull fails closed", flatten_pull_pages([[1]]), None)
    check("empty slurp is an empty list", flatten_pull_pages([]), [])
    check("forged worker-job lines alone resolve nothing", code_of(ident(forged)),
          REASON_NO_SOURCE)

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
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    try:
        backfill(args.target_repo, args.registry_repo, args.routing_file, args.apply)
    except BackfillError as exc:
        print(f"backfill-provenance: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
