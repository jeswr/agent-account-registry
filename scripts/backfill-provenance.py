#!/usr/bin/env python3
# One-shot provenance backfill for worker PRs opened BEFORE registry provenance recording
# existed. Without a record those open, unarmed, bot-authored PRs are fail-closed INVISIBLE to
# the review loop forever; this writes the missing orchestration/provenance/ files AND converts
# each PR to DRAFT (pre-migration PRs were opened non-draft, and both review gates hard-require
# draft — recording alone would leave them invisible). Idempotent: an existing record is never
# touched, an already-draft PR is left alone. Default is a DRY RUN — pass --apply to write.
"""backfill-provenance — reconstruct implementer provenance for pre-existing worker PRs.

Identity source (the ONLY one): the worker RUN. The head branch embeds the registry run id
(`sparq-agent/issue-<N>-<run_id>-<attempt>`); that run's log contains the exact
`lease claimed:`/`dispatcher lease adopted:` line with account + model alias.

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
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HEAD_RE = re.compile(r"^sparq-agent/issue-([1-9][0-9]*)-([0-9]+)-([0-9]+)$")
# ANCHORED to claim-job-prefixed lines (sol r1 on #147): `gh run view --log` prefixes every
# line `<job>\t<step>\t<timestamp> <content>`, and the claim line is printed by the "Claim
# live account lease" job, which runs no target/model code. An UNANCHORED search over the
# whole log let hostile worker-job output forge `lease claimed: account=...` and override the
# genuine identity — defeating the cross-provider inversion this record exists to protect.
CLAIM_LINE_RE = re.compile(
    r"(?mi)^[^\t]*claim[^\t]*\t[^\t]*\t\S+\s+"
    r"(?:lease claimed|dispatcher lease adopted): account=(acct[0-9a-z]{2,}), "
    r"model=([A-Za-z0-9][A-Za-z0-9_.-]*)")
class BackfillError(RuntimeError):
    """A concise, credential-free operational error."""


def parse_head_ref(ref):
    """(issue, run_id, attempt) from a worker head branch, or None."""
    match = HEAD_RE.fullmatch(ref or "")
    if not match:
        return None
    return int(match.group(1)), match.group(2), match.group(3)


# Tri-state sentinel (sol r2): "a source produced CONFLICTING matches" must never collapse
# into "a source is absent" — absent lets the other source stand alone, ambiguous is tamper
# evidence that fails the whole run.
AMBIGUOUS = object()


def claim_from_log(log_text):
    """Tri-state: (account, model_alias) from CLAIM-job-prefixed lines, None when absent, or
    AMBIGUOUS when differing repeats conflict (tamper evidence — sol r2)."""
    found = set(CLAIM_LINE_RE.findall(log_text or ""))
    if not found:
        return None
    return found.pop() if len(found) == 1 else AMBIGUOUS


def run_identity_from_log(log_text, target_repo, pr_number, issue, live_author):
    """The PR-BOUND (account, model_alias) for the run, or None (needs-human).

    Fail-closed rules (sol r1+r2):
    - The provenance-job source is REQUIRED — its command echo binds the identity to the exact
      PR being recorded (--target-repo/--pr/--issue must match the live PR); the run id in a
      head branch is model-forgeable, so an unbound identity (legacy claim line only) is never
      sufficient — that population (<= sparq#2542) already has master records anyway.
    - AMBIGUITY in EITHER source (conflicting repeats) fails the run — never fall back past a
      conflicted source.
    - When the legacy claim line is also present it must AGREE on (account, alias)."""
    anchored = provenance_job_identity_from_log(log_text)
    if anchored is None or anchored is AMBIGUOUS:
        return None
    if (anchored["target_repo"] != target_repo or anchored["pr"] != int(pr_number)
            or anchored["issue"] != int(issue)):
        return None
    # The historical job hard-required this exact App author (provenance_record
    # --verify-bot-login); the live PR author must still match it EXACTLY — any *[bot] is not
    # enough (sol r4: a job that failed VALIDATION, not the write, must never be recorded).
    if anchored["bot_login"] != live_author:
        return None
    legacy = claim_from_log(log_text)
    if legacy is AMBIGUOUS:
        return None
    identity = (anchored["account"], anchored["alias"])
    if legacy is not None and legacy != identity:
        return None
    return anchored["account"], anchored["alias"], anchored["provider"]


# Post-migration identity source (the #96 outage population: worker succeeded, the provenance
# JOB failed on the protected-master write, so no record exists and the worker log carries no
# handle). The failed provenance job's OWN log section still shows its env echo
# (`WORKER_IMPL_ACCOUNT: acctNN`) and command echo (`--impl-alias "<alias>"`). TRUST SCOPE: in
# `gh run view --log` output every line is prefixed `<job>\t<step>\t<timestamp> <content>`, and
# these patterns ANCHOR on a job name containing "provenance" — that job runs NO target/model
# code, so a hostile model printing a lookalike line lands under the WORKER job's prefix and
# can never match (same fail-closed posture as the no-trailer rule below).
# The Actions runner wraps every `run:` SCRIPT line in cyan SGR controls, and `gh run view
# --log` caret-sanitizes them (`^[[36;1m ... ^[[0m`) instead of stripping (sol r6 — with a
# synthetic-fixture false green, the six command fields matched NOTHING in a real log and
# every outage PR went AMBIGUOUS/needs-human). Accept an optional raw-ESC or caret-sanitized
# SGR wrapper before the field; env echoes (WORKER_IMPL_ACCOUNT) are runner-emitted, unwrapped.
_SGR_PREFIX = r"(?:(?:\^\[|\x1b)\[[0-9;]*m)?\s*"


def _prov_job_field(name, value_pattern):
    return re.compile(
        r"(?mi)^[^\t]*provenance[^\t]*\t[^\t]*\t\S+\s+" + _SGR_PREFIX + name
        + r"\s*" + value_pattern)


PROV_JOB_ACCOUNT_RE = _prov_job_field("WORKER_IMPL_ACCOUNT:", r"(acct[0-9a-z]{2,})\s*$")
PROV_JOB_ALIAS_RE = _prov_job_field("--impl-alias", r'"?([A-Za-z0-9][A-Za-z0-9_.-]*)"?')
# The PROVIDER is also run-bound (sol r3): deriving it from TODAY's mutable routing lets a
# routing remap flip a historical anthropic run to openai and defeat the cross-provider gate.
PROV_JOB_PROVIDER_RE = _prov_job_field("--impl-provider", r'"?(anthropic|openai)"?')
# The exact App-bot author the historical job REQUIRED (sol r4): accepting any *[bot] would
# record a provenance job that failed VALIDATION (hostile worker pointed it at another bot's
# PR) as if it were the #96 write outage.
PROV_JOB_BOTLOGIN_RE = _prov_job_field("--verify-bot-login",
                                       r'"?([A-Za-z0-9._-]+\[bot\])"?')
# PR-binding fields (sol r2): the provenance job's command echo names the exact PR it was
# recording — required to match the live PR, so a forged/reused run id in a head branch can
# never transplant another PR's identity.
PROV_JOB_TARGET_RE = _prov_job_field("--target-repo", r'"?([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)"?')
PROV_JOB_PR_RE = _prov_job_field("--pr", r'"?([1-9][0-9]*)"?')
PROV_JOB_ISSUE_RE = _prov_job_field("--issue", r'"?([1-9][0-9]*)"?')
# The resolve job's `policy resolved: models=<chain>` line — the DISPATCH-TIME route
# resolution, the trusted original for the record's immutable route_constraint (sol review r7
# finding 5: the source issue's CURRENT labels must never be captured as the original — a
# since-removed trust label would widen a historically opus-only PR to the default ladder).
# ANCHORED to the resolve job's log prefix exactly like the claim/provenance anchors above
# (sol r9 finding 2): that job ("Resolve policy without worker secrets") runs NO target/model
# code, so a hostile model printing a lookalike line lands under the WORKER job's prefix and
# can never match. The prior UNANCHORED search accepted a forged chain whenever the genuine
# line was absent from the fetched log — widening the immutable constraint.
CHAIN_LINE_RE = re.compile(
    r"(?mi)^[^\t]*resolve[^\t]*\t[^\t]*\t\S+\s+" + _SGR_PREFIX
    + r"policy resolved: models=([A-Za-z0-9][A-Za-z0-9_.-]*(?:,[A-Za-z0-9][A-Za-z0-9_.-]*)*)")


def provenance_job_identity_from_log(log_text):
    """Tri-state: a dict {account, alias, target_repo, pr, issue} from the FAILED provenance
    job's log section, None when the section/fields are absent, or AMBIGUOUS when any field
    has differing repeated matches (tamper evidence). Every field is required."""
    fields = {"account": PROV_JOB_ACCOUNT_RE, "alias": PROV_JOB_ALIAS_RE,
              "provider": PROV_JOB_PROVIDER_RE, "bot_login": PROV_JOB_BOTLOGIN_RE,
              "target_repo": PROV_JOB_TARGET_RE, "pr": PROV_JOB_PR_RE,
              "issue": PROV_JOB_ISSUE_RE}
    out = {}
    saw_any = False
    for key, pattern in fields.items():
        found = set(pattern.findall(log_text or ""))
        if len(found) > 1:
            return AMBIGUOUS
        if not found:
            continue
        saw_any = True
        out[key] = found.pop()
    if len(out) != len(fields):
        return AMBIGUOUS if saw_any else None
    out["pr"] = int(out["pr"])
    out["issue"] = int(out["issue"])
    return out


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


def chain_from_log(log_text):
    """Tri-state: the dispatch-time resolved model chain from RESOLVE-job-prefixed lines,
    None when absent, or AMBIGUOUS when differing anchored repeats conflict (tamper evidence
    — the resolve job prints the line exactly once per attempt)."""
    found = set(CHAIN_LINE_RE.findall(log_text or ""))
    if not found:
        return None
    return found.pop().split(",") if len(found) == 1 else AMBIGUOUS


def original_route_constraint(log_text, alias, routing):
    """(route_constraint, provenance_note) for the immutable record field, from TRUSTED run
    data only (sol review r7 finding 5 — never from the source issue's mutable current labels):
    - the resolve-job-anchored `policy resolved: models=` chain when it is present,
      UNAMBIGUOUS, names the implementing alias (the allocator only assigns chain members),
      AND every member is a catalog alias with a known provider. The membership checks stay
      load-bearing as defense-in-depth behind the job anchor (sol r9 finding 2): an
      unvalidated chain would flow raw `acct…` tokens into this workflow's public log and the
      immutable public record. Else
    - constraint-unknown, failing NARROWER: [alias] — the implementing alias is provably a
      member of the original chain, so every later fix-ladder intersection can only be a
      SUBSET of what the true original would allow, never a widening. AMBIGUOUS (conflicting
      anchored repeats) lands here too: tampering can only ever NARROW the recorded
      constraint, never widen it. (A narrowed alias the unified ladder does not carry fails
      the ladder intersection closed, to a human.)"""
    chain = chain_from_log(log_text)
    if chain is AMBIGUOUS:
        return [alias], ("constraint-unknown; narrowed to the implementing alias (the run "
                         "log's resolve-job chain lines CONFLICT — tamper evidence)")
    if (chain is not None and alias in chain
            and all(provider_of(member, routing) is not None for member in chain)):
        return chain, "dispatch-time resolved chain from the worker run log"
    return [alias], ("constraint-unknown; narrowed to the implementing alias (the run log "
                     "has no trustworthy resolved-chain line)")


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


def _load_worker_pr():
    path = Path(__file__).resolve().parent / "worker-pr.py"
    spec = importlib.util.spec_from_file_location("registry_worker_pr", path)
    if spec is None or spec.loader is None:
        raise BackfillError("cannot load worker-pr.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
        # ones on master. Either counts as already-recorded.
        probe = _run_gh(
            ["api", f"repos/{registry_repo}/contents/{record_path}?ref={worker_pr.LEDGER_REF}"],
            check=False)
        if probe.returncode != 0:
            probe = _run_gh(["api", f"repos/{registry_repo}/contents/{record_path}"],
                            check=False)
        if probe.returncode == 0:
            skipped += 1
            print(f"skip #{number}: provenance already recorded")
            # An EXISTING record that predates the required route_constraint field (sol review
            # r3 finding 2) is inadmissible by every consumer, and records are immutable —
            # this script must not silently dead-end the operator the admission error sent
            # here. Loud hand-off: a human deletes the stale record (a registry-maintainer
            # action) and re-runs this backfill, which then records the complete shape.
            try:
                meta = json.loads(probe.stdout)
                body = base64.b64decode("".join(meta["content"].split())).decode()
                if "route_constraint" not in json.loads(body):
                    needs_human += 1
                    print(f"NEEDS-HUMAN #{number}: the recorded provenance predates the "
                          "required route_constraint field; records are immutable, so a "
                          "human must delete the stale record and re-run this backfill")
            except (KeyError, ValueError, json.JSONDecodeError):
                needs_human += 1
                print(f"NEEDS-HUMAN #{number}: the recorded provenance is unreadable; a "
                      "human must inspect it")
            # Still reconcile the draft state (an earlier pass may have crashed between the two).
            _ensure_draft(target_repo, number, is_draft, apply_changes)
            continue

        # The worker RUN LOG is the only accepted identity source (no trailer fallback: trailers
        # on this pre-migration population are model-forgeable — see the module docstring).
        # The ATTEMPT encoded in the head branch is passed explicitly (sol r1): without it a
        # rerun's log could source identity from a different attempt than the one that pushed
        # this head.
        account = alias = None
        run_key = f"backfill:{run_id}.{attempt}"
        log = _run_gh(["run", "view", run_id, "--attempt", attempt,
                       "--repo", registry_repo, "--log"], check=False)
        echo_provider = None
        if log.returncode == 0:
            found = run_identity_from_log(log.stdout, target_repo, number, issue, login)
            if found:
                account, alias, echo_provider = found
        if alias is None or account is None:
            needs_human += 1
            print(f"NEEDS-HUMAN #{number}: worker run {run_id} attempt {attempt} log is "
                  "unavailable, has neither trusted job-anchored identity source, or the "
                  "sources DISAGREE (tampered/ambiguous evidence); leaving fail-closed "
                  "invisible (record provenance manually only after a human establishes the "
                  "implementer identity)")
            continue
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

        # Reconstruct the IMMUTABLE route constraint (a REQUIRED field, sol review r3
        # finding 2) from TRUSTED run data only — the same worker run log the identity came
        # from. The source issue's CURRENT labels are deliberately never consulted (sol
        # review r7 finding 5): labels are mutable, so a since-removed trust label would let
        # this backfill capture a WIDER-than-original chain as the immutable original —
        # exactly the weakening route_constraint exists to prevent. When the log carries no
        # trustworthy resolved chain the constraint falls back NARROWER, to the implementing
        # alias alone (provably a member of the original chain).
        route_constraint, constraint_note = original_route_constraint(log.stdout, alias,
                                                                      routing)
        print(f"#{number}: route constraint = {','.join(route_constraint)} "
              f"({constraint_note})")

        impl_account_h = worker_pr.account_hash(account, salt)
        if apply_changes:
            worker_pr.provenance_record(registry_repo, target_repo, number, opened_sha,
                                        provider, alias, impl_account_h, issue, run_key,
                                        route_constraint)
            written += 1
        else:
            # Privacy: never print the raw handle, only the (public-anyway) salted hash.
            print(f"DRY-RUN #{number}: would record impl={provider}/{alias} "
                  f"account_h={impl_account_h} issue=#{issue} opened={opened_sha[:8]} "
                  f"route={','.join(route_constraint)} ({run_key})")
            written += 1
        _ensure_draft(target_repo, number, is_draft, apply_changes)
    mode = "recorded" if apply_changes else "would record"
    print(f"backfill complete: {mode} {written}, skipped {skipped}, "
          f"needs-human {needs_human}")


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
    check("claim line parses (claim-job-anchored)",
          claim_from_log(f"{claim_job}\tAdopt\t2026-07-18T09:03:04Z "
                         "lease claimed: account=acct0fx3, model=fable, claim=deadbeef\n"),
          ("acct0fx3", "fable"))
    check("adopt line parses (claim-job-anchored)",
          claim_from_log(f"{claim_job}\tAdopt\t2026-07-18T09:03:04Z "
                         "dispatcher lease adopted: account=acct0fx4, model=terra, claim=ab"),
          ("acct0fx4", "terra"))
    check("UNANCHORED claim line no longer matches (worker-job forgery class)",
          claim_from_log("Run live target worker (DRAFT, review pending)\tmodel\t"
                         "2026-07-18T09:03:04Z lease claimed: account=acct0fx9, "
                         "model=terra, claim=ff"), None)
    check("no claim line", claim_from_log("nothing here"), None)
    # Trailer-derived identity is REJECTED by construction: there is no code path from a commit
    # message to a provenance record (a forged GPT trailer cannot flip the reviewer provider).
    check("no trailer-based identity source", hasattr(sys.modules[__name__],
                                                      "alias_from_trailer"), False)
    routing = {"models": {"terra": {"provider": "openai"}, "fable": {"provider": "anthropic"}}}
    check("provider lookup", provider_of("terra", routing), "openai")
    check("unknown alias provider", provider_of("ghost", routing), None)
    prov_job = "Record implementer provenance (no target code runs here)"

    def prov_lines(account="acct0fx1", alias="fable", provider="anthropic",
                   target="sparq-org/sparq", pr=3459, issue=3404, wrap=True):
        # wrap=True reproduces the LITERAL `gh run view --log` shape: command echoes carry
        # caret-sanitized SGR wrappers + a trailing continuation backslash (sol r6); the env
        # echo line is runner-emitted and unwrapped.
        step = f"{prov_job}\tRecord provenance\t2026-07-18T09:10:44Z "
        o, c, bs = ("^[[36;1m  ", " \\^[[0m", "") if wrap else ("", " \\", "")
        return (f"{step}  WORKER_IMPL_ACCOUNT: {account}\n"
                f'{step}{o}--target-repo "{target}"{c}\n'
                f'{step}{o}--pr "{pr}"{c}\n'
                f'{step}{o}--impl-provider "{provider}"{c}\n'
                f'{step}{o}--impl-alias "{alias}"{c}\n'
                f'{step}{o}--issue "{issue}"{c}\n'
                f'{step}{o}--verify-bot-login "sparq-orchestrator[bot]"{c}\n')

    prov_log = prov_lines()
    bound = {"account": "acct0fx1", "alias": "fable", "provider": "anthropic",
             "bot_login": "sparq-orchestrator[bot]",
             "target_repo": "sparq-org/sparq", "pr": 3459, "issue": 3404}
    check("provenance-job echo parses ALL binding fields (REAL caret-SGR log shape)",
          provenance_job_identity_from_log(prov_log), bound)
    check("unwrapped (raw-print) shape still parses",
          provenance_job_identity_from_log(prov_lines(wrap=False)), bound)
    forged = ("Run live target worker (DRAFT, review pending)\tmodel\t2026-07-18T09:10:44Z "
              "WORKER_IMPL_ACCOUNT: acct0fx9\n"
              "Run live target worker (DRAFT, review pending)\tmodel\t2026-07-18T09:10:44Z "
              '--impl-alias "opus"\n')
    check("worker-job forgery cannot match (job-prefix anchor)",
          provenance_job_identity_from_log(forged), None)
    check("conflicting repeats are AMBIGUOUS, not absent",
          provenance_job_identity_from_log(
              prov_log + prov_lines(account="acct0fx2")) is AMBIGUOUS, True)
    check("partial fields are AMBIGUOUS (never a half-bound identity)",
          provenance_job_identity_from_log(
              f"{prov_job}\ts\t2026-07-18T09:10:44Z   WORKER_IMPL_ACCOUNT: acct0fx1\n")
          is AMBIGUOUS, True)
    claim_ok = (f"{claim_job}\tAdopt\t2026-07-18T09:03:04Z "
                "lease claimed: account=acct0fx1, model=fable, claim=x\n")
    ident = lambda log, pr=3459, issue=3404, author="sparq-orchestrator[bot]": (
        run_identity_from_log(log, "sparq-org/sparq", pr, issue, author))
    check("bound identity resolves with the RUN's provider", ident(prov_log),
          ("acct0fx1", "fable", "anthropic"))
    check("agreeing legacy corroboration keeps it", ident(claim_ok + prov_log),
          ("acct0fx1", "fable", "anthropic"))
    check("provider conflicts are AMBIGUOUS",
          provenance_job_identity_from_log(
              prov_log + prov_lines(provider="openai")) is AMBIGUOUS, True)
    check("DISAGREEING trusted sources fail closed",
          ident(claim_ok.replace("acct0fx1", "acct0fx2") + prov_log), None)
    check("AMBIGUOUS legacy claims fail closed even with a clean anchored source (sol r2)",
          ident(claim_ok + claim_ok.replace("acct0fx1", "acct0fx2") + prov_log), None)
    check("claim-only identity is NEVER sufficient (unbound to the PR)",
          ident(claim_ok), None)
    check("PR-binding mismatch fails closed (reused run id)", ident(prov_log, pr=9999), None)
    check("issue-binding mismatch fails closed", ident(prov_log, issue=1), None)
    check("live author must EXACTLY match the echoed --verify-bot-login (sol r4)",
          ident(prov_log, author="different-bot[bot]"), None)
    check("two-page slurped listing flattens (sol r5)",
          flatten_pull_pages([[{"number": 1}], [{"number": 2}, {"number": 3}]]),
          [{"number": 1}, {"number": 2}, {"number": 3}])
    check("non-list page fails closed", flatten_pull_pages([[{"number": 1}], "x"]), None)
    check("non-dict pull fails closed", flatten_pull_pages([[1]]), None)
    check("empty slurp is an empty list", flatten_pull_pages([]), [])
    check("forged worker-job lines alone resolve nothing", ident(forged), None)
    # route_constraint is a REQUIRED provenance field (sol review r3 finding 2), reconstructed
    # from TRUSTED run data ONLY (sol review r7 finding 5): original_route_constraint takes
    # nothing but the run log and the claimed alias, so the source issue's mutable current
    # labels CANNOT influence the recorded original by construction.
    chain_routing = {"models": {
        "opus": {"provider": "anthropic"}, "fable": {"provider": "anthropic"},
        "haiku": {"provider": "anthropic"}, "luna": {"provider": "openai"},
        "sol": {"provider": "openai"}}}
    resolve_step = ("Resolve policy without worker secrets\tResolve issue routing through "
                    "registry policy\t2026-07-18T09:01:00Z ")
    worker_step = "Run live target worker (DRAFT, review pending)\tmodel\t2026-07-18T09:03:04Z "
    worker_log = (f"{resolve_step}policy resolved: models=opus, gate=registry-selftest, "
                  f"max_attempts=2\n{claim_job}\tAdopt\t2026-07-18T09:03:04Z "
                  "lease claimed: account=acct02, model=opus, claim=ab\n")
    check("dispatch-time chain parses from the resolve-job-anchored line",
          chain_from_log(f"{resolve_step}policy resolved: models=fable,haiku, "
                         "gate=crate-scoped, max_attempts=2"), ["fable", "haiku"])
    check("no resolved-chain line -> None", chain_from_log("nothing here"), None)
    # sol r9 finding 2, the load-bearing case: with the genuine resolve-job line ABSENT, a
    # forged line under the WORKER job's prefix must never be accepted — the job anchor makes
    # hostile model output unmatchable, so the constraint falls back NARROWER to [alias].
    forged_chain = f"{worker_step}policy resolved: models=opus,luna,fable,sol, gate=x\n"
    check("genuine-line-ABSENT + forged worker-job line -> no chain",
          chain_from_log(forged_chain), None)
    check("genuine-line-ABSENT + forged worker-job line falls back NARROWER",
          original_route_constraint(forged_chain, "opus", chain_routing)[0], ["opus"])
    check("a forged worker-job chain line cannot shadow the resolve job's line",
          chain_from_log(worker_log + forged_chain), ["opus"])
    # Conflicting RESOLVE-job-anchored repeats are tamper evidence: AMBIGUOUS, never a pick
    # between candidates — and the constraint still falls back NARROWER (tampering can only
    # ever narrow the record, never widen it).
    conflicted = worker_log + f"{resolve_step}policy resolved: models=opus,sol, gate=x\n"
    check("conflicting anchored chain lines are AMBIGUOUS, not a pick",
          chain_from_log(conflicted) is AMBIGUOUS, True)
    check("an AMBIGUOUS chain falls back NARROWER",
          original_route_constraint(conflicted, "opus", chain_routing)[0], ["opus"])
    check("route constraint recovers the dispatch-time original",
          original_route_constraint(worker_log, "opus", chain_routing)[0], ["opus"])
    # A logged chain that omits the claimed alias is corrupt/forged (the allocator only
    # assigns chain members) and must NOT be trusted — and the fallback must fail NARROWER:
    # [alias] is provably a subset of the true original, so no later fix ladder can widen.
    check("a chain omitting the claimed alias is not trusted (falls back narrower)",
          original_route_constraint(f"{resolve_step}policy resolved: models=luna,sol, gate=x",
                                    "opus", chain_routing)[0], ["opus"])
    check("constraint-unknown fails NARROWER to the implementing alias",
          original_route_constraint("no chain line at all", "fable", chain_routing)[0],
          ["fable"])
    # Defense-in-depth behind the job anchor: a chain member that is not a catalog alias (a
    # handle-shaped token, or any unknown name) invalidates the whole line — nothing
    # handle-shaped may reach the public log or the immutable record.
    check("a handle-shaped chain member is never trusted (no handle in log/record)",
          original_route_constraint(
              f"{resolve_step}policy resolved: models=opus,acct02xy, gate=x", "opus",
              chain_routing)[0], ["opus"])
    check("an unknown-alias chain member falls back narrower",
          original_route_constraint(f"{resolve_step}policy resolved: models=opus,ghost, "
                                    "gate=x", "opus", chain_routing)[0], ["opus"])
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
