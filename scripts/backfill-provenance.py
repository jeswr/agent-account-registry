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
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HEAD_RE = re.compile(r"^sparq-agent/issue-([1-9][0-9]*)-([0-9]+)-([0-9]+)$")
CLAIM_LINE_RE = re.compile(
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


def claim_from_log(log_text):
    """(account, model_alias) from a worker run log, or None. Matches the claim line format the
    PRE-migration worker.yml printed (historical logs; the current code no longer prints
    handles, but new PRs get provenance at publish time and never reach this script)."""
    match = CLAIM_LINE_RE.search(log_text or "")
    return (match.group(1), match.group(2)) if match else None


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

    pulls = _gh_json(["api", "--paginate",
                      f"repos/{target_repo}/pulls?state=open&per_page=100"])
    if not isinstance(pulls, list):
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
        issue, run_id, _attempt = parsed
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
            # Still reconcile the draft state (an earlier pass may have crashed between the two).
            _ensure_draft(target_repo, number, is_draft, apply_changes)
            continue

        # The worker RUN LOG is the only accepted identity source (no trailer fallback: trailers
        # on this pre-migration population are model-forgeable — see the module docstring).
        account = alias = None
        run_key = f"backfill:{run_id}"
        log = _run_gh(["run", "view", run_id, "--repo", registry_repo, "--log"], check=False)
        if log.returncode == 0:
            found = claim_from_log(log.stdout)
            if found:
                account, alias = found
        if alias is None or account is None:
            needs_human += 1
            print(f"NEEDS-HUMAN #{number}: worker run {run_id} log is unavailable or has no "
                  "claim line; leaving fail-closed invisible (record provenance manually only "
                  "after a human establishes the implementer identity)")
            continue
        provider = provider_of(alias, routing)
        if provider is None:
            needs_human += 1
            print(f"NEEDS-HUMAN #{number}: alias {alias!r} has no provider in routing")
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
    check("claim line parses",
          claim_from_log("...\nlease claimed: account=acct02, model=fable, claim=deadbeef\n"),
          ("acct02", "fable"))
    check("adopt line parses",
          claim_from_log("dispatcher lease adopted: account=acct01, model=terra, claim=ab"),
          ("acct01", "terra"))
    check("no claim line", claim_from_log("nothing here"), None)
    # Trailer-derived identity is REJECTED by construction: there is no code path from a commit
    # message to a provenance record (a forged GPT trailer cannot flip the reviewer provider).
    check("no trailer-based identity source", hasattr(sys.modules[__name__],
                                                      "alias_from_trailer"), False)
    routing = {"models": {"terra": {"provider": "openai"}, "fable": {"provider": "anthropic"}}}
    check("provider lookup", provider_of("terra", routing), "openai")
    check("unknown alias provider", provider_of("ghost", routing), None)
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
