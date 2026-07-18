#!/usr/bin/env python3
"""grant-account — the PURE account_pool grant logic behind set-up-account.yml.

account_pool membership IS the per-repository authorization every enforcement point re-checks
(policy-resolve validation, claim()'s pool filter, worker.yml's independent re-check), so the
broker's grant step must be exact-match and fail-closed. Extracted from the workflow's inline
python after review round 1 of #260 so the gate can regression-test it:

  THE #260 r1 DEFECT: membership was decided by substring-searching the RAW regex-captured
  array body for the quoted handle. A valid multiline account_pool can contain a comment such
  as `# retired "acct08"`; that text made the edit a no-op, and the textual no-op path then
  reported the handle "already present in every target pool" WITHOUT any parsed-TOML check —
  closing the request as granted while tomllib (and therefore every consumer) never saw the
  handle in the pool. Membership is now decided ONLY from parsed TOML (pending_targets), and
  the caller verifies the parsed postcondition on the no-op and the write path alike.

The workflow imports this module (importlib, like the read_accounts validation step) and keeps
only the contents-API CAS loop inline; everything decidable offline lives here, self-tested.

Usage:
  grant-account.py --self-test
"""
import re
import sys
import tomllib

SECTION_RE = re.compile(r'(?m)^\[repos\."([^"]+)"\]')
POOL_RE = re.compile(r"(?m)^(account_pool\s*=\s*\[)([^\]]*)(\])")


def pool_of(repos_doc, name):
    """The PARSED account_pool of one [repos."name"] row ([] when absent)."""
    return list((repos_doc.get(name) or {}).get("account_pool") or [])


PROVIDERS = ("openai", "anthropic")


def provider_from_labels(label_names):
    """The single provider a request's `provider:<name>` label selects (one of PROVIDERS),
    or None when absent, unknown, or AMBIGUOUS (several distinct provider labels). The broker
    fails closed on None — no silent default. Decided from the structured label LIST, never by
    splicing label text into shell `run:` source: a label name is untrusted and may carry shell
    metacharacters (a collaborator can add one before a trusted actor applies set-up-account),
    so `for lb in ${{ join(labels) }}` was a command-injection sink into a contents:write job."""
    present = [p for p in PROVIDERS if f"provider:{p}" in label_names]
    return present[0] if len(present) == 1 else None


def targets_from_labels(label_names):
    """The target-repo set a list of issue label names authorizes: every
    `target:<owner>/<name>` label (the same shape the broker's pre-login capture
    matches — `target:*/*`). Every other label authorizes nothing. Structured-list only,
    for the same injection reason as provider_from_labels — never shell-interpolated."""
    return {
        name[len("target:"):]
        for name in label_names
        if name.startswith("target:") and "/" in name[len("target:"):]
    }


def verify_live_targets(captured, live_label_names):
    """The write-time authorization re-check (#260 review round 2): the captured target set
    is a PRE-LOGIN snapshot of the event payload, and login can take ~13 min, during which a
    maintainer may remove or replace a `target:` label to revoke or redirect the request.
    The grant must therefore reflect the issue's CURRENT labels: the live-derived target set
    must be non-empty and EXACTLY equal the captured set — anything else (revoked, replaced,
    or even widened mid-login) refuses. Raises SystemExit (fail closed)."""
    live = targets_from_labels(live_label_names)
    if not live:
        raise SystemExit(
            "the live issue no longer carries any target:<owner>/<name> label — target "
            "authorization was revoked during login; refusing to grant (fail closed)")
    if live != set(captured):
        raise SystemExit(
            f"the live issue's target labels authorize {sorted(live)} but the pre-login "
            f"snapshot captured {sorted(set(captured))} — authorization changed during "
            "login; refusing to grant (fail closed)")


def pending_targets(repos_doc, targets, handle):
    """The targets whose PARSED account_pool does not contain `handle`. This is the only
    membership test: quoted-handle text elsewhere in the raw array body (a comment, a
    superstring entry) must never count as membership (#260 review round 1)."""
    return [t for t in targets if handle not in pool_of(repos_doc, t)]


def grant_targets(text, handle, grant_to):
    """Format-preserving edit: append `handle` to the account_pool line of exactly the rows
    named in `grant_to`, each inside its own [repos."owner/name"] section span (a whole-file
    subn — the #190 bug — would have granted every pool). The caller decides membership via
    pending_targets and MUST re-parse + verify_grant the result; this function only edits."""
    grant_to = set(grant_to)

    def append(match):
        head, entries, close = match.group(1), match.group(2), match.group(3)
        if "\n" not in entries:
            separator = ", " if entries.strip() else ""
            return f'{head}{entries}{separator}"{handle}"{close}'
        # Multiline array: an inline append lands on the LAST body line, which may be a
        # `# comment` that would swallow the new entry into the comment; insert on a fresh
        # line right after the opening bracket instead (a trailing comma after the inserted
        # entry is always valid TOML there, whatever follows).
        m = re.search(r"\n([ \t]*)\S", entries)
        indent = m.group(1) if m else "  "
        return f'{head}\n{indent}"{handle}",{entries}{close}'

    headers = list(SECTION_RE.finditer(text))
    if not headers:
        raise SystemExit('no [repos."..."] sections in policy/repos.toml')
    pieces = [text[:headers[0].start()]]
    for i, h in enumerate(headers):
        name = h.group(1)
        end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        section = text[h.start():end]
        if name in grant_to:
            section, count = POOL_RE.subn(append, section, count=1)
            if count == 0:
                raise SystemExit(f"target {name} has no account_pool line — refusing")
        pieces.append(section)
    return "".join(pieces)


def verify_grant(before, after, targets, handle):
    """The scoping invariant that closes #190 plus the #260 r1 postcondition, on PARSED
    documents: every target row's account_pool contains `handle` exactly once and gained
    nothing else; every non-target row's account_pool is unchanged. Raises SystemExit."""
    for name, row in before.items():
        old_pool = list(row.get("account_pool") or [])
        new_pool = pool_of(after, name)
        if name in targets:
            if new_pool.count(handle) != 1:
                raise SystemExit(
                    f"target {name} holds {handle} x{new_pool.count(handle)} (want exactly 1); refusing")
            if set(new_pool) - set(old_pool) - {handle}:
                raise SystemExit(f"target {name} gained unexpected members; refusing")
        elif new_pool != old_pool:
            raise SystemExit(
                f"non-target {name} account_pool changed — refusing to over-grant (fail closed)")


FIXTURE = '''\
# preamble comment stays byte-identical
[repos."o/single"]
enabled = true
account_pool = ["acct01", "acct02"]
max_concurrent = 1

[repos."o/multiline"]
enabled = true
account_pool = [
  "acct01",
  # retired "acct09"
]
max_concurrent = 1

[repos."o/empty"]
enabled = true
account_pool = []
max_concurrent = 1

[repos."o/nopool"]
enabled = false
max_concurrent = 1
'''


def _self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    def raises(name, fn):
        nonlocal ok
        try:
            fn()
        except SystemExit:
            print(f"  ok   {name}: refused (SystemExit)")
            return
        ok = False
        print(f"  FAIL {name}: did NOT refuse")

    before = tomllib.loads(FIXTURE).get("repos", {})

    # --- THE #260 r1 regression: a comment containing the quoted handle must NOT count as
    # membership. The old substring test saw `"acct09"` in the raw array body and skipped the
    # grant, then the textual no-op path reported success with no parsed-membership check.
    chk("comment text is not membership (the #260 r1 defect)",
        pending_targets(before, ["o/multiline"], "acct09"), ["o/multiline"])
    # ...and the grant to that multiline pool must survive the trailing comment line: the
    # entry lands on its own fresh line straight after the bracket (first, cosmetically —
    # membership is authorization, order is not), the parsed pool gains the handle, and
    # verify passes.
    granted = grant_targets(FIXTURE, "acct09", ["o/multiline"])
    after = tomllib.loads(granted).get("repos", {})
    chk("multiline grant is visible to tomllib (not swallowed by the comment)",
        pool_of(after, "o/multiline"), ["acct09", "acct01"])
    chk("the comment line itself is preserved", '# retired "acct09"' in granted, True)
    verify_grant(before, after, ["o/multiline"], "acct09")
    print("  ok   verify_grant accepts the multiline grant")

    # --- genuine membership (parsed) IS a verified no-op: nothing pending.
    chk("parsed membership makes the target non-pending",
        pending_targets(before, ["o/single", "o/multiline"], "acct01"), [])
    # --- THE #260 r5 regression: the no-op path (pending == []) must apply the SAME exact
    # postcondition as the write path — verify_grant(before, before, ...). A valid
    # single-occurrence no-op is accepted, but a target that already holds the handle MORE
    # THAN ONCE is still non-pending (pending_targets only tests `handle not in pool`) and so
    # would take the no-op path; without this check it would be reported "already granted"
    # despite violating the exactly-once grant invariant. Both directions must hold.
    verify_grant(before, before, ["o/single", "o/multiline"], "acct01")
    print("  ok   verify_grant accepts a valid single-occurrence no-op (before == after)")
    doubled_present = dict(before, **{"o/single": {"account_pool": ["acct01", "acct01"]}})
    chk("a doubled handle is still non-pending — it takes the no-op path",
        pending_targets(doubled_present, ["o/single"], "acct01"), [])
    raises("the no-op path refuses a target that already holds the handle twice",
           lambda: verify_grant(doubled_present, doubled_present, ["o/single"], "acct01"))

    # --- single-line + empty pools keep the compact append form; non-targets stay byte-identical.
    g2 = grant_targets(FIXTURE, "acct09", ["o/single", "o/empty"])
    a2 = tomllib.loads(g2).get("repos", {})
    chk("single-line append", 'account_pool = ["acct01", "acct02", "acct09"]' in g2, True)
    chk("empty-pool append", 'account_pool = ["acct09"]' in g2, True)
    chk("non-target multiline section is byte-identical",
        g2.split('[repos."o/multiline"]')[1].split('[repos."o/empty"]')[0]
        == FIXTURE.split('[repos."o/multiline"]')[1].split('[repos."o/empty"]')[0], True)
    verify_grant(before, a2, ["o/single", "o/empty"], "acct09")
    print("  ok   verify_grant accepts the single-line/empty grants")

    # --- refusal paths (fail closed, each must go red if weakened) ---
    raises("target without an account_pool line refuses",
           lambda: grant_targets(FIXTURE, "acct09", ["o/nopool"]))
    raises("document without [repos] sections refuses",
           lambda: grant_targets("just = 'toml'\n", "acct09", ["o/x"]))
    raises("verify refuses a target that did not gain the handle (old no-op shape)",
           lambda: verify_grant(before, before, ["o/multiline"], "acct09"))
    drifted = dict(after, **{"o/single": {"account_pool": ["acct01", "acct02", "evil"]}})
    raises("verify refuses non-target pool drift",
           lambda: verify_grant(before, drifted, ["o/multiline"], "acct09"))
    smuggled = dict(before, **{"o/single": {"account_pool": ["acct01", "acct02", "acct09", "evil"]}})
    raises("verify refuses an unexpected member riding the grant",
           lambda: verify_grant(before, smuggled, ["o/single"], "acct09"))
    doubled = dict(before, **{"o/single": {"account_pool": ["acct01", "acct02", "acct09", "acct09"]}})
    raises("verify refuses a double-appended handle",
           lambda: verify_grant(before, doubled, ["o/single"], "acct09"))

    # --- THE #260 r2 regression: the grant must re-check the issue's LIVE target labels at
    # write time. The captured set is a pre-login snapshot; a target label removed, replaced,
    # or added during the ~13-min login must refuse the grant, never silently proceed.
    live = ["set-up-account", "provider:openai", "target:o/single", "target:o/empty"]
    chk("target derivation matches the pre-login capture shape",
        targets_from_labels(live), {"o/single", "o/empty"})
    chk("non-target and slash-less labels authorize nothing",
        targets_from_labels(["target:noslash", "provider:openai", "o/em"]), set())

    # --- provider derivation is structured + fail-closed (the #260 r4 injection fix). These
    # labels are UNTRUSTED: parsing them from the list must never depend on shell-safe text,
    # and the provider must be exactly one known value or None (no silent default). ---
    chk("single provider label selects it",
        provider_from_labels(["set-up-account", "provider:anthropic"]), "anthropic")
    chk("no provider label -> None (fail closed, no default)",
        provider_from_labels(["set-up-account", "target:o/single"]), None)
    chk("unknown provider value -> None",
        provider_from_labels(["provider:evilcorp"]), None)
    chk("ambiguous (two providers) -> None (refuse, not last-wins)",
        provider_from_labels(["provider:openai", "provider:anthropic"]), None)
    # Injection-shaped label names the reviewer named (spaces/quotes/$()/;/newlines): as list
    # elements they are inert data — they select no provider/target and never reach a shell.
    hostile = ['provider:openai; rm -rf /', 'a "b"', '$(touch pwned)', 'x;y', 'line1\nprovider:anthropic', 'target:o/x`whoami`']
    chk("hostile look-alike labels select no provider",
        provider_from_labels(hostile), None)
    chk("a real provider label is still found alongside hostile look-alikes",
        provider_from_labels(hostile + ["provider:openai"]), "openai")
    chk("hostile target look-alikes do not forge a clean target",
        targets_from_labels(hostile), {"o/x`whoami`"})
    chk("newline-embedded provider text is not a real provider label",
        provider_from_labels(['provider:openai\nprovider:anthropic']), None)
    verify_live_targets(["o/single", "o/empty"], live)
    print("  ok   verify_live_targets accepts an unchanged live target set")
    raises("all target labels removed mid-login refuses (revocation)",
           lambda: verify_live_targets(["o/single"], ["set-up-account", "provider:openai"]))
    raises("target label replaced mid-login refuses",
           lambda: verify_live_targets(["o/single"], ["set-up-account", "target:o/other"]))
    raises("one of several target labels removed mid-login refuses",
           lambda: verify_live_targets(["o/single", "o/empty"], ["target:o/single"]))
    raises("target label added mid-login refuses (exact match, not subset)",
           lambda: verify_live_targets(["o/single"], ["target:o/single", "target:o/other"]))

    print("grant-account self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    if sys.argv[1:] == ["--self-test"]:
        return _self_test()
    print(__doc__.strip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
