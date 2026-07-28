#!/usr/bin/env python3
# [OPUS-5 #608] READ-ONLY grant-scope AUDIT for the set-up-account broker.
#
# WHY THIS EXISTS. Issue #579 made every NEW enrollment carry an explicit `target:<owner>/<repo>`
# authorization, but it deliberately left the grants that predate it alone: the rows already in
# policy/repos.toml were produced by the retired DOCUMENT-WIDE append, so both enabled targets
# still list the IDENTICAL `account_pool`. Every pre-#579 account is therefore still usable by
# every enabled target. #608 asks the audit question that must be answered before that can be
# narrowed: which accounts does each target actually NEED?
#
# WHAT THIS IS NOT. It is not a fix and it cannot become one. Narrowing an existing row REVOKES a
# live capability, so it is a maintainer POLICY decision, not a worker edit — this module holds no
# write path at all (grant-account.render_grant is the only sanctioned policy writer, and it only
# ADDS). Everything here is advisory evidence for a human, and the exit status is 0 whether or not
# revocation candidates are found: an audit that gated CI would turn an unmade decision into an
# outage.
#
# THE EVIDENCE, AND WHAT IT CAN HONESTLY PROVE. The durable per-(target, account) record is the
# implementer provenance corpus, `orchestration/provenance/<owner>--<name>--pr<N>.json`: the
# filename names the TARGET and `impl_account_h` is sha256(handle + ':' + PROVENANCE_SALT)[:16] —
# the account that did the work. Two other sources look usable and are not:
#   * `data/leases.json` is LIVE state, not history. groom.py's release path REMOVES a lease from
#     the array when it expires and keeps no ring, so it can only ever sample the present.
#   * `scripts/account-usage.py` probes LIVE rate-limit headroom per account and carries NO target
#     attribution whatsoever.
# So the provenance corpus is the only source that answers #608, and it answers it only for PRs
# that have a record. That bounds the audit, and the bound is enforced rather than narrated:
#
# FAIL-CLOSED, IN THE DIRECTION THAT MATTERS. The dangerous error here is proposing a revocation
# that is really just missing evidence. Absence of evidence is never reported as evidence of
# disuse:
#   1. A target with ZERO records yields `insufficient-evidence` and an EMPTY candidate list.
#   2. Without a salt the fingerprints cannot be mapped back to handles, so NO target ever yields
#      a candidate — the pool is "unknown", not "unused". Mapping is opt-in (`--salt-env`).
#   3. A fingerprint that no granted handle explains (a RETIRED account like acct03/acct06, or an
#      account granted to another row) is counted and surfaced, never silently dropped: it means
#      the corpus is describing accounts this row's pool does not, and the reader must know.
#
# PRIVACY. This registry is PUBLIC and the provenance README's rule is that records never carry a
# raw handle. A mapped report is exactly the join that rule avoids publishing, so NO report — text
# or JSON, mapped or not — ever emits a fingerprint; only handles the policy already lists in the
# clear, and counts. The report is therefore safe to paste into an issue. (--self-test proves it.)
"""Read-only per-target account_pool grant-scope evidence for a maintainer (issue #608)."""

import argparse
import collections
import hashlib
import importlib.util
import json
import os
import pathlib
import sys

FINGERPRINT_LENGTH = 16
# The `impl_account_h` shape asserted by worker-pr.record_document and mint-provenance.
_FINGERPRINT_ALPHABET = frozenset("0123456789abcdef")
# One record per worker PR; worker-pr.provenance_path builds exactly this name.
RECORD_SUFFIX = ".json"
RECORD_INFIX = "--pr"
DEFAULT_POLICY = "policy/repos.toml"
DEFAULT_PROVENANCE_DIR = "orchestration/provenance"
# The env var holding the salt, when the operator opts in to mapping. Never read unless asked for,
# never printed.
DEFAULT_SALT_ENV = "PROVENANCE_SALT"

STATUS_INSUFFICIENT = "insufficient-evidence"   # no records: say nothing about this row's pool
STATUS_UNMAPPED = "unmapped-evidence"           # records, but no salt: counts only, no candidates
STATUS_SCOPED = "scoped"                        # records + salt: candidates are meaningful


class AuditError(RuntimeError):
    """The evidence cannot be read safely, so no scope conclusion may be drawn from it."""


def _script_dir():
    return os.path.dirname(os.path.abspath(__file__))


def _load_sibling(filename, module_name):
    """Load a hyphen-named sibling script as a module (the account-usage._load_sibling pattern)."""
    spec = importlib.util.spec_from_file_location(
        module_name, os.path.join(_script_dir(), filename))
    if spec is None or spec.loader is None:
        raise AuditError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fingerprint(handle, salt):
    """The canonical public account identity. IDENTICAL to select-and-claim.account_fingerprint and
    worker-pr.account_hash — a drift here would map every handle to a fingerprint no record carries
    and report the whole pool as unused, so --self-test pins it against the real sibling."""
    if not isinstance(handle, str) or not handle or not isinstance(salt, str) or not salt:
        raise AuditError("a handle and a non-empty salt are required to map an account identity")
    return hashlib.sha256(f"{handle}:{salt}".encode()).hexdigest()[:FINGERPRINT_LENGTH]


def is_fingerprint(value):
    return (isinstance(value, str) and len(value) == FINGERPRINT_LENGTH
            and set(value) <= _FINGERPRINT_ALPHABET)


def pools_by_target(policy_text, grant_account):
    """{enabled target: sorted granted handles} from a policy document.

    Reuses grant-account's own parser so the audit reads the authorization boundary through the
    SAME lens the broker writes it with. A pool entry that is not a broker handle is a refusal: the
    audit must not reason about a row whose shape it does not recognise."""
    repos = grant_account._policy_repos(policy_text)
    pools = {}
    for target in grant_account.enabled_targets(policy_text):
        pool = repos[target].get("account_pool")
        if not isinstance(pool, list) or not pool:
            raise AuditError(f"enabled target {target!r} has no non-empty account_pool — refusing")
        for entry in pool:
            if not isinstance(entry, str) or not grant_account.HANDLE_RE.match(entry):
                raise AuditError(
                    f"target {target!r} lists account_pool entry {entry!r}, which is not a broker "
                    "handle — refusing to audit a pool shape this module cannot bound")
        if len(set(pool)) != len(pool):
            raise AuditError(f"target {target!r} lists a duplicate account_pool entry — refusing")
        pools[target] = sorted(pool)
    if not pools:
        raise AuditError("policy carries no `enabled = true` rows — nothing to audit")
    return pools


def record_prefix(target):
    """The provenance filename prefix worker-pr.provenance_path builds for `target`."""
    owner, _, name = target.partition("/")
    if not owner or not name:
        raise AuditError(f"target {target!r} is not an <owner>/<repo> name — refusing")
    return f"{owner}--{name}{RECORD_INFIX}"


def record_target(filename, targets):
    """The one audited target a record filename belongs to, or None when it belongs to none.

    Attribution is by the target's OWN prefix rather than by splitting the filename, because a
    repository name may itself contain `--` and a split would silently mis-attribute it. Two
    targets matching the same file is a refusal, not a first-wins guess."""
    if not filename.endswith(RECORD_SUFFIX):
        return None
    matched = [target for target in targets if filename.startswith(record_prefix(target))]
    if len(matched) > 1:
        raise AuditError(
            f"provenance record {filename!r} is attributable to more than one audited target "
            f"({', '.join(sorted(matched))}) — refusing to guess which row it is evidence for")
    return matched[0] if matched else None


def record_fingerprint(text, filename):
    """`impl_account_h` from one record's TEXT. Any unreadable record refuses the whole audit: a
    record we cannot parse is a PR whose account we do not know, and skipping it would quietly
    shrink the evidence for exactly the rows the audit is about to propose narrowing."""
    try:
        document = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise AuditError(f"provenance record {filename!r} does not parse as JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise AuditError(f"provenance record {filename!r} is not a JSON object — refusing")
    value = document.get("impl_account_h")
    if not is_fingerprint(value):
        raise AuditError(
            f"provenance record {filename!r} carries impl_account_h={value!r}, which is not a "
            f"{FINGERPRINT_LENGTH}-hex account fingerprint — refusing to audit a corpus with an "
            "unreadable record (fail closed)")
    return value


def collect_evidence(corpus, targets):
    """({target: {fingerprint: record count}}, records belonging to no audited target).

    `corpus` is an iterable of (filename, text) so the reader stays pure and the caller owns I/O."""
    evidence = {target: collections.Counter() for target in targets}
    foreign = 0
    for filename, text in corpus:
        target = record_target(filename, targets)
        if target is None:
            foreign += 1
            continue
        evidence[target][record_fingerprint(text, filename)] += 1
    return evidence, foreign


def read_corpus(directory):
    """Every `*--pr<N>.json` record under `directory`, as (filename, text). READ-ONLY."""
    root = pathlib.Path(directory)
    if not root.is_dir():
        raise AuditError(f"provenance directory {directory!r} is not a directory — refusing")
    corpus = []
    for path in sorted(root.iterdir()):
        if not path.is_file() or RECORD_INFIX not in path.name:
            continue
        if not path.name.endswith(RECORD_SUFFIX):
            continue
        corpus.append((path.name, path.read_text(encoding="utf-8")))
    return corpus


def shared_pool_groups(pools):
    """Sorted groups of 2+ enabled targets whose granted pools are EXACTLY equal — the #608
    condition itself. Two rows with an identical pool are provably unscoped relative to each
    other, whatever the usage evidence turns out to say."""
    by_pool = collections.defaultdict(list)
    for target, pool in pools.items():
        by_pool[tuple(pool)].append(target)
    return sorted([sorted(group) for group in by_pool.values() if len(group) > 1])


def audit(pools, evidence, foreign=0, salt=None):
    """The advisory report. `salt` unset => mapping is off => no target yields a candidate."""
    targets = {}
    for target, pool in sorted(pools.items()):
        counts = evidence.get(target, collections.Counter())
        records = sum(counts.values())
        row = {
            "granted": list(pool),
            "records": records,
            "distinct_accounts": len(counts),
            "evidenced": [],
            "revocation_candidates": [],
            "unexplained_accounts": 0,
        }
        if records == 0:
            # No record is not "no use" — it is no evidence. Say so and propose nothing.
            row["status"] = STATUS_INSUFFICIENT
        elif salt is None:
            # Records exist but nothing maps a fingerprint to a handle, so every granted handle is
            # UNKNOWN rather than unused. Counts only.
            row["status"] = STATUS_UNMAPPED
        else:
            row["status"] = STATUS_SCOPED
            seen = {fingerprint(handle, salt): handle for handle in pool}
            row["evidenced"] = sorted(seen[f] for f in counts if f in seen)
            row["revocation_candidates"] = sorted(set(pool) - set(row["evidenced"]))
            # A fingerprint no granted handle explains: a RETIRED handle (acct03/acct06 were
            # removed from both pools on 2026-07-25) or an account granted elsewhere. Surfaced,
            # because it means this row's pool does not describe everything that served this row.
            row["unexplained_accounts"] = sum(1 for f in counts if f not in seen)
        targets[target] = row
    return {
        "mapped": salt is not None,
        "foreign_records": foreign,
        "shared_pool_groups": shared_pool_groups(pools),
        "targets": targets,
        # Restated in the artifact so a reader who only ever sees the JSON cannot mistake it for a
        # decision, or for something that already happened.
        "decision": "maintainer",
        "revocation_applied": False,
    }


def render(report):
    """The human report. Emits handles and counts only — never a fingerprint (see PRIVACY)."""
    lines = ["grant-scope audit (issue #608) — ADVISORY EVIDENCE, no policy is changed",
             f"  account identity mapping: {'ON' if report['mapped'] else 'OFF (no salt)'}"]
    for group in report["shared_pool_groups"]:
        lines.append("  UNSCOPED: identical account_pool shared by " + ", ".join(group))
    if report["foreign_records"]:
        lines.append(f"  {report['foreign_records']} record(s) belong to no enabled target "
                     "(ignored)")
    for target, row in report["targets"].items():
        lines.append(f"  {target} [{row['status']}]")
        lines.append(f"    granted  ({len(row['granted'])}): {', '.join(row['granted'])}")
        lines.append(f"    records: {row['records']} across {row['distinct_accounts']} distinct "
                     "account(s)")
        if row["status"] == STATUS_SCOPED:
            lines.append(f"    evidenced ({len(row['evidenced'])}): "
                         f"{', '.join(row['evidenced']) or '(none)'}")
            lines.append(f"    revocation CANDIDATES ({len(row['revocation_candidates'])}): "
                         f"{', '.join(row['revocation_candidates']) or '(none)'}")
            if row["unexplained_accounts"]:
                lines.append(f"    {row['unexplained_accounts']} evidenced account(s) match NO "
                             "granted handle (retired, or granted to another row)")
        elif row["status"] == STATUS_INSUFFICIENT:
            lines.append("    no provenance record names this target — proposing nothing "
                         "(absence of evidence is not evidence of disuse)")
        else:
            lines.append("    no salt, so no fingerprint maps to a handle — proposing nothing")
    lines.append("  A revocation is a reviewed policy/repos.toml edit by the maintainer; this "
                 "tool never writes one.")
    return "\n".join(lines)


def run(policy_path, provenance_dir, salt=None):
    grant_account = _load_sibling("grant-account.py", "registry_grant_account")
    pools = pools_by_target(pathlib.Path(policy_path).read_text(encoding="utf-8"), grant_account)
    evidence, foreign = collect_evidence(read_corpus(provenance_dir), sorted(pools))
    return audit(pools, evidence, foreign=foreign, salt=salt)


# ---------------------------------------------------------------------------------------------
# SELF-TEST
# ---------------------------------------------------------------------------------------------
SALT = "test-salt"
_H = {handle: hashlib.sha256(f"{handle}:{SALT}".encode()).hexdigest()[:16]
      for handle in ("acct01", "acct02", "acct03", "acctzz")}


def _policy(rows):
    text = ""
    for target, (enabled, pool) in rows.items():
        listing = ", ".join(f'"{handle}"' for handle in pool)
        text += (f'[repos."{target}"]\nenabled = {str(enabled).lower()}\n'
                 f"account_pool = [{listing}]\n\n")
    return text


def _record(handle):
    return json.dumps({"pr_number": 1, "head_sha_at_open": "a" * 40, "impl_provider": "anthropic",
                       "impl_alias": "opus5", "impl_account_h": _H[handle], "issue": 1,
                       "recorded_at_run": "1.1"})


def _self_test():
    ok = True

    def check(label, got, want):
        nonlocal ok
        if got != want:
            ok = False
            print(f"FAIL {label}\n  got  {got!r}\n  want {want!r}")
        else:
            print(f"ok   {label}")

    def refuses(label, thunk):
        try:
            thunk()
        except AuditError:
            print(f"ok   {label}")
            return
        nonlocal ok
        ok = False
        print(f"FAIL {label}: no refusal")

    grant_account = _load_sibling("grant-account.py", "registry_grant_account")

    # -- IDENTITY PARITY. A drift here maps every handle to a fingerprint no record carries, so the
    # audit would report every pool entry unused: the exact false revocation this tool must not
    # produce. Pinned against the REAL sibling, with a wrong-salt positive control.
    sac = _load_sibling("select-and-claim.py", "registry_select_and_claim")
    check("fingerprint IS select-and-claim.account_fingerprint",
          fingerprint("acct01", SALT), sac.account_fingerprint("acct01", SALT))
    check("a different salt derives a DIFFERENT fingerprint (the check above is not vacuous)",
          fingerprint("acct01", SALT) == sac.account_fingerprint("acct01", "other"), False)
    refuses("an empty salt refuses rather than deriving an identity",
            lambda: fingerprint("acct01", ""))

    # -- POLICY READING
    both = _policy({"o/a": (True, ["acct01", "acct02", "acct03"]),
                    "o/b": (True, ["acct01", "acct02", "acct03"]),
                    "o/off": (False, ["acct01"])})
    pools = pools_by_target(both, grant_account)
    check("only ENABLED rows are audited", sorted(pools), ["o/a", "o/b"])
    check("the granted pool is read verbatim", pools["o/a"], ["acct01", "acct02", "acct03"])
    check("identical pools are reported as the #608 unscoped condition",
          shared_pool_groups(pools), [["o/a", "o/b"]])
    check("differing pools are NOT reported as unscoped (the check above is not vacuous)",
          shared_pool_groups({"o/a": ["acct01"], "o/b": ["acct02"]}), [])
    refuses("a pool entry that is not a broker handle refuses",
            lambda: pools_by_target(_policy({"o/a": (True, ["not a handle"])}), grant_account))
    refuses("an empty pool refuses",
            lambda: pools_by_target(_policy({"o/a": (True, [])}), grant_account))
    refuses("a policy with no enabled row refuses",
            lambda: pools_by_target(_policy({"o/a": (False, ["acct01"])}), grant_account))

    # -- RECORD ATTRIBUTION
    check("a record is attributed to its own target",
          record_target("o--a--pr7.json", ["o/a", "o/b"]), "o/a")
    check("a record for an unaudited target is attributed to NO target",
          record_target("x--y--pr7.json", ["o/a", "o/b"]), None)
    check("a repository name containing `--` is attributed by prefix, not by splitting",
          record_target("o--a--b--pr7.json", ["o/a--b", "o/a"]), "o/a--b")
    refuses("a record attributable to two targets refuses instead of guessing",
            lambda: record_target("o--a--pr1--pr7.json", ["o/a", "o/a--pr1"]))
    check("a well-formed record yields its fingerprint",
          record_fingerprint(_record("acct01"), "o--a--pr1.json"), _H["acct01"])
    refuses("a record with a non-fingerprint impl_account_h refuses the audit",
            lambda: record_fingerprint('{"impl_account_h": "zz"}', "o--a--pr1.json"))
    refuses("a record with NO impl_account_h refuses the audit",
            lambda: record_fingerprint('{"pr_number": 1}', "o--a--pr1.json"))
    refuses("an unparseable record refuses the audit (never skipped)",
            lambda: record_fingerprint("{not json", "o--a--pr1.json"))

    # -- THE CORE #608 QUESTION: usage is attributed PER TARGET, and does not leak across rows.
    corpus = [("o--a--pr1.json", _record("acct01")), ("o--a--pr2.json", _record("acct02")),
              ("o--b--pr3.json", _record("acct03")), ("x--y--pr4.json", _record("acct01"))]
    evidence, foreign = collect_evidence(corpus, ["o/a", "o/b"])
    check("records belonging to no audited target are counted, not attributed", foreign, 1)
    scoped = audit(pools, evidence, foreign=foreign, salt=SALT)
    check("a target's evidenced set is its OWN records only",
          scoped["targets"]["o/a"]["evidenced"], ["acct01", "acct02"])
    check("a handle used only by the OTHER target is a revocation candidate here",
          scoped["targets"]["o/a"]["revocation_candidates"], ["acct03"])
    check("and symmetrically for the other row",
          (scoped["targets"]["o/b"]["evidenced"],
           scoped["targets"]["o/b"]["revocation_candidates"]),
          (["acct03"], ["acct01", "acct02"]))
    check("the report never claims a revocation happened",
          (scoped["decision"], scoped["revocation_applied"]), ("maintainer", False))

    # -- FAIL CLOSED 1: no evidence for a row proposes NOTHING (not "revoke the whole pool").
    empty = audit(pools, {"o/a": collections.Counter(), "o/b": evidence["o/b"]}, salt=SALT)
    check("a target with zero records is insufficient-evidence",
          empty["targets"]["o/a"]["status"], STATUS_INSUFFICIENT)
    check("...and proposes NO revocation despite an entirely unevidenced pool",
          empty["targets"]["o/a"]["revocation_candidates"], [])
    check("...while the row that DOES have evidence still proposes (not vacuous)",
          empty["targets"]["o/b"]["revocation_candidates"], ["acct01", "acct02"])

    # -- FAIL CLOSED 2: no salt => no candidate anywhere, on the SAME corpus that produces them.
    unmapped = audit(pools, evidence, foreign=foreign, salt=None)
    check("without a salt every row is unmapped-evidence",
          sorted({row["status"] for row in unmapped["targets"].values()}), [STATUS_UNMAPPED])
    check("...and no row proposes a revocation",
          [row["revocation_candidates"] for row in unmapped["targets"].values()], [[], []])
    check("...though the distinct-account count is still reported honestly",
          unmapped["targets"]["o/a"]["distinct_accounts"], 2)

    # -- FAIL CLOSED 3: an evidenced account that no granted handle explains is surfaced.
    retired = {"o/a": collections.Counter({_H["acct01"]: 1, _H["acctzz"]: 3}),
               "o/b": collections.Counter()}
    row = audit(pools, retired, salt=SALT)["targets"]["o/a"]
    check("an unexplained (retired/foreign) account is counted", row["unexplained_accounts"], 1)
    check("...and does NOT mark any granted handle evidenced", row["evidenced"], ["acct01"])
    check("...so the remaining pool is still proposed for review",
          row["revocation_candidates"], ["acct02", "acct03"])

    # -- PRIVACY: no report ever emits a fingerprint, in either mode.
    check("the corpus really does carry the fingerprint (the checks below are not vacuous)",
          _H["acct01"] in corpus[0][1], True)
    for name, report in (("mapped", scoped), ("unmapped", unmapped)):
        blob = render(report) + json.dumps(report)
        leaked = sorted(value for value in _H.values() if value in blob)
        check(f"the {name} report emits no account fingerprint", leaked, [])
    check("...while still naming the handles the policy already lists in the clear",
          "acct03" in render(scoped), True)

    # -- END TO END over real files, and READ-ONLY: the inputs are byte-identical afterwards.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        policy_path = root / "repos.toml"
        policy_path.write_text(both, encoding="utf-8")
        prov = root / "provenance"
        prov.mkdir()
        for name, text in corpus:
            (prov / name).write_text(text, encoding="utf-8")
        (prov / "README.md").write_text("not a record", encoding="utf-8")
        before = {path.name: path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file()}
        end_to_end = run(str(policy_path), str(prov), salt=SALT)
        check("the end-to-end run reproduces the per-target scoping",
              end_to_end["targets"]["o/a"]["revocation_candidates"], ["acct03"])
        check("a non-record file in the corpus directory is ignored",
              end_to_end["foreign_records"], 1)
        after = {path.name: path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file()}
        check("the audit is READ-ONLY (policy + corpus byte-identical after a full run)",
              after, before)
        refuses("a missing provenance directory refuses",
                lambda: run(str(policy_path), str(root / "nope"), salt=SALT))

    # -- THE LIVE DOCUMENTS. Runs against this repo's real policy + provenance corpus, in the
    # DEFAULT (unmapped) mode, which is the mode CI would ever use. The assertion is the one that
    # stays true after the maintainer eventually narrows a row: the default mode is advisory-safe.
    repo = pathlib.Path(_script_dir()).parent
    live = run(str(repo / DEFAULT_POLICY), str(repo / DEFAULT_PROVENANCE_DIR))
    check("the real policy + corpus audit cleanly",
          all(row["granted"] for row in live["targets"].values()), True)
    check("the default (no-salt) mode proposes NO revocation on the real documents",
          [row["revocation_candidates"] for row in live["targets"].values()],
          [[] for _ in live["targets"]])
    print(render(live))
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default=DEFAULT_POLICY)
    parser.add_argument("--provenance-dir", default=DEFAULT_PROVENANCE_DIR)
    parser.add_argument(
        "--salt-env", nargs="?", const=DEFAULT_SALT_ENV, default=None,
        help=("opt in to mapping fingerprints back to handles by naming the env var holding "
              f"PROVENANCE_SALT (default {DEFAULT_SALT_ENV}). Without it no revocation candidate "
              "is ever proposed. The salt is never printed."))
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    salt = None
    if args.salt_env:
        salt = os.environ.get(args.salt_env) or None
        if salt is None:
            sys.stderr.write(
                f"{args.salt_env} is empty; continuing UNMAPPED (no revocation candidate will be "
                "proposed)\n")
    try:
        report = run(args.policy, args.provenance_dir, salt=salt)
    except AuditError as exc:
        sys.stderr.write(f"grant-scope-audit: {exc}\n")
        return 2
    print(json.dumps(report, indent=1, sort_keys=True) if args.json else render(report))
    # Always 0 on a successful read: this is advisory evidence for a human, never a gate. A
    # revocation is a maintainer decision, and an undecided decision must not fail anyone's CI.
    return 0


if __name__ == "__main__":
    sys.exit(main())
