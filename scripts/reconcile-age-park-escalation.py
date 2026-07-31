#!/usr/bin/env python3
"""[registry #1301] ONE-SHOT, AUDITED migration of the STALE AGE-PARK RECEIPTS that hold worker
PRs in the human-owned terminal with no machine exit — and nothing else.

WHY THESE PRs CANNOT DRAIN ON THEIR OWN. Until [registry #1298] `groom.age_park_generation`
summed the times the age sweep had PARKED a PR, while `AGE_UNPARK_MAX` bounds the automatic
RE-ADMISSIONS it has GRANTED. Every re-park therefore minted a receipt at a generation that had
never been written before, the hand-off's own receipt-fingerprint dedupe could never fire, the
comment was re-posted, the re-post bumped `updated_at`, and `stale_worker_pr_reason` re-derived
staleness from the clock the sweep had just wound. Three crossings with no push, no review and no
re-admission reached generation 3 and applied `needs:user`.

#1298 fixed the INFLOW: no new PR self-escalates. It does not drain the PRs already there, and
the binding blocker is NOT the missing cause-recovery provenance the #1298 body names. It is the
receipt itself: `groom.age_unpark_state` returns `(None, False)` whenever the LATEST park receipt
records `gen > AGE_UNPARK_MAX`, so the re-admission phase skips these PRs REGARDLESS of cause
recovery. Even if every one of them acquired a provenance record tomorrow they would still be
skipped. Measured on sparq-org/sparq#5001: three park receipts (gen 1/2/3), ZERO grant receipts,
one commit predating every park, the SAME head SHA in all three receipts, `review:parked` applied
once with no `UnlabeledEvent` anywhere, then `needs:user`.

WHY THIS IS A SCRIPT AND NOT A SWEEP — the same reason `reconcile-park-misescalation.py` is one.
`needs:user` is HUMAN-OWNED (park_policy invariant 3, written after an incident in which the
orchestrator re-applied it 37 minutes after the maintainer removed it). Teaching a cron to strip
it, or to rewrite a durable receipt, trades one silent failure for a worse one. What is correct is
a deliberate, one-off, per-PR-audited correction of a KNOWN, BOUNDED population that records on
each PR exactly why it is being moved and refuses every case it cannot prove.

RUN IT UNDER THE ORCHESTRATOR APP TOKEN, never by hand in the GitHub UI. A hand-applied or
hand-removed label carries no cause receipt and reads as a human action in the timeline forever —
the exact failure class this programme is repairing. Every write here is made by the bot, and the
label removal is authorised by, and preceded by, a durable receipt on the PR itself.

THE PROOF EACH PR MUST PASS (`verdict`, PURE and self-tested below). Every condition is a REFUSAL;
anything unproven leaves the PR exactly where it is:

  1. `needs:user` AND `review:parked` are BOTH live. The population is the double-labelled one:
     removing the human hold hands the PR back to grooming's own re-admission phase, which reads
     the machine park. A PR wearing only the human terminal is not this defect.
  2. No proven human ever APPLIED `needs:user` (park_policy.label_application_machine_owned, the
     #690 predicate — False for every ambiguity). `actor.type == "Bot"` is decisive for machine;
     the CONVERSE is not available, because the orchestrator session operates the maintainer's
     account, so a `User` actor FAILS CLOSED here and the hold stands.
  3. No injection / human-arm signal anywhere in the bot's own history
     (park_policy.LEGACY_PARK_DENY_PROSE — unconditional and order-independent).
  4. The newest age-park receipt is OVER the cap (`gen > AGE_UNPARK_MAX`) — i.e. it is the
     receipt that makes `age_unpark_state` skip the PR — AND its generation is NOT supported by
     the PR's own grant record (`gen > groom.age_park_generation(...)`, which counts un-park
     GRANT markers, malformed ones included, exactly as the mechanism counts them). A generation
     the grants DO support is a genuine flap: the cap is doing its job and the escalation stands.
  5. The corrected generation is itself within the cap, so the migration actually delivers a PR
     the re-admission phase can consider rather than one it will skip for the same reason.
  6. No residual human-owned hold would survive the removal
     (park_policy.migration_residual_holds).

THE CORRECTION. One audit comment naming the receipt pair that proves the staleness and CARRYING
A CORRECTED `GROOM_AGE_PARK_MARKER` RECEIPT at the generation the record supports, then the
removal of `needs:user`. RECEIPT-FIRST like every other park write here, and the removal is
VERIFIED by reading the labels back — a 2xx is not the same fact as the label being gone.

WHAT IT DOES NOT DO. It re-admits nothing. `review:parked` stands, and grooming clears it if and
only if that park's own cause is proven recovered, from the CORRECTED generation, under the same
`AGE_UNPARK_MAX` bound. So the migration terminates rather than returning these PRs to the thing
that parked them: the corrected receipt carries the stale receipt's own cause and head, which is
the fingerprint the hand-off's dedupe searches for, so a still-stale PR mints no new comment and
the self-wound clock does not restart.

DRY-RUN IS THE DEFAULT: it STATES THE POPULATION BY MEASUREMENT, with a per-refusal-code census
that always emits every row including a zero. `--apply` is required to write anything, and it
reports what it PROVED moved, attributed to this migration by its own durable marker.
"""
import argparse
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import park_policy

# The one-shot marker. Declared HERE, unlike park_policy.RECONCILE_MARKER, for the reason
# groom.AGE_UNPARK_STALL_MARKER is declared in groom: this one has NO reader in another checkout
# root — this script writes it and this script reads it back, for dedupe and convergence only.
# It must not CONTAIN either groom receipt marker, or age_receipts would read this comment's
# marker line as a receipt; the self-test asserts the body carries exactly ONE park marker and
# that groom's own parser reads it as the corrected receipt.
MIGRATION_MARKER = "<!-- registry-age-park-receipt-migrated:v1"

# The CLOSED refusal taxonomy, in the shape of park_policy's PARK_REFUSAL_* codes: a census keyed
# on prose cannot be counted, and this run's whole first half is a measurement.
CODE_MIGRATE = "stale-receipt"          # the population: an unsupported over-cap generation
CODE_CONVERGE = "converge"              # our receipt is on record; the label removal never landed
CODE_DONE = "reconciled"                # already migrated, and the hold is gone — one-shot
CODE_NO_HUMAN_HOLD = "no-human-hold"    # needs:user is not live
CODE_NO_MACHINE_PARK = "no-machine-park"
CODE_HUMAN_APPLIED = "human-applied"    # a proven human applied the hold (or it is unprovable)
CODE_DENY_PROSE = "deny-prose"          # injection / human-arm signal in the bot history
CODE_NO_RECEIPT = "no-receipt"          # not an age park of ours
CODE_WITHIN_CAP = "within-cap"          # the receipt does not block age_unpark_state at all
CODE_GRANTS_SUPPORT = "grants-support-gen"   # a GENUINE flap: the cap is doing its job
CODE_CAP_SPENT = "cap-spent"            # the corrected generation is over the cap too
CODE_RESIDUAL_HOLD = "residual-hold"    # another needs:* would survive the removal
CODE_SUPERSEDED = "superseded"          # a park application is newer than our own receipt
CODE_READ_FAILED = "read-failed"        # this PR's own GitHub state was unreadable
CODE_UNVERIFIED = "unverified"          # the removal could not be PROVEN to have landed
REFUSAL_CODES = (
    CODE_DONE, CODE_NO_HUMAN_HOLD, CODE_NO_MACHINE_PARK, CODE_HUMAN_APPLIED, CODE_DENY_PROSE,
    CODE_NO_RECEIPT, CODE_WITHIN_CAP, CODE_GRANTS_SUPPORT, CODE_CAP_SPENT, CODE_RESIDUAL_HOLD,
    CODE_SUPERSEDED, CODE_READ_FAILED, CODE_UNVERIFIED,
)


def _load(modname, filename):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    # Registered BEFORE exec: groom.py declares dataclasses, and `dataclasses` resolves a class's
    # own module out of sys.modules while processing it. An unregistered module raises there.
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


groom = _load("registry_groom", "groom.py")


def migration_record(comments, bot_login):
    """The NEWEST bot-authored comment carrying this script's marker, or None.

    Bot-authored only, like every other receipt reader here: a marker a third party could write is
    not a record of what this migration did, and trusting one would let a drive-by comment either
    suppress the correction or authorise the convergence delete below."""
    found = None
    for comment in (comments if isinstance(comments, list) else []):
        if not isinstance(comment, dict):
            continue
        login = str((comment.get("user") or {}).get("login", ""))
        if login.casefold() != str(bot_login or "\0").casefold():
            continue
        if MIGRATION_MARKER in str(comment.get("body", "")):
            found = comment
    return found


def verdict(pr_labels, park_receipts, supported_generation, bot_bodies, hold_applied_by_human,
            reconciled, migration_is_current=False):
    """PURE. ``(disposition, corrected_generation, code, detail)``.

    `disposition` is one of:
      - None         refused; the PR stays exactly as it is (every ambiguity lands here).
      - "migrate"    mint the corrected receipt, then remove `needs:user`.
      - "converge"   our corrected receipt is ALREADY on record but the hold is still live —
                     receipt-first ordering makes receipt-no-removal the only crash residue
                     possible, and it does NOT self-heal (the one-shot marker would refuse a
                     second migration forever). Retry the removal; mint nothing.

    `park_receipts` is groom.age_receipts(..., GROOM_AGE_PARK_MARKER, ...) output, oldest-first;
    `supported_generation` is groom.age_park_generation(...) — the generation the PR's own GRANT
    record supports, counting MARKERS so a corrupt grant receipt can never make the supported
    generation look SMALLER (which is the direction that would manufacture a migration).
    `hold_applied_by_human` MUST be True whenever that could not be determined (fail closed at
    the call site). `migration_is_current` is likewise a fail-closed caller computation: our
    receipt must be strictly newer than every park application, or a LATER, unrelated park is
    what the live label is and converging would delete it."""
    live = {label for label in (pr_labels or []) if isinstance(label, str)}
    if park_policy.HUMAN_PARK_LABEL not in live:
        return (None, None, CODE_DONE if reconciled else CODE_NO_HUMAN_HOLD,
                f"no live `{park_policy.HUMAN_PARK_LABEL}`"
                + (" — this migration is complete" if reconciled else " — nothing to migrate"))
    if park_policy.MACHINE_PARK_PR_LABEL not in live:
        return (None, None, CODE_NO_MACHINE_PARK,
                f"no live `{park_policy.MACHINE_PARK_PR_LABEL}` — removing the human hold would "
                "not hand this PR to grooming's re-admission phase, which reads the machine park")
    if hold_applied_by_human:
        return (None, None, CODE_HUMAN_APPLIED,
                "the hold is not PROVABLY machine-applied — a human decision is not the "
                "machine's to undo, and an unreadable timeline proves nothing")
    for body in bot_bodies or []:
        for pattern, denied in park_policy.LEGACY_PARK_DENY_PROSE:
            if pattern.search(str(body)):
                return (None, None, CODE_DENY_PROSE,
                        f"a {denied!r} signal is recorded on this PR — never automatically "
                        "re-classified, at any position in its history")
    receipts = [record for record in (park_receipts or [])
                if isinstance(record, dict) and isinstance(record.get("gen"), int)]
    residual = park_policy.migration_residual_holds(
        live, (), clearing=[park_policy.HUMAN_PARK_LABEL])
    if residual:
        return (None, None, CODE_RESIDUAL_HOLD,
                f"{'/'.join(sorted(residual))} would still hold this PR out after the removal — "
                "refusing to move a park into a state it could not leave")
    if reconciled:
        if not migration_is_current:
            return (None, None, CODE_SUPERSEDED,
                    "a park application is at least as new as this migration's own receipt, so "
                    "the live hold is a DIFFERENT, later decision — not the one we minted for")
        corrected = receipts[-1]["gen"] if receipts else None
        return ("converge", corrected, CODE_CONVERGE,
                "the corrected receipt is on record but the human-owned hold is still live — "
                "completing the interrupted removal, consuming no new evidence")
    if not receipts:
        return (None, None, CODE_NO_RECEIPT,
                "no age-park receipt — this is not a park grooming's age hand-off wrote, so "
                "nothing here proves how this PR reached the human terminal")
    stale = receipts[-1]["gen"]
    if stale <= groom.AGE_UNPARK_MAX:
        return (None, None, CODE_WITHIN_CAP,
                f"the newest age-park receipt is `gen={stale}`, within the cap — "
                "age_unpark_state already considers this park, so no receipt blocks it")
    if stale <= supported_generation:
        return (None, None, CODE_GRANTS_SUPPORT,
                f"`gen={stale}` IS supported by this PR's own grant record "
                f"(generation {supported_generation}) — the machine really did re-admit it and "
                "it really did come back, so the escalation is a genuine flap and stands")
    if supported_generation > groom.AGE_UNPARK_MAX:
        return (None, None, CODE_CAP_SPENT,
                f"the corrected generation {supported_generation} is over the cap too, so the "
                "migration would deliver a PR the re-admission phase skips for the same reason")
    return ("migrate", supported_generation, CODE_MIGRATE,
            f"the newest age-park receipt records `gen={stale}`, but this PR's own un-park GRANT "
            f"record supports generation {supported_generation} "
            f"({supported_generation - 1} automatic re-admission(s) on record): the generation "
            "that reached the human terminal was never earned")


def audit_body(pr_number, cause, head, stale_generation, corrected_generation, detail):
    """The per-PR audit record. It quotes the receipt PAIR that proves the staleness, so a reader
    can re-derive the verdict from the PR itself rather than trusting this run — and it CARRIES
    the corrected receipt, so the correction and its justification are one durable object."""
    grants = corrected_generation - 1
    return (
        "> 🤖 SPARQ agent — **migrating a stale age-park receipt** (registry #1301)\n\n"
        "This pull request was escalated to the human-owned "
        f"`{park_policy.HUMAN_PARK_LABEL}` terminal by grooming's age hand-off, on an age-park "
        "GENERATION its own durable record does not support.\n\n"
        "Until registry #1298 that generation counted how many times the sweep had **parked** "
        "this PR, while the cap it is spent against bounds the automatic re-admissions the sweep "
        "had **granted**. Each re-park therefore minted a receipt at a generation never written "
        "before, so the hand-off's own dedupe could not fire, the comment was re-posted, the "
        "re-post bumped `updated_at`, and the next staleness crossing followed from the sweep's "
        "own comment rather than from anything that happened to this PR.\n\n"
        f"**The proof, from this PR's own receipts:** the newest age-park receipt records "
        f"`gen={stale_generation}`, while the un-park **grant** receipts on record number "
        f"**{grants}** — so the generation this PR has actually earned is "
        f"`{corrected_generation}`. "
        f"{stale_generation - corrected_generation} of the generations it climbed to reach the "
        "terminal were never earned.\n\n"
        "**The correction.** A corrected age-park receipt at the generation the record supports "
        f"is minted below, and `{park_policy.HUMAN_PARK_LABEL}` is removed. **Nothing here "
        f"re-admits this PR**: the machine-owned `{park_policy.MACHINE_PARK_PR_LABEL}` park "
        "stands exactly as it is. What changes is that grooming's re-admission phase can "
        "CONSIDER it again — it was skipping this PR outright, whatever its cause had done — "
        "and it will clear the park if, and only if, that park's own cause is proven recovered, "
        "from the corrected generation and under the same cap.\n\n"
        "No review judgement is implied or changed, and no round or attempt budget is touched.\n\n"
        f"A human can still hold this PR at any time by re-applying "
        f"`{park_policy.HUMAN_PARK_LABEL}` — that gesture is sticky and no automation may "
        "override it.\n\n"
        f"{MIGRATION_MARKER} pr={pr_number} from-gen={stale_generation} "
        f"to-gen={corrected_generation} -->\n"
        f"<!-- migration basis: {detail} -->\n"
        f"{groom.AGE_PARK_MARKER} cause={cause} head={head} gen={corrected_generation} -->"
    )


def _gh(args, token=None, check=True):
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    result = subprocess.run(["gh", *args], capture_output=True, text=True, env=env, check=False)
    if check and result.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:3])} failed: {result.stderr[:300]}")
    return result


def _gh_json(args, token=None):
    return json.loads(_gh(args, token=token).stdout or "null")


def _paginated(repo, number, kind, token=None):
    pages = _gh_json(["api", "--paginate", "--slurp",
                      f"repos/{repo}/issues/{number}/{kind}?per_page=100"], token=token)
    if not isinstance(pages, list):
        raise RuntimeError(f"malformed {kind} payload for {repo}#{number}")
    out = []
    for page in pages:
        if not isinstance(page, list):
            raise RuntimeError(f"malformed {kind} page for {repo}#{number}")
        out.extend(page)
    return out


def _label_names(rows, what):
    """Label names from a labels payload, RAISING on any malformed entry.

    Skipping what it cannot parse would make an unreadable label set look like one the hold has
    left — reading "I cannot tell" as "it is gone", which is the direction the read-back exists
    to close (the groom `_label_gone` rule)."""
    names = set()
    for item in rows:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise RuntimeError(f"malformed {what}")
        names.add(item["name"])
    return names


def _maintainer_probe(repo, maintainer, token):
    """The strict human probe, FAIL-CLOSED for a delete of a HUMAN-OWNED label.

    park_policy._is_proven_human rejects `[bot]` logins and App-driven events before this is ever
    called, so what reaches it is a plain user account. Groom's veto probe answers "not a
    maintainer" when the collaborator read fails, because there an unverifiable actor must not
    MINT a veto. Here the same answer would AUTHORISE removing the human terminal, so the
    direction is inverted, exactly as reconcile-park-misescalation.py inverts it: anything this
    cannot verify counts as a human, and the hold stands."""
    def probe(login):
        if str(login).casefold() == str(maintainer or "").casefold():
            return True
        try:
            payload = _gh_json(
                ["api", f"repos/{repo}/collaborators/{urllib.parse.quote(str(login))}/permission"],
                token=token)
        except Exception:  # noqa: BLE001 — unverifiable actor on a human-terminal delete
            return True
        if not isinstance(payload, dict):
            return True
        return str(payload.get("permission", "")) in park_policy.HUMAN_MAINTAINER_PERMISSIONS

    return probe


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--repo")
    parser.add_argument("--bot-login")
    parser.add_argument("--maintainer", default=os.environ.get("MAINTAINER_HANDLE", "jeswr"))
    parser.add_argument("--token", default=None)
    parser.add_argument("--apply", action="store_true",
                        help="write. Without it the run is a DRY RUN and mutates nothing.")
    parser.add_argument("--limit", type=int, default=0, help="0 = no cap")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if not (args.repo and args.bot_login):
        parser.error("--repo and --bot-login are required outside --self-test")

    held = _gh_json(["api", f"repos/{args.repo}/issues?state=open"
                     f"&labels={urllib.parse.quote(park_policy.HUMAN_PARK_LABEL)}"
                     "&per_page=100", "--paginate", "--slurp"], token=args.token)
    rows = [row for page in (held if isinstance(held, list) else []) if isinstance(page, list)
            for row in page if isinstance(row, dict) and row.get("pull_request")]
    print(f"{len(rows)} open PR(s) on {park_policy.HUMAN_PARK_LABEL} in {args.repo}")
    moved, refused = [], []
    census = {code: 0 for code in REFUSAL_CODES}
    for row in sorted(rows, key=lambda row: row.get("number") or 0):
        number = row.get("number")
        try:
            pr_labels = _label_names(
                [label for label in (row.get("labels") or [])],
                f"label on {args.repo}#{number}")
            comments = _paginated(args.repo, number, "comments", token=args.token)
            timeline = _paginated(args.repo, number, "timeline", token=args.token)
            bot_bodies = [str(comment.get("body", ""))
                          for comment in comments if isinstance(comment, dict)
                          and str((comment.get("user") or {}).get("login", "")).casefold()
                          == args.bot_login.casefold()]
            is_human = _maintainer_probe(args.repo, args.maintainer, args.token)
            # FAIL CLOSED on the ownership probe: anything unreadable counts as "a human applied
            # it", so an unreadable timeline never authorises removing the human terminal. The
            # refusal lives in the `except` rather than in a pre-set default — a default here
            # would be dead (every path either assigns or `continue`s) and a dead guard reads as
            # protection that is not there.
            try:
                applied_by_human = not park_policy.label_application_machine_owned(
                    args.repo, number, park_policy.HUMAN_PARK_LABEL,
                    lambda _repo, num: timeline, is_human=is_human,
                    log=lambda *_a, **_k: None)
            except Exception as exc:  # noqa: BLE001
                print(f"  #{number}: REFUSED [{CODE_HUMAN_APPLIED}] — ownership probe failed "
                      f"({exc})")
                census[CODE_HUMAN_APPLIED] += 1
                refused.append((number, CODE_HUMAN_APPLIED))
                continue
            record = migration_record(comments, args.bot_login)
            # THE RECENCY CONJUNCT, and it is only consulted on the convergence path. Our own
            # receipt matching is a HISTORICAL fact; it does not prove that the label live RIGHT
            # NOW is the one we minted for. park_applications is the documented API for "when was
            # the newest park applied", and a park on ANY park label refuses — the conservative
            # direction, and the same call groom's convergence branch makes for the same reason.
            current = False
            if record is not None:
                stamp = record.get("created_at")
                if park_policy.valid_timestamp(stamp):
                    latest_park, _human, readable = park_policy.park_applications(
                        args.repo, number, None, lambda _repo, num: timeline,
                        is_human=is_human, log=lambda *_a, **_k: None)
                    current = bool(readable) and (
                        latest_park is None or park_policy.parse_ts(stamp) > latest_park)
            disposition, corrected, code, detail = verdict(
                pr_labels,
                groom.age_receipts(comments, groom.AGE_PARK_MARKER, args.bot_login),
                groom.age_park_generation(comments, args.bot_login),
                bot_bodies, applied_by_human, record is not None, current)
            if not disposition:
                print(f"  #{number}: REFUSED [{code}] — {detail}")
                census[code] += 1
                refused.append((number, code))
                continue
            print(f"  #{number}: {disposition.upper()} [{code}] — {detail}")
            if not args.apply:
                moved.append((number, corrected, f"dry-run/{disposition}"))
                continue
            if args.limit and len([m for m in moved if m[2].startswith("applied")]) >= args.limit:
                print(f"  #{number}: deferred — --limit {args.limit} reached this run")
                break
            if disposition == "migrate":
                # RECEIPT FIRST: the audit comment carries the corrected receipt AND is the
                # authorisation for the removal, so a crash after it leaves an explained PR whose
                # only residue the convergence path above completes.
                stale = groom.age_receipts(
                    comments, groom.AGE_PARK_MARKER, args.bot_login)[-1]
                body = audit_body(number, stale["cause"], stale["head"], stale["gen"],
                                  corrected, detail)
                _gh(["api", "-X", "POST", f"repos/{args.repo}/issues/{number}/comments",
                     "-f", f"body={body}"], token=args.token)
                print(f"    WRITE corrected age-park receipt pr={number} "
                      f"cause={stale['cause']} gen={stale['gen']} -> gen={corrected}")
            _gh(["api", "-X", "DELETE",
                 f"repos/{args.repo}/issues/{number}/labels/"
                 + urllib.parse.quote(park_policy.HUMAN_PARK_LABEL, safe="")],
                token=args.token)
            # VERIFY: a 2xx on the DELETE is not the same fact as the label being gone, and this
            # run's second job is to report what ACTUALLY moved.
            remaining = _label_names(
                _paginated(args.repo, number, "labels", token=args.token),
                f"label read-back for {args.repo}#{number}")
            if park_policy.HUMAN_PARK_LABEL in remaining:
                print(f"  #{number}: REFUSED [{CODE_UNVERIFIED}] — the DELETE reported success "
                      f"but `{park_policy.HUMAN_PARK_LABEL}` is still live; the corrected receipt "
                      "is on record and the next run converges on it")
                census[CODE_UNVERIFIED] += 1
                refused.append((number, CODE_UNVERIFIED))
                continue
            print(f"    WRITE remove label pr={number} "
                  f"label={park_policy.HUMAN_PARK_LABEL} (verified gone)")
            moved.append((number, corrected, f"applied/{disposition}"))
        except Exception as exc:  # noqa: BLE001 — one bad PR never stops the migration
            print(f"  #{number}: REFUSED [{CODE_READ_FAILED}] — {exc}")
            census[CODE_READ_FAILED] += 1
            refused.append((number, CODE_READ_FAILED))
    print(f"\n{'APPLIED' if args.apply else 'DRY RUN'}: "
          f"{len(moved)} migrated, {len(refused)} refused")
    for number, corrected, how in moved:
        print(f"  migrated #{number} (corrected generation {corrected}, {how})")
    # THE RESIDUAL, computed against the ENUMERATED population rather than against the rows that
    # reached a verdict: `--limit` and the per-PR `break` are losses that PREVENT entry, and a
    # total summed from the two outcome lists is structurally blind to them.
    print(f"population={len(rows)} migrated={len(moved)} refused={len(refused)} "
          f"not-reached={len(rows) - len(moved) - len(refused)}")
    # The census emits EVERY code, including a zero row: a refusal class that only appears when it
    # is non-empty cannot be noticed when a branch takes 100% of the population.
    print("refusal census (every code, zero rows included):")
    for code in REFUSAL_CODES:
        print(f"  {code}={census[code]}")
    return 0


def _self_test():
    ok = True
    checks = 0

    def check(name, got, want):
        nonlocal ok, checks
        checks += 1
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    bot = "sparq-orchestrator[bot]"
    head = "dfd6fef7" + "0" * 32
    live = [park_policy.HUMAN_PARK_LABEL, park_policy.MACHINE_PARK_PR_LABEL]

    def receipt(gen, cause="orphan-draft", sha=head):
        return {"cause": cause, "head": sha, "gen": gen, "at": "2026-07-29T07:18:01Z"}

    def v(**over):
        # sparq#5001's LIVE shape: park receipts gen 1/2/3, ZERO grants, both labels live, the
        # hold machine-applied. Literal generations throughout — deriving them from
        # AGE_UNPARK_MAX would leave every row green when the cap is moved.
        base = dict(pr_labels=live, park_receipts=[receipt(1), receipt(2), receipt(3)],
                    supported_generation=1, bot_bodies=["untouched beyond the threshold"],
                    hold_applied_by_human=False, reconciled=False, migration_is_current=False)
        base.update(over)
        return verdict(**base)

    check("the LIVE population migrates: a gen-3 receipt with ZERO grants on record is the "
          "stale escalation that makes age_unpark_state skip the PR (sparq#5001)",
          v()[:3], ("migrate", 1, CODE_MIGRATE))
    # The load-bearing negative. Same receipts, but the grants are REALLY on record: this PR was
    # re-admitted twice and came back twice, which is the flap the cap exists to escalate.
    check("a GENUINE flap is never migrated — a generation the grant record SUPPORTS stands",
          v(supported_generation=3)[:3], (None, None, CODE_GRANTS_SUPPORT))
    check("a receipt WITHIN the cap is not this population (it never blocked the exit phase)",
          v(park_receipts=[receipt(1), receipt(2)])[:3], (None, None, CODE_WITHIN_CAP))
    check("a corrected generation that is ITSELF over the cap refuses: the migration must "
          "deliver a PR the re-admission phase can consider, not one it skips identically",
          v(park_receipts=[receipt(4)], supported_generation=3)[:3],
          (None, None, CODE_CAP_SPENT))
    check("a hold that is not PROVABLY machine-applied is never removed (a `User` actor, an "
          "unreadable timeline and a missing labeled event all arrive here)",
          v(hold_applied_by_human=True)[:3], (None, None, CODE_HUMAN_APPLIED))
    check("an injection / human-arm signal refuses at ANY position in the bot history",
          [v(bot_bodies=[body])[2] for body in
           ("the reviewer flagged possible prompt injection",
            "untouched beyond the threshold\n\nprompt-injection flagged earlier",
            "this needs a human decision because of a security finding")],
          [CODE_DENY_PROSE, CODE_DENY_PROSE, CODE_DENY_PROSE])
    check("a PR with no age-park receipt is not this script's population",
          v(park_receipts=[])[:3], (None, None, CODE_NO_RECEIPT))
    check("the machine park must be LIVE — otherwise the removal hands the PR to nothing",
          v(pr_labels=[park_policy.HUMAN_PARK_LABEL])[:3], (None, None, CODE_NO_MACHINE_PARK))
    check("a PR not holding the human terminal is refused",
          v(pr_labels=[park_policy.MACHINE_PARK_PR_LABEL])[:3],
          (None, None, CODE_NO_HUMAN_HOLD))
    check("only the ONE `needs:user` hold is offered for clearing — any other needs:* would "
          "survive the removal and refuses the whole move",
          [v(pr_labels=live + [label])[2] for label in
           ("needs:ec2", "needs:external-audit", park_policy.HUMAN_PR_PARK_LABEL)],
          [CODE_RESIDUAL_HOLD, CODE_RESIDUAL_HOLD, CODE_RESIDUAL_HOLD])
    # Receipt-first ordering makes receipt-no-removal the only crash residue, and the one-shot
    # marker would otherwise refuse it forever.
    check("a migration whose receipt landed and whose removal did not CONVERGES (mints nothing) "
          "— and is DONE, not converging, once the hold is actually gone",
          (v(reconciled=True, migration_is_current=True,
             park_receipts=[receipt(3), receipt(1)])[:3],
           v(reconciled=True, migration_is_current=True,
             pr_labels=[park_policy.MACHINE_PARK_PR_LABEL])[:3]),
          (("converge", 1, CODE_CONVERGE), (None, None, CODE_DONE)))
    check("convergence refuses when a park application is not OLDER than our own receipt — the "
          "live hold is then a different, later decision",
          v(reconciled=True, migration_is_current=False)[:3], (None, None, CODE_SUPERSEDED))

    # ---- the AUDIT BODY, read back through groom's OWN parser --------------------------------
    body = audit_body(5001, "orphan-draft", head, 3, 1, "detail")
    parsed = groom.age_receipts([{"user": {"login": bot}, "body": body,
                                  "created_at": "2026-07-30T00:00:00Z"}],
                                groom.AGE_PARK_MARKER, bot)
    check("the audit comment carries EXACTLY ONE park marker, and groom's own receipt reader "
          "parses it as the CORRECTED receipt (same cause and head, supported generation)",
          (body.count(groom.AGE_PARK_MARKER),
           [(r["cause"], r["head"], r["gen"]) for r in parsed]),
          (1, [("orphan-draft", head, 1)]))
    check("the corrected receipt is NOT a grant: it must not advance the generation counter, or "
          "the migration would spend an automatic re-admission the machine never made",
          groom.age_park_generation([{"user": {"login": bot}, "body": body}], bot), 1)
    check("the audit comment self-identifies, quotes the receipt pair that proves the staleness, "
          "carries its own one-shot marker, and claims no re-admission",
          (body.startswith("> 🤖 SPARQ agent"), "gen=3" in body, MIGRATION_MARKER in body,
           "re-enters the ordinary review loop" in body, "Nothing here **re-admits" in body
           or "**Nothing here re-admits this PR**" in body),
          (True, True, True, False, True))
    check("the audit comment carries no deny-prose of its own — a correction that disqualified "
          "the PR from every later re-classification would be a hold in itself",
          [denied for pattern, denied in park_policy.LEGACY_PARK_DENY_PROSE
           if pattern.search(body)], [])
    check("the one-shot marker is trusted ONLY from the bot's own comments, and a malformed "
          "comment entry is skipped rather than crashing the read",
          (migration_record([{"user": {"login": bot}, "body": f"x {MIGRATION_MARKER} pr=1 -->"}],
                            bot) is not None,
           migration_record([{"user": {"login": "drive-by"},
                              "body": f"x {MIGRATION_MARKER} pr=1 -->"}], bot) is not None,
           migration_record(["not a comment", None,
                             {"user": {"login": bot}, "body": f"{MIGRATION_MARKER} -->"}],
                            bot) is not None),
          (True, False, True))

    # The entry point refuses to run at all without the two arguments that bound it to a repo:
    # a default here would point the migration at whatever `gh` happened to resolve.
    try:
        main([])
        missing_args = "no exit"
    except SystemExit as exc:
        missing_args = f"exit {exc.code}"
    check("`--repo` and `--bot-login` are REQUIRED outside --self-test (no implicit target)",
          missing_args, "exit 2")

    # ---- THE MARQUEE CLAIM, against the EVIDENCE PATH ----------------------------------------
    # The whole point of the migration is that groom.age_unpark_state stops skipping these PRs.
    # Asserting the comment's TEXT would not show that; asserting the CONSUMER does.
    stale_comments = [
        {"user": {"login": bot}, "created_at": "2026-07-29T07:18:01Z",
         "body": f"stale\n{groom.AGE_PARK_MARKER} cause=orphan-draft head={head} gen={gen} -->"}
        for gen in (1, 2, 3)]
    before = groom.age_unpark_state(stale_comments, bot)
    after = groom.age_unpark_state(
        stale_comments + [{"user": {"login": bot}, "created_at": "2026-07-30T00:00:00Z",
                           "body": audit_body(5001, "orphan-draft", head, 3, 1, "d")}], bot)
    check("BEFORE the migration age_unpark_state SKIPS the PR outright (this is the blocker: it "
          "is what makes cause recovery irrelevant), and AFTER it the park is considered again "
          "at the corrected generation with its recovery still unconsumed",
          (before, (after[0] or {}).get("gen"), (after[0] or {}).get("cause"), after[1]),
          ((None, False), 1, "orphan-draft", None))

    # ---- THE ENTRY POINT, driven over a fake gh ----------------------------------------------
    # main() is where a fabricating bug survives: the pure verdict above cannot see a dry run
    # that writes, a removal that is never verified, or an ownership probe that is never wired.
    def _fake_gh(state):
        def gh(argv, token=None, check=True):
            state["calls"].append(list(argv))
            joined = " ".join(argv)
            if argv[:3] == ["api", "-X", "POST"] or argv[:3] == ["api", "-X", "DELETE"]:
                state["writes"].append(list(argv))
                if argv[:3] == ["api", "-X", "DELETE"] and not state.get("delete_fails"):
                    # .get, not [] — a malformed fixture entry must reach the code under test,
                    # not raise inside this harness. It did, and the malformed-payload row below
                    # passed on the harness's own KeyError while its guard was deleted.
                    state["labels"] = [label for label in state["labels"]
                                       if label.get("name") != park_policy.HUMAN_PARK_LABEL]
                return type("R", (), {"stdout": "{}", "stderr": "", "returncode": 0})()
            if "issues?state=open" in joined:
                payload = [[{"number": number, "labels": state["labels"],
                             "pull_request": {"url": f"https://api.github.com/x/pulls/{number}"}}
                            for number in state["numbers"]]]
            elif "/comments" in joined:
                payload = (state["comments"] if state.get("raw_comments")
                           else [state["comments"]])
            elif "/timeline" in joined:
                payload = [state["timeline"]]
            elif "/labels" in joined:
                payload = [state["labels"]]
            elif "/permission" in joined:
                # A `gh api` non-2xx exits non-zero, which the real _gh turns into a RuntimeError.
                if state.get("permission") is None:
                    raise RuntimeError("gh api repos/.../permission failed: HTTP 404")
                payload = ({"permission": state["permission"]}
                           if state["permission"] != "MALFORMED" else ["not", "an", "object"])
            else:
                raise AssertionError(f"unexpected gh call: {joined}")
            return type("R", (), {"stdout": json.dumps(payload), "stderr": "",
                                  "returncode": 0})()
        return gh

    def run(argv, actor_login=bot, delete_fails=False, comments=None, permission="admin",
            labels=None, numbers=(5001,), raw_comments=False, ownership_raises=False):
        state = {
            "calls": [], "writes": [], "delete_fails": delete_fails, "permission": permission,
            "numbers": list(numbers), "raw_comments": raw_comments,
            "labels": labels if labels is not None else [
                {"name": park_policy.HUMAN_PARK_LABEL},
                {"name": park_policy.MACHINE_PARK_PR_LABEL}],
            "comments": comments if comments is not None else stale_comments,
            "timeline": [
                {"event": "labeled", "label": {"name": park_policy.MACHINE_PARK_PR_LABEL},
                 "created_at": "2026-07-29T07:18:01Z", "actor": {"login": bot}},
                {"event": "labeled", "label": {"name": park_policy.HUMAN_PARK_LABEL},
                 "created_at": "2026-07-29T10:49:22Z", "actor": {"login": actor_login}}],
        }
        real, out = _gh, io.StringIO()
        real_owner = park_policy.label_application_machine_owned
        globals()["_gh"] = _fake_gh(state)
        if ownership_raises:
            def _raise(*_a, **_k):
                raise TypeError("timeline shape defeated the ownership walk")
            park_policy.label_application_machine_owned = _raise
        try:
            with contextlib.redirect_stdout(out):
                rc = main(argv + ["--repo", "owner/repo", "--bot-login", bot])
        finally:
            globals()["_gh"] = real
            park_policy.label_application_machine_owned = real_owner
        return rc, out.getvalue(), state

    _rc, dry_log, dry = run([])
    check("the DRY RUN is the measurement and mutates NOTHING: it names the population, the "
          "disposition and the corrected generation, and issues no write call at all",
          (dry["writes"], "MIGRATE [stale-receipt]" in dry_log,
           "1 migrated, 0 refused" in dry_log, f"{CODE_UNVERIFIED}=0" in dry_log),
          ([], True, True, True))

    _rc, apply_log, applied = run(["--apply"])
    posted = [call[-1] for call in applied["writes"] if call[:3] == ["api", "-X", "POST"]]
    deleted = [call[-1] for call in applied["writes"] if call[:3] == ["api", "-X", "DELETE"]]
    kinds = [call[2] for call in applied["writes"]]
    check("--apply posts the corrected receipt FIRST and then removes exactly the ONE "
          "human-owned label, by its URL-encoded name",
          (len(posted), len(deleted), kinds,
           all(url.endswith("/labels/needs%3Auser") for url in deleted),
           any(f"{groom.AGE_PARK_MARKER} cause=orphan-draft head={head} gen=1 -->" in body
               for body in posted)),
          (1, 1, ["POST", "DELETE"], True, True))
    check("--apply reports what it PROVED moved, and the read-back is what proves it",
          ("verified gone" in apply_log, "1 migrated, 0 refused" in apply_log), (True, True))

    # A DELETE that reports success while the label survives must NOT be counted as a move.
    _rc, stuck_log, _s = run(["--apply"], delete_fails=True)
    check("a removal the read-back cannot prove is REFUSED, not reported as a migration (a 2xx "
          "is not the same fact as the label being gone)",
          (f"REFUSED [{CODE_UNVERIFIED}]" in stuck_log, "0 migrated, 1 refused" in stuck_log,
           f"{CODE_UNVERIFIED}=1" in stuck_log),
          (True, True, True))

    # The ownership probe must be WIRED, not merely present: a human-applied hold reaching main()
    # has to refuse before any write.
    _rc, human_log, human = run(["--apply"], actor_login="jeswr")
    check("a hold whose newest application is a PROVEN human refuses inside main() with NO "
          "write — the ownership probe is wired to the real timeline",
          (human["writes"], f"REFUSED [{CODE_HUMAN_APPLIED}]" in human_log), ([], True))
    # THE MAINTAINER PROBE'S OWN THREE DIRECTIONS, on a login that is NOT the --maintainer handle
    # (so the handle short-circuit cannot answer for it). The measured population is 15/15 `Bot`,
    # so the whole live question is what happens to the OTHER actor kinds — and the one that must
    # not be got wrong is the unreadable one.
    def _probe_run(permission):
        _rc, log, state = run(["--apply"], actor_login="drive-by", permission=permission)
        return (f"REFUSED [{CODE_HUMAN_APPLIED}]" in log, state["writes"] == [])

    check("a collaborator-permission read that FAILS — or returns a shape this cannot read — "
          "counts the actor as HUMAN and the hold stands (inverted from groom's veto probe on "
          "purpose: there an unverifiable actor must not MINT a veto, here the same answer would "
          "authorise removing the human terminal)",
          (_probe_run(None), _probe_run("MALFORMED"), _probe_run("admin"), _probe_run("read")),
          ((True, True), (True, True), (True, True), (False, False)))

    # The ownership walk absorbs its own read and shape failures, so this handler is the last
    # resort — and the one that would silently authorise a removal if it were ever reached with a
    # permissive default instead of a refusal.
    _rc, raise_log, raised = run(["--apply"], ownership_raises=True)
    check("an ownership probe that RAISES refuses the PR and writes nothing",
          (raised["writes"], f"REFUSED [{CODE_HUMAN_APPLIED}]" in raise_log,
           "ownership probe failed" in raise_log),
          ([], True, True))

    # A payload this cannot parse is a read failure, not an empty history: a comments page read
    # as empty would report ZERO grants and ZERO receipts on a PR that has both.
    check("a malformed comments payload — at the page level or the envelope level — refuses "
          "the PR rather than reading it as a PR with no receipts at all",
          [(run(["--apply"], comments={"oops": True}, raw_comments=raw)[1].count(
              f"REFUSED [{CODE_READ_FAILED}]"),
            run(["--apply"], comments={"oops": True}, raw_comments=raw)[2]["writes"])
           for raw in (False, True)],
          [(1, []), (1, [])])

    # --limit is tested by its VALUE, not its presence: `--limit 1` over a two-PR population must
    # write one PR and DEFER the second, not cap at some other number or ignore the flag.
    _rc, limit_log, limited = run(["--apply", "--limit", "1"], numbers=(5001, 5002))
    check("--limit caps the run at the number it names and DEFERS the rest (the flag's value is "
          "what is asserted, and the deferral is named) — and the residual line SEES the PR that "
          "never reached a verdict, which a total summed from the outcome lists cannot",
          (len([c for c in limited["writes"] if c[:3] == ["api", "-X", "POST"]]),
           "#5002: deferred — --limit 1 reached this run" in limit_log,
           "1 migrated, 0 refused" in limit_log,
           "population=2 migrated=1 refused=0 not-reached=1" in limit_log,
           "population=1 migrated=1 refused=0 not-reached=0" in apply_log),
          (1, True, True, True, True))

    # A read-back this cannot PARSE is not a read-back that shows the hold gone.
    _rc, malformed_log, _m = run(
        ["--apply"], labels=[{"name": park_policy.HUMAN_PARK_LABEL},
                             {"name": park_policy.MACHINE_PARK_PR_LABEL}, {"colour": "red"}])
    check("a MALFORMED label payload refuses rather than reading 'I cannot tell' as 'the hold is "
          "gone' — the migration is only ever credited with a removal it can prove",
          (f"REFUSED [{CODE_READ_FAILED}]" in malformed_log, "0 migrated" in malformed_log),
          (True, True))

    # And the one-shot: a second --apply run over a PR already carrying the marker (hold gone)
    # must be a no-op.
    done_comments = stale_comments + [
        {"user": {"login": bot}, "created_at": "2026-07-30T00:00:00Z",
         "body": audit_body(5001, "orphan-draft", head, 3, 1, "d")}]
    _rc, again_log, again = run(["--apply"], comments=done_comments)
    check("the migration is ONE-SHOT on the receipt side: a re-run over a PR whose hold is still "
          "live CONVERGES (removal only, no second receipt)",
          (len([c for c in again["writes"] if c[:3] == ["api", "-X", "POST"]]),
           len([c for c in again["writes"] if c[:3] == ["api", "-X", "DELETE"]]),
           "CONVERGE [converge]" in again_log),
          (0, 1, True))

    print(f"reconcile-age-park-escalation self-test ({checks} checks) "
          + ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
