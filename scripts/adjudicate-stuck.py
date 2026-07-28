#!/usr/bin/env python3
"""[registry #446] The STUCK-ESCALATION AUTO-ADJUDICATOR: a bounded sweep that drains PRs held in
the HUMAN terminal (`review:needs-user`) for a MACHINE reason, and gives every park it does NOT
drain a machine-readable reason.

THE STALL. Measured 2026-07-19: 36 open PRs (19 sparq + 17 registry) terminally parked on
`review:needs-user`, and nothing auto-resolved any of them. The review loop parks there on
round-budget exhaustion and on parks that recorded no cause at all, both of which are MACHINE
outcomes; `review:needs-user` is HUMAN-owned (park_policy invariant 3), so the only exit was the
maintainer. The active review set drained and merges stopped.

WHAT "ADJUDICATION" IS HERE, AND WHERE IT IS NOT. The adjudication that decides whether such a PR
is actually good is a CROSS-PROVIDER, ORCHESTRATOR-TIER READ OF THE DIFF — and the review lane
already is exactly that: review-fix.yml picks the OPPOSITE provider from the implementer at the
orchestrator tier, reads the diff plus the prior round's recorded verdict, grades progress, and
routes its result through the existing arm gate (trust surfaces human-arm, security surfaces never
auto-arm). So this sweep does NOT run a second judge and does NOT decide correctness. It decides
the ONE question the review lane cannot ask for itself, because a human-owned label is in the way:

    may this PR re-enter the loop at all, and with what budget?

  * `return-to-loop` — nothing human owns this hold and the park cause is machine-owned. The PR
    returns to `review:needs` with a REAL budget window, and the cross-provider re-review that
    buys is the adjudication. If that review approves, the EXISTING arm gate arms it — that is the
    "override-arm" outcome, reached through the gate rather than around it.
  * `genuinely-human` — anything else. The PR stays exactly where it is and gains a durable,
    machine-readable reason marker, so "36 parked PRs" stops being an undifferentiated pile.

THERE IS DELIBERATELY NO THIRD DISPOSITION. This sweep cannot arm, cannot label `review:pass`,
cannot touch a test, a gate, or a verdict. A second authority that could arm a PR by declaring a
reviewer's finding spurious IS the "weaken a trust check to arm" failure the issue's own guardrail
forbids, and it would be strictly weaker than the gate it bypassed. `_self_test` asserts the
disposition set stays closed at two.

FAIL-CLOSED, AND BOUNDED. `admission` is PURE and refuses on every ambiguity — an unreadable
timeline, a park-reason marker that failed validation, a `needs:*` hold that would survive the
move, a trust surface with a live blocking finding. Re-admissions are counted with the SAME
counter that bounds automatic re-admission everywhere else
(worker-pr.auto_readmission_marker_count against park_policy.AUTO_READMISSION_MAX), so the two can
never drift and this can never become a treadmill: past the cap the PR stays human, permanently.
Because the granted window is a MACHINE window, registry #797's window-authority attribution
charges it to the MACHINE ladder — a PR that fails its adjudicated round lands on the machine
terminal (retire, hand the issue back for decomposition), never back in the maintainer's inbox.

DRY-RUN IS THE DEFAULT. `--apply` is required to write anything.
"""
import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import park_policy

ADJUDICATION_MARKER = "<!-- sparq-adjudication:v1"

# THE CLOSED DISPOSITION SET. Two members, and the reason a third is absent is in the module
# docstring. Every consumer may assume this set never grows to include an arming action.
RETURN_TO_LOOP = "return-to-loop"
GENUINELY_HUMAN = "genuinely-human"
DISPOSITIONS = (RETURN_TO_LOOP, GENUINELY_HUMAN)

# The label that re-enters the review lane. `review:needs` is dispatch-claim's authoritative
# re-entry signal for a FRESH cross-provider review round (enumerate_review_items), which is what
# an adjudication needs — not `review:changes`, which dispatches a FIX seeded from a recorded
# verdict that the park has already proven inconclusive.
REENTRY_LABEL = "review:needs"

# THE CLOSED REASON TAXONOMY: code -> (disposition, sentence). A code outside it is never written
# and never read as a decision — `adjudication_marker` raises and `parse_adjudication` drops the
# marker, the same doctrine park_policy.parse_park_reason applies to a park cause.
ADJUDICATION_REASONS = {
    # --- machine-owned parks: the population this sweep exists to drain --------------------
    "budget-park": (RETURN_TO_LOOP,
                    "the park records a CAPACITY-class cause (a spent round budget or another "
                    "machine outcome), which is not a maintainer question"),
    "silent-park": (RETURN_TO_LOOP,
                    "the park recorded NO cause at all — a silent escalation, which cannot be a "
                    "human decision because no decision was written down"),
    # --- genuine human questions, and every ambiguity ---------------------------------------
    "not-parked": (GENUINELY_HUMAN, "no live `review:needs-user` — nothing to adjudicate"),
    "deny-prose": (GENUINELY_HUMAN,
                   "an injection or human-arm signal is recorded on this PR; no machine path may "
                   "ever re-admit those causes, at any position in the history"),
    "human-applied": (GENUINELY_HUMAN,
                      "a PROVEN human applied the hold — a human decision is not the machine's "
                      "to undo (and an unreadable timeline counts as human)"),
    "question-cause": (GENUINELY_HUMAN,
                       "the park records a QUESTION-class cause, which by taxonomy has no "
                       "machine exit"),
    "unclassified-park": (GENUINELY_HUMAN,
                          "a park-reason marker is present but failed validation, so the park is "
                          "unclassified — every consumer reads that as a human question"),
    "residual-hold": (GENUINELY_HUMAN,
                      "a human-owned hold would still be live after the move, so re-admitting "
                      "would trade a visible stall for a silent one"),
    "machine-park-live": (GENUINELY_HUMAN,
                          "a MACHINE park is also live on this PR or its source issue "
                          "(`review:parked` / `status:parked`), and the review lane excludes any "
                          "parked PR outright; whichever mechanism applied that park owns its "
                          "exit, so re-admitting here would be a silent no-op relabel that also "
                          "raced another sweep"),
    "issue-hold-human": (GENUINELY_HUMAN,
                         "the source issue's `needs:user` is human-owned or unprovable; the "
                         "review lane excludes any PR whose issue carries a `needs:*` hold, so "
                         "re-admitting the PR alone would be a no-op relabel"),
    "readmissions-spent": (GENUINELY_HUMAN,
                           "this PR has already spent every automatic re-admission "
                           "`AUTO_READMISSION_MAX` allows; more machine retries is not an answer"),
    "no-round-history": (GENUINELY_HUMAN,
                         "no review round was ever recorded, so this is not a round-budget or "
                         "silent park — something else put it here and that something is unread"),
    "trust-surface-finding": (GENUINELY_HUMAN,
                              "this is a ZK/MPC/security/trust surface and its last verdict "
                              "carries (or may carry) a blocking finding — those default to the "
                              "maintainer unless the standoff is provably not substantive"),
}

BLOCKING_SEVERITIES = frozenset({"blocker", "critical", "major"})

_ADJUDICATION_RE = re.compile(
    re.escape(ADJUDICATION_MARKER)
    + r" disposition=(\S+) reason=(\S+) head=(\S+) episode=(\S+) -->")


def _load(modname, filename):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _quiet(*_args, **_kwargs):
    return None


def admission(*, pr_labels, issue_labels, park_records, park_marker_present, bot_bodies,
              hold_applied_by_human, issue_hold_machine_owned, rounds_recorded,
              readmissions_spent, trust_surface, blocking_findings):
    """PURE. (disposition, reason, detail) — may this PR re-enter the review loop?

    `disposition` is a member of DISPOSITIONS and `reason` is a key of ADJUDICATION_REASONS whose
    registered disposition equals it; every branch below is one of those keys, so the marker
    writer can never be handed a code it must reject.

    Every refusal is a REFUSAL CONDITION: anything unproven leaves the PR exactly where it is.
    The caller MUST fail closed on each probe it cannot complete — `hold_applied_by_human=True`
    when the timeline is unreadable, `issue_hold_machine_owned=False` when the issue's label
    ownership is unprovable, `trust_surface=True` when the keyword union cannot be loaded, and
    `blocking_findings=None` when the last verdict record cannot be read.

    `park_records` is park_policy.park_reason_records output (oldest first, bot-authored only);
    `park_marker_present` is whether the BOT's history contains a raw PARK_REASON_MARKER at all,
    which is what separates a SILENT park (no marker — drainable) from a park whose marker was
    REJECTED by validation (unclassified — a human question). Reading only the parsed records
    would collapse those two into one and drain the dangerous half.

    `blocking_findings` is the count of blocker/critical/major findings in the LATEST recorded
    verdict, or None when that record is unreadable. It gates ONLY the trust-surface guardrail: a
    non-trust PR with real findings is precisely the "real but fixable" case that belongs back in
    the loop."""
    def out(reason, extra=""):
        disposition, sentence = ADJUDICATION_REASONS[reason]
        return (disposition, reason, f"{sentence}{extra}")

    if park_policy.HUMAN_PR_PARK_LABEL not in set(pr_labels or []):
        return out("not-parked")
    # DENY FIRST, unconditionally and order-independently (park_policy.LEGACY_PARK_DENY_PROSE):
    # a capacity comment landing after a security escalation must never talk a park out of the
    # terminal, whichever order the two were written in.
    for body in bot_bodies or []:
        for pattern, denied in park_policy.LEGACY_PARK_DENY_PROSE:
            if pattern.search(str(body)):
                return out("deny-prose", f" (signal: {denied})")
    if hold_applied_by_human:
        return out("human-applied")
    records = [record for record in (park_records or []) if isinstance(record, dict)]
    if records:
        latest = records[-1]
        cause = str(latest.get("cause", ""))
        # Trust the CLASS the taxonomy assigns the cause, never the class the marker claims —
        # parse_park_reason has already rejected any marker where the two disagree, so a record
        # reaching here is self-consistent, and re-deriving keeps it that way if that changes.
        if park_policy.park_cause_class(cause) != park_policy.PARK_CLASS_CAPACITY:
            return out("question-cause", f" (cause: {cause or 'unknown'})")
        machine_reason = "budget-park"
        machine_extra = f" (cause: {cause})"
    elif park_marker_present:
        return out("unclassified-park")
    else:
        machine_reason = "silent-park"
        machine_extra = ""
    residual = park_policy.migration_residual_holds(
        set(pr_labels or []) - {park_policy.HUMAN_PR_PARK_LABEL}, set(issue_labels or []),
        clearing=[park_policy.HUMAN_PARK_LABEL])
    if residual:
        return out("residual-hold", f" ({'/'.join(residual)})")
    # A re-admission that the review lane will not act on is worse than no re-admission: it
    # reads as "drained" in every count while the PR stays exactly as stuck. dispatch-claim's
    # enumerate_review_items excludes a PR outright when EITHER machine park label is live, so
    # this sweep must not move a PR that is also machine-parked — that park has its own owner and
    # its own exit (capacity_park_admission / the cause-gated sweeps), and racing them is how two
    # mechanisms end up half-clearing one park.
    machine_parks = ({park_policy.MACHINE_PARK_PR_LABEL} & set(pr_labels or [])) | \
                    ({park_policy.MACHINE_PARK_LABEL} & set(issue_labels or []))
    if machine_parks:
        return out("machine-park-live", f" ({'/'.join(sorted(machine_parks))})")
    if park_policy.HUMAN_PARK_LABEL in set(issue_labels or []) and not issue_hold_machine_owned:
        return out("issue-hold-human")
    if not isinstance(readmissions_spent, int) or isinstance(readmissions_spent, bool) \
            or readmissions_spent >= park_policy.AUTO_READMISSION_MAX:
        return out("readmissions-spent",
                   f" ({readmissions_spent} of {park_policy.AUTO_READMISSION_MAX} spent)")
    if not isinstance(rounds_recorded, int) or isinstance(rounds_recorded, bool) \
            or rounds_recorded < 1:
        return out("no-round-history")
    # THE TRUST-SURFACE DEFAULT (issue #446 guardrail). `!= 0` and not `> 0`: an unreadable
    # verdict record arrives as None and must block, exactly like a real blocker would.
    if trust_surface and blocking_findings != 0:
        found = "unreadable" if blocking_findings is None else f"{blocking_findings} finding(s)"
        return out("trust-surface-finding", f" ({found})")
    return out(machine_reason, machine_extra)


def adjudication_marker(disposition, reason, head, episode):
    """The durable, machine-readable record of one adjudication decision.

    Raises on anything outside the closed taxonomy or on a part that could break out of the
    `... key=<value> -->` grammar every receipt reader keys on (park_policy.safe_receipt_part) —
    a marker is only worth reading if it could not have been written wrong."""
    registered = ADJUDICATION_REASONS.get(reason)
    if registered is None:
        raise ValueError(f"adjudication reason {reason!r} is outside the closed taxonomy")
    if registered[0] != disposition:
        raise ValueError(f"reason {reason!r} belongs to disposition {registered[0]!r}, "
                         f"not {disposition!r}")
    for part in (str(head), str(episode)):
        if not park_policy.safe_receipt_part(part):
            raise ValueError("adjudication marker parts must be safe receipt parts")
    return (f"{ADJUDICATION_MARKER} disposition={disposition} reason={reason} "
            f"head={head} episode={episode} -->")


def parse_adjudication(body):
    """The LAST well-formed adjudication marker in `body`, else None. A marker whose disposition
    disagrees with its reason's registered disposition is DROPPED, not repaired: the dangerous
    direction is obvious, and a self-contradicting receipt is evidence of corruption or forgery."""
    if not isinstance(body, str):
        return None
    found = None
    for match in _ADJUDICATION_RE.finditer(body):
        disposition, reason, head, episode = match.groups()
        registered = ADJUDICATION_REASONS.get(reason)
        if registered is None or registered[0] != disposition:
            continue
        found = {"disposition": disposition, "reason": reason,
                 "head": head, "episode": episode}
    return found


def adjudication_records(comments, bot_login):
    """Every well-formed adjudication marker across the BOT's OWN comments, oldest first. Only
    the orchestration bot's comments are receipts — a third party must not be able to fake a
    prior decision, nor to suppress one by posting a corrupt copy."""
    if not bot_login:
        return []
    records = []
    for comment in comments if isinstance(comments, list) else []:
        if not isinstance(comment, dict):
            continue
        if str((comment.get("user") or {}).get("login", "")).casefold() \
                != str(bot_login).casefold():
            continue
        record = parse_adjudication(str(comment.get("body", "")))
        if record:
            records.append(record)
    return records


def already_recorded(comments, bot_login, disposition, head):
    """True when THIS head already carries THIS disposition from a previous sweep. Idempotence,
    per head rather than per PR: a genuinely-human park is explained ONCE (no comment spam every
    15 minutes), and a head that has moved since is a new fact worth re-recording."""
    return any(record["disposition"] == disposition and record["head"] == str(head)
               for record in adjudication_records(comments, bot_login))


def blocking_finding_count(record):
    """Blocker/critical/major findings in a recorded review verdict, or None when the record is
    not readable as one. None means UNKNOWN and every consumer must treat it as blocking — a
    verdict we cannot read is not a verdict with no findings."""
    if not isinstance(record, dict):
        return None
    issues = record.get("issues")
    if not isinstance(issues, list):
        return None
    count = 0
    for issue in issues:
        if not isinstance(issue, dict):
            return None
        if str(issue.get("severity", "")).strip().casefold() in BLOCKING_SEVERITIES:
            count += 1
    return count


def latest_verdict(verdict_roots, repo, pr_number):
    """The highest-round recorded verdict for this PR across the ledger/master record roots, or
    None. Host-validated registry records only — the PR's own comments are never read for this."""
    owner, _, name = str(repo).partition("/")
    best = None
    pattern = re.compile(rf"^{re.escape(owner)}--{re.escape(name)}--pr{int(pr_number)}"
                         r"-round([1-9][0-9]*)\.json$")
    for root in verdict_roots:
        directory = Path(root)
        if not directory.is_dir():
            continue
        for path in directory.iterdir():
            match = pattern.match(path.name)
            if not match:
                continue
            round_n = int(match.group(1))
            if best is None or round_n > best[0]:
                best = (round_n, path)
    if best is None:
        return (None, None)
    try:
        return (best[0], json.loads(best[1].read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return (best[0], None)


def target_matrix(targets):
    """PURE. The Actions matrix this sweep fans out over: one entry per ENABLED policy target,
    split into the owner and name a per-repo App-token mint needs so each job holds a token
    scoped to exactly the one repository it sweeps. Raises on a name that is not `owner/repo` —
    a malformed row must fail the plan, never mint a wider token by accident."""
    entries = []
    for target in targets or []:
        owner, slash, name = str(target).partition("/")
        if not (owner and slash and name) or "/" in name:
            raise ValueError(f"policy target {target!r} is not an <owner>/<repo> name")
        entries.append({"repo": target, "owner": owner, "name": name})
    return entries


def human_park_body(reason, detail, head, episode):
    """The comment a `genuinely-human` park gains: the machine-readable reason the issue asked
    for, plus the prose that makes it auditable without re-deriving it."""
    return (
        "> 🤖 SPARQ agent — **stuck-escalation adjudication: leaving this park in place** "
        "(registry #446)\n\n"
        f"The auto-adjudicator swept this pull request's `{park_policy.HUMAN_PR_PARK_LABEL}` "
        "hold and is **leaving it exactly as it is**. No label, comment, verdict, or budget on "
        "this PR was changed by that decision — this comment is the only thing it wrote.\n\n"
        f"**Why it was not drained:** {detail}.\n\n"
        "The sweep re-admits a park only when it can prove nothing human owns it, that its cause "
        "is machine-owned, and that re-admitting would actually put the PR back in front of a "
        "reviewer. It cannot prove all three here, so it stops — and records WHY, so this park "
        "is now distinguishable from the rest of the parked population instead of being one more "
        "undifferentiated entry in it.\n\n"
        f"{adjudication_marker(GENUINELY_HUMAN, reason, head, episode)}")


def readmission_body(receipt, reason, detail, head, episode):
    """The comment a `return-to-loop` re-admission posts, RECEIPT FIRST: `receipt` is
    worker-pr.auto_readmission_receipt under the `adjudication/` evidence namespace (the budget
    window itself, in the one format every budget consumer already reads), and this appends the
    adjudication's own machine-readable decision. One comment, two markers, two readers — and a
    crash after it leaves an EXPLAINED PR whose window is already durable, rather than a silently
    relabelled one."""
    return (
        f"{receipt}\n\n"
        f"**Why this park was machine-owned:** {detail}.\n\n"
        f"**What happens next:** the hold moves to `{REENTRY_LABEL}` and the loop runs one "
        "cross-provider, orchestrator-tier review round against the current head. That review — "
        "not this sweep — decides the outcome, and its approval routes through the unchanged arm "
        "gate (a trust surface still human-arms; a security surface still never auto-arms). If "
        "it does not converge, the window this receipt opened is a MACHINE window, so the "
        "escalation ladder charges the MACHINE terminal (registry #797): the PR retires and the "
        "source issue is handed back for decomposition. It does not come back to you.\n\n"
        "A human can hold this PR again at any time by re-applying the label — that gesture is "
        "sticky and no automation may override it.\n\n"
        f"{adjudication_marker(RETURN_TO_LOOP, reason, head, episode)}")


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


def _label_names(container):
    return [label.get("name") for label in (container.get("labels") or [])
            if isinstance(label, dict) and isinstance(label.get("name"), str)]


def _sweep(args, worker_pr, policy_resolve):
    """One sweep over the target's live `review:needs-user` PRs."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # FAIL CLOSED on the trust-surface keyword union: policy-resolve raises rather than return a
    # reduced set, and a set we could not load must classify EVERY PR as a trust surface.
    keywords, keyword_error = (), None
    try:
        keywords = tuple(policy_resolve.routing_security_keywords(
            args.repo, policy_file=args.policy_file, target_root=args.target_root))
    except Exception as exc:  # noqa: BLE001 — any failure means "assume trust surface"
        keyword_error = str(exc)[:160]
        print(f"::warning::trust-surface keywords unavailable ({keyword_error}); every PR in "
              "this sweep is classified as a trust surface")

    held = _gh_json(["api", f"repos/{args.repo}/issues?state=open"
                     f"&labels={urllib.parse.quote(park_policy.HUMAN_PR_PARK_LABEL)}"
                     "&per_page=100", "--paginate", "--slurp"], token=args.token)
    rows = [row for page in (held if isinstance(held, list) else []) if isinstance(page, list)
            for row in page if isinstance(row, dict) and row.get("pull_request")]
    print(f"{len(rows)} open PR(s) on {park_policy.HUMAN_PR_PARK_LABEL} in {args.repo}")
    readmitted, explained, skipped = [], [], []
    for row in sorted(rows, key=lambda row: row.get("number") or 0):
        number = row["number"]
        try:
            comments = _paginated(args.repo, number, "comments", token=args.token)
            timeline = _paginated(args.repo, number, "timeline", token=args.token)
            bot_bodies = [str(comment.get("body", ""))
                          for comment in comments if isinstance(comment, dict)
                          and str((comment.get("user") or {}).get("login", "")).casefold()
                          == args.bot_login.casefold()]
            is_human = (lambda login: login.casefold() == args.maintainer.casefold())
            # FAIL CLOSED: anything we cannot read counts as "a human applied it".
            applied_by_human = True
            try:
                applied_by_human = not park_policy.label_application_machine_owned(
                    args.repo, number, park_policy.HUMAN_PR_PARK_LABEL,
                    lambda _repo, _num: timeline, is_human=is_human, log=_quiet)
            except Exception as exc:  # noqa: BLE001
                print(f"  #{number}: hold-ownership probe failed ({exc}) — treated as human")

            pull = _gh_json(["api", f"repos/{args.repo}/pulls/{number}"], token=args.token)
            head_sha = str(((pull or {}).get("head") or {}).get("sha", ""))
            head_match = worker_pr.WORKER_HEAD_RE.fullmatch(
                str(((pull or {}).get("head") or {}).get("ref", "")))
            issue_number = int(head_match.group(1)) if head_match else None
            issue_labels, issue_hold_machine_owned = [], True
            if issue_number:
                issue = _gh_json(["api", f"repos/{args.repo}/issues/{issue_number}"],
                                 token=args.token)
                issue_labels = _label_names(issue if isinstance(issue, dict) else {})
                if park_policy.HUMAN_PARK_LABEL in set(issue_labels):
                    issue_hold_machine_owned = False   # fail closed until proven otherwise
                    try:
                        issue_timeline = _paginated(args.repo, issue_number, "timeline",
                                                    token=args.token)
                        issue_hold_machine_owned = park_policy.label_application_machine_owned(
                            args.repo, issue_number, park_policy.HUMAN_PARK_LABEL,
                            lambda _repo, _num: issue_timeline, is_human=is_human, log=_quiet)
                    except Exception as exc:  # noqa: BLE001
                        print(f"  #{number}: source-issue hold probe failed ({exc})")

            pr_labels = _label_names(row)
            trust_surface = True
            if keyword_error is None:
                trust_surface = worker_pr.security_flagged(
                    set(pr_labels) | set(issue_labels), extra_keywords=keywords)
            round_n, verdict_record = latest_verdict(args.verdict_root, args.repo, number)
            blocking = blocking_finding_count(verdict_record)
            readmissions_spent = worker_pr.auto_readmission_marker_count(comments, args.bot_login)

            disposition, reason, detail = admission(
                pr_labels=pr_labels,
                issue_labels=issue_labels,
                park_records=park_policy.park_reason_records(comments, args.bot_login,
                                                             log=_quiet),
                park_marker_present=any(park_policy.PARK_REASON_MARKER in body
                                        for body in bot_bodies),
                bot_bodies=bot_bodies,
                hold_applied_by_human=applied_by_human,
                issue_hold_machine_owned=issue_hold_machine_owned,
                rounds_recorded=worker_pr.count_rounds(comments, args.bot_login),
                readmissions_spent=readmissions_spent,
                trust_surface=trust_surface,
                blocking_findings=blocking)
            episode = readmissions_spent + 1
            verdict_note = (f"round {round_n} verdict: "
                            f"{'unreadable' if blocking is None else f'{blocking} blocking'}"
                            if round_n else "no recorded verdict")
            print(f"  #{number}: {disposition} [{reason}] — {detail} "
                  f"({verdict_note}; trust_surface={trust_surface})")

            if not park_policy.safe_receipt_part(head_sha):
                print(f"  #{number}: SKIP — head sha is missing or unsafe for a receipt")
                skipped.append((number, "unsafe head sha"))
                continue
            if issue_number is None:
                # Not a worker branch, so dispatch's head-ref gate would exclude it from the
                # review lane anyway: re-admitting it would be a relabel that changes nothing,
                # and there is no source issue whose holds this sweep could even read.
                print(f"  #{number}: SKIP — head is not a worker branch; the review lane could "
                      "not re-enter this PR and there is no source issue to read")
                skipped.append((number, "not a worker branch"))
                continue
            if reason == "not-parked":
                # The label went away between the listing and this read. There is nothing to
                # explain and nothing to drain — never comment a park onto an unparked PR.
                print(f"  #{number}: SKIP — the hold was cleared while this sweep was running")
                skipped.append((number, "hold cleared mid-sweep"))
                continue
            if already_recorded(comments, args.bot_login, disposition, head_sha):
                print(f"  #{number}: already recorded for head {head_sha[:12]} — no-op")
                continue
            if not args.apply:
                (readmitted if disposition == RETURN_TO_LOOP else explained).append(
                    (number, f"dry-run/{reason}"))
                continue
            if args.limit and len(readmitted) + len(explained) >= args.limit:
                print(f"  #{number}: deferred — --limit {args.limit} reached this run")
                break

            if disposition == GENUINELY_HUMAN:
                _gh(["api", "-X", "POST", f"repos/{args.repo}/issues/{number}/comments",
                     "-f", f"body={human_park_body(reason, detail, head_sha, episode)}"],
                    token=args.token)
                explained.append((number, reason))
                continue

            # RECEIPT FIRST. The comment carries the budget window (the auto-readmission receipt)
            # AND the decision, so a crash before the label writes leaves a PR that is explained
            # and window-bearing rather than one that was quietly moved.
            receipt = worker_pr.auto_readmission_receipt(
                f"{worker_pr.AUTO_READMIT_ADJUDICATION_PREFIX}{head_sha[:12]}/{episode}", now)
            _gh(["api", "-X", "POST", f"repos/{args.repo}/issues/{number}/comments",
                 "-f", f"body={readmission_body(receipt, reason, detail, head_sha, episode)}"],
                token=args.token)
            _gh(["api", "-X", "DELETE", f"repos/{args.repo}/issues/{number}/labels/"
                 + urllib.parse.quote(park_policy.HUMAN_PR_PARK_LABEL, safe="")],
                token=args.token)
            _gh(["api", "-X", "POST", f"repos/{args.repo}/issues/{number}/labels",
                 "-f", f"labels[]={REENTRY_LABEL}"], token=args.token)
            # The ISSUE half. `admission` already refused unless this is provably machine-applied,
            # so reaching here means the clear is authorised; without it the review lane would
            # still exclude the PR and the re-admission would be a no-op relabel.
            if issue_number and park_policy.HUMAN_PARK_LABEL in set(issue_labels):
                _gh(["api", "-X", "DELETE",
                     f"repos/{args.repo}/issues/{issue_number}/labels/"
                     + urllib.parse.quote(park_policy.HUMAN_PARK_LABEL, safe="")],
                    token=args.token)
            readmitted.append((number, reason))
        except Exception as exc:  # noqa: BLE001 — one bad PR never stops the sweep
            print(f"  #{number}: SKIP — {exc}")
            skipped.append((number, str(exc)[:120]))
    print(f"\n{'APPLIED' if args.apply else 'DRY RUN'}: {len(readmitted)} re-admitted, "
          f"{len(explained)} explained-and-left, {len(skipped)} skipped")
    for number, reason in readmitted:
        print(f"  re-admitted #{number} ({reason})")
    for number, reason in explained:
        print(f"  left with the maintainer #{number} ({reason})")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--print-matrix", action="store_true",
                        help="print the GITHUB_OUTPUT matrix line over enabled policy targets")
    parser.add_argument("--repo")
    parser.add_argument("--bot-login")
    parser.add_argument("--maintainer", default=os.environ.get("MAINTAINER_HANDLE", "jeswr"))
    parser.add_argument("--token", default=None)
    parser.add_argument("--policy-file", default="policy/repos.toml")
    parser.add_argument("--target-root", default=".",
                        help="checkout root the target's routing pointer resolves against")
    parser.add_argument("--verdict-root", action="append", default=None,
                        help="recorded-verdict directory (repeatable; ledger copy first)")
    parser.add_argument("--apply", action="store_true",
                        help="write. Without it the run is a DRY RUN and mutates nothing.")
    parser.add_argument("--limit", type=int, default=0, help="0 = no cap")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if args.print_matrix:
        grant_account = _load("registry_grant_account", "grant-account.py")
        targets = grant_account.enabled_targets(
            Path(args.policy_file).read_text(encoding="utf-8"))
        print("matrix=" + json.dumps({"include": target_matrix(targets)},
                                     separators=(",", ":")))
        return 0
    if not (args.repo and args.bot_login):
        parser.error("--repo and --bot-login are required outside --self-test")
    if not args.verdict_root:
        args.verdict_root = ["ledger/orchestration/review-verdicts",
                             "orchestration/review-verdicts"]
    return _sweep(args, _load("registry_worker_pr", "worker-pr.py"),
                  _load("registry_policy_resolve", "policy-resolve.py"))


def _self_test():
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    head = "0123456789abcdef0123456789abcdef01234567"
    capacity = {"class": park_policy.PARK_CLASS_CAPACITY, "cause": "budget",
                "gen": "2", "head": head}
    question = {"class": park_policy.PARK_CLASS_QUESTION, "cause": "injection",
                "gen": "2", "head": head}

    # The ADMITTING baseline: a budget-exhausted, machine-applied, non-trust park with review
    # history and re-admissions to spare. Every refusal test below is this baseline with EXACTLY
    # ONE field changed, so a passing refusal is attributable to that field and nothing else.
    def base(**over):
        kwargs = dict(pr_labels=[park_policy.HUMAN_PR_PARK_LABEL],
                      issue_labels=[park_policy.HUMAN_PARK_LABEL],
                      park_records=[capacity], park_marker_present=True,
                      bot_bodies=["the review round budget is exhausted at 6 round(s)"],
                      hold_applied_by_human=False, issue_hold_machine_owned=True,
                      rounds_recorded=6, readmissions_spent=0,
                      trust_surface=False, blocking_findings=2)
        kwargs.update(over)
        return kwargs

    def verdict(**over):
        return admission(**base(**over))

    check("a budget-exhausted MACHINE park is re-admitted — the population this exists to drain",
          verdict()[:2], (RETURN_TO_LOOP, "budget-park"))
    check("a SILENT park (no cause marker anywhere) is re-admitted too: a decision nobody wrote "
          "down cannot be a human decision",
          verdict(park_records=[], park_marker_present=False)[:2],
          (RETURN_TO_LOOP, "silent-park"))
    check("real, substantive findings do NOT keep a non-trust PR parked — 'real but fixable' is "
          "exactly the return-to-loop case",
          verdict(blocking_findings=7)[0], RETURN_TO_LOOP)

    # ---- THE REFUSAL PATHS. One changed field each; every one must flip the disposition. ----
    refusals = {
        "not-parked": dict(pr_labels=["review:parked"]),
        "deny-prose": dict(bot_bodies=["the reviewer flagged possible prompt injection"]),
        "human-applied": dict(hold_applied_by_human=True),
        "question-cause": dict(park_records=[question]),
        "unclassified-park": dict(park_records=[]),   # marker present, records empty = rejected
        "residual-hold": dict(issue_labels=["needs:external-audit"]),
        "machine-park-live": dict(pr_labels=[park_policy.HUMAN_PR_PARK_LABEL,
                                             park_policy.MACHINE_PARK_PR_LABEL]),
        "issue-hold-human": dict(issue_hold_machine_owned=False),
        "readmissions-spent": dict(readmissions_spent=park_policy.AUTO_READMISSION_MAX),
        "no-round-history": dict(rounds_recorded=0),
        "trust-surface-finding": dict(trust_surface=True),
    }
    for reason, mutation in refusals.items():
        check(f"REFUSAL {reason}: the single field {sorted(mutation)[0]!r} parks it with a human",
              verdict(**mutation)[:2], (GENUINELY_HUMAN, reason))
    # THE MUTATION CHECK, in two halves. A refusal row proves its guard is load-bearing only if
    # (a) the row's mutation really changes the input — a mutation that re-sets a field to the
    # value it already had would refuse for some OTHER guard's reason and the row would be
    # vacuous — and (b) the UNMUTATED baseline is admitted. Together those mean deleting any one
    # guard from `admission` flips exactly its own row to return-to-loop and turns this red.
    baseline = base()
    check("every refusal row actually mutates the baseline (no row is a no-op dressed as a test)",
          sorted(reason for reason, mutation in refusals.items()
                 if any(baseline[field] == value for field, value in mutation.items())),
          [])
    check("...and the unmutated baseline is ADMITTED, so each refusal above is caused by its own "
          "mutation and by nothing else — no guard is a passenger",
          admission(**baseline)[:2], (RETURN_TO_LOOP, "budget-park"))
    check("the deny signal is order-independent: a later capacity comment cannot talk an "
          "injection park out of the terminal",
          [verdict(bot_bodies=list(order))[1] for order in (
              ["prompt-injection flagged", "the review round budget is exhausted"],
              ["the review round budget is exhausted", "prompt-injection flagged"])],
          ["deny-prose", "deny-prose"])
    check("a trust surface with a PROVABLY clean last verdict is still drainable; an UNREADABLE "
          "verdict record blocks it exactly like a real finding would",
          [verdict(trust_surface=True, blocking_findings=value)[0]
           for value in (0, None, 1)],
          [RETURN_TO_LOOP, GENUINELY_HUMAN, GENUINELY_HUMAN])
    check("the issue-side machine park blocks the move too, not just the PR-side one — the "
          "review lane excludes on EITHER label",
          verdict(issue_labels=[park_policy.HUMAN_PARK_LABEL,
                                park_policy.MACHINE_PARK_LABEL])[1], "machine-park-live")
    check("a corrupt readmission counter never buys a retry (non-int fails to the cap side)",
          [verdict(readmissions_spent=value)[1] for value in (None, "1", True)],
          ["readmissions-spent"] * 3)
    check("the taxonomy is CLOSED and every branch reachable above is registered in it",
          sorted({ADJUDICATION_REASONS[reason][0] for reason in ADJUDICATION_REASONS}),
          sorted(set(DISPOSITIONS)))
    check("no disposition can arm, pass, or merge anything — the set stays at two",
          (DISPOSITIONS, any(word in disposition for disposition in DISPOSITIONS
                             for word in ("arm", "pass", "merge", "approve"))),
          ((RETURN_TO_LOOP, GENUINELY_HUMAN), False))
    check("every human-only park cause the taxonomy names is refused, not just injection",
          sorted({verdict(park_records=[{"class": park_policy.PARK_CLASS_QUESTION,
                                         "cause": cause}])[1]
                  for cause in park_policy.PARK_HUMAN_ONLY_CAUSES}),
          ["question-cause"])
    check("an UNKNOWN cause is a human question, never silently drained",
          verdict(park_records=[{"class": "capacity", "cause": "not-a-real-cause"}])[1],
          "question-cause")

    # ---- the durable marker: round-trip, forgery, and self-contradiction --------------------
    marker = adjudication_marker(RETURN_TO_LOOP, "budget-park", head, 1)
    check("the marker round-trips through its own reader",
          parse_adjudication(f"prose\n\n{marker}"),
          {"disposition": RETURN_TO_LOOP, "reason": "budget-park",
           "head": head, "episode": "1"})
    check("a marker whose disposition contradicts its reason is DROPPED, never repaired",
          parse_adjudication(f"{ADJUDICATION_MARKER} disposition={RETURN_TO_LOOP} "
                             f"reason=human-applied head={head} episode=1 -->"), None)
    check("a marker naming a reason outside the taxonomy is dropped too",
          parse_adjudication(f"{ADJUDICATION_MARKER} disposition={GENUINELY_HUMAN} "
                             f"reason=made-up head={head} episode=1 -->"), None)
    bad = []
    for label, call in (("unknown reason", lambda: adjudication_marker(
                            RETURN_TO_LOOP, "made-up", head, 1)),
                        ("mismatched disposition", lambda: adjudication_marker(
                            RETURN_TO_LOOP, "human-applied", head, 1)),
                        ("unsafe head", lambda: adjudication_marker(
                            RETURN_TO_LOOP, "budget-park", "a b --> c", 1))):
        try:
            call()
        except ValueError:
            continue
        bad.append(label)
    check("the writer REFUSES an unknown reason, a mismatched disposition, and an unsafe part "
          "(a marker is only worth reading if it could not be written wrong)", bad, [])
    bot = "sparq-orchestrator[bot]"
    check("markers are trusted ONLY from the bot's own comments",
          (len(adjudication_records([{"user": {"login": bot}, "body": marker}], bot)),
           len(adjudication_records([{"user": {"login": "drive-by"}, "body": marker}], bot))),
          (1, 0))
    check("idempotence is keyed on (disposition, head): the same head is never re-commented, a "
          "moved head is a new fact",
          (already_recorded([{"user": {"login": bot}, "body": marker}], bot,
                            RETURN_TO_LOOP, head),
           already_recorded([{"user": {"login": bot}, "body": marker}], bot,
                            GENUINELY_HUMAN, head),
           already_recorded([{"user": {"login": bot}, "body": marker}], bot,
                            RETURN_TO_LOOP, "f" * 40)),
          (True, False, False))

    # ---- the recorded-verdict reader: UNKNOWN is never zero ---------------------------------
    check("blocking findings are counted by severity, and an unreadable record is None (never 0)",
          [blocking_finding_count(record) for record in (
              {"issues": [{"severity": "major"}, {"severity": "minor"},
                          {"severity": "blocker"}]},
              {"issues": []}, {"issues": "nope"}, {}, None, {"issues": ["nope"]})],
          [2, 0, None, None, None, None])

    # ---- the comment bodies -----------------------------------------------------------------
    human_body = human_park_body("trust-surface-finding",
                                 ADJUDICATION_REASONS["trust-surface-finding"][1], head, 1)
    check("the genuinely-human comment self-identifies, states that nothing was changed, and "
          "carries its own machine-readable reason",
          (human_body.startswith("> 🤖 SPARQ agent"),
           "leaving it exactly as it is" in human_body,
           parse_adjudication(human_body)["reason"]),
          (True, True, "trust-surface-finding"))
    loop_body = readmission_body("RECEIPT-TEXT", "budget-park",
                                 ADJUDICATION_REASONS["budget-park"][1], head, 1)
    check("the re-admission comment leads with the budget RECEIPT, names the re-entry label, "
          "disclaims any arm authority, and says the machine terminal — not the maintainer — "
          "catches a failed adjudication",
          (loop_body.startswith("RECEIPT-TEXT"), REENTRY_LABEL in loop_body,
           "not this sweep — decides the outcome" in loop_body,
           "It does not come back to you." in loop_body,
           parse_adjudication(loop_body)["disposition"]),
          (True, True, True, True, RETURN_TO_LOOP))
    check("neither comment claims the PR is correct, ready, approved, or armed",
          sorted({word for body in (human_body, loop_body)
                  for word in ("is correct", "is ready", "approved", "armed")
                  if word in body}), [])

    # ---- the fan-out plan: least-privilege token scoping is a property of this split ---------
    check("the matrix splits each enabled target into the owner+name its own mint needs",
          target_matrix(["sparq-org/sparq", "jeswr/agent-account-registry"]),
          [{"repo": "sparq-org/sparq", "owner": "sparq-org", "name": "sparq"},
           {"repo": "jeswr/agent-account-registry", "owner": "jeswr",
            "name": "agent-account-registry"}])
    bad_targets = []
    for target in ("noslash", "owner/", "/name", "owner/extra/name", ""):
        try:
            target_matrix([target])
        except ValueError:
            continue
        bad_targets.append(target)
    check("a malformed policy target FAILS the plan rather than minting a wider-scoped token",
          bad_targets, [])

    print("adjudicate-stuck self-test " + ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
