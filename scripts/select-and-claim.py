#!/usr/bin/env python3
# Lease allocator (review C3): a correct, cross-codebase worker-slot lease over a
# compare-and-swap ledger — replaces the reaction "mutex" (which cannot count concurrent same-identity
# claims). Pure allocation logic is unit-tested; GitHub CAS I/O wraps it.
"""select-and-claim — allocate a model-account worker slot as a LEASE.

The ledger is a single JSON file `data/leases.json` in this registry:
    {"leases": [{"account","claim_id","holder","package","role","model","issued_at","expires_at"}, ...]}

``account`` is the canonical salted 16-hex fingerprint, never the catalog handle.

Claiming is a compare-and-swap: read the file + its blob SHA, reclaim expired leases, if an eligible
account (serving a model in the chain, under its cap, cache-affinity-preferred) has a free slot append
a unique lease, then PUT the file with the read SHA. A concurrent writer changes the SHA → the PUT is
rejected → retry. This serializes allocation across every codebase without reaction counting. Release
and heartbeat are keyed by the unique claim_id.

Every retry — conflict OR throttle (issue #558) — goes back through the transaction's own loop and
RE-READS the ledger, re-deriving both the expected blob SHA and the lease payload. No path ever
replays a stale expected-SHA, so the CAS guarantee is exactly as strong under retry as without it.
"""
import argparse
import base64
import collections
import datetime
import hashlib
import importlib.util
import json
import math
import os
import random
import re
import subprocess
import sys
import time


_retry_spec = importlib.util.spec_from_file_location(
    "registry_ledger_retry", os.path.join(os.path.dirname(__file__), "ledger_retry.py"))
if _retry_spec is None or _retry_spec.loader is None:
    raise RuntimeError("cannot load shared ledger retry policy")
ledger_retry = importlib.util.module_from_spec(_retry_spec)
_retry_spec.loader.exec_module(ledger_retry)

_schema_spec = importlib.util.spec_from_file_location(
    "registry_lease_schema", os.path.join(os.path.dirname(__file__), "lease_schema.py"))
if _schema_spec is None or _schema_spec.loader is None:
    raise RuntimeError("cannot load shared lease schema")
lease_schema = importlib.util.module_from_spec(_schema_spec)
_schema_spec.loader.exec_module(lease_schema)

LEDGER_PATH = "data/leases.json"
# The mutable data plane lives on a dedicated NON-code branch: branch protection on the default
# (code) branch rejects the bot's contents-API PUTs (issue #28 live incident 2026-07-17 — a
# required `gate` status check on master blocked every lease write and starved all dispatch),
# and a bot that can only write `ledger` can never push code to master. Env override is for
# tests/migration only; every reader and writer threads this single constant.
LEDGER_REF = os.environ.get("REGISTRY_LEDGER_REF", "ledger")


class LeaseIOError(RuntimeError):
    """A fail-closed ledger/catalog error that never includes credential material."""


# ---- pure allocation core (unit-tested) ---------------------------------------------------------
def reclaim_expired(leases, now):
    """Drop leases whose expiry has passed (conservative reclamation)."""
    return [x for x in leases if x.get("expires_at", 0) > now]


# ---- liveness-aware expiry: the groom-leases heartbeat (issue #35) -------------------------------
# The groom-leases cron used to drop EVERY lease past its TTL with no signal from the holder. A
# legitimately long run outlives that TTL while it is still WRITING: the worker lease's ttl is
# `worker_timeout_minutes * 60 + 900` (worker.yml), but that budget covers ONLY the agent job —
# the PR publish / review-prep / release jobs that follow it are separate jobs with their own
# timeouts. At `worker_timeout_minutes = 90` behind a slow cargo gate the run routinely runs past
# 105 minutes, and the blind reclaim then re-opens the issue to a SECOND worker: duplicate PRs,
# conflicting label transitions, and two concurrent sessions burning one account's quota window.
#
# WHY THIS RENEWS RATHER THAN "SKIPPING THE RECLAIM". Leaving an expired row in place fixes
# nothing, because every duplicate-suppression consumer keys on `expires_at > now` and NOT on the
# row's presence: `reclaim_expired` (so claim()'s holder-key single-flight and partition_available
# never see the row), and dispatch-claim's `_live_holder_keys` / `sibling_lease_conflict`. An
# expired-but-present row suppresses NOTHING and would leave the double-dispatch wide open while
# looking fixed. So the cron EXTENDS the expiry of a lease whose holder run is PROVABLY still
# running. That is the heartbeat the ledger never had — driven from this 15-minute cron rather
# than from the worker, so a run does not have to stay healthy enough to defend its own slot, and
# every consumer is corrected at once by the one field they all already read.
RENEWAL_SECONDS = 45 * 60
# ...and the renewal is PRE-EMPTIVE, which is what turns this from a mitigation into a fix. Renewing
# only rows that have ALREADY expired still leaves the gap between the expiry and the next tick —
# up to a full cron period in which every consumer reads the live worker's lease as expired and a
# dispatch tick in that window double-dispatches exactly as before. So a lease is re-decided once
# it comes within this LEAD of expiring: two cron periods, so a live lease is looked at (and, while
# its run is up, pushed forward) before it can ever be seen expired. `RENEWAL_SECONDS` is longer
# than the lead by design — a renewal must leave the row outside its own lead window at the moment
# it lands, or the row would be due again immediately.
RENEWAL_LEAD_SECONDS = 30 * 60
# UNPROVEN liveness gets a HOLD, not a pass. When the Actions API does not answer (403/5xx/garbage
# body) the ownership decision has to wait for the next tick — but "wait" cannot mean leaving an
# EXPIRED row byte-identical, because by the paragraph above such a row suppresses NOTHING: its
# account slot and its holder key go free to the next dispatcher while the original run may still
# be writing. That is exactly the double-dispatch this change exists to close, reopened by any
# transient API blip. So a due row whose liveness is unproven has its expiry pushed to this SHORT
# grace deadline instead — the row keeps suppressing on the one field every consumer reads, and the
# DECISION is what gets deferred. Long enough to outlast a skipped cron fire (>= two periods), and
# never longer than `RENEWAL_LEAD_SECONDS`, so a held row stays inside its lead window and is
# re-probed EVERY tick rather than quietly sitting on a slot; `RENEWAL_CEILING_SECONDS` still cuts
# off a probe that never recovers.
RENEWAL_GRACE_SECONDS = 30 * 60
# Absolute backstop. A renewal never pushes a lease past `issued_at + RENEWAL_CEILING_SECONDS`,
# and past that point the lease is reclaimed REGARDLESS of liveness. Without it a run wedged in
# `in_progress` — or a `gh` probe that keeps failing (which reads as "unproven", above) — would pin
# a scarce account slot forever, trading the double-dispatch for a permanent capacity leak. Six
# hours is GitHub's own hard per-job ceiling, so no honest lease-holding job can outlive it.
RENEWAL_CEILING_SECONDS = 6 * 3600
# The workflows that hold a lease for the WHOLE duration of their run, so "this run is still
# active" is evidence the lease is still owned. A holder naming any other run is NOT such evidence
# and is reclaimed exactly as before — that is also what stops an arbitrary run id (a long-lived
# cron, a tampered ledger row) from being able to pin a slot.
LEASE_HOLDING_WORKFLOWS = frozenset({
    ".github/workflows/worker.yml", ".github/workflows/review-fix.yml"})
# Mirrors groom.py's ACTIVE_RUN_STATUSES — the same run states, decided the same way.
ACTIVE_RUN_STATUSES = frozenset({"queued", "in_progress", "requested", "waiting", "pending"})

# worker.yml and review-fix.yml stamp `...@$GITHUB_RUN_ID.$GITHUB_RUN_ATTEMPT`. A dispatcher-minted
# lease stamps `@dispatch-<id>.<n>` and a repair lease may carry no `@` at all; NEITHER names a run
# that owns the lease for its duration, so neither matches here.
HOLDER_RUN = re.compile(r"[^@]*@(?P<run>[1-9][0-9]*)\.[1-9][0-9]*")

# ---- [#1128] liveness for a RUN-LESS holder: the dispatcher-minted repair lease ------------------
# A `review:`/`fix:` repair lease is MINTED by the dispatcher with an `@dispatch-<id>.<n>` holder and
# is ADOPTED by the review-fix run it dispatches, which rewrites the holder to its own
# `@<run>.<attempt>`. Between those two points — and FOREVER, when the run dies before reaching its
# adopt step — the holder names no run that owns the lease, so `holder_run_id` returns None and the
# holder-run probe has nothing to ask about. groom.py does not cover the gap either: it FILTERS
# repair holders out of its dead-lease sweep entirely (`is_repair_holder`), deliberately, because
# they are documented there as "TTL-managed by groom-leases". So a repair lease had NO reclaim path
# at all except running out its own TTL, in EITHER groomer.
#
# MEASURED (issue #1128, 2026-07-29): review-fix run 30409749675 concluded `failure` at 00:13:46Z
# still holding `fix:jeswr/agent-account-registry#1102@dispatch-30409404963.1`, whose TTL ran to
# 01:44:47Z. That one row pinned the last free review slot and the fleet took ZERO dispatches for
# the intervening 91 minutes ("no eligible review lease is free this tick", every tick).
#
# The evidence was available the whole time, in the dead run's OWN NAME: review-fix.yml stamps
# `claim=<claim_id>` into its `run-name`, so a lease correlates to the run holding it by CLAIM ID
# even when its holder string cannot name one. (This is the same correlation groom.py already does
# against worker.yml.) A POSITIVELY OBSERVED terminal conclusion therefore reclaims the row
# immediately, with no TTL wait.
#
# WHAT THIS DELIBERATELY DOES NOT DO — issue #1071. ABSENCE OF A RUN IS NOT DEATH. A lease minted
# seconds ago whose review-fix run has not materialised yet correlates to nothing, and reclaiming on
# that would race the dispatcher and hand one account to two workers — the direction that is not
# recoverable the way a stall is. An unmatched claim, an unparseable listing and a failed API read
# are ALL "unknown" here, and unknown NEVER reclaims: the row falls through to the pre-existing TTL
# path exactly as before. The only new reason a row can be dropped is a run document that says
# `status: completed`.
REVIEW_FIX_WORKFLOW = ".github/workflows/review-fix.yml"
# review-fix.yml: `run-name: review-fix <mode> <target_repo>#<pr> claim=<claim_id|'self'>`. Matched
# against the run's LIVE `display_title` (verified against the real API, not against the template):
# a `self`-claimed run holds no dispatcher lease and correlates to nothing, so only the 32-hex form
# is accepted here.
REVIEW_FIX_RUN_NAME = re.compile(r"review-fix \S+ \S+ claim=(?P<claim>[0-9a-f]{32})")
# Bounds the correlation walk on a busy repo: 20 x 100 runs. Exhausting it is NOT an error — the
# unmatched claims simply stay unknown and keep their TTL — because this is a groomer, not a gate.
CLAIM_RUN_PAGE_CEILING = 20

ReclaimOutcome = collections.namedtuple(
    "ReclaimOutcome", "reclaimed renewed deferred finished read", defaults=(0, 0))
# `read` is the SIZE OF THE POPULATION the transaction decided over, and it is reported because
# without it the cron's outcome line cannot distinguish the three states an operator most needs to
# tell apart: a healthy tick over rows that were simply not due, a genuinely empty ledger, and a
# ledger that was not read at all. Issue #1128 was filed on exactly that ambiguity — a
# `0 / 0 / 0` line over a TEN-ROW ledger was read as "the reclaim processed an empty set". The
# counters were right; the line just could not say what they were counted over.
# `finished` is reported apart from `reclaimed` because the two carry DIFFERENT evidence, and an
# operator reading the cron's outcome line has to be able to tell which fired: `reclaimed` is the
# TTL backstop (the row's expiry passed and nothing proved it alive), `finished` is the #1128 path
# (a correlated run positively concluded). Folding them would make "has the new path ever ACTED?"
# unanswerable from the logs — which is exactly how the TTL-only behaviour went unnoticed.
RenewalPlan = collections.namedtuple(
    "RenewalPlan", "leases renewed reclaimed deferred finished")


def classify_claim_run(run):
    """Liveness of one review-fix run correlated to a lease by CLAIM ID: ``live``/``finished``/
    ``unknown``.

    ``finished`` means a POSITIVELY OBSERVED terminal status and is the only verdict that reclaims
    a run-less holder ahead of its TTL — a `completed` run will not do any further work, whether it
    succeeded, failed or was cancelled, so its lease is unowned either way. Anything this cannot
    read — a non-document, a run from some other workflow, an unrecognised status — is ``unknown``
    and reclaims NOTHING (see the header: absence and unreadability are not death)."""
    if not isinstance(run, dict):
        return "unknown"
    if str(run.get("path", "")).split("@", 1)[0] != REVIEW_FIX_WORKFLOW:
        return "unknown"
    status = run.get("status")
    if status in ACTIVE_RUN_STATUSES:
        return "live"
    return "finished" if status == "completed" else "unknown"


def claim_liveness_map(pending, oldest_issued, fetch, ceiling=CLAIM_RUN_PAGE_CEILING):
    """Correlate claim ids to run liveness over paged review-fix run documents, purely.

    ``fetch(page)`` returns that page's run documents NEWEST-FIRST, or None for a page that could
    not be read. Returns ``{claim_id: "live" | "finished"}``; a claim NOTHING correlated is simply
    ABSENT, which every caller reads as unknown and never reclaims.

    A claim is ``live`` if ANY correlated run is still active and ``finished`` only when every
    correlated run has terminated — a re-dispatch that produced a second run must not let the
    older, finished one reclaim a slot the newer, live one is using.

    The walk stops as soon as every pending claim is correlated, the history is exhausted, a page
    predates the OLDEST live lease's issuance (no run older than that can hold a current lease, so
    the whole relevant window is then covered), or a page cannot be read. Unlike groom.py's
    equivalent it does NOT raise on a truncated snapshot: leaving a claim unknown costs one more
    TTL, and that is strictly safer here than failing the cron that frees every other slot."""
    verdicts = {}
    pending = set(pending)
    for page in range(1, ceiling + 1):
        if not pending:
            break
        runs = fetch(page)
        if runs is None:
            break                      # unreadable page: stop, leave the rest unknown.
        page_oldest = None
        for run in runs:
            if not isinstance(run, dict):
                continue
            created = _run_created_epoch(run)
            if created is not None:
                page_oldest = created if page_oldest is None else min(page_oldest, created)
            display = run.get("display_title")
            if not isinstance(display, str):
                continue
            match = REVIEW_FIX_RUN_NAME.fullmatch(display)
            if match is None or match.group("claim") not in pending:
                continue
            claim, state = match.group("claim"), classify_claim_run(run)
            if state == "unknown":
                continue
            # `live` is sticky: once any run for this claim reads active, no sibling run may
            # downgrade it to `finished`.
            if verdicts.get(claim) != "live":
                verdicts[claim] = state
        if len(runs) < 100:
            break                      # review-fix history exhausted.
        if page_oldest is not None and oldest_issued is not None and page_oldest < oldest_issued:
            break                      # the relevant time window is covered.
    return verdicts


def _run_created_epoch(run):
    """A run document's `created_at` as epoch seconds, or None when it cannot be read."""
    created = run.get("created_at")
    if not isinstance(created, str):
        return None
    try:
        parsed = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return int(parsed.timestamp()) if parsed.tzinfo is not None else None


def holder_run_id(holder):
    """The registry Actions run id a lease holder RECORDS, or None when it records none.

    Only the bare `<run>.<attempt>` suffix names a run that OWNS the lease for its whole life. A
    dispatcher holder (`@dispatch-<id>.<n>`), a repair holder with no run suffix, and any shape
    this cannot parse all return None — i.e. no liveness evidence, reclaimed exactly as before."""
    if not isinstance(holder, str):
        return None
    match = HOLDER_RUN.fullmatch(holder)
    return int(match.group("run")) if match else None


def classify_run(run):
    """Liveness of one Actions run document: ``live`` | ``dead`` | ``unknown``.

    ``dead`` also covers a run OUTSIDE `LEASE_HOLDING_WORKFLOWS`: a holder that names some other
    workflow's run is not evidence its lease is still held, and admitting it would let any
    long-lived run id pin a slot. ``unknown`` is reserved for "the API did not answer" — an
    unreadable document or an unrecognised status — and defers the decision one cron tick rather
    than guessing in either direction, holding the row's exclusivity meanwhile on
    `RENEWAL_GRACE_SECONDS`; `RENEWAL_CEILING_SECONDS` bounds how long that can last."""
    if not isinstance(run, dict):
        return "unknown"
    if str(run.get("path", "")).split("@", 1)[0] not in LEASE_HOLDING_WORKFLOWS:
        return "dead"
    status = run.get("status")
    if status in ACTIVE_RUN_STATUSES:
        return "live"
    return "dead" if status == "completed" else "unknown"


def _lease_epoch(lease, field):
    value = lease.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def plan_renewal(leases, now, liveness, renewal=RENEWAL_SECONDS,
                 ceiling=RENEWAL_CEILING_SECONDS, lead=RENEWAL_LEAD_SECONDS,
                 grace=RENEWAL_GRACE_SECONDS, claim_liveness=None):
    """THE groom-leases decision, pure: what the ledger should hold after this tick.

    Returns a ``RenewalPlan(leases, renewed, reclaimed, deferred, finished)``. A row is DUE for a
    decision once it
    has expired OR comes within `lead` of expiring; anything further out passes through untouched
    and costs no API call. A due row is:
      * RENEWED to `min(now + renewal, issued_at + ceiling)` when its run is provably active. This
        fires BEFORE expiry too, which is the point: renewing only already-expired rows would
        still leave a live worker's lease reading expired for up to one cron period, and a
        dispatch tick inside that window double-dispatches exactly as before.
      * RECLAIMED — only if it has ACTUALLY expired — when its holder names no run, when that run
        is dead/absent/not a lease-holding workflow, when its timestamps are unreadable, or when
        `issued_at + ceiling` has passed (the backstop: a blind reclaim, but a bounded one, and
        the only path that can still drop a lease whose run reads as live).
      * DEFERRED — the OWNERSHIP DECISION is re-taken next tick, but the row's EXCLUSIVITY is held
        meanwhile on `min(now + grace, issued_at + ceiling)` — when liveness is unproven. Leaving
        such a row byte-identical would not defer anything: an expired row suppresses nothing (see
        the module header), so a single 403/5xx would hand the slot and the holder key straight to
        the next dispatcher. Post-condition: an unproven row always leaves this function with
        `expires_at > now`, so every consumer still reads it as live. `ceiling` still bounds it.
      * left ALONE when it is not yet expired and its run is not live — there is nothing to renew
        and nothing to reclaim yet, and the row is still suppressing on its own expiry.

      * FINISHED — dropped with NO TTL wait, and the only decision here that can drop a row that
        has not expired — when the row's holder names no run BUT its claim id correlates to a
        review-fix run that has positively CONCLUDED (issue #1128). See the `REVIEW_FIX_RUN_NAME`
        header: this is the repair lease's only reclaim path, because `holder_run_id` cannot name
        its run and groom.py filters repair holders out of its own dead-lease sweep by design.

    `liveness` maps a run id to ``live``/``dead``/``unknown``. It is consulted ONLY for a due row
    inside its ceiling that actually names a lease-owning run, so an idle ledger costs no API calls
    at all.

    `claim_liveness` maps a CLAIM ID to ``live``/``finished`` (anything else, including a missing
    entry, is unknown) and is consulted only for a row whose holder names no run. It is deliberately
    consulted on EVERY tick and not merely inside the lead window: the lead window is 30 minutes and
    the stall this closes was the repair lease's full 105-minute TTL, so gating the death evidence
    on it would still have burned an hour. Passing None restores the pre-#1128 behaviour exactly."""
    next_leases, renewed, reclaimed, deferred, finished = [], 0, 0, 0, 0
    for lease in leases:
        expires = _lease_epoch(lease, "expires_at")
        issued = _lease_epoch(lease, "issued_at")
        run_id = holder_run_id(lease.get("holder"))
        # [#1128] A run-less holder is a dispatcher-minted repair lease. It has no holder-run
        # evidence BY CONSTRUCTION, so without this it can only ever be dropped by its TTL. A
        # positively terminal correlated run frees it now; an ABSENT or unreadable correlation
        # leaves it untouched on the TTL path below, which is the #1071 case this must not break.
        if run_id is None and claim_liveness is not None:
            if claim_liveness(lease.get("claim_id")) == "finished":
                finished += 1
                continue
        expired = expires is None or expires <= now
        if not expired and expires > now + lead:
            next_leases.append(lease)
            continue
        # Unreadable timestamps, no run to ask about, or the renewal ceiling is spent: there is no
        # liveness evidence to be had, so this stays the pre-#35 blind reclaim — which is the
        # RIGHT answer for exactly these rows, and is the only path that can still drop a live one.
        provable = (expires is not None and issued is not None and run_id is not None
                    and now < issued + ceiling)
        state = liveness(run_id) if provable else "dead"
        if state in ("live", "unknown"):
            # A proven-live run earns the full renewal; an unproven one earns only the short grace
            # hold. Both are clamped to the ceiling, and both are pre-emptive for the same reason —
            # waiting for the row to actually expire leaves a window in which it suppresses nothing.
            extended = min(now + (renewal if state == "live" else grace), issued + ceiling)
            moved = extended > expires
            next_leases.append({**lease, "expires_at": extended} if moved else lease)
            # An unproven row is DEFERRED either way: `not moved` means its existing expiry already
            # sits past the grace deadline, so the post-condition holds with no write. A renewal is
            # only COUNTED when it moved, so an untouched row never inflates the commit message.
            if state == "unknown":
                deferred += 1
            elif moved:
                renewed += 1
        elif not expired:
            next_leases.append(lease)     # nothing to reclaim yet; re-decided next tick
        else:
            reclaimed += 1
    return RenewalPlan(next_leases, renewed, reclaimed, deferred, finished)


ACCOUNT_FINGERPRINT_RE = re.compile(r"[0-9a-f]{16}")


def account_fingerprint(handle, salt=None):
    """Canonical public identity for an account. Missing salt fails closed."""
    salt = os.environ.get("PROVENANCE_SALT", "") if salt is None else salt
    if not isinstance(handle, str) or not handle or not isinstance(salt, str) or not salt:
        raise LeaseIOError("PROVENANCE_SALT and account handle are required for lease identity")
    return hashlib.sha256(f"{handle}:{salt}".encode()).hexdigest()[:16]


def validate_lease_account_identities(leases):
    """Drop legacy/raw identities so the next CAS write completes the bounded migration."""
    return [item for item in leases
            if isinstance(item.get("account"), str)
            and ACCOUNT_FINGERPRINT_RE.fullmatch(item["account"]) is not None]


def active_for(leases, account):
    fingerprint = account_fingerprint(account)
    return sum(1 for x in leases if x.get("account") == fingerprint)


# ---- usage-aware eligibility + expiry-priority (dynamic backoff) --------------------------------
# [OPUS-4.8] A worker must NOT start on an account that could hit a rate limit mid-run — that burns
# credits on a half-finished agent. So an account is eligible to START only if we KNOW its live usage
# (Anthropic anthropic-ratelimit-unified-* headers), its status is "allowed", and BOTH the 5h and 7d
# windows have >= SAFETY_MARGIN headroom. Fail closed on any missing/unknown usage. Among eligible
# accounts we prioritise the one whose WEEKLY window resets SOONEST — its unused credits are about to
# reset, so spend them before they vanish (use-it-or-lose-it).
SAFETY_MARGIN = 0.10  # default fraction of each window that must remain free to admit a new worker.
# CAVEAT: this is a POINT-IN-TIME headroom gate, not a projected-consumption model — an account admitted
# at (1 - margin) utilisation can still exceed its window mid-run if the worker's burn exceeds the
# remaining headroom. Set margin >= a typical worker's per-window burn to actually prevent half-finishes.
# Per-repo overridable via policy `usage_safety_margin`. Projected-burn admission is tracked as follow-up.

# [FABLE-5] Models whose OWN weekly sub-quota must ALSO have headroom before a worker starts —
# routing one of these to an account with low WHOLE-account usage but an exhausted premium bucket
# fails mid-run and burns credits. The alias -> gate map lives below `_fable_eligible` /
# `_opus5_eligible` (it holds the gates themselves, so PREMIUM_MODELS cannot name an alias that has
# no rule and quietly fall through to the whole-account test).
FABLE_WINDOW = "fable_7d_oi"  # prefix of the fable sub-quota util/reset keys in the usage map
# [#720] The keys account-usage.py's claude-opus-5 OBSERVATION writes into a usage entry. The window
# NAME is the arming signal: it is present iff that probe actually saw a rate-limit window the
# whole-account 5h/7d pair does not cover, so observation and enforcement are the same fact.
OPUS5_PREMIUM_WINDOW_KEY = "opus5_premium_window"
OPUS5_PREMIUM_UTIL_KEY = "opus5_premium_util"

# --- EXEMPTION IS NOT REACHABILITY (registry #639) -------------------------------------------------
# The probe exemption (issue #29) answers ONE question: this provider publishes no usage headers, so
# do not require them. It was ALSO being read as "assume the account is available", which is a
# different claim and one nothing had established — so a credential the system had already diagnosed
# as dead (`credential-remint-required`, #596 / alert #622) kept being handed to the allocator, and
# every review dispatch burned a runner plus a lease to reach a 3-second auth failure.
#
# So an exempt entry must now CARRY its reachability, derived from the health record by
# account-usage.py (model-health.credential_states): `live` = a success in the window, `dead` = a run
# of auth rejections with no later success, `unproven` = no decisive record. Only the two ADMITTING
# values are allowlisted below, so `dead`, an ABSENT field (a producer that never evaluated
# reachability — e.g. this stamping deleted), a non-string, or any unrecognised spelling is
# INELIGIBLE. Allowlisting the admitting side (rather than blocklisting "dead") is what makes the
# fail direction unprovable-or-unstated ⇒ NOT eligible.
#
# WHY `unproven` STILL ADMITS (deliberate, argued — registry #639). There is no independent liveness
# probe for an exempt provider: the only reachability evidence in this system is a run OUTCOME, and
# account-whoami.yml (the one credential probe) is manual-dispatch and disabled on a public repo. So
# refusing `unproven` outright SELF-LATCHES — no dispatch ⇒ no records ⇒ unproven forever ⇒ no
# dispatch — with no recovery path, converting a bounded cost into permanent starvation of the
# fleet's only cross-provider reviewer. What `unproven` actually buys is BOUNDED: at most
# CREDENTIAL_DEAD_MIN trial dispatches per health window, after which the evidence turns `dead` and
# the account is out until a success proves otherwise. That is the fail-closed bound that IS
# implementable here, and it is ~2 dead runs per 48 h window against the ~144/day the pre-fix
# unconditional exemption spent.
USAGE_REACHABILITY_LIVE = "live"
USAGE_REACHABILITY_DEAD = "dead"
USAGE_REACHABILITY_UNPROVEN = "unproven"
# Parity with model-health.CREDENTIAL_* is asserted in account-usage.py's self-test (the producer
# that maps one vocabulary onto the other), so the two spellings cannot drift apart silently.
USAGE_REACHABILITY_ADMITTED = frozenset({USAGE_REACHABILITY_LIVE, USAGE_REACHABILITY_UNPROVEN})


def _usage_num(v):
    # OverflowError (cross-provider review r2 finding 3): a forged `backoff_until: 10**400` is
    # valid JSON (Python ints are unbounded) but float() of it RAISES rather than returning inf —
    # uncaught, it aborted the whole dispatch instead of failing open to no-backoff.
    try:
        return float(v)
    except (TypeError, ValueError, OverflowError):
        return None


def _usage_window(u, prefix):
    """(utilization, reset_ts) for a named window, or (None, None) if absent/unparseable."""
    if not isinstance(u, dict):
        return None, None
    return _usage_num(u.get(prefix + "_util")), _usage_num(u.get(prefix + "_reset"))


def _fable_eligible(u, margin):
    """[FABLE-5] Fail-closed headroom test for the FABLE weekly sub-quota. Requires the account-usage
    fable probe to have SUCCEEDED (fable_ok) AND the 7d_oi window to have >= margin headroom. Unknown or
    unprobed -> ineligible, so a fable route never lands on an account with an exhausted (or unobserved)
    Fable bucket."""
    if not isinstance(u, dict) or not u.get("fable_ok"):
        return False
    util, _ = _usage_window(u, FABLE_WINDOW)
    return util is not None and (1.0 - util) >= margin


def _opus5_eligible(u, margin):
    """[#720] Headroom test for the opus5 premium sub-quota, ARMED BY OBSERVATION.

    opus5 (claude-opus-5) has been the SOLE anthropic tier since the 2026-07-26 deprecation, and it
    was never premium-gated because its rate-limit mapping was unobserved — so whole-account 5h/7d
    headroom was the only thing admitting an opus5 worker. That is genuine protection ONLY IF
    Anthropic publishes no separate bucket for claude-opus-5. account-usage.py now OBSERVES that
    (`_assemble_opus5`) and declares what it saw, and this reads the declaration. Three states,
    deliberately NOT fable's two:

      * NO window declared -> True. The probe saw no rate-limit window beyond the whole-account
        pair (or could not observe at all), so the 5h/7d gate above is the whole story and
        admission is EXACTLY what it is today. This is the no-regression arm, and it is why the
        gate could land before the answer was known: absence of evidence must not park the fleet's
        only anthropic tier, which is a machine-recoverable capacity condition escalating onto a
        human's desk (#703).
      * a window IS declared and READABLE -> require >= margin headroom IN THAT WINDOW.
      * a window IS declared and UNREADABLE -> False. An unknown premium bucket is precisely the
        case where whole-account headroom is misleading, so refuse rather than fall back to it.
    """
    if not isinstance(u, dict) or OPUS5_PREMIUM_WINDOW_KEY not in u:
        return True                                   # unobserved / no distinct bucket -> as today
    window = u.get(OPUS5_PREMIUM_WINDOW_KEY)
    if not isinstance(window, str) or not window.strip():
        return False                                  # declared but unnameable -> unreadable
    util = _usage_num(u.get(OPUS5_PREMIUM_UTIL_KEY))
    # Same SHAPE validation the base windows get (issue #196): a `nan` utilization makes every
    # comparison false and a NEGATIVE one looks like excess headroom, so both would admit an
    # account whose premium bucket is in an unknown state.
    if util is None or not (0.0 <= util <= 1.0):
        return False                                  # present but unreadable -> refuse, never
    return (1.0 - util) >= margin                     # fall back to whole-account headroom


# The alias -> premium-sub-quota gate map. PREMIUM_MODELS is DERIVED from it rather than written
# beside it: two hand-maintained copies of one membership are how an alias comes to be premium in
# name and ungated in fact (#945 — a duplicated guard makes each copy individually unkillable).
PREMIUM_WINDOW_GATES = {"fable": _fable_eligible, "opus5": _opus5_eligible}
PREMIUM_MODELS = frozenset(PREMIUM_WINDOW_GATES)


def usage_eligible(u, margin=SAFETY_MARGIN, model=None, now=None):
    """Fail-closed admission test for STARTING a worker (of `model`) on an account. Beyond the whole-account
    5h/7d headroom, a PREMIUM_MODELS route (fable, opus5) additionally requires ITS OWN premium
    sub-quota to have headroom — see PREMIUM_WINDOW_GATES.

    PROBE-EXEMPT providers (openai/codex — maintainer decision 2026-07-17, registry issue #29): their
    usage is not observable via any API, so the fail-closed require-usage arm does NOT apply to them —
    they need no usage DATA and are governed REACTIVELY instead: account-usage.py stamps
    `backoff_until` (derived from the model-health rate-limit records) onto an exempt entry, and the
    account is excluded while now < backoff_until. A missing or malformed stamp means NO backoff
    (fail-open — the backoff is an optimization; the exemption must never reintroduce the fail-closed
    starvation it removes).

    Needing no usage data is NOT the same as being REACHABLE (registry #639): the exempt arm
    additionally requires the entry to carry an admitted `reachability` (see
    USAGE_REACHABILITY_ADMITTED above), so a credential proven dead by the health record — or an
    entry that never stated reachability at all — is INELIGIBLE. Anthropic accounts keep the
    fail-closed probing below unchanged (a rejected credential there already fails the probe)."""
    if not isinstance(u, dict):
        return False                                  # no probe data -> do not risk it
    if u.get("exempt") is True:                       # STRICT: only the literal producer-set flag —
        # a forged truthy string (e.g. "false") must not ride the exempt arm (cross-provider r1).
        # [#639] Exemption skips the QUOTA PROBE; it never asserts reachability. The entry must state
        # a reachability the producer actually evaluated, and it must not be `dead`.
        reachability = u.get("reachability")
        # isinstance FIRST (the OverflowError lesson of cross-provider r2 finding 3): a forged
        # unhashable value — `{}` / `[]` in a hand-edited snapshot — makes a bare `in <frozenset>`
        # raise TypeError and abort the whole dispatch instead of failing closed on that one account.
        if not isinstance(reachability, str) or reachability not in USAGE_REACHABILITY_ADMITTED:
            return False                              # dead / unstated / unrecognised -> not eligible
        until = _usage_num(u.get("backoff_until"))
        # Finite stamps only (cross-provider review r1): `inf` would sideline the account FOREVER
        # (now < inf is always True) while usage-alert's nan/inf guard reports it healthy — a
        # dispatch/monitoring split. Non-finite = no backoff, matching _apply_backoff's fail-open.
        if until is not None and math.isfinite(until):
            if now is None:
                import time
                now = time.time()
            if now < until:
                return False                          # rate-limited earlier — backed off until it expires
        return True                                   # non-metered provider (e.g. codex) — not probe-gated
    if str(u.get("status", "")).strip().lower() != "allowed":
        # [ISSUE #196] require status EXACTLY `allowed`: an empty status was previously accepted
        # (the `("allowed", "")` set) and failed open as eligible capacity.
        return False                                  # empty/throttled/rejected -> not eligible
    for prefix in ("5h", "7d"):
        util, _ = _usage_window(u, prefix)
        # [ISSUE #196] Validate the SHAPE before trusting the headroom comparison: a base window of
        # `nan` (every comparison is false, so `(1 - util) < margin` never fires) or a NEGATIVE
        # utilization (looks like excess headroom) otherwise slips through and admits the account.
        # Require a finite fraction in [0,1]; anything else is fail-closed ineligible.
        if util is None or not (0.0 <= util <= 1.0) or (1.0 - util) < margin:
            return False                              # unknown, malformed, or too little headroom
    if model is not None and not isinstance(model, str):
        # isinstance FIRST, the same reason the reachability arm above does it: a forged/ill-typed
        # alias (an unhashable `[]` from a hand-edited chain) makes the dict lookup below RAISE and
        # abort the whole dispatch instead of failing closed on this one account.
        return False
    premium_gate = PREMIUM_WINDOW_GATES.get(model)
    if premium_gate is not None and not premium_gate(u, margin):
        return False                                  # whole-account fine, but the premium bucket isn't
    return True


def _weekly_reset(u):
    """Whole-account weekly reset used for provider-wide use-it-or-lose-it draining."""
    _, reset = _usage_window(u, "7d")
    return reset


def _order_eligible_accounts(accounts, leases, usage, package, role):
    """Deterministically order accounts that have already passed every eligibility gate.

    Preserve the allocator's cache-affinity/load/handle order, then stably promote known weekly
    resets from soonest to latest. Accounts without a 7d reset remain last in their prior relative
    order. This helper deliberately contains no availability, model, capacity, or usage gating.
    """
    def affinity(account):
        times = [lease.get("issued_at", 0) for lease in leases
                 if lease.get("account") == account_fingerprint(account["handle"])
                 and lease.get("package") == package and lease.get("role") == role]
        return max(times) if times else -1

    ordered = sorted(
        accounts,
        key=lambda account: (
            -affinity(account), active_for(leases, account["handle"]), account["handle"]),
    )
    if usage is not None:
        def weekly_key(account):
            reset = _weekly_reset(usage.get(account["handle"]))
            return reset is None, reset if reset is not None else 0.0

        ordered.sort(key=weekly_key)
    return ordered


def _choose_account_model(accounts, leases, model_chain, package, role, now, usage=None,
                          margin=SAFETY_MARGIN):
    """Return ``(account, model)`` for the first model with eligible capacity, or None.

    Each alias pass applies the complete account availability, concurrency, and usage/backoff gates
    before advancing to the next alias. Returning the alias with the account keeps the lease record
    bound to the model pass that actually admitted it.
    """
    live = reclaim_expired(leases, now)
    for model in model_chain:
        serving = [a for a in accounts
                   if a.get("available", True) and model in a.get("models", [])
                   and active_for(live, a["handle"]) < int(a.get("max_concurrent_workers", 4))]
        if usage is not None:
            serving = [a for a in serving
                       if usage_eligible(usage.get(a["handle"]), margin, model=model, now=now)]
        if not serving:
            continue

        serving = _order_eligible_accounts(serving, live, usage, package, role)
        return serving[0], model
    return None


def choose_account(accounts, leases, model_chain, package, role, now, usage=None, margin=SAFETY_MARGIN):
    """Return the account handle to claim, or None. `accounts`: list of dicts
    {handle, models:[...], max_concurrent_workers, available:bool}. Walks the model chain; within a
    model keeps accounts under their concurrency cap and — when live `usage` (a {handle: {status,
    5h_util,5h_reset,7d_util,7d_reset}} map) is supplied — only accounts that pass `usage_eligible`.
    Orders eligible accounts by EXPIRY-PRIORITY: soonest whole-account weekly reset first (use credits
    before they reset), preserving CACHE AFFINITY, least-loaded, and handle order for equal or unknown
    resets. With `usage=None` the behaviour is the original cache-affinity-then-least-loaded selection
    (backward compatible)."""
    selected = _choose_account_model(
        accounts, leases, model_chain, package, role, now, usage=usage, margin=margin)
    return selected[0]["handle"] if selected is not None else None


def dynamic_concurrency(accounts, usage, model_chain=None, absolute_cap=None, margin=SAFETY_MARGIN,
                        now=None):
    """How many workers may run right now = sum of per-account slots over accounts eligible to START
    (available, optionally serving `model_chain`, and `usage_eligible`). Starts HIGH when many accounts
    have headroom and BACKS OFF automatically as utilisation climbs (ineligible accounts drop out), so
    credits aren't spent on workers that would half-finish. `absolute_cap` is an optional hard ceiling.
    Returns 0 when `usage` is empty/None (probe unavailable) — the caller should then fall back to the
    static policy `max_concurrent`; a returned 0 WITH a non-empty usage map means every account is
    genuinely tapped out and nothing should dispatch."""
    if not usage:
        return 0
    total = 0
    for a in accounts:
        if not a.get("available", True):
            continue
        # [FABLE-5] An account counts only if it is eligible for a model it can actually serve from the
        # chain (a fable-only chain requires fable sub-quota headroom, not just whole-account headroom).
        servable = [m for m in model_chain if m in a.get("models", [])] if model_chain is not None \
            else [None]
        if model_chain is not None and not servable:
            continue
        u = usage.get(a["handle"])
        if any(usage_eligible(u, margin, model=m, now=now) for m in servable):
            total += int(a.get("max_concurrent_workers", 4))
    if absolute_cap is not None:
        total = min(total, absolute_cap)
    return total


def available_account_slots(accounts, leases, model_chain, now, account_pool=None, usage=None,
                            margin=SAFETY_MARGIN):
    """Return the live remaining worker slots able to serve ``model_chain``.

    This is the account-slot bound used by the review/fix dispatcher.  Unlike the historical
    shared ``review:`` / ``fix:`` lease-row caps, it counts each admitted account's configured
    ``max_concurrent_workers`` and subtracts that account's live leases.  Availability, policy
    pool membership, exact model membership, and the usage/backoff gate are all applied before an
    account contributes capacity.  Unknown usage therefore fails closed whenever a usage map is
    supplied, exactly like ``choose_account``; callers that deliberately allow the static path
    pass ``usage=None``.
    """
    live = reclaim_expired(leases, now)
    allowed = set(account_pool) if account_pool is not None else None
    slots = 0
    for account in accounts:
        handle = account.get("handle")
        if not isinstance(handle, str) or not handle:
            continue
        if allowed is not None and handle not in allowed:
            continue
        if not account.get("available", True):
            continue
        servable = [model for model in model_chain if model in account.get("models", [])]
        if not servable:
            continue
        if usage is not None and not any(
                usage_eligible(usage.get(handle), margin, model=model, now=now)
                for model in servable):
            continue
        try:
            cap = int(account.get("max_concurrent_workers", 4))
        except (TypeError, ValueError, OverflowError):
            continue
        slots += max(0, cap - active_for(live, handle))
    return slots


def make_lease(account, holder, package, role, model, now, ttl):
    return {"account": account_fingerprint(account), "claim_id": None, "holder": holder, "package": package,
            "role": role, "model": model, "issued_at": now, "expires_at": now + ttl}


def apply_claim(leases, account, holder, package, role, model, now, ttl, claim_id):
    live = reclaim_expired(leases, now)
    lease = make_lease(account, holder, package, role, model, now, ttl)
    lease["claim_id"] = claim_id
    live.append(lease)
    return live, lease


def apply_release(leases, claim_id, now):
    return [x for x in reclaim_expired(leases, now) if x.get("claim_id") != claim_id]


def claim_commit_message(claim_id, package, role):
    """Public ledger subject: operational identifiers only, never account identity."""
    return f"claim {claim_id[:8]} {package}/{role}"


def holder_key(holder):
    """Stable target-issue identity for duplicate suppression across dispatcher/run attempts."""
    if not isinstance(holder, str) or not holder:
        return ""
    return holder.split("@", 1)[0]


# Every dispatcher-minted holder carries this marker in its run-portion (after `@`):
# dispatch-claim.py mints `<repo>#<n>@dispatch-<run>.<attempt>` (impl lane) and
# `<lane:><repo>#<n>@dispatch-<run>.<attempt>` (review/fix). A worker run that ADOPTS the claim
# rewrites the holder to `<repo>#<n>@<run>.<attempt>` (NO marker), so the marker is what tells a
# still-dispatcher-owned claim apart from one already adopted by a worker (issue #132).
DISPATCHER_RUN_MARKER = "dispatch-"


def adoptable_holder(current, new_holder):
    """Whether the lease currently held by `current` may be CAS-adopted to `new_holder`.

    True only when the lease is STILL dispatcher-owned — its run-portion (after `@`) carries the
    `dispatch-` marker every dispatcher holder is minted with — or when it is ALREADY this exact
    worker run (idempotent re-adopt / revalidation). A holder that is a DIFFERENT worker run (one
    that has already adopted this claim) is rejected, so two runs can never both adopt the same
    claim and a queued worker cannot steal a slot a peer is actively holding (issue #132)."""
    if not isinstance(current, str):
        return False
    if current == new_holder:
        return True
    run_part = current.split("@", 1)[1] if "@" in current else ""
    return run_part.startswith(DISPATCHER_RUN_MARKER)


def partition_available(leases, holder_prefix, package):
    """Whether a repository-scoped partition is free in the active ledger.

    A partition key names a SET of areas (`lease_schema.plan_package`), so availability is
    SET-DISJOINTNESS, not string equality: `{a,b}` is free against a live `{c}` lease and taken
    against a live `{b,c}` one. `__global__` — the universal set, which zero-area rows still
    reduce to — intersects everything and therefore still serializes in both directions, exactly
    as the old `package == "__global__" -> not scoped` special case did.

    THE SAME PREDICATE AS PLAN. `dispatch-claim.filter_busy_area_items` /
    `revalidate_items_against_live_pulls` / `sibling_lease_conflict` all decide with
    `lease_schema.packages_conflict` too. Widening one side and not the other produces a scheduler
    that plans work the allocator then refuses (`package-single-flight` every tick, forever), which
    is worse than either width — so there is one predicate and every site imports it.

    A lease whose `package` is missing or unreadable reads as the UNIVERSAL set and therefore
    CONFLICTS. That is a tightening over the old `lease.get("package") in {package, "__global__"}`
    membership test, which was False for a `None` package and silently declared the partition free;
    `validate_ledger` requires a non-empty string, so the case is unreachable through the validated
    path and the fail-closed reading is the only safe one where it is not."""
    scoped = [
        lease for lease in leases
        if str(lease.get("holder", "")).startswith(holder_prefix)
    ]
    return not any(lease_schema.packages_conflict(lease.get("package"), package)
                   for lease in scoped)


# ---- GitHub CAS I/O -----------------------------------------------------------------------------
def ledger_read_path(repo):
    """Contents-API GET path for the lease ledger, pinned to the data-plane branch (never the
    protected default branch)."""
    return f"repos/{repo}/contents/{LEDGER_PATH}?ref={LEDGER_REF}"


def ledger_write_args(repo, message, content_b64, sha):
    """gh argv for the ledger CAS PUT, pinned to the data-plane branch (never the protected
    default branch — a PUT without `branch=` commits to the default branch and is rejected by
    its required-status-check protection)."""
    args = ["gh", "api", "-X", "PUT", f"repos/{repo}/contents/{LEDGER_PATH}",
            "-f", f"message={message}", "-f", f"content={content_b64}",
            "-f", f"branch={LEDGER_REF}"]
    if sha:
        args += ["-f", f"sha={sha}"]
    return args


def _ledger_branch_exists(repo):
    return subprocess.run(
        ["gh", "api", f"repos/{repo}/git/ref/heads/{LEDGER_REF}"],
        capture_output=True, text=True, check=False,
    ).returncode == 0


def _read_404(branch_exists):
    """Pure 404 policy: file-absent on a PRESENT ledger branch seeds an empty ledger (the first
    CAS PUT creates the file); an ABSENT/unreadable ledger branch fails LOUD — silently-empty
    would let every claim proceed against a ledger no other worker can see."""
    if branch_exists:
        return [], None
    raise LeaseIOError(
        f"ledger branch '{LEDGER_REF}' is missing or unreadable — create it from master "
        "(see data/README.md) before claiming")


def _is_retryable_read_error(stderr):
    """True for a ledger contents-GET failure that can clear by waiting. READ-scoped on purpose —
    see `ledger_retry.is_retryable_read` for why this is not `_is_transient_write_error`."""
    return ledger_retry.is_retryable_read(stderr)


def _read_ledger(repo, budget=None):
    """Return (leases_list, blob_sha or None).

    THE READ HALF OF A CAS TRANSACTION (registry #1246). Issue #558 hardened `_write_ledger`
    against the throttle/availability class and gave every transaction a `TransientWriteBudget`
    for it — but the READ that opens the same transaction, two lines above every one of those
    PUTs, kept failing loud on the FIRST non-404 error with a status-less "lease ledger read
    failed". MEASURED 2026-07-27..29: 23 worker runs published their pull request and then died
    exactly there in `release()`, stranding a scarce account lease for the remainder of its TTL
    (23.1 account-hours) — the very outcome #558's own docstring says it exists to prevent, arriving
    through the half it did not cover.

    With a `budget` the retry is IN PLACE, unlike the write's. That asymmetry is the point and it
    is safe in exactly one direction: a PUT may not be replayed because its expected blob SHA goes
    stale, so its caller must re-read and re-derive; a GET has no expected revision to invalidate
    and simply returns the tip as of the attempt that succeeded. The caller's CAS loop is unchanged
    and still bounded — `_cas_attempts` grows by `budget.rejections`, and the budget itself fails
    loud on its `attempts`-th rejection and is charged against the process-wide
    THROTTLE_WAIT_CEILING_S.

    `budget=None` (the default, for callers with no transaction loop, e.g. `inspect_claim`) keeps
    the historical fail-at-once behaviour, so nothing retries silently.
    """
    while True:
        result = subprocess.run(
            ["gh", "api", ledger_read_path(repo)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            break
        error_text = result.stderr or result.stdout or ""
        if "HTTP 404" in result.stderr:
            return _read_404(_ledger_branch_exists(repo))
        if budget is not None and _is_retryable_read_error(error_text):
            # Sleeps the shared throttle schedule, or raises LeaseIOError once the bounded budget
            # (or the process-wide ceiling) is spent. Then re-issue the GET.
            budget.note(error_text, operation="read")
            continue
        # The STATUS is quoted — never the raw body, which is the LeaseIOError credential contract.
        # Its absence is what made the live failures unattributable: 23 runs reported only "lease
        # ledger read failed", so a throttle was indistinguishable from a protection change.
        raise LeaseIOError(
            f"lease ledger read failed (HTTP {_error_status(error_text)}) — a refusal or usage "
            "error that cannot clear by waiting")
    try:
        meta = json.loads(result.stdout)
        content = json.loads(base64.b64decode(meta["content"]).decode() or '{"leases":[]}')
        leases = lease_schema.validate_ledger(content)
        sha = meta["sha"]
        if not isinstance(sha, str) or not sha:
            raise ValueError("blob sha is missing")
        return leases, sha
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise LeaseIOError("lease ledger is malformed") from exc


# ---- CAS retry backoff (issue #179) -------------------------------------------------------------
# Every CAS writer against the shared ledger tip (claim, release, reclaim — plus groom-leases and
# model-health on their own crons) previously retried immediately, so a burst that collided once
# stayed phase-locked and re-collided on every one of its six attempts, exhausting them all. An
# exponential, FULLY JITTERED sleep between attempts decorrelates the writers so a loser backs off a
# random amount and the tip has settled by its next read. Split ceiling (deterministic, unit-tested)
# from the random draw so the schedule is asserted without depending on the RNG.
def _backoff_ceiling(attempt, base=0.5, cap=8.0):
    """Upper bound (seconds) for the sleep before CAS retry `attempt` (1-based): exponential
    base*2**(attempt-1), clamped to `cap`."""
    return ledger_retry.backoff_ceiling(attempt, base, cap)


def _backoff_delay(attempt):
    return random.uniform(0, _backoff_ceiling(attempt))


def _sleep_backoff(attempt):
    """Sleep a full-jitter exponential backoff before CAS retry `attempt` (module-level so the
    self-test can stub it without sleeping)."""
    ledger_retry.sleep_backoff(attempt, sleeper=time.sleep, draw=random.uniform)


# ---- throttle / availability CAS-PUT retries (issue #558) ---------------------------------------
# LIVE 2026-07-24T00:21-00:22Z: four concurrent review-fix runs (claims 2baf8dcf / 493adb6a /
# 7f7d4786 / e6f52629) ALL died on _write_ledger's non-conflict raise —
#   "lease ledger CAS PUT failed with a non-conflict error (authorization, validation, missing
#    branch, or availability)"
# — while SIBLING writers landed ledger commits in the very same seconds (aa643bce0 00:22:30,
# f08b0217d 00:22:21, 31f87d685 00:22:18). The branch was healthy and UNPROTECTED, so this was
# never authorization: a BURST of concurrent contents-API PUTs against one branch trips GitHub's
# SECONDARY rate limit, which answers 403 — an authorization-SHAPED status — or a brief 5xx.
# Those clear by waiting, so they are now RETRYABLE alongside the 409-conflict path:
#   * the classifier and the wait schedule are the fleet-shared ones (ledger_retry -> gh_retry,
#     PR #564): bounded 5 attempts, exponential 2s->30s + jitter, capped Retry-After honour —
#     NOT a third retry implementation, and NOT the sub-second contention schedule (a burst
#     limiter blocks for seconds-to-a-minute; re-firing in 0.5s just re-trips it);
#   * genuine 401 / 404 / non-race 422 / permission-403 stay FATAL and fail on the FIRST attempt;
#   * CAS correctness is untouched: a throttle retry goes back through the CALLER's loop, which
#     RE-READS the ledger and RE-DERIVES both the expected blob sha and the payload. Nothing ever
#     replays a stale expected-SHA;
#   * exhaustion still FAILS LOUD (LeaseIOError) — a silently-skipped lease write would let two
#     workers share one credential.
TRANSIENT_WRITE_ATTEMPTS = ledger_retry.TRANSIENT_MAX_ATTEMPTS

# Process-wide ceiling on time spent SLEEPING on throttled ledger writes. The per-transaction budget
# above bounds ONE transaction, but a dispatch fan-out runs one CAS transaction per candidate item:
# if GitHub is throttling all of them, paying the full per-transaction wait on each would turn a
# fast, honest "everything deferred" tick into a 15-minute job TIMEOUT. Once a process has waited
# this long in aggregate, further throttle rejections fail loud IMMEDIATELY — the API is telling us
# to stop, and the next scheduled tick re-reads fresh state anyway.
THROTTLE_WAIT_CEILING_S = 90.0
_throttle_wait = {"spent": 0.0}

# Small pre-write de-synchronization jitter (issue #558 part b). Four review/fix lanes finishing
# within the same second issue their ledger PUTs in the same second — that phase-lock is what trips
# the burst limiter in the first place. A short random delay at the START of each CAS transaction
# spreads the fleet's read-modify-write pairs apart. Deliberately BEFORE the first read, not
# immediately before the PUT: sleeping between the read and the PUT would widen the CAS window and
# manufacture conflicts, while jittering the whole pair costs nothing in correctness.
PRE_WRITE_JITTER_S = 0.5


def _pre_write_jitter(*, sleeper=time.sleep, draw=random.uniform):
    """Sleep a bounded uniform [0, PRE_WRITE_JITTER_S) delay to de-phase concurrent lease writers
    (module-level so the self-test can assert the bounds without sleeping)."""
    sleeper(draw(0, PRE_WRITE_JITTER_S))


def _is_transient_write_error(stderr):
    """True for a NON-conflict PUT failure that can clear by waiting: a secondary/primary
    rate-limit or Retry-After 403, HTTP 429, any 5xx, or a network timeout/reset. Everything else —
    401, 404, non-race 422, permission/credential 403 — is permanent and must fail loud at once
    (retrying a validation error just burns the budget to reach the same failure)."""
    return ledger_retry.is_transient(stderr)


_HTTP_STATUS_RE = re.compile(r"HTTP[ :]*(\d{3})\b|\((\d{3})\)")


def _error_status(stderr):
    """The HTTP status in a gh error, or 'unknown'.

    The ONLY part of a raw API error quoted in a LeaseIOError message: that exception's contract is
    that it never carries credential material, so the raw stderr is never interpolated — only the
    status code, which is what an operator needs to tell a throttle from a protection change.
    """
    match = _HTTP_STATUS_RE.search(stderr or "")
    if match is None:
        return "unknown"
    return match.group(1) or match.group(2)


class TransientWriteBudget:
    """Per-CAS-transaction budget for THROTTLE/AVAILABILITY PUT rejections (issue #558).

    One instance per ledger transaction (claim / adopt / release / reclaim). ``note`` records a
    rejection and sleeps the shared throttle schedule so the caller's loop can re-read and
    re-derive; the ``attempts``-th rejection raises LeaseIOError instead, so a real outage or a
    sustained throttle terminates loudly inside a bounded budget rather than spinning. Kept
    SEPARATE from the conflict budget in both directions: a throttle blip must not consume the
    contention retries, and contention must not consume the throttle budget. Every sleep is also
    charged against the process-wide THROTTLE_WAIT_CEILING_S so a fan-out of transactions cannot
    accumulate into a job timeout.
    """

    def __init__(self, attempts=None, sleep=None):
        self.attempts = TRANSIENT_WRITE_ATTEMPTS if attempts is None else attempts
        self._sleep = ledger_retry.sleep_transient if sleep is None else sleep
        self.rejections = 0

    def note(self, stderr, operation="CAS PUT"):
        """Absorb one transient rejection (sleeping the shared backoff), or fail loud when either
        this transaction's bounded budget or the process-wide throttle-wait ceiling is spent.

        `operation` names the half of the transaction that was rejected — "CAS PUT" or "read"
        (registry #1246). ONE budget still covers both halves, so a transaction cannot spend its
        bounded tolerance twice; only the operator-facing noun changes, and it has to, because
        "CAS PUT" on a throttled GET is the same unattributable message this change removed.
        """
        self.rejections += 1
        if self.rejections >= self.attempts:
            raise LeaseIOError(
                f"lease ledger {operation} kept hitting a transient GitHub failure "
                f"(HTTP {_error_status(stderr)}) through {self.attempts} attempts — a "
                "rate-limit/availability condition that did not clear; failing loud rather than "
                "skipping the lease write")
        if _throttle_wait["spent"] >= THROTTLE_WAIT_CEILING_S:
            raise LeaseIOError(
                f"lease ledger {operation} is still throttled (HTTP {_error_status(stderr)}) and "
                f"this process has spent its {THROTTLE_WAIT_CEILING_S:.0f}s throttle-wait ceiling "
                "— failing loud now instead of stalling the run; the next scheduled tick re-reads "
                "fresh state")
        started = time.monotonic()
        self._sleep(self.rejections, ledger_retry.retry_after_seconds(stderr))
        _throttle_wait["spent"] += max(0.0, time.monotonic() - started)


def _cas_attempts(retries, budget):
    """Zero-based CAS attempt numbers for one ledger transaction.

    `retries` attempts for the contention path, PLUS one extra for every throttle rejection already
    absorbed: a secondary-rate-limit 403 is not contention and must not eat the conflict budget
    (issue #558). Still strictly bounded — the budget itself fails loud on its `attempts`-th
    rejection, so at most ``retries + budget.attempts - 1`` attempts are ever made.
    """
    attempt = 0
    while attempt < retries + budget.rejections:
        yield attempt
        attempt += 1


# GitHub's contents-PUT response when a sha-less (create-if-absent) write hits a file that
# appeared concurrently: HTTP 422 with message 'Invalid request.\n\n"sha" wasn't supplied.'
_CREATE_RACE_SIGNATURE = "\"sha\" wasn't supplied"


def _is_cas_conflict(stderr, create):
    """True only for a genuine compare-and-swap conflict on the ledger PUT. HTTP 409 is always a
    lost-SHA race. HTTP 422 counts ONLY when this was a create-if-absent PUT (`create=True`) AND
    the response carries GitHub's create-race signature — any other 422 is an ordinary request-
    validation failure (bad payload/branch) that must fail loud, not be retried as contention."""
    return ledger_retry.is_cas_conflict(stderr, create=create)


def _write_ledger(repo, leases, sha, message, budget=None):
    """PUT the ledger via CAS. Returns True on success, or False when the caller must RE-READ,
    RE-DERIVE and retry — which happens for exactly two classes:

      * a genuine CAS conflict (HTTP 409, or the create-race 422 on a sha-less PUT): the tip moved;
      * a THROTTLE/AVAILABILITY rejection (secondary/primary rate-limit or Retry-After 403, 429,
        5xx, network timeout/reset) when a `budget` was supplied — GitHub's burst limiter answers
        403, so the pre-#558 classifier read it as authorization and failed loud while sibling
        writers were landing commits in the same seconds. `budget.note` sleeps the shared throttle
        backoff and fails LOUD once its bounded attempts are spent.

    A PERMANENT failure — 401, missing branch/file (404), non-race request validation (422),
    permission/credential 403 — still raises LeaseIOError on the FIRST attempt: it can never clear
    by waiting, and collapsing it into 'CAS kept conflicting' after six wasted attempts is exactly
    what issue #179 removed. `budget=None` (the default, for callers with no retry loop) keeps that
    fail-at-once behaviour for the transient class too, so nothing retries silently.

    The retry is the CALLER's, never this function's: re-deriving the payload needs the caller's
    own decision logic, and replaying this PUT in place would blind-retry a now-stale expected-SHA.
    """
    body = base64.b64encode(json.dumps({"leases": leases}, indent=1).encode()).decode()
    r = subprocess.run(ledger_write_args(repo, message, body, sha), capture_output=True, text=True)
    if r.returncode == 0:
        return True
    error_text = r.stderr or r.stdout or ""
    if _is_cas_conflict(error_text, create=sha is None):
        return False  # lost the CAS race → caller re-reads and retries
    if budget is not None and _is_transient_write_error(error_text):
        # Sleeps, or raises LeaseIOError when the bounded budget is spent. On return the caller
        # re-reads the ledger and re-derives the expected revision before the next PUT.
        budget.note(error_text)
        return False
    raise LeaseIOError(
        f"lease ledger CAS PUT failed with a permanent non-conflict error "
        f"(HTTP {_error_status(error_text)}: authorization, validation, or missing branch) — "
        "failing loud rather than exhausting CAS retries")


def _probe_run(repo, run_id):
    """Live liveness for one registry Actions run (issue #35). Never raises: an API failure is
    ``unknown`` (defer a tick), a 404 is ``dead`` (the run does not exist, so reclaim as before).

    NOTE FOR THE CALLER'S WORKFLOW: this needs `actions: read`. groom-leases.yml declares
    `permissions:` explicitly, so every unlisted scope is `none` — without that grant every probe
    is a 403, every expired lease reads as unproven, and nothing is ever reclaimed until the
    ceiling. That is fail-safe but useless, which is why the grant is part of this change."""
    if run_id is None:
        return "dead"
    result = subprocess.run(
        ["gh", "api", f"repos/{repo}/actions/runs/{run_id}"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        return "dead" if "HTTP 404" in result.stderr else "unknown"
    try:
        return classify_run(json.loads(result.stdout))
    except (TypeError, ValueError, json.JSONDecodeError):
        return "unknown"


def _claim_runs_page(repo, page):
    """One page of review-fix run documents, newest-first — or None when it cannot be read.

    NEVER raises and never distinguishes a 403 from a 404 from a garbage body: every unreadable
    shape becomes None, `claim_liveness_map` stops the walk, the uncorrelated claims stay unknown,
    and unknown reclaims nothing. Failing this read closed (toward NOT reclaiming) is the safe
    direction — it costs one more TTL, where the other direction puts two workers on one account."""
    result = subprocess.run(
        ["gh", "api",
         f"repos/{repo}/actions/workflows/review-fix.yml/runs?per_page=100&page={page}"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        return None
    try:
        document = json.loads(result.stdout)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(document, dict):
        return None
    runs = document.get("workflow_runs")
    return runs if isinstance(runs, list) else None


def _claim_liveness_source(repo, fetch=_claim_runs_page):
    """Claim-id liveness for ONE reclaim transaction: `source(leases) -> lookup or None`.

    `None` — which `plan_renewal` reads as "do not consult a claim source at all" — whenever no row
    in the given ledger has a run-less holder, so an idle ledger and a ledger of ordinary worker
    leases both cost ZERO extra API calls.

    The paged walk runs AT MOST ONCE per transaction, for the same reason `_liveness_probe`
    memoizes the holder-run probe: a CAS retry re-reads the LEDGER (that is the point of the retry)
    but must not re-bill the Actions API for a correlation that cannot meaningfully change in the
    seconds between two attempts. A claim id that the resolved map does not carry — including one
    belonging to a row that only appeared on a later attempt — is simply unknown, and unknown
    reclaims nothing, so the memoization can only ever cost an extra TTL, never a wrong drop."""
    resolved, walked = {}, []

    def source(leases):
        # Scoped to REPAIR holders, not to every run-less holder. Two reasons, and they agree: the
        # correlation source is review-fix.yml's run history, which by construction only ever names
        # `review:`/`fix:` claims (a worker run's name is `worker <repo> claim=...`), so asking it
        # about anything else is a guaranteed miss; and repair leases are exactly the class that
        # has no other reclaim path, because groom.py filters them out of its dead-lease sweep.
        # Worker leases keep their existing owner — groom.py — untouched by this change.
        pending = {lease.get("claim_id") for lease in leases
                   if lease_schema.is_repair_holder(lease.get("holder"))
                   and holder_run_id(lease.get("holder")) is None}
        pending = {claim for claim in pending if isinstance(claim, str)}
        if not pending:
            return None
        if not walked:
            walked.append(True)
            issuances = [value for value in
                         (_lease_epoch(lease, "issued_at") for lease in leases)
                         if value is not None]
            resolved.update(claim_liveness_map(
                pending, min(issuances) if issuances else None,
                lambda page: fetch(repo, page)))
        return resolved.get

    return source


def _liveness_probe(repo, probe=_probe_run):
    """Memoize `probe` for one reclaim transaction, so a CAS retry re-reads the LEDGER (the whole
    point of the retry loop) without re-billing the Actions API for a run it already classified."""
    cache = {}

    def liveness(run_id):
        if run_id not in cache:
            cache[run_id] = probe(repo, run_id)
        return cache[run_id]

    return liveness


def reclaim(repo, now, retries=6, probe=_probe_run, claim_fetch=_claim_runs_page):
    """CAS-groom the ledger so crashed/cancelled workers free their slot while LIVE ones keep it.

    Expired leases are reclaimed as before EXCEPT where the holder's Actions run is provably still
    active, which instead RENEWS the expiry, or unprovable, which HOLDS it on a short grace deadline
    (issue #35 — see `plan_renewal`). A row whose holder names NO run — the dispatcher-minted
    `review:`/`fix:` repair lease — is additionally correlated to its review-fix run BY CLAIM ID and
    dropped as soon as that run has positively concluded, rather than waiting out its TTL (issue
    #1128). Returns a `ReclaimOutcome(reclaimed, renewed, deferred, finished)`, with
    `reclaimed == -1` if the CAS kept CONFLICTING. A permanent non-conflict PUT error
    (auth/validation/branch) raises LeaseIOError rather than masquerading as -1; a
    throttle/availability rejection is retried under its own bounded budget and only then raises
    (issue #558)."""
    budget = TransientWriteBudget()
    _pre_write_jitter()
    liveness = _liveness_probe(repo, probe)
    claim_source = _claim_liveness_source(repo, claim_fetch)
    for attempt in _cas_attempts(retries, budget):
        if attempt:
            _sleep_backoff(attempt)
        leases, sha = _read_ledger(repo, budget)
        # Asked against the ledger revision actually being planned — a retry re-reads because the
        # row set may have changed — while the underlying walk itself is memoized across attempts.
        live, renewed, n, deferred, finished = plan_renewal(
            leases, now, liveness, claim_liveness=claim_source(leases))
        # WRITE ON ANY CHANGE, not just on `n or renewed`: a deferred row's grace hold moves
        # `expires_at` too, and it is only that written field — never the row's presence — that any
        # duplicate-suppression consumer reads. Skipping the PUT here would leave the unproven row
        # expired in the ledger and re-open the double-dispatch on the first flaky probe.
        if live == leases:
            return ReclaimOutcome(0, 0, deferred, 0, len(leases))
        # The historical subject is preserved verbatim in the reclaim-only case, so the ledger
        # branch's commit log stays greppable across this change.
        message = "; ".join(
            part for part in (f"reclaim {n} expired lease(s)" if n else "",
                              f"renew {renewed} live lease(s)" if renewed else "",
                              f"hold {deferred} unproven lease(s)" if deferred else "",
                              f"drop {finished} concluded lease(s)" if finished else "") if part)
        if _write_ledger(repo, live, sha, message, budget):
            return ReclaimOutcome(n, renewed, deferred, finished, len(leases))
    return ReclaimOutcome(-1, 0, 0, 0, 0)


# ---- account catalog + live claim / release ----------------------------------------------------
def _run(args):
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise LeaseIOError("registry account catalog read failed")
    return result


def _parse_account(body):
    d = {"models": [], "max_concurrent_workers": 4}
    for line in (body or "").splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k, v = k.strip(), v.strip()
        if k == "models":
            d["models"] = [x.strip() for x in v.strip("[]").split(",") if x.strip()]
        elif k == "max_concurrent_workers":
            d[k] = int(v) if v.isdigit() else 1
        elif k in ("secret_ref", "provider", "harness", "credential_format"):
            d[k] = v
    return d


KNOWN_ACCOUNT_PROVIDERS = frozenset({"anthropic", "openai"})
KNOWN_CREDENTIAL_FORMATS = frozenset({
    "codex-auth-json",
    "claude-credentials-json",
    "claude-oauth-token",
    "anthropic-api-key",
})
ACCOUNT_ISSUE_TITLE_RE = re.compile(r"acct[0-9]+")
ACCOUNT_SECRET_REF_RE = re.compile(r"[A-Z][A-Z0-9_]*")
# [OPUS-5] The provider -> harness pairing worker.yml enforces at the very last gate before a
# secret is exposed ("claimed model has an unsupported harness"). It is asserted HERE too, at the
# catalog read, so a record that can never route is dropped BEFORE it wins a lease — see
# PROVIDER_HARNESS's use in _account_schema_errors below.
PROVIDER_HARNESS = {"anthropic": "claude", "openai": "codex"}
KNOWN_ACCOUNT_HARNESSES = frozenset(PROVIDER_HARNESS.values())


def _account_schema_errors(account, require_models=True):
    """Return parsed account-schema violations without emitting diagnostics."""
    reasons = []
    handle = account.get("handle")
    if not isinstance(handle, str) or not handle.strip():
        reasons.append("missing handle")
    provider = account.get("provider")
    if provider not in KNOWN_ACCOUNT_PROVIDERS:
        reasons.append("missing provider" if not provider else f"unknown provider {provider!r}")
    credential_format = account.get("credential_format")
    if credential_format not in KNOWN_CREDENTIAL_FORMATS:
        reasons.append("missing credential_format" if not credential_format else
                       f"unknown credential_format {credential_format!r}")
    secret_ref = account.get("secret_ref")
    if not secret_ref:
        reasons.append("missing secret_ref")
    elif ACCOUNT_SECRET_REF_RE.fullmatch(secret_ref) is None:
        reasons.append("unsafe secret_ref")
    if require_models:
        if not account.get("models"):
            reasons.append("missing models")
        # [OPUS-5] `harness` is a REQUIRED routing field of a complete record (live incident
        # 2026-07-26). worker.yml's claim/adopt heredocs fail CLOSED on an empty or missing
        # harness ("dispatcher claim returned an empty or missing harness") because an account
        # must never be routed on metadata it did not declare — but this schema did not require
        # the field, so a legacy harness-less record (acct02, minted before set-up-account.yml
        # started emitting `harness:`) stayed in the live catalog, WON claims, and then died at
        # that boundary AFTER the lease was spent: every claim allocated to it burned a lease and
        # a worker run, and the operator saw a message naming neither the account nor the missing
        # field's origin. Measured: 3/3 sampled "empty or missing harness" worker failures were
        # that one account; 0/9 sampled failures on a harness-declaring account carried it.
        # Requiring it here moves the rejection to the catalog read, where the drop diagnostic
        # already names the handle and the reason and no lease has been taken yet.
        #
        # DELIBERATELY NOT part of the require_models=False structural predicate: that predicate
        # only SELECTS candidate records, and narrowing it would make a harness-less record
        # silently unselected instead of loudly dropped.
        harness = account.get("harness")
        if harness not in KNOWN_ACCOUNT_HARNESSES:
            reasons.append("missing harness" if not harness else f"unknown harness {harness!r}")
        elif provider in PROVIDER_HARNESS and harness != PROVIDER_HARNESS[provider]:
            reasons.append(
                f"harness {harness!r} does not match provider {provider!r} "
                f"(expected {PROVIDER_HARNESS[provider]!r})")
    return reasons


def account_record_schema_errors(handle, body, require_models=True):
    """Parse a body and return its account-record schema violations without diagnostics.

    Keeping this pure lets the reader use it both for structural selection and for the loud
    validation boundary, and lets every writer reject an invalid replacement body before it
    reaches GitHub. ``require_models=False`` is the structural front-matter predicate: the three
    routing/credential fields are sufficient to identify a record even when its title is not an
    ``acctNN`` handle. Full read/write validation additionally requires a usable handle, a model
    list, and a `harness` that both exists and matches the record's provider.
    """
    account = _parse_account(body)
    account["handle"] = handle
    return _account_schema_errors(account, require_models=require_models)


def validate_account_record(handle, body):
    """Validate one complete account body for a write, returning its parsed representation.

    The exception text contains field-level corruption reasons but no credential material.
    """
    reasons = account_record_schema_errors(handle, body)
    if reasons:
        raise LeaseIOError(f"account record schema invalid: {'; '.join(reasons)}")
    account = _parse_account(body)
    account["handle"] = handle.strip()
    return account


def _issue_label_names(issue):
    return {
        label.get("name") for label in issue.get("labels", [])
        if isinstance(label, dict) and isinstance(label.get("name"), str)
    }


def select_account_issues(issues):
    """Structurally select account issues from a broad GitHub issue listing.

    A complete, schema-valid provider/credential/secret front-matter triple selects records with
    nonstandard legacy titles. Dedicated markers select fail-closed records even when that schema
    is corrupt: the exact ``account`` label or the ``acct<digits>`` title grammar. Everything else
    is outside the catalog and is silently ignored rather than parsed-and-dropped as corruption.
    This is the one selector used by dispatch claim and worker claim/adoption via ``read_accounts``;
    workflow-side dry-run validation imports it as well.
    """
    if not isinstance(issues, list):
        raise LeaseIOError("registry account catalog listing is malformed")
    selected = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        title = issue.get("title")
        title = title.strip() if isinstance(title, str) else ""
        marked = (ACCOUNT_ISSUE_TITLE_RE.fullmatch(title) is not None
                  or "account" in _issue_label_names(issue))
        front_matter_valid = not account_record_schema_errors(
            title, issue.get("body"), require_models=False)
        if marked or front_matter_valid:
            selected.append(issue)
    return selected


def _valid_catalog_account(account):
    """Reject selected records with malformed schema at the shared catalog parse boundary."""
    reasons = _account_schema_errors(account)
    if reasons:
        print(f"account catalog: dropping account {account.get('handle')!r}: "
              f"{'; '.join(reasons)}", file=sys.stderr)
        return False
    return True


# [FABLE-5] LEGACY-SHAPE NORMALIZATION (sol r3 f1), read-time only. The retired terra-era broker
# minted every openai account record as exactly `models: [terra]`; the current broker
# (set-up-account.yml) mints the FULL codex alias set. Membership gating in this file is LITERAL,
# so a legacy record that survives (or reappears via an old broker run) could never serve a
# sol/luna claim — starving every anthropic-authored PR review while the account sits available.
# Fix: an openai record whose models list is EXACTLY the legacy fingerprint `[terra]` (nothing
# else) expands, at read time, to the catalog's full codex alias set — the provider=openai aliases
# of orchestration/routing.toml ([models.sol]/[models.luna]/[models.terra]). Any OTHER explicit
# list (an operator-restricted `[terra, luna]` or `[sol]`) is preserved VERBATIM — operator
# customization wins over the expansion. The stored account issue is never mutated: the expansion
# applies to the in-memory catalog inside read_accounts — the single catalog read every membership
# consumer shares (claim selection via claim()/choose_account, dynamic-concurrency accounting in
# dispatch-claim.py, claim adoption via inspect_claim, usage probing via account-usage.py) — and
# each expansion is logged to stderr so it stays visible in dispatch/worker logs. PRIVACY (sol r4,
# locked decision 22a/22b): the registry is PUBLIC and the claim workflows redirect only stdout,
# so this stderr diagnostic lands in public Actions logs — and it runs BEFORE account_pool
# filtering, so a raw handle here could enumerate every legacy account. The diagnostic therefore
# NEVER carries a raw handle: with PROVENANCE_SALT present (every runtime path that reaches
# read_accounts exports it — the review-fix.yml claim/adopt steps, the dispatch.yml claim +
# usage-probe steps, the worker.yml claim step) it emits the provenance-record fingerprint
# sha256(handle + ':' + PROVENANCE_SALT)[:16], the exact worker-pr.py account_hash convention, so
# operators can correlate the line with provenance records; without the salt (self-test, ad-hoc
# CLI — `--reclaim` never reads the catalog) it emits a handle-free count-only line. Either way
# one line fires per expansion, so the expansion count stays visible.
LEGACY_OPENAI_SHAPE = ["terra"]              # the retired broker's exact fingerprint
CODEX_ALIAS_SET = ["sol", "luna", "terra"]   # catalog-derived: routing.toml provider=openai aliases


def _diag_account_ref(handle):
    """Public-log-safe account reference for the normalization diagnostic (locked decision 22a):
    the salted provenance fingerprint sha256(handle + ':' + PROVENANCE_SALT)[:16] — the same
    convention as worker-pr.py account_hash / the provenance records — or a handle-free marker
    when the salt is not in-context. NEVER the raw handle."""
    salt = os.environ.get("PROVENANCE_SALT", "")
    if salt and handle:
        return "hash=" + hashlib.sha256(f"{handle}:{salt}".encode()).hexdigest()[:16]
    return "[account ref withheld: PROVENANCE_SALT unset]"


def normalize_legacy_models(account):
    """Legacy-shape normalization, READ-TIME only: expand an openai record whose models list is
    EXACTLY the legacy `[terra]` broker fingerprint to the full codex alias set. Every other list
    passes through verbatim (operator customization wins). Returns a new dict on expansion and
    never mutates the input; each expansion logs one SALTED-HASH-ONLY line to stderr (visible,
    not silent, never the raw handle — stderr reaches public Actions logs)."""
    if account.get("provider") == "openai" and account.get("models") == LEGACY_OPENAI_SHAPE:
        print(f"legacy-shape normalization: 1 legacy openai record "
              f"{_diag_account_ref(account.get('handle'))} "
              f"models {LEGACY_OPENAI_SHAPE} -> {CODEX_ALIAS_SET} (read-time only; the stored "
              "record is unchanged)", file=sys.stderr)
        return {**account, "models": list(CODEX_ALIAS_SET)}
    return account


# [OPUS-5] The catalog read's page bound, and the reason it needs a truncation guard at all
# (2026-07-29 fleet outage, registry #1131). `gh issue list --limit N` returns the N NEWEST open
# issues and exits 0 — a truncated listing is byte-for-byte indistinguishable from a complete one.
# The account records are the OLDEST open issues in the registry (they are created once, at
# enrolment, and never close), so they sit at the TAIL of that ordering: as the registry's open-issue
# population grew past the bound, the account records fell out of the window one by one and then
# entirely. `read_accounts` returned [] from a rc=0 read, `account-usage.main` measured a fleet of
# zero accounts and exited 0 ("probe-succeeded"), the empty snapshot made `dispatch-claim._load_usage`
# return None, and every `require_usage` repo held fail-closed — a TOTAL fleet stall presenting as a
# healthy probe. The allocator saw the same empty pool, so every review/fix claim also read
# "no eligible lease is free" with zero leases outstanding.
#
# Raising the bound alone only moves the cliff, so the bound is paired with a POSITIVE truncation
# check: a listing that FILLS the page may be truncated, and a catalog we cannot prove complete is
# not a catalog. Fail closed on it — the same LeaseIOError a rc!=0 read raises — rather than hand
# every consumer a silently partial pool. This is the guard `metrics.py` and `model-health.py`
# already apply to their own listings; the catalog read was the one that never got it.
ACCOUNT_CATALOG_LIST_LIMIT = 2000


def read_accounts(repo):
    """The structurally selected account catalog from open issues.

    Non-account issues never reach the drop boundary. Selected records are validated loudly, then
    receive the shared legacy-shape normalization, so dispatch and worker adoption see one pool.

    A listing that fills the page bound cannot be proven complete and raises LeaseIOError — see
    ACCOUNT_CATALOG_LIST_LIMIT. A partial catalog is a silent capacity loss, and an empty one stalls
    the whole fleet; neither may be returned as if it were the fleet.
    """
    out = _run(["gh", "issue", "list", "-R", repo, "--state", "open",
                "--limit", str(ACCOUNT_CATALOG_LIST_LIMIT),
                "--json", "title,body,labels"]).stdout
    listing = json.loads(out or "[]")
    if isinstance(listing, list) and len(listing) >= ACCOUNT_CATALOG_LIST_LIMIT:
        # No count of ACCOUNTS is disclosed (locked decision 22b) — only that the ISSUE listing
        # filled its page, which is a property of the public issue tracker.
        raise LeaseIOError(
            "registry account catalog read may be TRUNCATED: the open-issue listing filled its "
            f"{ACCOUNT_CATALOG_LIST_LIMIT}-row page bound, so the catalog cannot be proven "
            "complete (raise ACCOUNT_CATALOG_LIST_LIMIT or reduce the open-issue population)")
    accounts = []
    for it in select_account_issues(listing):
        a = _parse_account(it.get("body"))
        a["handle"] = it["title"].strip()
        a["available"] = "status:available" in _issue_label_names(it)
        if _valid_catalog_account(a):
            accounts.append(normalize_legacy_models(a))
    return accounts


# ---- routing-catalog consistency audit (issue: cross-repo model skew) --------------------------
# [OPUS-5] THE GENERAL DEFECT behind the 2026-07-26 incident: an account record and the routing
# catalogs that must be able to route it live in DIFFERENT repositories on different merge
# schedules, and nothing compared them. Two failure shapes follow, and both had to be diagnosed
# from a live log capture because no periodic check named the offending pair:
#
#   (a) the record is not routable AT ALL — a required field is missing or contradicts its
#       provider, so the catalog read drops it (or, before this fix, the worker's fail-closed
#       boundary rejected it after a lease was already spent);
#   (b) the record names a model ALIAS that no enabled target's `[models]` catalog defines, or
#       defines with contradictory metadata — so a claim minted on that (account, model) pair dies
#       at worker.yml's "claimed model is missing from protected target routing" / strict routing
#       equality gate, again after the lease is spent.
#
# This audit REPORTS both, naming the offending pairs; it never becomes a new enforcement path.
# The enforcing boundaries stay exactly where they are (policy-resolve rejects an unknown model in
# a chain, the catalog read drops an invalid record, worker.yml re-proves everything before a
# secret is exposed) — a reporter that started failing dispatch would be a new outage surface, and
# the brief for this work explicitly asks for the offending pairs rather than a hard stop.
SKEW_UNKNOWN = "names a model no enabled target routing catalog defines"
SKEW_RETIRED = "names a RETIRED model alias"
SKEW_UNREADABLE = "target routing catalog could not be read"


def _retired_aliases():
    """The shared deprecation register (scripts/deprecated_models.py), IMPORTED rather than
    re-declared — two hand-maintained copies of a deprecation list is exactly how a retired model
    returns in one of them. Lazy: the workflow-side importers of this module load it by path from
    the registry checkout, and the audit is the only caller."""
    from pathlib import Path
    path = Path(__file__).resolve().with_name("deprecated_models.py")
    spec = importlib.util.spec_from_file_location("registry_deprecated_models", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.DEPRECATED_ALIASES


def dropped_account_records(issues):
    """Pure. ``[(handle, [reason, ...]), ...]`` for every SELECTED account record the catalog
    parse boundary rejects — i.e. every account silently absent from the live pool, with the
    reason. Capacity lost this way is otherwise invisible until a claim starves."""
    dropped = []
    for issue in select_account_issues(issues):
        handle = str(issue.get("title") or "").strip()
        reasons = account_record_schema_errors(handle, issue.get("body"))
        if reasons:
            dropped.append((handle, reasons))
    return sorted(dropped)


def routing_catalog_skew(accounts, catalogs, retired_aliases=frozenset(), unreadable=()):
    """Pure. ``[(handle, model, reason), ...]`` for every (account, model alias) pair that no
    supplied routing catalog can route.

    ``catalogs`` is ``{source_label: {alias: {provider, harness, credential_format, ...}}}``.
    ``unreadable`` is the source labels whose catalog could not be read — reported as rows of
    their own so a fetch failure can never be mistaken for "no skew found".
    """
    rows = [("", "", f"{SKEW_UNREADABLE}: {source}") for source in sorted(unreadable)]
    for account in sorted(accounts, key=lambda a: str(a.get("handle"))):
        handle = str(account.get("handle"))
        declared = {field: account.get(field)
                    for field in ("provider", "harness", "credential_format")}
        for model in account.get("models") or []:
            if model in retired_aliases:
                rows.append((handle, model, SKEW_RETIRED))
            hits = {source: table[model] for source, table in sorted(catalogs.items())
                    if isinstance(table, dict) and isinstance(table.get(model), dict)}
            if not hits:
                rows.append((handle, model, SKEW_UNKNOWN))
                continue
            for source, spec in hits.items():
                for field, own in declared.items():
                    routed = spec.get(field)
                    if routed and own and routed != own:
                        rows.append((handle, model,
                                     f"{source} routes it with {field}={routed!r} but the account "
                                     f"record declares {own!r}"))
    return rows


def enabled_policy_targets(policy_text):
    """Pure. ``[(repo, routing_path), ...]`` for every ENABLED target in a repos.toml document."""
    import tomllib
    policy = tomllib.loads(policy_text)
    targets = []
    for repo, row in sorted((policy.get("repos") or {}).items()):
        if isinstance(row, dict) and row.get("enabled") and isinstance(row.get("routing"), str):
            targets.append((repo, row["routing"]))
    return targets


def _fetch_target_routing(repo, path):
    """Read one target's routing.toml at its default branch through the authenticated CLI."""
    return _run(["gh", "api", f"repos/{repo}/contents/{path}",
                 "-H", "Accept: application/vnd.github.raw"]).stdout


def collect_routing_catalogs(targets, fetch=_fetch_target_routing):
    """``({source_label: models_table}, [unreadable_source, ...])`` over enabled targets."""
    import tomllib
    catalogs, unreadable = {}, []
    for repo, path in targets:
        source = f"{repo}:{path}"
        try:
            models = tomllib.loads(fetch(repo, path)).get("models")
        except Exception:                                  # noqa: BLE001 - reported, never raised
            unreadable.append(source)
            continue
        if not isinstance(models, dict):
            unreadable.append(source)
            continue
        catalogs[source] = models
    return catalogs, unreadable


def audit_catalog(repo, policy_text, fetch=_fetch_target_routing, retired_aliases=frozenset(),
                  issues=None):
    """Report account-catalog / target-routing skew. Returns ``(dropped, skew, catalogs)``."""
    if issues is None:
        issues = json.loads(_run(["gh", "issue", "list", "-R", repo, "--state", "open",
                                  "--limit", "500", "--json", "title,body,labels"]).stdout or "[]")
    dropped = dropped_account_records(issues)
    accounts = []
    for issue in select_account_issues(issues):
        account = _parse_account(issue.get("body"))
        account["handle"] = str(issue.get("title") or "").strip()
        if not account_record_schema_errors(account["handle"], issue.get("body")):
            accounts.append(normalize_legacy_models(account))
    catalogs, unreadable = collect_routing_catalogs(enabled_policy_targets(policy_text), fetch)
    skew = routing_catalog_skew(accounts, catalogs, retired_aliases=retired_aliases,
                                unreadable=unreadable)
    return dropped, skew, catalogs


def format_catalog_audit(dropped, skew, catalogs):
    """The operator-facing report, and the audit's ONE output boundary. One line per offending
    pair, each naming what is wrong.

    PRIVACY (locked decision 22a/22b, the same rule the legacy-shape diagnostic ~60 lines above
    obeys): this report is emitted by a 15-minute `groom` cron into logs that are not private, so
    an account is referenced ONLY by its salted provenance fingerprint via `_diag_account_ref` —
    the shared `sha256(handle + ':' + PROVENANCE_SALT)[:16]` convention (worker-pr.py
    account_hash), which operators can correlate with provenance records. A raw handle NEVER
    reaches these lines. "The handles are already enumerable from public issue titles" is an
    argument for changing the policy, not for a new writer deviating from it: this cron would add
    18+ handle mentions per sweep to logs that currently carry none.

    The reference must stay USEFUL as well as safe — an operator has to know WHICH record is
    skewed — so it is a stable, per-handle-distinct fingerprint, not an opaque counter. When the
    salt is absent every reference collapses to one withheld marker, which would silently make the
    report unreadable, so that case says so ONCE, loudly, at the top.
    """
    lines = [f"catalog audit: {len(catalogs)} target routing catalog(s) read: "
             f"{', '.join(sorted(catalogs)) or 'NONE'}"]
    if (dropped or skew) and not os.environ.get("PROVENANCE_SALT", ""):
        lines.append("catalog audit: WARNING — PROVENANCE_SALT is unset, so every account "
                     "reference below is withheld and the rows cannot be told apart; re-run with "
                     "the salt in context to identify the offending records")
    for handle, reasons in dropped:
        lines.append(f"catalog audit: account {_diag_account_ref(handle)} is NOT in the live "
                     f"pool: {'; '.join(reasons)}")
    for handle, model, reason in skew:
        subject = f"account {_diag_account_ref(handle)} model {model!r}" if handle else "policy"
        lines.append(f"catalog audit: {subject} {reason}")
    if not dropped and not skew:
        lines.append("catalog audit: no skew — every live account record is routable by every "
                     "enabled target catalog it names")
    return lines


def claim(repo, package, role, model_chain, holder, now, ttl=3600, retries=6,
          account_pool=None, holder_prefix="", max_holder_concurrent=None, usage=None,
          margin=SAFETY_MARGIN, account_slot_bound=False, return_reason=False):
    """CAS-claim a lease. Returns {account, secret_ref, model, claim_id} or None (none free).
    Raises LeaseIOError when an account WAS eligible but the ledger write kept failing — that is an
    infrastructure failure (persistent CAS contention, or the contents-API PUT rejected outright,
    e.g. by a required-status-check branch protection on the ledger's branch), NOT a capacity
    signal, and must not be reported as 'no eligible account' (issue #28).

    ``account_slot_bound`` makes the live sum of remaining per-account slots the aggregate bound.
    It is used by dispatch fan-out instead of a coarse fleet-wide lease-row constant.  Every item
    still takes its own CAS lease, so the account cap, holder-key duplicate check, and package
    partition remain first-writer-wins.  ``return_reason`` is an observability-only extension:
    existing callers retain the historical claim-or-None return, while the dispatcher receives
    ``(claim, reason)`` and can distinguish capacity from single-flight deferral.
    """
    import uuid

    def result(value, reason=""):
        return (value, reason) if return_reason else value

    budget = TransientWriteBudget()
    _pre_write_jitter()
    accounts = read_accounts(repo)
    if account_pool is not None:
        allowed = set(account_pool)
        accounts = [account for account in accounts if account["handle"] in allowed]
    for attempt in _cas_attempts(retries, budget):
        if attempt:
            _sleep_backoff(attempt)
        leases, sha = _read_ledger(repo, budget)
        live = reclaim_expired(leases, now)
        key = holder_key(holder)
        if key and any(holder_key(lease.get("holder")) == key for lease in live):
            return result(None, "pr-single-flight")
        if holder_prefix and not partition_available(live, holder_prefix, package):
            return result(None, "package-single-flight")
        if max_holder_concurrent is not None:
            if max_holder_concurrent <= 0 or not holder_prefix:
                return result(None, "lane-cap")
            active_holders = sum(
                1 for lease in live if str(lease.get("holder", "")).startswith(holder_prefix)
            )
            if active_holders >= max_holder_concurrent:
                return result(None, "lane-cap")
        if account_slot_bound and available_account_slots(
                accounts, live, model_chain, now, usage=usage, margin=margin) <= 0:
            return result(None, "no-account-slots")
        selected = _choose_account_model(
            accounts, live, model_chain, package, role, now, usage=usage, margin=margin)
        if selected is None:
            return result(None, "no-account-slots")
        a, model = selected
        acct = a["handle"]
        cid = uuid.uuid4().hex
        live, _lease = apply_claim(leases, acct, holder, package, role, model, now, ttl, cid)
        if _write_ledger(repo, live, sha, claim_commit_message(cid, package, role), budget):
            return result({
                "account": acct,
                "secret_ref": a.get("secret_ref"),
                "provider": a.get("provider"),
                "harness": a.get("harness"),
                "credential_format": a.get("credential_format"),
                "model": model,
                "claim_id": cid,
            })
    # Every retry found an eligible account yet the write never landed: an infra failure, not
    # a capacity condition. Raising (vs returning None) keeps the dispatcher's defer reason
    # honest — live incident 2026-07-17: a required `gate` status check added to the default
    # branch rejected every github-actions ledger PUT and every claim in BOTH target repos was
    # mislabeled "duplicate lease, repository cap, or account cap is active" for hours while
    # accounts were healthy and the lease ledger was empty.
    raise LeaseIOError(
        f"lease ledger write kept CONFLICTING after {retries} attempts "
        f"({budget.rejections} throttle rejection(s) absorbed separately) — persistent CAS "
        f"contention, or the {LEDGER_PATH} contents PUT is being rejected (e.g. branch protection "
        "with a required status check on the ledger branch blocks github-actions pushes)")


def inspect_claim(repo, claim_id, now, expected_holder_prefix=""):
    """Return one active lease plus its current account metadata, or None if it is not adoptable."""
    leases, _sha = _read_ledger(repo)
    matches = [
        lease for lease in reclaim_expired(leases, now)
        if lease.get("claim_id") == claim_id
    ]
    if len(matches) != 1:
        return None
    lease = matches[0]
    if expected_holder_prefix and not str(lease.get("holder", "")).startswith(expected_holder_prefix):
        return None
    accounts = [
        account for account in read_accounts(repo)
        if account_fingerprint(account.get("handle")) == lease.get("account")
        and account.get("available")
    ]
    if len(accounts) != 1 or lease.get("model") not in accounts[0].get("models", []):
        return None
    account = accounts[0]
    return {
        **lease,
        "account": account.get("handle"),
        "secret_ref": account.get("secret_ref"),
        "provider": account.get("provider"),
        "harness": account.get("harness"),
        "credential_format": account.get("credential_format"),
    }


def adopt(repo, claim_id, new_holder, now, ttl, expected_holder_prefix="", retries=6):
    """CAS-transfer a dispatcher-owned lease to this worker run — an OWNERSHIP change, not the
    read-only look inspect_claim performs (issue #132).

    Under compare-and-swap it rewrites the matched lease's holder to `new_holder` (the exact worker
    run) and re-bases its expiry to now+ttl, ONCE. It refuses — returning None — when the claim_id
    is expired/gone (reclaim_expired dropped it, so a queued worker cannot resurrect a stale,
    possibly-reallocated slot), when the holder does not start with `expected_holder_prefix` (a
    different issue), or when the lease is already adopted by another worker run (adoptable_holder),
    so no two runs ever share a lease. Returns the transferred lease plus account metadata (exactly
    the shape inspect_claim returned) on success. Raises LeaseIOError when the ledger write kept
    failing — an infrastructure failure that must fail LOUD, never masquerade as not-adoptable
    (mirrors claim()'s issue #28 contract). A throttle/availability rejection is retried under its
    own bounded budget first (issue #558); adopt is idempotent for the SAME holder
    (adoptable_holder), so a retry after an ambiguous transient failure re-adopts cleanly."""
    budget = TransientWriteBudget()
    _pre_write_jitter()
    for attempt in _cas_attempts(retries, budget):
        if attempt:
            _sleep_backoff(attempt)
        leases, sha = _read_ledger(repo, budget)
        live = reclaim_expired(leases, now)
        matches = [lease for lease in live if lease.get("claim_id") == claim_id]
        if len(matches) != 1:
            return None
        lease = matches[0]
        holder = str(lease.get("holder", ""))
        if expected_holder_prefix and not holder.startswith(expected_holder_prefix):
            return None
        if not adoptable_holder(holder, new_holder):
            return None
        accounts = [
            account for account in read_accounts(repo)
            if account_fingerprint(account.get("handle")) == lease.get("account")
            and account.get("available")
        ]
        if len(accounts) != 1 or lease.get("model") not in accounts[0].get("models", []):
            return None
        account = accounts[0]
        transferred = {**lease, "holder": new_holder, "issued_at": now, "expires_at": now + ttl}
        next_leases = [
            transferred if row.get("claim_id") == claim_id else row
            for row in live
        ]
        if _write_ledger(repo, next_leases, sha, f"adopt {claim_id[:8]} -> worker run", budget):
            return {
                **transferred,
                "account": account.get("handle"),
                "secret_ref": account.get("secret_ref"),
                "provider": account.get("provider"),
                "harness": account.get("harness"),
                "credential_format": account.get("credential_format"),
            }
    raise LeaseIOError(
        f"lease ledger adopt CAS write kept CONFLICTING after {retries} attempts "
        f"({budget.rejections} throttle rejection(s) absorbed separately) — persistent CAS "
        f"contention, or the {LEDGER_PATH} contents PUT is being rejected — failing loud rather "
        "than reporting an adoptable claim as not adoptable")


def release(repo, claim_id, now, retries=6):
    """CAS-drop this claim so the slot frees immediately instead of waiting for the TTL.

    Returns True once the claim is absent from the ledger (a write that landed, or a claim already
    gone — release is idempotent), False when the CAS kept conflicting. A throttle/availability
    rejection retries under its own bounded budget and then raises (issue #558: four concurrent
    review-fix lanes releasing in the same second tripped the secondary limiter, so every one of
    them failed its release job and STRANDED a scarce account slot until groom's dead-lease sweep);
    a permanent PUT error still raises at once."""
    budget = TransientWriteBudget()
    _pre_write_jitter()
    for attempt in _cas_attempts(retries, budget):
        if attempt:
            _sleep_backoff(attempt)
        leases, sha = _read_ledger(repo, budget)
        live = apply_release(leases, claim_id, now)
        if len(live) == len(leases):
            return True
        if _write_ledger(repo, live, sha, f"release {claim_id[:8]}", budget):
            return True
    return False


# ---- self-test ----------------------------------------------------------------------------------
def _self_test():
    ok = True
    # Lease identity is unusable without the production salt. A fixed test-only salt makes every
    # allocation assertion exercise the hash-only ledger representation.
    original_selftest_salt = os.environ.get("PROVENANCE_SALT")
    os.environ["PROVENANCE_SALT"] = "select-and-claim-self-test"
    # Every CAS transaction opens with the #558 de-synchronization jitter; the suite must never
    # actually sleep, so it runs against a counting no-op. The REAL function's bounds (and its
    # once-per-transaction, before-the-first-read position) are asserted explicitly further down.
    original_pre_write_jitter = globals()["_pre_write_jitter"]
    jitter_calls = []
    globals()["_pre_write_jitter"] = lambda: jitter_calls.append(1)

    def check(n, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {n}: {got} (want {want})")

    A = [
        {"handle": "acct01", "models": ["terra"], "max_concurrent_workers": 1, "available": True},
        {"handle": "acct02", "models": ["fable", "sonnet", "opus", "haiku"], "max_concurrent_workers": 2, "available": True},
    ]
    now = 1000
    check("route fable", choose_account(A, [], ["fable"], "pkg", "impl", now), "acct02")
    check("route terra", choose_account(A, [], ["terra", "fable"], "pkg", "impl", now), "acct01")
    # Broker-minted openai records (set-up-account.yml) carry the FULL codex alias set
    # [sol, luna, terra]: exact alias membership is what choose_account gates on, so the full
    # set satisfies a sol-led claim while a terra-only LIST at this pure-gate level defers it
    # (sol r2 f1). The gate stays LITERAL by design — it is read_accounts' legacy-shape
    # normalization (sol r3 f1, tested below) that rescues the exact legacy broker fingerprint
    # before it ever reaches this gate; a customized list is never expanded.
    BM = [{"handle": "acct09", "models": ["sol", "luna", "terra"], "max_concurrent_workers": 1,
           "available": True}]
    check("broker openai record [sol, luna, terra] serves a sol claim",
          choose_account(BM, [], ["sol", "luna"], "pkg", "impl", now), "acct09")
    check("un-normalized terra-only list defers a sol claim (the membership gate stays literal)",
          choose_account(A, [], ["sol", "luna"], "pkg", "impl", now), None)

    # ---- read-time legacy-shape normalization (sol r3 f1) ----
    import contextlib
    import io
    from types import SimpleNamespace

    # Pure: ONLY the exact legacy openai `[terra]` fingerprint expands; the input record is
    # never mutated (read-time only, no silent rewrite of the stored account issue).
    legacy_rec = {"handle": "acctL", "provider": "openai", "models": ["terra"]}
    with contextlib.redirect_stderr(io.StringIO()):
        norm_rec = normalize_legacy_models(legacy_rec)
    check("exact legacy [terra] expands to the full codex alias set",
          norm_rec["models"], ["sol", "luna", "terra"])
    check("normalization never mutates the input record", legacy_rec["models"], ["terra"])
    check("customized [terra, luna] preserved verbatim (operator restriction wins)",
          normalize_legacy_models({"handle": "c", "provider": "openai",
                                   "models": ["terra", "luna"]})["models"], ["terra", "luna"])
    check("restricted [sol] preserved verbatim",
          normalize_legacy_models({"handle": "c", "provider": "openai",
                                   "models": ["sol"]})["models"], ["sol"])
    check("broker-minted [sol, luna, terra] passes through unchanged",
          normalize_legacy_models({"handle": "c", "provider": "openai",
                                   "models": ["sol", "luna", "terra"]})["models"],
          ["sol", "luna", "terra"])
    check("non-openai record never expands (provider-scoped fingerprint)",
          normalize_legacy_models({"handle": "c", "provider": "anthropic",
                                   "models": ["terra"]})["models"], ["terra"])

    # End-to-end through the REAL read_accounts (gh issue list stubbed): the expansion is applied
    # at the single catalog read EVERY membership consumer shares, and it is LOGGED (visible) —
    # but SALTED-HASH-ONLY (sol r4, locked decision 22a/22b): stderr reaches public Actions logs
    # and normalization runs before account_pool filtering, so a raw handle here would enumerate
    # every legacy account. Both salt states are exercised, and a NEGATIVE sweep asserts no
    # fixture handle ever reaches the captured stderr/stdout.
    FIXTURE_HANDLES = ("acctL", "acctC")
    issue_rows = json.dumps([
        {"title": "acctL", "body": "provider: openai\nharness: codex\nmodels: [terra]\n"
         "secret_ref: L_TOKEN\ncredential_format: codex-auth-json",
         "labels": [{"name": "status:available"}]},
        {"title": "acctC", "body": "provider: openai\nharness: codex\nmodels: [terra, luna]\n"
         "secret_ref: C_TOKEN\ncredential_format: codex-auth-json",
         "labels": [{"name": "status:available"}]},
    ])
    real_run_fn = globals()["_run"]
    globals()["_run"] = lambda args: SimpleNamespace(stdout=issue_rows)
    saved_salt = os.environ.pop("PROVENANCE_SALT", None)
    os.environ["PROVENANCE_SALT"] = "selftest-salt"
    log_buf, out_buf = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stderr(log_buf), contextlib.redirect_stdout(out_buf):
            norm_cat = read_accounts("o/r")
    finally:
        globals()["_run"] = real_run_fn
        os.environ.pop("PROVENANCE_SALT", None)
    check("read_accounts expands ONLY the exact legacy shape",
          {a["handle"]: a["models"] for a in norm_cat},
          {"acctL": ["sol", "luna", "terra"], "acctC": ["terra", "luna"]})
    # (a) the diagnostic still fires, referencing the account ONLY by its salted provenance
    # fingerprint (the exact worker-pr.py account_hash convention: sha256(h + ':' + salt)[:16]).
    expected_hash = hashlib.sha256(b"acctL:selftest-salt").hexdigest()[:16]
    check("normalization diagnostic fires with the salted hash (no silent expansion)",
          "legacy-shape normalization" in log_buf.getvalue()
          and f"hash={expected_hash}" in log_buf.getvalue(), True)
    check("exactly one expansion line fires (count stays visible)",
          log_buf.getvalue().count("legacy-shape normalization"), 1)
    # (b) NEGATIVE (locked decision 22a): no raw fixture handle — expanded OR pass-through —
    # appears anywhere in the captured stderr/stdout.
    check("NEGATIVE: no raw fixture handle leaks into stderr/stdout",
          [h for h in FIXTURE_HANDLES
           if h in log_buf.getvalue() or h in out_buf.getvalue()], [])
    # Salt-less fallback (self-test / ad-hoc CLI context): the diagnostic still fires as a
    # handle-free count-only line — never falls back to the raw handle.
    globals()["_run"] = lambda args: SimpleNamespace(stdout=issue_rows)
    log_buf2, out_buf2 = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stderr(log_buf2), contextlib.redirect_stdout(out_buf2):
            read_accounts("o/r")
    finally:
        globals()["_run"] = real_run_fn
        if saved_salt is not None:
            os.environ["PROVENANCE_SALT"] = saved_salt
    check("salt-less diagnostic still fires, handle-free (count-only)",
          "legacy-shape normalization" in log_buf2.getvalue()
          and "PROVENANCE_SALT unset" in log_buf2.getvalue(), True)
    check("NEGATIVE: salt-less path leaks no raw fixture handle either",
          [h for h in FIXTURE_HANDLES
           if h in log_buf2.getvalue() or h in out_buf2.getvalue()], [])

    # ---- fail-closed account-catalog parse boundary (issue #424) ----
    # Reproduce the outage alongside healthy rows: the legacy acct01-shaped openai record has no
    # credential_format, while two valid records and two other malformed records share its catalog.
    boundary_rows = json.dumps([
        {"title": "healthy-openai",
         "body": "provider: openai\nharness: codex\nmodels: [sol]\n"
                 "credential_format: codex-auth-json\nsecret_ref: OPENAI_TOKEN",
         "labels": [{"name": "status:available"}]},
        {"title": "healthy-anthropic",
         "body": "provider: anthropic\nharness: claude\nmodels: [fable]\n"
                 "credential_format: claude-credentials-json\nsecret_ref: ANTHROPIC_TOKEN",
         "labels": [{"name": "status:available"}]},
        {"title": "acct01",
         "body": "provider: openai\nharness: codex\nmodels: [terra]\nsecret_ref: ACCT01_TOKEN",
         "labels": [{"name": "status:available"}]},
        {"title": "unknown-provider",
         "body": "provider: legacy\nharness: codex\nmodels: [terra]\n"
                 "credential_format: codex-auth-json\nsecret_ref: LEGACY_TOKEN",
         "labels": [{"name": "account"}, {"name": "status:available"}]},
        {"title": "bad-credential-format",
         "body": "provider: anthropic\nharness: claude\nmodels: [fable]\n"
                 "credential_format: legacy-token\nsecret_ref: BAD_TOKEN",
         "labels": [{"name": "account"}, {"name": "status:available"}]},
        # [OPUS-5] THE 2026-07-26 REGRESSION ROW. Complete in every other field — this record
        # passed the pre-fix schema, entered the live catalog, won claims, and then died in
        # worker.yml's adopt heredoc ("dispatcher claim returned an empty or missing harness")
        # AFTER the lease was spent. It must now be dropped at the read, before any claim.
        {"title": "acct02",
         "body": "provider: anthropic\nmodels: [opus5, sonnet, haiku]\n"
                 "credential_format: claude-oauth-token\nsecret_ref: ACCT02_TOKEN",
         "labels": [{"name": "status:available"}]},
        # A declared-but-wrong harness is the same defect one step later: worker.yml's last gate
        # rejects the (anthropic, codex) pair, so the record can never route either.
        {"title": "acct08",
         "body": "provider: anthropic\nharness: codex\nmodels: [opus5]\n"
                 "credential_format: claude-oauth-token\nsecret_ref: ACCT08_TOKEN",
         "labels": [{"name": "status:available"}]},
    ])
    globals()["_run"] = lambda args: SimpleNamespace(stdout=boundary_rows)
    boundary_log = io.StringIO()
    try:
        with contextlib.redirect_stderr(boundary_log):
            boundary_catalog = read_accounts("o/r")
    finally:
        globals()["_run"] = real_run_fn
    boundary_handles = [account["handle"] for account in boundary_catalog]
    check("valid provider+credential_format rows are kept",
          boundary_handles, ["healthy-openai", "healthy-anthropic"])
    check("missing credential_format is dropped at parse (acct01 outage regression)",
          "acct01" not in boundary_handles, True)
    check("unknown provider is dropped at parse",
          "unknown-provider" not in boundary_handles, True)
    check("out-of-set credential_format is dropped at parse",
          "bad-credential-format" not in boundary_handles, True)
    check("one bad row does not drop healthy rows", len(boundary_catalog), 2)
    check("missing credential_format warning names handle and reason",
          "dropping account 'acct01': missing credential_format" in boundary_log.getvalue(), True)
    check("unknown provider warning names handle and reason",
          "dropping account 'unknown-provider': unknown provider 'legacy'"
          in boundary_log.getvalue(), True)
    check("out-of-set credential_format warning names handle and reason",
          "dropping account 'bad-credential-format': unknown credential_format 'legacy-token'"
          in boundary_log.getvalue(), True)
    check("missing harness is dropped at parse (2026-07-26 acct02 lease-burn regression)",
          "acct02" not in boundary_handles, True)
    check("missing harness warning names handle and reason",
          "dropping account 'acct02': missing harness" in boundary_log.getvalue(), True)
    check("provider/harness mismatch is dropped at parse",
          "acct08" not in boundary_handles, True)
    check("provider/harness mismatch warning names handle, value and expectation",
          "dropping account 'acct08': harness 'codex' does not match provider 'anthropic' "
          "(expected 'claude')" in boundary_log.getvalue(), True)

    # ---- [OPUS-5] catalog-read TRUNCATION guard (registry #1131, the 2026-07-29 fleet outage) ----
    # `gh issue list --limit N` returns the N NEWEST open issues and EXITS 0, so a truncated listing
    # is indistinguishable from a complete one. Account records are the OLDEST open issues in the
    # registry — created once at enrolment, never closed — so a filled page drops precisely them.
    # Measured on the live registry that night: 515 open issues, all 10 account records at
    # created-desc positions 503..514, `--limit 500` selected ZERO of them. read_accounts returned []
    # from a rc=0 read; account-usage exited 0 having measured nothing; every `require_usage` repo
    # held fail-closed and every review/fix claim read "no eligible lease is free" against an empty
    # pool. The bound alone only moves the cliff, so a page we cannot prove complete FAILS CLOSED.
    truncation_row = {
        "title": "healthy-anthropic",
        "body": "provider: anthropic\nharness: claude\nmodels: [fable]\n"
                "credential_format: claude-credentials-json\nsecret_ref: ANTHROPIC_TOKEN",
        "labels": [{"name": "status:available"}]}
    truncation_filler = {"title": "ordinary work item", "body": "no account metadata here",
                         "labels": [{"name": "role:ci"}]}

    def _catalog_read(rows):
        """(raised_LeaseIOError, handles) from a REAL read_accounts over a stubbed listing."""
        globals()["_run"] = lambda args: SimpleNamespace(stdout=json.dumps(rows))
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                return False, [account["handle"] for account in read_accounts("o/r")]
        except LeaseIOError:
            return True, []
        finally:
            globals()["_run"] = real_run_fn

    # A page that FILLS the bound may have dropped the account records: refuse it. Deleting the
    # guard makes this row read (False, []) — the exact silent-empty-catalog shape of the outage.
    check("a catalog listing that FILLS its page bound fails closed, never returns partial",
          _catalog_read([truncation_filler] * ACCOUNT_CATALOG_LIST_LIMIT), (True, []))
    # ...and it must refuse even when the truncated page happens to still contain SOME accounts:
    # a partial catalog is silent capacity loss, which is how this outage began before it completed.
    check("a FILLED page still refuses when it carries some accounts (partial is not complete)",
          _catalog_read([truncation_row]
                        + [truncation_filler] * (ACCOUNT_CATALOG_LIST_LIMIT - 1)), (True, []))
    # NEGATIVE CONTROL: one row short of the bound is provably complete and must parse normally —
    # the guard must not convert every large-but-complete registry into a fleet outage of its own.
    check("a page one row SHORT of the bound is complete and still yields the catalog",
          _catalog_read([truncation_row]
                        + [truncation_filler] * (ACCOUNT_CATALOG_LIST_LIMIT - 2)),
          (False, ["healthy-anthropic"]))
    # The refusal message must not disclose how many ACCOUNTS exist (locked decision 22b); the page
    # bound and the fact the page filled are properties of the PUBLIC issue tracker.
    globals()["_run"] = lambda args: SimpleNamespace(
        stdout=json.dumps([truncation_row] * ACCOUNT_CATALOG_LIST_LIMIT))
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            read_accounts("o/r")
        truncation_message = ""
    except LeaseIOError as exc:
        truncation_message = str(exc)
    finally:
        globals()["_run"] = real_run_fn
    check("the truncation refusal names the condition and discloses no account count",
          ("TRUNCATED" in truncation_message,
           [t for t in ("healthy-anthropic", "ANTHROPIC_TOKEN") if t in truncation_message]),
          (True, []))

    # ---- structural account-issue selection (issue #521 escalation tripwires) ----
    # A broad issue listing is expected: audit/work items live beside account records. Only the
    # shared selector may reduce it. A non-account audit issue is silent; marker-selected corruption
    # stays loud; both dispatcher reads and worker adoption resolve the identical healthy pool.
    mixed_rows = json.dumps([
        {"title": "[sol-audit ledgergate] ordinary work item",
         "body": "The dispatcher and worker policy pools need an audit.\nNo account metadata here.",
         "labels": [{"name": "role:ci"}]},
        {"title": "acct21",
         "body": "provider: openai\nharness: codex\nmodels: [sol]\n"
                 "credential_format: codex-auth-json\nsecret_ref: ACCT21_TOKEN",
         "labels": [{"name": "status:available"}]},
        {"title": "named-anthropic",
         "body": "provider: anthropic\nharness: claude\nmodels: [opus]\n"
                 "credential_format: claude-oauth-token\nsecret_ref: NAMED_ANTHROPIC_TOKEN",
         "labels": [{"name": "status:available"}]},
        {"title": "acct22",
         "body": "provider: openai\nharness: codex\nmodels: [sol]\n"
                 "credential_format: codex-auth-json",
         "labels": [{"name": "status:available"}]},
        {"title": "explicitly-marked-corrupt",
         "body": "provider: retired\nmodels: [opus]\n"
                 "credential_format: claude-oauth-token\nsecret_ref: RETIRED_TOKEN",
         "labels": [{"name": "account"}, {"name": "status:available"}]},
        # [OPUS-5] QUANTIFIER ROW for the harness requirement: a NONSTANDARD-titled, UNLABELLED
        # record — selected ONLY by its complete provider/credential/secret front matter — that is
        # missing `harness`. It must be SELECTED and then dropped LOUDLY. If the harness check ever
        # migrates into the require_models=False structural predicate, this record stops being
        # selected at all and vanishes SILENTLY from the catalog with no drop line, which is
        # strictly worse than the outage being fixed (a mutation that deletes the `require_models:`
        # scoping leaves every other assertion here green — this row is what kills it).
        {"title": "legacy-nonstandard-title",
         "body": "provider: anthropic\nmodels: [opus5]\n"
                 "credential_format: claude-oauth-token\nsecret_ref: LEGACY_NS_TOKEN",
         "labels": [{"name": "status:available"}]},
    ])
    globals()["_run"] = lambda args: SimpleNamespace(stdout=mixed_rows)
    mixed_log = io.StringIO()
    try:
        with contextlib.redirect_stderr(mixed_log):
            dispatcher_pool = read_accounts("o/r")
    finally:
        globals()["_run"] = real_run_fn
    check("structural select: audit issue is not a candidate",
          [account["handle"] for account in dispatcher_pool],
          ["acct21", "named-anthropic"])
    check("structural select: non-account audit issue produces no drop line",
          "sol-audit ledgergate" in mixed_log.getvalue(), False)
    check("structural select: acctNN-selected corrupt record still drops loudly",
          "dropping account 'acct22': missing secret_ref" in mixed_log.getvalue(), True)
    check("structural select: account-label-selected corrupt record still drops loudly",
          "dropping account 'explicitly-marked-corrupt': unknown provider 'retired'"
          in mixed_log.getvalue(), True)
    check("structural select: a harness-less FRONT-MATTER-selected record drops LOUDLY, "
          "never silently unselected",
          "dropping account 'legacy-nonstandard-title': missing harness"
          in mixed_log.getvalue(), True)

    mixed_leases = []
    mixed_claims = {}
    for index, account in enumerate(dispatcher_pool):
        claim_id = f"MIXED{index}"
        lease = make_lease(account["handle"], "o/r#21@dispatch.1", "p", "impl",
                           account["models"][0], now, 100)
        lease["claim_id"] = claim_id
        mixed_leases.append(lease)
        mixed_claims[account["handle"]] = claim_id
    saved_mixed_ledger = globals()["_read_ledger"]
    globals()["_run"] = lambda args: SimpleNamespace(stdout=mixed_rows)
    globals()["_read_ledger"] = lambda repo, budget=None: (mixed_leases, "sha0")
    worker_pool = []
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            for account in dispatcher_pool:
                if inspect_claim("o/r", mixed_claims[account["handle"]], now,
                                 expected_holder_prefix="o/r#21@"):
                    worker_pool.append(account["handle"])
    finally:
        globals()["_run"] = real_run_fn
        globals()["_read_ledger"] = saved_mixed_ledger
    check("structural select: dispatcher and worker adoption resolve the same mixed-fixture pool",
          worker_pool, [account["handle"] for account in dispatcher_pool])

    valid_write_body = ("provider: openai\nharness: codex\nmodels: [sol]\n"
                        "credential_format: codex-auth-json\nsecret_ref: ACCT23_TOKEN")
    check("account write guard accepts a schema-valid record",
          validate_account_record("acct23", valid_write_body)["secret_ref"], "ACCT23_TOKEN")
    try:
        validate_account_record(
            "acct23", "provider: openai\nharness: codex\nmodels: [sol]\n"
                      "credential_format: codex-auth-json")
        check("account write guard rejects an invalid record before persistence",
              "no exception", "LeaseIOError")
    except LeaseIOError as exc:
        check("account write guard rejects an invalid record before persistence",
              (type(exc).__name__, "missing secret_ref" in str(exc)), ("LeaseIOError", True))
    # [OPUS-5] The WRITE half of the harness requirement: the broker (set-up-account.yml) already
    # derives `harness` from the provider, so a body that omits it can only come from a legacy or
    # hand-edited record — exactly the acct02 shape that burned leases on 2026-07-26. Rejecting it
    # at the write boundary stops the class from being re-minted.
    try:
        validate_account_record(
            "acct24", "provider: anthropic\nmodels: [opus5]\n"
                      "credential_format: claude-oauth-token\nsecret_ref: ACCT24_TOKEN")
        check("account write guard rejects a harness-less record (acct02 regression)",
              "no exception", "LeaseIOError")
    except LeaseIOError as exc:
        check("account write guard rejects a harness-less record (acct02 regression)",
              (type(exc).__name__, "missing harness" in str(exc)), ("LeaseIOError", True))
    try:
        validate_account_record(
            "acct25", "provider: anthropic\nharness: codex\nmodels: [opus5]\n"
                      "credential_format: claude-oauth-token\nsecret_ref: ACCT25_TOKEN")
        check("account write guard rejects a provider/harness mismatch",
              "no exception", "LeaseIOError")
    except LeaseIOError as exc:
        check("account write guard rejects a provider/harness mismatch",
              (type(exc).__name__,
               "harness 'codex' does not match provider 'anthropic'" in str(exc)),
              ("LeaseIOError", True))

    # CLAIM SELECTION: a legacy [terra] record now serves a sol-led claim end-to-end (claim()
    # reads the catalog through read_accounts), while a customized [terra, luna] record still
    # does NOT serve a sol-only chain.
    saved_rl, saved_wl = globals()["_read_ledger"], globals()["_write_ledger"]
    globals()["_run"] = lambda args: SimpleNamespace(stdout=issue_rows)
    globals()["_read_ledger"] = lambda repo, budget=None: ([], "sha0")
    globals()["_write_ledger"] = lambda repo, leases, sha, msg, budget=None: True
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            legacy_claim = claim("o/r", "p", "review", ["sol", "luna"],
                                 "review:o/r#1@run", now)
            customized_claim = claim("o/r", "p", "review", ["sol"], "review:o/r#2@run", now,
                                     account_pool=["acctC"])
    finally:
        globals()["_run"] = real_run_fn
        globals()["_read_ledger"], globals()["_write_ledger"] = saved_rl, saved_wl
    check("legacy [terra] record serves a sol claim (read-time expansion)",
          (legacy_claim and legacy_claim["account"], legacy_claim and legacy_claim["model"]),
          ("acctL", "sol"))
    check("fresh claim returns the plain account handle",
          legacy_claim and legacy_claim["account"], "acctL")
    check("customized [terra, luna] does NOT serve a sol-only claim", customized_claim, None)

    # ---- ROUTING-CATALOG CONSISTENCY AUDIT (the general defect behind the 2026-07-26 incident) --
    # An account record and the catalogs that must be able to route it live in different repos on
    # different merge schedules. These rows pin the four skew shapes plus the two ways an audit can
    # lie: reading an empty union as "clean", and swallowing a fetch failure.
    audit_issues = [
        {"title": "not-an-account", "body": "just a work item\n", "labels": [{"name": "role:ci"}]},
        {"title": "acct30",
         "body": "provider: anthropic\nharness: claude\nmodels: [opus5, ghost, fable]\n"
                 "credential_format: claude-oauth-token\nsecret_ref: ACCT30_TOKEN",
         "labels": [{"name": "status:available"}]},
        {"title": "acct31",   # the acct02 shape: complete except `harness`
         "body": "provider: anthropic\nmodels: [opus5]\n"
                 "credential_format: claude-oauth-token\nsecret_ref: ACCT31_TOKEN",
         "labels": [{"name": "status:available"}]},
    ]
    check("audit: a harness-less record is reported as NOT in the live pool, with the reason",
          dropped_account_records(audit_issues), [("acct31", ["missing harness"])])
    check("audit: a healthy record and a non-account issue produce no dropped row",
          [handle for handle, _ in dropped_account_records(audit_issues[:2])], [])

    ANTH = {"provider": "anthropic", "harness": "claude",
            "credential_format": "claude-oauth-token"}
    acct30 = {"handle": "acct30", "models": ["opus5", "ghost", "fable"], **ANTH}
    two_catalogs = {"a/a:r.toml": {"opus5": dict(ANTH)},
                    "b/b:r.toml": {"opus5": dict(ANTH), "fable": dict(ANTH)}}
    skew = routing_catalog_skew([acct30], two_catalogs, retired_aliases=frozenset({"fable"}))
    check("audit: an alias NO catalog defines is reported, naming the account and the model",
          [(h, m) for h, m, r in skew if r == SKEW_UNKNOWN], [("acct30", "ghost")])
    check("audit: an alias only ONE catalog defines is NOT reported unknown (union, not "
          "intersection)",
          [(h, m) for h, m, r in skew if r == SKEW_UNKNOWN and m == "fable"], [])
    check("audit: a RETIRED alias is reported even while a catalog still defines it",
          [(h, m) for h, m, r in skew if r == SKEW_RETIRED], [("acct30", "fable")])
    check("audit: a routable, current alias produces no row", [r for h, m, r in skew if m == "opus5"], [])
    disagree = routing_catalog_skew(
        [acct30], {"a/a:r.toml": {"opus5": {**ANTH, "harness": "codex"}}})
    check("audit: a catalog whose metadata contradicts the record is reported with source, "
          "field and BOTH values",
          [r for h, m, r in disagree if m == "opus5"],
          ["a/a:r.toml routes it with harness='codex' but the account record declares 'claude'"])
    check("audit: an UNREADABLE catalog is a row of its own (a fetch failure can never read as "
          "'no skew')",
          routing_catalog_skew([], {}, unreadable=["c/c:r.toml"]),
          [("", "", f"{SKEW_UNREADABLE}: c/c:r.toml")])
    check("audit: a fully routable pool reports nothing",
          routing_catalog_skew([{"handle": "acct32", "models": ["opus5"], **ANTH}],
                               {"a/a:r.toml": {"opus5": dict(ANTH)}}), [])

    audit_policy = ('[repos."o/enabled"]\nenabled = true\nrouting = "r/one.toml"\n\n'
                    '[repos."o/disabled"]\nenabled = false\nrouting = "r/two.toml"\n')
    check("audit: only ENABLED targets contribute a routing catalog",
          enabled_policy_targets(audit_policy), [("o/enabled", "r/one.toml")])
    bad_catalogs, bad_unreadable = collect_routing_catalogs(
        [("o/a", "r.toml"), ("o/b", "r.toml"), ("o/c", "r.toml")],
        fetch=lambda repo, path: {
            "o/a": '[models.opus5]\nprovider = "anthropic"\n',
            "o/b": "this is not toml {{{",
            "o/c": '[defaults]\nagent = "x"\n',        # parses, but has no [models] table
        }[repo])
    check("audit: an unparseable or models-less target catalog is REPORTED unreadable, "
          "not raised and not silently empty",
          (sorted(bad_catalogs), bad_unreadable),
          (["o/a:r.toml"], ["o/b:r.toml", "o/c:r.toml"]))
    e2e_dropped, e2e_skew, e2e_catalogs = audit_catalog(
        "o/r", audit_policy, issues=audit_issues,
        fetch=lambda repo, path: '[models.opus5]\nprovider = "anthropic"\nharness = "claude"\n',
        retired_aliases=frozenset({"fable"}))
    check("audit end-to-end: the harness-less record is dropped and the skew rows name the pairs",
          (e2e_dropped, sorted({(h, m) for h, m, _ in e2e_skew}), sorted(e2e_catalogs)),
          ([("acct31", ["missing harness"])], [("acct30", "fable"), ("acct30", "ghost")],
           ["o/enabled:r/one.toml"]))
    AUDIT_HANDLES = ("acct30", "acct31")
    e2e_report = format_catalog_audit(e2e_dropped, e2e_skew, e2e_catalogs)
    ref30, ref31 = _diag_account_ref("acct30"), _diag_account_ref("acct31")
    check("audit report names every offending pair on its own line",
          [line for line in e2e_report
           if f"{ref30} model 'ghost'" in line or f"{ref31} is NOT in the live pool" in line],
          [f"catalog audit: account {ref31} is NOT in the live pool: missing harness",
           f"catalog audit: account {ref30} model 'ghost' {SKEW_UNKNOWN}"])
    check("audit report says 'no skew' ONLY when there is none",
          ["no skew" in " ".join(format_catalog_audit([], [], {"a": {}})),
           "no skew" in " ".join(e2e_report)],
          [True, False])

    # ---- PRIVACY (locked decision 22a/22b): the audit report is emitted by a 15-minute cron into
    # logs that are not private. NEGATIVE assertion in the same shape as the legacy-shape
    # normalization rows above: NO raw account handle may appear ANYWHERE in the report, and the
    # salted reference must still be USEFUL — per-handle distinct and stable — or the operator
    # cannot tell which record is skewed. Reverting the report to `{handle!r}` turns the first row
    # red; replacing the fingerprint with an opaque counter turns the distinct/stable rows red.
    check("PRIVACY NEGATIVE: no raw account handle appears anywhere in the audit report",
          [h for h in AUDIT_HANDLES if h in " ".join(e2e_report)], [])
    check("PRIVACY: the audit reference is the shared salted provenance fingerprint",
          ref30, "hash=" + hashlib.sha256(
              f"acct30:{os.environ['PROVENANCE_SALT']}".encode()).hexdigest()[:16])
    check("PRIVACY: distinct accounts get DISTINCT references (the report stays usable)",
          ref30 != ref31, True)
    check("PRIVACY: the same account gets a STABLE reference across rows and sweeps",
          _diag_account_ref("acct30"), ref30)
    salt_held = os.environ.pop("PROVENANCE_SALT", None)
    try:
        withheld_report = format_catalog_audit(e2e_dropped, e2e_skew, e2e_catalogs)
        clean_saltless = format_catalog_audit([], [], {"a": {}})
    finally:
        if salt_held is not None:
            os.environ["PROVENANCE_SALT"] = salt_held
    check("PRIVACY: a salt-less run withholds the reference rather than falling back to the handle",
          ([h for h in AUDIT_HANDLES if h in " ".join(withheld_report)],
           "PROVENANCE_SALT unset" in " ".join(withheld_report)), ([], True))
    check("PRIVACY: a salt-less run SAYS the rows cannot be told apart (never silently "
          "unreadable)",
          sum(1 for line in withheld_report if "PROVENANCE_SALT is unset" in line), 1)
    check("PRIVACY: a salt-less run with NOTHING to report adds no spurious warning",
          [line for line in clean_saltless if "PROVENANCE_SALT is unset" in line], [])

    # The CLI contract, driven through main() exactly as groom.yml drives it: the default REPORTS
    # (exit 0 — a skew row must never take the sweep down), and the opt-in gate mode exits
    # non-zero. Both are asserted on the SAME skewed input, so neither can pass by accident.
    import tempfile
    from pathlib import Path as _CliPath

    def _audit_cli(extra_argv, issues_json, routing_toml):
        def fake_run(args):
            if "issue" in args:
                return SimpleNamespace(stdout=issues_json)
            return SimpleNamespace(stdout=routing_toml)
        saved_run, saved_argv = globals()["_run"], sys.argv
        with tempfile.TemporaryDirectory() as cli_td:
            policy_path = _CliPath(cli_td) / "repos.toml"
            policy_path.write_text(audit_policy, encoding="utf-8")
            globals()["_run"] = fake_run
            sys.argv = ["select-and-claim.py", "--audit-catalog", "--policy-file",
                        str(policy_path), *extra_argv]
            buf, err_buf = io.StringIO(), io.StringIO()
            try:
                # BOTH streams: the groom step's stderr lands in the same log as its stdout, so a
                # handle leaked on stderr is exactly as exposed as one on stdout.
                with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err_buf):
                    rc = main()
            finally:
                globals()["_run"] = saved_run
                sys.argv = saved_argv
        return rc, buf.getvalue() + err_buf.getvalue()

    skewed_json = json.dumps(audit_issues)
    clean_toml = '[models.opus5]\nprovider = "anthropic"\nharness = "claude"\n'
    rc_report, report_text = _audit_cli([], skewed_json, clean_toml)
    check("audit CLI: the default REPORTS skew and still exits 0 (never takes the sweep down)",
          (rc_report, f"{ref30} model 'ghost'" in report_text,
           f"{ref31} is NOT in the live pool" in report_text), (0, True, True))
    # The leak test that matters is over the WHOLE pipeline's real output — the exact bytes the
    # groom step writes, stdout AND stderr — not just the formatter's return value.
    check("PRIVACY NEGATIVE: no raw account handle reaches the audit CLI's real stdout/stderr",
          [h for h in AUDIT_HANDLES if h in report_text], [])
    rc_gate, _ = _audit_cli(["--fail-on-skew"], skewed_json, clean_toml)
    check("audit CLI: --fail-on-skew exits non-zero on the SAME skewed input",
          rc_gate, 1)
    rc_clean, clean_text = _audit_cli(
        ["--fail-on-skew"],
        json.dumps([{"title": "acct33",
                     "body": "provider: anthropic\nharness: claude\nmodels: [opus5]\n"
                             "credential_format: claude-oauth-token\nsecret_ref: ACCT33_TOKEN",
                     "labels": [{"name": "status:available"}]}]),
        clean_toml)
    check("audit CLI: --fail-on-skew exits 0 on a clean pool (the gate mode is not always-red)",
          (rc_clean, "no skew" in clean_text), (0, True))
    rc_unreadable, unreadable_text = _audit_cli(["--fail-on-skew"], skewed_json, "not toml {{{")
    check("audit CLI: --fail-on-skew fails CLOSED when a target catalog cannot be read",
          (rc_unreadable, SKEW_UNREADABLE in unreadable_text), (1, True))
    saved_argv = sys.argv
    try:
        sys.argv = ["select-and-claim.py", "--audit-catalog"]
        with contextlib.redirect_stderr(io.StringIO()):
            rc_no_policy = main()
    finally:
        sys.argv = saved_argv
    check("audit CLI: --audit-catalog without --policy-file is a usage error, not a silent pass",
          rc_no_policy, 2)

    # ---- THE YAML SEAM for the audit (measured repo lesson: every uncaught mutant lives here).
    # A pure function nothing CALLS is a vacuous guard, and `if: false` / a renamed flag / a
    # dropped call site are all invisible to the Python assertions above. Assert the wiring
    # STRUCTURALLY against the parsed workflow, and fail CLOSED if the workflow, the job, or the
    # step cannot be found — "zero steps matched" must never read as a pass.
    try:
        import yaml  # lazy, self-test only: a hard self-test-suite dependency already
        from pathlib import Path as _Path
        groom_path = (_Path(__file__).resolve().parent.parent / ".github" / "workflows" / "groom.yml")
        groom_doc = yaml.safe_load(groom_path.read_text(encoding="utf-8"))
        groom_jobs = groom_doc.get("jobs") or {}
        audit_steps = [(job_name, job, step)
                       for job_name, job in groom_jobs.items()
                       for step in (job.get("steps") or [])
                       if "--audit-catalog" in str(step.get("run", ""))]
        check("YAML seam: groom.yml has exactly one step invoking --audit-catalog",
              len(audit_steps), 1)
        seam_job_name, seam_job, seam_step = audit_steps[0]
        check("YAML seam: the audit step runs THIS script with the policy file",
              ("scripts/select-and-claim.py" in seam_step["run"],
               "--policy-file policy/repos.toml" in seam_step["run"]),
              (True, True))
        # Privacy + usefulness at the SEAM: without PROVENANCE_SALT in the step env every account
        # reference collapses to one withheld marker, so the report is safe but useless. Dropping
        # the env line is invisible to every Python assertion above.
        check("YAML seam: the audit step is given PROVENANCE_SALT (or its rows cannot be told "
              "apart)",
              "PROVENANCE_SALT" in (seam_step.get("env") or {}), True)
        # `if: false` (or any literal-false condition) on the step or its job silently un-wires the
        # audit while every substring assertion above stays green. Only an ABSENT condition passes.
        check("YAML seam: neither the audit step nor its job is if:-disabled",
              ("if" in seam_step, "if" in seam_job), (False, False))
        check("YAML seam: the audit step is not conditioned away by a job-level skip",
              (seam_job_name in groom_jobs, bool(seam_job.get("steps"))), (True, True))
    except Exception as exc:                       # noqa: BLE001 - fail CLOSED, never skip
        check(f"YAML seam: groom.yml audit wiring is inspectable ({type(exc).__name__}: {exc})",
              False, True)

    # DYNAMIC-CONCURRENCY ACCOUNTING: dispatch-claim.py feeds read_accounts output straight into
    # dynamic_concurrency, so the normalized legacy record counts capacity for a sol chain
    # (openai accounts are probe-exempt) while the customized record does not.
    # [#639] the probe stamps reachability on every exempt entry; a fixture without it is
    # ineligible by design, so the accounting rows below would pass for the wrong reason.
    exempt_live = {"exempt": True, "reachability": USAGE_REACHABILITY_LIVE}
    exempt_usage = {"acctL": dict(exempt_live), "acctC": dict(exempt_live)}
    check("dynamic concurrency counts the normalized legacy record for a sol chain",
          dynamic_concurrency(norm_cat, exempt_usage, ["sol"], now=now), 4)

    # CLAIM ADOPTION: a sol lease held on the legacy account is adoptable — inspect_claim's
    # model-membership check reads the SAME normalized catalog.
    sol_lease = {**make_lease("acctL", "o/r#1@run", "p", "impl", "sol", now, 100),
                 "claim_id": "CIDL"}
    globals()["_run"] = lambda args: SimpleNamespace(stdout=issue_rows)
    globals()["_read_ledger"] = lambda repo, budget=None: ([sol_lease], "sha0")
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            adopted = inspect_claim("o/r", "CIDL", now)
    finally:
        globals()["_run"] = real_run_fn
        globals()["_read_ledger"] = saved_rl
    check("sol lease on a legacy [terra] record is adoptable (adoption path normalized)",
          adopted and adopted.get("secret_ref"), "L_TOKEN")
    check("inspect_claim returns the plain account handle",
          adopted and adopted.get("account"), "acctL")

    # ---- CAS adopt: ownership TRANSFER, not a read-only inspect (issue #132) ----
    # adoptable_holder pure gate: a dispatcher-marked holder transfers; a DIFFERENT worker run is
    # refused (two runs can never both adopt); the exact same worker run re-adopts idempotently
    # (revalidation/heartbeat); a garbage/holderless value is refused.
    WORKER_HOLDER = "o/r#7@run9.1"
    check("adoptable: a dispatcher-held lease is adoptable",
          adoptable_holder("o/r#7@dispatch-42.1", WORKER_HOLDER), True)
    check("adoptable: another worker run is NOT adoptable (already adopted elsewhere)",
          adoptable_holder("o/r#7@run8.1", WORKER_HOLDER), False)
    check("adoptable: the exact same worker run re-adopts (idempotent revalidation)",
          adoptable_holder(WORKER_HOLDER, WORKER_HOLDER), True)
    check("adoptable: a garbage/holderless value is refused",
          adoptable_holder("no-at-marker", WORKER_HOLDER), False)

    # End-to-end adopt through a stubbed ledger. The holder is CAS-rewritten to the worker run and
    # the expiry is RE-BASED to now+ttl — a read-only inspect would leave both unchanged, so these
    # assertions flip red if adopt ever regresses to an inspect. Metadata mirrors inspect_claim.
    # Issued 500s ago with a still-LIVE 3600s ttl (expires now+3100), so the adopt re-base to
    # now+3600 is observably different from the dispatcher's original expiry.
    disp_lease = {**make_lease("acctL", "o/r#7@dispatch-42.1", "p", "impl", "sol", now - 500, 3600),
                  "claim_id": "ADOPTCID"}
    adopt_writes = {}

    def _capture_adopt_write(repo, leases, sha, msg, budget=None):
        adopt_writes["leases"] = leases
        adopt_writes["msg"] = msg
        return True

    globals()["_run"] = lambda args: SimpleNamespace(stdout=issue_rows)
    globals()["_read_ledger"] = lambda repo, budget=None: ([dict(disp_lease)], "sha0")
    globals()["_write_ledger"] = _capture_adopt_write
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            adopted_lease = adopt("o/r", "ADOPTCID", WORKER_HOLDER, now, 3600,
                                  expected_holder_prefix="o/r#7@")
    finally:
        globals()["_run"] = real_run_fn
        globals()["_read_ledger"], globals()["_write_ledger"] = saved_rl, saved_wl
    check("adopt transfers the holder to the exact worker run (CAS write, not inspect)",
          adopted_lease and adopted_lease["holder"], WORKER_HOLDER)
    check("adopt re-bases expiry to now+ttl (refreshes the lease for the worker's full run)",
          adopted_lease and adopted_lease["expires_at"], now + 3600)
    check("adopt returns the account secret_ref (metadata shape like inspect_claim)",
          adopted_lease and adopted_lease.get("secret_ref"), "L_TOKEN")
    check("adopt returns the plain account handle",
          adopted_lease and adopted_lease.get("account"), "acctL")
    expected_handle, account_pool = "acctL", ["acctL", "acctC"]
    check("adopted claim passes the worker's exact account policy check",
          (adopted_lease and adopted_lease.get("account") == expected_handle
           and adopted_lease.get("account") in account_pool), True)
    check("adopt persisted exactly the transferred holder to the ledger",
          [row["holder"] for row in adopt_writes.get("leases", [])], [WORKER_HOLDER])
    check("adopt keeps the salted account fingerprint in the persisted ledger",
          [row["account"] for row in adopt_writes.get("leases", [])],
          [account_fingerprint("acctL")])
    check("adopt preserves the stable holder_key (same target issue across the transfer)",
          holder_key(adopted_lease["holder"]), "o/r#7")

    # rejects already-adopted: a lease already held by ANOTHER worker run is refused, and the
    # ledger is never written (no CAS write is even attempted).
    other_adopted = {**disp_lease, "holder": "o/r#7@run8.1"}
    write_called = {"hit": False}

    def _forbid_write(repo, leases, sha, msg, budget=None):
        write_called["hit"] = True
        return True

    globals()["_run"] = lambda args: SimpleNamespace(stdout=issue_rows)
    globals()["_read_ledger"] = lambda repo, budget=None: ([dict(other_adopted)], "sha0")
    globals()["_write_ledger"] = _forbid_write
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            reject_adopted = adopt("o/r", "ADOPTCID", WORKER_HOLDER, now, 3600,
                                   expected_holder_prefix="o/r#7@")
    finally:
        globals()["_run"] = real_run_fn
        globals()["_read_ledger"], globals()["_write_ledger"] = saved_rl, saved_wl
    check("adopt REJECTS a claim already adopted by another worker run", reject_adopted, None)
    check("adopt never writes the ledger when it rejects (no lease stolen)",
          write_called["hit"], False)

    # a queued worker whose dispatcher lease has EXPIRED (reclaim_expired drops it) finds no match
    # and is refused — it cannot resurrect a stale, possibly-reallocated slot.
    expired_lease = {**disp_lease, "expires_at": now - 1}
    globals()["_run"] = lambda args: SimpleNamespace(stdout=issue_rows)
    globals()["_read_ledger"] = lambda repo, budget=None: ([dict(expired_lease)], "sha0")
    globals()["_write_ledger"] = lambda repo, leases, sha, msg, budget=None: True
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            reject_expired = adopt("o/r", "ADOPTCID", WORKER_HOLDER, now, 3600,
                                   expected_holder_prefix="o/r#7@")
    finally:
        globals()["_run"] = real_run_fn
        globals()["_read_ledger"], globals()["_write_ledger"] = saved_rl, saved_wl
    check("adopt refuses an EXPIRED dispatcher lease (no resurrection after reallocation)",
          reject_expired, None)

    # the claim_id exists but belongs to a DIFFERENT issue -> refused on the holder prefix.
    globals()["_run"] = lambda args: SimpleNamespace(stdout=issue_rows)
    globals()["_read_ledger"] = lambda repo, budget=None: ([dict(disp_lease)], "sha0")
    globals()["_write_ledger"] = lambda repo, leases, sha, msg, budget=None: True
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            reject_prefix = adopt("o/r", "ADOPTCID", WORKER_HOLDER, now, 3600,
                                  expected_holder_prefix="o/r#8@")
    finally:
        globals()["_run"] = real_run_fn
        globals()["_read_ledger"], globals()["_write_ledger"] = saved_rl, saved_wl
    check("adopt refuses when the holder prefix is a different issue", reject_prefix, None)

    # a persistent CAS write failure on an ADOPTABLE lease RAISES (infra failure) rather than
    # masquerading as not-adoptable (claim()'s #28 fail-loud contract).
    globals()["_run"] = lambda args: SimpleNamespace(stdout=issue_rows)
    globals()["_read_ledger"] = lambda repo, budget=None: ([dict(disp_lease)], "sha0")
    globals()["_write_ledger"] = lambda repo, leases, sha, msg, budget=None: False
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            adopt("o/r", "ADOPTCID", WORKER_HOLDER, now, 3600, expected_holder_prefix="o/r#7@")
        check("adopt raises on persistent CAS write failure", "no exception", "LeaseIOError")
    except LeaseIOError:
        check("adopt raises on persistent CAS write failure", "LeaseIOError", "LeaseIOError")
    finally:
        globals()["_run"] = real_run_fn
        globals()["_read_ledger"], globals()["_write_ledger"] = saved_rl, saved_wl

    # ---- WORKER.YML DRY-RUN PATH (round 5): the embedded "Validate dry-run account" heredoc
    # imports this module and must route its parsed record through the SAME read-time
    # legacy-shape normalization as read_accounts. It historically called _parse_account()
    # directly (literal model membership), so a legacy `models: [terra]` record failed the
    # sol-led dry-run even though the live claim path normalizes it. This extracts the REAL
    # heredoc from worker.yml and runs it against a legacy fixture that a sol route must
    # accept — red if the normalization call is ever dropped again. Fail closed: a missing
    # worker.yml / heredoc marker is a failure, not a skip (the enrolled-suite convention).
    import tempfile
    import textwrap
    from pathlib import Path

    wf_path = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "worker.yml"
    dryrun_rc, dryrun_out, dryrun_err, dryrun_gh_output = None, "", "", ""
    try:
        wf_text = wf_path.read_text(encoding="utf-8")
        step_at = wf_text.index("Validate dry-run account against resolved policy")
        hd_start = wf_text.index("<<'PY'\n", step_at) + len("<<'PY'\n")
        hd_end = wf_text.index("\n          PY\n", hd_start)
        dryrun_script = textwrap.dedent(wf_text[hd_start:hd_end])
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "target-routing").mkdir()
            (tdp / "target-routing" / "routing.toml").write_text(
                '[models.sol]\nprovider = "openai"\nharness = "codex"\n'
                'provider_model = "gpt-5.6-sol"\ncredential_format = "codex-auth-json"\n',
                encoding="utf-8")
            policy_path = tdp / "policy.json"
            policy_path.write_text(json.dumps({
                "routing": "routing.toml",
                "model_chain": ["sol", "luna", "terra"],
                "account_pool": ["acctlegacy"],
            }), encoding="utf-8")
            accounts_path = tdp / "accounts.json"
            accounts_path.write_text(json.dumps([{
                "title": "acctlegacy",
                "body": "provider: openai\nharness: codex\nmodels: [terra]\n"
                        "credential_format: codex-auth-json\nsecret_ref: ACCTLEGACY_TOKEN\n"
                        "max_concurrent_workers: 2",
                "labels": [{"name": "status:available"}],
            }]), encoding="utf-8")
            gh_output_path = tdp / "github_output"
            env = {k: v for k, v in os.environ.items() if k != "PROVENANCE_SALT"}
            env.update({"GITHUB_WORKSPACE": str(tdp), "ACCOUNT": "acctlegacy",
                        "GITHUB_OUTPUT": str(gh_output_path)})
            proc = subprocess.run(
                [sys.executable, "-", str(Path(__file__).resolve()),
                 str(policy_path), str(accounts_path)],
                input=dryrun_script, capture_output=True, text=True, env=env, check=False)
            dryrun_rc, dryrun_out, dryrun_err = proc.returncode, proc.stdout, proc.stderr
            if gh_output_path.exists():
                dryrun_gh_output = gh_output_path.read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:
        print(f"  FAIL worker.yml dry-run heredoc extraction: {exc}")
        ok = False
    dryrun_err_tail = dryrun_err.strip().splitlines()[-1] if dryrun_err.strip() else ""
    check(f"worker.yml dry-run validates a legacy [terra] record for a sol route "
          f"(stderr tail: {dryrun_err_tail!r})", dryrun_rc, 0)
    check("worker.yml dry-run resolves model=sol through the shared normalization",
          "model=sol" in dryrun_gh_output and "harness=codex" in dryrun_gh_output, True)
    check("worker.yml dry-run normalization diagnostic fires (shared function, not a re-impl)",
          "legacy-shape normalization" in dryrun_err, True)
    check("NEGATIVE: worker.yml dry-run leaks no raw handle to stdout/stderr",
          [s for s in ("stdout", "stderr")
           if "acctlegacy" in {"stdout": dryrun_out, "stderr": dryrun_err}[s]], [])

    # ---- WORKER.YML FAIL-CLOSED ROUTING METADATA (issue #142): the three embedded heredocs
    # that gate account routing metadata are trust checks with no script of their own, so the
    # enrolled suite executes the REAL workflow text. (a) The self-claim and adopt output
    # heredocs must reject a claim whose provider/harness/credential_format is missing or
    # empty instead of defaulting it to "" (the old `claim.get(...) or ""`). (b) The live
    # selected-model heredoc must require EXACT equality with protected routing — the old
    # `if claimed_provider and ...` guard skipped the comparison for an EMPTY claimed value
    # and would expose a secret on metadata the account never declared. Every EMPTY/MISSING
    # rejection below goes red if either permissive form returns; the fully-populated success
    # and mismatched-value failure controls prove the fixtures drive the real code path.
    # Fail closed: extraction or fixture failure is a FAIL, never a skip.
    try:
        wf_all = wf_path.read_text(encoding="utf-8")

        def _wf_heredoc(step_marker):
            step_at = wf_all.index(step_marker)
            start = wf_all.index("<<'PY'\n", step_at) + len("<<'PY'\n")
            end = wf_all.index("\n          PY\n", start)
            return textwrap.dedent(wf_all[start:end])

        claim_hd = _wf_heredoc("CAS claim from the policy-filtered account pool")
        adopt_hd = _wf_heredoc("Adopt dispatcher-owned CAS claim (ownership transfer)")
        selected_hd = _wf_heredoc("Resolve claimed account to concrete target model")

        def _run_hd(script, argv, extra_env, td, cwd=None):
            gh_out = Path(td) / "github_output"
            if gh_out.exists():
                gh_out.unlink()
            env = {k: v for k, v in os.environ.items() if k != "PROVENANCE_SALT"}
            env["GITHUB_OUTPUT"] = str(gh_out)
            env.update(extra_env)
            proc = subprocess.run([sys.executable, "-", *argv], input=script,
                                  capture_output=True, text=True, env=env, check=False,
                                  cwd=cwd)
            out = gh_out.read_text(encoding="utf-8") if gh_out.exists() else ""
            return proc.returncode, proc.stderr, out

        def _tail(err):
            return err.strip().splitlines()[-1] if err.strip() else ""

        cid = "ab" * 16
        base_claim = {"account": "acct01", "model": "sol", "claim_id": cid,
                      "secret_ref": "ACCT01_TOKEN", "provider": "openai",
                      "harness": "codex", "credential_format": "codex-auth-json"}
        adopt_env = {"ACCOUNT_POOL": "acct01,acct02", "MODELS": "sol,luna",
                     "EXPECTED_ACCOUNT": "acct01", "CLAIM_ID": cid, "ROLE": "impl",
                     "PACKAGES": "crate-a"}
        with tempfile.TemporaryDirectory() as hd_td:
            hd_tdp = Path(hd_td)
            fixture = hd_tdp / "claim.json"
            # The adopt heredoc IMPORTS the canonical partition reduction from the registry
            # checkout (`registry/scripts/lease_schema.py`, registry issue #112 / the 2026-07-26
            # mint-vs-adopt loop), so it must run in the layout the real step runs in:
            # actions/checkout with `path: registry`. Reproduce that instead of re-implementing the
            # reduction here — a re-implementation in the test is the same defect one layer out.
            hd_layout = hd_tdp / "workspace"
            hd_layout.mkdir()
            (hd_layout / "registry").symlink_to(Path(__file__).resolve().parent.parent)

            def _claim_case(record):
                fixture.write_text(json.dumps(record), encoding="utf-8")
                return _run_hd(claim_hd, [str(fixture), "acct01,acct02", "sol,luna"],
                               {}, hd_td)

            def _adopt_case(record, env=None):
                fixture.write_text(json.dumps(record), encoding="utf-8")
                return _run_hd(adopt_hd, [str(fixture)], {**adopt_env, **(env or {})}, hd_td,
                               cwd=str(hd_layout))

            for label, case, record, reject_word in (
                    ("claim", _claim_case, base_claim, "allocator"),
                    ("adopt", _adopt_case,
                     {**base_claim, "role": "impl", "package": "crate-a"}, "dispatcher claim")):
                rc, err, out = case(record)
                check(f"worker.yml {label} heredoc accepts fully declared routing metadata "
                      f"(stderr tail: {_tail(err)!r})",
                      (rc, "acquired=true" in out, "provider=openai" in out), (0, True, True))
                for field in ("provider", "harness", "credential_format"):
                    rc, err, out = case({k: v for k, v in record.items() if k != field})
                    check(f"worker.yml {label} heredoc rejects MISSING {field}",
                          (rc != 0, f"{reject_word} returned an empty or missing {field}" in err,
                           "acquired=true" in out), (True, True, False))
                    rc, err, out = case({**record, field: ""})
                    check(f"worker.yml {label} heredoc rejects EMPTY {field}",
                          (rc != 0, f"{reject_word} returned an empty or missing {field}" in err,
                           "acquired=true" in out), (True, True, False))

            # ---- THE MINT-vs-ADOPT PARTITION AGREEMENT, behaviourally (registry issue #112 / the
            # 2026-07-26 review-lane loop). The dispatcher mints `package` with
            # dispatch-claim.plan_package; this heredoc re-derives it and compares for EQUALITY.
            # Before the reduction was single-sourced, worker.yml's copy was a private
            # re-implementation held to the minter by a comment, and reverting it to the pre-#112
            # alphabetically-first rule left the entire enrolled suite green. These rows are the
            # counterfactual set: a multi-area claim minted with the CANONICAL COMPOSITE key must
            # be ADOPTED, and both the pre-#112 alphabetically-first value AND the pre-area-set
            # `__global__` value for the same issue must be REFUSED. Each flips if the heredoc's
            # derivation drifts in either direction.
            #
            # WHY REFUSING THE LEGACY `__global__` MINTING IS SAFE HERE, unlike #112: both halves
            # of THIS seam ship in the registry and deploy together, so a lease minted by the old
            # dispatcher can only meet a new adopter inside one lease TTL. The adopter releases the
            # lease and exits, and the NEXT tick's dispatcher — now also on the new reduction —
            # mints the composite the adopter re-derives. #112 was permanent because the two
            # derivations were in different files that never converged; this one converges on the
            # first tick after the merge, which is why the strict equality is kept rather than
            # widened with a legacy alternative that would then never be removed. (The PLAN artifact
            # is the seam that genuinely straddles two repos, and it is handled where it lives —
            # dispatch-claim._legacy_global_minting.)
            multi = {**base_claim, "role": "impl", "package": "crate-a,crate-b"}
            rc, err, out = _adopt_case(multi, {"PACKAGES": "crate-a,crate-b"})
            check("worker.yml adopt heredoc ADOPTS a multi-area claim minted as the CANONICAL "
                  f"composite key (stderr tail: {_tail(err)!r})",
                  (rc, "acquired=true" in out), (0, True))
            rc, err, out = _adopt_case({**multi, "package": "crate-b,crate-a"},
                                       {"PACKAGES": "crate-a,crate-b"})
            check("worker.yml adopt heredoc REFUSES a NON-canonical (unsorted) composite key — "
                  "the reduction is a function of the SET, so only one spelling can be minted",
                  (rc != 0, "work partition disagrees" in err, "acquired=true" in out),
                  (True, True, False))
            rc, err, out = _adopt_case({**multi, "package": "crate-a"},
                                       {"PACKAGES": "crate-a,crate-b"})
            check("worker.yml adopt heredoc REFUSES the pre-#112 alphabetically-first partition "
                  "for the same multi-area issue",
                  (rc != 0, "work partition disagrees" in err, "acquired=true" in out),
                  (True, True, False))
            rc, err, out = _adopt_case({**multi, "package": "__global__"},
                                       {"PACKAGES": "crate-a,crate-b"})
            check("worker.yml adopt heredoc REFUSES the pre-area-set __global__ minting for a "
                  "multi-area issue (the reduction moved; the equality check must see it)",
                  (rc != 0, "work partition disagrees" in err, "acquired=true" in out),
                  (True, True, False))
            rc, err, out = _adopt_case({**multi, "package": "crate-a"},
                                       {"PACKAGES": "crate-a"})
            check("worker.yml adopt heredoc ADOPTS a single-area claim minted as that area "
                  f"(stderr tail: {_tail(err)!r})",
                  (rc, "acquired=true" in out), (0, True))
            rc, err, out = _adopt_case({**multi, "package": "__global__"}, {"PACKAGES": ""})
            check("worker.yml adopt heredoc ADOPTS a NO-area claim minted as __global__ "
                  "(fail-closed: an arealess issue serializes)",
                  (rc, "acquired=true" in out), (0, True))

            # Live (DRY_RUN=false) selected-model gate against a fake protected target routing.
            (hd_tdp / "target").mkdir()
            (hd_tdp / "target" / "routing.toml").write_text(
                '[models.sol]\nprovider = "openai"\nharness = "codex"\n'
                'provider_model = "gpt-5.6-sol"\ncredential_format = "codex-auth-json"\n',
                encoding="utf-8")
            live_env = {"DRY_RUN": "false", "GITHUB_WORKSPACE": hd_td,
                        "ROUTING_PATH": "routing.toml", "LIVE_ACCOUNT": "acct01",
                        "LIVE_MODEL": "sol", "LIVE_SECRET_REF": "ACCT01_TOKEN",
                        "LIVE_PROVIDER": "openai", "LIVE_HARNESS": "codex",
                        "LIVE_CREDENTIAL_FORMAT": "codex-auth-json"}
            rc, err, out = _run_hd(selected_hd, [], live_env, hd_td)
            check(f"worker.yml selected-model heredoc accepts matching live routing metadata "
                  f"(stderr tail: {_tail(err)!r})",
                  (rc, "provider=openai" in out, "secret_ref=ACCT01_TOKEN" in out),
                  (0, True, True))
            for var, wrong in (("LIVE_PROVIDER", "anthropic"), ("LIVE_HARNESS", "claude"),
                               ("LIVE_CREDENTIAL_FORMAT", "claude-oauth-token")):
                for tag, value in (("EMPTY", ""), ("mismatched", wrong)):
                    rc, err, out = _run_hd(selected_hd, [], {**live_env, var: value}, hd_td)
                    check(f"worker.yml selected-model heredoc rejects {tag} {var} "
                          f"(no output written)",
                          (rc != 0, "conflicts with protected routing" in err,
                           "secret_ref=" in out), (True, True, False))
    except (OSError, ValueError, IndexError) as exc:
        print(f"  FAIL worker.yml fail-closed routing heredoc round: {exc}")
        ok = False

    full1 = [make_lease("acct01", "h", "p", "r", "terra", now, 100)]
    check("cap fallthrough", choose_account(A, full1, ["terra", "fable"], "p", "r", now), "acct02")
    exp = [make_lease("acct01", "h", "p", "r", "terra", 0, 10)]  # expires_at=10 < now → reclaimed
    check("expiry reclaim", choose_account(A, exp, ["terra"], "p", "r", now), "acct01")

    # ---- issue #35: the groom-leases heartbeat (liveness-aware expiry) ---------------------------
    # RED FOR THE BUG. Before this, groom-leases dropped EVERY expired row with no signal from the
    # holder, so a worker still writing at TTL+1 lost its lease and its issue was re-dispatched.
    # `plan_renewal` is the whole decision, pure, so each property below is a counterfactual: the
    # blind reclaim reverses the first two, and a "skip the reclaim but leave the row" fix (which
    # would suppress NOTHING — every consumer keys on `expires_at > now`, not on the row) reverses
    # the third.
    # A realistic wall-clock base: the self-test's `now = 1000` cannot express "issued six
    # thousand seconds ago" without a negative issuance the ledger schema rejects, and these rows
    # are read back through `validate_ledger` by the end-to-end drive below.
    T35 = 10_000_000

    def _lease35(holder, issued, expires, claim="c" * 32):
        row = make_lease("acct01", holder, "p", "impl", "terra", issued, expires - issued)
        row["claim_id"] = claim
        return row

    def _fixed(state):
        return lambda _run_id: state

    # Every assertion below reads a planned row through these, NEVER through `rows[0][...]`. A
    # mutant that drops the row would otherwise raise IndexError/TypeError out of the ASSERTION and
    # abort the suite — which records as a kill while every check underneath it silently never runs
    # (AGENTS.md: crash-after-partial-run). `"GONE"` is a value no fixture uses, so a dropped row
    # reds its own named check and the rest of the suite still executes.
    def _expiry(rows, index=0):
        return rows[index]["expires_at"] if index < len(rows) else "GONE"

    def _row_but_expiry(rows, index=0):
        return ({k: v for k, v in rows[index].items() if k != "expires_at"}
                if index < len(rows) else "GONE")

    def _rows_reclaimed(plan):
        """(surviving rows, TTL-reclaim count) of a plan — the pair these controls have always
        asserted, said by NAME now that a plan also carries `finished`. Reading it positionally
        would silently start comparing a different field the next time one is added."""
        return plan.leases, plan.reclaimed

    live_worker = _lease35("o/r#7@4242.1", T35 - 6000, T35 - 10)     # expired 10s ago, run alive
    dead_worker = _lease35("o/r#8@4243.1", T35 - 6000, T35 - 10, "d" * 32)
    renewed_rows, n_renew, n_reclaim, n_defer, _f = plan_renewal(
        [live_worker], T35, _fixed("live"))
    check("[RED #35] an EXPIRED lease whose worker run is LIVE is kept, not reclaimed",
          ([row["claim_id"] for row in renewed_rows], n_renew, n_reclaim, n_defer),
          ([live_worker["claim_id"]], 1, 0, 0))
    # Keeping the ROW is not enough and is the trap this check exists to close: reclaim_expired
    # (claim()'s holder-key single-flight, partition_available) and dispatch-claim's
    # `_live_holder_keys` all decide on `expires_at > now`. If the renewal did not MOVE that field
    # the duplicate suppression stays off and the double-dispatch is untouched.
    check("[RED #35] ...and its expiry is PUSHED FORWARD, so the suppression consumers see it live",
          (_expiry(renewed_rows), len(reclaim_expired(renewed_rows, T35))),
          (T35 + RENEWAL_SECONDS, 1))
    check("[RED #35] renewal rewrites expires_at and NOTHING else — issued_at is groom's "
          "policy-timeout anchor and the renewal ceiling's origin",
          _row_but_expiry(renewed_rows),
          {k: v for k, v in live_worker.items() if k != "expires_at"})
    # [CONTROL] the behaviour that must NOT regress: a crashed/finished worker still frees its slot.
    check("[CONTROL] an expired lease whose run is DEAD is reclaimed exactly as before",
          _rows_reclaimed(plan_renewal([dead_worker], T35, _fixed("dead"))), ([], 1))
    check("[CONTROL] a holder that records NO run is reclaimed without ever probing",
          ([row["claim_id"] for row in plan_renewal(
              [_lease35("review:o/r#9", T35 - 6000, T35 - 10)], T35,
              _fixed("live"))[0]], holder_run_id("review:o/r#9")), ([], None))
    far = _lease35("o/r#7@4242.1", T35, T35 + RENEWAL_LEAD_SECONDS + 600)
    far_probes = []
    check("[CONTROL] a lease nowhere near expiry passes through untouched and is NEVER probed",
          (plan_renewal([far], T35, lambda r: (far_probes.append(r), "dead")[1]), far_probes),
          ((([far], 0, 0, 0, 0)), []))
    # THE PRE-EMPTIVE RENEWAL — the difference between mitigating this bug and fixing it. Renewing
    # only ALREADY-expired rows leaves the live worker's lease reading expired for up to one cron
    # period, and a dispatch tick inside that window double-dispatches exactly as before. So a row
    # inside its lead window is renewed BEFORE it can ever be seen expired.
    soon = _lease35("o/r#7@4242.1", T35 - 3000, T35 + 60)   # 60s from expiry: inside the lead
    soon_rows, soon_renew, soon_reclaim, _d, _f = plan_renewal([soon], T35, _fixed("live"))
    check("[RED #35] a live lease is renewed BEFORE it expires, so it is never SEEN expired",
          (_expiry(soon_rows), soon_renew, soon_reclaim, len(reclaim_expired(soon_rows, T35))),
          (T35 + RENEWAL_SECONDS, 1, 0, 1))
    check("[CONTROL] a not-yet-expired lease is NEVER reclaimed and is still READ as live, "
          "whatever the probe says",
          [(lambda p: (p[2], len(reclaim_expired(p[0], T35))))(
              plan_renewal([soon], T35, _fixed(state))) for state in ("dead", "unknown")],
          [(0, 1)] * 2)
    check("[CONTROL] a not-yet-expired lease whose run is DEAD is left byte-identical "
          "(no ledger churn while it is still suppressing on its own expiry)",
          plan_renewal([soon], T35, _fixed("dead"))[0], [soon])
    # The lead has to outlast the cron it rides on, and a renewal has to leave the row OUTSIDE its
    # own lead window at the moment it lands — otherwise the row is due again immediately, or a
    # single skipped cron fire lets a live lease expire unseen.
    check("the renewal window and lead bracket the 15-minute groom-leases cron",
          (RENEWAL_LEAD_SECONDS >= 2 * 15 * 60, RENEWAL_SECONDS > RENEWAL_LEAD_SECONDS,
           RENEWAL_CEILING_SECONDS > RENEWAL_SECONDS), (True, True, True))
    # UNPROVEN liveness defers the DECISION rather than guessing — but a deferral has to HOLD the
    # slot, not hand it away. Leaving the expired row byte-identical defers nothing: by the module
    # header every duplicate-suppression consumer keys on `expires_at > now` and not on the row's
    # presence, so one 403/5xx/garbage body would free the account and the holder key to the next
    # dispatcher while the original run may still be writing — the very double-dispatch this change
    # closes, re-opened by a flaky API. So the row is held on a short, ceiling-clamped grace
    # deadline and re-probed next tick.
    deferred_rows, d_renew, d_reclaim, d_defer, _f = plan_renewal(
        [live_worker], T35, _fixed("unknown"))
    check("[RED #35] an UNPROVEN probe HOLDS the row on grace instead of reclaiming it",
          (_expiry(deferred_rows), d_renew, d_reclaim, d_defer),
          (T35 + RENEWAL_GRACE_SECONDS, 0, 0, 1))
    # ...and the claim that actually matters, measured through the REAL suppression consumers
    # instead of by asserting the row is present. `live_worker` IS the un-held row that a
    # byte-identical defer emits, so the second half of this tuple is the counterfactual measured on
    # the same consumers: every one of them hands the slot straight to a competing dispatcher.
    # `partition_available` is fed the RECLAIMED list by its one production caller (`claim()`), and
    # `choose_account` runs `reclaim_expired` itself — so both are driven here exactly as claim()
    # drives them, not on the raw ledger where an expired row would still look present.
    check("[RED #35] a grace-HELD unproven row still suppresses a competing claim, where the "
          "un-held row a byte-identical defer emits does NOT",
          (len(reclaim_expired(deferred_rows, T35)),
           partition_available(reclaim_expired(deferred_rows, T35), "o/r#7", "p"),
           choose_account(A, deferred_rows, ["terra"], "p", "impl", T35),
           len(reclaim_expired([live_worker], T35)),
           partition_available(reclaim_expired([live_worker], T35), "o/r#7", "p"),
           choose_account(A, [live_worker], ["terra"], "p", "impl", T35)),
          (1, False, None, 0, True, "acct01"))
    check("[RED #35] the grace hold rewrites expires_at and NOTHING else",
          _row_but_expiry(deferred_rows),
          {k: v for k, v in live_worker.items() if k != "expires_at"})
    check("the grace deadline comes from `grace` — not from the lead, and not from the full "
          "renewal a PROVEN-live run earns",
          (_expiry(plan_renewal([live_worker], T35, _fixed("unknown"), grace=123)[0]),
           _expiry(plan_renewal([live_worker], T35, _fixed("live"), grace=123)[0])),
          (T35 + 123, T35 + RENEWAL_SECONDS))
    # The grace is bounded on BOTH sides: long enough that a single skipped cron fire cannot let a
    # held row lapse unseen, and no longer than the lead, so a held row stays DUE and is re-probed
    # every tick instead of quietly sitting on a scarce slot.
    check("the grace hold brackets the 15-minute cron without out-staying its welcome",
          (RENEWAL_GRACE_SECONDS >= 2 * 15 * 60, RENEWAL_GRACE_SECONDS <= RENEWAL_LEAD_SECONDS,
           RENEWAL_GRACE_SECONDS < RENEWAL_SECONDS), (True, True, True))
    held_rows, _hr, h_reclaim, h_defer, _hf = plan_renewal(
        deferred_rows, T35 + 15 * 60, _fixed("unknown"))
    check("a still-unproven row is re-decided on the NEXT cron tick and held again, never "
          "silently coasting on the first hold",
          (h_reclaim, h_defer, _expiry(held_rows)),
          (0, 1, T35 + 15 * 60 + RENEWAL_GRACE_SECONDS))
    # THE CAPACITY BACKSTOP. Without the ceiling, a run wedged in `in_progress` — or a probe that
    # keeps failing — pins a scarce account slot forever, trading the double-dispatch for a
    # permanent capacity leak. Past the ceiling the reclaim happens REGARDLESS of liveness.
    wedged = _lease35("o/r#7@4242.1", T35 - RENEWAL_CEILING_SECONDS - 1, T35 - 10)
    check("[BACKSTOP] past issued_at + ceiling an expired lease is reclaimed even when LIVE",
          _rows_reclaimed(plan_renewal([wedged], T35, _fixed("live"))), ([], 1))
    check("[BACKSTOP] ...and even when the probe keeps failing (unproven cannot pin a slot)",
          _rows_reclaimed(plan_renewal([wedged], T35, _fixed("unknown"))), ([], 1))
    near = _lease35("o/r#7@4242.1", T35 - RENEWAL_CEILING_SECONDS + 60, T35 - 10)
    check("[BACKSTOP] a renewal CLAMPS to the ceiling rather than stepping over it",
          _expiry(plan_renewal([near], T35, _fixed("live"))[0]),
          near["issued_at"] + RENEWAL_CEILING_SECONDS)
    check("[BACKSTOP] a grace HOLD clamps to the same ceiling — an unanswered probe cannot buy "
          "more slot-time than a proven-live run",
          _expiry(plan_renewal([near], T35, _fixed("unknown"))[0]),
          near["issued_at"] + RENEWAL_CEILING_SECONDS)
    check("neither a renewal nor a grace hold lands at or before now (every deferred row leaves "
          "plan_renewal still readable as live)",
          [len(reclaim_expired(plan_renewal([near], T35, _fixed(state))[0], T35))
           for state in ("live", "unknown")], [1, 1])
    check("a lease with an unreadable expiry/issuance is reclaimed, never renewed",
          (_rows_reclaimed(plan_renewal([{**live_worker, "expires_at": "soon"}], T35, _fixed("live"))),
           _rows_reclaimed(plan_renewal([{**live_worker, "issued_at": None}], T35, _fixed("live")))),
          (([], 1), ([], 1)))
    check("the renewal window outlives the 15-minute groom-leases cron by several ticks",
          RENEWAL_SECONDS >= 3 * 15 * 60, True)

    # ---- issue #1128: the RUN-LESS repair lease, whose only reclaim path was its own TTL --------
    # THE INCIDENT, replayed at its real numbers. `fix:...#1102@dispatch-30409404963.1` was issued
    # 23:59:47Z with a 105-minute TTL to 01:44:47Z; the review-fix run holding it concluded FAILURE
    # at 00:13:46Z. groom-leases ran at 00:04:59 and 00:50:58 and dropped nothing, and the fleet
    # took ZERO dispatches for the intervening 91 minutes.
    #
    # NOTE WHAT THE PRE-FIX CONTROL BELOW MEASURES, because the issue's own diagnosis was wrong
    # about it: at 00:50 that row is 54 MINUTES from expiry, which is outside the 30-minute lead, so
    # `plan_renewal` never looked at it and REPORTED 0/0/0 CORRECTLY. The bug was never that the
    # reclaim "processed an empty set" — it was that a positively dead holder could not be seen at
    # all. So the control asserts the row SURVIVES with no claim source, and the RED asserts it does
    # not once one exists. A fix that only made the counters louder would leave the control green.
    ISSUED_1102, EXPIRES_1102 = 1_785_283_187, 1_785_289_487        # 23:59:47Z -> 01:44:47Z
    TICK_0050 = 1_785_287_458                                        # the 00:50:58Z groom tick
    repair = _lease35("fix:o/r#1102@dispatch-30409404963.1", ISSUED_1102, EXPIRES_1102, "f" * 32)
    check("[CONTROL #1128] the row is 54 minutes from expiry at the 00:50 tick — OUTSIDE the "
          "30-minute lead, so 0 reclaimed / 0 renewed was the CORRECT report, not a failed read",
          ((EXPIRES_1102 - TICK_0050) > RENEWAL_LEAD_SECONDS,
           holder_run_id(repair["holder"])), (True, None))
    check("[CONTROL #1128] with NO claim source the row survives the tick untouched — the "
          "105-minute TTL really was its only exit",
          _rows_reclaimed(plan_renewal([repair], TICK_0050, _fixed("live"))), ([repair], 0))
    concluded = plan_renewal([repair], TICK_0050, _fixed("live"),
                             claim_liveness={"f" * 32: "finished"}.get)
    check("[RED #1128] a repair lease whose correlated run has CONCLUDED is dropped on the very "
          "next tick, 54 minutes BEFORE its TTL, and is counted as `finished` not as expired",
          (concluded.leases, concluded.finished, concluded.reclaimed, concluded.renewed),
          ([], 1, 0, 0))
    check("[RED #1128] ...and the drop really frees the slot: the suppression consumers, which "
          "all key on `expires_at > now`, no longer read a live row",
          (len(reclaim_expired(concluded.leases, TICK_0050)),
           len(reclaim_expired(plan_renewal([repair], TICK_0050, _fixed("live")).leases,
                               TICK_0050))), (0, 1))
    # THE #1071 CASE, which this must not regress: a dispatcher-held lease whose review-fix run has
    # not MATERIALISED yet correlates to nothing. Absence of a run is not death — reclaiming on it
    # would race the dispatcher onto one account with two workers, the direction that is not
    # recoverable the way a stall is. `{}.get` is precisely "the walk ran and matched nothing".
    check("[CONTROL #1071] a dispatcher-held lease with NO materialised run is NOT reclaimed — "
          "an unmatched claim is unknown, and unknown never drops a row",
          _rows_reclaimed(plan_renewal([repair], TICK_0050, _fixed("live"), claim_liveness={}.get)),
          ([repair], 0))
    check("[CONTROL #1071] ...and neither is one whose correlated run is still LIVE",
          _rows_reclaimed(plan_renewal([repair], TICK_0050, _fixed("live"),
                                       claim_liveness={"f" * 32: "live"}.get)), ([repair], 0))
    check("[CONTROL #1128] an ORDINARY worker lease is never routed through the claim source — "
          "groom.py still owns those, and a `finished` verdict on its claim must not touch it",
          _rows_reclaimed(plan_renewal([far], T35, _fixed("dead"),
                                       claim_liveness=lambda _c: "finished")), ([far], 0))
    # A concluded run frees the row whatever it concluded WITH: success, failure and cancelled all
    # mean the run will do no further work, so its lease is unowned in every case. (A successful
    # run normally releases its own lease; this is the path for when it did not.)
    check("[#1128] `finished` is about TERMINATION, not about the conclusion's value",
          [classify_claim_run({"path": REVIEW_FIX_WORKFLOW, "status": "completed",
                               "conclusion": value})
           for value in ("failure", "cancelled", "success", "timed_out", None)],
          ["finished"] * 5)
    check("[#1128] an ACTIVE run is live, and every active status the ledger recognises counts",
          [classify_claim_run({"path": REVIEW_FIX_WORKFLOW, "status": status})
           for status in sorted(ACTIVE_RUN_STATUSES)], ["live"] * len(ACTIVE_RUN_STATUSES))
    # Fail-closed direction: everything unreadable is `unknown`, and unknown NEVER reclaims. The
    # one thing this must never do is return `finished` for something it could not read.
    check("[#1128] an unreadable run, or one from another workflow, is unknown — never finished",
          [classify_claim_run(run) for run in
           (None, "completed", {}, {"status": "completed"},
            {"path": ".github/workflows/worker.yml", "status": "completed"},
            {"path": REVIEW_FIX_WORKFLOW, "status": "banana"},
            {"path": REVIEW_FIX_WORKFLOW})],
          ["unknown"] * 7)

    # holder_run_id: ONLY the bare `<run>.<attempt>` suffix names a run that owns the lease for its
    # whole life. A dispatcher holder's run is dispatch.yml's, and a queued worker has not started.
    check("holder_run_id reads the worker/review-fix run suffix",
          (holder_run_id("o/r#7@4242.1"), holder_run_id("review:o/r#7@99.2")), (4242, 99))
    check("holder_run_id refuses every shape that is not evidence of a lease-owning run",
          [holder_run_id(h) for h in
           ("o/r#7@dispatch-4242.1", "o/r#7@run", "review:o/r#9", "o/r#7@4242", "o/r#7@0.1",
            "o/r#7@a@4242.1", None, 4242)],
          [None] * 8)
    # classify_run: the run must be one of the workflows that HOLD a lease for their whole run.
    # Without that binding any long-lived run id in a holder — a cron, a tampered ledger row —
    # could pin a scarce account slot indefinitely.
    check("classify_run: an ACTIVE lease-holding run is live",
          [classify_run({"path": p, "status": s})
           for p in sorted(LEASE_HOLDING_WORKFLOWS) for s in sorted(ACTIVE_RUN_STATUSES)],
          ["live"] * (len(LEASE_HOLDING_WORKFLOWS) * len(ACTIVE_RUN_STATUSES)))
    check("classify_run: a completed run is dead",
          classify_run({"path": ".github/workflows/worker.yml", "status": "completed"}), "dead")
    check("classify_run: an ACTIVE run of ANY OTHER workflow is dead, never live",
          [classify_run({"path": p, "status": "in_progress"}) for p in
           (".github/workflows/dispatch.yml", ".github/workflows/groom-leases.yml", "", None)],
          ["dead"] * 4)
    check("classify_run: a path with a ref suffix still binds to the workflow",
          classify_run({"path": ".github/workflows/worker.yml@refs/heads/master",
                        "status": "in_progress"}), "live")
    check("classify_run: an unreadable document or unrecognised status is UNPROVEN, not live",
          [classify_run(x) for x in
           (None, [], {"path": ".github/workflows/worker.yml"},
            {"path": ".github/workflows/worker.yml", "status": "banana"})],
          ["unknown"] * 4)
    # The probe is memoized per transaction: a CAS retry must re-read the LEDGER but must not
    # re-bill the Actions API for a run it already classified.
    probe_calls = []
    memoized = _liveness_probe("o/r", lambda repo, run_id: (
        probe_calls.append((repo, run_id)), "live")[1])
    check("the liveness probe is memoized across CAS attempts",
          ([memoized(4242), memoized(4242), memoized(7)], probe_calls),
          (["live", "live", "live"], [("o/r", 4242), ("o/r", 7)]))
    warm2 = [make_lease("acct02", "h", "pkg", "impl", "fable", now - 1, 100)]  # acct02 warm, cap2 has room
    check("cache affinity", choose_account(A, warm2, ["fable"], "pkg", "impl", now), "acct02")
    live, _lease = apply_claim([], "acct02", "run1", "pkg", "impl", "fable", now, 100, "CID")
    check("claim adds", len(live), 1)
    check("lease stores only canonical salted account fingerprint",
          _lease["account"], account_fingerprint("acct02"))
    check("lease fingerprint is 16 lowercase hex",
          ACCOUNT_FINGERPRINT_RE.fullmatch(_lease["account"]) is not None, True)
    check("raw account identity is dropped during bounded ledger migration",
          validate_lease_account_identities([{"account": "acct02"}]), [])
    check("canonical fingerprint survives bounded ledger migration",
          validate_lease_account_identities([{"account": _lease["account"]}]),
          [{"account": _lease["account"]}])
    subject = claim_commit_message("abcdef0123456789", "pkg", "impl")
    check("claim commit subject omits raw account identity",
          subject, "claim abcdef01 pkg/impl")
    check("claim commit subject negative: raw account absent", "acct02" in subject, False)
    check("release removes", apply_release(live, "CID", now), [])
    check("holder key ignores run identity", holder_key("owner/repo#7@run.1"), "owner/repo#7")
    scoped = [make_lease("acct01", "owner/repo#1@run", "crate-a", "impl", "terra", now, 100)]
    check("package partition blocks duplicate", partition_available(scoped, "owner/repo#", "crate-a"),
          False)
    check("package partition permits sibling", partition_available(scoped, "owner/repo#", "crate-b"),
          True)
    check("global partition serializes", partition_available(scoped, "owner/repo#", "__global__"),
          False)
    # ---- the CLAIM-time half of the area-SET partition. These are the allocator's own copy of
    # lease_schema's red test + controls: PLAN deciding `{A,B}` may co-run with `{C}` while the
    # allocator still refuses it is the exact one-sided-widening failure (`package-single-flight`
    # every tick on a row PLAN keeps offering), so the property is pinned at BOTH sites.
    check("[RED] a {A,B} claim is ADMITTED against a live {C} lease (sets are disjoint)",
          partition_available(
              [make_lease("acct01", "owner/repo#1@run", "crate-c", "impl", "terra", now, 100)],
              "owner/repo#", "crate-a,crate-b"),
          True)
    check("[RED] a {A,B} claim is REFUSED against a live {B,C} lease (sets intersect on B)",
          partition_available(
              [make_lease("acct01", "owner/repo#1@run", "crate-b,crate-c", "impl", "terra",
                          now, 100)],
              "owner/repo#", "crate-a,crate-b"),
          False)
    check("[CONTROL] a composite lease still blocks a SINGLE-area claim on one of its atoms",
          partition_available(
              [make_lease("acct01", "owner/repo#1@run", "crate-a,crate-b", "impl", "terra",
                          now, 100)],
              "owner/repo#", "crate-b"),
          False)
    check("[CONTROL] a ZERO-area claim (__global__) is still refused against ANY live lease, and "
          "a live __global__ lease still refuses a composite claim",
          [partition_available(scoped, "owner/repo#", "__global__"),
           partition_available(
               [make_lease("acct01", "owner/repo#1@run", "__global__", "impl", "terra", now, 100)],
               "owner/repo#", "crate-a,crate-b")],
          [False, False])
    check("[CONTROL] an empty ledger admits every shape",
          [partition_available([], "owner/repo#", p)
           for p in ("crate-a", "crate-a,crate-b", "__global__")],
          [True, True, True])
    check("a lease with an UNREADABLE package fails closed (it is unknown footprint, not free)",
          partition_available(
              [{**make_lease("acct01", "owner/repo#1@run", "crate-a", "impl", "terra", now, 100),
                "package": None}],
              "owner/repo#", "crate-b"),
          False)
    check("the allocator decides with lease_schema.packages_conflict, not its own copy",
          [lease_schema.packages_conflict("crate-a,crate-b", "crate-c"),
           lease_schema.packages_conflict("crate-a,crate-b", "crate-b,crate-c")],
          [False, True])

    class _StubLedger:
        """Drive claim()'s pure decision path without GitHub I/O (accounts + ledger stubbed)."""

        def __init__(self, accounts, leases, write_ok=True):
            self.accounts, self.leases, self.write_ok = accounts, leases, write_ok
            self.written = None

        def __enter__(self):
            self._saved = (read_accounts, _read_ledger, _write_ledger)
            globals()["read_accounts"] = lambda repo: self.accounts
            globals()["_read_ledger"] = lambda repo, budget=None: (list(self.leases), "sha0")

            def write(_repo, leases, _sha, _msg, _budget=None):
                self.written = list(leases)
                return self.write_ok

            globals()["_write_ledger"] = write
            return self

        def __exit__(self, *a):
            (globals()["read_accounts"], globals()["_read_ledger"],
             globals()["_write_ledger"]) = self._saved

    # ---- issue #514: capacity exhaustion walks the target-owned model chain ----
    # The fixture deliberately crosses providers (sol/openai -> fable/anthropic). These drive the
    # real claim path so the chosen alias must survive into both the returned claim and CAS ledger
    # row; selecting only the lead provider, walking unconditionally, or bypassing fallback gates
    # flips the corresponding assertion red.
    chain_accounts = [
        {"handle": "acctlead", "models": ["sol"], "max_concurrent_workers": 1,
         "available": True, "secret_ref": "ACCTLEAD_TOKEN", "provider": "openai",
         "harness": "codex", "credential_format": "codex-auth-json"},
        {"handle": "acctfallback", "models": ["fable"], "max_concurrent_workers": 1,
         "available": True, "secret_ref": "ACCTFALLBACK_TOKEN", "provider": "anthropic",
         "harness": "claude", "credential_format": "claude-oauth-token"},
    ]
    chain_usage = {
        "acctlead": {"exempt": True, "reachability": USAGE_REACHABILITY_LIVE},
        "acctfallback": {"status": "allowed", "5h_util": 0.2, "5h_reset": 2000,
                         "7d_util": 0.2, "7d_reset": 3000, "fable_ok": True,
                         "fable_7d_oi_util": 0.2, "fable_7d_oi_reset": 3000},
    }
    lead_full = make_lease("acctlead", "other#1@run", "other", "impl", "sol", now, 100)
    with _StubLedger(chain_accounts, [lead_full]) as fallback_ledger:
        fallback_claim = claim(
            "r", "p", "impl", ["sol", "fable"], "o/r#514@run", now,
            usage=chain_usage)
    check("chain walk: exhausted lead provider selects fallback and records fallback alias",
          (fallback_claim["account"], fallback_claim["model"],
           fallback_ledger.written[-1]["model"]),
          ("acctfallback", "fable", "fable"))

    fallback_full = make_lease(
        "acctfallback", "other#2@run", "other", "impl", "fable", now, 100)
    with _StubLedger(chain_accounts, [lead_full, fallback_full]):
        exhausted_claim = claim(
            "r", "p", "impl", ["sol", "fable"], "o/r#514@run", now,
            usage=chain_usage)
    check("chain walk: all providers exhausted returns none-free", exhausted_claim, None)

    with _StubLedger(chain_accounts, []):
        lead_claim = claim(
            "r", "p", "impl", ["sol", "fable"], "o/r#514@run", now,
            usage=chain_usage)
    check("chain walk: eligible lead provider wins without fallback",
          (lead_claim["account"], lead_claim["model"]), ("acctlead", "sol"))

    fallback_backoff_usage = {
        **chain_usage,
        "acctlead": {"exempt": True, "reachability": USAGE_REACHABILITY_LIVE,
                     "backoff_until": now + 60},
    }
    with _StubLedger(chain_accounts, [fallback_full]):
        backed_off_fallback = claim(
            "r", "p", "impl", ["fable", "sol"], "o/r#514@run", now,
            usage=fallback_backoff_usage)
    check("chain walk: per-account backoff still blocks the fallback account",
          backed_off_fallback, None)

    # ---- disjoint review:/fix: top-level lease prefixes (cross-provider review loop) ----
    # Review/fix holders are `review:<repo>#<PR>@run` / `fix:<repo>#<PR>@run`. Neither starts with
    # the impl prefix `<repo>#` (and vice-versa), so impl max_holder_concurrent never counts them,
    # review/fix caps never count impl, and partition_available never cross-blocks. Load-bearing:
    # a regression here silently masquerades as none-free.
    mixed = [
        make_lease("acct02", "owner/repo#12@r.1", "crate-a", "impl", "fable", now, 100),
        make_lease("acct01", "review:owner/repo#40@r.1", "crate-a", "review", "terra", now, 100),
        make_lease("acct02", "fix:owner/repo#41@r.1", "crate-b", "fix", "fable", now, 100),
    ]
    check("holder keys stay disjoint across namespaces",
          (holder_key("owner/repo#5@x"), holder_key("review:owner/repo#5@x"),
           holder_key("fix:owner/repo#5@x")),
          ("owner/repo#5", "review:owner/repo#5", "fix:owner/repo#5"))
    check("impl prefix counting excludes review/fix holders",
          sum(1 for x in mixed if str(x["holder"]).startswith("owner/repo#")), 1)
    check("review prefix counting excludes impl/fix holders",
          sum(1 for x in mixed if str(x["holder"]).startswith("review:")), 1)
    check("impl lease on a crate does not block a review claim (partition cross-check)",
          partition_available(mixed, "review:", "crate-b"), True)
    check("review lease invisible to the impl partition (partition cross-check)",
          partition_available([mixed[1]], "owner/repo#", "crate-a"), True)
    check("same-crate reviews still serialize under the shared review: prefix",
          partition_available(mixed, "review:", "crate-a"), False)

    # ---- issue #448: review/fix fan-out is bounded by LIVE per-account slots ----
    # The production sol account advertises its parallelism through this exact catalog field;
    # model the measured 12-slot shape and prove active leases are subtracted rather than merely
    # counting one "available account".  Foreign accounts/providers never consume sol capacity.
    sol12 = [{"handle": "acctsol", "models": ["sol", "luna"],
              "max_concurrent_workers": 12, "available": True,
              "secret_ref": "ACCTSOL_TOKEN", "provider": "openai"}]
    four_sol = [
        make_lease("acctsol", f"fix:o/r#{number}@r.1", f"crate-{number}", "fix", "sol",
                   now, 100)
        for number in range(4)
    ]
    check("12-slot sol account exposes 8 remaining slots",
          available_account_slots(sol12, four_sol, ["sol", "luna"], now,
                                  account_pool=["acctsol"]), 8)
    check("fully occupied sol account exposes zero slots (fail closed)",
          available_account_slots(sol12, four_sol + [
              make_lease("acctsol", f"fix:o/r#{number}@r.1", f"crate-{number}", "fix",
                         "sol", now, 100)
              for number in range(4, 12)
          ], ["sol"], now, account_pool=["acctsol"]), 0)
    check("unavailable sol account contributes no slots",
          available_account_slots([{**sol12[0], "available": False}], [], ["sol"], now), 0)
    check("active reactive backoff contributes no sol slots",
          available_account_slots(sol12, [], ["sol"], now,
                                  usage={"acctsol": {
                                      "exempt": True,
                                      "reachability": USAGE_REACHABILITY_LIVE,
                                      "backoff_until": now + 60}}), 0)

    # Reasoned claims make the telemetry's lease-conflict bucket testable without weakening the
    # historical claim-or-None API.  Same-repo package single-flight still wins before capacity.
    with _StubLedger(sol12, [
            make_lease("acctsol", "fix:o/r#40@r.1", "crate-a", "fix", "sol", now, 100)]):
        conflict, why = claim(
            "r", "crate-a", "fix", ["sol"], "fix:o/r#41@r.1", now,
            account_pool=["acctsol"], holder_prefix="fix:o/r#",
            account_slot_bound=True, return_reason=True)
    check("reasoned claim defers a package lease conflict", (conflict, why),
          (None, "package-single-flight"))
    with _StubLedger(sol12, [
            make_lease("acctsol", f"fix:o/r#{number}@r.1", f"crate-{number}", "fix", "sol",
                       now, 100)
            for number in range(12)]):
        no_slot, why = claim(
            "r", "fresh-crate", "fix", ["sol"], "fix:o/r#99@r.1", now,
            account_pool=["acctsol"], holder_prefix="fix:o/r#",
            account_slot_bound=True, return_reason=True)
    check("reasoned claim fails closed at S=0", (no_slot, why),
          (None, "no-account-slots"))

    # Two live review leases for DISTINCT PRs are bounded by the SHARED `review:` prefix cap
    # (max_holder_concurrent=2 = the static codex slot bound; codex is usage-exempt so the CLI
    # usage=None path is acceptable). A third claim must come back None, an impl claim must not.
    review_pair = [
        make_lease("acct01", "review:owner/repo#40@r.1", "crate-a", "review", "terra", now, 100),
        make_lease("acct01", "review:owner/repo#41@r.1", "crate-b", "review", "terra", now, 100),
    ]
    with _StubLedger([{"handle": "acct01", "models": ["terra"], "max_concurrent_workers": 3,
                       "available": True, "secret_ref": "ACCT01_TOKEN"}], review_pair):
        third = claim("r", "crate-c", "review", ["terra"], "review:owner/repo#42@r.1", now,
                      account_pool=["acct01"], holder_prefix="review:", max_holder_concurrent=2)
    check("third review claim bounded by the shared review: cap", third, None)
    with _StubLedger([{"handle": "acct02", "models": ["fable"], "max_concurrent_workers": 3,
                       "available": True, "secret_ref": "ACCT02_TOKEN"}], review_pair):
        impl_claim = claim("r", "crate-c", "impl", ["fable"], "owner/repo#9@r.1", now,
                           account_pool=["acct02"], holder_prefix="owner/repo#",
                           max_holder_concurrent=2)
    check("impl cap ignores the two review leases", bool(impl_claim), True)
    with _StubLedger([{"handle": "acct01", "models": ["terra"], "max_concurrent_workers": 3,
                       "available": True, "secret_ref": "ACCT01_TOKEN"}], review_pair[:1]):
        second = claim("r", "crate-c", "review", ["terra"], "review:owner/repo#41@r.1", now,
                       account_pool=["acct01"], holder_prefix="review:", max_holder_concurrent=2)
    check("second review claim under the cap succeeds", bool(second), True)
    # A persistent ledger-write failure with an ELIGIBLE account must raise LeaseIOError — never
    # return None (None = "no eligible account/slot" and the dispatcher would report the infra
    # failure as "account cap is active"; issue #28, live incident 2026-07-17).
    try:
        with _StubLedger([{"handle": "acct02", "models": ["fable"], "max_concurrent_workers": 3,
                           "available": True, "secret_ref": "ACCT02_TOKEN"}], [], write_ok=False):
            claim("r", "crate-c", "impl", ["fable"], "owner/repo#9@r.1", now,
                  account_pool=["acct02"], holder_prefix="owner/repo#", max_holder_concurrent=2)
        check("persistent ledger-write failure raises", "no exception", "LeaseIOError")
    except LeaseIOError:
        check("persistent ledger-write failure raises", "LeaseIOError", "LeaseIOError")
    check("none free", choose_account([{"handle": "a", "models": ["x"], "max_concurrent_workers": 0}],
                                      [], ["x"], "p", "r", now), None)
    pa = _parse_account("provider: openai\nmodels: [terra, gpt]\nmax_concurrent_workers: 2\n"
                        "secret_ref: ACCT01_TOKEN\ncredential_format: codex-auth-json")
    check("parse account", (pa["models"], pa["max_concurrent_workers"], pa["secret_ref"],
                            pa["credential_format"]),
          (["terra", "gpt"], 2, "ACCT01_TOKEN", "codex-auth-json"))

    # ---- usage-aware eligibility + expiry-priority + dynamic concurrency ----
    fresh = {"status": "allowed", "5h_util": 0.1, "5h_reset": 5000, "7d_util": 0.1, "7d_reset": 9000}
    check("eligible: allowed+headroom", usage_eligible(fresh), True)
    check("ineligible: missing", usage_eligible(None), False)
    check("ineligible: rejected", usage_eligible({**fresh, "status": "rejected"}), False)
    check("ineligible: 5h full", usage_eligible({**fresh, "5h_util": 0.95}), False)
    check("ineligible: 7d full", usage_eligible({**fresh, "7d_util": 0.95}), False)
    check("ineligible: unknown window", usage_eligible({"status": "allowed", "5h_util": 0.1}), False)
    # [#639] an exempt entry must CARRY its reachability; see the dedicated block below.
    live_exempt = {"exempt": True, "reachability": USAGE_REACHABILITY_LIVE}
    check("eligible: exempt provider (codex) with proven reachability",
          usage_eligible(dict(live_exempt)), True)
    # [ISSUE #196] malformed base SHAPE must fail CLOSED, not fail open as eligible capacity. Each
    # of these admitted the account before the fix: a NaN window (all comparisons false, so the
    # `(1 - util) < margin` headroom test never fired), a NEGATIVE utilization (looks like excess
    # headroom), an out-of-range fraction, and an EMPTY/MISSING status (once read as `allowed`).
    check("ineligible: NaN 5h util (fails open pre-fix)",
          usage_eligible({**fresh, "5h_util": float("nan")}), False)
    check("ineligible: string NaN 5h util", usage_eligible({**fresh, "5h_util": "nan"}), False)
    check("ineligible: negative 7d util (fake headroom pre-fix)",
          usage_eligible({**fresh, "7d_util": -1}), False)
    check("ineligible: string negative util", usage_eligible({**fresh, "5h_util": "-1"}), False)
    check("ineligible: out-of-range (>1) utilization", usage_eligible({**fresh, "5h_util": 1.5}), False)
    check("ineligible: empty status (once accepted as allowed)",
          usage_eligible({**fresh, "status": ""}), False)
    check("ineligible: missing status",
          usage_eligible({"5h_util": 0.1, "5h_reset": 5000, "7d_util": 0.1, "7d_reset": 9000}), False)

    # ---- probe-exempt (openai) + reactive backoff (decision 2026-07-17, registry issue #29) ----
    # (i) openai/codex accounts are eligible WITHOUT usage data — deleting the exempt arm turns
    # this red (the entry has no 5h/7d windows, so the fail-closed arm would reject it).
    check("exempt (openai): eligible with NO usage windows at all",
          usage_eligible(dict(live_exempt), now=now), True)
    # (iv) the exemption must NOT leak across providers: a non-exempt (anthropic) entry with the
    # same missing windows stays ineligible.
    check("anthropic without windows still fail-closed (no cross-provider leak)",
          usage_eligible({"status": "allowed"}, now=now), False)
    # (ii) an ACTIVE backoff excludes the account; (iii) an EXPIRED one readmits it.
    check("exempt with ACTIVE backoff excluded",
          usage_eligible({**live_exempt, "backoff_until": now + 60}, now=now), False)
    check("exempt with EXPIRED backoff eligible again",
          usage_eligible({**live_exempt, "backoff_until": now - 1}, now=now), True)
    # (v) a forged/malformed stamp fails OPEN to no-backoff (never crashes, never starves).
    check("malformed backoff stamp fails open",
          usage_eligible({**live_exempt, "backoff_until": "garbage"}, now=now), True)
    # (cross-provider review r1) non-finite stamps fail OPEN — inf must not sideline forever…
    check("inf backoff stamp fails open (no indefinite sideline)",
          usage_eligible({**live_exempt, "backoff_until": "inf"}, now=now), True)
    check("nan backoff stamp fails open",
          usage_eligible({**live_exempt, "backoff_until": "nan"}, now=now), True)
    # a huge JSON int (10**400) makes float() RAISE OverflowError, not return inf — the forged
    # stamp must fail open to no-backoff, never abort dispatch (cross-provider review r2 f3)
    check("huge-int backoff stamp fails open (OverflowError, no dispatch abort)",
          usage_eligible({**live_exempt, "backoff_until": 10**400}, now=now), True)

    # ---- [registry #639] EXEMPTION IS NOT REACHABILITY ------------------------------------------
    # THE defect: `{"exempt": True}` alone used to be eligible, so `acct01` — diagnosed dead
    # (`credential-remint-required`, #596 / alert #622) and the fleet's only cross-provider review
    # account — was handed to the allocator on every tick. Mutating the exempt arm back to
    # unconditional-available reds the first two rows here.
    check("[#639] exempt + credential proven DEAD is INELIGIBLE (was eligible: the live defect)",
          usage_eligible({"exempt": True, "reachability": USAGE_REACHABILITY_DEAD}, now=now), False)
    check("[#639] exempt with NO reachability stated at all is INELIGIBLE (unstated ⇒ refused)",
          usage_eligible({"exempt": True}, now=now), False)
    check("[#639] dead beats an expired backoff (it is evidence, not a TTL)",
          usage_eligible({"exempt": True, "reachability": USAGE_REACHABILITY_DEAD,
                          "backoff_until": now - 10_000}, now=now), False)
    # `unproven` admits — bounded to CREDENTIAL_DEAD_MIN trials per window — because there is no
    # independent liveness probe to break the no-dispatch/no-evidence deadlock (see the constant
    # block above). It is an EXPLICIT producer verdict, never an absent field.
    check("[#639] exempt + explicitly UNPROVEN reachability still admits (bounded trials)",
          usage_eligible({"exempt": True, "reachability": USAGE_REACHABILITY_UNPROVEN}, now=now),
          True)
    check("[#639] an unproven exempt account is still excluded by an ACTIVE backoff",
          usage_eligible({"exempt": True, "reachability": USAGE_REACHABILITY_UNPROVEN,
                          "backoff_until": now + 60}, now=now), False)
    # The admitting values are an ALLOWLIST, so every unrecognised/forged spelling fails CLOSED —
    # including the ones that merely LOOK healthy.
    for forged in ("LIVE", " live ", "available", "ok", True, 1, None, {}, ["live"]):
        check(f"[#639] forged reachability {forged!r} does not admit an exempt account",
              usage_eligible({"exempt": True, "reachability": forged}, now=now), False)
    # The gate is scoped to the EXEMPT arm: a probed anthropic account is admitted on its windows
    # and must not start needing a reachability stamp (that would starve the metered fleet).
    check("[#639] a probed (non-exempt) account needs no reachability stamp",
          usage_eligible(dict(fresh), now=now), True)
    # …and the exempt flag is STRICT: a forged truthy string must not exempt an account whose
    # entry otherwise lacks usage windows (would-be anthropic bypass).
    check("forged exempt='false' string does NOT exempt (fail-closed)",
          usage_eligible({"exempt": "false", "status": "allowed"}, now=now), False)
    check("forged exempt=1 does NOT exempt (fail-closed)",
          usage_eligible({"exempt": 1, "status": "allowed"}, now=now), False)
    # choose_account skips a backed-off exempt account and picks the free one; None when all backed off.
    OA = [{"handle": "cx1", "models": ["terra"], "max_concurrent_workers": 1, "available": True},
          {"handle": "cx2", "models": ["terra"], "max_concurrent_workers": 1, "available": True}]
    ousage = {"cx1": {**live_exempt, "backoff_until": now + 500}, "cx2": dict(live_exempt)}
    check("choose_account skips the backed-off exempt account",
          choose_account(OA, [], ["terra"], "p", "r", now, usage=ousage), "cx2")
    check("choose_account None when every exempt account is backed off",
          choose_account(OA, [], ["terra"], "p", "r", now,
                         usage={h: {**live_exempt, "backoff_until": now + 500} for h in ("cx1", "cx2")}),
          None)
    check("dynamic concurrency excludes the backed-off exempt account",
          dynamic_concurrency(OA, ousage, ["terra"], now=now), 1)
    # [#639] the same exclusion through the REAL selection call sites, not just the predicate: a dead
    # credential must not be selectable and must not contribute capacity.
    dead_usage = {"cx1": {"exempt": True, "reachability": USAGE_REACHABILITY_DEAD},
                  "cx2": dict(live_exempt)}
    check("[#639] choose_account skips the DEAD exempt account and takes the live one",
          choose_account(OA, [], ["terra"], "p", "r", now, usage=dead_usage), "cx2")
    check("[#639] a wholly dead exempt fleet selects NOTHING (no runner spent on a dead account)",
          choose_account(OA, [], ["terra"], "p", "r", now,
                         usage={h: {"exempt": True, "reachability": USAGE_REACHABILITY_DEAD}
                                for h in ("cx1", "cx2")}), None)
    check("[#639] a dead exempt account contributes no dynamic-concurrency capacity",
          (dynamic_concurrency(OA, dead_usage, ["terra"], now=now),
           available_account_slots(OA, [], ["terra"], now, usage=dead_usage)), (1, 1))
    U = [{"handle": "soon", "models": ["fable"], "max_concurrent_workers": 1, "available": True},
         {"handle": "middle", "models": ["fable"], "max_concurrent_workers": 1, "available": True},
         {"handle": "late", "models": ["fable"], "max_concurrent_workers": 1, "available": True},
         {"handle": "full", "models": ["fable"], "max_concurrent_workers": 1, "available": True}]
    usage = {
        "soon": {"status": "allowed", "5h_util": 0.2, "5h_reset": 100, "7d_util": 0.2, "7d_reset": 3000,
                 "fable_ok": True, "fable_7d_oi_util": 0.2, "fable_7d_oi_reset": 3000},
        "middle": {"status": "allowed", "5h_util": 0.2, "5h_reset": 100, "7d_util": 0.2, "7d_reset": 5000,
                   "fable_ok": True, "fable_7d_oi_util": 0.2, "fable_7d_oi_reset": 5000},
        "late": {"status": "allowed", "5h_util": 0.2, "5h_reset": 100, "7d_util": 0.2, "7d_reset": 8000,
                 "fable_ok": True, "fable_7d_oi_util": 0.2, "fable_7d_oi_reset": 8000},
        "full": {"status": "allowed", "5h_util": 0.99, "5h_reset": 100, "7d_util": 0.99, "7d_reset": 1000},
    }
    # expiry-priority: 'soon' (7d_reset 3000) beats 'late' (8000); 'full' is ineligible (no headroom).
    check("expiry priority picks soonest reset",
          choose_account(U, [], ["fable"], "p", "r", now, usage=usage), "soon")
    # if 'soon' is removed from usage entirely -> fail-closed skip -> next reset wins.
    check("fail-closed on missing usage",
          choose_account(U, [], ["fable"], "p", "r", now, usage={k: v for k, v in usage.items() if k != "soon"}),
          "middle")
    # dynamic concurrency: 3 eligible (soon,middle,late), 'full' backs off; absolute_cap clamps.
    check("dynamic concurrency counts eligible", dynamic_concurrency(U, usage, ["fable"]), 3)
    check("dynamic concurrency absolute cap", dynamic_concurrency(U, usage, ["fable"], absolute_cap=1), 1)
    allfull = {h: {**usage["full"]} for h in ("soon", "middle", "late", "full")}
    check("dynamic concurrency backs off to 0 when tapped out",
          dynamic_concurrency(U, allfull, ["fable"]), 0)
    check("dynamic concurrency 0 without usage (caller falls back to static)",
          dynamic_concurrency(U, None, ["fable"]), 0)
    # backward compat: usage=None keeps the original cache-affinity selection.
    check("usage=None backward compatible", choose_account(A, [], ["fable"], "pkg", "impl", now), "acct02")

    # ---- [FABLE-5] fable sub-quota (7d_oi) gate ----
    fable_ok = {**fresh, "fable_ok": True, "fable_7d_oi_util": 0.1, "fable_7d_oi_reset": 9000}
    check("fable eligible: whole-account + fable headroom",
          usage_eligible(fable_ok, model="fable"), True)
    check("non-fable model ignores fable bucket (haiku on same acct)",
          usage_eligible(fresh, model="haiku"), True)
    check("fable ineligible: bucket exhausted (whole-account fine)",
          usage_eligible({**fable_ok, "fable_7d_oi_util": 0.95}, model="fable"), False)
    check("same acct still eligible for haiku when fable bucket exhausted",
          usage_eligible({**fable_ok, "fable_7d_oi_util": 0.95}, model="haiku"), True)
    # Issue #450: the premium sub-quota is model-specific. A sol-authored PR reviews on OPUS;
    # exhausting Fable on an otherwise healthy anthropic account must not erase that OPUS slot.
    fable_capped = {**fable_ok, "fable_7d_oi_util": 1.0}
    check("Fable-100% account remains eligible for opus review",
          usage_eligible(fable_capped, model="opus"), True)
    opus_account = [{"handle": "acctopus", "models": ["fable", "opus"],
                     "max_concurrent_workers": 2, "available": True}]
    check("Fable-100% account contributes its opus review slots",
          available_account_slots(opus_account, [], ["opus", "fable"], now,
                                  usage={"acctopus": fable_capped}), 2)
    check("opus review selects the healthy account despite its capped Fable bucket",
          choose_account(opus_account, [], ["opus", "fable"], "p", "review", now,
                         usage={"acctopus": fable_capped}), "acctopus")
    check("fable ineligible: probe absent (fable_ok missing) fails closed",
          usage_eligible(fresh, model="fable"), False)
    check("fable ineligible: probe failed (fable_ok False)",
          usage_eligible({**fresh, "fable_ok": False}, model="fable"), False)
    check("fable ineligible: 7d_oi window unknown",
          usage_eligible({**fresh, "fable_ok": True}, model="fable"), False)

    # ---- [#720] opus5 premium sub-quota: OBSERVE, then gate --------------------------------------
    # opus5 is the SOLE anthropic tier. Before #720 nothing gated it on a premium bucket, so an
    # account with healthy WHOLE-ACCOUNT headroom admitted an opus5 worker even if its own bucket
    # was exhausted — the worker then fails MID-RUN, burning credits and a lease. `fresh` below is
    # exactly that account: 5h/7d at 10 %, i.e. the pre-#720 gate says "plenty of room".
    #
    # WHO WRITES THESE FIELDS: account-usage.py's `_assemble_opus5`, from the headers claude-opus-5
    # really returned. Its own self-test drives THESE key names through THIS function, so a rename
    # on either side reds there; the rows here pin the DECISION each observation must produce.
    opus5_cliff = {**fresh, "opus5_probe": "observed",
                   OPUS5_PREMIUM_WINDOW_KEY: "7d_oi", OPUS5_PREMIUM_UTIL_KEY: "0.96"}
    opus5_room = {**opus5_cliff, OPUS5_PREMIUM_UTIL_KEY: "0.05"}
    # (1) THE OBLIGATION: healthy whole-account headroom, exhausted opus5 bucket -> REFUSED.
    #     MUTANT: remove "opus5" from PREMIUM_WINDOW_GATES, or make `_opus5_eligible` return True
    #     unconditionally => this flips.
    check("[#720] REFUSED: whole-account headroom is healthy but the opus5 bucket is exhausted",
          usage_eligible(opus5_cliff, model="opus5"), False)
    # ... and the PAIR that proves the row above is the gate and not a broken fixture.
    check("[#720] ADMITTED: the same account with headroom IN the opus5 bucket",
          usage_eligible(opus5_room, model="opus5"), True)
    # (2) NO REGRESSION: an account with NO opus5 bucket data at all behaves exactly as today.
    #     MUTANT: make an absent window fail closed => the fleet's only anthropic tier parks on the
    #     first tick this ships, which is the outcome #720 explicitly refuses.
    check("[#720] NO REGRESSION: no opus5 bucket data -> admitted, as before",
          (usage_eligible(fresh, model="opus5"),
           usage_eligible({**fresh, "opus5_probe": "error"}, model="opus5"),
           usage_eligible({**fresh, "opus5_probe": "no-headers"}, model="opus5")),
          (True, True, True))
    # (3) FAIL CLOSED ON THE CLIFF, NOT OPEN: a DECLARED bucket that cannot be read must refuse
    #     rather than fall back to whole-account headroom — an unknown premium bucket is exactly the
    #     case where whole-account headroom is misleading. Each shape below admitted pre-#720.
    for _label, _bad in (("absent utilization", None), ("empty", ""), ("garbage", "unavailable"),
                         ("NaN", "nan"), ("negative (fake headroom)", "-1"),
                         ("out of range", "1.5"), ("non-string window", 7),
                         ("blank window name", "   ")):
        _entry = {**opus5_cliff}
        if _label in ("non-string window", "blank window name"):
            _entry[OPUS5_PREMIUM_WINDOW_KEY] = _bad
            _entry[OPUS5_PREMIUM_UTIL_KEY] = "0.05"     # a HEALTHY util must not rescue it
        elif _bad is None:
            _entry.pop(OPUS5_PREMIUM_UTIL_KEY)
        else:
            _entry[OPUS5_PREMIUM_UTIL_KEY] = _bad
        check(f"[#720] REFUSED: opus5 bucket declared but unreadable ({_label})",
              usage_eligible(_entry, model="opus5"), False)
    # (4) The bucket is MODEL-SPECIFIC (the issue #450 lesson, re-asked for opus5): an exhausted
    #     opus5 bucket must not erase the same account's slots for any other alias.
    check("[#720] a cliffed opus5 bucket leaves haiku/sonnet/sol routing on that account untouched",
          (usage_eligible(opus5_cliff, model="haiku"), usage_eligible(opus5_cliff, model="sonnet"),
           usage_eligible(opus5_cliff, model=None)),
          (True, True, True))
    # (5) PREMIUM_MODELS is DERIVED from the gate map, so an alias can never be premium in name and
    #     ungated in fact. MUTANT: re-introduce a hand-written `PREMIUM_MODELS = frozenset({...})`
    #     that omits opus5 => the membership row flips while every gate row above stays green.
    check("[#720] every premium alias HAS a gate, and every gate IS a premium alias",
          (PREMIUM_MODELS, frozenset(PREMIUM_WINDOW_GATES), "opus5" in PREMIUM_MODELS),
          (frozenset({"fable", "opus5"}), frozenset({"fable", "opus5"}), True))
    # (6) An ill-typed alias must fail CLOSED, never raise: an unhashable value from a hand-edited
    #     chain would abort the whole dispatch at the dict lookup (the OverflowError lesson).
    check("[#720] an ill-typed model alias is refused, not raised",
          (usage_eligible(fresh, model=["opus5"]), usage_eligible(fresh, model=7)), (False, False))
    # (7) THE CLIFF DELIVERS INTO A CAPACITY CONDITION, NOT A ROUTING ONE. dispatch-claim's
    #     `escalate_starved(escalate, usage, effective_cap)` reads exactly two things: a live usage
    #     map (NOT None) and a zero effective cap. A cliffed fleet must produce BOTH — a measured,
    #     non-empty snapshot whose eligible capacity is zero — because that is what routes to the
    #     machine-owned `status:parked` capacity hold with an automatic re-admission path, instead
    #     of the `usage is None` arm (an unmeasured fleet, which merely defers with no receipt).
    #     The dispatch-claim self-test asserts the other half of this composition against the LIVE
    #     routing table's single-rung opus5 chains.
    O5 = [{"handle": "o5a", "models": ["opus5"], "max_concurrent_workers": 2, "available": True},
          {"handle": "o5b", "models": ["opus5"], "max_concurrent_workers": 2, "available": True}]
    cliffed_fleet = {"o5a": dict(opus5_cliff), "o5b": dict(opus5_cliff)}
    healthy_fleet = {"o5a": dict(opus5_room), "o5b": dict(opus5_room)}
    check("[#720] a fleet-wide opus5 bucket cliff is MEASURED capacity exhaustion (cap 0, map live)",
          (dynamic_concurrency(O5, cliffed_fleet, ["opus5"]), cliffed_fleet == {},
           choose_account(O5, [], ["opus5"], "p", "r", now, usage=cliffed_fleet)),
          (0, False, None))
    check("[#720] ... and the same fleet with bucket headroom still serves opus5 (not a dead fixture)",
          (dynamic_concurrency(O5, healthy_fleet, ["opus5"]),
           choose_account(O5, [], ["opus5"], "p", "r", now, usage=healthy_fleet)),
          (4, "o5a"))

    # choose_account: fable route skips a fable-exhausted account, picks the healthy one.
    F = [{"handle": "fa", "models": ["fable"], "max_concurrent_workers": 1, "available": True},
         {"handle": "fb", "models": ["fable"], "max_concurrent_workers": 1, "available": True}]
    fusage = {
        "fa": {**fresh, "7d_reset": 3000, "fable_ok": True, "fable_7d_oi_util": 0.99, "fable_7d_oi_reset": 3000},
        "fb": {**fresh, "7d_reset": 8000, "fable_ok": True, "fable_7d_oi_util": 0.1, "fable_7d_oi_reset": 8000},
    }
    check("fable route skips exhausted-bucket account",
          choose_account(F, [], ["fable"], "p", "r", now, usage=fusage), "fb")
    # Drain priority always follows the whole-account weekly reset; fable_7d_oi remains an eligibility
    # gate but does not replace the provider-wide 7d ordering signal.
    fusage2 = {
        "fa": {**fresh, "7d_reset": 8000, "fable_ok": True,
               "fable_7d_oi_util": 0.1, "fable_7d_oi_reset": 3000},
        "fb": {**fresh, "7d_reset": 3000, "fable_ok": True,
               "fable_7d_oi_util": 0.1, "fable_7d_oi_reset": 8000},
    }
    check("fable drain uses whole-account 7d reset, not sub-quota reset",
          choose_account(F, [], ["fable"], "p", "r", now, usage=fusage2), "fb")
    # dynamic_concurrency on a fable-only chain counts only fable-eligible accounts.
    check("dynamic concurrency (fable chain) counts fable-eligible only",
          dynamic_concurrency(F, fusage, ["fable"]), 1)
    check("dynamic concurrency (haiku chain) ignores fable bucket",
          dynamic_concurrency(
              [{"handle": "fa", "models": ["haiku"], "max_concurrent_workers": 1, "available": True}],
              {"fa": {**fresh, "fable_ok": True, "fable_7d_oi_util": 0.99}}, ["haiku"]), 1)
    # [FABLE-5] claim() model assignment must match the pass that admitted the account: an account serving
    # BOTH fable+haiku with an EXHAUSTED fable bucket, on a ["fable","haiku"] chain, must be claimed as
    # haiku (not fable), or the gate is defeated.

    class _StubClaim:
        """Drive claim()'s pure decision path without GitHub I/O by stubbing the ledger/catalog."""
        def __init__(self, accounts):
            self.accounts, self.written = accounts, None

        def __enter__(self):
            self._ra, self._rl, self._wl = read_accounts, _read_ledger, _write_ledger
            return self

        def __exit__(self, *a):
            globals()["read_accounts"], globals()["_read_ledger"], globals()["_write_ledger"] = \
                self._ra, self._rl, self._wl

    drain_accounts = [
        {"handle": "acct-late", "models": ["haiku"], "max_concurrent_workers": 2,
         "available": True},
        {"handle": "acct-middle", "models": ["haiku"], "max_concurrent_workers": 2,
         "available": True},
        {"handle": "acct-soon", "models": ["haiku"], "max_concurrent_workers": 2,
         "available": True},
        {"handle": "a-missing", "models": ["haiku"], "max_concurrent_workers": 2,
         "available": True},
        {"handle": "z-missing", "models": ["haiku"], "max_concurrent_workers": 2,
         "available": True},
    ]
    without_reset = {key: value for key, value in fresh.items() if key != "7d_reset"}
    drain_usage = {
        "acct-late": {**fresh, "7d_reset": 9000},
        "acct-middle": {**fresh, "7d_reset": 6000},
        "acct-soon": {**fresh, "7d_reset": 3000},
        "a-missing": dict(without_reset),
        "z-missing": dict(without_reset),
    }
    warm_missing = [
        make_lease("z-missing", "other/repo#1@run", "p", "impl", "haiku", now - 5, 100),
    ]
    check("weekly-drain fixture accounts are all otherwise eligible",
          [usage_eligible(drain_usage[a["handle"]], model="haiku") for a in drain_accounts],
          [True, True, True, True, True])
    check("weekly drain sorts three resets soonest and leaves missing resets last/stable",
          [account["handle"] for account in _order_eligible_accounts(
              drain_accounts, warm_missing, drain_usage, "p", "impl")],
          ["acct-soon", "acct-middle", "acct-late", "z-missing", "a-missing"])

    claim_accounts = drain_accounts[:3]
    with _StubClaim(claim_accounts):
        globals()["read_accounts"] = lambda repo: claim_accounts
        globals()["_read_ledger"] = lambda repo, budget=None: ([], "sha0")
        globals()["_write_ledger"] = lambda repo, leases, sha, msg, budget=None: True
        drained = claim("r", "p", "impl", ["haiku"], "o/r#1@run", now,
                        usage=drain_usage)
    check("claim picks soonest of three distinct eligible weekly resets",
          drained and drained["account"], "acct-soon")

    dual = [{"handle": "acctdual", "models": ["fable", "haiku"], "max_concurrent_workers": 1,
             "available": True}]
    dual_usage = {"acctdual": {**fresh, "fable_ok": True, "fable_7d_oi_util": 0.99,
                               "fable_7d_oi_reset": 9000}}
    with _StubClaim(dual):
        globals()["read_accounts"] = lambda repo: dual
        globals()["_read_ledger"] = lambda repo, budget=None: ([], "sha0")
        globals()["_write_ledger"] = lambda repo, leases, sha, msg, budget=None: True
        claimed = claim("r", "p", "impl", ["fable", "haiku"], "o/r#1@run", now,
                        account_pool=["acctdual"], usage=dual_usage, margin=0.15)
    check("claim assigns model consistent with the admitting pass (haiku, not fable)",
          claimed and claimed["model"], "haiku")

    # ---- ledger-branch targeting (issue #28: data plane off the protected code branch) ----
    # Literal "ledger" on purpose: pointing either helper back at the default branch (or changing
    # the shipped REGISTRY_LEDGER_REF default) must turn these red.
    check("ledger read targets the ledger ref",
          ledger_read_path("o/r"), f"repos/o/r/contents/{LEDGER_PATH}?ref=ledger")
    wargs = ledger_write_args("o/r", "m", "Zm9v", "sha1")
    check("ledger write pins branch=ledger", "branch=ledger" in wargs, True)
    check("ledger write carries the CAS sha", "sha=sha1" in wargs, True)
    check("ledger write without sha omits it (create-if-absent)",
          any(a.startswith("sha=") for a in ledger_write_args("o/r", "m", "Zm9v", None)), False)
    check("404 with ledger branch present seeds an empty ledger", _read_404(True), ([], None))
    try:
        _read_404(False)
        check("404 with ledger branch MISSING fails loud", "no exception", "LeaseIOError")
    except LeaseIOError:
        check("404 with ledger branch MISSING fails loud", "LeaseIOError", "LeaseIOError")

    # ---- CAS conflict-retry against the ledger ref (fixture-level, through the REAL I/O fns) ----
    class _Res:
        def __init__(self, returncode, stdout="", stderr=""):
            self.returncode, self.stdout, self.stderr = returncode, stdout, stderr

    fixture_calls = []

    def _fake_gh(args, **_kwargs):
        fixture_calls.append(list(args))
        if "-X" not in args:  # contents GET: one expired lease, fresh sha per read
            expired = make_lease("a1", "o/r#1@run", "p", "impl", "m", now - 100, 1)
            expired["claim_id"] = "a" * 32
            meta = {"content": base64.b64encode(json.dumps(
                {"leases": [expired]}
            ).encode()).decode(), "sha": f"sha{len(fixture_calls)}"}
            return _Res(0, stdout=json.dumps(meta))
        puts = sum(1 for c in fixture_calls if "-X" in c)
        return _Res(1 if puts == 1 else 0, stderr="HTTP 409")  # first PUT loses the CAS race

    real_run = subprocess.run
    real_backoff = globals()["_sleep_backoff"]
    real_jitter = globals()["_pre_write_jitter"]
    backoff_attempts = []
    jitter_at_call = []
    subprocess.run = _fake_gh
    globals()["_sleep_backoff"] = lambda attempt: backoff_attempts.append(attempt)
    globals()["_pre_write_jitter"] = lambda: jitter_at_call.append(len(fixture_calls))
    try:
        reclaimed = reclaim("o/r", now)
    finally:
        subprocess.run = real_run
        globals()["_sleep_backoff"] = real_backoff
        globals()["_pre_write_jitter"] = real_jitter
    fixture_gets = [c for c in fixture_calls if "-X" not in c]
    fixture_puts = [c for c in fixture_calls if "-X" in c]
    check("fixture reclaim rides out one CAS conflict", reclaimed.reclaimed, 1)
    check("fixture reclaim re-read after the conflict (CAS retry)", len(fixture_gets), 2)
    check("fixture reads all target the ledger ref",
          all(c[2].endswith("?ref=ledger") for c in fixture_gets), True)
    check("fixture writes all pin branch=ledger",
          [sum(1 for a in c if a == "branch=ledger") for c in fixture_puts], [1, 1])
    # Backoff fires BETWEEN CAS attempts, never before the first read (issue #179): one conflict
    # here means exactly one jittered sleep, for retry attempt 1.
    check("fixture reclaim backs off once (only between attempts)", backoff_attempts, [1])
    # De-synchronization jitter (#558 part b) fires EXACTLY ONCE per CAS transaction and BEFORE the
    # first gh call — jittering between the read and the PUT would widen the CAS window instead.
    check("pre-write jitter fires once, before the first ledger read", jitter_at_call, [0])
    # The conflict retry RE-DERIVED its expected revision: each PUT carries the sha the read that
    # PRECEDED it returned (the fixture mints a fresh `sha<call-index>` per read), so the second PUT
    # is provably not a replay of the first, now-stale, expected-SHA.
    fixture_get_shas = [f"sha{i + 1}" for i, c in enumerate(fixture_calls) if "-X" not in c]
    check("conflict retry re-derives the expected sha from a fresh read",
          [next(a for a in c if a.startswith("sha=")) for c in fixture_puts],
          [f"sha={s}" for s in fixture_get_shas])

    # ---- registry #1246: the READ half of a CAS transaction rides out a throttle --------------
    # THE LIVE FAILURE this pins (measured 2026-07-27..29, 23 runs): a worker published its pull
    # request, then `release` died on the FIRST throttled contents GET with a status-less "lease
    # ledger read failed" — stranding a scarce account lease for the rest of its 105-minute TTL.
    # The PUT half has ridden exactly this out since #558; the GET two lines above it had no
    # retry at all. Reverting `_read_ledger` to raise on the first non-404 failure turns the first
    # three rows below red; dropping `, budget` at any transaction call site turns the fourth red.
    throttled_get = ("gh: API rate limit exceeded for installation. If you reach out to GitHub "
                     "Support for help, please include the request ID EC30:2B1128 (HTTP 403)")
    released = make_lease("a1", "o/r#1@run", "p", "impl", "m", now, 100)
    released["claim_id"] = "b" * 32
    read_fixture_calls = []

    def _throttled_then_ok(args, **_kwargs):
        read_fixture_calls.append(list(args))
        if "-X" in args:
            return _Res(0)                                   # the PUT lands first time
        if sum(1 for c in read_fixture_calls if "-X" not in c) == 1:
            return _Res(1, stderr=throttled_get)             # ...but the FIRST GET is throttled
        meta = {"content": base64.b64encode(json.dumps({"leases": [released]}).encode()).decode(),
                "sha": "sha-live"}
        return _Res(0, stdout=json.dumps(meta))

    read_throttle_sleeps = []
    real_sleep_transient = ledger_retry.sleep_transient
    subprocess.run = _throttled_then_ok
    globals()["_pre_write_jitter"] = lambda: None
    ledger_retry.sleep_transient = lambda attempt, retry_after=None: read_throttle_sleeps.append(
        (attempt, retry_after))
    saved_spent = _throttle_wait["spent"]
    _throttle_wait["spent"] = 0.0
    try:
        rode_it_out = release("o/r", "b" * 32, now)
    finally:
        subprocess.run = real_run
        globals()["_pre_write_jitter"] = real_jitter
        ledger_retry.sleep_transient = real_sleep_transient
        _throttle_wait["spent"] = saved_spent
    read_gets = [c for c in read_fixture_calls if "-X" not in c]
    read_puts = [c for c in read_fixture_calls if "-X" in c]
    check("[#1246] a throttled ledger READ is retried and the release still lands",
          (rode_it_out, len(read_gets), len(read_puts)), (True, 2, 1))
    # The THROTTLE schedule (gh_retry 2s->30s), not the sub-second CAS-contention one: re-firing a
    # burst limiter in 0.5s just re-trips it. `_sleep_backoff` is untouched here — a contention
    # sleep would mean the read failure was misrouted through the conflict path.
    check("[#1246] the throttled READ slept the shared throttle schedule once",
          read_throttle_sleeps, [(1, None)])
    # Fail-at-once is still the default for callers with no transaction loop (inspect_claim), and
    # the loud message now carries the STATUS — the missing field that made 23 live failures
    # unattributable. Only the status, never the body: that is the LeaseIOError contract.
    read_probe_calls = []

    def _always_throttled(args, **_kwargs):
        read_probe_calls.append(list(args))
        return _Res(1, stderr=throttled_get)

    subprocess.run = _always_throttled
    try:
        try:
            _read_ledger("o/r")
            check("[#1246] a budget-less READ fails loud at once, quoting only the status",
                  "no exception", "LeaseIOError")
        except LeaseIOError as exc:
            check("[#1246] a budget-less READ fails loud at once, quoting only the status",
                  ("HTTP 403" in str(exc), "request ID" in str(exc), len(read_probe_calls)),
                  (True, False, 1))
        # A PERMISSION 403 is a refusal, not a throttle: it must never be retried even WITH a
        # budget, or an unwound App permission would burn the budget to reach the same failure.
        read_probe_calls.clear()
        subprocess.run = lambda args, **k: (read_probe_calls.append(list(args)),
                                            _Res(1, stderr="gh: Resource not accessible by "
                                                            "integration (HTTP 403)"))[1]
        try:
            _read_ledger("o/r", TransientWriteBudget(attempts=5, sleep=lambda *a, **k: None))
            check("[#1246] a permission-403 READ is FATAL even with a budget",
                  "no exception", "LeaseIOError")
        except LeaseIOError:
            check("[#1246] a permission-403 READ is FATAL even with a budget",
                  ("LeaseIOError", len(read_probe_calls)), ("LeaseIOError", 1))
        # THE CLASSIFIER CHOICE ITSELF. A STATUSLESS transport failure is the one input on which
        # the read-scoped classifier (`classify_read_failure`, registry #748: an unclassifiable
        # READ defaults to RETRY) and the conservative write-scoped one (`is_transient_stderr`:
        # defaults to FATAL) DISAGREE — and it is the shape a throttled/dropped GET actually takes
        # when gh prints no status, which is precisely the shape that stranded these leases with no
        # status in the log. Pointing `_is_retryable_read_error` at `ledger_retry.is_transient`
        # turns this row red while every other row above stays green.
        read_probe_calls.clear()
        statusless = "error connecting to api.github.com"

        def _statusless_then_ok(args, **_kwargs):
            read_probe_calls.append(list(args))
            if len(read_probe_calls) == 1:
                return _Res(1, stderr=statusless)
            meta = {"content": base64.b64encode(json.dumps({"leases": []}).encode()).decode(),
                    "sha": "sha-after-transport-blip"}
            return _Res(0, stdout=json.dumps(meta))

        subprocess.run = _statusless_then_ok
        check("[#1246] a STATUSLESS read failure retries (the read-scoped classifier, not the "
              "write one)",
              (_read_ledger("o/r", TransientWriteBudget(attempts=5, sleep=lambda *a, **k: None)),
               len(read_probe_calls)),
              (([], "sha-after-transport-blip"), 2))
        # A budget that EXHAUSTS on the read must say so. Dropping `operation="read"` at the read
        # call site restores the message that made these 23 failures unattributable in the first
        # place — an operator reading "CAS PUT" hunts a write that never happened.
        read_probe_calls.clear()
        subprocess.run = _always_throttled
        try:
            _read_ledger("o/r", TransientWriteBudget(attempts=2, sleep=lambda *a, **k: None))
            check("[#1246] READ budget exhaustion names the READ, not the PUT",
                  "no exception", "LeaseIOError")
        except LeaseIOError as exc:
            check("[#1246] READ budget exhaustion names the READ, not the PUT",
                  ("read" in str(exc), "CAS PUT" in str(exc), len(read_probe_calls)),
                  (True, False, 2))
    finally:
        subprocess.run = real_run
    # ---- ONE budget INSTANCE across both halves, not merely "a second argument" ---------------
    # ARITY IS NOT IDENTITY (review round 1 of #1246). The first version of the pin below asserted
    # only that `_read_ledger` received a second argument. Handing each call site a FRESH
    # `TransientWriteBudget()` satisfies that — and a fresh budget per half is precisely the
    # DOUBLED-ALLOWANCE defect this change exists to avoid: two half-budgets tolerate 2x the
    # throttle the bound promises, and a transaction can outlive it. So both a RUNTIME row (the
    # instance and its accumulated counter) and a STRUCTURAL row (one mint, threaded to both
    # halves) are asserted, and each reds on the fresh-budget mutant on its own.
    #
    # RUNTIME: drive a real `release()` and record `id(budget)` at both halves plus the rejection
    # counter as each half sees it. One id and a counter that CARRIES (0 at the read, 1 at the PUT
    # after the read absorbed one) is the property; a fresh mint gives two ids and a counter that
    # resets to 0.
    identity_seen = []

    def _identity_read(repo, budget=None):
        identity_seen.append(("read", id(budget), None if budget is None else budget.rejections))
        if budget is not None:
            budget.rejections += 1            # one absorbed read rejection, carried into the PUT
        return [dict(released)], "sha-identity"

    def _identity_write(repo, leases, sha, message, budget=None):
        identity_seen.append(("put", id(budget), None if budget is None else budget.rejections))
        return True

    saved_rl, saved_wl = globals()["_read_ledger"], globals()["_write_ledger"]
    globals()["_read_ledger"] = _identity_read
    globals()["_write_ledger"] = _identity_write
    globals()["_pre_write_jitter"] = lambda: None
    try:
        identity_released = release("o/r", "b" * 32, now)
    finally:
        globals()["_read_ledger"], globals()["_write_ledger"] = saved_rl, saved_wl
        globals()["_pre_write_jitter"] = real_jitter
    check("[#1246] the READ and the PUT share ONE budget instance, whose count carries across",
          (identity_released,
           [half for half, _id, _n in identity_seen],
           len({_id for _half, _id, _n in identity_seen}),
           [n for _half, _id, n in identity_seen]),
          (True, ["read", "put"], 1, [0, 1]))
    # STRUCTURAL: re-derived from the parsed source, so it covers transactions this suite does not
    # drive and any future one. Every ledger transaction MINTS EXACTLY ONE budget and threads THAT
    # NAME to both its read and its PUT. Deleting `, budget` from a call site, or minting a second
    # budget for either half, turns this red and NAMES the function that did it.
    import ast as _ast_pin
    with open(__file__, encoding="utf-8") as _src:
        _module_ast = _ast_pin.parse(_src.read())

    def _budget_arg_name(call):
        """The NAME handed to this call as its budget, or None when it is anything else (a fresh
        `TransientWriteBudget()` mint is a Call, not a Name, so it can never satisfy this)."""
        node = None
        for keyword in call.keywords:
            if keyword.arg == "budget":
                node = keyword.value
        if node is None and len(call.args) >= 2 and getattr(call.func, "id", "") == "_read_ledger":
            node = call.args[1]
        if node is None and len(call.args) >= 5 and getattr(call.func, "id", "") == "_write_ledger":
            node = call.args[4]
        return node.id if isinstance(node, _ast_pin.Name) else None

    _budget_fns = []
    # TOP-LEVEL functions only, and never this suite: `_self_test` mints budgets and calls
    # `_read_ledger` directly BY DESIGN (rows above), so including it would assert against the test
    # rather than the production transactions. A new budgeted transaction that forgot the budget
    # still appears here as its own named row.
    for _node in _module_ast.body:
        if not isinstance(_node, _ast_pin.FunctionDef) or _node.name == "_self_test":
            continue
        # The name(s) bound by a `x = TransientWriteBudget(...)` assignment in this function.
        _mint_names = set()
        _mints = 0
        for _sub in _ast_pin.walk(_node):
            if isinstance(_sub, _ast_pin.Call) and getattr(_sub.func, "id", "") == "TransientWriteBudget":
                _mints += 1
            if isinstance(_sub, _ast_pin.Assign) and isinstance(_sub.value, _ast_pin.Call) \
                    and getattr(_sub.value.func, "id", "") == "TransientWriteBudget":
                _mint_names |= {t.id for t in _sub.targets if isinstance(t, _ast_pin.Name)}
        if not _mints:
            continue
        _calls = [c for c in _ast_pin.walk(_node)
                  if isinstance(c, _ast_pin.Call)
                  and getattr(c.func, "id", "") in ("_read_ledger", "_write_ledger")]
        _threaded = {c.func.id: sorted({_budget_arg_name(c) for c in _calls if c.func.id == n})
                     for n in ("_read_ledger", "_write_ledger") for c in _calls if c.func.id == n}
        _budget_fns.append((
            _node.name,
            _mints,                                            # exactly one mint per transaction
            sorted(_mint_names),                               # ...bound to one name
            _threaded.get("_read_ledger") == sorted(_mint_names),   # ...threaded to the READ
            _threaded.get("_write_ledger") == sorted(_mint_names),  # ...and to the PUT
        ))
    check("[#1246] every ledger transaction mints ONE budget and threads THAT name to read + PUT",
          sorted(_budget_fns),
          [("adopt", 1, ["budget"], True, True), ("claim", 1, ["budget"], True, True),
           ("reclaim", 1, ["budget"], True, True), ("release", 1, ["budget"], True, True)])

    # ---- CAS retry backoff schedule + typed PUT errors (issue #179) ----
    # Exponential, capped ceiling: dropping the exponent (linear) or the cap flips these red.
    check("backoff ceiling is exponential then capped",
          [_backoff_ceiling(a) for a in (1, 2, 3, 4, 5, 6, 10)],
          [0.5, 1.0, 2.0, 4.0, 8.0, 8.0, 8.0])
    # Full jitter: the delay must BE the RNG draw over exactly [0, ceiling]. Stubbing
    # random.uniform pins both properties — a deterministic delay (always 0, always the ceiling,
    # ceiling/2) would either never call the RNG or discard its draw, flipping these red.
    real_uniform = random.uniform
    uniform_calls = []
    sentinel = 123.456
    random.uniform = lambda lo, hi: (uniform_calls.append((lo, hi)), sentinel)[1]
    try:
        draws = [_backoff_delay(a) for a in range(1, 7)]
    finally:
        random.uniform = real_uniform
    check("backoff delay draws uniform(0, ceiling) with exact bounds",
          uniform_calls, [(0, _backoff_ceiling(a)) for a in range(1, 7)])
    check("backoff delay propagates the RNG draw unchanged", draws, [sentinel] * 6)
    # A genuine CAS conflict is retryable → False; any OTHER PUT failure fails LOUD with
    # LeaseIOError rather than being collapsed into "CAS kept conflicting" (the #179 complaint).
    # 422 is a conflict ONLY as the create-if-absent race: sha-less PUT + GitHub's
    # '"sha" wasn't supplied' signature — a bare 422 is a persistent payload/config validation
    # error that six retries would only obscure.
    race_422 = "gh: Invalid request.\n\n\"sha\" wasn't supplied. (HTTP 422)"
    real_run = subprocess.run
    subprocess.run = lambda args, **_k: _Res(0)
    try:
        check("successful PUT returns True", _write_ledger("o/r", [], "sha", "m"), True)
        subprocess.run = lambda args, **_k: _Res(1, stderr="gh: ... (HTTP 409)")
        check("CAS 409 PUT is retryable (False, not raise)", _write_ledger("o/r", [], "sha", "m"),
              False)
        subprocess.run = lambda args, **_k: _Res(1, stderr=race_422)
        check("create-race 422 on a sha-less PUT is retryable (False)",
              _write_ledger("o/r", [], None, "m"), False)
        # No `budget` is passed below, so EVERY non-conflict failure — including the transient
        # classes — must still fail at once: the transient retry is opt-in per CAS transaction
        # (issue #558), never a silent default for a caller that has no re-read loop.
        loud_puts = [("permission PUT 403 fails loud (not collapsed)",
                      "gh: Resource not accessible by integration (HTTP 403)", "sha"),
                     ("non-conflict PUT 404 fails loud (not collapsed)",
                      "gh: ... (HTTP 404)", "sha"),
                     ("PUT 500 with no transient budget fails loud (not collapsed)",
                      "gh: ... (HTTP 500)", "sha"),
                     ("secondary-limit 403 with no transient budget fails loud",
                      "gh: You have exceeded a secondary rate limit (HTTP 403)", "sha"),
                     ("non-race validation 422 fails loud (not a CAS conflict)",
                      "gh: Validation Failed (HTTP 422)", "sha"),
                     ("non-race validation 422 on a sha-less create fails loud",
                      "gh: Validation Failed (HTTP 422)", None),
                     ("race-signature 422 on a sha-carrying PUT fails loud", race_422, "sha")]
        for label, stderr_text, put_sha in loud_puts:
            subprocess.run = lambda args, _s=stderr_text, **_k: _Res(1, stderr=_s)
            try:
                _write_ledger("o/r", [], put_sha, "m")
                check(label, "no exception", "LeaseIOError")
            except LeaseIOError:
                check(label, "LeaseIOError", "LeaseIOError")
    finally:
        subprocess.run = real_run

    # ---- throttle/availability CAS-PUT retries (issue #558) --------------------------------------
    # LIVE 2026-07-24T00:21-00:22Z: four concurrent review-fix runs (claims 2baf8dcf / 493adb6a /
    # 7f7d4786 / e6f52629) all died on the non-conflict raise while SIBLING writers landed ledger
    # commits in the same seconds (aa643bce0 00:22:30, f08b0217d 00:22:21, 31f87d685 00:22:18) —
    # healthy, unprotected branch. That is GitHub's SECONDARY rate limiter answering a PUT burst
    # with a 403, i.e. an authorization-SHAPED throttle. It must retry; a real 401/404/422/
    # permission-403 must not.
    SECONDARY_403 = ("gh: You have exceeded a secondary rate limit and have been temporarily "
                     "blocked from content creation. Please retry your request again later. "
                     "(HTTP 403)")
    check("secondary-rate-limit 403 is RETRYABLE (the #558 misclassification)",
          _is_transient_write_error(SECONDARY_403), True)
    check("Retry-After 403 is RETRYABLE",
          _is_transient_write_error("gh: throttled; Retry-After: 30 (HTTP 403)"), True)
    check("5xx is RETRYABLE", _is_transient_write_error("gh: Bad Gateway (HTTP 502)"), True)
    check("429 is RETRYABLE", _is_transient_write_error("gh: (HTTP 429)"), True)
    check("network timeout is RETRYABLE",
          _is_transient_write_error("net/http: TLS handshake timeout"), True)
    for fatal_label, fatal_text in (
            ("permission 403", "gh: Resource not accessible by integration (HTTP 403)"),
            ("credential 403", "gh: Bad credentials (HTTP 403)"),
            ("401", "gh: Unauthorized (HTTP 401)"),
            ("404", "gh: Not Found (HTTP 404)"),
            ("validation 422", "gh: Validation Failed (HTTP 422)")):
        check(f"{fatal_label} stays FATAL (never retried)",
              _is_transient_write_error(fatal_text), False)
    # LeaseIOError must never carry credential material, so only the STATUS of a raw API error is
    # ever quoted in a loud message.
    check("_error_status quotes the status only", _error_status(SECONDARY_403), "403")
    check("_error_status of a status-less error", _error_status("boom"), "unknown")
    check("_error_status of the gh parenthesised form", _error_status("gh: oops (HTTP 503)"), "503")

    # The budget: bounded attempts, throttle-only sleeps, loud failure on exhaustion.
    budget_sleeps = []
    probe_budget = TransientWriteBudget(
        attempts=3, sleep=lambda attempt, retry_after=None: budget_sleeps.append(
            (attempt, retry_after)))
    probe_budget.note("gh: throttled; Retry-After: 7 (HTTP 403)")
    probe_budget.note(SECONDARY_403)
    check("budget sleeps the shared throttle schedule and honours Retry-After",
          budget_sleeps, [(1, 7.0), (2, None)])
    try:
        probe_budget.note(SECONDARY_403)
        check("budget exhaustion raises LeaseIOError", "no exception", "LeaseIOError")
    except LeaseIOError as exc:
        check("budget exhaustion raises LeaseIOError", "LeaseIOError", "LeaseIOError")
        check("exhaustion message names the transient class + status, not the raw body",
              ("HTTP 403" in str(exc), "3 attempts" in str(exc),
               "temporarily blocked" in str(exc)), (True, True, False))
    check("budget does not sleep on the exhausting rejection", len(budget_sleeps), 2)
    check("default budget bound is the fleet-shared gh_retry attempt bound",
          (TransientWriteBudget().attempts, TRANSIENT_WRITE_ATTEMPTS), (5, 5))
    # Process-wide throttle-wait ceiling: a dispatch fan-out runs one transaction PER candidate, so
    # without this a fleet-wide throttle would spend the per-transaction wait N times and time the
    # job out instead of deferring fast.
    ceiling_sleeps, saved_spent = [], _throttle_wait["spent"]
    _throttle_wait["spent"] = 0.0
    slow_budget = TransientWriteBudget(
        attempts=9, sleep=lambda attempt, retry_after=None: (
            ceiling_sleeps.append(attempt), time.sleep(0.02))[0])
    try:
        slow_budget.note(SECONDARY_403)
        check("throttle sleeps are charged to the process-wide ceiling",
              _throttle_wait["spent"] >= 0.02, True)
        _throttle_wait["spent"] = THROTTLE_WAIT_CEILING_S
        try:
            slow_budget.note(SECONDARY_403)
            check("spent throttle-wait ceiling fails loud", "no exception", "LeaseIOError")
        except LeaseIOError as exc:
            check("spent throttle-wait ceiling fails loud",
                  ("ceiling" in str(exc), len(ceiling_sleeps)), (True, 1))
    finally:
        _throttle_wait["spent"] = saved_spent
    check("ceiling is bounded well inside the tightest job timeout",
          0 < THROTTLE_WAIT_CEILING_S <= 300.0, True)

    # A throttle rejection buys ONE extra CAS attempt instead of consuming the conflict budget —
    # and the total stays bounded (retries + attempts - 1 at the very most).
    fresh_budget = TransientWriteBudget(attempts=3, sleep=lambda *a, **k: None)
    check("no throttle rejections → exactly `retries` attempts",
          list(_cas_attempts(4, fresh_budget)), [0, 1, 2, 3])
    grown, grow_budget = [], TransientWriteBudget(attempts=3, sleep=lambda *a, **k: None)
    for grow_attempt in _cas_attempts(2, grow_budget):
        grown.append(grow_attempt)
        if grow_attempt == 0:
            grow_budget.rejections = 1  # one throttle rejection absorbed
    check("a throttle rejection buys one extra attempt (conflict budget untouched)", grown,
          [0, 1, 2])
    capped_budget = TransientWriteBudget(attempts=3, sleep=lambda *a, **k: None)
    capped_budget.rejections = capped_budget.attempts - 1  # the most it can ever reach
    check("attempts stay bounded by retries + attempts - 1",
          len(list(_cas_attempts(2, capped_budget))), 2 + capped_budget.attempts - 1)

    # Pre-write de-synchronization jitter (#558 part b): a bounded uniform draw, sleeping exactly
    # what it drew — a fixed delay would neither de-phase writers nor stay bounded.
    jitter_bounds, jitter_slept = [], []
    original_pre_write_jitter(sleeper=jitter_slept.append,
                              draw=lambda lo, hi: (jitter_bounds.append((lo, hi)), hi)[1])
    check("pre-write jitter draws uniform(0, PRE_WRITE_JITTER_S)",
          jitter_bounds, [(0, PRE_WRITE_JITTER_S)])
    check("pre-write jitter sleeps the draw", jitter_slept, [PRE_WRITE_JITTER_S])
    check("pre-write jitter bound is small (never a visible dispatch stall)",
          0 < PRE_WRITE_JITTER_S <= 1.0, True)

    # ---- end-to-end through the REAL reclaim() CAS loop over a fake gh -----------------------
    def _drive_reclaim(put_errors, retries=6):
        """Drive the REAL reclaim() transaction: `put_errors[i]` is attempt i's PUT stderr ("" =
        success). Returns (result-or-'LeaseIOError', gh calls, throttle sleeps)."""
        calls, sleeps = [], []
        expired = make_lease("a1", "o/r#1@run", "p", "impl", "m", now - 100, 1)
        expired["claim_id"] = "b" * 32

        def fake_gh(args, **_kwargs):
            calls.append(list(args))
            if "-X" not in args:  # contents GET — FRESH sha per read, so a replay is detectable
                meta = {"content": base64.b64encode(json.dumps(
                    {"leases": [expired]}).encode()).decode(), "sha": f"rev{len(calls)}"}
                return _Res(0, stdout=json.dumps(meta))
            index = sum(1 for c in calls if "-X" in c) - 1
            text = put_errors[index] if index < len(put_errors) else ""
            return _Res(1 if text else 0, stderr=text)

        saved = (subprocess.run, globals()["_sleep_backoff"], globals()["_pre_write_jitter"],
                 ledger_retry.sleep_transient)
        subprocess.run = fake_gh
        globals()["_sleep_backoff"] = lambda attempt: None
        globals()["_pre_write_jitter"] = lambda: None
        ledger_retry.sleep_transient = (
            lambda attempt, retry_after=None, **_k: sleeps.append((attempt, retry_after)))
        try:
            outcome = reclaim("o/r", now, retries=retries)
        except LeaseIOError as exc:
            outcome = f"LeaseIOError:{exc}"
        finally:
            (subprocess.run, globals()["_sleep_backoff"], globals()["_pre_write_jitter"],
             ledger_retry.sleep_transient) = saved
        return outcome, calls, sleeps

    # (1) secondary-403 then success: retries, re-READS, re-DERIVES, and lands.
    outcome, calls, sleeps = _drive_reclaim([SECONDARY_403, ""])
    gets = [c for c in calls if "-X" not in c]
    puts = [c for c in calls if "-X" in c]
    check("secondary-403 then success: the reclaim lands", outcome.reclaimed, 1)
    check("secondary-403 retry re-READ the ledger", len(gets), 2)
    check("secondary-403 retry issued exactly two PUTs", len(puts), 2)
    read_revs = [f"rev{i + 1}" for i, c in enumerate(calls) if "-X" not in c]
    check("secondary-403 retry RE-DERIVED the expected sha (no stale-SHA replay)",
          ([next(a for a in c if a.startswith("sha=")) for c in puts],
           len(set(read_revs))),
          ([f"sha={rev}" for rev in read_revs], 2))
    check("secondary-403 retry slept the throttle schedule once", sleeps, [(1, None)])

    # (2) a Retry-After 403 hands the server's own wait to the sleep.
    _outcome, _calls, ra_sleeps = _drive_reclaim(["gh: slow down; Retry-After: 12 (HTTP 403)", ""])
    check("Retry-After 403 sleeps the server's requested wait", ra_sleeps, [(1, 12.0)])
    # (2b) ...but a `Retry-After: 0` is ABSENT, not a zero wait. It arrives only from an endpoint
    # that is already rate-limiting us, so honouring it literally would disable the backoff and
    # re-PUT immediately against that limiter — the retry apparatus amplifying the exact failure it
    # exists to survive. `None` here means the writer falls back to the exponential schedule.
    _o, _c, zero_ra_sleeps = _drive_reclaim(["gh: slow down; Retry-After: 0 (HTTP 403)", ""])
    check("a Retry-After 0 does NOT become a zero throttle sleep", zero_ra_sleeps, [(1, None)])

    # (3) fatal classes are NOT retried: exactly one PUT, then loud.
    for fatal_label, fatal_text in (("validation 422", "gh: Validation Failed (HTTP 422)"),
                                    ("401", "gh: Unauthorized (HTTP 401)"),
                                    ("permission 403",
                                     "gh: Resource not accessible by integration (HTTP 403)")):
        outcome, calls, sleeps = _drive_reclaim([fatal_text, ""])
        check(f"{fatal_label} is NOT retried (one PUT, loud failure, no sleep)",
              (str(outcome).startswith("LeaseIOError:"),
               sum(1 for c in calls if "-X" in c), sleeps), (True, 1, []))

    # (4) a persistent throttle exhausts the BOUNDED budget and fails LOUD — never silently
    # skips the lease write (two workers on one credential) and never spins forever.
    outcome, calls, sleeps = _drive_reclaim([SECONDARY_403] * 12)
    check("persistent throttle fails loud after the bounded budget",
          (str(outcome).startswith("LeaseIOError:"), "transient" in str(outcome)), (True, True))
    check("persistent throttle spends exactly TRANSIENT_WRITE_ATTEMPTS PUTs",
          sum(1 for c in calls if "-X" in c), TRANSIENT_WRITE_ATTEMPTS)
    check("persistent throttle re-read before every retry",
          sum(1 for c in calls if "-X" not in c), TRANSIENT_WRITE_ATTEMPTS)
    check("persistent throttle slept between attempts only",
          sleeps, [(i, None) for i in range(1, TRANSIENT_WRITE_ATTEMPTS)])

    # (5) a throttle burst that clears does NOT consume the conflict budget: four throttles plus
    # `retries` conflicts still leaves the final attempt to land (retries=2 here).
    outcome, calls, _sleeps = _drive_reclaim(
        [SECONDARY_403, "gh: ... (HTTP 409)", SECONDARY_403, ""], retries=2)
    check("throttle rejections do not consume the conflict budget", outcome.reclaimed, 1)
    check("throttle-plus-conflict mix issued four PUTs",
          sum(1 for c in calls if "-X" in c), 4)

    # (6) issue #35 END-TO-END through the REAL reclaim() transaction: a lease whose worker run is
    # still active is RENEWED in the ledger the cron actually writes, not dropped. The pure checks
    # above pin the decision; this one pins that reclaim() consults a probe at all and that what it
    # PUTs carries the pushed-forward expiry. Deleting the wiring while keeping `plan_renewal`
    # turns exactly this check red.
    def _drive_reclaim_liveness(state, holder="o/r#1@4242.1", issued=T35 - 6000, ttl=5900):
        """Drive reclaim() over a fake gh with an injected liveness verdict. Returns
        (outcome, probed run ids, the lease rows the PUT carried — the `"NO PUT"` sentinel when the
        writer issued none). The default row expired 100s before `T35`."""
        calls, probed = [], []
        expired = make_lease("a1", holder, "p", "impl", "m", issued, ttl)
        expired["claim_id"] = "e" * 32

        def fake_gh(args, **_kwargs):
            calls.append(list(args))
            if "-X" not in args:
                meta = {"content": base64.b64encode(json.dumps(
                    {"leases": [expired]}).encode()).decode(), "sha": f"rev{len(calls)}"}
                return _Res(0, stdout=json.dumps(meta))
            return _Res(0)

        saved = (subprocess.run, globals()["_sleep_backoff"], globals()["_pre_write_jitter"])
        subprocess.run = fake_gh
        globals()["_sleep_backoff"] = lambda attempt: None
        globals()["_pre_write_jitter"] = lambda: None
        try:
            result = reclaim("o/r", T35, probe=lambda _repo, run_id: (
                probed.append(run_id), state)[1])
        finally:
            (subprocess.run, globals()["_sleep_backoff"],
             globals()["_pre_write_jitter"]) = saved
        put = next((c for c in calls if "-X" in c), None)
        written = json.loads(base64.b64decode(
            next(a for a in put if a.startswith("content=")).split("=", 1)[1]).decode()) if put \
            else None
        # `"NO PUT"` rather than a bare None: a mutant that stops writing must red a NAMED check,
        # not raise TypeError out of the assertion and abort every check below it.
        return result, probed, (written or {}).get("leases", "NO PUT")

    def _put_summary(rows):
        """(claim ids, expiry offsets from T35, how many the suppression consumers read as LIVE) of
        the ledger a PUT carried — or the `"NO PUT"` sentinel when the writer issued none."""
        if not isinstance(rows, list):
            return rows
        return ([row["claim_id"] for row in rows], [row["expires_at"] - T35 for row in rows],
                len(reclaim_expired(rows, T35)))

    live_outcome, live_probed, live_written = _drive_reclaim_liveness("live")
    check("[RED #35 e2e] reclaim() probes the holder's run and RENEWS instead of dropping it",
          (live_outcome, live_probed), (ReclaimOutcome(0, 1, 0, 0, 1), [4242]))
    check("[RED #35 e2e] ...and the ledger it PUTs carries the row with a FUTURE expiry",
          _put_summary(live_written), (["e" * 32], [RENEWAL_SECONDS], 1))
    dead_outcome, dead_probed, dead_written = _drive_reclaim_liveness("dead")
    check("[CONTROL e2e] a dead run's lease is still reclaimed, and the PUT drops the row",
          (dead_outcome, dead_probed, dead_written), (ReclaimOutcome(1, 0, 0, 0, 1), [4242], []))
    # An unproven probe must still WRITE the grace hold. `reclaim()` used to skip the PUT whenever
    # nothing was reclaimed or renewed, which left the expired row in the ledger exactly as read —
    # and an expired row suppresses nothing, so a flapping Actions API re-opened the double-dispatch
    # on the very tick the deferral was supposed to protect. Measure the ledger the CRON ACTUALLY
    # WRITES: the row must come back with an expiry in the future.
    unknown_outcome, _p, unknown_written = _drive_reclaim_liveness("unknown")
    check("[RED #35 e2e] an unproven probe PUTs the row back with a FUTURE expiry rather than "
          "leaving it expired in the ledger",
          (unknown_outcome, _put_summary(unknown_written)),
          (ReclaimOutcome(0, 0, 1, 0, 1), (["e" * 32], [RENEWAL_GRACE_SECONDS], 1)))
    # ...and the other side of that write rule: a tick with nothing to decide must still write
    # NOTHING, or the 15-minute cron would rewrite the ledger branch forever. A row far outside its
    # lead window is not even probed.
    idle_outcome, idle_probed, idle_written = _drive_reclaim_liveness(
        "unknown", issued=T35, ttl=RENEWAL_LEAD_SECONDS + 600)
    check("[CONTROL e2e] a tick with nothing due issues no PUT and no probe",
          (idle_outcome, idle_probed, idle_written), (ReclaimOutcome(0, 0, 0, 0, 1), [], "NO PUT"))
    # A holder with no run suffix must not cost an Actions API call — the repair leases the
    # groom-leases header calls out are TTL-managed and reclaimed with no probe.
    norun_outcome, norun_probed, _w = _drive_reclaim_liveness("live", holder="review:o/r#1")
    check("[CONTROL e2e] a run-free holder is reclaimed without probing the Actions API",
          (norun_outcome, norun_probed), (ReclaimOutcome(1, 0, 0, 0, 1), []))

    # ---- issue #1128 END-TO-END: the repair lease's claim-id correlation --------------------------
    class _NoMatch:
        """Stand-in for a regex that did NOT match, so a drifted run-name reds its own named check
        instead of raising AttributeError out of the assertion and aborting every check below it
        (AGENTS.md: crash-after-partial-run). `"NO MATCH"` is a value no fixture uses."""

        def group(self, _name):
            return "NO MATCH"

    def _run_doc(claim, status="completed", conclusion="failure", mode="fix",
                 path=REVIEW_FIX_WORKFLOW, created="2026-07-28T23:59:53Z"):
        return {"path": path, "status": status, "conclusion": conclusion,
                "created_at": created,
                "display_title": f"review-fix {mode} o/r#1102 claim={claim}"}

    F = "f" * 32
    check("[#1128] a claim correlates to its run through the run NAME, and a terminal run is "
          "`finished`", claim_liveness_map({F}, None, lambda _p: [_run_doc(F)]), {F: "finished"})
    check("[#1128] a claim NOTHING correlated is ABSENT from the map, never `finished` — this is "
          "the #1071 no-materialised-run case, and absence is what stops it reclaiming",
          claim_liveness_map({F}, None, lambda _p: [_run_doc("a" * 32)]), {})
    check("[#1128] an UNREADABLE page yields no verdicts rather than an empty-and-therefore-dead "
          "answer — a 403 must cost a TTL, never a wrong drop",
          claim_liveness_map({F}, None, lambda _p: None), {})
    check("[#1128] `live` is STICKY across sibling runs: a re-dispatch that left an older "
          "finished run behind must not reclaim the slot the newer live run is using",
          (claim_liveness_map({F}, None, lambda _p: [_run_doc(F), _run_doc(F, "in_progress", None)]),
           claim_liveness_map({F}, None, lambda _p: [_run_doc(F, "in_progress", None), _run_doc(F)])),
          ({F: "live"}, {F: "live"}))
    walk_pages = []
    claim_liveness_map({F}, None,
                       lambda p: (walk_pages.append(p), [_run_doc(F)])[1])
    check("[#1128] the walk STOPS as soon as every pending claim is correlated",
          walk_pages, [1])
    short_pages = []
    claim_liveness_map({F}, None, lambda p: (short_pages.append(p), [_run_doc("b" * 32)])[1])
    check("[#1128] ...and stops when the run history is exhausted (a short page)",
          short_pages, [1])
    window_pages = []
    claim_liveness_map(
        {F}, 2_000_000_000,
        lambda p: (window_pages.append(p), [_run_doc("b" * 32)] * 100)[1])
    check("[#1128] ...and stops once a page predates the oldest live lease's issuance, so a busy "
          "repo cannot make this walk unbounded", window_pages, [1])
    ceiling_pages = []
    ceiling_map = claim_liveness_map(
        {F}, None, lambda p: (ceiling_pages.append(p), [_run_doc("b" * 32)] * 100)[1], ceiling=3)
    check("[#1128] ...and a truncated snapshot is BOUNDED and yields no verdict — it must not "
          "raise (this cron frees every other slot) and must not guess",
          (ceiling_pages, ceiling_map), ([1, 2, 3], {}))
    # THE YAML SEAM. `REVIEW_FIX_RUN_NAME` is a regex over a string another FILE produces, so it can
    # drift silently the moment that file's `run-name:` changes — which is not hypothetical: this
    # repo already carries one such regex, groom.py's `WORKER_RUN_NAME` (`worker claim=<id>`), which
    # a later `run-name` change to `worker <target_repo> claim=<id>` left unable to match ANY real
    # worker run. So render review-fix.yml's ACTUAL run-name expression and require a match.
    # The RENDERER is imported, not written here (#1144). This block used to hand-roll its own —
    # the second copy in the repo, after groom.py's — and its `_render_expr` fell back to "?" for
    # an unrecognised expression, so a NEW input could render to something a `\S+` still matched.
    # `run_name_grammar.py` is the one definition, it REPORTS an expression it has no sample for,
    # and its self-test reds if this file ever re-declares a reader of its own.
    _grammar_spec = importlib.util.spec_from_file_location(
        "registry_run_name_grammar",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_name_grammar.py"))
    assert _grammar_spec and _grammar_spec.loader, "run_name_grammar.py is missing"
    run_name_grammar = importlib.util.module_from_spec(_grammar_spec)
    _grammar_spec.loader.exec_module(run_name_grammar)
    review_fix_lane = run_name_grammar.REVIEW_FIX_LANE
    try:
        rendering = run_name_grammar.render_lane(review_fix_lane)
    except run_name_grammar.RunNameError as exc:
        rendering = run_name_grammar.Rendering("", ("unreadable",), ())
        print(f"  FAIL review-fix.yml run-name is unreadable: {exc}")
        ok = False
    rendered_run_name = rendering.text
    check("[#1128 YAML seam] every review-fix.yml run-name expression has a known rendering — an "
          "unsampled one renders to a sentinel rather than to something `\\S+` still matches",
          rendering.unknown, ())
    check("[#1128 YAML seam] review-fix.yml's OWN run-name expression, rendered, is matched by "
          "the correlation regex — the check groom.py's equivalent never had",
          (rendered_run_name,
           bool(REVIEW_FIX_RUN_NAME.fullmatch(rendered_run_name)),
           (REVIEW_FIX_RUN_NAME.fullmatch(rendered_run_name) or _NoMatch()).group("claim")),
          (f"review-fix fix o/r#1102 claim={'f' * 32}", True, "f" * 32))
    # ...and an independent anchor: the display_title MEASURED off the live Actions API for run
    # 30409749675, the run that actually held the stalling lease. The rendered-template check above
    # and this one can only agree if the regex matches reality, not just the template.
    check("[#1128 known-positive] the LIVE display_title of the run that held the stalling lease "
          "correlates to that lease's claim id",
          (REVIEW_FIX_RUN_NAME.fullmatch(
              "review-fix fix jeswr/agent-account-registry#1102 "
              "claim=b4f7fd219c60463bb75c25ba14f8d5db") or _NoMatch()).group("claim"),
          "b4f7fd219c60463bb75c25ba14f8d5db")
    check("[#1128] a `self`-claimed run holds no dispatcher lease and correlates to nothing",
          REVIEW_FIX_RUN_NAME.fullmatch("review-fix review o/r#7 claim=self"), None)

    # E2E through the REAL reclaim() transaction, over a fake gh serving BOTH the ledger and the
    # review-fix run listing. This is what pins the WIRING: deleting the `claim_liveness=` argument
    # in reclaim() while keeping every pure check above turns exactly this red.
    def _drive_reclaim_claim(runs_page, holder="fix:o/r#1102@dispatch-30409404963.1",
                             issued=T35, ttl=RENEWAL_LEAD_SECONDS + 6000, put_errors=()):
        """Drive reclaim() over a ledger holding ONE repair lease, well outside its lead window,
        plus a review-fix run listing. Returns (outcome, the rows the PUT carried or 'NO PUT',
        how many run-listing GETs were issued)."""
        calls = []
        row = make_lease("a1", holder, "p", "impl", "m", issued, ttl)
        row["claim_id"] = F

        def fake_gh(args, **_kwargs):
            calls.append(list(args))
            target = args[2] if len(args) > 2 else ""
            if "review-fix.yml/runs" in target:
                return _Res(0, stdout=json.dumps({"workflow_runs": runs_page})) \
                    if runs_page is not None else _Res(1, stderr="gh: HTTP 403")
            if "-X" not in args:
                return _Res(0, stdout=json.dumps({"content": base64.b64encode(json.dumps(
                    {"leases": [row]}).encode()).decode(), "sha": f"rev{len(calls)}"}))
            index = sum(1 for c in calls if "-X" in c) - 1
            text = put_errors[index] if index < len(put_errors) else ""
            return _Res(1 if text else 0, stderr=text)

        saved = (subprocess.run, globals()["_sleep_backoff"], globals()["_pre_write_jitter"])
        subprocess.run = fake_gh
        globals()["_sleep_backoff"] = lambda attempt: None
        globals()["_pre_write_jitter"] = lambda: None
        try:
            result = reclaim("o/r", T35, probe=lambda _repo, _run: "dead")
        finally:
            (subprocess.run, globals()["_sleep_backoff"],
             globals()["_pre_write_jitter"]) = saved
        put = next((c for c in calls if "-X" in c), None)
        written = json.loads(base64.b64decode(next(
            a for a in put if a.startswith("content=")).split("=", 1)[1]).decode()) if put else None
        return (result, (written or {}).get("leases", "NO PUT"),
                sum(1 for c in calls if len(c) > 2 and "review-fix.yml/runs" in c[2]))

    dead_out, dead_rows, dead_walks = _drive_reclaim_claim([_run_doc(F)])
    check("[RED #1128 e2e] reclaim() correlates the run-less repair lease by CLAIM ID, drops it, "
          "and PUTs a ledger without it — while the row is still 100 minutes from its TTL",
          (dead_out, dead_rows, dead_walks),
          (ReclaimOutcome(0, 0, 0, 1, 1), [], 1))
    live_out, live_rows, _w = _drive_reclaim_claim([_run_doc(F, "in_progress", None)])
    check("[CONTROL #1128 e2e] a repair lease whose correlated run is LIVE is left alone and "
          "costs no PUT", (live_out, live_rows), (ReclaimOutcome(0, 0, 0, 0, 1), "NO PUT"))
    none_out, none_rows, _w = _drive_reclaim_claim([])
    check("[CONTROL #1071 e2e] a dispatcher-held lease with NO materialised run survives, and the "
          "cron writes nothing at all", (none_out, none_rows),
          (ReclaimOutcome(0, 0, 0, 0, 1), "NO PUT"))
    err_out, err_rows, _w = _drive_reclaim_claim(None)
    check("[CONTROL #1128 e2e] a 403 on the run listing survives the lease rather than dropping "
          "it — the fail-closed direction costs a TTL, never a double-dispatch",
          (err_out, err_rows), (ReclaimOutcome(0, 0, 0, 0, 1), "NO PUT"))
    worker_out, _r, worker_walks = _drive_reclaim_claim(
        [_run_doc(F)], holder="o/r#1102@4242.1")
    check("[CONTROL #1128 e2e] an ordinary WORKER lease never triggers the run-listing walk at "
          "all — zero added API cost on a ledger with no repair rows",
          (worker_walks, worker_out.finished), (0, 0))
    # ...and the scoping is by REPAIR HOLDER, not merely by "has no parsable run id". A worker
    # holder whose run suffix is unreadable is still groom.py's to reclaim, and review-fix's run
    # history could never name it anyway — so it must not spend an Actions call either.
    stale_out, _r, stale_walks = _drive_reclaim_claim([_run_doc(F)], holder="o/r#1102@run")
    check("[CONTROL #1128 e2e] a RUN-LESS but non-repair holder is not walked either — the scope "
          "is `review:`/`fix:` rows, the class groom.py filters out of its own sweep",
          (stale_walks, stale_out.finished, holder_run_id("o/r#1102@run")), (0, 0, None))
    # THE API-COST GUARANTEE under CAS contention. A conflicted PUT re-reads the LEDGER — that is
    # the point of the retry — but must not re-bill the Actions API for a correlation that cannot
    # meaningfully change in the seconds between two attempts. #1088 measures ~9% of groom runs
    # already dying on `403 rate limit exceeded`, so a walk-per-attempt is a real regression, and
    # it is invisible to every check that drives only a first-attempt success.
    retry_out, retry_rows, retry_walks = _drive_reclaim_claim(
        [_run_doc(F)], put_errors=("gh: conflict (HTTP 409)",))
    check("[#1128] the run-listing walk happens AT MOST ONCE per transaction — a CAS retry "
          "re-reads the ledger but does not re-walk the Actions API",
          (retry_walks, retry_out.finished, retry_rows), (1, 1, []))

    # ---- issue #1128 criterion 3: a ledger READ FAILURE must not render as an empty set ---------
    # THE WORST SHAPE this issue names: a read error that looks identical to a healthy quiet tick.
    # registry #1088 measures ~9% of groom runs already dying on `403 rate limit exceeded`, so the
    # question is not hypothetical. Two things are asserted, at the two layers where either could be
    # lost: the transaction must RAISE rather than return zeros, and `main` must not swallow that
    # into a zero exit. And the OUTCOME LINE must state the population it decided over, so a real
    # `0 / 0 / 0` can be told from a ledger nobody read — the ambiguity this issue was filed on.
    class _Captured:
        def __init__(self):
            self.text = ""

        def write(self, chunk):
            self.text += chunk

        def flush(self):
            return None

    def _drive_reclaim_cli(gh):
        """Run the REAL `--reclaim` CLI path over a fake gh. Returns (exit code or the exception
        name, everything the command printed)."""
        captured, saved = _Captured(), (subprocess.run, sys.argv, sys.stdout,
                                        globals()["_pre_write_jitter"])
        subprocess.run = gh
        sys.argv = ["select-and-claim.py", "--reclaim", "--repo", "o/r"]
        globals()["_pre_write_jitter"] = lambda: None
        sys.stdout = captured
        try:
            outcome = f"exit {main()}"
        except LeaseIOError as exc:
            outcome = type(exc).__name__
        finally:
            (subprocess.run, sys.argv, sys.stdout,
             globals()["_pre_write_jitter"]) = saved
        return outcome, captured.text.strip()

    forbidden, forbidden_text = _drive_reclaim_cli(
        lambda args, **_k: _Res(1, stderr="gh: API rate limit exceeded (HTTP 403)"))
    check("[RED #1128 c3] a 403 on the ledger read RAISES out of the CLI — it never returns an "
          "exit 0, and it never prints a zeroed outcome line that reads like a quiet tick",
          (forbidden, "reclaimed" in forbidden_text), ("LeaseIOError", False))
    ten_rows = [{**make_lease("a1", f"o/r#{i + 1}@424{i}.1", "p", "impl", "m",
                              T35, RENEWAL_LEAD_SECONDS + 6000),
                 "claim_id": f"{i:032d}"} for i in range(10)]
    busy, busy_text = _drive_reclaim_cli(lambda args, **_k: _Res(0, stdout=json.dumps(
        {"content": base64.b64encode(json.dumps({"leases": ten_rows}).encode()).decode(),
         "sha": "s1"})) if "-X" not in args else _Res(0))
    empty, empty_text = _drive_reclaim_cli(lambda args, **_k: _Res(0, stdout=json.dumps(
        {"content": base64.b64encode(json.dumps({"leases": []}).encode()).decode(),
         "sha": "s1"})) if "-X" not in args else _Res(0))
    # THE EXACT AMBIGUITY THAT PRODUCED THIS ISSUE. Both ticks below are healthy and both reclaim
    # nothing; under the old line they printed the SAME text, and a ten-row ledger was read as "the
    # reclaim processed an empty set". They must now differ.
    check("[RED #1128 c3] a healthy tick over TEN not-due rows and one over an EMPTY ledger both "
          "exit 0 and reclaim nothing — but their outcome lines are DISTINGUISHABLE",
          (busy, empty, busy_text == empty_text,
           busy_text.startswith("read 10 lease(s);"), empty_text.startswith("read 0 lease(s);")),
          ("exit 0", "exit 0", False, True, True))
    # groom-leases.yml declares `permissions:` explicitly, so every unlisted scope is `none`. The
    # `actions: read` grant is what makes the probe answerable at all; without it every probe is a
    # 403 -> unproven -> nothing is reclaimed until the ceiling, i.e. the cron silently stops
    # freeing slots. So pin the grant to the workflow file — and read it out of the `permissions:`
    # BLOCK, not out of the file text: the header comment above it also says `actions: read`, and
    # a substring search over the whole file would be satisfied by that PROSE while the actual
    # grant was missing (measured: it was).
    try:
        groom_leases_yml = open(
            os.path.join(os.path.dirname(__file__), "..", ".github", "workflows",
                         "groom-leases.yml"), encoding="utf-8").read()
    except OSError as exc:
        groom_leases_yml = ""
        print(f"  FAIL groom-leases.yml is unreadable: {exc}")
        ok = False
    granted, in_block = set(), False
    for line in groom_leases_yml.splitlines():
        if not line.startswith((" ", "\t", "#")) and line.strip():
            in_block = line.startswith("permissions:")
            continue
        if in_block and line.strip() and not line.lstrip().startswith("#"):
            granted.add(line.split("#", 1)[0].strip())
    check("groom-leases.yml's permissions BLOCK grants the actions:read the probe needs, "
          "alongside the ledger write — and nothing else",
          sorted(granted), ["actions: read", "contents: write"])

    # (7) `_probe_run` is where a REAL gh outcome becomes the verdict every branch above keys on,
    # and it is the only part of this path the injected fakes never execute. The mapping is the
    # safety argument: a 403/5xx/garbage body MUST read `unknown` (grace hold, decide next tick) and
    # only a 404 may read `dead`. If a transient failure mapped to `dead` instead, the grace hold
    # would never fire and the blind reclaim of a live worker would be back, untouched.
    def _probe_with(returncode, stdout="", stderr=""):
        saved_run = subprocess.run
        subprocess.run = lambda args, **_kw: (
            probe_argv.append(list(args)), _Res(returncode, stdout, stderr))[1]
        try:
            return _probe_run("o/r", 4242)
        finally:
            subprocess.run = saved_run

    probe_argv = []
    live_body = json.dumps({"path": ".github/workflows/worker.yml", "status": "in_progress"})
    check("_probe_run maps a transient gh failure to UNPROVEN and only a 404 to dead",
          [_probe_with(1, stderr=err) for err in
           ("gh: ... (HTTP 403)", "gh: ... (HTTP 500)", "gh: ... (HTTP 502)",
            "dial tcp: connection refused", "gh: ... (HTTP 404)")],
          ["unknown", "unknown", "unknown", "unknown", "dead"])
    check("_probe_run maps a readable live run to live, and an unparseable body to UNPROVEN",
          [_probe_with(0, stdout=live_body), _probe_with(0, stdout="<html>not json</html>"),
           _probe_with(0, stdout="")], ["live", "unknown", "unknown"])
    check("_probe_run reads the RUN it was asked about, from the registry repo",
          probe_argv[-1], ["gh", "api", "repos/o/r/actions/runs/4242"])
    check("_probe_run never probes at all when the holder named no run",
          _probe_run("o/r", None), "dead")

    # ---- the SAME end-to-end drive for the OTHER THREE writers: release / adopt / claim ----------
    # #558's budget is PER CAS TRANSACTION: each of the four ledger writers builds its own
    # TransientWriteBudget and must hand it to its OWN `_write_ledger` call. Dropping the argument
    # at ONE call site silently reverts THAT writer to pre-#558 fail-loud while the other three keep
    # retrying — so the property needs a red check PER WRITER. A single shared check would be
    # satisfied by whichever writer happens to run it, and three of the four call sites could be
    # unwired with nothing going red (measured: they were).
    #
    # `release()` is first because it is the writer this PR's own docstring names as the incident's
    # victim: four concurrent review/fix lanes releasing in the same second tripped the secondary
    # limiter, every release job failed, and four scarce account slots were stranded until groom's
    # dead-lease sweep.
    #
    # Every fixture below mints a FRESH blob revision per read (`rev<call-index>`), exactly as
    # `_drive_reclaim` does. A CONSTANT sha would make stale-revision REPLAY undetectable BY
    # CONSTRUCTION — with only one revision in play there is nothing available to go stale, so a
    # hoisted read or a pinned expected-SHA could not fail the assertion no matter how wrong it was.
    def _drive_writer(transaction, ledger_rows, put_errors, accounts=()):
        """Drive one REAL writer transaction over a fake gh. `put_errors[i]` is attempt i's PUT
        stderr ("" = success). Returns (outcome-or-'LeaseIOError:...', gh calls, throttle sleeps,
        de-sync-jitter call positions)."""
        calls, sleeps, jitter_at = [], [], []

        def fake_gh(args, **_kwargs):
            calls.append(list(args))
            if "-X" not in args:  # contents GET — FRESH sha per read, so a replay is detectable
                meta = {"content": base64.b64encode(json.dumps(
                    {"leases": [dict(row) for row in ledger_rows]}).encode()).decode(),
                    "sha": f"rev{len(calls)}"}
                return _Res(0, stdout=json.dumps(meta))
            index = sum(1 for c in calls if "-X" in c) - 1
            text = put_errors[index] if index < len(put_errors) else ""
            return _Res(1 if text else 0, stderr=text)

        saved = (subprocess.run, globals()["_sleep_backoff"], globals()["_pre_write_jitter"],
                 ledger_retry.sleep_transient, globals()["read_accounts"])
        subprocess.run = fake_gh
        globals()["_sleep_backoff"] = lambda attempt: None
        globals()["_pre_write_jitter"] = lambda: jitter_at.append(len(calls))
        ledger_retry.sleep_transient = (
            lambda attempt, retry_after=None, **_k: sleeps.append((attempt, retry_after)))
        globals()["read_accounts"] = lambda repo: [dict(a) for a in accounts]
        try:
            outcome = transaction()
        except LeaseIOError as exc:
            outcome = f"LeaseIOError:{exc}"
        finally:
            (subprocess.run, globals()["_sleep_backoff"], globals()["_pre_write_jitter"],
             ledger_retry.sleep_transient, globals()["read_accounts"]) = saved
        return outcome, calls, sleeps, jitter_at

    def _writer_budget_checks(label, transaction, ledger_rows, project, landed, accounts=()):
        """The four #558 properties, asserted through ONE REAL writer transaction end to end."""
        # (a) THE BUDGET IS WIRED AT THIS WRITER'S PUT. Drop `budget` from THIS call site and
        #     `_write_ledger` raises LeaseIOError on the first secondary-403 (the pre-#558
        #     fail-loud behaviour), so this writer's copy of the check — and only this one — reds.
        outcome, calls, sleeps, jitter_at = _drive_writer(
            transaction, ledger_rows, [SECONDARY_403, ""], accounts)
        gets = [c for c in calls if "-X" not in c]
        puts = [c for c in calls if "-X" in c]
        check(f"{label} secondary-403 then success: the write RETRIES and LANDS "
              "(budget wired at this writer's PUT)", project(outcome), landed)
        check(f"{label} secondary-403 retry RE-READ the ledger", len(gets), 2)
        check(f"{label} secondary-403 retry issued exactly two PUTs", len(puts), 2)
        check(f"{label} secondary-403 retry slept the throttle schedule once", sleeps, [(1, None)])
        # THIS writer's de-sync jitter (#558 part b), asserted PER WRITER for the same reason the
        # budget is: the suite-wide "at least one jitter call happened" check is satisfied by any
        # one writer, so dropping `_pre_write_jitter()` from a single transaction left nothing red.
        # Exactly once, and BEFORE the first gh call — jittering between the read and the PUT would
        # widen the CAS window instead of de-phasing the writers.
        check(f"{label} the transaction opened with the de-sync jitter, once, before the first "
              "ledger read", jitter_at, [0])
        # (b) NO STALE-REVISION REPLAY: every PUT carries the revision returned by the read that
        #     PRECEDED it, and the reads returned DISTINCT revisions. Both halves are asserted —
        #     the second is what makes the first non-vacuous.
        read_revs = [f"rev{i + 1}" for i, c in enumerate(calls) if "-X" not in c]
        check(f"{label} the throttle retry RE-DERIVED the expected sha from a fresh read "
              "(no stale-revision replay)",
              ([next(a for a in c if a.startswith("sha=")) for c in puts], len(set(read_revs))),
              ([f"sha={rev}" for rev in read_revs], 2))
        # (c) FATAL still fails at ONCE for this writer: one PUT, loud, no sleep. The budget must
        #     widen the transient class only — never turn a permission verdict into four retries.
        outcome, calls, sleeps, _j = _drive_writer(
            transaction, ledger_rows,
            ["gh: Resource not accessible by integration (HTTP 403)", ""], accounts)
        check(f"{label} a permission 403 is NOT retried (one PUT, loud failure, no sleep)",
              (str(outcome).startswith("LeaseIOError:"),
               sum(1 for c in calls if "-X" in c), sleeps), (True, 1, []))
        # (d) a PERSISTENT throttle terminates LOUD inside the bounded budget: it never spins, and
        #     it never silently skips the ledger write (which strands or double-issues a slot).
        outcome, calls, _sl, _j = _drive_writer(
            transaction, ledger_rows, [SECONDARY_403] * 12, accounts)
        check(f"{label} a persistent throttle fails loud inside the bounded budget",
              (str(outcome).startswith("LeaseIOError:"), "transient" in str(outcome),
               sum(1 for c in calls if "-X" in c)),
              (True, True, TRANSIENT_WRITE_ATTEMPTS))

    W558_ACCOUNTS = [{"handle": "acctw558", "models": ["sol"], "max_concurrent_workers": 4,
                      "available": True, "secret_ref": "ACCTW558_TOKEN", "provider": "openai",
                      "harness": "codex", "credential_format": "codex-auth-json"}]
    RELEASE_CID, ADOPT_CID = "c" * 32, "d" * 32
    release_row = {**make_lease("acctw558", "o/r#558@run9.1", "p", "impl", "sol", now, 3600),
                   "claim_id": RELEASE_CID}
    _writer_budget_checks("release():", lambda: release("o/r", RELEASE_CID, now),
                          [release_row], lambda outcome: outcome, True)
    adopt_row = {**make_lease("acctw558", "o/r#558@dispatch-42.1", "p", "impl", "sol", now, 3600),
                 "claim_id": ADOPT_CID}
    _writer_budget_checks(
        "adopt():",
        lambda: adopt("o/r", ADOPT_CID, "o/r#558@run9.1", now, 3600,
                      expected_holder_prefix="o/r#558@"),
        [adopt_row], lambda outcome: isinstance(outcome, dict) and outcome.get("holder"),
        "o/r#558@run9.1", accounts=W558_ACCOUNTS)
    _writer_budget_checks(
        "claim():", lambda: claim("o/r", "p", "impl", ["sol"], "o/r#559@run9.1", now),
        [], lambda outcome: isinstance(outcome, dict) and outcome.get("account"), "acctw558",
        accounts=W558_ACCOUNTS)
    # release()'s LOST-RELEASE contract, which nothing pinned: a CAS that keeps CONFLICTING must
    # return False. Returning True there is a SILENT SUCCESS — the caller stops retrying, believes
    # the slot is free, and the lease sits stranded until groom's dead-lease sweep reaps it, which
    # is the same stranded-slot outcome #558 exists to prevent, reached by a different route.
    lost_release, lost_calls, _ls, _lj = _drive_writer(
        lambda: release("o/r", RELEASE_CID, now), [release_row], ["gh: ... (HTTP 409)"] * 12)
    check("release(): a CAS that keeps CONFLICTING returns False, never a silent success",
          (lost_release, sum(1 for c in lost_calls if "-X" in c)), (False, 6))

    # Every CAS transaction driven above opened with the jitter (never zero — a lost call would mean
    # a writer path that no longer de-synchronizes).
    check("every CAS transaction in this suite opened with the de-sync jitter",
          len(jitter_calls) > 0, True)
    globals()["_pre_write_jitter"] = original_pre_write_jitter
    if original_selftest_salt is None:
        os.environ.pop("PROVENANCE_SALT", None)
    else:
        os.environ["PROVENANCE_SALT"] = original_selftest_salt
    print("select-and-claim self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--validate-account-record", action="store_true",
                    help="validate an account body from stdin before a catalog write")
    ap.add_argument("--account-handle", default="",
                    help="account handle for --validate-account-record")
    ap.add_argument("--reclaim", action="store_true", help="CAS-remove expired leases (cron)")
    ap.add_argument("--claim", action="store_true", help="claim a lease")
    ap.add_argument("--adopt", metavar="CLAIM_ID",
                    help="CAS-transfer a dispatcher lease to this worker run (--holder), refreshing expiry")
    ap.add_argument("--inspect", metavar="CLAIM_ID", help="inspect an active lease for worker adoption")
    ap.add_argument("--release", metavar="CLAIM_ID", help="release a lease by claim id")
    ap.add_argument("--package", default="")
    ap.add_argument("--role", default="")
    ap.add_argument("--models", default="", help="comma-separated model fallback chain")
    ap.add_argument("--account-pool", default="",
                    help="comma-separated allow-list from the resolved repository policy")
    ap.add_argument("--holder", default="", help="owner/repo@run identifier")
    ap.add_argument("--holder-prefix", default="",
                    help="prefix used with --max-holder-concurrent for repository caps")
    ap.add_argument("--max-holder-concurrent", type=int,
                    help="CAS-enforced concurrent lease cap for --holder-prefix")
    ap.add_argument("--expected-holder-prefix", default="",
                    help="required holder prefix when inspecting a dispatcher claim")
    ap.add_argument("--ttl", type=int, default=3600, help="lease lifetime in seconds")
    ap.add_argument("--repo", default="jeswr/agent-account-registry")
    ap.add_argument("--audit-catalog", action="store_true",
                    help="report account-record / target-routing catalog skew (reports, never "
                         "blocks dispatch)")
    ap.add_argument("--policy-file", default="",
                    help="repos.toml whose ENABLED targets supply the routing catalogs to audit")
    ap.add_argument("--fail-on-skew", action="store_true",
                    help="exit non-zero when --audit-catalog reports anything (gate use)")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()
    if args.audit_catalog:
        if not args.policy_file:
            print("catalog audit requires --policy-file", file=sys.stderr)
            return 2
        with open(args.policy_file, encoding="utf-8") as handle:
            policy_text = handle.read()
        dropped, skew, catalogs = audit_catalog(
            args.repo, policy_text, retired_aliases=_retired_aliases())
        for line in format_catalog_audit(dropped, skew, catalogs):
            print(line)
        # Reporting is the contract: a skew row must not take dispatch down (see the
        # routing-catalog audit header). --fail-on-skew is the opt-in gate mode. An UNREADABLE
        # catalog is a skew row too, so the gate mode fails closed on a fetch failure rather than
        # reading "no skew found" off an empty audit.
        return 1 if args.fail_on_skew and (dropped or skew) else 0
    if args.validate_account_record:
        if not args.account_handle:
            print("account record write rejected: --account-handle is required", file=sys.stderr)
            return 2
        try:
            validate_account_record(args.account_handle, sys.stdin.read())
        except LeaseIOError as exc:
            print(f"account record write rejected: {exc}", file=sys.stderr)
            return 2
        print("account record schema valid")
        return 0
    if args.reclaim:
        outcome = reclaim(args.repo, int(time.time()))
        if outcome.reclaimed < 0:
            print("reclaim: CAS kept conflicting")
            return 1
        # The POPULATION comes first: every counter after it is a count OVER that number, and
        # without it "0; 0; 0" reads identically whether the ledger held ten rows that were not due
        # or none at all (issue #1128). A read that FAILS never reaches this line at all — it
        # raises LeaseIOError out of `main`, so the job exits non-zero rather than printing zeroes.
        print(f"read {outcome.read} lease(s); "
              f"reclaimed {outcome.reclaimed} expired lease(s); "
              f"renewed {outcome.renewed} live lease(s); "
              f"held {outcome.deferred} unproven lease(s) on grace; "
              f"dropped {outcome.finished} concluded lease(s)")
        return 0
    if args.claim:
        chain = [m.strip() for m in args.models.split(",") if m.strip()]
        pool = [a.strip() for a in args.account_pool.split(",") if a.strip()]
        if not chain or not pool or args.ttl <= 0:
            print("claim requires non-empty --models/--account-pool and positive --ttl",
                  file=sys.stderr)
            return 2
        res = claim(args.repo, args.package, args.role, chain, args.holder, int(time.time()),
                    ttl=args.ttl, account_pool=pool, holder_prefix=args.holder_prefix,
                    max_holder_concurrent=args.max_holder_concurrent)
        print(json.dumps(res) if res else "none-free")
        return 0 if res else 3
    if args.adopt:
        if not args.holder or args.ttl <= 0:
            print("adopt requires a non-empty --holder and a positive --ttl", file=sys.stderr)
            return 2
        res = adopt(args.repo, args.adopt, args.holder, int(time.time()), args.ttl,
                    expected_holder_prefix=args.expected_holder_prefix)
        print(json.dumps(res) if res else "not-adoptable")
        return 0 if res else 3
    if args.inspect:
        res = inspect_claim(args.repo, args.inspect, int(time.time()), args.expected_holder_prefix)
        print(json.dumps(res) if res else "not-adoptable")
        return 0 if res else 3
    if args.release:
        released = release(args.repo, args.release, int(time.time()))
        print("released" if released else "release-failed")
        return 0 if released else 1
    print("select-and-claim: allocation core + reclaim + live claim/release ready (wires into dispatch, Phase 3).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
