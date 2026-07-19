#!/usr/bin/env python3
# [OPUS-4.8] Model-access health alerting (registry issue #32 consumes the UNCONSUMED
# worker-live.sh exit-class; part of #28 zero-dispatch visibility; #39 ALERT_TOKEN fail-silent).
#
# WHY this exists: the pipeline silently stalled for hours when Anthropic-side model access failed
# (a mix of transient API errors and usage-limit/credit exhaustion) and NOTHING alerted. The
# dispatcher FAILS CLOSED (it just skips a capped/erroring account), so a whole provider going dark
# looks identical to "nothing ready" from the logs. This script makes the registry NOTICE when it
# stops having successful model access, and it deliberately DISTINGUISHES:
#   (a) transient errors  -> alert ONLY when persistent (a burst, not a blip), and
#   (b) usage-limit exhaustion -> record reset times, alert only when a WHOLE provider is capped
#       (a single capped account is normal 5h/7d-window churn and must NOT page the maintainer).
#
# Two subcommands over one bounded, privacy-safe ledger (data/model-health.json):
#   record  — called from the always()-guarded worker.yml/review-fix.yml outcome jobs (so FAILURES
#             record too — that is the whole point) and from dispatch.yml on a zero-dispatch tick.
#             Appends {ts, provider, account (SALTED HASH only — decision 22a), model_alias,
#             exit_class, run_id, reset_hint?} via the SAME contents-API CAS pattern as the lease
#             ledger, bounded to a rolling window (last MAX_RECORDS / WINDOW_HOURS; pruned on write).
#   decide  — reads the record window (+ the enabled provider->account fleet) and returns alert
#             ACTIONS. Idempotent: exactly ONE open alert issue per (condition, provider), updated
#             not duplicated (a hidden marker in the body keys the upsert). decide also probes the
#             provider's PUBLIC Statuspage API (issue #70) and annotates firing outage/transient
#             alerts with `provider-status:` — operational means a transient burst is likely
#             SELF-INDUCED over-parallelization; degraded/outage means a known provider incident.
#             The probe FAILS OPEN to `unknown` and can NEVER suppress an alert.
#
# Privacy (locked decision 22): NO raw account handle ever appears in a record, a log line, or an
# alert body — only the 16-hex salted hash (reuse worker-pr.account_hash). The public workflow log
# never carries provider counts either; the detail lives only in the alert issue body.
#
# The pure decision core (classify_records / decide) + the CAS writer (against a stub API) + the
# salting privacy property are unit-tested (--self-test); the CLI wraps them over `gh` / the
# contents API.
import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time

LEDGER_PATH = "data/model-health.json"
# Mutable data plane lives on a dedicated non-code branch (issue #28): required-status-check
# protection on the default branch rejects the bot's contents-API PUTs, so every ledger read and
# write pins this ref. Keep in sync with select-and-claim.py / groom.py LEDGER_REF.
LEDGER_REF = os.environ.get("REGISTRY_LEDGER_REF", "ledger")

# --- ledger bounds (WHY): a rolling window is enough to decide "is access failing NOW"; an
# unbounded append would grow the committed file forever and slow every CAS write. 200 records / 48h
# comfortably covers the ~40-slot fleet across several dispatch ticks while staying tiny in git.
MAX_RECORDS = 200
WINDOW_HOURS = 48
WINDOW_SECONDS = WINDOW_HOURS * 3600
# Future-stamp guard (cross-provider review r2 finding 2): record stamps are write-time, but the
# ledger is CAS-writable by every outcome job — a forged or clock-skewed stamp far in the FUTURE
# would (a) never age out of the rolling window and (b) anchor account_backoffs' per-record clamp
# (which is relative to the RECORD ts), yielding a backoff far past BACKOFF_CAP_SECONDS relative
# to the sweep's now. Stamps more than this far ahead of the reader's clock are implausible and
# dropped fail-open; the allowance absorbs legitimate cross-runner clock skew.
FUTURE_SKEW_SECONDS = 5 * 60

# --- exit-class taxonomy. worker-live.sh emits {session-limit, rate-limit, auth, setup, unknown}
# (all derived from HOST-observable signals only: the CLI exit code + the CLI's own error lines,
# never model-authored stdout); a clean run records `success`. We fold those into decision classes.
# `limit` == the account's usage window is exhausted (maintainer must RESET it, not retry);
# `transient` == a retryable API blip (429/529/overloaded); `auth`/`billing` == a credential/credit
# problem (rotate/top up); `unknown` == the host observed a failure but could not attribute it to
# the provider (timeout/cancelled/pre-launch abort/unrecognised nonzero exit).
SUCCESS = "success"
CLASS_LIMIT = "limit"        # session-limit: subscription/usage window exhausted
CLASS_TRANSIENT = "transient"  # rate-limit / overloaded: retryable
CLASS_AUTH = "auth"          # token invalid/expired/forbidden
CLASS_BILLING = "billing"    # credits/quota/payment (codex/openai top-up)
CLASS_SETUP = "setup"        # runner/tooling problem (NOT a provider-access signal)
CLASS_UNKNOWN = "unknown"    # unattributable failure: counts toward PERSISTENCE, never OUTAGE
CLASS_ZERO_DISPATCH = "zero-dispatch"  # dispatch planned >0 but launched 0 (fleet-wide signal)

# raw worker-live.sh exit-class -> decision class
_EXIT_CLASS_MAP = {
    "session-limit": CLASS_LIMIT,
    "rate-limit": CLASS_TRANSIENT,
    "auth": CLASS_AUTH,
    "billing": CLASS_BILLING,
    "setup": CLASS_SETUP,
    # An unrecognised nonzero exit / timeout / cancellation / pre-launch abort is host-observed
    # but NOT provider-attributable: `unknown` counts toward persistence (a sustained burst of
    # them still degrades throughput) but NEVER toward a provider-outage page (review defect #4 —
    # the old fold of `other` into `transient` let un-attributable failures page an outage).
    "other": CLASS_UNKNOWN,
    "zero-dispatch": CLASS_ZERO_DISPATCH,
    # claim-abort: the dispatcher's claim phase died before launching anything (review defect #6);
    # it counts toward the zero-dispatch consecutive-tick run.
    "claim-abort": CLASS_ZERO_DISPATCH,
    SUCCESS: SUCCESS,
    # decision classes are also accepted verbatim (a caller may pass the already-folded class, and
    # the self-test uses them directly).
    CLASS_LIMIT: CLASS_LIMIT,
    CLASS_TRANSIENT: CLASS_TRANSIENT,
    CLASS_AUTH: CLASS_AUTH,
    CLASS_BILLING: CLASS_BILLING,
    CLASS_SETUP: CLASS_SETUP,
    CLASS_UNKNOWN: CLASS_UNKNOWN,
}
# The launch-failure classes that count toward a PROVIDER-OUTAGE (a genuine "cannot reach a working
# model" signal). `setup` is a runner/tooling fault and `unknown` is not provider-attributable
# (host could not classify), so both are EXCLUDED — unknown still counts toward the
# persistent-transient burst below.
LAUNCH_FAIL_CLASSES = frozenset({CLASS_AUTH, CLASS_BILLING, CLASS_LIMIT, CLASS_TRANSIENT})
# The classes that count toward the PERSISTENT burst (transient-for-persistence).
PERSISTENCE_CLASSES = frozenset({CLASS_TRANSIENT, CLASS_UNKNOWN})

# --- thresholds (WHY each is what it is). Tuned to page on a real stall, stay quiet on churn.
# PROVIDER-OUTAGE: >=3 launch failures within 30 min from >= max(2, ceil(enabled-fleet/2)) distinct
# accounts whose PER-ACCOUNT tail runs contain no interleaved success (a success clears only ITS
# account — review defects #2/#3: a global success-breaks-all rule let one healthy account mask a
# real outage, while two bad accounts in a large healthy fleet could page). The fleet size comes
# from the account catalog; when the catalog is unavailable we fall back to the accounts OBSERVED
# in the window. DELIBERATE MISSES (fail-safe, documented): sparse sub-threshold failures — e.g.
# exactly two accounts failing once each, or failures straddling the 30-min window — stay silent;
# the persistent-transient and provider-capped paths cover slow burns, and record timestamps are
# write-time (a delayed outcome job records late), so a razor-thin window would misfire either way.
OUTAGE_MIN_FAILS = 3
OUTAGE_MIN_ACCOUNTS = 2
OUTAGE_WINDOW_SECONDS = 30 * 60
# PERSISTENT-TRANSIENT: >=5 transient-class failures in 15 min (even from ONE account) — a blip is
# 1-2, a genuine API degradation is a sustained burst.
TRANSIENT_MIN_FAILS = 5
TRANSIENT_WINDOW_SECONDS = 15 * 60
# ZERO-DISPATCH: >=3 consecutive ticks that planned work but launched nothing — a persistent
# inability to place ready work (capacity/access), not a single quiet tick.
ZERO_DISPATCH_MIN = 3
# REACTIVE BACKOFF (maintainer decision 2026-07-17, registry issue #29): probe-EXEMPT providers
# (openai/codex — no usage API) are used until a run hits a rate limit; the health window then
# yields a per-account backoff DERIVED from the records already CAS-appended here (no separate
# ledger, no new write path). A limit/transient record starts/extends a backoff: the provider's
# own reset hint when machine-parseable, else 15 min doubling per CONSECUTIVE hit, capped at 5 h;
# a SUCCESS record resets the multiplier. Both hinted and exponential backoffs are capped so a
# forged "rate limit" line in hostile CLI-adjacent text can only sideline ONE account for <= 5 h
# per hit (availability nuisance, accepted residual — noted in the introducing PR body).
BACKOFF_BASE_SECONDS = 15 * 60
BACKOFF_CAP_SECONDS = 5 * 3600
BACKOFF_CLASSES = frozenset({CLASS_LIMIT, CLASS_TRANSIENT})
# The consecutive-hit count at which the exponential arm saturates the 5 h cap (smallest n with
# BASE * 2**(n-1) >= CAP). prune's active-backoff retention (issue #82) keeps at most this many
# tail records of a live chain: past saturation, extra chain records cannot change the derived
# backoff_until (and the last record's parseable hint, when present, overrides the exponential
# anyway), so truncating there preserves the derived backoff EXACTLY while keeping the
# MAX_RECORDS bound hard.
BACKOFF_CHAIN_KEEP = 1 + (BACKOFF_CAP_SECONDS // BACKOFF_BASE_SECONDS - 1).bit_length()

# --- provider status probe (issue #70). At decide time the classifier consults the provider's
# PUBLIC Statuspage API — standard shape {"status": {"indicator": "none|minor|major|critical"}} —
# to tell a provider-side incident apart from self-induced over-parallelization. The probe is
# ANNOTATION ONLY: it can reframe an alert body but must NEVER flip `fire` off — a probe failure
# or a green status page never suppresses an alert (fail-open, mutation-checked in --self-test).
# These are public unauthenticated endpoints: no secret enters the request, no account handle
# enters the URL, and the response feeds only the fixed indicator->status fold below.
PROVIDER_STATUS_URLS = {
    "anthropic": "https://status.claude.com/api/v2/status.json",
    "openai": "https://status.openai.com/api/v2/status.json",
}
# Two-layer probe bound (review #72 round 3): the socket timeout only caps INDIVIDUAL blocking
# operations (DNS, connect, each recv) — a peer trickling one byte per few seconds never trips
# it — so the whole request additionally runs under a hard WALL-CLOCK deadline, and the body
# under a size cap (a real status.json is a few hundred bytes).
STATUS_PROBE_TIMEOUT_SECONDS = 10   # per-socket-operation timeout
STATUS_PROBE_DEADLINE_SECONDS = 20  # end-to-end wall-clock cap on one probe
STATUS_PROBE_MAX_BYTES = 1 << 20    # response-size bound
STATUS_OPERATIONAL = "operational"
STATUS_DEGRADED = "degraded"    # indicator: minor
STATUS_OUTAGE = "outage"        # indicator: major / critical
STATUS_UNKNOWN = "unknown"      # probe unreachable/malformed, or an unrecognised indicator
_INDICATOR_MAP = {"none": STATUS_OPERATIONAL, "minor": STATUS_DEGRADED,
                  "major": STATUS_OUTAGE, "critical": STATUS_OUTAGE}
# The alert conditions that carry the provider-status annotation.
PROBED_CONDITIONS = frozenset({"provider-outage", "persistent-transient"})

ALERT_LABEL = "ops-alert"
MARKER_PREFIX = "model-health-alert"   # hidden HTML marker keying the idempotent upsert

# Authoritative cap for the marker-issue lookup (#203). The old lookup read only 50 issues, but
# CLOSED alert markers accumulate across every flap and are never deleted, so a small window could
# push a reopen-eligible marker out of view — the caller then treated "not in the window" as "not
# found" and minted a DUPLICATE alert over it. gh paginates the API internally to fill --limit, so
# a generous cap turns the lookup authoritative; a result AT the cap is treated as possibly
# truncated and raised (a distinct state the caller fails closed on, never a blind create).
ALERT_LOOKUP_CAP = 1000


# ---------------------------------------------------------------------------------------------
# pure helpers (unit-tested)
# ---------------------------------------------------------------------------------------------
def account_hash(handle, salt):
    """Privacy-preserving account fingerprint (locked decision 22a), IDENTICAL to
    worker-pr.account_hash: sha256(handle + ':' + salt)[:16]. The registry is PUBLIC, so a record
    stores ONLY this hash — never the raw acctNN handle. A missing handle/salt fails loud so a
    record can never be written with a raw or empty identifier."""
    if not handle or not salt:
        raise ValueError("account hashing requires both a handle and a salt")
    return hashlib.sha256(f"{handle}:{salt}".encode()).hexdigest()[:16]


def _decision_class(exit_class):
    """Fold a raw worker-live.sh exit-class into a decision class (fail-safe: a novel class maps to
    `unknown`, which still counts toward persistence but can never page a provider-outage — the
    host did not attribute it to the provider)."""
    return _EXIT_CLASS_MAP.get(exit_class, CLASS_UNKNOWN)


def make_record(provider, account_h, model_alias, exit_class, run_id, now, reset_hint=None):
    """Build one health record. `account_h` MUST already be the salted hash (a raw handle here is a
    privacy bug — the caller salts). reset_hint (a provider reset time string) is kept ONLY for the
    limit + transient (rate-limit) classes, where it is actionable (maintainer alert body / the
    reactive-backoff duration for probe-exempt providers)."""
    if not isinstance(account_h, str) or not account_h:
        raise ValueError("record requires a salted account hash")
    rec = {
        "ts": int(now),
        "provider": str(provider),
        "account": account_h,
        "model_alias": str(model_alias or ""),
        "exit_class": _decision_class(exit_class),
        "run_id": str(run_id or ""),
    }
    if rec["exit_class"] in BACKOFF_CLASSES and reset_hint:
        rec["reset_hint"] = str(reset_hint)
    return rec


def prune(records, now):
    """Keep the rolling window: drop records older than WINDOW_SECONDS — or stamped more than
    FUTURE_SKEW_SECONDS ahead of `now` (an implausibly-future forgery would never age out) — then
    cap to the most recent MAX_RECORDS. Sorted by ts so the window/consecutive logic below is well
    defined.

    ACTIVE-BACKOFF RETENTION (issue #82, fix-forward for #62): the MAX_RECORDS cap is GLOBAL, but
    account_backoffs derives backoff state from the PRUNED window (account-usage._load_backoffs
    prunes before deriving) — so a flood of later unrelated records (e.g. a healthy anthropic
    fleet's successes) could evict an openai account's live rate-limit record and readmit the
    capped account long before its backoff expired. A record feeding a still-ACTIVE backoff is
    therefore never evicted by the cap: for each account whose derived backoff_until > now, the
    tail of its current consecutive chain (the limit/transient records since its last success,
    truncated to BACKOFF_CHAIN_KEEP — past cap-saturation extra records cannot change the
    derived backoff_until) is preserved. Earlier records cannot affect the derived state (a
    success resets it), so re-deriving backoff_until on the pruned window is exact.

    BOUND CONTRACT (PR #85 finding 1): preserved records spend the MAX_RECORDS budget first and
    the newest non-preserved records fill only the REMAINING budget, so the total is bounded by
    max(len(preserved), MAX_RECORDS) — never live-backoffs PLUS a full 200 of expired filler.
    When the live-backoff set alone exceeds MAX_RECORDS (> MAX_RECORDS / BACKOFF_CHAIN_KEEP
    simultaneously live chains), correctness wins over the cap — a live backoff is never
    evicted — but NEVER silently: every expired/non-preserved record is evicted and a ::warning::
    diagnostic surfaces the overshoot (that many simultaneously backed-off accounts is a
    fleet-wide rate-limit saturation signal the maintainer must see, not a bookkeeping detail).
    len(preserved) itself is bounded by live_accounts * BACKOFF_CHAIN_KEEP, and every backoff
    expires within BACKOFF_CAP_SECONDS, so the overshoot is transient, not unbounded growth."""
    kept = [r for r in records if isinstance(r, dict)
            and isinstance(r.get("ts"), int)
            and (now - r["ts"]) <= WINDOW_SECONDS
            and r["ts"] <= now + FUTURE_SKEW_SECONDS]
    kept.sort(key=lambda r: r["ts"])
    if len(kept) <= MAX_RECORDS:
        return kept
    preserved = set()
    active = account_backoffs(kept, now)
    if active:
        chains = {}                 # account -> indices of its current consecutive chain
        for index, r in enumerate(kept):
            acct, cls = r.get("account"), r.get("exit_class")
            if cls == SUCCESS:
                chains.pop(acct, None)      # a success resets the chain — and the derived state
            elif cls in BACKOFF_CLASSES:
                chains.setdefault(acct, []).append(index)
        for acct in active:
            preserved.update(chains.get(acct, ())[-BACKOFF_CHAIN_KEEP:])
    budget = MAX_RECORDS - len(preserved)
    if budget < 0:
        # Live backoffs alone exceed the nominal cap: keep them all (correctness over the cap),
        # evict everything else, and surface the overshoot — this many simultaneously
        # backed-off accounts is a fleet-wide rate-limit saturation signal.
        print(f"::warning::model-health: {len(active)} accounts hold live backoffs "
              f"({len(preserved)} preserved records), exceeding the nominal MAX_RECORDS="
              f"{MAX_RECORDS} cap — expired records evicted, live backoffs kept "
              "(fleet-wide rate-limit saturation)", file=sys.stderr)
    newest = [i for i in range(len(kept)) if i not in preserved][-budget:] if budget > 0 else []
    return [kept[i] for i in sorted(preserved.union(newest))]


def validate_ledger(document):
    """Fail-closed shape check mirroring the lease ledger validator: {records:[...]} with well
    formed entries. A malformed ledger raises rather than silently resetting the window."""
    if not isinstance(document, dict) or set(document) != {"records"}:
        raise ValueError("model-health ledger top level is malformed")
    records = document["records"]
    if not isinstance(records, list):
        raise ValueError("model-health ledger records field is malformed")
    for r in records:
        if not isinstance(r, dict):
            raise ValueError("model-health ledger contains a non-object entry")
        if not isinstance(r.get("ts"), int) or isinstance(r.get("ts"), bool):
            raise ValueError("model-health record has a malformed timestamp")
        for field in ("provider", "account", "exit_class"):
            if not isinstance(r.get(field), str) or not r[field]:
                raise ValueError(f"model-health record {field} is malformed")
        # Privacy invariant, enforced at READ too: an account field must look like a 16-hex hash,
        # never a raw acctNN handle. A non-hash here is a privacy regression and fails closed.
        if not _is_hash(r["account"]):
            raise ValueError("model-health record account is not a salted hash")
    return records


def _is_hash(value):
    return (isinstance(value, str) and len(value) == 16
            and all(c in "0123456789abcdef" for c in value))


def _per_account_tail_failures(records, window_seconds, now):
    """PER-ACCOUNT tail runs of launch failures within `window_seconds`: {account: [fail records]}.
    The zero-interleaved-successes rule is evaluated per account — a success clears ONLY ITS OWN
    account's run (review defects #2/#3: the old global break let any single healthy account, or a
    late-recorded long-running success, wipe every other account's failure run). Records are walked
    newest-first; an account with a success newer than its failures contributes nothing."""
    tails, cleared = {}, set()
    for r in reversed(records):
        if (now - r["ts"]) > window_seconds:
            break
        cls, acct = r.get("exit_class"), r.get("account")
        if cls == SUCCESS:
            cleared.add(acct)        # clears ITS account only
        elif cls in LAUNCH_FAIL_CLASSES and acct not in cleared:
            tails.setdefault(acct, []).append(r)
        # a non-launch class (setup / unknown / zero-dispatch) neither counts nor breaks a run
    return tails


def _outage_required_accounts(fleet_size):
    """Distinct FAILING accounts required to call a provider-outage: majority of the enabled fleet,
    never fewer than OUTAGE_MIN_ACCOUNTS (review defect #2: two bad accounts in a much larger,
    otherwise healthy fleet must not page)."""
    return max(OUTAGE_MIN_ACCOUNTS, -(-fleet_size // 2))  # ceil(fleet/2)


# Relative reset forms the CLIs actually emit ("try again in 1.2s", "retry after 120 seconds").
_HINT_RELATIVE_RE = re.compile(
    r"(?:\bin|\bafter)[ :]*([0-9]+(?:\.[0-9]+)?)\s*"
    r"(s|secs?|seconds?|m|mins?|minutes?|h|hrs?|hours?)\b", re.IGNORECASE)
_HINT_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600}
# HTTP-style unitless Retry-After ("retry-after: 120" — delay-seconds by RFC 9110 §10.2.3). The
# advertised form MUST actually parse (cross-provider review r1); unitless is seconds by spec.
_HINT_RETRY_AFTER_RE = re.compile(
    r"retry[ -]?after[ :]*([0-9]+(?:\.[0-9]+)?)(?!\.)\b(?!\s*(?:s|secs?|seconds?|m|mins?|"
    r"minutes?|h|hrs?|hours?)\b)", re.IGNORECASE)


def parse_reset_hint(hint, record_ts):
    """Best-effort EPOCH from a sanitized provider reset hint, or None. Machine-safe forms only:
    a relative "in/after N s|m|h" (codex style), an HTTP "retry-after: N" (unitless = seconds, RFC
    9110), or a bare epoch-seconds number. Free-text hints ("resets 2pm (Europe/London)") are NOT
    guessed — the caller falls back to the exponential default, so a garbled or forged hint can
    never crash the sweep or (with the caller's cap) extend a backoff past BACKOFF_CAP_SECONDS."""
    if not isinstance(hint, str) or not hint.strip():
        return None
    text = hint.strip()
    match = _HINT_RELATIVE_RE.search(text)
    if match:
        return record_ts + float(match.group(1)) * _HINT_UNIT_SECONDS[match.group(2)[0].lower()]
    match = _HINT_RETRY_AFTER_RE.search(text)
    if match:
        return record_ts + float(match.group(1))    # unitless Retry-After is delay-SECONDS
    if re.fullmatch(r"[0-9]{9,12}", text):          # bare epoch seconds (a plausible-era stamp)
        ts = int(text)
        return float(ts) if ts > record_ts else None
    return None


def account_backoffs(records, now):
    """Reactive per-account backoff for probe-exempt providers (maintainer decision 2026-07-17,
    registry issue #29), DERIVED purely from the pruned health window. Walks records in ts order:
    a limit/transient (rate-limit) record starts or extends the account's backoff — the provider's
    parseable reset hint when present, else BACKOFF_BASE_SECONDS doubling per CONSECUTIVE hit —
    and a SUCCESS record clears the account (multiplier reset). Every duration is clamped to
    [record_ts, record_ts + BACKOFF_CAP_SECONDS], and record_ts itself may sit at most
    FUTURE_SKEW_SECONDS ahead of `now` (cross-provider review r2 finding 2: the per-record clamp
    would otherwise let a forged far-future stamp yield a backoff far past the 5 h ceiling —
    future-forged records are skipped fail-open here, not just in prune, because this walk must
    not RELY on callers pre-pruning). The final clamp is against NOW (cross-provider review r3
    finding 1: a within-skew record at now+300 with a capped hint would otherwise end 5 minutes
    past the ceiling), so every returned backoff ends within now + BACKOFF_CAP_SECONDS — the cap
    is a hard bound on how long an account can be sidelined. Returns only ACTIVE backoffs:
    {account_hash: {"backoff_until", "consecutive", "saturated", "last_signal", "last_ts"}} —
    `saturated` means consecutive >= BACKOFF_CHAIN_KEEP, where prune may have truncated the
    chain, so the count is a lower bound (display "xN+", never an exact "xN")."""
    state = {}
    valid = []
    for record in records:
        if not isinstance(record, dict):
            continue
        acct, ts = record.get("account"), record.get("ts")
        if (not isinstance(acct, str) or not isinstance(ts, (int, float))
                or isinstance(ts, bool) or ts != ts or ts in (float("inf"), float("-inf"))
                or ts > now + FUTURE_SKEW_SECONDS):
            continue                # non-str acct / non-finite or future-forged ts: skip fail-open
        valid.append(record)
    # Defensive ts-sort (cross-provider review r1): the consecutive/success-reset walk is order-
    # sensitive; the production caller pre-prunes (which sorts), but do not RELY on callers.
    valid.sort(key=lambda r: r["ts"])
    for record in valid:
        acct, cls, ts = record.get("account"), record.get("exit_class"), record.get("ts")
        if cls == SUCCESS:
            state.pop(acct, None)                   # a successful run resets the multiplier
        elif cls in BACKOFF_CLASSES:
            consecutive = state.get(acct, {}).get("consecutive", 0) + 1
            exponential = ts + min(BACKOFF_BASE_SECONDS * (2 ** (consecutive - 1)),
                                   BACKOFF_CAP_SECONDS)
            hinted = parse_reset_hint(record.get("reset_hint"), ts)
            until = exponential if hinted is None else min(max(hinted, ts),
                                                           ts + BACKOFF_CAP_SECONDS)
            until = min(until, now + BACKOFF_CAP_SECONDS)   # the 5 h cap binds relative to NOW:
            # a within-skew future ts (clock drift, <= now + FUTURE_SKEW_SECONDS) must not let a
            # capped hint/exponential end past the ceiling (cross-provider review r3 finding 1)
            state[acct] = {"backoff_until": int(until), "consecutive": consecutive,
                           # At/past cap-saturation, prune may have truncated this chain to its
                           # BACKOFF_CHAIN_KEEP tail, so a re-derived count is a LOWER BOUND —
                           # a 20-hit chain re-derives as 6 (PR #85 finding 2). Consumers must
                           # render a saturated count as "x6+", never as an exact "x6".
                           "saturated": consecutive >= BACKOFF_CHAIN_KEEP,
                           "last_signal": cls, "last_ts": int(ts)}
        # other classes (auth/setup/unknown) neither extend nor clear a backoff
    return {acct: b for acct, b in state.items() if b["backoff_until"] > now}


def classify_records(records, provider_accounts, now, open_alerts=()):
    """The PURE decision core. Given the pruned record window and `provider_accounts`
    ({provider: set-of-enabled-salted-hashes}, the enabled fleet per provider), return a list of
    ACTIONS. Each action = {condition, provider, fire (bool), reason, reset_hint?}. `fire=True`
    means raise/refresh the alert; `fire=False` means recover/close an existing one. RECOVERY is a
    first success after failures within the window.

    `open_alerts` is the set of (condition, provider) pairs whose alert issue is currently OPEN
    (issue #205). Actions are keyed on records, but a provider whose records have all aged out of
    the rolling window would otherwise produce NO action at all — so its open alert (and, most
    acutely, the fleet zero-dispatch alert, whose empty-frontier ticks intentionally record
    nothing) could stay open forever. For every open marker the record-driven pass did not already
    cover — AND whose provider has no records left in the window at all — an explicit recovery
    (fire=False) is emitted so `decide` can close it. Alerts for a provider still present in the
    window are left to the per-condition logic above (closing on absent side-knowledge, e.g. a
    momentarily-empty fleet map, would be a false recovery, not evidence of health).

    Conditions:
      provider-outage    : >=3 launch fails in 30 min from >= max(2, ceil(enabled-fleet/2))
                           distinct accounts, per-account runs unbroken by their OWN success.
      persistent-transient: >=5 transient/unknown fails in 15 min (even one account).
      provider-capped    : EVERY enabled account's LATEST limit/success outcome is limit-class.
      zero-dispatch      : >=3 consecutive zero-dispatch ticks (provider == 'fleet').
    """
    actions = []
    providers = {r["provider"] for r in records if isinstance(r.get("provider"), str)}

    for provider in sorted(providers):
        # Ordered by RECORD time so "later" is well defined for the per-account invalidation
        # rules below (prune() sorts, but classify_records must not rely on caller ordering).
        prov_records = sorted((r for r in records if r.get("provider") == provider),
                              key=lambda r: r["ts"])
        if not prov_records:
            continue

        # ---- zero-dispatch (fleet pseudo-provider) --------------------------------------------
        # Consecutiveness is over the TICK SEQUENCE: dispatch.yml records a dispatch-SUCCESS
        # record on every productive planned>0 tick (review defect #5), so the tail run below
        # resets on a real dispatch and the fire=False action closes an open alert.
        if provider == "fleet":
            zd_tail = []
            for r in reversed(prov_records):
                if r.get("exit_class") == CLASS_ZERO_DISPATCH:
                    zd_tail.append(r)
                else:
                    break
            fire = len(zd_tail) >= ZERO_DISPATCH_MIN
            actions.append({
                "condition": "zero-dispatch",
                "provider": "fleet",
                "fire": fire,
                "reason": (f"{len(zd_tail)} consecutive ticks planned ready work but launched "
                           f"nothing (>= {ZERO_DISPATCH_MIN} pages)" if fire
                           else "dispatch is placing work again"),
            })
            continue

        last_cls = prov_records[-1].get("exit_class")
        recovered = last_cls == SUCCESS

        # ---- provider-outage -------------------------------------------------------------------
        # Per-account tail runs (a success clears only ITS account) compared against the ENABLED
        # fleet size from the account catalog; when the catalog is unavailable, fall back to the
        # accounts OBSERVED in the window. Deliberate fail-safe misses are documented at the
        # OUTAGE_* threshold block above.
        tails = _per_account_tail_failures(prov_records, OUTAGE_WINDOW_SECONDS, now)
        total_fails = sum(len(v) for v in tails.values())
        enabled = provider_accounts.get(provider) or set()
        observed = {r["account"] for r in prov_records if isinstance(r.get("account"), str)}
        fleet_size = len(enabled) if enabled else len(observed)
        need_accounts = _outage_required_accounts(fleet_size)
        outage = total_fails >= OUTAGE_MIN_FAILS and len(tails) >= need_accounts
        actions.append({
            "condition": "provider-outage",
            "provider": provider,
            "fire": bool(outage),
            "reason": (f"{total_fails} model-launch failures across {len(tails)} of "
                       f"{fleet_size} accounts in {OUTAGE_WINDOW_SECONDS // 60} min with no "
                       "per-account successes" if outage
                       else "the failing-account set is below the fleet outage threshold"),
        })

        # ---- persistent-transient --------------------------------------------------------------
        # `unknown` counts here (transient-for-persistence): a sustained burst of unattributable
        # failures still degrades throughput even though it can never page an OUTAGE.
        transient_recent = [
            r for r in prov_records
            if r.get("exit_class") in PERSISTENCE_CLASSES
            and (now - r["ts"]) <= TRANSIENT_WINDOW_SECONDS]
        persistent = len(transient_recent) >= TRANSIENT_MIN_FAILS
        # Failure-class composition (review #72 finding 2): the persistence bucket mixes
        # provider-attributed transients (429/529/overloaded) with UNATTRIBUTABLE `unknown`
        # failures (timeouts/cancellations/pre-launch aborts). The advice layer needs the split:
        # a green status page only supports a self-induced-rate-limit diagnosis when the burst
        # was actually attributed to rate limits.
        counts = {cls: sum(1 for r in transient_recent if r.get("exit_class") == cls)
                  for cls in (CLASS_TRANSIENT, CLASS_UNKNOWN)}
        composition = ", ".join(f"{counts[c]} {c}"
                                for c in (CLASS_TRANSIENT, CLASS_UNKNOWN) if counts[c])
        actions.append({
            "condition": "persistent-transient",
            "provider": provider,
            "fire": bool(persistent) and not recovered,
            "class_counts": counts,
            "reason": (f"{len(transient_recent)} transient/unknown API failures in "
                       f"{TRANSIENT_WINDOW_SECONDS // 60} min "
                       f"({composition}; persistent, not a blip)"
                       if persistent
                       else "a model launch succeeded again" if recovered
                       else "transient failures are within blip tolerance"),
        })

        # ---- provider-capped -------------------------------------------------------------------
        # Every ENABLED account of the provider is usage-limited within the window. STALENESS
        # (review defect #1): a limit record is invalidated by any LATER success from the SAME
        # account (records iterated in ts order), so `A limit -> A success -> B limit` caps only
        # B. Individual capped accounts are normal window churn and are deliberately NOT alerted.
        # The earliest known reset is surfaced so the maintainer knows when capacity restores.
        if enabled:
            capped = {}
            for r in prov_records:
                acct = r.get("account")
                if acct not in enabled:
                    continue
                if r.get("exit_class") == CLASS_LIMIT:
                    capped.setdefault(acct, r.get("reset_hint"))
                elif r.get("exit_class") == SUCCESS:
                    capped.pop(acct, None)   # a LATER success invalidates the stale cap
            all_capped = set(capped) >= enabled and enabled
            reset_hints = sorted(h for h in capped.values() if h)
            actions.append({
                "condition": "provider-capped",
                "provider": provider,
                "fire": bool(all_capped),
                "reason": (f"all {len(enabled)} enabled {provider} accounts are usage-limited"
                           if all_capped
                           else f"{len(capped)}/{len(enabled)} accounts capped (normal churn)"),
                "reset_hint": reset_hints[0] if reset_hints else None,
            })

    # ---- orphaned open alerts (issue #205) -----------------------------------------------------
    # An alert whose provider has DISAPPEARED from the rolling window gets no action above, so it
    # would never be closed. Emit an explicit recovery for each open marker the record-driven pass
    # did not cover whose provider is absent from the window — this is the union of "providers with
    # records" and "providers with an open alert", so recovery no longer relies on the provider
    # still being present. A provider still in the window is left to its per-condition logic.
    emitted = {(a["condition"], a["provider"]) for a in actions}
    for condition, provider in sorted(set(open_alerts)):
        if (condition, provider) in emitted or provider in providers:
            continue
        actions.append({
            "condition": condition,
            "provider": provider,
            "fire": False,
            "reason": "no records remain in the window for this provider — the alert is stale "
                      "and is being cleared",
        })

    return actions


def _marker(condition, provider):
    return f"<!-- {MARKER_PREFIX}:{condition}:{provider} -->"


# The (condition, provider) pair carried by a hidden alert marker. condition/provider are keyword
# tokens (no colon or whitespace), so the char classes stop cleanly before the ` -->` close.
_MARKER_RE = re.compile(re.escape(MARKER_PREFIX) + r":([^\s:>]+):([^\s:>]+)")


def parse_alert_markers(bodies):
    """The set of (condition, provider) pairs found in the given issue bodies (issue #205). PURE
    so it is unit-tested without gh: `decide` feeds the resulting set to classify_records so an
    alert whose provider aged out of the window still earns an explicit recovery."""
    markers = set()
    for body in bodies:
        if isinstance(body, str):
            markers.update(_MARKER_RE.findall(body))
    return markers


def _alert_title(condition, provider):
    labels = {
        "provider-outage": f"model access OUTAGE — provider `{provider}`",
        "persistent-transient": f"persistent transient model errors — provider `{provider}`",
        "provider-capped": f"provider `{provider}` fully usage-CAPPED",
        "zero-dispatch": "dispatcher launched nothing while work was ready",
    }
    return f"⚠️ {labels.get(condition, condition)}"


def render_body(action, maintainer):
    """Alert body. Enumerates NO account handles (records carry only salted hashes; a hash is not
    maintainer-actionable and would only clutter) — the actionable facts are the provider, the
    condition, and any reset time."""
    cond = action["condition"]
    lines = [_marker(cond, action["provider"]),
             "> 🤖 SPARQ agent — automated model-access health alert.\n"]
    if cond == "provider-outage":
        lines.append(f"🚨 **Provider `{action['provider']}` model access is DOWN.** "
                     f"{action['reason']}. Every recent launch on this provider failed — the "
                     "pipeline is stalled for this provider, not idle.")
        lines.append("\nLikely causes: an Anthropic/OpenAI-side API incident, every token expired, "
                     "or credits exhausted. Check the provider status page; rotate tokens "
                     "(`claude setup-token` / codex `login --device-auth`) if it is credential.")
    elif cond == "persistent-transient":
        if (action.get("class_counts") or {}).get(CLASS_UNKNOWN):
            # Review #72 finding 2: an unknown/mixed burst must not be described as retryable
            # 429s — part of it was never attributed to the provider at all.
            lines.append(f"⚠️ **Provider `{action['provider']}` launches are failing in a "
                         f"sustained burst.** {action['reason']}. Part of the burst is "
                         "UNATTRIBUTABLE (timeouts/cancellations/pre-launch aborts), so treat "
                         "the failure class as unconfirmed until the run logs say otherwise.")
        else:
            lines.append(f"⚠️ **Provider `{action['provider']}` is throwing sustained transient "
                         f"errors.** {action['reason']}. These are individually retryable "
                         "(429/529/overloaded) but the burst is degrading throughput.")
    elif cond == "provider-capped":
        lines.append(f"⏳ **Every enabled `{action['provider']}` account is usage-capped.** "
                     f"{action['reason']}.")
        if action.get("reset_hint"):
            lines.append(f"\nEarliest known reset: **{action['reset_hint']}** — capacity should "
                         "self-restore then. Reset a subscription window sooner to unblock.")
    elif cond == "zero-dispatch":
        lines.append(f"🚨 **The dispatcher planned ready work but launched NOTHING.** "
                     f"{action['reason']}. Ready issues exist but no worker started — a capacity, "
                     "access, or lease-contention problem, not an empty backlog.")
    advice = _status_advice(action)
    if advice:
        lines.append(advice)
    lines.append(f"\n@{maintainer} — this issue updates itself and closes automatically on the "
                 "first successful model launch for this provider.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------------
# provider status probe (issue #70) — pure fold + fail-open fetch + decide-time annotation
# ---------------------------------------------------------------------------------------------
def classify_status_payload(payload):
    """PURE fold of a Statuspage status.json document into (status, raw_indicator). Any shape
    surprise — non-dict payload, missing keys, non-string or unrecognised indicator — is
    `unknown`, never an exception: the probe must not be able to break `decide`."""
    if not isinstance(payload, dict):
        return STATUS_UNKNOWN, ""
    status = payload.get("status")
    indicator = status.get("indicator") if isinstance(status, dict) else None
    if not isinstance(indicator, str):
        return STATUS_UNKNOWN, ""
    return _INDICATOR_MAP.get(indicator, STATUS_UNKNOWN), indicator


def _fetch_status_json(url, deadline=STATUS_PROBE_DEADLINE_SECONDS):
    """GET one of the two fixed PROVIDER_STATUS_URLS (never a caller-built URL). Review #72
    round 3: the socket timeout bounds only individual blocking operations, so a peer that
    trickles data can exceed it indefinitely — the whole request therefore runs in a DAEMON
    thread that is ABANDONED after `deadline` wall-clock seconds (daemon: it cannot block
    interpreter exit), and the body is read in bounded chunks with a hard size cap. Any
    transport, parse, size, or deadline failure raises HealthError for the fail-open above."""
    import http.client
    import threading

    def fetch_bounded():
        from urllib.request import Request, urlopen
        request = Request(url, headers={"User-Agent": "registry-model-health"})
        with urlopen(request, timeout=STATUS_PROBE_TIMEOUT_SECONDS) as response:
            chunks, size = [], 0
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > STATUS_PROBE_MAX_BYTES:
                    raise HealthError("provider status response exceeds size bound")
                chunks.append(chunk)
        return json.loads(b"".join(chunks).decode())

    outcome = {}

    def run():
        try:
            outcome["value"] = fetch_bounded()
        except BaseException as exc:  # re-raised/normalized below on the caller's thread
            outcome["error"] = exc

    worker = threading.Thread(target=run, name="status-probe", daemon=True)
    worker.start()
    worker.join(deadline)
    if worker.is_alive():
        raise HealthError("provider status probe exceeded wall-clock deadline")
    if "error" in outcome:
        exc = outcome["error"]
        if isinstance(exc, HealthError):
            raise exc
        if isinstance(exc, (OSError, http.client.HTTPException, ValueError)):
            # OSError subsumes URLError/HTTPError/TimeoutError AND the raw socket errors
            # (ConnectionResetError etc.) that response.read() can raise mid-body; HTTPException
            # covers a truncated/half-closed response (http.client.IncompleteRead). Review #72
            # finding 1: neither was normalized before, so a mid-read failure escaped HealthError
            # and aborted _cmd_decide BEFORE the alert upsert — the one failure mode the fail-open
            # design forbids. ValueError covers both JSONDecodeError and UnicodeDecodeError.
            raise HealthError("provider status probe failed") from exc
        raise exc  # unnormalized surprise: probe_provider_status's broad backstop folds it


def probe_provider_status(provider, fetch=None):
    """(status, indicator) from the provider's public status page. FAIL-OPEN (mutation-checked):
    an unmapped provider, an unreachable API, or a malformed body all return ('unknown', '') —
    and the caller must never suppress an alert on that basis."""
    url = PROVIDER_STATUS_URLS.get(provider)
    if not url:
        return STATUS_UNKNOWN, ""
    try:
        payload = (fetch or _fetch_status_json)(url)
    except HealthError:
        return STATUS_UNKNOWN, ""
    except Exception:
        # Defensive backstop at the annotation boundary (review #72 finding 1): the probe is
        # ANNOTATION ONLY and must NEVER be able to abort `decide` (which would suppress the
        # alert upsert), so even an exception class the fetch failed to normalize folds to
        # unknown. Deliberately broad — narrowing it reopens the suppress-on-crash hole.
        return STATUS_UNKNOWN, ""
    return classify_status_payload(payload)


def annotate_provider_status(actions, probe=None):
    """Attach provider_status/status_indicator to the FIRING outage/transient actions, one probe
    per provider per decide tick (cached; a quiet tick makes NO network call). ANNOTATION ONLY:
    `fire` is never touched here — a green status page reframes the alert as self-induced, it
    does not silence it."""
    cache = {}
    for action in actions:
        if action["condition"] not in PROBED_CONDITIONS or not action["fire"]:
            continue
        provider = action["provider"]
        if provider not in cache:
            cache[provider] = (probe or probe_provider_status)(provider)
        action["provider_status"], action["status_indicator"] = cache[provider]
    return actions


def _status_display(status, indicator):
    """`degraded (minor)` / `outage (major|critical)`; operational/unknown carry no qualifier."""
    if status in (STATUS_DEGRADED, STATUS_OUTAGE) and indicator:
        return f"{status} ({indicator})"
    return status


def _status_advice(action):
    """The provider-status annotation line for an alert body, or None when the action was not
    probed. operational + transient burst -> SELF-INDUCED + shed parallelism; degraded/outage ->
    known-incident framing + harder backoff; unknown -> state the fail-open explicitly."""
    status = action.get("provider_status")
    if not status:
        return None
    head = ("\n`provider-status: "
            f"{_status_display(status, action.get('status_indicator') or '')}`")
    if status == STATUS_OPERATIONAL:
        if action["condition"] == "persistent-transient":
            # SELF-INDUCED is claimed ONLY for a qualifying TRUE-transient burst: the
            # provider-attributed transient count must clear the persistence threshold on its
            # own (review #72 finding 2 — an unknown/mixed burst that fired on unattributable
            # timeouts/cancellations proves nothing about rate limits, so advising "shed
            # parallelism" there is a false diagnosis). Missing counts fall to the unverified
            # framing: never claim self-induction on evidence we do not hold.
            counts = action.get("class_counts") or {}
            if counts.get(CLASS_TRANSIENT, 0) >= TRANSIENT_MIN_FAILS:
                return (head + " — **likely SELF-INDUCED.** The provider's public status page "
                        "reports no incident, so this burst is most consistent with over-"
                        "parallelization on our side (concurrent workers sharing the same "
                        "rate-limit windows). SHED PARALLELISM — run fewer concurrent workers "
                        "on this provider — rather than retrying at the same width.")
            return (head + " — **cause UNVERIFIED.** The status page is green, but this burst "
                    "is not a clean rate-limit signature: it leans on UNATTRIBUTABLE failures "
                    "(timeouts / cancellations / pre-launch aborts the host could not pin on "
                    "the provider). Do NOT assume self-induced rate limiting — inspect the "
                    "failing run logs to attribute the burst before shedding parallelism or "
                    "blaming the provider.")
        return (head + " — the status page is green while every launch fails, which points at "
                "our side (expired tokens / exhausted credits), not a provider incident.")
    if status in (STATUS_DEGRADED, STATUS_OUTAGE):
        return (head + " — **known provider incident.** The status page confirms a provider-side "
                "problem, so this is not local misbehaviour: back off HARDER (longer retry "
                "spacing, reduced dispatch width) and wait out the incident before blaming "
                "accounts or tokens.")
    return (head + " — the status API probe failed, so provider health is unverified. This alert "
            "fails OPEN: it is NEVER suppressed on a probe failure — treat the failures as "
            "possibly provider-side.")


# ---------------------------------------------------------------------------------------------
# CAS ledger I/O over the GitHub contents API (mirrors groom.py _read_ledger/_release_claims)
# ---------------------------------------------------------------------------------------------
class HealthError(RuntimeError):
    """A concise, credential-free operational error."""


class HealthConflict(HealthError):
    """A retryable contents-API compare-and-swap conflict."""


def ledger_read_path(registry_repo):
    """Contents-API GET path for the model-health ledger, pinned to the data-plane branch."""
    return f"/repos/{registry_repo}/contents/{LEDGER_PATH}?ref={LEDGER_REF}"


def read_ledger(api, registry_repo):
    """Return (records, sha). A MISSING ledger FILE on a present ledger branch (first ever record)
    is not an error — it seeds an empty window with sha=None so the first PUT creates it. A MISSING
    ledger BRANCH fails LOUD (issue #28): silently-empty would hide the exact outage class this
    ref exists to prevent."""
    result = api.request("GET", ledger_read_path(registry_repo), allow_404=True)
    if result is None:
        if api.request("GET", f"/repos/{registry_repo}/git/ref/heads/{LEDGER_REF}",
                       allow_404=True) is None:
            raise HealthError(
                f"ledger branch '{LEDGER_REF}' is missing — create it from master "
                "(see data/README.md) before recording model health")
        return [], None
    if not isinstance(result, dict):
        raise HealthError("model-health ledger response is malformed")
    content, sha = result.get("content"), result.get("sha")
    if not isinstance(content, str) or not isinstance(sha, str) or not sha:
        raise HealthError("model-health ledger metadata is malformed")
    try:
        document = json.loads(base64.b64decode("".join(content.split()), validate=True).decode())
    except (ValueError, UnicodeDecodeError) as exc:
        raise HealthError("model-health ledger content is malformed") from exc
    return validate_ledger(document), sha


def append_record(api, registry_repo, record, now, retries=6):
    """CAS-append one record and prune the window (bounded write). Retries on conflict exactly like
    the lease-ledger writer. Returns the pruned record count on success."""
    for _ in range(retries):
        records, sha = read_ledger(api, registry_repo)
        records = prune(records + [record], now)
        encoded = base64.b64encode(
            (json.dumps({"records": records}, indent=1) + "\n").encode()).decode()
        body = {"message": f"model-health record ({record['provider']}/{record['exit_class']})",
                "content": encoded,
                "branch": LEDGER_REF}  # pin the data-plane branch, never the protected default
        if sha:
            body["sha"] = sha
        try:
            result = api.request(
                "PUT", f"/repos/{registry_repo}/contents/{LEDGER_PATH}", body, retry_conflict=True)
        except HealthConflict:
            continue
        if isinstance(result, dict) and isinstance(result.get("content"), dict):
            return len(records)
    raise HealthError("model-health ledger CAS conflicts did not settle")


class GitHubAPI:
    """Minimal contents/issues API client (same shape as groom.GitHubAPI). Kept local so the script
    has no cross-module import at CLI time; the salt/token never enter a target-code job."""

    def __init__(self, token):
        from urllib.request import Request  # Local import keeps --self-test import-light.
        if not token:
            raise HealthError("registry token is missing")
        self._token = token
        self._Request = Request

    def request(self, method, path, body=None, allow_404=False, retry_conflict=False):
        from urllib.error import HTTPError, URLError
        from urllib.request import urlopen
        if not path.startswith("/") or "\n" in path or "\r" in path:
            raise HealthError("unsafe GitHub API path")
        payload = json.dumps(body).encode() if body is not None else None
        request = self._Request(
            "https://api.github.com" + path, data=payload, method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "registry-model-health",
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Content-Type": "application/json"} if payload is not None else {}),
            })
        try:
            with urlopen(request, timeout=30) as response:
                raw = response.read()
        except HTTPError as exc:
            if allow_404 and exc.code == 404:
                return None
            if retry_conflict and exc.code in {409, 422}:
                raise HealthConflict("model-health ledger compare-and-swap conflict") from exc
            raise HealthError(f"GitHub API {method} failed with HTTP {exc.code}") from exc
        except (URLError, TimeoutError) as exc:
            raise HealthError("GitHub API request failed") from exc
        try:
            return json.loads(raw or b"null")
        except json.JSONDecodeError as exc:
            raise HealthError("GitHub API returned malformed JSON") from exc

    def paginate(self, path):
        sep = "&" if "?" in path else "?"
        items = []
        for page in range(1, 21):
            result = self.request("GET", f"{path}{sep}per_page=100&page={page}")
            if not isinstance(result, list):
                raise HealthError("GitHub API returned a malformed page")
            items.extend(result)
            if len(result) < 100:
                return items
        raise HealthError("model-health snapshot may be truncated")


# ---------------------------------------------------------------------------------------------
# alert routing (issue #39 fix: ALERT_REPO without ALERT_TOKEN falls back to the registry repo)
# ---------------------------------------------------------------------------------------------
def _alert_target():
    """Where the alert issue lives + the token to write it with (locked decision 22c).

    ALERT_REPO (jeswr/agent-account-data) + ALERT_TOKEN routes the alert to a PRIVATE repo. THE #39
    FIX: when ALERT_REPO is set but ALERT_TOKEN is absent/empty, DO NOT fail silently (the old bug —
    the private write had no usable token so nothing was filed). Fall back to filing on the REGISTRY
    repo itself with the ambient workflow token. Account identifiers stay salted either way, so the
    fallback to the public registry leaks nothing."""
    registry_repo = os.environ["REGISTRY_REPO"]
    alert_repo = os.environ.get("ALERT_REPO") or ""
    alert_token = os.environ.get("ALERT_TOKEN") or ""
    ambient = os.environ.get("REGISTRY_ALERT_TOKEN") or os.environ.get("GH_TOKEN") or ""
    if alert_repo and alert_token:
        return alert_repo, alert_token
    # ALERT_REPO set but no ALERT_TOKEN -> fall back to the registry repo (do not drop the alert).
    return registry_repo, ambient


def _registry_fallback():
    """The always-available public route: (registry_repo, ambient_token). Used at RUN TIME when
    the primary (private) route's token is present but UNUSABLE (issue #175) — a nonempty
    ALERT_TOKEN selects the private route without proving access, so an expired/wrong token would
    otherwise drop every alert while the run stays green. Identifiers are salted (decision 22a), so
    retrying the alert on the public registry leaks nothing."""
    return (os.environ["REGISTRY_REPO"],
            os.environ.get("REGISTRY_ALERT_TOKEN") or os.environ.get("GH_TOKEN") or "")


def _deliver_alerts(actions, maintainer, fallback_open=frozenset()):
    """Upsert every action on the primary route; on a failed FIRING action retry the salted alert
    on the public registry with the ambient token (issue #175). `fallback_open` is the set of
    (condition, provider) markers currently OPEN on the fallback route: the firing retry can
    CREATE an alert there, so a RECOVERY whose marker was seen on the fallback is delivered on
    BOTH routes and counts as delivered only when each route it targets confirms (review #340).
    Beyond that explicit binding, recoveries never fall back cross-repo — "no open issue" on a
    repository whose marker was never seen is a no-op that cannot confirm a close (review round
    2). Returns the actions still undelivered (empty == all delivered) so the caller can exit
    nonzero — an unusable alert token must fail the run, never silently drop the alert."""
    repo, token = _alert_target()
    fb_repo, fb_token = _registry_fallback()
    fb_distinct = (repo, token) != (fb_repo, fb_token) and bool(fb_token)
    undelivered = []
    for action in actions:
        delivered = _upsert_alert(action, repo, token, maintainer)
        if action["fire"]:
            # Primary failed while FIRING: retry on the registry with the ambient token. Never
            # re-run the identical route (no value).
            if not delivered and fb_distinct:
                print(f"::warning::model-health: {action['condition']}/{action['provider']} alert "
                      "delivery failed on the private route — retrying on the registry")
                delivered = _upsert_alert(action, fb_repo, fb_token, maintainer)
        elif fb_distinct and (action["condition"], action["provider"]) in fallback_open:
            # The marker was SEEN open on the fallback repo (a prior firing retry created it):
            # close it there too, and require BOTH routes to confirm — a steady no-op on the
            # primary says nothing about the issue that lives on the fallback (review #340).
            delivered = _upsert_alert(action, fb_repo, fb_token, maintainer) and delivered
        if not delivered:
            undelivered.append(action)
    return undelivered


def _gh(args, token, capture=False):
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    return subprocess.run(["gh"] + args, capture_output=capture, text=True, env=env)


def _find_marker_issue(repo, token, marker, state):
    """The issue number carrying the hidden marker in `state`, or None if the read succeeded, was
    complete, and nothing matched. RAISES HealthError on a failed/garbled/possibly-truncated gh
    list (issues #175, #203): a failed OR truncated read must NEVER be mistaken for 'not found' —
    that let an unreadable/oversized tracker be treated as empty and a duplicate alert created over
    it. The lookup is authoritative — gh paginates the API to fill ALERT_LOOKUP_CAP, and a result
    AT the cap is treated as possibly truncated and raised. The caller turns a raise into a
    delivery FAILURE (retry the fallback route, then fail nonzero), never a blind create."""
    proc = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", state,
                "--json", "number,body", "--limit", str(ALERT_LOOKUP_CAP)], token, capture=True)
    if proc.returncode != 0:
        raise HealthError(f"gh issue list ({state}) failed")
    try:
        found = json.loads(proc.stdout or "[]")
    except ValueError as exc:
        raise HealthError("gh issue list returned malformed JSON") from exc
    if not isinstance(found, list):
        # Valid-but-wrong JSON ({} / null / a scalar) is just as unreadable as garbled JSON:
        # treating it as an empty tracker would re-enable the blind create this guard exists for.
        raise HealthError("gh issue list returned non-list JSON")
    if len(found) >= ALERT_LOOKUP_CAP:
        # The window is full: a matching marker could exist beyond it. Fail closed on a possibly
        # truncated read rather than mistake it for 'not found' and risk a blind duplicate (#203).
        raise HealthError(f"gh issue list ({state}) hit the {ALERT_LOOKUP_CAP}-issue lookup cap "
                          "(possibly truncated)")
    return next((i["number"] for i in found if isinstance(i, dict)
                 and marker in (i.get("body") or "")), None)


def _open_alert_markers(repo, token):
    """Every (condition, provider) whose model-health alert issue is currently OPEN on `repo`
    (issue #205), so `decide` can recover an alert whose provider has aged out of the window.
    FAIL-OPEN: an unreadable/garbled/possibly-truncated list yields the EMPTY set — the orphan
    recovery it feeds only ever CLOSES a stale alert, so a spurious open here would fabricate a
    recovery. A read failure must therefore delay a recovery (retry next tick), never invent one;
    a firing alert is unaffected because its own records still drive its action."""
    proc = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", "open",
                "--json", "body", "--limit", str(ALERT_LOOKUP_CAP)], token, capture=True)
    if proc.returncode != 0:
        print("::warning::model-health decide: cannot list open alerts for recovery "
              "(will retry next tick)")
        return set()
    try:
        found = json.loads(proc.stdout or "[]")
    except ValueError:
        return set()
    if not isinstance(found, list) or len(found) >= ALERT_LOOKUP_CAP:
        # Non-list JSON is unreadable; a full window is possibly truncated. Fail open to empty
        # (no fabricated recovery) rather than act on a partial view.
        return set()
    return parse_alert_markers(i.get("body") for i in found if isinstance(i, dict))


def _upsert_alert(action, repo, token, maintainer):
    """Idempotent one-issue-per-(condition,provider) upsert keyed by the hidden body marker.
    OPERATIONAL idempotency (review defect #7): every gh return code is checked; a flap REOPENS the
    closed marker issue instead of creating a duplicate; and the recovery comment is posted only
    AFTER a CONFIRMED close, so a failed close retries next tick without comment spam.

    Returns True iff the desired state is CONFIRMED — the mutation succeeded, or nothing was needed
    (steady no-alert with no open issue). Returns False on ANY failed gh mutation or an unreadable
    tracker (issue #175): the caller retries the fallback route and, if that also fails, exits
    NONZERO so an unusable ALERT_TOKEN can never drop an alert while the run stays green."""
    title = _alert_title(action["condition"], action["provider"])
    marker = _marker(action["condition"], action["provider"])
    body = render_body(action, maintainer)
    # best-effort, idempotent (exists -> nonzero is fine)
    _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", "d73a4a",
         "--description", "Autonomous model-access health alert (maintainer action)"],
        token, capture=True)
    try:
        num = _find_marker_issue(repo, token, marker, "open")
    except HealthError as exc:
        # An unreadable tracker is NOT 'not found' — do not create over it (would duplicate).
        print(f"::warning::model-health: cannot read the {action['condition']} alert tracker "
              f"({exc}) — treating as undelivered (no blind create)")
        return False
    if action["fire"]:
        if num is not None:
            if _gh(["issue", "edit", str(num), "-R", repo, "--body", body], token).returncode == 0:
                print(f"::warning::model-health: refreshed {action['condition']} alert "
                      "(detail in the issue)")
                return True
            print(f"::warning::model-health: refresh of {action['condition']} alert FAILED "
                  "(will retry next tick)")
            return False
        # Flap: reuse (REOPEN) the closed marker issue rather than minting a new one.
        try:
            closed = _find_marker_issue(repo, token, marker, "closed")
        except HealthError as exc:
            print(f"::warning::model-health: cannot read the {action['condition']} closed tracker "
                  f"({exc}) — treating as undelivered (no blind create)")
            return False
        if closed is not None:
            # True only when BOTH the reopen and the body refresh land: a reopened issue with a
            # stale body is not the desired state. A reopen that lands with a failed edit is safe
            # to retry — next tick finds the issue open and takes the refresh path.
            if (_gh(["issue", "reopen", str(closed), "-R", repo], token).returncode == 0
                    and _gh(["issue", "edit", str(closed), "-R", repo,
                             "--body", body], token).returncode == 0):
                print(f"::warning::model-health: reopened {action['condition']} alert "
                      "(detail in the issue)")
                return True
            print(f"::warning::model-health: reopen of {action['condition']} alert FAILED "
                  "(will retry next tick)")
            return False
        if _gh(["issue", "create", "-R", repo, "--title", title,
                "--label", ALERT_LABEL, "--body", body], token).returncode == 0:
            print(f"::warning::model-health: raised {action['condition']} alert "
                  "(detail in the issue)")
            return True
        print(f"::warning::model-health: raising {action['condition']} alert FAILED "
              "(will retry next tick)")
        return False
    elif num is not None:
        # Close FIRST; comment only on a CONFIRMED state change so a failed close cannot
        # re-comment every tick.
        if _gh(["issue", "close", str(num), "-R", repo], token).returncode == 0:
            _gh(["issue", "comment", str(num), "-R", repo, "--body",
                 "✅ Recovered — successful model access is back. Auto-closed."], token)
            print(f"model-health: recovered {action['condition']} — alert closed")
            return True
        print(f"::warning::model-health: close of {action['condition']} alert FAILED "
              "(will retry next tick without commenting)")
        return False
    # Steady no-alert with no open issue: nothing to deliver.
    return True


# ---------------------------------------------------------------------------------------------
# provider fleet resolution for `decide`
# ---------------------------------------------------------------------------------------------
def _enabled_provider_accounts(api, registry_repo, policy_path, salt):
    """{provider: set-of-salted-hashes} for the enabled fleet — needed by provider-capped ("EVERY
    enabled account"). Union of the enabled policy rows' account_pool, mapped to provider via the
    account catalog, then salted. Best-effort: an empty map only disables the provider-capped path
    (the outage/transient paths need no fleet knowledge). Never emits a raw handle."""
    import tomllib
    try:
        with open(policy_path, "rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    pool = set()
    for row in (document.get("repos") or {}).values():
        if isinstance(row, dict) and row.get("enabled") is True:
            pool.update(h for h in (row.get("account_pool") or []) if isinstance(h, str) and h)
    if not pool or not salt:
        return {}
    # account catalog: handle -> provider (open account issues, title=handle, YAML body).
    result = {}
    try:
        issues = api.paginate(f"/repos/{registry_repo}/issues?state=open")
    except HealthError:
        return {}
    for it in issues:
        if not isinstance(it, dict) or "pull_request" in it:
            continue
        handle = (it.get("title") or "").strip()
        if handle not in pool:
            continue
        provider = _provider_of(it.get("body") or "")
        if provider:
            result.setdefault(provider, set()).add(account_hash(handle, salt))
    return result


def _provider_of(body):
    """Extract the `provider:` field from an account issue's YAML body (tolerant line scan; no YAML
    dep). Returns '' if absent."""
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("provider:"):
            return stripped.split(":", 1)[1].strip()
    return ""


# ---------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------
def _cmd_record(args):
    salt = os.environ.get("PROVENANCE_SALT", "")
    # provider=fleet + zero-dispatch carries NO account (there is no single account); everything
    # else salts the raw handle HERE so a raw handle never reaches the ledger.
    if args.exit_class == CLASS_ZERO_DISPATCH or args.provider == "fleet":
        # A fleet/zero-dispatch record has no single account; use a fixed hash-shaped sentinel so
        # the ledger's "account is a salted hash" privacy invariant still holds (validate_ledger).
        account_h = hashlib.sha256(b"fleet-zero-dispatch").hexdigest()[:16]
    else:
        handle = os.environ.get("WORKER_ACCOUNT_HANDLE", args.account or "")
        if not handle or not salt:
            print("::warning::model-health record: no account handle/salt — recording without a "
                  "per-account hash is unsafe; skipping (telemetry must never fail a run)")
            return 0
        account_h = account_hash(handle, salt)
    record = make_record(args.provider, account_h, args.model_alias, args.exit_class,
                         args.run_id, time.time(), reset_hint=args.reset_hint)
    try:
        api = GitHubAPI(os.environ.get("GH_TOKEN") or os.environ.get("REGISTRY_ALERT_TOKEN") or "")
        kept = append_record(api, os.environ["REGISTRY_REPO"], record, time.time())
    except HealthError as exc:
        # A dropped record leaves an outage invisibly below threshold, so this exits NONZERO
        # (review defect #8 — the old warning-and-exit-0 silently discarded failures on CAS
        # exhaustion). The model run itself is safe: every record call site is a SEPARATE
        # always()-guarded job/continue-on-error step, so this failure is VISIBLE there without
        # failing or reclassifying the run.
        print(f"::error::model-health record failed ({exc})")
        return 1
    print(f"model-health: recorded {record['provider']}/{record['exit_class']} "
          f"(window={kept})")
    return 0


def _cmd_decide(args):
    salt = os.environ.get("PROVENANCE_SALT", "")
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")
    registry_repo = os.environ["REGISTRY_REPO"]
    api = GitHubAPI(os.environ.get("GH_TOKEN") or "")
    now = time.time()
    try:
        records = prune(read_ledger(api, registry_repo)[0], now)
    except HealthError as exc:
        # Every ledger reader fails LOUD (review r3, issue #28): an unreadable/missing ledger is
        # the exact outage class this branch exists to surface, so warn-and-exit-0 would hide it.
        # groom.yml's decide step is continue-on-error, so the maintenance sweep still completes
        # while this step goes visibly red.
        print(f"::error::model-health decide: cannot read ledger ({exc})")
        return 1
    provider_accounts = _enabled_provider_accounts(
        api, registry_repo, args.policy_file, salt)
    # Currently-open alert markers on EVERY route this system may have delivered to (issues #205,
    # review #340): the firing retry (issue #175) can create an alert on the FALLBACK route, so
    # enumerating only the primary would leave that issue open forever once its provider ages out
    # of the window. Feed the union to classify_records so such an alert still earns an explicit
    # recovery, and pass the fallback's markers to _deliver_alerts so each recovery closes the
    # marker on the repository it was found on (route binding — a no-op on the primary is never
    # proof the fallback issue closed). Each enumeration stays fail-open-to-empty, so an
    # unreadable/truncated list only defers a recovery to the next tick, never fabricates one.
    alert_repo, alert_token = _alert_target()
    open_alerts = _open_alert_markers(alert_repo, alert_token)
    fb_repo, fb_token = _registry_fallback()
    fallback_open = set()
    if (fb_repo, fb_token) != (alert_repo, alert_token) and fb_token:
        fallback_open = _open_alert_markers(fb_repo, fb_token)
    actions = classify_records(records, provider_accounts, now, open_alerts | fallback_open)
    # Issue #70: annotate firing outage/transient actions with the provider's public status —
    # AFTER classification, so a probe result can reframe an alert but never decide one.
    annotate_provider_status(actions)
    # Deliver on the primary route, falling back to the salted public registry when a private
    # ALERT_TOKEN is present but unusable (issue #175). A steady no-alert condition with no open
    # issue is a confirmed no-op (never touched), so it never churns nor counts as undelivered.
    undelivered = _deliver_alerts(actions, maintainer, fallback_open)
    fired = [a["condition"] for a in actions if a["fire"]]
    print(f"model-health decide: {len(actions)} conditions checked, "
          f"{len(fired)} firing ({','.join(sorted(set(fired))) or 'none'})")
    if undelivered:
        conds = sorted({f"{a['condition']}/{a['provider']}" for a in undelivered})
        print(f"::error::model-health decide: {len(undelivered)} alert(s) undeliverable on any "
              f"route ({', '.join(conds)}) — an unusable ALERT_TOKEN must fail the run, not drop "
              "the alert silently")
        return 1
    return 0


def main(argv):
    parser = argparse.ArgumentParser(description="Model-access health record + decide")
    sub = parser.add_subparsers(dest="cmd", required=True)

    rec = sub.add_parser("record", help="append one health record (CAS)")
    rec.add_argument("--provider", required=True)
    rec.add_argument("--account", default="", help="RAW handle (salted here; env WORKER_ACCOUNT_HANDLE preferred)")
    rec.add_argument("--model-alias", default="")
    rec.add_argument("--exit-class", required=True)
    rec.add_argument("--run-id", default="")
    rec.add_argument("--reset-hint", default=None)
    rec.set_defaults(func=_cmd_record)

    dec = sub.add_parser("decide", help="evaluate the window and upsert/close alerts")
    dec.add_argument("--policy-file", default="policy/repos.toml")
    dec.set_defaults(func=_cmd_decide)

    args = parser.parse_args(argv)
    return args.func(args)


# ---------------------------------------------------------------------------------------------
# self-tests: every decision path ACT + DO-NOTHING + flip-goes-red; the CAS writer; the salting
# privacy property.
# ---------------------------------------------------------------------------------------------
def _self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    salt = "s3cret"
    now = 1_000_000

    def rec(provider, handle, cls, dt=0, model="fable", run="1", reset=None):
        return make_record(provider, account_hash(handle, salt), model, cls, run,
                           now + dt, reset_hint=reset)

    def fires(actions, condition, provider):
        return any(a["condition"] == condition and a["provider"] == provider and a["fire"]
                   for a in actions)

    # ---- SALTING PRIVACY PROPERTY: no raw handle ever appears in a written record ------------
    r = rec("anthropic", "acct02", CLASS_LIMIT, reset="14:00 UTC")
    chk("record stores salted hash not handle", r["account"], account_hash("acct02", salt))
    chk("raw handle absent from record", "acct02" not in json.dumps(r), True)
    chk("hash is 16-hex", _is_hash(r["account"]), True)
    chk("make_record rejects a raw/empty account", _raises(lambda: make_record(
        "p", "", "m", "auth", "1", now)), True)
    chk("account_hash needs salt", _raises(lambda: account_hash("acct02", "")), True)
    # exit-class folding
    chk("session-limit -> limit", _decision_class("session-limit"), CLASS_LIMIT)
    chk("rate-limit -> transient", _decision_class("rate-limit"), CLASS_TRANSIENT)
    chk("novel class -> unknown (never outage)", _decision_class("weird"), CLASS_UNKNOWN)
    chk("other -> unknown (not provider-attributable)", _decision_class("other"), CLASS_UNKNOWN)
    chk("claim-abort counts as a zero-dispatch tick",
        _decision_class("claim-abort"), CLASS_ZERO_DISPATCH)
    chk("success passthrough", _decision_class(SUCCESS), SUCCESS)
    chk("limit keeps reset_hint", "reset_hint" in r, True)
    chk("non-limit drops reset_hint",
        "reset_hint" in rec("anthropic", "a", CLASS_AUTH, reset="x"), False)

    # ---- PROVIDER-OUTAGE: ACT / DO-NOTHING / flip-goes-red ----------------------------------
    outage = [rec("anthropic", "acct01", CLASS_AUTH, dt=0),
              rec("anthropic", "acct02", CLASS_TRANSIENT, dt=60),
              rec("anthropic", "acct03", CLASS_LIMIT, dt=120)]
    chk("outage ACT (3 fails/3 accts)", fires(classify_records(outage, {}, now + 200),
                                              "provider-outage", "anthropic"), True)
    # DO-NOTHING: only one account -> not an outage (rules out one bad token)
    one_acct = [rec("anthropic", "acct01", CLASS_AUTH, dt=i * 30) for i in range(3)]
    chk("outage DO-NOTHING (single account)",
        fires(classify_records(one_acct, {}, now + 100), "provider-outage", "anthropic"), False)
    # flip-goes-red -> green: PER-ACCOUNT clearing (review defects #2/#3) — a success clears
    # ONLY its own account's run...
    own_success = outage + [rec("anthropic", "acct01", SUCCESS, dt=150)]
    chk("outage: an account's own success clears ITS run (drops below threshold)",
        fires(classify_records(own_success, {}, now + 200), "provider-outage", "anthropic"), False)
    # ...so an UNINVOLVED account's (possibly late-recorded) success cannot mask the outage
    masked = outage + [rec("anthropic", "acct01", CLASS_AUTH, dt=140),
                       rec("anthropic", "acct04", SUCCESS, dt=150)]
    chk("outage: an uninvolved account's success does NOT mask the outage",
        fires(classify_records(masked, {}, now + 200), "provider-outage", "anthropic"), True)
    # fleet threshold (review defect #2): failing accounts are compared to the ENABLED fleet —
    # 2 bad accounts in a 6-account catalog fleet stay quiet; a majority (3 of 6) pages.
    big_fleet = {"anthropic": {account_hash(f"acct{i:02d}", salt) for i in range(1, 7)}}
    two_bad = [rec("anthropic", "acct01", CLASS_AUTH, dt=0),
               rec("anthropic", "acct02", CLASS_AUTH, dt=30),
               rec("anthropic", "acct01", CLASS_AUTH, dt=60),
               rec("anthropic", "acct02", CLASS_AUTH, dt=90)]
    chk("outage DO-NOTHING (2 bad accounts of an enabled fleet of 6)",
        fires(classify_records(two_bad, big_fleet, now + 200), "provider-outage", "anthropic"),
        False)
    three_bad = two_bad + [rec("anthropic", "acct03", CLASS_AUTH, dt=120)]
    chk("outage ACT (failing majority 3 of enabled fleet of 6)",
        fires(classify_records(three_bad, big_fleet, now + 200), "provider-outage", "anthropic"),
        True)
    chk("outage account floor is max(2, ceil(fleet/2))",
        [_outage_required_accounts(n) for n in (0, 1, 2, 3, 4, 6, 7)], [2, 2, 2, 2, 2, 3, 4])
    # unknown-class exclusion (review defect #4): unattributable failures never page an outage...
    unknown_fails = [rec("anthropic", "acct01", "other", dt=0),
                     rec("anthropic", "acct02", "unknown", dt=30),
                     rec("anthropic", "acct03", "weird-novel", dt=60)]
    chk("outage DO-NOTHING (unknown class never pages an outage)",
        fires(classify_records(unknown_fails, {}, now + 100), "provider-outage", "anthropic"),
        False)
    # ...but DO count toward the persistence burst (transient-for-persistence)
    unknown_burst = [rec("anthropic", "acct01", "unknown", dt=i * 30) for i in range(5)]
    chk("unknown counts toward persistent-transient",
        fires(classify_records(unknown_burst, {}, now + 200), "persistent-transient", "anthropic"),
        True)
    # ...yet an unknown burst must NOT be sold as self-induced rate limiting (review #72
    # finding 2): composition rides the action, and a green status page renders the
    # unverified framing end-to-end — never SELF-INDUCED / shed-parallelism.
    ub_acts = annotate_provider_status(classify_records(unknown_burst, {}, now + 200),
                                       probe=lambda p: (STATUS_OPERATIONAL, "none"))
    ub = next(a for a in ub_acts if a["condition"] == "persistent-transient")
    chk("burst action carries its failure-class composition",
        ub["class_counts"], {CLASS_TRANSIENT: 0, CLASS_UNKNOWN: 5})
    chk("burst reason discloses the composition", "5 unknown" in ub["reason"], True)
    ub_body = render_body(ub, "m")
    chk("green-status unknown burst renders UNVERIFIED end-to-end (never SELF-INDUCED)",
        ("SELF-INDUCED" in ub_body, "cause UNVERIFIED" in ub_body), (False, True))
    # too-old failures fall outside the 30-min window
    stale = [rec("anthropic", "acct01", CLASS_AUTH, dt=-4000),
             rec("anthropic", "acct02", CLASS_AUTH, dt=-3900),
             rec("anthropic", "acct03", CLASS_AUTH, dt=-3800)]
    chk("outage DO-NOTHING (outside window)",
        fires(classify_records(prune(stale, now), {}, now), "provider-outage", "anthropic"), False)

    # ---- PERSISTENT-TRANSIENT: ACT / DO-NOTHING ---------------------------------------------
    burst = [rec("anthropic", "acct01", CLASS_TRANSIENT, dt=i * 30) for i in range(5)]
    chk("transient ACT (5 in 15m)",
        fires(classify_records(burst, {}, now + 200), "persistent-transient", "anthropic"), True)
    blip = [rec("anthropic", "acct01", CLASS_TRANSIENT, dt=i * 30) for i in range(2)]
    chk("transient DO-NOTHING (blip of 2)",
        fires(classify_records(blip, {}, now + 100), "persistent-transient", "anthropic"), False)
    # flip: a later success clears it
    burst_ok = burst + [rec("anthropic", "acct01", SUCCESS, dt=200)]
    chk("transient RECOVERS on success",
        fires(classify_records(burst_ok, {}, now + 300), "persistent-transient", "anthropic"), False)
    # a TRUE-transient burst keeps the self-induced diagnosis end-to-end (mutation guard for
    # review #72 finding 2: dropping the class_counts attachment turns this red).
    tb_acts = annotate_provider_status(classify_records(burst, {}, now + 200),
                                       probe=lambda p: (STATUS_OPERATIONAL, "none"))
    tb = next(a for a in tb_acts if a["condition"] == "persistent-transient")
    chk("pure transient burst carries its composition",
        tb["class_counts"], {CLASS_TRANSIENT: 5, CLASS_UNKNOWN: 0})
    chk("green-status TRUE-transient burst still renders SELF-INDUCED end-to-end",
        "SELF-INDUCED" in render_body(tb, "m"), True)

    # ---- PROVIDER-CAPPED: ACT (all capped) / DO-NOTHING (one capped) -------------------------
    fleet = {"anthropic": {account_hash("acct01", salt), account_hash("acct02", salt)}}
    all_capped = [rec("anthropic", "acct01", CLASS_LIMIT, reset="14:00"),
                  rec("anthropic", "acct02", CLASS_LIMIT, dt=60, reset="15:00")]
    acts = classify_records(all_capped, fleet, now + 100)
    chk("capped ACT (all enabled capped)", fires(acts, "provider-capped", "anthropic"), True)
    chk("capped surfaces earliest reset",
        next(a["reset_hint"] for a in acts
             if a["condition"] == "provider-capped"), "14:00")
    one_capped = [rec("anthropic", "acct01", CLASS_LIMIT, reset="14:00")]
    chk("capped DO-NOTHING (1/2 capped = churn)",
        fires(classify_records(one_capped, fleet, now + 100), "provider-capped", "anthropic"), False)
    # flip: a success on a capped account clears the cap alert
    capped_ok = all_capped + [rec("anthropic", "acct01", SUCCESS, dt=120)]
    chk("capped RECOVERS on success",
        fires(classify_records(capped_ok, fleet, now + 200), "provider-capped", "anthropic"), False)
    # STALE-CAP invalidation (review defect #1): a limit record is voided by any LATER success
    # from the SAME account — `A limit -> A success -> B limit` caps only B...
    stale_cap = [rec("anthropic", "acct01", CLASS_LIMIT, dt=0, reset="14:00"),
                 rec("anthropic", "acct01", SUCCESS, dt=60),
                 rec("anthropic", "acct02", CLASS_LIMIT, dt=120, reset="15:00")]
    chk("capped DO-NOTHING (later same-account success invalidates the stale cap)",
        fires(classify_records(stale_cap, fleet, now + 200), "provider-capped", "anthropic"),
        False)
    # ...and a limit AFTER that success re-caps the account (ordering by record time)
    recap = stale_cap + [rec("anthropic", "acct01", CLASS_LIMIT, dt=180, reset="16:00")]
    chk("capped ACT (re-capped after its own success)",
        fires(classify_records(recap, fleet, now + 300), "provider-capped", "anthropic"), True)
    # no fleet knowledge -> provider-capped path is simply absent (no false alert)
    chk("capped absent without fleet map",
        any(a["condition"] == "provider-capped" for a in classify_records(all_capped, {}, now + 100)),
        False)

    # ---- ZERO-DISPATCH: ACT (3 consecutive) / DO-NOTHING (2) / flip -------------------------
    zd = [make_record("fleet", account_hash("z", salt), "", CLASS_ZERO_DISPATCH, str(i), now + i * 60)
          for i in range(3)]
    chk("zero-dispatch ACT (3 ticks)", fires(classify_records(zd, {}, now + 300),
                                             "zero-dispatch", "fleet"), True)
    chk("zero-dispatch DO-NOTHING (2 ticks)",
        fires(classify_records(zd[:2], {}, now + 200), "zero-dispatch", "fleet"), False)
    # RESET (review defect #5): a dispatch-success record between zero ticks breaks the
    # consecutive run, so 2+2 zero ticks around a productive tick do NOT page...
    def zrec(cls, dt, run="r"):
        return make_record("fleet", account_hash("z", salt), "", cls, run, now + dt)
    zd_reset = (zd[:2] + [zrec(SUCCESS, 150)]
                + [zrec(CLASS_ZERO_DISPATCH, 200 + i * 60, str(9 + i)) for i in range(2)])
    chk("zero-dispatch RESETS on a dispatch-success record",
        fires(classify_records(zd_reset, {}, now + 400), "zero-dispatch", "fleet"), False)
    # ...and a dispatch-success AFTER a firing run recovers (closes) the alert
    zd_ok = zd + [zrec(SUCCESS, 400)]
    chk("zero-dispatch RECOVERS on a dispatch-success record",
        fires(classify_records(zd_ok, {}, now + 500), "zero-dispatch", "fleet"), False)
    # a claim-abort tick counts toward the consecutive run (review defect #6)
    zd_abort = zd[:2] + [zrec("claim-abort", 200)]
    chk("zero-dispatch ACT (claim-abort completes the run)",
        fires(classify_records(zd_abort, {}, now + 300), "zero-dispatch", "fleet"), True)

    # ---- ORPHANED OPEN ALERTS (issue #205): a provider that aged out of the window still closes --
    def recovers(actions, condition, provider):
        return any(a["condition"] == condition and a["provider"] == provider and not a["fire"]
                   for a in actions)

    # the acute case: the fleet zero-dispatch alert is open, but every fleet record has aged out of
    # the window (empty-frontier ticks record nothing). With NO open-marker knowledge the old code
    # emitted nothing, so the alert stayed open forever; feeding the open marker yields a recovery.
    chk("orphan zero-dispatch alert with no fleet records is NOT recovered without marker knowledge",
        any(a["provider"] == "fleet" for a in classify_records([], {}, now)), False)
    chk("orphan zero-dispatch alert recovers when its marker is open but the fleet aged out",
        recovers(classify_records([], {}, now, {("zero-dispatch", "fleet")}),
                 "zero-dispatch", "fleet"), True)
    # any provider/condition works, not just the fleet — an aged-out outage alert closes too
    chk("orphan provider-outage alert recovers when the provider aged out",
        recovers(classify_records([], {}, now, {("provider-outage", "anthropic")}),
                 "provider-outage", "anthropic"), True)
    # the recovery is a CLOSE, never a fresh fire
    orphan = classify_records([], {}, now, {("zero-dispatch", "fleet")})
    chk("orphan recovery never fires (close only)", any(a["fire"] for a in orphan), False)
    # a provider STILL in the window is governed by its per-condition logic, not orphan recovery:
    # a firing outage with an open marker stays firing (not force-closed)...
    chk("open marker does NOT force-close a provider still firing in the window",
        fires(classify_records(outage, {"anthropic": set()}, now + 200,
                               {("provider-outage", "anthropic")}), "provider-outage", "anthropic"),
        True)
    # ...and an open provider-capped marker for a provider present in the window but with NO fleet
    # map is left alone (closing on absent side-knowledge would be a false recovery, not health)
    present_no_fleet = classify_records(
        [rec("anthropic", "acct01", CLASS_TRANSIENT, dt=0)], {}, now + 10,
        {("provider-capped", "anthropic")})
    chk("open capped marker for an in-window provider without a fleet map is left untouched",
        any(a["condition"] == "provider-capped" for a in present_no_fleet), False)
    # already-covered markers are not double-emitted (the record-driven action wins)
    covered = classify_records(burst, {}, now + 200, {("persistent-transient", "anthropic")})
    chk("an already-covered open marker is not double-emitted",
        sum(1 for a in covered if a["condition"] == "persistent-transient"), 1)

    # ---- marker parsing (pure) + fail-open enumeration --------------------------------------
    body = (render_body({"condition": "zero-dispatch", "provider": "fleet",
                         "fire": True, "reason": "r"}, "m"))
    chk("parse_alert_markers recovers (condition, provider) from a rendered body",
        parse_alert_markers([body]), {("zero-dispatch", "fleet")})
    chk("parse_alert_markers reads every marker across bodies",
        parse_alert_markers([_marker("provider-outage", "anthropic"),
                             _marker("provider-capped", "openai"), "no marker here"]),
        {("provider-outage", "anthropic"), ("provider-capped", "openai")})
    chk("parse_alert_markers ignores non-string bodies", parse_alert_markers([None, 5, {}]), set())
    ok = _test_open_markers(chk) and ok

    # ---- reactive backoff for probe-exempt providers (decision 2026-07-17, issue #29) --------
    ah = account_hash("codex01", salt)
    # (i) first hit -> BASE (15 min) from the record ts, exponential default (no hint)
    hit1 = [rec("openai", "codex01", "rate-limit", dt=0)]
    b = account_backoffs(hit1, now + 60)
    chk("backoff first hit = base 15 min", b.get(ah, {}).get("backoff_until"),
        now + BACKOFF_BASE_SECONDS)
    chk("backoff first hit consecutive=1", b.get(ah, {}).get("consecutive"), 1)
    # consecutive hits DOUBLE: 15 -> 30 -> 60 min from the LAST hit
    hit3 = [rec("openai", "codex01", "rate-limit", dt=i * 100) for i in range(3)]
    b3 = account_backoffs(hit3, now + 300)
    chk("backoff doubles per consecutive hit (3rd = 60 min)",
        b3.get(ah, {}).get("backoff_until"), now + 200 + 4 * BACKOFF_BASE_SECONDS)
    chk("backoff tracks consecutive count", b3.get(ah, {}).get("consecutive"), 3)
    # exponential growth is CAPPED at 5 h
    hitmany = [rec("openai", "codex01", "rate-limit", dt=i * 10) for i in range(12)]
    bmany = account_backoffs(hitmany, now + 200)
    chk("backoff exponential capped at 5 h",
        bmany.get(ah, {}).get("backoff_until"), now + 110 + BACKOFF_CAP_SECONDS)
    # (iii) a SUCCESS resets the multiplier: hit, success, hit -> base again
    reset_run = [rec("openai", "codex01", "rate-limit", dt=0),
                 rec("openai", "codex01", SUCCESS, dt=100),
                 rec("openai", "codex01", "rate-limit", dt=200)]
    br = account_backoffs(reset_run, now + 300)
    chk("success resets the multiplier (next hit = base)",
        (br.get(ah, {}).get("backoff_until"), br.get(ah, {}).get("consecutive")),
        (now + 200 + BACKOFF_BASE_SECONDS, 1))
    chk("success alone clears the backoff",
        account_backoffs([rec("openai", "codex01", "rate-limit", dt=0),
                          rec("openai", "codex01", SUCCESS, dt=100)], now + 200), {})
    # expired backoffs are filtered out entirely
    chk("expired backoff absent from the map",
        account_backoffs(hit1, now + BACKOFF_BASE_SECONDS + 1), {})
    # session-limit (limit class) also backs off; auth/setup/unknown neither extend nor clear
    bl = account_backoffs([rec("openai", "codex01", "session-limit", dt=0),
                           rec("openai", "codex01", CLASS_AUTH, dt=50)], now + 100)
    chk("limit class backs off; auth does not clear it",
        (bl.get(ah, {}).get("last_signal"), bl.get(ah, {}).get("consecutive")), (CLASS_LIMIT, 1))
    # provider reset hint (machine-safe forms) overrides the exponential default…
    bh = account_backoffs([rec("openai", "codex01", "rate-limit", dt=0, reset="try again in 120 s")],
                          now + 10)
    chk("parseable reset hint wins", bh.get(ah, {}).get("backoff_until"), now + 120)
    # …but (v) a forged/absurd hint is CLAMPED to the 5 h cap, and garbage falls back cleanly
    bf = account_backoffs([rec("openai", "codex01", "rate-limit", dt=0,
                               reset="in 999999 hours")], now + 10)
    chk("forged huge hint clamped to cap", bf.get(ah, {}).get("backoff_until"),
        now + BACKOFF_CAP_SECONDS)
    bg = account_backoffs([rec("openai", "codex01", "rate-limit", dt=0,
                               reset="resets 2pm (Europe/London)")], now + 10)
    chk("free-text hint falls back to exponential (no crash)",
        bg.get(ah, {}).get("backoff_until"), now + BACKOFF_BASE_SECONDS)
    # malformed records are skipped, never crash the sweep
    chk("malformed records skipped fail-open",
        account_backoffs([{"account": None, "exit_class": "rate-limit", "ts": now},
                          {"weird": True}, "not-a-dict",
                          {"account": ah, "exit_class": "rate-limit", "ts": True}], now), {})
    # parse_reset_hint pure forms
    chk("hint: relative minutes", parse_reset_hint("Please try again in 5 minutes", 1000), 1300.0)
    chk("hint: retry after seconds", parse_reset_hint("retry after 90 seconds", 1000), 1090.0)
    # the advertised HTTP unitless form must actually parse (cross-provider review r1):
    # RFC 9110 Retry-After delay-seconds
    chk("hint: unitless retry-after is seconds", parse_reset_hint("retry-after: 120", 1000), 1120.0)
    chk("hint: unitless Retry After variant", parse_reset_hint("Retry After 45", 1000), 1045.0)
    # the SUCCESS-reset / consecutive walk must not depend on caller ordering (r1): shuffled
    # input yields the same state as ts-order (success at ts=100 clears the ts=0 hit; the ts=200
    # hit then restarts at base)
    chk("out-of-order records are ts-sorted before the walk",
        account_backoffs([rec("openai", "codex01", "rate-limit", dt=200),
                          rec("openai", "codex01", SUCCESS, dt=100),
                          rec("openai", "codex01", "rate-limit", dt=0)], now + 300)
        .get(ah, {}).get("consecutive"), 1)
    # non-finite ts records are skipped fail-open, never crash int()
    chk("non-finite ts skipped fail-open",
        account_backoffs([{"account": ah, "exit_class": "rate-limit", "ts": float("inf")},
                          {"account": ah, "exit_class": "rate-limit", "ts": float("nan")}],
                         now), {})
    # future-stamp guard (cross-provider review r2 finding 2): the per-record clamp is relative to
    # the RECORD ts, so a forged now+50h stamp would otherwise back off far past the 5 h ceiling —
    # it must be dropped from the window AND skipped by the backoff walk (fail-open, like the
    # forged-stamp contract everywhere else); a within-skew stamp (runner clock drift) still works.
    chk("prune drops an implausibly-future stamp",
        len(prune([rec("openai", "codex01", "rate-limit", dt=FUTURE_SKEW_SECONDS + 10)], now)), 0)
    chk("prune keeps a within-skew stamp",
        len(prune([rec("openai", "codex01", "rate-limit", dt=60)], now)), 1)
    chk("future-forged stamp skipped fail-open (never a beyond-cap backoff)",
        account_backoffs([{"account": ah, "exit_class": CLASS_TRANSIENT, "ts": now + 180000}],
                         now), {})
    bskew = account_backoffs([{"account": ah, "exit_class": CLASS_TRANSIENT, "ts": now + 60}], now)
    chk("within-skew stamp still backs off (bounded by now + cap)",
        bskew.get(ah, {}).get("backoff_until"), now + 60 + BACKOFF_BASE_SECONDS)
    # the cap binds relative to NOW, not the record ts (cross-provider review r3 finding 1): a
    # record at exactly now + FUTURE_SKEW with a capped hint would otherwise return
    # now + 300 + 18000 — five minutes past the 5 h ceiling
    bcaph = account_backoffs([rec("openai", "codex01", "rate-limit", dt=FUTURE_SKEW_SECONDS,
                                  reset="in 999999 hours")], now)
    chk("within-skew stamp + capped hint ends at now + cap exactly",
        bcaph.get(ah, {}).get("backoff_until"), now + BACKOFF_CAP_SECONDS)
    # same bound on the exponential arm: last hit at now+110, derived at now+50 -> now+50+cap
    bcape = account_backoffs([rec("openai", "codex01", "rate-limit", dt=i * 10)
                              for i in range(12)], now + 50)
    chk("within-skew stamp + capped exponential ends at now + cap exactly",
        bcape.get(ah, {}).get("backoff_until"), now + 50 + BACKOFF_CAP_SECONDS)
    chk("hint: bare epoch", parse_reset_hint("1770000000", 1000), 1770000000.0)
    chk("hint: past epoch rejected", parse_reset_hint("1770000000", 1780000000), None)
    chk("hint: garbage -> None", parse_reset_hint("resets at 2pm", 1000), None)
    chk("hint: empty/None -> None", (parse_reset_hint("", 1000), parse_reset_hint(None, 1000)),
        (None, None))
    # transient (rate-limit) records now KEEP their reset hint (the backoff needs it)
    chk("rate-limit record keeps reset_hint",
        "reset_hint" in rec("openai", "codex01", "rate-limit", reset="in 20s"), True)

    # ---- prune / window bound ---------------------------------------------------------------
    many = [rec("anthropic", "acct01", CLASS_TRANSIENT, dt=i) for i in range(MAX_RECORDS + 50)]
    chk("prune caps to MAX_RECORDS", len(prune(many, now + MAX_RECORDS + 100)), MAX_RECORDS)
    old_new = [rec("anthropic", "a", CLASS_AUTH, dt=-(WINDOW_SECONDS + 10)),
               rec("anthropic", "a", CLASS_AUTH, dt=0)]
    chk("prune drops out-of-window", len(prune(old_new, now)), 1)

    # ---- ACTIVE-BACKOFF RETENTION across the MAX_RECORDS cap (issue #82, fix-forward #62) ----
    # End-to-end regression: an openai rate-limit hit with a 5 h reset hint, followed by 200+
    # LATER unrelated records, must still be enforced after pruning — before the fix the global
    # newest-MAX_RECORDS cap evicted the hit, so account_backoffs on the pruned window derived {}
    # and the capped account was readmitted hours early.
    hint_hit = [rec("openai", "codex01", "rate-limit", dt=0, reset="in 5 hours")]
    flood = [rec("anthropic", f"bulk{i:03d}", SUCCESS, dt=100 + i)
             for i in range(MAX_RECORDS + 30)]
    window = prune(hint_hit + flood, now + 1000)
    chk("live 5 h backoff survives a MAX_RECORDS flood of unrelated records",
        account_backoffs(window, now + 1000).get(ah, {}).get("backoff_until"),
        now + BACKOFF_CAP_SECONDS)
    chk("retention keeps the window bounded at MAX_RECORDS", len(window), MAX_RECORDS)
    # a short consecutive chain is preserved WHOLE, so the doubled multiplier re-derives exactly
    chain = [rec("openai", "codex01", "rate-limit", dt=i * 30) for i in range(3)]
    cb = account_backoffs(prune(chain + flood, now + 500), now + 500)
    chk("consecutive chain preserved across the cap (multiplier intact)",
        (cb.get(ah, {}).get("consecutive"), cb.get(ah, {}).get("backoff_until")),
        (3, now + 60 + 4 * BACKOFF_BASE_SECONDS))
    # a chain PAST cap-saturation keeps only its BACKOFF_CHAIN_KEEP tail — same derived
    # backoff_until (the exponential is capped either way), bound stays hard
    long_chain = [rec("openai", "codex01", "rate-limit", dt=i * 10) for i in range(20)]
    lwindow = prune(long_chain + flood, now + 500)
    chk("saturated chain truncates to its tail yet derives the same capped backoff",
        (len(lwindow), account_backoffs(lwindow, now + 500).get(ah, {}).get("backoff_until")),
        (MAX_RECORDS, now + 190 + BACKOFF_CAP_SECONDS))
    chk("chain-keep is the cap-saturation count", BACKOFF_CHAIN_KEEP, 6)
    # ...but truncation FLOORS the re-derived consecutive count at BACKOFF_CHAIN_KEEP (a 20-hit
    # chain re-derives as 6 — PR #85 finding 2), so a saturated count is only a LOWER BOUND and
    # the state says so; consumers render "x6+", never an exact "x6".
    lb = account_backoffs(lwindow, now + 500).get(ah, {})
    chk("truncated 20-hit chain: consecutive floors at chain-keep, flagged saturated",
        (lb.get("consecutive"), lb.get("saturated")), (BACKOFF_CHAIN_KEEP, True))
    lb_full = account_backoffs(long_chain, now + 500).get(ah, {})
    chk("untruncated 20-hit chain: exact count, still flagged saturated (>= chain-keep)",
        (lb_full.get("consecutive"), lb_full.get("saturated")), (20, True))
    chk("short chain: exact count, NOT saturated",
        (cb.get(ah, {}).get("consecutive"), cb.get(ah, {}).get("saturated")), (3, False))
    # mutation guards: only a LIVE backoff earns retention — an expired one, or one already
    # cleared by the account's own success, prunes normally (no unbounded pinning)
    ewindow = prune(hint_hit + flood, now + BACKOFF_CAP_SECONDS + 2000)
    chk("EXPIRED backoff record is not preserved (cap applies normally)",
        (len(ewindow), any(r["account"] == ah for r in ewindow)), (MAX_RECORDS, False))
    cleared = [rec("openai", "codex01", "rate-limit", dt=0),
               rec("openai", "codex01", SUCCESS, dt=50)]
    swindow = prune(cleared + flood, now + 1000)
    chk("success-cleared backoff record is not preserved",
        (len(swindow), any(r["account"] == ah for r in swindow)), (MAX_RECORDS, False))
    # ---- cap EXCEEDED by live backoffs alone (PR #85 finding 1) ------------------------------
    # When more than MAX_RECORDS records feed still-live backoffs (34 saturated 6-record chains
    # already total 204), the nominal cap CANNOT hold: every live backoff survives (correctness
    # over the cap), every expired/non-preserved record is evicted (the total is the preserved
    # set, never preserved + expired filler), and the overshoot is surfaced LOUDLY as a
    # fleet-wide saturation ::warning:: — never a silent bound violation.
    import contextlib
    import io
    live_count = MAX_RECORDS + 10
    live = [rec("openai", f"live{i:03d}", "rate-limit", dt=0) for i in range(live_count)]
    # expired: rate-limit hits whose 15-min backoff lapsed hours ago (still inside the 48 h window)
    lapsed = [rec("openai", f"dead{i:03d}", "rate-limit", dt=-7200 - i) for i in range(40)]
    sat_err = io.StringIO()
    with contextlib.redirect_stderr(sat_err):
        sat_window = prune(live + lapsed, now + 60)
    live_hashes = {account_hash(f"live{i:03d}", salt) for i in range(live_count)}
    chk("cap-exceeded: every live backoff survives the prune (correctness over cap)",
        sum(1 for r in sat_window if r["account"] in live_hashes), live_count)
    chk("cap-exceeded: expired records all evicted — total bounded by the live set",
        (len(sat_window), any(r["account"] not in live_hashes for r in sat_window)),
        (live_count, False))
    chk("cap-exceeded: every live backoff still derives on the pruned window",
        len(account_backoffs(sat_window, now + 60)), live_count)
    chk("cap-exceeded: saturation is SURFACED (::warning:: names the cap)",
        ("::warning::" in sat_err.getvalue(), f"MAX_RECORDS={MAX_RECORDS}" in sat_err.getvalue()),
        (True, True))
    # ...and an ordinary over-cap prune (live set within budget) stays silent — the saturation
    # warning must keep its operational signal, not fire on every routine bounded write.
    quiet_err = io.StringIO()
    with contextlib.redirect_stderr(quiet_err):
        quiet = prune(many, now + MAX_RECORDS + 100)
    chk("under-saturation prune emits no warning (bound still hard)",
        (len(quiet), quiet_err.getvalue()), (MAX_RECORDS, ""))

    # ---- validate_ledger rejects a RAW handle (privacy enforced at read) --------------------
    chk("ledger read rejects raw-handle account", _raises(lambda: validate_ledger(
        {"records": [{"ts": now, "provider": "p", "account": "acct01", "exit_class": "auth"}]})), True)
    chk("ledger read accepts salted hash", validate_ledger(
        {"records": [{"ts": now, "provider": "p", "account": account_hash("a", salt),
                      "exit_class": "auth"}]}) is not None, True)

    # ---- CAS writer against a stub API (create + append + conflict retry) --------------------
    ok = _test_cas(chk) and ok

    # ---- alert upsert operational idempotency (defect #7) ------------------------------------
    ok = _test_upsert(chk) and ok

    # ---- #203: marker lookup is authoritative + paginated (truncation != 'not found') --------
    ok = _test_lookup_pagination(chk) and ok

    # ---- record exits NONZERO on CAS exhaustion (defect #8) ----------------------------------
    ok = _test_record_exit(chk) and ok

    # ---- decide exits NONZERO on an unreadable ledger (review r3) ----------------------------
    ok = _test_decide_exit(chk) and ok

    # ---- #39 routing fallback ---------------------------------------------------------------
    ok = _test_routing(chk) and ok

    # ---- #175: unusable private token retries the registry, else fails nonzero ---------------
    ok = _test_delivery(chk) and ok

    # ---- review #340: an alert created on the fallback route is still recovered --------------
    ok = _test_fallback_orphan(chk) and ok

    # ---- provider fleet resolution (account catalog -> salted provider map) ------------------
    chk("provider parsed from YAML body",
        _provider_of("harness: claude\nprovider: anthropic\nmodels: [fable]"), "anthropic")
    chk("provider absent -> empty", _provider_of("models: [x]"), "")
    ok = _test_fleet(chk) and ok

    # ---- provider status probe + annotation (issue #70) --------------------------------------
    ok = _test_provider_status(chk) and ok
    ok = _test_probe_fetch(chk) and ok
    ok = _test_decide_annotation(chk) and ok

    print("model-health self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def _raises(fn):
    try:
        fn()
        return False
    except (ValueError, HealthError):
        return True


class _StubAPI:
    """In-memory contents API for the CAS writer test. `conflict_first` simulates a lost CAS race
    on the first PUT (a 409) so the retry loop is exercised. Ledger-branch discipline (issue #28)
    is enforced structurally: a GET that does not pin `?ref=ledger` misses, a PUT that does not
    carry `branch=ledger` fails — so pointing the I/O back at the default branch turns the whole
    CAS suite red. `branch_missing` simulates an absent ledger branch."""

    def __init__(self, seed=None, conflict_first=False, branch_missing=False):
        self._blob = None if seed is None else base64.b64encode(
            json.dumps({"records": seed}).encode()).decode()
        self._sha = None if seed is None else "sha0"
        self._n = 0
        self._conflict_first = conflict_first
        self._branch_missing = branch_missing
        self.last_put_branch = None

    def request(self, method, path, body=None, allow_404=False, retry_conflict=False):
        if method == "GET" and "/git/ref/heads/" in path:
            if self._branch_missing or not path.endswith("/git/ref/heads/ledger"):
                if allow_404:
                    return None
                raise HealthError("missing branch")
            return {"object": {"sha": "ledger-tip"}}
        if method == "GET":
            if self._blob is None or self._branch_missing or not path.endswith(
                    f"/contents/{LEDGER_PATH}?ref=ledger"):
                if allow_404:
                    return None
                raise HealthError("missing")
            return {"content": self._blob, "sha": self._sha}
        # PUT
        self.last_put_branch = body.get("branch")
        if self.last_put_branch != "ledger":
            raise HealthError("PUT did not pin the ledger branch")
        self._n += 1
        if self._conflict_first and self._n == 1:
            if retry_conflict:
                raise HealthConflict("stub conflict")
        self._blob = body["content"]
        self._sha = f"sha{self._n}"
        return {"content": {"sha": self._sha}}

    def records(self):
        return json.loads(base64.b64decode(self._blob).decode())["records"]


def _test_cas(chk):
    salt, now = "s3cret", 2_000_000
    r = make_record("anthropic", account_hash("acct01", salt), "fable", "auth", "9", now)
    # create-from-missing
    api = _StubAPI(seed=None)
    kept = append_record(api, "o/r", r, now)
    chk("CAS creates ledger from missing", (kept, len(api.records())), (1, 1))
    chk("CAS wrote a salted hash", api.records()[0]["account"], account_hash("acct01", salt))
    # append onto existing
    kept = append_record(api, "o/r", make_record(
        "anthropic", account_hash("acct02", salt), "fable", "success", "10", now + 1), now + 1)
    chk("CAS appends", kept, 2)
    # conflict retry
    apic = _StubAPI(seed=[], conflict_first=True)
    kept = append_record(apic, "o/r", r, now)
    chk("CAS retries past a conflict", kept, 1)
    # ---- ledger-branch targeting (issue #28: data plane off the protected code branch) ----
    chk("ledger read targets the ledger ref",
        ledger_read_path("o/r"), f"/repos/o/r/contents/{LEDGER_PATH}?ref=ledger")
    chk("CAS writes pinned branch=ledger", api.last_put_branch, "ledger")
    missing_branch_loud = False
    try:
        read_ledger(_StubAPI(seed=None, branch_missing=True), "o/r")
    except HealthError:
        missing_branch_loud = True
    chk("missing ledger BRANCH fails loud (never silently-empty)", missing_branch_loud, True)
    chk("missing ledger FILE on a present branch seeds empty (first-write path)",
        read_ledger(_StubAPI(seed=None), "o/r"), ([], None))
    return True


def _test_upsert(chk):
    """_upsert_alert operational idempotency (review defect #7), against a scripted fake gh:
    flap REOPENS the closed marker issue (never a duplicate create); a FAILED close posts no
    recovery comment (no next-tick spam); a confirmed close posts exactly the recovery comment."""
    import types
    global _gh
    real_gh, calls = _gh, []

    def fake_gh(open_issues, closed_issues, fail_verbs, list_fails=False):
        def run(args, token, capture=False):
            calls.append(list(args))
            if args[:2] == ["issue", "list"]:
                if list_fails:
                    return types.SimpleNamespace(returncode=1, stdout="", stderr="boom")
                state = args[args.index("--state") + 1]
                issues = open_issues if state == "open" else closed_issues
                return types.SimpleNamespace(returncode=0, stdout=json.dumps(issues), stderr="")
            verb = args[1] if args[0] == "issue" else args[0]
            return types.SimpleNamespace(returncode=1 if verb in fail_verbs else 0,
                                         stdout="", stderr="")
        return run

    def issue_verbs():
        return [c[1] for c in calls if c and c[0] == "issue"]

    marker = _marker("provider-outage", "anthropic")
    action = {"condition": "provider-outage", "provider": "anthropic", "fire": True, "reason": "r"}
    try:
        # flap: no open issue, a CLOSED marker issue exists -> REOPEN, never create
        _gh, calls[:] = fake_gh([], [{"number": 7, "body": marker}], set()), []
        chk("upsert returns True on a confirmed reopen", _upsert_alert(action, "o/r", "t", "m"), True)
        chk("upsert reopens the closed marker issue on flap", "reopen" in issue_verbs(), True)
        chk("upsert does not create a duplicate on flap", "create" in issue_verbs(), False)
        # fresh alert (no open, no closed) -> create
        _gh, calls[:] = fake_gh([], [], set()), []
        chk("upsert returns True on a confirmed create", _upsert_alert(action, "o/r", "t", "m"), True)
        chk("fresh alert creates the issue", "create" in issue_verbs(), True)
        # FAILED create -> returns False (issue #175: caller must see the failure, not exit 0)
        _gh, calls[:] = fake_gh([], [], {"create"}), []
        chk("upsert returns False on a FAILED create", _upsert_alert(action, "o/r", "t", "m"), False)
        # FAILED close -> returns False, and NO recovery comment (retries next tick)
        _gh, calls[:] = fake_gh([{"number": 8, "body": marker}], [], {"close"}), []
        chk("upsert returns False on a FAILED close",
            _upsert_alert({**action, "fire": False}, "o/r", "t", "m"), False)
        chk("failed close posts no recovery comment", "comment" in issue_verbs(), False)
        # confirmed close -> returns True + recovery comment
        _gh, calls[:] = fake_gh([{"number": 8, "body": marker}], [], set()), []
        chk("upsert returns True on a confirmed close",
            _upsert_alert({**action, "fire": False}, "o/r", "t", "m"), True)
        chk("confirmed close posts the recovery comment", "comment" in issue_verbs(), True)
        # steady no-alert with no open issue -> confirmed no-op (True), no mutation
        _gh, calls[:] = fake_gh([], [], set()), []
        chk("steady no-alert is a confirmed no-op (True)",
            _upsert_alert({**action, "fire": False}, "o/r", "t", "m"), True)
        chk("steady no-alert touches nothing", issue_verbs(), ["list"])
        # UNREADABLE tracker (list read fails) -> False and NEVER a blind create (issue #175)
        _gh, calls[:] = fake_gh([], [], set(), list_fails=True), []
        chk("unreadable tracker returns False (undelivered)",
            _upsert_alert(action, "o/r", "t", "m"), False)
        chk("unreadable tracker does NOT create over itself", "create" in issue_verbs(), False)
        # valid-but-NON-LIST list JSON ({} / null) is unreadable too, never an empty tracker
        _gh, calls[:] = fake_gh({}, [], set()), []
        chk("non-list tracker JSON ({}) returns False (undelivered)",
            _upsert_alert(action, "o/r", "t", "m"), False)
        chk("non-list tracker JSON ({}) does NOT create over itself",
            "create" in issue_verbs(), False)
        _gh, calls[:] = fake_gh(None, [], set()), []
        chk("null tracker JSON returns False (undelivered)",
            _upsert_alert(action, "o/r", "t", "m"), False)
        chk("null tracker JSON does NOT create over itself", "create" in issue_verbs(), False)
        # reopen lands but the body refresh FAILS -> False (stale body is not the desired state)
        _gh, calls[:] = fake_gh([], [{"number": 7, "body": marker}], {"edit"}), []
        chk("upsert returns False when reopen succeeds but the edit fails",
            _upsert_alert(action, "o/r", "t", "m"), False)
    finally:
        _gh = real_gh
    return True


def _test_lookup_pagination(chk):
    """_find_marker_issue is an AUTHORITATIVE, paginated lookup (#203): it reads up to
    ALERT_LOOKUP_CAP issues (gh paginates the API to fill --limit, far past the old 50-issue
    window), and a result AT the cap is treated as possibly truncated and RAISED — a failed OR
    truncated read must never be mistaken for 'not found' and let a duplicate be minted over an
    unseen marker. The cap assertion + the full-window raise both go RED on the pre-fix
    --limit-50, no-truncation-guard code."""
    import types
    global _gh
    real_gh, calls = _gh, []

    def fake_gh(issues):
        def run(args, token, capture=False):
            calls.append(list(args))
            return types.SimpleNamespace(returncode=0, stdout=json.dumps(issues), stderr="")
        return run

    marker = _marker("provider-outage", "anthropic")
    try:
        # the lookup asks for the authoritative cap, not the old 50-issue window
        _gh, calls[:] = fake_gh([]), []
        _find_marker_issue("o/r", "t", marker, "open")
        limit = calls[0][calls[0].index("--limit") + 1]
        chk("lookup requests the authoritative cap, not 50", limit, str(ALERT_LOOKUP_CAP))

        # a marker sitting BEYOND the old 50-issue window is still found (paginated)
        window = [{"number": i, "body": f"decoy-{i}"} for i in range(120)]
        window[110]["body"] = marker
        _gh = fake_gh(window)
        chk("marker beyond the old 50-window is found",
            _find_marker_issue("o/r", "t", marker, "closed"), 110)

        # a FULL window (cap items, no marker) is possibly truncated -> RAISE, never 'not found'
        full = [{"number": i, "body": f"decoy-{i}"} for i in range(ALERT_LOOKUP_CAP)]
        _gh = fake_gh(full)
        chk("full window raises (a truncated read is not 'not found')",
            _raises(lambda: _find_marker_issue("o/r", "t", marker, "closed")), True)
    finally:
        _gh = real_gh
    return True


def _test_open_markers(chk):
    """_open_alert_markers extracts every open (condition, provider) pair and FAILS OPEN to the
    empty set on any unreadable/garbled/possibly-truncated list (issue #205) — the orphan recovery
    it feeds only closes stale alerts, so a fabricated 'open' here would invent a recovery, while a
    missed read merely defers one to the next tick."""
    import types
    global _gh
    real_gh = _gh

    def fake_gh(returncode=0, stdout=None, issues=None):
        payload = stdout if stdout is not None else json.dumps(issues or [])

        def run(args, token, capture=False):
            return types.SimpleNamespace(returncode=returncode, stdout=payload, stderr="")
        return run

    try:
        _gh = fake_gh(issues=[{"body": _marker("zero-dispatch", "fleet")},
                              {"body": _marker("provider-outage", "anthropic")},
                              {"body": "unrelated issue, no marker"}])
        chk("open markers enumerated from the tracker",
            _open_alert_markers("o/r", "t"),
            {("zero-dispatch", "fleet"), ("provider-outage", "anthropic")})
        _gh = fake_gh(returncode=1)
        chk("a failed list fails open to empty (no fabricated recovery)",
            _open_alert_markers("o/r", "t"), set())
        _gh = fake_gh(stdout="{not json")
        chk("garbled list JSON fails open to empty", _open_alert_markers("o/r", "t"), set())
        _gh = fake_gh(stdout="{}")
        chk("non-list list JSON fails open to empty", _open_alert_markers("o/r", "t"), set())
        _gh = fake_gh(issues=[{"body": _marker("zero-dispatch", "fleet")}] * ALERT_LOOKUP_CAP)
        chk("a full (possibly truncated) window fails open to empty",
            _open_alert_markers("o/r", "t"), set())
    finally:
        _gh = real_gh
    return True


def _test_record_exit(chk):
    """_cmd_record exits NONZERO when the CAS write is exhausted (review defect #8) — the record
    call sites are separate always()-guarded jobs, so the failure is visible, never silent."""
    import argparse as _ap
    global GitHubAPI
    real_api = GitHubAPI
    saved = {k: os.environ.get(k) for k in
             ("REGISTRY_REPO", "WORKER_ACCOUNT_HANDLE", "PROVENANCE_SALT",
              "GH_TOKEN", "REGISTRY_ALERT_TOKEN")}

    class _ExhaustAPI:
        def __init__(self, token):
            pass

        def request(self, method, path, body=None, allow_404=False, retry_conflict=False):
            if method == "GET":
                return None    # empty ledger; every PUT below loses the CAS race
            raise HealthConflict("stub: permanent CAS contention")

    try:
        os.environ.update(REGISTRY_REPO="o/r", WORKER_ACCOUNT_HANDLE="acct01",
                          PROVENANCE_SALT="s3cret", GH_TOKEN="tok")
        GitHubAPI = _ExhaustAPI
        args = _ap.Namespace(provider="anthropic", account="", model_alias="fable",
                             exit_class="auth", run_id="1", reset_hint=None)
        chk("record exits nonzero on CAS exhaustion", _cmd_record(args), 1)
    finally:
        GitHubAPI = real_api
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return True


def _test_decide_exit(chk):
    """_cmd_decide exits NONZERO when the ledger cannot be read (review r3) — every ledger
    reader fails LOUD; groom.yml's continue-on-error keeps the sweep alive while the step
    goes red, so this must never be softened back to warn-and-exit-0."""
    import argparse as _ap
    global GitHubAPI
    real_api = GitHubAPI
    saved = {k: os.environ.get(k) for k in ("REGISTRY_REPO", "GH_TOKEN")}
    try:
        os.environ.update(REGISTRY_REPO="o/r", GH_TOKEN="tok")
        GitHubAPI = lambda token: _StubAPI(seed=None, branch_missing=True)
        chk("decide exits nonzero on an unreadable ledger",
            _cmd_decide(_ap.Namespace(policy_file="policy/repos.toml")), 1)
    finally:
        GitHubAPI = real_api
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return True


def _test_routing(chk):
    saved = {k: os.environ.get(k) for k in
             ("REGISTRY_REPO", "ALERT_REPO", "ALERT_TOKEN", "REGISTRY_ALERT_TOKEN", "GH_TOKEN")}
    try:
        os.environ["REGISTRY_REPO"] = "jeswr/agent-account-registry"
        os.environ.pop("GH_TOKEN", None)
        os.environ["REGISTRY_ALERT_TOKEN"] = "amb"
        # private repo + token -> route private
        os.environ["ALERT_REPO"] = "jeswr/agent-account-data"
        os.environ["ALERT_TOKEN"] = "priv"
        chk("route private when repo+token", _alert_target(), ("jeswr/agent-account-data", "priv"))
        # #39: ALERT_REPO set, NO token -> fall back to the registry repo + ambient token (not silent)
        os.environ["ALERT_TOKEN"] = ""
        chk("route falls back to registry when token absent (#39)",
            _alert_target(), ("jeswr/agent-account-registry", "amb"))
        # no ALERT_REPO at all -> registry repo
        os.environ.pop("ALERT_REPO", None)
        chk("route registry when no ALERT_REPO",
            _alert_target(), ("jeswr/agent-account-registry", "amb"))
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return True


def _test_delivery(chk):
    """Issue #175: a nonempty-but-unusable ALERT_TOKEN must NOT silently drop alerts. The private
    route failing retries the salted alert on the public registry with the ambient token; only when
    NEITHER route delivers is the action reported undelivered (caller then exits nonzero). A
    fake gh keyed on (token, repo) proves the retry hits the REGISTRY with the AMBIENT token."""
    import types
    global _gh
    real_gh, calls = _gh, []

    def fake_gh(bad_tokens):
        def run(args, token, capture=False):
            repo = args[args.index("-R") + 1] if "-R" in args else None
            calls.append((args[0], args[1] if args[0] == "issue" else None, token, repo))
            if args[:2] == ["issue", "list"]:
                # list reads always succeed and return empty (fresh -> create path)
                return types.SimpleNamespace(returncode=0, stdout="[]", stderr="")
            rc = 1 if token in bad_tokens else 0
            return types.SimpleNamespace(returncode=rc, stdout="", stderr="")
        return run

    def creates():
        return [(t, r) for (v, sub, t, r) in calls if sub == "create"]

    saved = {k: os.environ.get(k) for k in
             ("REGISTRY_REPO", "ALERT_REPO", "ALERT_TOKEN", "REGISTRY_ALERT_TOKEN", "GH_TOKEN")}
    fire = {"condition": "provider-outage", "provider": "anthropic", "fire": True, "reason": "r"}
    try:
        os.environ["REGISTRY_REPO"] = "jeswr/agent-account-registry"
        os.environ["REGISTRY_ALERT_TOKEN"] = "amb"
        os.environ.pop("GH_TOKEN", None)
        os.environ["ALERT_REPO"] = "jeswr/agent-account-data"
        os.environ["ALERT_TOKEN"] = "priv"

        # (a) private token UNUSABLE, ambient usable -> retried on the registry, delivered
        _gh, calls[:] = fake_gh({"priv"}), []
        undelivered = _deliver_alerts([fire], "m")
        chk("unusable private token: alert delivered via the registry fallback", undelivered, [])
        chk("fallback create targets the REGISTRY with the AMBIENT token",
            ("amb", "jeswr/agent-account-registry") in creates(), True)
        chk("private route was attempted first (priv token create tried)",
            ("priv", "jeswr/agent-account-data") in creates(), True)

        # (b) BOTH routes unusable -> reported undelivered (caller exits nonzero)
        _gh, calls[:] = fake_gh({"priv", "amb"}), []
        undelivered = _deliver_alerts([fire], "m")
        chk("both routes unusable -> action reported undelivered", len(undelivered), 1)

        # (c) end-to-end: _cmd_decide returns NONZERO when the alert cannot be delivered.
        #     Stub the ledger + fleet + probe so a firing outage reaches delivery deterministically.
        import argparse as _ap
        global GitHubAPI, _enabled_provider_accounts, annotate_provider_status, prune, read_ledger
        real = (GitHubAPI, _enabled_provider_accounts, annotate_provider_status, prune, read_ledger)
        try:
            GitHubAPI = lambda token: object()
            read_ledger = lambda api, repo: ([], None)
            prune = lambda records, now: []
            _enabled_provider_accounts = lambda api, repo, policy, salt: {}
            annotate_provider_status = lambda actions, **kw: None  # no-op (probe-free)
            # force a single firing action regardless of records
            global classify_records
            real_classify = classify_records
            classify_records = lambda records, fleet, now, open_alerts=(): [dict(fire)]
            _gh, calls[:] = fake_gh({"priv", "amb"}), []
            chk("decide exits NONZERO when no route can deliver the alert (#175)",
                _cmd_decide(_ap.Namespace(policy_file="policy/repos.toml")), 1)
            classify_records = real_classify
        finally:
            (GitHubAPI, _enabled_provider_accounts, annotate_provider_status,
             prune, read_ledger) = real

        # (d) no private ALERT_TOKEN at all -> primary IS the registry; no pointless retry, and a
        #     failing ambient token is reported undelivered (fail-closed, never a silent green).
        os.environ["ALERT_TOKEN"] = ""
        _gh, calls[:] = fake_gh({"amb"}), []
        undelivered = _deliver_alerts([fire], "m")
        chk("registry-only route with a bad ambient token is undelivered", len(undelivered), 1)
        chk("registry-only route is not retried against itself",
            sum(1 for c in creates()), 1)

        # (e) review round 2: a FAILED private recovery (fire=false, open marker on the private
        #     route, close fails) must stay undelivered. Pre-fix, the registry fallback found no
        #     open marker, returned True as a steady no-op, and the failed close vanished green.
        os.environ["ALERT_TOKEN"] = "priv"  # restore the private route cleared by (d)
        recover = {**fire, "fire": False}
        marker = _marker(recover["condition"], recover["provider"])

        def recovery_gh(args, token, capture=False):
            repo = args[args.index("-R") + 1] if "-R" in args else None
            calls.append((args[0], args[1] if args[0] == "issue" else None, token, repo))
            if args[:2] == ["issue", "list"]:
                if repo == "jeswr/agent-account-data":
                    return types.SimpleNamespace(
                        returncode=0, stdout=json.dumps([{"number": 7, "body": marker}]),
                        stderr="")
                return types.SimpleNamespace(returncode=0, stdout="[]", stderr="")
            if args[:2] == ["issue", "close"]:
                return types.SimpleNamespace(returncode=1, stdout="", stderr="")
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        _gh, calls[:] = recovery_gh, []
        undelivered = _deliver_alerts([recover], "m")
        chk("failed private recovery stays undelivered (fallback no-op cannot confirm it)",
            len(undelivered), 1)
        chk("recovery never retries cross-repo (no registry calls on fire=false)",
            any(r == "jeswr/agent-account-registry" for (_, _, _, r) in calls), False)
    finally:
        _gh = real_gh
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return True


def _test_fallback_orphan(chk):
    """Review #340: an alert CREATED ON THE FALLBACK ROUTE (by the #175 firing retry) must still
    be recovered. End-to-end against a stateful two-repo gh fake: primary firing delivery fails,
    the fallback create succeeds, the records age out, and the next decide closes the fallback
    issue — with the red direction proving a failed fallback close is NOT confirmed by the
    primary's steady no-op (pre-fix, decide exited 0 and the issue stayed open forever)."""
    import argparse as _ap
    import types
    global _gh, GitHubAPI, _enabled_provider_accounts, annotate_provider_status, prune, read_ledger
    real_gh = _gh
    real = (GitHubAPI, _enabled_provider_accounts, annotate_provider_status, prune, read_ledger)
    saved = {k: os.environ.get(k) for k in
             ("REGISTRY_REPO", "ALERT_REPO", "ALERT_TOKEN", "REGISTRY_ALERT_TOKEN", "GH_TOKEN")}
    priv_repo, reg_repo = "jeswr/agent-account-data", "jeswr/agent-account-registry"
    repos = {priv_repo: {}, reg_repo: {}}
    seq = {"n": 100}
    bad_tokens = {"priv"}          # phase 1: the private token is unusable
    fail_close = {"on": False}

    def state_gh(args, token, capture=False):
        repo = args[args.index("-R") + 1] if "-R" in args else None
        if args[0] == "label":
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        if token in bad_tokens:
            return types.SimpleNamespace(returncode=1, stdout="", stderr="")
        verb, issues = args[1], repos[repo]
        if verb == "list":
            state = args[args.index("--state") + 1]
            out = [{"number": n, "body": i["body"]}
                   for n, i in sorted(issues.items()) if i["state"] == state]
            return types.SimpleNamespace(returncode=0, stdout=json.dumps(out), stderr="")
        if verb == "create":
            seq["n"] += 1
            issues[seq["n"]] = {"body": args[args.index("--body") + 1], "state": "open"}
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        num = int(args[2])
        if verb == "close":
            if fail_close["on"]:
                return types.SimpleNamespace(returncode=1, stdout="", stderr="")
            issues[num]["state"] = "closed"
        elif verb == "edit":
            issues[num]["body"] = args[args.index("--body") + 1]
        elif verb == "reopen":
            issues[num]["state"] = "open"
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    def reg_states():
        return [i["state"] for _, i in sorted(repos[reg_repo].items())]

    fire = {"condition": "provider-outage", "provider": "anthropic", "fire": True, "reason": "r"}
    try:
        os.environ.update(REGISTRY_REPO=reg_repo, ALERT_REPO=priv_repo, ALERT_TOKEN="priv",
                          REGISTRY_ALERT_TOKEN="amb")
        os.environ.pop("GH_TOKEN", None)
        _gh = state_gh

        # phase 1: primary firing delivery fails -> the alert is CREATED on the fallback.
        chk("fallback-orphan: firing delivered via the fallback create",
            _deliver_alerts([fire], "m"), [])
        chk("fallback-orphan: the issue lives on the registry, none on the private route",
            (reg_states(), repos[priv_repo]), (["open"], {}))

        # phase 2: the private token works again and the records have aged out. decide must
        # enumerate the fallback marker, emit the orphan recovery, and close it THERE.
        bad_tokens.clear()
        GitHubAPI = lambda token: object()
        read_ledger = lambda api, repo: ([], None)
        prune = lambda records, now: []
        _enabled_provider_accounts = lambda api, repo, policy, salt: {}
        annotate_provider_status = lambda actions, **kw: None
        ns = _ap.Namespace(policy_file="policy/repos.toml")

        # red direction first: the fallback close FAILS -> the primary's steady no-op must not
        # count as delivery (pre-fix, decide exited 0 here with the issue still open).
        fail_close["on"] = True
        chk("fallback-orphan: failed fallback close -> decide exits NONZERO, issue still open",
            (_cmd_decide(ns), reg_states()), (1, ["open"]))

        fail_close["on"] = False
        chk("fallback-orphan: next decide closes the fallback issue and exits 0",
            (_cmd_decide(ns), reg_states()), (0, ["closed"]))
    finally:
        _gh = real_gh
        (GitHubAPI, _enabled_provider_accounts, annotate_provider_status,
         prune, read_ledger) = real
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return True


def _test_fleet(chk):
    """_enabled_provider_accounts maps enabled-pool handles -> {provider: {salted hashes}} and
    emits NO raw handle. Uses a stub API returning a policy-pool + account catalog."""
    import tempfile
    salt = "s3cret"
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as fh:
        fh.write('[repos."o/a"]\nenabled = true\naccount_pool = ["acct01", "acct02"]\n'
                 '[repos."o/b"]\nenabled = false\naccount_pool = ["acct99"]\n')
        policy = fh.name

    class _CatalogAPI:
        def paginate(self, path):
            return [
                {"title": "acct01", "body": "provider: anthropic\nmodels: [fable]"},
                {"title": "acct02", "body": "provider: openai\nmodels: [terra]"},
                {"title": "acct99", "body": "provider: openai\nmodels: [gpt]"},  # disabled row
                {"title": "acct01", "pull_request": {}, "body": "ignore PRs"},
            ]

    got = _enabled_provider_accounts(_CatalogAPI(), "o/r", policy, salt)
    empty = _enabled_provider_accounts(_CatalogAPI(), "o/r", policy, "")
    os.unlink(policy)
    want = {"anthropic": {account_hash("acct01", salt)},
            "openai": {account_hash("acct02", salt)}}
    chk("fleet maps enabled pool to provider+hash", got, want)
    chk("fleet emits no raw handle", "acct01" not in json.dumps(sorted(
        h for hs in got.values() for h in hs)), True)
    chk("fleet empty without salt", empty, {})
    return True


def _test_provider_status(chk):
    """Provider status probe (issue #70): recorded Statuspage fixtures for ALL FOUR indicators
    plus the unreachable path. FAIL-OPEN is mutation-checked: a raising fetch must fold to
    ('unknown', '') — deleting the except in probe_provider_status crashes this test red — and
    annotation must never flip `fire` off, whatever the probe says."""
    # Recorded fixture: the real status.claude.com/status.openai.com /api/v2/status.json shape.
    def fixture(indicator, description):
        return {"page": {"id": "23dnwm3xnarn", "name": "Claude",
                         "url": "https://status.claude.com", "updated_at": "2026-07-17T00:00:00Z"},
                "status": {"indicator": indicator, "description": description}}

    chk("indicator none -> operational",
        classify_status_payload(fixture("none", "All Systems Operational")),
        (STATUS_OPERATIONAL, "none"))
    chk("indicator minor -> degraded",
        classify_status_payload(fixture("minor", "Partially Degraded Service")),
        (STATUS_DEGRADED, "minor"))
    chk("indicator major -> outage",
        classify_status_payload(fixture("major", "Partial System Outage")),
        (STATUS_OUTAGE, "major"))
    chk("indicator critical -> outage",
        classify_status_payload(fixture("critical", "Major System Outage")),
        (STATUS_OUTAGE, "critical"))
    chk("novel indicator -> unknown (fail-open fold)",
        classify_status_payload(fixture("maintenance", "x"))[0], STATUS_UNKNOWN)
    chk("malformed payload -> unknown",
        classify_status_payload({"status": "green"}), (STATUS_UNKNOWN, ""))
    chk("non-dict payload -> unknown",
        classify_status_payload(None), (STATUS_UNKNOWN, ""))

    # probe: URL pinning + FAIL-OPEN on unreachable (the mutation check)
    calls = []

    def ok_fetch(url):
        calls.append(url)
        return fixture("minor", "d")

    def unreachable(url):
        raise HealthError("stub: connection timed out")

    chk("probe anthropic folds the fetched indicator",
        probe_provider_status("anthropic", fetch=ok_fetch), (STATUS_DEGRADED, "minor"))
    chk("probe openai hits its own recorded URL",
        (probe_provider_status("openai", fetch=ok_fetch), calls[-1]),
        ((STATUS_DEGRADED, "minor"), "https://status.openai.com/api/v2/status.json"))
    chk("probe pins the recorded anthropic URL",
        calls[0], "https://status.claude.com/api/v2/status.json")
    chk("UNREACHABLE fails OPEN to unknown (mutation: drop the except -> crashes red)",
        probe_provider_status("anthropic", fetch=unreachable), (STATUS_UNKNOWN, ""))
    chk("unmapped provider -> unknown without any fetch",
        probe_provider_status("fleet", fetch=unreachable), (STATUS_UNKNOWN, ""))

    # annotation: firing outage/transient only, one probe per provider, fire NEVER touched
    probes = []

    def probe(provider):
        probes.append(provider)
        return STATUS_OPERATIONAL, "none"

    actions = [
        {"condition": "persistent-transient", "provider": "anthropic", "fire": True, "reason": "r"},
        {"condition": "provider-outage", "provider": "anthropic", "fire": True, "reason": "r"},
        {"condition": "provider-capped", "provider": "anthropic", "fire": True, "reason": "r"},
        {"condition": "persistent-transient", "provider": "openai", "fire": False, "reason": "r"},
    ]
    annotate_provider_status(actions, probe=probe)
    chk("one probe per provider, none for quiet/unprobed conditions", probes, ["anthropic"])
    chk("only firing outage/transient actions are annotated",
        [a.get("provider_status") for a in actions],
        [STATUS_OPERATIONAL, STATUS_OPERATIONAL, None, None])
    chk("operational NEVER suppresses: fire flags untouched by annotation",
        [a["fire"] for a in actions], [True, True, True, False])

    # body rendering: SELF-INDUCED / unverified / known-incident / fail-open framings.
    # counts defaults to a pure TRUE-transient burst; finding-2 checks override it.
    def body(cond, status, indicator, counts=None):
        action = {"condition": cond, "provider": "anthropic", "fire": True,
                  "reason": "5 transient/unknown API failures in 15 min",
                  "provider_status": status, "status_indicator": indicator}
        if cond == "persistent-transient":
            action["class_counts"] = (counts if counts is not None
                                      else {CLASS_TRANSIENT: 5, CLASS_UNKNOWN: 0})
        return render_body(action, "m")

    green = body("persistent-transient", STATUS_OPERATIONAL, "none")
    chk("operational TRUE-transient burst is labelled SELF-INDUCED", "SELF-INDUCED" in green, True)
    chk("...with shed-parallelism advice", "SHED PARALLELISM" in green, True)
    chk("...and the provider-status annotation", "provider-status: operational" in green, True)
    # review #72 finding 2: unknown/mixed bursts get the UNVERIFIED framing, never SELF-INDUCED
    all_unknown = body("persistent-transient", STATUS_OPERATIONAL, "none",
                       counts={CLASS_TRANSIENT: 0, CLASS_UNKNOWN: 5})
    chk("operational all-unknown burst is NOT labelled SELF-INDUCED",
        ("SELF-INDUCED" in all_unknown, "SHED PARALLELISM" in all_unknown), (False, False))
    chk("...it gets the unverified framing instead",
        ("cause UNVERIFIED" in all_unknown, "UNATTRIBUTABLE" in all_unknown), (True, True))
    chk("...and its headline drops the retryable-429 claim",
        "individually retryable" in all_unknown, False)
    mixed = body("persistent-transient", STATUS_OPERATIONAL, "none",
                 counts={CLASS_TRANSIENT: 2, CLASS_UNKNOWN: 3})
    chk("mixed burst below the true-transient threshold is unverified",
        ("SELF-INDUCED" in mixed, "cause UNVERIFIED" in mixed), (False, True))
    qualified = body("persistent-transient", STATUS_OPERATIONAL, "none",
                     counts={CLASS_TRANSIENT: 5, CLASS_UNKNOWN: 2})
    chk("a qualifying true-transient burst keeps SELF-INDUCED despite extra unknowns",
        "SELF-INDUCED" in qualified, True)
    no_counts = render_body({"condition": "persistent-transient", "provider": "anthropic",
                             "fire": True, "reason": "r",
                             "provider_status": STATUS_OPERATIONAL,
                             "status_indicator": "none"}, "m")
    chk("missing composition never claims SELF-INDUCED (evidence not held)",
        "SELF-INDUCED" in no_counts, False)
    minor = body("persistent-transient", STATUS_DEGRADED, "minor")
    chk("degraded carries the qualified annotation",
        "provider-status: degraded (minor)" in minor, True)
    chk("degraded uses known-incident framing + harder backoff",
        ("known provider incident" in minor, "back off HARDER" in minor), (True, True))
    crit = body("provider-outage", STATUS_OUTAGE, "critical")
    chk("critical outage carries the qualified annotation",
        "provider-status: outage (critical)" in crit, True)
    chk("outage uses known-incident framing", "known provider incident" in crit, True)
    green_outage = body("provider-outage", STATUS_OPERATIONAL, "none")
    chk("operational outage points at credentials/credits, not the provider",
        "expired tokens" in green_outage, True)
    unknown = body("persistent-transient", STATUS_UNKNOWN, "")
    chk("unknown states the fail-open (never suppressed)",
        ("provider-status: unknown" in unknown, "NEVER suppressed" in unknown), (True, True))
    plain = render_body({"condition": "persistent-transient", "provider": "anthropic",
                         "fire": True, "reason": "r"}, "m")
    chk("unprobed action renders no provider-status line", "provider-status" in plain, False)
    return True


def _test_probe_fetch(chk):
    """The PRODUCTION fetch path (review #72 findings, rounds 2+3): failures raised by
    response.read() MID-BODY — a raw OSError (connection reset) or http.client.IncompleteRead
    (truncated response) — must normalize to HealthError; a TRICKLING response must be
    abandoned at the wall-clock deadline; an OVERSIZED body must trip the size bound. In every
    case the probe fails OPEN instead of stalling or aborting `decide` before the alert
    upsert. urlopen is patched; no network is touched. Mutation strength: dropping the
    OSError/HTTPException normalization crashes the mid-read checks red (the raw exception
    escapes _raises); dropping the deadline thread turns the elapsed-time check red; dropping
    the size cap parses the oversized body successfully and turns its check red."""
    import http.client
    import urllib.request

    class _MidReadResponse:
        def __init__(self, exc):
            self._exc = exc

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def read(self, amt=None):
            raise self._exc

    real_urlopen = urllib.request.urlopen
    try:
        for name, exc in (("OSError (connection reset)", ConnectionResetError("reset")),
                          ("IncompleteRead", http.client.IncompleteRead(b"partial"))):
            urllib.request.urlopen = (
                lambda request, timeout=None, _exc=exc: _MidReadResponse(_exc))
            chk(f"fetch normalizes mid-read {name} to HealthError",
                _raises(lambda: _fetch_status_json(PROVIDER_STATUS_URLS["anthropic"])), True)
            chk(f"probe production path fails OPEN on mid-read {name}",
                probe_provider_status("anthropic"), (STATUS_UNKNOWN, ""))
    finally:
        urllib.request.urlopen = real_urlopen

    # The annotation boundary itself is a backstop: even an exception class the fetch failed
    # to normalize folds to unknown (mutation: drop the broad except in probe_provider_status
    # -> this crashes red), so a probe surprise can never abort `decide`.
    def unnormalized(url):
        raise RuntimeError("stub: exception class the fetch did not normalize")

    chk("annotation boundary fails OPEN on an unnormalized exception",
        probe_provider_status("anthropic", fetch=unnormalized), (STATUS_UNKNOWN, ""))

    # Review #72 round 3: a peer that TRICKLES bytes — each individual read fast enough that
    # the per-socket-op timeout never fires, but the total unbounded — must not hold the fetch
    # past its wall-clock deadline. The stub yields one byte per 0.15s read forever; with a
    # 0.4s deadline the fetch must abandon it and fail OPEN. Mutation strength: reverting to a
    # direct (threadless) call makes the fetch ride the trickle to its end (~3s), turning the
    # elapsed-time check red.
    class _TrickleResponse:
        def __init__(self):
            self._reads = 0

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def read(self, amt=None):
            self._reads += 1
            if self._reads > 20:  # let the abandoned daemon thread terminate eventually
                return b""
            time.sleep(0.15)
            return b"x"

    real_urlopen = urllib.request.urlopen
    try:
        urllib.request.urlopen = lambda request, timeout=None: _TrickleResponse()
        started = time.monotonic()
        chk("trickling response is abandoned at the wall-clock deadline (HealthError)",
            _raises(lambda: _fetch_status_json(
                PROVIDER_STATUS_URLS["anthropic"], deadline=0.4)), True)
        chk("...without riding the trickle to completion",
            time.monotonic() - started < 1.5, True)
        chk("probe production path fails OPEN on a trickling response",
            probe_provider_status(
                "anthropic",
                fetch=lambda url: _fetch_status_json(url, deadline=0.4)),
            (STATUS_UNKNOWN, ""))
    finally:
        urllib.request.urlopen = real_urlopen

    # Size bound: an OVERSIZED but otherwise VALID JSON body must be rejected, not parsed.
    # Mutation strength: dropping the size cap lets this parse successfully -> chk goes red
    # (it cannot pass by accident via a parse error).
    oversized = json.dumps({"status": {"indicator": "none"},
                            "pad": "a" * (STATUS_PROBE_MAX_BYTES + 1)}).encode()

    class _OversizedResponse:
        def __init__(self):
            self._pos = 0

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def read(self, amt=None):
            chunk = oversized[self._pos:self._pos + (amt or len(oversized))]
            self._pos += len(chunk)
            return chunk

    try:
        urllib.request.urlopen = lambda request, timeout=None: _OversizedResponse()
        chk("oversized valid-JSON body trips the size bound (HealthError)",
            _raises(lambda: _fetch_status_json(PROVIDER_STATUS_URLS["anthropic"])), True)
        chk("probe production path fails OPEN on an oversized body",
            probe_provider_status("anthropic"), (STATUS_UNKNOWN, ""))
    finally:
        urllib.request.urlopen = real_urlopen
    return True


def _test_decide_annotation(chk):
    """decide WIRES the probe (deleting the annotate_provider_status call in _cmd_decide turns
    this red): a firing persistent-transient action reaches the alert upsert already carrying
    provider-status, with the network probe and gh upsert both stubbed out."""
    import argparse as _ap
    global GitHubAPI, probe_provider_status, _upsert_alert, _open_alert_markers
    real_api, real_probe, real_upsert = GitHubAPI, probe_provider_status, _upsert_alert
    real_markers = _open_alert_markers
    saved = {k: os.environ.get(k) for k in
             ("REGISTRY_REPO", "GH_TOKEN", "ALERT_REPO", "ALERT_TOKEN", "REGISTRY_ALERT_TOKEN")}
    now, salt, seen = int(time.time()), "s3cret", []
    burst = [make_record("anthropic", account_hash("acct01", salt), "fable",
                         CLASS_TRANSIENT, str(i), now - 300 + i * 60) for i in range(5)]
    try:
        os.environ.update(REGISTRY_REPO="o/r", GH_TOKEN="tok")
        os.environ.pop("ALERT_REPO", None)
        os.environ.pop("ALERT_TOKEN", None)
        stub = _StubAPI(seed=burst)
        GitHubAPI = lambda token: stub
        probe_provider_status = lambda provider, fetch=None: (STATUS_OPERATIONAL, "none")
        _open_alert_markers = lambda repo, token: set()  # hermetic: no real gh subprocess
        # returns True: the new delivery contract (issue #175) treats a confirmed upsert as True.
        _upsert_alert = lambda action, repo, token, maintainer: seen.append(action) or True
        rc = _cmd_decide(_ap.Namespace(policy_file="/nonexistent/repos.toml"))
        fired = [a for a in seen
                 if a["condition"] == "persistent-transient" and a["fire"]]
        chk("decide exits 0 and fires the transient alert", (rc, len(fired)), (0, 1))
        chk("decide-time annotation reaches the upsert",
            (fired or [{}])[0].get("provider_status"), STATUS_OPERATIONAL)
    finally:
        GitHubAPI, probe_provider_status, _upsert_alert = real_api, real_probe, real_upsert
        _open_alert_markers = real_markers
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return True


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main(sys.argv[1:]))
