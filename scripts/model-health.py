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
#             not duplicated (a hidden marker in the body keys the upsert).
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
import subprocess
import sys
import time

LEDGER_PATH = "data/model-health.json"

# --- ledger bounds (WHY): a rolling window is enough to decide "is access failing NOW"; an
# unbounded append would grow the committed file forever and slow every CAS write. 200 records / 48h
# comfortably covers the ~40-slot fleet across several dispatch ticks while staying tiny in git.
MAX_RECORDS = 200
WINDOW_HOURS = 48
WINDOW_SECONDS = WINDOW_HOURS * 3600

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

ALERT_LABEL = "ops-alert"
MARKER_PREFIX = "model-health-alert"   # hidden HTML marker keying the idempotent upsert


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
    limit class, where it is actionable."""
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
    if rec["exit_class"] == CLASS_LIMIT and reset_hint:
        rec["reset_hint"] = str(reset_hint)
    return rec


def prune(records, now):
    """Keep the rolling window: drop records older than WINDOW_SECONDS, then cap to the most recent
    MAX_RECORDS. Sorted by ts so the window/consecutive logic below is well defined."""
    kept = [r for r in records if isinstance(r, dict)
            and isinstance(r.get("ts"), int)
            and (now - r["ts"]) <= WINDOW_SECONDS]
    kept.sort(key=lambda r: r["ts"])
    return kept[-MAX_RECORDS:]


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


def classify_records(records, provider_accounts, now):
    """The PURE decision core. Given the pruned record window and `provider_accounts`
    ({provider: set-of-enabled-salted-hashes}, the enabled fleet per provider), return a list of
    ACTIONS. Each action = {condition, provider, fire (bool), reason, reset_hint?}. `fire=True`
    means raise/refresh the alert; `fire=False` means recover/close an existing one. RECOVERY is a
    first success after failures within the window.

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
        actions.append({
            "condition": "persistent-transient",
            "provider": provider,
            "fire": bool(persistent) and not recovered,
            "reason": (f"{len(transient_recent)} transient API failures in "
                       f"{TRANSIENT_WINDOW_SECONDS // 60} min (persistent, not a blip)"
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

    return actions


def _marker(condition, provider):
    return f"<!-- {MARKER_PREFIX}:{condition}:{provider} -->"


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
        lines.append(f"⚠️ **Provider `{action['provider']}` is throwing sustained transient errors.** "
                     f"{action['reason']}. These are individually retryable (429/529/overloaded) "
                     "but the burst is degrading throughput.")
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
    lines.append(f"\n@{maintainer} — this issue updates itself and closes automatically on the "
                 "first successful model launch for this provider.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------------
# CAS ledger I/O over the GitHub contents API (mirrors groom.py _read_ledger/_release_claims)
# ---------------------------------------------------------------------------------------------
class HealthError(RuntimeError):
    """A concise, credential-free operational error."""


class HealthConflict(HealthError):
    """A retryable contents-API compare-and-swap conflict."""


def read_ledger(api, registry_repo):
    """Return (records, sha). A MISSING ledger file (first ever record) is not an error — it seeds
    an empty window with sha=None so the first PUT creates it."""
    result = api.request("GET", f"/repos/{registry_repo}/contents/{LEDGER_PATH}", allow_404=True)
    if result is None:
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
                "content": encoded}
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


def _gh(args, token, capture=False):
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    return subprocess.run(["gh"] + args, capture_output=capture, text=True, env=env)


def _find_marker_issue(repo, token, marker, state):
    """The issue number carrying the hidden marker in `state`, or None. A failed/garbled gh list is
    None (callers treat 'not found' conservatively — never create over an unreadable tracker)."""
    proc = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", state,
                "--json", "number,body", "--limit", "50"], token, capture=True)
    if proc.returncode != 0:
        return None
    try:
        found = json.loads(proc.stdout or "[]")
    except ValueError:
        return None
    return next((i["number"] for i in found if isinstance(i, dict)
                 and marker in (i.get("body") or "")), None)


def _upsert_alert(action, repo, token, maintainer):
    """Idempotent one-issue-per-(condition,provider) upsert keyed by the hidden body marker.
    OPERATIONAL idempotency (review defect #7): every gh return code is checked; a flap REOPENS the
    closed marker issue instead of creating a duplicate; and the recovery comment is posted only
    AFTER a CONFIRMED close, so a failed close retries next tick without comment spam."""
    title = _alert_title(action["condition"], action["provider"])
    marker = _marker(action["condition"], action["provider"])
    body = render_body(action, maintainer)
    # best-effort, idempotent (exists -> nonzero is fine)
    _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", "d73a4a",
         "--description", "Autonomous model-access health alert (maintainer action)"],
        token, capture=True)
    num = _find_marker_issue(repo, token, marker, "open")
    if action["fire"]:
        if num is not None:
            if _gh(["issue", "edit", str(num), "-R", repo, "--body", body], token).returncode == 0:
                print(f"::warning::model-health: refreshed {action['condition']} alert "
                      "(detail in the issue)")
            else:
                print(f"::warning::model-health: refresh of {action['condition']} alert FAILED "
                      "(will retry next tick)")
            return
        # Flap: reuse (REOPEN) the closed marker issue rather than minting a new one.
        closed = _find_marker_issue(repo, token, marker, "closed")
        if closed is not None:
            if _gh(["issue", "reopen", str(closed), "-R", repo], token).returncode == 0:
                _gh(["issue", "edit", str(closed), "-R", repo, "--body", body], token)
                print(f"::warning::model-health: reopened {action['condition']} alert "
                      "(detail in the issue)")
            else:
                print(f"::warning::model-health: reopen of {action['condition']} alert FAILED "
                      "(will retry next tick)")
            return
        if _gh(["issue", "create", "-R", repo, "--title", title,
                "--label", ALERT_LABEL, "--body", body], token).returncode == 0:
            print(f"::warning::model-health: raised {action['condition']} alert "
                  "(detail in the issue)")
        else:
            print(f"::warning::model-health: raising {action['condition']} alert FAILED "
                  "(will retry next tick)")
    elif num is not None:
        # Close FIRST; comment only on a CONFIRMED state change so a failed close cannot
        # re-comment every tick.
        if _gh(["issue", "close", str(num), "-R", repo], token).returncode == 0:
            _gh(["issue", "comment", str(num), "-R", repo, "--body",
                 "✅ Recovered — successful model access is back. Auto-closed."], token)
            print(f"model-health: recovered {action['condition']} — alert closed")
        else:
            print(f"::warning::model-health: close of {action['condition']} alert FAILED "
                  "(will retry next tick without commenting)")


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
        print(f"::warning::model-health decide: cannot read ledger ({exc}); no action")
        return 0
    provider_accounts = _enabled_provider_accounts(
        api, registry_repo, args.policy_file, salt)
    actions = classify_records(records, provider_accounts, now)
    repo, token = _alert_target()
    for action in actions:
        # Only touch the tracker when there is something to do (fire) or an OPEN alert to recover;
        # a steady no-alert condition stays silent (no issue churn).
        _upsert_alert(action, repo, token, maintainer)
    fired = [a["condition"] for a in actions if a["fire"]]
    print(f"model-health decide: {len(actions)} conditions checked, "
          f"{len(fired)} firing ({','.join(sorted(set(fired))) or 'none'})")
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

    # ---- prune / window bound ---------------------------------------------------------------
    many = [rec("anthropic", "acct01", CLASS_TRANSIENT, dt=i) for i in range(MAX_RECORDS + 50)]
    chk("prune caps to MAX_RECORDS", len(prune(many, now + MAX_RECORDS + 100)), MAX_RECORDS)
    old_new = [rec("anthropic", "a", CLASS_AUTH, dt=-(WINDOW_SECONDS + 10)),
               rec("anthropic", "a", CLASS_AUTH, dt=0)]
    chk("prune drops out-of-window", len(prune(old_new, now)), 1)

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

    # ---- record exits NONZERO on CAS exhaustion (defect #8) ----------------------------------
    ok = _test_record_exit(chk) and ok

    # ---- #39 routing fallback ---------------------------------------------------------------
    ok = _test_routing(chk) and ok

    # ---- provider fleet resolution (account catalog -> salted provider map) ------------------
    chk("provider parsed from YAML body",
        _provider_of("harness: claude\nprovider: anthropic\nmodels: [fable]"), "anthropic")
    chk("provider absent -> empty", _provider_of("models: [x]"), "")
    ok = _test_fleet(chk) and ok

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
    on the first PUT (a 409) so the retry loop is exercised."""

    def __init__(self, seed=None, conflict_first=False):
        self._blob = None if seed is None else base64.b64encode(
            json.dumps({"records": seed}).encode()).decode()
        self._sha = None if seed is None else "sha0"
        self._n = 0
        self._conflict_first = conflict_first

    def request(self, method, path, body=None, allow_404=False, retry_conflict=False):
        if method == "GET":
            if self._blob is None:
                if allow_404:
                    return None
                raise HealthError("missing")
            return {"content": self._blob, "sha": self._sha}
        # PUT
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
    return True


def _test_upsert(chk):
    """_upsert_alert operational idempotency (review defect #7), against a scripted fake gh:
    flap REOPENS the closed marker issue (never a duplicate create); a FAILED close posts no
    recovery comment (no next-tick spam); a confirmed close posts exactly the recovery comment."""
    import types
    global _gh
    real_gh, calls = _gh, []

    def fake_gh(open_issues, closed_issues, fail_verbs):
        def run(args, token, capture=False):
            calls.append(list(args))
            if args[:2] == ["issue", "list"]:
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
        _upsert_alert(action, "o/r", "t", "m")
        chk("upsert reopens the closed marker issue on flap", "reopen" in issue_verbs(), True)
        chk("upsert does not create a duplicate on flap", "create" in issue_verbs(), False)
        # fresh alert (no open, no closed) -> create
        _gh, calls[:] = fake_gh([], [], set()), []
        _upsert_alert(action, "o/r", "t", "m")
        chk("fresh alert creates the issue", "create" in issue_verbs(), True)
        # FAILED close -> NO recovery comment (retries next tick)
        _gh, calls[:] = fake_gh([{"number": 8, "body": marker}], [], {"close"}), []
        _upsert_alert({**action, "fire": False}, "o/r", "t", "m")
        chk("failed close posts no recovery comment", "comment" in issue_verbs(), False)
        # confirmed close -> recovery comment
        _gh, calls[:] = fake_gh([{"number": 8, "body": marker}], [], set()), []
        _upsert_alert({**action, "fire": False}, "o/r", "t", "m")
        chk("confirmed close posts the recovery comment", "comment" in issue_verbs(), True)
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


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main(sys.argv[1:]))
