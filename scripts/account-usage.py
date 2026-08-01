#!/usr/bin/env python3
# [OPUS-4.8] Probe live per-account usage for usage-aware dispatch. Emits a JSON map
#   {handle: {"status","5h_util","5h_reset","7d_util","7d_reset", (fable fields), (opus5 fields)}}
#     for anthropic accounts
#   {handle: {"exempt": true, ("backoff_until": epoch...)}}  for PROBE-EXEMPT providers (openai/codex)
#
# PROBE EXEMPTION + REACTIVE BACKOFF (maintainer decision 2026-07-17, registry issue #29): openai
# usage is not observable via any API, so those accounts are exempt from probing and admitted
# WITHOUT usage data. They are governed reactively instead: the model-health ledger already records
# a host-derived rate-limit exit class per salted account, and this script stamps the DERIVED
# `backoff_until` onto the exempt entry so usage_eligible excludes the account until it expires.
# The overlay FAILS OPEN with a loud log line (an unreadable ledger/missing salt only disables the
# backoff optimization — the exemption must never reintroduce fail-closed starvation).
# to stdout. Each anthropic token is probed with a max_tokens:1 POST /v1/messages and the
# anthropic-ratelimit-unified-* response headers are read. Tokens come from SECRETS_JSON (toJSON(secrets))
# by each account's secret_ref and are NEVER printed. FAIL-CLOSED: an account whose token is missing or
# whose probe returns no rate-limit headers is OMITTED from the map, so choose_account() will skip it.
#
# [FABLE-5] FABLE SUB-QUOTA: an Anthropic account has a SEPARATE weekly premium sub-quota for
# claude-fable-5, surfaced as the `anthropic-ratelimit-unified-7d_oi-*` headers. It is DISTINCT from the
# whole-account 5h/7d windows — an account can read 7d_util=0.1 yet have an exhausted Fable bucket, so a
# Fable worker started there fails mid-run and burns credits. Empirically (probing acct2/3/4 + the box's
# own session), the 7d_oi headers appear ONLY when the request carries BOTH the Claude-Code user-agent AND
# the "You are Claude Code" system prompt (a subscription-OAuth premium-path gate) AND the model is
# claude-fable-5 — a plain haiku/opus probe never surfaces them. So fable-capable accounts get a SECOND,
# Claude-Code-shaped fable probe whose 7d_oi headroom gates fable-model routing specifically. If that probe
# is rejected or returns no 7d_oi headers, the account is fail-closed for FABLE only (its 5h/7d base signal
# from the haiku probe still governs non-fable routing).
import contextlib
import importlib.util
import io
import json
import os
import re
import shlex
import subprocess
import sys

# The subscription-OAuth premium path (claude-fable-5) is gated to Claude-Code-shaped requests; without
# this exact pair the API returns 429 for fable and never emits the 7d_oi sub-quota headers.
_CLAUDE_CODE_UA = "claude-cli/2.1.177 (external, cli)"
_CLAUDE_CODE_SYSTEM = "You are Claude Code, Anthropic's official CLI for Claude."

# Secret-exfil hardening (audit-2026-07-17): a secret_ref is DEREFERENCED from the secrets map, so a
# poisoned account issue could otherwise name ANY workflow secret (e.g. REGISTRY_ADMIN_APP_KEY) and
# route it into the probe. Only worker-account token names are ever dereferenced. Matches the real
# naming scheme `${handle^^}_TOKEN` (ACCT01_TOKEN, ACCT2CSS_TOKEN, ...).
SECRET_REF_RE = re.compile(r"ACCT[A-Z0-9]+_TOKEN")


def _parse_rate_headers(header_text):
    """Parse raw curl -D header output into the anthropic-ratelimit-unified-* map (lowercased keys,
    prefix stripped). Pure — unit-tested by --self-test."""
    hdr = {}
    for line in header_text.splitlines():
        low = line.lower()
        if low.startswith("anthropic-ratelimit-unified-") and ":" in line:
            key, _, val = line.partition(":")
            hdr[key.strip().lower()[len("anthropic-ratelimit-unified-"):]] = val.strip()
    return hdr


def _probe_curl_command(token, model, claude_code=False):
    """Build the (argv, stdin) pair for one probe. The bearer token is fed through curl's STDIN
    header stream (`-H @-`), NEVER placed in argv (issue #195) — so the credential cannot leak via
    process inspection (`ps`/`/proc/<pid>/cmdline`) or diagnostic command capture. Only non-secret
    headers appear on the command line. Pure — unit-tested by --self-test."""
    body = {"model": model, "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]}
    args = ["curl", "-s", "-D", "-", "-o", "/dev/null", "--max-time", "20", "-X", "POST",
            "https://api.anthropic.com/v1/messages",
            "-H", "@-",  # read the (secret-bearing) Authorization header from stdin, not argv
            "-H", "anthropic-version: 2023-06-01",
            "-H", "content-type: application/json",
            "-H", "anthropic-beta: oauth-2025-04-20"]
    if claude_code:
        body["system"] = [{"type": "text", "text": _CLAUDE_CODE_SYSTEM}]
        args += ["-H", "user-agent: " + _CLAUDE_CODE_UA]
    args += ["-d", json.dumps(body)]
    return args, "Authorization: Bearer " + token + "\n"


def _probe_headers(token, model, claude_code=False):
    """POST a max_tokens:1 message and return the parsed anthropic-ratelimit-unified-* header map
    (lowercased keys, 'anthropic-ratelimit-unified-' prefix stripped), or None on any transport error.
    An empty dict means the request completed but carried no rate-limit headers (e.g. 401/429-block)."""
    # [FABLE-5] Strip the credential: a stored secret can carry a trailing newline (e.g. `gh secret set`
    # from a file), which would otherwise land in the Authorization header and 400 the probe -> the healthy
    # account is silently omitted. Fail-closed either way, but the strip avoids dropping usable accounts.
    token = (token or "").strip()
    if not token:
        return None
    args, stdin = _probe_curl_command(token, model, claude_code)
    try:
        proc = subprocess.run(args, input=stdin, capture_output=True, text=True,
                              timeout=30, check=False)
    except (subprocess.SubprocessError, OSError):
        return None
    return _parse_rate_headers(proc.stdout)


def _assemble_usage(hdr):
    """Build the per-account usage entry from a parsed header map. Includes the raw *-limit header
    values when the provider exposes them (capacity-model measurement: the per-account tier limits
    were 'TBD' — persisting the live limits stops admission flying blind). Pure — unit-tested."""
    entry = {"status": hdr.get("status"),
             "5h_util": hdr.get("5h-utilization"), "5h_reset": hdr.get("5h-reset"),
             "7d_util": hdr.get("7d-utilization"), "7d_reset": hdr.get("7d-reset")}
    for key, source in (("5h_limit", "5h-limit"), ("7d_limit", "7d-limit")):
        if hdr.get(source) is not None:
            entry[key] = hdr.get(source)
    return entry


def _probe_anthropic(token):
    """Whole-account 5h/7d usage via a cheap, ungated haiku probe. None -> fail-closed omit.
    A well-SHAPED entry is required: a base window that drifts to `nan`/`-1`/'' (or an empty
    status) is OMITTED here (issue #196) instead of being emitted to fail open as eligible
    capacity downstream — see _valid_base_usage."""
    hdr = _probe_headers(token, "claude-haiku-4-5")
    if hdr is None or hdr.get("status") is None:
        return None  # transport error or no rate-limit headers (e.g. 401/blocked) -> fail-closed omit
    entry = _assemble_usage(hdr)
    if not _valid_base_usage(entry):
        return None  # malformed status / base-utilization shape (issue #196) -> fail-closed omit
    return entry


def _valid_utilization(val):
    """True iff `val` is a header string that parses to a utilization fraction in [0.0, 1.0].
    A provider-side shape change that leaves the header present but with a non-numeric or
    out-of-range value (e.g. 'unknown', '', '95%', '1.5') is REJECTED here so it fail-closes
    rather than parsing to garbage. Pure — unit-tested by --self-test."""
    if not isinstance(val, str) or not val.strip():
        return False
    try:
        num = float(val.strip())
    except (TypeError, ValueError):
        return False
    return 0.0 <= num <= 1.0


def _valid_base_usage(entry):
    """True iff the whole-account base entry is well-SHAPED enough to gate dispatch (issue #196).
    The strict [0,1] utilization validator above was used ONLY for the Fable sub-quota, so a
    provider shape drift that left a BASE 5h/7d window as `nan`, `-1`, `1.5`, `''` — or an empty
    status — was emitted UNCHANGED and failed open downstream: a NaN compares false in every
    direction (so the `(1 - util) < margin` headroom test never fires) and a negative utilization
    looks like excess headroom, so choose_account admitted the account as eligible capacity.
    Require a NON-EMPTY status and BOTH base windows to be finite fractions in [0,1]; a caller
    OMITS the account (fail-closed) on any mismatch. A well-formed NON-`allowed` status (e.g.
    `throttled`) is a valid provider state, NOT a shape mismatch — it is kept so usage-alert can
    report it precisely, and the eligibility gate (select-and-claim.usage_eligible) is what
    requires status exactly `allowed`. Pure — unit-tested by --self-test."""
    if not isinstance(entry, dict):
        return False
    if not str(entry.get("status") or "").strip():
        return False  # empty/missing status is a shape mismatch (an empty status once read as allowed)
    return _valid_utilization(entry.get("5h_util")) and _valid_utilization(entry.get("7d_util"))


def _assemble_fable(hdr):
    """[FABLE-5] Classify a parsed fable-probe header map into the fable sub-quota entry, or None
    (UNAVAILABLE / fail-closed) on any parse mismatch. The account is admitted for FABLE only when the
    7d_oi utilization header is present AND parses to a valid [0,1] fraction — a version-pinned request
    shape that the provider later changes can otherwise leave a header present with a garbage value that
    would classify a capped/dead account as eligible (issue #30). None means: rejected/gated/absent OR
    a shape drift the probe no longer understands -> the caller fail-closes FABLE routing. Pure —
    unit-tested by --self-test."""
    if hdr is None:
        return None
    util = hdr.get("7d_oi-utilization")
    if not _valid_utilization(util):
        return None  # absent, or present-but-unparseable (provider shape drift) -> UNAVAILABLE
    result = {"fable_ok": True,
              "fable_7d_oi_util": util,
              "fable_7d_oi_reset": hdr.get("7d_oi-reset")}
    if hdr.get("7d_oi-limit") is not None:
        result["fable_7d_oi_limit"] = hdr.get("7d_oi-limit")
    return result


def _probe_fable(token):
    """[FABLE-5] Probe the FABLE weekly sub-quota (anthropic-ratelimit-unified-7d_oi-*) with the
    Claude-Code request shape. Returns {"fable_ok": True, "fable_7d_oi_util","fable_7d_oi_reset"} when the
    account currently serves fable AND exposes a well-formed sub-quota window; None otherwise
    (rejected/gated/no or unparseable 7d_oi header) so the caller fail-closes FABLE routing for the
    account. Absence of the extra probe (or a None result) never blocks non-fable routing, which the base
    5h/7d signal governs on its own. Classification is delegated to the pure `_assemble_fable` so shape
    drift is caught by the self-test."""
    hdr = _probe_headers(token, "claude-fable-5", claude_code=True)
    return _assemble_fable(hdr)


# --- [#720] OPUS5 PREMIUM-BUCKET OBSERVATION ------------------------------------------------------
# opus5 (claude-opus-5) became the SOLE anthropic tier at the 2026-07-26 deprecation, and it was
# never wired to a premium sub-quota because its rate-limit mapping was UNOBSERVED — so the
# whole-account 5h/7d gate is the only thing admitting an opus5 worker. That is genuine protection
# ONLY IF Anthropic publishes no separate bucket for claude-opus-5; if one exists, workers are
# admitted on healthy whole-account headroom while the opus5 bucket is exhausted and they fail
# MID-RUN, burning credits and a lease per attempt. Blocking on an unobserved mapping is blocking on
# absence of evidence, so the shape is: OBSERVE HERE, then gate in select-and-claim's
# `_opus5_eligible` off what was observed — one change, no window in which we know but do not act.
#
# THE DISCRIMINATOR IS STRUCTURAL, NOT A GUESSED NAME. `5h` and `7d` are the whole-account windows.
# ANY OTHER `<window>-utilization` header this probe returns is by construction a sub-quota that
# gate cannot see — that is exactly what `7d_oi` is for fable. So a bucket Anthropic ships under a
# name nobody here predicted still arms the gate the moment it appears in a real response.
OPUS5_PROVIDER_MODEL = "claude-opus-5"  # parity with orchestration/routing.toml [models.opus5]
BASE_WINDOWS = frozenset({"5h", "7d"})
_UTILIZATION_SUFFIX = "-utilization"


def _premium_window(hdr):
    """(window, raw utilization header) for the NON-base rate-limit window a premium gate must key
    on, or None when the parsed header map declares none. Pure — unit-tested by --self-test.

    A provider may publish more than one. Admission must key on the one with the LEAST headroom, and
    an UNREADABLE window OUTRANKS every readable one: an unparseable premium window is precisely the
    state select-and-claim must refuse on, so it must never be hidden behind a healthy sibling.
    Ties break on the window name so the choice is deterministic."""
    if not isinstance(hdr, dict):
        return None
    windows = []
    for key in sorted(hdr):
        if not key.endswith(_UTILIZATION_SUFFIX):
            continue
        window = key[:-len(_UTILIZATION_SUFFIX)]
        if window and window not in BASE_WINDOWS:
            windows.append((window, hdr[key]))
    if not windows:
        return None
    unreadable = [pair for pair in windows if not _valid_utilization(pair[1])]
    if unreadable:
        return unreadable[0]
    return max(windows, key=lambda pair: float(pair[1].strip()))


def _assemble_opus5(hdr):
    """[#720] The claude-opus-5 OBSERVATION RECORD for one account, from a parsed header map. Pure —
    unit-tested by --self-test. Always a dict, so the snapshot always says what was seen:

        opus5_probe    "observed" | "no-headers" | "error"  — did the probe get an answer at all
        opus5_headers  the FULL parsed rate-limit header map (only when the probe answered)
        opus5_premium_window / _util / _reset / _limit  — ONLY when a non-base window appeared

    The window key is the ARMING SIGNAL that select-and-claim._opus5_eligible reads: absent means
    "no distinct bucket was seen", present means "gate on this window, and refuse if it is
    unreadable". A probe that could not answer at all records `error` and declares NO window — it
    must not fail closed, because opus5 is the fleet's only anthropic tier and a probe blip would
    then park every single-rung chain onto a human's desk, which is the outcome #703 names."""
    if hdr is None:
        return {"opus5_probe": "error"}
    entry = {"opus5_probe": "observed" if hdr else "no-headers", "opus5_headers": dict(hdr)}
    selected = _premium_window(hdr)
    if selected is not None:
        window, util = selected
        entry["opus5_premium_window"] = window
        entry["opus5_premium_util"] = util
        for field, suffix in (("opus5_premium_reset", "-reset"),
                              ("opus5_premium_limit", "-limit")):
            value = hdr.get(window + suffix)
            if value is not None:
                entry[field] = value
    return entry


def _probe_opus5(token):
    """[#720] Observe claude-opus-5's rate-limit headers with the SAME request shape the worker uses.

    `claude_code=True` is not decoration: every opus5 worker runs through the Claude Code CLI, and
    the fable measurement showed the premium sub-quota headers surface only on that subscription-
    OAuth path. Probing any other shape would answer a question about a request nobody makes."""
    return _assemble_opus5(_probe_headers(token, OPUS5_PROVIDER_MODEL, claude_code=True))


def _load_account_catalog(script_dir):
    spec = importlib.util.spec_from_file_location(
        "registry_select_and_claim", os.path.join(script_dir, "select-and-claim.py"))
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load shared account catalog")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_accounts(script_dir, registry_repo):
    return _load_account_catalog(script_dir).read_accounts(registry_repo)


def _load_sibling(script_dir, filename, module_name):
    """Load a hyphen-named sibling script as a module (the _load_model_health pattern). Used by
    --self-test for CROSS-SCRIPT parity and wiring assertions — the reachability vocabulary, the probe
    sidecar contract, and dashboard-gen's workflow-step extraction primitives are shared rather than
    re-implemented here, where they would drift (registry #639)."""
    spec = importlib.util.spec_from_file_location(module_name, os.path.join(script_dir, filename))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_model_health(script_dir):
    spec = importlib.util.spec_from_file_location(
        "registry_model_health", os.path.join(script_dir, "model-health.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_health_state(mh, now, api=None):
    """ONE ledger read -> ONE pruned window -> BOTH derivations the exempt lane needs:

        {"backoffs": {hash: backoff}, "credentials": {hash: {"state", ...}}}

    Split out for registry #639 so the reachability question (credential_states) does not have to
    re-read the ledger and does not enter `_load_backoffs`' scope, which stays exactly what it was
    documented to be — rate-limit/cooldown BACKOFFS only. Same FAIL-OPEN contract, for any failure
    class, with the same single loud line: both derivations come back empty, which for the backoff
    means "no backoff" (as before) and for reachability means `unproven` (no decisive record), never
    a fabricated `live`."""
    try:
        path = os.environ.get("MODEL_HEALTH_FILE")
        if path:
            with open(path, encoding="utf-8") as handle:
                records = mh.validate_ledger(json.load(handle))
        else:
            if api is None:
                api = mh.GitHubAPI(os.environ.get("GH_TOKEN")
                                   or os.environ.get("GITHUB_TOKEN", ""))
            records, _sha = mh.read_ledger(api, os.environ["REGISTRY_REPO"])
        window = mh.prune(records, now)
        return {"backoffs": mh.account_backoffs(window, now),
                "credentials": mh.credential_states(window, now)}
    except Exception:
        # Broad by design: the fail-open contract above must hold no matter what the ledger
        # read raises (mh.HealthError, OSError, ValueError, KeyError, ...).
        print("::warning::account-usage: model-health ledger unreadable — exempt accounts admitted "
              "WITHOUT rate-limit backoff this tick (fail-open; fix the ledger to restore backoff)",
              file=sys.stderr)
        return {"backoffs": {}, "credentials": {}}


def _load_backoffs(mh, now, api=None):
    """{salted_account_hash: backoff} via the already-loaded model-health module `mh`. The ledger
    lives on the LEDGER branch (the mutable data plane), NOT in this job's checkout: the CLAIM job
    checks out the DEFAULT ref, whose data/model-health.json is the empty master seed, so a
    checkout-relative read validated cleanly, warned about nothing, and made the reactive backoff
    silently inert (cross-provider review r3 finding 2). The read therefore goes through
    model-health's contents API pinned to ?ref=ledger (mh.read_ledger) under the ambient
    GH_TOKEN; MODEL_HEALTH_FILE remains as an explicit file override (self-test / a caller that
    already holds a ledger-branch checkout), and `api` is injectable for the self-test. FAIL-OPEN
    by design, for ANY failure class (unreadable file, API/transport error, missing ledger
    branch, missing token/env): return {} after a LOUD log line — a lost backoff ledger merely
    admits a possibly rate-limited openai account (one wasted run), while failing closed here
    would starve the whole exempt provider, the exact regression the exemption removes.

    SCOPE IS UNCHANGED by registry #639: this still returns ONLY backoff records (rate-limit chain +
    the #596 auth cooldown that already rides the same primitive). It is now a thin projection of
    `_load_health_state` so the reachability derivation costs no second ledger read; nothing about
    what a backoff means, or its fail-open direction, moves."""
    return _load_health_state(mh, now, api=api)["backoffs"]


# The exempt PROVIDER allowlist (cross-provider review r1): the maintainer decision names openai;
# binding the exemption to an explicit allowlist (vs "any non-anthropic string") keeps a missing,
# misspelled, or unknown provider on the fail-closed probe path (it will surface as UNAVAILABLE in
# usage-alert — loud), so a catalog typo can never silently exempt an account from usage gating.
EXEMPT_PROVIDERS = frozenset({"openai"})


def _is_exempt_provider(provider):
    """True only for the explicitly probe-exempt providers (pure; whitespace/case tolerant)."""
    return str(provider or "").strip().lower() in EXEMPT_PROVIDERS


# The reachability an exempt entry carries when nothing decisive is known (registry #639): no salt, an
# unreadable ledger, or a fleet with no run outcomes in the window. It is the value this script must
# be able to emit WITHOUT the model-health module loaded, hence a local literal; --self-test asserts
# it equals model-health.CREDENTIAL_UNPROVEN and select-and-claim.USAGE_REACHABILITY_UNPROVEN, so the
# three spellings cannot drift.
REACHABILITY_UNPROVEN = "unproven"


def _probe_account(account, secrets, probe=None, fable_probe=None, opus5_probe=None):
    """Probed usage entry for ONE non-exempt account, or None (fail-closed omit). The provider
    MUST normalize to `anthropic` BEFORE the secret is even dereferenced (cross-provider review
    r3 finding 3): the probe below is addressed to the Anthropic API, so a missing, misspelled,
    or unknown provider (e.g. `openia`) previously TRANSMITTED that account's token to a provider
    the catalog never named — and admitted the account on the response. Unknown providers now
    never reach a probe; the omitted entry surfaces as UNAVAILABLE in usage-alert (loud), like
    every other fail-closed omit. `probe`/`fable_probe` are injectable for the self-test ONLY."""
    if str(account.get("provider") or "").strip().lower() != "anthropic":
        return None
    ref = account.get("secret_ref")
    if not isinstance(ref, str) or SECRET_REF_RE.fullmatch(ref) is None:
        return None  # fail-closed omit: never dereference a non-worker-token secret name
    # Bind the secret to THIS handle (issue #197): the ACCT*_TOKEN allow-list above accepts ANY
    # worker token, so a poisoned or typo'd catalog row for one handle could name a DIFFERENT
    # account's credential (e.g. handle acct01 -> secret_ref ACCT02_TOKEN). The probe would then
    # bill acct02's token to acct01 — corrupting selection + tier-limit persistence, and later
    # failing the worker's own account check into repeated dead leases. The real broker
    # (set-up-account.yml) mints secret_ref = `${handle^^}_TOKEN` verbatim, so require exactly that;
    # any mismatch fail-closed OMITS (surfaces as UNAVAILABLE in usage-alert, like every other omit).
    handle = account.get("handle")
    if not isinstance(handle, str) or ref != f"{handle.upper()}_TOKEN":
        return None  # fail-closed omit: secret_ref must be this handle's OWN token
    token = secrets.get(ref)
    if not token:
        return None  # fail-closed omit
    probed = (probe or _probe_anthropic)(token)
    if probed is None:
        return None
    # [FABLE-5] Only fable-capable accounts need the extra Claude-Code-shaped fable probe. A missing
    # or failed fable probe leaves the fable sub-quota fields absent -> usage_eligible fail-closes FABLE
    # routing for this account, while its base 5h/7d signal still admits it for non-fable models.
    if "fable" in account.get("models", []):
        fable = (fable_probe or _probe_fable)(token)
        if fable is not None:
            probed.update(fable)
    # [#720] opus5 is the sole anthropic tier, so every opus5-capable account is OBSERVED: record
    # whatever rate-limit headers claude-opus-5 actually returns. The observation carries its own
    # verdict (`opus5_probe`) and arms select-and-claim's premium gate only when it saw a window the
    # whole-account pair does not cover — so this answers the question with data instead of argument
    # and enforces the answer in the same tick.
    if "opus5" in account.get("models", []):
        probed.update((opus5_probe or _probe_opus5)(token))
    return probed


def _apply_backoff(entry, backoff):
    """Annotate one exempt usage entry with an ACTIVE backoff record (pure). Tolerant fail-open:
    a malformed/forged record (non-dict, non-numeric/non-finite backoff_until) leaves the entry
    untouched — never crashes the sweep, never blocks the account.

    `backoff_signal` is the model-health class that produced the hold: `limit`/`transient` for the
    reactive rate-limit chain, and (registry #596) `auth` for the bounded CREDENTIAL COOLDOWN after
    AUTH_COOLDOWN_MIN consecutive auth failures. Both arrive in the same shape through the same
    account_backoffs read, so nothing here needs to distinguish them."""
    if not isinstance(backoff, dict):
        return entry
    try:
        until = int(float(backoff.get("backoff_until")))
    except (TypeError, ValueError, OverflowError):
        return entry               # nan/inf/garbage: fail open (int() rejects non-finite floats)
    entry["backoff_until"] = until
    if isinstance(backoff.get("consecutive"), int):
        entry["backoff_consecutive"] = backoff["consecutive"]
    if backoff.get("saturated") is True:
        # model-health prune may have truncated a saturated chain to its BACKOFF_CHAIN_KEEP tail,
        # so the consecutive count is a LOWER BOUND — usage-alert renders it "xN+", never an
        # exact "xN" (PR #85 finding 2). STRICT is-True: a forged truthy string stays dropped.
        entry["backoff_saturated"] = True
    if isinstance(backoff.get("last_signal"), str):
        entry["backoff_signal"] = backoff["last_signal"]
    return entry


def _load_secrets():
    """The ACCT_* token subset. SECRETS_FILE (a host-filtered file containing ONLY worker-account
    tokens) is preferred; SECRETS_JSON (toJSON(secrets)) remains as a fallback for older callers."""
    path = os.environ.get("SECRETS_FILE")
    if path:
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}
    try:
        data = json.loads(os.environ.get("SECRETS_JSON", "{}"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _usable_secret_refs(secrets):
    """The worker-token names in `secrets` whose value is a NON-EMPTY string, sorted.

    The same predicate the workflow's subset validator applies, in Python where it is unit-testable
    (registry #612 review round 4 measured that `grep -q '"ACCT'` proved neither valid JSON nor a
    non-empty token: `{"ACCT01_TOKEN":""}` and the truncated `{"ACCT01_TOKEN":` both passed it).
    `_load_secrets` already collapses an unreadable or unparseable subset to `{}`, so an empty return
    here covers malformed, empty, and token-less documents alike. Pure — unit-tested by
    --self-test."""
    if not isinstance(secrets, dict):
        return []
    return sorted(key for key, value in secrets.items()
                  if isinstance(key, str) and SECRET_REF_RE.fullmatch(key)
                  and isinstance(value, str) and value.strip())


# --- tier-limit persistence (capacity model, 2026-07-17 measurement) ------------------------------
# [#720] `opus5_premium_window` is not a limit, and it is here on purpose: this line is the only
# DURABLE per-account record this repo keeps of what a probe saw, and the whole point of #720 is
# that "does claude-opus-5 have its own bucket, and what is it called" must be answered by data
# that survives the tick. A per-account front-matter line does; a snapshot in $RUNNER_TEMP does not.
# select-and-claim._parse_account ignores unknown keys and dashboard-gen._front_matter keeps only
# the `<window>_limit` names it knows, so both extra tokens are inert for every existing consumer.
LIMIT_KEYS = ("5h_limit", "7d_limit", "fable_7d_oi_limit",
              "opus5_premium_window", "opus5_premium_limit")

# The two diagnostics this lane emits, as named constants. They are the strings the self-test's
# loudness rows assert against, and a message and its assertion that are two separate literals
# drift apart in the permissive direction exactly once and then stay there.
SCHEMA_REJECT_WARNING = "::warning::account-usage: account-record write rejected by schema guard"
WRITE_FAILURE_WARNING = (
    "::warning::account-usage: one or more tier-limit writes failed (gh error, or a concurrent "
    "catalog edit landed inside the write window — the prior revision is recoverable from the "
    "issue's edit history) — capacity model may be stale for those accounts")


def _limits_line(entry):
    """The single `limits:` front-matter line for an account issue, or None when the probe exposed
    no *-limit headers. Values are the raw header strings (no unit guessing)."""
    parts = [f"{key}={entry[key]}" for key in LIMIT_KEYS
             if isinstance(entry, dict) and entry.get(key)]
    return ("limits: " + " ".join(parts)) if parts else None


def _upsert_limits_line(body, line):
    """(new_body, changed): replace or append the one `limits:` line, idempotently (an identical
    line means changed=False, so re-probes do not churn issue bodies)."""
    lines = (body or "").splitlines()
    out, replaced, changed = [], False, False
    for existing in lines:
        if existing.strip().startswith("limits:") and not replaced:
            replaced = True
            if existing.strip() != line:
                out.append(line)
                changed = True
            else:
                out.append(existing)
        else:
            out.append(existing)
    if not replaced:
        out.append(line)
        changed = True
    return "\n".join(out), changed


PERSIST_ATTEMPTS = 3  # bounded re-merge attempts when a writer lands AFTER our edit (issue #198)

# One GraphQL read serves body + the body-edit count. userContentEdits counts BODY revisions only
# (title renames / labels / comments do not increment it), and every `gh issue edit --body` adds
# exactly one — so totalCount is the version stamp the guarded write below keys on.
_ISSUE_READ_QUERY = (
    "query($owner:String!,$name:String!,$number:Int!){"
    "repository(owner:$owner,name:$name){issue(number:$number){"
    "body userContentEdits(first:1){totalCount}}}}")


def _issue_view(number, registry_repo, run):
    """(body, edit_count, ok) for one issue read. edit_count is the issue's body-edit count
    (GraphQL userContentEdits.totalCount) — the version stamp for the write-window guard in
    _persist_one. ok=False on a non-zero gh returncode or an unparseable/ill-typed response so the
    caller PROPAGATES the failure rather than mistaking a failed read for an empty body (issue
    #198)."""
    owner, _, name = (registry_repo or "").partition("/")
    if not owner or not name:
        return "", 0, False
    proc = run(["gh", "api", "graphql", "-f", "query=" + _ISSUE_READ_QUERY,
                "-f", "owner=" + owner, "-f", "name=" + name, "-F", "number=" + str(number)],
               capture_output=True, text=True, timeout=60, check=False)
    if proc.returncode != 0:
        return "", 0, False
    try:
        doc = json.loads(proc.stdout or "null")
    except json.JSONDecodeError:
        return "", 0, False
    issue = doc.get("data") if isinstance(doc, dict) else None
    issue = issue.get("repository") if isinstance(issue, dict) else None
    issue = issue.get("issue") if isinstance(issue, dict) else None
    if not isinstance(issue, dict):
        return "", 0, False
    count = (issue.get("userContentEdits") or {}).get("totalCount")
    if not isinstance(count, int):
        return "", 0, False
    return issue.get("body") or "", count, True


def _persist_one(number, handle, line, registry_repo, run, schema_errors):
    """Merge the single `limits:` line into ONE account issue via a GUARDED read-merge-write (issue
    #198). `gh issue edit --body` REPLACES the whole body and GitHub's issue API has no conditional
    (If-Match/CAS) write, so a plain read->merge->write can clobber a provider / credential-format /
    secret-reference / notes edit landing inside the read->write window — and a body-only confirm
    cannot see that: it reads back exactly our merge and calls the loss success. The body-edit
    count is the version stamp that closes the hole: success is claimed ONLY when the confirm shows
    our merged body AND exactly ONE body edit (ours) happened since the fresh read. When the count
    proves a foreign edit landed inside the window (our write replaced it), FAIL LOUDLY instead of
    retrying — a retry would re-read our own body, find nothing to change and launder the loss into
    a false 'refreshed'; the replaced revision stays recoverable from the issue's edit history and
    the caller surfaces a red annotation. A foreign edit strictly AFTER ours (confirm body is
    theirs, exactly two edits) clobbered nothing, so the merge is re-applied onto their fresh body,
    bounded by PERSIST_ATTEMPTS. Automated writers cannot even reach the window — dispatch.yml
    self-serializes (`registry-dispatcher`, cancel-in-progress: false) and set-up-account only
    CREATES catalog issues (fail-closed on re-registration) — so this guard covers out-of-band
    manual edits, and its soundness does not depend on that workflow config. Returns True on
    success (incl. an idempotent no-op), False otherwise — the caller PROPAGATES it."""
    for _ in range(PERSIST_ATTEMPTS):
        body0, count0, ok = _issue_view(number, registry_repo, run)
        if not ok:
            return False
        new_body, changed = _upsert_limits_line(body0, line)
        if not changed:
            return True  # the live body already carries this exact limits line — nothing to write
        # WRITE GUARD (#521): validate the complete replacement body through the allocator's exact
        # schema before `gh issue edit --body` can persist it. This catches both a malformed live
        # record and any corruption introduced by this merge. Keep the annotation handle-free.
        if schema_errors(handle, new_body):
            print(SCHEMA_REJECT_WARNING)
            return False
        edit = run(["gh", "issue", "edit", str(number), "-R", registry_repo, "--body", new_body],
                   capture_output=True, text=True, timeout=60, check=False)
        if edit.returncode != 0:
            return False
        body2, count2, ok = _issue_view(number, registry_repo, run)
        if not ok:
            return False
        if count2 - count0 == 1:
            # ours was provably the ONLY edit in the read->write->confirm window; a body mismatch
            # here is an inconsistent read -> fail closed
            return body2 == new_body
        if count2 - count0 == 2 and body2 != new_body:
            # ours is not the live body, so the one foreign edit landed strictly AFTER ours:
            # nothing was lost -> re-merge the limits line onto the writer's fresh body
            continue
        # any other shape (our body live with >=2 edits, or >=3 edits) means a foreign edit may
        # have landed INSIDE our read->write window and been replaced by our write -> fail loudly
        return False
    return False


def persist_limits(usage_path, run=None):
    """Write probed tier limits into the account issues' front-matter (title == handle) so the
    capacity model stops flying blind. Best-effort but HONEST (issue #198): every gh failure is
    PROPAGATED as a non-zero return (the step is continue-on-error, so this surfaces the failure as a
    red annotation instead of a false 'refreshed'), and each per-issue write goes through _persist_one
    so a concurrent metadata edit is never silently overwritten (a clobber inside the write window is
    detected via the body-edit count and surfaced as failure, not confirmed as success). select-and-claim's _parse_account
    ignores unknown keys, so the extra line is inert for the allocator. Privacy: prints carry no
    handles or counts (locked decision 22b). `run` is injectable for the self-test ONLY."""
    run = run or subprocess.run
    registry_repo = os.environ["REGISTRY_REPO"]
    try:
        account_catalog = _load_account_catalog(os.path.dirname(os.path.abspath(__file__)))
    except Exception:
        print("::warning::account-usage: shared account schema unavailable; refusing tier-limit "
              "writes")
        return 1
    try:
        with open(usage_path, encoding="utf-8") as handle:
            usage = json.load(handle)
    except (OSError, json.JSONDecodeError):
        print("account-usage: no usage snapshot; tier-limit persistence skipped")
        return 0
    if not isinstance(usage, dict):
        print("account-usage: usage snapshot is not a map; tier-limit persistence skipped")
        return 0
    # [OPUS-5] Same page bound + same truncation posture as the catalog read this lane writes back
    # to (select-and-claim.ACCOUNT_CATALOG_LIST_LIMIT, registry #1131). The bound is IMPORTED, not
    # re-declared: two hand-maintained copies is exactly how one lane silently keeps reading a
    # truncated catalog after the other is fixed. Account issues are the OLDEST open issues, so a
    # filled page silently drops precisely the records this lane exists to update.
    catalog_limit = account_catalog.ACCOUNT_CATALOG_LIST_LIMIT
    listing = run(["gh", "issue", "list", "-R", registry_repo, "--state", "open",
                   "--limit", str(catalog_limit), "--json", "number,title"],
                  capture_output=True, text=True, timeout=60, check=False)
    if listing.returncode != 0:
        # PROPAGATE (issue #198): the old code swallowed a failed catalog read and still printed
        # 'refreshed'. A non-zero return makes the (continue-on-error) step surface the failure.
        print("::warning::account-usage: account catalog read failed; tier-limit persistence skipped")
        return 1
    try:
        issues = json.loads(listing.stdout or "[]")
    except json.JSONDecodeError:
        print("::warning::account-usage: account catalog read unparseable; tier-limit persistence "
              "skipped")
        return 1
    if isinstance(issues, list) and len(issues) >= catalog_limit:
        # A filled page cannot be proven complete; writing tier limits from a listing that may have
        # dropped the oldest (= the account) records would silently skip exactly those accounts.
        print("::warning::account-usage: account catalog listing filled its page bound and may be "
              "TRUNCATED; refusing tier-limit writes")
        return 1
    failures = 0
    for issue in issues:
        handle = str(issue.get("title", "")).strip()
        line = _limits_line(usage.get(handle))
        if not line:
            continue
        if not _persist_one(issue.get("number"), handle, line, registry_repo, run,
                            account_catalog.account_record_schema_errors):
            failures += 1
    if failures:
        # No count (locked decision 22b) — only that at least one write did not land.
        print(WRITE_FAILURE_WARNING)
        return 1
    print("account-usage: tier-limit lines refreshed")
    return 0


def main():
    import time
    script_dir = os.path.dirname(os.path.abspath(__file__))
    registry_repo = os.environ["REGISTRY_REPO"]
    secrets = _load_secrets()
    pool = json.loads(os.environ.get("ACCOUNT_POOL", "[]"))  # optional handle allow-list
    now = time.time()
    salt = os.environ.get("PROVENANCE_SALT", "")
    health = None      # lazily loaded on the first probe-exempt account
    mh = None          # the model-health module once loaded (None until then / on load failure)
    salt_warned = False
    usage = {}
    accounts = [account for account in _load_accounts(script_dir, registry_repo)
                if not pool or account.get("handle") in pool]

    # MATERIALIZATION PROOF GATE (registry #639). This MUST precede the loop, and specifically the
    # exempt branch below. Pre-fix, the exempt branch ran BEFORE `secrets` was ever touched, so a
    # failed/never-run ACCT_* materialization still produced a NON-EMPTY map (`{"acct01": {"exempt":
    # true}}`) — every wholesale-outage detector keys on emptiness (usage-alert's `probe_empty=not
    # usage`, dashboard-gen's no-measurement branch), so precisely WHEN measurement had not happened,
    # nothing fired and dispatch launched on an unmeasured fleet. An unusable subset must therefore
    # yield an EMPTY document and a nonzero exit, not a partial one.
    #
    # SCOPED like the workflow guard it backs up (#612 round 4's own recommendation): the proof is
    # required only when the fleet actually CONTAINS a token-needing account. An all-exempt catalog
    # legitimately needs no token, and refusing there would degrade a healthy steady state. Today the
    # catalog is anthropic-majority by construction, so this condition is always true in production;
    # it exists so the guard cannot become a false alarm if that ever changes.
    # [OPUS-5] EMPTY-CATALOG GATE (2026-07-29 fleet outage, registry #1131). This MUST precede the
    # materialization proof gate below, because that gate's population is `accounts` — over an EMPTY
    # catalog `any(...)` is False, the proof is VACUOUS, the loop emits nothing, and this script
    # exits 0 having "measured" a fleet of zero accounts. The workflow then records
    # `outcome=ok detail=probe-succeeded` next to an empty snapshot, usage-alert's sidecar check
    # reads MEASURED, and dispatch's `_load_usage` collapses `{}` to None -> every `require_usage`
    # repo holds fail-closed. That is a TOTAL fleet stall wearing a green probe.
    #
    # A registry with zero readable account records is never a legitimate steady state for this
    # probe: it is a catalog read that lost the fleet (truncated listing, parse boundary dropping
    # every record, wrong repo). Exit NONZERO so the outcome sidecar says the measurement did NOT
    # happen and usage-alert raises the wholesale banner WITH a cause. This does not change what
    # dispatch does — it already holds — it stops the hold from being indistinguishable from a
    # healthy tick. No counts, no handles (locked decision 22b).
    if not accounts:
        print("::error::account-usage: the account catalog read yielded NO account records — "
              "refusing to emit a usage snapshot (an empty catalog is an unread fleet, never a "
              "measured one with no capacity)", file=sys.stderr)
        json.dump({}, sys.stdout)
        return 1

    if any(not _is_exempt_provider(account.get("provider")) for account in accounts) \
            and not _usable_secret_refs(secrets):
        # No counts, no names (locked decision 22b) — the condition, not the fleet.
        print("::error::account-usage: the ACCT_* token subset carries no usable worker token — "
              "refusing to emit ANY usage entry (an unproven materialization must read as "
              "UNMEASURED, never as free capacity)", file=sys.stderr)
        json.dump({}, sys.stdout)
        return 1

    for account in accounts:
        handle = account["handle"]
        if _is_exempt_provider(account.get("provider")):
            # Probe-exempt provider (decision 2026-07-17, issue #29): needs no usage DATA, and is
            # reactively backed off via the model-health rate-limit records. No salt -> no hash
            # mapping -> loud fail-open (backoff disabled, exemption intact). Any provider NOT on
            # the explicit allowlist (incl. missing/misspelled) is fail-closed OMITTED by
            # _probe_account below — never probed — and surfaces as UNAVAILABLE in usage-alert.
            #
            # [#639] The entry CARRIES its reachability, because needing no token is not evidence of
            # being reachable. `live`/`dead`/`unproven` come from the health record
            # (model-health.credential_states) — the same window the backoff is derived from — and
            # select-and-claim.usage_eligible admits only the two non-dead values. Without a salt (or
            # with an unreadable ledger) there is no hash mapping, so the honest answer is `unproven`,
            # never `live`.
            entry = {"exempt": True, "reachability": REACHABILITY_UNPROVEN}
            if salt:
                if health is None:
                    # Guarded module load (cross-provider review r1): an import failure here must
                    # fail OPEN like an unreadable ledger — an uncaught exception would crash the
                    # probe, the shell would write '{}', and EVERY account (anthropic included)
                    # would fail closed: the exact starvation the exemption exists to prevent.
                    try:
                        mh = _load_model_health(script_dir)
                        health = _load_health_state(mh, now)
                    except Exception:
                        print("::warning::account-usage: model-health module unavailable — exempt "
                              "accounts admitted WITHOUT rate-limit backoff this tick (fail-open)",
                              file=sys.stderr)
                        mh, health = None, {"backoffs": {}, "credentials": {}}
                if mh is not None:
                    hashed = mh.account_hash(handle, salt)
                    entry["reachability"] = mh.credential_state(health["credentials"], hashed)
                    entry = _apply_backoff(entry, health["backoffs"].get(hashed))
            elif not salt_warned:
                # Once, not per account: a per-account repeat would leak the exempt-account COUNT
                # into the public log (locked decision 22b) and drown the signal.
                salt_warned = True
                print("::warning::account-usage: PROVENANCE_SALT missing — exempt accounts "
                      "admitted WITHOUT rate-limit backoff (fail-open)", file=sys.stderr)
            usage[handle] = entry
            continue
        probed = _probe_account(account, secrets)
        if probed is None:
            continue  # fail-closed omit: unknown provider / bad secret_ref / no token / failed probe
        usage[handle] = probed
    json.dump(usage, sys.stdout)
    return 0


# --- [OPUS-5] SELF-TEST ANNOTATION CONTAINMENT ----------------------------------------------------
# A `::warning::`/`::error::`/`::notice::` line on stdout or stderr is not a log line — it is a
# GitHub workflow COMMAND, and the runner turns it into an annotation on the job. dispatch.yml runs
# `account-usage.py --self-test` as a preflight INSIDE the live CLAIM job (dispatch.yml, the
# usage-probe step), so every fixture that drives a diagnostic on purpose publishes that diagnostic
# as a real annotation about the live fleet.
#
# THIS FILE ALREADY KNEW THE RULE and applied it per-site: `_load_backoffs_captured` captures the
# malformed-ledger fixtures' stderr precisely so "a self-test run never emits a real workflow
# annotation" (see the comment above it). The `persist_limits` fixtures below print to STDOUT and
# were never covered, so the rule held on one stream and not the other.
#
# MEASURED on the live estate, 2026-07-29: a CLAIM job carried 16 annotations, of which 8 came from
# this self-test — the single most frequent annotation on the job was the fixture-driven
# "capacity model may be stale for those accounts", emitted on every executed dispatch tick while
# the real `--persist-limits` step in the same job reported success. An operator (or an agent)
# reading the job cannot tell that annotation from a live capacity-model outage, and one such
# investigation was spent on it.
#
# The fix is NOT to silence the diagnostic: the live path still prints it, and the rows below now
# ASSERT its loudness. The fix is to stop the FIXTURE from reaching the workflow's annotation
# stream, and to make the containment an INVARIANT rather than a convention that the next writer
# has to remember — `_run_self_test_contained` proxies both real streams and `_self_test` reds if
# anything got through, so a future uncaptured fixture fails the gate instead of quietly rejoining
# the noise.
WORKFLOW_COMMAND_RE = re.compile(r"^::(?:error|warning|notice)::")


def workflow_commands(text):
    """PURE: the workflow-command LINES in a captured stream, in order. Line-anchored — a
    `::warning::` quoted mid-line is prose, not a command the runner would act on."""
    return [line for line in (text or "").splitlines() if WORKFLOW_COMMAND_RE.match(line)]


class _AnnotationEscapeRecorder:
    """Write-through text-stream proxy that RECORDS every workflow-command line reaching the real
    stream.

    Bytes are forwarded VERBATIM and the return value of the underlying `write` is preserved, so
    installing this changes nothing an operator sees — a genuine escape stays readable in the log
    (it is a real defect and hiding it would be the same mistake in the other direction). Only the
    recording is new. Line assembly is buffered because `print` writes the text and the newline as
    two separate calls, so a per-call match would never see a complete line.

    Unknown attributes delegate to the wrapped stream, so `flush`/`fileno`/`isatty` and a
    `subprocess(stdout=sys.stdout)` hand-off all behave exactly as before.
    """

    def __init__(self, stream, escaped):
        self._stream = stream
        self._escaped = escaped
        self._residue = ""

    def write(self, text):
        written = self._stream.write(text)
        self._residue += text
        while "\n" in self._residue:
            line, _, self._residue = self._residue.partition("\n")
            if WORKFLOW_COMMAND_RE.match(line):
                self._escaped.append(line)
        return written

    def __getattr__(self, name):
        return getattr(self.__dict__["_stream"], name)


def _run_self_test_contained():
    """Run the self-test with both real streams proxied, and hand the escape list to `_self_test`.

    `_self_test` REQUIRES the list (its containment row compares against `[]`, and the default
    `None` can never equal it), so deleting this wiring reds the suite at runtime instead of
    silently disarming the recorder — a source-level pin would be needed otherwise, because a
    detector that is never installed records nothing and reds nothing.

    The verdict itself is reported through `chk`'s ordinary vocabulary and the exit status, never
    as a `::error::` — a containment failure that manufactured an annotation of its own would be
    self-defeating.
    """
    escaped = []
    saved_out, saved_err = sys.stdout, sys.stderr
    sys.stdout = _AnnotationEscapeRecorder(saved_out, escaped)
    sys.stderr = _AnnotationEscapeRecorder(saved_err, escaped)
    try:
        status = _self_test(escaped=escaped)
    finally:
        sys.stdout, sys.stderr = saved_out, saved_err
    # Printed on the RESTORED stream, and carrying the status, so the verdict survives a proxy that
    # stops forwarding: that mutant destroys the display channel every other row reports through,
    # including its own, and would otherwise fail the suite with nothing on screen to read.
    print("account-usage self-test containment:",
          "clean" if not escaped else f"{len(escaped)} fixture annotation(s) ESCAPED",
          f"(status {status})")
    return status


def _self_test(escaped=None):
    ok = True

    def chk(n, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        # Continuation lines are INDENTED, losslessly. A row whose value carries a captured
        # diagnostic would otherwise put `::warning::` at column 0 of a continuation line and the
        # REPORT would emit the very annotation the fixture was captured to contain. (Found by the
        # containment row below, on its first run — which is the row doing its job.)
        print(f"  {'ok  ' if good else 'FAIL'} {n}: {got} (want {want})".replace("\n", "\n    "))

    # secret_ref allow-list: only worker-account token names are dereferenced (audit-2026-07-17)
    for ref, want in (("ACCT01_TOKEN", True), ("ACCT2CSS_TOKEN", True), ("ACCT99_TOKEN", True),
                      ("GITHUB_TOKEN", False), ("REGISTRY_ADMIN_APP_KEY", False),
                      ("acct01_token", False), ("ACCT01_TOKEN\n", False), ("ACCT_", False)):
        chk(f"secret_ref gate {ref!r}", SECRET_REF_RE.fullmatch(ref) is not None, want)
    # header parsing from raw curl -D output (case-insensitive names, values trimmed)
    hdr = _parse_rate_headers(
        "HTTP/2 200\r\n"
        "Anthropic-Ratelimit-Unified-Status: allowed\r\n"
        "anthropic-ratelimit-unified-5h-utilization: 0.42\r\n"
        "anthropic-ratelimit-unified-5h-limit:  1000000 \r\n"
        "anthropic-ratelimit-unified-7d-utilization: 0.1\r\n"
        "x-other: ignored\r\n")
    chk("header parse status", hdr.get("status"), "allowed")
    chk("header parse limit trimmed", hdr.get("5h-limit"), "1000000")
    chk("header parse ignores others", "x-other" in hdr, False)
    # credential never lands in argv (issue #195): the bearer token is fed through curl's stdin
    # (-H @-), so process inspection / diagnostic command capture see only non-secret headers.
    args, stdin = _probe_curl_command("sk-secret-tok", "claude-haiku-4-5")
    chk("probe: token absent from argv", any("sk-secret-tok" in a for a in args), False)
    chk("probe: token carried on stdin only", stdin, "Authorization: Bearer sk-secret-tok\n")
    chk("probe: argv reads the auth header from stdin", "@-" in args, True)
    chk("probe: no literal Authorization header in argv",
        any(a.lower().startswith("authorization:") for a in args), False)
    chk("probe: body still carries the model", any('"claude-haiku-4-5"' in a for a in args), True)
    #   the fable variant adds the Claude-Code UA but STILL keeps the token off argv
    fargs, fstdin = _probe_curl_command("sk-secret-tok", "claude-fable-5", claude_code=True)
    chk("fable probe: token still absent from argv",
        any("sk-secret-tok" in a for a in fargs), False)
    chk("fable probe: token on stdin", fstdin, "Authorization: Bearer sk-secret-tok\n")
    chk("fable probe: Claude-Code UA present in argv", any(_CLAUDE_CODE_UA in a for a in fargs), True)
    # usage assembly includes limits ONLY when the provider exposes them
    entry = _assemble_usage(hdr)
    chk("assemble includes exposed limit", entry.get("5h_limit"), "1000000")
    chk("assemble omits absent limit", "7d_limit" in entry, False)
    chk("assemble keeps util fields", entry.get("5h_util"), "0.42")
    # limits front-matter line + idempotent upsert
    chk("limits line", _limits_line({"5h_limit": "10", "7d_limit": "70"}),
        "limits: 5h_limit=10 7d_limit=70")
    chk("limits line absent", _limits_line({"5h_util": "0.1"}), None)
    body = "provider: anthropic\nmodels: [haiku]\n"
    body2, changed = _upsert_limits_line(body, "limits: 5h_limit=10")
    chk("upsert appends", (changed, body2.endswith("limits: 5h_limit=10")), (True, True))
    body3, changed2 = _upsert_limits_line(body2, "limits: 5h_limit=10")
    chk("upsert is idempotent", (changed2, body3), (False, body2))
    body4, changed3 = _upsert_limits_line(body2, "limits: 5h_limit=20")
    chk("upsert replaces on change", (changed3, "5h_limit=20" in body4, "5h_limit=10" in body4),
        (True, True, False))
    # [FABLE-5] fable sub-quota classification (issue #30): shape-drift is caught here, and a present-
    # but-unparseable window fail-closes to UNAVAILABLE (None) rather than parsing to garbage.
    #   utilization validator: numeric [0,1] strings only
    for val, want in (("0.0", True), ("0.42", True), ("1.0", True), (" 0.1 ", True),
                      ("1.5", False), ("-0.1", False), ("", False), ("unknown", False),
                      ("95%", False), (None, False), (0.42, False)):
        chk(f"valid utilization {val!r}", _valid_utilization(val), want)
    #   recorded good fable response: the exact Claude-Code-shaped 7d_oi header shape we pin to
    good_fable = _parse_rate_headers(
        "HTTP/2 200\r\n"
        "anthropic-ratelimit-unified-status: allowed\r\n"
        "anthropic-ratelimit-unified-7d_oi-utilization: 0.2\r\n"
        "anthropic-ratelimit-unified-7d_oi-reset: 1737072000\r\n"
        "anthropic-ratelimit-unified-7d_oi-limit: 500000\r\n")
    fable = _assemble_fable(good_fable)
    chk("fable good: fable_ok", (fable or {}).get("fable_ok"), True)
    chk("fable good: util", (fable or {}).get("fable_7d_oi_util"), "0.2")
    chk("fable good: reset", (fable or {}).get("fable_7d_oi_reset"), "1737072000")
    chk("fable good: limit", (fable or {}).get("fable_7d_oi_limit"), "500000")
    #   shape drift / mismatch -> UNAVAILABLE (fail-closed None), NOT a garbage fable_ok entry
    chk("fable absent window -> unavailable", _assemble_fable(_parse_rate_headers(
        "anthropic-ratelimit-unified-status: allowed\r\n")), None)
    chk("fable garbage value -> unavailable", _assemble_fable(_parse_rate_headers(
        "anthropic-ratelimit-unified-7d_oi-utilization: unavailable\r\n")), None)
    chk("fable out-of-range value -> unavailable", _assemble_fable(_parse_rate_headers(
        "anthropic-ratelimit-unified-7d_oi-utilization: 1.7\r\n")), None)
    chk("fable no headers (transport error) -> unavailable", _assemble_fable(None), None)
    #   limit is optional: a good window without a *-limit header still admits
    fable_nolimit = _assemble_fable(_parse_rate_headers(
        "anthropic-ratelimit-unified-7d_oi-utilization: 0.3\r\n"))
    chk("fable good sans limit: fable_ok", (fable_nolimit or {}).get("fable_ok"), True)
    chk("fable good sans limit: no limit key", "fable_7d_oi_limit" in (fable_nolimit or {}), False)
    # ---- [#720] OPUS5 PREMIUM-BUCKET OBSERVATION ------------------------------------------------
    # The rule under test is STRUCTURAL: 5h/7d are the whole-account windows, so any OTHER
    # `<window>-utilization` header claude-opus-5 returns is a sub-quota the whole-account gate
    # cannot see. Each row below is chosen so that deleting the guard it names flips it.
    opus5_dir = os.path.dirname(os.path.abspath(__file__))
    base_only = _parse_rate_headers(
        "HTTP/2 200\r\n"
        "anthropic-ratelimit-unified-status: allowed\r\n"
        "anthropic-ratelimit-unified-5h-utilization: 0.3\r\n"
        "anthropic-ratelimit-unified-7d-utilization: 0.4\r\n")
    #   MUTANT: drop the `not in BASE_WINDOWS` filter => this returns ('5h', '0.3') and every opus5
    #   admission starts gating on the WHOLE-ACCOUNT window under a premium name.
    chk("[#720] base-only headers declare NO premium window", _premium_window(base_only), None)
    chk("[#720] a non-base window IS a premium window", _premium_window(_parse_rate_headers(
        "anthropic-ratelimit-unified-5h-utilization: 0.3\r\n"
        "anthropic-ratelimit-unified-7d_oi-utilization: 0.2\r\n")), ("7d_oi", "0.2"))
    #   Two readable buckets: the gate must key on the one with the LEAST headroom. The values are
    #   chosen so a `min`/first-wins mutant returns the OTHER window by name, not merely the other
    #   number, and neither appears anywhere else in this block.
    chk("[#720] with two readable buckets, the LEAST headroom wins", _premium_window(
        _parse_rate_headers("anthropic-ratelimit-unified-7d_oi-utilization: 0.11\r\n"
                            "anthropic-ratelimit-unified-30d_px-utilization: 0.77\r\n")),
        ("30d_px", "0.77"))
    #   ... and an UNREADABLE bucket outranks a healthy sibling: a garbage premium window is exactly
    #   the state admission must refuse on, so it must not hide behind the healthy one. MUTANT:
    #   delete the `unreadable` short-circuit => this returns ('7d_oi', '0.11').
    chk("[#720] an UNREADABLE bucket outranks a healthy sibling", _premium_window(
        _parse_rate_headers("anthropic-ratelimit-unified-7d_oi-utilization: 0.11\r\n"
                            "anthropic-ratelimit-unified-30d_px-utilization: who-knows\r\n")),
        ("30d_px", "who-knows"))
    chk("[#720] non-dict header map declares no window", _premium_window(None), None)
    #   The observation record itself.
    obs_base = _assemble_opus5(base_only)
    chk("[#720] observed: the FULL header set is recorded verbatim",
        (obs_base["opus5_probe"], obs_base["opus5_headers"]), ("observed", base_only))
    chk("[#720] observed with no distinct bucket: NO window is declared",
        "opus5_premium_window" in obs_base, False)
    obs_bucket = _assemble_opus5(_parse_rate_headers(
        "anthropic-ratelimit-unified-status: allowed\r\n"
        "anthropic-ratelimit-unified-5h-utilization: 0.3\r\n"
        "anthropic-ratelimit-unified-7d_oi-utilization: 0.96\r\n"
        "anthropic-ratelimit-unified-7d_oi-reset: 1737072123\r\n"
        "anthropic-ratelimit-unified-7d_oi-limit: 424242\r\n"))
    chk("[#720] a distinct bucket is declared with its window, util, reset and limit",
        (obs_bucket.get("opus5_premium_window"), obs_bucket.get("opus5_premium_util"),
         obs_bucket.get("opus5_premium_reset"), obs_bucket.get("opus5_premium_limit")),
        ("7d_oi", "0.96", "1737072123", "424242"))
    #   A garbage utilization is DECLARED, not dropped: dropping it would silently re-open the
    #   whole-account fallback for a bucket in an unknown state (requirement 3 of #720).
    obs_garbage = _assemble_opus5(_parse_rate_headers(
        "anthropic-ratelimit-unified-7d_oi-utilization: unavailable\r\n"))
    chk("[#720] an UNREADABLE bucket is still DECLARED (never silently dropped)",
        (obs_garbage.get("opus5_premium_window"), obs_garbage.get("opus5_premium_util")),
        ("7d_oi", "unavailable"))
    #   A probe that could not answer declares NOTHING — opus5 is the sole anthropic tier and a
    #   transport blip must not park every single-rung chain (registry #703).
    chk("[#720] a transport error records `error` and declares no window",
        (_assemble_opus5(None), "opus5_premium_window" in _assemble_opus5(None)),
        ({"opus5_probe": "error"}, False))
    chk("[#720] a completed probe with NO rate-limit headers records `no-headers`",
        (_assemble_opus5({}).get("opus5_probe"), "opus5_premium_window" in _assemble_opus5({})),
        ("no-headers", False))
    #   THE CROSS-SCRIPT SEAM. These field names are a contract with select-and-claim, and the
    #   expected verdicts are taken from the BINDING layer (usage_eligible), not from a local
    #   re-implementation of the rule — a renamed key, a dropped field or a relaxed gate on EITHER
    #   side reds these rows. `opus5_base` has healthy WHOLE-ACCOUNT headroom throughout, which is
    #   the whole point: it is what the pre-#720 gate admitted on.
    opus5_alloc = _load_account_catalog(opus5_dir)
    opus5_base = {"status": "allowed", "5h_util": "0.1", "5h_reset": "1", "7d_util": "0.1",
                  "7d_reset": "2"}
    chk("[#720] healthy whole-account + EXHAUSTED opus5 bucket is REFUSED by the allocator",
        opus5_alloc.usage_eligible({**opus5_base, **obs_bucket}, model="opus5"), False)
    chk("[#720] healthy whole-account + UNREADABLE opus5 bucket is REFUSED by the allocator",
        opus5_alloc.usage_eligible({**opus5_base, **obs_garbage}, model="opus5"), False)
    #   ... and the PAIR that proves those two are the gate and not a broken fixture: the same
    #   account, the same observation shape, a HEALTHY bucket -> admitted.
    obs_healthy = _assemble_opus5(_parse_rate_headers(
        "anthropic-ratelimit-unified-7d_oi-utilization: 0.05\r\n"))
    chk("[#720] healthy whole-account + healthy opus5 bucket is ADMITTED",
        opus5_alloc.usage_eligible({**opus5_base, **obs_healthy}, model="opus5"), True)
    #   NO REGRESSION: an account the probe observed with no distinct bucket — and one it could not
    #   observe at all — must be admitted exactly as before #720.
    chk("[#720] no distinct bucket observed -> admitted exactly as today",
        (opus5_alloc.usage_eligible({**opus5_base, **obs_base}, model="opus5"),
         opus5_alloc.usage_eligible({**opus5_base, **_assemble_opus5(None)}, model="opus5"),
         opus5_alloc.usage_eligible(dict(opus5_base), model="opus5")),
        (True, True, True))
    #   The alias the probe addresses must be the alias the routing table dispatches, or the
    #   observation answers a question about a model nobody runs.
    import tomllib as _tomllib
    with open(os.path.join(os.path.dirname(opus5_dir), "orchestration", "routing.toml"),
              "rb") as _routing_handle:
        _routing_models = _tomllib.load(_routing_handle).get("models", {})
    chk("[#720] the probe addresses the SAME provider model routing.toml dispatches for opus5",
        _routing_models.get("opus5", {}).get("provider_model"), OPUS5_PROVIDER_MODEL)
    #   The request SHAPE: the fable measurement showed the premium sub-quota headers surface only
    #   on the Claude-Code subscription-OAuth path, which is also the shape every opus5 worker
    #   uses. MUTANT: flip `claude_code=True` to False => the recorded call loses the flag.
    _opus5_calls = []
    _saved_probe_headers = globals()["_probe_headers"]
    globals()["_probe_headers"] = lambda token, model, claude_code=False: (
        _opus5_calls.append((token, model, claude_code)) or {})
    try:
        _probe_opus5("tok-720")
    finally:
        globals()["_probe_headers"] = _saved_probe_headers
    chk("[#720] the opus5 probe uses the model AND the Claude-Code request shape",
        _opus5_calls, [("tok-720", OPUS5_PROVIDER_MODEL, True)])
    #   And that shape really does carry BOTH halves of the premium path (UA + system prompt).
    _opus5_argv, _ = _probe_curl_command("tok", OPUS5_PROVIDER_MODEL, claude_code=True)
    chk("[#720] the opus5 probe body carries the Claude-Code UA and system prompt",
        ("user-agent: " + _CLAUDE_CODE_UA in _opus5_argv,
         _CLAUDE_CODE_SYSTEM in _opus5_argv[_opus5_argv.index("-d") + 1],
         OPUS5_PROVIDER_MODEL in _opus5_argv[_opus5_argv.index("-d") + 1]),
        (True, True, True))
    #   DURABILITY: the observation has to outlive the tick, so the window name and its limit go
    #   into the account issue's front-matter line. MUTANT: drop either key from LIMIT_KEYS.
    chk("[#720] the observation is persisted into the account catalog's limits line",
        _limits_line({**opus5_base, "5h_limit": "10", **obs_bucket}),
        "limits: 5h_limit=10 opus5_premium_window=7d_oi opus5_premium_limit=424242")
    # [ISSUE #196] the SAME strict validator now guards the BASE 5h/7d windows (previously only the
    # Fable sub-quota): a malformed base window / empty status OMITS the account (fail-closed) rather
    # than being emitted to fail open as eligible capacity downstream. `good_base` is the parsed
    # allowed/0.42/0.1 header from above.
    good_base = _assemble_usage(hdr)
    chk("base usage: well-formed allowed entry is usable", _valid_base_usage(good_base), True)
    chk("base usage: well-formed throttled entry kept (valid state, not a shape mismatch)",
        _valid_base_usage({**good_base, "status": "throttled"}), True)
    chk("base usage: empty status -> omit", _valid_base_usage({**good_base, "status": ""}), False)
    chk("base usage: missing status -> omit",
        _valid_base_usage({"5h_util": "0.4", "7d_util": "0.1"}), False)
    chk("base usage: NaN 5h util -> omit", _valid_base_usage({**good_base, "5h_util": "nan"}), False)
    chk("base usage: negative 7d util -> omit", _valid_base_usage({**good_base, "7d_util": "-1"}), False)
    chk("base usage: >1 util -> omit", _valid_base_usage({**good_base, "5h_util": "1.5"}), False)
    chk("base usage: non-numeric util -> omit",
        _valid_base_usage({**good_base, "7d_util": "unknown"}), False)
    chk("base usage: missing window -> omit", _valid_base_usage({**good_base, "5h_util": None}), False)
    chk("base usage: non-dict -> omit", _valid_base_usage(None), False)
    # ---- probe-exempt backoff overlay (decision 2026-07-17, registry issue #29) ----
    import tempfile
    script_dir = os.path.dirname(os.path.abspath(__file__))
    #   pure annotation: active backoff lands on the entry; malformed/absent stays fail-open
    chk("apply backoff annotates the exempt entry",
        _apply_backoff({"exempt": True}, {"backoff_until": 2000, "consecutive": 2,
                                          "last_signal": "transient"}),
        {"exempt": True, "backoff_until": 2000, "backoff_consecutive": 2,
         "backoff_signal": "transient"})
    #   a saturated (possibly chain-truncated) count carries the lower-bound flag through to the
    #   snapshot entry (PR #85 finding 2); a forged non-bool flag is dropped (strict is-True)
    chk("apply backoff: saturated count marked as a lower bound",
        _apply_backoff({"exempt": True}, {"backoff_until": 2000, "consecutive": 6,
                                          "saturated": True, "last_signal": "transient"}),
        {"exempt": True, "backoff_until": 2000, "backoff_consecutive": 6,
         "backoff_saturated": True, "backoff_signal": "transient"})
    chk("apply backoff: forged non-bool saturated flag is dropped",
        "backoff_saturated" in _apply_backoff(
            {"exempt": True}, {"backoff_until": 2000, "saturated": "yes"}), False)
    chk("apply backoff: absent record leaves entry untouched",
        _apply_backoff({"exempt": True}, None), {"exempt": True})
    chk("apply backoff: forged/malformed record fails open (no crash)",
        _apply_backoff({"exempt": True}, {"backoff_until": "garbage"}), {"exempt": True})
    chk("apply backoff: non-dict record fails open", _apply_backoff({"exempt": True}, "x"),
        {"exempt": True})
    #   non-finite stamps must fail OPEN, not crash (cross-provider review r1: int(nan) raises
    #   ValueError, int(inf) raises OverflowError — both outside a naive float() guard)
    chk("apply backoff: nan fails open (no crash)",
        _apply_backoff({"exempt": True}, {"backoff_until": "nan"}), {"exempt": True})
    chk("apply backoff: inf fails open (no indefinite sideline)",
        _apply_backoff({"exempt": True}, {"backoff_until": "inf"}), {"exempt": True})
    #   the exemption is bound to an explicit provider allowlist (cross-provider review r1):
    #   missing/misspelled/unknown providers stay on the fail-closed probe path
    chk("exempt allowlist: openai (case/space tolerant)",
        (_is_exempt_provider("openai"), _is_exempt_provider(" OpenAI ")), (True, True))
    chk("exempt allowlist: anthropic/missing/typo/unknown all fail closed",
        (_is_exempt_provider("anthropic"), _is_exempt_provider(""), _is_exempt_provider(None),
         _is_exempt_provider("antropic"), _is_exempt_provider("codex")),
        (False, False, False, False, False))
    #   ledger round-trip: a rate-limit record for a salted handle surfaces as an active backoff
    mh = _load_model_health(script_dir)
    test_now = 1_000_000
    hashed = mh.account_hash("codex01", "s3cret")
    ledger_record = {"ts": test_now, "provider": "openai", "account": hashed,
                     "model_alias": "gpt", "exit_class": "transient", "run_id": "1"}
    good_ledger = {"records": [ledger_record]}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(good_ledger, fh)
        good_path = fh.name
    os.environ["MODEL_HEALTH_FILE"] = good_path
    backoffs = _load_backoffs(mh, test_now + 60)
    chk("ledger round-trip: active backoff derived for the salted handle",
        backoffs.get(hashed, {}).get("backoff_until"), test_now + mh.BACKOFF_BASE_SECONDS)
    #   retention regression (issue #82, fix-forward for #62): the backoff is derived AFTER
    #   mh.prune, whose global newest-MAX_RECORDS cap used to evict a live rate-limit record
    #   under a flood of later unrelated records — readmitting the capped account hours early.
    #   [registry #699] The flood is now CEILING-scale, and it has to be: prune gained a 7 h
    #   time-based retention floor, and a live backoff record is at most BACKOFF_CAP_SECONDS (5 h)
    #   old, so it always sits inside the floor and the COUNT cap can no longer reach it. A
    #   MAX_RECORDS-scale flood would evict nothing and this assertion would hold with the whole
    #   preservation path deleted. Only the ABSOLUTE ceiling can still evict, so that is the regime
    #   the guard is exercised in — and prune's ceiling ::warning:: is captured, exactly like the
    #   intentional failures below, so a self-test run never emits a real workflow annotation.
    flood_hit = dict(ledger_record, reset_hint="in 5 hours")
    other = mh.account_hash("acct01", "s3cret")
    flood = [{"ts": test_now + 100 + i // 8, "provider": "anthropic", "account": other,
              "model_alias": "haiku", "exit_class": "success", "run_id": str(i)}
             for i in range(mh.RETENTION_CEILING_RECORDS + 30)]
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump({"records": [flood_hit] + flood}, fh)
        flood_path = fh.name
    os.environ["MODEL_HEALTH_FILE"] = flood_path
    flood_err = io.StringIO()
    with contextlib.redirect_stderr(flood_err):
        flooded = _load_backoffs(mh, test_now + 1000)
        flood_window = mh.prune(mh.validate_ledger(json.load(open(flood_path, encoding="utf-8"))),
                                test_now + 1000)
    chk("retention: live 5 h backoff survives a CEILING-scale flood end-to-end",
        (flooded.get(hashed, {}).get("backoff_until"), len(flood_window),
         "RETENTION CEILING BINDING" in flood_err.getvalue()),
        (test_now + mh.BACKOFF_CAP_SECONDS, mh.RETENTION_CEILING_RECORDS, True))
    os.unlink(flood_path)
    #   a >6-hit (cap-saturated, possibly truncated) chain surfaces the lower-bound flag
    #   end-to-end: ledger -> _load_backoffs -> _apply_backoff -> snapshot entry (PR #85 f.2)
    sat_records = [dict(ledger_record, ts=test_now + i, run_id=str(i)) for i in range(7)]
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump({"records": sat_records}, fh)
        sat_path = fh.name
    os.environ["MODEL_HEALTH_FILE"] = sat_path
    sat_backoff = _load_backoffs(mh, test_now + 100).get(hashed) or {}
    chk("ledger round-trip: >6-hit chain flags saturated on the snapshot entry",
        (sat_backoff.get("consecutive"), sat_backoff.get("saturated"),
         _apply_backoff({"exempt": True}, sat_backoff).get("backoff_saturated")),
        (7, True, True))
    os.unlink(sat_path)
    os.environ["MODEL_HEALTH_FILE"] = good_path
    #   (v) malformed ledger -> loud fail-open {} (never crashes the sweep). CAPTURED stderr
    #   (cross-provider review r1): un-captured, these intentional failures would emit REAL
    #   ::warning:: annotations on every workflow run (the step runs --self-test first) and
    #   destroy the warning's operational signal. Capturing also lets us ASSERT the loudness.

    def _load_backoffs_captured(now_arg, api=None):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            result = _load_backoffs(mh, now_arg, api=api)
        return result, buf.getvalue()

    with open(good_path, "w", encoding="utf-8") as fh:
        fh.write('{"records": "not-a-list"}')
    got, err = _load_backoffs_captured(test_now)
    chk("malformed ledger fails open to no-backoff", got, {})
    chk("malformed ledger fail-open is LOUD (::warning::)", "::warning::" in err, True)
    with open(good_path, "w", encoding="utf-8") as fh:
        fh.write("not json at all")
    got, err = _load_backoffs_captured(test_now)
    chk("unparseable ledger fails open", got, {})
    chk("unparseable ledger fail-open is LOUD", "::warning::" in err, True)
    os.environ["MODEL_HEALTH_FILE"] = os.path.join(good_path, "nope")  # unreadable path
    got, err = _load_backoffs_captured(test_now)
    chk("missing ledger file fails open", got, {})
    chk("missing ledger fail-open is LOUD", "::warning::" in err, True)
    #   the warning line itself must stay sanitized: no handle, no salt, no count
    chk("fail-open warning carries no handle/salt", ("codex01" in err, "s3cret" in err),
        (False, False))
    del os.environ["MODEL_HEALTH_FILE"]
    os.unlink(good_path)
    #   (vi) ledger-BRANCH API read (cross-provider review r3 finding 2): without MODEL_HEALTH_FILE
    #   the read must go through model-health's contents API pinned to ?ref=ledger — the job's
    #   checkout is the DEFAULT ref whose data/model-health.json is the empty master seed, so a
    #   checkout-relative read made the reactive backoff silently inert. mh._StubAPI enforces the
    #   ledger pin structurally (an unpinned GET misses).
    saved_repo = os.environ.get("REGISTRY_REPO")
    os.environ["REGISTRY_REPO"] = "o/r"
    got, err = _load_backoffs_captured(test_now + 60, api=mh._StubAPI(seed=[ledger_record]))
    chk("no MODEL_HEALTH_FILE -> ledger-pinned API read derives the backoff",
        got.get(hashed, {}).get("backoff_until"), test_now + mh.BACKOFF_BASE_SECONDS)
    chk("API-read success path emits no warning", err, "")
    #   a MISSING ledger branch fails open (never crashes the probe) but stays LOUD
    got, err = _load_backoffs_captured(test_now, api=mh._StubAPI(branch_missing=True))
    chk("missing ledger branch fails open to no-backoff", got, {})
    chk("missing ledger branch fail-open is LOUD", "::warning::" in err, True)
    #   a missing ledger FILE on a present branch is the legitimate first-write state: genuinely
    #   no backoffs, and NOT a warning (an always-on warning would destroy the signal)
    got, err = _load_backoffs_captured(test_now, api=mh._StubAPI(seed=None))
    chk("first-write empty ledger -> no backoffs, no warning", (got, err), ({}, ""))
    if saved_repo is None:
        os.environ.pop("REGISTRY_REPO", None)
    else:
        os.environ["REGISTRY_REPO"] = saved_repo
    # ---- provider-addressed probing (cross-provider review r3 finding 3) ----
    #   an unknown/missing/misspelled provider must NEVER reach a probe: the probe is addressed
    #   to the Anthropic API, so transmitting the token there both leaks the credential to an
    #   endpoint the catalog never named AND admits the account on the response. Fail-closed
    #   omit (None), with ZERO probe invocations.
    probe_calls = []

    def _rec_probe(token):
        probe_calls.append(token)
        return {"status": "allowed", "5h_util": "0.1"}

    stub_secrets = {"ACCT01_TOKEN": "tok"}
    for prov in ("openia", "codex", "gemini", "", None):
        got = _probe_account({"handle": "x", "provider": prov, "secret_ref": "ACCT01_TOKEN",
                              "models": ["haiku"]}, stub_secrets,
                             probe=_rec_probe, fable_probe=_rec_probe)
        chk(f"unknown provider {prov!r} fail-closed omitted", got, None)
    chk("unknown providers never invoked a probe", probe_calls, [])
    got = _probe_account({"handle": "acct01", "provider": " Anthropic ", "secret_ref": "ACCT01_TOKEN",
                          "models": ["haiku"]}, stub_secrets,
                         probe=_rec_probe, fable_probe=_rec_probe)
    chk("anthropic account still probes (normalized match)", (got or {}).get("status"), "allowed")
    chk("non-fable account probes exactly once", probe_calls, ["tok"])
    probe_calls.clear()
    _probe_account({"handle": "acct01", "provider": "anthropic", "secret_ref": "ACCT01_TOKEN",
                    "models": ["fable"]}, stub_secrets, probe=_rec_probe, fable_probe=_rec_probe)
    chk("fable account gets the second (fable) probe", probe_calls, ["tok", "tok"])
    probe_calls.clear()
    # [#720] the opus5 observation is WIRED: an opus5-capable account gets the second probe and its
    # declaration is merged onto the base entry; a haiku-only account does NOT (the base probe is
    # the only call). MUTANT: delete the `if "opus5" in ...` block => the first row loses its
    # second call AND its window key; MUTANT: drop the models guard => the second row gains one.
    _opus5_obs = {"opus5_probe": "observed", "opus5_premium_window": "9q_zz",
                  "opus5_premium_util": "0.99"}
    _opus5_entry = _probe_account(
        {"handle": "acct01", "provider": "anthropic", "secret_ref": "ACCT01_TOKEN",
         "models": ["opus5"]}, stub_secrets, probe=_rec_probe, fable_probe=_rec_probe,
        opus5_probe=lambda token: probe_calls.append(token) or dict(_opus5_obs))
    chk("[#720] an opus5 account is probed twice and carries its observation",
        (probe_calls, _opus5_entry.get("opus5_premium_window"), _opus5_entry.get("status")),
        (["tok", "tok"], "9q_zz", "allowed"))
    probe_calls.clear()
    _haiku_entry = _probe_account(
        {"handle": "acct01", "provider": "anthropic", "secret_ref": "ACCT01_TOKEN",
         "models": ["haiku"]}, stub_secrets, probe=_rec_probe, fable_probe=_rec_probe,
        opus5_probe=lambda token: probe_calls.append(token) or dict(_opus5_obs))
    chk("[#720] a non-opus5 account is NOT opus5-probed and declares no window",
        (probe_calls, "opus5_premium_window" in _haiku_entry), (["tok"], False))
    probe_calls.clear()
    chk("non-worker secret_ref still never dereferenced/probed",
        (_probe_account({"handle": "acct01", "provider": "anthropic",
                         "secret_ref": "REGISTRY_ADMIN_APP_KEY"},
                        {"REGISTRY_ADMIN_APP_KEY": "priv"},
                        probe=_rec_probe, fable_probe=_rec_probe), probe_calls), (None, []))
    # ---- secret_ref bound to its OWN handle (issue #197) ----
    #   the ACCT*_TOKEN allow-list alone lets a catalog row name ANOTHER account's credential; the
    #   probe would then bill the foreign token to the wrong handle, corrupting selection + tier-
    #   limit persistence and later dead-leasing. A ref that PASSES the allow-list but is not THIS
    #   handle's own `${handle^^}_TOKEN` must fail-closed OMIT (None) with ZERO probe invocations —
    #   this case returned a probed entry under the old allow-list-only gate.
    probe_calls.clear()
    chk("foreign ACCT token (wrong handle) fail-closed omitted",
        _probe_account({"handle": "acct01", "provider": "anthropic", "secret_ref": "ACCT02_TOKEN",
                        "models": ["haiku"]}, {"ACCT02_TOKEN": "victim-tok"},
                       probe=_rec_probe, fable_probe=_rec_probe), None)
    chk("foreign-token row never dereferenced/probed", probe_calls, [])
    chk("own-handle token still probes (mixed-case handle binds)",
        (_probe_account({"handle": "Acct01", "provider": "anthropic", "secret_ref": "ACCT01_TOKEN",
                         "models": ["haiku"]}, {"ACCT01_TOKEN": "tok"},
                        probe=_rec_probe, fable_probe=_rec_probe) or {}).get("status"), "allowed")
    chk("missing handle fail-closed omitted (no probe)",
        (_probe_account({"provider": "anthropic", "secret_ref": "ACCT01_TOKEN", "models": ["haiku"]},
                        {"ACCT01_TOKEN": "tok"}, probe=_rec_probe, fable_probe=_rec_probe)), None)
    probe_calls.clear()
    # ---- tier-limit persistence: honest failure propagation + no silent overwrite (issue #198) ----
    class _R:  # a tiny CompletedProcess stand-in for the fake gh runner
        def __init__(self, rc, out=""):
            self.returncode, self.stdout, self.stderr = rc, out, ""

    def _fake_gh(script):
        """(run, edits). `script` keys:
          'list': (rc, stdout_json)                     -> the bulk `issue list` response
          'view': {num: [(body, edit_count)|None, ...]} -> successive GraphQL issue reads
                                                           (None = gh failure)
          'edit': {num: [rc, ...]}                      -> successive `issue edit` returncodes
                                                           (default 0)
        Every `issue edit` records (num, body) into the returned `edits` list."""
        edits = []

        def run(args, **_kw):
            if args[1] == "api" and args[2] == "graphql":  # _issue_view read (body + edit count)
                num = next(a.split("=", 1)[1] for a in args if a.startswith("number="))
                queue = script.get("view", {}).get(num, [])
                entry = queue.pop(0) if queue else ("", 0)
                if entry is None:
                    return _R(1, "")               # simulate a failed read
                body, count = entry
                return _R(0, json.dumps({"data": {"repository": {"issue": {
                    "body": body, "userContentEdits": {"totalCount": count}}}}}))
            sub = args[2]  # ["gh", "issue", <sub>, <num?>, ...]
            if sub == "list":
                rc, out = script.get("list", (0, "[]"))
                return _R(rc, out)
            if sub == "edit":
                num = args[3]
                body = args[args.index("--body") + 1]
                edits.append((num, body))
                queue = script.get("edit", {}).get(num, [])
                return _R(queue.pop(0) if queue else 0)
            return _R(0, "")
        return run, edits

    def _usage_file(obj):
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(obj, fh)
        fh.close()
        return fh.name

    # `persist_limits` reports through STDOUT workflow commands, and every failure fixture below
    # drives one on purpose. Captured for the same reason `_load_backoffs_captured` captures the
    # ledger fixtures' stderr — and, like it, capturing is what lets the loudness be ASSERTED
    # rather than merely hidden.
    def _persist_captured(*args, **kwargs):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = persist_limits(*args, **kwargs)
        return rc, buf.getvalue()

    saved_repo = os.environ.get("REGISTRY_REPO")
    os.environ["REGISTRY_REPO"] = "o/r"
    limits_usage = {"acct01": {"5h_limit": "100", "7d_limit": "700"}}
    upath = _usage_file(limits_usage)
    limits_line = "limits: 5h_limit=100 7d_limit=700"
    # `harness` is a REQUIRED account-record field (2026-07-26 acct02 lease-burn regression):
    # select-and-claim's write guard rejects a replacement body without it, so these VALID fixtures
    # must declare it or they would assert the guard's failure path instead of the merge behaviour.
    valid_anthropic = ("provider: anthropic\nharness: claude\nmodels: [haiku]\n"
                       "credential_format: claude-oauth-token\nsecret_ref: ACCT01_TOKEN\n")
    valid_openai = ("provider: openai\nharness: codex\nmodels: [sol]\n"
                    "credential_format: codex-auth-json\nsecret_ref: ACCT01_TOKEN\n")

    #   (i) the concurrent-overwrite regression: a provider edit lands between the bulk `list` and the
    #   mutation. The write MUST merge onto the FRESH view body (preserving `provider: openai`),
    #   never the stale snapshot. This is the core #198 assertion — it flips red if the merge reads a
    #   stale body or drops the concurrent field.
    fresh = valid_openai
    merged = _upsert_limits_line(fresh, limits_line)[0]
    run, edits = _fake_gh({"list": (0, json.dumps([{"number": 7, "title": "acct01"}])),
                           "view": {"7": [(fresh, 0), (merged, 1)]}})
    rc, out = _persist_captured(upath, run=run)
    chk("persist: success returns 0", rc, 0)
    chk("persist: a landed write reports success and emits NO workflow command",
        (out.strip(), workflow_commands(out)),
        ("account-usage: tier-limit lines refreshed", []))
    chk("persist: merges limits onto the FRESH body (no stale overwrite)",
        (len(edits), "provider: openai" in edits[0][1], limits_line in edits[0][1]),
        (1, True, True))

    #   (ii) idempotent no-op: the live body already carries the exact line -> zero edits, still 0
    run, edits = _fake_gh({"list": (0, json.dumps([{"number": 7, "title": "acct01"}])),
                           "view": {"7": [(valid_anthropic + limits_line + "\n", 0)]}})
    chk("persist: idempotent live body writes nothing",
        (_persist_captured(upath, run=run)[0], edits), (0, []))

    #   (iii) a failed bulk catalog read is PROPAGATED (was swallowed with a false 'refreshed')
    run, edits = _fake_gh({"list": (1, "")})
    rc, out = _persist_captured(upath, run=run)
    chk("persist: list failure propagates (rc=1, no edits)", (rc, edits), (1, []))
    chk("persist: list failure is LOUD (::warning::)", workflow_commands(out),
        ["::warning::account-usage: account catalog read failed; tier-limit persistence skipped"])

    #   (iv) an `issue edit` failure is PROPAGATED as a non-zero return, BEFORE the confirm read.
    #   The confirm view is queued to MATCH new_body, so swallowing the edit returncode would
    #   confirm-match and wrongly return 0 — this asserts the returncode is honoured immediately.
    edit_body0 = valid_anthropic
    edit_merged = _upsert_limits_line(edit_body0, limits_line)[0]
    run, edits = _fake_gh({"list": (0, json.dumps([{"number": 7, "title": "acct01"}])),
                           "view": {"7": [(edit_body0, 0), (edit_merged, 1)]},
                           "edit": {"7": [1]}})
    rc, out = _persist_captured(upath, run=run)
    chk("persist: edit failure propagates (rc=1, no confirm swallow)", (rc, len(edits)), (1, 1))
    chk("persist: a failed write is LOUD, and says the capacity model may be stale",
        [line for line in workflow_commands(out) if "capacity model may be stale" in line],
        [WRITE_FAILURE_WARNING])

    #   (v) a failed re-read (view rc!=0) is PROPAGATED, not treated as an empty body
    run, edits = _fake_gh({"list": (0, json.dumps([{"number": 7, "title": "acct01"}])),
                           "view": {"7": [None]}})
    chk("persist: view failure propagates (rc=1)", _persist_captured(upath, run=run)[0], 1)

    #   (vi) retry-merges-on-change: a concurrent writer lands strictly AFTER our edit (their body
    #   is live, edit count shows exactly ours + theirs — nothing lost); the merge is re-applied
    #   onto the writer's NEW body, then confirmed as the only edit of the second window.
    body0 = valid_anthropic
    clob = valid_anthropic + "notes: touched-by-other\n"              # concurrent notes edit
    merged2 = _upsert_limits_line(clob, limits_line)[0]
    run, edits = _fake_gh({"list": (0, json.dumps([{"number": 7, "title": "acct01"}])),
                           "view": {"7": [(body0, 0), (clob, 2), (clob, 2), (merged2, 3)]}})
    rc = _persist_captured(upath, run=run)[0]
    chk("persist: retries the merge after a concurrent clobber, then succeeds",
        (rc, len(edits), "notes: touched-by-other" in edits[-1][1], limits_line in edits[-1][1]),
        (0, 2, True, True))

    #   (vii) an unrecoverable writer that keeps reverting our line: retries are BOUNDED and the
    #   exhausted state PROPAGATES as failure (never a false 'refreshed')
    revert_seq = []
    for i in range(PERSIST_ATTEMPTS):
        revert_seq += [(body0, 2 * i), (body0, 2 * i + 2)]
    run, edits = _fake_gh({"list": (0, json.dumps([{"number": 7, "title": "acct01"}])),
                           "view": {"7": revert_seq}})
    chk("persist: exhausted retries propagate as failure, bounded edit attempts",
        (_persist_captured(upath, run=run)[0], len(edits)), (1, PERSIST_ATTEMPTS))

    #   (ix) THE losing interleaving (#198 review round 2): a concurrent metadata edit lands
    #   BETWEEN our fresh read and our unconditional write, so our write replaces it and the
    #   confirm reads back exactly our merged body. A body-only confirm calls that success and the
    #   loss is silent; the edit-count guard sees TWO body edits since the fresh read and must
    #   FAIL (rc=1) after exactly one write — and never retry, because a retry would find nothing
    #   left to change and launder the loss into a false 'refreshed'.
    run, edits = _fake_gh({"list": (0, json.dumps([{"number": 7, "title": "acct01"}])),
                           "view": {"7": [(fresh, 0), (merged, 2)]}})
    rc, out = _persist_captured(upath, run=run)
    chk("persist: writer clobbered inside the read->write window fails loudly (no silent loss)",
        (rc, len(edits), workflow_commands(out)), (1, 1, [WRITE_FAILURE_WARNING]))

    #   (x) a confirm that counts OUR edit as the only one but shows a non-matching body is an
    #   inconsistent read — fail closed, no retry
    run, edits = _fake_gh({"list": (0, json.dumps([{"number": 7, "title": "acct01"}])),
                           "view": {"7": [(fresh, 0), (fresh, 1)]}})
    chk("persist: single-edit confirm with mismatched body fails closed",
        (_persist_captured(upath, run=run)[0], len(edits)), (1, 1))

    #   (xi) WRITE GUARD (#521): a selected account whose live replacement body is missing a
    #   required schema field is rejected BEFORE `gh issue edit`; no corrupt record is persisted.
    # Exactly ONE field short (secret_ref) so this row still discriminates the guard it was
    # written for: without `harness` it would be rejected for the harness requirement too and would
    # keep passing with the secret_ref check deleted.
    invalid_body = ("provider: openai\nharness: codex\nmodels: [sol]\n"
                    "credential_format: codex-auth-json\n")
    run, edits = _fake_gh({"list": (0, json.dumps([{"number": 7, "title": "acct01"}])),
                           "view": {"7": [(invalid_body, 0)]}})
    rc, out = _persist_captured(upath, run=run)
    chk("persist: schema-invalid account body is rejected before write", (rc, len(edits)), (1, 0))
    chk("persist: the schema-guard rejection is LOUD, and names no handle",
        (workflow_commands(out), "acct01" in out),
        ([SCHEMA_REJECT_WARNING, WRITE_FAILURE_WARNING], False))

    #   (viii) a non-dict usage snapshot is handled (no probed limits) without touching the catalog
    lpath = _usage_file(["not", "a", "map"])
    run, edits = _fake_gh({"list": (0, json.dumps([{"number": 7, "title": "acct01"}]))})
    chk("persist: non-map usage snapshot skips cleanly",
        (_persist_captured(lpath, run=run)[0], edits), (0, []))
    os.unlink(lpath)
    os.unlink(upath)
    if saved_repo is None:
        os.environ.pop("REGISTRY_REPO", None)
    else:
        os.environ["REGISTRY_REPO"] = saved_repo

    ok = _self_test_ledgergate(chk) and ok

    # --- annotation containment ------------------------------------------------------------------
    #   the line-anchored selector: a workflow command is only a command at column 0.
    chk("workflow_commands selects command lines only",
        workflow_commands("plain\n::warning::w\n  ::warning::indented\n"
                          "see ::error::x inline\n::notice::n\n::debug::d"),
        ["::warning::w", "::notice::n"])
    #   the recorder: forwards VERBATIM (a real escape must stay readable) and records the commands.
    sink = io.StringIO()
    seen = []
    proxy = _AnnotationEscapeRecorder(sink, seen)
    print("ordinary", file=proxy)
    print(WRITE_FAILURE_WARNING, file=proxy)
    proxy.write("::error::split")          # a command spanning two writes is still one line
    proxy.write(" tail\n")
    proxy.write("::warning::unterminated")  # no newline yet -> not a line yet
    chk("recorder forwards bytes verbatim",
        sink.getvalue(),
        f"ordinary\n{WRITE_FAILURE_WARNING}\n::error::split tail\n::warning::unterminated")
    chk("recorder records exactly the completed command lines",
        seen, [WRITE_FAILURE_WARNING, "::error::split tail"])
    chk("recorder delegates unknown attributes to the wrapped stream",
        proxy.getvalue() == sink.getvalue(), True)
    #   THE INVARIANT. `escaped` is supplied only by `_run_self_test_contained`; the default None
    #   can never equal [], so deleting that wiring reds this row instead of disarming the recorder
    #   silently. A non-empty list names every fixture diagnostic that reached the live job log.
    chk("[containment] the entrypoint installed the recorder AND no fixture annotation reached "
        "the real workflow log", escaped, [])

    print("account-usage self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


# --- [registry #639] THE DISPATCH LEDGERGATE ------------------------------------------------------
# The subset fixtures the workflow validator must judge. The last four are #612 review round 4's
# measurement: each PASSES a `grep -q '"ACCT'` substring test while leaving the probe with no usable
# token, which is how the probe-EXEMPT accounts were published as free capacity off an unusable
# subset. Shared by the Python predicate rows and the executed workflow-body rows below, so the two
# layers are judged on the SAME documents.
SUBSET_FIXTURES = {
    "tokens": '{"ACCT01_TOKEN": "redacted"}',
    "empty-subset": "{}",
    "empty-value": '{"ACCT01_TOKEN": ""}',
    "blank-value": '{"ACCT01_TOKEN": "   "}',
    "non-string-value": '{"ACCT01_TOKEN": 1234}',
    "wrong-key": '{"NOT_AN_ACCT_TOKEN": "redacted", "ACCTLOOKALIKE": "redacted"}',
    "truncated": '{"ACCT01_TOKEN":',
    "not-an-object": '["ACCT01_TOKEN"]',
}
# (fixture, expected recorded detail) for every shape that must be REFUSED by the workflow probe step.
SUBSET_REFUSALS = (("empty-subset", "secret-subset-empty"), ("empty-value", "secret-subset-empty"),
                   ("blank-value", "secret-subset-empty"),
                   ("non-string-value", "secret-subset-empty"),
                   ("wrong-key", "secret-subset-empty"),
                   ("truncated", "secret-subset-malformed"),
                   ("not-an-object", "secret-subset-malformed"))


def _self_test_ledgergate(chk):
    """The registry #639 seam: the probe lane that SPENDS capacity must PROVE its materialization, and
    exemption must not imply reachability.

    Split into its own function only for size. It is the WIRING half of the suite, which is where a
    mutation harness measured this repo to be weakest: 18/18 mutations against Python guards were
    caught while every uncaught one was a workflow `if:` condition, a workflow step body, or a
    production call site. So the workflow step bodies are EXTRACTED FROM dispatch.yml AND EXECUTED,
    the step-level `continue-on-error` shape is asserted, the env wiring is read as a mapping, and
    main() is driven end to end rather than through its helpers."""
    import contextlib
    import io
    import tempfile
    import time
    ok = True

    def sub(name, got, want):
        nonlocal ok
        chk(name, got, want)
        ok = ok and got == want

    # ---- (1) the subset predicate, in Python where it is unit-testable ---------------------------
    for fixture, document in sorted(SUBSET_FIXTURES.items()):
        try:
            parsed = json.loads(document)
        except json.JSONDecodeError:
            parsed = None            # _load_secrets collapses an unparseable subset to {}
        sub(f"[#639] usable refs in the {fixture!r} subset",
            bool(_usable_secret_refs(parsed if isinstance(parsed, dict) else {})),
            fixture == "tokens")
    sub("[#639] the predicate returns the NAMES, so it cannot be satisfied by a stray key",
        _usable_secret_refs({"ACCT01_TOKEN": "a", "ACCT7X_TOKEN": " b ", "ACCT02_TOKEN": "",
                            "GITHUB_TOKEN": "c", "ACCTLOOKALIKE": "d", 7: "e"}),
        ["ACCT01_TOKEN", "ACCT7X_TOKEN"])

    # ---- (2) one reachability vocabulary across the three scripts that speak it -------------------
    script_dir = os.path.dirname(os.path.abspath(__file__))
    mh = _load_model_health(script_dir)
    allocator = _load_account_catalog(script_dir)
    sub("[#639] the unproven spelling is identical in probe / health record / allocator",
        (REACHABILITY_UNPROVEN, mh.CREDENTIAL_UNPROVEN),
        (allocator.USAGE_REACHABILITY_UNPROVEN, allocator.USAGE_REACHABILITY_UNPROVEN))
    sub("[#639] the live/dead spellings are identical too",
        (mh.CREDENTIAL_LIVE, mh.CREDENTIAL_DEAD),
        (allocator.USAGE_REACHABILITY_LIVE, allocator.USAGE_REACHABILITY_DEAD))
    sub("[#639] the allocator admits exactly {live, unproven} — dead is not admissible",
        (sorted(allocator.USAGE_REACHABILITY_ADMITTED),
         mh.CREDENTIAL_DEAD in allocator.USAGE_REACHABILITY_ADMITTED),
        ([mh.CREDENTIAL_LIVE, mh.CREDENTIAL_UNPROVEN], False))

    # ---- (3) main() END TO END: the ordering fix and the reachability stamp -----------------------
    # Driven through main() rather than its helpers because both defects live in main's STRUCTURE: the
    # exempt branch ran before `secrets` was ever consulted, and the entry it built asserted
    # availability with no reachability evidence at all.
    exempt_account = {"handle": "acctexempt", "provider": "openai", "models": ["sol"],
                      "secret_ref": "ACCTEXEMPT_TOKEN", "available": True,
                      "max_concurrent_workers": 1}
    # The probed account's secret_ref matches the `tokens` subset fixture, so the healthy row below
    # exercises a real token handoff rather than the fail-closed omit.
    probed_account = {"handle": "acct01", "provider": "anthropic", "models": ["haiku"],
                      "secret_ref": "ACCT01_TOKEN", "available": True,
                      "max_concurrent_workers": 1}
    e2e_salt = "e2e-salt"
    exempt_hash = mh.account_hash(exempt_account["handle"], e2e_salt)
    stamp = int(time.time())

    def record(exit_class, offset, run):
        return {"ts": stamp - offset, "provider": "openai", "account": exempt_hash,
                "model_alias": "sol", "exit_class": exit_class, "run_id": run}

    def run_main(subset="tokens", accounts=(exempt_account, probed_account), records=(),
                 salt=e2e_salt, ledger="records"):
        """(rc, usage map | "MALFORMED", stderr) from a real main() call over a stubbed catalog and a
        stubbed per-account probe. Only the two IO edges are stubbed; the gate, the ordering and the
        stamping under test are the production code path."""
        saved_env = {name: os.environ.get(name) for name in
                     ("REGISTRY_REPO", "PROVENANCE_SALT", "MODEL_HEALTH_FILE", "SECRETS_FILE",
                      "SECRETS_JSON", "ACCOUNT_POOL")}
        saved_catalog, saved_probe = globals()["_load_accounts"], globals()["_probe_account"]
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            secrets_path = os.path.join(directory, "acct-secrets.json")
            with open(secrets_path, "w", encoding="utf-8") as handle:
                handle.write(SUBSET_FIXTURES[subset])
            ledger_path = os.path.join(directory, "model-health.json")
            with open(ledger_path, "w", encoding="utf-8") as handle:
                if ledger == "records":
                    json.dump({"records": list(records)}, handle)
                else:
                    handle.write(ledger)          # a malformed ledger: fail-open, never `live`
            os.environ.update(REGISTRY_REPO="o/r", PROVENANCE_SALT=salt,
                              MODEL_HEALTH_FILE=ledger_path, SECRETS_FILE=secrets_path)
            os.environ.pop("SECRETS_JSON", None)
            os.environ.pop("ACCOUNT_POOL", None)
            globals()["_load_accounts"] = lambda _dir, _repo: [dict(a) for a in accounts]
            globals()["_probe_account"] = lambda account, secrets: (
                {"status": "allowed", "5h_util": "0.1", "5h_reset": stamp + 3600,
                 "7d_util": "0.1", "7d_reset": stamp + 86400}
                if secrets.get(account.get("secret_ref")) else None)
            try:
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = main()
            finally:
                globals()["_load_accounts"], globals()["_probe_account"] = saved_catalog, saved_probe
                for name, value in saved_env.items():
                    if value is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = value
        try:
            snapshot = json.loads(out.getvalue())
        except json.JSONDecodeError:
            snapshot = "MALFORMED"
        return code, snapshot, err.getvalue()

    # (a) THE ORDERING FIX. An unusable subset must yield an EMPTY document and a nonzero exit. Before
    # the fix the exempt branch ran first, so this returned {"acctexempt": {"exempt": true}} — a
    # NON-EMPTY map, which is exactly what makes every wholesale-outage detector (usage-alert's
    # `probe_empty = not usage`, dashboard-gen's no-measurement branch) stay silent.
    for subset, _detail in SUBSET_REFUSALS:
        code, snapshot, err = run_main(subset=subset)
        sub(f"[#639] an unusable ({subset}) subset yields an EMPTY map, not an exempt entry",
            (code, snapshot, "::error::" in err), (1, {}, True))
    sub("[#639] the refusal names the condition and leaks no token/handle/count",
        [token for token in ("redacted", "ACCT01_TOKEN", "acctexempt", "1 ")
         if token in run_main(subset="empty-value")[2]], [])

    # ---- [OPUS-5] EMPTY-CATALOG GATE (registry #1131, the 2026-07-29 fleet outage) ----------------
    # The materialization proof gate above is SCOPED to `any(non-exempt account)`. Over an EMPTY
    # catalog that population does not exist, so the proof is VACUOUS, the loop emits nothing, and
    # pre-fix main() returned (0, {}, no ::error::). The workflow then recorded
    # `outcome=ok detail=probe-succeeded` beside an empty snapshot, usage-alert's sidecar read
    # MEASURED, and dispatch's `_load_usage` collapsed {} to None -> every `require_usage` repo held
    # fail-closed for hours with nothing anywhere saying the fleet had never been read.
    # This is the same shape as the #639 ordering defect one layer out: the guard that proves
    # measurement happened cannot be conditioned on a population the failure ERASES.
    empty_catalog_code, empty_catalog_snapshot, empty_catalog_err = run_main(accounts=())
    sub("[#1131] an EMPTY account catalog exits NONZERO with an empty map and a loud cause",
        (empty_catalog_code, empty_catalog_snapshot, "::error::" in empty_catalog_err),
        (1, {}, True))
    sub("[#1131] the empty-catalog refusal leaks no handle/token/count",
        [token for token in ("acct01", "acctexempt", "ACCT01_TOKEN", "redacted", "0 accounts")
         if token in empty_catalog_err], [])
    # NEGATIVE CONTROL: the gate is not a blanket refusal — a populated catalog still measures and
    # still exits 0, so this cannot pass merely by making the probe always fail.
    sub("[#1131] a POPULATED catalog is unaffected by the empty-catalog gate",
        (run_main()[0], sorted(run_main()[1])), (0, ["acct01", "acctexempt"]))
    # ...and that empty map is what MAKES the outage detection fire. Asserted through the real
    # consumer, so "empty map" is not merely asserted to be empty but shown to be actionable.
    alerts = _load_sibling(script_dir, "usage-alert.py", "registry_usage_alert")
    empty_code, empty_snapshot, _err = run_main(subset="empty-subset")
    eligible, rows = alerts.classify([exempt_account["handle"], probed_account["handle"]],
                                     empty_snapshot, 0.10, now=stamp)
    sub("[#639] the empty map fires wholesale-outage detection (every account UNAVAILABLE)",
        (empty_code, empty_snapshot, eligible, [row[2] for row in rows],
         "did NOT measure" in alerts.render(eligible, rows, ["a", "b"], 2, "m", probe_empty=True)),
        (1, {}, 0, [False, False], True))
    # A USABLE subset still measures the whole fleet — the gate must not degrade the healthy path.
    code, snapshot, err = run_main()
    sub("[#639] a usable subset still probes the fleet (the gate is not a blanket refusal)",
        (code, sorted(snapshot), snapshot.get(probed_account["handle"], {}).get("status")),
        (0, ["acct01", "acctexempt"], "allowed"))
    # An ALL-EXEMPT fleet legitimately needs no token (the #612-round-4 scoping recommendation), so
    # the Python gate does not fire there — and the entry it emits is still reachability-stamped.
    code, snapshot, err = run_main(subset="empty-subset", accounts=(exempt_account,))
    sub("[#639] an all-exempt fleet needs no token, and is still not assumed reachable",
        (code, snapshot), (0, {"acctexempt": {"exempt": True,
                                             "reachability": REACHABILITY_UNPROVEN}}))

    # (b) THE BEHAVIOURAL HEART: a probe-exempt account whose credential is KNOWN DEAD is INELIGIBLE.
    # `acct01` is live in this state right now (`credential-remint-required`, #596 / alert #622) and is
    # the fleet's only cross-provider review account, so pre-fix every review dispatch was launched
    # against a credential the system had already diagnosed as unusable.
    # The rejections are stamped OLDER than AUTH_COOLDOWN_SECONDS on purpose: the #596 cooldown has
    # already EXPIRED, so nothing but the reachability verdict can be holding the account out. With a
    # fresh run the active cooldown would satisfy every allocator row below for the wrong reason (a
    # vacuity this harness measured on itself), and it would not model the live case anyway —
    # `acct01` has been `credential-remint-required` for days, far past any 15-minute hold.
    dead_records = [record(mh.CLASS_AUTH, mh.AUTH_COOLDOWN_SECONDS + 600, "a1"),
                    record(mh.CLASS_AUTH, mh.AUTH_COOLDOWN_SECONDS + 300, "a2")]
    for label, records, want_reach in (
            ("DEAD (a run of auth rejections, no later success)", dead_records, mh.CREDENTIAL_DEAD),
            ("LIVE (a success in the window)", [record(mh.SUCCESS, 60, "s1")], mh.CREDENTIAL_LIVE),
            ("LIVE again (a success AFTER the rejections clears it)",
             dead_records + [record(mh.SUCCESS, 30, "s2")], mh.CREDENTIAL_LIVE),
            ("UNPROVEN (no decisive record at all)", [], mh.CREDENTIAL_UNPROVEN)):
        code, snapshot, _err = run_main(records=records)
        entry = snapshot.get(exempt_account["handle"], {})
        sub(f"[#639] exempt entry is stamped {label}",
            (code, entry.get("exempt"), entry.get("reachability"), entry.get("backoff_until")),
            (0, True, want_reach, None))
        sub(f"[#639] ...and the ALLOCATOR agrees for {want_reach}",
            allocator.usage_eligible(dict(entry), now=stamp),
            want_reach != mh.CREDENTIAL_DEAD)
    # The dead account must not be selectable through the real selection call site either.
    dead_entry = run_main(records=dead_records)[1]
    saved_salt = os.environ.get("PROVENANCE_SALT")
    os.environ["PROVENANCE_SALT"] = e2e_salt      # the allocator hashes handles for lease identity
    try:
        selected = allocator.choose_account([exempt_account], [], ["sol"], "p", "r", stamp,
                                            usage=dead_entry)
        live_selected = allocator.choose_account(
            [exempt_account], [], ["sol"], "p", "r", stamp,
            usage=run_main(records=[record(mh.SUCCESS, 60, "s1")])[1])
    finally:
        if saved_salt is None:
            os.environ.pop("PROVENANCE_SALT", None)
        else:
            os.environ["PROVENANCE_SALT"] = saved_salt
    # The PAIR is what makes this non-vacuous: the same call site must still select the account when
    # its credential is proven live, so `None` above is the reachability gate and not a broken fixture.
    sub("[#639] choose_account refuses the DEAD exempt account and still takes the LIVE one",
        (selected, live_selected), (None, exempt_account["handle"]))
    # FAIL-OPEN must never fabricate `live`: no salt and an unreadable ledger both mean UNPROVEN.
    no_salt_code, no_salt, no_salt_err = run_main(records=dead_records, salt="")
    sub("[#639] with no salt there is no hash mapping -> unproven (loudly), never live",
        (no_salt_code, no_salt[exempt_account["handle"]]["reachability"],
         "::warning::" in no_salt_err),
        (0, REACHABILITY_UNPROVEN, True))
    bad_code, bad_ledger, bad_err = run_main(records=dead_records, ledger='{"records": "nope"}')
    sub("[#639] an unreadable ledger fails open to unproven (loudly), never live",
        (bad_code, bad_ledger[exempt_account["handle"]]["reachability"],
         "::warning::" in bad_err),
        (0, REACHABILITY_UNPROVEN, True))

    # ---- (4) THE WORKFLOW WIRING: extracted from dispatch.yml and EXECUTED -----------------------
    # This is the seam the mutation harness found uncaught. The extraction primitives are dashboard-
    # gen's (#612) deliberately: ONE implementation of "locate exactly this step, fail closed if you
    # cannot", so a wiring assertion can never pass vacuously.
    dg = _load_sibling(script_dir, "dashboard-gen.py", "registry_dashboard_gen")
    dispatch_yml = dg._repo_file(".github", "workflows", "dispatch.yml")
    dashboard_yml = dg._repo_file(".github", "workflows", "dashboard.yml")
    materialize_step = dg._workflow_step(dispatch_yml, "acct-secrets")
    probe_step = dg._workflow_step(dispatch_yml, "usage-probe")

    def continue_on_error(step_text):
        return re.findall(r"^\s*continue-on-error:\s*(\S+)", step_text, re.M)

    # (f) RESTORING `continue-on-error: true` on the materialization must go RED. The neighbouring
    # probe step DOES carry one (deliberately — a probe failure must not block dispatch), and reading
    # it with the same predicate is what proves this assertion is not vacuous.
    sub("[#639] the materialization step carries NO continue-on-error (and the probe step does)",
        (continue_on_error(materialize_step), continue_on_error(probe_step)), ([], ["true"]))
    # The env wiring: execution can never catch its deletion, because the harness supplies the
    # variable from the process environment. Read as a MAPPING, and the step id it names must resolve.
    probe_env = dg._workflow_step_env(dispatch_yml, "usage-probe")
    wired = re.fullmatch(r"\$\{\{\s*steps\.([A-Za-z0-9_-]+)\.outcome\s*\}\}",
                         probe_env.get("SECRETS_STEP_OUTCOME") or "")
    probe_script = dg._workflow_step_script(dispatch_yml, "usage-probe")
    sub("[#639] the probe step's gate is WIRED to the materialization step's outcome, by id",
        (wired.group(1) if wired else None,
         '"${SECRETS_STEP_OUTCOME}" != "success"' in probe_script,
         bool(wired) and dg._workflow_step_script(dispatch_yml, wired.group(1)) != ""),
        ("acct-secrets", True, True))
    # The laundering itself: `|| printf '{}'` on the materialization/probe invocation is what made a
    # failure indistinguishable from an idle fleet. Asserted scoped to THIS step.
    sub("[#639] the probe step no longer launders a failure into an empty-but-valid document",
        ("|| printf" in probe_script, "usage-probe.json" in probe_script), (False, True))
    # The sidecar's only consumer in this job is the alert step; deleting the env line silently
    # reverts to inferring an outage from an empty map.
    alert_env = dg._workflow_step_env(dispatch_yml, "usage-alert")
    sub("[#639] the probe sidecar is WIRED into the alert step that consumes it",
        (alert_env.get("USAGE_PROBE_STATUS_FILE"),
         "usage-probe.json" in (alert_env.get("USAGE_PROBE_STATUS_FILE") or "")),
        ("${{ runner.temp }}/usage-probe.json", True))
    # [#720] THE DURABILITY SEAM. The opus5 observation only answers anything if it OUTLIVES the
    # tick, and the persist step is what writes it into the account issues. Located by `id:`
    # (_workflow_step raises unless EXACTLY ONE step carries it, so a deleted or renamed step is a
    # hard failure, not a quiet pass), then pinned three ways a substring check cannot express:
    #   * the step carries NO `if:` AT ALL — `if: false` is the mutant the count/substring forms
    #     miss, and asserting the ABSENCE of the key is what makes it unexpressible here;
    #   * its argv is EXACT and ADJACENT — `--persist-limits-DROPPED`, a reordered argument, or an
    #     extra flag all red it, where `"--persist-limits" in script` accepts every one of them;
    #   * the path it READS is byte-identical to the one the probe step WRITES, so a repointed
    #     snapshot cannot leave this step persisting a file nobody produces.
    persist_step = dg._workflow_step(dispatch_yml, "persist-limits")
    persist_run = re.findall(r"^\s*run:\s*(\S.*)$", persist_step, re.M)
    persist_argv = shlex.split(persist_run[0]) if len(persist_run) == 1 else []
    persist_snapshot = persist_argv[-1] if persist_argv else None
    sub("[#720] the tier-limit/observation persist step is present, unconditional and exact",
        (len(persist_run), persist_argv, re.findall(r"^\s*if:", persist_step, re.M),
         persist_snapshot is not None and f'"{persist_snapshot}"' in probe_script),
        (1, ["python3", "registry/scripts/account-usage.py", "--persist-limits",
             "$RUNNER_TEMP/usage.json"], [], True))

    probe_stub = ("import json, os, sys\n"
                  "if '--self-test' in sys.argv:\n"
                  "    sys.exit(int(os.environ['STUB_SELFTEST_EXIT']))\n"
                  "json.dump({'acct-fixture': {'status': 'allowed'}}, sys.stdout)\n"
                  "sys.exit(int(os.environ['STUB_PROBE_EXIT']))\n")

    def run_probe_step(script, stub_relpath, secrets_outcome="success", secrets_file="tokens",
                       selftest_exit=0, probe_exit=0):
        """Execute a REAL probe step body. Returns (exit code, sidecar|"MALFORMED"|None, snapshot
        text|None, combined log). The stub prints a snapshot even when it EXITS NONZERO: real probes
        are incremental, so a dropped `!` must be caught by the recorded OUTCOME, not by an
        accidentally-empty file."""
        with tempfile.TemporaryDirectory() as directory:
            stub = os.path.join(directory, stub_relpath)
            os.makedirs(os.path.dirname(stub), exist_ok=True)
            with open(stub, "w", encoding="utf-8") as handle:
                handle.write(probe_stub)
            temp = os.path.join(directory, "runner-temp")
            os.mkdir(temp)
            secrets_path = os.path.join(directory, "acct-secrets.json")
            # "missing": the materialization body was replaced by `true` — it reports success and
            # leaves no file behind.
            if secrets_file != "missing":
                with open(secrets_path, "w", encoding="utf-8") as handle:
                    handle.write(SUBSET_FIXTURES[secrets_file])
            completed = subprocess.run(
                ["bash", "-c", script], cwd=directory, capture_output=True, text=True, timeout=120,
                check=False,
                env=dict(os.environ, RUNNER_TEMP=temp, SECRETS_STEP_OUTCOME=secrets_outcome,
                         SECRETS_FILE=secrets_path, STUB_SELFTEST_EXIT=str(selftest_exit),
                         STUB_PROBE_EXIT=str(probe_exit), GH_TOKEN="", PROVENANCE_SALT="",
                         REGISTRY_REPO="owner/repo",
                         MODEL_HEALTH_FILE=os.path.join(directory, "absent.json")))
            sidecar = None
            sidecar_path = os.path.join(temp, "usage-probe.json")
            if os.path.isfile(sidecar_path):
                with open(sidecar_path, encoding="utf-8") as handle:
                    body = handle.read()
                try:
                    sidecar = json.loads(body)
                except json.JSONDecodeError:
                    sidecar = "MALFORMED"
            snapshot_path = os.path.join(temp, "usage.json")
            snapshot = None
            if os.path.isfile(snapshot_path):
                with open(snapshot_path, encoding="utf-8") as handle:
                    snapshot = handle.read()
            return (completed.returncode, sidecar, snapshot,
                    completed.stdout + completed.stderr)

    def dispatch_probe(**kwargs):
        code, sidecar, snapshot, _log = run_probe_step(
            probe_script, os.path.join("registry", "scripts", "account-usage.py"), **kwargs)
        marker = sidecar if isinstance(sidecar, dict) else {}
        return code, marker.get("outcome"), marker.get("detail"), snapshot

    sub("[#639] probe step: a succeeding probe records ok and keeps its real snapshot",
        dispatch_probe(), (0, "ok", "probe-succeeded", '{"acct-fixture": {"status": "allowed"}}'))
    # THE polarity mutation: without the `!` this row reads ("ok", "probe-succeeded", <stub json>).
    sub("[#639] probe step: a NONZERO probe is recorded failed and its output discarded",
        dispatch_probe(probe_exit=1), (0, "failed", "probe-exited-nonzero", "{}"))
    sub("[#639] probe step: a failing probe self-test is recorded failed",
        dispatch_probe(selftest_exit=1), (0, "failed", "probe-self-test-failed", "{}"))
    sub("[#639] probe step: a failed secret materialization is recorded failed",
        dispatch_probe(secrets_outcome="failure"),
        (0, "failed", "secret-materialization-failed", "{}"))
    # (a) THE `true`-BODY MUTATION on the materialization step: outcome `success`, no file. Pre-fix
    # this measured nothing, exited 0, and left the exempt accounts published as free capacity.
    sub("[#639] probe step: `success` with NO subset file is refused, not measured",
        dispatch_probe(secrets_file="missing"), (0, "failed", "secret-file-missing", "{}"))
    # (c)+(d) the round-4 shapes a substring test accepts: an empty-string token value and truncated
    # JSON. Each of these reads ("ok", "probe-succeeded", <stub json>) under a `grep -q '"ACCT'` guard.
    for subset, detail in SUBSET_REFUSALS:
        sub(f"[#639] probe step: a `{subset}` subset is refused, not measured",
            dispatch_probe(secrets_file=subset), (0, "failed", detail, "{}"))
    # The refusal must stay SILENT about the document, for every shape.
    for subset in sorted(SUBSET_FIXTURES):
        code, _sidecar, _snapshot, logged = run_probe_step(
            probe_script, os.path.join("registry", "scripts", "account-usage.py"),
            secrets_file=subset)
        sub(f"[#639] probe step: the `{subset}` refusal leaks no subset bytes to the log",
            (code, "ACCT01_TOKEN" in logged, "redacted" in logged, "Traceback" in logged),
            (0, False, False, False))
    # PARITY with the page lane (#612/#219): the two probe bodies are separate shell copies, so assert
    # they return the IDENTICAL verdict for every fixture — a fix to one lane cannot drift from the
    # other, which is how this lane came to be missing the gate in the first place.
    dashboard_probe_script = dg._workflow_step_script(dashboard_yml, "usage-probe")

    def dashboard_probe(**kwargs):
        code, sidecar, snapshot, _log = run_probe_step(
            dashboard_probe_script, os.path.join("scripts", "account-usage.py"), **kwargs)
        marker = sidecar if isinstance(sidecar, dict) else {}
        return code, marker.get("outcome"), marker.get("detail"), snapshot

    for kwargs in [{}, {"probe_exit": 1}, {"selftest_exit": 1}, {"secrets_outcome": "failure"},
                   {"secrets_file": "missing"}] + [{"secrets_file": name}
                                                   for name, _d in SUBSET_REFUSALS]:
        sub(f"[#639] dispatch and dashboard probe bodies agree on {kwargs or 'the healthy path'}",
            dispatch_probe(**kwargs), dashboard_probe(**kwargs))
    # The sidecar the step really wrote must be what the ALERT's fail-closed parser accepts/refuses —
    # the shell -> python contract, which no substring assertion could express.
    sub("[#639] the sidecar the dispatch step writes is what usage-alert accepts/refuses",
        [alerts.probe_outcome(run_probe_step(
            probe_script, os.path.join("registry", "scripts", "account-usage.py"), **kwargs)[1],
            time.time())[0]
         for kwargs in ({}, {"probe_exit": 1}, {"secrets_file": "missing"},
                        {"secrets_file": "empty-value"}, {"secrets_file": "truncated"})],
        [True, False, False, False, False])
    # (i) The PRODUCER: the materialization body is EXECUTED against a fake complete secret map. It is
    # also the filter that keeps every NON-worker secret away from the probe, so assert the exact
    # subset and the 0600 mode, not merely that a file appeared. `run: true` writes no file.
    materialize_script = dg._workflow_step_script(dispatch_yml, "acct-secrets")
    with tempfile.TemporaryDirectory() as directory:
        temp = os.path.join(directory, "runner-temp")
        os.mkdir(temp)
        all_secrets = {"ACCT01_TOKEN": "worker-one", "ACCT7X_TOKEN": "worker-two",
                       "PROVENANCE_SALT": "not-a-worker-token", "GITHUB_TOKEN": "not-a-worker-token",
                       "ACCT01_TOKEN_BACKUP": "not-exactly-the-shape", "ACCTLOOKALIKE": "no-suffix",
                       "ACCT02_TOKEN": ["not", "a", "string"]}
        completed = subprocess.run(
            ["bash", "-c", materialize_script], cwd=directory, capture_output=True, text=True,
            timeout=120, check=False,
            env=dict(os.environ, RUNNER_TEMP=temp, ALL_SECRETS=json.dumps(all_secrets)))
        written = os.path.join(temp, "acct-secrets.json")
        subset_doc, mode = None, None
        if os.path.isfile(written):
            with open(written, encoding="utf-8") as handle:
                subset_doc = json.load(handle)
            mode = oct(os.stat(written).st_mode & 0o777)
        sub("[#639] materialization step: EXECUTED, it writes exactly the ACCT*_TOKEN string subset",
            (completed.returncode, subset_doc, mode),
            (0, {"ACCT01_TOKEN": "worker-one", "ACCT7X_TOKEN": "worker-two"}, "0o600"))
        sub("[#639] materialization step: no secret VALUE of any kind reaches its own step log",
            [value for value in ("worker-one", "worker-two", "not-a-worker-token")
             if value in completed.stdout + completed.stderr], [])
        # The two halves MEET: whatever the filter writes must be judged by BOTH the workflow probe
        # body and the Python predicate identically. A token-less secret map is a real production
        # shape (a repo with no worker tokens yet).
        empty_temp = os.path.join(directory, "runner-temp-empty")
        os.mkdir(empty_temp)
        empty_run = subprocess.run(
            ["bash", "-c", materialize_script], cwd=directory, capture_output=True, text=True,
            timeout=120, check=False,
            env=dict(os.environ, RUNNER_TEMP=empty_temp, ALL_SECRETS=json.dumps(
                {"PROVENANCE_SALT": "salt"})))
        empty_written = os.path.join(empty_temp, "acct-secrets.json")
        # A body replaced by `true` leaves NO file: report that as a value the row below can NAME,
        # never as a crash inside the harness.
        empty_subset = None
        if os.path.isfile(empty_written):
            with open(empty_written, encoding="utf-8") as handle:
                empty_subset = json.load(handle)
    with tempfile.TemporaryDirectory() as directory:
        stub = os.path.join(directory, "registry", "scripts", "account-usage.py")
        os.makedirs(os.path.dirname(stub))
        with open(stub, "w", encoding="utf-8") as handle:
            handle.write(probe_stub)
        handoff = os.path.join(directory, "acct-secrets.json")
        with open(handoff, "w", encoding="utf-8") as handle:
            json.dump(empty_subset if empty_subset is not None else {"unwritten": True}, handle)
        handoff_run = subprocess.run(
            ["bash", "-c", probe_script], cwd=directory, capture_output=True, text=True, timeout=120,
            check=False,
            env=dict(os.environ, RUNNER_TEMP=directory, SECRETS_STEP_OUTCOME="success",
                     SECRETS_FILE=handoff, STUB_SELFTEST_EXIT="0", STUB_PROBE_EXIT="0",
                     GH_TOKEN="", PROVENANCE_SALT="", REGISTRY_REPO="owner/repo",
                     MODEL_HEALTH_FILE=os.path.join(directory, "absent.json")))
        with open(os.path.join(directory, "usage-probe.json"), encoding="utf-8") as handle:
            handoff_sidecar = json.load(handle)
    sub("[#639] the two step bodies MEET: a token-less filter output is refused by the probe",
        (empty_run.returncode, empty_subset, _usable_secret_refs(empty_subset),
         handoff_run.returncode, handoff_sidecar["outcome"], handoff_sidecar["detail"]),
        (0, {}, [], 0, "failed", "secret-subset-empty"))
    return ok


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_run_self_test_contained())
    if "--persist-limits" in sys.argv:
        index = sys.argv.index("--persist-limits")
        sys.exit(persist_limits(sys.argv[index + 1]))
    sys.exit(main())
