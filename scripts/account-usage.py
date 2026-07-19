#!/usr/bin/env python3
# [OPUS-4.8] Probe live per-account usage for usage-aware dispatch. Emits a JSON map
#   {handle: {"status","5h_util","5h_reset","7d_util","7d_reset", (fable fields)}}  for anthropic accounts
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
import importlib.util
import json
import os
import re
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
    body = {"model": model, "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]}
    args = ["curl", "-s", "-D", "-", "-o", "/dev/null", "--max-time", "20", "-X", "POST",
            "https://api.anthropic.com/v1/messages",
            "-H", "Authorization: Bearer " + token,
            "-H", "anthropic-version: 2023-06-01",
            "-H", "content-type: application/json",
            "-H", "anthropic-beta: oauth-2025-04-20"]
    if claude_code:
        body["system"] = [{"type": "text", "text": _CLAUDE_CODE_SYSTEM}]
        args += ["-H", "user-agent: " + _CLAUDE_CODE_UA]
    args += ["-d", json.dumps(body)]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=30, check=False)
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
    """Whole-account 5h/7d usage via a cheap, ungated haiku probe. None -> fail-closed omit."""
    hdr = _probe_headers(token, "claude-haiku-4-5")
    if hdr is None or hdr.get("status") is None:
        return None  # transport error or no rate-limit headers (e.g. 401/blocked) -> fail-closed omit
    return _assemble_usage(hdr)


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


def _load_accounts(script_dir, registry_repo):
    spec = importlib.util.spec_from_file_location(
        "registry_select_and_claim", os.path.join(script_dir, "select-and-claim.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.read_accounts(registry_repo)


def _load_model_health(script_dir):
    spec = importlib.util.spec_from_file_location(
        "registry_model_health", os.path.join(script_dir, "model-health.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
    would starve the whole exempt provider, the exact regression the exemption removes."""
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
        return mh.account_backoffs(mh.prune(records, now), now)
    except Exception:
        # Broad by design: the fail-open contract above must hold no matter what the ledger
        # read raises (mh.HealthError, OSError, ValueError, KeyError, ...).
        print("::warning::account-usage: model-health ledger unreadable — exempt accounts admitted "
              "WITHOUT rate-limit backoff this tick (fail-open; fix the ledger to restore backoff)",
              file=sys.stderr)
        return {}


# The exempt PROVIDER allowlist (cross-provider review r1): the maintainer decision names openai;
# binding the exemption to an explicit allowlist (vs "any non-anthropic string") keeps a missing,
# misspelled, or unknown provider on the fail-closed probe path (it will surface as UNAVAILABLE in
# usage-alert — loud), so a catalog typo can never silently exempt an account from usage gating.
EXEMPT_PROVIDERS = frozenset({"openai"})


def _is_exempt_provider(provider):
    """True only for the explicitly probe-exempt providers (pure; whitespace/case tolerant)."""
    return str(provider or "").strip().lower() in EXEMPT_PROVIDERS


def _probe_account(account, secrets, probe=None, fable_probe=None):
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
    return probed


def _apply_backoff(entry, backoff):
    """Annotate one exempt usage entry with an ACTIVE backoff record (pure). Tolerant fail-open:
    a malformed/forged record (non-dict, non-numeric/non-finite backoff_until) leaves the entry
    untouched — never crashes the sweep, never blocks the account."""
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


# --- tier-limit persistence (capacity model, 2026-07-17 measurement) ------------------------------
LIMIT_KEYS = ("5h_limit", "7d_limit", "fable_7d_oi_limit")


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


PERSIST_ATTEMPTS = 3  # optimistic-concurrency retries per account issue (issue #198)


def _issue_view(number, registry_repo, run):
    """(doc, ok) for one `gh issue view --json body,updatedAt`. ok=False on a non-zero gh
    returncode or unparseable JSON so the caller PROPAGATES the failure rather than mistaking a
    failed read for an empty body (issue #198). `doc` is the parsed dict on success."""
    proc = run(["gh", "issue", "view", str(number), "-R", registry_repo,
                "--json", "body,updatedAt"],
               capture_output=True, text=True, timeout=60, check=False)
    if proc.returncode != 0:
        return None, False
    try:
        doc = json.loads(proc.stdout or "null")
    except json.JSONDecodeError:
        return None, False
    return (doc, True) if isinstance(doc, dict) else (None, False)


def _persist_one(number, line, registry_repo, run):
    """Merge the single `limits:` line into ONE account issue under optimistic concurrency (issue
    #198). `gh issue edit --body` REPLACES the whole body, so the old code — which rewrote a body
    snapshot captured in the earlier bulk `issue list` — silently clobbered any concurrent
    provider / credential-format / secret-reference / notes edit made between the list and the write.
    Instead re-read the CURRENT body immediately before the write and merge only the limits line onto
    THAT fresh body; then confirm the merge is live, and if a concurrent writer raced our edit,
    re-read its body and retry the merge. Returns True on success (incl. an idempotent no-op), False
    on any gh failure or exhausted retries — the caller PROPAGATES it. NOTE: gh has no conditional
    (If-Match) write, so a tiny read->write window remains; workflow-level serialization against the
    other catalog writers (set-up-account) is the belt-and-braces close (see follow-up)."""
    for _ in range(PERSIST_ATTEMPTS):
        doc, ok = _issue_view(number, registry_repo, run)
        if not ok:
            return False
        new_body, changed = _upsert_limits_line(doc.get("body") or "", line)
        if not changed:
            return True  # the live body already carries this exact limits line — nothing to write
        edit = run(["gh", "issue", "edit", str(number), "-R", registry_repo, "--body", new_body],
                   capture_output=True, text=True, timeout=60, check=False)
        if edit.returncode != 0:
            return False
        confirm, ok = _issue_view(number, registry_repo, run)
        if not ok:
            return False
        if (confirm.get("body") or "") == new_body:
            return True  # our merge is the live body
        # a concurrent writer changed the issue under us -> re-read its body and re-merge the line
    return False


def persist_limits(usage_path, run=None):
    """Write probed tier limits into the account issues' front-matter (title == handle) so the
    capacity model stops flying blind. Best-effort but HONEST (issue #198): every gh failure is
    PROPAGATED as a non-zero return (the step is continue-on-error, so this surfaces the failure as a
    red annotation instead of a false 'refreshed'), and each per-issue write goes through _persist_one
    so a concurrent metadata edit is not silently overwritten. select-and-claim's _parse_account
    ignores unknown keys, so the extra line is inert for the allocator. Privacy: prints carry no
    handles or counts (locked decision 22b). `run` is injectable for the self-test ONLY."""
    run = run or subprocess.run
    registry_repo = os.environ["REGISTRY_REPO"]
    try:
        with open(usage_path, encoding="utf-8") as handle:
            usage = json.load(handle)
    except (OSError, json.JSONDecodeError):
        print("account-usage: no usage snapshot; tier-limit persistence skipped")
        return 0
    if not isinstance(usage, dict):
        print("account-usage: usage snapshot is not a map; tier-limit persistence skipped")
        return 0
    listing = run(["gh", "issue", "list", "-R", registry_repo, "--state", "open", "--limit", "500",
                   "--json", "number,title"],
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
    failures = 0
    for issue in issues:
        handle = str(issue.get("title", "")).strip()
        line = _limits_line(usage.get(handle))
        if not line:
            continue
        if not _persist_one(issue.get("number"), line, registry_repo, run):
            failures += 1
    if failures:
        # No count (locked decision 22b) — only that at least one write did not land.
        print("::warning::account-usage: one or more tier-limit writes failed (gh returncode "
              "surfaced) — capacity model may be stale for those accounts")
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
    backoffs = None    # lazily loaded on the first probe-exempt account
    mh = None          # the model-health module once loaded (None until then / on load failure)
    salt_warned = False
    usage = {}
    for account in _load_accounts(script_dir, registry_repo):
        handle = account["handle"]
        if pool and handle not in pool:
            continue
        if _is_exempt_provider(account.get("provider")):
            # Probe-exempt provider (decision 2026-07-17, issue #29): eligible without usage data,
            # reactively backed off via the model-health rate-limit records. No salt -> no hash
            # mapping -> loud fail-open (backoff disabled, exemption intact). Any provider NOT on
            # the explicit allowlist (incl. missing/misspelled) is fail-closed OMITTED by
            # _probe_account below — never probed — and surfaces as UNAVAILABLE in usage-alert.
            entry = {"exempt": True}
            if salt:
                if backoffs is None:
                    # Guarded module load (cross-provider review r1): an import failure here must
                    # fail OPEN like an unreadable ledger — an uncaught exception would crash the
                    # probe, the shell would write '{}', and EVERY account (anthropic included)
                    # would fail closed: the exact starvation the exemption exists to prevent.
                    try:
                        mh = _load_model_health(script_dir)
                        backoffs = _load_backoffs(mh, now)
                    except Exception:
                        print("::warning::account-usage: model-health module unavailable — exempt "
                              "accounts admitted WITHOUT rate-limit backoff this tick (fail-open)",
                              file=sys.stderr)
                        mh, backoffs = None, {}
                if mh is not None:
                    entry = _apply_backoff(entry, backoffs.get(mh.account_hash(handle, salt)))
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


def _self_test():
    ok = True

    def chk(n, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {n}: {got} (want {want})")

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
    #   End-to-end: a 5 h reset hint + 200+ later unrelated success records still enforce it.
    flood_hit = dict(ledger_record, reset_hint="in 5 hours")
    other = mh.account_hash("acct01", "s3cret")
    flood = [{"ts": test_now + 100 + i, "provider": "anthropic", "account": other,
              "model_alias": "haiku", "exit_class": "success", "run_id": str(i)}
             for i in range(mh.MAX_RECORDS + 30)]
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump({"records": [flood_hit] + flood}, fh)
        flood_path = fh.name
    os.environ["MODEL_HEALTH_FILE"] = flood_path
    flooded = _load_backoffs(mh, test_now + 1000)
    chk("retention: live 5 h backoff survives 200+ later unrelated records end-to-end",
        flooded.get(hashed, {}).get("backoff_until"), test_now + mh.BACKOFF_CAP_SECONDS)
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
    import contextlib
    import io

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
          'list': (rc, stdout_json)              -> the bulk `issue list` response
          'view': {num: [body_or_None, ...]}     -> successive `issue view` bodies (None = rc!=0)
          'edit': {num: [rc, ...]}               -> successive `issue edit` returncodes (default 0)
        Every `issue edit` records (num, body) into the returned `edits` list."""
        edits = []

        def run(args, **_kw):
            sub = args[2]  # ["gh", "issue", <sub>, <num?>, ...]
            if sub == "list":
                rc, out = script.get("list", (0, "[]"))
                return _R(rc, out)
            if sub == "view":
                num = args[3]
                queue = script.get("view", {}).get(num, [])
                body = queue.pop(0) if queue else ""
                if body is None:
                    return _R(1, "")               # simulate a failed read
                return _R(0, json.dumps({"body": body, "updatedAt": "t"}))
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

    saved_repo = os.environ.get("REGISTRY_REPO")
    os.environ["REGISTRY_REPO"] = "o/r"
    limits_usage = {"acct01": {"5h_limit": "100", "7d_limit": "700"}}
    upath = _usage_file(limits_usage)
    limits_line = "limits: 5h_limit=100 7d_limit=700"

    #   (i) the concurrent-overwrite regression: a provider edit lands between the bulk `list` and the
    #   mutation. The write MUST merge onto the FRESH view body (preserving `provider: anthropic-eu`),
    #   never the stale snapshot. This is the core #198 assertion — it flips red if the merge reads a
    #   stale body or drops the concurrent field.
    fresh = "provider: anthropic-eu\nmodels: [haiku]\n"
    merged = _upsert_limits_line(fresh, limits_line)[0]
    run, edits = _fake_gh({"list": (0, json.dumps([{"number": 7, "title": "acct01"}])),
                           "view": {"7": [fresh, merged]}})
    rc = persist_limits(upath, run=run)
    chk("persist: success returns 0", rc, 0)
    chk("persist: merges limits onto the FRESH body (no stale overwrite)",
        (len(edits), "provider: anthropic-eu" in edits[0][1], limits_line in edits[0][1]),
        (1, True, True))

    #   (ii) idempotent no-op: the live body already carries the exact line -> zero edits, still 0
    run, edits = _fake_gh({"list": (0, json.dumps([{"number": 7, "title": "acct01"}])),
                           "view": {"7": ["provider: anthropic\n" + limits_line + "\n"]}})
    chk("persist: idempotent live body writes nothing", (persist_limits(upath, run=run), edits),
        (0, []))

    #   (iii) a failed bulk catalog read is PROPAGATED (was swallowed with a false 'refreshed')
    run, edits = _fake_gh({"list": (1, "")})
    chk("persist: list failure propagates (rc=1, no edits)", (persist_limits(upath, run=run), edits),
        (1, []))

    #   (iv) an `issue edit` failure is PROPAGATED as a non-zero return, BEFORE the confirm read.
    #   The confirm view is queued to MATCH new_body, so swallowing the edit returncode would
    #   confirm-match and wrongly return 0 — this asserts the returncode is honoured immediately.
    edit_body0 = "provider: anthropic\n"
    edit_merged = _upsert_limits_line(edit_body0, limits_line)[0]
    run, edits = _fake_gh({"list": (0, json.dumps([{"number": 7, "title": "acct01"}])),
                           "view": {"7": [edit_body0, edit_merged]},
                           "edit": {"7": [1]}})
    chk("persist: edit failure propagates (rc=1, no confirm swallow)",
        (persist_limits(upath, run=run), len(edits)), (1, 1))

    #   (v) a failed re-read (view rc!=0) is PROPAGATED, not treated as an empty body
    run, edits = _fake_gh({"list": (0, json.dumps([{"number": 7, "title": "acct01"}])),
                           "view": {"7": [None]}})
    chk("persist: view failure propagates (rc=1)", persist_limits(upath, run=run), 1)

    #   (vi) retry-merges-on-change: a concurrent writer clobbers our edit; the confirm re-read
    #   detects the mismatch and the merge is re-applied onto the writer's NEW body, then confirmed.
    body0 = "provider: anthropic\n"
    clob = "provider: anthropic\nnotes: touched-by-other\n"           # concurrent notes edit
    merged2 = _upsert_limits_line(clob, limits_line)[0]
    run, edits = _fake_gh({"list": (0, json.dumps([{"number": 7, "title": "acct01"}])),
                           "view": {"7": [body0, clob, clob, merged2]}})
    rc = persist_limits(upath, run=run)
    chk("persist: retries the merge after a concurrent clobber, then succeeds",
        (rc, len(edits), "notes: touched-by-other" in edits[-1][1], limits_line in edits[-1][1]),
        (0, 2, True, True))

    #   (vii) an unrecoverable writer that keeps reverting our line: retries are BOUNDED and the
    #   exhausted state PROPAGATES as failure (never a false 'refreshed')
    run, edits = _fake_gh({"list": (0, json.dumps([{"number": 7, "title": "acct01"}])),
                           "view": {"7": [body0] * (2 * PERSIST_ATTEMPTS)}})
    chk("persist: exhausted retries propagate as failure, bounded edit attempts",
        (persist_limits(upath, run=run), len(edits)), (1, PERSIST_ATTEMPTS))

    #   (viii) a non-dict usage snapshot is handled (no probed limits) without touching the catalog
    lpath = _usage_file(["not", "a", "map"])
    run, edits = _fake_gh({"list": (0, json.dumps([{"number": 7, "title": "acct01"}]))})
    chk("persist: non-map usage snapshot skips cleanly", (persist_limits(lpath, run=run), edits),
        (0, []))
    os.unlink(lpath)
    os.unlink(upath)
    if saved_repo is None:
        os.environ.pop("REGISTRY_REPO", None)
    else:
        os.environ["REGISTRY_REPO"] = saved_repo
    print("account-usage self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    if "--persist-limits" in sys.argv:
        index = sys.argv.index("--persist-limits")
        sys.exit(persist_limits(sys.argv[index + 1]))
    sys.exit(main())
