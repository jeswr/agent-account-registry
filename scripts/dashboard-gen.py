#!/usr/bin/env python3
"""Build the privacy-preserving static account-fleet dashboard payload."""

import argparse
import copy
import datetime as dt
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import zipfile


SCHEMA = "account-fleet-dashboard/v1"
WINDOWS = (("5h", "5 hour"), ("7d", "7 day"), ("fable_7d_oi", "Fable 7 day"))
ACCOUNT_REF_RE = re.compile(r"ACCT[A-Z0-9]+_TOKEN")
SAFE_PROVIDER_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")
SAFE_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}")
# The `owner/name` shape, defined ONCE. The holder grammar below embeds it, and the serviced-target
# reader (issue #78) validates policy/repos.toml's table keys against the same pattern — so the
# repositories the census SEEDS and the repositories it COUNTS can never be two different grammars.
SAFE_REPOSITORY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")
HOLDER_RE = re.compile(
    r"^(?:review:|fix:)?(?P<repository>" + SAFE_REPOSITORY_RE.pattern + r")#\d+@\S+$")
# The per-repository agent census reads its ROW SET from this repo's own worker policy (issue #78).
# Not a CLI flag on purpose: the set of repositories this orchestrator services is a property of the
# checkout the generator runs from, so there is no seam an invocation could point somewhere else.
POLICY_PATH_PARTS = ("policy", "repos.toml")
DISPATCH_COMPLETE_RE = re.compile(
    r"^\S+\s+dispatcher complete:\s+(\d+) worker/review/fix run\(s\) launched", re.MULTILINE)
DISPATCHED_RE = re.compile(r"^\S+\s+dispatched\s", re.MULTILINE)
DEFERRED_RE = re.compile(r"^\S+\s+defer(?:red)?\s", re.MULTILINE)
# Per-lane tick counts (issues #108/#323). dispatch-claim.py prints one
# `lane <name>: planned=N launched=N deferred=N error=N` line per lane immediately after
# `dispatcher complete:`, from the same counters it writes into the dispatch-summary.json the
# tick-health recorder reads — that summary is a runner-temp file the dashboard build never sees,
# so the RUN LOG is the only place these counts are reachable from here. The lane NAME is read from
# the log rather than pinned to a list, exactly as _obs_lane_rows does for the collector's lanes: a
# lane added to dispatch-claim's DISPATCH_LANES appears on the page with no change here. Counts are
# digit-bounded and the name must be a safe token.
DISPATCH_LANE_RE = re.compile(
    r"^\S+\s+lane (?P<lane>[A-Za-z0-9][A-Za-z0-9_.-]{0,31}): "
    r"planned=(?P<planned>\d{1,6}) launched=(?P<launched>\d{1,6}) "
    r"deferred=(?P<deferred>\d{1,6}) error=(?P<error>\d{1,6})\s*$", re.MULTILINE)
DISPATCH_LANE_CAP = 12
# The block dispatch-claim prints is BOUNDED on both sides — `dispatcher complete:`, the
# `fix-dispatch:` fan-out line, one lane line per DISPATCH_LANES, then `defer attribution:` — and
# `_dispatch_lane_rows` validates it as a WHOLE against these two anchors plus the lanes below.
# A tick truncated mid-block has no terminator; a lane row omitted from a rendered tick reads as a
# healthy lane that simply is not there. Both must be "unknown", never a selectively complete tick.
DISPATCH_FIX_LINE_RE = re.compile(r"^\S+\s+fix-dispatch: ")
DISPATCH_LANE_END_RE = re.compile(r"^\S+\s+defer attribution:")
# The lanes dispatch-claim's DISPATCH_LANES prints on EVERY tick, in THIS order (it iterates that
# tuple), and so the minimum a rendered block must carry. This is a floor on the SET and a pin on
# the ORDER of these four: an ADDED lane still reaches the page unread-ahead (the name comes from
# the log) wherever it sits in the block, while a MISSING one — the stalled review or failed disarm
# this feature exists to expose — refuses the whole block instead of publishing the survivors, and
# so does a block whose four required rows arrive in an order the dispatcher cannot emit. Should
# dispatch-claim ever reorder its own DISPATCH_LANES, ticks read `—` until this tuple is matched to
# it: unknown, which is the safe direction, rather than a block of unclear provenance published as
# the dispatcher's own.
DISPATCH_REQUIRED_LANES = ("worker", "review", "fix", "disarm")

# Agent-run observability (issue #246). The collector persists a snapshot of cache-effectiveness /
# per-lane run-health / flow metrics + auto-fixer trigger fires on the ledger data-plane branch
# (data/observability.json); dashboard.yml hands it in via --observability and
# _normalize_observability() validates it FAIL-CLOSED here before it may reach the public
# data.json (rendered by the dashboard's Observability panels; absent file => hidden panel).
# Decision 22: no raw account handles anywhere on the public surface — observability lease rows
# must already carry the collector's salted label (OBS_SALTED_LABEL_RE below); anything else
# dies loudly, and _assert_private additionally backstops every known raw handle over the finished
# document. Issue #374 additionally stops the SALTED per-account rows being published at all — see
# the fleet-composition block below — but the label validation stays, because a raw handle reaching
# the collector output is a privacy incident whether or not this build would have published it.
# Issue #841: the snapshot itself is readable on the PUBLIC `ledger` branch, so this contract no
# longer REQUIRES the per-account rows either — `flow.lease_utilization_1h` may be sent already
# aggregated, and a collector that does so writes no per-account row array to a public branch.
OBS_SCHEMA = "registry-observability/v1"
# Issue #375: the salted label is the CANONICAL account fingerprint — sha256(handle:salt)[:16],
# locked decision 22a, the one shape model-health.account_hash / worker-pr.account_hash produce and
# lease_schema.ACCOUNT / groom.SAFE_ACCOUNT_HASH / select-and-claim.ACCOUNT_FINGERPRINT_RE already
# validate. This read `[0-9a-f]{8}` — a second, shorter fingerprint format that no producer in this
# repo can emit, so a collector handing over the fingerprint every other surface uses would have
# failed the build. Tightening it here is safe in exactly this order because the collector has not
# landed yet (dashboard.yml: the snapshot is OPTIONAL until it does, and the panel stays hidden) —
# there is no producer to break, and the shape it must be built against is now the canonical one.
# The self-test pins this against model-health.account_hash's real output, not against a literal,
# so the two cannot drift apart again.
OBS_SALTED_LABEL_RE = re.compile(r"[0-9a-f]{16}")
OBS_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:+-]{0,63}")
OBS_QUEUE_CLASS_RE = re.compile(r"[1-4][a-z]?")   # the #243 queue classes (1, 2, 2a..2d, 3, 4)
OBS_HISTOGRAM_KEY_RE = re.compile(r"\d{1,2}\+?")
OBS_EVIDENCE_RE = re.compile(r"https://github\.com/[A-Za-z0-9_.~!$&'()*+,;=:@/?#%-]{1,220}")
OBS_THRESHOLD_KEYS = {"workflow_failure_rate", "defer_reason_hourly",
                      "queue_age_clamp_minutes", "merge_stall_minutes"}

# Usage-probe outcome sidecar (issue #219). dashboard.yml's secret-materialization and probe steps
# are `continue-on-error`, and a failed probe used to be replaced by `{}` — indistinguishable from
# "every account is idle". The probe job now PERSISTS its outcome next to the snapshot and the
# build hands it in via --usage-status; anything that is not an explicit, FRESH `ok` means the
# measurement did not happen, so no account may be published as usable capacity on its basis.
PROBE_SCHEMA = "account-usage-probe/v1"
# The probe runs on dashboard.yml's */15 cron; one hour is four missed slots. Beyond it the
# snapshot describes a fleet state nobody has observed recently, so it stops counting as measured.
PROBE_MAX_AGE_SECONDS = 3600
# Runner/generator clock skew is seconds, not minutes; a stamp further in the future than this is
# not a clock artifact but a bogus stamp, and bogus == unmeasured.
PROBE_MAX_SKEW_SECONDS = 300

# FLEET-COMPOSITION MINIMIZATION (issue #374, closing the sol-audit finding #184 deferred).
#
# The line this repo had already accepted is model-health.render_body's PUBLIC-registry route
# (sol-audit #204): when an alert lands on the public registry it carries the provider and the
# condition and SUPPRESSES the failure/fleet counts, reset hints and diagnostics, because those
# "would compositionally disclose the worker-account fleet". The dashboard was the loud version of
# the very same disclosure and had never been held to that line: it published one row per account
# (salted label, provider, availability, live windows, active-agent count) plus
# accounts_total/available/capped/unavailable/unknown, single_account, per-window
# accounts_reporting/remaining_account_windows/limit_remaining/limits_known, and
# fleet.capacity {eligible, total}. Every one of those is a direct read of the fleet's CARDINALITY,
# and the salted labels were stable across builds, so the page also tracked individual accounts
# over time.
#
# The counts are NOT deleted — they remain the internal single source of truth for "is there usable
# headroom" (_provider_quota / the capacity tally in build_dashboard), still unit-tested here, still
# the one predicate shared with the allocator. They are PROJECTED AWAY at publication time by
# _public_provider_quota + _public_capacity, which keep the operational answer (has this provider
# headroom, how full are its windows on average, when does it refill) while being invariant under
# cloning the fleet. _assert_no_fleet_composition then backstops the FINISHED document fail-closed,
# so a future field cannot silently re-open the surface this closes.
#
# KNOWN RESIDUAL, stated rather than hidden: `fleet.active_agents` (and the per-repository model
# counts it summarizes) is a count of LIVE LEASES, not of accounts. It used to be documented here as
# a lower BOUND on the fleet size — "the catalog's `max_concurrent_workers` is 1, so N concurrent
# agents implies at least N accounts" — and that premise is false (#882): accounts carry their own
# cap, acct01 was hand-set to 12 long ago, and since #278 set-up-account MINTS at the per-provider
# default (openai 12, anthropic 4). One account can therefore hold many of these leases at once, so
# N live leases implies only ceil(N / the largest cap in the catalog) accounts — a far weaker
# inference, and one whose divisor is not even published. The residual is thus WEAKER than it was
# stated to be, never stronger; nothing that was safe becomes unsafe. Do not restore the cap-1
# reasoning: a future minimization pass that trusts it would be reading a false invariant, and the
# suite pins the counter-example (one account, three concurrent leases, `active_agents` 3).
# It is kept because it is the dashboard's core operational number and
# because the same count is already public on the `ledger` branch (`data/leases.json`); removing it
# is a product call for the maintainer, tracked separately, not something to decide inside a
# minimization pass.
#
# So the property this change actually establishes is "the public payload carries no ACCOUNT CENSUS
# and no per-account row", NOT "no fleet count" — and both halves are load-bearing statements that
# the suite pins: the clone-invariance test below runs each fleet size WITH one live lease per
# account, so it asserts the invariance where the residual is live, and asserts the residual itself
# (the agent counts DO scale) rather than avoiding load and implying it does not. The page footer is
# worded to the same scope; do not restore an absolute "no fleet counts are published" claim while
# `active_agents` ships.
FLEET_COMPOSITION_KEYS = frozenset({
    "accounts", "accounts_total", "accounts_available", "accounts_capped", "accounts_unavailable",
    "accounts_unknown", "accounts_reporting", "single_account", "remaining_account_windows",
    "limit_remaining", "limits_known", "eligible", "total", "label",
})


# [#1353 BLOCKED] Thresholds that CANNOT be re-sized to satisfy the #680 bound: setting
# groom.yml=1200 / retriage.yml=2400 in .github/workflows/dashboard.yml makes GitHub refuse
# to ingest the workflow (action_required, jobs total_count=0 — measured on master
# 2026-07-31T03:04Z, PR #1363, reverted by #1364). Mechanism unknown; tracked in #1353.
# REMOVE THIS SET the moment #1353 is resolved — it is the weaker of the two states.
_THRESHOLD_BOUND_EXEMPT = frozenset({"groom.yml", "retriage.yml"})


class DashboardError(RuntimeError):
    pass


_LEASE_SCHEMA_MODULE = None


def _lease_schema_module():
    global _LEASE_SCHEMA_MODULE
    if _LEASE_SCHEMA_MODULE is None:
        path = Path(__file__).resolve().with_name("lease_schema.py")
        spec = importlib.util.spec_from_file_location("registry_lease_schema", path)
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load shared lease schema")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _LEASE_SCHEMA_MODULE = module
    return _LEASE_SCHEMA_MODULE


def _utc_iso(value):
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, (int, float)) or re.fullmatch(r"\d+(?:\.\d+)?", str(value).strip()):
            stamp = float(value)
            if stamp > 10_000_000_000:
                stamp /= 1000
            parsed = dt.datetime.fromtimestamp(stamp, tz=dt.timezone.utc)
        else:
            text = str(value).strip().replace("Z", "+00:00")
            parsed = dt.datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            parsed = parsed.astimezone(dt.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def _json_documents(text):
    decoder = json.JSONDecoder()
    documents = []
    index = 0
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index == len(text):
            break
        try:
            document, index = decoder.raw_decode(text, index)
        except json.JSONDecodeError as exc:
            raise DashboardError("JSON input is malformed") from exc
        documents.append(document)
    return documents


def _issue_list_from_text(text):
    documents = _json_documents(text)
    issues = []
    for document in documents:
        if isinstance(document, dict) and isinstance(document.get("items"), list):
            document = document["items"]
        if not isinstance(document, list):
            raise DashboardError("account issue input must contain JSON arrays")
        for item in document:
            if isinstance(item, list):
                issues.extend(row for row in item if isinstance(row, dict))
            elif isinstance(item, dict):
                issues.append(item)
    return issues


def _read_json(path, default=None, required=False):
    if path is None or not Path(path).is_file():
        if required:
            raise DashboardError(f"required JSON file is missing: {path}")
        return default
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise DashboardError(f"cannot read JSON file: {path}") from exc


def _load_gh_403():
    """Load scripts/gh_403.py (same checkout) — THE 403 taxonomy (registry #1208). By PATH, not
    `import gh_403`: `scripts/` is not a package. The `build` job takes a FULL checkout, so a
    missing file means someone made it sparse and must be told, not silently degraded to the
    unclassified message this replaces."""
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gh_403.py")
    spec = importlib.util.spec_from_file_location("registry_gh_403_for_dashboard", path)
    if spec is None or spec.loader is None:
        raise DashboardError(
            "cannot load scripts/gh_403.py — if the build job was made sparse, add "
            "scripts/gh_403.py to its sparse-checkout list in dashboard.yml")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gh_403 = _load_gh_403()

_GH_DETAIL_LIMIT = 300
_GH_TOKEN_SHAPE = re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,})\b")


def _gh_failure_suffix(result):
    """`: <class> — <masked stderr>` for a failed `gh` call, or "" when it said nothing.

    WHY. Until now this raised a bare `public account issue query failed` — no exit code, no
    status, no stderr. Measured 2026-07-28/29, dashboard.yml failed 10 times in the window and
    NOT ONE of them is classifiable after the fact.

    THE DEGRADED PATH, KNOWINGLY. `gh` stderr carries no response headers, so this uses
    `classify_403_text` and — per that function's contract — must NOT claim to have read
    `x-ratelimit-remaining`, because it has not. It also establishes the STATUS first, which the
    classifier requires of its caller: without a `(HTTP 403)` marker an unrelated failure whose
    message happens to say "retry later" would be labelled a rate limit."""
    text = " ".join((result.stderr or "").split())
    parts = [f"rc={result.returncode}"]
    if "(HTTP 403)" in text or "HTTP 403" in text:
        parts.append(gh_403.classify_403_text(text) + " (classified from gh stderr; no response "
                     "headers on this path, so no rate-limit count was read)")
    detail = _GH_TOKEN_SHAPE.sub("***", text)
    if len(detail) > _GH_DETAIL_LIMIT:
        detail = detail[:_GH_DETAIL_LIMIT] + "…"
    if detail:
        parts.append(detail)
    return ": " + " — ".join(parts)


def _fetch_issues(repo):
    if not repo or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repo):
        raise DashboardError("REGISTRY_REPO must be an owner/repository name")
    result = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{repo}/issues?state=open&per_page=100"],
        capture_output=True, text=True, timeout=90, check=False)
    if result.returncode != 0:
        raise DashboardError("public account issue query failed" + _gh_failure_suffix(result))
    return _issue_list_from_text(result.stdout)


def _front_matter(body):
    fields = {}
    limits = {}
    for line in (body or "").splitlines():
        if ":" not in line:
            continue
        key, _, raw = line.partition(":")
        key, value = key.strip(), raw.strip()
        if key in {"provider", "models", "secret_ref", "email"}:
            fields[key] = value.strip('"\'')
        elif key == "limits":
            try:
                parts = shlex.split(value)
            except ValueError:
                parts = []
            for part in parts:
                limit_key, separator, limit_value = part.partition("=")
                if (separator and limit_key in {f"{prefix}_limit" for prefix, _ in WINDOWS}
                        and 0 < len(limit_value) <= 80 and limit_value.isprintable()):
                    limits[limit_key] = limit_value
    fields["limits"] = limits
    return fields


def _labels(issue):
    names = set()
    for label in issue.get("labels") or []:
        name = label.get("name") if isinstance(label, dict) else label
        if isinstance(name, str):
            names.add(name.strip().lower())
    return names


def _catalog(issues):
    accounts = []
    private_values = set()
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        handle = str(issue.get("title") or "").strip()
        fields = _front_matter(issue.get("body"))
        provider = str(fields.get("provider") or "").lower()
        models = fields.get("models") or ""
        secret_ref = fields.get("secret_ref") or ""
        if (not handle or SAFE_PROVIDER_RE.fullmatch(provider) is None or not models.startswith("[")
                or ACCOUNT_REF_RE.fullmatch(secret_ref) is None):
            continue
        labels = _labels(issue)
        accounts.append({
            "handle": handle,
            "provider": provider,
            "catalog_available": "status:available" in labels,
            "limits": fields["limits"],
        })
        private_values.add(handle)
        if fields.get("email"):
            private_values.add(fields["email"])
    accounts.sort(key=lambda account: (account["provider"], account["handle"]))
    return accounts, private_values


def _require_salt(salt):
    """Issue #184's fail-closed salt precondition, RETAINED after #374 removed the last
    handle-derived label from the payload. It no longer guards a value this build publishes; it
    guards the ENVIRONMENT. A dashboard that builds happily with PROVENANCE_SALT unset is exactly
    the environment in which a re-added account label would be published unsalted (the pre-#184 bug
    deployed literal `salt-missing` rows, pinning a public row to a single account with no salt at
    all). One string check, and the whole build dies rather than proceeding unsalted."""
    if not isinstance(salt, str) or not salt.strip() or not salt.isprintable():
        raise DashboardError(
            "the dashboard build requires a non-empty printable PROVENANCE_SALT (issue #184)")


def _percent(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not (number >= 0) or number == float("inf"):
        return None
    return round(number * 100, 1)


def _availability(account, usage_entry):
    if not account["catalog_available"]:
        return "unavailable"
    if not isinstance(usage_entry, dict) or not usage_entry:
        # NO measurement exists for this account (issue #219). account-usage.py fail-closed OMITS an
        # account whose token is missing or whose probe failed, and a wholly failed probe publishes
        # an EMPTY map — so this branch is exactly the "measurement did not happen" case. It used to
        # return "available", which is why a failed probe rendered the entire catalog as fresh
        # usable capacity. Dispatch (select-and-claim.usage_eligible) treats the omission as
        # INELIGIBLE, so the honest public label is "unknown", never "available".
        return "unknown"
    status = str(usage_entry.get("status") or "").strip().lower()
    if status not in {"", "allowed"}:
        return "unavailable"
    known = [_percent(usage_entry.get(f"{prefix}_util")) for prefix, _ in WINDOWS]
    if any(value is not None and value >= 100 for value in known):
        return "capped"
    return "available"


_SELECT_AND_CLAIM_MODULE = None


def _select_and_claim_module():
    """Load scripts/select-and-claim.py (hyphenated name — importlib, the _model_health_module
    pattern) so the ALLOCATOR'S backoff-stamp parsing semantics are SHARED, not re-implemented
    here where they would drift (sol finding 3, PR #281 fix round)."""
    global _SELECT_AND_CLAIM_MODULE
    if _SELECT_AND_CLAIM_MODULE is None:
        path = Path(__file__).resolve().with_name("select-and-claim.py")
        spec = importlib.util.spec_from_file_location("registry_select_and_claim", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _SELECT_AND_CLAIM_MODULE = module
    return _SELECT_AND_CLAIM_MODULE


def _backoff_epoch(value):
    """A backoff_until stamp parsed with the ALLOCATOR'S semantics, or None (fail open):
    select-and-claim.usage_eligible admits the stamp iff `_usage_num` parses it AND it is
    finite. This dashboard used to diverge both ways — it accepted Infinity/absurd integers
    (rendering "capped indefinitely" while the allocator failed open and kept using the
    account) and ignored parseable string epochs (rendering "available" while the allocator
    backed off). The self-test's parity vector locks the two scripts to one predicate."""
    number = _select_and_claim_module()._usage_num(value)
    if number is None or not math.isfinite(number):
        return None
    return number


def _quota_state(account, entry, now):
    """Availability for the CUMULATIVE provider view AND (since issue #219) for the per-account
    cards + `fleet.capacity.eligible`, so one predicate decides every "is this capacity usable"
    claim on the public page: the per-account state from _availability — where (a) a
    catalog-available account with NO usage entry is already "unknown", because the probe
    fail-closed OMITS an account whose token is missing or whose probe failed and dispatch
    (select-and-claim.usage_eligible) plus usage-alert treat that omission as UNAVAILABLE, so
    counting it free would advertise quota the allocator will never use (sol finding 2, PR #281
    fix round) — refined so that (b) a probe-exempt account under an ACTIVE reactive
    backoff (its only quota signal — issue #29) counts as capped until the backoff expires,
    with the stamp parsed by the allocator's shared `_backoff_epoch` semantics; and (c) a
    non-exempt account counts "available" only with BOTH mandatory windows (5h AND 7d) validly
    reported — account-usage.py can emit a PARTIAL entry (status-only, or one window without
    the other), and dispatch (usage_eligible: `util is None` → ineligible) plus usage-alert
    (classify: `u5 is None or u7 is None` → UNAVAILABLE) both fail closed on that shape, so
    rendering it free would again advertise quota the allocator will never use (sol finding 1,
    PR #281 fix round 3); partial ⇒ "unknown". Returns (state, backoff_epoch_or_None).
    Pure — unit-tested by --self-test."""
    if not isinstance(entry, dict) or not entry:
        # No measurement at all. _availability already answers "unknown"/"unavailable" here; the
        # restatement keeps this function TOTAL (every dict access below is unreachable on a
        # non-dict) rather than resting on a caller-invisible coupling to that branch.
        return _availability(account, entry), None
    availability = _availability(account, entry)
    if availability != "available":
        return availability, None
    if entry.get("exempt") is True:
        # [registry #639] Exemption skips the QUOTA probe; it never asserts reachability. The page
        # must not publish as capacity what dispatch refuses to use, in EITHER direction (sol finding
        # 2, PR #281), so the same allowlist the allocator applies decides here: a credential the
        # health record proves dead is `unavailable` (a rejected credential, exactly like a non-allowed
        # probe status), and an entry that states no reachability at all is `unknown` (the producer did
        # not evaluate it — no measurement to publish), never `available`.
        reachability = entry.get("reachability")
        if reachability == _select_and_claim_module().USAGE_REACHABILITY_DEAD:
            return "unavailable", None
        if not isinstance(reachability, str) or \
                reachability not in _select_and_claim_module().USAGE_REACHABILITY_ADMITTED:
            return "unknown", None
        until = _backoff_epoch(entry.get("backoff_until"))
        if until is not None and until > now:
            return "capped", until
        return "available", None
    if any(_percent(entry.get(f"{prefix}_util")) is None for prefix in ("5h", "7d")):
        return "unknown", None
    return "available", None


def _quota_probe_signal(probe):
    """The provider-row `signal` for a snapshot the probe verdict DISTRUSTED (issue #628).

    When `_probe_outcome` says the snapshot was not measured, build_dashboard discards the usage
    map, so every provider row used to fall through to the "no live usage signal (catalog
    availability only)" wording — the SAME string a provider that genuinely exposes no usage
    headers emits, and one that still implies catalog availability is the signal (it is
    deliberately not counted as free any more). The reason word tracks the normalized outcome so
    "the probe reported a failure", "the last success is too old" and "no usable sidecar exists"
    stay distinguishable on the row itself. Pure — unit-tested by --self-test."""
    outcome = probe.get("outcome") if isinstance(probe, dict) else None
    if outcome == "failed":
        reason = "usage probe failed"
    elif outcome == "ok":
        # `ok` but not measured can only mean the freshness check rejected the stamp.
        reason = "usage probe is stale"
    else:
        reason = "usage probe outcome is unknown"
    return (f"{reason} — no measurement for this snapshot "
            "(catalog availability is not counted as free)")


def _provider_quota(accounts, usage, now, probe=None):
    """Per-provider CUMULATIVE quota rows (maintainer request 2026-07-18): where a provider has
    several accounts, the AGGREGATE headroom across them; single-account providers still emit a
    row, marked `single_account`. HONEST aggregation of the signals that actually exist — no
    invented precision:

    * Probed (anthropic) accounts expose per-window utilization FRACTIONS (plus a raw unit-less
      `*-limit` header value when the provider sends one), so the aggregate unit is
      "account-windows free": Σ over reporting accounts of that account's remaining window
      fraction (a provider with 2.4 of 3 account-windows free has, e.g., one fresh account, one
      at 60% and one capped). `limit_remaining` additionally sums limit×remaining, but ONLY over
      the accounts whose limit header is known — `limits_known`/`accounts_reporting` says how
      partial that sum is, and its unit is whatever the provider's opaque limit header means.
    * Probe-exempt providers (openai) have NO usage observability at all (issue #29): the row
      aggregates only the availability trichotomy + active reactive backoffs, and `signal` says
      so — `windows` stays empty rather than fabricating a remaining-quota number.

    Accounts fail-closed omitted from the usage snapshot count in `accounts_total` and in
    `accounts_unknown` ("unreported" — dispatch treats the omission as unavailable, so they are
    NEVER counted free), and never in `accounts_reporting`. The same holds for PARTIAL probe
    entries (quota state "unknown"): the whole account is excluded from the aggregation — its
    parseable window contributes NOTHING to the window sums, `limit_remaining`/`limits_known`,
    or the reset stamps (sol finding, PR #281 fix round 4: a 5h-only entry used to render
    "accounts_unknown: 1" NEXT TO headroom summed from that very account). The exclusion is
    keyed off the SAME `_quota_state` result as the counts — one source of truth, no
    re-derivation. `soonest_reset`/`oldest_reset` span
    every known window-reset/backoff stamp for the provider: soonest = the first moment ANY
    quota refills, oldest = when the last known window has refilled. Pure — unit-tested by
    --self-test; rows carry provider names + counts only (decision 22: no account identifiers,
    salted or otherwise, on this surface).

    `probe` is the normalized probe verdict (`_probe_outcome`) for the snapshot, when the caller
    has one. It changes NO count — the counts already fail closed on the empty map build_dashboard
    hands over — only the `signal` label, which must name the broken probe instead of borrowing the
    "this provider exposes no usage headers" wording (issue #628). A distrusted verdict takes
    precedence over the probed/exempt derivation below, because both of those are read out of the
    very snapshot the verdict rejected: the row must never claim a live measurement it cannot back.

    These rows are INTERNAL as of issue #374. The counts below are the source of truth for the
    capacity decision and are asserted in both directions by the suite, but they are never
    published: build_dashboard emits `_public_provider_quota(_provider_quota(...))`, which keeps the
    operational answer and drops every field that reads out the fleet's size."""
    # #628: `probe=None` means "the caller stated nothing about the probe" and leaves the labels
    # exactly as they were; any verdict that is not an explicit measurement distrusts the snapshot.
    distrusted = probe is not None and not (isinstance(probe, dict) and probe.get("measured") is True)
    groups = {}
    for account in accounts:
        groups.setdefault(account["provider"], []).append(account)
    rows = []
    for provider in sorted(groups):
        members = groups[provider]
        counts = {"available": 0, "capped": 0, "unavailable": 0, "unknown": 0}
        probed = exempt = False
        stats = {prefix: {"reporting": 0, "remaining": 0.0, "limits_known": 0,
                          "limit_remaining": 0.0, "resets": []}
                 for prefix, _ in WINDOWS}
        provider_resets = []
        for account in members:
            entry = usage.get(account["handle"])
            state, backoff_until = _quota_state(account, entry, now)
            counts[state] += 1
            backoff_iso = _utc_iso(backoff_until)
            if backoff_iso:
                provider_resets.append(backoff_iso)
            if not isinstance(entry, dict):
                continue
            if entry.get("exempt") is True:
                exempt = True
            elif entry:
                probed = True
            if state == "unknown":
                # An "unknown" account (PARTIAL probe entry — e.g. 5h-only) contributes NOTHING
                # to the aggregate (sol finding, PR #281 fix round 4): its parseable window used
                # to leak into the sums, rendering "accounts_unknown: 1" next to account-window
                # headroom from that same account. Keyed off the _quota_state result above —
                # the single source of truth the counts already use, not a re-derivation.
                continue
            for prefix, _name in WINDOWS:
                used = _percent(entry.get(f"{prefix}_util"))
                if used is None:
                    continue
                window = stats[prefix]
                window["reporting"] += 1
                remaining = max(0.0, 100.0 - used) / 100.0
                window["remaining"] += remaining
                limit = entry.get(f"{prefix}_limit")
                if limit is None:
                    limit = account["limits"].get(f"{prefix}_limit")
                try:
                    limit_number = float(limit)
                except (TypeError, ValueError, OverflowError):
                    # OverflowError (sol finding 2, PR #281 fix round 3): a huge-int limit
                    # (10**400) is valid JSON but float() of it RAISES rather than returning
                    # inf — same trap select-and-claim._usage_num already guards.
                    limit_number = None
                if limit_number is not None and math.isfinite(limit_number) and limit_number >= 0:
                    # Individually-finite limits can still overflow the WEIGHTED SUM (two
                    # "1e308" limits are each finite but their sum is inf), and round(inf) at
                    # render would crash the whole dashboard build on one malformed account
                    # record (sol finding 2, PR #281 fix round 3). Validate the product AND
                    # the running sum; on overflow, reject THIS account's limit contribution
                    # (its limit stays unknown — not in limits_known) and keep the build alive.
                    product = limit_number * remaining
                    if math.isfinite(product) and math.isfinite(window["limit_remaining"] + product):
                        window["limits_known"] += 1
                        window["limit_remaining"] += product
                # _utc_iso emits a fixed-width "...Z" format, so lexicographic min/max below is
                # chronological.
                reset_iso = _utc_iso(entry.get(f"{prefix}_reset"))
                if reset_iso:
                    window["resets"].append(reset_iso)
                    provider_resets.append(reset_iso)
        windows = []
        for prefix, name in WINDOWS:
            window = stats[prefix]
            if not window["reporting"]:
                continue  # nothing measured for this window (e.g. fable on a non-fable provider)
            windows.append({
                "name": name,
                "accounts_reporting": window["reporting"],
                "remaining_account_windows": round(window["remaining"], 2),
                "limit_remaining": round(window["limit_remaining"])
                if window["limits_known"] else None,
                "limits_known": window["limits_known"],
                "soonest_reset": min(window["resets"], default=None),
                "oldest_reset": max(window["resets"], default=None),
            })
        if distrusted:
            signal = _quota_probe_signal(probe)
        elif probed and exempt:
            signal = "mixed: live rate-limit-header probe + probe-exempt accounts"
        elif probed:
            signal = "live rate-limit-header probe (per-window utilization)"
        elif exempt:
            signal = ("not observable (probe-exempt provider): catalog availability "
                      "+ reactive rate-limit backoff only")
        else:
            signal = "no live usage signal (catalog availability only)"
        rows.append({
            "provider": provider,
            "accounts_total": len(members),
            "accounts_available": counts["available"],
            "accounts_capped": counts["capped"],
            "accounts_unavailable": counts["unavailable"],
            "accounts_unknown": counts["unknown"],
            "single_account": len(members) == 1,
            "signal": signal,
            "windows": windows,
            "soonest_reset": min(provider_resets, default=None),
            "oldest_reset": max(provider_resets, default=None),
        })
    return rows


def _provider_headroom(row):
    """The cardinality-free replacement for a provider row's five-number account census (#374):
    WHETHER this provider has usable headroom right now and, when it does not, why. A strict
    function of the same counts `fleet.capacity` and the allocator key off — so the page still
    cannot advertise capacity dispatch would refuse — but four words instead of a fleet census.
    Precedence is "can we dispatch?" first, then the most actionable reason: capped refills at
    `soonest_reset`, unknown means the probe told us nothing, unavailable means the catalog or a
    dead credential took the provider out."""
    if row["accounts_available"]:
        return "available"
    if row["accounts_capped"]:
        return "capped"
    if row["accounts_unknown"]:
        return "unknown"
    return "unavailable"


def _public_provider_quota(rows):
    """Project the internal provider rows onto the published payload (#374).

    Dropped outright: accounts_total/available/capped/unavailable/unknown, single_account,
    accounts_reporting, limit_remaining, limits_known. Every one is either a count of accounts or
    a sum whose magnitude scales with the number of accounts (`limit_remaining` is Σ limit×remaining
    over reporting accounts, so a publicly-known plan limit divides straight back out to a fleet
    size). `remaining_account_windows` was itself Σ of per-account fractions and therefore bounded
    ABOVE by the fleet size — 2.4 said "at least 3 accounts" out loud — so it is published as the
    MEAN remaining fraction instead: same headroom reading, invariant under cloning the fleet."""
    public = []
    for row in rows:
        windows = []
        for window in row["windows"]:
            reporting = window["accounts_reporting"]
            if reporting <= 0:
                continue    # _provider_quota never emits one; never divide by it if it ever does
            windows.append({
                "name": window["name"],
                "remaining_fraction": round(
                    window["remaining_account_windows"] / reporting, 2),
                "soonest_reset": window["soonest_reset"],
                "oldest_reset": window["oldest_reset"],
            })
        public.append({
            "provider": row["provider"],
            "headroom": _provider_headroom(row),
            "signal": row["signal"],
            "windows": windows,
            "soonest_reset": row["soonest_reset"],
            "oldest_reset": row["oldest_reset"],
        })
    return public


def _public_capacity(capacity):
    """fleet.capacity, cardinality-free (#374): per provider, WHETHER the allocator would find an
    eligible account right now — not how many eligible out of how many held."""
    return {provider: values["eligible"] > 0 for provider, values in capacity.items()}


def _assert_no_fleet_composition(document):
    """Fail-closed backstop over the FINISHED public document (#374) — the composition twin of
    _assert_private. Every name in FLEET_COMPOSITION_KEYS was, until this change, a published read
    of the fleet's size or of one identified account; `accounts` and `label` additionally catch a
    re-introduced per-account row array (the shape both the account cards and the observability
    lease rows used). Refusing the build is the point: the projection above is easy to bypass by
    adding one key to the document literal, and a public-surface regression that only prose forbids
    is a regression waiting to happen."""
    found = set()

    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in FLEET_COMPOSITION_KEYS:
                    found.add(key)
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(document)
    if found:
        raise DashboardError(
            "fleet-composition assertion failed: the public dashboard payload may not disclose "
            f"{sorted(found)} (issue #374)")


# --- WIRING ASSERTIONS: reading the workflow / the page script without letting a comment or a
# neighbouring occurrence stand in for the call site under test. ------------------------------------
#
# #612 cross-provider review round 2 (class E). A mutation harness found that 18/18 mutations
# against this repo's PYTHON guards were caught while EVERY surviving mutation was a workflow `if:`,
# a workflow step body, or a production call site. Concretely, on this PR: dropping the `!` from the
# probe step's snapshot condition, replacing the materialization step's body with `true`, deleting
# `probe_status=probe_status` from `main()`, and deleting `summary.append(probe)` /
# `updateFreshness(..., data.usage_probe)` from the page script all left the suite green. These
# helpers exist so the assertions below are scoped to ONE step or ONE function — a whole-file
# substring search is satisfiable by prose or by any of several other occurrences — and so the
# probe step's shell body can be EXECUTED rather than pattern-matched (`bash -n` and actionlint
# cannot see polarity). Every helper raises DashboardError when it cannot resolve its target: a
# wiring assertion that cannot find what it is asserting about must fail, never pass vacuously.
def _repo_file(*parts):
    """Text of a repository file addressed relative to the repo root, independent of cwd.

    Used both by the wiring assertions below and, since issue #78, by the BUILD itself to read the
    worker policy the per-repository census seeds its rows from — hence the neutral message: either
    caller must fail loudly when the file is not there, never continue on a default."""
    path = Path(__file__).resolve().parent.parent.joinpath(*parts)
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DashboardError(f"cannot read the repository file {path}") from exc


def _strip_yaml_comments(text):
    """`text` with every whole-line `#` comment removed (YAML comments and, inside `run:` blocks,
    shell/python comments alike). A claim in prose must never satisfy an assertion about code."""
    return "\n".join(line for line in text.split("\n") if not line.lstrip().startswith("#"))


def _cron_minutes(expression):
    """The set of minutes-past-the-hour one `on: schedule:` cron fires at.

    Only pure minute-field schedules are expressible; any other field carrying a value is a
    REFUSAL. A cadence this reader silently mis-derives would make the #680 threshold bound it
    feeds satisfiable by any threshold at all, so it must fail rather than guess."""
    fields = expression.split()
    if len(fields) != 5 or any(field != "*" for field in fields[1:]):
        raise DashboardError(
            f"cron {expression!r} is not a pure minute-field schedule — refusing to derive a "
            "nominal cadence from it (fail closed)")
    minutes = set()
    for term in fields[0].split(","):
        base, _, raw_step = term.partition("/")
        if raw_step:
            if not raw_step.isdigit() or int(raw_step) < 1:
                raise DashboardError(f"cron {expression!r}: unreadable step in {term!r} — refusing")
            step = int(raw_step)
        else:
            step = 1
        if base == "*":
            low, high = 0, 59
        else:
            low_text, dash, high_text = base.partition("-")
            high_text = high_text if dash else low_text
            if not (low_text.isdigit() and high_text.isdigit()):
                raise DashboardError(
                    f"cron {expression!r}: unreadable minute term {term!r} — refusing")
            low, high = int(low_text), int(high_text)
        if not 0 <= low <= high <= 59:
            raise DashboardError(
                f"cron {expression!r}: minute term {term!r} out of range — refusing")
        minutes.update(range(low, high + 1, step))
    if not minutes:
        # Unreachable under the grammar above (an accepted term always has low <= high, so it
        # contributes at least one minute) and kept as the structural backstop for a future term
        # form that does not: an empty firing set would otherwise reach the wrap-around gap in
        # _cron_cadence_seconds as an IndexError rather than as a named refusal.
        raise DashboardError(f"cron {expression!r} fires at no minute at all — refusing")
    return minutes


def _cron_cadence_seconds(*expressions):
    """The NOMINAL gap, in seconds, between consecutive fires of a set of hourly crons.

    The WIDEST gap in the union of their firing minutes (the wrap-around gap from the last minute
    of one hour to the first of the next included) — that is the interval a keepalive threshold has
    to clear, so the widest is the only safe reading."""
    if not expressions:
        raise DashboardError("no cron expression supplied — refusing to invent a cadence")
    minutes = set()
    for expression in expressions:
        minutes.update(_cron_minutes(expression))
    fires = sorted(minutes)
    gaps = [later - earlier for earlier, later in zip(fires, fires[1:])]
    gaps.append(fires[0] + 60 - fires[-1])
    return max(gaps) * 60


def _schedule_cadence_seconds(text, label):
    """The nominal cadence of one workflow YAML's `on: schedule:` block.

    Split from the file read below purely so its two refusal branches are reachable from the
    self-test: a refusal nothing ever executes is a refusal nothing has checked. The scan is
    bounded to the top-level `on:` block, so a `cron:` in prose or in some other mapping cannot
    supply the cadence a keepalive threshold is then sized against."""
    lines = _strip_yaml_comments(text).split("\n")
    heads = [index for index, line in enumerate(lines) if line.rstrip() == "on:"]
    if len(heads) != 1:
        raise DashboardError(
            f"{label} has {len(heads)} top-level `on:` blocks, expected exactly 1 — refusing")
    end = len(lines)
    for index in range(heads[0] + 1, len(lines)):
        if lines[index].strip() and not lines[index][:1].isspace():
            end = index
            break
    crons = re.findall(r"^\s*-\s*cron:\s*['\"]?([^'\"\n]+?)['\"]?\s*$",
                       "\n".join(lines[heads[0]:end]), re.MULTILINE)
    if not crons:
        raise DashboardError(
            f"{label} declares no `on: schedule:` cron — refusing to size a keepalive threshold "
            "against a workflow that has no schedule for the keepalive to be a fallback to")
    return _cron_cadence_seconds(*crons)


def _workflow_cadence_seconds(workflow):
    """The nominal cadence of `.github/workflows/<workflow>`, read out of THAT file's own
    `on: schedule:` block.

    Never restated here: the whole point of the #680 bound is that a re-timed cron and the
    keepalive threshold sized against it cannot drift apart silently."""
    return _schedule_cadence_seconds(_repo_file(".github", "workflows", workflow), workflow)


def _workflow_step(text, step_id):
    """The full YAML text of the ONE step whose `id:` is `step_id`, comments stripped.

    Bounded by the enclosing `- ` sequence entry's indentation, so a call in a NEIGHBOURING step
    cannot satisfy an assertion about this one."""
    lines = text.split("\n")
    marks = [index for index, line in enumerate(lines) if line.strip() == f"id: {step_id}"]
    if len(marks) != 1:
        raise DashboardError(
            f"expected exactly one workflow step with `id: {step_id}`, found {len(marks)} — "
            "refusing to assert against a step that cannot be located (fail closed)")
    starts = [index for index in range(marks[0], -1, -1) if lines[index].lstrip().startswith("- ")]
    if not starts:
        raise DashboardError(f"step `id: {step_id}` has no enclosing `- ` sequence entry — refusing")
    start = starts[0]
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if not line.strip():
            continue
        here = len(line) - len(line.lstrip())
        if here < indent or (here == indent and line.lstrip().startswith("- ")):
            end = index
            break
    body = _strip_yaml_comments("\n".join(lines[start:end]))
    if not body.strip():
        raise DashboardError(f"step `id: {step_id}` extracted to an empty body — refusing")
    return body


def _workflow_step_block(text, step_id, key):
    """The dedented block-scalar value of `<key>: |` inside the step whose `id:` is `step_id`.

    Raises when the step has no such block or the block is empty — a step body that cannot be
    recovered must not silently become a no-op the harness then 'passes'."""
    lines = _workflow_step(text, step_id).split("\n")
    wanted = {f"{key}: |", f"{key}: |-"}
    starts = [index for index, line in enumerate(lines) if line.strip() in wanted]
    if len(starts) != 1:
        raise DashboardError(
            f"step `id: {step_id}` has {len(starts)} block `{key}:` values, expected exactly 1")
    head = starts[0]
    indent = len(lines[head]) - len(lines[head].lstrip())
    body = []
    for line in lines[head + 1:]:
        if line.strip() and (len(line) - len(line.lstrip())) <= indent:
            break
        body.append(line[indent + 2:] if line.strip() else "")
    value = "\n".join(body)
    if not value.strip():
        raise DashboardError(
            f"step `id: {step_id}` extracted to an empty `{key}:` block — refusing")
    return value


def _workflow_step_script(text, step_id):
    """The EXECUTABLE `run:` script of the step whose `id:` is `step_id`, dedented.

    Comments are NOT kept — this text comes through _workflow_step, which strips them (the round-4
    correction of an earlier docstring that claimed otherwise). That is harmless for execution and
    is the point for pattern-matching, so the two uses share one extractor."""
    return _workflow_step_block(text, step_id, "run")


def _workflow_step_env(text, step_id):
    """The `env:` mapping of the step whose `id:` is `step_id`, as {NAME: raw expression text}.

    #612 review round 4: deleting `SECRETS_STEP_OUTCOME: ${{ steps.acct-secrets.outcome }}` from the
    probe step survived the suite, because the executed body reads the variable from the process
    environment the HARNESS supplies — execution can never see a missing workflow-level wiring. A
    mapping (rather than a substring search) is what makes "this step defines this variable, from
    that step's outcome" falsifiable, and resolving the step id it names is what stops the wiring
    from pointing at a step that no longer exists."""
    lines = _workflow_step(text, step_id).split("\n")
    heads = [index for index, line in enumerate(lines) if line.strip() == "env:"]
    if len(heads) != 1:
        raise DashboardError(
            f"step `id: {step_id}` has {len(heads)} `env:` mappings, expected exactly 1")
    head = heads[0]
    indent = len(lines[head]) - len(lines[head].lstrip())
    mapping = {}
    for line in lines[head + 1:]:
        if not line.strip():
            continue
        if (len(line) - len(line.lstrip())) <= indent:
            break
        name, separator, value = line.strip().partition(":")
        if separator:
            mapping[name.strip()] = value.strip()
    if not mapping:
        raise DashboardError(f"step `id: {step_id}` has an empty `env:` mapping — refusing")
    return mapping


def _js_function_body(text, name):
    """The brace-matched body of `function <name>(...)` in a JS source, or raise.

    Scoping a call-site assertion to ONE function is the difference between "this file mentions
    updateFreshness" and "render() passes the probe to it": `grant-account.py` appears 7× in its
    own workflow, and whole-file greps on repeated tokens are exactly the vacuity #612 round 2
    flagged."""
    marks = [match.start() for match in re.finditer(rf"\bfunction\s+{re.escape(name)}\s*\(", text)]
    if len(marks) != 1:
        raise DashboardError(
            f"expected exactly one `function {name}(` definition, found {len(marks)} — refusing")
    open_brace = text.find("{", marks[0])
    if open_brace < 0:
        raise DashboardError(f"`function {name}(` has no body — refusing")
    depth, index = 0, open_brace
    while index < len(text):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace:index + 1]
        index += 1
    raise DashboardError(f"`function {name}(` body is unbalanced — refusing")


def _js_code_count(text, needle):
    """Occurrences of `needle` at CODE positions of `text`: comments are blanked out first, and a
    match that BEGINS inside a string/template literal does not count.

    #612 review round 4 (MINOR, class E): the round-3 UI assertions were satisfiable by a COMMENT —
    commenting out `summary.append(probe)` kept the suite green while the operator warning was gone —
    and by any string literal that happened to contain the needle. Counting only code positions
    closes both, and asserting an exact COUNT (rather than presence) is what stops a neighbouring
    branch's occurrence from standing in for the one under test."""
    chars = list(text)
    in_string = [False] * len(text)
    index, quote, comment = 0, None, None
    while index < len(text):
        char, pair = text[index], text[index:index + 2]
        if comment == "line":
            if char == "\n":
                comment = None
            else:
                chars[index] = " "
            index += 1
        elif comment == "block":
            if pair == "*/":
                chars[index] = chars[index + 1] = " "
                comment = None
                index += 2
                continue
            if char != "\n":
                chars[index] = " "
            index += 1
        elif quote:
            in_string[index] = True
            if char == "\\":
                if index + 1 < len(text):
                    in_string[index + 1] = True
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
        elif pair == "//":
            comment = "line"
        elif pair == "/*":
            comment = "block"
        elif char in "\"'`":
            quote, in_string[index] = char, True
            index += 1
        else:
            index += 1
    code = "".join(chars)
    hits, at = 0, code.find(needle)
    while at >= 0:
        if not in_string[at]:
            hits += 1
        at = code.find(needle, at + 1)
    return hits


def _node_json(script, payload):
    """Run `script` under `node` with `payload` on stdin and parse its stdout as JSON, or raise.

    #612 review round 4: the page's consumption of the probe marker was asserted LEXICALLY, so
    flipping `if (!measured)` to `if (measured)` survived. `node` is present on every runner this
    suite runs on (ubuntu-latest, and the worker image copies it in), so the two call sites are
    EXECUTED instead — and a missing interpreter fails the suite loudly rather than skipping a
    check, which would be the same false pass in a different costume."""
    try:
        completed = subprocess.run(["node", "-e", script], input=json.dumps(payload),
                                   capture_output=True, text=True, timeout=120, check=False)
    except OSError as exc:
        raise DashboardError(
            "`node` is required to EXECUTE the dashboard page's probe call sites — refusing to "
            f"skip that assertion ({exc})") from exc
    if completed.returncode != 0:
        raise DashboardError(
            f"the page-script harness exited {completed.returncode}: {completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise DashboardError(
            f"the page-script harness printed no parseable result: {completed.stdout!r}") from exc


def _probe_epoch(value):
    """`value` as a UTC epoch second, reusing _utc_iso's tolerant epoch/ISO parsing, or None."""
    iso = _utc_iso(value)
    if iso is None:
        return None
    return dt.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def _probe_outcome(document, now):
    """Normalize the probe job's persisted outcome sidecar, FAIL-CLOSED (issue #219).

    `measured` is True ONLY for an explicit, correctly-schema'd `ok` outcome with a fresh
    attempt stamp. Every other shape — a `failed` outcome, an absent/empty/alien document, an
    unparseable or missing stamp, a stamp older than PROBE_MAX_AGE_SECONDS or implausibly far in
    the future — is "we did not measure", and build_dashboard then refuses to publish ANY account
    as usable capacity on the strength of a snapshot nobody produced. Pure — unit-tested by
    --self-test.

    `None` (no sidecar supplied at all) is the WEAKEST evidence of the lot and normalizes to the
    same unmeasured verdict as `{}` — #612 review finding 1: treating it as measured was a
    fail-open branch inside the capacity decision itself."""
    outcome, detail, attempted = "unknown", "probe outcome was not persisted", None
    if isinstance(document, dict) and document.get("schema") == PROBE_SCHEMA:
        raw = str(document.get("outcome") or "").strip().lower()
        outcome = raw if raw in {"ok", "failed"} else "unknown"
        # `detail` reaches the PUBLIC page and arrives from another job's artifact, so it is held
        # to the same bounded safe-token shape this generator uses for every externally-sourced
        # label — never published as free text.
        text = str(document.get("detail") or "").strip()
        detail = text if OBS_TOKEN_RE.fullmatch(text) else ""
        attempted = _probe_epoch(document.get("attempted_at"))
    # #612 review round 4 (MINOR): the freshness comparison runs on the EXACT age, not on a
    # truncated one — `int()` rounds toward zero, so an attempt 3600.9s old (or 300.9s in the
    # future) used to compare as 3600/-300 and stay `measured` at the nominal limit. Production
    # writes integer epochs (`date -u +%s`) so nothing was mismeasured in practice, but the
    # predicate now implements the boundary it documents. The PUBLISHED age stays an integer.
    exact_age = (now - attempted) if attempted is not None else None
    age = int(exact_age) if exact_age is not None else None
    stale = (exact_age is None or exact_age > PROBE_MAX_AGE_SECONDS
             or exact_age < -PROBE_MAX_SKEW_SECONDS)
    return {
        "outcome": outcome,
        "detail": detail,
        "attempted_at": _utc_iso(attempted),
        "age_seconds": age,
        "stale": stale,
        "measured": outcome == "ok" and not stale,
    }


def _dispatch_lane_state(planned, launched, error):
    """The DISPLAY tone for one lane's tick: ok | idle | stalled (the vocabulary the page's
    existing `.lane-dot` states already use).

    Deliberately WIDER than the ALERTING predicate, which lives in the tick-health step of
    `.github/workflows/dispatch.yml` and is the authority — it pages on a `disarm` error, or on a
    review/fix lane that planned work, launched nothing AND hit hard errors. Both of those are
    strict subsets of `error > 0 or (planned > 0 and launched == 0)`, so every lane the alert fires
    on is shown red here, and a lane merely held by capacity contention (planned, launched some,
    deferred the rest) still reads `ok`. The containment direction is the safety property: widening
    this can only over-report, narrowing it could hide a lane the alert is paging on, so it must
    never be tightened toward the workflow's predicate (the self-test pins the containment)."""
    if error > 0 or (planned > 0 and launched == 0):
        return "stalled"
    return "idle" if planned == 0 else "ok"


def _dispatch_lane_rows(log_text):
    """Per-lane tick counts (issues #108/#323) for ONE dispatch run, or None when the run printed
    none (a claim that aborted before the dispatcher finished, or a pre-#108 run).

    Read ONLY from the block after the LAST `dispatcher complete:` line. dispatch-claim prints the
    lane block immediately after that line, so the block is the dispatcher's own trusted output —
    while everything before it is a whole run's log, into which target-controlled text (an issue
    title, a rejected plan row) is echoed. Every line of a raw Actions log carries a timestamp
    prefix, so `^\\S+\\s+` alone does not make a line the dispatcher's; anchoring to the block is
    what stops an echoed string from FABRICATING a lane row (AGENTS.md pre-flight item 5: who can
    write the thing this reads?). No complete line => no lanes, rather than a scan of the log.

    The block is validated as a WHOLE, and a partial one is refused rather than trimmed (review
    round 1): the rows must be CONTIGUOUS between the `fix-dispatch:` header and the
    `defer attribution:` terminator, each must parse, none may repeat, DISPATCH_REQUIRED_LANES must
    all be present IN THAT ORDER (review round 2 — the dispatcher iterates one fixed tuple, so a
    complete-but-permuted block is one it could not have printed; unknown lanes are exempt and may
    sit anywhere), and the block may not exceed DISPATCH_LANE_CAP rows. Publishing the survivors of
    a truncated or malformed block renders the vanished lane as absent rather than unknown — which
    is exactly how a stalled review/fix lane or a failed disarm would disappear from the one cell
    built to show it — so every one of those shapes returns None and the page shows `—`. Trailing
    output cannot reach the rows either: the scan STOPS at the terminator, so a lane line echoed
    after the block cannot overwrite the dispatcher's own count for that lane."""
    complete = list(DISPATCH_COMPLETE_RE.finditer(log_text))
    if not complete:
        return None
    # `[1:]` drops the remainder of the completion line itself; last block wins, matching the
    # `complete[-1]` rule above for a log that carries more than one dispatcher run.
    lines = log_text[complete[-1].end():].splitlines()[1:]
    if not lines or not DISPATCH_FIX_LINE_RE.match(lines[0]):
        return None
    rows = {}
    for line in lines[1:]:
        if DISPATCH_LANE_END_RE.match(line):
            # Presence AND order in one comparison: `rows` keeps the block's own order, so the
            # required lanes read out of it — extra lanes dropped, they are exempt — must be the
            # authoritative tuple exactly. A short list is a missing lane, a permuted one is a
            # block the dispatcher's single loop cannot have printed; both are unknown.
            if [lane for lane in rows if lane in DISPATCH_REQUIRED_LANES] != list(
                    DISPATCH_REQUIRED_LANES):
                return None
            return list(rows.values())
        match = DISPATCH_LANE_RE.match(line)
        if match is None or match.group("lane") in rows or len(rows) >= DISPATCH_LANE_CAP:
            return None
        planned, launched, error = (int(match.group(key))
                                    for key in ("planned", "launched", "error"))
        # `deferred` is READ from the line, not re-derived: dispatch-claim derives it there
        # (planned-launched-error, clamped) and re-deriving it here would republish this build's
        # arithmetic as if it were the dispatcher's count.
        rows[match.group("lane")] = {
            "lane": match.group("lane"), "planned": planned, "launched": launched,
            "deferred": int(match.group("deferred")), "error": error,
            "state": _dispatch_lane_state(planned, launched, error)}
    return None   # ran off the end of the log: the block was truncated, so nothing is known


def _parse_dispatch_log(log_text):
    complete = DISPATCH_COMPLETE_RE.findall(log_text)
    dispatched = int(complete[-1]) if complete else len(DISPATCHED_RE.findall(log_text))
    deferred = len(DEFERRED_RE.findall(log_text))
    return dispatched, deferred, _dispatch_lane_rows(log_text)


def _run_log_counts(repo, run_id):
    result = subprocess.run(
        ["gh", "api", f"repos/{repo}/actions/runs/{run_id}/logs"],
        capture_output=True, timeout=60, check=False)
    if result.returncode != 0:
        return None, None, None
    try:
        with zipfile.ZipFile(io.BytesIO(result.stdout)) as archive:
            names = [name for name in archive.namelist()
                     if "/" in name and "Strictly validate" in name and name.endswith(".txt")]
            if not names:
                return None, None, None
            log_text = "\n".join(
                archive.read(name).decode("utf-8", errors="replace") for name in names)
    except (OSError, zipfile.BadZipFile):
        return None, None, None
    return _parse_dispatch_log(log_text)


def _fetch_dispatch_history(repo, count):
    result = subprocess.run(
        ["gh", "api", f"repos/{repo}/actions/workflows/dispatch.yml/runs?per_page={count}"],
        capture_output=True, text=True, timeout=60, check=False)
    if result.returncode != 0:
        return []
    try:
        runs = json.loads(result.stdout).get("workflow_runs") or []
    except (AttributeError, json.JSONDecodeError):
        return []
    history = []
    for run in runs[:count]:
        if not isinstance(run, dict):
            continue
        dispatched, deferred, lanes = (None, None, None)
        if run.get("status") == "completed" and isinstance(run.get("id"), int):
            dispatched, deferred, lanes = _run_log_counts(repo, run["id"])
        history.append({
            "at": _utc_iso(run.get("run_started_at") or run.get("created_at")),
            "conclusion": str(run.get("conclusion") or run.get("status") or "unknown")[:24],
            "dispatched": dispatched,
            "deferred": deferred,
            # Issue #323: the per-lane breakdown (or None for a run that printed none), so a
            # persistently stalled review/fix lane — or a failed safety disarm, which consumes no
            # lease and is therefore invisible in `dispatched` — is legible on the ops page and not
            # only inside the model-health alert.
            "lanes": lanes,
        })
    return history


def _health_status(value):
    if isinstance(value, bool):
        return "healthy" if value else "unhealthy"
    text = str(value or "").strip().lower()
    if text in {"ok", "pass", "passed", "passing", "healthy", "available", "up", "success"}:
        return "healthy"
    if text in {"warn", "warning", "degraded", "partial"}:
        return "degraded"
    if text in {"fail", "failed", "failing", "unhealthy", "unavailable", "down", "error"}:
        return "unhealthy"
    return "unknown"


_MODEL_HEALTH_MODULE = None


def _model_health_module():
    """Load scripts/model-health.py (hyphenated name — importlib, same pattern as
    account-usage._load_model_health) so the ledger validator + exit-class taxonomy are SHARED,
    not re-implemented here where they would drift."""
    global _MODEL_HEALTH_MODULE
    if _MODEL_HEALTH_MODULE is None:
        path = Path(__file__).resolve().with_name("model-health.py")
        spec = importlib.util.spec_from_file_location("registry_model_health", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _MODEL_HEALTH_MODULE = module
    return _MODEL_HEALTH_MODULE


def _normalize_ledger_health(document):
    """Canonical model-health ledger, {"records": [...]} (issue #218): validate with the shared
    model-health validator — a malformed ledger fails LOUD, never renders a fabricated check —
    then derive one status per (provider, model): the NEWEST record's exit-class, folded to
    healthy/degraded/unhealthy/unknown. Records without a model alias (zero-dispatch fleet
    signals) carry no per-model information and are skipped; account hashes never reach the
    output. Output is bounded: one check per distinct (provider, model), newest 20 pairs."""
    health = _model_health_module()
    try:
        records = health.validate_ledger(document)
    except ValueError as exc:
        raise DashboardError(f"model-health ledger is malformed: {exc}") from exc
    class_status = {
        health.SUCCESS: "healthy",
        health.CLASS_LIMIT: "degraded",
        health.CLASS_TRANSIENT: "degraded",
        health.CLASS_AUTH: "unhealthy",
        health.CLASS_BILLING: "unhealthy",
    }
    latest = {}
    for record in records:
        provider = str(record["provider"]).lower()
        model = str(record.get("model_alias") or "")
        if (SAFE_PROVIDER_RE.fullmatch(provider) is None
                or SAFE_MODEL_RE.fullmatch(model) is None):
            continue
        key = (provider, model)
        if key not in latest or record["ts"] >= latest[key]["ts"]:
            latest[key] = record
    newest_pairs = sorted(latest.items(), key=lambda item: item[1]["ts"], reverse=True)[:20]
    checks = sorted(({
        "model": model,
        "provider": provider,
        "status": class_status.get(record["exit_class"], "unknown"),
        "checked_at": _utc_iso(record["ts"]),
    } for (provider, model), record in newest_pairs),
        key=lambda check: (check["provider"], check["model"]))
    generated_at = _utc_iso(max((record["ts"] for record in records), default=None))
    return {"generated_at": generated_at, "checks": checks}


def _normalize_model_health(document):
    if document is None:
        return None
    if isinstance(document, dict) and "records" in document:
        return _normalize_ledger_health(document)
    generated_at = None
    candidates = document
    if isinstance(document, dict):
        generated_at = _utc_iso(
            document.get("generated_at") or document.get("checked_at") or document.get("timestamp"))
        candidates = next((document[key] for key in ("models", "checks", "results", "statuses")
                           if isinstance(document.get(key), (list, dict))), None)
        if candidates is None:
            candidates = {key: value for key, value in document.items()
                          if key not in {"generated_at", "checked_at", "timestamp", "schema"}}
    if isinstance(candidates, dict):
        candidates = [({"model": key, **value} if isinstance(value, dict)
                       else {"model": key, "status": value}) for key, value in candidates.items()]
    if not isinstance(candidates, list):
        candidates = []
    checks = []
    for item in candidates[:50]:
        if not isinstance(item, dict):
            continue
        model = next((item.get(key) for key in ("model", "model_id", "name", "alias")
                      if item.get(key)), None)
        if not isinstance(model, str) or SAFE_MODEL_RE.fullmatch(model) is None:
            continue
        raw_status = next((item.get(key) for key in ("status", "health", "conclusion", "outcome")
                           if key in item), item.get("healthy"))
        provider = str(item.get("provider") or "").lower()
        checks.append({
            "model": model,
            "provider": provider if SAFE_PROVIDER_RE.fullmatch(provider) else None,
            "status": _health_status(raw_status),
            "checked_at": _utc_iso(
                item.get("checked_at") or item.get("generated_at") or item.get("timestamp")),
        })
        if len(checks) == 20:
            break
    return {"generated_at": generated_at, "checks": checks}


def _live_leases(leases, now):
    live = []
    for lease in leases:
        if not isinstance(lease, dict):
            raise DashboardError("lease ledger entries must be objects")
        expires_at = lease.get("expires_at")
        if (not isinstance(expires_at, (int, float)) or isinstance(expires_at, bool)):
            raise DashboardError("lease ledger entry has an invalid expiry")
        if expires_at > now:
            live.append(lease)
    return live


def _serviced_repositories(policy_text):
    """The ENABLED `[repos."owner/name"]` targets of this repo's worker policy.

    Issue #78: these are the repositories the orchestrator SERVICES, and so the rows the
    per-repository agent census must emit on EVERY tick. Before this, the census listed only the
    repositories that happened to hold a live lease, which is the #938 shape — a serviced target
    running zero agents was indistinguishable from a target that is not serviced at all, and on a
    fully quiet tick the whole table vanished. That is exactly the state an operator interrogates
    after a stall, so a zero row has to be published rather than omitted.

    Every refusal below is fail-closed on the SET: a policy this reader cannot fully understand
    would silently narrow the census (a hidden serviced repo reads as "not serviced"), so it
    refuses the build instead of publishing the rows it did manage to parse."""
    try:
        document = tomllib.loads(policy_text)
    except tomllib.TOMLDecodeError as exc:
        raise DashboardError(f"worker policy is not parseable TOML: {exc}") from exc
    rows = document.get("repos")
    if not isinstance(rows, dict) or not rows:
        raise DashboardError("worker policy carries no [repos.*] targets")
    serviced = []
    for repository, row in rows.items():
        if not isinstance(row, dict):
            raise DashboardError(f"worker policy target {repository!r} is not a table")
        enabled = row.get("enabled")
        # A non-boolean `enabled` is NOT read as "disabled": guessing here drops a serviced
        # repository off the census, which is the disclosure failure this function exists to close.
        if not isinstance(enabled, bool):
            raise DashboardError(
                f"worker policy target {repository!r} has a non-boolean enabled flag")
        if not enabled:
            continue
        if SAFE_REPOSITORY_RE.fullmatch(repository) is None:
            raise DashboardError(
                f"worker policy target {repository!r} is not an owner/name repository")
        serviced.append(repository)
    if not serviced:
        raise DashboardError(
            "worker policy has no ENABLED targets — refusing to publish an agent census with no "
            "rows (an empty row set is what issue #78 closes)")
    return sorted(serviced)


def _repository_activity(live, serviced):
    # Seeded from the SERVICED set, so an idle target publishes an explicit zero row rather than
    # disappearing. A repository that holds a live lease without being serviced still gets its row
    # below — live evidence is never dropped just because the policy did not predict it.
    counts = {repository: {} for repository in serviced}
    models = set()
    for lease in live:
        holder = lease.get("holder")
        match = HOLDER_RE.fullmatch(holder) if isinstance(holder, str) else None
        if match is None:
            raise DashboardError("live lease has an invalid holder")
        model = lease.get("model")
        if not isinstance(model, str) or SAFE_MODEL_RE.fullmatch(model) is None:
            raise DashboardError("live lease has an invalid model")
        repository = match.group("repository")
        models.add(model)
        repository_counts = counts.setdefault(repository, {})
        repository_counts[model] = repository_counts.get(model, 0) + 1
    return {
        "models": sorted(models),
        "repositories": [
            {"repository": repository, "counts": counts[repository]}
            for repository in sorted(counts)
        ],
    }


def _assert_private(document, private_values):
    strings = []

    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                strings.append(str(key))
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
        elif isinstance(value, str):
            strings.append(value)

    visit(document)
    public_text = "\n".join(strings).casefold()
    leaked = [value for value in private_values
              if isinstance(value, str) and value and value.casefold() in public_text]
    if leaked:
        raise DashboardError("privacy assertion failed: raw account identity reached public JSON")


def _obs_fraction(value):
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not 0.0 <= number <= 1.0:
        return None
    return round(number, 4)


def _obs_count(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _obs_minutes(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return round(float(value), 1) if 0 <= value < 10_000_000 else None


def _obs_text(value, cap):
    text = str(value or "").strip()
    return text[:cap] if text and text.isprintable() else ""


def _obs_lane_rows(lanes):
    """Per-workflow (worker/review-fix/drain/groom/...) run outcomes over the 1h/24h windows.
    Lane names are declared by the collector, validated as safe tokens here — a new lane appears
    on the dashboard without a UI change. Malformed rows are dropped, not fatal."""
    rows = []
    if not isinstance(lanes, dict):
        return rows
    for name in sorted(str(key) for key in lanes):
        row = lanes.get(name)
        if (len(rows) == 12 or OBS_TOKEN_RE.fullmatch(name) is None
                or not isinstance(row, dict)):
            continue
        out = {"lane": name}
        for window in ("1h", "24h"):
            source = row.get(window)
            if not isinstance(source, dict):
                out[window] = None
                continue
            out[window] = {key: _obs_count(source.get(key)) or 0
                           for key in ("success", "failure", "defer")}
        rows.append(out)
    return rows


def _obs_counted_rows(items, key_field, cap):
    """[{<key_field>, count}] sorted by count descending (the TOP-N contract for defer reasons)."""
    rows = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        key = item.get(key_field)
        count = _obs_count(item.get("count"))
        if not isinstance(key, str) or OBS_TOKEN_RE.fullmatch(key) is None or count is None:
            continue
        rows.append({key_field: key, "count": count})
    rows.sort(key=lambda row: (-row["count"], row[key_field]))
    return rows[:cap]


def _obs_exit_rows(items):
    rows = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        model, exit_class = item.get("model"), item.get("exit_class")
        count = _obs_count(item.get("count"))
        if (not isinstance(model, str) or SAFE_MODEL_RE.fullmatch(model) is None
                or not isinstance(exit_class, str)
                or OBS_TOKEN_RE.fullmatch(exit_class) is None or count is None):
            continue
        rows.append({"model": model, "exit_class": exit_class, "count": count})
    rows.sort(key=lambda row: (-row["count"], row["model"], row["exit_class"]))
    return rows[:16]


def _obs_lease_aggregate(value):
    """A lease-utilization aggregate the COLLECTOR computed, i.e. the row-free form of the input
    (issue #841). Same published shape as the rows-derived one: ``{"mean", "max"}``.

    Fail-closed to None — the panel stat hides — rather than to a plausible-looking number: both
    fields must be real fractions and ``max >= mean``, which no aggregate over real samples can
    violate. DROPPING rather than raising is the tolerance this document already declares: inside
    a well-formed snapshot a malformed row is dropped and only a privacy violation is fatal, and
    this value carries no identity to violate."""
    if not isinstance(value, dict):
        return None
    mean = _obs_fraction(value.get("mean"))
    maximum = _obs_fraction(value.get("max"))
    if mean is None or maximum is None or maximum < mean:
        return None
    return {"mean": round(mean, 2), "max": round(maximum, 2)}


def _obs_flow(flow):
    """Queue depth/age per class, fleet-wide lease utilization, review rounds, park rates,
    arm→merge latency, target-CI congestion. A lease row whose label is not the canonical 16-hex
    salted account fingerprint (issue #375) is a raw account identity reaching the collector
    output — or a second identity format nothing else here speaks — a decision-22 privacy
    incident, fatal — and since issue #374 the rows themselves are aggregated away rather than
    republished (issue #841: and since the rows sit on a PUBLIC branch, they need not be sent at
    all)."""
    if not isinstance(flow, dict):
        return None
    queue = []
    for item in flow.get("queue") if isinstance(flow.get("queue"), list) else []:
        if not isinstance(item, dict):
            continue
        queue_class = item.get("class")
        depth = _obs_count(item.get("depth"))
        if (not isinstance(queue_class, str)
                or OBS_QUEUE_CLASS_RE.fullmatch(queue_class) is None or depth is None):
            continue
        queue.append({"class": queue_class, "depth": depth,
                      "oldest_age_minutes": _obs_minutes(item.get("oldest_age_minutes"))})
    queue.sort(key=lambda row: row["class"])

    # Issue #374: the per-account lease rows are validated but NOT published. A list of up to 40
    # {label, provider, utilization} rows is a per-account row array by another name — it reads out
    # the fleet's size directly and its labels are stable across builds, which is exactly what the
    # `accounts` array was removed for. The load-balance question the panel answers ("is one account
    # carrying the fleet?") survives as summary statistics that are invariant under cloning the
    # fleet. The decision-22 label check still runs on every INPUT row: a raw handle in the
    # collector's output is a privacy incident regardless of what this build would have published.
    #
    # Issue #841: #374 fixed what this build PUBLISHES; it did not stop the rows EXISTING. The
    # collector's snapshot lives at data/observability.json on the `ledger` branch of this PUBLIC
    # repo, so a consumer contract that says "keep sending one row per account and we will drop
    # them" still parks a per-account row array — fleet size, stable salted labels — one branch
    # over from the page #374 cleaned. So the aggregate is now accepted DIRECTLY as
    # `flow.lease_utilization_1h`, and a collector can satisfy this panel while writing no rows to
    # the public branch at all. Two properties this must NOT trade away, both self-tested:
    #   * rows-first precedence, keyed on the PRESENCE of the legacy `leases` key rather than on
    #     whether a row happened to parse. A collector mid-migration that sends both keeps exactly
    #     today's published value — including the null it publishes when the rows it sent carry no
    #     usable `utilization_1h` — so the new key can never override a legacy result. Only the
    #     genuinely row-free form (no `leases` key at all) consults the collector's aggregate.
    #   * the decision-22 label check is unconditional over the rows that ARE present. Supplying
    #     the aggregate is not a way to smuggle an unvalidated row past it, and a collector that
    #     regresses to writing rows is still caught the moment a raw handle appears in one.
    lease_utilizations = []
    for item in flow.get("leases") if isinstance(flow.get("leases"), list) else []:
        if not isinstance(item, dict):
            continue
        label = item.get("label")
        if not isinstance(label, str) or OBS_SALTED_LABEL_RE.fullmatch(label) is None:
            raise DashboardError(
                "observability lease row does not carry a salted account label (decision 22)")
        utilization = _obs_fraction(item.get("utilization_1h"))
        if utilization is not None:
            lease_utilizations.append(utilization)
    if "leases" in flow:
        lease_utilization = {
            "mean": round(sum(lease_utilizations) / len(lease_utilizations), 2),
            "max": round(max(lease_utilizations), 2),
        } if lease_utilizations else None
    else:
        lease_utilization = _obs_lease_aggregate(flow.get("lease_utilization_1h"))

    rounds = flow.get("review_rounds")
    review_rounds = None
    if isinstance(rounds, dict):
        mean = rounds.get("mean")
        review_rounds = {
            "mean": round(float(mean), 2)
            if isinstance(mean, (int, float)) and not isinstance(mean, bool)
            and math.isfinite(mean) and mean >= 0
            else None,
            "max": _obs_count(rounds.get("max")),
            "budget_exhausted_1h": _obs_count(rounds.get("budget_exhausted_1h")),
        }

    parks = flow.get("parks_1h")
    parks_1h = None
    if isinstance(parks, dict):
        parks_1h = {key: _obs_count(parks.get(key)) or 0
                    for key in ("needs_user", "needs_orchestrator")}

    latency = flow.get("arm_to_merge_minutes_24h")
    arm_to_merge = None
    if isinstance(latency, dict):
        arm_to_merge = {"p50": _obs_minutes(latency.get("p50")),
                        "p90": _obs_minutes(latency.get("p90")),
                        "samples": _obs_count(latency.get("samples")) or 0}

    ci_queue = []
    for item in (flow.get("target_ci_queue")
                 if isinstance(flow.get("target_ci_queue"), list) else []):
        if not isinstance(item, dict):
            continue
        repository = item.get("repository")
        depth = _obs_count(item.get("depth"))
        if (not isinstance(repository, str) or depth is None or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repository)):
            continue
        ci_queue.append({"repository": repository, "depth": depth})

    return {"queue": queue[:12], "lease_utilization_1h": lease_utilization,
            "review_rounds": review_rounds,
            "parks_1h": parks_1h, "arm_to_merge_minutes_24h": arm_to_merge,
            "target_ci_queue": ci_queue[:12]}


def _obs_trigger_rows(items):
    """Auto-fixer trigger fires (fire-only alarm semantics — the collector records each fire; the
    dashboard only displays). Evidence links are pinned to github.com — anything else is dropped
    loudly rather than published on the public page."""
    rows = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        rule = item.get("rule")
        if not isinstance(rule, str) or OBS_TOKEN_RE.fullmatch(rule) is None:
            continue
        evidence = []
        for link in (item.get("evidence") if isinstance(item.get("evidence"), list) else [])[:8]:
            if isinstance(link, str) and OBS_EVIDENCE_RE.fullmatch(link):
                evidence.append(link)
            else:
                print("dashboard-gen: dropped a non-GitHub observability evidence link")
        task = item.get("enqueued_task")
        rows.append({
            "rule": rule,
            "fired_at": _utc_iso(item.get("fired_at")),
            "summary": _obs_text(item.get("summary"), 240),
            "evidence": evidence[:5],
            "enqueued_task": task if isinstance(task, str)
            and OBS_TOKEN_RE.fullmatch(task) else None,
        })
    rows.sort(key=lambda row: row["fired_at"] or "", reverse=True)
    return rows[:20]


def _normalize_observability(document):
    """Validate + sanitize the collector's ledger observability snapshot before publication.

    An ABSENT file is the not-yet-deployed collector => None (the panel hides; never blocks the
    rest of the dashboard). A PRESENT document that is not the declared schema dies loudly — this
    is collector-written data-plane input and must never be published on a guess. Inside a
    well-formed document, malformed rows are dropped (the _normalize_model_health tolerance),
    EXCEPT privacy-shaped violations (a non-salted lease label), which are always fatal."""
    if document is None:
        return None
    if not isinstance(document, dict) or document.get("schema") != OBS_SCHEMA:
        raise DashboardError(f"observability snapshot must declare schema {OBS_SCHEMA!r}")

    cache_source = document.get("cache")
    cache = None
    if isinstance(cache_source, dict):
        histogram = {}
        raw_histogram = cache_source.get("chain_length_histogram")
        if isinstance(raw_histogram, dict):
            for key in sorted(str(k) for k in raw_histogram)[:12]:
                count = _obs_count(raw_histogram.get(key))
                if OBS_HISTOGRAM_KEY_RE.fullmatch(key) and count is not None:
                    histogram[key] = count
        cache = {
            "prompt_cache_read_fraction_1h":
                _obs_fraction(cache_source.get("prompt_cache_read_fraction_1h")),
            "usage_samples_1h": _obs_count(cache_source.get("usage_samples_1h")) or 0,
            "warm_drain_rate_1h": _obs_fraction(cache_source.get("warm_drain_rate_1h")),
            "drained_1h": _obs_count(cache_source.get("drained_1h")) or 0,
            "chain_length_histogram": histogram,
        }

    thresholds_source = document.get("thresholds")
    thresholds = None
    if isinstance(thresholds_source, dict):
        thresholds = {}
        for key in OBS_THRESHOLD_KEYS:
            value = thresholds_source.get(key)
            if (isinstance(value, (int, float)) and not isinstance(value, bool)
                    and math.isfinite(value) and value >= 0):
                thresholds[key] = value

    return {
        "generated_at": _utc_iso(document.get("generated_at")),
        "cache": cache,
        "lanes": _obs_lane_rows(document.get("lanes")),
        "defer_reasons_1h": _obs_counted_rows(document.get("defer_reasons_1h"), "reason", 16),
        "model_exit_classes_1h": _obs_exit_rows(document.get("model_exit_classes_1h")),
        "flow": _obs_flow(document.get("flow")),
        "trigger_fires": _obs_trigger_rows(document.get("trigger_fires")),
        "thresholds": thresholds,
    }


def build_dashboard(issues, leases_document, usage, dispatch_history, model_health, now, salt,
                    observability=None, probe_status=None, serviced=None):
    accounts, private_values = _catalog(issues)
    # Issue #78. `serviced=None` means "READ THE LIVE POLICY", never "no serviced repositories": an
    # empty seed would silently restore the vanishing census this closes, which is the #612 review
    # finding 1 shape (a `None` default that selects the fail-OPEN branch inside the very function
    # that makes the decision). `_repo_file` raises when the policy is unreadable, so a checkout
    # without one refuses the build rather than publishing a lease-only row set.
    if serviced is None:
        serviced = _serviced_repositories(_repo_file(*POLICY_PATH_PARTS))
    _require_salt(salt)
    usage = usage if isinstance(usage, dict) else {}
    try:
        leases = _lease_schema_module().validate_ledger(leases_document)
    except ValueError as exc:
        raise DashboardError(f"lease ledger is malformed: {exc}") from exc
    live = _live_leases(leases, now)
    # Only the AGGREGATE lease count reaches the payload (#374); lease identities never do. Raw
    # handles come only from the catalog/usage inputs and remain in the privacy deny-set.
    private_values.update(str(handle) for handle in usage)

    # Issue #219: a snapshot the probe did not actually produce is not evidence of anything. When
    # the persisted outcome is not a fresh `ok`, the usage map is DISCARDED for every rendering
    # decision — accounts, per-provider aggregates and eligible capacity all fall back to
    # "unknown" — rather than being published as fresh available capacity.
    #
    # #612 review finding 1: NO SIDECAR AT ALL IS THE WEAKEST EVIDENCE OF THE LOT, so it degrades
    # exactly like an unusable one. The first form made `probe_status=None` mean MEASURED, which put
    # a fail-OPEN branch inside the very function that decides capacity: a caller could hand
    # build_dashboard a (possibly stale) non-empty usage map with no sidecar and get every account
    # rendered "available", `fleet.capacity.eligible` positive, and — because the degradation key was
    # omitted in that same branch — NO warning anywhere on the page. That is the #219 failure mode
    # reachable through a different door. `main()`'s `--usage-status`-is-required check guards only
    # the CLI; the invariant belongs here, where the decision is made. The sidecar is now the ONLY
    # thing that can license publishing usage as capacity, and the marker is ALWAYS emitted so no
    # code path can drop the page's degradation notice.
    probe = _probe_outcome(probe_status, now)
    usage_rendered = usage if probe["measured"] else {}

    # The internal capacity tally. ONE predicate for the provider row and eligible capacity: an
    # account is counted eligible only where the allocator would also admit it. Issue #374: this
    # stays a count internally — it is what decides "is there headroom" — but only the boolean
    # projection of it is published.
    capacity = {}
    for account in accounts:
        entry = usage_rendered.get(account["handle"])
        availability, _backoff_until = _quota_state(account, entry, now)
        provider_capacity = capacity.setdefault(
            account["provider"], {"eligible": 0, "total": 0})
        provider_capacity["total"] += 1
        if availability == "available":
            provider_capacity["eligible"] += 1
    history = dispatch_history if isinstance(dispatch_history, list) else []
    document = {
        "schema": SCHEMA,
        "generated_at": _utc_iso(now),
        # Per-provider headroom (maintainer request 2026-07-18), MINIMIZED for the public payload
        # (issue #374). The per-account `accounts` array that used to sit under this key is gone;
        # this section is now the whole quota surface.
        "provider_quota": _public_provider_quota(
            # The verdict travels WITH the snapshot it licensed (#628): when it distrusted the
            # snapshot, the row says so instead of reading like a provider with no usage headers.
            _provider_quota(accounts, usage_rendered, now, probe)),
        "fleet": {
            "active_agents": len(live),
            "capacity": _public_capacity(capacity),
            "last_sweep_at": history[0].get("at") if history else None,
            "dispatch_outcomes": history,
        },
        # Issue #78: one row per SERVICED repository on every tick (zeroes included), plus a column
        # per model that is live somewhere — "how many instances of each model are running on each
        # repo we service", readable at a glance instead of inferred from which rows are absent.
        "active_by_repository": _repository_activity(live, serviced),
        "model_health": _normalize_model_health(model_health),
    }
    # Degradation marker (issue #219): the page renders probe age + failure so a stale or failed
    # measurement is visible instead of silently looking like a fresh, idle fleet. ALWAYS present
    # (#612 review finding 1) — it used to be omitted on exactly the branch that also trusted the
    # usage map unconditionally, so the one state that most needed a warning carried none.
    document["usage_probe"] = probe
    observability = _normalize_observability(observability)
    if observability is not None:
        # Optional key (absent => the dashboard hides the Observability panels), placed INSIDE the
        # document so the raw-identity assertion below covers every observability string too.
        document["observability"] = observability
    _assert_private(document, private_values)
    _assert_no_fleet_composition(document)
    return document


def _write_site(document, assets, site):
    assets, site = Path(assets).resolve(), Path(site).resolve()
    if not assets.is_dir() or assets == site:
        raise DashboardError("dashboard asset directory is missing or unsafe")
    site.mkdir(parents=True, exist_ok=True)
    copied = 0
    for source in assets.rglob("*"):
        if source.is_symlink():
            raise DashboardError("dashboard assets may not contain symlinks")
        if source.is_file():
            target = site / source.relative_to(assets)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            copied += 1
    if copied == 0:
        raise DashboardError("dashboard asset directory is empty")
    with open(site / "data.json", "w", encoding="utf-8") as handle:
        # allow_nan=False: NaN/Infinity would serialize as non-standard JSON tokens that browser
        # response.json() rejects, taking down the whole public page — die here instead.
        json.dump(document, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")


def _optional_usage_path(cli_path):
    candidates = [cli_path, os.environ.get("WORKER_USAGE_FILE"),
                  "data/usage.json", "data/account-usage.json"]
    return next((path for path in candidates if path and Path(path).is_file()), None)


# Issue #78. The per-repository census is only observability if the PAGE renders it, and the #612
# round-4 lesson is that a lexical assertion about `renderRepositoryAgents` is satisfiable by a
# comment or a neighbouring occurrence. So the real function is EXECUTED against a stub DOM and the
# rendered header/rows are compared cell by cell — including the quiet tick, where every count is
# zero and the pre-#78 page named no repository at all.
_REPO_AGENTS_PAGE_HARNESS = r"""
const fs = require("fs");
const source = fs.readFileSync(__APP_JS__, "utf8");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
function element(tag) {
  const self = {
    tagName: tag, children: [], hidden: false, textContent: "", className: "",
    append: (...kids) => { for (const kid of kids) self.children.push(kid); },
    replaceChildren: (...kids) => { self.children = [...kids]; },
    setAttribute: () => {},
    classList: { add: () => {}, remove: () => {}, contains: () => false },
  };
  return self;
}
const ids = {};
globalThis.document = {
  getElementById: (id) => (ids[id] = ids[id] || element("div#" + id)),
  createElement: element,
  createElementNS: (_ns, tag) => element(tag),
  createTextNode: (text) => ({ textContent: text, children: [] }),
};
globalThis.fetch = () => Promise.reject(new Error("network is not under test"));
globalThis.setInterval = () => 0;
(async () => {
  const scope = new Function(source + "; return { renderRepositoryAgents };")();
  await new Promise((resolve) => setImmediate(resolve));
  const out = {};
  for (const [name, spec] of Object.entries(input.cases)) {
    for (const id of ["repo-agents-empty", "repo-agents-table", "repo-agents-head",
                      "repo-agents-body"]) {
      ids[id] = element(id);
    }
    let error = null;
    try {
      scope.renderRepositoryAgents(spec.activity, spec.active);
    } catch (raised) {
      error = String((raised && raised.message) || raised);
    }
    const head = ids["repo-agents-head"].children[0];
    out[name] = {
      error,
      tableHidden: ids["repo-agents-table"].hidden === true,
      emptyText: ids["repo-agents-empty"].hidden === true
        ? null : ids["repo-agents-empty"].textContent,
      header: head ? head.children.map((cell) => cell.textContent) : [],
      rows: ids["repo-agents-body"].children.map((row) =>
        row.children.map((cell) => cell.textContent)),
    };
  }
  process.stdout.write(JSON.stringify(out));
})().catch((error) => { console.error(error && error.stack || error); process.exit(1); });
"""


_LANE_PAGE_HARNESS = r"""
const fs = require("fs");
const source = fs.readFileSync(__APP_JS__, "utf8");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
function element(tag) {
  const self = {
    tagName: tag, children: [], hidden: false, textContent: "", className: "",
    append: (...kids) => { for (const kid of kids) self.children.push(kid); },
    replaceChildren: (...kids) => { self.children = [...kids]; },
    setAttribute: () => {},
    classList: { add: () => {}, remove: () => {}, contains: () => false },
  };
  return self;
}
const ids = {};
globalThis.document = {
  getElementById: (id) => (ids[id] = ids[id] || element("div#" + id)),
  createElement: element,
  createElementNS: (_ns, tag) => element(tag),
  createTextNode: (text) => ({ textContent: text, children: [] }),
};
globalThis.fetch = () => Promise.reject(new Error("network is not under test"));
globalThis.setInterval = () => 0;
const flat = (node) => [node.textContent || "", ...(node.children || []).flatMap(flat)];
(async () => {
  const scope = new Function(source + "; return { renderOutcomes };")();
  await new Promise((resolve) => setImmediate(resolve));
  const out = {};
  for (const [name, outcomes] of Object.entries(input.outcomes)) {
    ids.outcomes = element("tbody#outcomes");
    scope.renderOutcomes(outcomes);
    out[name] = ids.outcomes.children.map((row) => {
      const cell = row.children[4];
      return {
        cells: row.children.length,
        colSpan: row.children[0] ? (row.children[0].colSpan ?? null) : null,
        cellText: cell ? flat(cell).join("").trim() : null,
        chips: cell ? (cell.children || []).map((chip) => ({
          dot: chip.children && chip.children[0] ? chip.children[0].className : "",
          text: flat(chip).join("").trim(),
        })) : [],
      };
    });
  }
  process.stdout.write(JSON.stringify(out));
})().catch((error) => { console.error(error && error.stack || error); process.exit(1); });
"""


def _self_test_dispatch_lanes(check, history, issues, leases, usage, now, measured_sidecar):
    """Issue #323 — the per-lane dispatch tick counts, from the RUN LOG they are parsed out of, all
    the way to the cell the page renders.

    Split out of `_self_test` only because that function is already thousands of lines; every row
    below is part of the same suite and `check` is the same accumulator."""
    # --- the parser. `deferred` is the LINE's value (5-1-1 would derive 3, the line says 2), so a
    # re-derivation here goes red; the second dispatcher block wins, matching `complete[-1]`.
    log = (
        "2025-01-01Z lane review: planned=9 launched=0 deferred=0 error=9\n"   # pre-complete: not
        "2025-01-01Z dispatched worker owner/repo#1\n"                         # the dispatcher's
        "2025-01-01Z dispatcher complete: 1 worker/review/fix run(s) launched\n"
        "2025-01-01Z fix-dispatch: 0 eligible, 0 launched, 0 deferred (reasons: none)\n"
        "2025-01-01Z lane worker: planned=4 launched=4 deferred=0 error=0\n"
        "2025-01-01Z lane review: planned=4 launched=4 deferred=0 error=0\n"
        "2025-01-01Z lane fix: planned=4 launched=4 deferred=0 error=0\n"
        "2025-01-01Z lane disarm: planned=4 launched=4 deferred=0 error=0\n"
        "2025-01-01Z defer attribution: none\n"
        "2025-01-01Z dispatcher complete: 2 worker/review/fix run(s) launched\n"
        "2025-01-01Z fix-dispatch: 3 eligible, 1 launched, 2 deferred (reasons: capacity=2)\n"
        "2025-01-01Z lane worker: planned=5 launched=1 deferred=2 error=1\n"
        "2025-01-01Z lane review: planned=2 launched=0 deferred=2 error=0\n"
        "2025-01-01Z lane fix: planned=0 launched=0 deferred=0 error=0\n"
        "2025-01-01Z lane disarm: planned=1 launched=1 deferred=0 error=1\n"
        "2025-01-01Z defer attribution: none\n"
        # Echoed AFTER the block's terminator — a clean `review` row that would have overwritten
        # the dispatcher's stalled one under a last-wins scan of the whole tail.
        "2025-01-01Z lane review: planned=0 launched=0 deferred=0 error=0\n")
    check("[#323] the lane block parses into per-lane rows with the LINE's deferred count and a "
          "display state per lane",
          _dispatch_lane_rows(log),
          [{"lane": "worker", "planned": 5, "launched": 1, "deferred": 2, "error": 1,
            "state": "stalled"},
           {"lane": "review", "planned": 2, "launched": 0, "deferred": 2, "error": 0,
            "state": "stalled"},
           {"lane": "fix", "planned": 0, "launched": 0, "deferred": 0, "error": 0,
            "state": "idle"},
           {"lane": "disarm", "planned": 1, "launched": 1, "deferred": 0, "error": 1,
            "state": "stalled"}])
    # AGENTS.md pre-flight item 5 — who can write the thing this reads? A whole run's log carries
    # target-controlled text, and every line of a raw Actions log is timestamp-prefixed, so the
    # `^\S+\s+` shape is NOT evidence the dispatcher printed it. The forged `review` row above sits
    # before the last `dispatcher complete:` and must not appear at all; here it is the only lane
    # line in the log, and the answer is still no rows rather than a fabricated stall.
    check("[#323] a lane line the dispatcher did not print (before the last `dispatcher "
          "complete:`) cannot fabricate a lane row",
          (_dispatch_lane_rows(
              "2025-01-01Z lane review: planned=9 launched=0 deferred=0 error=9\n"
              "2025-01-01Z dispatcher complete: 1 worker/review/fix run(s) launched\n"),
           _dispatch_lane_rows(
               "2025-01-01Z lane review: planned=9 launched=0 deferred=0 error=9\n")),
          (None, None))
    check("[#323] a lane row echoed AFTER the block's terminator cannot overwrite the "
          "dispatcher's own row for that lane (the scan stops at the terminator)",
          [row for row in (_dispatch_lane_rows(log) or []) if row["lane"] == "review"],
          [{"lane": "review", "planned": 2, "launched": 0, "deferred": 2, "error": 0,
            "state": "stalled"}])

    def lane_names(rows):
        """The parsed lane names, or the refusal itself — so a mutant that turns a published block
        into `None` reds ONE named row instead of raising out of the comprehension and aborting the
        suite, which records as a kill while every check below it never runs (pre-flight item 4)."""
        return None if rows is None else [row["lane"] for row in rows]

    # --- the block is validated as a WHOLE (review round 1). Publishing the survivors of a
    # damaged block renders a vanished lane as absent rather than unknown, which is precisely how
    # the stalled review/fix lane or the failed disarm this cell exists to expose would go missing.
    # Every shape below is a block the dispatcher could not have printed, and each must be None —
    # asserting "no partial lane set is published" rather than "the bad row was dropped".
    def block(*body):
        """One dispatcher block: the completion marker, the fix-dispatch header, then `body`."""
        return ("2025-01-01Z dispatcher complete: 1 worker/review/fix run(s) launched\n"
                "2025-01-01Z fix-dispatch: 0 eligible, 0 launched, 0 deferred (reasons: none)\n"
                + "".join(line + "\n" for line in body))

    worker_row = "2025-01-01Z lane worker: planned=5 launched=0 deferred=5 error=0"
    review_row = "2025-01-01Z lane review: planned=2 launched=0 deferred=2 error=0"
    fix_row = "2025-01-01Z lane fix: planned=1 launched=1 deferred=0 error=0"
    disarm_row = "2025-01-01Z lane disarm: planned=1 launched=0 deferred=0 error=1"
    terminator = "2025-01-01Z defer attribution: none"
    check("[#323] a block missing a required lane publishes NOTHING — neither the stalled review "
          "lane nor the failed disarm may be silently absent from an otherwise healthy tick",
          (_dispatch_lane_rows(block(worker_row, fix_row, disarm_row, terminator)),
           _dispatch_lane_rows(block(worker_row, review_row, fix_row, terminator))),
          (None, None))
    check("[#323] a malformed row inside the block refuses the WHOLE block (an unsafe lane name, a "
          "count that is not a bounded integer, and a duplicated lane)",
          (_dispatch_lane_rows(block(
              worker_row, review_row, fix_row,
              "2025-01-01Z lane bad name: planned=1 launched=0 deferred=0 error=1", terminator)),
           _dispatch_lane_rows(block(
               worker_row, review_row, fix_row,
               "2025-01-01Z lane disarm: planned=1234567 launched=0 deferred=0 error=1",
               terminator)),
           _dispatch_lane_rows(block(
               worker_row, review_row, fix_row, disarm_row, disarm_row, terminator))),
          (None, None, None))
    check("[#323] a block that is truncated or non-contiguous is unknown rather than partially "
          "published",
          (_dispatch_lane_rows(block(worker_row, review_row, fix_row, disarm_row)),
           _dispatch_lane_rows(block(worker_row, review_row,
                                     "2025-01-01Z dispatched worker owner/repo#7",
                                     fix_row, disarm_row, terminator))),
          (None, None))
    # The header anchor needs its OWN input, carrying a COMPLETE lane set — the two guards are
    # otherwise mutually masking (pre-flight item 4): with the header line simply absent, the first
    # lane row is eaten in its place, the block then looks like it is missing that lane, and the
    # required-lane floor refuses it for the wrong reason. Deleting the anchor outright survived the
    # suite until this row existed. Here the header's slot holds a foreign line and all four lanes
    # follow, so ONLY the anchor can refuse it.
    check("[#323] a block whose fix-dispatch header is not there — an unrelated line in its slot, "
          "or no header line at all — publishes nothing even with every lane row present",
          (_dispatch_lane_rows(block(worker_row, review_row, fix_row, disarm_row, terminator)
                               .replace("2025-01-01Z fix-dispatch: 0 eligible, 0 launched, "
                                        "0 deferred (reasons: none)",
                                        "2025-01-01Z dispatched worker owner/repo#7")),
           _dispatch_lane_rows(
               "2025-01-01Z dispatcher complete: 1 worker/review/fix run(s) launched\n"
               + "".join(line + "\n" for line in
                         (worker_row, review_row, fix_row, disarm_row, terminator)))),
          (None, None))
    # ...and the required set is a FLOOR, not a pin: a lane added to dispatch-claim's
    # DISPATCH_LANES still reaches the page with no change here (a check that only ever expected
    # None would be satisfied by hard-coding `return None`).
    check("[#323] a block carrying an UNKNOWN extra lane still publishes, extra row included",
          lane_names(_dispatch_lane_rows(block(
              worker_row, review_row, fix_row, disarm_row,
              "2025-01-01Z lane audit: planned=3 launched=3 deferred=0 error=0", terminator))),
          ["worker", "review", "fix", "disarm", "audit"])
    # --- ...and the required four are ORDERED (review round 2). dispatch-claim iterates ONE fixed
    # tuple, so a complete, contiguous, terminated block whose four required rows are permuted is a
    # block it cannot have printed — provenance the membership/duplicate/cap checks all wave
    # through. Both permutations are written LITERALLY, in an order no rotation of the shipped
    # tuple produces, so neither this input nor its expectation moves if DISPATCH_REQUIRED_LANES is
    # edited (pre-flight item 2(b)/(c)).
    check("[#323] a COMPLETE block whose required lanes arrive out of the dispatcher's emission "
          "order publishes nothing — every lane present is not evidence the dispatcher printed it",
          (_dispatch_lane_rows(block(worker_row, fix_row, review_row, disarm_row, terminator)),
           _dispatch_lane_rows(block(disarm_row, review_row, fix_row, worker_row, terminator))),
          (None, None))
    # The exemption is what keeps that order rule from being a pin on the whole block: an unknown
    # lane may sit ANYWHERE, including between two required rows, and publishes in its own place.
    # Without this row, refusing every block whose lane list is not exactly the required tuple —
    # which would silently drop a future lane off the page — stays green.
    check("[#323] an unknown extra lane INTERLEAVED among the required rows still publishes, in "
          "the position the dispatcher printed it",
          lane_names(_dispatch_lane_rows(block(
              worker_row, review_row,
              "2025-01-01Z lane audit: planned=3 launched=3 deferred=0 error=0",
              fix_row, disarm_row, terminator))),
          ["worker", "review", "audit", "fix", "disarm"])
    # 12 and 13 are LITERAL here. Deriving either from DISPATCH_LANE_CAP would make the row
    # vacuous — raising the constant would raise the input and the expectation together and stay
    # green, which is the #941 shape AGENTS.md pre-flight item 2(c) names.
    def padded(count):
        return block(worker_row, review_row, fix_row, disarm_row, *[
            f"2025-01-01Z lane l{index}: planned=1 launched=1 deferred=0 error=0"
            for index in range(count)], terminator)

    twelve = _dispatch_lane_rows(padded(8))
    check("[#323] the lane row count is bounded at twelve, and a block that EXCEEDS the bound is "
          "refused whole rather than truncated to the first twelve lanes",
          (len(twelve or []), (lane_names(twelve) or ["<refused>"])[-1],
           _dispatch_lane_rows(padded(9))),
          (12, "l7", None))

    # --- the display tone. The ALERTING predicate is the tick-health step of dispatch.yml; this
    # oracle restates it (there is no importable copy — it is inline python inside the workflow),
    # and the property is CONTAINMENT: everything that pages must render red. A tone rule that ever
    # narrows toward the alert would hide a lane the operator is being paged about.
    def workflow_alerts(lane, planned, launched, error):
        if lane == "disarm":
            return error > 0
        if lane in ("review", "fix"):
            return planned > 0 and launched == 0 and error > 0
        return False

    grid = [(lane, planned, launched, error)
            for lane in ("worker", "review", "fix", "disarm")
            for planned in range(3) for launched in range(planned + 1) for error in range(3)]
    alerting = [case for case in grid if workflow_alerts(*case)]
    check("[#323] EVERY lane state the dispatch.yml tick-health step pages on renders `stalled` "
          "(containment), over a non-empty grid of cases",
          (bool(alerting),
           sorted({_dispatch_lane_state(*case[1:]) for case in alerting})),
          (True, ["stalled"]))
    check("[#323] ...and the tone is STRICTLY wider than the alert — a lane that planned work and "
          "launched none of it is red here even with no hard error",
          (_dispatch_lane_state(2, 0, 0), workflow_alerts("worker", 2, 0, 0)),
          ("stalled", False))
    check("[#323] the tone actually discriminates (a constant would satisfy containment alone)",
          (_dispatch_lane_state(0, 0, 0), _dispatch_lane_state(3, 3, 0),
           _dispatch_lane_state(3, 3, 1)),
          ("idle", "ok", "stalled"))

    # --- ...and the same rows reaching a published document through the REAL fetch path. Both
    # `_fetch_dispatch_history` and `_run_log_counts` shell out to `gh`, so neither had ever
    # executed in this suite (AGENTS.md pre-flight item 1: the entry points are where a fabricating
    # bug survives) — dropping `"lanes": lanes` from the history entry was unkillable. `gh` is
    # stubbed here, so the seam between the log parser and the published payload is real.
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("dispatch/9_Strictly validate, CAS claim, and dispatch.txt", log)
    logs_zip = archive.getvalue()
    stepless = io.BytesIO()
    with zipfile.ZipFile(stepless, "w") as bundle:
        bundle.writestr("dispatch/1_Set up job.txt", log)
    stepless_zip = stepless.getvalue()
    runs_payload = json.dumps({"workflow_runs": [
        {"id": 11, "status": "completed", "conclusion": "success",
         "run_started_at": "2025-06-15T15:05:00Z"},
        {"id": 12, "status": "completed", "conclusion": "failure",
         "run_started_at": "2025-06-15T14:05:00Z"},
        {"id": 13, "status": "in_progress", "run_started_at": "2025-06-15T13:05:00Z"},
        # The two log-shaped failures the counts share with the lanes: an archive with no claim
        # step in it, and a body that is not an archive at all. Both must reach the caller as a
        # THREE-value answer — the arity is the seam this change moved, and an unexercised return
        # there raises out of _fetch_dispatch_history and takes the whole build down.
        {"id": 14, "status": "completed", "conclusion": "success",
         "run_started_at": "2025-06-15T12:05:00Z"},
        {"id": 15, "status": "completed", "conclusion": "success",
         "run_started_at": "2025-06-15T11:05:00Z"},
    ]})

    class _Completed:
        def __init__(self, returncode, stdout):
            self.returncode, self.stdout = returncode, stdout

    def fake_gh(command, **kwargs):
        url = command[-1]
        if "/workflows/dispatch.yml/runs" in url:
            return _Completed(0, runs_payload)
        if url.endswith("/runs/11/logs"):
            return _Completed(0, logs_zip)
        if url.endswith("/runs/14/logs"):
            return _Completed(0, stepless_zip)   # an archive with no claim-step member
        if url.endswith("/runs/15/logs"):
            return _Completed(0, b"not a zip")   # an unreadable archive
        return _Completed(1, b"")                # run 12: the log fetch fails

    # Every read below reports rather than raises. A mutant that changes `_run_log_counts`'s arity
    # aborts this call, and an abort records as a kill while every check after it never runs
    # (AGENTS.md pre-flight item 4, crash-after-partial-run) — so the failure is turned into a NAMED
    # red row and the suite continues to its full check count.
    saved_run = subprocess.run
    try:
        subprocess.run = fake_gh
        fetched, fetch_error = _fetch_dispatch_history("owner/registry", 5), None
    except Exception as exc:                    # noqa: BLE001 - reported as a row, never swallowed
        fetched, fetch_error = [], f"{type(exc).__name__}: {exc}"
    finally:
        subprocess.run = saved_run
    check("[#323] the fetched history carries the per-lane rows for the run whose log was read, "
          "and an explicit None — never a fabricated empty lane set — for a run whose log it "
          "could not read or which has not finished",
          fetch_error or [(entry.get("dispatched"), entry.get("deferred"),
                           None if entry.get("lanes") is None
                           else [row["lane"] for row in entry["lanes"]])
                          for entry in fetched],
          # `deferred` is 2 because the fixture log carries the TWO dispatcher blocks the
          # last-block-wins rule above is stated over, and DEFERRED_RE matches each block's
          # `defer attribution:` header (pre-existing counting behaviour, untouched here).
          [(2, 2, ["worker", "review", "fix", "disarm"]), (None, None, None), (None, None, None),
           (None, None, None), (None, None, None)])
    published = build_dashboard(issues, leases, usage, fetched, None, now, "fixture-salt",
                                probe_status=measured_sidecar)
    published_sweeps = published["fleet"]["dispatch_outcomes"]
    published_lanes = next((sweep.get("lanes") or [] for sweep in published_sweeps), [])
    # Stated as LITERALS, not as `fetched[0]["lanes"]`: comparing the payload against the object
    # that was handed in is a tautology over a pass-through (pre-flight item 2(b)).
    check("[#323] ...and they survive into the public payload the page fetches",
          published_lanes[:2],
          [{"lane": "worker", "planned": 5, "launched": 1, "deferred": 2, "error": 1,
            "state": "stalled"},
           {"lane": "review", "planned": 2, "launched": 0, "deferred": 2, "error": 0,
            "state": "stalled"}])

    # --- the page. The header and the row must agree on the column count: a cell appended without
    # a `<th>` renders under the wrong heading, which is the failure this seam check exists for.
    index_html = _repo_file("dashboard", "index.html")
    thead = re.search(r"<thead>(.*?)</thead>\s*<tbody id=\"outcomes\">", index_html, re.S)
    if thead is None:
        raise DashboardError("wiring assertion cannot locate the dispatch-outcomes table header")
    app_js = _repo_file("dashboard", "app.js")
    outcomes_body = _js_function_body(app_js, "renderOutcomes")
    check("[#323] renderOutcomes() appends the lane cell from the outcome's OWN lanes, and the "
          "empty-history row spans the widened table",
          (_js_code_count(outcomes_body, "laneCell(outcome.lanes)"),
           _js_code_count(outcomes_body, "cell.colSpan = 5;")),
          (1, 1))
    lane_body = _js_function_body(app_js, "laneCell")
    check("[#323] the lane tone comes from the GENERATOR's verdict, with an unknown state falling "
          "back rather than reaching the stylesheet unvalidated",
          _js_code_count(
              lane_body,
              'const state = LANE_STATES.has(lane.state) ? lane.state : "unknown";'), 1)
    harness = _LANE_PAGE_HARNESS.replace("__APP_JS__", json.dumps(
        str(Path(__file__).resolve().parent.parent / "dashboard" / "app.js")))
    fixtures = {
        "lanes": published_sweeps[:1],
        "absent": [dict(history[0], lanes=None)],
        "empty": [],
        # A state token no stylesheet rule matches, and one that is not a string at all: both
        # must land on `unknown` rather than being concatenated into the class attribute.
        "hostile": [dict(history[0], lanes=[
            {"lane": "worker", "planned": 1, "launched": 1, "deferred": 0, "error": 0,
             "state": "ok stalled"},
            {"lane": "review", "planned": 1, "launched": 1, "deferred": 0, "error": 0,
             "state": None}])],
    }
    try:
        page = _node_json(harness, {"outcomes": fixtures})
    except DashboardError as exc:
        # A page that throws while rendering IS the finding; reporting it as the value of every
        # row below keeps those rows named and red instead of aborting the suite mid-run.
        page = {"page script raised": str(exc)[:160]}

    def rendered(name, field):
        rows = page.get(name)
        return rows[0].get(field) if isinstance(rows, list) and rows else page

    def chips(name, *fields):
        found = rendered(name, "chips")
        if not isinstance(found, list):
            return found
        return [tuple(chip.get(field) for field in fields) if len(fields) > 1
                else chip.get(fields[0]) for chip in found]

    check("[#323] EXECUTED page script: the header and the rendered row agree on the column count",
          (len(re.findall(r"<th\b", thead.group(1))), rendered("lanes", "cells"),
           rendered("empty", "colSpan")),
          (5, 5, 5))
    check("[#323] EXECUTED page script: every lane renders all four counts unconditionally "
          "(including the zeroes of a quiet lane) with the generator's tone on the dot",
          chips("lanes", "dot", "text"),
          [("lane-dot stalled", "worker 5p 1l 2d 1e"),
           ("lane-dot stalled", "review 2p 0l 2d 0e"),
           ("lane-dot idle", "fix 0p 0l 0d 0e"),
           ("lane-dot stalled", "disarm 1p 1l 0d 1e")])
    check("[#323] EXECUTED page script: a sweep with no lane data renders an explicit blank, not "
          "an all-zero lane set that would read as a healthy tick",
          (rendered("absent", "cellText"), rendered("absent", "chips")), ("—", []))
    check("[#323] EXECUTED page script: a state token that is not one of the four known ones "
          "renders `unknown` — it never reaches the class attribute as written",
          chips("hostile", "dot"), ["lane-dot unknown", "lane-dot unknown"])


def _self_test():
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {name}: {got!r} (want {want!r})")

    # ---- [#1303] THE FAILURE MESSAGE MUST NAME THE CAUSE. ----------------------------
    # 10 dashboard failures on 2026-07-28/29, every one of them `public account issue query
    # failed` with no exit code, no status and no stderr — unclassifiable after the fact.
    class _Result:
        def __init__(self, rc, stderr):
            self.returncode, self.stderr, self.stdout = rc, stderr, ""

    _budget = _gh_failure_suffix(_Result(
        1, "gh: API rate limit exceeded for installation. (HTTP 403)"))
    check("gh failure: an installation-budget 403 is named 'budget' and keeps the exit code",
          ("budget" in _budget, "rc=1" in _budget,
           "API rate limit exceeded for installation." in _budget), (True, True, True))
    # THE CONTRACT of the headerless path: it must NOT claim a count it cannot have read.
    check("gh failure: the degraded path does not claim to have read a rate-limit count",
          "x-ratelimit-remaining=" in _budget, False)
    _secondary = _gh_failure_suffix(_Result(
        1, "gh: You have exceeded a secondary rate limit ... retry your request again later. "
           "(HTTP 403)"))
    check("gh failure: a secondary 403 is NOT called budget (the responses are opposite)",
          ("secondary" in _secondary, "budget" in _secondary), (True, False))
    _perm = _gh_failure_suffix(_Result(1, "gh: Resource not accessible by integration (HTTP 403)"))
    check("gh failure: a permission 403 is the residual class", "permission" in _perm, True)
    check("gh failure: the three classes are distinguishable (non-vacuity)",
          len({_budget.split("—")[1], _secondary.split("—")[1], _perm.split("—")[1]}), 3)
    # STATUS FIRST. classify_403_text answers "IF this is a 403, which one" — so a non-403 whose
    # text happens to carry a marker must not be labelled a rate limit.
    _not403 = _gh_failure_suffix(_Result(1, "gh: connection reset, please retry later"))
    check("gh failure: a non-403 carrying a 403 marker word is NOT classified",
          any(c in _not403 for c in ("budget", "secondary", "permission")), False)
    check("gh failure: ...but its stderr still reaches the log",
          "connection reset" in _not403, True)
    _leak = _gh_failure_suffix(_Result(1, "bad token ghp_" + "B" * 40 + " (HTTP 403)"))
    check("gh failure: a token-shaped string in stderr is masked",
          ("ghp_" + "B" * 40 not in _leak, "***" in _leak), (True, True))
    check("gh failure: the detail is bounded",
          len(_gh_failure_suffix(_Result(1, "x" * 5000))) < _GH_DETAIL_LIMIT + 200, True)

    def _raises_dashboard(thunk):
        try:
            thunk()
        except DashboardError:
            return True
        return False

    now = 1_750_000_000
    # #612 review finding 1: since a build with NO sidecar publishes nothing as capacity (correct —
    # an unsupplied measurement is the weakest evidence of all), every fixture below that means to
    # exercise the real CAPACITY/rendering path must SAY the probe measured. That this whole golden
    # block previously ran through the sidecar-less branch is itself the evidence that the fail-open
    # branch was load-bearing for the suite: the tests were mostly exercising the unguarded path.
    measured_sidecar = {"schema": PROBE_SCHEMA, "outcome": "ok", "detail": "probe-succeeded",
                        "attempted_at": now - 30}
    measured_marker = {"outcome": "ok", "detail": "probe-succeeded",
                       "attempted_at": _utc_iso(now - 30), "age_seconds": 30, "stale": False,
                       "measured": True}
    handle = "acct-fixture"
    email = "private@example.invalid"
    issues = [{
        "title": handle,
        "labels": [{"name": "status:available"}],
        "body": ("provider: anthropic\nmodels: [opus]\nsecret_ref: ACCTFIXTURE_TOKEN\n"
                 f"email: {email}\nlimits: 5h_limit=1000 7d_limit=7000\n"),
    }]
    lease_account = hashlib.sha256(f"{handle}:fixture-salt".encode()).hexdigest()[:16]
    leases = {"leases": [
        {"account": lease_account, "claim_id": "a" * 32,
         "holder": "owner/repo#7@run.1", "package": "pkg", "role": "impl", "model": "opus",
         "issued_at": now - 60, "expires_at": now + 60},
        {"account": lease_account, "claim_id": "b" * 32,
         "holder": "owner/repo#8@run.1", "package": "pkg", "role": "impl", "model": "opus",
         "issued_at": now - 60, "expires_at": now - 1},
    ]}
    usage = {handle: {"status": "allowed", "5h_util": "0.42", "5h_reset": now + 3600,
                      "7d_util": "0.8", "7d_reset": now + 86400}}
    # Issue #323: the fixture sweep carries all four lanes in all three display states — `worker`
    # productive, `review` stalled the way the alert defines it, `disarm` errored while still
    # launching (the safety case the fleet `dispatched` count cannot see), `fix` idle — so the page
    # assertions below can state a TONE per lane rather than merely that a cell was populated.
    fixture_lanes = [
        {"lane": "worker", "planned": 3, "launched": 2, "deferred": 1, "error": 0, "state": "ok"},
        {"lane": "review", "planned": 2, "launched": 0, "deferred": 0, "error": 2,
         "state": "stalled"},
        {"lane": "fix", "planned": 0, "launched": 0, "deferred": 0, "error": 0, "state": "idle"},
        {"lane": "disarm", "planned": 1, "launched": 1, "deferred": 0, "error": 1,
         "state": "stalled"},
    ]
    history = [{"at": "2025-06-15T15:05:00Z", "conclusion": "success",
                "dispatched": 2, "deferred": 3, "lanes": fixture_lanes}]
    # `serviced` is pinned to the fixture's own repository (#78) so this golden document stays
    # hermetic: the default reads the live policy, which is exercised on its own rows further down.
    got = build_dashboard(issues, leases, usage, history, None, now, "fixture-salt",
                          probe_status=measured_sidecar, serviced=("owner/repo",))
    expected = {
        "schema": SCHEMA,
        "generated_at": "2025-06-15T15:06:40Z",
        # Issue #374: NO `accounts` array, and the provider row carries a headroom WORD plus mean
        # window fractions instead of the five-number account census + Σ-over-accounts sums.
        "provider_quota": [{
            "provider": "anthropic",
            "headroom": "available",
            "signal": "live rate-limit-header probe (per-window utilization)",
            "windows": [
                {"name": "5 hour", "remaining_fraction": 0.58,
                 "soonest_reset": "2025-06-15T16:06:40Z", "oldest_reset": "2025-06-15T16:06:40Z"},
                {"name": "7 day", "remaining_fraction": 0.2,
                 "soonest_reset": "2025-06-16T15:06:40Z", "oldest_reset": "2025-06-16T15:06:40Z"},
            ],
            "soonest_reset": "2025-06-15T16:06:40Z", "oldest_reset": "2025-06-16T15:06:40Z",
        }],
        "fleet": {
            "active_agents": 1,
            "capacity": {"anthropic": True},
            "last_sweep_at": "2025-06-15T15:05:00Z",
            "dispatch_outcomes": history,
        },
        "active_by_repository": {
            "models": ["opus"],
            "repositories": [{"repository": "owner/repo", "counts": {"opus": 1}}],
        },
        "model_health": None,
        # The degradation marker is now on EVERY document (#612 review finding 1), so the golden
        # fixture carries it too — and a measured build must say `measured: True` rather than omit
        # the key, which is what let a sidecar-less build look indistinguishable from a healthy one.
        "usage_probe": measured_marker,
    }
    check("fixture leases + limits -> expected JSON", got, expected)
    check("dispatch log counts", _parse_dispatch_log(
        "2025-01-01Z dispatched worker owner/repo#1\n"
        "2025-01-01Z defer owner/repo#2: busy\n"
        "2025-01-01Z dispatcher complete: 1 worker/review/fix run(s) launched\n"), (1, 1, None))
    _self_test_dispatch_lanes(check, history, issues, leases, usage, now, measured_sidecar)
    check("raw identity absent", handle not in json.dumps(got) and email not in json.dumps(got), True)
    leaky = copy.deepcopy(got)
    leaky["provider_quota"][0]["debug"] = handle
    try:
        _assert_private(leaky, {handle})
    except DashboardError:
        rejected = True
    else:
        rejected = False
    check("privacy assertion rejects injected raw handle", rejected, True)
    try:
        build_dashboard(issues, {"leases": []}, {}, [], None, now, "")
    except DashboardError:
        salt_missing_failed = True
    else:
        salt_missing_failed = False
    check("missing salt fails closed (no dashboard is built without PROVENANCE_SALT)",
          salt_missing_failed, True)
    invalid_salts_rejected = []
    for invalid_salt in (None, "", "   ", "salt\nvalue"):
        try:
            _require_salt(invalid_salt)
        except DashboardError:
            invalid_salts_rejected.append(True)
        else:
            invalid_salts_rejected.append(False)
    check("invalid salts fail closed", invalid_salts_rejected, [True, True, True, True])
    check("a real salt is accepted (the precondition is not vacuously fatal)",
          _require_salt("fixture-salt"), None)

    # --- Issue #374: NO FLEET COMPOSITION ON THE PUBLIC PAYLOAD. -------------------------------
    # The sharpest statement of the property, and the one that goes red on any partial revert: two
    # fleets that differ ONLY in how many accounts they contain must publish the same document apart
    # from the live-agent counts named as the KNOWN RESIDUAL above. The three-account fixture below
    # is three clones of the one-account fixture — same provider, same limits, same probe numbers,
    # same resets — so every surviving field is one an observer cannot count accounts with, and it
    # is run both idle and at full occupancy. Pre-#374 this was red on accounts (1 row vs 3),
    # accounts_total (1 vs 3),
    # single_account (True vs False), accounts_available (1 vs 3), remaining_account_windows
    # (0.58 vs 1.74), limit_remaining (580 vs 1740), limits_known/accounts_reporting (1 vs 3) and
    # fleet.capacity (eligible/total 1/1 vs 3/3) — i.e. on every field this change touched.
    def clone_fleet(size, busy=0, leases_per_account=1):
        """`size` identical accounts, the first `busy` of them holding `leases_per_account` live
        leases each (accounts really do run several at once — see the #882 note in the
        FLEET-COMPOSITION block: mint-time `max_concurrent_workers` is 12/4, not 1)."""
        clone_issues, clone_usage, clone_leases = [], {}, []
        for index in range(size):
            clone_handle = f"acct-clone-{index}"
            clone_issues.append({
                "title": clone_handle,
                "labels": [{"name": "status:available"}],
                "body": ("provider: anthropic\nmodels: [opus]\n"
                         f"secret_ref: ACCTCLONE{index}_TOKEN\n"
                         "limits: 5h_limit=1000 7d_limit=7000\n"),
            })
            clone_usage[clone_handle] = {"status": "allowed", "5h_util": "0.42",
                                         "5h_reset": now + 3600, "7d_util": "0.8",
                                         "7d_reset": now + 86400}
            if index < busy:
                for slot in range(leases_per_account):
                    clone_leases.append({
                        "account": hashlib.sha256(
                            f"{clone_handle}:fixture-salt".encode()).hexdigest()[:16],
                        "claim_id": f"{len(clone_leases):032x}",
                        "holder": f"owner/repo#{index + 1}@run.{slot + 1}",
                        "package": "pkg", "role": "impl", "model": "opus",
                        "issued_at": now - 60, "expires_at": now + 60})
        # Hermetic serviced set (#78): the clone-invariance property is about the ACCOUNT fleet, so
        # the census row set is pinned to the fixture's own repository rather than reading the live
        # policy — which would make onboarding a target move this row's index.
        built = build_dashboard(clone_issues, {"leases": clone_leases}, clone_usage, history, None,
                                now, "fixture-salt", probe_status=measured_sidecar,
                                serviced=("owner/repo",))
        return {"provider_quota": built["provider_quota"], "fleet": built["fleet"],
                "active_by_repository": built["active_by_repository"]}

    def without_agent_counts(published):
        """The payload minus the KNOWN RESIDUAL (see the FLEET-COMPOSITION block at the top): the
        live-lease counts, which are not claimed to be invariant and are not published as if they
        were."""
        trimmed = copy.deepcopy(published)
        trimmed["fleet"].pop("active_agents")
        trimmed.pop("active_by_repository")
        return trimmed

    check("[#374] a 1-account and a 3-account IDLE fleet publish a byte-identical payload",
          clone_fleet(1), clone_fleet(3))
    # #839 review round 1, finding 1: idle fleets exercise the property at ZERO load, where nothing
    # about the fleet is in play — which is precisely the state the residual cannot be seen from.
    # Re-run it with one live agent per account, so each fixture is a fleet at full occupancy and
    # the per-account census fields (accounts_total 1 vs 3, remaining_account_windows 0.58 vs 1.74,
    # limit_remaining 580 vs 1740, capacity 1/1 vs 3/3) are all live and would diverge on a partial
    # revert.
    check("[#374] ...and so do a BUSY 1-account and 3-account fleet, one live agent per account",
          without_agent_counts(clone_fleet(1, busy=1)),
          without_agent_counts(clone_fleet(3, busy=3)))
    # The residual, ASSERTED rather than implied by omission: the counts trimmed above really do
    # scale with the fleet under load, so the property is "no account census", not "no fleet count".
    # This row is what keeps the page footer and the block comment honest — a change that removes
    # `active_agents` (or one that quietly restores an absolute no-fleet-count claim) has to come
    # through here.
    check("[#374] KNOWN RESIDUAL: the live-agent counts DO scale with the fleet under load",
          [(clone_fleet(size, busy=size)["fleet"]["active_agents"],
            clone_fleet(size, busy=size)["active_by_repository"]["repositories"][0]["counts"])
           for size in (1, 3)],
          [(1, {"opus": 1}), (3, {"opus": 3})])
    # #882: and the residual is exactly that — a LEASE count, which bounds the account count only
    # by ceil(N / the largest `max_concurrent_workers` in the catalog). ONE account holding three
    # concurrent leases publishes the same `active_agents` as three accounts holding one each, so
    # the retired "cap is 1, therefore ≥N accounts" reading is refuted here rather than in prose
    # alone. This goes red if `active_agents` is ever redefined as a count of BUSY ACCOUNTS (the
    # shape a pass that believed the old invariant would think equivalent): the first tuple would
    # read 1, not 3.
    check("[#882] active_agents counts LEASES: 1 account x3 leases == 3 accounts x1 lease",
          [(clone_fleet(1, busy=1, leases_per_account=3)["fleet"]["active_agents"],
            clone_fleet(1, busy=1,
                        leases_per_account=3)["active_by_repository"]["repositories"][0]["counts"]),
           (clone_fleet(3, busy=3)["fleet"]["active_agents"],
            clone_fleet(3, busy=3)["active_by_repository"]["repositories"][0]["counts"])],
          [(3, {"opus": 3}), (3, {"opus": 3})])
    check("[#374] ...and that payload still reports the headroom honestly (not blanked out)",
          (clone_fleet(3)["provider_quota"][0]["headroom"],
           clone_fleet(3)["provider_quota"][0]["windows"][0]["remaining_fraction"],
           clone_fleet(3)["fleet"]["capacity"]),
          ("available", 0.58, {"anthropic": True}))
    check("[#374] the golden document carries none of the composition keys",
          sorted(FLEET_COMPOSITION_KEYS
                 & set(re.findall(r'"([^"]+)":', json.dumps(got)))), [])
    for banned_key, banned_value in (("accounts", []), ("accounts_total", 3),
                                     ("single_account", True), ("label", "26208fef35e33b14"),
                                     ("eligible", 1), ("limit_remaining", 580)):
        poisoned = copy.deepcopy(got)
        poisoned["fleet"][banned_key] = banned_value
        try:
            _assert_no_fleet_composition(poisoned)
        except DashboardError:
            composition_rejected = True
        else:
            composition_rejected = False
        check(f"[#374] a re-introduced `{banned_key}` key fails the build closed",
              composition_rejected, True)
    check("[#374] ...and the real document passes the same assertion (not vacuously fatal)",
          _assert_no_fleet_composition(got), None)
    check("[#374] the assertion reaches keys nested inside lists, not just the top level",
          _raises_dashboard(lambda: _assert_no_fleet_composition(
              {"provider_quota": [{"windows": [{"accounts_reporting": 2}]}]})), True)

    def issue(account_handle, provider, secret):
        return {
            "title": account_handle,
            "labels": [{"name": "status:available"}],
            "body": (f"provider: {provider}\nmodels: [haiku]\n"
                     f"secret_ref: {secret}\n"),
        }

    ordered_handles = ["anth-late", "anth-unknown", "anth-soon", "openai-one", "future-one"]
    ordered_issues = [
        issue("anth-late", "anthropic", "ACCTLATE_TOKEN"),
        issue("anth-unknown", "anthropic", "ACCTUNKNOWN_TOKEN"),
        issue("anth-soon", "anthropic", "ACCTSOON_TOKEN"),
        issue("openai-one", "openai", "ACCTOPENAI_TOKEN"),
        issue("future-one", "future-provider", "ACCTFUTURE_TOKEN"),
    ]
    ordered_usage = {
        "anth-late": {"status": "allowed", "7d_reset": now + 900},
        "anth-unknown": {"status": "allowed"},
        "anth-soon": {"status": "allowed", "7d_reset": now + 100},
        # [#639] the probe stamps reachability on every exempt entry (absent => unknown, so a
        # fixture without it would exercise the refusal path rather than the healthy one).
        "openai-one": {"exempt": True, "reachability": "live"},
        "future-one": {"status": "allowed", "7d_reset": now + 500},
    }
    activity_leases = {"leases": [
        {"account": "1" * 16, "claim_id": "1" * 32,
         "holder": "org/alpha#1@run.1", "package": "pkg", "role": "impl", "model": "sol",
         "issued_at": now - 30, "expires_at": now + 30},
        {"account": "2" * 16, "claim_id": "2" * 32,
         "holder": "review:org/alpha#2@run.1", "package": "pkg", "role": "review",
         "model": "fable", "issued_at": now - 30, "expires_at": now + 20},
        {"account": "3" * 16, "claim_id": "3" * 32,
         "holder": "fix:org/beta#3@run.1", "package": "pkg", "role": "fix", "model": "opus",
         "issued_at": now - 30, "expires_at": now + 10},
        {"account": "4" * 16, "claim_id": "4" * 32,
         "holder": "org/expired#4@old", "package": "pkg", "role": "impl", "model": "terra",
         "issued_at": now - 30, "expires_at": now - 1},
    ]}
    # Live ledger fixture — the exact {"records": [...]} shape model-health.py writes (#218).
    health_ledger = {"records": [
        {"ts": now - 900, "provider": "anthropic", "account": "a" * 16,
         "model_alias": "fable", "exit_class": "transient", "run_id": "r1"},
        {"ts": now - 600, "provider": "anthropic", "account": "b" * 16,
         "model_alias": "fable", "exit_class": "success", "run_id": "r2"},
        {"ts": now - 300, "provider": "openai", "account": "c" * 16,
         "model_alias": "codex", "exit_class": "limit", "run_id": "r3",
         "reset_hint": "2025-06-15T18:00:00Z"},
        {"ts": now - 120, "provider": "anthropic", "account": "d" * 16,
         "model_alias": "", "exit_class": "zero-dispatch", "run_id": "r4"},
    ]}
    # Issue #78: the serviced set handed in here is deliberately NOT the set of repositories the
    # fixture's leases name. `org/alpha` is serviced AND busy, `org/idle` is serviced and quiet (so
    # it must publish an explicit zero row), and `org/beta` holds a live lease WITHOUT being
    # serviced (so live evidence must survive a policy that did not predict it). None of these three
    # names appears anywhere else in this suite, so nothing here can pass by colliding with another
    # fixture's value.
    ordered = build_dashboard(
        ordered_issues, activity_leases, ordered_usage, [], health_ledger, now, "fixture-salt",
        probe_status=measured_sidecar, serviced=("org/alpha", "org/idle"))
    check("canonical records ledger -> per-provider/model checks", ordered["model_health"], {
        "generated_at": _utc_iso(now - 120),
        "checks": [
            {"model": "fable", "provider": "anthropic", "status": "healthy",
             "checked_at": _utc_iso(now - 600)},
            {"model": "codex", "provider": "openai", "status": "degraded",
             "checked_at": _utc_iso(now - 300)},
        ],
    })
    try:
        _normalize_model_health({"records": [
            {"ts": now, "provider": "anthropic", "account": "acct01",
             "model_alias": "fable", "exit_class": "success", "run_id": "r5"},
        ]})
    except DashboardError:
        ledger_rejected = True
    else:
        ledger_rejected = False
    check("malformed records ledger fails loudly, never a fabricated check",
          ledger_rejected, True)
    # Issue #374 replaced the per-account rows this used to order with one row per provider; the
    # surviving public ordering promise is "one alphabetical row per provider, no account rows".
    check("one alphabetical provider row, and no per-account rows at all",
          ([row["provider"] for row in ordered["provider_quota"]], "accounts" in ordered),
          (["anthropic", "future-provider", "openai"], False))
    check("repo/model table parses impl + review + fix and excludes expired, and [#78] emits a "
          "ZERO row for a serviced-but-quiet repository while keeping a busy unserviced one", [
        ordered["fleet"]["active_agents"], ordered["active_by_repository"]
    ], [3, {
        "models": ["fable", "opus", "sol"],
        "repositories": [
            {"repository": "org/alpha", "counts": {"sol": 1, "fable": 1}},
            {"repository": "org/beta", "counts": {"opus": 1}},
            {"repository": "org/idle", "counts": {}},
        ],
    }])
    check("expanded fixture preserves private account identities",
          all(account_handle not in json.dumps(ordered) for account_handle in ordered_handles), True)

    # --- Issue #78: WHERE THE CENSUS ROW SET COMES FROM, and that it cannot narrow silently. -----
    # The row set is the ENABLED targets of policy/repos.toml. Every leg below is either a hermetic
    # policy literal or a claim about the LIVE file that is written here rather than read out of the
    # reader (pre-flight item 2(b): an expected value taken from the code under test cannot fail).
    # The path is written out LITERALLY here rather than taken from POLICY_PATH_PARTS (pre-flight
    # item 2(c)): an input derived from the constant the code reads moves with it, so a repoint at
    # some other readable TOML would keep this row green. The constant is pinned by equality instead.
    check("[#78] the census reads THIS repo's worker policy, and nothing else can be substituted "
          "for it", POLICY_PATH_PARTS, ("policy", "repos.toml"))
    live_serviced = _serviced_repositories(_repo_file("policy", "repos.toml"))
    check("[#78] the live worker policy resolves to owner/name targets, and the registry itself is "
          "one of them — so the real board can never render a census with no rows",
          ("jeswr/agent-account-registry" in live_serviced,
           bool(live_serviced) and all(SAFE_REPOSITORY_RE.fullmatch(repo) is not None
                                       for repo in live_serviced),
           live_serviced == sorted(set(live_serviced))),
          (True, True, True))
    # The `enabled` filter, killed by its own row: a reader that ignored the flag would publish
    # `off/two` as a serviced repository the pipeline never dispatches to.
    check("[#78] only ENABLED targets become census rows, de-duplicated and sorted",
          _serviced_repositories('[repos."on/one"]\nenabled = true\n'
                                 '[repos."off/two"]\nenabled = false\n'
                                 '[repos."on/three"]\nenabled = true\n'),
          ["on/one", "on/three"])

    def serviced_refused(text):
        try:
            _serviced_repositories(text)
        except DashboardError:
            return True
        return False

    # Each refusal narrows or fabricates the ROW SET if it is waved through, so each must die. The
    # last leg is the non-vacuity control: the minimal well-formed policy is ACCEPTED, which is what
    # stops a reader that simply refuses everything from passing the five rows above it.
    #
    # ⚠️ The malformed-row and non-boolean-`enabled` legs each pair their bad target with a VALID
    # enabled one on purpose. Measured: with a lone bad target, a mutant that reads an unparseable
    # `enabled` as "disabled" still refuses — via the no-enabled-targets guard below — and SURVIVED.
    # Two guards masking each other is pre-flight item 4's fourth outcome; the valid neighbour is
    # what makes each leg fail on its own guard rather than on the other one.
    check("[#78] a policy this reader cannot fully understand refuses the build instead of "
          "publishing the rows it did manage to parse — and a well-formed one is still accepted",
          (serviced_refused("this is not = [ toml"),
           serviced_refused("# a policy with no [repos.*] table at all\n"),
           serviced_refused('[repos]\n"bad/one" = 1\n[repos."ok/one"]\nenabled = true\n'),
           serviced_refused('[repos."ok/one"]\nenabled = true\n[repos."o/r"]\nenabled = 1\n'),
           serviced_refused('[repos."o/r"]\nenabled = false\n'),
           serviced_refused('[repos."ok/one"]\nenabled = true\n'
                            '[repos."not-a-repository"]\nenabled = true\n'),
           serviced_refused('[repos."o/r"]\nenabled = true\n')),
          (True, True, True, True, True, True, False))
    # THE DEFAULT IS NOT AN EMPTY SEED (#612 review finding 1 applied to this argument): omitting
    # `serviced` must read the live policy, not skip the seeding. A build with no catalog, no leases
    # and no history still names every repository we service, each at an explicit zero.
    default_rows = build_dashboard([], {"leases": []}, None, [], None, now,
                                   "fixture-salt")["active_by_repository"]
    check("[#78] with NO serviced argument the build reads the LIVE policy — the default can never "
          "be the lease-only row set this issue closes",
          (default_rows["models"],
           "jeswr/agent-account-registry" in [row["repository"]
                                              for row in default_rows["repositories"]],
           all(row["counts"] == {} for row in default_rows["repositories"])),
          ([], True, True))

    def activity_refused(lease):
        try:
            _repository_activity([lease], ())
        except DashboardError:
            return True
        return False

    # Measured with `python3 -m trace --count` before this change: BOTH refusal lines of
    # `_repository_activity` were never executed by this suite. The one row that looked like it
    # covered them ("malformed live lease fails loudly") is rejected earlier, by
    # lease_schema.validate_ledger, so the census's own guards were untested.
    activity_lease = {"holder": "org/gamma#9@run.1", "model": "sol"}
    check("[#78] the census refuses a live lease whose holder or model it cannot read, and accepts "
          "the well-formed one (so the five refusals are not a reader that refuses everything)",
          (activity_refused(dict(activity_lease, holder="org/gamma#9")),
           activity_refused(dict(activity_lease, holder="org/gamma#9@run.1 extra")),
           activity_refused(dict(activity_lease, holder=None)),
           activity_refused(dict(activity_lease, model="sol sol")),
           activity_refused(dict(activity_lease, model=None)),
           activity_refused(activity_lease)),
          (True, True, True, True, True, False))

    # --- the page. EXECUTED, not pattern-matched: what an operator can read off the table. -------
    # First the LAST HOP (pre-flight item 11): a census that renders perfectly but is never called
    # from `render()` delivers into a panel still reading "Loading agent activity…".
    check("[#78] render() actually hands the payload's census and the published live-lease count to "
          "the table renderer",
          _js_code_count(_js_function_body(_repo_file("dashboard", "app.js"), "render"),
                         "renderRepositoryAgents(data.active_by_repository, "
                         "data.fleet.active_agents);"), 1)
    repo_agents_page = _REPO_AGENTS_PAGE_HARNESS.replace("__APP_JS__", json.dumps(
        str(Path(__file__).resolve().parent.parent / "dashboard" / "app.js")))
    try:
        rendered_agents = _node_json(repo_agents_page, {"cases": {
            # A fully quiet fleet: no model is live anywhere, so there are no per-model columns and
            # the row total is the ONLY number on the page. Pre-#78 this rendered no rows at all.
            "quiet": {"active": 0, "activity": {"models": [], "repositories": [
                {"repository": "quiet/one", "counts": {}},
                {"repository": "quiet/two", "counts": {}}]}},
            # The mixed tick the issue actually asks for: per-model counts per repository, with a
            # serviced-but-idle repository reading zero rather than being absent.
            "mixed": {"active": 3, "activity": {"models": ["opus5", "sol"], "repositories": [
                {"repository": "busy/one", "counts": {"sol": 2, "opus5": 1}},
                {"repository": "idle/two", "counts": {}}]}},
            # A payload that names NO serviced repository is not evidence of an idle fleet.
            "norows": {"active": 0, "activity": {"models": [], "repositories": []}},
            # The row set and the fleet count must still be cross-checked.
            "mismatch": {"active": 9, "activity": {"models": ["sol"], "repositories": [
                {"repository": "busy/one", "counts": {"sol": 2}}]}},
        }})
    except DashboardError as exc:
        rendered_agents = {"page script raised": str(exc)[:160]}

    def agents_case(name, field):
        case = rendered_agents.get(name)
        return case.get(field) if isinstance(case, dict) else rendered_agents

    check("[#78] EXECUTED page script: a quiet tick still publishes one row per serviced "
          "repository, each carrying an explicit 0 — the table does not vanish",
          (agents_case("quiet", "header"), agents_case("quiet", "rows"),
           agents_case("quiet", "tableHidden"), agents_case("quiet", "emptyText")),
          (["Repository", "Agents"], [["quiet/one", "0"], ["quiet/two", "0"]], False, None))
    check("[#78] EXECUTED page script: one column per live model plus the row total, and the "
          "header and every row agree on the column count",
          (agents_case("mixed", "header"), agents_case("mixed", "rows"),
           [len(row) for row in agents_case("mixed", "rows")]
           if isinstance(agents_case("mixed", "rows"), list) else None),
          (["Repository", "Agents", "opus5", "sol"],
           [["busy/one", "3", "1", "2"], ["idle/two", "0", "0", "0"]], [4, 4]))
    check("[#78] EXECUTED page script: a payload naming no serviced repository says so, rather "
          "than reporting an idle fleet it never observed",
          (agents_case("norows", "emptyText"), agents_case("norows", "tableHidden"),
           agents_case("norows", "rows")),
          ("No serviced repositories in this snapshot.", True, []))
    check("[#78] EXECUTED page script: the zero rows do not weaken the cross-check against the "
          "published live-lease count",
          agents_case("mismatch", "error"), "repository activity does not match live lease count")

    # --- provider-cumulative quota (maintainer request 2026-07-18): 2 providers — one
    # multi-account anthropic with mixed capped/free (+ one fail-closed-omitted account), one
    # single-account probe-exempt openai under an active backoff. Asserts the aggregation math,
    # the honest signal labels, and that no raw handle reaches the rows (decision 22). ----------
    quota_handles = ["multi-a", "multi-b", "multi-c", "solo-openai"]
    quota_accounts = [
        {"handle": "multi-a", "provider": "anthropic", "catalog_available": True, "limits": {}},
        {"handle": "multi-b", "provider": "anthropic", "catalog_available": True,
         "limits": {"5h_limit": "1000"}},  # overridden by the probe's live 5h_limit below
        {"handle": "multi-c", "provider": "anthropic", "catalog_available": True, "limits": {}},
        {"handle": "solo-openai", "provider": "openai", "catalog_available": True, "limits": {}},
    ]
    quota_usage = {
        "multi-a": {"status": "allowed", "5h_util": "0.25", "5h_reset": now + 600,
                    "7d_util": "0.5", "7d_reset": now + 4000},
        # multi-b: capped on the 7d window, but with NONZERO 5h headroom (0.1) so the
        # limit-weighted sum distinguishes limit PRECEDENCE non-vacuously (sol finding 4,
        # PR #281 fix round): the LIVE 5h_limit header (2000) must beat the persisted catalog
        # limit (1000) — 2000×0.1=200, not 100. Swapping the precedence turns this red.
        "multi-b": {"status": "allowed", "5h_util": "0.9", "5h_reset": now + 1200,
                    "5h_limit": "2000", "7d_util": "1.0", "7d_reset": now + 90000},
        # multi-c: probe fail-closed omitted — counts in the total and as UNKNOWN/unreported
        # (dispatch treats the omission as unavailable), never in accounts_reporting and
        # never as free (sol finding 2, PR #281 fix round)
        "solo-openai": {"exempt": True, "reachability": "live", "backoff_until": now + 300},
    }
    quota_rows = _provider_quota(quota_accounts, quota_usage, now)
    check("cumulative quota: multi-account provider aggregates mixed capped/free", quota_rows[0], {
        "provider": "anthropic", "accounts_total": 3, "accounts_available": 1,
        "accounts_capped": 1, "accounts_unavailable": 0, "accounts_unknown": 1,
        "single_account": False,
        "signal": "live rate-limit-header probe (per-window utilization)",
        "windows": [
            # 0.75 free (multi-a) + 0.1 free (7d-capped multi-b); only multi-b's LIVE limit is
            # known, so the limit-weighted sum is PARTIAL (limits_known 1 of 2) and equals
            # live 2000 × 0.1 = 200 (the persisted-limit precedence would fabricate 100).
            {"name": "5 hour", "accounts_reporting": 2, "remaining_account_windows": 0.85,
             "limit_remaining": 200, "limits_known": 1,
             "soonest_reset": _utc_iso(now + 600), "oldest_reset": _utc_iso(now + 1200)},
            # no account exposes a 7d limit -> no limit-weighted sum is fabricated
            {"name": "7 day", "accounts_reporting": 2, "remaining_account_windows": 0.5,
             "limit_remaining": None, "limits_known": 0,
             "soonest_reset": _utc_iso(now + 4000), "oldest_reset": _utc_iso(now + 90000)},
        ],
        "soonest_reset": _utc_iso(now + 600), "oldest_reset": _utc_iso(now + 90000),
    })
    check("cumulative quota: single-account probe-exempt provider stays honest", quota_rows[1], {
        "provider": "openai", "accounts_total": 1, "accounts_available": 0,
        "accounts_capped": 1, "accounts_unavailable": 0, "accounts_unknown": 0,
        "single_account": True,
        "signal": ("not observable (probe-exempt provider): catalog availability "
                   "+ reactive rate-limit backoff only"),
        "windows": [],  # no usage signal exists -> no remaining-quota number is fabricated
        "soonest_reset": _utc_iso(now + 300), "oldest_reset": _utc_iso(now + 300),
    })
    # [#628] A DISTRUSTED snapshot must not borrow the future-provider wording. Once the probe
    # verdict fails closed, build_dashboard hands over an empty usage map, so every row fell into
    # the "no live usage signal (catalog availability only)" branch — which says the provider
    # exposes no usage headers (it may well expose them; the probe broke) and still credits catalog
    # availability as the signal (it is deliberately not counted as free). Each reason word is
    # pinned separately, so collapsing the outcomes into one label turns a row red.
    def _distrust_signal(reason):
        return (f"{reason} — no measurement for this snapshot "
                "(catalog availability is not counted as free)")

    unmeasured_probes = {
        "failed": _probe_outcome({"schema": PROBE_SCHEMA, "outcome": "failed",
                                  "attempted_at": now - 30}, now),
        "stale ok": _probe_outcome({"schema": PROBE_SCHEMA, "outcome": "ok",
                                    "attempted_at": now - PROBE_MAX_AGE_SECONDS - 1}, now),
        "no sidecar": _probe_outcome(None, now),
    }
    check("[#628] a distrusted snapshot names the probe, and the reason tracks the outcome",
          {name: _provider_quota(quota_accounts[3:], {}, now, probe)[0]["signal"]
           for name, probe in unmeasured_probes.items()},
          {"failed": _distrust_signal("usage probe failed"),
           "stale ok": _distrust_signal("usage probe is stale"),
           "no sidecar": _distrust_signal("usage probe outcome is unknown")})
    check("[#628] ...and none of them is the no-usage-headers label that provider would emit",
          [_provider_quota(quota_accounts[3:], {}, now)[0]["signal"],
           any(_provider_quota(quota_accounts[3:], {}, now, probe)[0]["signal"]
               == _provider_quota(quota_accounts[3:], {}, now)[0]["signal"]
               for probe in unmeasured_probes.values())],
          ["no live usage signal (catalog availability only)", False])
    # Both directions of the precedence. A distrusted verdict wins over the probed/exempt
    # derivation (those are read out of the rejected snapshot, so "live rate-limit-header probe"
    # would be a claim the verdict cannot back) — and a MEASURED verdict changes nothing at all,
    # so the new branch cannot swallow the honest labels.
    check("[#628] a distrusted verdict never claims a live measurement, however live the map looks",
          [row["signal"] for row in _provider_quota(quota_accounts, quota_usage, now,
                                                    unmeasured_probes["failed"])],
          [_distrust_signal("usage probe failed")] * 2)
    check("[#628] a measured verdict leaves the probed/exempt signals exactly as they were",
          [row["signal"] for row in _provider_quota(
              quota_accounts, quota_usage, now,
              _probe_outcome({"schema": PROBE_SCHEMA, "outcome": "ok",
                              "attempted_at": now - 30}, now))],
          [quota_rows[0]["signal"], quota_rows[1]["signal"]])
    check("cumulative quota: fail-closed-omitted account is unknown, never free",
          [(row["accounts_available"], row["accounts_unknown"]) for row in _provider_quota(
              [{"handle": "ghost", "provider": "anthropic", "catalog_available": True,
                "limits": {}}], {}, now)],
          [(0, 1)])
    # Backoff-stamp parsing PARITY (sol finding 3, PR #281 fix round): the dashboard's "capped"
    # rendering and the allocator's admission decision must be the same predicate on the same
    # input — dashboard-gen used to accept Infinity/absurd integers (rendering "capped
    # indefinitely" while select-and-claim failed open and kept USING the account) and ignored
    # parseable string epochs (rendering "available" while the allocator backed off). One shared
    # vector locks both scripts to the allocator's _usage_num + isfinite semantics.
    allocator = _select_and_claim_module()
    exempt_account = {"handle": "solo-openai", "provider": "openai",
                      "catalog_available": True, "limits": {}}
    for stamp, want_capped in ((now + 300, True), (float(now + 300), True),
                               (str(now + 300), True),          # parseable string epoch: capped
                               (f"{now + 300}.5", True),
                               (now - 1, False),                # expired: free again
                               (float("inf"), False),           # non-finite: fail OPEN
                               ("inf", False), ("nan", False),
                               (10 ** 400, False),              # absurd int: float() overflows
                               ("garbage", False), (None, False), ([], False), ({}, False),
                               (True, False)):
        entry = {"exempt": True, "reachability": "live", "backoff_until": stamp}
        state, _until = _quota_state(exempt_account, entry, now)
        check(f"backoff stamp {str(stamp)[:24]!r}: dashboard capped == allocator excluded",
              (state == "capped", not allocator.usage_eligible(entry, now=now)),
              (want_capped, want_capped))
    # [registry #639] EXEMPTION IS NOT REACHABILITY, on the page too. #612 made the page honest about
    # a failed PROBE; this makes it honest about a dead CREDENTIAL. The pairing is the point: every row
    # asserts the page state and the allocator verdict TOGETHER, so neither surface can drift into
    # advertising capacity the other refuses (or vice versa).
    for reachability, want_state in (("live", "available"), ("unproven", "available"),
                                     ("dead", "unavailable"),
                                     (None, "unknown"),          # producer never stated it
                                     ("LIVE", "unknown"), ("available", "unknown"),
                                     (True, "unknown"), ({}, "unknown")):
        reach_entry = {"exempt": True}
        if reachability is not None:
            reach_entry["reachability"] = reachability
        state, _until = _quota_state(exempt_account, reach_entry, now)
        check(f"[#639] exempt reachability {reachability!r}: page state == allocator verdict",
              (state, state == "available", allocator.usage_eligible(dict(reach_entry), now=now)),
              (want_state, want_state == "available", want_state == "available"))
    check("[#639] a DEAD exempt account contributes no cumulative capacity either",
          [(row["accounts_available"], row["accounts_capped"], row["accounts_unavailable"])
           for row in _provider_quota(
               quota_accounts[3:], {"solo-openai": {"exempt": True, "reachability": "dead"}}, now)],
          [(0, 0, 1)])
    check("cumulative quota: expired backoff no longer counts as capped",
          [(row["accounts_available"], row["accounts_capped"]) for row in _provider_quota(
              quota_accounts[3:],
              {"solo-openai": {"exempt": True, "reachability": "live", "backoff_until": now - 1}},
              now)],
          [(1, 0)])
    # PARTIAL probe entries are never free (sol finding 1, PR #281 fix round 3):
    # account-usage.py can emit an entry whose mandatory utilization windows are missing
    # (status-only, or 5h without 7d) — dispatch (usage_eligible) and usage-alert (classify)
    # both fail closed on that shape, so the dashboard must file it under accounts_unknown
    # ("unreported — treated unavailable by dispatch"), not "1 free". Each shape is also
    # parity-checked against the allocator's own admission predicate.
    partial_account = {"handle": "partial", "provider": "anthropic",
                       "catalog_available": True, "limits": {}}
    for shape_name, partial_entry in (
            ("status-only", {"status": "allowed"}),
            ("5h-only", {"status": "allowed", "5h_util": "0.2", "5h_reset": now + 600,
                         "5h_limit": "1000"})):
        state, _until = _quota_state(partial_account, partial_entry, now)
        check(f"partial probe entry ({shape_name}) is unknown, never free",
              (state, allocator.usage_eligible(dict(partial_entry), now=now)),
              ("unknown", False))
        # The COMPLETE row (sol finding, PR #281 fix round 4): an unknown account contributes
        # NOTHING — even though the 5h-only shape carries a fully parseable window (util 0.2 +
        # reset + limit), the row's windows stay EMPTY and no reset/limit is aggregated. Before
        # this round it rendered "accounts_unknown: 1" NEXT TO "0.8 of 1 account-window free"
        # summed from that very account.
        check(f"partial probe entry ({shape_name}) contributes nothing to the provider row",
              _provider_quota([partial_account], {"partial": dict(partial_entry)}, now),
              [{"provider": "anthropic", "accounts_total": 1, "accounts_available": 0,
                "accounts_capped": 0, "accounts_unavailable": 0, "accounts_unknown": 1,
                "single_account": True,
                "signal": "live rate-limit-header probe (per-window utilization)",
                "windows": [], "soonest_reset": None, "oldest_reset": None}])
    check("both-windows entry still counts available (not over-rejected)",
          _quota_state(partial_account,
                       {"status": "allowed", "5h_util": "0.2", "7d_util": "0.3"}, now),
          ("available", None))
    # Mixed complete+partial provider (sol finding, PR #281 fix round 4): the sums must reflect
    # ONLY the complete account. The partial account's parseable 5h window is a trap on every
    # aggregate axis — earlier reset (would flip soonest_reset), big known limit (would inflate
    # limit_remaining + limits_known), 0.9 headroom (would inflate remaining + reporting) — so
    # reverting the aggregation exclusion turns this red on the first leaked field.
    mixed_accounts = [
        {"handle": "mixed-full", "provider": "anthropic", "catalog_available": True,
         "limits": {}},
        {"handle": "mixed-partial", "provider": "anthropic", "catalog_available": True,
         "limits": {}},
    ]
    mixed_usage = {
        "mixed-full": {"status": "allowed", "5h_util": "0.25", "5h_reset": now + 600,
                       "5h_limit": "1000", "7d_util": "0.5", "7d_reset": now + 4000},
        "mixed-partial": {"status": "allowed", "5h_util": "0.1", "5h_reset": now + 60,
                          "5h_limit": "9000"},
    }
    check("mixed complete+partial: sums reflect only the complete account",
          _provider_quota(mixed_accounts, mixed_usage, now),
          [{"provider": "anthropic", "accounts_total": 2, "accounts_available": 1,
            "accounts_capped": 0, "accounts_unavailable": 0, "accounts_unknown": 1,
            "single_account": False,
            "signal": "live rate-limit-header probe (per-window utilization)",
            "windows": [
                {"name": "5 hour", "accounts_reporting": 1, "remaining_account_windows": 0.75,
                 "limit_remaining": 750, "limits_known": 1,
                 "soonest_reset": _utc_iso(now + 600), "oldest_reset": _utc_iso(now + 600)},
                {"name": "7 day", "accounts_reporting": 1, "remaining_account_windows": 0.5,
                 "limit_remaining": None, "limits_known": 0,
                 "soonest_reset": _utc_iso(now + 4000), "oldest_reset": _utc_iso(now + 4000)},
            ],
            "soonest_reset": _utc_iso(now + 600), "oldest_reset": _utc_iso(now + 4000)}])
    # Malformed/extreme limit headers must never crash the build (sol finding 2, PR #281 fix
    # round 3): float() of a huge JSON int RAISES OverflowError, and two individually-FINITE
    # "1e308" limits overflow the weighted SUM to inf — round(inf) at render then raised and
    # one malformed account record killed the whole dashboard. The offending contribution is
    # rejected (limit stays unknown — outside limits_known) and the build stays alive.
    def _limit_window(limits_map):
        rows_ = _provider_quota(
            [{"handle": f"lim-{i}", "provider": "anthropic", "catalog_available": True,
              "limits": {}} for i in range(len(limits_map))],
            {f"lim-{i}": {"status": "allowed", "5h_util": "0.0", "5h_limit": limit_value,
                          "7d_util": "0.0"}
             for i, limit_value in enumerate(limits_map)}, now)
        window = rows_[0]["windows"][0]
        return (window["limits_known"], window["limit_remaining"],
                window["limit_remaining"] is None
                or isinstance(window["limit_remaining"], int))
    check("single 1e308 limit: finite, counted, round() survives",
          _limit_window(["1e308"]), (1, round(1e308), True))
    check("two 1e308 limits: finite each, infinite sum -> second rejected, build alive",
          _limit_window(["1e308", "1e308"]), (1, round(1e308), True))
    check("huge-int limit (10**400): float() OverflowError caught, limit unknown",
          _limit_window([10 ** 400]), (0, None, True))
    check("'inf'/'nan'/negative limit strings rejected, never summed",
          _limit_window(["inf", "nan", "-5"]), (0, None, True))
    check("cumulative quota rows carry no raw account identifier (decision 22)",
          all(h not in json.dumps(quota_rows) for h in quota_handles), True)
    # The INTERNAL rows still carry the census (they are what decides capacity); the PUBLISHED rows
    # carry the headroom word derived from it. Both halves are asserted so neither can drift.
    check("ordered fixture: internal census -> published headroom, per provider",
          [(row["provider"], row["accounts_total"], row["single_account"],
            _provider_headroom(row))
           for row in _provider_quota(_catalog(ordered_issues)[0], ordered_usage, now)],
          # every anthropic/future entry in ordered_usage is a PARTIAL probe row (a reset stamp with
          # no utilization), which _quota_state files as unknown — so the census is 3/1 accounts,
          # none of them free, and the headroom word says exactly that without saying how many.
          [("anthropic", 3, False, "unknown"), ("future-provider", 1, True, "unknown"),
           ("openai", 1, True, "available")])
    check("ordered fixture publishes headroom words, never the census behind them",
          [(row["provider"], row["headroom"]) for row in ordered["provider_quota"]],
          [("anthropic", "unknown"), ("future-provider", "unknown"),
           ("openai", "available")])
    # The headroom precedence, all four branches, both directions: "can we dispatch" wins, then the
    # most actionable reason. Collapsing any branch into another (or always answering "available")
    # turns a row red.
    for census, want_headroom in (
            ({"accounts_available": 1, "accounts_capped": 9, "accounts_unknown": 9,
              "accounts_unavailable": 9}, "available"),
            ({"accounts_available": 0, "accounts_capped": 1, "accounts_unknown": 9,
              "accounts_unavailable": 9}, "capped"),
            ({"accounts_available": 0, "accounts_capped": 0, "accounts_unknown": 1,
              "accounts_unavailable": 9}, "unknown"),
            ({"accounts_available": 0, "accounts_capped": 0, "accounts_unknown": 0,
              "accounts_unavailable": 1}, "unavailable")):
        check(f"headroom precedence resolves to {want_headroom}",
              _provider_headroom(census), want_headroom)

    # --- usage-probe outcome (issue #219): dashboard.yml's secret-materialization + probe steps
    # are continue-on-error and a failed probe was replaced by `{}`, so precisely WHEN measurement
    # failed the public page showed every catalog-available account as fresh usable capacity. Every
    # case below feeds the IDENTICAL complete usage entry and varies only the persisted outcome.
    #
    # WHICH MUTATION EACH ROW KILLS (#612 review finding 3 asked for this to be stated precisely
    # rather than claimed in aggregate):
    #   * the REJECT rows (failed / stale / alien schema / unstamped / unknown word / NO sidecar)
    #     go red on ANY weakening of the gate — including the narrow one that keeps the marker and
    #     only stops discarding the usage map.
    #   * the ACCEPT row (fresh `ok`) kills the WHOLE-GATE deletion, because its expected tuple
    #     includes `usage_probe.measured is True` and a build with no gate emits no marker at all
    #     (`.get("measured")` -> None). It does NOT — and cannot — kill the narrow "always trust
    #     usage" mutation: by construction a passing gate and an absent gate agree on a fresh probe.
    #     Its job there is over-rejection regression cover, which is a real but different job.
    # -----------------------------------------------------------------------------------------
    fresh_probe = {"schema": PROBE_SCHEMA, "outcome": "ok", "detail": "probe-succeeded",
                   "attempted_at": now - 30}
    failed_probe = {"schema": PROBE_SCHEMA, "outcome": "failed",
                    "detail": "secret-materialization-failed", "attempted_at": now - 30}
    stale_probe = {"schema": PROBE_SCHEMA, "outcome": "ok", "detail": "probe-succeeded",
                   "attempted_at": now - PROBE_MAX_AGE_SECONDS - 1}

    def probe_view(status):
        built = build_dashboard(issues, leases, usage, history, None, now, "fixture-salt",
                                probe_status=status)
        # #374 moved the observable from the per-account row + the census to the headroom word and
        # the capacity boolean. It is the SAME predicate underneath, so this block still fails on
        # any weakening of the #219/#612 gate — an unmeasured probe must read `unknown`/no capacity.
        return (built["provider_quota"][0]["headroom"], built["fleet"]["capacity"],
                built["provider_quota"][0]["windows"],
                (built.get("usage_probe") or {}).get("measured"))

    check("fresh ok probe: a real measurement still publishes real capacity",
          probe_view(fresh_probe),
          ("available", {"anthropic": True},
           [{"name": "5 hour", "remaining_fraction": 0.58,
             "soonest_reset": _utc_iso(now + 3600), "oldest_reset": _utc_iso(now + 3600)},
            {"name": "7 day", "remaining_fraction": 0.2,
             "soonest_reset": _utc_iso(now + 86400), "oldest_reset": _utc_iso(now + 86400)}],
           True))
    for probe_name, probe_status in (
            ("failed", failed_probe),
            ("stale ok", stale_probe),
            ("empty/absent sidecar", {}),
            # #612 review finding 1: NO sidecar at all used to mean MEASURED — the usage map was
            # taken at face value, capacity went positive AND the degradation key was omitted, so
            # the page carried no warning. Non-vacuous: pre-fix this row read
            # ("available", eligible 1, 1, 0, None).
            ("no sidecar supplied at all", None),
            ("alien schema", {"schema": "wrong/v0", "outcome": "ok", "attempted_at": now}),
            ("unstamped ok", {"schema": PROBE_SCHEMA, "outcome": "ok"}),
            ("unknown outcome word", {"schema": PROBE_SCHEMA, "outcome": "maybe",
                                      "attempted_at": now})):
        check(f"{probe_name} probe: the SAME usage input is never published as capacity",
              probe_view(probe_status),
              ("unknown", {"anthropic": False}, [], False))
    degraded = build_dashboard(issues, leases, usage, history, None, now, "fixture-salt",
                               probe_status=failed_probe)
    check("failed probe publishes no window numbers or reset stamps from the dead snapshot",
          [(row["windows"], row["soonest_reset"], row["oldest_reset"])
           for row in degraded["provider_quota"]],
          [([], None, None)])
    check("failed probe surfaces its outcome, detail and age on the public document",
          degraded["usage_probe"],
          {"outcome": "failed", "detail": "secret-materialization-failed",
           "attempted_at": _utc_iso(now - 30), "age_seconds": 30, "stale": False,
           "measured": False})
    # [#628] The WIRING: the verdict must actually reach the row build_dashboard publishes. Dropping
    # the `probe` argument at the call site leaves every other assertion in this file green while the
    # page goes back to blaming the provider for a broken probe, so it is asserted end-to-end here —
    # once for a failed sidecar and once for none at all, which carry different reason words.
    check("[#628] the published row blames the probe, not the provider, on a distrusted snapshot",
          [degraded["provider_quota"][0]["signal"],
           build_dashboard(issues, leases, usage, history, None, now,
                           "fixture-salt")["provider_quota"][0]["signal"]],
          [_distrust_signal("usage probe failed"),
           _distrust_signal("usage probe outcome is unknown")])
    check("[#628] ...while a fresh measurement publishes the live-probe signal unchanged",
          build_dashboard(issues, leases, usage, history, None, now, "fixture-salt",
                          probe_status=fresh_probe)["provider_quota"][0]["signal"],
          "live rate-limit-header probe (per-window utilization)")
    check("stale ok probe surfaces its age and stops counting as measured",
          _probe_outcome(stale_probe, now),
          {"outcome": "ok", "detail": "probe-succeeded",
           "attempted_at": _utc_iso(now - PROBE_MAX_AGE_SECONDS - 1),
           "age_seconds": PROBE_MAX_AGE_SECONDS + 1, "stale": True, "measured": False})
    check("free-text probe detail is dropped, never published as-is on the public page",
          _probe_outcome({"schema": PROBE_SCHEMA, "outcome": "failed",
                          "attempted_at": now, "detail": "token acct-fixture rejected"},
                         now)["detail"], "")
    check("probe age boundary: exactly at the limit is measured, one second past is not",
          [_probe_outcome({"schema": PROBE_SCHEMA, "outcome": "ok",
                           "attempted_at": now - probe_age}, now)["measured"]
           for probe_age in (PROBE_MAX_AGE_SECONDS, PROBE_MAX_AGE_SECONDS + 1)],
          [True, False])
    check("future probe stamp: clock skew tolerated, an implausible stamp is not measured",
          [_probe_outcome({"schema": PROBE_SCHEMA, "outcome": "ok",
                           "attempted_at": now + skew}, now)["measured"]
           for skew in (PROBE_MAX_SKEW_SECONDS, PROBE_MAX_SKEW_SECONDS + 1)],
          [True, False])
    # #612 review round 4 (MINOR): the comparison used to run on `int(now - attempted)`, which
    # rounds toward zero — an age of 3600.9s (or a 300.9s future stamp) compared as 3600/-300 and
    # stayed `measured` past the documented boundary. Production stamps are integers so nothing was
    # mismeasured, but a caller with a float `now` was outside the predicate's own contract.
    check("fractional ages obey the documented boundary (not a truncated one)",
          [_probe_outcome({"schema": PROBE_SCHEMA, "outcome": "ok",
                           "attempted_at": now - PROBE_MAX_AGE_SECONDS}, now + fraction)["measured"]
           for fraction in (0.0, 0.9)]
          + [_probe_outcome({"schema": PROBE_SCHEMA, "outcome": "ok",
                             "attempted_at": now + PROBE_MAX_SKEW_SECONDS},
                            now - fraction)["measured"]
             for fraction in (0.0, 0.9)],
          [True, False, True, False])
    check("...while the PUBLISHED age stays an integer",
          _probe_outcome({"schema": PROBE_SCHEMA, "outcome": "ok",
                          "attempted_at": now - 30}, now + 0.4)["age_seconds"],
          30)
    # #612 review finding 2: this check used to assert "no degradation key" against `got` — a
    # DIFFERENT document built ~350 lines earlier — so that half would have stayed green even if the
    # sidecar-less build had started emitting a bogus marker; and its availability half deliberately
    # pinned the pre-fix PERMISSIVE behaviour, locking in the fail-open of finding 1. It now asserts
    # against the document the adjacent call actually builds, and pins the fail-CLOSED behaviour:
    # a build with no sidecar publishes nothing as capacity AND carries the degradation marker.
    sidecarless = build_dashboard(issues, leases, usage, history, None, now, "fixture-salt")
    # `.get` on purpose: under the pre-fix code the key is ABSENT, and this check must then go red
    # with a legible value rather than take the suite down with a KeyError.
    sidecarless_marker = sidecarless.get("usage_probe") or {}
    check("[#612] NO sidecar: nothing published as capacity, and the marker IS on the document",
          (sidecarless["provider_quota"][0]["headroom"],
           sidecarless["fleet"]["capacity"],
           "usage_probe" in sidecarless,
           (sidecarless_marker.get("outcome"), sidecarless_marker.get("measured"),
            sidecarless_marker.get("stale"), sidecarless_marker.get("attempted_at"))),
          ("unknown", {"anthropic": False}, True,
           ("unknown", False, True, None)))
    check("[#612] and no window numbers or reset stamps leak from the untrusted snapshot",
          [(row["windows"], row["soonest_reset"]) for row in sidecarless["provider_quota"]],
          [([], None)])
    # The core misreport (issue #219): a catalog-available account the probe never reported on used
    # to render "available" and count toward eligible capacity. It is the allocator's INELIGIBLE
    # shape, so it is "unknown" and eligible 0 — even with a perfectly healthy probe.
    unreported = build_dashboard(issues, leases, {}, history, None, now, "fixture-salt",
                                 probe_status=fresh_probe)
    check("catalog-available account with NO probe entry is unknown and not eligible capacity",
          (unreported["provider_quota"][0]["headroom"], unreported["fleet"]["capacity"]),
          ("unknown", {"anthropic": False}))
    # The one-shared-predicate parity, restated on the minimized surface (#374): published capacity
    # is true for exactly the providers whose published headroom is "available". Both projections
    # read the SAME internal count, so the page cannot advertise capacity dispatch would refuse.
    check("published capacity agrees with the published headroom word (one shared predicate)",
          [(row["provider"], row["headroom"] == "available")
           for row in ordered["provider_quota"]],
          sorted(ordered["fleet"]["capacity"].items()))
    with tempfile.TemporaryDirectory() as directory:
        usage_file = Path(directory, "usage.json")
        usage_file.write_text(json.dumps(usage), encoding="utf-8")
        leases_file = Path(directory, "leases.json")
        leases_file.write_text(json.dumps(leases), encoding="utf-8")
        health_file = Path(directory, "model-health.json")
        health_file.write_text(json.dumps({"records": []}), encoding="utf-8")
        try:
            main(["--leases", str(leases_file), "--model-health", str(health_file),
                  "--usage", str(usage_file)])
        except DashboardError as exc:
            # Assert on the MESSAGE, not merely that something raised: main() has several later
            # fail-closed exits (no REGISTRY_REPO, gh unavailable) that would make a bare
            # "did it raise" assertion pass with the coupling deleted — i.e. vacuous.
            status_required = "--usage-status" in str(exc)
        else:
            status_required = False
        check("a usage snapshot without --usage-status is refused (the #219 caller coupling)",
              status_required, True)

    # --- #612 review round 2, finding 4 (MAJOR): the probe step's shell body is EXECUTED, not
    # pattern-matched. `bash -n` and actionlint cannot see polarity, so dropping the `!` from
    # `if [ "$outcome" = ok ] && ! python3 scripts/account-usage.py > "$RUNNER_TEMP/usage.json"`
    # inverted the whole classification with the full suite green: a NONZERO probe stayed `ok` and
    # published a fresh `measured` sidecar. The step body is extracted from the real workflow and
    # run under bash against a stubbed probe, so each row below dies on a one-token change to the
    # shell — including replacing the body with `true` (no sidecar is written at all).
    # ------------------------------------------------------------------------------------------
    dashboard_workflow = _repo_file(".github", "workflows", "dashboard.yml")
    probe_script = _workflow_step_script(dashboard_workflow, "usage-probe")
    # The stub prints a snapshot on stdout even when it EXITS NONZERO: real probes are incremental,
    # so the `!`-dropped mutation must be caught by the recorded OUTCOME rather than by an
    # accidentally-empty file.
    probe_stub = ("import json, os, sys\n"
                  "if '--self-test' in sys.argv:\n"
                  "    sys.exit(int(os.environ['STUB_SELFTEST_EXIT']))\n"
                  "json.dump({'acct-fixture': {'status': 'allowed'}}, sys.stdout)\n"
                  "sys.exit(int(os.environ['STUB_PROBE_EXIT']))\n")
    # Every document round 3's `grep -q '"ACCT'` accepted, next to the one it should. The last four
    # are the round-4 measurement: they pass a substring search and still leave the probe with no
    # usable token, so the exempt accounts were published as free capacity off an unusable subset.
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

    def run_probe_step(secrets_outcome="success", secrets_file="tokens",
                       selftest_exit=0, probe_exit=0):
        """Execute the REAL probe step body.

        Returns (exit code, sidecar dict|"MALFORMED"|None, snapshot text|None, combined step log,
        the names of the files the step left in RUNNER_TEMP)."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "scripts" / "account-usage.py").write_text(probe_stub, encoding="utf-8")
            temp = root / "runner-temp"
            temp.mkdir()
            secrets_path = root / "acct-secrets.json"
            # "missing": the materialization step's body was replaced by `true` — it reports
            # `success` and leaves no file behind. Every other shape below is a document that the
            # round-3 `grep -q '"ACCT'` guard ACCEPTED while `_load_secrets` yielded no usable
            # token (#612 review round 4, MAJOR).
            if secrets_file != "missing":
                secrets_path.write_text(SUBSET_FIXTURES[secrets_file], encoding="utf-8")
            environment = dict(os.environ,
                               RUNNER_TEMP=str(temp),
                               SECRETS_STEP_OUTCOME=secrets_outcome,
                               SECRETS_FILE=str(secrets_path),
                               STUB_SELFTEST_EXIT=str(selftest_exit),
                               STUB_PROBE_EXIT=str(probe_exit),
                               GH_TOKEN="", PROVENANCE_SALT="", REGISTRY_REPO="owner/repo",
                               MODEL_HEALTH_FILE=str(root / "absent-model-health.json"))
            completed = subprocess.run(["bash", "-c", probe_script], cwd=str(root),
                                       env=environment, capture_output=True, text=True,
                                       timeout=120, check=False)
            sidecar_path, snapshot_path = temp / "usage-probe.json", temp / "usage.json"
            sidecar = None
            if sidecar_path.is_file():
                try:
                    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    sidecar = "MALFORMED"
            return (completed.returncode, sidecar,
                    snapshot_path.read_text(encoding="utf-8") if snapshot_path.is_file() else None,
                    completed.stdout + completed.stderr,
                    sorted(item.name for item in temp.iterdir()))

    def probe_step_view(**kwargs):
        code, sidecar, snapshot, _log, _produced = run_probe_step(**kwargs)
        marker = sidecar if isinstance(sidecar, dict) else {}
        return (code, marker.get("schema"), marker.get("outcome"), marker.get("detail"), snapshot)

    check("[#612] probe step: a succeeding probe records ok and keeps its real snapshot",
          probe_step_view(),
          (0, PROBE_SCHEMA, "ok", "probe-succeeded",
           '{"acct-fixture": {"status": "allowed"}}'))
    # THE polarity mutation: without the `!` this row reads ("ok", "probe-succeeded", <stub json>).
    check("[#612] probe step: a NONZERO probe is recorded failed and its output discarded",
          probe_step_view(probe_exit=1),
          (0, PROBE_SCHEMA, "failed", "probe-exited-nonzero", "{}"))
    check("[#612] probe step: a failing probe self-test is recorded failed",
          probe_step_view(selftest_exit=1),
          (0, PROBE_SCHEMA, "failed", "probe-self-test-failed", "{}"))
    check("[#612] probe step: a failed secret materialization is recorded failed",
          probe_step_view(secrets_outcome="failure"),
          (0, PROBE_SCHEMA, "failed", "secret-materialization-failed", "{}"))
    # The `true`-body mutation on the materialization step: outcome `success`, no file. Pre-fix this
    # row read ("ok", "probe-succeeded") — a false-healthy probe status with nothing measured, and
    # the probe-EXEMPT providers published as free capacity off a materialization that never ran.
    check("[#612] probe step: `success` with NO subset file is recorded failed, not measured",
          probe_step_view(secrets_file="missing"),
          (0, PROBE_SCHEMA, "failed", "secret-file-missing", "{}"))
    check("[#612] probe step: an EMPTY token subset is recorded failed, not measured",
          probe_step_view(secrets_file="empty-subset"),
          (0, PROBE_SCHEMA, "failed", "secret-subset-empty", "{}"))
    # --- #612 review round 4 (MAJOR): `grep -q '"ACCT'` proves NEITHER valid JSON NOR a non-empty
    # token. Measured: `{"ACCT01_TOKEN":""}` and the truncated `{"ACCT01_TOKEN":` both passed it, so
    # `outcome` stayed `ok`, the sidecar published `measured=True`, and the probe-EXEMPT accounts
    # were published as fresh free capacity off a subset carrying no usable token — the SAME
    # overgrant this PR exists to close, surviving the fix. Each row below reads
    # ("ok", "probe-succeeded", <stub json>) under the grep guard and dies under the parsing one.
    # ------------------------------------------------------------------------------------------
    for subset_name, subset_detail in (("empty-value", "secret-subset-empty"),
                                       ("blank-value", "secret-subset-empty"),
                                       ("non-string-value", "secret-subset-empty"),
                                       ("wrong-key", "secret-subset-empty"),
                                       ("truncated", "secret-subset-malformed"),
                                       ("not-an-object", "secret-subset-malformed")):
        check(f"[#612] probe step: a `{subset_name}` subset is refused, not measured",
              probe_step_view(secrets_file=subset_name),
              (0, PROBE_SCHEMA, "failed", subset_detail, "{}"))
    # ...and the refusal must stay SILENT about the document: the validator's only stdout is one of
    # three fixed words (captured, never echoed) and it has no traceback path, so no fragment of a
    # token can reach the step log. Asserted over the union of every stream, for every shape.
    for subset_name in SUBSET_FIXTURES:
        code, _sidecar, _snapshot, logged, _produced = run_probe_step(secrets_file=subset_name)
        check(f"[#612] probe step: the `{subset_name}` refusal leaks no subset bytes to the log",
              (code, "ACCT01_TOKEN" in logged, "redacted" in logged, "Traceback" in logged),
              (0, False, False, False))
    # The shell -> python contract itself: whatever the step actually wrote must parse HERE. This is
    # what a scoped substring assertion could never do — it ties the printf's schema string, outcome
    # vocabulary and stamp format to _probe_outcome's fail-closed parser.
    step_now = int(time.time())
    check("[#612] the sidecar the step really wrote is what _probe_outcome accepts/refuses",
          [_probe_outcome(run_probe_step(**kwargs)[1], step_now)["measured"]
           for kwargs in ({}, {"probe_exit": 1}, {"secrets_file": "missing"},
                          {"secrets_file": "empty-value"}, {"secrets_file": "truncated"})],
          [True, False, False, False, False])
    build_step = _workflow_step(dashboard_workflow, "dashboard-build")
    check("[#612] the build step passes the sidecar WITH the snapshot (scoped to that one step)",
          ('--usage "$RUNNER_TEMP/usage.json"' in build_step,
           '--usage-status "$RUNNER_TEMP/usage-probe.json"' in build_step),
          (True, True))

    # --- #612 review round 4: the four survivors in the WIRING seam around the probe step. Round 3
    # executed the probe body; the PRODUCER of the file that body checks, the env wiring that hands
    # it the producer's outcome, and the transport that carries the sidecar to the build job were all
    # still assertion-free, so `run: true` on the materialization step, deleting `id: acct-secrets`,
    # deleting the `SECRETS_STEP_OUTCOME` env line and dropping `usage-probe.json` from the upload
    # each left the whole suite green.
    #
    # (i) The materialization step body is EXECUTED, against a fake complete secret map. This is the
    # producer, and it is also the filter that keeps every NON-worker secret away from the probe — so
    # the row asserts the exact subset, not merely that a file appeared. `run: true` writes no file.
    # ------------------------------------------------------------------------------------------
    materialize_script = _workflow_step_script(dashboard_workflow, "acct-secrets")

    def run_materialize_step(all_secrets):
        """Execute the REAL materialization step body; return (exit code, subset|None, mode|None)."""
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory, "runner-temp")
            temp.mkdir()
            completed = subprocess.run(
                ["bash", "-c", materialize_script], cwd=directory, capture_output=True, text=True,
                timeout=120, check=False,
                env=dict(os.environ, RUNNER_TEMP=str(temp), ALL_SECRETS=json.dumps(all_secrets)))
            written = temp / "acct-secrets.json"
            if not written.is_file():
                return completed.returncode, None, None, completed.stdout + completed.stderr
            return (completed.returncode,
                    json.loads(written.read_text(encoding="utf-8")),
                    oct(written.stat().st_mode & 0o777),
                    completed.stdout + completed.stderr)
    all_secrets = {"ACCT01_TOKEN": "worker-one", "ACCT7X_TOKEN": "worker-two",
                   "PROVENANCE_SALT": "not-a-worker-token", "GITHUB_TOKEN": "not-a-worker-token",
                   "ACCT01_TOKEN_BACKUP": "not-exactly-the-shape", "ACCTLOOKALIKE": "no-suffix",
                   "ACCT02_TOKEN": ["not", "a", "string"]}
    code, subset, mode, materialize_log = run_materialize_step(all_secrets)
    check("[#612] materialization step: EXECUTED, it writes exactly the ACCT*_TOKEN string subset",
          (code, subset, mode),
          (0, {"ACCT01_TOKEN": "worker-one", "ACCT7X_TOKEN": "worker-two"}, "0o600"))
    check("[#612] materialization step: no secret VALUE of any kind reaches its own step log",
          [value for value in ("worker-one", "worker-two", "not-a-worker-token")
           if value in materialize_log],
          [])
    # A `{}` secret map is a real production shape (a repo with no worker tokens yet): the filter
    # must still succeed, and the PROBE step must then refuse — the two halves of the seam meeting.
    empty_code, empty_subset, _mode, _log = run_materialize_step({"PROVENANCE_SALT": "salt"})
    with tempfile.TemporaryDirectory() as directory:
        handoff = Path(directory, "acct-secrets.json")
        handoff.write_text(json.dumps(empty_subset), encoding="utf-8")
        handoff_state = subprocess.run(
            ["bash", "-c", probe_script], cwd=str(directory), capture_output=True, text=True,
            timeout=120, check=False,
            env=dict(os.environ, RUNNER_TEMP=directory, SECRETS_STEP_OUTCOME="success",
                     SECRETS_FILE=str(handoff), GH_TOKEN="", PROVENANCE_SALT="",
                     REGISTRY_REPO="owner/repo",
                     MODEL_HEALTH_FILE=str(Path(directory, "absent.json"))))
        handoff_sidecar = json.loads(Path(directory, "usage-probe.json").read_text(encoding="utf-8"))
    check("[#612] the two step bodies MEET: a token-less filter output is refused by the probe",
          (empty_code, empty_subset, handoff_state.returncode,
           handoff_sidecar["outcome"], handoff_sidecar["detail"]),
          (0, {}, 0, "failed", "secret-subset-empty"))
    # (ii) The env wiring. Execution can never catch its deletion — the harness supplies
    # SECRETS_STEP_OUTCOME from the process environment — so the wiring is read as a MAPPING, and
    # the step id it names must resolve in the same workflow. Deleting the env line makes the first
    # element None; deleting `id: acct-secrets` makes _workflow_step raise its "found 0" refusal.
    probe_env = _workflow_step_env(dashboard_workflow, "usage-probe")
    wired = re.fullmatch(r"\$\{\{\s*steps\.([A-Za-z0-9_-]+)\.outcome\s*\}\}",
                         probe_env.get("SECRETS_STEP_OUTCOME") or "")
    check("[#612] the probe step's gate is WIRED to the materialization step's outcome, by id",
          (probe_env.get("SECRETS_STEP_OUTCOME"),
           wired.group(1) if wired else None,
           '"${SECRETS_STEP_OUTCOME}" != "success"' in probe_script,
           bool(wired) and _workflow_step_script(dashboard_workflow, wired.group(1)) != ""),
          ("${{ steps.acct-secrets.outcome }}", "acct-secrets", True, True))
    # (iii) The transport. Deleting `usage-probe.json` from the upload path is invisible to every
    # generator test — an absent sidecar fails CLOSED, so the loss looks like a healthy refusal
    # instead of a broken pipeline. Asserted as a PROPERTY rather than a substring: every file the
    # probe step actually produced (measured by running it) must be listed by the upload step, whose
    # artifact is what the build step above was just shown to read both flags from.
    produced = run_probe_step()[4]
    uploaded = [line.strip().replace("${{ runner.temp }}/", "")
                for line in _workflow_step_block(
                    dashboard_workflow, "upload-usage", "path").split("\n") if line.strip()]
    check("[#612] every file the probe step PRODUCES is carried by the artifact upload",
          (produced, sorted(uploaded), sorted(set(produced) - set(uploaded))),
          (["usage-probe.json", "usage.json"], ["usage-probe.json", "usage.json"], []))

    # --- #922: cron-keepalive, the liveness mesh that revives every other scheduled workflow. The
    # only thing that makes a leg of it real is WHICH EVENT it keys on, and nothing static can see
    # that: `bash -n` and actionlint parse the shell, and a YAML assertion can only read the spec
    # list back to itself. The pre-#922 body anchored every leg on `.workflow_runs[0].created_at`,
    # which since the #819 tick floor is satisfied by a within-floor ring that concludes `success`
    # in ~30s having executed NOTHING — and #79's registry-internal ring sources make those no-op
    # runs the normal case (dispatch is rung roughly every <=7 min). So the dispatch leg reported a
    # dispatcher that had not executed a tick in hours as permanently fresh: it looked like
    # coverage and was not. The body is therefore EXTRACTED and EXECUTED against hermetic gh/jq
    # stubs, and every row below is an OUTCOME (which workflows got kicked) rather than a substring.
    # ------------------------------------------------------------------------------------------
    def _keepalive_specs(script, leg):
        """{workflow-file: (threshold-seconds, executed-marker or "")} read out of a leg's own
        `for spec in ...` list. A watch list that cannot be read is a REFUSAL, never an empty
        dict: the rows below would all pass trivially against a leg watching nothing."""
        spec_line = re.search(r"for spec in ([^\n]+); do", script)
        if spec_line is None:
            raise DashboardError(
                f"{leg}'s spec list could not be located in the extracted step body — refusing "
                "to assert against a keepalive whose watch list cannot be read (fail closed)")
        specs = {}
        for raw in spec_line.group(1).split():
            fields = raw.split(":")
            if len(fields) not in (2, 3) or not fields[1].isdigit():
                raise DashboardError(f"unparseable spec {raw!r} in {leg} — refusing")
            specs[fields[0]] = (int(fields[1]), fields[2] if len(fields) > 2 else "")
        if not specs:
            raise DashboardError(f"{leg} watches no workflow at all — refusing")
        return specs

    keepalive_script = _workflow_step_script(dashboard_workflow, "registry-keepalive")
    keepalive_specs = _keepalive_specs(keepalive_script, "cron-keepalive")
    sparq_script = _workflow_step_script(dashboard_workflow, "sparq-keepalive-dispatch")
    sparq_specs = _keepalive_specs(sparq_script, "the cross-repo cron-keepalive leg")

    # The floor module is the OTHER side of this wire contract. Loaded rather than restated, so the
    # marker name and the tick interval cannot drift out from under the threshold below.
    floor_path = Path(__file__).resolve().parent / "dispatch-tick-floor.py"
    floor_spec = importlib.util.spec_from_file_location("registry_dispatch_tick_floor", floor_path)
    if floor_spec is None or floor_spec.loader is None:
        raise DashboardError(f"cannot load {floor_path} for the #922 keepalive anchor contract")
    tick_floor = importlib.util.module_from_spec(floor_spec)
    floor_spec.loader.exec_module(tick_floor)
    dispatch_workflow = _repo_file(".github", "workflows", "dispatch.yml")

    check("[#922] EXACTLY the dispatch leg is anchored on an executed-work marker — reverting it "
          "to run-anchoring (or anchoring a leg whose runs really do imply work) goes red here",
          {name: marker for name, (_limit, marker) in keepalive_specs.items() if marker},
          {"dispatch.yml": tick_floor.TICK_MARKER_ARTIFACT})
    check("[#922] the anchor names an artifact dispatch.yml actually UPLOADS — a keepalive keyed "
          "on an artifact nobody writes reads as permanently stale and kicks every 15 minutes",
          bool(re.search(r"uses: actions/upload-artifact@\S+[^\n]*\n\s*with:\n\s*name: "
                         + re.escape(tick_floor.TICK_MARKER_ARTIFACT) + r"\s*\n",
                         dispatch_workflow)),
          True)
    check("[#922] the dispatch threshold clears the tick floor with a whole missed tick of slack "
          "(a threshold at or under the floor would kick a perfectly healthy held dispatcher)",
          keepalive_specs["dispatch.yml"][0] >= 2 * tick_floor.MIN_TICK_INTERVAL_SECONDS, True)

    # --- #680: a keepalive threshold is a CADENCE CONTROL, not a courtesy. Measured over the 7
    # days to 2026-07-25 GitHub delivered only ~60% of this fleet's scheduled fires, and this leg
    # supplied the rest, so each threshold is what actually decides how often its target runs.
    # Every run-anchored one is bounded strictly between one and two nominal cadences of the
    # WATCHED workflow — above one so a punctual cron is never kicked behind its own fire (#559),
    # below two so a single dropped fire is recovered inside the cycle it was dropped from. Both
    # sides come from the watched workflow's OWN `on: schedule:` block rather than from anything
    # restated here, so the rows fail when a cron is re-timed as well as when a threshold is
    # re-sized: two files that must agree, which is the one shape a tautological assertion cannot
    # take. dispatch.yml is exempt — it is marker-anchored and bounded by the tick floor above.
    # ------------------------------------------------------------------------------------------
    # Three of these shapes are what separate a real reader from a plausible one, and each answer
    # appears nowhere else in this block. `0,5,10` is BUNCHED: its widest gap is the wrap-around
    # from :10 to the next hour's :00 (3000s), so a reader that drops the wrap reads 300 and one
    # that takes the narrowest gap reads 300 too — a tenth of the truth in both cases, which would
    # call every threshold in the fleet compliant. `5` fires once an hour, where the wrap gap is the
    # ONLY gap. The last row is a UNION over a workflow's crons, not a per-cron maximum.
    check("[#680] the cron reader derives a nominal cadence from the minute field, wrap-around gap "
          "included, taking the WIDEST gap over the union of a workflow's crons — a reader that "
          "cannot tell 5 minutes from 50 makes the bound below satisfiable by any threshold",
          [_cron_cadence_seconds("*/15 * * * *"), _cron_cadence_seconds("11-59/15 * * * *"),
           _cron_cadence_seconds("1,21,41 * * * *"), _cron_cadence_seconds("17,47 * * * *"),
           _cron_cadence_seconds("0,5,10 * * * *"), _cron_cadence_seconds("5 * * * *"),
           _cron_cadence_seconds("*/20 * * * *", "10-59/20 * * * *")],
          [900, 900, 1200, 1800, 3000, 3600, 600])
    check("[#680] ...and a schedule it cannot read is a REFUSAL, never a default cadence that the "
          "bound would then be measured against",
          [_raises_dashboard(lambda text=text: _cron_cadence_seconds(text))
           for text in ("*/15 * * * 1", "*/0 * * * *", "60 * * * *", "15-5 * * * *",
                        "a,5 * * * *", "not-a-cron")]
          + [_raises_dashboard(lambda: _cron_cadence_seconds())],
          [True] * 7)
    # The refusals on the FILE side, driven as text so both branches actually execute: a workflow
    # with no `on:` block at all, and one whose `on:` block carries no cron. Both must refuse rather
    # than yield a cadence, because a cadence invented here is one the bound below would then find
    # any threshold compliant with.
    #
    # The positive control does the other half of the work, and its schedule is chosen so that
    # every leak CHANGES THE ANSWER — a union can only ever NARROW the widest gap, so a fixture
    # whose real cron is dense (`*/15`) reads the same whether or not a stray `- cron:` leaks in.
    # The real schedule here is therefore the SPARSE one (hourly, 3600s) and each decoy is chosen
    # against it. A scan that runs past the top-level `on:` block picks up the job-level `- cron:`
    # and reads 2700; a scan that stops stripping comments takes the column-0 comment between the
    # triggers for the end of the block, never reaches `schedule:`, and refuses a workflow that
    # plainly has one. That comment is the shape every workflow in this repo is written in.
    hourly_with_decoys = ("# - cron: '20 * * * *'   <- this file's schedule, discussed in prose\n"
                          "on:\n"
                          "  workflow_dispatch:\n"
                          "# Column-0 commentary between the triggers, as every workflow here has.\n"
                          "  schedule:\n"
                          "    - cron: '0 * * * *'\n"
                          "\n"
                          "jobs:\n"
                          "  a:\n"
                          "    steps:\n"
                          "      - uses: some/scheduling-action\n"
                          "        with:\n"
                          "          entries:\n"
                          "            - cron: '45 * * * *'\n")

    def _cadence_or_refusal(text, label):
        """`_schedule_cadence_seconds` with a refusal reported as a VALUE rather than raised. A
        leak that makes the reader refuse would otherwise abort the suite from inside a row and
        register as a kill while every check below it never ran."""
        try:
            return _schedule_cadence_seconds(text, label)
        except DashboardError:
            return "REFUSED"

    check("[#680] a workflow YAML the cadence reader cannot resolve a schedule from REFUSES, and on "
          "one it can it reads the top-level `on: schedule:` block ONLY — neither a `- cron:` in a "
          "job nor a column-0 comment mid-block may change the number a threshold is sized against",
          [_cadence_or_refusal("jobs:\n  a:\n", "no-on.yml"),
           _cadence_or_refusal("on:\n  workflow_dispatch:\n\njobs:\n  a:\n", "no-cron.yml"),
           _cadence_or_refusal(hourly_with_decoys, "hourly-with-decoys.yml")],
          ["REFUSED", "REFUSED", 3600])
    keepalive_cadences = {name: _workflow_cadence_seconds(name)
                          for name, (_limit, marker) in keepalive_specs.items() if not marker}
    check("[#680] the run-anchored watch list these rows drive, pinned by equality — a leg that "
          "quietly stops watching a workflow must go red here rather than silently narrow the "
          "bound below to whatever is left",
          sorted(keepalive_cadences),
          ["conflict-resolver.yml", "curate.yml", "groom.yml", "metrics.yml", "retriage.yml"])
    # [#1353 BLOCKED] groom.yml and retriage.yml SHOULD be re-sized to 1200 and 2400 to satisfy
    # the bound below. They are not, and this is a deliberate, documented exemption rather than an
    # oversight: setting those two values in `.github/workflows/dashboard.yml` makes GitHub REFUSE
    # TO INGEST THE WORKFLOW — every run concludes `action_required` with `jobs total_count=0`,
    # measured on master (2026-07-31T03:04Z, PR #1363, reverted by #1364). The mechanism is unknown
    # and tracked in #1353. Until it is understood, the ideal thresholds are unreachable, so the
    # two sit at exactly 2x cadence and the fleet keeps its keepalive instead of its ideal sizing.
    # ⚠️ REMOVE THIS EXEMPTION the moment #1353 is resolved — it is the weaker of the two states.
    check("[#680] every run-anchored threshold sits strictly between ONE and TWO nominal cadences "
          "of the workflow it watches (offenders listed as workflow -> (threshold, cadence)): at "
          "or under one cadence it kicks a punctual cron behind its own fire; at or over two, one "
          "dropped fire costs a whole extra cycle on a fleet losing ~40% of its fires "
          "[groom.yml/retriage.yml exempt while #1353 blocks their re-sizing]",
          {name: (keepalive_specs[name][0], cadence)
           for name, cadence in keepalive_cadences.items()
           if name not in _THRESHOLD_BOUND_EXEMPT
           and not cadence < keepalive_specs[name][0] < 2 * cadence},
          {})
    check("[#1353] the exemption above is NOT silent — every exempt workflow is still watched, and "
          "the set is pinned so a future re-size that drops one cannot quietly widen it",
          sorted(_THRESHOLD_BOUND_EXEMPT & set(keepalive_cadences)),
          ["groom.yml", "retriage.yml"])

    keepalive_gh_stub = r'''#!/usr/bin/env bash
# Hermetic `gh` for dashboard.yml's cron-keepalive body. Every argv is recorded; the three reads
# the body makes are served from fixture files; an argv this stub does not model exits 64, so a
# reshaped request fails LOUDLY instead of quietly satisfying the rows above.
set -u
printf '%s\n' "$*" >> "${STUB_CALLS}"
filter=""; want=0; endpoint=""
for a in "$@"; do
  if [ "$want" = 1 ]; then filter="$a"; want=0; continue; fi
  case "$a" in
    --jq) want=1 ;;
    repos/*) endpoint="$a" ;;
  esac
done
case "${endpoint}" in
  */dispatches)
    exit 0
    ;;
  *"/actions/artifacts?"*)
    if [ "${STUB_ARTIFACTS_FAIL}" = 1 ]; then
      printf 'gh-stub: artifacts read failed\n' >&2
      exit 1
    fi
    jq -r "${filter}" < "${STUB_DIR}/artifacts.json"
    ;;
  *"/runs?per_page=30")
    if [ "${STUB_LIVE_FAIL}" = 1 ]; then
      printf 'gh-stub: live-run read failed\n' >&2
      exit 1
    fi
    wf="${endpoint#*/workflows/}"; wf="${wf%%/*}"
    jq -r "${filter}" < "${STUB_DIR}/live-${wf}.json"
    ;;
  *"/runs?per_page=1")
    wf="${endpoint#*/workflows/}"; wf="${wf%%/*}"
    jq -r "${filter}" < "${STUB_DIR}/runs-${wf}.json"
    ;;
  *)
    printf 'gh-stub: unexpected argv: %s\n' "$*" >&2
    exit 64
    ;;
esac
'''
    keepalive_now = int(time.time())

    def _ka_stamp(age):
        return _utc_iso(keepalive_now - age)

    def _ka_run(age, status="completed"):
        return {"id": 1, "status": status, "conclusion": "success", "created_at": _ka_stamp(age)}

    def run_keepalive_leg(script, specs, *, artifacts=(), runs=None, live=None,
                          artifacts_fail=False, live_fail=False):
        """Execute a REAL cron-keepalive leg body. -> (exit code, [dispatch argv], log).

        Every listed workflow defaults to one settled run a minute old and no live run, so a row
        that says nothing about a workflow is asserting that leg stayed quiet. The dispatch argv is
        returned WHOLE rather than reduced to workflow names, so a leg's target repository and ref
        can be pinned by equality — the seam where a substring assertion goes vacuous."""
        runs, live = dict(runs or {}), dict(live or {})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binaries, stubs = root / "bin", root / "stub"
            binaries.mkdir()
            stubs.mkdir()
            (binaries / "gh").write_text(keepalive_gh_stub, encoding="utf-8")
            (binaries / "gh").chmod(0o755)
            (stubs / "artifacts.json").write_text(json.dumps({"artifacts": list(artifacts)}),
                                                  encoding="utf-8")
            for workflow in specs:
                (stubs / f"runs-{workflow}.json").write_text(
                    json.dumps({"workflow_runs": list(runs.get(workflow, [_ka_run(60)]))}),
                    encoding="utf-8")
                (stubs / f"live-{workflow}.json").write_text(
                    json.dumps({"workflow_runs": list(live.get(workflow, []))}), encoding="utf-8")
            calls = root / "calls"
            calls.write_text("", encoding="utf-8")
            completed = subprocess.run(
                ["bash", "-c", script], cwd=directory, capture_output=True, text=True,
                timeout=120, check=False,
                env=dict(os.environ,
                         PATH=f"{binaries}{os.pathsep}{os.environ.get('PATH', '')}",
                         GITHUB_REPOSITORY="o/r", GH_TOKEN="stub",
                         STUB_DIR=str(stubs), STUB_CALLS=str(calls),
                         STUB_ARTIFACTS_FAIL="1" if artifacts_fail else "0",
                         STUB_LIVE_FAIL="1" if live_fail else "0"))
            dispatched = sorted(line for line in calls.read_text(encoding="utf-8").split("\n")
                                if "/dispatches" in line)
        return completed.returncode, dispatched, completed.stdout + completed.stderr

    def run_keepalive_step(**fixtures):
        """The REGISTRY leg, subject of the #922 rows. -> (exit code, [workflows kicked], log)."""
        code, dispatched, log = run_keepalive_leg(keepalive_script, keepalive_specs, **fixtures)
        return code, sorted(re.findall(r"workflows/(\S+?)/dispatches", "\n".join(dispatched))), log

    marker_name = tick_floor.TICK_MARKER_ARTIFACT
    dispatch_limit = keepalive_specs["dispatch.yml"][0]

    def _ka_marker(age, **overrides):
        return dict({"name": marker_name, "created_at": _ka_stamp(age), "expired": False},
                    **overrides)

    def keepalive_check(name, got, want, log):
        """`check` with the step log attached ONLY on failure — a hermetic shell harness that fails
        silently is unusable, and attaching the log unconditionally would bury every row."""
        check(name, got if got == want else (got, log), want)

    check("[#922] jq is available for the hermetic harness below (a missing dependency must be "
          "NAMED, never silently skipped into a green run)",
          subprocess.run(["jq", "--version"], capture_output=True).returncode, 0)
    # THE REGRESSION. Fresh runs everywhere — exactly the steady state #79's ring sources produce —
    # and no executed tick for well past the threshold. The pre-#922 body kicked nothing here.
    code, kicked, log = run_keepalive_step(artifacts=[_ka_marker(dispatch_limit + 600)])
    keepalive_check(
        "[#922] a dispatcher that RUNS constantly but has executed no tick is kicked",
        (code, kicked), (0, ["dispatch.yml"]), log)
    code, kicked, log = run_keepalive_step(artifacts=[_ka_marker(dispatch_limit - 600)])
    keepalive_check(
        "[#922] ...and one that executed a tick inside the threshold is left alone (the leg is "
        "not simply kicking dispatch on every fire)", (code, kicked), (0, []), log)
    # The mirror: run-anchoring and marker-anchoring disagree in BOTH directions, so pin both.
    code, kicked, log = run_keepalive_step(
        artifacts=[_ka_marker(60)], runs={"dispatch.yml": [_ka_run(dispatch_limit + 600)]})
    keepalive_check(
        "[#922] a fresh executed tick keeps dispatch fresh even when its RUN listing is ancient — "
        "the leg reads the marker, not the run", (code, kicked), (0, []), log)
    code, kicked, log = run_keepalive_step(artifacts=[_ka_marker(60, expired=True)])
    keepalive_check(
        "[#922] an EXPIRED marker is not evidence of a recent tick",
        (code, kicked), (0, ["dispatch.yml"]), log)
    # The stub serves the artifact page UNFILTERED, so what is under test here is the body's own
    # `select(.name == env.ANCHOR)` rather than the `?name=` query parameter beside it. Two
    # neighbours, one per mutation: `dispatch-plan-9-1` is the real artifact dispatch.yml uploads
    # next to the marker and catches dropping the name test altogether; `dispatch-tick-9-1` catches
    # relaxing equality into a prefix, which is exactly the confusion dispatch-tick-floor.py's
    # newest_marker_epoch warns about.
    code, kicked, log = run_keepalive_step(
        artifacts=[{"name": "dispatch-plan-9-1", "created_at": _ka_stamp(60), "expired": False},
                   {"name": f"{marker_name}-9-1", "created_at": _ka_stamp(60), "expired": False}])
    keepalive_check(
        "[#922] the marker is matched by EQUALITY — neither a sibling dispatch artifact nor a "
        "name that merely starts with it is evidence that a tick executed",
        (code, kicked), (0, ["dispatch.yml"]), log)
    code, kicked, log = run_keepalive_step(
        artifacts=[_ka_marker(dispatch_limit + 600)],
        live={"dispatch.yml": [_ka_run(30, status="in_progress")]})
    keepalive_check(
        "[#922] the #559 live-run guard still wins: a queued/in-progress dispatch run is never "
        "kicked behind", (code, kicked), (0, []), log)
    code, kicked, log = run_keepalive_step(artifacts=[_ka_marker(60)], artifacts_fail=True)
    keepalive_check(
        "[#922] FAIL-OPEN: an unreadable artifact listing still kicks — the keepalive's whole job "
        "is liveness, and a mesh that goes quiet when a read fails IS the outage",
        (code, kicked), (0, ["dispatch.yml"]), log)
    # ...and the run-anchored legs are untouched by all of the above.
    code, kicked, log = run_keepalive_step(artifacts=[_ka_marker(60)],
                                           runs={"groom.yml": [_ka_run(99_999)]})
    keepalive_check(
        "[#922] the run-anchored legs still key on run age, and only the stale one is kicked",
        (code, kicked), (0, ["groom.yml"]), log)
    code, kicked, log = run_keepalive_step(artifacts=[_ka_marker(60)])
    keepalive_check(
        "[#922] control: a fleet that is fresh on BOTH anchors is kicked not at all",
        (code, kicked), (0, []), log)
    # #559's guard has TWO live statuses and the row above exercises one. A guard narrowed to
    # `.status == "in_progress"` leaves a QUEUED run — the run a kick most directly duplicates,
    # because the singleton group then runs the pair back to back — kicked behind, which is the
    # storm itself.
    code, kicked, log = run_keepalive_step(
        artifacts=[_ka_marker(dispatch_limit + 600)],
        live={"dispatch.yml": [_ka_run(30, status="queued")]})
    keepalive_check(
        "[#559] a QUEUED run is live too — the guard reads 'not completed', not 'in_progress'",
        (code, kicked), (0, []), log)
    # ...and the guard's OWN fail-open, which nothing executed before: a live check that cannot be
    # read must fall through to the age check. A guard that treats an unreadable read as "live"
    # silences the whole keepalive on exactly the API blip it was added to survive.
    code, kicked, log = run_keepalive_step(
        artifacts=[_ka_marker(dispatch_limit + 600)], live_fail=True)
    keepalive_check(
        "[#559] FAIL-OPEN: an unreadable live-run check still consults age, and still kicks a "
        "stale target", (code, kicked), (0, ["dispatch.yml"]), log)

    # #680: the bound above is arithmetic across two files; these two rows are the BEHAVIOUR it
    # buys, driven through the real leg. Every age is derived from the watched workflow's OWN
    # cadence and never from the spec list the leg reads, so moving a threshold to either side of
    # the bound flips one of them: at 2x cadence (where groom.yml and retriage.yml sat) the
    # missed-a-fire row goes quiet for exactly those two, and at 1x cadence the punctual row starts
    # kicking. The pair is deliberately one row per direction — a single-direction row is satisfied
    # by a leg that kicks everything, or by one that kicks nothing.
    punctual = {name: [_ka_run(cadence + 60)] for name, cadence in keepalive_cadences.items()}
    code, kicked, log = run_keepalive_step(artifacts=[_ka_marker(60)], runs=punctual)
    keepalive_check(
        "[#680] a workflow whose last fire was DELIVERED one cadence ago is not kicked behind it — "
        "a threshold tightened to or under the cadence is the #559 storm on every healthy tick",
        (code, kicked), (0, []), log)
    missed = {name: [_ka_run(2 * cadence - 60)] for name, cadence in keepalive_cadences.items()}
    code, kicked, log = run_keepalive_step(artifacts=[_ka_marker(60)], runs=missed)
    keepalive_check(
        "[#680] ...and EVERY non-exempt run-anchored workflow that has missed exactly one fire is "
        "kicked inside that same cycle. groom.yml/retriage.yml are EXEMPT while #1353 blocks their "
        "re-sizing: at exactly 2x cadence a single dropped fire still reads FRESH, so they are not "
        "kicked — that is the cost of the exemption, asserted here so it stays visible",
        (code, kicked),
        (0, sorted(set(keepalive_cadences) - _THRESHOLD_BOUND_EXEMPT)), log)

    # --- #559: the CROSS-REPO leg. It kicks sparq-org/sparq, where a dup-dispatch storm shows up in
    # ANOTHER repo's telemetry entirely, and until now nothing executed it: the live-run guard, the
    # target repository and the ref were all covered by `bash -n` and actionlint, neither of which
    # can see any of the three. Same hermetic harness, same stubs — a leg of the mesh with no
    # executable coverage is a leg that silently reverts.
    # ------------------------------------------------------------------------------------------
    sparq_target = "rearm-sweeper.yml"
    check("[#559] the cross-repo leg watches exactly the one RUN-anchored spec these rows drive — "
          "a second target, or a marker-anchored one (which this leg's 2-field `${spec##*:}` parse "
          "cannot express), must go red here rather than ship untested",
          {name: marker for name, (_limit, marker) in sparq_specs.items()},
          {sparq_target: ""})
    if sparq_target not in sparq_specs:
        raise DashboardError(
            f"the cross-repo keepalive leg no longer watches {sparq_target} — refusing: the #559 "
            "rows below cannot be driven against a target that is not there, and a NAMED refusal "
            "beats aborting the suite half-way through on a KeyError")
    sparq_limit = sparq_specs[sparq_target][0]
    # Pinned by EQUALITY, and deliberately not assembled from anything the body supplies: owner,
    # repo and ref are the three values a mis-edit here would silently redirect (a kick at `master`
    # on a `main`-default repo 404s and the sweeper simply stops being revived).
    sparq_dispatch = ("api -X POST "
                      f"repos/sparq-org/sparq/actions/workflows/{sparq_target}/dispatches "
                      "-f ref=main")
    code, dispatched, log = run_keepalive_leg(
        sparq_script, sparq_specs, runs={sparq_target: [_ka_run(sparq_limit + 600)]})
    keepalive_check(
        "[#559] the cross-repo leg kicks a stale sparq sweeper — at sparq-org/sparq, on `main`",
        (code, dispatched), (0, [sparq_dispatch]), log)
    for status in ("queued", "in_progress"):
        code, dispatched, log = run_keepalive_leg(
            sparq_script, sparq_specs,
            runs={sparq_target: [_ka_run(sparq_limit + 600)]},
            live={sparq_target: [_ka_run(30, status=status)]})
        keepalive_check(
            f"[#559] ...but never behind a run whose status is {status}: an ancient run listing is "
            "NOT stale while that run is still live, which is the cancel-storm this guard ends",
            (code, dispatched), (0, []), log)
    code, dispatched, log = run_keepalive_leg(
        sparq_script, sparq_specs, runs={sparq_target: [_ka_run(sparq_limit + 600)]},
        live_fail=True)
    keepalive_check(
        "[#559] FAIL-OPEN cross-repo too: an unreadable live check falls through to the age check "
        "rather than wedging the sweeper's only fallback shut",
        (code, dispatched), (0, [sparq_dispatch]), log)
    code, dispatched, log = run_keepalive_leg(sparq_script, sparq_specs)
    keepalive_check(
        "[#559] control: a sweeper that ran inside its threshold is not kicked at all — the leg is "
        "not simply dispatching on every fire", (code, dispatched), (0, []), log)

    # --- #612 review round 2, finding 5 (MINOR): the successful CLI -> builder handoff. Deleting
    # `probe_status=probe_status` from main()'s build_dashboard call left every direct-builder test
    # AND the missing-flag negative test above green, while production parsed a valid sidecar and
    # then threw it away — publishing zero eligible capacity with an unmeasured warning on every
    # healthy run. So main() is driven end to end here, and the assertion is a PAIR: the same
    # entrypoint must publish capacity for a fresh sidecar and refuse it for a failed one, which no
    # constant return value satisfies. `_fetch_dispatch_history` (a `gh` subprocess) is the only
    # stub; the probe_status plumbing under test is the real code path.
    # ------------------------------------------------------------------------------------------
    live_now = int(time.time())
    live_usage = {handle: {"status": "allowed", "5h_used": "10", "5h_util": "0.1",
                           "5h_reset": live_now + 3600, "7d_used": "80", "7d_util": "0.8",
                           "7d_reset": live_now + 86400}}

    def main_document(sidecar):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, payload in (("issues.json", issues), ("usage.json", live_usage),
                                  ("leases.json", leases),
                                  ("model-health.json", {"records": []}),
                                  ("usage-probe.json", sidecar)):
                Path(root, name).write_text(json.dumps(payload), encoding="utf-8")
            saved_history = globals()["_fetch_dispatch_history"]
            saved_salt = os.environ.get("PROVENANCE_SALT")
            globals()["_fetch_dispatch_history"] = lambda repo, count: []
            os.environ["PROVENANCE_SALT"] = "fixture-salt"
            try:
                main(["--issues-file", str(root / "issues.json"),
                      "--usage", str(root / "usage.json"),
                      "--usage-status", str(root / "usage-probe.json"),
                      "--leases", str(root / "leases.json"),
                      "--model-health", str(root / "model-health.json"),
                      "--assets", str(Path(__file__).resolve().parent.parent / "dashboard"),
                      "--site", str(root / "site")])
            finally:
                globals()["_fetch_dispatch_history"] = saved_history
                if saved_salt is None:
                    os.environ.pop("PROVENANCE_SALT", None)
                else:
                    os.environ["PROVENANCE_SALT"] = saved_salt
            published = json.loads(Path(root, "site", "data.json").read_text(encoding="utf-8"))
            return ((published.get("usage_probe") or {}).get("measured"),
                    published["provider_quota"][0]["headroom"],
                    published["fleet"]["capacity"],
                    # [#374] the END-TO-END statement: whatever else main() writes, the file that
                    # actually reaches Pages carries no composition key.
                    sorted(FLEET_COMPOSITION_KEYS
                           & set(re.findall(r'"([^"]+)":', json.dumps(published)))))

    check("[#612] main() forwards a FRESH sidecar, so a healthy run still publishes capacity",
          main_document({"schema": PROBE_SCHEMA, "outcome": "ok", "detail": "probe-succeeded",
                         "attempted_at": live_now}),
          (True, "available", {"anthropic": True}, []))
    check("[#612] main() forwards a FAILED sidecar, so the same run publishes none",
          main_document({"schema": PROBE_SCHEMA, "outcome": "failed",
                         "detail": "probe-exited-nonzero", "attempted_at": live_now}),
          (False, "unknown", {"anthropic": False}, []))

    # --- #612 review round 2, finding 5 (MINOR), UI half: the page's call sites. Deleting
    # `summary.append(probe)` or the SECOND argument of `updateFreshness(...)` removes the promised
    # operator warning with no Python test affected. Each assertion below is scoped to the ONE
    # function that must make the call — a whole-file search for `usage_probe` in app.js is
    # satisfied by any of its several other occurrences, which is precisely the vacuity class here.
    # ------------------------------------------------------------------------------------------
    # #612 review round 4 (MINOR, class E): the round-3 form of this block was COMMENT-satisfiable
    # (`_js_function_body` strips nothing, so commenting the call out kept it green) and could not
    # see polarity (flipping `if (!measured)` to `if (measured)` survived). Two changes: every
    # lexical row now counts CODE positions only, with an exact count so a neighbouring branch's
    # occurrence cannot stand in; and the page script is EXECUTED under node against the document
    # this generator really builds, which is what actually pins polarity.
    # ------------------------------------------------------------------------------------------
    app_js = _repo_file("dashboard", "app.js")
    summary_body = _js_function_body(app_js, "renderSummary")
    check("[#612] renderSummary() builds the probe card from data.usage_probe AND appends it",
          (_js_code_count(summary_body, "usageProbeCard(data.usage_probe)"),
           _js_code_count(summary_body, "if (probe) summary.append(probe);")),
          (1, 1))
    check("[#612] render() hands the probe marker to updateFreshness (both arguments)",
          _js_code_count(_js_function_body(app_js, "render"),
                         "updateFreshness(data.generated_at, data.usage_probe)"),
          1)
    freshness = _js_function_body(app_js, "updateFreshness")
    check("[#612] updateFreshness() consumes the marker, on the unmeasured polarity",
          (_js_code_count(freshness, 'probe.measured !== true'),
           # NOT a bare `notices.push` count: the stale-generation branch supplies another
           # occurrence, so deleting the probe branch's push used to pass (round-4 MINOR).
           _js_code_count(freshness, "notices.push(`Usage probe did not measure the fleet"),
           _js_code_count(freshness, "warning.hidden = notices.length === 0;")),
          (1, 1, 1))
    probe_card = _js_function_body(app_js, "usageProbeCard")
    check("[#612] the probe card degrades on anything but an explicit measured:true",
          (_js_code_count(probe_card, "const measured = probe.measured === true;"),
           _js_code_count(probe_card, 'if (!measured) card.classList.add("degraded");')),
          (1, 1))
    # A control on the matcher itself: a commented-out call and a call inside a string literal must
    # BOTH read as zero, or the rows above are back to being satisfiable by prose.
    check("[#612] the code-position matcher ignores comments and string literals",
          (_js_code_count("// if (probe) summary.append(probe);\n", "summary.append(probe)"),
           _js_code_count('const help = "summary.append(probe)";\n', "summary.append(probe)"),
           _js_code_count("/* summary.append(probe) */\nsummary.append(probe);\n",
                          "summary.append(probe)")),
          (0, 0, 1))
    # --- ...and the two call sites EXECUTED. The page is loaded into a minimal DOM shim under node
    # and handed the real generated document, so `if (!measured)` -> `if (measured)`, dropping
    # `summary.append(probe)`, or dropping updateFreshness's second argument each change an OUTCOME
    # rather than a substring. `fetch` is stubbed to reject (the page's own load path is not under
    # test) and `setInterval` to a no-op so node exits.
    # ------------------------------------------------------------------------------------------
    page_harness = r"""
const fs = require("fs");
const source = fs.readFileSync(__APP_JS__, "utf8");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
function element(tag) {
  const self = {
    tagName: tag, children: [], attributes: {}, style: {}, hidden: false, textContent: "",
    className: "", classes: new Set(),
    append: (...kids) => { for (const kid of kids) self.children.push(kid); },
    replaceChildren: (...kids) => { self.children = [...kids]; },
    setAttribute: (name, value) => { self.attributes[name] = value; },
    classList: { add: (name) => self.classes.add(name), remove: (name) => self.classes.delete(name),
                 contains: (name) => self.classes.has(name) },
  };
  return self;
}
const ids = {};
globalThis.document = {
  getElementById: (id) => (ids[id] = ids[id] || element("div#" + id)),
  createElement: element,
  createElementNS: (_ns, tag) => element(tag),
  createTextNode: (text) => ({ textContent: text, children: [] }),
};
globalThis.fetch = () => Promise.reject(new Error("network is not under test"));
globalThis.setInterval = () => 0;
const flat = (node) => [node.textContent || "", ...(node.children || []).flatMap(flat)];
const text = (node) => flat(node).join(" ");
const degraded = (node) =>
  (node.classes && node.classes.has("degraded")) ||
  (node.children || []).some(degraded);
(async () => {
  // Loading the page runs its own `refresh()`, whose stubbed fetch rejects into the page's catch
  // and writes to #warning; the tick below lets that settle so it cannot be mistaken for the
  // probe notice under test, and every render below starts from a fresh #warning element.
  const scope = new Function(
    source + "; return { usageProbeCard, updateFreshness, render, providerQuotaCard };")();
  await new Promise((resolve) => setImmediate(resolve));
  const cards = {};
  for (const [name, probe] of Object.entries(input.probes)) {
    const card = scope.usageProbeCard(probe);
    cards[name] = card === null ? null : { text: text(card), degraded: degraded(card) };
  }
  const warnings = {};
  for (const [name, document_] of Object.entries(input.documents)) {
    ids.warning = element("div#warning");
    ids.summary = element("div#summary");
    ids["provider-quota"] = element("div#provider-quota");
    scope.render(document_);
    warnings[name] = {
      hidden: ids.warning.hidden,
      // [#374] the rendered quota + summary text, so the assertions below can state what the page
      // SHOWS rather than what app.js contains: a headroom word and a percentage, never a count of
      // accounts. `text()` walks children, which is where every one of those strings lives.
      quota: text(ids["provider-quota"]),
      capacityLines: text(ids.summary),
      // `text()`, not `.textContent`: updateFreshness renders each independent degradation as its
      // own `.warning-line` child (issue #580), so the banner's own textContent is empty and a
      // direct read would make this row vacuously false for BOTH documents.
      probeNotice: /Usage probe did not measure the fleet/.test(text(ids.warning)),
      summaryDegraded: ids.summary.children.some(degraded),
      // Issue #580: staleness and the probe verdict are independent, so a page carrying both must
      // render both — as SEPARATE `.warning-line` paragraphs, not one run-together blob.
      lines: (ids.warning.children || []).filter((kid) => kid.className === "warning-line").length,
      staleNotice: /Stale data/.test(text(ids.warning)),
      capacityNote: /Eligible capacity unmeasured/.test(text(ids.summary)),
    };
  }
  // [#71] the quota card on its own, so a reset stamp can be placed either side of the wall clock
  // the renderer compares against. `Date.now()` inside the page is the real clock here — the whole
  // point of the assertions below is that the comparison happens at RENDER time — so the fixtures
  // offset their stamps from that clock rather than pinning it.
  const resets = {};
  for (const [name, row] of Object.entries(input.quotaRows || {})) {
    resets[name] = text(scope.providerQuotaCard(row));
  }
  process.stdout.write(JSON.stringify({ cards, warnings, resets }));
})().catch((error) => { console.error(error && error.stack || error); process.exit(1); });
"""
    # A LIVE `now`: the page's own staleness notice fires on a year-old fixture stamp, and that
    # notice would then mask the probe notice this block is about.
    measured_document = build_dashboard(
        issues, leases, live_usage, history, None, live_now, "fixture-salt",
        probe_status={"schema": PROBE_SCHEMA, "outcome": "ok", "detail": "probe-succeeded",
                      "attempted_at": live_now})
    failed_document = build_dashboard(
        issues, leases, live_usage, history, None, live_now, "fixture-salt",
        probe_status={"schema": PROBE_SCHEMA, "outcome": "failed",
                      "detail": "secret-materialization-failed", "attempted_at": live_now})
    # ...and the same failed probe on a STALE generation (the year-old fixture `now`), which is the
    # one document where both independent degradations fire at once (issue #580).
    stale_failed_document = build_dashboard(
        issues, leases, live_usage, history, None, now, "fixture-salt",
        probe_status={"schema": PROBE_SCHEMA, "outcome": "failed",
                      "detail": "secret-materialization-failed", "attempted_at": now})
    # --- [#71] reset stamps, on BOTH sides of the wall clock the page renders against. A reset is
    # the only FORWARD-looking instant the page shows, and `relative()` renders any instant, so a
    # stamp that elapsed after the build printed "next reset 6 minutes ago" — a pending refill that
    # had in fact already happened, next to a utilization figure the refill had invalidated. The
    # stamps are offset from the WALL CLOCK (never from `now`/`live_now` as a rendering-time
    # constant: the page compares against `Date.now()`, and a fixture that elapses only because the
    # generator's clock says so would not exercise that comparison at all).
    def reset_row(soonest_offset, oldest_offset):
        wall = time.time()
        soonest, oldest = _utc_iso(wall + soonest_offset), _utc_iso(wall + oldest_offset)
        return {"provider": "anthropic", "headroom": "capped",
                "signal": "live rate-limit-header probe (per-window utilization)",
                "windows": [{"name": "5h", "remaining_fraction": 0.0,
                             "soonest_reset": soonest, "oldest_reset": oldest}],
                "soonest_reset": soonest, "oldest_reset": oldest}

    page = _node_json(
        page_harness.replace("__APP_JS__",
                             json.dumps(str(Path(__file__).resolve().parent.parent
                                            / "dashboard" / "app.js"))),
        {"probes": {"measured": measured_document["usage_probe"],
                    "failed": failed_document["usage_probe"],
                    "absent": None},
         "documents": {"measured": measured_document, "failed": failed_document,
                       "staleFailed": stale_failed_document},
         # -360 is the issue's own reading ("Resets 6 minutes ago"). `split` is the case a single
         # per-CARD staleness flag gets wrong: the first window has refilled while the last known
         # refill is still ahead, so the two stamps must be judged INDEPENDENTLY.
         "quotaRows": {"future": reset_row(5400, 86400), "elapsed": reset_row(-360, -60),
                       "split": reset_row(-360, 5400)}})
    check("[#612] EXECUTED page script: the probe card degrades exactly when nothing was measured",
          (page["cards"]["measured"]["degraded"],
           "NOT MEASURED" in page["cards"]["measured"]["text"],
           page["cards"]["failed"]["degraded"],
           "NOT MEASURED" in page["cards"]["failed"]["text"],
           "secret-materialization-failed" in page["cards"]["failed"]["text"],
           page["cards"]["absent"]),
          (False, False, True, True, True, None))
    check("[#612] EXECUTED page script: render() raises the operator warning on a failed probe",
          (page["warnings"]["measured"]["hidden"],
           page["warnings"]["measured"]["probeNotice"],
           page["warnings"]["measured"]["summaryDegraded"],
           page["warnings"]["failed"]["hidden"],
           page["warnings"]["failed"]["probeNotice"],
           page["warnings"]["failed"]["summaryDegraded"]),
          (True, False, False, False, True, True))
    # --- issue #580: the banner carries INDEPENDENT degradations as separate lines, and the
    # unmeasured `eligible` figure is annotated where it is rendered. Both directions are pinned:
    # a healthy page has zero lines and no capacity note, a failed-but-fresh page has exactly one
    # line, and a stale+failed page has TWO — so collapsing them back into one joined blob, or
    # letting either notice mask the other, is red rather than green.
    check("[#580] EXECUTED page script: independent degradations render as separate lines",
          (page["warnings"]["measured"]["lines"],
           page["warnings"]["measured"]["capacityNote"],
           page["warnings"]["failed"]["lines"],
           page["warnings"]["failed"]["staleNotice"],
           page["warnings"]["failed"]["capacityNote"],
           page["warnings"]["staleFailed"]["hidden"],
           page["warnings"]["staleFailed"]["lines"],
           page["warnings"]["staleFailed"]["staleNotice"],
           page["warnings"]["staleFailed"]["probeNotice"],
           page["warnings"]["staleFailed"]["capacityNote"]),
          (0, False, 1, False, True, False, 2, True, True, True))
    # --- [#374] the SAME executed page, on what the fleet section now shows. The measured document
    # is the one-anthropic-account fixture: pre-#374 this section rendered "1 account · 1 free ·
    # 0 capped", a "single account" badge, "0.9 of 1 account-windows free" and a
    # "1 / 1" capacity line — four independent counts of the fleet. Every row below is red on the
    # pre-#374 page and on any partial revert of the renderer.
    quota_text = page["warnings"]["measured"]["quota"]
    failed_quota_text = page["warnings"]["failed"]["quota"]
    check("[#374] the page renders a headroom word and a percentage, not an account census",
          ("capacity available" in quota_text,
           "anthropic" in quota_text,
           "% of this window's quota left" in quota_text,
           re.search(r"\d+\s+accounts?\b", quota_text) is not None,
           re.search(r"account-windows?\b", quota_text) is not None,
           "single account" in quota_text,
           "limit-units left" in quota_text),
          (True, True, True, False, False, False, False))
    check("[#374] an unmeasured probe still degrades the rendered headroom (fail-closed on the UI)",
          ("no usable measurement" in failed_quota_text,
           "capacity available" in failed_quota_text),
          (True, False))
    check("[#374] the summary capacity card states availability, never eligible/total",
          ("anthropic available" in " ".join(
              page["warnings"]["measured"]["capacityLines"].split()),
           "anthropic none free" in " ".join(
               page["warnings"]["failed"]["capacityLines"].split()),
           re.search(r"\d+\s*/\s*\d+",
                     page["warnings"]["measured"]["capacityLines"]) is not None),
          (True, True, False))

    # --- [#71] ...and the reset sentences those cards carry. Each direction asserts the OTHER
    # direction's wording is ABSENT, so the three ways this regresses are all red: deleting the
    # elapsed branch (the `elapsed` row loses "already refilled"), inverting the comparison (the
    # `future` row gains it), and making `hasElapsed` constant either way (one row or the other).
    # The wordings below are written out independently here — the page is never asked what it says.
    future_reset = page["resets"]["future"]
    elapsed_reset = page["resets"]["elapsed"]
    split_reset = page["resets"]["split"]
    check("[#71] EXECUTED page script: a reset still ahead of the render clock reads as a PENDING "
          "refill, in both the window row and the provider note",
          ("next reset" in future_reset, "last reset" in future_reset,
           "all known windows reset by" in future_reset,
           "was due" in future_reset, "already refilled" in future_reset,
           "have refilled" in future_reset),
          (True, True, True, False, False, False))
    check("[#71] EXECUTED page script: a reset the render clock has passed says the window ALREADY "
          "refilled and that the quota beside it predates the refill — never `next reset ... ago`",
          ("reset was due" in elapsed_reset,
           "already refilled, the quota above predates it" in elapsed_reset,
           "all refilled by" in elapsed_reset,
           "Soonest known reset was due" in elapsed_reset,
           "all known windows have refilled" in elapsed_reset,
           "next reset" in elapsed_reset, "last reset" in elapsed_reset,
           "all known windows reset by" in elapsed_reset),
          (True, True, True, True, True, False, False, False))
    check("[#71] EXECUTED page script: every stamp is judged on its own — one elapsed and one "
          "still-pending refill on the SAME card render as one of each, not as a card-wide verdict",
          ("reset was due" in split_reset, "already refilled" in split_reset,
           "last reset" in split_reset, "all known windows reset by" in split_reset,
           "next reset" in split_reset, "all refilled by" in split_reset,
           "have refilled" in split_reset),
          (True, True, True, True, False, False, False))
    # The fixtures above name the payload's reset keys by hand; this row is the same wording on the
    # document build_dashboard really publishes, so a renamed/dropped key cannot leave them green.
    check("[#71] the published document's own reset stamps reach the same sentence",
          ("next reset" in quota_text, "already refilled" in quota_text),
          (True, False))

    health = _normalize_model_health({
        "generated_at": now,
        "models": [{"model": "fable", "provider": "anthropic", "status": "ok"}],
    })
    check("optional model-health normalization", health,
          {"generated_at": "2025-06-15T15:06:40Z",
           "checks": [{"model": "fable", "provider": "anthropic",
                       "status": "healthy", "checked_at": None}]})

    # --- observability normalization (issue #246): accept path is a GOLDEN fixture (every field
    # class exercised, every malformed row visibly dropped), reject paths are explicit. ---------
    obs_fixture = {
        "schema": "registry-observability/v1",
        "generated_at": now,
        "cache": {"prompt_cache_read_fraction_1h": 0.62, "usage_samples_1h": 7,
                  "warm_drain_rate_1h": "0.5", "drained_1h": 12,
                  "chain_length_histogram": {"1": 4, "2": 3, "5+": 1, "bogus": 2, "3": -1}},
        "lanes": {"worker": {"1h": {"success": 3, "failure": 1, "defer": 2},
                             "24h": {"success": 30, "failure": 4, "defer": 9}},
                  "review-fix": {"1h": {"success": 1, "failure": 0, "defer": 0}},
                  "bad lane!": {"1h": {"success": 1}}},
        "defer_reasons_1h": [{"reason": "partial-disarm", "count": 7},
                             {"reason": "trust-gate-missing", "count": 9},
                             {"reason": "bad reason!", "count": 3},
                             {"reason": "plan-ordering", "count": "x"}],
        "model_exit_classes_1h": [{"model": "fable", "exit_class": "success", "count": 3},
                                  {"model": "terra", "exit_class": "no-changes", "count": 8},
                                  {"model": "bad model!", "exit_class": "x", "count": 1}],
        "flow": {"queue": [{"class": "2a", "depth": 1, "oldest_age_minutes": 12.34},
                           {"class": "4", "depth": 9, "oldest_age_minutes": 3},
                           {"class": "9z", "depth": 1}],
                 "leases": [{"label": "ab12cd340a5f9e71", "provider": "anthropic",
                             "utilization_1h": 0.8},
                            {"label": "ef56ab78b3c2d104", "provider": "anthropic",
                             "utilization_1h": 0.4},
                            {"label": "cd90ef1276a8b535", "provider": "openai"}],
                 "review_rounds": {"mean": 1.44444, "max": 3, "budget_exhausted_1h": 0},
                 "parks_1h": {"needs_user": 2, "needs_orchestrator": 1},
                 "arm_to_merge_minutes_24h": {"p50": 18, "p90": 55.5, "samples": 9},
                 "target_ci_queue": [{"repository": "sparq-org/sparq", "depth": 5},
                                     {"repository": "not-a-repo", "depth": 2}]},
        "trigger_fires": [
            {"rule": "worker-failure-rate", "fired_at": now - 300,
             "summary": "worker failure rate 67% over 3 consecutive runs",
             "evidence": ["https://github.com/jeswr/agent-account-registry/actions/runs/1",
                          "https://evil.example/exfil"],
             "enqueued_task": "heal-2a-0001"},
            {"rule": "bad rule!", "fired_at": now, "summary": "must be skipped"}],
        "thresholds": {"workflow_failure_rate": 0.5, "defer_reason_hourly": 4,
                       "queue_age_clamp_minutes": 10, "merge_stall_minutes": 90, "bogus": 1},
    }
    obs_expected = {
        "generated_at": "2025-06-15T15:06:40Z",
        "cache": {"prompt_cache_read_fraction_1h": 0.62, "usage_samples_1h": 7,
                  "warm_drain_rate_1h": 0.5, "drained_1h": 12,
                  "chain_length_histogram": {"1": 4, "2": 3, "5+": 1}},
        "lanes": [
            {"lane": "review-fix", "1h": {"success": 1, "failure": 0, "defer": 0}, "24h": None},
            {"lane": "worker", "1h": {"success": 3, "failure": 1, "defer": 2},
             "24h": {"success": 30, "failure": 4, "defer": 9}}],
        "defer_reasons_1h": [{"reason": "trust-gate-missing", "count": 9},
                             {"reason": "partial-disarm", "count": 7}],
        "model_exit_classes_1h": [{"model": "terra", "exit_class": "no-changes", "count": 8},
                                  {"model": "fable", "exit_class": "success", "count": 3}],
        "flow": {"queue": [{"class": "2a", "depth": 1, "oldest_age_minutes": 12.3},
                           {"class": "4", "depth": 9, "oldest_age_minutes": 3.0}],
                 # [#374] three validated lease rows in, ZERO published: only the mean/max of the
                 # utilizations that parsed (0.8, 0.4 -> 0.6/0.8). The unparseable third row proves
                 # the aggregate is taken over reporting rows, and the count itself never appears.
                 "lease_utilization_1h": {"mean": 0.6, "max": 0.8},
                 "review_rounds": {"mean": 1.44, "max": 3, "budget_exhausted_1h": 0},
                 "parks_1h": {"needs_user": 2, "needs_orchestrator": 1},
                 "arm_to_merge_minutes_24h": {"p50": 18.0, "p90": 55.5, "samples": 9},
                 "target_ci_queue": [{"repository": "sparq-org/sparq", "depth": 5}]},
        "trigger_fires": [
            {"rule": "worker-failure-rate", "fired_at": "2025-06-15T15:01:40Z",
             "summary": "worker failure rate 67% over 3 consecutive runs",
             "evidence": ["https://github.com/jeswr/agent-account-registry/actions/runs/1"],
             "enqueued_task": "heal-2a-0001"}],
        "thresholds": {"workflow_failure_rate": 0.5, "defer_reason_hourly": 4,
                       "queue_age_clamp_minutes": 10, "merge_stall_minutes": 90},
    }

    class ObsRefusal(dict):
        """A FATAL `_normalize_observability` refusal rendered as a value instead of an exception.

        The rows below hand this seam whole documents and then subscript the result, so a refusal
        raised out of any one of them aborts every check after it — the crash-after-partial-run
        shape (AGENTS.md, AUTHOR pre-flight item 4), which records as a kill while the rest of the
        suite never ran. It measured as exactly that here: narrowing OBS_SALTED_LABEL_RE back to
        the pre-#375 8-hex width took the run from 214 checks to 181 with no named row. A dict, so
        subscript chains keep working (any missing key yields the refusal itself), carrying the
        message and equal to nothing any row expects — one named red row, suite intact.
        Rows that assert a refusal IS raised keep their own try/except and do not use this.
        """

        def __missing__(self, _key):
            return self

    def obs_normalized(document):
        try:
            return _normalize_observability(document)
        except DashboardError as error:
            return ObsRefusal(refused=str(error))

    check("observability golden normalization (bad rows dropped, top-N sorted, links pinned)",
          obs_normalized(obs_fixture), obs_expected)
    check("absent observability snapshot stays hidden (None)",
          _normalize_observability(None), None)
    overflow = copy.deepcopy(obs_fixture)
    overflow["flow"]["review_rounds"]["mean"] = 1e309       # JSON 1e309 decodes to +Infinity
    overflow["thresholds"]["workflow_failure_rate"] = 1e309
    overflow_normalized = obs_normalized(overflow)
    check("non-finite review-round mean is rejected, never published",
          overflow_normalized["flow"]["review_rounds"]["mean"], None)
    check("non-finite threshold is dropped, never published",
          "workflow_failure_rate" in overflow_normalized["thresholds"], False)
    for bad_document in ({"schema": "wrong/v0"}, ["not", "a", "dict"], {}):
        try:
            _normalize_observability(bad_document)
        except DashboardError:
            schema_rejected = True
        else:
            schema_rejected = False
        check(f"alien observability document rejected loudly ({type(bad_document).__name__})",
              schema_rejected, True)
    raw_label = copy.deepcopy(obs_fixture)
    raw_label["flow"]["leases"][0]["label"] = handle   # a raw account handle, not the salted form
    try:
        _normalize_observability(raw_label)
    except DashboardError:
        label_rejected = True
    else:
        label_rejected = False
    check("raw (non-salted) lease label is a fatal privacy violation (decision 22)",
          label_rejected, True)
    # [#374] ...and the salted labels are not published either. Two fleets whose lease rows differ
    # only in COUNT must normalize identically; pre-#374 the row array itself was the disclosure.
    def obs_leases(rows):
        fixture = copy.deepcopy(obs_fixture)
        fixture["flow"]["leases"] = rows
        return obs_normalized(fixture)["flow"]

    one_lease = obs_leases([{"label": "ab12cd340a5f9e71", "provider": "anthropic",
                             "utilization_1h": 0.5}])
    four_leases = obs_leases([{"label": f"ab12cd340a5f9e7{index}", "provider": "anthropic",
                               "utilization_1h": 0.5} for index in range(4)])
    check("[#374] lease rows of different fleet sizes normalize to the same published flow",
          (one_lease, one_lease == four_leases,
           "ab12cd340a5f9e71" in json.dumps(one_lease)),
          (four_leases, True, False))
    check("[#374] no reported lease utilization publishes nothing rather than a zero",
          obs_leases([])["lease_utilization_1h"], None)
    # ---- [#375] the salted label IS the canonical account fingerprint, sha256(handle:salt)[:16]
    # (locked decision 22a). Pre-#375 this seam validated an 8-hex shape that NOTHING in this repo
    # produces, so a collector handing over the same fingerprint model-health / worker-pr / the
    # lease ledger all carry would have failed the build, while a truncated half of one was waved
    # through as "salted". The accept row derives its label from the canonical implementation
    # rather than from a literal, so a shortening on EITHER side of the wire turns it red.
    canonical_label = _model_health_module().account_hash("acct-obs-375", "fixture-salt")
    canonical_flow = obs_leases([{"label": canonical_label, "provider": "anthropic",
                                  "utilization_1h": 0.5}])
    check("[#375] the CANONICAL salted fingerprint (model-health.account_hash) is the accepted "
          "lease label, and its row is really consumed rather than merely tolerated",
          (len(canonical_label), canonical_flow["lease_utilization_1h"]),
          (16, {"mean": 0.5, "max": 0.5}))
    # ...and the pre-#375 8-hex format is now fatal rather than a second accepted identity shape.
    # Widening the pattern back to `{8}` kills the row above; widening it to `{8,16}`/`{8,}` — the
    # tempting "accept both" — is what these rows exist to kill, so they assert REJECTION.
    for case, bad_label in (("the pre-#375 8-hex format", "ab12cd34"),
                            ("the canonical fingerprint truncated to 8 hex", canonical_label[:8]),
                            ("a 15-hex near-miss", canonical_label[:15]),
                            ("a 17-hex overrun", canonical_label + "0")):
        mis_shaped = copy.deepcopy(obs_fixture)
        mis_shaped["flow"]["leases"][0]["label"] = bad_label
        check(f"[#375] {case} is a fatal decision-22 violation, never a second accepted format",
              _raises_dashboard(lambda: _normalize_observability(mis_shaped)), True)
    # ---- [#841] the ROW-FREE collector contract. #374 stopped this build PUBLISHING the rows; it
    # did not stop them EXISTING at data/observability.json on the public `ledger` branch. So the
    # aggregate is accepted directly and a collector need write no per-account rows anywhere.
    def obs_flow_without_rows(aggregate):
        fixture = copy.deepcopy(obs_fixture)
        fixture["flow"].pop("leases", None)          # the collector sends NO per-account rows
        fixture["flow"]["lease_utilization_1h"] = aggregate
        return obs_normalized(fixture)["flow"]["lease_utilization_1h"]

    check("[#841] a collector that sends NO lease rows still publishes the aggregate it computed",
          obs_flow_without_rows({"mean": 0.31, "max": 0.77}), {"mean": 0.31, "max": 0.77})
    # Precedence is ROWS-FIRST and total, so a collector mid-migration that sends both publishes
    # exactly its pre-#841 value — the new key can never silently override real measurements.
    # Flipping the precedence turns this into {0.99, 0.99}.
    both = copy.deepcopy(obs_fixture)
    both["flow"]["lease_utilization_1h"] = {"mean": 0.99, "max": 0.99}
    check("[#841] lease ROWS outrank a collector-supplied aggregate (no silent override)",
          obs_normalized(both)["flow"]["lease_utilization_1h"],
          {"mean": 0.6, "max": 0.8})
    # ...and precedence keys on the legacy KEY, not on a row happening to parse. Rows that are
    # present but report no usable utilization published null pre-#841 and must still publish null:
    # make the fallback conditional on `lease_utilizations` instead and these become {0.99, 0.99},
    # i.e. the new key overriding a legacy source that was sent.
    for case, rows in (
        ("no utilization field", [{"label": "ab12cd340a5f9e71", "provider": "anthropic"}]),
        ("malformed utilization", [{"label": "ab12cd340a5f9e71", "provider": "anthropic",
                                    "utilization_1h": "busy"}]),
        ("zero rows", []),
    ):
        unparseable = copy.deepcopy(both)
        unparseable["flow"]["leases"] = rows
        check(f"[#841] legacy rows with {case} keep their pre-#841 null, aggregate or not",
              obs_normalized(unparseable)["flow"]["lease_utilization_1h"], None)
    # ...and sending the aggregate is NOT a way around the decision-22 check on the rows that ARE
    # present. Make the label check conditional on the rows being used and this normalizes happily.
    both_raw = copy.deepcopy(both)
    both_raw["flow"]["leases"][0]["label"] = handle    # a raw account handle alongside a valid mean
    try:
        _normalize_observability(both_raw)
    except DashboardError:
        aggregate_is_no_bypass = True
    else:
        aggregate_is_no_bypass = False
    check("[#841] a raw lease label stays fatal even when an aggregate is also supplied",
          aggregate_is_no_bypass, True)
    for case, aggregate in (
        ("incoherent (max < mean)", {"mean": 0.8, "max": 0.4}),
        ("out-of-range fraction", {"mean": 0.2, "max": 1.4}),
        ("half-supplied (no max)", {"mean": 0.2}),
        ("non-numeric", {"mean": "busy", "max": "busy"}),
        ("non-object", [0.2, 0.4]),
    ):
        check(f"[#841] {case} collector aggregate is dropped, never published",
              obs_flow_without_rows(aggregate), None)
    try:
        with_observability = build_dashboard(
            issues, leases, usage, history, None, now, "fixture-salt", observability=obs_fixture)
    except DashboardError as error:                 # same crash-after-partial-run guard as above
        with_observability = ObsRefusal(refused=str(error))
    check("build_dashboard publishes the normalized observability key",
          with_observability.get("observability"), obs_expected)
    check("no observability input leaves data.json without the key (panel hidden)",
          "observability" in got, False)
    leak = copy.deepcopy(obs_fixture)
    leak["trigger_fires"][0]["summary"] = f"lane stalled on {handle}"
    try:
        build_dashboard(issues, leases, usage, history, None, now, "fixture-salt",
                        observability=leak)
    except DashboardError:
        leak_rejected = True
    else:
        leak_rejected = False
    check("raw handle inside observability text is caught by the privacy assertion",
          leak_rejected, True)
    empty = build_dashboard([], {"leases": []}, None, [], None, now, "fixture-salt",
                            serviced=("solo/target",))
    # [#78] Even the do-nothing case publishes a row: no catalog, no leases, no history — and the one
    # serviced repository still reports an explicit ZERO rather than being omitted, which is the
    # state pre-#78 rendered as "No agents currently active." with no repository named at all.
    check("do-nothing case", (empty["provider_quota"], empty["fleet"],
                              empty["active_by_repository"]),
          ([], {"active_agents": 0, "capacity": {}, "last_sweep_at": None,
                "dispatch_outcomes": []},
           {"models": [], "repositories": [{"repository": "solo/target", "counts": {}}]}))
    try:
        build_dashboard([], {"leases": [{
            "account": "a" * 16, "holder": "malformed", "model": "sol",
            "expires_at": now + 1,
        }]}, {}, [], None, now, "fixture-salt")
    except DashboardError:
        malformed_rejected = True
    else:
        malformed_rejected = False
    check("malformed live lease fails loudly instead of rendering empty", malformed_rejected, True)
    with tempfile.TemporaryDirectory() as directory:
        assets = Path(directory, "assets")
        assets.mkdir()
        (assets / "index.html").write_text("fixture", encoding="utf-8")
        site = Path(directory, "site")
        _write_site(empty, assets, site)
        check("site assets + JSON emitted",
              ((site / "index.html").read_text(encoding="utf-8"),
               json.loads((site / "data.json").read_text(encoding="utf-8"))["schema"]),
              ("fixture", SCHEMA))
        try:
            _write_site({"schema": SCHEMA, "poison": float("inf")}, assets, site)
        except ValueError:
            nonfinite_blocked = True
        else:
            nonfinite_blocked = False
        check("_write_site refuses non-finite numbers (allow_nan=False backstop)",
              nonfinite_blocked, True)
    print("dashboard-gen self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    # No defaults for the data-plane inputs (issue #28, review round 1): the live files sit on
    # the `ledger` branch, so a default of `data/*.json` would silently render the frozen master
    # tombstones (a falsely-empty dashboard). Callers must point at a ledger-branch checkout.
    parser.add_argument("--leases")
    parser.add_argument("--issues-file")
    parser.add_argument("--usage")
    # The probe job's persisted outcome sidecar (issue #219). REQUIRED whenever a usage snapshot is
    # in play: without it a failed probe's `{}` is indistinguishable from an idle fleet.
    parser.add_argument("--usage-status")
    parser.add_argument("--model-health")
    # Optional: the collector's observability snapshot from a `ledger`-branch checkout (issue
    # #246). Absent file => the Observability panels stay hidden; a present-but-invalid document
    # fails LOUD in _normalize_observability (never published on a guess).
    parser.add_argument("--observability")
    parser.add_argument("--assets", default="dashboard")
    parser.add_argument("--site", default="site")
    parser.add_argument("--history", type=int, default=8)
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if not args.leases or not args.model_health:
        raise DashboardError(
            "--leases and --model-health are required and must point at a `ledger`-branch "
            "checkout — the master copies under data/ are frozen tombstones (issue #28; "
            "see data/README.md)")
    if not 1 <= args.history <= 20:
        raise DashboardError("--history must be between 1 and 20")
    usage_path = _optional_usage_path(args.usage)
    if usage_path and not args.usage_status:
        # Fail-closed coupling (issue #219): dropping --usage-status from the caller would restore
        # exactly the bug — a FAILED probe's empty/partial snapshot published as fresh capacity
        # with no degradation marker — so a usage snapshot without its outcome sidecar is refused
        # rather than rendered on trust.
        raise DashboardError(
            "--usage-status is required alongside a usage snapshot (issue #219): without the "
            "probe's persisted outcome a failed measurement is indistinguishable from an idle "
            "fleet, and every catalog-available account would be published as fresh capacity")
    repo = os.environ.get("REGISTRY_REPO") or os.environ.get("GITHUB_REPOSITORY") or ""
    if args.issues_file:
        try:
            issue_text = Path(args.issues_file).read_text(encoding="utf-8")
        except OSError as exc:
            raise DashboardError("cannot read account issue fixture") from exc
        issues = _issue_list_from_text(issue_text)
    else:
        issues = _fetch_issues(repo)
    leases = _read_json(args.leases, required=True)
    usage = _read_json(usage_path, default={})
    probe_status = None
    if args.usage_status:
        try:
            # A missing or malformed sidecar degrades to the "unknown" outcome instead of taking
            # the whole public page down over one unreadable status file. `{}` and `None` are both
            # unmeasured verdicts (#612 review finding 1), so this degradation cannot publish
            # capacity either way.
            probe_status = _read_json(args.usage_status, default={})
        except DashboardError:
            probe_status = {}
        if not isinstance(probe_status, dict):
            probe_status = {}
    model_health = _read_json(args.model_health, default=None)
    observability = _read_json(args.observability, default=None)
    history = _fetch_dispatch_history(repo, args.history)
    document = build_dashboard(
        issues, leases, usage, history, model_health, int(time.time()),
        os.environ.get("PROVENANCE_SALT", ""), observability=observability,
        probe_status=probe_status)
    _write_site(document, args.assets, args.site)
    # Public workflow log: never disclose the account count (issue #184; the codebase norm in
    # model-health.py — "the public workflow log never carries provider counts").
    print(f"dashboard-gen: wrote {args.site}/data.json")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except DashboardError as exc:
        print(f"dashboard-gen: {exc}", file=sys.stderr)
        sys.exit(1)
