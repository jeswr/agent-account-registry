#!/usr/bin/env python3
# [OPUS-4.8] Maintainer alerting — the opposite posture from the dispatcher (which FAILS CLOSED and
# silently skips a capped account): this FAILS LOUD so the maintainer learns when worker throughput is
# degraded and can act (reset a subscription usage window, rotate an expired setup-token, top up codex).
#
# It reuses the usage map account-usage.py already probes (per-account 5h/7d utilization + reset, fable
# sub-quota, or {"exempt": true} for non-metered providers; a missing entry == token invalid/expired or
# the probe failed → treated as UNAVAILABLE). The pool is the UNION of every enabled policy row's
# account_pool (read straight from policy/repos.toml — never passed through env/log lines, privacy
# d22b) and the probed handles, and the margin comes from the same policy (the MAX across enabled rows,
# so the alert is at least as conservative as the strictest admission gate). classify() mirrors
# usage_eligible's FAIL-CLOSED semantics: a missing/unparseable window or a non-allowed probe status is
# UNAVAILABLE, never "0% used". A wholesale probe failure (empty usage with a configured pool) therefore
# classifies EVERY account UNAVAILABLE and always fires the alert — the exact case that used to no-op.
#
# Privacy (locked decision 22, issue #107; sol-audit issue #204; hardened #432 round 1): the
# DETAILED body — raw account handles AND per-account/aggregate counts, pool size, and reset
# times — is emitted ONLY over a POSITIVELY VERIFIED private route: ALERT_REPO distinct from the
# public registry repo AND confirmed `"private": true` by a live GET /repos/{ALERT_REPO} under
# ALERT_TOKEN. Configuration alone (two non-empty strings) is NOT verification — it could name
# the registry itself or any other public repository. EVERY other shape falls back to the public
# registry with ONLY a generic, non-compositional "availability is degraded" signal — never a
# handle, never a count, never a reset time (issue #204: even the aggregate
# capped/unavailable/ok counts disclose the worker-account fleet on a public repo): the
# half-configured case (ALERT_REPO set, ALERT_TOKEN missing — writing to the private repo under
# the ambient token that can't reach it would fail silently and drop the alert, issue #39), the
# fully-unconfigured case (no ALERT_REPO), the same-repo case, and a public/unverifiable
# ALERT_REPO. Account handles never appear in workflow logs.
# Writes go through _gh(check=True), which surfaces a non-zero gh returncode as a sanitized
# ::warning:: (op + returncode only — never gh stderr, which can echo request bodies under
# GH_DEBUG=api). Delivery is additionally FAIL-LOUD end-to-end (#432 round 2): the visibility
# probe proves only metadata read, so a fine-grained ALERT_TOKEN without Issues write can pass it
# and then fail at issue list/create/edit. _deliver_alert() returns that failure to main(), which
# retries a FRESHLY RENDERED redacted body on the public registry under the ambient token (never
# the detailed body — the fallback repo is public) and exits nonzero when every route fails,
# instead of printing "maintainer alerted" over a dropped alert.
#
# Pure classify()/_policy_pool_margin() are unit-tested (--self-test); the CLI wraps them over the
# usage file + `gh`.
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib

ALERT_TITLE = "⚠️ Worker account availability — action may be needed"
ALERT_LABEL = "ops-alert"

# --- PROBE OUTCOME SIDECAR (registry #639; schema shared with issue #219's dashboard lane). Both
# probe jobs persist `{"schema","outcome","detail","attempted_at"}` next to the snapshot. This script
# used to infer a wholesale failure from `not usage`, which cannot tell "the fleet is idle" from
# "nothing was measured" and misses a PARTIAL failure completely. Read fail-closed: when
# USAGE_PROBE_STATUS_FILE is set, anything that is not an explicit, fresh `ok` means the measurement
# did not happen. The variable being UNSET keeps the legacy emptiness inference (callers that do not
# produce a sidecar), so this can never turn a non-dispatch caller permanently degraded.
PROBE_SCHEMA = "account-usage-probe/v1"          # parity with dashboard-gen.PROBE_SCHEMA (self-test)
PROBE_MAX_AGE_SECONDS = 30 * 60                  # dispatch ticks every 10 min; 3 missed slots
# The reachability values an exempt entry may carry (registry #639). MIRRORS
# select-and-claim.USAGE_REACHABILITY_ADMITTED — the dispatch gate — so monitoring and dispatch never
# split (parity asserted in --self-test). `dead` / absent / unrecognised are UNAVAILABLE here exactly
# as they are ineligible there.
REACHABILITY_ADMITTED = frozenset({"live", "unproven"})
REACHABILITY_DEAD = "dead"


def probe_status(path, now):
    """(measured, detail) for a persisted probe-outcome sidecar. FAIL-CLOSED: an absent, unparseable,
    wrong-schema, non-`ok` or STALE sidecar is (False, <reason>) — never "assume it ran". `path` None
    means no sidecar was configured, reported as (None, "") so the caller keeps its legacy inference
    rather than treating an unwired variable as an outage."""
    if not path:
        return None, ""
    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError):
        return False, "probe-status-unreadable"
    return probe_outcome(document, now)


def probe_outcome(document, now):
    """(measured, detail) for an already-PARSED sidecar. Split from probe_status so account-usage.py's
    self-test can feed it the document the workflow step ACTUALLY wrote and assert the shell -> python
    contract (schema string, outcome vocabulary, stamp format) end to end. Pure — unit-tested."""
    if not isinstance(document, dict) or document.get("schema") != PROBE_SCHEMA:
        return False, "probe-status-malformed"
    stamp = document.get("attempted_at")
    if not isinstance(stamp, (int, float)) or isinstance(stamp, bool) or stamp != stamp:
        return False, "probe-status-undated"
    if not -PROBE_MAX_AGE_SECONDS <= (now - stamp) <= PROBE_MAX_AGE_SECONDS:
        return False, "probe-status-stale"
    if document.get("outcome") != "ok":
        detail = document.get("detail")
        # The detail is rendered into an issue body, so accept ONLY the producer's fixed vocabulary
        # shape (lowercase-hyphen token) — a file that somehow carried markup or a handle can never
        # reach the alert.
        return False, detail if isinstance(detail, str) \
            and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", detail) else "probe-not-ok"
    return True, "probe-succeeded"


def _policy_pool_margin(policy_path):
    """(pool, margin) from policy/repos.toml: the union of enabled repos' account_pool and the MAX
    usage_safety_margin. (None, None) when the file is absent/unreadable — the caller falls back to
    env/probe. NOTE (task #325 seam): the pool list is slated to move to a private location; this
    reader is the single place to repoint when it does."""
    try:
        with open(policy_path, "rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return None, None
    pool, margin = set(), None
    repos = document.get("repos") if isinstance(document, dict) else None
    for row in (repos or {}).values():
        if not isinstance(row, dict) or row.get("enabled") is not True:
            continue
        pool.update(h for h in (row.get("account_pool") or []) if isinstance(h, str) and h)
        m = row.get("usage_safety_margin")
        if isinstance(m, (int, float)) and not isinstance(m, bool):
            margin = float(m) if margin is None else max(margin, float(m))
    return (sorted(pool) or None), margin


def _util(value):
    """Parse one utilization field FAIL-CLOSED: missing/None/unparseable/NaN -> None (never 0.0).
    A literal `nan`/`inf` header would parse as a float whose comparisons are all False, so a CAPPED
    account would classify `ok` — treat any non-finite value as unparseable (issue #39). Real provider
    headers are decimal so this is a guard, not a currently-reachable path."""
    if value is None:
        return None
    # OverflowError (cross-provider review r2 finding 3): float() of a forged huge JSON int
    # (10**400) RAISES rather than returning inf — uncaught, the monitoring tick died and the
    # alert was dropped. Unparseable, exactly like nan/inf.
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed != parsed or parsed in (float("inf"), float("-inf")):  # NaN (self-inequality) or ±inf
        return None
    return parsed


def _repo_confirmed_private(repo, token):
    """True ONLY on a definitive `"private": true` from GET /repos/{repo} read under the route
    token (sol review round 1 of #432). A configured ALERT_REPO+ALERT_TOKEN pair alone must never
    select the account-enumerating body: the pair can name the public registry itself or any
    other public repository, and token presence proves nothing about destination visibility.
    FAIL-CLOSED: a failed lookup, an unparseable payload, or anything but a literal boolean true
    reads as NOT private and the caller redacts. The response body is parsed, never echoed."""
    proc = _gh(["api", f"repos/{repo}"], capture=True, token=token)
    if proc.returncode != 0:
        return False
    try:
        payload = json.loads(proc.stdout or "")
    except ValueError:
        return False
    return isinstance(payload, dict) and payload.get("private") is True


def _alert_route(alert_repo, alert_token, registry_repo, confirmed_private=None):
    """(repo, token, redact_handles) for the alert issue (issue #107/#39/#204, privacy d22c;
    hardened in review round 1 of #432). The DETAILED body — account handles AND
    per-account/aggregate counts, pool size, and reset times — is emitted ONLY over a POSITIVELY
    VERIFIED private route: ALERT_REPO and ALERT_TOKEN both set, ALERT_REPO distinct from the
    public registry repo (case-insensitive — a "private route" naming the registry IS the public
    repo), AND the destination CONFIRMED private by a live GET /repos/{ALERT_REPO} under
    ALERT_TOKEN. EVERY other shape falls back to the registry repo and REDACTS to a generic,
    non-compositional degraded signal, because that repo is public: a public alert must never
    publish raw account identifiers (issue #107) NOR the counts/reset times that compositionally
    disclose the fleet (issue #204). This covers the half-configured case (ALERT_REPO set,
    ALERT_TOKEN missing — where writing to the private repo under the ambient registry token
    would fail silently and drop the alert, issue #39), the fully-unconfigured case (no
    ALERT_REPO at all), the same-repo case, and a public or unverifiable ALERT_REPO (#432 round
    1: presence of a token is not privacy). token=None means "use the ambient GH_TOKEN"; the
    write still fails loud via _gh(check=True) (review r1). `confirmed_private` is injectable
    for the self-test; the default performs the live lookup, consulted only once both halves of
    the route are set."""
    if alert_repo and alert_token:
        same_repo = alert_repo.strip().lower() == (registry_repo or "").strip().lower()
        check = confirmed_private if confirmed_private is not None else _repo_confirmed_private
        if not same_repo and check(alert_repo, alert_token):
            return alert_repo, alert_token, False
    return registry_repo, None, True


def classify(pool, usage, margin, now=None):
    """Return (eligible_count, rows[(handle, status_str, ok_bool)]). Mirrors usage_eligible's
    fail-closed posture: an account is usable ONLY with a positive, parseable probe result — missing
    entry, a status that is not EXACTLY `allowed` (an empty/absent one included, issue #421), or a
    5h/7d window that is missing, unparseable, or outside [0,1] is UNAVAILABLE. PROBE-EXEMPT
    providers (openai/codex — maintainer decision 2026-07-17, registry issue #29) are `ok` by design
    (never flagged probe-missing) UNLESS the reactive-backoff stamp on the entry is still active, in
    which case the backoff is surfaced (BACKED OFF) so degraded exempt capacity is visible."""
    if now is None:
        import time
        now = time.time()
    rows = []
    eligible = 0
    for h in pool:
        u = usage.get(h)
        if u is None:
            rows.append((h, "UNAVAILABLE — token invalid/expired or probe failed (rotate setup-token)", False))
            continue
        if u.get("exempt") is True:  # STRICT, mirroring usage_eligible (cross-provider review r1)
            # [#639] Exemption skips the QUOTA probe; it never asserts reachability. Mirrors
            # usage_eligible's allowlist exactly, so a credential the allocator refuses is reported
            # UNAVAILABLE here instead of "ok — probe-exempt provider" (the split that let a dead
            # account look healthy on the monitoring surface while burning a runner per tick).
            reachability = u.get("reachability")
            if not isinstance(reachability, str) or reachability not in REACHABILITY_ADMITTED:
                dead = reachability == REACHABILITY_DEAD
                rows.append((h, "UNAVAILABLE — worker credential REJECTED by the provider "
                                "(re-mint required; dispatch is holding this account out)" if dead
                                else "UNAVAILABLE — reachability not stated by the probe "
                                     "(fail-closed; dispatch holds this account out)", False))
                continue
            until = _util(u.get("backoff_until"))
            if until is not None and now < until:
                # A saturated chain may have been truncated in the health ledger (model-health
                # BACKOFF_CHAIN_KEEP), so its re-derived count is a LOWER BOUND — render "x6+",
                # never an exact "x6" (PR #85 finding 2). STRICT is-True, like `exempt`.
                hits = (f"x{u.get('backoff_consecutive', 1)}"
                        + ("+" if u.get("backoff_saturated") is True else ""))
                rows.append((h, f"BACKED OFF — provider rate limit hit "
                                f"({hits}); resumes at epoch "
                                f"{int(until)} (self-clearing)", False))
                continue
            eligible += 1
            rows.append((h, "ok — probe-exempt provider (reactive rate-limit backoff)", True))
            continue
        # [ISSUE #421] Require status EXACTLY `allowed`, character-for-character with
        # usage_eligible (strip + lower). The old `not in ("allowed", "")` accepted an EMPTY or
        # ABSENT status as allowed — the same fail-open issue #196 closed on the admission gate and
        # the producer. Leaving it here meant a forged/hand-authored usage map could report an
        # account eligible on the monitoring surface while dispatch refused it (a monitoring split).
        if str(u.get("status", "")).strip().lower() != "allowed":
            stated = u.get("status")
            rows.append((h, "UNAVAILABLE — provider status not stated by the probe (fail-closed)"
                            if stated is None or not str(stated).strip()
                            else f"UNAVAILABLE — provider status `{stated}` (throttled/rejected)",
                         False))
            continue
        u5 = _util(u.get("5h_util"))
        u7 = _util(u.get("7d_util"))
        if u5 is None or u7 is None:
            rows.append((h, "UNAVAILABLE — usage window missing/unparseable (fail-closed)", False))
            continue
        # [ISSUE #421] Validate the SHAPE before trusting the headroom comparison, exactly as
        # usage_eligible does: `_util` only rejects nan/inf, so a NEGATIVE base utilization (-1
        # looks like excess headroom) or one ABOVE 1.0 slipped past the CAPPED threshold and
        # classified `ok`. A base window is a fraction in [0,1]; anything else is fail-closed.
        # (Deliberately NOT folded into `_util`, which also parses the backoff_until EPOCH.)
        if not (0.0 <= u5 <= 1.0) or not (0.0 <= u7 <= 1.0):
            rows.append((h, "UNAVAILABLE — usage window out of range (fail-closed)", False))
            continue
        cap = 1.0 - margin
        if u5 >= cap or u7 >= cap:
            win, util, reset = ("5h", u5, u.get("5h_reset")) if u5 >= cap else ("7d", u7, u.get("7d_reset"))
            rows.append((h, f"CAPPED — {win} window {util:.0%} used, resets {reset}", False))
        else:
            eligible += 1
            rows.append((h, f"ok — 5h {u5:.0%}, 7d {u7:.0%}", True))
    return eligible, rows


def render(eligible, rows, pool, threshold, maintainer, probe_empty=False, redact_handles=False,
           probe_detail=""):
    header = "> 🤖 SPARQ agent — automated worker-account availability check.\n"
    if redact_handles:
        # PUBLIC-registry fallback (issue #107, #39, #204): whenever the alert lands on the PUBLIC
        # registry repo — because no verified private route is configured, or only a
        # half-configured one (ALERT_REPO set, ALERT_TOKEN missing) — it carries ONLY a generic,
        # NON-COMPOSITIONAL degraded signal. Issue #204 (sol-audit): even aggregate counts and the
        # pool size are a compositional disclosure of the worker-account fleet, so the public body
        # emits NO account handles, NO per-account/aggregate counts, NO pool size, and NO reset
        # times — nothing but "availability is degraded" plus how to open the private channel. All
        # per-account (and per-count) detail requires the verified private ALERT_REPO+ALERT_TOKEN
        # route.
        return "\n".join([
            header,
            "⚠️ **Worker-account availability is DEGRADED and needs maintainer action.**\n",
            "Per-account detail — how many accounts are affected, which are capped vs. "
            "unavailable, and any reset times — is SUPPRESSED here because this alert landed on "
            "the **public** registry repo, where those counts would themselves disclose the "
            "worker-account fleet. To receive the full breakdown privately, configure a private "
            "`ALERT_REPO` together with an `ALERT_TOKEN` secret that can write to it (the private "
            "route is used only when BOTH are set).\n",
            f"@{maintainer} — autonomous worker throughput is **degraded**. Open the private alert "
            "channel above to see which accounts to reset (`claude setup-token`) or re-token "
            "(codex `login --device-auth`). This issue updates itself and closes automatically "
            "when availability recovers.",
        ])
    lines = [header]
    if probe_empty:
        # [#639] `probe_detail` is the probe's OWN recorded cause when the persisted sidecar says the
        # measurement did not happen (secret-subset-empty, probe-exited-nonzero, ...). Without it this
        # banner could only guess from an empty map — and could not fire at all for a partial failure.
        cause = f" Recorded cause: `{probe_detail}`." if probe_detail else ""
        lines.append("🚨 **The usage probe did NOT measure this fleet — dispatch is holding "
                     "fail-closed.** This is a probe/secret-infrastructure failure (malformed "
                     "secrets, endpoint or header change, curl outage), not N individually capped "
                     f"accounts.{cause}\n")
    lines.append(f"**Usable workers: {eligible}/{len(pool)}**  (degraded below {threshold}).\n")
    for h, s, ok in rows:
        lines.append(f"- {'✅' if ok else '⛔'} `{h}`: {s}")
    if eligible < threshold:
        lines.append(f"\n@{maintainer} — autonomous worker throughput is **degraded**. To restore it: reset the "
                     "usage window on any `CAPPED` subscription account, and rotate the token for any "
                     "`UNAVAILABLE` one (`claude setup-token` / codex `login --device-auth`). This issue "
                     "updates itself and closes automatically when availability recovers.")
    return "\n".join(lines)


def _gh(args, capture=False, token=None, check=False):
    # Privacy routing (locked decision 22c): the caller resolves the alert repo+token via
    # _alert_route(); pass the resolved `token` here (None -> ambient GH_TOKEN). `check=True` on a
    # write surfaces a non-zero gh returncode instead of dropping the alert silently (issue #39).
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    result = subprocess.run(["gh"] + args, capture_output=capture, text=True, env=env)
    if check and result.returncode != 0:
        # Privacy (review r1): do NOT echo gh stderr — under GH_DEBUG=api it can contain the
        # request body (i.e. account handles). Log only the operation + returncode.
        print(f"::warning::usage-alert: gh {args[0]} {args[1] if len(args) > 1 else ''} "
              f"failed (rc={result.returncode})")
    return result


def _deliver_alert(repo, token, body):
    """Create-or-update the alert issue on `repo` under `token` (None -> ambient GH_TOKEN).
    Returns True ONLY when the existing-issue lookup AND the create/edit both succeed (review
    round 2 of #432): a failed `issue list` must NOT be read as "no open alert" (its empty stdout
    would parse as []), and a failed create/edit must not report success — a fine-grained token
    with metadata read but no Issues write passes the visibility probe and would otherwise drop
    the alert while the run stays green. The label create stays best-effort (it fails routinely
    when the label already exists)."""
    _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", "d73a4a",
         "--description", "Autonomous worker availability alert (maintainer action)"],
        capture=True, token=token)
    listed = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", "open",
                  "--json", "number,title", "--limit", "10"], capture=True, token=token,
                 check=True)
    if listed.returncode != 0:
        return False
    try:
        found = json.loads(listed.stdout or "[]")
    except ValueError:
        return False
    num = next((i["number"] for i in found
                if isinstance(i, dict) and i.get("title") == ALERT_TITLE), None)
    if num:
        written = _gh(["issue", "edit", str(num), "-R", repo, "--body", body], capture=True,
                      token=token, check=True)
    else:
        written = _gh(["issue", "create", "-R", repo, "--title", ALERT_TITLE, "--label",
                       ALERT_LABEL, "--body", body], capture=True, token=token, check=True)
    return written.returncode == 0


def main():
    registry_repo = os.environ["REGISTRY_REPO"]
    # Where the alert issue lives + which token writes it. A private ALERT_REPO is used ONLY when
    # ALERT_TOKEN can write there; otherwise fall back to the registry repo (issue #39) so a
    # half-configured deployment never silently drops the alert.
    repo, alert_token, redact_handles = _alert_route(
        os.environ.get("ALERT_REPO"), os.environ.get("ALERT_TOKEN"), registry_repo)
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")
    usage_file = os.environ.get("WORKER_USAGE_FILE")
    usage = json.load(open(usage_file)) if usage_file and os.path.exists(usage_file) else {}
    # [#639] The probe's persisted outcome decides whether this snapshot may be TRUSTED at all. An
    # explicit non-`ok` (or absent/stale) sidecar means the measurement did not happen, so the
    # snapshot is classified as EMPTY — every configured account reads UNAVAILABLE, the wholesale
    # banner fires with the recorded cause, and the alert cannot report a fleet as healthy on data the
    # probe itself disclaims. This also catches a PARTIAL failure, which `not usage` never could.
    import time
    probe_measured, probe_detail = probe_status(
        os.environ.get("USAGE_PROBE_STATUS_FILE"), time.time())
    unmeasured = probe_measured is False
    if unmeasured:
        print("::warning::usage-alert: the usage probe recorded that it did NOT measure this fleet "
              f"({probe_detail}) — classifying every configured account as unavailable")
    trusted_usage = {} if unmeasured else usage
    policy_pool, policy_margin = _policy_pool_margin(
        os.environ.get("POLICY_FILE", "policy/repos.toml"))
    margin = policy_margin if policy_margin is not None \
        else float(os.environ.get("USAGE_SAFETY_MARGIN", "0.10"))
    # UNION of the configured pool and the probed handles (the docstring contract): an account whose
    # token went bad — hence MISSING from the probe — can never silently vanish from the check, and a
    # wholesale probe failure still checks (and fails) every configured account.
    env_pool = [h for h in json.loads(os.environ.get("ACCOUNT_POOL", "[]")) if isinstance(h, str)]
    pool = sorted(set(policy_pool or env_pool) | set(usage.keys()))
    if not pool:
        print("usage-alert: no accounts to check (empty pool and empty probe)")
        return 0

    eligible, rows = classify(pool, trusted_usage, margin)
    threshold = max(1, (len(pool) + 1) // 2)      # degraded if fewer than half the pool is usable
    degraded = eligible < threshold
    body = render(eligible, rows, pool, threshold, maintainer, probe_empty=not trusted_usage,
                  redact_handles=redact_handles, probe_detail=probe_detail if unmeasured else "")

    # Privacy (locked decision 22b): NOTHING printed to the (public) workflow log carries an account
    # handle, a per-provider count, or the pool size — the detail lives only in the alert issue body.
    if degraded:
        if redact_handles:
            # FAIL LOUD (issue #204): a degraded fleet is being alerted with per-account detail
            # SUPPRESSED because no verified private ALERT_REPO+ALERT_TOKEN route is configured.
            # The public issue carries only a generic signal; say so in the (public) log — with no
            # handle, count, or pool size — so the missing private channel is visible to operators.
            print("::warning::usage-alert: no verified private ALERT_REPO+ALERT_TOKEN route — "
                  "per-account detail SUPPRESSED; the public alert carries a generic signal only")
        delivered = _deliver_alert(repo, alert_token, body)
        if not delivered and not redact_handles:
            # DEGRADED private-route delivery failure (review round 2 of #432): the visibility
            # probe proves only that ALERT_TOKEN can READ repo metadata, not that it can write
            # Issues, so delivery can still fail after route selection. Retry on the public
            # registry under the ambient token with a FRESHLY RENDERED redacted body — NEVER the
            # detailed one already in `body`: the fallback repo is public and must see no handle,
            # count, or reset time.
            print("::warning::usage-alert: private-route alert delivery FAILED — retrying a "
                  "REDACTED generic alert on the public registry repo")
            body = render(eligible, rows, pool, threshold, maintainer,
                          probe_empty=not trusted_usage, redact_handles=True,
                          probe_detail=probe_detail if unmeasured else "")
            delivered = _deliver_alert(registry_repo, None, body)
        if not delivered:
            # FAIL LOUD (review round 2 of #432): every route failed, so the degraded-fleet
            # signal was dropped — a green exit here would hide exactly the condition this
            # script exists to surface.
            print("::error::usage-alert: degraded=true but the alert could NOT be delivered on "
                  "any route — treat this run as FAILED")
            return 1
        print("::warning::usage-alert: degraded=true — maintainer alerted (detail in the alert issue)")
    else:
        listed = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", "open",
                      "--json", "number,title", "--limit", "10"], capture=True,
                     token=alert_token, check=True)
        if listed.returncode != 0:
            # Review round 2 of #432: a failed lookup is NOT "no open alert" — a stale degraded
            # alert may remain open, pointing the maintainer at a problem that already cleared.
            print("::warning::usage-alert: recovered, but the open-alert lookup failed — a "
                  "stale alert may remain open")
            return 1
        try:
            found = json.loads(listed.stdout or "[]")
        except ValueError:
            print("::warning::usage-alert: recovered, but the open-alert lookup returned an "
                  "unparseable payload — a stale alert may remain open")
            return 1
        num = next((i["number"] for i in found
                    if isinstance(i, dict) and i.get("title") == ALERT_TITLE), None)
        if num:
            commented = _gh(["issue", "comment", str(num), "-R", repo, "--body",
                             "✅ Recovered — worker availability is back above the degraded "
                             "threshold. Auto-closing."],
                            capture=True, token=alert_token, check=True)
            closed = _gh(["issue", "close", str(num), "-R", repo], capture=True,
                         token=alert_token, check=True)
            if commented.returncode != 0 or closed.returncode != 0:
                print("::warning::usage-alert: recovered, but closing the stale alert failed — "
                      "it may still show as open")
                return 1
        print("usage-alert: degraded=false")
    return 0


def _self_test():
    ok = True

    def chk(n, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'ok  ' if good else 'FAIL'} {n}: {got} (want {want})")

    pool = ["a", "b", "c", "d"]
    usage = {
        # [#421] every metered entry states `status: allowed` — an absent status is no longer read
        # as allowed, so these fixtures carry the shape the producer actually writes.
        "a": {"status": "allowed", "5h_util": "0.2", "7d_util": "0.3",
              "5h_reset": "t1", "7d_reset": "t2"},                                      # ok
        # [#639] an exempt entry carries its reachability; `live` is the probed-healthy shape
        "b": {"exempt": True, "reachability": "live"},                                   # ok (codex)
        "c": {"status": "allowed", "5h_util": "0.95", "7d_util": "0.1",
              "5h_reset": "14:00"},                                                     # capped 5h
        # "d" missing -> token bad -> UNAVAILABLE
    }
    eligible, rows = classify(pool, usage, 0.10)
    chk("eligible count", eligible, 2)
    chk("capped detected", any("CAPPED" in s for h, s, o in rows if h == "c"), True)
    chk("missing -> unavailable", any("UNAVAILABLE" in s for h, s, o in rows if h == "d"), True)
    chk("exempt ok", any(o for h, s, o in rows if h == "b"), True)
    e2, _ = classify(["a", "b"], usage, 0.10)
    chk("small pool all ok", e2, 2)
    # FAIL-CLOSED alignment with usage_eligible (the old classify read missing windows as 0.0 "ok"):
    # [#421] each of these states `allowed` so the assertion actually reaches the WINDOW arm it
    # names — without it the status guard short-circuits first and they pass for the wrong reason.
    e3, r3 = classify(["x"], {"x": {"status": "allowed", "5h_util": "0.1"}}, 0.10)  # 7d missing
    chk("missing window -> unavailable",
        (e3, "usage window missing/unparseable" in r3[0][1]), (0, True))
    e4, r4 = classify(["x"], {"x": {"status": "rejected", "5h_util": "0", "7d_util": "0"}}, 0.10)
    chk("rejected status -> unavailable", (e4, "UNAVAILABLE" in r4[0][1]), (0, True))
    e5, r5 = classify(["x"], {"x": {"status": "allowed", "5h_util": "nan-ish%", "7d_util": "0"}},
                      0.10)
    chk("unparseable -> unavailable",
        (e5, r5[0][2], "usage window missing/unparseable" in r5[0][1]), (0, False, True))
    # Wholesale probe failure: empty usage + configured pool -> every account UNAVAILABLE -> degraded.
    e6, r6 = classify(pool, {}, 0.10)
    chk("empty probe -> all unavailable", (e6, all(not o for _h, _s, o in r6)), (0, True))
    chk("empty probe fires the alert", e6 < max(1, (len(pool) + 1) // 2), True)
    chk("probe-failure banner", "holding fail-closed" in render(0, r6, pool, 2, "m", probe_empty=True), True)

    # ---- [registry #639] EXEMPTION IS NOT REACHABILITY, and monitoring must not split from dispatch.
    # `classify` is documented as mirroring usage_eligible; the two vocabularies are asserted EQUAL
    # against the allocator itself, and each state is then checked through classify. Before the fix a
    # dead exempt account rendered "ok — probe-exempt provider" while dispatch burned a runner on it.
    import importlib.util as _ilu
    _sac_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "select-and-claim.py")
    _spec = _ilu.spec_from_file_location("registry_select_and_claim_alert", _sac_path)
    _allocator = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_allocator)
    chk("[#639] the admitted-reachability allowlist is IDENTICAL to the allocator's",
        REACHABILITY_ADMITTED, _allocator.USAGE_REACHABILITY_ADMITTED)
    chk("[#639] the dead spelling is IDENTICAL to the allocator's",
        REACHABILITY_DEAD, _allocator.USAGE_REACHABILITY_DEAD)
    for state, want_ok in (("live", True), ("unproven", True), ("dead", False)):
        entry = {"exempt": True, "reachability": state}
        e_state, r_state = classify(["x"], {"x": entry}, 0.10)
        chk(f"[#639] classify and usage_eligible agree for reachability={state}",
            (bool(e_state), r_state[0][2], _allocator.usage_eligible(dict(entry), now=1000)),
            (want_ok, want_ok, want_ok))
    e_dead, r_dead = classify(["x"], {"x": {"exempt": True, "reachability": "dead"}}, 0.10)
    chk("[#639] a DEAD exempt credential reads UNAVAILABLE and names the maintainer action",
        (e_dead, "UNAVAILABLE" in r_dead[0][1], "re-mint" in r_dead[0][1]), (0, True, True))
    e_bare, r_bare = classify(["x"], {"x": {"exempt": True}}, 0.10)
    chk("[#639] an exempt entry with NO reachability stated is UNAVAILABLE (fail-closed)",
        (e_bare, "UNAVAILABLE" in r_bare[0][1]), (0, True))
    e_forged, _r = classify(["x"], {"x": {"exempt": True, "reachability": "LIVE"}}, 0.10)
    chk("[#639] a forged reachability spelling does not read as usable", e_forged, 0)

    # ---- [registry #421] THE METERED ARM must not split from dispatch either. Issue #196 hardened
    # usage_eligible + the producer to require status EXACTLY `allowed` and a base utilization in
    # [0,1]; classify still carried the OLD semantics (empty status == allowed; no range check, so
    # `-1` read as excess headroom and classified `ok`). On a forged/hand-authored usage map the
    # monitor therefore reported an account ELIGIBLE while the gate refused it. Every shape below is
    # asserted against the ALLOCATOR's own verdict (pre-flight question (b): the expected value does
    # NOT come from the code under test) — reverting either guard turns these RED.
    # Margins are 0.10 with utils of 0.0/0.1, well clear of the cap, so only the shape is under test.
    for _label, _entry, _want_ok in (
            ("an EMPTY status", {"status": "", "5h_util": "0.1", "7d_util": "0.1"}, False),
            ("an ABSENT status", {"5h_util": "0.1", "7d_util": "0.1"}, False),
            ("a whitespace-only status", {"status": "   ", "5h_util": "0.1", "7d_util": "0.1"},
             False),
            ("a padded/upper-case allowed", {"status": " ALLOWED ", "5h_util": "0.1",
                                             "7d_util": "0.1"}, True),
            ("a NEGATIVE 5h util", {"status": "allowed", "5h_util": "-1", "7d_util": "0.1"}, False),
            ("a NEGATIVE 7d util", {"status": "allowed", "5h_util": "0.1", "7d_util": "-0.5"},
             False),
            ("an ABOVE-1 5h util", {"status": "allowed", "5h_util": "1.5", "7d_util": "0.1"},
             False),
            ("an ABOVE-1 7d util", {"status": "allowed", "5h_util": "0.1", "7d_util": "2"}, False),
            ("a zero-boundary util", {"status": "allowed", "5h_util": "0.0", "7d_util": "0.0"},
             True)):
        _e421, _r421 = classify(["x"], {"x": dict(_entry)}, 0.10, now=1000)
        chk(f"[#421] classify and usage_eligible agree for {_label}",
            (bool(_e421), _r421[0][2], _allocator.usage_eligible(dict(_entry), 0.10, now=1000)),
            (_want_ok, _want_ok, _want_ok))
    # The two rejections must be DISTINGUISHABLE in the body (and neither may render as `ok`), so a
    # maintainer reading the private alert can tell a throttled provider from a malformed snapshot.
    _e_nostat, _r_nostat = classify(["x"], {"x": {"5h_util": "0.1", "7d_util": "0.1"}}, 0.10)
    chk("[#421] an absent status renders 'status not stated', never `None` or ok",
        (_e_nostat, "status not stated" in _r_nostat[0][1], "None" in _r_nostat[0][1],
         _r_nostat[0][1].startswith("ok")), (0, True, False, False))
    _e_neg, _r_neg = classify(["x"], {"x": {"status": "allowed", "5h_util": "-1",
                                            "7d_util": "0.1"}}, 0.10)
    chk("[#421] an out-of-range util renders 'out of range', not a negative percentage",
        (_e_neg, "out of range" in _r_neg[0][1], "-100%" in _r_neg[0][1]), (0, True, False))
    # The UPPER bound needs its OWN row: an above-1 util is ineligible either way (1.5 also trips the
    # CAPPED threshold), so the eligibility-parity row above is VALUE-IDENTICAL there and cannot see
    # the bound being dropped — it survived exactly that mutant. What the upper bound actually buys
    # is the DIAGNOSIS: an above-1 window is a MALFORMED snapshot, and reporting it as genuine quota
    # exhaustion ("CAPPED — 5h window 150% used, resets 14:00") sends the maintainer to reset a
    # window that is not the problem. So assert the MESSAGE, not just the verdict.
    _e_hi, _r_hi = classify(["x"], {"x": {"status": "allowed", "5h_util": "1.5", "7d_util": "0.1",
                                          "5h_reset": "14:00"}}, 0.10)
    chk("[#421] an ABOVE-1 util is MALFORMED, not a capped account (never rendered as `150%`)",
        (_e_hi, "out of range" in _r_hi[0][1], "CAPPED" in _r_hi[0][1], "150%" in _r_hi[0][1]),
        (0, True, False, False))
    # The upper bound is INCLUSIVE: a util of exactly 1.0 is a well-formed FULLY-CONSUMED window, so
    # it must still report CAPPED (with its reset time) rather than being mislabelled malformed —
    # tightening the guard to `< 1.0` flips this row and goes RED.
    _e_full, _r_full = classify(["x"], {"x": {"status": "allowed", "5h_util": "1.0",
                                              "7d_util": "0.1", "5h_reset": "14:00"}}, 0.10)
    chk("[#421] a util of exactly 1.0 is IN RANGE -> CAPPED with its reset, not 'out of range'",
        (_e_full, "CAPPED" in _r_full[0][1], "14:00" in _r_full[0][1],
         "out of range" in _r_full[0][1]), (0, True, True, False))
    # `_util` stays the BACKOFF-STAMP parser: the [0,1] gate belongs to the 5h/7d windows only, so an
    # exempt account's `backoff_until` epoch (far outside [0,1]) must still suppress eligibility.
    chk("[#421] _util still parses an out-of-[0,1] epoch (the backoff stamp is not range-gated)",
        _util(1_700_000_000), 1_700_000_000.0)
    _e_bo, _r_bo = classify(["cx"], {"cx": {"exempt": True, "reachability": "live",
                                            "backoff_until": 1_700_000_300}}, 0.10,
                            now=1_700_000_000)
    chk("[#421] an epoch backoff stamp still backs the account off (range gate is windows-only)",
        (_e_bo, "BACKED OFF" in _r_bo[0][1]), (0, True))

    # ---- [registry #639] the PROBE-OUTCOME SIDECAR: `probe_empty = not usage` cannot tell an idle
    # fleet from an unmeasured one, and misses a partial failure entirely. Read fail-closed. --------
    def _sidecar(document, name="usage-probe.json"):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(document if isinstance(document, str) else json.dumps(document))
        return path

    probe_now = 1_700_000_000
    chk("[#639] an UNSET sidecar path keeps the legacy inference (None, not an outage)",
        probe_status(None, probe_now), (None, ""))
    chk("[#639] a fresh ok sidecar is measured",
        probe_status(_sidecar({"schema": PROBE_SCHEMA, "outcome": "ok", "detail": "probe-succeeded",
                               "attempted_at": probe_now}), probe_now),
        (True, "probe-succeeded"))
    chk("[#639] a failed sidecar is NOT measured and carries the recorded cause",
        probe_status(_sidecar({"schema": PROBE_SCHEMA, "outcome": "failed",
                               "detail": "secret-subset-empty", "attempted_at": probe_now}),
                     probe_now),
        (False, "secret-subset-empty"))
    chk("[#639] an ABSENT sidecar (path set, file missing) fails closed",
        probe_status(os.path.join(tempfile.mkdtemp(), "nope.json"), probe_now),
        (False, "probe-status-unreadable"))
    chk("[#639] truncated JSON fails closed",
        probe_status(_sidecar('{"schema":"account-usage-probe/v1"'), probe_now),
        (False, "probe-status-unreadable"))
    chk("[#639] a wrong-schema sidecar fails closed",
        probe_status(_sidecar({"schema": "something-else", "outcome": "ok",
                               "attempted_at": probe_now}), probe_now),
        (False, "probe-status-malformed"))
    chk("[#639] an undated sidecar fails closed",
        probe_status(_sidecar({"schema": PROBE_SCHEMA, "outcome": "ok"}), probe_now),
        (False, "probe-status-undated"))
    chk("[#639] a STALE ok sidecar fails closed (a leftover from an earlier run)",
        probe_status(_sidecar({"schema": PROBE_SCHEMA, "outcome": "ok", "detail": "probe-succeeded",
                               "attempted_at": probe_now - PROBE_MAX_AGE_SECONDS - 1}), probe_now),
        (False, "probe-status-stale"))
    chk("[#639] a markup/handle-bearing detail is not rendered verbatim",
        probe_status(_sidecar({"schema": PROBE_SCHEMA, "outcome": "failed",
                               "detail": "acct01 <img src=x>", "attempted_at": probe_now}),
                     probe_now),
        (False, "probe-not-ok"))
    chk("[#639] the unmeasured banner names the recorded cause",
        "`secret-subset-empty`" in render(0, r6, pool, 2, "m", probe_empty=True,
                                          probe_detail="secret-subset-empty"), True)
    # Schema parity with the OTHER producer/consumer of this sidecar (#219's dashboard lane): one
    # contract, so a rename there cannot silently make this reader fail closed forever.
    _dg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard-gen.py")
    _dg_spec = _ilu.spec_from_file_location("registry_dashboard_gen_alert", _dg_path)
    _dg = _ilu.module_from_spec(_dg_spec)
    _dg_spec.loader.exec_module(_dg)
    chk("[#639] the probe-sidecar schema matches dashboard-gen's", PROBE_SCHEMA, _dg.PROBE_SCHEMA)
    # Policy reader: pool union + strictest (max) margin across enabled rows; disabled rows ignored.
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as fh:
        fh.write('[repos."o/a"]\nenabled = true\naccount_pool = ["acct01", "acct02"]\n'
                 'usage_safety_margin = 0.15\n'
                 '[repos."o/b"]\nenabled = true\naccount_pool = ["acct02", "acct03"]\n'
                 'usage_safety_margin = 0.10\n'
                 '[repos."o/c"]\nenabled = false\naccount_pool = ["acct99"]\n')
        policy_path = fh.name
    got_pool, got_margin = _policy_pool_margin(policy_path)
    os.unlink(policy_path)
    chk("policy pool union", got_pool, ["acct01", "acct02", "acct03"])
    chk("policy margin is the max", got_margin, 0.15)
    chk("absent policy falls back", _policy_pool_margin("/nonexistent/policy.toml"), (None, None))
    # Alert routing (issue #39; hardened #432 round 1): the private repo is used ONLY when its
    # token is present, it is distinct from the registry, AND its visibility is positively
    # CONFIRMED private; a half-configured deployment (repo set, token missing) falls back to the
    # registry repo so the write can't fail silently under the ambient token. token=None means
    # "use the ambient GH_TOKEN".
    vis_calls = []
    chk("route: repo+token+CONFIRMED private -> private + token, no redaction",
        _alert_route("org/private", "tok", "org/registry",
                     confirmed_private=lambda r, t: vis_calls.append((r, t)) or True),
        ("org/private", "tok", False))
    chk("route: the visibility check runs against the ALERT repo under the ALERT token",
        vis_calls, [("org/private", "tok")])
    # #432 round 1: configuration alone is NOT verification — same-repo and public/unverifiable
    # ALERT_REPOs must land redacted on the registry even with both env vars non-empty.
    chk("route: ALERT_REPO == REGISTRY_REPO -> registry, REDACTED (#432 r1)",
        _alert_route("org/registry", "tok", "org/registry",
                     confirmed_private=lambda r, t: True), ("org/registry", None, True))
    chk("route: same-repo rejection is case-insensitive (GitHub repo names are)",
        _alert_route("Org/Registry", "tok", "org/registry",
                     confirmed_private=lambda r, t: True), ("org/registry", None, True))
    chk("route: UNCONFIRMED visibility (public repo or failed lookup) -> registry, REDACTED "
        "(#432 r1)",
        _alert_route("org/other-public", "tok", "org/registry",
                     confirmed_private=lambda r, t: False), ("org/registry", None, True))
    half_calls = []
    chk("route: repo but NO token -> registry fallback, REDACTED, and NO visibility call",
        (_alert_route("org/private", "", "org/registry",
                      confirmed_private=lambda r, t: half_calls.append(r) or True), half_calls),
        (("org/registry", None, True), []))
    chk("route: repo but None token -> registry fallback, REDACTED",
        _alert_route("org/private", None, "org/registry",
                     confirmed_private=lambda r, t: True), ("org/registry", None, True))
    # Issue #107: an UNCONFIGURED route (no ALERT_REPO) must ALSO land redacted on the public
    # registry — a lone ALERT_TOKEN is not a verified private destination, and no route at all
    # certainly is not. The public fallback must never enumerate raw account handles.
    chk("route: token but NO repo -> registry fallback, REDACTED (#107)",
        _alert_route("", "tok", "org/registry",
                     confirmed_private=lambda r, t: True), ("org/registry", None, True))
    chk("route: neither repo nor token -> registry fallback, REDACTED (#107)",
        _alert_route("", "", "org/registry",
                     confirmed_private=lambda r, t: True), ("org/registry", None, True))
    chk("route: None repo/token -> registry fallback, REDACTED (#107)",
        _alert_route(None, None, "org/registry",
                     confirmed_private=lambda r, t: True), ("org/registry", None, True))
    # Redacted PUBLIC-registry fallback (issue #204): the body must carry NEITHER an account
    # handle NOR any count/pool-size/reset time — only a generic degraded signal plus the
    # private-route fix-it hint. rrows deliberately carries a capped %, a reset marker and an ok
    # row so a regression that re-enumerates counts/resets goes RED here.
    rrows = [("acct-priv-h1", "CAPPED — 5h window 95% used, resets t", False),
             ("acct-priv-h2", "UNAVAILABLE — token invalid/expired or probe failed", False),
             ("acct-priv-h3", "ok — 5h 10%, 7d 20%", True)]
    red = render(1, rrows, ["p", "q", "r"], 2, "m", redact_handles=True)
    chk("redacted body carries no handle",
        ("acct-priv-h1" in red, "acct-priv-h2" in red, "acct-priv-h3" in red), (False, False, False))
    chk("redacted body carries NO counts, NO pool size, NO reset time (#204)",
        ("capped: " in red, "unavailable: " in red, "✅ ok: " in red, "Usable workers" in red,
         "1/3" in red, "95%" in red),
        (False, False, False, False, False, False))
    chk("redacted body keeps the generic degraded signal + private-route hint",
        ("DEGRADED" in red, "SUPPRESSED" in red, "ALERT_REPO" in red, "ALERT_TOKEN" in red),
        (True, True, True, True))
    # Issue #204: the redacted PUBLIC body enumerates NO categories at all — not even a backed-off
    # count — and no reset epoch. The handle, the "x2" hit count and the "epoch 99" reset must all
    # be absent (a regression that re-adds the aggregate category line goes RED here).
    rback = render(0, [("acct-priv-h4", "BACKED OFF — provider rate limit hit (x2); resumes at "
                        "epoch 99 (self-clearing)", False)], ["p"], 1, "m", redact_handles=True)
    chk("redacted backed-off row leaks no handle, no count, no reset epoch (#204)",
        ("backed off: " in rback, "x2" in rback, "epoch 99" in rback, "acct-priv-h4" in rback,
         "0/1" in rback),
        (False, False, False, False, False))
    # _gh(check=True) fail-loud + sanitization (review r1): a non-zero gh returncode must emit a
    # ::warning:: naming the op + rc, and must NOT republish gh stderr (GH_DEBUG=api can echo the
    # request body) nor any argument content.
    import contextlib
    import io

    class _FailedRun:
        returncode = 1
        stderr = "SENTINEL-STDERR-ECHO"
        stdout = ""

    real_run = subprocess.run
    subprocess.run = lambda *a, **k: _FailedRun()
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _gh(["issue", "edit", "1", "--body", "SENTINEL-BODY-HANDLE"], capture=True, check=True)
        warned = buf.getvalue()
    finally:
        subprocess.run = real_run
    chk("gh check=True warns op+rc on failure",
        ("::warning::" in warned, "issue edit" in warned, "rc=1" in warned), (True, True, True))
    chk("gh failure warning is sanitized",
        ("SENTINEL-STDERR-ECHO" in warned, "SENTINEL-BODY-HANDLE" in warned), (False, False))
    # _repo_confirmed_private (#432 round 1): True ONLY on a definitive `"private": true`; every
    # failure shape is False (fail closed), and the lookup runs under the ROUTE token.
    vis_seen = []

    def _vis_run(rc, stdout):
        def run(args, **kw):
            vis_seen.append((list(args), (kw.get("env") or {}).get("GH_TOKEN")))

            class _R:
                returncode, stderr = rc, ""
            _R.stdout = stdout
            return _R()
        return run

    real_run = subprocess.run
    try:
        subprocess.run = _vis_run(0, json.dumps({"private": True, "full_name": "org/private"}))
        chk("_repo_confirmed_private: definitive private=true -> True, GET /repos under the "
            "route token",
            (_repo_confirmed_private("org/private", "route-tok"), vis_seen[0]),
            (True, (["gh", "api", "repos/org/private"], "route-tok")))
        subprocess.run = _vis_run(0, json.dumps({"private": False}))
        chk("_repo_confirmed_private: a PUBLIC destination -> False (fail closed)",
            _repo_confirmed_private("org/pub", "t"), False)
        subprocess.run = _vis_run(1, "")
        chk("_repo_confirmed_private: failed lookup -> False (never assumed private)",
            _repo_confirmed_private("org/private", "t"), False)
        subprocess.run = _vis_run(0, "gh: not json")
        chk("_repo_confirmed_private: unparseable payload -> False (fail closed)",
            _repo_confirmed_private("org/private", "t"), False)
        subprocess.run = _vis_run(0, json.dumps({"visibility": "private"}))
        chk("_repo_confirmed_private: anything but a literal private=true bool -> False",
            _repo_confirmed_private("org/private", "t"), False)
    finally:
        subprocess.run = real_run
    # END-TO-END redaction wiring (review r2): main() itself must feed _alert_route's redact flag
    # into render() AND write to the registry repo — deleting the redact_handles wiring in main()
    # (not just the pure helpers) must go red here. Half-configured env + stubbed gh.
    calls = []

    class _OkRun:
        returncode = 0
        stdout = "[]"
        stderr = ""

    def _capture_run(args, **_kw):
        calls.append(list(args))
        return _OkRun()

    wired_env = {"REGISTRY_REPO": "org/registry", "ALERT_REPO": "org/private",
                 "ACCOUNT_POOL": '["acct-wire-h1", "acct-wire-h2"]',
                 "POLICY_FILE": "/nonexistent/policy.toml"}
    saved_env = {k: os.environ.get(k)
                 for k in list(wired_env) + ["ALERT_TOKEN", "WORKER_USAGE_FILE"]}
    os.environ.update(wired_env)
    os.environ.pop("ALERT_TOKEN", None)
    os.environ.pop("WORKER_USAGE_FILE", None)
    real_run = subprocess.run
    subprocess.run = _capture_run
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            main()
    finally:
        subprocess.run = real_run
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    created = next((c for c in calls if c[:3] == ["gh", "issue", "create"]), None)
    body_arg = created[created.index("--body") + 1] if created and "--body" in created else ""
    repo_arg = created[created.index("-R") + 1] if created and "-R" in created else ""
    chk("main() half-configured: alert created on the REGISTRY repo", repo_arg, "org/registry")
    chk("main() half-configured: body is generic END-TO-END — no handles, no counts, no pool "
        "size (#204)",
        ("acct-wire-h1" in body_arg, "acct-wire-h2" in body_arg, "unavailable: " in body_arg,
         "Usable workers" in body_arg, "SUPPRESSED" in body_arg, "ALERT_TOKEN" in body_arg),
        (False, False, False, False, True, True))
    # END-TO-END #107 guard: the FULLY-UNCONFIGURED case (no ALERT_REPO at all) must ALSO land on
    # the public registry repo with account handles redacted. This is the exact defect issue #107
    # names — the old `redact_handles = bool(alert_repo)` published raw handles here. Reverting the
    # fix to that expression must go RED on this assertion, not just the pure-helper ones above.
    calls2 = []

    def _capture_run2(args, **_kw):
        calls2.append(list(args))
        return _OkRun()

    unconfigured_env = {"REGISTRY_REPO": "org/registry",
                        "ACCOUNT_POOL": '["acct-wire-h1", "acct-wire-h2"]',
                        "POLICY_FILE": "/nonexistent/policy.toml"}
    saved_env2 = {k: os.environ.get(k)
                  for k in list(unconfigured_env) + ["ALERT_REPO", "ALERT_TOKEN", "WORKER_USAGE_FILE"]}
    os.environ.update(unconfigured_env)
    os.environ.pop("ALERT_REPO", None)
    os.environ.pop("ALERT_TOKEN", None)
    os.environ.pop("WORKER_USAGE_FILE", None)
    real_run = subprocess.run
    subprocess.run = _capture_run2
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            main()
    finally:
        subprocess.run = real_run
        for k, v in saved_env2.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    created2 = next((c for c in calls2 if c[:3] == ["gh", "issue", "create"]), None)
    body2 = created2[created2.index("--body") + 1] if created2 and "--body" in created2 else ""
    repo2 = created2[created2.index("-R") + 1] if created2 and "-R" in created2 else ""
    chk("main() unconfigured (#107): alert created on the public REGISTRY repo", repo2, "org/registry")
    chk("main() unconfigured (#107/#204): body is generic END-TO-END — no handles, no counts",
        ("acct-wire-h1" in body2, "acct-wire-h2" in body2, "unavailable: " in body2,
         "Usable workers" in body2, "SUPPRESSED" in body2, "ALERT_TOKEN" in body2),
        (False, False, False, False, True, True))
    # END-TO-END #432 round 1: a fully-configured route is honoured ONLY once GET /repos answers
    # `"private": true` under ALERT_TOKEN. (3) confirmed private -> detailed body on the private
    # repo; (4) the SAME configuration with an unverifiable destination (the stub answers the
    # visibility probe with junk) -> generic body on the registry. Reverting _alert_route to
    # trust configuration alone turns (4) RED — that is the exact fail-open the finding names.
    class _VisOk:
        returncode = 0
        stdout = json.dumps({"private": True})
        stderr = ""

    for label, private_ok, want_repo, want_handles in [
            ("verified-private route -> FULL body on the private repo", True,
             "org/private", True),
            ("UNVERIFIABLE ALERT_REPO -> generic body on the registry (fail closed)", False,
             "org/registry", False)]:
        calls3 = []

        def _capture_run3(args, **_kw):
            calls3.append(list(args))
            if args[:3] == ["gh", "api", "repos/org/private"]:
                return _VisOk() if private_ok else _OkRun()   # _OkRun stdout "[]" -> not private
            return _OkRun()

        configured_env = {"REGISTRY_REPO": "org/registry", "ALERT_REPO": "org/private",
                          "ALERT_TOKEN": "tok",
                          "ACCOUNT_POOL": '["acct-wire-h1", "acct-wire-h2"]',
                          "POLICY_FILE": "/nonexistent/policy.toml"}
        saved_env3 = {k: os.environ.get(k)
                      for k in list(configured_env) + ["WORKER_USAGE_FILE"]}
        os.environ.update(configured_env)
        os.environ.pop("WORKER_USAGE_FILE", None)
        real_run = subprocess.run
        subprocess.run = _capture_run3
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                main()
        finally:
            subprocess.run = real_run
            for k, v in saved_env3.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        created3 = next((c for c in calls3 if c[:3] == ["gh", "issue", "create"]), None)
        body3 = created3[created3.index("--body") + 1] if created3 and "--body" in created3 else ""
        repo3 = created3[created3.index("-R") + 1] if created3 and "-R" in created3 else ""
        chk(f"main() {label} (#432 r1)",
            (repo3, "acct-wire-h1" in body3, "SUPPRESSED" in body3),
            (want_repo, want_handles, not want_handles))
    # END-TO-END delivery-failure handling (review round 2 of #432): _repo_confirmed_private
    # proves only metadata READ, so a fine-grained ALERT_TOKEN without Issues write passes the
    # visibility probe and then fails at issue list/create/edit. main() must observe that
    # failure, retry a FRESHLY RENDERED redacted body on the public registry under the ambient
    # token (never reuse the detailed body), print "maintainer alerted" only on a real delivery,
    # and return nonzero when every route fails.

    class _Res:
        def __init__(self, rc, stdout=""):
            self.returncode, self.stdout, self.stderr = rc, stdout, ""

    def _e2e(env, stub):
        """Run main() with env overrides (None -> unset) and a stubbed subprocess.run; returns
        (exit code, captured stdout)."""
        saved = {k: os.environ.get(k) for k in env}
        for k, v in env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        real = subprocess.run
        subprocess.run = stub
        try:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                rc = main()
        finally:
            subprocess.run = real
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        return rc, out.getvalue()

    def _fail_stub(fail, calls):
        """gh stub: the visibility probe answers private:true, `issue list` answers []; any
        ("list"/"create"/"edit", repo) pair in `fail` returns rc 1."""
        def run(args, **_kw):
            calls.append(list(args))
            if args[:3] == ["gh", "api", "repos/org/private"]:
                return _Res(0, json.dumps({"private": True}))
            op = args[2] if args[:2] == ["gh", "issue"] else None
            repo_of = args[args.index("-R") + 1] if "-R" in args else None
            if op and (op, repo_of) in fail:
                return _Res(1)
            return _Res(0, "[]" if op == "list" else "")
        return run

    CONF = {"REGISTRY_REPO": "org/registry", "ALERT_REPO": "org/private", "ALERT_TOKEN": "tok",
            "ACCOUNT_POOL": '["acct-wire-h1", "acct-wire-h2"]',
            "POLICY_FILE": "/nonexistent/policy.toml", "WORKER_USAGE_FILE": None}
    # (1) private issue-LIST failure -> no detailed create anywhere, redacted retry on registry.
    calls_lf = []
    rc_lf, out_lf = _e2e(CONF, _fail_stub({("list", "org/private")}, calls_lf))
    fb = next((c for c in calls_lf if c[:3] == ["gh", "issue", "create"]
               and c[c.index("-R") + 1] == "org/registry"), None)
    fb_body = fb[fb.index("--body") + 1] if fb else ""
    priv_create = next((c for c in calls_lf if c[:3] == ["gh", "issue", "create"]
                        and c[c.index("-R") + 1] == "org/private"), None)
    chk("e2e private list failure -> redacted retry on the registry, rc 0 (#432 r2)",
        (rc_lf, priv_create, fb is not None, "maintainer alerted" in out_lf),
        (0, None, True, True))
    chk("e2e fallback body is FRESHLY REDACTED — no handle, generic signal only (#432 r2)",
        ("acct-wire-h1" in fb_body, "acct-wire-h2" in fb_body, "Usable workers" in fb_body,
         "SUPPRESSED" in fb_body), (False, False, False, True))
    # (2) private CREATE failure (the exact metadata-read-only token shape) -> public fallback.
    calls_cf = []
    rc_cf, _out_cf = _e2e(CONF, _fail_stub({("create", "org/private")}, calls_cf))
    fb2 = next((c for c in calls_cf if c[:3] == ["gh", "issue", "create"]
                and c[c.index("-R") + 1] == "org/registry"), None)
    fb2_body = fb2[fb2.index("--body") + 1] if fb2 else ""
    chk("e2e private create failure -> successful REDACTED public fallback, rc 0 (#432 r2)",
        (rc_cf, fb2 is not None, "acct-wire-h1" in fb2_body, "SUPPRESSED" in fb2_body),
        (0, True, False, True))
    # (2b) private EDIT failure on an existing alert issue -> same public fallback.
    calls_ef = []

    def _edit_fail(args, **_kw):
        calls_ef.append(list(args))
        if args[:3] == ["gh", "api", "repos/org/private"]:
            return _Res(0, json.dumps({"private": True}))
        if args[:3] == ["gh", "issue", "list"]:
            on_private = args[args.index("-R") + 1] == "org/private"
            return _Res(0, json.dumps([{"number": 7, "title": ALERT_TITLE}]) if on_private
                        else "[]")
        if args[:3] == ["gh", "issue", "edit"]:
            return _Res(1)
        return _Res(0)

    rc_ef, _out_ef = _e2e(CONF, _edit_fail)
    fb3 = next((c for c in calls_ef if c[:3] == ["gh", "issue", "create"]
                and c[c.index("-R") + 1] == "org/registry"), None)
    fb3_body = fb3[fb3.index("--body") + 1] if fb3 else ""
    chk("e2e private edit failure -> REDACTED public fallback, rc 0 (#432 r2)",
        (rc_ef, fb3 is not None, "acct-wire-h1" in fb3_body, "SUPPRESSED" in fb3_body),
        (0, True, False, True))
    # (3) BOTH routes fail -> nonzero exit, ::error::, and NO "maintainer alerted" claim.
    calls_bf = []
    rc_bf, out_bf = _e2e(CONF, _fail_stub({("create", "org/private"),
                                           ("create", "org/registry")}, calls_bf))
    chk("e2e BOTH routes fail -> rc 1, ::error::, no 'maintainer alerted' (#432 r2)",
        (rc_bf, "::error::" in out_bf, "maintainer alerted" in out_bf), (1, True, False))
    # (4) recovery side: a failed `issue list` is a LOOKUP FAILURE (rc 1, stale alert may remain
    # open), never parsed as "no open alert"; a healthy fleet with working gh stays rc 0.
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as uf:
        json.dump({"acct-wire-h1": {"status": "allowed", "5h_util": "0.1", "7d_util": "0.1"},
                   "acct-wire-h2": {"exempt": True, "reachability": "live"}}, uf)
        healthy_usage = uf.name
    HEALTHY = dict(CONF, ALERT_REPO=None, ALERT_TOKEN=None, WORKER_USAGE_FILE=healthy_usage)
    calls_rf = []
    rc_rf, out_rf = _e2e(HEALTHY, _fail_stub({("list", "org/registry")}, calls_rf))
    calls_rok = []
    rc_rok, out_rok = _e2e(HEALTHY, _fail_stub(set(), calls_rok))
    os.unlink(healthy_usage)
    chk("e2e recovery-side list failure observed -> rc 1, stale-alert warning (#432 r2)",
        (rc_rf, "stale alert" in out_rf), (1, True))
    chk("e2e healthy fleet + working gh -> rc 0, degraded=false",
        (rc_rok, "degraded=false" in out_rok), (0, True))
    # [#421] BINDING LAYER: the whole point of the tightening is that main() can no longer report a
    # fleet HEALTHY on a snapshot dispatch would refuse. This is the forged-map scenario from the
    # issue — an empty status and a negative utilization, the two shapes the producer can no longer
    # emit — driven through main() rather than through classify() alone. Before the fix both
    # accounts read `ok` and the tick printed `degraded=false`; now both are UNAVAILABLE, so the
    # alert fires. `_util`'s own nan/inf guard cannot catch either shape.
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as ff:
        json.dump({"acct-wire-h1": {"status": "", "5h_util": "0.1", "7d_util": "0.1"},
                   "acct-wire-h2": {"status": "allowed", "5h_util": "-1", "7d_util": "0.1"}}, ff)
        forged_usage = ff.name
    FORGED = dict(CONF, ALERT_REPO=None, ALERT_TOKEN=None, WORKER_USAGE_FILE=forged_usage)
    calls_forged = []
    rc_forged, out_forged = _e2e(FORGED, _fail_stub(set(), calls_forged))
    os.unlink(forged_usage)
    forged_created = next((c for c in calls_forged if c[:3] == ["gh", "issue", "create"]), None)
    chk("[#421] e2e a forged map (empty status + negative util) is DEGRADED end-to-end, "
        "never 'degraded=false'",
        (rc_forged, "degraded=false" in out_forged, "degraded=true" in out_forged,
         forged_created is not None), (0, False, True, True))
    # Probe-exempt backoff surfacing (decision 2026-07-17, registry issue #29): an exempt account
    # is `ok` by design (never probe-missing), but an ACTIVE backoff is surfaced + not eligible,
    # an EXPIRED one clears, and a forged/malformed stamp fails open to `ok` (never crashes).
    tnow = 5_000
    e8, r8 = classify(["cx"], {"cx": {"exempt": True, "reachability": "live", "backoff_until": tnow + 300,
                                      "backoff_consecutive": 2}}, 0.10, now=tnow)
    chk("active backoff surfaced + not eligible",
        (e8, "BACKED OFF" in r8[0][1], "x2" in r8[0][1], r8[0][2]), (0, True, True, False))
    chk("unsaturated backoff count stays EXACT (no lower-bound suffix)",
        "x2+" in r8[0][1], False)
    # A saturated (>6-hit, possibly ledger-truncated) chain displays the LOWER-BOUND form —
    # "x6+", never an exact "x6" (PR #85 finding 2: prune truncation floors the re-derived
    # count, so an exact display corrupts the diagnostic). Forged non-bool flags add nothing.
    e8b, r8b = classify(["cx"], {"cx": {"exempt": True, "reachability": "live", "backoff_until": tnow + 300,
                                        "backoff_consecutive": 6,
                                        "backoff_saturated": True}}, 0.10, now=tnow)
    chk("saturated backoff displays the lower-bound form (x6+, never exact x6)",
        ("(x6+)" in r8b[0][1], "(x6)" in r8b[0][1], r8b[0][2]), (True, False, False))
    e8c, r8c = classify(["cx"], {"cx": {"exempt": True, "reachability": "live", "backoff_until": tnow + 300,
                                        "backoff_consecutive": 6,
                                        "backoff_saturated": "yes"}}, 0.10, now=tnow)
    chk("forged non-bool saturated flag never adds the suffix (strict is-True)",
        ("(x6)" in r8c[0][1], "(x6+)" in r8c[0][1]), (True, False))
    e9, r9 = classify(["cx"], {"cx": {"exempt": True, "reachability": "live", "backoff_until": tnow - 1}}, 0.10, now=tnow)
    chk("expired backoff -> ok again", (e9, r9[0][2]), (1, True))
    e10, r10 = classify(["cx"], {"cx": {"exempt": True, "reachability": "live", "backoff_until": "garbage"}}, 0.10, now=tnow)
    chk("malformed backoff stamp fails open to ok", (e10, r10[0][2]), (1, True))
    # inf/nan stamps fail open to ok (matches usage_eligible's finite-only comparison, r1)
    e11, r11 = classify(["cx"], {"cx": {"exempt": True, "reachability": "live", "backoff_until": "inf"}}, 0.10, now=tnow)
    chk("inf backoff stamp fails open to ok (no dispatch/alert split)", (e11, r11[0][2]), (1, True))
    # a huge JSON int (10**400) makes float() RAISE OverflowError, not return inf — the monitoring
    # tick must survive it: exempt backoff fails OPEN to ok, a usage window fails CLOSED to
    # UNAVAILABLE (cross-provider review r2 finding 3)
    e13, r13 = classify(["cx"], {"cx": {"exempt": True, "reachability": "live", "backoff_until": 10**400}}, 0.10, now=tnow)
    chk("huge-int backoff stamp fails open to ok (no alert drop)", (e13, r13[0][2]), (1, True))
    e14, r14 = classify(["a"], {"a": {"status": "allowed", "5h_util": 10**400, "7d_util": 0.1}},
                        0.10, now=tnow)
    chk("huge-int usage window classifies fail-closed UNAVAILABLE", (e14, r14[0][2]), (0, False))
    # a forged truthy exempt STRING does not ride the exempt arm (STRICT flag, r1)
    e12, r12 = classify(["cx"], {"cx": {"exempt": "false"}}, 0.10, now=tnow)
    chk("forged exempt string classifies fail-closed UNAVAILABLE", (e12, r12[0][2]), (0, False))
    # NaN/inf guard (issue #39): a literal `nan`/`inf` header must classify UNAVAILABLE, not `ok`
    # (NaN comparisons are all False, so it would otherwise slip past the CAPPED threshold).
    chk("nan header -> None (fail-closed)", _util("nan"), None)
    chk("inf header -> None (fail-closed)", _util("inf"), None)
    chk("-inf header -> None (fail-closed)", _util("-inf"), None)
    chk("decimal header still parses", _util("0.42"), 0.42)
    e7, r7 = classify(["x"], {"x": {"status": "allowed", "5h_util": "nan", "7d_util": "0"}}, 0.10)
    chk("nan util -> unavailable, not ok",
        (e7, r7[0][2], "usage window missing/unparseable" in r7[0][1]), (0, False, True))
    print("usage-alert self-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    sys.exit(main())
