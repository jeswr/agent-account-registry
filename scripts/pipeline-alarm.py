#!/usr/bin/env python3
# [FABLE-5] Unified loud-fail pipeline alarm (registry issue: "we should see NONE [failures] and
# lots of visibility when one happens").
#
# WHY THIS EXISTS. Before this, a pipeline failure was visible ONLY as a red run buried in the
# Actions tab of a private repo. The two existing dispatch.yml alarm steps (model-health record +
# usage-alert) live INSIDE the CLAIM job, so a PLAN-job crash (needs: plan) SKIPS them and the whole
# tick goes silent (the run-29617040167 whole-sweep-kill posture). groom.yml / groom-leases.yml /
# triage-issue.yml / set-up-account.yml / worker.yml / review-fix.yml had NO always()-final alarm at
# all. This script is the shared, reusable mechanism EVERY pipeline workflow invokes as its final
# `if: ${{ failure() || cancelled() }}` step so NO failure is ever silent.
#
# WHAT IT DOES, on any job failure/cancel/timeout:
#   (a) CLASSIFY {workflow, job, failed-step, failure-class} from the run context (the GitHub-
#       provided env + the caller-passed job results). No secrets are read to classify.
#   (b) CAPTURE a BOUNDED, CREDENTIAL-SAFE diagnostic tail. It NEVER emits a raw model transcript,
#       an account handle (`acctNN`), a worker-account email, or a token — it reuses worker-live.sh's
#       posture: only a short, redacted, host-observable summary line. A diagnostic input that even
#       LOOKS like a credential OR an account identity (email / `acctNN`) is redacted, and every
#       markdown-active / ledger-delimiter char is stripped, before it can reach the issue body or
#       the hidden JSON ledger — enforced HERE (see _sanitize / SECRET_PATTERNS), not merely by
#       which callers exist today, and locked by --self-test (a leak mutation goes RED).
#   (c) RAISE a LOUD, DEDUPED, maintainer-visible alert: a SINGLE rolling "⚠️ pipeline failures"
#       issue (label `pipeline-alert`), keyed by a hidden HTML body marker (the model-health.py
#       upsert pattern), carrying a compact table (class × count × last-seen × run-link). A recurring
#       failure UPDATES the rolling record — it never spams a new issue. This shares the ledger
#       alert-channel philosophy with the throughput observability work (PR #93 `throughput-alert`):
#       one failure surface, one throughput surface, both rolling+deduped, both @-mentioning the
#       maintainer — never two mechanisms fighting. On a HEALTHY run (`--resolve`) the workflow's
#       rows are pruned and the issue auto-closes once the ledger empties (PR #51's plan-alert
#       auto-close-on-heal, GENERALIZED here to every workflow — this script supersedes plan-alert).
#   (d) FAIL-SOFT. The alarm can NEVER mask or replace the primary failure. main() ALWAYS exits 0
#       (it is a diagnostic reporter, not a gate — a nonzero here would REPLACE the real failure's
#       red X with the alarm's own). Its own internal failure degrades to a plain `::error::`
#       annotation. The load-bearing invariant, enforced by --self-test.
#
# The alert body table is bounded to MAX_TABLE_ROWS newest classes and each cell is redacted; the
# ledger-of-failures lives in the issue body itself (a hidden JSON block), so no extra data branch
# is needed and a torn issue-read degrades to "append a fresh row" rather than losing the alarm.

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

# --- alert surface (COORDINATED with PR #93's throughput-alert) --------------------------------
# A DISTINCT label from throughput-alert / ops-alert: a maintainer filtering "why did a run go red"
# wants the failure surface, not the "backlog is growing" surface. Same rolling+deduped+marker
# discipline, same maintainer @-mention, same repo/token routing (ALERT_REPO/ALERT_TOKEN privacy
# fallback), so the two coexist as ONE coherent alert channel rather than two spammers.
ALERT_LABEL = "pipeline-alert"
ALERT_COLOR = "b60205"
MARKER = "<!-- pipeline-alarm:rolling -->"            # keys the single rolling issue's upsert
LEDGER_MARKER_OPEN = "<!-- pipeline-alarm:ledger"     # opens the hidden JSON failure ledger block
LEDGER_MARKER_CLOSE = "pipeline-alarm:ledger -->"
ALERT_TITLE = "⚠️ pipeline failures"

# --- bounds (WHY): the issue body is the durable store; keep it small + readable. ----------------
MAX_TABLE_ROWS = 30          # newest N (workflow/job/class) rows shown in the table + kept in ledger
MAX_DETAIL_LEN = 400         # per-row sanitized diagnostic tail cap (chars)
GH_TIMEOUT_S = 45            # per gh call
# Optimistic-concurrency bound: the issue body is a SHARED ledger with no server-side CAS, so every
# writer runs a read/merge/write/RE-READ loop — if the re-read shows a concurrent writer clobbered
# our merge (our row absent / our prune undone), we retry against THEIR body so concurrent alarms
# MERGE instead of overwrite. Bounded: exhaustion degrades to a loud ::error:: (fail-soft), and the
# row retries on the next failing tick anyway.
MAX_WRITE_ATTEMPTS = 4
RETRY_SLEEP_S = 0.5          # small linear backoff between optimistic-concurrency retries

# --- credential-safe redaction (reuse worker-live.sh's "sanitized class only" posture) ----------
# Any diagnostic string is scrubbed BEFORE it can reach the issue body. These patterns are
# deliberately broad — a false-positive redaction (over-scrubbing) is safe; a leaked token is not.
SECRET_PATTERNS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}"),                 # GitHub PAT / App / OAuth / refresh
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),               # fine-grained PAT
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}"),                 # Anthropic-style key (before sk-)
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),                     # OpenAI-style key
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}"),  # JWT
    re.compile(r"(?i)\b(token|secret|password|passwd|api[_-]?key|bearer|authorization)\b"
               r"\s*[:=]\s*\S+"),                              # key: value credential lines
    # Account identity is a credential-adjacent PII shape the repo traffics in (acct* handles +
    # worker-account emails, cf account-usage.py / backfill-provenance.py). The alarm body is an
    # operational failure report, NOT an identity ledger, so redact BOTH the `acct*` handle and
    # any email before either can reach the issue body (the docstring's "never an account handle"
    # guarantee is enforced HERE, not merely by which callers exist today). REAL registry handles
    # are alphanumeric, not digit-only (policy/repos.toml carries acct2css/acct3css/acct4css
    # alongside acct01..acct07), so the pattern is `acct` + any word-run — unbounded, because a
    # bounded quantifier plus \b would let an over-long handle skip the match and leak whole.
    re.compile(r"(?i)\bacct[0-9a-z_-]*\b"),                    # acct* worker-account handle
    re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),  # email address (PII)
    re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),                   # long base64-ish blobs (token-shaped)
]
_REDACTED = "[redacted]"

# Markdown-active + ledger-delimiter characters a detail cell must never carry into the rolling
# issue body. Stripping these makes an arbitrary future caller's `detail` incapable of (a) injecting
# a clickable link / image / @-mention into the maintainer-facing issue, or (b) forging the hidden
# `<!-- pipeline-alarm:ledger ... -->` delimiters to truncate/wipe the accumulated JSON ledger on
# the next tick. Backtick/pipe were already stripped (table-breaking); this widens the set.
_MARKDOWN_ACTIVE = "`|<>[]!@"


def _now(now=None):
    return now if now is not None else datetime.now(timezone.utc)


def _sanitize(text):
    """Scrub credentials + collapse to a single bounded line. NEVER let a raw transcript, handle, or
    token through: apply every SECRET_PATTERN, strip control chars, drop newlines, and cap length.
    A None/blank input degrades to a fixed placeholder (never an exception)."""
    if not text:
        return "(no diagnostic captured)"
    s = str(text)
    for pat in SECRET_PATTERNS:
        s = pat.sub(_REDACTED, s)
    # Neutralize the hidden-ledger delimiters BEFORE per-char stripping so a detail carrying a
    # forged `<!-- pipeline-alarm:ledger ... -->` pair can never truncate/wipe the accumulated JSON
    # ledger on the next _parse_ledger tick. (Char-stripping alone would break the `<!--` but the
    # `pipeline-alarm:ledger` word-run would survive; kill the whole marker token explicitly.)
    for marker in (LEDGER_MARKER_OPEN, LEDGER_MARKER_CLOSE, MARKER, "pipeline-alarm:ledger"):
        s = s.replace(marker, "[marker]")
    # single line, printable only, bounded; strip markdown-active + table-breaking chars so a
    # detail can never inject a link/image/mention or forge a delimiter into the issue body
    s = "".join(ch if (ch.isprintable() and ch not in _MARKDOWN_ACTIVE) else " " for ch in s)
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > MAX_DETAIL_LEN:
        s = s[:MAX_DETAIL_LEN - 1].rstrip() + "…"
    return s or "(no diagnostic captured)"


def classify_failure(job_result, step_conclusion, cancelled):
    """Map the caller-passed run signals to a compact, stable failure CLASS. HOST-OBSERVABLE ONLY —
    the job result string GitHub sets + whether the run was cancelled/timed-out. Never inspects
    model output. Unknown maps to `job-failure` (still loud, never dropped)."""
    jr = (job_result or "").strip().lower()
    if cancelled or jr == "cancelled":
        return "cancelled-or-timeout"
    if jr == "skipped":
        # A downstream job SKIPPED because a needs: dependency failed (the PLAN-crash class): the
        # whole sweep died upstream. This is EXACTLY the silent class the maintainer is fighting.
        return "upstream-skip"
    if jr in ("failure", "") or jr not in ("success",):
        return "job-failure"
    return "job-failure"


# ------------------------------------------------------------------------------------------------
# issue body (de)serialization: the hidden JSON ledger + the rendered table
# ------------------------------------------------------------------------------------------------
def _parse_ledger(body):
    """Extract the hidden JSON failure ledger from an existing issue body. A torn/garbled/missing
    ledger degrades to [] (the alarm APPENDS a fresh row rather than ever losing the signal)."""
    if not body:
        return []
    start = body.find(LEDGER_MARKER_OPEN)
    if start < 0:
        return []
    start = body.find("\n", start)
    end = body.find(LEDGER_MARKER_CLOSE, start if start >= 0 else 0)
    if start < 0 or end < 0:
        return []
    blob = body[start:end].strip()
    # blob is a ```json fenced block; strip fences defensively
    blob = blob.strip("`").strip()
    if blob.startswith("json"):
        blob = blob[4:].strip()
    try:
        data = json.loads(blob)
        return data if isinstance(data, list) else []
    except (ValueError, TypeError):
        return []


def _merge_row(ledger, new_row):
    """Upsert a (workflow, job, failure_class) row: bump count + last-seen/run-link, keep first-seen.
    Deduplication is on the (workflow, job, failure_class) KEY so a recurring failure UPDATES its row
    instead of spamming — the load-bearing dedupe invariant."""
    key = (new_row["workflow"], new_row["job"], new_row["failure_class"])
    for row in ledger:
        if (row.get("workflow"), row.get("job"), row.get("failure_class")) == key:
            row["count"] = int(row.get("count", 0)) + 1
            row["last_seen"] = new_row["last_seen"]
            row["run_url"] = new_row["run_url"]
            row["detail"] = new_row["detail"]
            row["failed_step"] = new_row.get("failed_step") or row.get("failed_step", "")
            return ledger
    row = dict(new_row)
    row["count"] = 1
    row.setdefault("first_seen", new_row["last_seen"])
    ledger.append(row)
    return ledger


def _sanitize_row(row):
    """Return a copy of a ledger row with EVERY free-text field re-sanitized. Applied before the
    ledger is serialized into the hidden JSON block AND before any cell is rendered — so a leak can
    survive neither the human-visible table NOR the hidden persistence block (the block is
    plain-text in the issue body and is read by anyone who opens the issue)."""
    out = dict(row)
    out["workflow"] = _sanitize(row.get("workflow", "?"))
    out["job"] = _sanitize(row.get("job", "?"))
    out["failure_class"] = _sanitize(row.get("failure_class", "?"))
    out["detail"] = _sanitize(row.get("detail"))
    out["failed_step"] = _sanitize(row.get("failed_step") or "")
    url = row.get("run_url", "")
    out["run_url"] = url if isinstance(url, str) and url.startswith("https://") else ""
    return out


def _prune(ledger):
    """Keep the newest MAX_TABLE_ROWS rows by last_seen so the body stays bounded + readable, and
    re-sanitize every retained row (defense-in-depth against a tampered/inherited ledger)."""
    ledger.sort(key=lambda r: r.get("last_seen", ""), reverse=True)
    return [_sanitize_row(r) for r in ledger[:MAX_TABLE_ROWS]]


def render_body(ledger, maintainer):
    """Render the rolling failure issue: the marker, a maintainer @-mention, the compact
    class×count×last-seen×run-link table, and the hidden JSON ledger block for the next tick.
    EVERY rendered cell is re-sanitized — the body is the only thing a human reads, so nothing
    unsanitized may reach it even if a prior tick's ledger was tampered."""
    total = sum(int(r.get("count", 0)) for r in ledger)
    lines = [
        MARKER,
        f"> 🤖 SPARQ agent — automated pipeline-failure alarm. @{maintainer}",
        "",
        f"🚨 **{total}** pipeline failure occurrence(s) recorded across "
        f"**{len(ledger)}** distinct failure class(es). "
        "Each row is a `(workflow, job, failure-class)` that went red/cancelled/skipped; "
        "recurrences bump the count in place (this issue is never duplicated).",
        "",
        "| workflow | job | class | count | last seen (UTC) | run |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for r in ledger:
        wf = _sanitize(r.get("workflow", "?"))
        job = _sanitize(r.get("job", "?"))
        cls = _sanitize(r.get("failure_class", "?"))
        cnt = int(r.get("count", 0))
        last = _sanitize(r.get("last_seen", "?"))
        url = r.get("run_url", "")
        run_cell = f"[run]({url})" if url.startswith("https://") else "—"
        lines.append(f"| {wf} | {job} | `{cls}` | {cnt} | {last} | {run_cell} |")
    lines.append("")
    lines.append("**Most recent diagnostic tails (credential-safe, host-observable only):**")
    for r in sorted(ledger, key=lambda x: x.get("last_seen", ""), reverse=True)[:5]:
        step = _sanitize(r.get("failed_step") or "")
        detail = _sanitize(r.get("detail"))
        loc = f" · step `{step}`" if step and step != "(no diagnostic captured)" else ""
        lines.append(f"- `{_sanitize(r.get('workflow','?'))}`/`{_sanitize(r.get('job','?'))}`"
                     f"{loc}: {detail}")
    lines.append("")
    lines.append("_This issue auto-updates each failing tick and reopens on the next failure. "
                 "Recovery IS auto-detected: a healthy run of a workflow prunes its rows, and the "
                 "issue auto-closes once the ledger empties (ported from the plan-alert #51 "
                 "auto-close-on-heal, generalized to every workflow)._")
    # hidden ledger for the next tick
    lines.append("")
    lines.append(f"{LEDGER_MARKER_OPEN}")
    lines.append("```json")
    lines.append(json.dumps(_prune(ledger), separators=(",", ":")))
    lines.append("```")
    lines.append(f"{LEDGER_MARKER_CLOSE}")
    return "\n".join(lines)


# ------------------------------------------------------------------------------------------------
# gh IO (fail-soft: every call is best-effort; a failed gh degrades to a ::error:: annotation)
# ------------------------------------------------------------------------------------------------
def _gh(args, token, capture=False):
    env = dict(os.environ)
    if token:
        env["GH_TOKEN"] = token
    try:
        return subprocess.run(["gh"] + args, capture_output=capture, text=True, env=env,
                              timeout=GH_TIMEOUT_S)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"::error::pipeline-alarm: gh call failed ({exc}); "
              "the primary failure is still the run's red X")
        return subprocess.CompletedProcess(args, 1, "", str(exc))


def _resolve_alert_target():
    """(repo, token) for the alert, honoring the ALERT_REPO/ALERT_TOKEN privacy routing used by
    model-health / usage-alert. ALERT_REPO without ALERT_TOKEN falls back to the registry repo +
    ambient token (never drops the alert)."""
    registry_repo = os.environ.get("REGISTRY_REPO") or os.environ.get("GITHUB_REPOSITORY") or ""
    alert_repo = os.environ.get("ALERT_REPO") or ""
    alert_token = os.environ.get("ALERT_TOKEN") or ""
    ambient = os.environ.get("ALARM_GH_TOKEN") or os.environ.get("GH_TOKEN") or ""
    if alert_repo and alert_token:
        return alert_repo, alert_token
    return registry_repo, ambient


def _find_rolling_issue(repo, token, state):
    """Return (number, body) of the CANONICAL rolling issue in `state` — the LOWEST-numbered issue
    carrying the marker. Lowest-first is the concurrency tiebreak: two racing first-creates both
    re-list after creating, both pick the same (lowest) canonical, and the loser folds its row into
    it and closes its own duplicate — duplicate first-creates CONVERGE instead of persisting."""
    proc = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", state,
                "--json", "number,body", "--limit", "50"], token, capture=True)
    if proc.returncode != 0:
        return None, None
    try:
        found = json.loads(proc.stdout or "[]")
    except ValueError:
        return None, None
    marked = [issue for issue in found
              if isinstance(issue, dict) and isinstance(issue.get("number"), int)
              and MARKER in (issue.get("body") or "")]
    if not marked:
        return None, None
    canonical = min(marked, key=lambda issue: issue["number"])
    return canonical["number"], canonical.get("body") or ""


def _issue_view(num, repo, token):
    """(body, state) of an issue, or (None, None) on any read failure (callers degrade fail-soft)."""
    proc = _gh(["issue", "view", str(num), "-R", repo, "--json", "body,state"],
               token, capture=True)
    if proc.returncode != 0:
        return None, None
    try:
        doc = json.loads(proc.stdout or "{}")
    except ValueError:
        return None, None
    if not isinstance(doc, dict):
        return None, None
    return doc.get("body") or "", str(doc.get("state") or "")


def _row_reflected(body, row):
    """True iff the CURRENT issue body carries `row`'s (workflow, job, class) key at least as fresh
    as `row` itself. This is the optimistic-concurrency verify predicate for a failure write: if a
    concurrent writer clobbered our merge, our key is absent (or stale) in their body and we retry
    the merge against it. `>=` (not `==`) terminates the two-writers-same-key race: whichever
    recurrence's last_seen survives satisfies BOTH writers (the count may undercount by one in that
    rare interleave — the ROW, i.e. the alarm itself, is what must never be lost)."""
    key = (row.get("workflow"), row.get("job"), row.get("failure_class"))
    for existing in _parse_ledger(body):
        if (existing.get("workflow"), existing.get("job"), existing.get("failure_class")) == key:
            return str(existing.get("last_seen", "")) >= str(row.get("last_seen", ""))
    return False


def _create_issue(repo, token, rendered):
    """Create the rolling issue; return its number (parsed from the printed URL) or None."""
    proc = _gh(["issue", "create", "-R", repo, "--title", ALERT_TITLE,
                "--label", ALERT_LABEL, "--body", rendered], token, capture=True)
    if proc.returncode != 0:
        return None
    match = re.search(r"/issues/([0-9]+)\s*$", (proc.stdout or "").strip())
    return int(match.group(1)) if match else 0   # 0 = created but number unknown (best-effort)


def upsert_alarm(new_row, repo, token, maintainer):
    """Idempotent single-rolling-issue upsert under OPTIMISTIC CONCURRENCY. The issue body is a
    shared ledger with no server-side CAS, so every write is read/merge/edit/RE-READ: if the re-read
    shows a concurrent writer overwrote our merge (our row absent), we retry the merge against
    THEIR body — concurrent alarms from different workflows MERGE instead of losing rows. Racing
    first-creates converge on the lowest-numbered marker issue (the loser closes its duplicate and
    folds its row in). A verify that finds the issue CLOSED (a racing --resolve closed it after our
    row landed) REOPENS it — a live failure row never hides behind a closed alert. Every gh return
    code is checked; failure degrades LOUD to ::error:: and never raises (fail-soft)."""
    if not repo or not token:
        print("::error::pipeline-alarm: no alert repo/token resolved; failure NOT recorded to an "
              "issue (still visible as the run's red X). Set REGISTRY_REPO + a token env.")
        return False
    _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", ALERT_COLOR,
         "--description", "Automated pipeline-failure alarm (maintainer action)"],
        token, capture=True)
    # Sanitize the key fields UP FRONT so the merge key matches the (sanitized) persisted ledger —
    # otherwise a workflow name carrying a stripped char could never verify and would spin the loop.
    new_row = _sanitize_row(new_row)
    for attempt in range(MAX_WRITE_ATTEMPTS):
        if attempt:
            time.sleep(RETRY_SLEEP_S * attempt)
        num, body = _find_rolling_issue(repo, token, "open")
        reopened = False
        if num is None:
            num, body = _find_rolling_issue(repo, token, "closed")
            reopened = num is not None
        if num is None:
            rendered = render_body(_prune(_merge_row([], dict(new_row))), maintainer)
            created = _create_issue(repo, token, rendered)
            if created is None:
                print("::error::pipeline-alarm: raising the alert FAILED (retries next failing "
                      "tick); primary failure still visible as the run's red X")
                return False
            # Duplicate-first-create convergence: re-list; if a DIFFERENT (lower-numbered) marker
            # issue exists, ours is the duplicate — close it and retry, folding our row into the
            # canonical issue instead. Both racing creators pick the same canonical (lowest).
            canonical, _ = _find_rolling_issue(repo, token, "open")
            if canonical is not None and created and canonical != created:
                _gh(["issue", "close", str(created), "-R", repo, "--comment",
                     f"Duplicate of #{canonical} (concurrent first-create); folding this row "
                     "into the canonical rolling alert."], token)
                continue
            print("::warning::pipeline-alarm: raised the rolling pipeline-failure alert")
            return True
        ledger = _merge_row(_parse_ledger(body), dict(new_row))
        rendered = render_body(_prune(ledger), maintainer)
        if reopened:
            _gh(["issue", "reopen", str(num), "-R", repo], token)
        rc = _gh(["issue", "edit", str(num), "-R", repo, "--body", rendered], token).returncode
        if rc != 0:
            print("::error::pipeline-alarm: updating the alert FAILED (retries next failing "
                  "tick); primary failure still visible as the run's red X")
            return False
        # RE-READ verify: did our merge survive, or did a concurrent writer clobber it?
        current, state = _issue_view(num, repo, token)
        if current is None or _row_reflected(current, new_row):
            # (an unreadable verify degrades to trusting our own write — fail-soft; the row
            # re-merges on the next failing tick regardless)
            if state and state.upper() == "CLOSED" and not reopened:
                # close-vs-failure race: a concurrent --resolve closed the issue AFTER our row
                # landed. A live failure row must never hide behind a closed alert — reopen.
                _gh(["issue", "reopen", str(num), "-R", repo], token)
                print(f"::warning::pipeline-alarm: reopened #{num} — a concurrent recovery "
                      "closed it over this still-live failure row")
            print(f"::warning::pipeline-alarm: {'reopened' if reopened else 'refreshed'} "
                  f"the rolling pipeline-failure alert (#{num})")
            return True
        print(f"::warning::pipeline-alarm: concurrent writer clobbered the merge on #{num}; "
              f"retrying against the fresh body (attempt {attempt + 1}/{MAX_WRITE_ATTEMPTS})")
    print("::error::pipeline-alarm: could not converge the ledger merge after "
          f"{MAX_WRITE_ATTEMPTS} attempts of concurrent writes (retries next failing tick); "
          "primary failure still visible as the run's red X")
    return False


def _resolve_ledger(ledger, workflow, before=None):
    """Drop every row whose `workflow` matches `workflow` (a workflow just ran healthy, so its
    prior failures are recovered) AND whose last_seen predates `before` (when given). Returns
    (kept_rows, dropped_count). Recovery is WORKFLOW-scoped because the rolling issue is
    fleet-wide: a healthy `dispatch` tick must not close an alert that a still-failing `worker`
    also owns. The `before` bound is the close-vs-failure race guard: a CONCURRENT failure of the
    same workflow (recorded after this healthy tick started) is NEWER information and must survive
    the prune — --resolve never erases a failure it did not observe recover. Ported from PR #51's
    plan-alert auto-close-on-heal, applied to whichever workflow just recovered."""
    wf = _sanitize(workflow) if workflow else ""
    if not wf:
        return list(ledger), 0
    kept = [r for r in ledger
            if _sanitize(r.get("workflow", "")) != wf
            or (before is not None and str(r.get("last_seen", "")) >= before)]
    return kept, len(ledger) - len(kept)


def _prune_reflected(body, workflow, before):
    """Optimistic-concurrency verify predicate for a recovery write: True iff the CURRENT body
    carries no pre-`before` row for `workflow`. A concurrent stale-merge that resurrected a pruned
    row fails this and triggers a retry; a concurrent NEW failure (last_seen >= before) passes —
    it is newer information the prune deliberately preserves."""
    wf = _sanitize(workflow) if workflow else ""
    return all(_sanitize(r.get("workflow", "")) != wf or str(r.get("last_seen", "")) >= before
               for r in _parse_ledger(body))


def resolve_alarm(workflow, repo, token, maintainer, now=None):
    """Auto-close-on-heal (PR #51's recovery behavior, generalized): on a HEALTHY run of `workflow`,
    prune that workflow's PRE-EXISTING rows from the rolling ledger. If rows remain (other
    workflows still failing, or a CONCURRENT new failure landed) the issue is refreshed; if the
    ledger empties, the rolling issue is COMMENTED + CLOSED (it reopens on the next failure).

    Concurrency: the same read/edit/RE-READ optimistic loop as upsert_alarm — a concurrent writer
    that clobbers the prune triggers a retry against the fresh body, and rows recorded AFTER this
    healthy tick started (last_seen >= `before`) are never pruned, so --resolve cannot close over a
    concurrent new failure. After a close, the body is re-read ONCE more: if a writer slipped a row
    in between the verify and the close, the issue is REOPENED (the writer-side verify carries the
    symmetric guard). A green tick with no open alert is a cheap no-op (one list).
    Fail-soft: every gh rc is checked, never raises, returns a bool for the self-test."""
    if not repo or not token:
        # No target to read/close — nothing to do on a healthy tick (do NOT redden: success path).
        return False
    if not workflow or not _sanitize(workflow):
        return False   # never mass-prune on a missing workflow name
    before = _now(now).strftime("%Y-%m-%dT%H:%M:%SZ")
    for attempt in range(MAX_WRITE_ATTEMPTS):
        if attempt:
            time.sleep(RETRY_SLEEP_S * attempt)
        num, body = _find_rolling_issue(repo, token, "open")
        if num is None:
            # No open alert for this fleet — a healthy tick is a cheap no-op (matches #51's
            # green-tick-is-side-effect-free posture).
            return False
        ledger = _parse_ledger(body)
        kept, dropped = _resolve_ledger(ledger, workflow, before)
        if dropped == 0:
            # This workflow had no open failure rows; leave the alert untouched (another workflow
            # owns it). Never close an issue whose failures we did not just recover.
            return False
        rendered = render_body(_prune(kept), maintainer) if kept else render_body([], maintainer)
        rc = _gh(["issue", "edit", str(num), "-R", repo, "--body", rendered], token).returncode
        if rc != 0:
            print("::error::pipeline-alarm: pruning the recovered rows FAILED (retries next tick)")
            return False
        # RE-READ verify: did the prune survive, or did a concurrent stale merge resurrect rows?
        current, _state = _issue_view(num, repo, token)
        if current is not None and not _prune_reflected(current, workflow, before):
            print(f"::warning::pipeline-alarm: concurrent writer clobbered the recovery prune on "
                  f"#{num}; retrying (attempt {attempt + 1}/{MAX_WRITE_ATTEMPTS})")
            continue
        if kept:
            print(f"::warning::pipeline-alarm: {_sanitize(workflow)} recovered — pruned its rows "
                  f"from the rolling alert (#{num}); other rows remain open")
            return True
        # Ledger emptied: every recorded failure recovered → comment + close (reopens on next
        # failure). The verify above already confirmed no concurrent row survived the prune.
        _gh(["issue", "comment", str(num), "-R", repo, "--body",
             f"✅ Recovered — `{_sanitize(workflow)}` succeeded and no pipeline failures remain in "
             "the ledger. Auto-closing; this issue reopens on the next failure."], token)
        rc = _gh(["issue", "close", str(num), "-R", repo], token).returncode
        if rc != 0:
            print("::error::pipeline-alarm: closing the recovered alert FAILED (retries next tick)")
            return False
        # Close-vs-failure race guard: re-read AFTER the close — a writer that landed a row
        # between our verify and the close must not stay hidden behind a closed alert.
        post, _post_state = _issue_view(num, repo, token)
        if post is not None and _parse_ledger(post):
            _gh(["issue", "reopen", str(num), "-R", repo], token)
            print(f"::warning::pipeline-alarm: reopened #{num} — a failure row landed "
                  "concurrently with the recovery close")
            return True
        print(f"::warning::pipeline-alarm: all pipeline failures recovered — closed the rolling "
              f"alert (#{num})")
        return True
    print("::error::pipeline-alarm: recovery prune could not converge after "
          f"{MAX_WRITE_ATTEMPTS} attempts of concurrent writes (retries next healthy tick)")
    return False


def build_row(now=None):
    """Assemble the failure row from the run context env. All sources are GitHub-provided run
    metadata (workflow/job/run ids) + caller-passed job signals — no secret is read."""
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    run_url = f"{server}/{repo}/actions/runs/{run_id}" if (repo and run_id) else ""
    if run_url and attempt:
        run_url = f"{run_url}/attempts/{attempt}"
    job_result = os.environ.get("ALARM_JOB_RESULT", "")
    cancelled = os.environ.get("ALARM_CANCELLED", "").lower() in ("true", "1", "yes")
    failure_class = classify_failure(job_result, os.environ.get("ALARM_STEP_CONCLUSION"), cancelled)
    return {
        "workflow": os.environ.get("GITHUB_WORKFLOW", "?"),
        "job": os.environ.get("ALARM_JOB_NAME") or os.environ.get("GITHUB_JOB", "?"),
        "failed_step": _sanitize(os.environ.get("ALARM_FAILED_STEP", "")),
        "failure_class": failure_class,
        "detail": _sanitize(os.environ.get("ALARM_DETAIL", "")),
        "run_url": run_url,
        "last_seen": _now(now).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Unified loud-fail pipeline alarm")
    parser.add_argument("--self-test", action="store_true", help="run the self-test suite")
    parser.add_argument("--resolve", action="store_true",
                        help="HEALTHY-tick recovery: prune this workflow's rows from the rolling "
                             "alert and auto-close it once the ledger empties (PR #51's "
                             "auto-close-on-heal, generalized to any recovered workflow)")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")
    if args.resolve:
        # Recovery path: a workflow just ran healthy. This NEVER redddens (it is the success tick)
        # and is fail-soft, so a recovery-write hiccup can't turn a green run red.
        try:
            workflow = os.environ.get("GITHUB_WORKFLOW", "")
            repo, token = _resolve_alert_target()
            resolve_alarm(workflow, repo, token, maintainer)
        except Exception as exc:  # noqa: BLE001 — recovery must never redden a healthy run
            print(f"::warning::pipeline-alarm: recovery step errored ({exc}); the alert (if any) "
                  "will be re-evaluated next healthy tick — the run itself stays green")
        return 0
    try:
        row = build_row()
        repo, token = _resolve_alert_target()
        # Print the classification to the run log unconditionally (visible even if the issue write
        # fails): the annotation itself is a fallback surface.
        print(f"::warning::pipeline-alarm: {row['workflow']}/{row['job']} failed "
              f"(class={row['failure_class']}) — {row['detail']}")
        upsert_alarm(row, repo, token, maintainer)
    except Exception as exc:  # noqa: BLE001 — fail-soft is the whole point
        # The alarm can NEVER mask the primary failure: degrade to a plain annotation, exit 0.
        print(f"::error::pipeline-alarm: alarm itself errored ({exc}); the primary failure is still "
              "the run's red X and is not masked")
    # ALWAYS exit 0 — a nonzero here would REPLACE the real failure's red X with the alarm's own.
    return 0


# ================================================================================================
# self-test (gh stubbed; the LOAD-BEARING invariants are dedupe, classify, credential-safety,
# fail-soft, and never-mask-primary). A mutation that lets the alarm mask the primary failure, or
# leak a credential into the diagnostic, MUST go RED here.
# ================================================================================================
def _self_test():
    import io
    import contextlib
    failures = []

    def chk(name, got, want):
        if got != want:
            failures.append(f"{name}: got {got!r} want {want!r}")

    def ok(name, cond):
        if not cond:
            failures.append(name)

    now = datetime(2026, 7, 18, 12, 0, 0, tzinfo=timezone.utc)

    # --- classify -------------------------------------------------------------------------------
    chk("classify: failure", classify_failure("failure", None, False), "job-failure")
    chk("classify: skipped is the silent PLAN-crash class",
        classify_failure("skipped", None, False), "upstream-skip")
    chk("classify: cancelled", classify_failure("success", None, True), "cancelled-or-timeout")
    chk("classify: explicit cancelled result",
        classify_failure("cancelled", None, False), "cancelled-or-timeout")
    chk("classify: empty/unknown still loud", classify_failure("", None, False), "job-failure")
    chk("classify: success is not a failure class we ever record on the failure path — but if it "
        "reaches here (misuse) it is still surfaced, never dropped",
        classify_failure("success", None, False), "job-failure")

    # --- credential-safety (LOAD-BEARING): no token/handle/transcript may survive _sanitize -----
    leaks = [
        "ghp_" + "a" * 36,
        "github_pat_" + "b" * 40,
        "sk-ant-" + "c" * 40,
        "sk-" + "d" * 40,
        "token: hunter2secretvalue",
        "Authorization: Bearer " + "e" * 50,
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij",
        "A" * 60,  # long base64-ish blob
        "j99379855@example.com",   # worker-account email (PII) — the "never a handle" claim
        "acct04",                  # digit-suffixed worker-account handle
        "acct2css",                # REAL alphanumeric handle shape (policy/repos.toml account_pool)
        "acct4css",                # ditto — digits-only matching let these leak (review finding)
        "ACCT3CSS",                # case-insensitive: an upcased handle must not slip through
    ]
    for i, leak in enumerate(leaks):
        san = _sanitize(f"error near {leak} happened")
        ok(f"sanitize scrubs secret #{i} ({leak[:8]}…)",
           leak not in san and "hunter2secretvalue" not in san)
    # the account-handle / email guarantee the docstring makes must hold for the bare handle too,
    # not only when embedded in a sentence. Assert the IDENTITY local-part/handle is REDACTED (not
    # merely that the `@`/handle char was stripped): the email pattern, not char-stripping, is what
    # must remove the PII — otherwise `jmwright.045 gmail.com` still leaks who ran the job.
    ok("sanitize REDACTS a worker-account email local-part (not just strips @)",
       "jmwright.045" not in _sanitize("worker jmwright.045@gmail.com failed"))
    ok("sanitize REDACTS the email domain user", "j99379855" not in _sanitize("acct j99379855@example.com"))
    ok("sanitize scrubs a bare acctNN handle", "acct02" not in _sanitize("acct02"))
    ok("sanitize scrubs an acctNN handle in a key=value form",
       "acct04" not in _sanitize("account acct04=capped"))
    # REAL registry handle shapes are alphanumeric (acct2css/acct3css/acct4css in
    # policy/repos.toml), not digit-only — the "never a raw account handle" boundary must hold
    # for them bare, in prose, and when over-long (an unbounded run, so no bounded-quantifier
    # \b escape leaks the whole token).
    ok("sanitize scrubs a bare alphanumeric handle", "acct2css" not in _sanitize("acct2css"))
    ok("sanitize scrubs an alphanumeric handle mid-sentence",
       "acct3css" not in _sanitize("worker acct3css hit the cap"))
    ok("sanitize scrubs an over-long acct handle whole",
       "acct" not in _sanitize("acct" + "x" * 64))
    # sanitize also strips table-breaking + markdown-active chars + bounds length
    ok("sanitize strips backtick/pipe", "`" not in _sanitize("a`b|c") and "|" not in _sanitize("a`b|c"))
    ok("sanitize strips markdown link/image/mention chars",
       all(c not in _sanitize("click [here](x) ![img](y) @everyone <b>") for c in "[]!@<>"))
    # a detail can NEVER forge the hidden ledger delimiters (would truncate/wipe the JSON ledger)
    ok("sanitize neutralizes a forged ledger-marker pair",
       LEDGER_MARKER_OPEN not in _sanitize(f"{LEDGER_MARKER_OPEN} evil {LEDGER_MARKER_CLOSE}")
       and "pipeline-alarm:ledger" not in _sanitize(f"{LEDGER_MARKER_OPEN} evil"))
    ok("sanitize bounds length", len(_sanitize("x" * 5000)) <= MAX_DETAIL_LEN)
    chk("sanitize blank -> placeholder", _sanitize(""), "(no diagnostic captured)")
    chk("sanitize None -> placeholder", _sanitize(None), "(no diagnostic captured)")

    # a full row's rendered body must ALSO be leak-free even if the ledger was tampered upstream —
    # and in EVERY free-text field, not only `detail` (locks the render_body/_sanitize_row re-scrub
    # against a mutation that skips the non-detail fields; that mutation previously stayed green).
    tampered = [{
        "workflow": "wf-" + "ghp_" + "w" * 36, "job": "job-" + "ghp_" + "j" * 36,
        "failure_class": "cls-" + "ghp_" + "f" * 36, "count": 1,
        "last_seen": "2026-07-18T11:00:00Z", "run_url": "https://x/1",
        "failed_step": "step-" + "ghp_" + "s" * 36, "detail": "ghp_" + "z" * 36 + " leaked",
    }]
    rendered = render_body(tampered, "jeswr")
    for fld, tok in (("detail", "ghp_" + "z" * 36), ("workflow", "ghp_" + "w" * 36),
                     ("job", "ghp_" + "j" * 36), ("failure_class", "ghp_" + "f" * 36),
                     ("failed_step", "ghp_" + "s" * 36)):
        ok(f"render_body re-sanitizes a tampered ledger {fld} field", tok not in rendered)
    # the hidden JSON ledger block persisted for the next tick must be leak-free in every field too
    persisted = json.dumps(_prune([dict(tampered[0])]))
    for fld, tok in (("workflow", "ghp_" + "w" * 36), ("job", "ghp_" + "j" * 36),
                     ("failed_step", "ghp_" + "s" * 36)):
        ok(f"persisted ledger re-sanitizes {fld}", tok not in persisted)
    # a forged ledger-marker planted in a field must not survive into the rendered body either
    forged = render_body([{
        "workflow": f"w{LEDGER_MARKER_CLOSE}", "job": "j", "failure_class": "job-failure",
        "count": 1, "last_seen": "2026-07-18T11:00:00Z", "run_url": "https://x/1",
        "failed_step": "", "detail": f"{LEDGER_MARKER_OPEN} forged",
    }], "jeswr")
    # exactly ONE real ledger block delimiter pair may exist in the body (our own)
    ok("a forged marker in a field cannot inject a 2nd ledger open delimiter",
       forged.count(LEDGER_MARKER_OPEN) == 1)

    # --- dedupe (LOAD-BEARING): a recurrence bumps the row in place, never a second row ----------
    r1 = {"workflow": "dispatch", "job": "plan", "failure_class": "job-failure",
          "detail": "boom", "run_url": "https://x/1", "last_seen": "2026-07-18T12:00:00Z"}
    ledger = _merge_row([], dict(r1))
    chk("first occurrence -> 1 row", len(ledger), 1)
    chk("first occurrence -> count 1", ledger[0]["count"], 1)
    r2 = dict(r1, last_seen="2026-07-18T12:10:00Z", run_url="https://x/2", detail="boom2")
    ledger = _merge_row(ledger, r2)
    chk("recurrence -> still 1 row (DEDUPED)", len(ledger), 1)
    chk("recurrence -> count bumped", ledger[0]["count"], 2)
    chk("recurrence -> last_seen advanced", ledger[0]["last_seen"], "2026-07-18T12:10:00Z")
    chk("recurrence -> run_url refreshed", ledger[0]["run_url"], "https://x/2")
    ok("recurrence -> first_seen preserved", ledger[0]["first_seen"] == "2026-07-18T12:00:00Z")
    # a DIFFERENT class is a distinct row
    r3 = dict(r1, failure_class="upstream-skip")
    ledger = _merge_row(ledger, r3)
    chk("distinct class -> new row", len(ledger), 2)

    # --- round-trip: parse the ledger back out of a rendered body -------------------------------
    body = render_body(ledger, "jeswr")
    reparsed = _parse_ledger(body)
    chk("ledger round-trips through render/parse", len(reparsed), 2)
    ok("marker present in body", MARKER in body)
    ok("maintainer @-mentioned", "@jeswr" in body)
    # a torn/garbled ledger degrades to [] (append-fresh, never lose the alarm)
    chk("torn ledger -> []", _parse_ledger("no ledger here"), [])
    chk("garbled ledger json -> []",
        _parse_ledger(f"{LEDGER_MARKER_OPEN}\n```json\n{{not json[[[\n```\n{LEDGER_MARKER_CLOSE}"), [])

    # --- prune bounds the body ------------------------------------------------------------------
    big = []
    for i in range(MAX_TABLE_ROWS + 15):
        big = _merge_row(big, {"workflow": "w", "job": f"j{i}", "failure_class": "job-failure",
                               "detail": "d", "run_url": "https://x",
                               "last_seen": f"2026-07-18T{i % 24:02d}:00:00Z"})
    chk("prune bounds row count", len(_prune(big)), MAX_TABLE_ROWS)

    # --- build_row from env ---------------------------------------------------------------------
    saved = dict(os.environ)
    try:
        os.environ.update({
            "GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "jeswr/x",
            "GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_WORKFLOW": "dispatch",
            "GITHUB_JOB": "plan", "ALARM_JOB_RESULT": "skipped",
            "ALARM_FAILED_STEP": "assemble", "ALARM_DETAIL": "ghp_" + "q" * 36,
        })
        row = build_row(now=now)
        chk("build_row workflow", row["workflow"], "dispatch")
        chk("build_row class from skipped", row["failure_class"], "upstream-skip")
        ok("build_row run_url points at the attempt",
           row["run_url"] == "https://github.com/jeswr/x/actions/runs/42/attempts/1")
        ok("build_row detail is sanitized", ("ghp_" + "q" * 36) not in row["detail"])
    finally:
        os.environ.clear()
        os.environ.update(saved)

    # --- fail-soft + never-mask-primary (LOAD-BEARING) ------------------------------------------
    # main() must ALWAYS exit 0, even when the alert target is unresolved or gh explodes — a nonzero
    # would REPLACE the primary failure's red X with the alarm's own.
    saved = dict(os.environ)
    try:
        for k in ("ALERT_REPO", "ALERT_TOKEN", "ALARM_GH_TOKEN", "GH_TOKEN",
                  "REGISTRY_REPO", "GITHUB_REPOSITORY"):
            os.environ.pop(k, None)
        os.environ["GITHUB_WORKFLOW"] = "groom"
        os.environ["ALARM_JOB_RESULT"] = "failure"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main([])
        chk("main exits 0 even with NO alert target (never masks primary)", rc, 0)
        ok("main annotates the missing-target degrade", "::error::" in buf.getvalue())
    finally:
        os.environ.clear()
        os.environ.update(saved)

    # main() must swallow an internal explosion too (fail-soft): stub _gh to raise via a bad repo.
    saved = dict(os.environ)
    try:
        os.environ.update({"REGISTRY_REPO": "jeswr/x", "GH_TOKEN": "tok",
                           "GITHUB_WORKFLOW": "worker", "ALARM_JOB_RESULT": "failure"})
        real_gh = globals()["_gh"]

        def boom(*a, **k):
            raise RuntimeError("simulated gh catastrophe")
        globals()["_gh"] = boom
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main([])
        chk("main exits 0 even when the alarm itself errors", rc, 0)
        ok("internal error degrades to ::error:: (not a raise, not a mask)",
           "::error::" in buf.getvalue())
        globals()["_gh"] = real_gh
    finally:
        globals()["_gh"] = real_gh if "real_gh" in dir() else globals().get("_gh")
        os.environ.clear()
        os.environ.update(saved)

    # --- upsert dedupe against a stubbed gh: recurrence EDITS, does not CREATE a 2nd issue -------
    calls = []
    existing = {"body": ""}

    def fake_gh(args, token, capture=False):
        calls.append(list(args))
        verb = args[1] if len(args) > 1 else ""
        if verb == "list":
            if existing["body"]:
                return subprocess.CompletedProcess(
                    args, 0, json.dumps([{"number": 7, "body": existing["body"]}]), "")
            return subprocess.CompletedProcess(args, 0, "[]", "")
        if verb == "view":
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"body": existing["body"], "state": "OPEN"}), "")
        if verb in ("create", "edit"):
            # capture the written body (the --body value)
            if "--body" in args:
                existing["body"] = args[args.index("--body") + 1]
            if verb == "create":
                return subprocess.CompletedProcess(args, 0, "https://x/issues/7\n", "")
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    real_gh = globals()["_gh"]
    globals()["_gh"] = fake_gh
    try:
        row = {"workflow": "dispatch", "job": "plan", "failure_class": "job-failure",
               "failed_step": "assemble", "detail": "kaboom", "run_url": "https://x/1",
               "last_seen": "2026-07-18T12:00:00Z"}
        upsert_alarm(dict(row), "jeswr/x", "tok", "jeswr")
        creates = sum(1 for c in calls if c[:2] == ["issue", "create"])
        chk("first failure CREATES the rolling issue", creates, 1)
        calls.clear()
        row2 = dict(row, last_seen="2026-07-18T12:10:00Z", run_url="https://x/2")
        upsert_alarm(dict(row2), "jeswr/x", "tok", "jeswr")
        creates2 = sum(1 for c in calls if c[:2] == ["issue", "create"])
        edits2 = sum(1 for c in calls if c[:2] == ["issue", "edit"])
        chk("recurrence does NOT create a 2nd issue (DEDUPE)", creates2, 0)
        ok("recurrence EDITS the rolling issue", edits2 >= 1)
        final = _parse_ledger(existing["body"])
        ok("rolling ledger shows the bumped count", any(r.get("count") == 2 for r in final))
    finally:
        globals()["_gh"] = real_gh

    # --- reopen-on-flap: a CLOSED rolling issue is REOPENED, never duplicated --------------------
    calls = []
    closed_body = render_body([{"workflow": "w", "job": "j", "failure_class": "job-failure",
                                "count": 1, "last_seen": "2026-07-18T10:00:00Z",
                                "run_url": "https://x/1", "detail": "d"}], "jeswr")

    flap_store = {"body": closed_body}

    def fake_gh_closed(args, token, capture=False):
        calls.append(list(args))
        verb = args[1] if len(args) > 1 else ""
        if verb == "list":
            state = args[args.index("--state") + 1] if "--state" in args else ""
            if state == "closed":
                return subprocess.CompletedProcess(
                    args, 0, json.dumps([{"number": 9, "body": flap_store["body"]}]), "")
            return subprocess.CompletedProcess(args, 0, "[]", "")
        if verb == "view":
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"body": flap_store["body"], "state": "OPEN"}), "")
        if verb == "edit" and "--body" in args:
            flap_store["body"] = args[args.index("--body") + 1]
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    globals()["_gh"] = fake_gh_closed
    try:
        upsert_alarm({"workflow": "w", "job": "j", "failure_class": "job-failure",
                      "detail": "again", "run_url": "https://x/2",
                      "last_seen": "2026-07-18T12:00:00Z"}, "jeswr/x", "tok", "jeswr")
        reopens = sum(1 for c in calls if c[:2] == ["issue", "reopen"])
        creates = sum(1 for c in calls if c[:2] == ["issue", "create"])
        ok("flap REOPENS the closed rolling issue", reopens >= 1)
        chk("flap does NOT create a duplicate", creates, 0)
    finally:
        globals()["_gh"] = real_gh

    # --- unreadable target: no repo/token -> loud ::error::, returns False, never raises ---------
    ok("upsert with no repo/token returns False (loud, not silent)",
       upsert_alarm({"workflow": "w", "job": "j", "failure_class": "job-failure",
                     "detail": "d", "run_url": "", "last_seen": "2026-07-18T12:00:00Z"},
                    "", "", "jeswr") is False)

    # --- resolve/heal (LOAD-BEARING: ported PR #51 auto-close-on-heal, generalized) -------------
    # _resolve_ledger prunes ONLY the recovered workflow's rows (recovery is workflow-scoped
    # because the rolling issue is fleet-wide).
    mixed = [
        {"workflow": "dispatch", "job": "plan", "failure_class": "upstream-skip", "count": 3},
        {"workflow": "worker", "job": "run", "failure_class": "job-failure", "count": 1},
    ]
    kept, dropped = _resolve_ledger(mixed, "dispatch")
    chk("resolve prunes ONLY the recovered workflow's rows", dropped, 1)
    ok("resolve leaves other workflows' rows intact",
       len(kept) == 1 and kept[0]["workflow"] == "worker")
    _, dropped_none = _resolve_ledger(mixed, "groom")
    chk("resolve of a workflow with no rows drops nothing (never touches others)", dropped_none, 0)
    _, dropped_blank = _resolve_ledger(mixed, "")
    chk("resolve with no workflow name is a no-op (never mass-prunes)", dropped_blank, 0)
    # the close-vs-failure race bound: a row recorded AFTER the healthy tick started
    # (last_seen >= before) is NEWER information and must survive the prune.
    racing = [
        {"workflow": "dispatch", "job": "plan", "failure_class": "job-failure", "count": 1,
         "last_seen": "2026-07-18T10:00:00Z"},
        {"workflow": "dispatch", "job": "plan", "failure_class": "upstream-skip", "count": 1,
         "last_seen": "2026-07-18T13:00:00Z"},
    ]
    kept_racing, dropped_racing = _resolve_ledger(racing, "dispatch", "2026-07-18T12:00:00Z")
    chk("resolve prunes only rows OLDER than the healthy tick", dropped_racing, 1)
    ok("a concurrent NEW failure row survives the prune",
       len(kept_racing) == 1 and kept_racing[0]["last_seen"] == "2026-07-18T13:00:00Z")

    # resolve_alarm against a stubbed gh: a healthy tick that EMPTIES the ledger COMMENTS + CLOSES;
    # a healthy tick that leaves other rows only EDITS; a green tick with no open alert is a no-op.
    def make_resolve_gh(open_body):
        seen = []
        store = {"body": open_body}

        def fake(args, token, capture=False):
            seen.append(list(args))
            verb = args[1] if len(args) > 1 else ""
            if verb == "list":
                state = args[args.index("--state") + 1] if "--state" in args else ""
                if state == "open" and store["body"] is not None:
                    return subprocess.CompletedProcess(
                        args, 0, json.dumps([{"number": 5, "body": store["body"]}]), "")
                return subprocess.CompletedProcess(args, 0, "[]", "")
            if verb == "view":
                return subprocess.CompletedProcess(
                    args, 0, json.dumps({"body": store["body"] or "", "state": "OPEN"}), "")
            if verb == "edit" and "--body" in args:
                store["body"] = args[args.index("--body") + 1]
                return subprocess.CompletedProcess(args, 0, "", "")
            return subprocess.CompletedProcess(args, 0, "", "")
        return fake, seen

    # (i) sole-owner recovery empties the ledger -> comment + close
    sole = render_body([{"workflow": "dispatch", "job": "plan", "failure_class": "upstream-skip",
                         "count": 2, "last_seen": "2026-07-18T10:00:00Z",
                         "run_url": "https://x/1", "detail": "d"}], "jeswr")
    fake, seen = make_resolve_gh(sole)
    globals()["_gh"] = fake
    try:
        resolve_alarm("dispatch", "jeswr/x", "tok", "jeswr", now=now)
        closes = sum(1 for c in seen if c[:2] == ["issue", "close"])
        comments = sum(1 for c in seen if c[:2] == ["issue", "comment"])
        chk("healthy tick that empties the ledger CLOSES the alert", closes, 1)
        ok("close is preceded by a recovery comment", comments >= 1)
    finally:
        globals()["_gh"] = real_gh

    # (ii) recovery with another workflow still failing -> EDIT (prune), never close
    twowf = render_body([
        {"workflow": "dispatch", "job": "plan", "failure_class": "upstream-skip", "count": 1,
         "last_seen": "2026-07-18T10:00:00Z", "run_url": "https://x/1", "detail": "d"},
        {"workflow": "worker", "job": "run", "failure_class": "job-failure", "count": 1,
         "last_seen": "2026-07-18T10:05:00Z", "run_url": "https://x/2", "detail": "d"},
    ], "jeswr")
    fake, seen = make_resolve_gh(twowf)
    globals()["_gh"] = fake
    try:
        resolve_alarm("dispatch", "jeswr/x", "tok", "jeswr", now=now)
        closes = sum(1 for c in seen if c[:2] == ["issue", "close"])
        edits = sum(1 for c in seen if c[:2] == ["issue", "edit"])
        chk("recovery with a still-failing workflow does NOT close", closes, 0)
        ok("recovery with a still-failing workflow EDITS (prunes its rows)", edits >= 1)
        # and the pruned body must no longer carry the recovered workflow's row
        pruned_body = next((c[c.index("--body") + 1] for c in seen
                            if c[:2] == ["issue", "edit"] and "--body" in c), "")
        remaining = _parse_ledger(pruned_body)
        ok("pruned ledger drops the recovered workflow, keeps the other",
           all(r.get("workflow") != "dispatch" for r in remaining)
           and any(r.get("workflow") == "worker" for r in remaining))
    finally:
        globals()["_gh"] = real_gh

    # (iii) green tick with NO open alert -> cheap no-op (one list, no mutation)
    fake, seen = make_resolve_gh(None)
    globals()["_gh"] = fake
    try:
        resolve_alarm("dispatch", "jeswr/x", "tok", "jeswr", now=now)
        muts = sum(1 for c in seen if c[:2] in (["issue", "close"], ["issue", "edit"],
                                                ["issue", "comment"]))
        chk("green tick with no open alert makes zero mutations", muts, 0)
    finally:
        globals()["_gh"] = real_gh

    # --- OPTIMISTIC CONCURRENCY (review P1): interleaved writers MERGE, never lose a row --------
    # Writer A's row is already in the ledger. Writer B edits, but a concurrent stale-base writer
    # clobbers the body between B's edit and B's RE-READ verify (B's merge vanishes — the classic
    # lost update). B must detect it on the verify, retry against the fresh body, and converge
    # with BOTH rows present. Deleting the re-read/retry loop in upsert_alarm turns this red.
    row_a = {"workflow": "dispatch", "job": "plan", "failure_class": "job-failure",
             "failed_step": "", "detail": "a", "run_url": "https://x/1",
             "last_seen": "2026-07-18T12:00:00Z", "count": 3}
    body_with_a = render_body(_prune([dict(row_a)]), "jeswr")
    inter = {"body": body_with_a, "clobbered": False}

    def interleaved_gh(args, token, capture=False):
        verb = args[1] if len(args) > 1 else ""
        if verb == "list":
            state = args[args.index("--state") + 1] if "--state" in args else ""
            if state == "open":
                return subprocess.CompletedProcess(
                    args, 0, json.dumps([{"number": 3, "body": inter["body"]}]), "")
            return subprocess.CompletedProcess(args, 0, "[]", "")
        if verb == "edit" and "--body" in args:
            inter["body"] = args[args.index("--body") + 1]
            if not inter["clobbered"]:
                # the concurrent stale-base writer lands right after B's first edit, overwriting
                # the body with a merge that never saw B's row (the lost-update interleave)
                inter["body"] = body_with_a
                inter["clobbered"] = True
            return subprocess.CompletedProcess(args, 0, "", "")
        if verb == "view":
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"body": inter["body"], "state": "OPEN"}), "")
        return subprocess.CompletedProcess(args, 0, "", "")

    globals()["_gh"] = interleaved_gh
    try:
        converged = upsert_alarm(
            {"workflow": "worker", "job": "run", "failure_class": "job-failure",
             "failed_step": "", "detail": "b", "run_url": "https://x/2",
             "last_seen": "2026-07-18T12:05:00Z"}, "jeswr/x", "tok", "jeswr")
        final = _parse_ledger(inter["body"])
        ok("interleaved writer converges (returns True)", converged is True)
        ok("the clobber interleave was actually exercised", inter["clobbered"])
        ok("BOTH rows survive the interleave (merge, not overwrite)",
           any(r.get("workflow") == "dispatch" for r in final)
           and any(r.get("workflow") == "worker" for r in final))
        ok("the pre-existing row's count survives the retry merge",
           any(r.get("workflow") == "dispatch" and r.get("count") == 3 for r in final))
    finally:
        globals()["_gh"] = real_gh

    # --- duplicate first-creates CONVERGE on the lowest-numbered issue --------------------------
    # Two racing first alarms both see "no issue" and both create. The loser (higher number) must
    # detect the concurrent canonical on its post-create re-list, close its own duplicate, and
    # fold its row into the canonical — never leave two rolling issues.
    other_body = render_body(_prune([{
        "workflow": "groom", "job": "groom", "failure_class": "job-failure", "count": 1,
        "last_seen": "2026-07-18T12:00:00Z", "run_url": "https://x/9", "detail": "d",
        "failed_step": ""}]), "jeswr")
    dup = {"created": False, "canonical_body": other_body, "closed": [], "edits": 0}

    def dup_create_gh(args, token, capture=False):
        if args and args[0] != "issue":   # the ensure-label call also has args[1] == "create"
            return subprocess.CompletedProcess(args, 0, "", "")
        verb = args[1] if len(args) > 1 else ""
        if verb == "list":
            state = args[args.index("--state") + 1] if "--state" in args else ""
            if state != "open" or not dup["created"]:
                # before our create the racer's issue is not yet visible (the race window)
                return subprocess.CompletedProcess(args, 0, "[]", "")
            # after our create the re-list reveals BOTH: the racer's #4 (canonical) and our #8
            issues = [{"number": 8, "body": MARKER + " ours"},
                      {"number": 4, "body": dup["canonical_body"]}]
            return subprocess.CompletedProcess(args, 0, json.dumps(issues), "")
        if verb == "create":
            dup["created"] = True
            return subprocess.CompletedProcess(args, 0, "https://x/issues/8\n", "")
        if verb == "close":
            dup["closed"].append(args[2])
            return subprocess.CompletedProcess(args, 0, "", "")
        if verb == "edit" and "--body" in args:
            dup["edits"] += 1
            dup["canonical_body"] = args[args.index("--body") + 1]
            return subprocess.CompletedProcess(args, 0, "", "")
        if verb == "view":
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"body": dup["canonical_body"], "state": "OPEN"}), "")
        return subprocess.CompletedProcess(args, 0, "", "")

    globals()["_gh"] = dup_create_gh
    try:
        upsert_alarm({"workflow": "worker", "job": "run", "failure_class": "job-failure",
                      "failed_step": "", "detail": "d", "run_url": "https://x/2",
                      "last_seen": "2026-07-18T12:10:00Z"}, "jeswr/x", "tok", "jeswr")
        chk("the duplicate first-create is CLOSED (converged, not left as a 2nd spammer)",
            dup["closed"], ["8"])
        ok("the loser folds its row into the canonical issue",
           dup["edits"] >= 1
           and any(r.get("workflow") == "worker" for r in _parse_ledger(dup["canonical_body"]))
           and any(r.get("workflow") == "groom" for r in _parse_ledger(dup["canonical_body"])))
    finally:
        globals()["_gh"] = real_gh

    # --- upsert verify reopens if a concurrent --resolve closed over our fresh row --------------
    cvr = {"body": "", "reopened": 0}

    def closed_after_write_gh(args, token, capture=False):
        verb = args[1] if len(args) > 1 else ""
        if verb == "list":
            state = args[args.index("--state") + 1] if "--state" in args else ""
            if state == "open":
                return subprocess.CompletedProcess(
                    args, 0, json.dumps([{"number": 2, "body": render_body([], "jeswr")}]), "")
            return subprocess.CompletedProcess(args, 0, "[]", "")
        if verb == "edit" and "--body" in args:
            cvr["body"] = args[args.index("--body") + 1]
            return subprocess.CompletedProcess(args, 0, "", "")
        if verb == "view":
            # our row landed, but a racing recovery closed the issue right after
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"body": cvr["body"], "state": "CLOSED"}), "")
        if verb == "reopen":
            cvr["reopened"] += 1
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    globals()["_gh"] = closed_after_write_gh
    try:
        upsert_alarm({"workflow": "w", "job": "j", "failure_class": "job-failure",
                      "failed_step": "", "detail": "d", "run_url": "https://x/1",
                      "last_seen": "2026-07-18T12:00:00Z"}, "jeswr/x", "tok", "jeswr")
        chk("a concurrent close over a fresh failure row is REOPENED by the writer",
            cvr["reopened"], 1)
    finally:
        globals()["_gh"] = real_gh

    # --- --resolve never closes over a concurrent new failure -----------------------------------
    # The resolver empties the ledger and closes, but a failure row lands between its verify and
    # the close. The post-close re-read must catch it and REOPEN the issue.
    race = {"body": render_body(_prune([{
        "workflow": "dispatch", "job": "plan", "failure_class": "job-failure", "count": 1,
        "last_seen": "2026-07-18T10:00:00Z", "run_url": "https://x/1", "detail": "d",
        "failed_step": ""}]), "jeswr"), "closed": False, "reopened": 0}
    late_row_body = render_body(_prune([{
        "workflow": "worker", "job": "run", "failure_class": "job-failure", "count": 1,
        "last_seen": "2026-07-18T12:30:00Z", "run_url": "https://x/2", "detail": "d",
        "failed_step": ""}]), "jeswr")

    def close_race_gh(args, token, capture=False):
        verb = args[1] if len(args) > 1 else ""
        if verb == "list":
            state = args[args.index("--state") + 1] if "--state" in args else ""
            if state == "open" and not race["closed"]:
                return subprocess.CompletedProcess(
                    args, 0, json.dumps([{"number": 6, "body": race["body"]}]), "")
            return subprocess.CompletedProcess(args, 0, "[]", "")
        if verb == "edit" and "--body" in args:
            race["body"] = args[args.index("--body") + 1]
            return subprocess.CompletedProcess(args, 0, "", "")
        if verb == "close":
            # the concurrent worker failure lands JUST as the close is issued
            race["closed"] = True
            race["body"] = late_row_body
            return subprocess.CompletedProcess(args, 0, "", "")
        if verb == "reopen":
            race["reopened"] += 1
            return subprocess.CompletedProcess(args, 0, "", "")
        if verb == "view":
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"body": race["body"],
                                     "state": "CLOSED" if race["closed"] else "OPEN"}), "")
        return subprocess.CompletedProcess(args, 0, "", "")

    globals()["_gh"] = close_race_gh
    try:
        resolve_alarm("dispatch", "jeswr/x", "tok", "jeswr", now=now)
        chk("a failure landing at close time REOPENS the alert (never silently closed)",
            race["reopened"], 1)
    finally:
        globals()["_gh"] = real_gh

    # (iv) --resolve mode never reddens: main(['--resolve']) exits 0 even if _gh explodes
    saved = dict(os.environ)
    try:
        os.environ.update({"REGISTRY_REPO": "jeswr/x", "GH_TOKEN": "tok",
                           "GITHUB_WORKFLOW": "dispatch"})

        def boom_resolve(*a, **k):
            raise RuntimeError("simulated gh catastrophe on the healthy tick")
        globals()["_gh"] = boom_resolve
        rc = main(["--resolve"])
        chk("main --resolve exits 0 even if recovery errors (never reddens a green run)", rc, 0)
    finally:
        globals()["_gh"] = real_gh
        os.environ.clear()
        os.environ.update(saved)

    if failures:
        print("pipeline-alarm --self-test FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("pipeline-alarm --self-test: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
