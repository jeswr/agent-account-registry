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
# The alert body table is bounded to MAX_TABLE_ROWS newest classes and each cell is redacted. The
# DURABLE record of each failure is an atomic issue COMMENT (server-serialized append — see the
# concurrency-model note at MAX_WRITE_ATTEMPTS); the issue body is a materialized view of the
# comment log plus the hidden JSON ledger block (rows + fold watermark), so no extra data branch
# is needed, a torn issue-read degrades to "append a fresh row", and a concurrent body clobber
# self-heals from the log rather than losing the alarm.

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
ROW_COMMENT_MARKER = "<!-- pipeline-alarm:row -->"    # keys a durable per-failure row comment
ALERT_TITLE = "⚠️ pipeline failures"
# Comment-fold trust gate: comments are world-writable on a public repo, so only a row comment
# authored by the repo's own actors may be folded into the ledger. Associations are the same
# trusted-association posture dispatch.yml applies to target issues; bot identity is an EXACT
# login allowlist (round-5 P2: `endswith("[bot]")` admitted EVERY GitHub App — any installed app
# could inject a syntactically valid row). The workflow bot is the only built-in automation
# identity; a maintainer routing alerts through a different App token extends the set via the
# comma-separated ALARM_TRUSTED_LOGINS env. An untrusted row comment is IGNORED (never folded).
TRUSTED_COMMENT_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}
TRUSTED_COMMENT_LOGINS = {"github-actions[bot]"}


def _trusted_logins():
    extra = os.environ.get("ALARM_TRUSTED_LOGINS", "")
    return TRUSTED_COMMENT_LOGINS | {t.strip() for t in extra.split(",") if t.strip()}

# --- bounds (WHY): the issue body is the rendered view; keep it small + readable. ----------------
MAX_TABLE_ROWS = 30          # newest N (workflow/job/class) rows shown in the table + kept in ledger
MAX_DETAIL_LEN = 400         # per-row sanitized diagnostic tail cap (chars)
GH_TIMEOUT_S = 45            # per gh call
# CONCURRENCY MODEL (round-3 P1: the body-only optimistic loop could still LOSE a row — A edits and
# verifies, then B overwrites from a stale base and verifies only its own row). GitHub issues offer
# no server-side CAS on the body, so the body can never be the durable store under concurrency.
# The protocol is therefore two-layer:
#   LAYER 1 (durability, server-serialized): every failure row is APPENDED as an issue COMMENT
#   first (`_append_row_comment`). Comment creation is atomic — each writer gets its own
#   monotonically-increasing comment id — so a concurrent writer can NEVER erase another's row.
#   LAYER 2 (visibility): the body is a MATERIALIZED VIEW. Each writer folds every trusted pending
#   row comment newer than the body's `folded_through` watermark into the ledger, merges its own
#   row, and writes body+watermark atomically (one edit). A clobbered body write loses the
#   watermark advance TOGETHER with the folded rows, so the next writer re-folds exactly what the
#   lost write had folded — the view self-heals from the comment log; nothing is ever lost.
# The read/merge/edit/RE-READ retry loop below remains as the fast path that usually converges the
# view within the same tick. Bounded: exhaustion degrades to a loud ::error:: (fail-soft) — but the
# row itself is already durable in the comment log by then.
MAX_WRITE_ATTEMPTS = 4
RETRY_SLEEP_S = 0.5          # small linear backoff between view-convergence retries
MAX_FOLD_COMMENTS = 50       # oldest-first pending-comment fold bound per write (rest fold next tick)
GC_MIN_AGE_S = 3600          # never GC a folded row comment younger than this (job timeouts are
                             # minutes, so no in-flight stale writer's watermark regression can
                             # reach a comment this old)

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


def _valid_ts(value):
    """Structurally valid `%Y-%m-%dT%H:%M:%SZ` UTC stamp — the ONLY format this ledger writes.
    Everything time-ordered here (the recovery prune boundary, last_seen retention, the folded-
    comment GC age gate) compares these lexicographically, so a free-form or future-shaped
    string is an ordering hazard, not just noise (round-5 P2: an injected future last_seen
    would be retained by recovery indefinitely)."""
    if not isinstance(value, str) or not value:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        return True
    except ValueError:
        return False


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
    for marker in (LEDGER_MARKER_OPEN, LEDGER_MARKER_CLOSE, MARKER, ROW_COMMENT_MARKER,
                   "pipeline-alarm:ledger", "pipeline-alarm:row"):
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
def _safe_count(value, default=0):
    """int() that can never raise on hostile ledger data (round-3 P1: a retained `"count":"oops"`
    row reached int() in render_body and wedged EVERY subsequent alarm)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_row(row):
    """Validate + coerce one ledger/comment row of HOSTILE data into the canonical shape, or None
    when the row is unkeyable (no usable workflow/job/failure_class — merging is impossible, so it
    is DROPPED; round-3 P1: a semantically malformed retained row must never wedge the alarm).
    Rebuilds a fresh dict so unknown/hostile extra fields never persist through the ledger."""
    if not isinstance(row, dict):
        return None
    out = {}
    for field in ("workflow", "job", "failure_class"):
        value = row.get(field)
        if not isinstance(value, str) or not value.strip():
            return None
        out[field] = value
    out["count"] = max(1, _safe_count(row.get("count", 1), 1))
    # Timestamps are STRUCTURAL (they order the recovery prune): anything that is not the exact
    # canonical stamp repairs to "" (sorts oldest -> prunable), so a hostile/garbled value can
    # neither wedge an ordering nor pin a row past recovery (round-5 P2).
    last_seen = row.get("last_seen")
    out["last_seen"] = last_seen if _valid_ts(last_seen) else ""
    first_seen = row.get("first_seen")
    if _valid_ts(first_seen):
        out["first_seen"] = first_seen
    detail = row.get("detail")
    out["detail"] = detail if isinstance(detail, str) else None
    failed_step = row.get("failed_step")
    out["failed_step"] = failed_step if isinstance(failed_step, str) else ""
    url = row.get("run_url")
    out["run_url"] = url if isinstance(url, str) else ""
    return out


def _parse_ledger_doc(body):
    """Extract (rows, folded_through) from the hidden JSON ledger block of an issue body.
    `folded_through` is the comment-fold watermark: every durable row comment with id <= it has
    already been merged into `rows` by some successful body write. A torn/garbled/missing ledger
    degrades to ([], 0) — the alarm APPENDS a fresh row (and re-folds the comment log) rather than
    ever losing the signal. Every row is validated/coerced (_coerce_row); malformed rows are
    DROPPED so a hostile/corrupt persisted ledger can never wedge subsequent alarms. The legacy
    bare-list format (pre-watermark) parses as (rows, 0)."""
    if not body:
        return [], 0
    start = body.find(LEDGER_MARKER_OPEN)
    if start < 0:
        return [], 0
    start = body.find("\n", start)
    end = body.find(LEDGER_MARKER_CLOSE, start if start >= 0 else 0)
    if start < 0 or end < 0:
        return [], 0
    blob = body[start:end].strip()
    # blob is a ```json fenced block; strip fences defensively
    blob = blob.strip("`").strip()
    if blob.startswith("json"):
        blob = blob[4:].strip()
    try:
        data = json.loads(blob)
    except (ValueError, TypeError):
        return [], 0
    if isinstance(data, dict):
        raw_rows = data.get("rows")
        folded_through = max(0, _safe_count(data.get("folded_through"), 0))
    else:
        raw_rows, folded_through = data, 0
    if not isinstance(raw_rows, list):
        return [], folded_through
    rows = [coerced for coerced in (_coerce_row(row) for row in raw_rows) if coerced is not None]
    return rows, folded_through


def _parse_ledger(body):
    """Rows-only view of _parse_ledger_doc (the watermark is a body-write concern)."""
    return _parse_ledger_doc(body)[0]


def _merge_row(ledger, new_row):
    """Upsert a (workflow, job, failure_class) row: bump count + last-seen/run-link, keep first-seen.
    Deduplication is on the (workflow, job, failure_class) KEY so a recurring failure UPDATES its row
    instead of spamming — the load-bearing dedupe invariant."""
    key = (new_row["workflow"], new_row["job"], new_row["failure_class"])
    for row in ledger:
        if (row.get("workflow"), row.get("job"), row.get("failure_class")) == key:
            row["count"] = _safe_count(row.get("count", 0), 0) + 1
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
    # count/last_seen are structural, not free-text, but a tampered ledger can carry any type in
    # them — normalize so nothing non-JSON-safe or int()-hostile survives into the persisted block.
    if "count" in out:
        out["count"] = max(1, _safe_count(out.get("count"), 1))
    if not isinstance(out.get("last_seen", ""), str):
        out["last_seen"] = ""
    return out


def _prune(ledger):
    """Keep the newest MAX_TABLE_ROWS rows by last_seen so the body stays bounded + readable, and
    re-sanitize every retained row (defense-in-depth against a tampered/inherited ledger)."""
    ledger.sort(key=lambda r: str(r.get("last_seen", "")), reverse=True)
    return [_sanitize_row(r) for r in ledger[:MAX_TABLE_ROWS]]


def render_body(ledger, maintainer, folded_through=0):
    """Render the rolling failure issue: the marker, a maintainer @-mention, the compact
    class×count×last-seen×run-link table, and the hidden JSON ledger block for the next tick
    (rows + the comment-fold watermark, written ATOMICALLY together in one body — the property the
    self-healing fold protocol rests on). EVERY rendered cell is re-sanitized — the body is the
    only thing a human reads, so nothing unsanitized may reach it even if a prior tick's ledger
    was tampered — and every count read is exception-proof (_safe_count), so a semantically
    malformed retained row can never wedge the render (round-3 P1)."""
    total = sum(_safe_count(r.get("count"), 0) for r in ledger)
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
        cnt = _safe_count(r.get("count"), 0)
        last = _sanitize(r.get("last_seen", "?"))
        url = r.get("run_url", "")
        run_cell = f"[run]({url})" if url.startswith("https://") else "—"
        lines.append(f"| {wf} | {job} | `{cls}` | {cnt} | {last} | {run_cell} |")
    lines.append("")
    lines.append("**Most recent diagnostic tails (credential-safe, host-observable only):**")
    for r in sorted(ledger, key=lambda x: str(x.get("last_seen", "")), reverse=True)[:5]:
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
    # hidden ledger for the next tick: rows + comment-fold watermark, one atomic body write
    lines.append("")
    lines.append(f"{LEDGER_MARKER_OPEN}")
    lines.append("```json")
    lines.append(json.dumps({"rows": _prune(ledger),
                             "folded_through": max(0, _safe_count(folded_through, 0))},
                            separators=(",", ":")))
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


def _find_marked_issues(repo, token, state):
    """EVERY marker-carrying issue in `state` as [(number, body)] ascending — the lowest is the
    canonical; any others are concurrent-first-create duplicates awaiting reconcile (round-5 P1:
    eventual-consistency listings can let TWO first-creates each initially see only themselves,
    so duplicates can outlive the create-time check and must be folded by later writes). Returns
    None on a failed/garbled listing (callers pick their fail direction)."""
    proc = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", state,
                "--json", "number,body", "--limit", "50"], token, capture=True)
    if proc.returncode != 0:
        return None
    try:
        found = json.loads(proc.stdout or "[]")
    except ValueError:
        return None
    return sorted((issue["number"], issue.get("body") or "") for issue in found
                  if isinstance(issue, dict) and isinstance(issue.get("number"), int)
                  and MARKER in (issue.get("body") or ""))


def _find_rolling_issue(repo, token, state):
    """(number, body) of the CANONICAL rolling issue in `state` — the LOWEST-numbered issue
    carrying the marker — or (None, None). Lowest-first is the concurrency tiebreak: every
    racing writer picks the same canonical, and upsert_alarm folds+closes the rest."""
    marked = _find_marked_issues(repo, token, state)
    if not marked:
        return None, None
    return marked[0]


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


def _ledger_reflects(rows, row):
    """True iff `rows` carries `row`'s (workflow, job, class) key at least as fresh as `row`
    itself. `>=` (not `==`) terminates the two-writers-same-key race: whichever recurrence's
    last_seen survives satisfies BOTH writers (the count may undercount by one in that rare
    interleave — the ROW, i.e. the alarm itself, is what must never be lost)."""
    key = (row.get("workflow"), row.get("job"), row.get("failure_class"))
    for existing in rows:
        if (existing.get("workflow"), existing.get("job"), existing.get("failure_class")) == key:
            return str(existing.get("last_seen", "")) >= str(row.get("last_seen", ""))
    return False


def _row_reflected(body, row):
    """The optimistic-concurrency verify predicate for a failure write: if a concurrent writer
    clobbered our merge, our key is absent (or stale) in their body and we retry against it."""
    return _ledger_reflects(_parse_ledger(body), row)


def _merge_ledgers(base, extra_rows):
    """Fold ANOTHER ledger's already-aggregated rows into `base` (duplicate-issue reconcile,
    round-5 P1). Unlike _merge_row (ONE new occurrence -> bump count by 1), same-key counts SUM
    (each ledger counted its own occurrences), the fresher last_seen's detail/run_url win, and
    the earliest first_seen is kept. Every folded row is re-coerced (hostile duplicate bodies
    must never wedge the canonical); junk rows are dropped."""
    for raw in extra_rows or []:
        row = _coerce_row(raw)
        if row is None:
            continue
        key = (row["workflow"], row["job"], row["failure_class"])
        for existing in base:
            if (existing.get("workflow"), existing.get("job"),
                    existing.get("failure_class")) == key:
                existing["count"] = (_safe_count(existing.get("count"), 0)
                                     + _safe_count(row.get("count"), 1))
                if str(row.get("last_seen", "")) >= str(existing.get("last_seen", "")):
                    existing["last_seen"] = row["last_seen"]
                    existing["run_url"] = row["run_url"]
                    existing["detail"] = row["detail"]
                    if row.get("failed_step"):
                        existing["failed_step"] = row["failed_step"]
                firsts = [ts for ts in (existing.get("first_seen"), row.get("first_seen"))
                          if _valid_ts(ts)]
                if firsts:
                    existing["first_seen"] = min(firsts)
                break
        else:
            base.append(dict(row))
    return base


def _create_issue(repo, token, rendered):
    """Create the rolling issue; return its number (parsed from the printed URL) or None."""
    proc = _gh(["issue", "create", "-R", repo, "--title", ALERT_TITLE,
                "--label", ALERT_LABEL, "--body", rendered], token, capture=True)
    if proc.returncode != 0:
        return None
    match = re.search(r"/issues/([0-9]+)\s*$", (proc.stdout or "").strip())
    return int(match.group(1)) if match else 0   # 0 = created but number unknown (best-effort)


# ------------------------------------------------------------------------------------------------
# durable row-comment log (LAYER 1 of the concurrency protocol — see the MAX_WRITE_ATTEMPTS note)
# ------------------------------------------------------------------------------------------------
def _row_comment_body(row):
    """A durable row comment: the hidden marker + the sanitized row as a fenced JSON block. The
    row is _sanitize_row'd by the caller, and _sanitize strips backticks/angle-brackets from every
    free-text field, so a hostile detail can neither close the fence early nor forge a marker."""
    payload = json.dumps(_sanitize_row(row), separators=(",", ":"), sort_keys=True)
    return (f"{ROW_COMMENT_MARKER}\n"
            "⚠️ failure row durably recorded (folds into the table above on the next write).\n"
            f"```json\n{payload}\n```")


def _append_row_comment(num, repo, token, row):
    """ATOMIC durable append of the failure row as an issue comment — the server assigns each
    comment its own monotonically-increasing id, so concurrent writers can never erase each
    other's rows (the round-3 lost-update repro is impossible at this layer). Returns the comment
    id, 0 when created-but-id-unreadable, or None on failure (caller degrades to body-merge-only,
    loudly)."""
    proc = _gh(["api", f"repos/{repo}/issues/{int(num)}/comments",
                "-f", f"body={_row_comment_body(row)}"], token, capture=True)
    if proc.returncode != 0:
        return None
    try:
        doc = json.loads(proc.stdout or "{}")
    except ValueError:
        return 0
    cid = doc.get("id") if isinstance(doc, dict) else None
    return cid if isinstance(cid, int) and not isinstance(cid, bool) and cid > 0 else 0


def _list_row_comments(num, repo, token):
    """[(comment_id, coerced_row, created_at)] of every TRUSTED pending row comment on the rolling
    issue, oldest-first, bounded to MAX_FOLD_COMMENTS (the rest fold next tick — delayed, never
    lost). Untrusted authors are ignored (comment-injection gate: comments are world-writable on a
    public repo; only the workflow bot / collaborators may feed the ledger). Returns None when the
    listing itself failed (callers degrade to a body-only write — fail-soft), [] when readable but
    empty/garbled."""
    proc = _gh(["api", "--paginate", "--slurp",
                f"repos/{repo}/issues/{int(num)}/comments?per_page=100"], token, capture=True)
    if proc.returncode != 0:
        return None
    try:
        pages = json.loads(proc.stdout or "[]")
    except ValueError:
        return []
    if not isinstance(pages, list):
        return []
    comments = []
    for page in pages:                       # --slurp wraps pages: [[...], [...]]
        if isinstance(page, list):
            comments.extend(page)
        elif isinstance(page, dict):         # tolerate an unwrapped single page
            comments.append(page)
    out = []
    for comment in comments:
        if not isinstance(comment, dict):
            continue
        cid = comment.get("id")
        body = comment.get("body")
        if (not isinstance(cid, int) or isinstance(cid, bool) or cid <= 0
                or not isinstance(body, str) or ROW_COMMENT_MARKER not in body):
            continue
        user = comment.get("user") if isinstance(comment.get("user"), dict) else {}
        login = user.get("login") if isinstance(user.get("login"), str) else ""
        association = str(comment.get("author_association") or "").upper()
        # EXACT automation-login allowlist (round-5 P2: `endswith("[bot]")` trusted every
        # installed GitHub App, letting a foreign bot inject rows) — see TRUSTED_COMMENT_LOGINS.
        if not (login in _trusted_logins() or association in TRUSTED_COMMENT_ASSOCIATIONS):
            continue
        match = re.search(r"```json\s*(\{.*?\})\s*```", body, re.DOTALL)
        if not match:
            continue
        try:
            row = _coerce_row(json.loads(match.group(1)))
        except ValueError:
            continue
        if row is None:
            continue
        created_at = str(comment.get("created_at") or "")
        # Structural-timestamp clamp (round-5 P2): a row's last_seen can never postdate its own
        # SERVER-assigned comment creation time. Clamping (not dropping) keeps the row while
        # removing the future-stamp vector that would pin it past every recovery prune.
        if _valid_ts(row.get("last_seen", "")) and _valid_ts(created_at) \
                and row["last_seen"] > created_at:
            row["last_seen"] = created_at
        out.append((cid, row, created_at))
    out.sort(key=lambda entry: entry[0])
    return out[:MAX_FOLD_COMMENTS]


def _fold_pending(rows, pending, own_comment_id, folded_through):
    """Merge every pending row comment newer than the watermark into `rows`; returns
    (rows, new_watermark). The caller merges its OWN row in-memory (fresher detail), so its own
    comment id only advances the watermark. Because the watermark is written atomically WITH the
    folded rows in one body edit, a clobbered write regresses both together and the next fold
    repeats exactly the lost work — idempotent, so a row can neither be lost nor double-counted."""
    watermark = folded_through
    for cid, row, _created in pending or []:
        if cid <= folded_through:
            continue
        if own_comment_id and cid == own_comment_id:
            watermark = max(watermark, cid)
            continue
        rows = _merge_row(rows, dict(row))
        watermark = max(watermark, cid)
    return rows, watermark


def _gc_folded_comments(num, repo, token, pending, folded_through, now=None):
    """Best-effort deletion of row comments a durable body write has ALREADY folded (id <= the
    watermark READ from the body, i.e. covered before this write even started). Age-gated by
    GC_MIN_AGE_S: any concurrent stale writer's watermark regression is bounded by job lifetimes
    (minutes), so it can never reach back to a comment this old — deletion cannot orphan a row.
    Bounded per tick; a failed delete just retries on a later tick."""
    deleted = 0
    now_dt = _now(now)
    for cid, _row, created in pending or []:
        if cid > folded_through or deleted >= 10:
            continue
        try:
            age = (now_dt - datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ")
                   .replace(tzinfo=timezone.utc)).total_seconds()
        except ValueError:
            continue
        if age < GC_MIN_AGE_S:
            continue
        _gh(["api", "-X", "DELETE", f"repos/{repo}/issues/comments/{cid}"], token)
        deleted += 1


def upsert_alarm(new_row, repo, token, maintainer):
    """Idempotent single-rolling-issue upsert under the TWO-LAYER protocol (see the
    MAX_WRITE_ATTEMPTS note): the row is first APPENDED as a durable issue comment (atomic,
    server-serialized — a concurrent writer can never erase it, closing the round-3 lost-update),
    then the body view is converged via read/fold/merge/edit/RE-READ. Racing first-creates
    converge on the lowest-numbered marker issue; because an eventually-consistent listing can
    show EACH racing creator only its own issue (round-5 P1), every subsequent write ALSO
    reconciles: it folds every higher-numbered marked issue's ledger (body rows + durable row
    comments) into the canonical and closes the duplicate only AFTER the folded body write is
    verified. The first-create path appends its durable row comment FROM BIRTH so a duplicate's
    row is always foldable. A CLOSED issue must be SUCCESSFULLY reopened before the row write
    counts (round-3 P1) — the reopen rc is checked, transient failures retry, and the post-write
    verify re-checks the final state is OPEN, reopening (rc-checked) if a racing --resolve
    closed it. Every gh return code is checked; failure degrades LOUD to ::error:: and never
    raises (fail-soft)."""
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
    own_comment_id = None      # durable row comment id once it lands (LAYER 1)...
    own_comment_issue = None   # ...and WHICH issue it landed on (a create-path comment can live
                               # on our own duplicate, whose fold below carries the row instead)
    created_dup = None         # our own first-create that lost the canonical race (fold, THEN close)
    for attempt in range(MAX_WRITE_ATTEMPTS):
        if attempt:
            time.sleep(RETRY_SLEEP_S * attempt)
        open_marked = _find_marked_issues(repo, token, "open") or []
        dups = open_marked[1:]
        was_closed = False
        if open_marked:
            num, body = open_marked[0]
        else:
            num, body = _find_rolling_issue(repo, token, "closed")
            was_closed = num is not None
        if num is None:
            rendered = render_body(_prune(_merge_row([], dict(new_row))), maintainer)
            created = _create_issue(repo, token, rendered)
            if created is None:
                print("::error::pipeline-alarm: raising the alert FAILED (retries next failing "
                      "tick); primary failure still visible as the run's red X")
                return False
            if created:
                # LAYER-1 durability FROM BIRTH (round-5 P1: the first-create path had no durable
                # row comment, so a duplicate first-create's row was unfoldable). The follow-up
                # body edit advances the watermark over our own comment so a later fold cannot
                # double-count the row already rendered in the created body; if that edit fails,
                # the fail direction is a duplicate count bump on a later fold, never a lost row.
                cid = _append_row_comment(created, repo, token, new_row)
                if cid:
                    own_comment_id, own_comment_issue = cid, created
                    _gh(["issue", "edit", str(created), "-R", repo, "--body",
                         render_body(_prune(_merge_row([], dict(new_row))), maintainer,
                                     folded_through=cid)], token)
            # Duplicate-first-create convergence: re-list; if a DIFFERENT (lower-numbered) marker
            # issue exists, ours is the duplicate — but do NOT close it yet (round-5 P1: its row
            # must be folded into the canonical FIRST). Retry: the reconcile pass below folds our
            # duplicate's rows into the canonical and only then closes it. If the re-list shows
            # only ourselves, a racing creator may simply not be VISIBLE yet (eventual
            # consistency) — that pair converges on the next write's reconcile instead.
            canonical, _ = _find_rolling_issue(repo, token, "open")
            if canonical is not None and created and canonical != created:
                created_dup = created
                print(f"::warning::pipeline-alarm: concurrent first-create race — #{created} "
                      f"duplicates canonical #{canonical}; folding and closing it on retry")
                continue
            print("::warning::pipeline-alarm: raised the rolling pipeline-failure alert")
            return True
        if was_closed:
            # The reopen MUST succeed before this attempt counts (round-3 P1: rc was ignored and
            # both rows landed invisibly inside a still-CLOSED issue reported as success). A
            # transient failure retries the loop; exhaustion falls through to the loud failure.
            if _gh(["issue", "reopen", str(num), "-R", repo], token).returncode != 0:
                print(f"::error::pipeline-alarm: reopening closed alert #{num} FAILED "
                      f"(attempt {attempt + 1}/{MAX_WRITE_ATTEMPTS}); the failure row must not "
                      "hide behind a closed issue — retrying")
                continue
        if own_comment_id is None and created_dup is None:
            # LAYER 1: durable, atomic row append. From here the row can no longer be lost to any
            # concurrent body write — the view below merely makes it visible in the table. (When
            # our own duplicate first-create already carries the row — created_dup — the fold
            # below is its durability path; a second comment here would double-count it.)
            own_comment_id = _append_row_comment(num, repo, token, new_row)
            own_comment_issue = num
            if own_comment_id is None:
                print("::warning::pipeline-alarm: durable row-comment append failed; relying on "
                      "the body merge alone this tick")
        rows, folded_before = _parse_ledger_doc(body)
        pending = _list_row_comments(num, repo, token)
        # The watermark may only advance through ids the fold actually SAW: when the listing
        # succeeded it includes our own just-appended comment (folded via the in-memory merge), so
        # the watermark covers it; when the listing FAILED, the watermark must stay put — jumping
        # to our own id would silently claim every lower unfolded id (another writer's pending
        # row) as folded and orphan it. The fail direction of a stuck watermark is a duplicate
        # count bump on a later re-fold, never a lost row.
        rows, watermark = _fold_pending(
            rows, pending, own_comment_id if own_comment_issue == num else None, folded_before)
        # DUPLICATE RECONCILE (round-5 P1): fold EVERY higher-numbered marked issue — body rows
        # PLUS its durable row comments above its own watermark — into the canonical ledger. A
        # duplicate whose comment log is unreadable is folded body-only and left OPEN (fail
        # closed: never close an issue whose durable rows we could not read); it reconciles on a
        # later write. Closing happens only after the folded body write is VERIFIED below.
        folded_dups = []
        own_row_folded = False
        for dup_num, dup_body in dups:
            dup_rows, dup_watermark = _parse_ledger_doc(dup_body)
            rows = _merge_ledgers(rows, dup_rows)
            dup_pending = _list_row_comments(dup_num, repo, token)
            if dup_pending is None:
                print(f"::warning::pipeline-alarm: cannot read duplicate alert #{dup_num}'s "
                      "comment log; folded its body rows only and left it open to reconcile on "
                      "a later write")
                continue
            rows = _merge_ledgers(rows, [row for cid, row, _created in dup_pending
                                         if cid > dup_watermark and cid != own_comment_id])
            folded_dups.append(dup_num)
            if created_dup is not None and dup_num == created_dup:
                own_row_folded = True
        if not (own_row_folded and _ledger_reflects(rows, new_row)):
            # Skip the occurrence merge only when our own duplicate's fold already carried this
            # exact row (same key, same-or-fresher last_seen) — merging again would count one
            # failure twice.
            rows = _merge_row(rows, dict(new_row))
        rendered = render_body(_prune(rows), maintainer, folded_through=watermark)
        rc = _gh(["issue", "edit", str(num), "-R", repo, "--body", rendered], token).returncode
        if rc != 0:
            if own_comment_id is not None or created_dup is not None:
                print(f"::warning::pipeline-alarm: body refresh failed on #{num}, but the failure "
                      "row IS durably recorded on the alert (comment log / duplicate) and folds "
                      "into the table on the next write")
                return True
            print("::error::pipeline-alarm: updating the alert FAILED (retries next failing "
                  "tick); primary failure still visible as the run's red X")
            return False
        # RE-READ verify: did our merge survive, or did a concurrent writer clobber the view?
        current, state = _issue_view(num, repo, token)
        if current is None or _row_reflected(current, new_row):
            # (an unreadable verify degrades to trusting our own write — fail-soft; the row is
            # durable in the comment log regardless)
            if state and state.upper() == "CLOSED":
                # Final state MUST be OPEN (round-3 P1) — whether we reopened above and something
                # re-closed it, or a concurrent --resolve closed over our fresh row. rc-checked:
                # a failed reopen is a FAILURE, never silent success behind a closed alert.
                if _gh(["issue", "reopen", str(num), "-R", repo], token).returncode != 0:
                    print(f"::error::pipeline-alarm: alert #{num} is CLOSED over a live failure "
                          "row and reopening FAILED; retrying next failing tick")
                    return False
                print(f"::warning::pipeline-alarm: reopened #{num} — a concurrent recovery "
                      "closed it over this still-live failure row")
            # GC only comments the PRE-EXISTING body watermark already covered (folded by a prior
            # durable write), never anything folded first by this write.
            _gc_folded_comments(num, repo, token, pending, folded_before)
            # Close the reconciled duplicates ONLY behind a verified fold (current is not None):
            # a failed close leaves the duplicate open for a later reconcile (fail direction: a
            # duplicate count bump on the re-fold, never a lost row).
            if current is not None:
                for dup_num in folded_dups:
                    if _gh(["issue", "close", str(dup_num), "-R", repo, "--comment",
                            f"Duplicate of #{num} (concurrent first-create); its failure rows "
                            "are folded into the canonical rolling alert."],
                           token).returncode != 0:
                        print(f"::warning::pipeline-alarm: closing duplicate alert #{dup_num} "
                              "failed; it stays open and reconciles on a later write")
            print(f"::warning::pipeline-alarm: {'reopened' if was_closed else 'refreshed'} "
                  f"the rolling pipeline-failure alert (#{num})")
            return True
        print(f"::warning::pipeline-alarm: concurrent writer clobbered the view on #{num}; "
              f"retrying against the fresh body (attempt {attempt + 1}/{MAX_WRITE_ATTEMPTS})")
    if own_comment_id is not None or created_dup is not None:
        print(f"::warning::pipeline-alarm: the body view did not converge after "
              f"{MAX_WRITE_ATTEMPTS} attempts, but the failure row IS durably recorded on the "
              "alert (comment log / open duplicate) and folds into the table on the next write")
        return True
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


def resolve_alarm(workflow, repo, token, maintainer, run_started=None):
    """Auto-close-on-heal (PR #51's recovery behavior, generalized): on a HEALTHY run of `workflow`,
    prune that workflow's PRE-EXISTING rows from the rolling ledger. If rows remain (other
    workflows still failing, or a CONCURRENT new failure landed) the issue is refreshed; if the
    ledger empties, the rolling issue is COMMENTED + CLOSED (it reopens on the next failure).

    TEMPORAL BOUNDARY (round-5 P1): `run_started` must be the healthy RUN'S START time (the
    workflow run's run_started_at), never the recover job's own execution time — overlapping
    runs are permitted, so a failure recorded while this healthy run was already executing
    (last_seen >= run start) is NEWER information the healthy evidence does not cover and must
    survive the prune. No trustworthy boundary -> no recovery this tick (fail closed).

    FAIL-CLOSED READS (round-5 P1: resolve_alarm returned True with the issue still closed —
    once during a comment-list outage read as an "empty" log, once when a reopen denial was
    ignored): recovery may only prune/close what it can PROVE recovered. An unreadable comment
    log ABORTS the prune; an unverifiable post-close state forces a reopen; every reopen rc is
    checked and the final state must verify as OPEN, else the resolve reports failure.

    Concurrency: the resolver participates in the same two-layer protocol as upsert_alarm — it
    FOLDS every pending durable row comment into the ledger BEFORE deciding (a row whose writer's
    body view was clobbered must be weighed, never closed over), then runs the read/edit/RE-READ
    view-convergence loop. After a close, the body AND the comment log are re-read once more: if
    a writer slipped a row in between the verify and the close, the issue is REOPENED (the
    writer-side verify carries the symmetric guard). A green tick with no open alert is a cheap
    no-op (one list). Fail-soft at the process level: every gh rc is checked, never raises,
    returns a bool for the self-test."""
    if not repo or not token:
        # No target to read/close — nothing to do on a healthy tick (do NOT redden: success path).
        return False
    if not workflow or not _sanitize(workflow):
        return False   # never mass-prune on a missing workflow name
    if not _valid_ts(run_started):
        print("::warning::pipeline-alarm: no trustworthy run-start boundary for recovery; "
              "recovery SKIPPED this tick (fail closed — pruning against the recover job's own, "
              "LATER, execution time could erase a failure recorded while this run executed)")
        return False
    before = run_started
    for attempt in range(MAX_WRITE_ATTEMPTS):
        if attempt:
            time.sleep(RETRY_SLEEP_S * attempt)
        num, body = _find_rolling_issue(repo, token, "open")
        if num is None:
            # No open alert for this fleet — a healthy tick is a cheap no-op (matches #51's
            # green-tick-is-side-effect-free posture).
            return False
        ledger, folded_before = _parse_ledger_doc(body)
        # Fold every pending durable row comment BEFORE deciding: a failure row that only exists
        # in the comment log (its writer's body view was clobbered or never converged) must be
        # weighed by the recovery decision, never closed over.
        pending = _list_row_comments(num, repo, token)
        if pending is None:
            # FAIL CLOSED (round-5 P1 repro: a comment-list outage was read as an EMPTY log and
            # recovery closed over a durable, unfolded failure row). Unreadable state is never
            # provably-recovered state; the alert stays as-is until a readable healthy tick.
            print("::error::pipeline-alarm: cannot read the alert's durable comment log; "
                  "recovery ABORTED (fail closed — retries next healthy tick)")
            return False
        ledger, watermark = _fold_pending(ledger, pending, None, folded_before)
        kept, dropped = _resolve_ledger(ledger, workflow, before)
        if dropped == 0:
            # This workflow had no open failure rows; leave the alert untouched (another workflow
            # owns it). Never close an issue whose failures we did not just recover.
            return False
        rendered = render_body(_prune(kept), maintainer, folded_through=watermark) if kept \
            else render_body([], maintainer, folded_through=watermark)
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
        # Close-vs-failure race guard + FAIL-CLOSED post-close verification (round-5 P1): a
        # writer that landed a row (in the body OR as a durable row comment newer than our fold
        # watermark) between our verify and the close must not stay hidden behind a closed
        # alert — and an UNREADABLE post-close state must be treated the same way, because "we
        # could not check" is not "no row landed".
        post, _post_state = _issue_view(num, repo, token)
        post_pending = _list_row_comments(num, repo, token)
        unverifiable = post is None or post_pending is None
        late_row = ((post is not None and bool(_parse_ledger(post)))
                    or any(cid > watermark for cid, _row, _created in post_pending or []))
        if unverifiable or late_row:
            why = ("a failure row landed concurrently with the recovery close" if late_row
                   else "the post-close state is unreadable (fail closed)")
            if _gh(["issue", "reopen", str(num), "-R", repo], token).returncode != 0:
                # The round-5 repro: this rc used to be ignored and the resolve reported success
                # with the issue still closed over a live failure.
                print(f"::error::pipeline-alarm: alert #{num} may be closed over a live failure "
                      f"({why}) and reopening FAILED; recovery reports failure — retries next "
                      "tick")
                return False
            _final_body, final_state = _issue_view(num, repo, token)
            if str(final_state or "").upper() != "OPEN":
                print(f"::error::pipeline-alarm: reopen of alert #{num} did not verify as OPEN "
                      f"({why}); recovery reports failure — retries next tick")
                return False
            print(f"::warning::pipeline-alarm: reopened #{num} — {why}")
            return True
        print(f"::warning::pipeline-alarm: all pipeline failures recovered — closed the rolling "
              f"alert (#{num})")
        return True
    print("::error::pipeline-alarm: recovery prune could not converge after "
          f"{MAX_WRITE_ATTEMPTS} attempts of concurrent writes (retries next healthy tick)")
    return False


def _run_start_boundary():
    """The current run's START time for --resolve, as a validated `%Y-%m-%dT%H:%M:%SZ` stamp.
    Preference order: ALARM_RUN_STARTED_AT (explicit caller-passed stamp), then the runs API
    (`repos/{repo}/actions/runs/{run_id}` .run_started_at — per-attempt on re-runs, which is
    exactly the window the healthy evidence covers; needs actions:read on the calling job).
    Returns None when no trustworthy stamp is available — the caller then SKIPS recovery (fail
    closed) rather than pruning against the recover job's own, later, execution time (round-5
    P1: that boundary let an overlapping run's failure be pruned as recovered). The query uses
    the RUN repo + ambient token, never the ALERT_REPO routing (the run does not live there)."""
    explicit = os.environ.get("ALARM_RUN_STARTED_AT", "").strip()
    if _valid_ts(explicit):
        return explicit
    run_repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    token = os.environ.get("ALARM_GH_TOKEN") or os.environ.get("GH_TOKEN") or ""
    if not run_repo or not re.fullmatch(r"[0-9]+", run_id or ""):
        return None
    proc = _gh(["api", f"repos/{run_repo}/actions/runs/{run_id}",
                "--jq", ".run_started_at"], token, capture=True)
    ts = (proc.stdout or "").strip()
    return ts if proc.returncode == 0 and _valid_ts(ts) else None


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
    class_override = os.environ.get("ALARM_FAILURE_CLASS", "").strip()
    if class_override:
        # Explicit caller-declared class (round-5 P1: dispatch raises a NON-TERMINAL
        # `repo-degraded` row for a green-but-partial PLAN — a class the job-result signals
        # cannot express). Sanitized like every other field.
        failure_class = _sanitize(class_override)
    else:
        failure_class = classify_failure(job_result, os.environ.get("ALARM_STEP_CONCLUSION"),
                                         cancelled)
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
            # The recovery boundary is this run's START (round-5 P1) — resolve_alarm skips
            # (fail closed) when no trustworthy stamp is derivable.
            resolve_alarm(workflow, repo, token, maintainer,
                          run_started=_run_start_boundary())
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
        # explicit class override (the dispatch degraded-target non-terminal alarm channel)
        os.environ["ALARM_FAILURE_CLASS"] = "repo-degraded"
        chk("build_row honors an explicit ALARM_FAILURE_CLASS override",
            build_row(now=now)["failure_class"], "repo-degraded")
        os.environ["ALARM_FAILURE_CLASS"] = "evil`|[x]@class"
        ok("the class override is sanitized like every field",
           all(ch not in build_row(now=now)["failure_class"] for ch in "`|[]@"))
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
        resolve_alarm("dispatch", "jeswr/x", "tok", "jeswr", run_started="2026-07-18T11:30:00Z")
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
        resolve_alarm("dispatch", "jeswr/x", "tok", "jeswr", run_started="2026-07-18T11:30:00Z")
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
        resolve_alarm("dispatch", "jeswr/x", "tok", "jeswr", run_started="2026-07-18T11:30:00Z")
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

    # --- EVENTUAL-CONSISTENCY first-create dedup (round-5 P1): two racing creators each --------
    # initially list ONLY THEIR OWN new issue, so BOTH persist and both report success — the
    # create-time canonical check cannot see the racer. A SUBSEQUENT write must reconcile: fold
    # the higher-numbered duplicate's rows (durably recorded from birth) into the canonical and
    # close the duplicate — without double-counting any occurrence.
    ec = {"issues": {}, "next_issue": 4, "next_cid": 501, "hidden": set()}

    def ec_gh(args, token, capture=False):
        if args and args[0] == "api":
            if "--slurp" in args:
                match = re.search(r"/issues/([0-9]+)/comments", args[-1])
                n = int(match.group(1))
                return subprocess.CompletedProcess(
                    args, 0, json.dumps([ec["issues"][n]["comments"]]), "")
            match = re.search(r"/issues/([0-9]+)/comments$", args[1]) if len(args) > 1 else None
            if match and "-f" in args:
                n = int(match.group(1))
                cid = ec["next_cid"]
                ec["next_cid"] += 1
                ec["issues"][n]["comments"].append({
                    "id": cid, "body": args[args.index("-f") + 1][len("body="):],
                    "user": {"login": "github-actions[bot]"}, "author_association": "NONE",
                    "created_at": "2026-07-18T12:30:00Z"})
                return subprocess.CompletedProcess(args, 0, json.dumps({"id": cid}), "")
            return subprocess.CompletedProcess(args, 0, "", "")
        if args and args[0] != "issue":    # e.g. the ensure-label call (also verb "create")
            return subprocess.CompletedProcess(args, 0, "", "")
        verb = args[1] if len(args) > 1 else ""
        if verb == "list":
            state = args[args.index("--state") + 1] if "--state" in args else ""
            want = "OPEN" if state == "open" else "CLOSED"
            listed = [{"number": n, "body": ec["issues"][n]["body"]}
                      for n in sorted(ec["issues"])
                      if n not in ec["hidden"] and ec["issues"][n]["state"] == want]
            return subprocess.CompletedProcess(args, 0, json.dumps(listed), "")
        if verb == "create":
            n = ec["next_issue"]
            ec["next_issue"] += 4          # creator A gets #4, creator B gets #8
            ec["issues"][n] = {"body": args[args.index("--body") + 1], "state": "OPEN",
                               "comments": []}
            return subprocess.CompletedProcess(args, 0, f"https://x/issues/{n}\n", "")
        if verb == "edit" and "--body" in args:
            ec["issues"][int(args[2])]["body"] = args[args.index("--body") + 1]
            return subprocess.CompletedProcess(args, 0, "", "")
        if verb == "close":
            ec["issues"][int(args[2])]["state"] = "CLOSED"
            return subprocess.CompletedProcess(args, 0, "", "")
        if verb == "view":
            n = int(args[2])
            return subprocess.CompletedProcess(args, 0, json.dumps(
                {"body": ec["issues"][n]["body"], "state": ec["issues"][n]["state"]}), "")
        return subprocess.CompletedProcess(args, 0, "", "")

    globals()["_gh"] = ec_gh
    try:
        row_a5 = {"workflow": "dispatch", "job": "plan", "failure_class": "job-failure",
                  "failed_step": "", "detail": "a", "run_url": "https://x/1",
                  "last_seen": "2026-07-18T12:00:00Z"}
        row_b5 = {"workflow": "worker", "job": "run", "failure_class": "job-failure",
                  "failed_step": "", "detail": "b", "run_url": "https://x/2",
                  "last_seen": "2026-07-18T12:05:00Z"}
        row_w5 = {"workflow": "groom", "job": "groom", "failure_class": "job-failure",
                  "failed_step": "", "detail": "w", "run_url": "https://x/3",
                  "last_seen": "2026-07-18T12:10:00Z"}
        ok("creator A converges on its own issue",
           upsert_alarm(dict(row_a5), "jeswr/x", "tok", "jeswr") is True)
        chk("A created the canonical-to-be #4", sorted(ec["issues"]), [4])
        ec["hidden"] = {4}                 # B's reads race ahead of A's listing visibility
        ok("creator B — blind to A's issue — also converges (the reproduced ordering)",
           upsert_alarm(dict(row_b5), "jeswr/x", "tok", "jeswr") is True)
        ec["hidden"] = set()
        chk("the race leaves TWO open marked issues (the repro precondition)",
            sorted(n for n in ec["issues"] if ec["issues"][n]["state"] == "OPEN"), [4, 8])
        ok("a subsequent write reconciles the pair",
           upsert_alarm(dict(row_w5), "jeswr/x", "tok", "jeswr") is True)
        chk("the duplicate #8 is CLOSED after its rows are folded",
            ec["issues"][8]["state"], "CLOSED")
        chk("the canonical #4 stays OPEN", ec["issues"][4]["state"], "OPEN")
        final5 = _parse_ledger(ec["issues"][4]["body"])
        ok("A's, B's (duplicate-born), and W's rows ALL converge in the canonical ledger",
           {r.get("workflow") for r in final5} >= {"dispatch", "worker", "groom"})
        ok("no occurrence is double-counted by the reconcile",
           all(r.get("count") == 1 for r in final5))
    finally:
        globals()["_gh"] = real_gh

    # A duplicate whose durable COMMENT LOG is unreadable is folded body-only and left OPEN
    # (fail closed: never close an issue whose durable rows could not be read).
    fd = {"closes": [],
          "body4": render_body(_prune([{
              "workflow": "groom", "job": "groom", "failure_class": "job-failure", "count": 1,
              "last_seen": "2026-07-18T11:00:00Z", "run_url": "https://x/1", "detail": "d",
              "failed_step": ""}]), "jeswr"),
          "body8": render_body(_prune([{
              "workflow": "worker", "job": "run", "failure_class": "job-failure", "count": 1,
              "last_seen": "2026-07-18T11:05:00Z", "run_url": "https://x/2", "detail": "d",
              "failed_step": ""}]), "jeswr")}

    def fd_gh(args, token, capture=False):
        if args and args[0] == "api":
            if "--slurp" in args:
                if "/issues/8/" in args[-1]:
                    return subprocess.CompletedProcess(args, 1, "", "dup log unreadable")
                return subprocess.CompletedProcess(args, 0, "[]", "")
            return subprocess.CompletedProcess(args, 0, "", "")
        verb = args[1] if len(args) > 1 else ""
        if verb == "list":
            state = args[args.index("--state") + 1] if "--state" in args else ""
            if state == "open":
                return subprocess.CompletedProcess(args, 0, json.dumps(
                    [{"number": 4, "body": fd["body4"]},
                     {"number": 8, "body": fd["body8"]}]), "")
            return subprocess.CompletedProcess(args, 0, "[]", "")
        if verb == "edit" and "--body" in args:
            fd["body4"] = args[args.index("--body") + 1]
            return subprocess.CompletedProcess(args, 0, "", "")
        if verb == "close":
            fd["closes"].append(args[2])
            return subprocess.CompletedProcess(args, 0, "", "")
        if verb == "view":
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"body": fd["body4"], "state": "OPEN"}), "")
        return subprocess.CompletedProcess(args, 0, "", "")

    globals()["_gh"] = fd_gh
    try:
        ok("a write against an unreadable-log duplicate still succeeds",
           upsert_alarm({"workflow": "dispatch", "job": "plan",
                         "failure_class": "job-failure", "failed_step": "", "detail": "d",
                         "run_url": "https://x/9", "last_seen": "2026-07-18T12:00:00Z"},
                        "jeswr/x", "tok", "jeswr") is True)
        ok("the unreadable duplicate's BODY rows are still folded into the canonical",
           any(r.get("workflow") == "worker" for r in _parse_ledger(fd["body4"])))
        chk("the unreadable duplicate is NOT closed (fail closed — reconciles later)",
            fd["closes"], [])
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
    # the close. The post-close re-read must catch it, REOPEN the issue (rc-checked), and verify
    # the final state is OPEN.
    def make_close_race_gh(reopen_rc):
        st = {"body": render_body(_prune([{
            "workflow": "dispatch", "job": "plan", "failure_class": "job-failure", "count": 1,
            "last_seen": "2026-07-18T10:00:00Z", "run_url": "https://x/1", "detail": "d",
            "failed_step": ""}]), "jeswr"), "closed": False, "reopened": 0}
        late_row_body = render_body(_prune([{
            "workflow": "worker", "job": "run", "failure_class": "job-failure", "count": 1,
            "last_seen": "2026-07-18T12:30:00Z", "run_url": "https://x/2", "detail": "d",
            "failed_step": ""}]), "jeswr")

        def fake(args, token, capture=False):
            if args and args[0] == "api":
                return subprocess.CompletedProcess(args, 0, "", "")
            verb = args[1] if len(args) > 1 else ""
            if verb == "list":
                state = args[args.index("--state") + 1] if "--state" in args else ""
                if state == "open" and not st["closed"]:
                    return subprocess.CompletedProcess(
                        args, 0, json.dumps([{"number": 6, "body": st["body"]}]), "")
                return subprocess.CompletedProcess(args, 0, "[]", "")
            if verb == "edit" and "--body" in args:
                st["body"] = args[args.index("--body") + 1]
                return subprocess.CompletedProcess(args, 0, "", "")
            if verb == "close":
                # the concurrent worker failure lands JUST as the close is issued
                st["closed"] = True
                st["body"] = late_row_body
                return subprocess.CompletedProcess(args, 0, "", "")
            if verb == "reopen":
                st["reopened"] += 1
                if reopen_rc == 0:
                    st["closed"] = False
                return subprocess.CompletedProcess(args, reopen_rc, "", "")
            if verb == "view":
                return subprocess.CompletedProcess(
                    args, 0, json.dumps({"body": st["body"],
                                         "state": "CLOSED" if st["closed"] else "OPEN"}), "")
            return subprocess.CompletedProcess(args, 0, "", "")
        return fake, st

    fake, race = make_close_race_gh(reopen_rc=0)
    globals()["_gh"] = fake
    try:
        ok("a failure landing at close time REOPENS the alert (never silently closed)",
           resolve_alarm("dispatch", "jeswr/x", "tok", "jeswr",
                         run_started="2026-07-18T12:00:00Z") is True and race["reopened"] == 1)
        ok("the reopened alert's final state verifies OPEN", race["closed"] is False)
    finally:
        globals()["_gh"] = real_gh
    # (round-5 P1 repro #2): the same race but the reopen is DENIED — resolve must report
    # FAILURE, never success with the issue still closed over a live failure row.
    fake, race = make_close_race_gh(reopen_rc=1)
    globals()["_gh"] = fake
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            denied = resolve_alarm("dispatch", "jeswr/x", "tok", "jeswr",
                                   run_started="2026-07-18T12:00:00Z")
        ok("a DENIED reopen after a racing close is a resolve FAILURE (rc checked)",
           denied is False and race["reopened"] >= 1)
        ok("the denied reopen is LOUD (::error::)", "::error::" in buf.getvalue())
    finally:
        globals()["_gh"] = real_gh

    # --- FAIL-CLOSED recovery reads (round-5 P1 repro #1): a comment-list OUTAGE during -------
    # recovery must ABORT the prune — an unreadable log is NOT an empty log (resolve used to
    # treat None as [] and closed over a durable, unfolded failure row).
    fc_body = render_body(_prune([{
        "workflow": "dispatch", "job": "plan", "failure_class": "job-failure", "count": 1,
        "last_seen": "2026-07-18T10:00:00Z", "run_url": "https://x/1", "detail": "d",
        "failed_step": ""}]), "jeswr")
    fc = {"muts": 0}

    def outage_gh(args, token, capture=False):
        if args and args[0] == "api":
            if "--slurp" in args:
                return subprocess.CompletedProcess(args, 1, "", "comment-list outage")
            return subprocess.CompletedProcess(args, 0, "", "")
        verb = args[1] if len(args) > 1 else ""
        if verb == "list":
            state = args[args.index("--state") + 1] if "--state" in args else ""
            if state == "open":
                return subprocess.CompletedProcess(
                    args, 0, json.dumps([{"number": 71, "body": fc_body}]), "")
            return subprocess.CompletedProcess(args, 0, "[]", "")
        if verb in ("edit", "close", "reopen", "comment"):
            fc["muts"] += 1
        return subprocess.CompletedProcess(args, 0, "", "")

    globals()["_gh"] = outage_gh
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            aborted = resolve_alarm("dispatch", "jeswr/x", "tok", "jeswr",
                                    run_started="2026-07-18T12:00:00Z")
        ok("a comment-log outage ABORTS recovery (fail closed, returns False)",
           aborted is False)
        chk("the aborted recovery performs ZERO mutations", fc["muts"], 0)
        ok("the aborted recovery is LOUD (::error::)", "::error::" in buf.getvalue())
    finally:
        globals()["_gh"] = real_gh

    # An UNVERIFIABLE post-close state (both re-reads fail) is treated like a live row: the
    # resolve must attempt the reopen and — with the final state unverifiable too — report
    # FAILURE, never "closed and recovered".
    uv = {"closed": False, "reopens": 0,
          "body": render_body(_prune([{
              "workflow": "dispatch", "job": "plan", "failure_class": "job-failure",
              "count": 1, "last_seen": "2026-07-18T10:00:00Z", "run_url": "https://x/1",
              "detail": "d", "failed_step": ""}]), "jeswr")}

    def unverifiable_gh(args, token, capture=False):
        if args and args[0] == "api":
            if "--slurp" in args:
                if uv["closed"]:
                    return subprocess.CompletedProcess(args, 1, "", "post-close outage")
                return subprocess.CompletedProcess(args, 0, "[]", "")
            return subprocess.CompletedProcess(args, 0, "", "")
        verb = args[1] if len(args) > 1 else ""
        if verb == "list":
            state = args[args.index("--state") + 1] if "--state" in args else ""
            if state == "open" and not uv["closed"]:
                return subprocess.CompletedProcess(
                    args, 0, json.dumps([{"number": 81, "body": uv["body"]}]), "")
            return subprocess.CompletedProcess(args, 0, "[]", "")
        if verb == "edit" and "--body" in args:
            uv["body"] = args[args.index("--body") + 1]
            return subprocess.CompletedProcess(args, 0, "", "")
        if verb == "close":
            uv["closed"] = True
            return subprocess.CompletedProcess(args, 0, "", "")
        if verb == "reopen":
            uv["reopens"] += 1
            return subprocess.CompletedProcess(args, 0, "", "")
        if verb == "view":
            if uv["closed"]:
                return subprocess.CompletedProcess(args, 1, "", "post-close outage")
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"body": uv["body"], "state": "OPEN"}), "")
        return subprocess.CompletedProcess(args, 0, "", "")

    globals()["_gh"] = unverifiable_gh
    try:
        ok("an unverifiable post-close state forces a reopen attempt and FAILS the resolve",
           resolve_alarm("dispatch", "jeswr/x", "tok", "jeswr",
                         run_started="2026-07-18T12:00:00Z") is False and uv["reopens"] >= 1)
    finally:
        globals()["_gh"] = real_gh

    # --- RUN-START recovery boundary (round-5 P1): resolve REFUSES to run without one ----------
    def _no_gh_allowed(*_a, **_k):
        raise AssertionError("resolve must not touch gh before validating its boundary")

    globals()["_gh"] = _no_gh_allowed
    try:
        ok("resolve without a run-start boundary is REFUSED before any gh call (fail closed)",
           resolve_alarm("dispatch", "jeswr/x", "tok", "jeswr", run_started=None) is False)
        ok("resolve with a garbage boundary is REFUSED",
           resolve_alarm("dispatch", "jeswr/x", "tok", "jeswr",
                         run_started="not-a-time") is False)
    finally:
        globals()["_gh"] = real_gh

    # OVERLAPPING RUNS end-to-end through main(['--resolve']): the boundary is the healthy RUN'S
    # start (fetched from the runs API), not the recover job's execution time. A failure recorded
    # AFTER the healthy run began (12:01) but BEFORE its recover job executed must SURVIVE the
    # prune; only the pre-run-start row (10:00) is recovered. Reverting `before` to "now at
    # recover time" turns this red.
    overlap_body = render_body(_prune([
        {"workflow": "dispatch", "job": "plan", "failure_class": "job-failure", "count": 1,
         "last_seen": "2026-07-18T10:00:00Z", "run_url": "https://x/1", "detail": "d",
         "failed_step": ""},
        {"workflow": "dispatch", "job": "claim", "failure_class": "job-failure", "count": 1,
         "last_seen": "2026-07-18T12:01:00Z", "run_url": "https://x/2", "detail": "d",
         "failed_step": ""},
    ]), "jeswr")
    ov = {"body": overlap_body, "closes": 0}

    def overlap_gh(args, token, capture=False):
        if args and args[0] == "api":
            if len(args) > 1 and args[1].endswith("/actions/runs/4242"):
                return subprocess.CompletedProcess(args, 0, "2026-07-18T12:00:00Z\n", "")
            if "--slurp" in args:
                return subprocess.CompletedProcess(args, 0, "[]", "")
            return subprocess.CompletedProcess(args, 0, "", "")
        verb = args[1] if len(args) > 1 else ""
        if verb == "list":
            state = args[args.index("--state") + 1] if "--state" in args else ""
            if state == "open":
                return subprocess.CompletedProcess(
                    args, 0, json.dumps([{"number": 61, "body": ov["body"]}]), "")
            return subprocess.CompletedProcess(args, 0, "[]", "")
        if verb == "edit" and "--body" in args:
            ov["body"] = args[args.index("--body") + 1]
            return subprocess.CompletedProcess(args, 0, "", "")
        if verb == "close":
            ov["closes"] += 1
            return subprocess.CompletedProcess(args, 0, "", "")
        if verb == "view":
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"body": ov["body"], "state": "OPEN"}), "")
        return subprocess.CompletedProcess(args, 0, "", "")

    saved = dict(os.environ)
    globals()["_gh"] = overlap_gh
    try:
        for k in ("ALERT_REPO", "ALERT_TOKEN", "ALARM_RUN_STARTED_AT"):
            os.environ.pop(k, None)
        os.environ.update({"REGISTRY_REPO": "jeswr/x", "GH_TOKEN": "tok",
                           "GITHUB_REPOSITORY": "jeswr/x", "GITHUB_RUN_ID": "4242",
                           "GITHUB_WORKFLOW": "dispatch"})
        chk("main --resolve exits 0 on the overlapping-run prune", main(["--resolve"]), 0)
        remaining = _parse_ledger(ov["body"])
        ok("a failure recorded AFTER the healthy run started SURVIVES the prune "
           "(run-start boundary, not recover-job time)",
           any(r.get("last_seen") == "2026-07-18T12:01:00Z" for r in remaining))
        ok("the pre-run-start row IS recovered",
           all(r.get("last_seen") != "2026-07-18T10:00:00Z" for r in remaining))
        chk("the overlap prune never closes the alert (a live row remains)", ov["closes"], 0)
    finally:
        globals()["_gh"] = real_gh
        os.environ.clear()
        os.environ.update(saved)

    # ...and when NO boundary is derivable (runs API denied, no ALARM_RUN_STARTED_AT), the whole
    # recovery is a fail-closed no-op: exit 0 (never reddens), ZERO mutations.
    nb = {"muts": 0}

    def no_boundary_gh(args, token, capture=False):
        if args and args[0] == "api":
            return subprocess.CompletedProcess(args, 1, "", "403 actions:read missing")
        if args and args[0] == "issue" and len(args) > 1 \
                and args[1] in ("edit", "close", "reopen", "comment"):
            nb["muts"] += 1
        return subprocess.CompletedProcess(args, 0, "[]", "")

    saved = dict(os.environ)
    globals()["_gh"] = no_boundary_gh
    try:
        for k in ("ALERT_REPO", "ALERT_TOKEN", "ALARM_RUN_STARTED_AT"):
            os.environ.pop(k, None)
        os.environ.update({"REGISTRY_REPO": "jeswr/x", "GH_TOKEN": "tok",
                           "GITHUB_REPOSITORY": "jeswr/x", "GITHUB_RUN_ID": "4242",
                           "GITHUB_WORKFLOW": "dispatch"})
        chk("main --resolve without a derivable boundary exits 0 (never reddens)",
            main(["--resolve"]), 0)
        chk("...and performs ZERO mutations (fail closed)", nb["muts"], 0)
    finally:
        globals()["_gh"] = real_gh
        os.environ.clear()
        os.environ.update(saved)

    # ALARM_RUN_STARTED_AT (explicit caller-passed stamp) takes precedence over the API query.
    saved = dict(os.environ)
    try:
        os.environ["ALARM_RUN_STARTED_AT"] = "2026-07-18T11:59:00Z"
        globals()["_gh"] = _no_gh_allowed   # the explicit stamp must satisfy the boundary alone
        chk("_run_start_boundary honors an explicit valid ALARM_RUN_STARTED_AT",
            _run_start_boundary(), "2026-07-18T11:59:00Z")
    finally:
        globals()["_gh"] = real_gh
        os.environ.clear()
        os.environ.update(saved)

# --- HOSTILE LEDGER (round-3 P1): a semantically malformed retained row must never wedge -----
    # the alarm. The reviewer reproduced `"count":"oops"` reaching int() in render_body and raising
    # on EVERY subsequent alarm. Coercion at parse (+_safe_count everywhere) must drop/repair.
    chk("coerce: non-dict row dropped", _coerce_row("not-a-dict"), None)
    chk("coerce: unkeyable row dropped (blank workflow)",
        _coerce_row({"workflow": "", "job": "j", "failure_class": "c"}), None)
    chk("coerce: missing failure_class dropped", _coerce_row({"workflow": "w", "job": "j"}), None)
    ok("coerce: count 'oops' repairs to 1",
       _coerce_row({"workflow": "w", "job": "j", "failure_class": "c",
                    "count": "oops"})["count"] == 1)
    ok("coerce: count None repairs to 1",
       _coerce_row({"workflow": "w", "job": "j", "failure_class": "c",
                    "count": None})["count"] == 1)
    ok("coerce: count list repairs to 1",
       _coerce_row({"workflow": "w", "job": "j", "failure_class": "c",
                    "count": [9, 9]})["count"] == 1)
    ok("coerce: non-str last_seen repairs to ''",
       _coerce_row({"workflow": "w", "job": "j", "failure_class": "c",
                    "last_seen": 12345})["last_seen"] == "")
    ok("coerce: hostile extra fields never persist",
       "evil" not in _coerce_row({"workflow": "w", "job": "j", "failure_class": "c",
                                  "evil": "payload"}))
    hostile_rows = [
        {"workflow": "wa", "job": "ja", "failure_class": "job-failure", "count": "oops",
         "last_seen": "2026-07-18T10:00:00Z", "run_url": "https://x/1", "detail": "d",
         "failed_step": ""},
        "not-a-dict",
        {"workflow": "", "job": "j", "failure_class": "c", "count": 2},
        {"workflow": "wb", "job": "jb", "failure_class": "job-failure", "count": None,
         "last_seen": 12345, "run_url": None, "detail": {"k": "v"}},
    ]
    hostile_body = "\n".join([
        MARKER, LEDGER_MARKER_OPEN, "```json",
        json.dumps({"rows": hostile_rows, "folded_through": "evil"}),
        "```", LEDGER_MARKER_CLOSE,
    ])
    hostile_parsed, hostile_wm = _parse_ledger_doc(hostile_body)
    chk("hostile ledger: malformed rows dropped, repairable rows kept", len(hostile_parsed), 2)
    chk("hostile ledger: non-int watermark coerces to 0", hostile_wm, 0)
    ok("hostile ledger: every retained count is a usable int",
       all(isinstance(r["count"], int) and r["count"] >= 1 for r in hostile_parsed))
    rendered_hostile = render_body(hostile_parsed, "jeswr")   # must not raise (the repro'd wedge)
    ok("hostile ledger renders (no int() wedge)", MARKER in rendered_hostile)
    # a subsequent alarm against the hostile body must REPAIR the persisted ledger, not crash:
    heal = {"body": hostile_body}

    def hostile_gh(args, token, capture=False):
        if args and args[0] == "api":
            return subprocess.CompletedProcess(args, 0, "", "")
        verb = args[1] if len(args) > 1 else ""
        if verb == "list":
            state = args[args.index("--state") + 1] if "--state" in args else ""
            if state == "open":
                return subprocess.CompletedProcess(
                    args, 0, json.dumps([{"number": 13, "body": heal["body"]}]), "")
            return subprocess.CompletedProcess(args, 0, "[]", "")
        if verb == "edit" and "--body" in args:
            heal["body"] = args[args.index("--body") + 1]
            return subprocess.CompletedProcess(args, 0, "", "")
        if verb == "view":
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"body": heal["body"], "state": "OPEN"}), "")
        return subprocess.CompletedProcess(args, 0, "", "")

    globals()["_gh"] = hostile_gh
    try:
        ok("upsert against a hostile ledger succeeds (repairs, never wedges)",
           upsert_alarm({"workflow": "wc", "job": "jc", "failure_class": "job-failure",
                         "failed_step": "", "detail": "d", "run_url": "https://x/9",
                         "last_seen": "2026-07-18T12:00:00Z"}, "jeswr/x", "tok", "jeswr") is True)
        healed = _parse_ledger(heal["body"])
        ok("hostile ledger is REPAIRED in place (all counts int, junk rows gone)",
           len(healed) == 3 and all(isinstance(r.get("count"), int) for r in healed)
           and any(r.get("workflow") == "wc" for r in healed))
    finally:
        globals()["_gh"] = real_gh
    # legacy bare-list ledger format (pre-watermark bodies) still parses — a deploy across the
    # format change must not drop the accumulated ledger.
    legacy_body = "\n".join([
        MARKER, LEDGER_MARKER_OPEN, "```json",
        json.dumps([{"workflow": "w", "job": "j", "failure_class": "job-failure", "count": 2,
                     "last_seen": "2026-07-18T10:00:00Z"}]),
        "```", LEDGER_MARKER_CLOSE,
    ])
    legacy_rows, legacy_wm = _parse_ledger_doc(legacy_body)
    chk("legacy list-format ledger still parses", len(legacy_rows), 1)
    chk("legacy list-format ledger implies watermark 0", legacy_wm, 0)

    # --- DURABLE ROW COMMENTS (round-3 P1: the body-only loop LOST rows under concurrency) ------
    # The reproduced interleave: A writes+verifies, then B — merging from a STALE base — over-
    # writes A's body and verifies only its own row. With the two-layer protocol A's row lives in
    # the comment log, so B's stale-base fold restores it: the lost update is impossible.
    def make_comment_gh(initial_body):
        log = {"body": initial_body, "comments": [], "next_id": 101, "fail_listing": False}

        def fake(args, token, capture=False):
            if args and args[0] == "api":
                if len(args) >= 4 and args[1].endswith("/comments") and args[2] == "-f":
                    cid = log["next_id"]
                    log["next_id"] += 1
                    log["comments"].append({
                        "id": cid, "body": args[3][len("body="):],
                        "user": {"login": "github-actions[bot]"},
                        "author_association": "NONE",
                        "created_at": "2026-07-18T12:00:00Z"})
                    return subprocess.CompletedProcess(args, 0, json.dumps({"id": cid}), "")
                if "--slurp" in args:
                    if log["fail_listing"]:
                        return subprocess.CompletedProcess(args, 1, "", "boom")
                    return subprocess.CompletedProcess(
                        args, 0, json.dumps([log["comments"]]), "")
                return subprocess.CompletedProcess(args, 0, "", "")
            verb = args[1] if len(args) > 1 else ""
            if verb == "list":
                state = args[args.index("--state") + 1] if "--state" in args else ""
                if state == "open":
                    return subprocess.CompletedProcess(
                        args, 0, json.dumps([{"number": 21, "body": log["body"]}]), "")
                return subprocess.CompletedProcess(args, 0, "[]", "")
            if verb == "edit" and "--body" in args:
                log["body"] = args[args.index("--body") + 1]
                return subprocess.CompletedProcess(args, 0, "", "")
            if verb == "view":
                return subprocess.CompletedProcess(
                    args, 0, json.dumps({"body": log["body"], "state": "OPEN"}), "")
            return subprocess.CompletedProcess(args, 0, "", "")
        return fake, log

    base_body = render_body([], "jeswr")
    row_a = {"workflow": "dispatch", "job": "plan", "failure_class": "job-failure",
             "failed_step": "", "detail": "a", "run_url": "https://x/1",
             "last_seen": "2026-07-18T12:00:00Z"}
    row_b = {"workflow": "worker", "job": "run", "failure_class": "job-failure",
             "failed_step": "", "detail": "b", "run_url": "https://x/2",
             "last_seen": "2026-07-18T12:05:00Z"}
    fake, log = make_comment_gh(base_body)
    globals()["_gh"] = fake
    try:
        ok("writer A converges", upsert_alarm(dict(row_a), "jeswr/x", "tok", "jeswr") is True)
        _rows_a, wm_a = _parse_ledger_doc(log["body"])
        ok("A's durable comment landed and A's body write covers it (watermark advanced)",
           len(log["comments"]) == 1 and wm_a >= log["comments"][0]["id"])
        # B merges from a STALE base (the exact reproduced interleave: B never saw A's write)
        log["body"] = base_body
        ok("writer B (stale base) converges", upsert_alarm(dict(row_b), "jeswr/x", "tok",
                                                           "jeswr") is True)
        final_rows = _parse_ledger(log["body"])
        ok("A's row SURVIVES B's stale-base overwrite (folded from the durable comment log — "
           "the round-3 lost-update is impossible)",
           any(r.get("workflow") == "dispatch" for r in final_rows)
           and any(r.get("workflow") == "worker" for r in final_rows))
    finally:
        globals()["_gh"] = real_gh
    # Worst case: B cannot even LIST the comment log (fold degraded) and clobbers A's view. A's
    # row must still be durable (pending comment above the watermark) and the NEXT writer heals
    # the view from the log.
    fake, log = make_comment_gh(base_body)
    globals()["_gh"] = fake
    try:
        upsert_alarm(dict(row_a), "jeswr/x", "tok", "jeswr")
        log["body"] = base_body          # B reads a stale base…
        log["fail_listing"] = True       # …and its comment-log fold fails
        upsert_alarm(dict(row_b), "jeswr/x", "tok", "jeswr")
        rows_after_b, wm_after_b = _parse_ledger_doc(log["body"])
        ok("degraded-fold clobber: A's row is out of the VIEW but never out of the LOG",
           all(r.get("workflow") != "dispatch" for r in rows_after_b)
           and any(c["id"] > wm_after_b and "dispatch" in c["body"] for c in log["comments"]))
        log["fail_listing"] = False
        upsert_alarm({"workflow": "groom", "job": "groom", "failure_class": "job-failure",
                      "failed_step": "", "detail": "c", "run_url": "https://x/3",
                      "last_seen": "2026-07-18T12:10:00Z"}, "jeswr/x", "tok", "jeswr")
        healed_rows = _parse_ledger(log["body"])
        ok("the next writer HEALS the view from the durable log (A restored)",
           any(r.get("workflow") == "dispatch" for r in healed_rows)
           and any(r.get("workflow") == "worker" for r in healed_rows)
           and any(r.get("workflow") == "groom" for r in healed_rows))
    finally:
        globals()["_gh"] = real_gh

    # --- comment-injection gate: an UNTRUSTED row comment is never folded ------------------------
    # (round-5 P2: the gate must admit only EXACT configured automation logins — `evil-app[bot]`
    # is a syntactically-bot login every GitHub App gets, and it must be rejected.)
    inj_comments = [[
        {"id": 301, "body": f"{ROW_COMMENT_MARKER}\n```json\n" + json.dumps(
            {"workflow": "evil", "job": "evil", "failure_class": "job-failure"}) + "\n```",
         "user": {"login": "drive-by-user"}, "author_association": "NONE",
         "created_at": "2026-07-18T12:00:00Z"},
        {"id": 302, "body": f"{ROW_COMMENT_MARKER}\n```json\n" + json.dumps(
            {"workflow": "worker", "job": "run", "failure_class": "job-failure"}) + "\n```",
         "user": {"login": "github-actions[bot]"}, "author_association": "NONE",
         "created_at": "2026-07-18T12:00:00Z"},
        {"id": 303, "body": f"{ROW_COMMENT_MARKER}\n```json\n" + json.dumps(
            {"workflow": "groom", "job": "g", "failure_class": "job-failure"}) + "\n```",
         "user": {"login": "jeswr"}, "author_association": "OWNER",
         "created_at": "2026-07-18T12:00:00Z"},
        {"id": 304, "body": f"{ROW_COMMENT_MARKER}\n```json\n" + json.dumps(
            {"workflow": "evil2", "job": "evil2", "failure_class": "job-failure",
             "last_seen": "2099-01-01T00:00:00Z"}) + "\n```",
         "user": {"login": "evil-app[bot]"}, "author_association": "NONE",
         "created_at": "2026-07-18T12:00:00Z"},
    ]]

    def inj_gh(args, token, capture=False):
        return subprocess.CompletedProcess(args, 0, json.dumps(inj_comments), "")

    globals()["_gh"] = inj_gh
    try:
        listed = _list_row_comments(21, "jeswr/x", "tok")
        chk("untrusted row comments are IGNORED (injection gate; a foreign [bot] is untrusted)",
            [cid for cid, _r, _c in listed], [302, 303])
        # a maintainer-configured extra automation login IS admitted (exact match only)
        saved_logins = os.environ.get("ALARM_TRUSTED_LOGINS")
        os.environ["ALARM_TRUSTED_LOGINS"] = "evil-app[bot]"
        try:
            listed_extra = _list_row_comments(21, "jeswr/x", "tok")
            chk("ALARM_TRUSTED_LOGINS extends the exact-login allowlist",
                [cid for cid, _r, _c in listed_extra], [302, 303, 304])
            # ...and even a TRUSTED writer's future last_seen is CLAMPED to the server-assigned
            # comment time (round-5 P2: a future stamp would survive every recovery prune).
            future_row = [r for cid, r, _c in listed_extra if cid == 304][0]
            chk("a future last_seen is clamped to the comment's created_at",
                future_row["last_seen"], "2026-07-18T12:00:00Z")
        finally:
            if saved_logins is None:
                os.environ.pop("ALARM_TRUSTED_LOGINS", None)
            else:
                os.environ["ALARM_TRUSTED_LOGINS"] = saved_logins
    finally:
        globals()["_gh"] = real_gh

    # --- structural timestamps + ledger-to-ledger merge helpers ---------------------------------
    ok("_valid_ts accepts the canonical stamp", _valid_ts("2026-07-18T12:00:00Z"))
    ok("_valid_ts rejects junk/None/partial stamps",
       not _valid_ts("yesterday-ish") and not _valid_ts(None)
       and not _valid_ts("2026-07-18 12:00") and not _valid_ts(""))
    ok("coerce: a garbage last_seen repairs to '' (sorts oldest, prunable)",
       _coerce_row({"workflow": "w", "job": "j", "failure_class": "c",
                    "last_seen": "yesterday-ish"})["last_seen"] == "")
    merged_ledgers = _merge_ledgers(
        [{"workflow": "w", "job": "j", "failure_class": "c", "count": 2,
          "last_seen": "2026-07-18T10:00:00Z", "first_seen": "2026-07-18T09:00:00Z",
          "run_url": "https://x/1", "detail": "old", "failed_step": ""}],
        [{"workflow": "w", "job": "j", "failure_class": "c", "count": 3,
          "last_seen": "2026-07-18T11:00:00Z", "first_seen": "2026-07-18T08:00:00Z",
          "run_url": "https://x/2", "detail": "new", "failed_step": ""},
         {"workflow": "w2", "job": "j", "failure_class": "c", "count": 1,
          "last_seen": "2026-07-18T10:30:00Z", "run_url": "https://x/3", "detail": "d",
          "failed_step": ""},
         "junk-not-a-row"])
    same_key = next(r for r in merged_ledgers if r["workflow"] == "w")
    ok("_merge_ledgers SUMS same-key counts (each ledger counted its own occurrences)",
       same_key["count"] == 5)
    ok("_merge_ledgers keeps the fresher last_seen/detail and the earliest first_seen",
       same_key["last_seen"] == "2026-07-18T11:00:00Z" and same_key["detail"] == "new"
       and same_key["first_seen"] == "2026-07-18T08:00:00Z")
    ok("_merge_ledgers appends new keys and drops junk rows",
       len(merged_ledgers) == 2 and any(r["workflow"] == "w2" for r in merged_ledgers))

    # --- GC of folded comments: only ≤ watermark AND old enough --------------------------------
    gc_deletes = []

    def gc_gh(args, token, capture=False):
        if args and args[0] == "api" and "-X" in args:
            gc_deletes.append(args[-1])
        return subprocess.CompletedProcess(args, 0, "", "")

    globals()["_gh"] = gc_gh
    try:
        gc_row = {"workflow": "w", "job": "j", "failure_class": "c", "count": 1,
                  "last_seen": "", "detail": None, "failed_step": "", "run_url": ""}
        _gc_folded_comments(21, "jeswr/x", "tok", [
            (1, gc_row, "2026-07-18T09:00:00Z"),   # folded + old -> deleted
            (2, gc_row, "2026-07-18T11:59:00Z"),   # folded but YOUNG -> kept (regression window)
            (3, gc_row, "2026-07-18T09:00:00Z"),   # above the watermark -> NEVER deleted
        ], 2, now=now)
        chk("GC deletes only folded, old comments", gc_deletes,
            ["repos/jeswr/x/issues/comments/1"])
    finally:
        globals()["_gh"] = real_gh

    # --- REOPEN MUST SUCCEED (round-3 P1: a failed reopen was reported as success while the ----
    # alarm stayed hidden behind a CLOSED issue). Transient failure retries; permanent failure
    # returns False LOUDLY; the post-write verify enforces final-state-open too.
    def make_reopen_gh(closed_body_text, reopen_rcs):
        st = {"body": closed_body_text, "state": "CLOSED", "reopens": 0,
              "rcs": list(reopen_rcs)}

        def fake(args, token, capture=False):
            if args and args[0] == "api":
                return subprocess.CompletedProcess(args, 0, "", "")
            verb = args[1] if len(args) > 1 else ""
            if verb == "list":
                state = args[args.index("--state") + 1] if "--state" in args else ""
                if (state == "open") == (st["state"] == "OPEN"):
                    return subprocess.CompletedProcess(
                        args, 0, json.dumps([{"number": 31, "body": st["body"]}]), "")
                return subprocess.CompletedProcess(args, 0, "[]", "")
            if verb == "reopen":
                st["reopens"] += 1
                rc = st["rcs"].pop(0) if st["rcs"] else 0
                if rc == 0:
                    st["state"] = "OPEN"
                return subprocess.CompletedProcess(args, rc, "", "")
            if verb == "edit" and "--body" in args:
                st["body"] = args[args.index("--body") + 1]
                return subprocess.CompletedProcess(args, 0, "", "")
            if verb == "view":
                return subprocess.CompletedProcess(
                    args, 0, json.dumps({"body": st["body"], "state": st["state"]}), "")
            return subprocess.CompletedProcess(args, 0, "", "")
        return fake, st

    closed_body2 = render_body([{"workflow": "w", "job": "j", "failure_class": "job-failure",
                                 "count": 1, "last_seen": "2026-07-18T10:00:00Z",
                                 "run_url": "https://x/1", "detail": "d"}], "jeswr")
    flap_row = {"workflow": "w", "job": "j", "failure_class": "job-failure", "failed_step": "",
                "detail": "again", "run_url": "https://x/2", "last_seen": "2026-07-18T12:00:00Z"}
    fake, st = make_reopen_gh(closed_body2, [1, 0])
    globals()["_gh"] = fake
    try:
        ok("transient reopen failure RETRIES and succeeds",
           upsert_alarm(dict(flap_row), "jeswr/x", "tok", "jeswr") is True)
        ok("the reopen was actually retried", st["reopens"] >= 2)
        chk("final state is OPEN after the retried reopen", st["state"], "OPEN")
    finally:
        globals()["_gh"] = real_gh
    fake, st = make_reopen_gh(closed_body2, [1, 1, 1, 1, 1, 1])
    globals()["_gh"] = fake
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            permanent = upsert_alarm(dict(flap_row), "jeswr/x", "tok", "jeswr")
        ok("permanent reopen failure returns False (NEVER success behind a closed alert)",
           permanent is False)
        ok("permanent reopen failure is LOUD (::error::)", "::error::" in buf.getvalue())
        chk("the issue was never edited while closed", _parse_ledger(st["body"]),
            _parse_ledger(closed_body2))
    finally:
        globals()["_gh"] = real_gh
    # verify-detects-closed variant: the write lands on an OPEN issue, a racing --resolve closes
    # it, and the rc-checked reopen FAILS -> the writer must report failure, not success.
    cvrf = {"body": "", "reopen_rc": 1}

    def closed_verify_reopen_fails_gh(args, token, capture=False):
        if args and args[0] == "api":
            return subprocess.CompletedProcess(args, 0, "", "")
        verb = args[1] if len(args) > 1 else ""
        if verb == "list":
            state = args[args.index("--state") + 1] if "--state" in args else ""
            if state == "open":
                return subprocess.CompletedProcess(
                    args, 0, json.dumps([{"number": 2, "body": render_body([], "jeswr")}]), "")
            return subprocess.CompletedProcess(args, 0, "[]", "")
        if verb == "edit" and "--body" in args:
            cvrf["body"] = args[args.index("--body") + 1]
            return subprocess.CompletedProcess(args, 0, "", "")
        if verb == "view":
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"body": cvrf["body"], "state": "CLOSED"}), "")
        if verb == "reopen":
            return subprocess.CompletedProcess(args, cvrf["reopen_rc"], "", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    globals()["_gh"] = closed_verify_reopen_fails_gh
    try:
        ok("a failed reopen at verify time is a FAILURE, not silent success",
           upsert_alarm(dict(flap_row), "jeswr/x", "tok", "jeswr") is False)
    finally:
        globals()["_gh"] = real_gh

    # --- resolver folds the durable comment log BEFORE deciding (never closes over a pending ---
    # row whose writer's body view was clobbered) -----------------------------------------------
    rf_body = render_body([{"workflow": "dispatch", "job": "plan",
                            "failure_class": "job-failure", "count": 1,
                            "last_seen": "2026-07-18T10:00:00Z", "run_url": "https://x/1",
                            "detail": "d", "failed_step": ""}], "jeswr", folded_through=400)
    rf = {"body": rf_body, "closes": 0, "edits": 0}
    rf_comments = [[{
        "id": 401, "body": f"{ROW_COMMENT_MARKER}\n```json\n" + json.dumps(
            {"workflow": "worker", "job": "run", "failure_class": "job-failure", "count": 1,
             "last_seen": "2026-07-18T11:00:00Z", "run_url": "https://x/7", "detail": "d",
             "failed_step": ""}) + "\n```",
        "user": {"login": "github-actions[bot]"}, "author_association": "NONE",
        "created_at": "2026-07-18T11:00:00Z"}]]

    def resolver_fold_gh(args, token, capture=False):
        if args and args[0] == "api":
            if "--slurp" in args:
                return subprocess.CompletedProcess(args, 0, json.dumps(rf_comments), "")
            return subprocess.CompletedProcess(args, 0, "", "")
        verb = args[1] if len(args) > 1 else ""
        if verb == "list":
            state = args[args.index("--state") + 1] if "--state" in args else ""
            if state == "open":
                return subprocess.CompletedProcess(
                    args, 0, json.dumps([{"number": 41, "body": rf["body"]}]), "")
            return subprocess.CompletedProcess(args, 0, "[]", "")
        if verb == "edit" and "--body" in args:
            rf["edits"] += 1
            rf["body"] = args[args.index("--body") + 1]
            return subprocess.CompletedProcess(args, 0, "", "")
        if verb == "close":
            rf["closes"] += 1
            return subprocess.CompletedProcess(args, 0, "", "")
        if verb == "view":
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"body": rf["body"], "state": "OPEN"}), "")
        return subprocess.CompletedProcess(args, 0, "", "")

    globals()["_gh"] = resolver_fold_gh
    try:
        resolve_alarm("dispatch", "jeswr/x", "tok", "jeswr", run_started="2026-07-18T12:00:00Z")
        chk("resolver NEVER closes over a pending durable row comment", rf["closes"], 0)
        ok("resolver folds the pending comment row into the refreshed body",
           rf["edits"] >= 1
           and any(r.get("workflow") == "worker" for r in _parse_ledger(rf["body"]))
           and all(r.get("workflow") != "dispatch" for r in _parse_ledger(rf["body"])))
        ok("resolver advances the watermark over the folded comment",
           _parse_ledger_doc(rf["body"])[1] >= 401)
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
