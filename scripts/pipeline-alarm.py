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
#       an account handle, or a token — it reuses worker-live.sh's posture: only a short, redacted,
#       host-observable summary line. A diagnostic input that even LOOKS like a credential is
#       redacted before it can reach the issue body (see _sanitize / SECRET_PATTERNS).
#   (c) RAISE a LOUD, DEDUPED, maintainer-visible alert: a SINGLE rolling "⚠️ pipeline failures"
#       issue (label `pipeline-alert`), keyed by a hidden HTML body marker (the model-health.py
#       upsert pattern), carrying a compact table (class × count × last-seen × run-link). A recurring
#       failure UPDATES the rolling record — it never spams a new issue. This shares the ledger
#       alert-channel philosophy with the throughput observability work (PR #93 `throughput-alert`):
#       one failure surface, one throughput surface, both rolling+deduped, both @-mentioning the
#       maintainer — never two mechanisms fighting.
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

# --- credential-safe redaction (reuse worker-live.sh's "sanitized class only" posture) ----------
# Any diagnostic string is scrubbed BEFORE it can reach the issue body. These patterns are
# deliberately broad — a false-positive redaction (over-scrubbing) is safe; a leaked token is not.
SECRET_PATTERNS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}"),                 # GitHub PAT / App / OAuth / refresh
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),               # fine-grained PAT
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),                     # OpenAI-style key
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}"),                 # Anthropic-style key
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}"),  # JWT
    re.compile(r"(?i)\b(token|secret|password|passwd|api[_-]?key|bearer|authorization)\b"
               r"\s*[:=]\s*\S+"),                              # key: value credential lines
    re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),                   # long base64-ish blobs (token-shaped)
]
_REDACTED = "[redacted]"


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
    # single line, printable only, bounded
    s = "".join(ch if (ch.isprintable() and ch not in "`|") else " " for ch in s)
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
    lines.append("_This issue auto-updates each failing tick and is safe to close once resolved; "
                 "it reopens on the next failure. Recovery is not auto-detected (a failure alarm is "
                 "loud-on-fail, quiet-on-heal)._")
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
    proc = _gh(["issue", "list", "-R", repo, "--label", ALERT_LABEL, "--state", state,
                "--json", "number,body", "--limit", "50"], token, capture=True)
    if proc.returncode != 0:
        return None, None
    try:
        found = json.loads(proc.stdout or "[]")
    except ValueError:
        return None, None
    for issue in found:
        if isinstance(issue, dict) and MARKER in (issue.get("body") or ""):
            return issue.get("number"), issue.get("body") or ""
    return None, None


def upsert_alarm(new_row, repo, token, maintainer):
    """Idempotent single-rolling-issue upsert. Loads the existing ledger (open, else the closed
    marker issue to REOPEN it rather than mint a duplicate), merges the new failure row, and writes
    the refreshed body. Every gh return code is checked; a failure degrades LOUD to ::error:: and
    never raises (fail-soft)."""
    if not repo or not token:
        print("::error::pipeline-alarm: no alert repo/token resolved; failure NOT recorded to an "
              "issue (still visible as the run's red X). Set REGISTRY_REPO + a token env.")
        return False
    _gh(["label", "create", ALERT_LABEL, "-R", repo, "--color", ALERT_COLOR,
         "--description", "Automated pipeline-failure alarm (maintainer action)"],
        token, capture=True)
    num, body = _find_rolling_issue(repo, token, "open")
    reopened = False
    if num is None:
        num, body = _find_rolling_issue(repo, token, "closed")
        reopened = num is not None
    ledger = _parse_ledger(body)
    ledger = _merge_row(ledger, new_row)
    ledger = _prune(ledger)
    rendered = render_body(ledger, maintainer)
    if num is None:
        rc = _gh(["issue", "create", "-R", repo, "--title", ALERT_TITLE,
                  "--label", ALERT_LABEL, "--body", rendered], token).returncode
        if rc == 0:
            print("::warning::pipeline-alarm: raised the rolling pipeline-failure alert")
            return True
        print("::error::pipeline-alarm: raising the alert FAILED (retries next failing tick); "
              "primary failure still visible as the run's red X")
        return False
    if reopened:
        _gh(["issue", "reopen", str(num), "-R", repo], token)
    rc = _gh(["issue", "edit", str(num), "-R", repo, "--body", rendered], token).returncode
    if rc == 0:
        print(f"::warning::pipeline-alarm: {'reopened' if reopened else 'refreshed'} "
              f"the rolling pipeline-failure alert (#{num})")
        return True
    print("::error::pipeline-alarm: updating the alert FAILED (retries next failing tick); "
          "primary failure still visible as the run's red X")
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
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    maintainer = os.environ.get("MAINTAINER_HANDLE", "jeswr")
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
    ]
    for i, leak in enumerate(leaks):
        san = _sanitize(f"error near {leak} happened")
        ok(f"sanitize scrubs secret #{i} ({leak[:8]}…)",
           leak not in san and "hunter2secretvalue" not in san)
    # sanitize also strips table-breaking chars + bounds length
    ok("sanitize strips backtick/pipe", "`" not in _sanitize("a`b|c") and "|" not in _sanitize("a`b|c"))
    ok("sanitize bounds length", len(_sanitize("x" * 5000)) <= MAX_DETAIL_LEN)
    chk("sanitize blank -> placeholder", _sanitize(""), "(no diagnostic captured)")
    chk("sanitize None -> placeholder", _sanitize(None), "(no diagnostic captured)")

    # a full row's rendered body must ALSO be leak-free even if the ledger was tampered upstream
    tampered = [{
        "workflow": "worker", "job": "run", "failure_class": "job-failure", "count": 1,
        "last_seen": "2026-07-18T11:00:00Z", "run_url": "https://x/1",
        "failed_step": "model", "detail": "ghp_" + "z" * 36 + " leaked",
    }]
    rendered = render_body(tampered, "jeswr")
    ok("render_body re-sanitizes a tampered ledger detail",
       ("ghp_" + "z" * 36) not in rendered)

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
        if verb in ("create", "edit"):
            # capture the written body (the --body value)
            if "--body" in args:
                existing["body"] = args[args.index("--body") + 1]
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

    def fake_gh_closed(args, token, capture=False):
        calls.append(list(args))
        verb = args[1] if len(args) > 1 else ""
        if verb == "list":
            state = args[args.index("--state") + 1] if "--state" in args else ""
            if state == "closed":
                return subprocess.CompletedProcess(
                    args, 0, json.dumps([{"number": 9, "body": closed_body}]), "")
            return subprocess.CompletedProcess(args, 0, "[]", "")
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

    if failures:
        print("pipeline-alarm --self-test FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("pipeline-alarm --self-test: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
